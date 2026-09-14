"""The packaged RBAC map (src/cnc_mcp/data/rbac_map.json) and its generator
(scripts/rbac_map.py): the map names every registered tool, every requirement
points at a catalogued API, the playbooks are composed from the right siblings,
and regenerating offline changes nothing (the --check CI guard).

No network: the generator's --check mode reads the catalogue embedded in the
committed map.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

from cnc_mcp.tools.admin import (
    RBAC_ALL_METHODS,
    evaluate_rbac_map,
    listen_path_pattern,
    load_rbac_map,
)
from cnc_mcp.tools.composite import SIBLING_CALLS

REPO = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO / "src" / "cnc_mcp" / "tools"
MAP_PATH = REPO / "src" / "cnc_mcp" / "data" / "rbac_map.json"
DOC_PATH = REPO / "docs" / "RBAC.md"
ROLE_FILES = {
    "readonly": REPO / "docs" / "rbac" / "cnc-mcp-readonly.role.json",
    "operator": REPO / "docs" / "rbac" / "cnc-mcp-operator.role.json",
}

if str(REPO / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO / "scripts"))

import rbac_map  # noqa: E402  (scripts/ on sys.path)

_REGISTER_RE = re.compile(r'@register_tool\(\s*mcp,\s*ctx,\s*name="([^"]+)"', re.S)


@pytest.fixture(scope="module")
def rbac() -> dict:
    return json.loads(MAP_PATH.read_text(encoding="utf-8"))


def registered_names_in_source() -> set[str]:
    names: set[str] = set()
    for path in TOOLS_DIR.glob("*.py"):
        names.update(_REGISTER_RE.findall(path.read_text(encoding="utf-8")))
    return names


# --- the committed map -----------------------------------------------------------------


def test_map_names_every_register_tool_call(rbac):
    source_names = registered_names_in_source()
    assert len(source_names) > 200  # the regex found the decorators
    missing = source_names - set(rbac["tools"])
    extra = set(rbac["tools"]) - source_names
    assert not missing, f"tools missing from rbac_map.json (run make rbac): {sorted(missing)}"
    assert not extra, f"tools in rbac_map.json that no longer exist: {sorted(extra)}"
    assert rbac["generated_from"]["tool_count"] == len(rbac["tools"])


def test_packaged_map_loads_through_importlib_resources(rbac):
    assert load_rbac_map() == rbac


def test_every_requirement_names_a_catalogued_api(rbac):
    apis = rbac["apis"]
    assert len(apis) == rbac["generated_from"]["api_count"]
    for api_id, api in apis.items():
        assert set(api) == {"feature", "listen_path", "name"}, api_id  # sanitised: nothing else
        assert api["listen_path"].startswith("/"), api_id
    for name, spec in rbac["tools"].items():
        assert set(spec) >= {"area", "read_only", "requirements"}, name
        for req in spec["requirements"]:
            assert set(req) == {"api_id", "method", "path"}, (name, req)
            assert req["api_id"] in apis, (name, req)
            assert req["method"] in RBAC_ALL_METHODS or req["method"] == "*", (name, req)
            assert req["path"].startswith("/crosswork/"), (name, req)
            # the api's listen path really claims the template (same rule as the runtime check)
            assert listen_path_pattern(apis[req["api_id"]]["listen_path"]).match(req["path"]), (
                name,
                req,
            )


def test_every_non_playbook_tool_has_requirements_and_nothing_is_unresolved(rbac):
    assert rbac["unresolved"] == []
    for name, spec in rbac["tools"].items():
        if "composed_from" in spec:
            continue
        assert spec["requirements"], f"{name} has endpoints but no requirement"


def test_playbooks_are_composed_from_their_sibling_calls(rbac):
    playbooks = {name for name, spec in rbac["tools"].items() if "composed_from" in spec}
    assert playbooks == set(SIBLING_CALLS)
    for name, siblings in SIBLING_CALLS.items():
        spec = rbac["tools"][name]
        assert spec["area"] == "composite"
        assert spec["composed_from"] == sorted(siblings)
        union = {
            (r["method"], r["path"], r["api_id"])
            for sibling in siblings
            for r in rbac["tools"][sibling]["requirements"]
        }
        assert {(r["method"], r["path"], r["api_id"]) for r in spec["requirements"]} == union


def test_map_is_sorted_and_deterministic(rbac):
    assert list(rbac["tools"]) == sorted(rbac["tools"])
    assert list(rbac["apis"]) == sorted(rbac["apis"])
    assert "generated_at" not in rbac["generated_from"]  # no timestamps: --check must be stable
    assert MAP_PATH.read_text(encoding="utf-8") == rbac_map.dump_json(rbac)


def test_sso_ticket_calls_are_not_in_the_map(rbac):
    """The CAS login legs are not gateway APIs (documented, never mapped)."""
    for spec in rbac["tools"].values():
        assert not any("/crosswork/sso/" in r["path"] for r in spec["requirements"])
    assert "sso/v1/tickets" in DOC_PATH.read_text(encoding="utf-8")


# --- the generated role bodies ---------------------------------------------------------


def grants(rbac: dict, *, read_only: bool | None) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for spec in rbac["tools"].values():
        if read_only is not None and spec["read_only"] is not read_only:
            continue
        for req in spec["requirements"]:
            methods = set(RBAC_ALL_METHODS) if req["method"] == "*" else {req["method"]}
            out.setdefault(req["api_id"], set()).update(methods)
    return out


def role(kind: str) -> dict:
    body = json.loads(ROLE_FILES[kind].read_text(encoding="utf-8"))
    assert list(body) == [f"cnc-mcp-{kind}"]
    return body[f"cnc-mcp-{kind}"]


def requirements(rbac: dict, *, read_only: bool | None) -> set[tuple[str, str, str]]:
    """Every (method, path template, api_id) the selected tools send (``*`` = all five)."""
    out: set[tuple[str, str, str]] = set()
    for spec in rbac["tools"].values():
        if read_only is not None and spec["read_only"] is not read_only:
            continue
        for req in spec["requirements"]:
            methods = RBAC_ALL_METHODS if req["method"] == "*" else (req["method"],)
            out.update((m, req["path"], req["api_id"]) for m in methods)
    return out


def concrete(template: str) -> str:
    """A plausible request for a template: ``abc`` mid-path, a RESTCONF key with a ``/``
    (``a/b=c``) in the last segment."""
    segments = template.split("/")
    return "/".join(
        seg.replace("{}", "a/b=c" if i == len(segments) - 1 else "abc")
        for i, seg in enumerate(segments)
    )


def tyk_permits(role_body: dict, api_id: str, method: str, path: str) -> bool:
    """Tyk v5.1.1 granular access: the API is granted and some allowed_urls entry lists
    the method and matches the FULL path as an unanchored regexp search."""
    grant = role_body["access_rights"].get(api_id)
    if grant is None:
        return False
    return any(
        method in entry["methods"] and re.compile(entry["url"]).search(path)
        for entry in grant["allowed_urls"]
    )


def top_level_alternatives(url: str) -> list[str]:
    """The alternatives of a regex split on ``|`` at nesting depth 0 (an escaped
    metacharacter never opens, closes or splits a group)."""
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    i = 0
    while i < len(url):
        char = url[i]
        if char == "\\":
            current.append(url[i : i + 2])
            i += 2
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "|" and depth == 0:
            parts.append("".join(current))
            current = []
            i += 1
            continue
        current.append(char)
        i += 1
    parts.append("".join(current))
    return parts


def assert_re2_compatible_and_anchored(url: str, context: object) -> None:
    """The generated URL pattern reads the same under Go RE2 (Tyk) and Python's ``re``,
    and every top-level alternative is anchored at both ends: only the characters the
    generator can emit, escapes shared by both engines (``\\.`` ``\\+`` ``\\(``...),
    no lookaround ``(?``, no possessive ``++``/``*+``/``?+`` (accepted by Python 3.11,
    rejected by RE2), no backreference, no ``\\A``/``\\Z``, no ``/.*``; the only
    wildcards are ``.+`` and ``[^/]+`` (a bare ``.`` or another class is a bug)."""
    assert re.fullmatch(r"[A-Za-z0-9/:=_\-^$()|.+\[\]\\]+", url), context
    assert not re.search(r"\\[^.^$*+?()\[\]{}|\\]", url), context
    assert not re.search(r"[*+?]\+|\(\?", url), context
    assert not re.search(r"(?<!\\)\.(?!\+)", url), context
    assert set(re.findall(r"(?<!\\)\[[^\]]*\]", url)) <= {"[^/]"}, context
    assert "/.*" not in url, context
    re.compile(url)
    for alternative in top_level_alternatives(url):
        assert alternative.startswith("^") and alternative.endswith("$"), (context, alternative)


@pytest.mark.parametrize("kind", ["readonly", "operator"])
def test_role_bodies_carry_exactly_the_needed_methods_one_anchored_entry_each(rbac, kind):
    body = role(kind)
    assert body["name"] == f"cnc-mcp-{kind}"
    for key, value in rbac_map.ROLE_SKELETON.items():  # copied from the admin role dump
        assert body[key] == value, key
    expected = grants(rbac, read_only=True if kind == "readonly" else None)
    assert set(body["access_rights"]) == set(expected)
    for api_id, grant in body["access_rights"].items():
        assert grant["api_id"] == api_id
        assert grant["api_name"] == rbac["apis"][api_id]["name"]
        assert grant["versions"] == ["Default"] and grant["allowance_scope"] == ""
        entries = grant["allowed_urls"]
        assert entries
        seen: list[str] = []
        for entry in entries:
            assert entry["methods"] == [m for m in RBAC_ALL_METHODS if m in entry["methods"]]
            seen.extend(entry["methods"])
            assert_re2_compatible_and_anchored(entry["url"], (kind, api_id))
        # one entry per method (methods sending the same paths share one), no overlap
        assert len(seen) == len(set(seen)), api_id
        assert set(seen) == expected[api_id], api_id
        assert [e["methods"][0] for e in entries] == sorted(
            (e["methods"][0] for e in entries), key=RBAC_ALL_METHODS.index
        )


@pytest.mark.parametrize(
    ("kind", "read_only"), [("readonly", True), ("operator", None)], ids=["readonly", "operator"]
)
def test_role_bodies_permit_every_requirement_of_their_tools(rbac, kind, read_only):
    """(a)/(c): every requirement of every read tool (and of every any_of alternative) is
    permitted by the read-only body, every requirement of every tool by the operator
    body — under Tyk's rule, against a concrete request path."""
    body = role(kind)
    reqs = requirements(rbac, read_only=read_only)
    assert len(reqs) > 150
    refused = [r for r in reqs if not tyk_permits(body, r[2], r[0], concrete(r[1]))]
    assert refused == []
    # the any_of alternatives are both granted (either suffices for the tool)
    for group in rbac["tools"]["cnc_check_permissions"]["any_of"]:
        assert set(group) <= set(body["access_rights"])


REFUSED_WRITES = [
    ("POST", "/crosswork/inventory/v1/nodes"),
    ("POST", "/crosswork/inventory/v1/tags"),
    ("POST", "/crosswork/inventory/v1/credentials"),
    ("POST", "/crosswork/inventory/v1/providers"),
    ("POST", "/crosswork/inventory/v1/locknodes"),
    ("POST", "/crosswork/inventory/v1/nso/sync-to"),
    ("PUT", "/crosswork/alarms/v1/ack"),
    ("PATCH", "/crosswork/inventory/v1/nodes"),
    (
        "POST",
        "/crosswork/nbi/optimization/v3/restconf/operations/"
        "cisco-crosswork-optimization-engine-sr-policy-operations:sr-policy-create",
    ),
    (
        "POST",
        "/crosswork/nbi/optimization/v3/restconf/operations/"
        "cisco-crosswork-optimization-engine-sr-policy-operations:sr-policy-delete",
    ),
    ("DELETE", "/crosswork/inventory/v1/nodes"),
    ("DELETE", "/crosswork/inventory/v1/tags"),
]

# Write-tool GETs the read-only body permits because a READ tool's own runtime-valued
# template covers them (GET /crosswork/proxy/nso/restconf/data/{} reads any RESTCONF data
# path — a read tool can send these too). Never a mutating method: the generator stops.
READONLY_GET_EXCEPTIONS = {
    ("GET", "/crosswork/proxy/nso/restconf/data/{}-plan={}"),
    ("GET", "/crosswork/proxy/nso/restconf/data/{}/{}-plan={}"),
}


def test_readonly_body_refuses_every_write_only_path(rbac):
    """(b) true least privilege: no (method, path) that only the write tools send is
    permitted by the read-only body — the POST creates that share a row and a method
    with the POST queries, every DELETE, ... — except the documented GET reads."""
    body = role("readonly")
    read_pairs = {(m, p) for m, p, _ in requirements(rbac, read_only=True)}
    write_only = {r for r in requirements(rbac, read_only=False) if (r[0], r[1]) not in read_pairs}
    assert len(write_only) > 40
    write_only_pairs = {(m, p) for m, p, _ in write_only}
    for method, path in REFUSED_WRITES:
        assert (method, path) in write_only_pairs, (method, path)  # the template still exists
    deletes = {(m, p) for m, p in write_only_pairs if m == "DELETE"}
    assert len(deletes) >= 5 and "DELETE" not in {m for m, _ in read_pairs}
    permitted = {(m, p) for m, p, api_id in write_only if tyk_permits(body, api_id, m, concrete(p))}
    assert permitted == READONLY_GET_EXCEPTIONS
    assert all(m == "GET" for m, _ in permitted)
    assert rbac_map.readonly_exceptions({"cnc-mcp-readonly": body}, rbac["tools"]) == sorted(
        READONLY_GET_EXCEPTIONS
    )
    # the read tools' generic RESTCONF GET is what covers the two exceptions, and the
    # generated guide attributes them to it
    generic = "/crosswork/proxy/nso/restconf/data/{}"
    assert ("GET", generic) in read_pairs
    assert rbac_map.covering_reads(
        sorted(READONLY_GET_EXCEPTIONS), rbac["tools"], rbac["apis"]
    ) == {pair: [generic] for pair in READONLY_GET_EXCEPTIONS}
    assert f"under `GET {generic}`" in DOC_PATH.read_text(encoding="utf-8")
    with pytest.raises(SystemExit, match="no read tool's template covers"):
        rbac_map.covering_reads(
            [("POST", "/crosswork/inventory/v1/nodes")], rbac["tools"], rbac["apis"]
        )
    # the refused set is also refused as a literal path (no runtime value) on every API
    # the write tools send it to, and with the write path sent as a sub-path of a
    # permitted read path
    for method, path in REFUSED_WRITES:
        api_ids = {api_id for m, p, api_id in write_only if (m, p) == (method, path)}
        assert api_ids, (method, path)
        for api_id in api_ids:
            assert not tyk_permits(body, api_id, method, path), (method, path, api_id)
    assert not tyk_permits(body, "inventory_cwinventory", "POST", "/crosswork/inventory/v1/nodes/")
    assert tyk_permits(body, "inventory_cwinventory", "POST", "/crosswork/inventory/v1/nodes/query")


@pytest.mark.parametrize("kind", ["readonly", "operator"])
@pytest.mark.parametrize("api_id", rbac_map.AAA_APIS)
def test_aaa_api_listing_is_refused_by_both_bodies(rbac, kind, api_id):
    """(d) neither body permits the gateway's full API-definition listing
    (administrative data) on either AAA row, with any method."""
    body = role(kind)
    listen = rbac["apis"][api_id]["listen_path"]
    for forbidden in (
        "/crosswork/aaaread/v1/api",
        "/crosswork/aaa/v1/api",
        f"{listen}v1/api",
        f"{listen}v1/api/",
        f"{listen}v1/api/anything",
    ):
        for method in RBAC_ALL_METHODS:
            assert not tyk_permits(body, api_id, method, forbidden), (forbidden, method)
    # and every alternative is anchored: a granted path under another prefix never matches
    for method, path, granted_api in requirements(
        rbac, read_only=True if kind == "readonly" else None
    ):
        if granted_api == api_id:
            assert not tyk_permits(body, api_id, method, "/crosswork/other" + concrete(path))


def test_path_regex_renders_mid_path_and_tail_placeholders():
    """(f) the regex builder: ``^<base>/(alt|alt)$``, a mid-path ``{}`` is one segment
    (``[^/]+``), a last-segment ``{}`` may carry ``/`` (``.+``), a template equal to the
    listen path is ``^<base>$``, alternatives sorted and deduplicated, a listen-path
    variable (``v{.}``) rendered as the literal the template carries."""
    url = rbac_map.path_regex(
        "/crosswork/aaa/",
        [
            "/crosswork/aaa/v1/role",
            "/crosswork/aaa/v1/role/{}",
            "/crosswork/aaa/v1/role/{}",  # duplicate
            "/crosswork/aaa/v1/user/{}/task",
            "/crosswork/aaa/v2/api",
            "/crosswork/aaa/v2/{}:{}/vpn-service={}",
        ],
    )
    assert url == (
        "^/crosswork/aaa/(v1/role|v1/role/.+|v1/user/[^/]+/task|v2/[^/]+:[^/]+/vpn-service=.+"
        "|v2/api)$"
    )
    pattern = re.compile(url)
    for ok in (
        "/crosswork/aaa/v1/role",
        "/crosswork/aaa/v1/role/admin",
        "/crosswork/aaa/v1/role/a/b=c",
        "/crosswork/aaa/v1/user/mcp-ro/task",
        "/crosswork/aaa/v2/api",
        "/crosswork/aaa/v2/ietf:l3vpn/vpn-service=x/y",
    ):
        assert pattern.search(ok), ok
    for bad in (
        "/crosswork/aaa/v1/api",
        "/crosswork/aaa/v1/roles",
        "/crosswork/aaa/v1/user/a/b/task",  # mid-path value is one segment
        "/crosswork/aaa/v1/user/mcp-ro",
        "/crosswork/aaa/v2/api/x",
        "/crosswork/aaa/v2/x/vpn-service=1",
        "/crosswork/aaaread/v1/role/admin",
        "/x/crosswork/aaa/v1/role",
    ):
        assert not pattern.search(bad), bad
    # the listen path itself, escaped metacharacters, and a listen-path variable
    assert rbac_map.path_regex("/crosswork/alarms/v1/ack", ["/crosswork/alarms/v1/ack"]) == (
        "^/crosswork/alarms/v1/ack$"
    )
    assert rbac_map.path_regex("/crosswork/x.y/", ["/crosswork/x.y/a+b/(c)"]) == (
        r"^/crosswork/x\.y/a\+b/\(c\)$"
    )
    assert (
        rbac_map.path_regex(
            "/crosswork/performance/v{.}/dashboards/",
            [
                "/crosswork/performance/v1/dashboards/summary",
                "/crosswork/performance/v2/dashboards",
            ],
        )
        == "^/crosswork/performance/v1/dashboards/summary$|^/crosswork/performance/v2/dashboards$"
    )
    with pytest.raises(SystemExit, match="not under listen path"):
        rbac_map.path_regex("/crosswork/aaa/", ["/crosswork/aaaread/v1/role"])


def test_path_regex_renders_a_template_a_runtime_value_could_extend_into_the_listen_path():
    """build_map records a runtime-valued template on a second API when a value of its
    ``{}`` could extend it into that API's longer listen path (Router.ambiguous): the
    listen path claims nothing literal of the template, so the row's alternative is the
    whole rendered template — exactly the paths the tool can send there."""
    listen = CATALOGUE["ems-inventory"]["listen_path"]  # /crosswork/inventory/v1/networkelement
    template = "/crosswork/inventory/v1/{}"
    assert rbac_map.Router(CATALOGUE).ambiguous(template, "inventory_cwinventory") == [
        "ems-inventory"
    ]
    assert rbac_map.could_extend_into(template, listen)
    assert rbac_map.path_regex(listen, [template]) == "^/crosswork/inventory/v1/.+$"
    # next to a template the listen path does claim; a mid-path value is one segment
    assert rbac_map.path_regex(
        listen, [template, f"{listen}/query", "/crosswork/inventory/v1/{}/count"]
    ) == (
        "^/crosswork/inventory/v1/.+$|^/crosswork/inventory/v1/[^/]+/count$"
        "|^/crosswork/inventory/v1/networkelement/query$"
    )
    # through the role body (the row build_map adds for the ambiguity)
    tool = {
        "read_only": True,
        "requirements": [
            {"method": "GET", "path": template, "api_id": "inventory_cwinventory"},
            {"method": "GET", "path": template, "api_id": "ems-inventory"},
        ],
    }
    body = rbac_map.role_body("ro", rbac_map.paths_for([tool]), CATALOGUE)
    assert body["ro"]["access_rights"]["ems-inventory"]["allowed_urls"] == [
        {"url": "^/crosswork/inventory/v1/.+$", "methods": ["GET"]}
    ]
    assert rbac_map.body_permits(body, "ems-inventory", "GET", f"{listen}/x/y")
    assert body["ro"]["access_rights"]["inventory_cwinventory"]["allowed_urls"] == [
        {"url": "^/crosswork/inventory/v1/.+$", "methods": ["GET"]}
    ]
    # a template no runtime value could extend into the listen path is still refused
    for other in ("/crosswork/inventory/v1/nodes/{}", "/crosswork/inventory/v1/nodes"):
        assert not rbac_map.could_extend_into(other, listen)
        with pytest.raises(SystemExit, match="not under listen path"):
            rbac_map.path_regex(listen, [other])


@pytest.mark.parametrize(
    "bad",
    [
        "^a$|b|^c$",  # an unanchored top-level alternative
        "^a$|^b",  # a missing end anchor
        "^a++$",  # possessive: Python 3.11 accepts, RE2 rejects
        "^(?=a)b$",  # lookaround
        "^(a)\\1$",  # backreference
        "^\\Aa\\Z$",  # Python-only anchors
        "^/x/.*$",  # every path
        "^a.b$",  # a bare dot that is not the .+ wildcard
        "^a\\-b$",  # an escape the generator never writes
        "^[a-z]+$",  # a class other than [^/]
        "^a{2}$",  # counted repetition
        "^a|b$",  # anchors at both ends of the whole, neither alternative carrying both
    ],
)
def test_re2_assertion_rejects_what_the_generator_must_not_emit(bad):
    """The per-entry check of the role bodies is not vacuous."""
    with pytest.raises(AssertionError):
        assert_re2_compatible_and_anchored(bad, "self-test")
    assert top_level_alternatives("^a/(b|c)$|^d\\|e$|^f$") == ["^a/(b|c)$", "^d\\|e$", "^f$"]


def test_render_doc_stops_when_a_refused_example_is_no_longer_write_only(rbac, monkeypatch):
    """The refused-path examples the guide names are re-checked at render time against
    what only the write tools send."""
    bodies = {kind: {f"cnc-mcp-{kind}": role(kind)} for kind in ROLE_FILES}
    monkeypatch.setattr(
        rbac_map, "REFUSED_EXAMPLES", (("POST", "/crosswork/inventory/v1/nodes/query"),)
    )
    with pytest.raises(SystemExit, match="nodes/query is no longer a write-only path"):
        rbac_map.render_doc(rbac, rbac["apis"], bodies["readonly"], bodies["operator"])


def test_allowed_urls_merge_methods_that_send_the_same_paths():
    entries = rbac_map.allowed_urls_for(
        "/crosswork/inventory/",
        {
            "DELETE": {"/crosswork/inventory/v1/nodes"},
            "POST": {"/crosswork/inventory/v1/nodes", "/crosswork/inventory/v1/nodes/query"},
            "GET": {"/crosswork/inventory/v1/nodes/count"},
            "PATCH": {"/crosswork/inventory/v1/nodes"},
        },
    )
    assert entries == [
        {"url": "^/crosswork/inventory/v1/nodes/count$", "methods": ["GET"]},
        {"url": "^/crosswork/inventory/(v1/nodes|v1/nodes/query)$", "methods": ["POST"]},
        {"url": "^/crosswork/inventory/v1/nodes$", "methods": ["PATCH", "DELETE"]},
    ]


def test_readonly_exceptions_stop_on_a_mutating_leak():
    """A read tool whose runtime-valued template covers a write path a write tool sends
    would make the read-only body permit that write: the generator refuses."""
    tools = {
        "cnc_get_x": {
            "read_only": True,
            "requirements": [{"method": "POST", "path": "/crosswork/x/v1/{}", "api_id": "x"}],
        },
        "cnc_create_x": {
            "read_only": False,
            "requirements": [{"method": "POST", "path": "/crosswork/x/v1/create", "api_id": "x"}],
        },
    }
    catalogue = {"x": {"name": "X", "feature": "X", "listen_path": "/crosswork/x/"}}
    read_only = rbac_map.role_body("ro", rbac_map.paths_for([tools["cnc_get_x"]]), catalogue)
    with pytest.raises(SystemExit, match="POST /crosswork/x/v1/create"):
        rbac_map.readonly_exceptions(read_only, tools)
    tools["cnc_create_x"]["requirements"][0]["method"] = "GET"
    tools["cnc_get_x"]["requirements"][0]["method"] = "GET"
    read_only = rbac_map.role_body("ro", rbac_map.paths_for([tools["cnc_get_x"]]), catalogue)
    assert rbac_map.readonly_exceptions(read_only, tools) == [("GET", "/crosswork/x/v1/create")]


def test_check_permissions_alternatives_are_an_any_of_group(rbac):
    """cnc_check_permissions reads the role through the mirror, then aaa/v1: the map records
    both as alternatives (one group suffices) and only the two objects it reads."""
    spec = rbac["tools"]["cnc_check_permissions"]
    assert spec["any_of"] == [["aaa_cw_role_read"], ["aaa_cwaaa"]]
    assert {(r["method"], r["path"]) for r in spec["requirements"]} == {
        ("GET", "/crosswork/aaaread/v1/role/{}"),
        ("GET", "/crosswork/aaaread/v1/roleAccess/{}"),
        ("GET", "/crosswork/aaa/v1/role/{}"),
        ("GET", "/crosswork/aaa/v1/roleAccess/{}"),
    }
    for name, spec in rbac["tools"].items():
        for group in spec.get("any_of", []):
            required = {r["api_id"] for r in spec["requirements"]}
            assert group and set(group) <= required, (name, group)
    assert {name for name, spec in rbac["tools"].items() if "any_of" in spec} == set(
        rbac_map.ANY_OF
    )


def test_provision_service_records_put_and_patch_only(rbac):
    """The tool validates method against ('put', 'patch'); the analyser reads a passed-
    through method as '*', so METHOD_CHOICES narrows it — no POST/DELETE on the proxy."""
    spec = rbac["tools"]["cnc_provision_service"]
    by_path = {}
    for r in spec["requirements"]:
        by_path.setdefault(r["path"], set()).add(r["method"])
    assert by_path["/crosswork/proxy/nso/restconf/data/{}"] == {"GET", "PUT", "PATCH"}
    assert not any(r["method"] == "*" for r in spec["requirements"])
    proxy = grants(rbac, read_only=None)["proxy_cw-proxy"]
    assert "POST" not in proxy


def test_generated_files_carry_no_gateway_material_or_lab_identifiers():
    """The catalogue is sanitised to api_id/name/listen_path; none of a Tyk API
    definition's other fields (its auth configuration, ``proxy.target_url``, ...) and
    no lab address may reach the repository. (``secret`` alone is not a marker — the
    catalogue carries a real api_id ``cwm_secret`` — and ``hmac_enabled: false`` is a
    policy field the role skeleton copies from admin.)"""
    for path in (MAP_PATH, DOC_PATH, *ROLE_FILES.values()):
        text = path.read_text(encoding="utf-8").lower()
        for marker in (
            "jwt_source",
            "signing",
            "hmac_allowed",
            "hmac-sha",
            "target_url",
            "198.18.",
        ):
            assert marker not in text, (path.name, marker)


def test_readonly_role_is_a_subset_of_the_operator_role(rbac):
    ro, op = role("readonly"), role("operator")
    assert set(ro["access_rights"]) <= set(op["access_rights"])
    # everything the read-only body permits, the operator body permits too
    for method, path, api_id in requirements(rbac, read_only=True):
        assert tyk_permits(op, api_id, method, concrete(path)), (method, path)
    # a read-only role never carries a destructive method anywhere
    for grant in ro["access_rights"].values():
        for entry in grant["allowed_urls"]:
            assert "DELETE" not in entry["methods"], grant["api_id"]


def test_runtime_check_agrees_with_the_bodies(rbac):
    """cnc_check_permissions' evaluator (the runtime reading of the same Tyk rule, with
    ``{}`` as one literal segment) permits every read tool and refuses every write tool
    under the read-only body, and permits every tool under the operator body."""
    names = sorted(rbac["tools"])
    reads = {n for n in names if rbac["tools"][n]["read_only"]}
    verdict = evaluate_rbac_map(names, rbac, role("readonly")["access_rights"])
    assert set(verdict["permitted"]) == reads
    assert {r["tool"] for r in verdict["refused"]} == set(names) - reads
    assert verdict["not_in_map"] == []
    verdict = evaluate_rbac_map(names, rbac, role("operator")["access_rights"])
    assert set(verdict["permitted"]) == set(names) and verdict["refused"] == []


# --- the generator ---------------------------------------------------------------------


def test_check_passes_offline():
    """Regenerating from the embedded catalogue reproduces every committed file (the CI
    guard: a tool edit without `make rbac` fails here)."""
    assert rbac_map.main(["--check", "--quiet"]) == 0


def test_check_names_a_stale_file():
    """--check exits 1 naming the file that differs (main() prints stale_files())."""
    on_disk = MAP_PATH.read_text(encoding="utf-8")
    assert rbac_map.stale_files({str(rbac_map.MAP_RELATIVE): on_disk}, REPO) == []
    assert rbac_map.stale_files({str(rbac_map.MAP_RELATIVE): on_disk + "x"}, REPO) == [
        str(rbac_map.MAP_RELATIVE)
    ]
    assert rbac_map.stale_files({"docs/rbac/missing.role.json": "{}"}, REPO) == [
        "docs/rbac/missing.role.json"
    ]


def test_sanitise_catalogue_copies_only_three_fields():
    """api_id, name and proxy.listen_path — never a Tyk API definition's other fields
    (its auth configuration, the target URL, ...)."""
    v1 = [
        {
            "api_id": "inventory_cwinventory",
            "name": "Inventory APIs",
            "proxy": {"listen_path": "/crosswork/inventory/", "target_url": "http://x"},
            "jwt_source": "c2VjcmV0",
            "hmac_allowed_algorithms": ["hmac-sha512"],
        },
        {"api_id": "orphan", "name": "Orphan", "proxy": {"listen_path": "/crosswork/orphan/"}},
    ]
    v2 = {"Inventory": [{"api_id": "inventory_cwinventory", "name": "Inventory APIs"}]}
    catalogue = rbac_map.sanitise_catalogue(v1, v2)
    assert catalogue == {
        "inventory_cwinventory": {
            "name": "Inventory APIs",
            "feature": "Inventory",
            "listen_path": "/crosswork/inventory/",
        },
        "orphan": {
            "name": "Orphan",
            "feature": rbac_map.UNCATEGORISED,
            "listen_path": "/crosswork/orphan/",
        },
    }
    assert "c2VjcmV0" not in json.dumps(catalogue)


CATALOGUE = {
    "inventory_cwinventory": {
        "name": "Inventory APIs",
        "feature": "Inventory",
        "listen_path": "/crosswork/inventory/",
    },
    "ems-inventory": {
        "name": "Device Inventory",
        "feature": "Device Monitoring",
        "listen_path": "/crosswork/inventory/v1/networkelement",
    },
    "aaa_cwaaa": {"name": "Users and Roles", "feature": "AAA", "listen_path": "/crosswork/aaa/"},
    "aaa_cw_role_read": {
        "name": "Know my role",
        "feature": "AAA",
        "listen_path": "/crosswork/aaaread/",
    },
    "performance-rest-apis": {
        "name": "PM Dashboards",
        "feature": "Device Monitoring",
        "listen_path": "/crosswork/performance/v{.}/dashboards/",
    },
    "platform_cwplatform": {
        "name": "Platform APIs",
        "feature": "Platform",
        "listen_path": "/crosswork/platform",
    },
    "cw-fault-get-alarms": {
        "name": "Platform alarms",
        "feature": "Alarms",
        "listen_path": "/crosswork/platform/alarms/v1/alarms",
    },
}


@pytest.mark.parametrize(
    ("template", "expected"),
    [
        ("/crosswork/inventory/v1/nodes/query", "inventory_cwinventory"),
        # the longest listen path wins
        ("/crosswork/inventory/v1/networkelement/collectionstatussummary/query", "ems-inventory"),
        # segment boundary: /crosswork/aaa/ must not claim /crosswork/aaaread/...
        ("/crosswork/aaaread/v1/role/{}", "aaa_cw_role_read"),
        ("/crosswork/aaa/v1/role/{}", "aaa_cwaaa"),
        # {...} in a listen path matches one segment
        ("/crosswork/performance/v1/dashboards/summary", "performance-rest-apis"),
        # no trailing slash on the listen path; the longer sibling only for its own subtree
        ("/crosswork/platform/v2/cluster/version/show", "platform_cwplatform"),
        ("/crosswork/platform/alarms/v1/alarms/query", "cw-fault-get-alarms"),
        ("/crosswork/performance/v1/policies", None),
        ("/crosswork/platformx/v2", None),
    ],
)
def test_router_longest_listen_path_wins(template, expected):
    assert rbac_map.Router(CATALOGUE).route(template) == expected


def test_router_reports_listen_paths_a_runtime_value_could_extend_into():
    router = rbac_map.Router(CATALOGUE)
    # /crosswork/inventory/v1/{} could expand to .../v1/networkelement/...: both are recorded
    assert router.ambiguous("/crosswork/inventory/v1/{}", "inventory_cwinventory") == [
        "ems-inventory"
    ]
    assert router.ambiguous("/crosswork/inventory/v1/nodes/{}", "inventory_cwinventory") == []
    assert router.ambiguous("/crosswork/inventory/v1/nodes/query", "inventory_cwinventory") == []
