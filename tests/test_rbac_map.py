"""The packaged RBAC map (src/cnc_mcp/data/rbac_map.json) and its generator
(scripts/rbac_map.py): the map names every registered tool, every requirement
points at a catalogued API, the playbooks are composed from the right siblings,
the platform block carries the read templates and baseline rows, the generated
role bodies are UI-shaped and — evaluated as the AAA service stores them —
permit exactly what docs/RBAC.md says, the generator's model of how the
service stores a role reproduces the live read-backs in tests/fixtures/rbac/,
and regenerating offline changes nothing (the --check CI guard).

No network: the generator's --check mode reads the catalogue and the platform
block embedded in the committed map; the read-backs are committed fixtures.
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

# The read tools a Read-only role cannot call (verified 2026-09-14 against the read
# templates the platform stores): each reads through a POST outside its API's template.
READ_TOOLS_REFUSED_BY_READ = {
    "cnc_check_nso_device_sync",
    "cnc_explain_sr_policy",
    "cnc_get_config_backup_job",
    "cnc_get_lcm_recommendation_preview",
    "cnc_get_oam_settings",
    "cnc_get_oam_trace_route",
    "cnc_get_sr_policy_metrics",
    "cnc_get_sr_policy_path_notification_state",
    "cnc_investigate_device",
    "cnc_list_config_backup_jobs",
    "cnc_list_oam_trace_routes",
    "cnc_list_sensor_templates",
    "cnc_wait_for_config_backup_job",
    "cnc_wait_for_oam_trace_route",
}
# The one write tool the Read tick permits: cw-probe-mgr's read template names
# reactivateProbe.
WRITE_TOOLS_PERMITTED_BY_READ = {"cnc_reactivate_probe"}
READ_TOOL_COUNT = 182
TOOL_COUNT = 245


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
    assert rbac["generated_from"]["tool_count"] == len(rbac["tools"]) == TOOL_COUNT
    assert sum(spec["read_only"] for spec in rbac["tools"].values()) == READ_TOOL_COUNT


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


def test_platform_block_carries_only_url_and_methods(rbac):
    """The captured read templates and baseline rows: every api_id catalogued, every
    entry exactly {url, methods} with a regex that compiles and known methods in order,
    the two baseline APIs kept apart from the templates, a capture date."""
    platform = rbac["platform"]
    assert set(platform) == {"version", "captured", "read_templates", "baseline_rows"}
    assert platform["version"] == "7.2.0"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", platform["captured"])
    assert set(platform["baseline_rows"]) == set(rbac_map.BASELINE_APIS)
    assert not set(platform["read_templates"]) & set(rbac_map.BASELINE_APIS)
    assert len(platform["read_templates"]) == 17
    for block in ("read_templates", "baseline_rows"):
        assert list(platform[block]) == sorted(platform[block])
        for api_id, entries in platform[block].items():
            assert api_id in rbac["apis"], api_id
            assert entries, api_id
            assert entries == sorted(entries, key=lambda e: (e["url"], e["methods"]))
            for entry in entries:
                assert set(entry) == {"url", "methods"}, (api_id, entry)
                re.compile(entry["url"])
                assert entry["methods"] == [m for m in RBAC_ALL_METHODS if m in entry["methods"]]
                assert entry["methods"], (api_id, entry)
    # every read template is a POST entry (what the Read tick adds beyond GET)
    for api_id, entries in platform["read_templates"].items():
        assert all(entry["methods"] == ["POST"] for entry in entries), api_id
    assert platform["read_templates"]["inventory_cwinventory"] == [
        {"url": "/.+/query$", "methods": ["POST"]}
    ]
    assert platform["baseline_rows"]["aaa_selected_pref"] == [
        {"url": "/.*", "methods": ["GET", "PUT"]}
    ]


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


# --- helpers ---------------------------------------------------------------------------


def grants(rbac: dict, *, read_only: bool | None) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for spec in rbac["tools"].values():
        if read_only is not None and spec["read_only"] is not read_only:
            continue
        for req in spec["requirements"]:
            methods = set(RBAC_ALL_METHODS) if req["method"] == "*" else {req["method"]}
            out.setdefault(req["api_id"], set()).update(methods)
    return out


def body(kind: str) -> dict:
    data = json.loads(ROLE_FILES[kind].read_text(encoding="utf-8"))
    assert list(data) == [f"cnc-mcp-{kind}"]
    return data


def role(kind: str) -> dict:
    return body(kind)[f"cnc-mcp-{kind}"]


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
    """A plausible request for a template: ``abc`` for a runtime value, except a RESTCONF
    key with a ``/`` (``a/b=c``) in the last segment of a ``/restconf/`` template."""
    return rbac_map.concrete_path(template)


def tyk_permits(access_rights: dict, api_id: str, method: str, path: str) -> bool:
    """Tyk v5.1.1 granular access: the API is granted and some allowed_urls entry lists
    the method and matches the FULL path as an unanchored regexp search."""
    grant = access_rights.get(api_id)
    if grant is None:
        return False
    return any(
        method in entry["methods"] and re.compile(entry["url"]).search(path)
        for entry in grant["allowed_urls"]
    )


def stored(rbac: dict, kind: str) -> dict:
    """The access_rights the AAA service stores for a generated body: the body's rows
    plus the read templates (on rows with a GET entry and no POST entry) and the
    baseline rows."""
    return rbac_map.stored_access_rights(body(kind), rbac["platform"], rbac["apis"])


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
    """An anchored AAA URL pattern reads the same under Go RE2 (Tyk) and Python's
    ``re``, and every top-level alternative is anchored at both ends: only the
    characters the generator can emit, escapes shared by both engines (``\\.`` ``\\+``
    ``\\(``...), no lookaround ``(?``, no possessive ``++``/``*+``/``?+`` (accepted by
    Python 3.11, rejected by RE2), no backreference, no ``\\A``/``\\Z``, no ``/.*``;
    the only wildcards are ``.+`` and ``[^/]+`` (a bare ``.`` or another class is a
    bug)."""
    assert re.fullmatch(r"[A-Za-z0-9/:=_\-^$()|.+\[\]\\]+", url), context
    assert not re.search(r"\\[^.^$*+?()\[\]{}|\\]", url), context
    assert not re.search(r"[*+?]\+|\(\?", url), context
    assert not re.search(r"(?<!\\)\.(?!\+)", url), context
    assert set(re.findall(r"(?<!\\)\[[^\]]*\]", url)) <= {"[^/]"}, context
    assert "/.*" not in url, context
    re.compile(url)
    for alternative in top_level_alternatives(url):
        assert alternative.startswith("^") and alternative.endswith("$"), (context, alternative)


# --- the generated role bodies ---------------------------------------------------------


@pytest.mark.parametrize("kind", ["readonly", "operator"])
def test_role_bodies_are_ui_shaped_one_entry_per_tick(rbac, kind):
    """Every row carries the entries the UI's ticks are stored as — ``/.*`` with
    ``[GET]`` (R), ``[POST, PUT, PATCH]`` (W), ``[DELETE]`` (D), in that order, never
    a custom POST entry — except that the R entry of the two AAA rows is the anchored
    GET regex. The read-only body is R on every row it carries; the operator body
    carries exactly the ticks the classification says every tool needs."""
    role_obj = role(kind)
    assert role_obj["name"] == f"cnc-mcp-{kind}"
    for key, value in rbac_map.ROLE_SKELETON.items():  # copied from the admin role dump
        assert role_obj[key] == value, key
    read_templates = rbac["platform"]["read_templates"]
    specs = [s for s in rbac["tools"].values() if kind == "operator" or s["read_only"]]
    needed = rbac_map.ticks_for(specs, read_templates)
    if kind == "readonly":
        expected = {api_id: {"R"} for api_id in needed}
    else:
        expected = needed
    assert rbac_map.body_ticks(body(kind)) == expected
    for api_id, grant in role_obj["access_rights"].items():
        assert grant["api_id"] == api_id
        assert grant["api_name"] == rbac["apis"][api_id]["name"]
        assert grant["versions"] == ["Default"] and grant["allowance_scope"] == ""
        entries = grant["allowed_urls"]
        assert entries, api_id
        ticks = [
            tick
            for tick in rbac_map.TICKS
            if any(list(rbac_map.TICK_METHODS[tick]) == e["methods"] for e in entries)
        ]
        assert [e["methods"] for e in entries] == [list(rbac_map.TICK_METHODS[t]) for t in ticks]
        for entry in entries:
            if api_id in rbac_map.AAA_APIS and entry["methods"] == ["GET"]:
                assert_re2_compatible_and_anchored(entry["url"], (kind, api_id))
            else:
                assert entry["url"] == "/.*", (kind, api_id, entry)
    assert len(role_obj["access_rights"]) == (43 if kind == "readonly" else 47)


def test_readonly_body_is_read_only_and_a_subset_of_the_operator_body(rbac):
    ro, op = role("readonly"), role("operator")
    assert set(ro["access_rights"]) <= set(op["access_rights"])
    ro_ticks, op_ticks = (
        rbac_map.body_ticks(body("readonly")),
        rbac_map.body_ticks(body("operator")),
    )
    for api_id, ticks in ro_ticks.items():
        assert ticks == {"R"} and ticks <= op_ticks[api_id], api_id
    for grant in ro["access_rights"].values():
        for entry in grant["allowed_urls"]:
            assert entry["methods"] == ["GET"], grant["api_id"]
    # the operator body: Write on 13 rows, Delete on 5, Write without Read on 4
    assert sum("W" in t for t in op_ticks.values()) == 13
    assert sum("D" in t for t in op_ticks.values()) == 5
    assert sorted(a for a, t in op_ticks.items() if "R" not in t) == [
        "cw-fault-ack-api",
        "cw-fault-clear-api",
        "cw-fault-notes-api",
        "nso-connector",
    ]


def test_stored_readonly_role_permits_168_reads_and_refuses_the_pinned_14(rbac):
    """The body as the AAA service stores it (R rows + the read templates + the baseline
    rows), evaluated by cnc_check_permissions' evaluator under Tyk's rule: exactly the
    pinned 14 read tools are refused (each through a POST outside its API's read
    template) and cnc_reactivate_probe is the only write tool permitted."""
    access_rights = stored(rbac, "readonly")
    assert len(access_rights) == 45  # 43 rows + the two baseline rows
    assert set(access_rights) - set(role("readonly")["access_rights"]) == set(
        rbac_map.BASELINE_APIS
    )
    # the templates were added to every row (every row has a GET entry and no POST)
    for api_id, entries in rbac["platform"]["read_templates"].items():
        if api_id in access_rights and api_id not in rbac_map.BASELINE_APIS:
            assert all(entry in access_rights[api_id]["allowed_urls"] for entry in entries)
    names = sorted(rbac["tools"])
    verdict = evaluate_rbac_map(names, rbac, access_rights)
    assert verdict["not_in_map"] == []
    reads = {n for n in names if rbac["tools"][n]["read_only"]}
    permitted_reads = set(verdict["permitted"]) & reads
    refused_reads = {r["tool"] for r in verdict["refused"]} & reads
    assert refused_reads == READ_TOOLS_REFUSED_BY_READ
    assert len(permitted_reads) == 168 and len(refused_reads) == 14
    assert permitted_reads | refused_reads == reads and len(reads) == READ_TOOL_COUNT
    assert set(verdict["permitted"]) - reads == WRITE_TOOLS_PERMITTED_BY_READ
    # every refusal is a POST the Read tick does not name (never a missing row)
    for entry in verdict["refused"]:
        if entry["tool"] in reads:
            for row in entry["missing"]:
                assert row["method"] == "POST" and row["missing_methods"] == ["POST"], entry
                assert row["reason"] == "method or path not in the API's allowed_urls", entry
                assert row["api_id"] in {
                    "cwcollection",
                    "device-config",
                    "inventory_cwinventory",
                    "optima_restconf",
                }
    # the classification agrees with the Tyk evaluation
    by_classification = {
        n
        for n in reads
        if rbac_map.non_read_requirements(rbac["tools"][n], rbac["platform"]["read_templates"])
    }
    assert by_classification == READ_TOOLS_REFUSED_BY_READ
    assert rbac_map.non_read_requirements(
        rbac["tools"]["cnc_get_lcm_recommendation_preview"], rbac["platform"]["read_templates"]
    ) == [
        (
            "POST",
            "/crosswork/nbi/optimization/v3/restconf/operations/cisco-crosswork-optimization-"
            "engine-lcm-recommendation-operations:get-lcm-msl-recommendation-preview",
            "optima_restconf",
            "W",
        )
    ]
    # and the reactivate-probe exception is what the template says it is
    assert tyk_permits(
        access_rights, "cw-probe-mgr", "POST", "/crosswork/probemgr/v1/reactivateProbe"
    )
    assert not tyk_permits(
        access_rights, "inventory_cwinventory", "POST", "/crosswork/inventory/v1/nodes"
    )
    assert tyk_permits(
        access_rights, "inventory_cwinventory", "POST", "/crosswork/inventory/v1/nodes/query"
    )
    assert not tyk_permits(
        access_rights, "inventory_cwinventory", "DELETE", "/crosswork/inventory/v1/nodes"
    )


def test_stored_operator_role_permits_every_tool(rbac):
    access_rights = stored(rbac, "operator")
    assert len(access_rights) == 49
    names = sorted(rbac["tools"])
    verdict = evaluate_rbac_map(names, rbac, access_rights)
    assert set(verdict["permitted"]) == set(names) and len(names) == TOOL_COUNT
    assert verdict["refused"] == [] and verdict["not_in_map"] == []
    # every requirement, against a concrete request path, under Tyk's rule
    for method, path, api_id in requirements(rbac, read_only=None):
        assert tyk_permits(access_rights, api_id, method, concrete(path)), (method, path)
    for group in rbac["tools"]["cnc_check_permissions"]["any_of"]:
        assert set(group) <= set(access_rights)


@pytest.mark.parametrize("kind", ["readonly", "operator"])
@pytest.mark.parametrize("api_id", rbac_map.AAA_APIS)
def test_aaa_anchored_get_covers_every_template_and_not_the_api_listing(rbac, kind, api_id):
    """The anchored GET entry of an AAA row permits every path the tools send on the
    row (as a concrete request) and nothing else: not the gateway's full
    API-definition listing (administrative data), not a granted path under another
    prefix, and no method but GET."""
    access_rights = role(kind)["access_rights"]
    (entry,) = [e for e in access_rights[api_id]["allowed_urls"] if "GET" in e["methods"]]
    assert entry["methods"] == ["GET"]
    listen = rbac["apis"][api_id]["listen_path"]
    sent = {
        (m, p)
        for m, p, a in requirements(rbac, read_only=True if kind == "readonly" else None)
        if a == api_id
    }
    assert sent and all(m == "GET" for m, _ in sent)
    for method, path in sent:
        assert tyk_permits(access_rights, api_id, method, concrete(path)), path
        assert not tyk_permits(access_rights, api_id, method, "/crosswork/other" + concrete(path))
        if path.endswith("{}"):  # a role or user name is one segment: nothing below it
            assert not tyk_permits(access_rights, api_id, method, concrete(path) + "/x"), path
            assert "/.+" not in access_rights[api_id]["allowed_urls"][0]["url"]
    for forbidden in (
        "/crosswork/aaaread/v1/api",
        "/crosswork/aaa/v1/api",
        f"{listen}v1/api",
        f"{listen}v1/api/",
        f"{listen}v1/api/anything",
    ):
        for method in RBAC_ALL_METHODS:
            assert not tyk_permits(access_rights, api_id, method, forbidden), (forbidden, method)
    # the stored row keeps the anchored GET (the service keeps a custom GET URL verbatim)
    # and gains its template only where the platform has one
    stored_row = stored(rbac, kind)[api_id]["allowed_urls"]
    assert stored_row[0] == entry
    assert stored_row[1:] == rbac["platform"]["read_templates"].get(api_id, [])


# --- classification --------------------------------------------------------------------

READ_TEMPLATES = {
    "inventory_cwinventory": [{"url": "/.+/query$", "methods": ["POST"]}],
    "cw-probe-mgr": [{"url": "/.+/(probeStatusReport|reactivateProbe)$", "methods": ["POST"]}],
}


@pytest.mark.parametrize(
    ("method", "path", "api_id", "tick"),
    [
        ("GET", "/crosswork/inventory/v1/nodes/count", "inventory_cwinventory", "R"),
        ("GET", "/crosswork/x/v1/{}", "no-template-api", "R"),
        # a POST a read template names is Read
        ("POST", "/crosswork/inventory/v1/nodes/query", "inventory_cwinventory", "R"),
        ("POST", "/crosswork/probemgr/v1/reactivateProbe", "cw-probe-mgr", "R"),
        # a POST outside the template (or on an API without one) is Write
        ("POST", "/crosswork/inventory/v1/nodes", "inventory_cwinventory", "W"),
        ("POST", "/crosswork/inventory/v1/nso/check-sync", "inventory_cwinventory", "W"),
        ("POST", "/crosswork/inventory/v1/nodes/{}", "inventory_cwinventory", "W"),
        ("POST", "/crosswork/x/v1/query", "no-template-api", "W"),
        ("PUT", "/crosswork/inventory/v1/nodes/query", "inventory_cwinventory", "W"),
        ("PATCH", "/crosswork/inventory/v1/nodes", "inventory_cwinventory", "W"),
        ("DELETE", "/crosswork/inventory/v1/nodes/query", "inventory_cwinventory", "D"),
    ],
)
def test_classify(method, path, api_id, tick):
    assert rbac_map.classify(method, path, api_id, READ_TEMPLATES) == tick


def test_classify_rejects_a_non_method_and_expands_the_wildcard():
    with pytest.raises(ValueError):
        rbac_map.classify("*", "/crosswork/x", "x", {})
    req = {"method": "*", "path": "/crosswork/inventory/v1/nodes/query", "api_id": "x"}
    assert rbac_map.requirement_ticks(req, {}) == {"R", "W", "D"}
    req = {
        "method": "POST",
        "path": "/crosswork/inventory/v1/nodes/query",
        "api_id": "inventory_cwinventory",
    }
    assert rbac_map.requirement_ticks(req, READ_TEMPLATES) == {"R"}


def test_ticks_for_unions_per_api_and_non_read_requirements_honours_any_of():
    tools = {
        "cnc_list_x": {
            "read_only": True,
            "requirements": [
                {
                    "method": "POST",
                    "path": "/crosswork/inventory/v1/nodes/query",
                    "api_id": "inventory_cwinventory",
                },
                {
                    "method": "GET",
                    "path": "/crosswork/inventory/v1/nodes/count",
                    "api_id": "inventory_cwinventory",
                },
            ],
        },
        "cnc_delete_x": {
            "read_only": False,
            "requirements": [
                {
                    "method": "DELETE",
                    "path": "/crosswork/inventory/v1/nodes",
                    "api_id": "inventory_cwinventory",
                },
                {"method": "PUT", "path": "/crosswork/alarms/v1/ack", "api_id": "cw-fault-ack-api"},
            ],
        },
    }
    assert rbac_map.ticks_for([tools["cnc_list_x"]], READ_TEMPLATES) == {
        "inventory_cwinventory": {"R"}
    }
    assert rbac_map.ticks_for(tools.values(), READ_TEMPLATES) == {
        "inventory_cwinventory": {"R", "D"},
        "cw-fault-ack-api": {"W"},
    }
    assert rbac_map.ordered_ticks({"D", "R", "W"}) == "RWD"
    assert rbac_map.non_read_requirements(tools["cnc_list_x"], READ_TEMPLATES) == []
    assert rbac_map.non_read_requirements(tools["cnc_delete_x"], READ_TEMPLATES) == [
        ("DELETE", "/crosswork/inventory/v1/nodes", "inventory_cwinventory", "D"),
        ("PUT", "/crosswork/alarms/v1/ack", "cw-fault-ack-api", "W"),
    ]
    # any_of: one fully-Read alternative suffices; when none is, the first group's rows
    spec = {
        "read_only": True,
        "any_of": [["a"], ["b"]],
        "requirements": [
            {"method": "POST", "path": "/crosswork/a/v1/x", "api_id": "a"},
            {"method": "GET", "path": "/crosswork/b/v1/x", "api_id": "b"},
        ],
    }
    assert rbac_map.non_read_requirements(spec, {}) == []
    spec["requirements"][1]["method"] = "PUT"
    assert rbac_map.non_read_requirements(spec, {}) == [("POST", "/crosswork/a/v1/x", "a", "W")]


def test_get_templates_for_collects_get_paths_per_api():
    specs = [
        {
            "requirements": [
                {"method": "GET", "path": "/crosswork/aaa/v1/role/{}", "api_id": "aaa_cwaaa"},
                {"method": "*", "path": "/crosswork/aaa/v1/x", "api_id": "aaa_cwaaa"},
                {"method": "POST", "path": "/crosswork/aaa/v1/y", "api_id": "aaa_cwaaa"},
            ]
        }
    ]
    assert rbac_map.get_templates_for(specs) == {
        "aaa_cwaaa": {"/crosswork/aaa/v1/role/{}", "/crosswork/aaa/v1/x"}
    }


# --- bodies and the stored role --------------------------------------------------------

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
    "aaa_cwpassword": {
        "name": "Password Change",
        "feature": "AAA",
        "listen_path": "/crosswork/password/",
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

PLATFORM = {
    "version": "7.2.0",
    "captured": "2026-09-14",
    "read_templates": {"inventory_cwinventory": [{"url": "/.+/query$", "methods": ["POST"]}]},
    "baseline_rows": {"aaa_cwpassword": [{"url": "/.*", "methods": ["GET", "PUT"]}]},
}


def test_allowed_urls_for_renders_the_ui_entries_in_r_w_d_order():
    assert rbac_map.allowed_urls_for("inventory_cwinventory", {"D", "R", "W"}, {}, CATALOGUE) == [
        {"url": "/.*", "methods": ["GET"]},
        {"url": "/.*", "methods": ["POST", "PUT", "PATCH"]},
        {"url": "/.*", "methods": ["DELETE"]},
    ]
    assert rbac_map.allowed_urls_for("inventory_cwinventory", {"W"}, {}, CATALOGUE) == [
        {"url": "/.*", "methods": ["POST", "PUT", "PATCH"]}
    ]
    # an AAA row: the R entry is anchored over the GET templates, W/D stay UI-shaped
    templates = {"aaa_cwaaa": {"/crosswork/aaa/v1/role", "/crosswork/aaa/v1/user/{}"}}
    assert rbac_map.allowed_urls_for("aaa_cwaaa", {"R", "W"}, templates, CATALOGUE) == [
        {"url": "^/crosswork/aaa/(v1/role|v1/user/[^/]+)$", "methods": ["GET"]},
        {"url": "/.*", "methods": ["POST", "PUT", "PATCH"]},
    ]
    with pytest.raises(SystemExit, match="without a GET template"):
        rbac_map.allowed_urls_for("aaa_cwaaa", {"R"}, {}, CATALOGUE)


def test_role_body_skips_rows_without_ticks_and_copies_the_skeleton():
    ticks = {"inventory_cwinventory": {"R"}, "ems-inventory": set(), "aaa_cwaaa": {"R"}}
    templates = {"aaa_cwaaa": {"/crosswork/aaa/v1/role/{}"}}
    out = rbac_map.role_body("ro", ticks, templates, CATALOGUE)
    assert list(out) == ["ro"]
    assert out["ro"]["name"] == "ro"
    for key, value in rbac_map.ROLE_SKELETON.items():
        assert out["ro"][key] == value
    assert list(out["ro"]["access_rights"]) == ["aaa_cwaaa", "inventory_cwinventory"]
    row = out["ro"]["access_rights"]["inventory_cwinventory"]
    assert row == {
        "api_name": "Inventory APIs",
        "api_id": "inventory_cwinventory",
        "versions": ["Default"],
        "allowed_urls": [{"url": "/.*", "methods": ["GET"]}],
        "limit": None,
        "allowance_scope": "",
    }
    assert rbac_map.body_ticks(out) == {"aaa_cwaaa": {"R"}, "inventory_cwinventory": {"R"}}
    assert rbac_map.body_permits(out, "aaa_cwaaa", "GET", "/crosswork/aaa/v1/role/x")
    assert not rbac_map.body_permits(out, "aaa_cwaaa", "GET", "/crosswork/aaa/v1/api")
    assert not rbac_map.body_permits(out, "ems-inventory", "GET", "/crosswork/inventory/v1/x")


def test_stored_access_rights_adds_templates_under_read_only_and_the_baseline_rows():
    """Verified 2026-09-14: a row with a GET entry and no POST entry gains its API's
    read template; a row with a POST entry (Read + Write) does not; the baseline rows
    are added when absent and left alone when the body carries them."""
    templates = {"aaa_cwaaa": {"/crosswork/aaa/v1/role/{}"}}
    ro = rbac_map.role_body("ro", {"inventory_cwinventory": {"R"}}, templates, CATALOGUE)
    stored_ro = rbac_map.stored_access_rights(ro, PLATFORM, CATALOGUE)
    assert list(stored_ro) == ["inventory_cwinventory", "aaa_cwpassword"]
    assert stored_ro["inventory_cwinventory"]["allowed_urls"] == [
        {"url": "/.*", "methods": ["GET"]},
        {"url": "/.+/query$", "methods": ["POST"]},
    ]
    assert stored_ro["aaa_cwpassword"] == {
        "api_name": "Password Change",
        "api_id": "aaa_cwpassword",
        "versions": ["Default"],
        "allowed_urls": [{"url": "/.*", "methods": ["GET", "PUT"]}],
        "limit": None,
        "allowance_scope": "",
    }
    # the body is not modified
    assert ro["ro"]["access_rights"]["inventory_cwinventory"]["allowed_urls"] == [
        {"url": "/.*", "methods": ["GET"]}
    ]
    rw = rbac_map.role_body(
        "op", {"inventory_cwinventory": {"R", "W"}, "aaa_cwpassword": {"D"}}, templates, CATALOGUE
    )
    stored_rw = rbac_map.stored_access_rights(rw, PLATFORM, CATALOGUE)
    assert stored_rw["inventory_cwinventory"]["allowed_urls"] == [
        {"url": "/.*", "methods": ["GET"]},
        {"url": "/.*", "methods": ["POST", "PUT", "PATCH"]},
    ]
    assert stored_rw["aaa_cwpassword"]["allowed_urls"] == [{"url": "/.*", "methods": ["DELETE"]}]
    # an API without a template gains nothing
    ems = rbac_map.role_body("ro", {"ems-inventory": {"R"}}, {}, CATALOGUE)
    assert rbac_map.stored_access_rights(ems, PLATFORM, CATALOGUE)["ems-inventory"][
        "allowed_urls"
    ] == [{"url": "/.*", "methods": ["GET"]}]


# --- the stored-role model against the live read-backs ---------------------------------

FIXTURE_DIR = REPO / "tests" / "fixtures" / "rbac"
FIXTURES = (
    "stored_readonly_R_experiment",
    "stored_operator_WD_experiment",
    "stored_readonly_body",
)


def fixture(name: str) -> dict:
    """A sanitised read-back (``GET aaa/v1/role/<r>`` after a PUT): what was submitted
    (per-row ticks, or the committed body) and, per api_id, only the url and methods of
    every stored ``allowed_urls`` entry."""
    data = json.loads((FIXTURE_DIR / f"{name}.json").read_text(encoding="utf-8"))
    assert set(data) == {"captured", "how", "submitted", "stored"}, name
    return data


def normalised(rows: dict) -> dict[str, list[tuple[str, tuple[str, ...]]]]:
    """Per api_id the sorted (url, methods) entries: the order the service lists a row's
    entries in is not part of the model."""
    return {
        api_id: sorted((e["url"], tuple(e["methods"])) for e in entries)
        for api_id, entries in rows.items()
    }


def modelled_rows(body_obj: dict, rbac: dict) -> dict:
    stored_rows = rbac_map.stored_access_rights(body_obj, rbac["platform"], rbac["apis"])
    return normalised({api_id: grant["allowed_urls"] for api_id, grant in stored_rows.items()})


def ui_shaped_body(name: str, ticks: dict[str, str], rbac: dict) -> dict:
    """A role body in the shape the experiments submitted: per row one ``/.*`` entry per
    tick letter, the AAA rows included (no anchored pattern)."""
    access_rights = {
        api_id: {
            "api_name": rbac["apis"][api_id]["name"],
            "api_id": api_id,
            "versions": ["Default"],
            "allowed_urls": [
                {"url": "/.*", "methods": list(rbac_map.TICK_METHODS[tick])}
                for tick in rbac_map.TICKS
                if tick in letters
            ],
            "limit": None,
            "allowance_scope": "",
        }
        for api_id, letters in sorted(ticks.items())
    }
    return {name: {"name": name, **rbac_map.ROLE_SKELETON, "access_rights": access_rights}}


def fixture_access_rights(data: dict) -> dict:
    """The read-back in the shape cnc_check_permissions evaluates."""
    return {
        api_id: {"api_id": api_id, "allowed_urls": entries}
        for api_id, entries in data["stored"].items()
    }


@pytest.mark.parametrize("name", FIXTURES)
def test_fixture_is_sanitised_and_well_formed(name):
    data = fixture(name)
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", data["captured"])
    assert set(data["submitted"]) in ({"ticks"}, {"body"})
    for api_id, letters in data["submitted"].get("ticks", {}).items():
        assert letters and re.fullmatch(r"R?W?D?", letters), api_id
        assert api_id in data["stored"], api_id
    if "body" in data["submitted"]:
        assert (REPO / data["submitted"]["body"]).exists()
    assert list(data["stored"]) == sorted(data["stored"])
    for api_id, entries in data["stored"].items():
        assert entries, api_id
        for entry in entries:
            assert set(entry) == {"url", "methods"}, (api_id, entry)
            re.compile(entry["url"])
            assert entry["methods"] == [m for m in RBAC_ALL_METHODS if m in entry["methods"]]
    text = (FIXTURE_DIR / f"{name}.json").read_text(encoding="utf-8").lower()
    for marker in ("last_updated", "meta_data", '"_id"', "198.18.", "jwt", "api_name", "org_id"):
        assert marker not in text, (name, marker)


def test_stored_model_reproduces_the_all_read_experiment(rbac):
    """(a) A body whose every row is ``{url: "/.*", methods: ["GET"]}``: stored_access_rights
    reproduces the read-back exactly — the read template on the 17 rows that have one, GET
    only on the other 26, the two baseline rows added although none was submitted. The
    rows are the read-only body's, which the capture was taken on: when a read tool starts
    using another API, re-capture (scripts/rbac_map.py --read-templates) and refresh this
    fixture."""
    data = fixture("stored_readonly_R_experiment")
    ticks = data["submitted"]["ticks"]
    assert set(ticks.values()) == {"R"}
    assert set(ticks) == set(role("readonly")["access_rights"]), (
        "the read-only body's rows changed since the capture: re-capture and refresh the fixture"
    )
    assert modelled_rows(ui_shaped_body("x", ticks, rbac), rbac) == normalised(data["stored"])
    assert set(data["stored"]) - set(ticks) == set(rbac_map.BASELINE_APIS)
    # the platform block IS this capture: a template on exactly the rows that gained one
    templated = {
        api_id
        for api_id, entries in data["stored"].items()
        if api_id not in rbac_map.BASELINE_APIS and len(entries) > 1
    }
    assert templated == set(rbac["platform"]["read_templates"])
    assert len(templated) == 17 and len(ticks) - len(templated) == 26
    for api_id in templated:
        assert data["stored"][api_id][0] == {"url": "/.*", "methods": ["GET"]}
        assert data["stored"][api_id][1:] == sorted(
            rbac["platform"]["read_templates"][api_id], key=lambda e: e["url"]
        )
    for api_id, entries in data["stored"].items():
        if api_id in rbac_map.BASELINE_APIS:
            assert normalised({api_id: entries}) == normalised(
                {api_id: rbac["platform"]["baseline_rows"][api_id]}
            )


def test_stored_model_reproduces_the_read_write_delete_experiment(rbac):
    """(b) A body with ``/.*`` entries per tick — R on every row, W on 21, D on 5 (the
    earlier generation's operator classification, a superset of the operator body's 13 W
    rows): a row with a POST entry received no template, a GET-only row did, the baseline
    rows were added."""
    data = fixture("stored_operator_WD_experiment")
    ticks = data["submitted"]["ticks"]
    assert len(ticks) == 47 and all("R" in letters for letters in ticks.values())
    assert sum("W" in letters for letters in ticks.values()) == 21
    assert sum("D" in letters for letters in ticks.values()) == 5
    assert modelled_rows(ui_shaped_body("x", ticks, rbac), rbac) == normalised(data["stored"])
    for api_id, letters in ticks.items():
        entries = data["stored"][api_id]
        if "W" in letters:
            assert all(entry["url"] == "/.*" for entry in entries), api_id  # no template
        elif api_id in rbac["platform"]["read_templates"]:
            assert any(entry["url"] != "/.*" for entry in entries), api_id
    # the operator body's rows and ticks are within what was submitted
    op_ticks = rbac_map.body_ticks(body("operator"))
    assert set(op_ticks) == set(ticks), (
        "the operator body's rows changed since the capture: re-capture and refresh the fixture"
    )
    for api_id, tick_set in op_ticks.items():
        assert tick_set <= set(ticks[api_id]), api_id


def test_stored_model_reproduces_the_read_back_of_the_committed_read_only_body(rbac):
    """(c) The committed read-only body itself, PUT and read back: the anchored GET pattern
    of the two AAA rows kept verbatim (``[^/]+`` and all), the read templates on the rows
    that have one, the baseline rows — exactly ``stored_access_rights`` of the body. Refresh
    the fixture whenever the body changes (re-PUT, read back, sanitise)."""
    data = fixture("stored_readonly_body")
    assert data["submitted"] == {"body": "docs/rbac/cnc-mcp-readonly.role.json"}
    assert modelled_rows(body("readonly"), rbac) == normalised(data["stored"]), (
        "the read-only body changed since the capture: re-PUT it, read it back and refresh "
        "tests/fixtures/rbac/stored_readonly_body.json"
    )
    for api_id in rbac_map.AAA_APIS:
        (submitted,) = role("readonly")["access_rights"][api_id]["allowed_urls"]
        assert data["stored"][api_id][0] == submitted, api_id  # kept verbatim, listed first
    assert len(data["stored"]) == 45
    verdict = evaluate_rbac_map(sorted(rbac["tools"]), rbac, fixture_access_rights(data))
    assert {r["tool"] for r in verdict["refused"]} == READ_TOOLS_REFUSED_BY_READ | {
        name for name, spec in rbac["tools"].items() if not spec["read_only"]
    } - WRITE_TOOLS_PERMITTED_BY_READ
    assert len(verdict["permitted"]) == 168 + len(WRITE_TOOLS_PERMITTED_BY_READ)


def test_every_tool_evaluated_against_the_read_backs_gives_the_pinned_numbers(rbac):
    """The pinned verdicts hold against the rows the service actually stored, not only
    against the generator's model of them: the all-Read read-back refuses the 14 and
    permits cnc_reactivate_probe; the R/W/D read-back permits every tool."""
    names = sorted(rbac["tools"])
    reads = {name for name in names if rbac["tools"][name]["read_only"]}
    verdict = evaluate_rbac_map(
        names, rbac, fixture_access_rights(fixture("stored_readonly_R_experiment"))
    )
    assert verdict["not_in_map"] == []
    assert {r["tool"] for r in verdict["refused"]} & reads == READ_TOOLS_REFUSED_BY_READ
    assert len(set(verdict["permitted"]) & reads) == 168
    assert set(verdict["permitted"]) - reads == WRITE_TOOLS_PERMITTED_BY_READ
    verdict = evaluate_rbac_map(
        names, rbac, fixture_access_rights(fixture("stored_operator_WD_experiment"))
    )
    assert set(verdict["permitted"]) == set(names) and len(names) == TOOL_COUNT
    assert verdict["refused"] == [] and verdict["not_in_map"] == []


def test_render_doc_stops_when_the_operator_body_does_not_permit_every_tool(rbac):
    with pytest.raises(SystemExit, match="operator body does not permit every tool"):
        rbac_map.render_doc(rbac, rbac["apis"], body("readonly"), body("readonly"))


def test_refused_read_rows_stops_when_evaluation_and_classification_disagree(rbac):
    verdict = evaluate_rbac_map(sorted(rbac["tools"]), rbac, stored(rbac, "readonly"))
    rows = rbac_map.refused_read_rows(verdict, rbac["tools"], rbac["platform"])
    assert [name for name, _ in rows] == sorted(READ_TOOLS_REFUSED_BY_READ)
    assert rows[0] == (
        "cnc_check_nso_device_sync",
        [("POST", "/crosswork/inventory/v1/nso/check-sync", "inventory_cwinventory")],
    )
    verdict["refused"] = [r for r in verdict["refused"] if r["tool"] != "cnc_list_sensor_templates"]
    with pytest.raises(SystemExit, match="disagree"):
        rbac_map.refused_read_rows(verdict, rbac["tools"], rbac["platform"])


def test_doc_names_the_refused_tools_and_the_permitted_write(rbac):
    text = DOC_PATH.read_text(encoding="utf-8")
    assert "### The 14 read tools a Read-only role cannot call" in text
    assert "permits 168 of the 182 read tools" in text
    for name in READ_TOOLS_REFUSED_BY_READ:
        assert f"  - `{name}`: `POST /crosswork/" in text, name
    assert "CNC_MCP_DISABLED_TOOLS=" + ",".join(sorted(READ_TOOLS_REFUSED_BY_READ)) in text
    assert "`cnc_reactivate_probe` (`POST /crosswork/probemgr/v1/reactivateProbe`" in text
    assert "**Read permits this write**" in text
    assert "charset=UTF-8" in text
    assert "custom-URL POST entry is reinterpreted" in text
    for api_id in rbac_map.REINTERPRETED_POST_APIS:
        assert f"`{api_id}`" in text
    assert (
        "was kept verbatim (and no template added) on "
        + ", ".join(f"`{api_id}`" for api_id in rbac_map.VERBATIM_POST_BESIDE_GET_APIS)
        in text
    )
    # The refusal itself was observed 2026-09-15 with a user on the read-only role.
    assert "no user carrying one has logged in yet" not in text
    assert "Access to this API has been disallowed" in text
    assert "Access to this resource has been disallowed" in text
    assert "confirmed live 2026-09-15 by users carrying the generated roles" in text
    assert "all 432 read and write steps of the smoke answered" in text
    # the UI equivalence is an inference, said so in every place it is used
    assert "The role editor's own wire shape. No UI-built role exists on the lab" in text
    assert "is taken to produce (inferred, section 1)" in text
    assert "This is what the UI's Read tick grants" not in text
    assert "cannot be narrowed" not in text
    assert "A narrowed POST entry beside the GET entry was stored verbatim on " in text
    # the templates sentence is data-driven, the AAA template note rendered from the map
    assert "The 17 APIs with a template among the 43 rows the read tools use" in text
    assert (
        "(The `aaa_cw_role_read` row still receives its read template, POST `/.+/query$`, "
        "when stored; no read tool sends a POST there.)"
    ) in text
    # a refused read with a declared Read-permitted form says so, once, and the disable
    # list notes it
    for name, (path, how) in rbac_map.READ_FORMS.items():
        assert text.count(f"`{name}`: `POST ") == 1, name
        assert f" — its `POST {path}` ({how}) is within the template, so that form" in text
    assert (
        "(`cnc_get_lcm_recommendation_preview` is in the list although one form of the "
        "call runs under Read, above — leave it out to keep that form.)"
    ) in text
    # the old exact-path model is gone from every generated file
    for path in ROLE_FILES.values():
        role_text = path.read_text(encoding="utf-8")
        assert role_text.count('"url": "/.*"') >= 41
        assert re.findall(r'"url": "\^[^"]+"', role_text).__len__() == 2  # the two AAA rows
    assert "one entry per HTTP method" not in text


# --- the anchored AAA pattern ----------------------------------------------------------


def test_path_regex_renders_mid_path_and_tail_placeholders():
    """The regex builder: ``^<base>/(alt|alt)$``, a ``{}`` is one segment (``[^/]+``) —
    also in the last segment, where a role or user name goes — except the last segment
    of a ``/restconf/`` template, whose key may carry ``/`` (``.+``); a template equal to
    the listen path is ``^<base>$``, alternatives sorted and deduplicated, a listen-path
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
            "/crosswork/aaa/restconf/data/{}",
        ],
    )
    assert url == (
        "^/crosswork/aaa/(restconf/data/.+|v1/role|v1/role/[^/]+|v1/user/[^/]+/task"
        "|v2/[^/]+:[^/]+/vpn-service=[^/]+|v2/api)$"
    )
    pattern = re.compile(url)
    for ok in (
        "/crosswork/aaa/v1/role",
        "/crosswork/aaa/v1/role/admin",
        "/crosswork/aaa/v1/user/mcp-ro/task",
        "/crosswork/aaa/v2/api",
        "/crosswork/aaa/v2/ietf:l3vpn/vpn-service=x",
        "/crosswork/aaa/restconf/data/a/b=c",
        "/crosswork/aaa/restconf/data/tailf-ncs:devices/device=x/config",
    ):
        assert pattern.search(ok), ok
    for bad in (
        "/crosswork/aaa/v1/api",
        "/crosswork/aaa/v1/roles",
        "/crosswork/aaa/v1/role/a/b=c",  # a name is one segment: nothing below it
        "/crosswork/aaa/v1/role/admin/anything",
        "/crosswork/aaa/v1/user/a/b/task",  # mid-path value is one segment
        "/crosswork/aaa/v1/user/mcp-ro",
        "/crosswork/aaa/v2/api/x",
        "/crosswork/aaa/v2/x/vpn-service=1",
        "/crosswork/aaa/v2/ietf:l3vpn/vpn-service=x/y",
        "/crosswork/aaaread/v1/role/admin",
        "/x/crosswork/aaa/v1/role",
    ):
        assert not pattern.search(bad), bad
    # the sample request paths follow the same rule
    assert rbac_map.concrete_path("/crosswork/aaa/v1/user/{}") == "/crosswork/aaa/v1/user/abc"
    assert rbac_map.concrete_path("/crosswork/aaa/v1/user/{}/task") == (
        "/crosswork/aaa/v1/user/abc/task"
    )
    assert rbac_map.concrete_path("/crosswork/proxy/nso/restconf/data/{}") == (
        "/crosswork/proxy/nso/restconf/data/a/b=c"
    )
    assert not rbac_map.tail_may_carry_slash("/crosswork/aaa/v1/user/{}")
    assert rbac_map.tail_may_carry_slash("/crosswork/nbi/topology/v3/restconf/data/x/node={}")
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
    """The per-entry check of the AAA rows is not vacuous."""
    with pytest.raises(AssertionError):
        assert_re2_compatible_and_anchored(bad, "self-test")
    assert top_level_alternatives("^a/(b|c)$|^d\\|e$|^f$") == ["^a/(b|c)$", "^d\\|e$", "^f$"]


# --- the map's overrides -----------------------------------------------------------------


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
    """The catalogue is sanitised to api_id/name/listen_path and the platform block to
    url/methods; none of a Tyk API definition's other fields (its auth configuration,
    ``proxy.target_url``, ...), no server-assigned role field and no lab address may
    reach the repository. (``secret`` alone is not a marker — the catalogue carries a
    real api_id ``cwm_secret`` — and ``hmac_enabled: false`` is a policy field the role
    skeleton copies from admin.)"""
    for path in (MAP_PATH, DOC_PATH, *ROLE_FILES.values()):
        text = path.read_text(encoding="utf-8").lower()
        for marker in (
            "jwt_source",
            "signing",
            "hmac_allowed",
            "hmac-sha",
            "target_url",
            "last_updated",
            "meta_data",
            "198.18.",
        ):
            assert marker not in text, (path.name, marker)


# --- the generator ---------------------------------------------------------------------


def test_check_passes_offline():
    """Regenerating from the embedded catalogue and platform block reproduces every
    committed file (the CI guard: a tool edit without `make rbac` fails here)."""
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


def test_generate_is_deterministic_and_reuses_the_committed_platform_block(rbac):
    """Two offline generations are byte-identical, and the platform block loaded from the
    committed map equals what the map carries."""
    catalogue = rbac_map.load_catalogue_map(MAP_PATH)
    platform = rbac_map.load_platform_map(MAP_PATH, catalogue)
    assert platform == rbac["platform"]
    first, _, _ = rbac_map.generate(catalogue, platform, rbac_map.DEFAULT_SRC)
    second, _, _ = rbac_map.generate(catalogue, platform, rbac_map.DEFAULT_SRC)
    assert first == second
    assert set(first) == {
        "src/cnc_mcp/data/rbac_map.json",
        "docs/RBAC.md",
        "docs/rbac/cnc-mcp-readonly.role.json",
        "docs/rbac/cnc-mcp-operator.role.json",
    }
    for relative, content in first.items():
        assert (REPO / relative).read_text(encoding="utf-8") == content, relative


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


def test_sanitise_platform_keeps_url_and_methods_only_and_splits_the_baseline_rows():
    raw = {
        "inventory_cwinventory": [
            {"url": "/.+/query$", "methods": ["post"], "limit": None, "extra": "x"}
        ],
        "aaa_cwpassword": [
            {"url": "/.*", "methods": ["PUT", "GET"]},
            {"url": "/(.*passwordHistoryCheck.*)$", "methods": ["POST"]},
        ],
    }
    platform = rbac_map.sanitise_platform(raw, {}, "2026-09-14", CATALOGUE)
    assert platform == {
        "version": "7.2.0",
        "captured": "2026-09-14",
        "read_templates": {"inventory_cwinventory": [{"url": "/.+/query$", "methods": ["POST"]}]},
        "baseline_rows": {
            "aaa_cwpassword": [
                {"url": "/(.*passwordHistoryCheck.*)$", "methods": ["POST"]},
                {"url": "/.*", "methods": ["GET", "PUT"]},
            ]
        },
    }
    assert "limit" not in json.dumps(platform) and "extra" not in json.dumps(platform)
    with pytest.raises(SystemExit, match="not in the secured-API catalogue"):
        rbac_map.sanitise_platform({"nope": []}, {}, "2026-09-14", CATALOGUE)
    with pytest.raises(SystemExit, match="unknown method"):
        rbac_map.sanitise_platform(
            {"inventory_cwinventory": [{"url": "/x", "methods": ["FETCH"]}]},
            {},
            "2026-09-14",
            CATALOGUE,
        )
    with pytest.raises(SystemExit, match="not a valid regex"):
        rbac_map.sanitise_platform(
            {"inventory_cwinventory": [{"url": "/(x", "methods": ["POST"]}]},
            {},
            "2026-09-14",
            CATALOGUE,
        )
    with pytest.raises(SystemExit, match="without url/methods"):
        rbac_map.sanitise_platform(
            {"inventory_cwinventory": [{"url": "/x"}]}, {}, "2026-09-14", CATALOGUE
        )
    with pytest.raises(SystemExit, match="YYYY-MM-DD"):
        rbac_map.sanitise_platform({}, {}, "yesterday", CATALOGUE)
    with pytest.raises(SystemExit, match="must be"):
        rbac_map.sanitise_platform([], {}, "2026-09-14", CATALOGUE)


def test_load_platform_file_accepts_a_capture_or_a_bare_mapping(tmp_path):
    capture = tmp_path / "capture.json"
    capture.write_text(
        json.dumps(
            {
                "captured": "2026-09-15",
                "how": "GET role after PUT",
                "read_templates": {
                    "inventory_cwinventory": [{"url": "/.+/query$", "methods": ["POST"]}],
                    "aaa_cwpassword": [{"url": "/.*", "methods": ["GET", "PUT"]}],
                },
            }
        )
    )
    platform = rbac_map.load_platform_file(capture, CATALOGUE)
    assert platform["captured"] == "2026-09-15"
    assert list(platform["read_templates"]) == ["inventory_cwinventory"]
    assert list(platform["baseline_rows"]) == ["aaa_cwpassword"]
    bare = tmp_path / "bare.json"
    bare.write_text(
        json.dumps({"inventory_cwinventory": [{"url": "/.+/query$", "methods": ["POST"]}]})
    )
    platform = rbac_map.load_platform_file(bare, CATALOGUE)
    assert platform["captured"] == rbac_map.TEMPLATES_CAPTURED
    assert platform["baseline_rows"] == {}
    bad = tmp_path / "bad.json"
    bad.write_text("[]")
    with pytest.raises(SystemExit, match="expected a JSON object"):
        rbac_map.load_platform_file(bad, CATALOGUE)


def test_load_platform_map_requires_the_platform_block(tmp_path):
    stale = tmp_path / "rbac_map.json"
    stale.write_text(json.dumps({"apis": CATALOGUE, "tools": {}}))
    with pytest.raises(SystemExit, match="--read-templates"):
        rbac_map.load_platform_map(stale, CATALOGUE)


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
