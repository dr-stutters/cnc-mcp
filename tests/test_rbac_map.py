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

from cnc_mcp.tools.admin import RBAC_ALL_METHODS, listen_path_pattern, load_rbac_map
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


@pytest.mark.parametrize("kind", ["readonly", "operator"])
def test_role_bodies_carry_exactly_the_needed_methods(rbac, kind):
    body = json.loads(ROLE_FILES[kind].read_text(encoding="utf-8"))
    role_name = f"cnc-mcp-{kind}"
    assert list(body) == [role_name]
    role = body[role_name]
    assert role["name"] == role_name
    for key, value in rbac_map.ROLE_SKELETON.items():  # copied from the admin role dump
        assert role[key] == value, key
    expected = grants(rbac, read_only=True if kind == "readonly" else None)
    assert set(role["access_rights"]) == set(expected)
    for api_id, entry in role["access_rights"].items():
        assert entry["api_id"] == api_id
        assert entry["api_name"] == rbac["apis"][api_id]["name"]
        assert entry["versions"] == ["Default"] and entry["allowance_scope"] == ""
        assert len(entry["allowed_urls"]) == 1
        assert entry["allowed_urls"][0]["methods"] == [
            m for m in RBAC_ALL_METHODS if m in expected[api_id]
        ]
        url = entry["allowed_urls"][0]["url"]
        if api_id in rbac_map.ANCHORED_APIS:
            assert url.startswith("^") and "/.*" not in url, api_id
        else:
            assert url == "/.*", api_id


def templates(rbac: dict, api_id: str, *, read_only: bool | None) -> set[str]:
    return {
        req["path"]
        for spec in rbac["tools"].values()
        if read_only is None or spec["read_only"] is read_only
        for req in spec["requirements"]
        if req["api_id"] == api_id
    }


@pytest.mark.parametrize("kind", ["readonly", "operator"])
@pytest.mark.parametrize("api_id", rbac_map.ANCHORED_APIS)
def test_aaa_rows_are_anchored_to_exactly_the_paths_the_tools_send(rbac, kind, api_id):
    """Tyk searches allowed_urls unanchored on the full path: the AAA rows must match every
    template the tools send to that API (with a runtime value in place of ``{}``) and
    must NOT match the broader v1/api listing (administrative data)."""
    role = json.loads(ROLE_FILES[kind].read_text(encoding="utf-8"))[f"cnc-mcp-{kind}"]
    pattern = re.compile(role["access_rights"][api_id]["allowed_urls"][0]["url"])
    paths = templates(rbac, api_id, read_only=True if kind == "readonly" else None)
    assert paths
    for template in paths:
        concrete = template.replace("{}", "some-role")
        assert pattern.search(concrete), template
        # every alternative is anchored: the same path under another prefix never matches
        assert not pattern.search("/crosswork/other" + concrete), template
    listen = rbac["apis"][api_id]["listen_path"]
    for forbidden in (f"{listen}v1/api", f"{listen}v1/api/", f"{listen}v1/api/anything"):
        assert not pattern.search(forbidden), forbidden


def test_anchored_url_groups_resources_per_version():
    url = rbac_map.anchored_url(
        "/crosswork/aaa/",
        {
            "/crosswork/aaa/v1/role",
            "/crosswork/aaa/v1/role/{}",
            "/crosswork/aaa/v1/user/{}",
            "/crosswork/aaa/v1/sessionconfig",
            "/crosswork/aaa/v2/api",
            "/crosswork/aaa/v2/{}/x",
            "/crosswork/aaa/v3",
        },
    )
    assert url == (
        "^/crosswork/aaa/v1/(role|user)(/|$)|^/crosswork/aaa/v1/sessionconfig$"
        "|^/crosswork/aaa/v2/[^/]+(/|$)|^/crosswork/aaa/v2/api$|^/crosswork/aaa/v3$"
    )
    pattern = re.compile(url)
    for ok in (
        "/crosswork/aaa/v1/role",
        "/crosswork/aaa/v1/role/admin",
        "/crosswork/aaa/v1/user/mcp-ro",
        "/crosswork/aaa/v1/sessionconfig",
        "/crosswork/aaa/v2/api",
        "/crosswork/aaa/v2/anything/x",
        "/crosswork/aaa/v3",
    ):
        assert pattern.search(ok), ok
    for bad in (
        "/crosswork/aaa/v1/api",
        "/crosswork/aaa/v1/roles",
        "/crosswork/aaa/v1/sessionconfig/x",
        "/crosswork/aaa/v1/userpermission",
        "/crosswork/aaa/v3/x",
        "/crosswork/aaaread/v1/role/admin",
        "/x/crosswork/aaa/v1/role",
    ):
        assert not pattern.search(bad), bad
    with pytest.raises(SystemExit, match="not under listen path"):
        rbac_map.anchored_url("/crosswork/aaa/", {"/crosswork/aaaread/v1/role"})


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


def test_readonly_role_is_a_subset_of_the_operator_role():
    ro = json.loads(ROLE_FILES["readonly"].read_text(encoding="utf-8"))["cnc-mcp-readonly"]
    op = json.loads(ROLE_FILES["operator"].read_text(encoding="utf-8"))["cnc-mcp-operator"]
    for api_id, entry in ro["access_rights"].items():
        assert set(entry["allowed_urls"][0]["methods"]) <= set(
            op["access_rights"][api_id]["allowed_urls"][0]["methods"]
        )
    # a read-only role never carries a destructive method on the inventory API
    assert (
        "DELETE" not in ro["access_rights"]["inventory_cwinventory"]["allowed_urls"][0]["methods"]
    )


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
