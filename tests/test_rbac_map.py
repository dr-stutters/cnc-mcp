"""The packaged RBAC map (src/cnc_mcp/data/rbac_map.json) and its generator
(scripts/rbac_map.py): the map names every registered tool, every requirement
points at a catalogued API, the playbooks are composed from the right siblings,
the platform block carries the read templates and baseline rows, the generated
role bodies are what the role editor submits (verified 2026-09-15 against a
UI-built role) and — evaluated as the AAA service stores them — permit exactly
what docs/RBAC.md says, the generator's model of how the service stores a role
reproduces the live read-backs in tests/fixtures/rbac/, and regenerating
offline changes nothing (the --check CI guard).

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
READ_TOOL_COUNT = 187
TOOL_COUNT = 285
READS_PERMITTED_BY_READ = 173  # READ_TOOL_COUNT minus the 14
# The requests only WRITE tools send that the stored read-only role permits (what they
# read before they write): GETs on rows the read tools use, and the one POST a read
# template names — every one classed R (Phase D added the config-service GETs to the
# two NSO plan GETs; its PM-policy inventory GET left the list when the SRv6 locator
# statistics read tool started sending it).
READONLY_EXCEPTIONS = [
    ("GET", "/crosswork/configsvc/v1/configs/files/{}", "cw-config-service-deprecated"),
    ("GET", "/crosswork/configsvc/v1/configs/{}", "cw-config-service-deprecated"),
    ("GET", "/crosswork/proxy/nso/restconf/data/{}-plan={}", "proxy_cw-proxy"),
    ("GET", "/crosswork/proxy/nso/restconf/data/{}/{}-plan={}", "proxy_cw-proxy"),
    ("POST", "/crosswork/probemgr/v1/reactivateProbe", "cw-probe-mgr"),
]
# The operator body (Phase D): its rows, the rows carrying DELETE (all Read+Write+Delete)
# and the Write-only rows (no read tool uses the API).
OPERATOR_ROW_COUNT = 49
OPERATOR_DELETE_ROWS = [
    "cw-config-service-deprecated",
    "cw-grouping-service",
    "cw-ztp-service",
    "device-config",
    "event-processing-service-suppressionpolicy-api",
    "external-notification-subscription",
    "inventory_cwinventory",
    "nb-api-subscription-api-700",
    "performance-policies-rest-apis",
    "proxy_cw-proxy",
]
OPERATOR_WRITE_ONLY_ROWS = [
    "cw-fault-ack-api",
    "cw-fault-alarm-autoclear",
    "cw-fault-alarm-autoclear-revert",
    "cw-fault-clear-api",
    "cw-fault-notes-api",
    "nb-api-alarm-nt-3-700",
    "nso-connector",
]


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
        assert set(api) == set(rbac_map.CATALOGUE_FIELDS), api_id  # sanitised: nothing else
        assert api["listen_path"].startswith("/"), api_id
    # every api_id has its place in the aaa/v2/api response (the editor's row order)
    positions = [api["position"] for api in apis.values()]
    assert sorted(positions) == list(range(len(apis)))
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
    the three baseline APIs kept apart from the templates (only aaa_cw_role_read is
    also a template), a capture date; the split rule's data (the ten POST-delete APIs,
    sorted, and the not-delete pattern as read back)."""
    platform = rbac["platform"]
    assert set(platform) == {
        "version",
        "captured",
        "read_templates",
        "baseline_rows",
        "post_delete_apis",
        "not_delete_pattern",
    }
    assert platform["version"] == "7.2.0"
    assert platform["post_delete_apis"] == sorted(rbac_map.POST_DELETE_APIS)
    assert len(platform["post_delete_apis"]) == 10
    # every POST-delete API is either verified (a fixture) or inferred (the 2026-09-14
    # experiment), the two lists disjoint; the inferred ones are among the nine the
    # POST-only shape was tried on, and the four two-entry APIs are catalogued too
    assert set(rbac_map.POST_DELETE_VERIFIED) < set(platform["post_delete_apis"])
    assert rbac_map.POST_DELETE_VERIFIED == (
        "cwcollection",
        "optima_restconf",
        "platform_cwplatform",
    )
    assert rbac_map.POST_DELETE_INFERRED == (
        "collection_dg-manager",
        "cw-fault-alarms-api",
        "cw-fault-events-api",
        "cw-probe-mgr",
        "cw-ztp-service",
        "dg-manager-global-parameters-api",
        "optima_analytics_api",
    )
    assert set(rbac_map.POST_DELETE_APIS) == set(rbac_map.POST_DELETE_VERIFIED) | set(
        rbac_map.POST_DELETE_INFERRED
    )
    assert not set(rbac_map.POST_DELETE_VERIFIED) & set(rbac_map.POST_DELETE_INFERRED)
    assert len(rbac_map.POST_ONLY_EXPERIMENT_APIS) == 9
    assert set(rbac_map.POST_DELETE_INFERRED) < set(rbac_map.POST_ONLY_EXPERIMENT_APIS)
    assert set(rbac_map.POST_ONLY_EXPERIMENT_APIS) - set(rbac_map.POST_DELETE_INFERRED) == {
        "cwcollection",
        "optima_restconf",
    }
    assert rbac_map.POST_BESIDE_GET_EXPERIMENT_APIS == (
        "device-config",
        "inventory_cwinventory",
        "platform_cwplatform",
        "tsdn_cat-restconf-nbi",
    )
    assert not set(rbac_map.POST_ONLY_EXPERIMENT_APIS) & set(
        rbac_map.POST_BESIDE_GET_EXPERIMENT_APIS
    )
    for api_id in (*rbac_map.POST_ONLY_EXPERIMENT_APIS, *rbac_map.POST_BESIDE_GET_EXPERIMENT_APIS):
        assert api_id in rbac["apis"], api_id
    assert all(api_id in rbac["apis"] for api_id in platform["post_delete_apis"])
    assert platform["not_delete_pattern"] == rbac_map.NOT_DELETE_PATTERN
    not_delete = re.compile(platform["not_delete_pattern"])
    for path in ("/crosswork/x/v1/delete", "/crosswork/x/v1/delete/", "/a/delete"):
        assert not not_delete.search(path), path
    for path in (
        "/crosswork/x/v1/query",
        "/crosswork/x/v1/deletes",
        "/crosswork/x/v1/delet",
        "/crosswork/x/v1/Delete",
        "/crosswork/x/v1/delete/x",
        "/crosswork/nbi/optimization/v3/restconf/operations/cisco-crosswork-optimization-"
        "engine-sr-policy-operations:sr-policy-delete",
    ):
        assert not_delete.search(path), path
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", platform["captured"])
    assert set(platform["baseline_rows"]) == set(rbac_map.BASELINE_APIS)
    # aaa_cw_role_read is both: its baseline row carries the template it also receives
    # when submitted as a GET-only row (both read back, 2026-09-14 and 2026-09-15)
    assert set(platform["read_templates"]) & set(rbac_map.BASELINE_APIS) == {"aaa_cw_role_read"}
    assert len(platform["read_templates"]) == 17
    for block in ("read_templates", "baseline_rows"):
        assert list(platform[block]) == sorted(platform[block])
        for api_id, entries in platform[block].items():
            assert api_id in rbac["apis"], api_id
            assert entries, api_id
            assert entries == sorted(entries, key=rbac_map.entry_order)
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
    # a baseline row starts with its /.* entry, where the service stores it (the
    # editor reads only that first entry); the custom-url template follows
    for api_id, entries in platform["baseline_rows"].items():
        assert entries[0]["url"] == "/.*", api_id
    assert platform["baseline_rows"]["aaa_selected_pref"] == [
        {"url": "/.*", "methods": ["GET", "PUT"]}
    ]
    assert platform["baseline_rows"]["aaa_cwpassword"] == [
        {"url": "/.*", "methods": ["GET", "PUT"]},
        {"url": "/(.*passwordHistoryCheck.*)$", "methods": ["POST"]},
    ]
    assert platform["baseline_rows"]["aaa_cw_role_read"] == [
        {"url": "/.*", "methods": ["GET"]},
        {"url": "/.+/query$", "methods": ["POST"]},
    ]
    assert platform["read_templates"]["aaa_cw_role_read"] == [
        {"url": "/.+/query$", "methods": ["POST"]}
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


# --- the generated role bodies ---------------------------------------------------------


@pytest.mark.parametrize("kind", ["readonly", "operator"])
def test_role_bodies_are_what_the_editor_submits(rbac, kind):
    """Every row is exactly what the role editor sends for its ticks (verified 2026-09-15
    against a UI-built role): ONE ``/.*`` entry whose methods are the union of the ticks
    in the editor's order (GET, POST, PUT, PATCH, DELETE), ``versions []``, the editor's
    role fields, never a custom url, never a baseline row. The read-only body is R on
    every row it carries; the operator body carries exactly the ticks the classification
    says every tool needs (the baseline API the reads use, aaa_cw_role_read, left out)."""
    role_obj = role(kind)
    assert role_obj["name"] == f"cnc-mcp-{kind}"
    assert set(role_obj) == {"name", "access_rights", *rbac_map.ROLE_SKELETON}
    for key, value in rbac_map.ROLE_SKELETON.items():  # the editor's Afe defaults
        assert role_obj[key] == value, key
    assert role_obj["rate"] == 1000 and "versions" not in role_obj
    read_templates = rbac["platform"]["read_templates"]
    specs = [s for s in rbac["tools"].values() if kind == "operator" or s["read_only"]]
    needed = rbac_map.ticks_for(specs, read_templates)
    assert set(needed) & set(rbac_map.BASELINE_APIS) == {"aaa_cw_role_read"}
    expected = {
        api_id: {"R"} if kind == "readonly" else ticks
        for api_id, ticks in needed.items()
        if api_id not in rbac_map.BASELINE_APIS
    }
    assert rbac_map.body_ticks(body(kind)) == expected
    for api_id, grant in role_obj["access_rights"].items():
        assert api_id not in rbac_map.BASELINE_APIS
        assert grant["api_id"] == api_id
        assert grant["api_name"] == rbac["apis"][api_id]["name"]
        assert grant["versions"] == [] and grant["allowance_scope"] == ""
        assert grant["limit"] is None
        (entry,) = grant["allowed_urls"]
        assert entry["url"] == "/.*", (kind, api_id)
        methods = entry["methods"]
        assert methods and methods == [m for m in RBAC_ALL_METHODS if m in methods]
        # the union of whole ticks: Write is all of POST, PUT, PATCH or none of them
        assert ({"POST", "PUT", "PATCH"} <= set(methods)) or not (
            {"POST", "PUT", "PATCH"} & set(methods)
        )
    assert len(role_obj["access_rights"]) == (42 if kind == "readonly" else OPERATOR_ROW_COUNT)


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
    # the operator body: Write on 26 rows, Delete on 10 (every one of them Read+Write+
    # Delete), Write without Read on 7
    assert sum("W" in t for t in op_ticks.values()) == 26
    assert sorted(a for a, t in op_ticks.items() if "D" in t) == OPERATOR_DELETE_ROWS
    assert all(op_ticks[a] == {"R", "W", "D"} for a in OPERATOR_DELETE_ROWS)
    assert sorted(a for a, t in op_ticks.items() if "R" not in t) == OPERATOR_WRITE_ONLY_ROWS
    assert len(op_ticks) == OPERATOR_ROW_COUNT


def test_stored_readonly_role_permits_173_reads_and_refuses_the_pinned_14(rbac):
    """The body as the AAA service stores it (R rows + the read templates + the baseline
    rows), evaluated by cnc_check_permissions' evaluator under Tyk's rule: exactly the
    pinned 14 read tools are refused (each through a POST outside its API's read
    template) and cnc_reactivate_probe is the only write tool permitted."""
    access_rights = stored(rbac, "readonly")
    assert len(access_rights) == 45  # 42 rows + the three baseline rows
    assert set(access_rights) - set(role("readonly")["access_rights"]) == set(
        rbac_map.BASELINE_APIS
    )
    # the templates were added to every row (every row has a GET entry and no POST)
    for api_id, entries in rbac["platform"]["read_templates"].items():
        if api_id in access_rights:
            assert all(entry in access_rights[api_id]["allowed_urls"] for entry in entries)
    # the baseline row every role has is what lets cnc_check_permissions read the role
    assert access_rights["aaa_cw_role_read"]["allowed_urls"][0] == {
        "url": "/.*",
        "methods": ["GET"],
    }
    names = sorted(rbac["tools"])
    verdict = evaluate_rbac_map(names, rbac, access_rights)
    assert verdict["not_in_map"] == []
    reads = {n for n in names if rbac["tools"][n]["read_only"]}
    permitted_reads = set(verdict["permitted"]) & reads
    refused_reads = {r["tool"] for r in verdict["refused"]} & reads
    assert refused_reads == READ_TOOLS_REFUSED_BY_READ
    assert len(permitted_reads) == READS_PERMITTED_BY_READ and len(refused_reads) == 14
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


def test_readonly_exceptions_are_the_read_legs_of_the_write_tools(rbac):
    """The requests only write tools send that the stored read-only role permits: the
    pinned GETs (Read is GET ``/.*`` on the rows the read tools use — the NSO plan of a
    service being provisioned and the config file reads) plus the
    one POST a read template names; every one classed R, every non-GET one sent by
    exactly the write tools the role permits, and each GET's senders refused (they also
    send a write). A request only write tools send that the Read tick does not cover
    stops the generator."""
    exceptions = rbac_map.readonly_exceptions(
        body("readonly"), rbac["tools"], rbac["platform"], rbac["apis"]
    )
    assert exceptions == READONLY_EXCEPTIONS
    read_sent = requirements(rbac, read_only=True)
    access_rights = stored(rbac, "readonly")
    for method, path, api_id in exceptions:
        assert (method, path, api_id) not in read_sent
        assert (method, path, api_id) in requirements(rbac, read_only=False)
        assert tyk_permits(access_rights, api_id, method, concrete(path))
        assert rbac_map.classify(method, path, api_id, rbac["platform"]["read_templates"]) == "R"
        assert method == "GET" or api_id in rbac["platform"]["read_templates"]
    assert [e for e in exceptions if e[0] != "GET"] == [
        ("POST", "/crosswork/probemgr/v1/reactivateProbe", "cw-probe-mgr")
    ]
    verdict = evaluate_rbac_map(sorted(rbac["tools"]), rbac, access_rights)
    permitted = set(verdict["permitted"])

    def senders(method: str, path: str, api_id: str) -> set[str]:
        return {
            name
            for name, spec in rbac["tools"].items()
            if not spec["read_only"]
            and any(
                r["path"] == path and r["api_id"] == api_id and r["method"] in (method, "*")
                for r in spec["requirements"]
            )
        }

    assert senders("POST", "/crosswork/probemgr/v1/reactivateProbe", "cw-probe-mgr") == (
        WRITE_TOOLS_PERMITTED_BY_READ
    )
    get_senders = set().union(*(senders(*e) for e in exceptions if e[0] == "GET"))
    assert len(get_senders) == 14 and not get_senders & permitted
    assert "cnc_provision_service" in get_senders and "cnc_upload_ztp_config_file" not in (
        get_senders
    )
    # a Write entry in the body: the permitted POST/PUT/PATCH only write tools send
    leaky = json.loads(json.dumps(body("readonly")))
    leaky["cnc-mcp-readonly"]["access_rights"]["cw-grouping-service"]["allowed_urls"] = [
        {"url": "/.*", "methods": ["GET", "POST", "PUT", "PATCH"]}
    ]
    with pytest.raises(SystemExit, match="does not cover: POST /crosswork/grouping/"):
        rbac_map.readonly_exceptions(leaky, rbac["tools"], rbac["platform"], rbac["apis"])
    # the guide's section 2 states them
    text = DOC_PATH.read_text(encoding="utf-8")
    assert (
        "Read on these rows also permits what the write tools read before they write: 4 GET "
        "request templates no read tool sends — `GET /crosswork/configsvc/v1/configs/files/{}` "
        "and `GET /crosswork/configsvc/v1/configs/{}` on `cw-config-service-deprecated`; "
        "`GET /crosswork/proxy/nso/restconf/data/{}-plan={}` "
        "and `GET /crosswork/proxy/nso/restconf/data/{}/{}-plan={}` on `proxy_cw-proxy` — sent "
        "by 14 write tools, and the 1 POST a read template names — `POST "
        "/crosswork/probemgr/v1/reactivateProbe` on `cw-probe-mgr` (`cnc_reactivate_probe`). "
        "`cnc_reactivate_probe` is the one write tool whose every request the role permits "
        "(section 6); every other write tool also sends a request it refuses."
    ) in text


def test_stored_operator_role_permits_every_tool(rbac):
    access_rights = stored(rbac, "operator")
    assert len(access_rights) == OPERATOR_ROW_COUNT + len(rbac_map.BASELINE_APIS) == 52
    names = sorted(rbac["tools"])
    verdict = evaluate_rbac_map(names, rbac, access_rights)
    assert set(verdict["permitted"]) == set(names) and len(names) == TOOL_COUNT
    assert verdict["refused"] == [] and verdict["not_in_map"] == []
    # every requirement, against a concrete request path, under Tyk's rule
    for method, path, api_id in requirements(rbac, read_only=None):
        assert tyk_permits(access_rights, api_id, method, concrete(path)), (method, path)
    for group in rbac["tools"]["cnc_check_permissions"]["any_of"]:
        assert set(group) <= set(access_rights)


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
    "read_templates": {
        "aaa_cw_role_read": [{"url": "/.+/query$", "methods": ["POST"]}],
        "inventory_cwinventory": [{"url": "/.+/query$", "methods": ["POST"]}],
    },
    "baseline_rows": {
        "aaa_cw_role_read": [
            {"url": "/.*", "methods": ["GET"]},
            {"url": "/.+/query$", "methods": ["POST"]},
        ],
        "aaa_cwpassword": [{"url": "/.*", "methods": ["GET", "PUT"]}],
    },
    # the split rule's data, on the one POST-delete API this catalogue has
    "post_delete_apis": ["platform_cwplatform"],
    "not_delete_pattern": rbac_map.NOT_DELETE_PATTERN,
}
SPLIT_RULE = {key: PLATFORM[key] for key in rbac_map.SPLIT_RULE_KEYS}
NOT_DELETE = {"url": rbac_map.NOT_DELETE_PATTERN, "methods": ["POST"]}


def test_allowed_urls_for_renders_one_entry_with_the_union_of_the_ticks():
    """The editor's getPayload: one ``/.*`` entry per row, methods pushed as GET (Read),
    POST, PUT, PATCH (Write), DELETE (Delete) — whatever order the ticks come in."""
    assert rbac_map.allowed_urls_for({"D", "R", "W"}) == [
        {"url": "/.*", "methods": ["GET", "POST", "PUT", "PATCH", "DELETE"]}
    ]
    assert rbac_map.allowed_urls_for({"W"}) == [{"url": "/.*", "methods": ["POST", "PUT", "PATCH"]}]
    assert rbac_map.allowed_urls_for({"R"}) == [{"url": "/.*", "methods": ["GET"]}]
    assert rbac_map.allowed_urls_for({"D", "R"}) == [{"url": "/.*", "methods": ["GET", "DELETE"]}]
    assert rbac_map.allowed_urls_for(set()) == []


def test_role_body_skips_rows_without_ticks_and_baseline_rows_and_uses_the_editor_fields():
    ticks = {
        "inventory_cwinventory": {"R"},
        "ems-inventory": set(),
        "aaa_cwaaa": {"R", "W"},
        "aaa_cw_role_read": {"R"},  # a baseline row: the service adds it, never the body
        "aaa_cwpassword": {"D"},
    }
    out = rbac_map.role_body("ro", ticks, CATALOGUE)
    assert list(out) == ["ro"]
    assert out["ro"]["name"] == "ro"
    assert set(out["ro"]) == {"name", "access_rights", *rbac_map.ROLE_SKELETON}
    for key, value in rbac_map.ROLE_SKELETON.items():
        assert out["ro"][key] == value
    assert out["ro"]["rate"] == 1000 and out["ro"]["partitions"] == {
        "quota": False,
        "rate_limit": False,
        "acl": False,
    }
    assert list(out["ro"]["access_rights"]) == ["aaa_cwaaa", "inventory_cwinventory"]
    assert out["ro"]["access_rights"]["inventory_cwinventory"] == {
        "api_name": "Inventory APIs",
        "api_id": "inventory_cwinventory",
        "versions": [],
        "allowed_urls": [{"url": "/.*", "methods": ["GET"]}],
        "limit": None,
        "allowance_scope": "",
    }
    assert out["ro"]["access_rights"]["aaa_cwaaa"]["allowed_urls"] == [
        {"url": "/.*", "methods": ["GET", "POST", "PUT", "PATCH"]}
    ]
    assert rbac_map.body_ticks(out) == {"aaa_cwaaa": {"R", "W"}, "inventory_cwinventory": {"R"}}
    assert rbac_map.body_permits(out, "aaa_cwaaa", "GET", "/crosswork/aaa/v1/role/x")
    assert rbac_map.body_permits(out, "aaa_cwaaa", "PATCH", "/crosswork/aaa/v1/role/x")
    assert not rbac_map.body_permits(out, "aaa_cwaaa", "DELETE", "/crosswork/aaa/v1/role/x")
    assert not rbac_map.body_permits(out, "ems-inventory", "GET", "/crosswork/inventory/v1/x")
    assert not rbac_map.body_permits(out, "aaa_cw_role_read", "GET", "/crosswork/aaaread/v1/x")
    assert rbac_map.without_row(out, "aaa_cwaaa")["ro"]["access_rights"].keys() == {
        "inventory_cwinventory"
    }
    assert "aaa_cwaaa" in out["ro"]["access_rights"]  # not modified


def test_stored_access_rights_adds_templates_under_read_only_and_the_baseline_rows():
    """Verified 2026-09-14/15: a row with a GET entry and no POST entry gains its API's
    read template; a row with a POST entry (Read + Write) does not; the baseline rows
    are added verbatim when absent and left alone when the body carries them."""
    ro = rbac_map.role_body("ro", {"inventory_cwinventory": {"R"}}, CATALOGUE)
    stored_ro = rbac_map.stored_access_rights(ro, PLATFORM, CATALOGUE)
    assert list(stored_ro) == ["inventory_cwinventory", "aaa_cw_role_read", "aaa_cwpassword"]
    assert stored_ro["inventory_cwinventory"]["allowed_urls"] == [
        {"url": "/.*", "methods": ["GET"]},
        {"url": "/.+/query$", "methods": ["POST"]},
    ]
    assert stored_ro["aaa_cwpassword"] == {
        "api_name": "Password Change",
        "api_id": "aaa_cwpassword",
        "versions": ["Default"],  # the service's own row (the UI fixture's 'versions')
        "allowed_urls": [{"url": "/.*", "methods": ["GET", "PUT"]}],
        "limit": None,
        "allowance_scope": "",
    }
    assert stored_ro["aaa_cw_role_read"]["versions"] == rbac_map.BASELINE_VERSIONS
    assert stored_ro["aaa_cw_role_read"]["allowed_urls"] == [
        {"url": "/.*", "methods": ["GET"]},
        {"url": "/.+/query$", "methods": ["POST"]},
    ]
    # the body is not modified
    assert ro["ro"]["access_rights"]["inventory_cwinventory"]["allowed_urls"] == [
        {"url": "/.*", "methods": ["GET"]}
    ]
    rw = rbac_map.role_body("op", {"inventory_cwinventory": {"R", "W"}}, CATALOGUE)
    stored_rw = rbac_map.stored_access_rights(rw, PLATFORM, CATALOGUE)
    assert stored_rw["inventory_cwinventory"]["allowed_urls"] == [
        {"url": "/.*", "methods": ["GET", "POST", "PUT", "PATCH"]}
    ]
    # a submitted baseline row (the API-stored experiments did) is kept, plus its template
    submitted = ui_shaped_body(
        "x", {"aaa_cw_role_read": "R", "aaa_cwpassword": "D"}, {"apis": CATALOGUE}
    )
    stored_sub = rbac_map.stored_access_rights(submitted, PLATFORM, CATALOGUE)
    assert stored_sub["aaa_cw_role_read"]["allowed_urls"] == [
        {"url": "/.*", "methods": ["GET"]},
        {"url": "/.+/query$", "methods": ["POST"]},
    ]
    assert stored_sub["aaa_cwpassword"]["allowed_urls"] == [{"url": "/.*", "methods": ["DELETE"]}]
    # an API without a template gains nothing
    ems = rbac_map.role_body("ro", {"ems-inventory": {"R"}}, CATALOGUE)
    assert rbac_map.stored_access_rights(ems, PLATFORM, CATALOGUE)["ems-inventory"][
        "allowed_urls"
    ] == [{"url": "/.*", "methods": ["GET"]}]


def test_stored_access_rights_splits_write_without_delete_on_a_post_delete_api():
    """Verified 2026-09-15 (the operator body read back): on a POST-delete API a row whose
    single entry carries POST without DELETE is split — the other methods stay on the
    entry's url in ALPHABETICAL order, POST moves to the not-delete pattern; a row
    carrying DELETE, a row of two entries (Read and Write submitted separately, the
    2026-09-14 experiment) and any row on another API are stored verbatim; a Read-only
    row on a POST-delete API gets its template as usual."""

    def stored(ticks: dict[str, set[str]]) -> list[dict]:
        body_obj = rbac_map.role_body("x", ticks, CATALOGUE)
        rights = rbac_map.stored_access_rights(body_obj, PLATFORM, CATALOGUE)
        (api_id,) = ticks
        return rights[api_id]["allowed_urls"]

    assert stored({"platform_cwplatform": {"R", "W"}}) == [
        {"url": "/.*", "methods": ["GET", "PATCH", "PUT"]},
        NOT_DELETE,
    ]
    # a Write-only row on such an API: the model's extrapolation (none in the bodies)
    assert stored({"platform_cwplatform": {"W"}}) == [
        {"url": "/.*", "methods": ["PATCH", "PUT"]},
        NOT_DELETE,
    ]
    # DELETE on the entry: stored verbatim (extrapolated from the five DELETE rows read
    # back on other APIs)
    assert stored({"platform_cwplatform": {"R", "W", "D"}}) == [
        {"url": "/.*", "methods": ["GET", "POST", "PUT", "PATCH", "DELETE"]}
    ]
    assert stored({"platform_cwplatform": {"R", "D"}}) == [
        {"url": "/.*", "methods": ["GET", "DELETE"]}
    ]
    assert stored({"platform_cwplatform": {"R"}}) == [{"url": "/.*", "methods": ["GET"]}]
    # the same union entry on an API off the list: verbatim (cw-inventory-job-dashboard
    # in the operator read-back)
    assert stored({"inventory_cwinventory": {"R", "W"}}) == [
        {"url": "/.*", "methods": ["GET", "POST", "PUT", "PATCH"]}
    ]
    # Read and Write as two entries beside each other: not split (the WD experiment)
    two = ui_shaped_body("x", {"platform_cwplatform": "RW"}, {"apis": CATALOGUE})
    assert rbac_map.stored_access_rights(two, PLATFORM, CATALOGUE)["platform_cwplatform"][
        "allowed_urls"
    ] == [
        {"url": "/.*", "methods": ["GET"]},
        {"url": "/.*", "methods": ["POST", "PUT", "PATCH"]},
    ]
    # the POST-only single entry (the 2026-09-14 custom-url experiment's shape): the same
    # rule — the entry is kept with its methods stripped to [] (it permits nothing) and
    # the pattern entry appended, as that experiment read back (the maintainer's notes
    # and the guide's earlier generation: "its methods stripped to [] and a service
    # pattern ... added"); the entry is never dropped
    assert rbac_map.split_post_entry({"url": "/x", "methods": ["POST"]}, "p") == [
        {"url": "/x", "methods": []},
        {"url": "p", "methods": ["POST"]},
    ]
    assert rbac_map.split_post_entry({"url": "/.*", "methods": ["GET", "POST"]}, "p") == [
        {"url": "/.*", "methods": ["GET"]},
        {"url": "p", "methods": ["POST"]},
    ]
    custom_post_only = {
        "x": {
            "name": "x",
            **rbac_map.ROLE_SKELETON,
            "access_rights": {
                "platform_cwplatform": rbac_map.role_row(
                    "platform_cwplatform", [{"url": "/x", "methods": ["POST"]}], CATALOGUE
                )
            },
        }
    }
    assert rbac_map.stored_access_rights(custom_post_only, PLATFORM, CATALOGUE)[
        "platform_cwplatform"
    ]["allowed_urls"] == [{"url": "/x", "methods": []}, NOT_DELETE]
    union = {"url": "/.*", "methods": ["GET", "POST"]}
    assert rbac_map.is_split_row("platform_cwplatform", [union], PLATFORM)
    assert not rbac_map.is_split_row("platform_cwplatform", [], PLATFORM)
    assert not rbac_map.is_split_row("platform_cwplatform", [union, union], PLATFORM)
    assert not rbac_map.is_split_row("ems-inventory", [union], PLATFORM)
    # the body is not modified
    body_obj = rbac_map.role_body("x", {"platform_cwplatform": {"R", "W"}}, CATALOGUE)
    rbac_map.stored_access_rights(body_obj, PLATFORM, CATALOGUE)
    assert body_obj["x"]["access_rights"]["platform_cwplatform"]["allowed_urls"] == [
        {"url": "/.*", "methods": ["GET", "POST", "PUT", "PATCH"]}
    ]


def test_post_delete_requests_names_the_posts_the_not_delete_pattern_refuses(rbac):
    """No POST any tool sends on a POST-delete API ends in the segment 'delete' (the
    Optimization Engine's delete RPC ends in '...:sr-policy-delete', which the pattern
    permits); a tool that did would be named."""
    assert rbac_map.post_delete_requests(rbac["tools"], rbac["platform"]) == []
    delete_rpc = rbac["tools"]["cnc_delete_sr_policy"]["requirements"]
    assert [r["path"].rsplit("/", 1)[1] for r in delete_rpc if r["method"] == "POST"] == [
        "cisco-crosswork-optimization-engine-sr-policy-operations:sr-policy-delete"
    ]
    tools = {
        "cnc_x": {
            "read_only": False,
            "requirements": [
                {
                    "method": "POST",
                    "path": "/crosswork/platform/v2/x/delete",
                    "api_id": "platform_cwplatform",
                },
                {
                    "method": "*",
                    "path": "/crosswork/platform/v2/{}/delete",
                    "api_id": "platform_cwplatform",
                },
                {
                    "method": "POST",
                    "path": "/crosswork/platform/v2/x/query",
                    "api_id": "platform_cwplatform",
                },
                {
                    "method": "DELETE",
                    "path": "/crosswork/platform/v2/y/delete",
                    "api_id": "platform_cwplatform",
                },
                {
                    "method": "POST",
                    "path": "/crosswork/inventory/v1/delete",
                    "api_id": "inventory_cwinventory",
                },
            ],
        }
    }
    assert rbac_map.post_delete_requests(tools, PLATFORM) == [
        ("cnc_x", "/crosswork/platform/v2/x/delete", "platform_cwplatform"),
        ("cnc_x", "/crosswork/platform/v2/{}/delete", "platform_cwplatform"),
    ]


def test_display_groups_and_editor_rows():
    """A row in the editor is every api_id sharing a display name (HTML-unescaped), the
    hidden api_ids left out; editor_rows maps per-api_id ticks to those rows with the
    sibling api_ids a tick grants as well."""
    catalogue = {
        **CATALOGUE,
        "cw-fault-alarms-api": {
            "name": "Alarms &amp; Events",
            "feature": "Alarms and Events",
            "listen_path": "/crosswork/alarms/v1/query",
        },
        "cw-fault-ack-api": {
            "name": "Alarms &amp; Events",
            "feature": "Alarms and Events",
            "listen_path": "/crosswork/alarms/v1/ack",
        },
        "aaa_selected_pref": {
            "name": "User Selected Preferences",
            "feature": "AAA",
            "listen_path": "/crosswork/pref/",
        },
    }
    groups = rbac_map.display_groups(catalogue)
    assert groups["Alarms & Events"] == ["cw-fault-ack-api", "cw-fault-alarms-api"]
    assert groups["Inventory APIs"] == ["inventory_cwinventory"]
    assert not set(groups) & {"Know my role", "Password Change", "User Selected Preferences"}
    rows = rbac_map.editor_rows(
        {
            "cw-fault-alarms-api": {"R"},
            "inventory_cwinventory": {"R", "W"},
            "aaa_cw_role_read": {"R"},
        },
        catalogue,
        groups,
    )
    assert rows == [
        (
            "Alarms and Events",
            "Alarms & Events",
            ["cw-fault-alarms-api"],
            ["cw-fault-ack-api"],
            {"R"},
        ),
        ("Inventory", "Inventory APIs", ["inventory_cwinventory"], [], {"R", "W"}),
    ]
    assert rbac_map.editor_row_cells(*rows[0][:4]) == (
        "| Alarms and Events | Alarms & Events | `cw-fault-alarms-api` | `cw-fault-ack-api`"
    )


def test_first_in_editor_order_and_rows_shown_unticked():
    """The editor displays a group as its first api_id in aaa/v2/api order (the bundle's
    setAllApis / setDuplicateApi), not the alphabetical order the tables use; a role
    granting a sibling but not that api_id shows the row unticked."""
    catalogue = {
        "cw-fault-alarms-api": {
            "name": "Alarms &amp; Events",
            "feature": "Alarms and Events",
            "listen_path": "/crosswork/alarms/v1/query",
            "position": 12,
        },
        "cw-fault-ack-api": {
            "name": "Alarms &amp; Events",
            "feature": "Alarms and Events",
            "listen_path": "/crosswork/alarms/v1/ack",
            "position": 11,
        },
        "alarm-rest-service-summary-rest-api": {
            "name": "Alarms &amp; Events",
            "feature": "Alarms and Events",
            "listen_path": "/crosswork/alarms/v1/summary",
            "position": 10,
        },
        "inventory_cwinventory": {**CATALOGUE["inventory_cwinventory"], "position": 0},
        "ems-inventory": {**CATALOGUE["ems-inventory"], "position": 1},
    }
    groups = rbac_map.display_groups(catalogue)
    # alphabetically alarm-rest-service-summary-rest-api is first as well: use ack vs alarms
    assert rbac_map.first_in_editor_order(
        ["cw-fault-alarms-api", "cw-fault-ack-api"], catalogue
    ) == ("cw-fault-ack-api")
    assert rbac_map.first_in_editor_order(groups["Alarms & Events"], catalogue) == (
        "alarm-rest-service-summary-rest-api"
    )
    # a sibling granted, the displayed api_id not: shown unticked
    assert rbac_map.rows_shown_unticked({"cw-fault-alarms-api"}, catalogue, groups) == [
        ("Alarms and Events", "Alarms & Events", "alarm-rest-service-summary-rest-api")
    ]
    # the displayed api_id granted, or no member granted, or a single-api_id row: nothing
    assert (
        rbac_map.rows_shown_unticked(
            {"alarm-rest-service-summary-rest-api", "cw-fault-alarms-api"}, catalogue, groups
        )
        == []
    )
    assert rbac_map.rows_shown_unticked({"inventory_cwinventory"}, catalogue, groups) == []
    assert rbac_map.rows_shown_unticked(set(), catalogue, groups) == []
    with pytest.raises(SystemExit, match="no aaa/v2/api position"):
        rbac_map.first_in_editor_order(["inventory_cwinventory"], CATALOGUE)


def test_doc_names_the_rows_the_bodies_leave_unticked_in_the_editor(rbac):
    """The six rows of the guide are computed from the map's v2 positions and the two
    bodies: neither grants the first api_id of the group while granting a sibling."""
    groups = rbac_map.display_groups(rbac["apis"])
    granted = set(role("readonly")["access_rights"]) | set(role("operator")["access_rights"])
    rows = rbac_map.rows_shown_unticked(granted, rbac["apis"], groups)
    assert [(name, shown) for _feature, name, shown in rows] == [
        ("Users and Roles Management", "get-WebSocket-Subscription"),
        ("External Notification Subscription", "external-kafka-subscription"),
        ("RESTCONF Notification Subscription", "nb-api-alarm-nt-5"),
        ("Alarms & Events", "alarm-rest-service-summary-rest-api"),
        ("Alarms and Events RESTCONF", "nb-api-alarm-1"),
        ("Device Inventory", "cw-inventory-job-dashboard-deprecated"),
    ]
    for _feature, name, shown in rows:
        assert shown == rbac_map.first_in_editor_order(groups[name], rbac["apis"])
        assert shown not in granted and granted & set(groups[name])
        # not what the alphabetical order of the tables would suggest, on most rows
    assert sorted(groups["Users and Roles Management"])[0] == "aaa_cwaaa"
    text = DOC_PATH.read_text(encoding="utf-8")
    assert "On 6 rows neither generated body grants that first api_id" in text
    for _feature, name, shown in rows:
        assert f"*{name}* (`{shown}`)" in text


# --- the stored-role model against the live read-backs ---------------------------------

FIXTURE_DIR = REPO / "tests" / "fixtures" / "rbac"
EXPERIMENT_FIXTURES = ("stored_readonly_R_experiment", "stored_operator_WD_experiment")
UI_FIXTURE = "stored_ui_built_role"
# the generated bodies as committed, PUT through an admin API session and read back
GENERATED_FIXTURES = {
    "readonly": "stored_generated_readonly",
    "operator": "stored_generated_operator",
}
FIXTURES = (*EXPERIMENT_FIXTURES, UI_FIXTURE, *GENERATED_FIXTURES.values())
# the read-backs that keep the role's other fields (role_fields, versions, api_names)
FULL_FIXTURES = (UI_FIXTURE, *GENERATED_FIXTURES.values())


def fixture(name: str) -> dict:
    """A sanitised read-back (``GET aaa/v1/role/<r>`` after a PUT, or after saving in the
    role editor): what was submitted (per-api_id ticks for the API-stored experiments,
    per-editor-row ticks for the UI-built role, the committed body for the generated
    ones) and, per api_id, only the url and methods of every stored ``allowed_urls``
    entry in the order read back."""
    data = json.loads((FIXTURE_DIR / f"{name}.json").read_text(encoding="utf-8"))
    full = {"captured", "how", "role_fields", "stored", "api_names", "versions"}
    if name == UI_FIXTURE:
        assert set(data) == full | {"ticks"}
    elif name in FULL_FIXTURES:
        assert set(data) == full, name
    else:
        assert set(data) == {"captured", "how", "submitted", "stored"}, name
    return data


def normalised(rows: dict) -> dict[str, list[tuple[str, tuple[str, ...]]]]:
    """Per api_id the (url, methods) entries IN STORED ORDER: the service lists a row's
    ``/.*`` entry first, then what it appended (the templates, the not-delete POST
    entry), and the model reproduces that order."""
    return {
        api_id: [(e["url"], tuple(e["methods"])) for e in entries]
        for api_id, entries in rows.items()
    }


def modelled_rows(body_obj: dict, rbac: dict) -> dict:
    stored_rows = rbac_map.stored_access_rights(body_obj, rbac["platform"], rbac["apis"])
    return normalised({api_id: grant["allowed_urls"] for api_id, grant in stored_rows.items()})


def ui_shaped_body(name: str, ticks: dict[str, str], rbac: dict) -> dict:
    """A role body in the shape the API-stored experiments submitted: per row one ``/.*``
    entry per tick letter (the earlier generation's shape — the editor sends the union
    in one entry, which the service stores the same way), the AAA rows included."""
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


def test_fixture_dir_holds_exactly_the_pinned_read_backs():
    """Five real read-backs, nothing stale: the two generated bodies as committed, the
    UI-built role and the two 2026-09-14 experiments; the earlier read-back of the
    committed read-only body (custom-URL AAA rows, superseded 2026-09-15) was deleted
    with that shape."""
    assert sorted(p.stem for p in FIXTURE_DIR.glob("*.json")) == sorted(FIXTURES)
    assert len(FIXTURES) == 5
    assert {str(p) for p in rbac_map.GENERATED_FIXTURES.values()} == {
        f"tests/fixtures/rbac/{name}.json" for name in GENERATED_FIXTURES.values()
    }


@pytest.mark.parametrize("name", FIXTURES)
def test_fixture_is_sanitised_and_well_formed(name):
    data = fixture(name)
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", data["captured"])
    if name == UI_FIXTURE:
        for row, letters in data["ticks"].items():
            assert letters and re.fullmatch(r"R?W?D?", letters), row
    elif name in FULL_FIXTURES:
        assert "as committed" in data["how"] and "PUT /crosswork/aaa/v1/role/" in data["how"]
        assert set(data["versions"]) == set(data["api_names"]) == set(data["stored"])
    else:
        assert set(data["submitted"]) == {"ticks"}
        for api_id, letters in data["submitted"]["ticks"].items():
            assert letters and re.fullmatch(r"R?W?D?", letters), api_id
            assert api_id in data["stored"], api_id
    assert list(data["stored"]) == sorted(data["stored"])
    for api_id, entries in data["stored"].items():
        assert entries, api_id
        # the service stores the /.* entry first on every row: the templates it appends
        # sit at index 1 or later (which the editor never reads — the guide's warning)
        assert entries[0]["url"] == "/.*", (name, api_id)
        for entry in entries:
            assert set(entry) == {"url", "methods"}, (api_id, entry)
            re.compile(entry["url"])
            wire_order = [m for m in RBAC_ALL_METHODS if m in entry["methods"]]
            if entry["url"] == "/.*" and entries[-1]["url"] == rbac_map.NOT_DELETE_PATTERN:
                # a split row: the remaining methods come back in alphabetical order
                assert api_id in rbac_map.POST_DELETE_VERIFIED, (name, api_id)
                assert entry["methods"] == sorted(entry["methods"]) != wire_order, (name, api_id)
            else:
                assert entry["methods"] == wire_order, (name, api_id, entry)
    text = (FIXTURE_DIR / f"{name}.json").read_text(encoding="utf-8").lower()
    for marker in ("last_updated", "meta_data", '"_id"', "198.18.", "jwt", "org_id"):
        if name in FULL_FIXTURES and marker == "org_id":
            continue  # these fixtures keep the role fields that were submitted
        assert marker not in text, (name, marker)
    if name not in FULL_FIXTURES:
        assert "api_name" not in text


@pytest.mark.parametrize("kind", ["readonly", "operator"])
def test_stored_model_reproduces_the_generated_body_read_back(rbac, kind):
    """The committed body, PUT through an admin API session and read back (2026-09-15,
    the Phase D generation): ``stored_access_rights`` reproduces every stored row entry
    for entry, in stored order — the read-only body's 42 Read rows with their templates
    (45 rows with the baseline three); the operator body's 49 rows, its union entries
    verbatim except the three Write-without-Delete rows on the verified POST-delete
    APIs, which came back split (the other methods alphabetical on ``/.*``, POST under
    the not-delete pattern) — the Read+Write+Delete row on the POST-delete API
    ``cw-ztp-service`` came back verbatim, no split. The role fields are the editor's
    plus what the service adds; ``versions`` is ``[]`` on every submitted row and
    ``["Default"]`` on the baseline rows; ``api_name`` is what the body submitted (the
    v1 catalogue's HTML-escaped name)."""
    data = fixture(GENERATED_FIXTURES[kind])
    body_obj = body(kind)
    stored_rows = rbac_map.stored_access_rights(body_obj, rbac["platform"], rbac["apis"])
    assert {a: g["allowed_urls"] for a, g in stored_rows.items()} == data["stored"]
    assert modelled_rows(body_obj, rbac) == normalised(data["stored"])
    assert set(data["stored"]) - set(role(kind)["access_rights"]) == set(rbac_map.BASELINE_APIS)
    assert len(data["stored"]) == (45 if kind == "readonly" else OPERATOR_ROW_COUNT + 3)
    assert data["role_fields"] == {
        "name": f"cnc-mcp-{kind}",
        **rbac_map.ROLE_SKELETON,
        **rbac_map.STORED_ROLE_FIELDS,
    }
    for api_id, grant in stored_rows.items():
        assert data["versions"][api_id] == grant["versions"], api_id
        assert data["versions"][api_id] == (
            rbac_map.BASELINE_VERSIONS if api_id in rbac_map.BASELINE_APIS else []
        ), api_id
        assert data["api_names"][api_id] == grant["api_name"], api_id
    split_rows = sorted(
        api_id
        for api_id, grant in role(kind)["access_rights"].items()
        if rbac_map.is_split_row(api_id, grant["allowed_urls"], rbac["platform"])
    )
    if kind == "readonly":
        assert split_rows == []
        for api_id, entries in data["stored"].items():
            if api_id not in rbac_map.BASELINE_APIS:
                assert entries[0] == {"url": "/.*", "methods": ["GET"]}, api_id
                assert entries[1:] == rbac["platform"]["read_templates"].get(api_id, []), api_id
        return
    assert split_rows == sorted(rbac_map.POST_DELETE_VERIFIED)
    for api_id in split_rows:
        assert role(kind)["access_rights"][api_id]["allowed_urls"] == [
            {"url": "/.*", "methods": ["GET", "POST", "PUT", "PATCH"]}
        ]
        assert data["stored"][api_id] == [
            {"url": "/.*", "methods": ["GET", "PATCH", "PUT"]},
            {"url": rbac_map.NOT_DELETE_PATTERN, "methods": ["POST"]},
        ]
    # every other submitted row came back verbatim: the same union entry on an API off
    # the list, the rows carrying DELETE, the Write-only rows
    op_ticks = rbac_map.body_ticks(body_obj)
    verbatim = {a for a in role(kind)["access_rights"] if a not in split_rows}
    for api_id in verbatim:
        assert data["stored"][api_id][0] == role(kind)["access_rights"][api_id]["allowed_urls"][0]
    assert data["stored"]["cw-inventory-job-dashboard"] == [
        {"url": "/.*", "methods": ["GET", "POST", "PUT", "PATCH"]}
    ]
    delete_rows = sorted(a for a, t in op_ticks.items() if "D" in t)
    assert delete_rows == OPERATOR_DELETE_ROWS
    for api_id in delete_rows:
        assert data["stored"][api_id] == [
            {"url": "/.*", "methods": ["GET", "POST", "PUT", "PATCH", "DELETE"]}
        ]
    for api_id in OPERATOR_WRITE_ONLY_ROWS:
        assert data["stored"][api_id] == [{"url": "/.*", "methods": ["POST", "PUT", "PATCH"]}]
    # of the verbatim rows only cw-ztp-service is on the POST-delete list — a single
    # entry carrying DELETE, read back VERBATIM (the split is for Write without Delete);
    # no Write-only row is on the list, and no Write-without-Delete row on it escaped
    # the split
    post_delete = set(rbac["platform"]["post_delete_apis"])
    assert set(delete_rows) & post_delete == set(rbac_map.DELETE_ROW_VERBATIM_VERIFIED)
    assert rbac_map.DELETE_ROW_VERBATIM_VERIFIED == ("cw-ztp-service",)
    assert "cw-ztp-service" in rbac_map.POST_DELETE_INFERRED and "cw-ztp-service" in verbatim
    assert not rbac_map.is_split_row(
        "cw-ztp-service",
        role(kind)["access_rights"]["cw-ztp-service"]["allowed_urls"],
        rbac["platform"],
    )
    assert not {a for a, t in op_ticks.items() if "R" not in t} & post_delete
    assert {a for a, t in op_ticks.items() if t == {"R", "W"}} & post_delete == set(split_rows)


def test_stored_model_reproduces_the_ui_built_role(rbac):
    """The role built in the editor with three ticks (Read on 'Alarm Settings', Write on
    'Alarm Suppression Policies', Delete on 'Alarms and Events RESTCONF'), read back
    through the API: a body carrying, for every api_id of each ticked display-name
    group, the single entry the editor submits for the tick — and nothing else — is
    stored as ``stored_access_rights`` predicts: those entries verbatim, the three
    baseline rows added, no template anywhere (none of the seventeen templated APIs is
    in a ticked group). The role fields are the editor's defaults plus what the service
    adds; ``versions`` is ``[]`` on every submitted row."""
    data = fixture(UI_FIXTURE)
    groups = rbac_map.display_groups(rbac["apis"])
    ticks = {}
    for row, letters in data["ticks"].items():
        assert row in groups, row
        for api_id in groups[row]:
            ticks[api_id] = set(letters)
    assert len(ticks) == 7 + 1 + 6
    body_obj = rbac_map.role_body("cnc-mcp-ui-test", ticks, rbac["apis"])
    (role_obj,) = body_obj.values()
    for api_id, grant in role_obj["access_rights"].items():
        assert grant["api_name"] == data["api_names"][api_id], api_id
        assert grant["versions"] == data["versions"][api_id] == [], api_id
    assert modelled_rows(body_obj, rbac) == normalised(data["stored"])
    assert set(data["stored"]) - set(ticks) == set(rbac_map.BASELINE_APIS)
    stored_rows = rbac_map.stored_access_rights(body_obj, rbac["platform"], rbac["apis"])
    for api_id in rbac_map.BASELINE_APIS:
        # the service's own rows: versions ['Default'], which the model reproduces
        assert data["versions"][api_id] == rbac_map.BASELINE_VERSIONS == ["Default"]
        assert stored_rows[api_id]["versions"] == data["versions"][api_id]
        assert normalised({api_id: data["stored"][api_id]}) == normalised(
            {api_id: rbac["platform"]["baseline_rows"][api_id]}
        )
    # the fixture pins single-tick entries only: no union entry was read back
    for api_id, entries in data["stored"].items():
        if api_id not in rbac_map.BASELINE_APIS:
            assert entries[0]["methods"] in (["GET"], ["POST", "PUT", "PATCH"], ["DELETE"])
    # the GET-only rows outside the read-only body the guide names as template-free
    get_only = rbac_map.ui_fixture_get_only_rows()
    assert get_only == sorted(
        api_id for api_id in ticks if data["stored"][api_id] == [{"url": "/.*", "methods": ["GET"]}]
    )
    assert [a for a in get_only if a not in role("readonly")["access_rights"]] == [
        "cw-fault-alarm-autoclear",
        "cw-fault-alarm-autoclear-revert",
    ]
    # the editor's tick -> entry mapping, observed
    for row, letters in data["ticks"].items():
        expected = [
            {
                "url": "/.*",
                "methods": rbac_map.ordered(
                    m for tick in letters for m in rbac_map.TICK_METHODS[tick]
                ),
            }
        ]
        for api_id in groups[row]:
            assert data["stored"][api_id] == expected, (row, api_id)
    assert data["stored"]["event-processing-service-suppressionpolicy-api"] == [
        {"url": "/.*", "methods": ["POST", "PUT", "PATCH"]}
    ]
    # the role fields: the editor's defaults, plus what the service adds
    expected_fields = {
        "name": "cnc-mcp-ui-test",
        **rbac_map.ROLE_SKELETON,
        **rbac_map.STORED_ROLE_FIELDS,
    }
    assert data["role_fields"] == expected_fields
    assert set(rbac_map.STORED_ROLE_FIELDS) - set(rbac_map.ROLE_SKELETON) == {
        "throttle_interval",
        "throttle_retry_limit",
        "enable_http_signature_validation",
    }


def test_stored_model_reproduces_the_all_read_experiment(rbac):
    """(a) A body whose every row is ``{url: "/.*", methods: ["GET"]}`` — the 43 rows the
    read tools used at the time, the two AAA rows included: stored_access_rights
    reproduces the read-back exactly — the read template on the 17 rows that have one,
    GET only on the other 26, the two baseline rows the body lacked added. The rows are
    the read-only body's plus aaa_cw_role_read (now a baseline row the body never
    carries): when a read tool starts using another API, re-capture
    (scripts/rbac_map.py --read-templates) and refresh this fixture."""
    data = fixture("stored_readonly_R_experiment")
    ticks = data["submitted"]["ticks"]
    assert set(ticks.values()) == {"R"}
    assert set(ticks) == set(role("readonly")["access_rights"]) | {"aaa_cw_role_read"}, (
        "the read-only body's rows changed since the capture: re-capture and refresh the fixture"
    )
    assert modelled_rows(ui_shaped_body("x", ticks, rbac), rbac) == normalised(data["stored"])
    assert set(data["stored"]) - set(ticks) == set(rbac_map.BASELINE_APIS) - {"aaa_cw_role_read"}
    # the platform block's templates ARE this capture: a template on exactly the rows
    # that gained one
    templated = {
        api_id
        for api_id, entries in data["stored"].items()
        if api_id not in ("aaa_cwpassword", "aaa_selected_pref") and len(entries) > 1
    }
    assert templated == set(rbac["platform"]["read_templates"])
    assert len(templated) == 17 and len(ticks) - len(templated) == 26
    for api_id in templated:
        assert data["stored"][api_id][0] == {"url": "/.*", "methods": ["GET"]}
        assert data["stored"][api_id][1:] == sorted(
            rbac["platform"]["read_templates"][api_id], key=lambda e: e["url"]
        )
    for api_id in rbac_map.BASELINE_APIS:
        assert normalised({api_id: data["stored"][api_id]}) == normalised(
            {api_id: rbac["platform"]["baseline_rows"][api_id]}
        )


def test_stored_model_reproduces_the_read_write_delete_experiment(rbac):
    """(b) A body with ``/.*`` entries per tick — the 47 rows of the operator body of
    2026-09-14, R on every one, W on 21, D on 5 (that generation's classification,
    before the template capture): reproduced from the fixture's OWN submitted rows — a
    row with a POST entry received no template, a GET-only row did, the baseline rows
    were added. Those 47 rows are all still rows of the bodies (the operator body has
    since gained rows and ticks — Phase D — and lost the Write the template capture
    reclassified as Read; neither direction of tick inclusion holds, and neither is
    what the fixture pins)."""
    data = fixture("stored_operator_WD_experiment")
    ticks = data["submitted"]["ticks"]
    assert len(ticks) == 47 and all("R" in letters for letters in ticks.values())
    assert sum("W" in letters for letters in ticks.values()) == 21
    assert sum("D" in letters for letters in ticks.values()) == 5
    assert modelled_rows(ui_shaped_body("x", ticks, rbac), rbac) == normalised(data["stored"])
    assert set(data["stored"]) - set(ticks) == set(rbac_map.BASELINE_APIS) - {"aaa_cw_role_read"}
    for api_id, letters in ticks.items():
        entries = data["stored"][api_id]
        # the submitted per-tick entries came back first, verbatim and in tick order
        submitted = [
            {"url": "/.*", "methods": list(rbac_map.TICK_METHODS[tick])}
            for tick in rbac_map.TICKS
            if tick in letters
        ]
        assert entries[: len(submitted)] == submitted, api_id
        if "W" in letters:
            assert entries == submitted, api_id  # no template beside a POST entry
        else:  # a GET-only row: its template (aaa_cw_role_read's is its baseline one)
            assert entries[1:] == rbac["platform"]["read_templates"].get(api_id, []), api_id
    # the experiment's rows are the read-only body's, the baseline row aaa_cw_role_read
    # and the write-only rows of that day — every one still a row of a body
    op_rows = set(role("operator")["access_rights"])
    assert set(role("readonly")["access_rights"]) < set(ticks) <= op_rows | {"aaa_cw_role_read"}
    assert sorted(set(ticks) - set(role("readonly")["access_rights"])) == [
        "aaa_cw_role_read",
        "cw-fault-ack-api",
        "cw-fault-clear-api",
        "cw-fault-notes-api",
        "nso-connector",
    ]
    assert sorted(op_rows - set(ticks)) == [
        "cw-fault-alarm-autoclear",
        "cw-fault-alarm-autoclear-revert",
        "nb-api-alarm-nt-3-700",
    ]


def test_every_tool_evaluated_against_the_read_backs_gives_the_pinned_numbers(rbac):
    """The pinned verdicts hold against the rows the service actually stored, not only
    against the generator's model of them: the all-Read read-back refuses the 14 and
    permits cnc_reactivate_probe; the R/W/D read-back of 2026-09-14 permits every tool
    of that generation — 257 of the 285, the other 28 being Phase D write tools needing
    a row or tick it did not submit — exactly the model's verdict on its submitted
    rows; the UI-built role (three alarm rows) permits only the alarm-settings reads
    and the suppression-policy writes, and lets cnc_check_permissions read the role
    through the baseline mirror row it never asked for."""
    names = sorted(rbac["tools"])
    reads = {name for name in names if rbac["tools"][name]["read_only"]}
    verdict = evaluate_rbac_map(
        names, rbac, fixture_access_rights(fixture("stored_readonly_R_experiment"))
    )
    assert verdict["not_in_map"] == []
    assert {r["tool"] for r in verdict["refused"]} & reads == READ_TOOLS_REFUSED_BY_READ
    assert len(set(verdict["permitted"]) & reads) == READS_PERMITTED_BY_READ
    assert set(verdict["permitted"]) - reads == WRITE_TOOLS_PERMITTED_BY_READ
    data = fixture("stored_operator_WD_experiment")
    verdict = evaluate_rbac_map(names, rbac, fixture_access_rights(data))
    assert verdict["not_in_map"] == [] and len(names) == TOOL_COUNT
    assert len(verdict["permitted"]) == 257 and len(verdict["refused"]) == 28
    assert reads <= set(verdict["permitted"])
    experiment = data["submitted"]["ticks"]
    for entry in verdict["refused"]:
        assert not rbac["tools"][entry["tool"]]["read_only"], entry["tool"]
        for row in entry["missing"]:  # a tick, or a row, the experiment did not submit
            tick = rbac_map.classify(
                row["method"], row["path"], row["api_id"], rbac["platform"]["read_templates"]
            )
            assert tick not in experiment.get(row["api_id"], ""), (entry["tool"], row)
    model = evaluate_rbac_map(
        names,
        rbac,
        rbac_map.stored_access_rights(
            ui_shaped_body("x", experiment, rbac), rbac["platform"], rbac["apis"]
        ),
    )
    assert rbac_map.verdict_drift(model, verdict) == []
    verdict = evaluate_rbac_map(names, rbac, fixture_access_rights(fixture(UI_FIXTURE)))
    permitted = set(verdict["permitted"])
    assert "cnc_check_permissions" in permitted
    assert {"cnc_get_alarm_settings", "cnc_create_alarm_suppression_policy"} <= permitted
    assert not permitted & {"cnc_list_alarms", "cnc_list_devices", "cnc_list_roles"}
    missing = {
        r["tool"]: {(m["method"], m["missing_methods"][0]) for m in r["missing"]}
        for r in verdict["refused"]
    }
    # Write ticked on the suppression-policy row, not Read or Delete
    assert missing["cnc_list_alarm_suppression_policies"] == {("GET", "GET")}
    assert missing["cnc_delete_alarm_suppression_policy"] == {("DELETE", "DELETE")}


def test_generated_bodies_read_back_give_the_model_verdict_for_every_tool(rbac):
    """The read-backs of the committed bodies, evaluated by cnc_check_permissions'
    evaluator on the rows the service actually stored: the read-only role permits 173 of
    the 187 read tools and refuses the pinned 14 (plus cnc_reactivate_probe permitted),
    the operator role permits all 285 — the same verdict, tool for tool, as the model's
    stored form of each body (the split rows permit every request the tools send on
    the POST-delete APIs). ``read_back_verdict`` / ``verdict_drift`` are what the
    generator uses to say so in section 6."""
    names = sorted(rbac["tools"])
    reads = {name for name in names if rbac["tools"][name]["read_only"]}
    data, verdict = rbac_map.read_back_verdict(rbac_map.READONLY_ROLE, rbac)
    assert data == fixture(GENERATED_FIXTURES["readonly"])
    assert verdict["not_in_map"] == []
    assert {r["tool"] for r in verdict["refused"]} & reads == READ_TOOLS_REFUSED_BY_READ
    assert len(set(verdict["permitted"]) & reads) == READS_PERMITTED_BY_READ
    assert set(verdict["permitted"]) - reads == WRITE_TOOLS_PERMITTED_BY_READ
    model = evaluate_rbac_map(names, rbac, stored(rbac, "readonly"))
    assert rbac_map.verdict_drift(model, verdict) == []
    assert model["permitted"] == verdict["permitted"]
    assert [r["tool"] for r in model["refused"]] == [r["tool"] for r in verdict["refused"]]
    data, verdict = rbac_map.read_back_verdict(rbac_map.OPERATOR_ROLE, rbac)
    assert data == fixture(GENERATED_FIXTURES["operator"])
    assert set(verdict["permitted"]) == set(names) and len(names) == TOOL_COUNT
    assert verdict["refused"] == [] and verdict["not_in_map"] == []
    assert (
        rbac_map.verdict_drift(evaluate_rbac_map(names, rbac, stored(rbac, "operator")), verdict)
        == []
    )
    # every requirement on a split row, under Tyk's rule against the stored entries
    rows = fixture_access_rights(data)
    for method, path, api_id in requirements(rbac, read_only=None):
        if api_id in rbac_map.POST_DELETE_VERIFIED:
            assert tyk_permits(rows, api_id, method, concrete(path)), (method, path)
    assert not tyk_permits(rows, "optima_restconf", "POST", "/crosswork/nbi/optimization/v3/delete")
    assert not tyk_permits(rows, "optima_restconf", "DELETE", "/crosswork/nbi/optimization/v3/x")
    assert tyk_permits(
        rows,
        "optima_restconf",
        "POST",
        "/crosswork/nbi/optimization/v3/restconf/operations/cisco-crosswork-optimization-"
        "engine-sr-policy-operations:sr-policy-delete",
    )
    assert rbac_map.verdict_drift({"permitted": ["a", "b"]}, {"permitted": ["b", "c"]}) == [
        "a",
        "c",
    ]


def write_generated_fixtures(fixture_dir: Path, edit) -> None:
    """The two generated-body fixtures copied under ``fixture_dir`` after ``edit(name,
    data)`` has changed them — a repo the generator reads the read-backs from."""
    fixture_dir.mkdir(parents=True, exist_ok=True)
    for name in GENERATED_FIXTURES.values():
        data = fixture(name)
        edit(name, data)
        (fixture_dir / f"{name}.json").write_text(json.dumps(data), encoding="utf-8")


def test_render_doc_and_generate_report_a_read_back_of_a_previous_body(rbac, tmp_path):
    """A generated-body fixture that is not of the current body — its verdict differs
    from the model's (here: the operator read-back with a row removed, which also
    changes the verdict on one tool), or only its stored rows differ while the verdict
    is unchanged (the previous generation's situation: the same refusals from different
    entries): the guide's sections 1 and 6 say the read-backs are of a previous body and
    name the tools and rows, and generate() returns the same as a warning — never a
    silent claim that the bodies as committed were read back."""
    fixture_dir = tmp_path / "tests" / "fixtures" / "rbac"

    def drop_row(name: str, data: dict) -> None:
        if name == GENERATED_FIXTURES["operator"]:
            del data["stored"]["nso-connector"]

    write_generated_fixtures(fixture_dir, drop_row)
    text = rbac_map.render_doc(rbac, rbac["apis"], body("readonly"), body("operator"), tmp_path)
    assert "are of a PREVIOUS body" in text
    assert (
        "under `cnc-mcp-operator` its verdict differs on 1 tool(s) "
        "(`cnc_resync_service_inventory`); its stored rows differ on 1 row(s) (`nso-connector`)"
    ) in text
    assert "give the same verdict for every tool" not in text
    assert "What the fixtures pin: both bodies as committed" not in text
    assert "What the fixtures pinned for a PREVIOUS generation of the bodies" in text
    assert "re-PUT the bodies, read them back and refresh the fixtures" in text
    catalogue = rbac_map.load_catalogue_map(MAP_PATH)
    _files, _map, warnings = rbac_map.generate(
        catalogue, rbac["platform"], rbac_map.DEFAULT_SRC, tmp_path
    )
    assert warnings == [
        "tests/fixtures/rbac/stored_generated_operator.json is a read-back of a previous "
        "cnc-mcp-operator body: its verdict differs on 1 tool(s) (cnc_resync_service_inventory); "
        "its stored rows differ on 1 row(s) (nso-connector) — re-PUT the body, read it back and "
        "refresh the fixture"
    ]
    # rows that differ from the committed body's stored form WITHOUT changing the verdict
    # (a Write entry on a read-only row where no tool needs Write — a template-less one,
    # so the entry is the whole row — and on an operator row that is Write-only already):
    # the verdict comparison alone would pass this as the body as committed
    needed = rbac_map.ticks_for(rbac["tools"].values(), rbac["platform"]["read_templates"])
    template_free_read_rows = sorted(
        api_id
        for api_id, ticks in needed.items()
        if ticks == {"R"}
        and api_id in role("readonly")["access_rights"]
        and api_id not in rbac["platform"]["read_templates"]
    )
    assert "cw-grouping-service" not in template_free_read_rows  # Phase D: writes need W
    read_row = template_free_read_rows[0]
    assert read_row == "aaa_cwaaa"
    changed = {"cw-fault-ack-api": "operator", read_row: "readonly"}

    def change_rows(name: str, data: dict) -> None:
        for api_id, kind in changed.items():
            if name == GENERATED_FIXTURES[kind]:
                data["stored"][api_id][0]["methods"] = ["GET", "POST", "PUT", "PATCH"]

    write_generated_fixtures(fixture_dir, change_rows)
    for kind in ("readonly", "operator"):
        data, verdict = rbac_map.read_back_verdict(
            getattr(rbac_map, f"{kind.upper()}_ROLE"), rbac, tmp_path
        )
        model = rbac_map.evaluate_body(body(kind), rbac, rbac["apis"])
        assert rbac_map.verdict_drift(model, verdict) == []
    assert rbac_map.row_drift(body("operator"), data, rbac["platform"], rbac["apis"]) == [
        "cw-fault-ack-api"
    ]
    text = rbac_map.render_doc(rbac, rbac["apis"], body("readonly"), body("operator"), tmp_path)
    assert "are of a PREVIOUS body" in text
    assert (
        f"under `cnc-mcp-readonly` its stored rows differ on 1 row(s) (`{read_row}`); "
        "under `cnc-mcp-operator` its stored rows differ on 1 row(s) (`cw-fault-ack-api`)"
    ) in text
    assert "its verdict differs" not in text
    assert "the bodies as committed were stored through the API and read back" not in text
    _files, _map, warnings = rbac_map.generate(
        catalogue, rbac["platform"], rbac_map.DEFAULT_SRC, tmp_path
    )
    assert warnings == [
        "tests/fixtures/rbac/stored_generated_readonly.json is a read-back of a previous "
        f"cnc-mcp-readonly body: its stored rows differ on 1 row(s) ({read_row}) — "
        "re-PUT the body, read it back and refresh the fixture",
        "tests/fixtures/rbac/stored_generated_operator.json is a read-back of a previous "
        "cnc-mcp-operator body: its stored rows differ on 1 row(s) (cw-fault-ack-api) — "
        "re-PUT the body, read it back and refresh the fixture",
    ]
    # the Phase D counter-example: Write on cw-grouping-service in the read-only
    # read-back permits the two grouping writes that need RW only, so the verdict differs
    changed = {"cw-grouping-service": "readonly"}
    write_generated_fixtures(fixture_dir, change_rows)
    data, verdict = rbac_map.read_back_verdict(rbac_map.READONLY_ROLE, rbac, tmp_path)
    assert rbac_map.verdict_drift(
        rbac_map.evaluate_body(body("readonly"), rbac, rbac["apis"]), verdict
    ) == ["cnc_move_group_members", "cnc_set_device_group_members"]

    # the order of a row's entries is part of the comparison (the service's stored order)
    def swap_entries(name: str, data: dict) -> None:
        if name == GENERATED_FIXTURES["readonly"]:
            data["stored"]["inventory_cwinventory"].reverse()

    write_generated_fixtures(fixture_dir, swap_entries)
    data, _verdict = rbac_map.read_back_verdict(rbac_map.READONLY_ROLE, rbac, tmp_path)
    assert rbac_map.row_drift(body("readonly"), data, rbac["platform"], rbac["apis"]) == [
        "inventory_cwinventory"
    ]
    # a fixture that is not a read-back at all, and a missing one
    (fixture_dir / "stored_generated_readonly.json").write_text("[]", encoding="utf-8")
    with pytest.raises(SystemExit, match="expected a read-back"):
        rbac_map.render_doc(rbac, rbac["apis"], body("readonly"), body("operator"), tmp_path)
    (fixture_dir / "stored_generated_readonly.json").unlink()
    with pytest.raises(SystemExit, match="stored_generated_readonly.json is missing: PUT the"):
        rbac_map.render_doc(rbac, rbac["apis"], body("readonly"), body("operator"), tmp_path)
    with pytest.raises(SystemExit, match="is missing"):
        rbac_map.generate(catalogue, rbac["platform"], rbac_map.DEFAULT_SRC, tmp_path)
    # the committed state: no warning, the read-backs are of the bodies as committed
    _files, _map, warnings = rbac_map.generate(catalogue, rbac["platform"], rbac_map.DEFAULT_SRC)
    assert warnings == []
    for kind in ("readonly", "operator"):
        data = fixture(GENERATED_FIXTURES[kind])
        assert rbac_map.row_drift(body(kind), data, rbac["platform"], rbac["apis"]) == []


def test_render_doc_stops_when_the_operator_body_does_not_permit_every_tool(rbac):
    with pytest.raises(SystemExit, match="operator body does not permit every tool"):
        rbac_map.render_doc(rbac, rbac["apis"], body("readonly"), body("readonly"))


def test_render_doc_stops_when_a_body_carries_a_baseline_row(rbac):
    bad = json.loads(json.dumps(body("operator")))
    bad["cnc-mcp-operator"]["access_rights"]["aaa_cw_role_read"] = rbac_map.role_row(
        "aaa_cw_role_read", [{"url": "/.*", "methods": ["GET"]}], rbac["apis"]
    )
    with pytest.raises(SystemExit, match="baseline row"):
        rbac_map.render_doc(rbac, rbac["apis"], body("readonly"), bad)


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
    assert f"permits {READS_PERMITTED_BY_READ} of the {READ_TOOL_COUNT} read tools" in text
    assert "permits 173 of the 187 read tools" in text
    for name in READ_TOOLS_REFUSED_BY_READ:
        assert f"  - `{name}`: `POST /crosswork/" in text, name
    assert "CNC_MCP_DISABLED_TOOLS=" + ",".join(sorted(READ_TOOLS_REFUSED_BY_READ)) in text
    assert "`cnc_reactivate_probe` (`POST /crosswork/probemgr/v1/reactivateProbe`" in text
    assert "**Read permits this write**" in text
    assert "charset=UTF-8" in text
    # the refusal itself was observed 2026-09-15 with users on the generated roles
    assert "Access to this API has been disallowed" in text
    assert "Access to this resource has been disallowed" in text
    assert "confirmed live 2026-09-15 by users carrying the generated roles" in text
    assert "all 432 read and write steps of the smoke answered" in text
    # the templates sentence is data-driven
    assert "The 16 APIs with a template among the 42 rows the read-only body carries" in text
    # a refused read with a declared Read-permitted form says so, once, and the disable
    # list notes it
    for name, (path, how) in rbac_map.READ_FORMS.items():
        assert text.count(f"`{name}`: `POST ") == 1, name
        assert f" — its `POST {path}` ({how}) is within the template, so that form" in text
    assert (
        "(`cnc_get_lcm_recommendation_preview` is in the list although one form of the "
        "call runs under Read, above — leave it out to keep that form.)"
    ) in text
    # the old exact-path and custom-URL models are gone from every generated file
    for path in ROLE_FILES.values():
        role_text = path.read_text(encoding="utf-8")
        assert role_text.count('"url": "/.*"') >= 42
        assert not re.findall(r'"url": "\^', role_text)
    assert "one entry per HTTP method" not in text


def test_doc_states_the_verified_editor_facts_and_none_of_the_removed_wording(rbac):
    """Section 1: the editor's tick -> wire mapping citing the UI-built fixture, the
    display-name groups and their consequence, the three baseline rows (neutral wording
    about the mirror's listing), the custom-URL crash as a warning, the first-entry
    display rule (first api_id in aaa/v2/api order); 'Not verified' names what is read
    from the bundle or extrapolated; sections 2/3 by editor row; section 6's body
    sentence. And none of the removed wording — in the README and SECURITY.md too."""
    text = DOC_PATH.read_text(encoding="utf-8")
    assert "**What a tick submits.**" in text
    assert (
        '`{url: "/.*", methods: <union>}` — **Read** adds `GET`, **Write** adds `POST, PUT, '
        "PATCH`, **Delete** adds `DELETE`"
    ) in text
    assert "(`tests/fixtures/rbac/stored_ui_built_role.json`)" in text
    assert "**A row is a display-name group.**" in text
    assert "**the UI cannot grant a single api_id of a group; the API can**" in text
    assert "15 of the editor's 102 rows cover more than one api_id" in text
    assert "(7 for *Alarm Settings*, 6 for *Alarms and Events RESTCONF*, 31 for" in text
    assert "reads only the FIRST `allowed_urls` entry of each api_id" in text
    assert (
        "a group row shows the ticks of its first api_id in `aaa/v2/api` order (the editor's "
        "row order, not the alphabetical order of the tables here)"
    ) in text
    assert "so the editor shows those rows unticked while the grant is live" in text
    assert (
        "`rate`/`per` is the gateway's per-key rate limit — 1000 requests per 60 s, the "
        "editor's default, where the built-in `admin` role carries 5000"
    ) in text
    assert "Every stored role gains 3 **baseline rows**" in text
    assert "`aaa_cw_role_read` (GET `/.*`; POST `/.+/query$`)" in text
    # the /.* entry rendered first, as stored — not the map's url order
    assert "`aaa_cwpassword` (GET, PUT `/.*`; POST `/(.*passwordHistoryCheck.*)$`)" in text
    assert "the mirror's catalogue listing, by platform design" in text
    # what the fixtures pin about the baseline rows, and nothing more
    assert (
        "the UI-built role, submitted with none of them, came back with all three; the two "
        "2026-09-14 API-stored experiments, submitted with `aaa_cw_role_read` only, came "
        "back with the other two"
    ) in text
    assert (
        "were not in the template capture (2026-09-14), so their templates are unknown and "
        "any POST there is classed W — except that the UI-built role stored "
        "`cw-fault-alarm-autoclear`, `cw-fault-alarm-autoclear-revert` as GET-only rows, "
        "template-free"
    ) in text
    # the smoke ran on the previous generation of the bodies — for the 245 tools of that
    # day; the 40 tools added since (37 Phase D, 3 SRv6 reads) were not exercised by it
    # and the read-only verdict it
    # confirmed still holds tool for tool — and the committed bodies were read back and
    # give the same verdict: said in both places (section 1 and 6), computed from the
    # generator's SMOKE_* constants and the map, never hard-coded
    assert (rbac_map.SMOKE_TOOL_COUNT, rbac_map.SMOKE_READ_TOOL_COUNT) == (245, 182)
    assert set(rbac_map.SMOKE_REFUSED_READS) == READ_TOOLS_REFUSED_BY_READ
    assert set(rbac_map.SMOKE_PERMITTED_WRITES) == WRITE_TOOLS_PERMITTED_BY_READ
    smoke_clause = (
        "the smoke runs were on the previous generation of the bodies — those of the 245 "
        "tools registered on 2026-09-15 (182 read) — which differed from the generated bodies "
        "of those tools only in the two AAA rows — `aaa_cwaaa` a GET pattern limited to the "
        "paths the tools send then, `/.*` now; `aaa_cw_role_read` in the body then, left to "
        "the baseline row now — `versions` and the `rate` field; the bodies as committed now "
        f"also carry what the {TOOL_COUNT - 245} tools added since ({READ_TOOL_COUNT - 182} "
        f"read, {TOOL_COUNT - READ_TOOL_COUNT - 63} write) need — rows and ticks that smoke "
        "did not exercise — and the refusal predictions for the tools of that day are "
        "identical (the same 14 read tools refused under `cnc-mcp-readonly`, "
        "`cnc_reactivate_probe` permitted, every tool permitted under `cnc-mcp-operator`); "
    )
    assert "40 tools added since (5 read, 35 write)" in smoke_clause
    assert text.count(smoke_clause) == 2
    assert "which differed only in the two AAA rows" not in text
    assert "now but not then" not in text  # the verdict of that day holds tool for tool
    read_back_clause = (
        "the bodies as committed were stored through the API and read back (2026-09-15: "
        "`tests/fixtures/rbac/stored_generated_readonly.json`, "
        "`tests/fixtures/rbac/stored_generated_operator.json`); evaluated on the stored form "
        "they give the same verdict for every tool as the model — `cnc-mcp-readonly`: "
        f"{READS_PERMITTED_BY_READ} of the {READ_TOOL_COUNT} read tools permitted, 14 refused, "
        f"1 write tool permitted (`cnc_reactivate_probe`); `cnc-mcp-operator`: {TOOL_COUNT} of "
        f"{TOOL_COUNT} permitted"
    )
    assert text.count(smoke_clause + read_back_clause) == 2
    assert "have not been stored in their current shape" not in text
    assert "the two generated bodies as committed stored through the API and read back" in text
    # the split rule: the pattern quoted, what it means, the three verified APIs, the
    # seven inferred, the consequence, and what the map says of the OE delete RPC
    split_bullet = next(line for line in text.splitlines() if "is **split**" in line)
    assert split_bullet.startswith("- A row ticked Read **and** Write is stored as its single")
    # why the service carves the segment out is a presumption, marked as one: no tool
    # POSTs a `/delete` tail on any of the ten APIs
    assert (
        "**except on the APIs on which the service reserves a last segment `delete` for the "
        "Delete tick** (presumably the ones that delete through `POST .../delete` — no tool "
        "POSTs such a path, so the map does not show one)"
    ) in split_bullet
    assert "the APIs that delete through" not in text
    assert f'`{{url: "{rbac_map.NOT_DELETE_PATTERN}", methods: [POST]}}`' in split_bullet
    assert "matches every path whose LAST segment is not the six-character word `delete`" in (
        split_bullet
    )
    assert "read back as `[GET, PATCH, PUT] /.*` + `[POST] <the pattern>`" in split_bullet
    assert (
        "Verified 2026-09-15 on `cwcollection`, `optima_restconf`, `platform_cwplatform` (the "
        "operator body's Write rows there, `tests/fixtures/rbac/stored_generated_operator.json`)"
    ) in split_bullet
    assert (
        "**inferred** for `collection_dg-manager`, `cw-fault-alarms-api`, `cw-fault-events-api`, "
        "`cw-probe-mgr`, `cw-ztp-service`, `dg-manager-global-parameters-api`, "
        "`optima_analytics_api` from the 2026-09-14 experiment"
    ) in split_bullet
    # the POST-only experiment's stored shape as the maintainer's notes and the guide's
    # earlier generation record it — the entry kept with methods [], the pattern
    # appended — the counts and the parenthetical derived from the constants
    assert (
        "in which a row whose only entry was a custom-url POST came back with its methods "
        "stripped to `[]` and this same pattern entry appended, on those seven (and on "
        "`cwcollection`, `optima_restconf`) — the same split, POST being the entry's only "
        "method; no union entry has been stored on them"
    ) in split_bullet
    assert "came back as this same pattern" not in text
    assert "the split there is the model's extrapolation, not a read-back" in split_bullet
    # Phase D: cw-ztp-service carries Read+Write+Delete on a POST-delete API and was read
    # back verbatim — the split is for Write without Delete only
    assert (
        f"so were the operator body's {len(OPERATOR_DELETE_ROWS)} rows carrying DELETE and its "
        f"{len(OPERATOR_WRITE_ONLY_ROWS)} Write-only rows (`[POST, PUT, PATCH]`) — including "
        "`cw-ztp-service` on this list: a single entry carrying DELETE is stored verbatim, the "
        "split applies only to Write without Delete (read back 2026-09-15)"
    ) in split_bullet
    assert "10 rows carrying DELETE and its 7 Write-only rows" in split_bullet
    assert "none of them on this list" not in text
    # the two-entry observation of the same submission — what the single-entry condition
    # of the split keys on
    assert (
        "In the same 2026-09-14 submission a custom GET entry beside a custom POST entry was "
        "stored verbatim on `platform_cwplatform` (and on three APIs off this list, "
        "`device-config`, `inventory_cwinventory`, `tsdn_cat-restconf-nbi`) — the split keys "
        "on the row having a single entry."
    ) in split_bullet
    assert (
        "**Consequence: Write without Delete on these APIs still permits every POST except a "
        "path ending in `/delete`.**"
    ) in split_bullet
    assert (
        "an operator role without Delete can still create policies, and the delete RPC the "
        "map records — `POST /crosswork/nbi/optimization/v3/restconf/operations/"
        "cisco-crosswork-optimization-engine-sr-policy-operations:sr-policy-delete` "
        "(`cnc_delete_sr_policy`) — ends in the segment "
        "`cisco-crosswork-optimization-engine-sr-policy-operations:sr-policy-delete`, not "
        "`delete`, so it stays permitted too; no POST any tool sends on these 10 APIs ends "
        "in `/delete`."
    ) in split_bullet
    assert text.count("inferred") == 1  # the seven APIs, and nothing else
    assert (
        "came back with its methods stripped to `[]` and the not-delete pattern above appended "
        "— a wider grant than the url submitted — on the nine APIs it was tried on"
    ) in text
    assert "came back as the not-delete pattern" not in text
    # section 2, option 1: Write's POST on a POST-delete API is the not-delete pattern,
    # not the whole API
    assert (
        "because Write is `/.*` on the whole API for PUT/PATCH and — except on the "
        "POST-delete APIs of section 1 — for POST, and a narrower custom-URL entry is not an "
        "option (section 1's warning):"
    ) in text
    assert "Write is `/.*` for POST/PUT/PATCH on the whole API" not in text
    option_rows = [
        line
        for line in text.splitlines()
        if line.startswith("  - `") and "Write also permits" in line
    ]
    assert [line.split("`")[1] for line in option_rows] == [
        "cwcollection",
        "device-config",
        "inventory_cwinventory",
        "optima_restconf",
    ]
    pattern_note = (
        "— POST under the not-delete pattern, every path except one ending in `/delete` "
        "(section 1)."
    )
    for line in option_rows:
        api_id = line.split("`")[1]
        assert line.endswith(pattern_note) == (api_id in rbac["platform"]["post_delete_apis"]), line
    assert (
        "  - `cwcollection`: Write also permits every POST/PUT/PATCH the API serves (no cnc-mcp "
        f"write tool uses it) {pattern_note}"
    ) in text
    assert '> **Warning — never load a role body with a url other than `"/.*"`.**' in text
    assert "crashes the Roles page for everyone" in text
    assert "Cannot read properties of undefined (reading 'read')" in text
    assert "**Not verified:**\n\n- The editor's wire shape, the display-name groups" in text
    assert (
        "the stored form of single-tick, per-tick and union entries (the generated bodies "
        "read back), the baseline rows, the split of a Write-without-Delete row on "
        "`cwcollection`, `optima_restconf`, `platform_cwplatform` and the gateway's refusals "
        "are all observed"
    ) in text
    assert (
        "Extrapolated, not read back: the same split on the 7 other POST-delete APIs (from a "
        "POST-only experiment), and what the service stores for a Write-only row on any of "
        "them, or a row carrying DELETE on one other than `cw-ztp-service` (the bodies have "
        "none)"
    ) in text
    assert "what the service stores for a row carrying DELETE, or a Write-only row" not in text
    assert "Extrapolated from the per-row rule" not in text
    assert "**By editor row** (tick Read on each):" in text
    assert "| feature | editor row | api_ids the read tools use | sibling api_ids" in text
    assert "| AAA | Users and Roles Management | `aaa_cwaaa` | `get-WebSocket-Subscription`" in text
    assert "**By api_id** (what an API-loaded body grants" in text
    assert "| R (baseline row: every role has it) |" in text
    assert (
        "Drop that row and the account can no longer read them: the gateway refuses these 10 tools"
        in text
    )
    assert "`cnc_list_roles`, `cnc_list_secured_apis`, `cnc_list_users`" in text
    assert (
        "| feature | editor row | api_ids the writes use | sibling api_ids the tick also "
        "grants | ticks to add |"
    ) in text
    assert (
        "**The generated bodies are the shape the editor submits** (verified 2026-09-15 "
        "against the UI-built role's read-back, `tests/fixtures/rbac/stored_ui_built_role.json`)"
    ) in text
    assert "minus the empty `_id`/`id` the editor also sends" in text
    assert (
        "What the fixtures pin: both bodies as committed, stored and read back (2026-09-15: "
        "`tests/fixtures/rbac/stored_generated_readonly.json`, "
        "`tests/fixtures/rbac/stored_generated_operator.json` — the model reproduces every "
        "stored row entry for entry: the read-only body's 42 Read rows with their templates; "
        "the operator body's union entries, `[GET, POST, PUT, PATCH]` on 9 rows and all five "
        "methods on 10, verbatim except the 3 split rows section 1 describes — `cwcollection`, "
        "`optima_restconf`, `platform_cwplatform` — where POST came back under the "
        "not-delete pattern; plus the three baseline rows on each)"
    ) in text
    op_ticks = rbac_map.body_ticks(body("operator"))
    assert sum(t == {"R", "W"} for t in op_ticks.values()) == 9
    assert sum(t == {"R", "W", "D"} for t in op_ticks.values()) == 10 == len(OPERATOR_DELETE_ROWS)
    assert "have not been read back" not in text
    assert "follow from the per-row rule" not in text
    assert "**an API-loaded role is managed through the API only**" in text
    assert "a Save rebuilds every group from the editor's model" in text
    assert (
        f"`cnc-mcp-operator.role.json` carries {OPERATOR_ROW_COUNT} rows: 26 with Write, "
        f"{len(OPERATOR_DELETE_ROWS)} with Delete, {len(OPERATOR_WRITE_ONLY_ROWS)} Write-only"
    ) in text
    assert "carries 49 rows: 26 with Write, 10 with Delete, 7 Write-only" in text
    # none of the removed wording — in the guide, the README and SECURITY.md alike
    # (SECURITY.md kept the superseded AAA-row paragraph once); the CHANGELOG describes
    # what changed, so it is checked for the claims no fixture supports only
    removed_wording = (
        "administrative data",
        "is taken to",
        "plausibly",
        "No UI-built role exists",
        "restrict the URL",
        "The two AAA rows",
        "custom-URL POST entry is reinterpreted",
        "reinterpreted into a wider grant",
        "narrowed POST entry",
        "have not yet been loaded",
        "have not been read back",
        "have not been stored in their current shape",
    )
    unsupported_claims = (
        "exactly what the editor submits",
        "exactly what the Crosswork role editor submits",
        "the two generated roles stored",
        "generated roles opened in the editor",
        "lab verified both",
        "were never stored as GET-only rows",
        "none submitted with any of them",
    )
    for doc in (DOC_PATH, REPO / "README.md", REPO / "SECURITY.md"):
        doc_text = doc.read_text(encoding="utf-8")
        for gone in (*removed_wording, *unsupported_claims):
            assert gone not in doc_text, (doc.name, gone)
        assert not re.search(r"\banchored\b", doc_text), doc.name  # 'unanchored' stays
        if doc != DOC_PATH:
            assert "inferred" not in doc_text, doc.name  # only the split rule's seven APIs
    changelog = " ".join((REPO / "CHANGELOG.md").read_text(encoding="utf-8").split())
    for gone in unsupported_claims:
        assert gone not in changelog, gone
    assert "The smoke runs were on the previous generation of the bodies" in changelog
    assert "`cnc-mcp-readonly` permits 168 of the 182 read tools" in changelog
    assert "`cnc-mcp-operator` all 245" in changelog
    assert "split" in changelog and "inferred for the seven" in changelog
    # the same in the generator's own documentation and in the map: 'inferred' names the
    # seven APIs the split is extrapolated to, nothing else
    source = (REPO / "scripts" / "rbac_map.py").read_text(encoding="utf-8")
    assert "# VERIFIED for the union entry (2026-09-15" in source
    assert "# INFERRED from the 2026-09-14 POST-only experiment (not a fixture)" in source
    for gone in removed_wording:
        assert gone not in source, gone
    assert not re.search(r"\banchored\b", source)
    ticks = rbac["generated_from"]["ticks"]
    assert "inferred" not in ticks
    assert "verified 2026-09-15 by reading a UI-built role back" in ticks
    # the counts are the constants' (three verified, seven inferred), spelled out
    assert (rbac_map.count_word(3), rbac_map.count_word(7), rbac_map.count_word(12)) == (
        "three",
        "seven",
        "12",
    )
    assert (
        "on the 'platform.post_delete_apis' a row whose single entry carries POST without "
        "DELETE is split — the other methods stay on '/.*' in alphabetical order and POST "
        "moves to 'platform.not_delete_pattern', every path except one ending in the "
        "segment 'delete' (verified 2026-09-15 by reading the generated operator role back "
        f"on {rbac_map.count_word(len(rbac_map.POST_DELETE_VERIFIED))} of them, extrapolated "
        f"to the {rbac_map.count_word(len(rbac_map.POST_DELETE_INFERRED))} others from a "
        "POST-only experiment)"
    ) in ticks
    assert "on three of them, extrapolated to the seven others" in ticks


def test_render_doc_stops_when_post_delete_apis_carry_an_undocumented_api(rbac):
    """The guide documents every POST-delete API as verified or inferred and counts
    them: a platform block (from a --read-templates capture) carrying an api_id in
    neither list, or lacking one, stops the generator instead of being documented as
    'inferred from the 2026-09-14 experiment' with the wrong count."""
    platform = rbac["platform"]
    extra = {
        **rbac,
        "platform": {
            **platform,
            "post_delete_apis": [*platform["post_delete_apis"], "ems-inventory"],
        },
    }
    with pytest.raises(
        SystemExit, match="neither verified nor in the 2026-09-14 experiment: \\['ems-inventory'\\]"
    ):
        rbac_map.render_doc(extra, rbac["apis"], body("readonly"), body("operator"))
    fewer = {
        **rbac,
        "platform": {
            **platform,
            "post_delete_apis": [a for a in platform["post_delete_apis"] if a != "cw-probe-mgr"],
        },
    }
    with pytest.raises(SystemExit, match="lacks a verified or inferred API: \\['cw-probe-mgr'\\]"):
        rbac_map.render_doc(fewer, rbac["apis"], body("readonly"), body("operator"))


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
    real api_id ``cwm_secret`` — and ``hmac_enabled: false`` is one of the editor's
    default role fields.)"""
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


def test_sanitise_catalogue_copies_only_four_fields():
    """api_id, name and proxy.listen_path from v1, the feature and the position from
    v2 (response order: features, then entries — the role editor's row order) — never
    a Tyk API definition's other fields (its auth configuration, the target URL, ...)."""
    v1 = [
        {
            "api_id": "inventory_cwinventory",
            "name": "Inventory APIs",
            "proxy": {"listen_path": "/crosswork/inventory/", "target_url": "http://x"},
            "jwt_source": "c2VjcmV0",
            "hmac_allowed_algorithms": ["hmac-sha512"],
        },
        {"api_id": "orphan", "name": "Orphan", "proxy": {"listen_path": "/crosswork/orphan/"}},
        {"api_id": "ems-inventory", "name": "Device Inventory", "proxy": {"listen_path": "/x"}},
    ]
    v2 = {
        "Device Monitoring": [{"api_id": "ems-inventory", "name": "Device Inventory"}],
        "Inventory": [{"api_id": "inventory_cwinventory", "name": "Inventory APIs"}],
    }
    catalogue = rbac_map.sanitise_catalogue(v1, v2)
    assert catalogue == {
        "inventory_cwinventory": {
            "name": "Inventory APIs",
            "feature": "Inventory",
            "listen_path": "/crosswork/inventory/",
            "position": 1,
        },
        "orphan": {
            "name": "Orphan",
            "feature": rbac_map.UNCATEGORISED,
            "listen_path": "/crosswork/orphan/",
            "position": None,
        },
        "ems-inventory": {
            "name": "Device Inventory",
            "feature": "Device Monitoring",
            "listen_path": "/x",
            "position": 0,
        },
    }
    assert "c2VjcmV0" not in json.dumps(catalogue)
    # the committed map carries the positions and the offline loader requires them
    loaded = rbac_map.load_catalogue_map(MAP_PATH)
    assert loaded == {
        api_id: dict(api) for api_id, api in json.loads(MAP_PATH.read_text())["apis"].items()
    }


def test_sanitise_platform_keeps_url_and_methods_only_and_checks_the_baseline_rows():
    def sanitise(templates, baseline, captured, catalogue):
        return rbac_map.sanitise_platform(templates, baseline, captured, catalogue, **SPLIT_RULE)

    templates = {
        "inventory_cwinventory": [
            {"url": "/.+/query$", "methods": ["post"], "limit": None, "extra": "x"}
        ],
        "aaa_cw_role_read": [{"url": "/.+/query$", "methods": ["POST"]}],
    }
    baseline = {
        "aaa_cwpassword": [
            {"url": "/.*", "methods": ["PUT", "GET"]},
            {"url": "/(.*passwordHistoryCheck.*)$", "methods": ["POST"]},
        ],
        "aaa_cw_role_read": [
            {"url": "/.+/query$", "methods": ["POST"]},
            {"url": "/.*", "methods": ["GET"], "versions": ["Default"]},
        ],
    }
    platform = sanitise(templates, baseline, "2026-09-14", CATALOGUE)
    assert platform == {
        "version": "7.2.0",
        "captured": "2026-09-14",
        "read_templates": {
            "aaa_cw_role_read": [{"url": "/.+/query$", "methods": ["POST"]}],
            "inventory_cwinventory": [{"url": "/.+/query$", "methods": ["POST"]}],
        },
        "baseline_rows": {
            "aaa_cw_role_read": [
                {"url": "/.*", "methods": ["GET"]},
                {"url": "/.+/query$", "methods": ["POST"]},
            ],
            "aaa_cwpassword": [
                {"url": "/.*", "methods": ["GET", "PUT"]},
                {"url": "/(.*passwordHistoryCheck.*)$", "methods": ["POST"]},
            ],
        },
        **SPLIT_RULE,
    }
    for marker in ("limit", "extra", "versions"):
        assert marker not in json.dumps(platform), marker
    # a capture in the previous format — the baseline rows listed among the templates
    # with their GET/PUT entries — is refused, not re-split
    with pytest.raises(SystemExit, match="is a baseline row, not a read template"):
        sanitise(
            {"aaa_cwpassword": [{"url": "/.*", "methods": ["GET", "PUT"]}]},
            {},
            "2026-09-14",
            CATALOGUE,
        )
    with pytest.raises(SystemExit, match="is a baseline row, not a read template"):
        sanitise({"aaa_cwpassword": []}, {}, "2026-09-14", CATALOGUE)
    with pytest.raises(SystemExit, match="a read template is the POST entries"):
        sanitise(
            {"inventory_cwinventory": [{"url": "/.*", "methods": ["GET", "PUT"]}]},
            {},
            "2026-09-14",
            CATALOGUE,
        )
    with pytest.raises(SystemExit, match="a read template is the POST entries"):
        sanitise(
            {"inventory_cwinventory": [{"url": "/.+/query$", "methods": ["POST", "GET"]}]},
            {},
            "2026-09-14",
            CATALOGUE,
        )
    with pytest.raises(SystemExit, match="not in the secured-API catalogue"):
        sanitise({"nope": []}, {}, "2026-09-14", CATALOGUE)
    with pytest.raises(SystemExit, match="not a baseline API"):
        sanitise({}, {"inventory_cwinventory": []}, "2026-09-14", CATALOGUE)
    with pytest.raises(SystemExit, match="unknown method"):
        sanitise(
            {"inventory_cwinventory": [{"url": "/x", "methods": ["FETCH"]}]},
            {},
            "2026-09-14",
            CATALOGUE,
        )
    with pytest.raises(SystemExit, match="not a valid regex"):
        sanitise(
            {"inventory_cwinventory": [{"url": "/(x", "methods": ["POST"]}]},
            {},
            "2026-09-14",
            CATALOGUE,
        )
    with pytest.raises(SystemExit, match="without url/methods"):
        sanitise({"inventory_cwinventory": [{"url": "/x"}]}, {}, "2026-09-14", CATALOGUE)
    with pytest.raises(SystemExit, match="YYYY-MM-DD"):
        sanitise({}, {}, "yesterday", CATALOGUE)
    with pytest.raises(SystemExit, match="must be"):
        sanitise([], {}, "2026-09-14", CATALOGUE)


def test_sanitise_platform_checks_the_split_rule_data():
    """post_delete_apis: catalogued api_ids, stored sorted and de-duplicated;
    not_delete_pattern: a regex that refuses a path ending in the segment 'delete' and
    permits any other (the meaning the guide states) — the constants pass, and a capture
    that carries something else is refused before the guide could misdescribe it."""
    platform = rbac_map.sanitise_platform(
        {}, {}, "2026-09-15", CATALOGUE, ["platform_cwplatform", "platform_cwplatform"]
    )
    assert platform["post_delete_apis"] == ["platform_cwplatform"]
    assert platform["not_delete_pattern"] == rbac_map.NOT_DELETE_PATTERN
    catalogue = rbac_map.load_catalogue_map(MAP_PATH)
    platform = rbac_map.sanitise_platform({}, {}, "2026-09-15", catalogue)  # the defaults
    assert platform["post_delete_apis"] == sorted(rbac_map.POST_DELETE_APIS)
    with pytest.raises(SystemExit, match="post_delete_apis: cwcollection is not in the catalogue"):
        rbac_map.sanitise_platform({}, {}, "2026-09-15", CATALOGUE)
    with pytest.raises(SystemExit, match="must be a list of api_ids"):
        rbac_map.sanitise_platform({}, {}, "2026-09-15", CATALOGUE, "platform_cwplatform")
    with pytest.raises(SystemExit, match="must be a regex string"):
        rbac_map.sanitise_platform({}, {}, "2026-09-15", CATALOGUE, [], None)
    with pytest.raises(SystemExit, match="not a valid regex"):
        rbac_map.sanitise_platform({}, {}, "2026-09-15", CATALOGUE, [], "/(x")
    for wrong in ("/.*", "/delete$", "^/x$", "/[^d]+$"):
        with pytest.raises(SystemExit, match="does not mean 'every path except one ending"):
            rbac_map.sanitise_platform({}, {}, "2026-09-15", CATALOGUE, [], wrong)
    # an equivalent spelling of the rule is accepted: the meaning is checked, not the text
    platform = rbac_map.sanitise_platform(
        {}, {}, "2026-09-15", CATALOGUE, [], r"^(?!.*/delete/?$).*$"
    )
    assert platform["not_delete_pattern"] == r"^(?!.*/delete/?$).*$"


def test_load_platform_file_takes_a_capture_and_falls_back_to_the_committed_baseline(tmp_path):
    capture = tmp_path / "capture.json"
    capture.write_text(
        json.dumps(
            {
                "captured": "2026-09-15",
                "how": "GET role after PUT",
                "read_templates": {
                    "inventory_cwinventory": [{"url": "/.+/query$", "methods": ["POST"]}]
                },
                "baseline_rows": {"aaa_cwpassword": [{"url": "/.*", "methods": ["GET", "PUT"]}]},
                "post_delete_apis": ["platform_cwplatform"],
            }
        )
    )
    platform = rbac_map.load_platform_file(capture, CATALOGUE, None)
    assert platform["captured"] == "2026-09-15"
    assert list(platform["read_templates"]) == ["inventory_cwinventory"]
    assert list(platform["baseline_rows"]) == ["aaa_cwpassword"]
    # the capture's post_delete_apis, the constant pattern (no committed map to take it from)
    assert platform["post_delete_apis"] == ["platform_cwplatform"]
    assert platform["not_delete_pattern"] == rbac_map.NOT_DELETE_PATTERN
    templates_only = tmp_path / "templates.json"
    templates_only.write_text(
        json.dumps(
            {
                "read_templates": {
                    "inventory_cwinventory": [{"url": "/.+/query$", "methods": ["POST"]}]
                }
            }
        )
    )
    platform = rbac_map.load_platform_file(templates_only, CATALOGUE, PLATFORM)
    assert platform["captured"] == rbac_map.TEMPLATES_CAPTURED
    assert platform["baseline_rows"] == PLATFORM["baseline_rows"]
    # without the split rule's keys a capture keeps the committed map's
    assert platform["post_delete_apis"] == PLATFORM["post_delete_apis"]
    assert platform["not_delete_pattern"] == PLATFORM["not_delete_pattern"]
    spelling = r"^(?!.*/delete/?$).*$"
    fallback = {**PLATFORM, "post_delete_apis": [], "not_delete_pattern": spelling}
    platform = rbac_map.load_platform_file(templates_only, CATALOGUE, fallback)
    assert platform["post_delete_apis"] == [] and platform["not_delete_pattern"] == spelling
    # ... and the constants when there is no committed map either (the real catalogue:
    # the constants name ten of its APIs)
    full = tmp_path / "full.json"
    full.write_text(json.dumps({"read_templates": {}, "baseline_rows": {}}))
    platform = rbac_map.load_platform_file(full, rbac_map.load_catalogue_map(MAP_PATH), None)
    assert platform["post_delete_apis"] == sorted(rbac_map.POST_DELETE_APIS)
    assert platform["not_delete_pattern"] == rbac_map.NOT_DELETE_PATTERN
    with pytest.raises(SystemExit, match="no 'baseline_rows'"):
        rbac_map.load_platform_file(templates_only, CATALOGUE, None)
    # the previous capture format (2026-09-14: the baseline APIs under read_templates with
    # their GET/PUT entries, no baseline_rows) is refused even with a committed fallback
    previous = tmp_path / "previous.json"
    previous.write_text(
        json.dumps(
            {
                "captured": "2026-09-14",
                "read_templates": {
                    "aaa_cw_role_read": [{"url": "/.+/query$", "methods": ["POST"]}],
                    "aaa_cwpassword": [
                        {"url": "/.*", "methods": ["GET", "PUT"]},
                        {"url": "/(.*passwordHistoryCheck.*)$", "methods": ["POST"]},
                    ],
                    "inventory_cwinventory": [{"url": "/.+/query$", "methods": ["POST"]}],
                },
            }
        )
    )
    with pytest.raises(SystemExit, match="aaa_cwpassword is a baseline row"):
        rbac_map.load_platform_file(previous, CATALOGUE, PLATFORM)
    for bad_text in ("[]", json.dumps({"inventory_cwinventory": []})):
        bad = tmp_path / "bad.json"
        bad.write_text(bad_text)
        with pytest.raises(SystemExit, match="'read_templates' mapping"):
            rbac_map.load_platform_file(bad, CATALOGUE, None)


def test_load_platform_map_requires_the_platform_block(tmp_path):
    stale = tmp_path / "rbac_map.json"
    stale.write_text(json.dumps({"apis": CATALOGUE, "tools": {}}))
    with pytest.raises(SystemExit, match="--read-templates"):
        rbac_map.load_platform_map(stale, CATALOGUE)


def test_load_platform_map_takes_the_split_rule_from_the_map_or_the_constants(rbac, tmp_path):
    """A map from before the split rule was modelled (no post_delete_apis /
    not_delete_pattern in its platform block) loads with the constants; one that carries
    them keeps what it carries."""
    catalogue = rbac_map.load_catalogue_map(MAP_PATH)
    previous = tmp_path / "rbac_map.json"
    platform = {k: v for k, v in rbac["platform"].items() if k not in rbac_map.SPLIT_RULE_KEYS}
    previous.write_text(json.dumps({**rbac, "platform": platform}))
    assert rbac_map.load_platform_map(previous, catalogue) == rbac["platform"]
    carried = tmp_path / "carried.json"
    platform = {**rbac["platform"], "post_delete_apis": ["cwcollection"]}
    carried.write_text(json.dumps({**rbac, "platform": platform}))
    assert rbac_map.load_platform_map(carried, catalogue)["post_delete_apis"] == ["cwcollection"]


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
