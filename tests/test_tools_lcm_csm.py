"""LCM / CSM tools end-to-end through MCPServer (schema validation included).

The module is registered directly (not through build_server) so the test does
not depend on tools/__init__.py's module list. All HTTP is mocked with respx.
The "verified" fixtures are verbatim what Crosswork 7.2 answered live on
2026-09-13 (platform notes, "LCM / CSM RPCs"): the single disabled domain
``"0"``, its configuration (keys as listed live; values not captured in the
notes are the LCM defaults), the answers without managed interfaces /
recommendation / bandwidth pools / CS policies, and the per-node and per-link
CSM answers. The populated shapes (a recommendation with solutions, a preview,
CS policy paths, bandwidth pools, the pause answer) follow the 7.2 OpenAPI
documents and are marked as such. The two CSM tools that send node /
interface names resolve them against the topology NBI first, so their tests
mock the ``networks`` collection GET (the verified shape, minimal) as the
sr_te_operations tests do.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx
from mcp.server.mcpserver import MCPServer

from cnc_mcp.auth import StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.config import Settings
from cnc_mcp.errors import PlatformError
from cnc_mcp.restconf import EMPTY_500_EXPLANATION
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import lcm_csm
from cnc_mcp.tools.lcm_csm import (
    BACKEND_SUSPECT,
    CSM_CONFIG_MODULE,
    CSM_POLICY_MODULE,
    FUNCTION_PACK_MODULE,
    LCM_DOMAIN_MODULE,
    LCM_RECOMMENDATION_MODULE,
    RPC_GET_LCM_MSL_RECOMMENDATION_PREVIEW,
    RPC_GET_LCM_RECOMMENDATION_PREVIEW,
    check_lcm_output,
    check_recommendation_checks,
    config_lines,
    domain_suspect,
    empty_500_hint,
    lcm_interface,
    names_suspect,
    parse_hostnames,
    recommendation_pending,
)
from tests.conftest import BASE_URL, call_tool_text

YANG_JSON = "application/yang-data+json"
OPERATIONS = f"{BASE_URL}/crosswork/nbi/optimization/v3/restconf/operations"
NETWORKS_URL = f"{BASE_URL}/crosswork/nbi/topology/v3/restconf/data/ietf-network-state:networks"
GI0 = "GigabitEthernet0/0/0/0"
GI1 = "GigabitEthernet0/0/0/1"


def rpc(module: str, name: str) -> str:
    return f"{OPERATIONS}/{module}:{name}"


def out(module: str, **fields: Any) -> dict:
    return {f"{module}:output": fields}


# --- topology fixture (the verified networks-collection shape, minimal) --------------

TP_LIST = "ietf-network-topology-state:termination-point"
L3_NODE = "ietf-l3-unicast-topology-state:l3-node-attributes"


def topo_node(node_id: str, index: int) -> dict[str, Any]:
    """A node as the collection GET lists it: id, termination points, router-id."""
    return {
        "node-id": node_id,
        TP_LIST: [{"tp-id": GI0}, {"tp-id": GI1}, {"tp-id": "Loopback0"}],
        L3_NODE: {"name": node_id, "router-id": [f"10.0.0.{index}"]},
    }


TOPO_NODES = [topo_node("PE1", 1), topo_node("P1", 2), topo_node("PE2", 3), topo_node("P2", 4)]
NETWORKS = {
    "ietf-network-state:networks": {
        "network": [{"network-id": "Default-network", "node": TOPO_NODES}]
    }
}
NO_NETWORKS: dict = {}


# --- verified fixtures (verbatim from the wire, 2026-09-13) --------------------------

DOMAINS_OUT = out(
    LCM_DOMAIN_MODULE,
    **{
        "response-result": "valid",
        "domain": [
            {
                "domain-id": "0",
                "description": "LCM startup config",
                "recommendation-timestamp": "",
                "status": "disabled",
            }
        ],
    },
)
DOMAINS_EMPTY = out(LCM_DOMAIN_MODULE, **{"response-result": "valid"})
# Keys as answered live (the notes list them; the answer was truncated after
# "conge…"). Values not captured live are the documented / UI defaults.
CONFIG_OUT = out(
    FUNCTION_PACK_MODULE,
    **{
        "status": "accepted",
        "adjacency-hop-type": "protected-preferred",
        "history-retention-time": 30,
        "description": "LCM startup config",
        "profile-id": 0,
        "color": 2000,
        "maximum-parallel-tactical-sr-policies": 1,
        "auto-repair-solution": True,
        "stay-in-area": False,
        "debug-maximum-plans": 0,
        "over-provision-factor": 0,
        "delete-tactical-sr-policies": True,
        "geo-ha-traffic-collection-hold-time": 180,
        "utilization-hold-margin": 5,
        "optimization-objective": "igp-metric",
        "congestion-check-interval": 600,
        "congestion-check-suspension-interval": 300,
        "utilization-threshold": 80,
        "enable": False,
        "operation-mode": "manual",
        "include-all-interfaces": False,
        "deployment-timeout": 180,
        "throttle-mode-threshold": 5,
    },
)
MANAGED_EMPTY = out(FUNCTION_PACK_MODULE, status="accepted")
RECOMMENDATION_NONE = out(
    LCM_RECOMMENDATION_MODULE,
    **{
        "urgency": "none",
        "last-recommendation-timestamp": "",
        "recommendation-id": "",
        "response-result": "valid",
    },
)
POOLS_EMPTY = out(CSM_CONFIG_MODULE, **{"response-result": "valid"})
ALL_PATHS_EMPTY = out(CSM_POLICY_MODULE, message="", status="accepted")
ON_NODES_OUT = out(
    CSM_POLICY_MODULE,
    status="accepted",
    **{"node-cs-policies": [{"node": "PE1", "operational-state": "active"}]},
)
ON_INTERFACE_OUT = out(
    CSM_POLICY_MODULE,
    **{"link-cs-policies": [{"node": "PE1", "interface": GI0, "operational-state": "up"}]},
)
# The COE's answer to an unknown LCM domain (verified) — and to an absent backend.
EMPTY_500 = httpx.Response(500)

# --- document-shaped fixtures (7.2 OpenAPI; unverified live) ------------------------

MANAGED_OUT = out(
    FUNCTION_PACK_MODULE,
    status="accepted",
    **{
        "managed-interfaces": [
            {"node": "PE1", "interface": GI0, "utilization-threshold": 70},
            {"node": "P1", "interface": GI1},
        ]
    },
)
SOLUTION = {
    "node": "PE1",
    "interface": GI0,
    "recommended-action": "create-set",
    "threshold-util": 80,
    "policy-set-status": "none",
    "policies-deployed": 0,
    "lcm-state": "congested",
    "evaluation-util": 92,
    "solution-timestamp": "2026-09-13T10:00:00Z",
    "expected-util": 61,
    "commit-status": "none",
}
RECOMMENDATION_OUT = out(
    LCM_RECOMMENDATION_MODULE,
    **{
        "response-result": "valid",
        "urgency": "high",
        "recommendation-id": "1789293787548",
        "last-recommendation-timestamp": "2026-09-13T10:00:00Z",
        "solutions": [SOLUTION],
    },
)
PREVIEW_OUT = out(
    LCM_RECOMMENDATION_MODULE,
    **{
        "response-result": "valid",
        "rec-id-check": "accepted",
        "request-check-result-enum": "accepted",
        "reason": "",
        "description": "Mitigate PE1 GigabitEthernet0/0/0/0",
        "lcm-int": {"node": "PE1", "interface": GI0},
        "tte-policy-preview": [
            {
                "policy-change": "create",
                "segment-list-hop": [
                    {"topo-element-id": "uuid-p2", "hop-type": "hop-ipv4-node-sid", "sid": 16004},
                    {"topo-element-id": "uuid-pe2", "hop-type": "hop-ipv4-node-sid", "sid": 16003},
                ],
                "igp-path": [f"PE1:{GI1}", f"P2:{GI0}"],
            }
        ],
    },
)
PREVIEW_REFRESH = out(
    LCM_RECOMMENDATION_MODULE,
    **{
        "response-result": "valid",
        "rec-id-check": "refresh",
        "request-check-result-enum": "accepted",
        "reason": "Recommendation has been updated",
    },
)
PREVIEW_INVALID = out(
    LCM_RECOMMENDATION_MODULE,
    **{
        "response-result": "valid",
        "rec-id-check": "accepted",
        "request-check-result-enum": "invalid",
        "reason": "lcm-int not found in recommendation",
    },
)
POOLS_OUT = out(
    CSM_CONFIG_MODULE,
    **{
        "response-result": "valid",
        "interface-bandwidth-pools": [
            {"node": "PE1", "interface": GI0, "bandwidth-pool": 80},
            {"node": "P1", "interface": GI1, "bandwidth-pool": 50},
        ],
    },
)
CS_PATH_WORKING = {
    "head-end": "10.0.0.1",
    "end-point": "10.0.0.3",
    "color": 1000,
    "preference": 100,
    "operational-state": "up",
}
CS_PATH_PROTECT = {**CS_PATH_WORKING, "preference": 50, "operational-state": "down"}
ALL_PATHS_OUT = out(
    CSM_POLICY_MODULE,
    status="accepted",
    message="",
    **{"cs-policy-paths": [CS_PATH_WORKING, CS_PATH_PROTECT]},
)
ON_NODES_WITH_PATHS = out(
    CSM_POLICY_MODULE,
    status="accepted",
    **{
        "node-cs-policies": [
            {"node": "PE1", "operational-state": "active", "cs-policy-paths": [CS_PATH_WORKING]},
            {"node": "P1", "operational-state": "active", "message": "no CS policies"},
        ]
    },
)
PAUSE_OUT = out(
    LCM_RECOMMENDATION_MODULE,
    **{
        "response-result": "valid",
        "pause-state": True,
        "request-check-result-enum": "accepted",
        "reason": "",
    },
)
PAUSE_DISAGREES = out(
    LCM_RECOMMENDATION_MODULE, **{"response-result": "valid", "pause-state": False}
)
PAUSE_INVALID = out(
    LCM_RECOMMENDATION_MODULE,
    **{
        "response-result": "valid",
        "request-check-result-enum": "invalid",
        "reason": "LCM is disabled in domain 0",
    },
)

# Failure idioms inside HTTP 200.
STATUS_ERROR = {"status": "error", "message": "failed to load LCM config"}
STATUS_REJECTED = {"status": "rejected", "message": "domain is pending removal"}
RESULT_ERROR = {"response-result": "error", "reason": "internal LCM error"}
RESULT_INVALID = {"response-result": "invalid"}


# --- harness ----------------------------------------------------------------------


def build(settings: Settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    lcm_csm.register(mcp, ctx)
    return mcp


@pytest.fixture
def writes(make_settings) -> MCPServer:
    return build(make_settings(enable_writes=True))


@pytest.fixture
def reads(settings) -> MCPServer:
    return build(settings)


def ok(body: Any) -> httpx.Response:
    return httpx.Response(200, json=body)


# The documented "204 No response" success (every LCM/CSM RPC lists it) — no body at all.
NO_CONTENT = httpx.Response(204)
# A 500 WITH a body is a different condition from the COE's empty 500 (NATS parse failure).
NATS_500 = httpx.Response(500, json={"error": "NATS request failed"})


def mock_networks(body: Any = NETWORKS) -> respx.Route:
    return respx.get(NETWORKS_URL).mock(return_value=ok(body))


def sent(route: respx.Route, index: int = 0) -> dict:
    return json.loads(route.calls[index].request.content)


def assert_yang_post(route: respx.Route, index: int = 0) -> None:
    request = route.calls[index].request
    assert request.method == "POST"
    assert request.headers["Content-Type"] == YANG_JSON
    assert request.headers["Accept"] == YANG_JSON


def assert_bodiless_post(route: respx.Route, index: int = 0) -> None:
    request = route.calls[index].request
    assert request.method == "POST"
    assert request.content == b""
    assert request.headers["Accept"] == YANG_JSON
    assert "Content-Type" not in request.headers


READ_TOOLS = {
    "cnc_list_lcm_domains",
    "cnc_get_lcm_config",
    "cnc_list_lcm_managed_interfaces",
    "cnc_get_lcm_recommendation",
    "cnc_get_lcm_recommendation_preview",
    "cnc_list_csm_bandwidth_pools",
    "cnc_list_cs_policy_paths",
    "cnc_list_cs_policies_on_nodes",
    "cnc_list_cs_policies_on_interface",
}
WRITE_TOOLS = {"cnc_pause_lcm_recommendations"}


# --- registration / gating -----------------------------------------------------------


async def test_write_tools_hidden_unless_enabled(make_settings):
    names = {t.name for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert names == READ_TOOLS
    names = {t.name for t in await build(make_settings(enable_writes=True)).list_tools()}
    assert names == READ_TOOLS | WRITE_TOOLS


async def test_annotations_and_flat_schemas(writes):
    tools = {t.name: t for t in await writes.list_tools()}
    for name in READ_TOOLS:
        assert tools[name].annotations.read_only_hint is True, name
        assert tools[name].annotations.idempotent_hint is True, name
        assert tools[name].annotations.destructive_hint is False, name
    pause = tools["cnc_pause_lcm_recommendations"].annotations
    assert pause.read_only_hint is False
    assert pause.destructive_hint is False
    assert pause.idempotent_hint is True
    # The bodiless RPCs take only the response format.
    for name in ("cnc_list_lcm_domains", "cnc_list_csm_bandwidth_pools"):
        assert set(tools[name].input_schema["properties"]) == {"response_format"}, name
    assert "required" not in tools["cnc_get_lcm_config"].input_schema  # domain_id defaults to "0"
    preview = tools["cnc_get_lcm_recommendation_preview"].input_schema
    assert set(preview["required"]) == {"domain_id", "recommendation_id"}
    assert preview["properties"]["msl"]["default"] is True
    assert set(tools["cnc_pause_lcm_recommendations"].input_schema["required"]) == {
        "domain_id",
        "paused",
    }
    # The two name-resolving CSM tools take the topology network, defaulted, like the SR ones.
    for name in ("cnc_list_cs_policies_on_nodes", "cnc_list_cs_policies_on_interface"):
        schema = tools[name].input_schema
        assert schema["properties"]["network"]["default"] == "Default-network", name
        assert "network" not in schema["required"], name
    # Every argument is a flat scalar (the only $ref is the ResponseFormat enum).
    for tool in tools.values():
        for arg, prop in tool.input_schema["properties"].items():
            ref = prop.get("$ref") or "".join(str(a.get("$ref", "")) for a in prop.get("anyOf", []))
            assert ref in ("", "#/$defs/ResponseFormat"), f"{tool.name}.{arg}"


# --- pure helpers -------------------------------------------------------------------


def test_check_lcm_output_passes_success_and_absent_fields():
    assert check_lcm_output({"status": "accepted"}, "x") == {"status": "accepted"}
    assert check_lcm_output({"response-result": "valid"}, "x") == {"response-result": "valid"}
    assert check_lcm_output({}, "x") == {}


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        (STATUS_ERROR, "get-lcm-config failed: failed to load LCM config"),
        (
            STATUS_REJECTED,
            "get-lcm-config was rejected by the Optimization Engine: domain is pending removal",
        ),
        (RESULT_ERROR, "get-lcm-config failed: response-result error: internal LCM error"),
        (RESULT_INVALID, "get-lcm-config failed: response-result invalid: no message given"),
        (
            {"response-result": "error", "error-description": "domain removal failed"},
            "get-lcm-config failed: response-result error: domain removal failed",
        ),
    ],
)
def test_check_lcm_output_failures(output, expected):
    with pytest.raises(PlatformError) as excinfo:
        check_lcm_output(output, "get-lcm-config")
    assert str(excinfo.value) == expected


def test_check_recommendation_checks():
    accepted = {"rec-id-check": "accepted", "request-check-result-enum": "accepted"}
    assert check_recommendation_checks(accepted, "preview", "1") is accepted
    assert check_recommendation_checks({}, "preview", "1") == {}
    with pytest.raises(PlatformError, match="recommendation id '1' is stale"):
        check_recommendation_checks({"rec-id-check": "refresh"}, "preview", "1")
    with pytest.raises(PlatformError, match="rec-id-check error"):
        check_recommendation_checks({"rec-id-check": "error", "reason": "gone"}, "preview", "1")
    with pytest.raises(PlatformError, match="request-check-result invalid\\): no lcm-int"):
        check_recommendation_checks(
            {"request-check-result-enum": "invalid", "reason": "no lcm-int"}, "preview", "1"
        )


def test_parse_hostnames():
    assert parse_hostnames(" PE1, p1 ,,P2 ", "nodes", "PE1,P1") == ["PE1", "p1", "P2"]
    with pytest.raises(PlatformError, match="nodes is empty"):
        parse_hostnames(" , ", "nodes", "PE1,P1")


def test_lcm_interface_both_or_neither():
    assert lcm_interface("", " ") is None
    assert lcm_interface(" PE1 ", GI0) == {"node": "PE1", "interface": GI0}
    with pytest.raises(PlatformError, match="node and interface go together"):
        lcm_interface("PE1", "")
    with pytest.raises(PlatformError, match="node and interface go together"):
        lcm_interface("", GI0)


def test_recommendation_pending():
    nothing_pending = RECOMMENDATION_NONE[f"{LCM_RECOMMENDATION_MODULE}:output"]
    assert recommendation_pending(nothing_pending) is False
    assert recommendation_pending({"recommendation-id": "7"}) is True
    assert recommendation_pending({"recommendation-id": "", "solutions": [SOLUTION]}) is True


def test_config_lines_follow_knob_order_and_skip_absent():
    lines = config_lines({"color": 2000, "enable": False, "unknown-leaf": 1})
    assert lines == [
        "- enable: false  (LCM function pack on/off for the domain)",
        "- color: 2000  (first color of the tactical SR policies (assigned incrementally from it))",
    ]


def test_empty_500_hint_is_self_contained_and_leads_with_the_suspect():
    """Bad INPUT first (verified: an unknown domain-id), backend-absent second — never the
    generic "retrying will not help, the feature is absent" verdict."""
    text = empty_500_hint(domain_suspect("9"))
    assert text.startswith(
        "the Optimization Engine rejected the request (unknown LCM domain? domain-id '9' was sent)"
    )
    assert EMPTY_500_EXPLANATION not in text
    for check in ("cnc_list_lcm_domains", "cnc_list_topology_nodes", "cnc_list_node_interfaces"):
        assert check in text, check
    assert "absent or down" in text
    # The CSM names are topology-resolved before the RPC, so the suspect says so.
    assert names_suspect(["PE1", f"P1:{GI0}"]) == (
        "the CSM did not resolve a name the topology knows? sent, as the topology spells "
        f"them: PE1, P1:{GI0}"
    )


# --- cnc_list_lcm_domains ---------------------------------------------------------------


@respx.mock
async def test_list_lcm_domains_sends_no_body_and_renders_the_verified_answer(reads):
    route = respx.post(rpc(LCM_DOMAIN_MODULE, "get-lcm-domains")).mock(return_value=ok(DOMAINS_OUT))
    text = await call_tool_text(reads, "cnc_list_lcm_domains", {})
    assert route.call_count == 1
    assert_bodiless_post(route)
    assert text.startswith("# LCM domains (1)")
    assert "- domain 0 — LCM startup config: status disabled; last recommendation -" in text
    assert "LCM is disabled in every domain" in text


@respx.mock
async def test_list_lcm_domains_enabled_domain_shows_urgency_and_mode(reads):
    body = out(
        LCM_DOMAIN_MODULE,
        **{
            "response-result": "valid",
            "domain": [
                {
                    "domain-id": "0",
                    "description": "LCM startup config",
                    "status": "enabled",
                    "urgency": "high",
                    "operation-mode": "manual",
                    "recommendation-timestamp": "2026-09-13T10:00:00Z",
                }
            ],
        },
    )
    respx.post(rpc(LCM_DOMAIN_MODULE, "get-lcm-domains")).mock(return_value=ok(body))
    text = await call_tool_text(reads, "cnc_list_lcm_domains", {})
    assert (
        "- domain 0 — LCM startup config: status enabled; operation-mode manual; urgency high; "
        "last recommendation 2026-09-13T10:00:00Z" in text
    )
    assert "LCM is enabled in domain(s) 0" in text


@respx.mock
async def test_list_lcm_domains_json(reads):
    respx.post(rpc(LCM_DOMAIN_MODULE, "get-lcm-domains")).mock(return_value=ok(DOMAINS_OUT))
    text = await call_tool_text(reads, "cnc_list_lcm_domains", {"response_format": "json"})
    assert json.loads(text) == DOMAINS_OUT[f"{LCM_DOMAIN_MODULE}:output"]


@respx.mock
async def test_list_lcm_domains_empty_is_not_an_error(reads):
    respx.post(rpc(LCM_DOMAIN_MODULE, "get-lcm-domains")).mock(return_value=ok(DOMAINS_EMPTY))
    text = await call_tool_text(reads, "cnc_list_lcm_domains", {})
    assert text.startswith("No LCM domains are configured.")


@respx.mock
async def test_list_lcm_domains_204_no_content_is_the_empty_answer(reads):
    """The document lists "204 No response" for every LCM/CSM RPC: no body -> {} -> none."""
    respx.post(rpc(LCM_DOMAIN_MODULE, "get-lcm-domains")).mock(return_value=NO_CONTENT)
    text = await call_tool_text(reads, "cnc_list_lcm_domains", {})
    assert text.startswith("No LCM domains are configured.")
    text = await call_tool_text(reads, "cnc_list_lcm_domains", {"response_format": "json"})
    assert json.loads(text) == {}


@respx.mock
async def test_list_lcm_domains_pending_removal_domain_is_rendered(reads):
    body = out(
        LCM_DOMAIN_MODULE,
        **{
            "response-result": "valid",
            "domain": [
                {"domain-id": "0", "description": "LCM startup config", "status": "disabled"},
                {
                    "domain-id": "7",
                    "description": "",
                    "recommendation-timestamp": "",
                    "status": "pending-removal",
                },
            ],
        },
    )
    respx.post(rpc(LCM_DOMAIN_MODULE, "get-lcm-domains")).mock(return_value=ok(body))
    text = await call_tool_text(reads, "cnc_list_lcm_domains", {})
    assert text.startswith("# LCM domains (2)")
    assert "- domain 7 — (no description): status pending-removal; last recommendation -" in text
    # pending-removal is not enabled: the disabled verdict stands.
    assert "LCM is disabled in every domain" in text


@respx.mock
async def test_list_lcm_domains_500_with_a_body_is_not_the_empty_500_hint(reads):
    """A 500 that carries a body (the NATS parse failure) falls through to http_error."""
    route = respx.post(rpc(LCM_DOMAIN_MODULE, "get-lcm-domains")).mock(return_value=NATS_500)
    text = await call_tool_text(reads, "cnc_list_lcm_domains", {})
    assert route.call_count == 1
    assert text.startswith("Error: API request failed with status 500.")
    assert "NATS request failed" in text
    assert "malformed request body" in text
    assert "rejected the request" not in text


@respx.mock
async def test_list_lcm_domains_response_result_error_inside_200(reads):
    respx.post(rpc(LCM_DOMAIN_MODULE, "get-lcm-domains")).mock(
        return_value=ok(out(LCM_DOMAIN_MODULE, **RESULT_ERROR))
    )
    text = await call_tool_text(reads, "cnc_list_lcm_domains", {})
    assert text == "Error: get-lcm-domains failed: response-result error: internal LCM error"


@respx.mock
async def test_list_lcm_domains_empty_500_names_the_backend(reads):
    route = respx.post(rpc(LCM_DOMAIN_MODULE, "get-lcm-domains")).mock(return_value=EMPTY_500)
    text = await call_tool_text(reads, "cnc_list_lcm_domains", {})
    assert route.call_count == 1  # a POST: never auto-retried
    assert text == f"Error: {empty_500_hint(BACKEND_SUSPECT)}"


@respx.mock
async def test_list_lcm_domains_http_error(reads):
    respx.post(rpc(LCM_DOMAIN_MODULE, "get-lcm-domains")).mock(
        return_value=httpx.Response(403, json={"message": "Unauthorized request"})
    )
    text = await call_tool_text(reads, "cnc_list_lcm_domains", {})
    assert text.startswith("Error: API request failed with status 403.")
    assert "Unauthorized request" in text


# --- cnc_get_lcm_config ------------------------------------------------------------------


@respx.mock
async def test_get_lcm_config_sends_domain_and_renders_knobs_plus_raw(reads):
    route = respx.post(rpc(FUNCTION_PACK_MODULE, "get-lcm-config")).mock(
        return_value=ok(CONFIG_OUT)
    )
    text = await call_tool_text(reads, "cnc_get_lcm_config", {})
    assert_yang_post(route)
    assert sent(route) == {"input": {"domain-id": "0"}}
    assert text.startswith("# LCM configuration of domain 0")
    assert "- enable: false" in text
    assert "- operation-mode: manual" in text
    assert "- optimization-objective: igp-metric" in text
    assert "- color: 2000" in text
    assert "- maximum-parallel-tactical-sr-policies: 1" in text
    assert "- utilization-threshold: 80" in text
    assert "- utilization-hold-margin: 5" in text
    assert "- over-provision-factor: 0" in text
    assert "- adjacency-hop-type: protected-preferred" in text
    assert "- auto-repair-solution: true" in text
    assert "- delete-tactical-sr-policies: true" in text
    assert "- history-retention-time: 30" in text
    assert "- congestion-check-interval: 600" in text
    # Leaves the document omits still reach the agent through the raw block.
    assert '"geo-ha-traffic-collection-hold-time": 180' in text
    assert "```json" in text


@respx.mock
async def test_get_lcm_config_other_domain_and_json(reads):
    route = respx.post(rpc(FUNCTION_PACK_MODULE, "get-lcm-config")).mock(
        return_value=ok(CONFIG_OUT)
    )
    text = await call_tool_text(
        reads, "cnc_get_lcm_config", {"domain_id": "1", "response_format": "json"}
    )
    assert sent(route) == {"input": {"domain-id": "1"}}
    assert json.loads(text) == CONFIG_OUT[f"{FUNCTION_PACK_MODULE}:output"]


@respx.mock
async def test_get_lcm_config_status_error_inside_200(reads):
    respx.post(rpc(FUNCTION_PACK_MODULE, "get-lcm-config")).mock(
        return_value=ok(out(FUNCTION_PACK_MODULE, **STATUS_ERROR))
    )
    text = await call_tool_text(reads, "cnc_get_lcm_config", {})
    assert text == "Error: get-lcm-config failed: failed to load LCM config"


@respx.mock
async def test_get_lcm_config_status_rejected_inside_200(reads):
    respx.post(rpc(FUNCTION_PACK_MODULE, "get-lcm-config")).mock(
        return_value=ok(out(FUNCTION_PACK_MODULE, **STATUS_REJECTED))
    )
    text = await call_tool_text(reads, "cnc_get_lcm_config", {})
    assert text == (
        "Error: get-lcm-config was rejected by the Optimization Engine: domain is pending removal"
    )


@respx.mock
async def test_get_lcm_config_empty_500_names_the_domain(reads):
    route = respx.post(rpc(FUNCTION_PACK_MODULE, "get-lcm-config")).mock(return_value=EMPTY_500)
    text = await call_tool_text(reads, "cnc_get_lcm_config", {"domain_id": "9"})
    assert route.call_count == 1
    assert text.startswith(
        "Error: the Optimization Engine rejected the request (unknown LCM domain? domain-id '9'"
    )
    assert text == f"Error: {empty_500_hint(domain_suspect('9'))}"


@respx.mock
async def test_get_lcm_config_non_json_body_is_error(reads):
    respx.post(rpc(FUNCTION_PACK_MODULE, "get-lcm-config")).mock(
        return_value=httpx.Response(200, text="<html>oops</html>")
    )
    text = await call_tool_text(reads, "cnc_get_lcm_config", {})
    assert text.startswith("Error: The Optimization Engine returned a non-JSON response")


# --- cnc_list_lcm_managed_interfaces --------------------------------------------------------


@respx.mock
async def test_list_lcm_managed_interfaces_verified_empty_answer(reads):
    route = respx.post(rpc(FUNCTION_PACK_MODULE, "get-lcm-managed-interfaces")).mock(
        return_value=ok(MANAGED_EMPTY)
    )
    text = await call_tool_text(reads, "cnc_list_lcm_managed_interfaces", {})
    assert_yang_post(route)
    assert sent(route) == {"input": {"domain-id": "0"}}
    assert text.startswith("No interfaces are managed by LCM in domain 0.")


@respx.mock
async def test_list_lcm_managed_interfaces_populated(reads):
    respx.post(rpc(FUNCTION_PACK_MODULE, "get-lcm-managed-interfaces")).mock(
        return_value=ok(MANAGED_OUT)
    )
    text = await call_tool_text(reads, "cnc_list_lcm_managed_interfaces", {"domain_id": "0"})
    assert text.startswith("# LCM managed interfaces of domain 0 (2)")
    assert f"- PE1:{GI0} — utilization-threshold 70%" in text
    assert f"- P1:{GI1} — utilization-threshold: the domain's default" in text


@respx.mock
async def test_list_lcm_managed_interfaces_json(reads):
    respx.post(rpc(FUNCTION_PACK_MODULE, "get-lcm-managed-interfaces")).mock(
        return_value=ok(MANAGED_EMPTY)
    )
    text = await call_tool_text(
        reads, "cnc_list_lcm_managed_interfaces", {"response_format": "json"}
    )
    assert json.loads(text) == {"status": "accepted"}


@respx.mock
async def test_list_lcm_managed_interfaces_status_error(reads):
    respx.post(rpc(FUNCTION_PACK_MODULE, "get-lcm-managed-interfaces")).mock(
        return_value=ok(out(FUNCTION_PACK_MODULE, **STATUS_ERROR))
    )
    text = await call_tool_text(reads, "cnc_list_lcm_managed_interfaces", {})
    assert text == "Error: get-lcm-managed-interfaces failed: failed to load LCM config"


@respx.mock
async def test_list_lcm_managed_interfaces_empty_500(reads):
    respx.post(rpc(FUNCTION_PACK_MODULE, "get-lcm-managed-interfaces")).mock(return_value=EMPTY_500)
    text = await call_tool_text(reads, "cnc_list_lcm_managed_interfaces", {"domain_id": "9"})
    assert text == f"Error: {empty_500_hint(domain_suspect('9'))}"


# --- cnc_get_lcm_recommendation -----------------------------------------------------------


@respx.mock
async def test_get_lcm_recommendation_verified_nothing_pending(reads):
    route = respx.post(rpc(LCM_RECOMMENDATION_MODULE, "get-lcm-recommendation")).mock(
        return_value=ok(RECOMMENDATION_NONE)
    )
    text = await call_tool_text(reads, "cnc_get_lcm_recommendation", {})
    assert_yang_post(route)
    assert sent(route) == {"input": {"domain-id": "0"}}
    assert text.startswith("No LCM recommendation is pending for domain 0 (urgency none)")
    assert not text.startswith("Error")


@respx.mock
async def test_get_lcm_recommendation_populated(reads):
    respx.post(rpc(LCM_RECOMMENDATION_MODULE, "get-lcm-recommendation")).mock(
        return_value=ok(RECOMMENDATION_OUT)
    )
    text = await call_tool_text(reads, "cnc_get_lcm_recommendation", {"domain_id": "0"})
    assert text.startswith("# LCM recommendation 1789293787548 for domain 0 (urgency high)")
    assert "- last-recommendation-timestamp: 2026-09-13T10:00:00Z" in text
    assert "## Solutions (1)" in text
    assert (
        f"- PE1:{GI0} — recommended-action create-set; lcm-state congested; utilization "
        "evaluation 92% / threshold 80% / expected 61%; policies-deployed 0; policy-set-status "
        "none; commit-status none; solution-timestamp 2026-09-13T10:00:00Z" in text
    )


@respx.mock
async def test_get_lcm_recommendation_json(reads):
    respx.post(rpc(LCM_RECOMMENDATION_MODULE, "get-lcm-recommendation")).mock(
        return_value=ok(RECOMMENDATION_NONE)
    )
    text = await call_tool_text(reads, "cnc_get_lcm_recommendation", {"response_format": "json"})
    assert json.loads(text) == RECOMMENDATION_NONE[f"{LCM_RECOMMENDATION_MODULE}:output"]


@respx.mock
async def test_get_lcm_recommendation_204_no_content_is_nothing_pending(reads):
    """The documented bodiless success: {} carries no id and no solutions -> not pending."""
    route = respx.post(rpc(LCM_RECOMMENDATION_MODULE, "get-lcm-recommendation")).mock(
        return_value=NO_CONTENT
    )
    text = await call_tool_text(reads, "cnc_get_lcm_recommendation", {"domain_id": "0"})
    assert route.call_count == 1
    assert text.startswith("No LCM recommendation is pending for domain 0 (urgency none)")
    assert not text.startswith("Error")


@respx.mock
async def test_get_lcm_recommendation_500_with_a_body_is_the_generic_api_failure(reads):
    respx.post(rpc(LCM_RECOMMENDATION_MODULE, "get-lcm-recommendation")).mock(return_value=NATS_500)
    text = await call_tool_text(reads, "cnc_get_lcm_recommendation", {"domain_id": "0"})
    assert text.startswith("Error: API request failed with status 500.")
    assert "NATS request failed" in text
    assert "unknown LCM domain" not in text


@respx.mock
async def test_get_lcm_recommendation_unknown_domain_empty_500(reads):
    """Verified live: get-lcm-recommendation with a domain-id that does not exist answers a
    bare 500 with an empty body."""
    route = respx.post(rpc(LCM_RECOMMENDATION_MODULE, "get-lcm-recommendation")).mock(
        return_value=EMPTY_500
    )
    text = await call_tool_text(reads, "cnc_get_lcm_recommendation", {"domain_id": "nope"})
    assert route.call_count == 1
    assert text.startswith(
        "Error: the Optimization Engine rejected the request (unknown LCM domain? domain-id "
        "'nope' was sent)"
    )
    assert "retrying with the same inputs will not help" in text


@respx.mock
async def test_get_lcm_recommendation_response_result_invalid(reads):
    respx.post(rpc(LCM_RECOMMENDATION_MODULE, "get-lcm-recommendation")).mock(
        return_value=ok(out(LCM_RECOMMENDATION_MODULE, **RESULT_INVALID))
    )
    text = await call_tool_text(reads, "cnc_get_lcm_recommendation", {})
    assert text == (
        "Error: get-lcm-recommendation failed: response-result invalid: no message given"
    )


# --- cnc_get_lcm_recommendation_preview ------------------------------------------------------

PREVIEW_ARGS = {"domain_id": "0", "recommendation_id": "1789293787548"}
# The default RPC: the 7.2 document says to use the MSL preview; the legacy one "will be
# deprecated". Same Input schema, same documented Output shape.
MSL_PREVIEW_URL = rpc(LCM_RECOMMENDATION_MODULE, RPC_GET_LCM_MSL_RECOMMENDATION_PREVIEW)
LEGACY_PREVIEW_URL = rpc(LCM_RECOMMENDATION_MODULE, RPC_GET_LCM_RECOMMENDATION_PREVIEW)


def test_preview_rpc_names_follow_the_document():
    assert RPC_GET_LCM_MSL_RECOMMENDATION_PREVIEW == "get-lcm-msl-recommendation-preview"
    assert RPC_GET_LCM_RECOMMENDATION_PREVIEW == "get-lcm-recommendation-preview"


@respx.mock
async def test_get_lcm_recommendation_preview_domain_wide_calls_the_msl_rpc(reads):
    legacy = respx.post(LEGACY_PREVIEW_URL).mock(return_value=ok(PREVIEW_OUT))
    route = respx.post(MSL_PREVIEW_URL).mock(return_value=ok(PREVIEW_OUT))
    text = await call_tool_text(reads, "cnc_get_lcm_recommendation_preview", PREVIEW_ARGS)
    assert route.call_count == 1
    assert legacy.call_count == 0
    assert_yang_post(route)
    assert sent(route) == {"input": {"domain-id": "0", "recommendation-id": "1789293787548"}}
    assert text.startswith(f"# LCM recommendation 1789293787548 preview for domain 0 (PE1:{GI0})")
    assert "- description: Mitigate PE1 GigabitEthernet0/0/0/0" in text
    assert "## Tactical SR policies (1)" in text
    assert "- tactical policy 1: policy-change create" in text
    assert (
        "  segment list: hop-ipv4-node-sid sid 16004 (topo-element uuid-p2) > "
        "hop-ipv4-node-sid sid 16003 (topo-element uuid-pe2)" in text
    )
    assert f"  igp-path: PE1:{GI1}, P2:{GI0}" in text
    assert "not yet verified" in text


@respx.mock
async def test_get_lcm_recommendation_preview_msl_false_calls_the_legacy_rpc(reads):
    """The legacy RPC stays reachable for a build without the MSL one; same body, same parser."""
    msl = respx.post(MSL_PREVIEW_URL).mock(return_value=ok(PREVIEW_OUT))
    route = respx.post(LEGACY_PREVIEW_URL).mock(return_value=ok(PREVIEW_OUT))
    text = await call_tool_text(
        reads, "cnc_get_lcm_recommendation_preview", {**PREVIEW_ARGS, "msl": False}
    )
    assert route.call_count == 1
    assert msl.call_count == 0
    assert sent(route) == {"input": {"domain-id": "0", "recommendation-id": "1789293787548"}}
    assert text.startswith(f"# LCM recommendation 1789293787548 preview for domain 0 (PE1:{GI0})")
    # The failure spelling names the RPC that was actually called.
    respx.post(LEGACY_PREVIEW_URL).mock(return_value=ok(PREVIEW_REFRESH))
    text = await call_tool_text(
        reads, "cnc_get_lcm_recommendation_preview", {**PREVIEW_ARGS, "msl": False}
    )
    assert text.startswith("Error: get-lcm-recommendation-preview: recommendation id")


@respx.mock
async def test_get_lcm_recommendation_preview_sends_lcm_int(reads):
    route = respx.post(MSL_PREVIEW_URL).mock(return_value=ok(PREVIEW_OUT))
    text = await call_tool_text(
        reads,
        "cnc_get_lcm_recommendation_preview",
        {**PREVIEW_ARGS, "node": "PE1", "interface": GI0, "response_format": "json"},
    )
    assert sent(route) == {
        "input": {
            "domain-id": "0",
            "recommendation-id": "1789293787548",
            "lcm-int": {"node": "PE1", "interface": GI0},
        }
    }
    assert json.loads(text) == PREVIEW_OUT[f"{LCM_RECOMMENDATION_MODULE}:output"]


@respx.mock
async def test_get_lcm_recommendation_preview_half_lcm_int_is_not_sent(reads):
    route = respx.post(MSL_PREVIEW_URL).mock(return_value=ok(PREVIEW_OUT))
    text = await call_tool_text(
        reads, "cnc_get_lcm_recommendation_preview", {**PREVIEW_ARGS, "node": "PE1"}
    )
    assert route.call_count == 0
    assert text.startswith("Error: node and interface go together")


@respx.mock
async def test_get_lcm_recommendation_preview_stale_id(reads):
    respx.post(MSL_PREVIEW_URL).mock(return_value=ok(PREVIEW_REFRESH))
    text = await call_tool_text(reads, "cnc_get_lcm_recommendation_preview", PREVIEW_ARGS)
    assert text.startswith(
        "Error: get-lcm-msl-recommendation-preview: recommendation id '1789293787548' is stale "
        "(rec-id-check refresh)"
    )
    assert "cnc_get_lcm_recommendation" in text
    assert text.endswith("Platform said: Recommendation has been updated")


@respx.mock
async def test_get_lcm_recommendation_preview_request_invalid(reads):
    respx.post(MSL_PREVIEW_URL).mock(return_value=ok(PREVIEW_INVALID))
    text = await call_tool_text(reads, "cnc_get_lcm_recommendation_preview", PREVIEW_ARGS)
    assert text == (
        "Error: get-lcm-msl-recommendation-preview was not accepted (request-check-result "
        "invalid): lcm-int not found in recommendation"
    )


@respx.mock
async def test_get_lcm_recommendation_preview_empty_500(reads):
    respx.post(MSL_PREVIEW_URL).mock(return_value=EMPTY_500)
    text = await call_tool_text(reads, "cnc_get_lcm_recommendation_preview", PREVIEW_ARGS)
    assert text == f"Error: {empty_500_hint(domain_suspect('0'))}"


@respx.mock
async def test_get_lcm_recommendation_preview_unknown_path_403_names_the_msl_fallback(reads):
    """An older build without the MSL RPC answers Tyk's 403 for the unknown path; the generic
    hint applies and the docstring tells the agent to retry with msl=false."""
    respx.post(MSL_PREVIEW_URL).mock(
        return_value=httpx.Response(403, json={"error": "Unauthorized request"})
    )
    text = await call_tool_text(reads, "cnc_get_lcm_recommendation_preview", PREVIEW_ARGS)
    assert text.startswith("Error: API request failed with status 403.")
    assert "Unauthorized request" in text


@respx.mock
async def test_get_lcm_recommendation_preview_no_policies(reads):
    body = out(
        LCM_RECOMMENDATION_MODULE, **{"response-result": "valid", "rec-id-check": "accepted"}
    )
    respx.post(MSL_PREVIEW_URL).mock(return_value=ok(body))
    text = await call_tool_text(reads, "cnc_get_lcm_recommendation_preview", PREVIEW_ARGS)
    assert text.startswith("# LCM recommendation 1789293787548 preview for domain 0\n")
    assert "- (the platform reported no tactical policy for this preview)" in text


@respx.mock
async def test_get_lcm_recommendation_preview_204_no_content(reads):
    """A bodiless success has no checks to fail and no policies: a plain empty preview."""
    respx.post(MSL_PREVIEW_URL).mock(return_value=NO_CONTENT)
    text = await call_tool_text(reads, "cnc_get_lcm_recommendation_preview", PREVIEW_ARGS)
    assert text.startswith("# LCM recommendation 1789293787548 preview for domain 0\n")
    assert "- (the platform reported no tactical policy for this preview)" in text


# --- cnc_list_csm_bandwidth_pools -------------------------------------------------------


@respx.mock
async def test_list_csm_bandwidth_pools_verified_empty_answer(reads):
    route = respx.post(rpc(CSM_CONFIG_MODULE, "get-csm-interfaces-bandwidth-pool")).mock(
        return_value=ok(POOLS_EMPTY)
    )
    text = await call_tool_text(reads, "cnc_list_csm_bandwidth_pools", {})
    assert_bodiless_post(route)
    assert text.startswith("No CSM interface bandwidth pools are configured.")


@respx.mock
async def test_list_csm_bandwidth_pools_populated(reads):
    respx.post(rpc(CSM_CONFIG_MODULE, "get-csm-interfaces-bandwidth-pool")).mock(
        return_value=ok(POOLS_OUT)
    )
    text = await call_tool_text(reads, "cnc_list_csm_bandwidth_pools", {})
    assert text.startswith("# CSM interface bandwidth pools (2)")
    assert f"- PE1:{GI0} — bandwidth-pool 80" in text
    assert f"- P1:{GI1} — bandwidth-pool 50" in text


@respx.mock
async def test_list_csm_bandwidth_pools_json(reads):
    respx.post(rpc(CSM_CONFIG_MODULE, "get-csm-interfaces-bandwidth-pool")).mock(
        return_value=ok(POOLS_EMPTY)
    )
    text = await call_tool_text(reads, "cnc_list_csm_bandwidth_pools", {"response_format": "json"})
    assert json.loads(text) == {"response-result": "valid"}


@respx.mock
async def test_list_csm_bandwidth_pools_response_result_error(reads):
    respx.post(rpc(CSM_CONFIG_MODULE, "get-csm-interfaces-bandwidth-pool")).mock(
        return_value=ok(out(CSM_CONFIG_MODULE, **RESULT_ERROR))
    )
    text = await call_tool_text(reads, "cnc_list_csm_bandwidth_pools", {})
    assert text == (
        "Error: get-csm-interfaces-bandwidth-pool failed: response-result error: internal LCM error"
    )


@respx.mock
async def test_list_csm_bandwidth_pools_empty_500(reads):
    respx.post(rpc(CSM_CONFIG_MODULE, "get-csm-interfaces-bandwidth-pool")).mock(
        return_value=EMPTY_500
    )
    text = await call_tool_text(reads, "cnc_list_csm_bandwidth_pools", {})
    assert text == f"Error: {empty_500_hint(BACKEND_SUSPECT)}"


@respx.mock
async def test_list_csm_bandwidth_pools_500_with_body_is_generic(reads):
    respx.post(rpc(CSM_CONFIG_MODULE, "get-csm-interfaces-bandwidth-pool")).mock(
        return_value=NATS_500
    )
    text = await call_tool_text(reads, "cnc_list_csm_bandwidth_pools", {})
    assert text.startswith("Error: API request failed with status 500.")
    assert "NATS request failed" in text
    assert "rejected the request" not in text


# --- the documented "204 No response" success on the remaining reads -----------------------


@pytest.mark.parametrize(
    ("module", "name", "tool", "args", "expected"),
    [
        (
            FUNCTION_PACK_MODULE,
            "get-lcm-config",
            "cnc_get_lcm_config",
            {},
            "- (none of the usual configuration leaves was reported)",
        ),
        (
            FUNCTION_PACK_MODULE,
            "get-lcm-managed-interfaces",
            "cnc_list_lcm_managed_interfaces",
            {"domain_id": "0"},
            "No interfaces are managed by LCM in domain 0.",
        ),
        (
            CSM_CONFIG_MODULE,
            "get-csm-interfaces-bandwidth-pool",
            "cnc_list_csm_bandwidth_pools",
            {},
            "No CSM interface bandwidth pools are configured.",
        ),
        (
            CSM_POLICY_MODULE,
            "all-cs-policy-paths",
            "cnc_list_cs_policy_paths",
            {"include_paths_without_hops": True},
            "No Circuit-Style SR policies are reported.",
        ),
    ],
)
@respx.mock
async def test_204_no_content_is_the_empty_answer(reads, module, name, tool, args, expected):
    route = respx.post(rpc(module, name)).mock(return_value=NO_CONTENT)
    text = await call_tool_text(reads, tool, args)
    assert route.call_count == 1
    assert not text.startswith("Error")
    assert expected in text


# --- cnc_list_cs_policy_paths ----------------------------------------------------------


@respx.mock
async def test_list_cs_policy_paths_verified_empty_answer(reads):
    route = respx.post(rpc(CSM_POLICY_MODULE, "all-cs-policy-paths")).mock(
        return_value=ok(ALL_PATHS_EMPTY)
    )
    text = await call_tool_text(reads, "cnc_list_cs_policy_paths", {})
    assert_yang_post(route)
    assert sent(route) == {"input": {"paths-with-no-hops": False}}
    assert text.startswith("No Circuit-Style SR policies are reported.")
    assert "include_paths_without_hops=true" in text


@respx.mock
async def test_list_cs_policy_paths_include_paths_without_hops(reads):
    route = respx.post(rpc(CSM_POLICY_MODULE, "all-cs-policy-paths")).mock(
        return_value=ok(ALL_PATHS_EMPTY)
    )
    text = await call_tool_text(
        reads, "cnc_list_cs_policy_paths", {"include_paths_without_hops": True}
    )
    assert sent(route) == {"input": {"paths-with-no-hops": True}}
    assert text == "No Circuit-Style SR policies are reported."


@respx.mock
async def test_list_cs_policy_paths_populated(reads):
    respx.post(rpc(CSM_POLICY_MODULE, "all-cs-policy-paths")).mock(return_value=ok(ALL_PATHS_OUT))
    text = await call_tool_text(reads, "cnc_list_cs_policy_paths", {})
    assert text.startswith("# Circuit-Style SR policy paths (2)")
    assert "- 10.0.0.1 -> 10.0.0.3 color 1000 preference 100 — operational-state up" in text
    assert "- 10.0.0.1 -> 10.0.0.3 color 1000 preference 50 — operational-state down" in text


@respx.mock
async def test_list_cs_policy_paths_json(reads):
    respx.post(rpc(CSM_POLICY_MODULE, "all-cs-policy-paths")).mock(return_value=ok(ALL_PATHS_OUT))
    text = await call_tool_text(reads, "cnc_list_cs_policy_paths", {"response_format": "json"})
    assert json.loads(text) == ALL_PATHS_OUT[f"{CSM_POLICY_MODULE}:output"]


@respx.mock
async def test_list_cs_policy_paths_status_error(reads):
    respx.post(rpc(CSM_POLICY_MODULE, "all-cs-policy-paths")).mock(
        return_value=ok(out(CSM_POLICY_MODULE, status="error", message="CSM not ready"))
    )
    text = await call_tool_text(reads, "cnc_list_cs_policy_paths", {})
    assert text == "Error: all-cs-policy-paths failed: CSM not ready"


@respx.mock
async def test_list_cs_policy_paths_empty_500(reads):
    respx.post(rpc(CSM_POLICY_MODULE, "all-cs-policy-paths")).mock(return_value=EMPTY_500)
    text = await call_tool_text(reads, "cnc_list_cs_policy_paths", {})
    assert text.startswith(
        "Error: the Optimization Engine rejected the request (the CSM backend is absent or down"
    )


# --- cnc_list_cs_policies_on_nodes ------------------------------------------------------


ON_NODES_URL = rpc(CSM_POLICY_MODULE, "cs-policy-paths-on-nodes")


@respx.mock
async def test_list_cs_policies_on_nodes_verified_answer(reads):
    networks = mock_networks()
    route = respx.post(ON_NODES_URL).mock(return_value=ok(ON_NODES_OUT))
    text = await call_tool_text(reads, "cnc_list_cs_policies_on_nodes", {"nodes": "PE1"})
    # One topology GET (yang-data+json) to resolve the names, then the RPC.
    assert networks.call_count == 1
    assert networks.calls[0].request.headers["Accept"] == YANG_JSON
    assert_yang_post(route)
    assert sent(route) == {"input": {"nodes": [{"node": "PE1"}]}}
    assert text.startswith("# Circuit-Style SR policies on PE1")
    assert "## PE1 — operational-state active (0 CS policy paths)" in text
    assert "- (none)" in text
    assert "0 CS policy path(s) in total" in text


@respx.mock
async def test_list_cs_policies_on_nodes_resolves_case_and_router_ids_to_node_ids(reads):
    """'pe1' and a router-id go on the wire as the topology's exact node ids, and the markdown
    sections are keyed on those ids (so the platform's echo 'PE1' matches 'pe1')."""
    mock_networks()
    route = respx.post(ON_NODES_URL).mock(return_value=ok(ON_NODES_WITH_PATHS))
    text = await call_tool_text(
        reads, "cnc_list_cs_policies_on_nodes", {"nodes": " pe1, 10.0.0.2 ,PE2"}
    )
    assert sent(route) == {"input": {"nodes": [{"node": "PE1"}, {"node": "P1"}, {"node": "PE2"}]}}
    assert text.startswith("# Circuit-Style SR policies on PE1, P1, PE2")
    assert "## PE1 — operational-state active (1 CS policy paths)" in text
    assert "- 10.0.0.1 -> 10.0.0.3 color 1000 preference 100 — operational-state up" in text
    assert "## P1 — operational-state active (0 CS policy paths)" in text
    assert "  message: no CS policies" in text
    # A resolved node the CSM answered nothing for is reported, not silently dropped.
    assert "## PE2 — (the Optimization Engine returned no entry)" in text
    assert "## pe1" not in text
    assert "1 CS policy path(s) in total" in text


@respx.mock
async def test_list_cs_policies_on_nodes_unknown_node_is_refused_before_the_rpc(reads):
    mock_networks()
    route = respx.post(ON_NODES_URL).mock(return_value=ok(ON_NODES_OUT))
    text = await call_tool_text(reads, "cnc_list_cs_policies_on_nodes", {"nodes": "PE1,P9"})
    assert route.call_count == 0
    assert text.startswith("Error: no node 'P9' in the topology")
    assert "cnc_list_topology_nodes" in text


@respx.mock
async def test_list_cs_policies_on_nodes_no_networks_is_error_before_the_rpc(reads):
    mock_networks(NO_NETWORKS)
    route = respx.post(ON_NODES_URL).mock(return_value=ok(ON_NODES_OUT))
    text = await call_tool_text(reads, "cnc_list_cs_policies_on_nodes", {"nodes": "PE1"})
    assert route.call_count == 0
    assert text.startswith("Error: the topology NBI reports no networks yet")
    assert "Circuit-Style Manager" in text


@respx.mock
async def test_list_cs_policies_on_nodes_unknown_network_lists_the_present_ones(reads):
    mock_networks()
    route = respx.post(ON_NODES_URL).mock(return_value=ok(ON_NODES_OUT))
    text = await call_tool_text(
        reads, "cnc_list_cs_policies_on_nodes", {"nodes": "PE1", "network": "other"}
    )
    assert route.call_count == 0
    assert text.startswith(
        "Error: no network 'other' on the topology NBI. Networks present: Default-network."
    )


@respx.mock
async def test_list_cs_policies_on_nodes_tolerates_the_cs_policies_alias(reads):
    """The document names the per-node list cs-policy-paths; a build spelling it cs-policies
    still renders its paths."""
    mock_networks()
    body = out(
        CSM_POLICY_MODULE,
        status="accepted",
        **{
            "node-cs-policies": [
                {"node": "PE1", "operational-state": "active", "cs-policies": [CS_PATH_WORKING]}
            ]
        },
    )
    respx.post(ON_NODES_URL).mock(return_value=ok(body))
    text = await call_tool_text(reads, "cnc_list_cs_policies_on_nodes", {"nodes": "PE1"})
    assert "## PE1 — operational-state active (1 CS policy paths)" in text
    assert "- 10.0.0.1 -> 10.0.0.3 color 1000 preference 100 — operational-state up" in text
    assert "1 CS policy path(s) in total" in text


@respx.mock
async def test_list_cs_policies_on_nodes_json(reads):
    mock_networks()
    respx.post(ON_NODES_URL).mock(return_value=ok(ON_NODES_OUT))
    text = await call_tool_text(
        reads, "cnc_list_cs_policies_on_nodes", {"nodes": "PE1", "response_format": "json"}
    )
    assert json.loads(text) == ON_NODES_OUT[f"{CSM_POLICY_MODULE}:output"]


@respx.mock
async def test_list_cs_policies_on_nodes_blank_names_not_sent(reads):
    networks = mock_networks()
    route = respx.post(ON_NODES_URL).mock(return_value=ok(ON_NODES_OUT))
    text = await call_tool_text(reads, "cnc_list_cs_policies_on_nodes", {"nodes": " , "})
    assert networks.call_count == 0
    assert route.call_count == 0
    assert text.startswith("Error: nodes is empty")


@respx.mock
async def test_list_cs_policies_on_nodes_empty_500_names_the_resolved_nodes(reads):
    """The names resolved in the topology, so the residual empty 500 says the CSM did not."""
    mock_networks()
    route = respx.post(ON_NODES_URL).mock(return_value=EMPTY_500)
    text = await call_tool_text(reads, "cnc_list_cs_policies_on_nodes", {"nodes": "pe1,P1"})
    assert route.call_count == 1  # a POST: never auto-retried
    assert text == f"Error: {empty_500_hint(names_suspect(['PE1', 'P1']))}"
    assert (
        "the CSM did not resolve a name the topology knows? sent, as the topology spells "
        "them: PE1, P1" in text
    )
    assert "absent or down" in text


@respx.mock
async def test_list_cs_policies_on_nodes_204_no_content(reads):
    mock_networks()
    respx.post(ON_NODES_URL).mock(return_value=NO_CONTENT)
    text = await call_tool_text(reads, "cnc_list_cs_policies_on_nodes", {"nodes": "PE1"})
    assert not text.startswith("Error")
    assert "## PE1 — (the Optimization Engine returned no entry)" in text
    assert "0 CS policy path(s) in total" in text


@respx.mock
async def test_list_cs_policies_on_nodes_status_error(reads):
    mock_networks()
    respx.post(ON_NODES_URL).mock(
        return_value=ok(out(CSM_POLICY_MODULE, status="error", message="node PE2 unknown"))
    )
    text = await call_tool_text(reads, "cnc_list_cs_policies_on_nodes", {"nodes": "PE2"})
    assert text == "Error: cs-policy-paths-on-nodes failed: node PE2 unknown"


@respx.mock
async def test_list_cs_policies_on_nodes_topology_failure_is_reported_before_the_rpc(reads):
    respx.get(NETWORKS_URL).mock(
        return_value=httpx.Response(403, json={"error": "Unauthorized request"})
    )
    route = respx.post(ON_NODES_URL).mock(return_value=ok(ON_NODES_OUT))
    text = await call_tool_text(reads, "cnc_list_cs_policies_on_nodes", {"nodes": "PE1"})
    assert route.call_count == 0
    assert text.startswith("Error: API request failed with status 403.")


# --- cnc_list_cs_policies_on_interface ----------------------------------------------------

INTERFACE_ARGS = {"node": "PE1", "interface": GI0}
ON_INTERFACE_URL = rpc(CSM_POLICY_MODULE, "cs-policy-paths-on-interface")


@respx.mock
async def test_list_cs_policies_on_interface_verified_answer(reads):
    networks = mock_networks()
    route = respx.post(ON_INTERFACE_URL).mock(return_value=ok(ON_INTERFACE_OUT))
    text = await call_tool_text(reads, "cnc_list_cs_policies_on_interface", INTERFACE_ARGS)
    assert networks.call_count == 1
    assert_yang_post(route)
    assert sent(route) == {"input": {"interfaces": [{"node": "PE1", "interface": GI0}]}}
    assert text.startswith(f"# Circuit-Style SR policies on PE1:{GI0}")
    assert f"## PE1:{GI0} — operational-state up (0 CS policy paths)" in text
    assert "- (none)" in text


@respx.mock
async def test_list_cs_policies_on_interface_resolves_router_id_and_interface_case(reads):
    """A router-id becomes the node id and a case-insensitive unique interface match is sent
    in the topology's exact spelling."""
    mock_networks()
    route = respx.post(ON_INTERFACE_URL).mock(return_value=ok(ON_INTERFACE_OUT))
    text = await call_tool_text(
        reads,
        "cnc_list_cs_policies_on_interface",
        {"node": "10.0.0.1", "interface": "gigabitethernet0/0/0/0"},
    )
    assert sent(route) == {"input": {"interfaces": [{"node": "PE1", "interface": GI0}]}}
    assert text.startswith(f"# Circuit-Style SR policies on PE1:{GI0}")


@respx.mock
async def test_list_cs_policies_on_interface_unknown_interface_lists_them_and_skips_the_rpc(
    reads,
):
    mock_networks()
    route = respx.post(ON_INTERFACE_URL).mock(return_value=ok(ON_INTERFACE_OUT))
    text = await call_tool_text(
        reads, "cnc_list_cs_policies_on_interface", {"node": "PE1", "interface": "Gi0/0/0/0"}
    )
    assert route.call_count == 0
    assert text.startswith("Error: no interface 'Gi0/0/0/0' on node 'PE1' in the topology.")
    assert f"{GI0}, {GI1}, Loopback0" in text
    assert "cnc_list_node_interfaces" in text


@respx.mock
async def test_list_cs_policies_on_interface_unknown_node_skips_the_rpc(reads):
    mock_networks()
    route = respx.post(ON_INTERFACE_URL).mock(return_value=ok(ON_INTERFACE_OUT))
    text = await call_tool_text(
        reads, "cnc_list_cs_policies_on_interface", {"node": "P9", "interface": GI0}
    )
    assert route.call_count == 0
    assert text.startswith("Error: no node 'P9' in the topology")


@respx.mock
async def test_list_cs_policies_on_interface_with_paths_and_json(reads):
    mock_networks()
    body = out(
        CSM_POLICY_MODULE,
        status="accepted",
        **{
            "link-cs-policies": [
                {
                    "node": "PE1",
                    "interface": GI0,
                    "operational-state": "up",
                    "cs-policy-paths": [CS_PATH_WORKING],
                }
            ]
        },
    )
    respx.post(ON_INTERFACE_URL).mock(return_value=ok(body))
    text = await call_tool_text(reads, "cnc_list_cs_policies_on_interface", INTERFACE_ARGS)
    assert f"## PE1:{GI0} — operational-state up (1 CS policy paths)" in text
    assert "- 10.0.0.1 -> 10.0.0.3 color 1000 preference 100 — operational-state up" in text
    text = await call_tool_text(
        reads, "cnc_list_cs_policies_on_interface", {**INTERFACE_ARGS, "response_format": "json"}
    )
    assert json.loads(text) == body[f"{CSM_POLICY_MODULE}:output"]


@respx.mock
async def test_list_cs_policies_on_interface_cs_policies_alias(reads):
    mock_networks()
    body = out(
        CSM_POLICY_MODULE,
        **{
            "link-cs-policies": [
                {
                    "node": "PE1",
                    "interface": GI0,
                    "operational-state": "up",
                    "cs-policies": [CS_PATH_WORKING, CS_PATH_PROTECT],
                }
            ]
        },
    )
    respx.post(ON_INTERFACE_URL).mock(return_value=ok(body))
    text = await call_tool_text(reads, "cnc_list_cs_policies_on_interface", INTERFACE_ARGS)
    assert f"## PE1:{GI0} — operational-state up (2 CS policy paths)" in text
    assert "preference 50 — operational-state down" in text


@respx.mock
async def test_list_cs_policies_on_interface_no_entry(reads):
    mock_networks()
    respx.post(ON_INTERFACE_URL).mock(return_value=ok(out(CSM_POLICY_MODULE, status="accepted")))
    text = await call_tool_text(reads, "cnc_list_cs_policies_on_interface", INTERFACE_ARGS)
    assert "- (the Optimization Engine returned no entry)" in text


@respx.mock
async def test_list_cs_policies_on_interface_204_no_content(reads):
    mock_networks()
    respx.post(ON_INTERFACE_URL).mock(return_value=NO_CONTENT)
    text = await call_tool_text(reads, "cnc_list_cs_policies_on_interface", INTERFACE_ARGS)
    assert not text.startswith("Error")
    assert "- (the Optimization Engine returned no entry)" in text


@respx.mock
async def test_list_cs_policies_on_interface_blank_not_sent(reads):
    networks = mock_networks()
    route = respx.post(ON_INTERFACE_URL).mock(return_value=ok(ON_INTERFACE_OUT))
    text = await call_tool_text(
        reads, "cnc_list_cs_policies_on_interface", {"node": "PE1", "interface": " "}
    )
    assert networks.call_count == 0
    assert route.call_count == 0
    assert text.startswith("Error: node and interface are required")


@respx.mock
async def test_list_cs_policies_on_interface_empty_500(reads):
    mock_networks()
    respx.post(ON_INTERFACE_URL).mock(return_value=EMPTY_500)
    text = await call_tool_text(reads, "cnc_list_cs_policies_on_interface", INTERFACE_ARGS)
    assert text == f"Error: {empty_500_hint(names_suspect([f'PE1:{GI0}']))}"


@respx.mock
async def test_list_cs_policies_on_interface_500_with_body_is_generic(reads):
    mock_networks()
    respx.post(ON_INTERFACE_URL).mock(return_value=NATS_500)
    text = await call_tool_text(reads, "cnc_list_cs_policies_on_interface", INTERFACE_ARGS)
    assert text.startswith("Error: API request failed with status 500.")
    assert "NATS request failed" in text
    assert "rejected the request" not in text


@respx.mock
async def test_list_cs_policies_on_interface_status_rejected(reads):
    mock_networks()
    respx.post(ON_INTERFACE_URL).mock(
        return_value=ok(out(CSM_POLICY_MODULE, status="rejected", message="bad interface"))
    )
    text = await call_tool_text(reads, "cnc_list_cs_policies_on_interface", INTERFACE_ARGS)
    assert text == (
        "Error: cs-policy-paths-on-interface was rejected by the Optimization Engine: bad interface"
    )


# --- cnc_pause_lcm_recommendations (write) ------------------------------------------------

PAUSE_URL = rpc(LCM_RECOMMENDATION_MODULE, "set-lcm-recommendation-pause")


@respx.mock
async def test_pause_domain_wide(writes):
    route = respx.post(PAUSE_URL).mock(return_value=ok(PAUSE_OUT))
    text = await call_tool_text(
        writes, "cnc_pause_lcm_recommendations", {"domain_id": "0", "paused": True}
    )
    assert route.call_count == 1  # a POST: never auto-retried
    assert_yang_post(route)
    assert sent(route) == {"input": {"domain-id": "0", "pause-state": True}}
    assert text.startswith("LCM recommendations are now paused in domain 0.")
    assert "cnc_get_lcm_recommendation" in text
    assert '"pause-state": true' in text


@respx.mock
async def test_pause_one_interface_and_resume(writes):
    body = out(LCM_RECOMMENDATION_MODULE, **{"response-result": "valid", "pause-state": False})
    route = respx.post(PAUSE_URL).mock(return_value=ok(body))
    text = await call_tool_text(
        writes,
        "cnc_pause_lcm_recommendations",
        {"domain_id": "0", "paused": False, "node": "PE1", "interface": GI0},
    )
    assert sent(route) == {
        "input": {
            "domain-id": "0",
            "pause-state": False,
            "lcm-int": {"node": "PE1", "interface": GI0},
        }
    }
    assert text.startswith(f"LCM recommendations are now resumed in domain 0 for PE1:{GI0}.")


@respx.mock
async def test_pause_half_lcm_int_is_not_sent(writes):
    route = respx.post(PAUSE_URL).mock(return_value=ok(PAUSE_OUT))
    text = await call_tool_text(
        writes,
        "cnc_pause_lcm_recommendations",
        {"domain_id": "0", "paused": True, "interface": GI0},
    )
    assert route.call_count == 0
    assert text.startswith("Error: node and interface go together")


@respx.mock
async def test_pause_answer_disagrees_is_error(writes):
    respx.post(PAUSE_URL).mock(return_value=ok(PAUSE_DISAGREES))
    text = await call_tool_text(
        writes, "cnc_pause_lcm_recommendations", {"domain_id": "0", "paused": True}
    )
    assert text.startswith(
        "Error: the platform accepted the change but reports pause-state false (wanted true) "
        "for domain 0."
    )


@respx.mock
async def test_pause_without_boolean_state_reports_raw_answer(writes):
    respx.post(PAUSE_URL).mock(
        return_value=ok(out(LCM_RECOMMENDATION_MODULE, **{"response-result": "valid"}))
    )
    text = await call_tool_text(
        writes, "cnc_pause_lcm_recommendations", {"domain_id": "0", "paused": True}
    )
    assert text.startswith("The change to paused in domain 0 was accepted;")
    assert not text.startswith("Error")


@respx.mock
async def test_pause_request_invalid_is_error(writes):
    respx.post(PAUSE_URL).mock(return_value=ok(PAUSE_INVALID))
    text = await call_tool_text(
        writes, "cnc_pause_lcm_recommendations", {"domain_id": "0", "paused": True}
    )
    assert text == (
        "Error: set-lcm-recommendation-pause was not accepted (request-check-result invalid): "
        "LCM is disabled in domain 0"
    )


@respx.mock
async def test_pause_response_result_error_inside_200(writes):
    respx.post(PAUSE_URL).mock(return_value=ok(out(LCM_RECOMMENDATION_MODULE, **RESULT_ERROR)))
    text = await call_tool_text(
        writes, "cnc_pause_lcm_recommendations", {"domain_id": "0", "paused": True}
    )
    assert text == (
        "Error: set-lcm-recommendation-pause failed: response-result error: internal LCM error"
    )


@respx.mock
async def test_pause_empty_500_names_the_domain(writes):
    route = respx.post(PAUSE_URL).mock(return_value=EMPTY_500)
    text = await call_tool_text(
        writes, "cnc_pause_lcm_recommendations", {"domain_id": "9", "paused": True}
    )
    assert route.call_count == 1
    assert text == f"Error: {empty_500_hint(domain_suspect('9'))}"


async def test_pause_hidden_when_writes_disabled(reads):
    names = {t.name for t in await reads.list_tools()}
    assert "cnc_pause_lcm_recommendations" not in names
