"""SR-TE operations tools end-to-end through MCPServer (schema validation included).

The module is registered directly (not through build_server) so the test does
not depend on tools/__init__.py's module list. All HTTP is mocked with respx.
Fixtures mirror what was verified live on Crosswork 7.2 (2026-09-13, SR-PCE
gRPC feed up, full create/modify/delete cycle — see the platform notes): the
``ietf-network-state:networks`` COLLECTION with the four SR nodes (PE1
10.0.0.1/16001, P1 10.0.0.2/16002, PE2 10.0.0.3/16003, P2 10.0.0.4/16004,
each with its ``<router-id>/32`` prefix-SID entry and termination points), the
COE read outputs (``status`` + per-item ``path-computation-status``,
``interface-use`` as the string "0.5"), the dry-run / create / modify / delete
``results[]`` outputs with the verified failure messages, and the 409
``data-missing`` document of the topology NBI.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx
from mcp.server.mcpserver import MCPServer

from cnc_mcp import polling
from cnc_mcp.auth import StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.config import Settings
from cnc_mcp.errors import PlatformError
from cnc_mcp.restconf import EMPTY_500_EXPLANATION
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import sr_te_operations
from cnc_mcp.tools.sr_te_operations import (
    COE_EMPTY_500_HINT,
    ResolvedNode,
    build_policy_path,
    coe_url,
    explicit_hops,
    find_node,
    node_prefix_sid,
    normalize_relation,
    parse_names,
    pcep_flag_c,
    policy_key,
    require_sr,
    resolve_interface,
    resolve_node,
    select_router_id,
    srp_url,
    write_outcome,
)
from tests.conftest import BASE_URL, call_tool_text

YANG_JSON = "application/yang-data+json"
OPERATIONS = f"{BASE_URL}/crosswork/nbi/optimization/v3/restconf/operations"
COE = "cisco-crosswork-optimization-engine-operations"
SRP = "cisco-crosswork-optimization-engine-sr-policy-operations"
TOPOLOGY_DATA = f"{BASE_URL}/crosswork/nbi/topology/v3/restconf/data"
NETWORKS_URL = f"{TOPOLOGY_DATA}/ietf-network-state:networks"
SR_POLICIES_URL = f"{TOPOLOGY_DATA}/cisco-crosswork-segment-routing-policy:sr-policies"


def coe(rpc: str) -> str:
    return f"{OPERATIONS}/{COE}:{rpc}"


def srp(rpc: str) -> str:
    return f"{OPERATIONS}/{SRP}:{rpc}"


def policy_url(headend: str, endpoint: str, color: int) -> str:
    return f"{SR_POLICIES_URL}/policy={headend},{endpoint},{color}"


# --- topology fixture (the verified networks-collection shape) ----------------------

TP_LIST = "ietf-network-topology-state:termination-point"
TP_ATTRS = "cisco-crosswork-topology-state:termination-point-attributes"
L3_NODE = "ietf-l3-unicast-topology-state:l3-node-attributes"
SR_MPLS = "ietf-sr-mpls-topology-state:sr-mpls"
SPF_ALGORITHM = "ietf-segment-routing-common:prefix-sid-algorithm-shortest-path"
GI0 = "GigabitEthernet0/0/0/0"
GI1 = "GigabitEthernet0/0/0/1"


def tp(tp_id: str) -> dict[str, Any]:
    return {
        "tp-id": tp_id,
        TP_ATTRS: {"l2-termination-point-attributes": {"encapsulation-type": "ethernet"}},
    }


def sr_node(node_id: str, index: int, extra_prefixes: list[dict[str, Any]] | None = None) -> dict:
    """A node as the collection GET lists it: router-id, SRGB and the /32 prefix-SID."""
    router_id = f"10.0.0.{index}"
    return {
        "node-id": node_id,
        TP_LIST: [tp(GI0), tp(GI1), tp("Loopback0")],
        L3_NODE: {
            "name": node_id,
            "router-id": [router_id],
            SR_MPLS: {"srgb": [{"lower-bound": 16000, "upper-bound": 23999}], "msd": 10},
            "prefix": [
                # A connected prefix without a SID, listed first on purpose.
                {"prefix": f"10.1.{index}.0/30"},
                {
                    "prefix": f"{router_id}/32",
                    # verified shape: an SRGB index, not a label (16000 + index on the wire)
                    SR_MPLS: [
                        {
                            "algorithm-value": 0,
                            "algorithm": SPF_ALGORITHM,
                            "value-type": "index",
                            "is-local": False,
                            "range": 1,
                            "last-hop-behavior": "php",
                            "is-node": True,
                            "start-sid": index,
                        }
                    ],
                },
            ]
            + (extra_prefixes or []),
        },
    }


PE1 = sr_node("PE1", 1)
P1 = sr_node("P1", 2)
PE2 = sr_node("PE2", 3)
P2 = sr_node("P2", 4)
# A node the topology knows but the account has no permission for (verified message).
P3 = sr_node("P3", 99)
# An LLDP-only node: no l3-node-attributes at all (the feed does not know it as SR).
LLDP_ONLY = {"node-id": "SW1", TP_LIST: [tp(GI0)]}
NODES = [PE1, P1, PE2, P2, P3, LLDP_ONLY]
NETWORK = {"network-id": "Default-network", "node": NODES}
NETWORKS = {"ietf-network-state:networks": {"network": [NETWORK]}}
NO_NETWORKS: dict = {}

# --- verified RPC outputs -----------------------------------------------------------

KEY_PE1_PE2 = {"head-end": "10.0.0.1", "end-point": "10.0.0.3", "color": 100}
KEY_PE2_PE1 = {"head-end": "10.0.0.3", "end-point": "10.0.0.1", "color": 100}


def coe_out(**fields: Any) -> dict:
    return {f"{COE}:output": {"status": "accepted", **fields}}


def srp_out(**fields: Any) -> dict:
    return {f"{SRP}:output": fields}


ON_NODE_OUT = coe_out(
    **{
        "node-sr-policies": [
            {"node": "PE1", "message": "", "sr-policies": [KEY_PE1_PE2, KEY_PE2_PE1]},
            {"node": "P1", "message": "No SR policies found for node P1", "sr-policies": []},
        ]
    }
)
ON_INTERFACE_OUT = coe_out(
    **{
        "interface-sr-policies": [
            {"node": "P1", "interface": GI0, "message": "", "sr-policies": [KEY_PE2_PE1]}
        ]
    }
)
ROUTE = [
    {"node": "PE1", "interface": GI0, "interface-use": "0.5"},
    {"node": "PE1", "interface": GI1, "interface-use": "0.5"},
    {"node": "P1", "interface": GI1, "interface-use": "0.5"},
    {"node": "P2", "interface": GI0, "interface-use": "0.5"},
]
ROUTES_OUT = coe_out(
    results=[{**KEY_PE1_PE2, "path-computation-status": "success", "igp-route": ROUTE}]
)
ROUTES_FAILURE_OUT = coe_out(
    results=[{"head-end": "10.0.0.1", "end-point": "10.0.0.3", "color": 999,
              "path-computation-status": "failure"}]
)  # fmt: skip
METRICS_OUT = coe_out(
    results=[
        {
            **KEY_PE1_PE2,
            "path-computation-status": "success",
            "igp-metric": 20,
            "te-metric": 20,
            "delay": 20,
        }
    ]
)
METRICS_FAILURE_OUT = coe_out(
    results=[{**KEY_PE1_PE2, "color": 999, "path-computation-status": "failure"}]
)
PREVIEW_OUT = coe_out(
    **{
        "path-computation-status": "success",
        "igp-route": [
            {"node": "PE1", "interface": GI1, "interface-use": "1"},
            {"node": "P2", "interface": GI0, "interface-use": "1"},
        ],
    }
)
PREVIEW_FAILURE_OUT = coe_out(**{"path-computation-status": "failure"})
STATUS_ERROR_OUT = {
    f"{COE}:output": {"status": "error", "message": "failed to export network: Abort"}
}
NOTIFICATIONS_ENABLED = coe_out(enabled=True)
NOTIFICATIONS_DISABLED = coe_out(enabled=False)
SET_ACCEPTED = coe_out()

DRYRUN_SUCCESS = srp_out(
    state="success",
    **{
        "segment-list-hops": [
            {"step": 0, "sid": 16004, "ip-address": "10.0.0.4", "type": "node-ipv4"},
            {"step": 1, "sid": 16003, "ip-address": "10.0.0.3", "type": "node-ipv4"},
        ],
        "igp-route": [{"node": "PE1", "interface": GI1}, {"node": "P2", "interface": GI0}],
    },
)
NO_PATH_MESSAGE = "No path found for the given constraints. "
BWOD_MESSAGE = "Bandwidth On Demand currently dormant: disabled"
SID_ONLY_MESSAGE = "There is not enough info to lookup for node hop_type: HOP_IPV4_NODE_SID"
DRYRUN_NO_PATH = srp_out(state="failure", message=NO_PATH_MESSAGE)
DRYRUN_BWOD = srp_out(state="failure", message=BWOD_MESSAGE)
DRYRUN_DEGRADED = srp_out(
    state="degraded",
    message="Path computed with relaxed constraints",
    **{"segment-list-hops": [], "igp-route": []},
)

DUPLICATE_MESSAGE = "An SR Policy with same color, headend and endpoint already exists."
NO_PERMISSION_MESSAGE = (
    "No permission for device 10.0.0.99. Contact your administrator for permissions."
)
UNKNOWN_POLICY_MESSAGE = "Policy does not exist in the system to update."


def write_result(headend: str, endpoint: str, color: int, state: str, message: str = "") -> dict:
    return srp_out(
        results=[
            {"head-end": headend, "end-point": endpoint, "color": color, "state": state,
             "message": message}
        ]
    )  # fmt: skip


CREATE_SUCCESS = write_result("10.0.0.1", "10.0.0.3", 200, "success")
CREATE_DUPLICATE = write_result("10.0.0.1", "10.0.0.3", 100, "failure", DUPLICATE_MESSAGE)
CREATE_NO_PERMISSION = write_result("10.0.0.99", "10.0.0.3", 200, "failure", NO_PERMISSION_MESSAGE)
MODIFY_SUCCESS = write_result("10.0.0.1", "10.0.0.3", 200, "success")
MODIFY_UNKNOWN = write_result("10.0.0.1", "10.0.0.3", 555, "failure", UNKNOWN_POLICY_MESSAGE)
DELETE_SUCCESS = write_result("10.0.0.1", "10.0.0.3", 200, "success")
DELETE_FAILURE = write_result("10.0.0.1", "10.0.0.3", 200, "failure", "Policy delete failed")

# --- topology NBI policy fixtures (the verified keyed GET shape) -----------------------


def nbi_policy(headend: str, endpoint: str, color: int, flag_c: int, oper: str = "UP") -> dict:
    hop = {"type": "IPV4-NODE-SID", "local-ip-addr": endpoint, "label": 16003}
    return {
        "headend": headend,
        "endpoint": endpoint,
        "color": color,
        "policy-details": {
            "pcep-info": {"pcep-flag-c": flag_c},
            "path": [
                {
                    "path-name": "mcp-dyn-200" if flag_c else "CNC-DYN-100",
                    "path-type": "PT-DYNAMIC",
                    "preference": 100,
                    "oper-state": oper,
                    "segment-list": [{"weight": 1, "hop": [hop]}],
                    "hop": [hop],
                }
            ],
            "binding-sid": 24005,
            "update-time": "1789293787548",
            "pce-controlled": True,
            "pcc-address": headend,
        },
        "admin-state": "UP",
        "oper-state": oper,
        "sr-policy-type": "REGULAR",
    }


PCE_INITIATED = nbi_policy("10.0.0.1", "10.0.0.3", 200, flag_c=1)
PCC_INITIATED = nbi_policy("10.0.0.1", "10.0.0.3", 100, flag_c=0)


def keyed(policy: dict) -> dict:
    """The keyed GET answers the bare list key with one entry (verified)."""
    return {"cisco-crosswork-segment-routing-policy:policy": [policy]}


DATA_MISSING_409 = httpx.Response(
    409,
    json={
        "errors": {
            "error": [
                {
                    "error-tag": "data-missing",
                    "error-message": (
                        "Request could not be completed because the relevant data model "
                        "content does not exist"
                    ),
                    "error-type": "protocol",
                }
            ]
        }
    },
)
# The COE's answer to input it cannot resolve — and to an absent backend.
EMPTY_500 = httpx.Response(500)


# --- harness ----------------------------------------------------------------------


def build(settings: Settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    sr_te_operations.register(mcp, ctx)
    return mcp


@pytest.fixture
def writes(make_settings) -> MCPServer:
    return build(make_settings(enable_writes=True))


@pytest.fixture
def reads(settings) -> MCPServer:
    return build(settings)


def ok(body: Any) -> httpx.Response:
    return httpx.Response(200, json=body)


def mock_networks(body: Any = NETWORKS) -> respx.Route:
    return respx.get(NETWORKS_URL).mock(return_value=ok(body))


def sent(route: respx.Route, index: int = 0) -> dict:
    return json.loads(route.calls[index].request.content)


def assert_yang_post(route: respx.Route, index: int = 0) -> None:
    request = route.calls[index].request
    assert request.method == "POST"
    assert request.headers["Content-Type"] == YANG_JSON
    assert request.headers["Accept"] == YANG_JSON


class _FakeClock:
    """Stands in for both ``time`` and ``asyncio`` inside cnc_mcp.polling."""

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def fake_clock(monkeypatch) -> _FakeClock:
    clock = _FakeClock()
    monkeypatch.setattr(polling, "time", clock)
    monkeypatch.setattr(polling, "asyncio", clock)
    return clock


def mock_policy(*responses: httpx.Response) -> respx.Route:
    """The keyed policy GET answering the responses in order; the last repeats forever."""
    replies = list(responses)

    def answer(_request: httpx.Request) -> httpx.Response:
        return replies.pop(0) if len(replies) > 1 else replies[0]

    return respx.get(policy_url("10.0.0.1", "10.0.0.3", 200)).mock(side_effect=answer)


READ_TOOLS = {
    "cnc_list_sr_policies_on_nodes",
    "cnc_list_sr_policies_on_interface",
    "cnc_get_sr_policy_routes",
    "cnc_get_sr_policy_metrics",
    "cnc_preview_sr_policy_route",
    "cnc_dryrun_sr_policy",
    "cnc_get_sr_policy_path_notification_state",
    "cnc_wait_for_sr_policy_oper_state",
}
WRITE_TOOLS = {
    "cnc_create_sr_policy",
    "cnc_update_sr_policy",
    "cnc_delete_sr_policy",
    "cnc_set_sr_policy_path_notifications",
}

RESOLVED_PE1 = ResolvedNode("PE1", "10.0.0.1", 16001)
RESOLVED_PE2 = ResolvedNode("PE2", "10.0.0.3", 16003)
RESOLVED_P2 = ResolvedNode("P2", "10.0.0.4", 16004)
WIRE_HOPS_P2_PE2 = [
    {"step": 0, "hop": {"node-ipv4-address": "10.0.0.4", "node-ipv4-sid": 16004}},
    {"step": 1, "hop": {"node-ipv4-address": "10.0.0.3", "node-ipv4-sid": 16003}},
]


# --- registration / gating -----------------------------------------------------------


async def test_write_tools_hidden_unless_enabled(make_settings):
    names = {t.name for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert names == READ_TOOLS
    names = {t.name for t in await build(make_settings(enable_writes=True)).list_tools()}
    assert names == READ_TOOLS | WRITE_TOOLS


async def test_annotations(writes):
    tools = {t.name: t for t in await writes.list_tools()}
    for name in READ_TOOLS:
        assert tools[name].annotations.read_only_hint is True, name
        assert tools[name].annotations.idempotent_hint is True, name
        assert tools[name].annotations.destructive_hint is False, name
    for name in WRITE_TOOLS:
        assert tools[name].annotations.read_only_hint is False, name
    create = tools["cnc_create_sr_policy"].annotations
    assert create.destructive_hint is False and create.idempotent_hint is False
    update = tools["cnc_update_sr_policy"].annotations
    assert update.destructive_hint is True and update.idempotent_hint is True
    delete = tools["cnc_delete_sr_policy"].annotations
    assert delete.destructive_hint is True and delete.idempotent_hint is True
    notify = tools["cnc_set_sr_policy_path_notifications"].annotations
    assert notify.destructive_hint is False and notify.idempotent_hint is True
    # path_name is REQUIRED by the platform ("SR Policy name is empty." otherwise).
    assert "path_name" in tools["cnc_create_sr_policy"].input_schema["required"]
    assert "path_name" in tools["cnc_update_sr_policy"].input_schema["required"]
    # The bodiless state read takes no arguments at all.
    state_read = tools["cnc_get_sr_policy_path_notification_state"]
    assert state_read.input_schema.get("properties", {}) == {}
    # Every argument is a flat scalar (the only $ref is the ResponseFormat enum).
    for tool in tools.values():
        for name, prop in tool.input_schema["properties"].items():
            ref = prop.get("$ref") or "".join(str(a.get("$ref", "")) for a in prop.get("anyOf", []))
            assert ref in ("", "#/$defs/ResponseFormat"), f"{tool.name}.{name}"


# --- pure helpers: names, relations, resolver ---------------------------------------


def test_parse_names_splits_and_strips():
    assert parse_names(" PE1, p1 ,,P2 ", "nodes", "PE1,P1") == ["PE1", "p1", "P2"]


def test_parse_names_empty_is_error():
    with pytest.raises(PlatformError, match="nodes is empty"):
        parse_names(" , ", "nodes", "PE1,P1")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("source", "nodes-as-source"),
        ("Destination", "nodes-as-destination"),
        ("source_or_destination", "nodes-as-source-or-destination"),
        (" through ", "through-nodes"),
        ("nodes-as-source", "nodes-as-source"),
    ],
)
def test_normalize_relation(value, expected):
    assert normalize_relation(value) == expected


def test_normalize_relation_unknown_is_error():
    with pytest.raises(PlatformError, match="Unknown relation 'via'"):
        normalize_relation("via")


def test_find_node_by_id_case_insensitive_and_by_router_id():
    assert find_node(NODES, "PE1") is PE1
    assert find_node(NODES, "pe2") is PE2
    assert find_node(NODES, " 10.0.0.4 ") is P2


def test_find_node_unknown_is_error_with_listing_hint():
    with pytest.raises(PlatformError) as info:
        find_node(NODES, "PE9")
    assert str(info.value) == (
        "no node 'PE9' in the topology (node ids are inventory host names; router-ids are TE "
        "loopbacks) — list with cnc_list_topology_nodes"
    )


def test_find_node_empty_is_error():
    with pytest.raises(PlatformError, match="node name is empty"):
        find_node(NODES, "  ")


def test_resolve_node_gives_router_id_and_algorithm_zero_sid():
    assert resolve_node(NODES, "PE1") == RESOLVED_PE1
    assert resolve_node(NODES, "10.0.0.3") == RESOLVED_PE2
    assert resolve_node(NODES, "SW1") == ResolvedNode("SW1", None, None)


def test_node_prefix_sid_prefers_algorithm_zero_of_the_router_id_prefix():
    l3 = {
        "router-id": ["10.0.0.1"],
        "prefix": [
            {"prefix": "10.0.0.9/32", SR_MPLS: [{"algorithm-value": 0, "sid": 16009}]},
            {
                "prefix": "10.0.0.1/32",
                SR_MPLS: [
                    {"algorithm-value": 128, "sid": 17001},
                    {"algorithm-value": 0, "sid": 16001},
                ],
            },
        ],
    }
    assert node_prefix_sid(l3, "10.0.0.1") == 16001


def test_node_prefix_sid_never_substitutes_a_sid_that_does_not_belong_to_the_router_id():
    """The address and SID of a hop must belong together: no Flex-Algo or other-prefix fallback."""
    flex = [{"algorithm-value": 128, "sid": 17001}]
    flex_only = {"prefix": [{"prefix": "10.0.0.1/32", SR_MPLS: flex}]}
    assert node_prefix_sid(flex_only, "10.0.0.1") is None
    spf = [{"algorithm-value": 0, "sid": 16009}]
    other = {"prefix": [{"prefix": "10.0.0.9/32", SR_MPLS: spf}]}
    assert node_prefix_sid(other, "10.0.0.1") is None
    # The reviewer's reproduction: Loopback0 (the router-id) unsigned, Loopback1 signed.
    loopback1 = {
        "router-id": ["10.0.0.1"],
        "prefix": [
            {"prefix": "10.0.0.1/32"},
            {"prefix": "10.0.1.1/32", SR_MPLS: [{"algorithm-value": 0, "sid": 16011}]},
        ],
    }
    assert node_prefix_sid(loopback1, "10.0.0.1") is None
    # An entry without algorithm-value is not taken for algorithm 0 either.
    unlabelled = {"prefix": [{"prefix": "10.0.0.1/32", SR_MPLS: [{"sid": 16001}]}]}
    assert node_prefix_sid(unlabelled, "10.0.0.1") is None
    assert node_prefix_sid({"prefix": [{"prefix": "10.1.1.0/30"}]}, "10.0.0.1") is None
    assert node_prefix_sid({}, None) is None


def test_unsigned_router_id_is_refused_as_a_hop_and_nothing_is_paired():
    """End to end through the resolver: the wrong-SID hop from the review can no longer be built."""
    node = {
        "node-id": "PE6",
        L3_NODE: {
            "router-id": ["10.0.0.6"],
            "prefix": [
                {"prefix": "10.0.0.6/32"},
                {"prefix": "10.0.1.6/32", SR_MPLS: [{"algorithm-value": 0, "sid": 16016}]},
            ],
        },
    }
    resolved = resolve_node([node], "PE6")
    assert resolved == ResolvedNode("PE6", "10.0.0.6", None)
    assert require_sr(resolved) is resolved  # still fine as a head-end / endpoint
    with pytest.raises(PlatformError, match="no algorithm-0 prefix-SID for 10.0.0.6/32"):
        explicit_hops([resolved])


def test_select_router_id_prefers_the_named_one_then_the_first_ipv4():
    ids = ["2001:db8::1", "10.0.0.1", "10.0.0.11"]
    assert select_router_id(ids, "10.0.0.11") == "10.0.0.11"
    assert select_router_id(ids, " 10.0.0.1 ") == "10.0.0.1"
    assert select_router_id(ids, "PE1") == "10.0.0.1"
    assert select_router_id(["2001:db8::1"], "PE1") == "2001:db8::1"
    assert select_router_id(["not-an-ip", "10.0.0.1"], "PE1") == "10.0.0.1"
    assert select_router_id([], "PE1") is None


def test_resolve_node_with_several_router_ids_uses_the_named_or_ipv4_one():
    """router-id is a leaf-list: an IPv6 entry first must not leak onto the IPv4 wire fields."""
    node = {
        "node-id": "PE6",
        L3_NODE: {
            "router-id": ["2001:db8::6", "10.0.0.6"],
            "prefix": [
                {"prefix": "10.0.0.6/32", SR_MPLS: [{"algorithm-value": 0, "sid": 16006}]},
            ],
        },
    }
    assert resolve_node([node], "10.0.0.6") == ResolvedNode("PE6", "10.0.0.6", 16006)
    assert resolve_node([node], "PE6") == ResolvedNode("PE6", "10.0.0.6", 16006)
    # Naming the IPv6 router-id explicitly keeps it (and finds no /32 SID for it).
    assert resolve_node([node], "2001:db8::6") == ResolvedNode("PE6", "2001:db8::6", None)


def test_require_sr_errors_name_the_missing_data():
    assert require_sr(RESOLVED_PE1, need_sid=True) is RESOLVED_PE1
    with pytest.raises(PlatformError, match="node 'SW1' has no SR data .*no TE router-id"):
        require_sr(ResolvedNode("SW1", None, None))
    no_sid = ResolvedNode("PE1", "10.0.0.1", None)
    assert require_sr(no_sid) is no_sid  # a router-id is enough for head-end / end-point
    with pytest.raises(PlatformError, match="no algorithm-0 prefix-SID for 10.0.0.1/32"):
        require_sr(no_sid, need_sid=True)


def test_resolve_interface_exact_and_case_insensitive():
    assert resolve_interface(P1, GI0) == GI0
    assert resolve_interface(P1, " gigabitethernet0/0/0/1 ") == GI1


def test_resolve_interface_mismatch_lists_the_termination_points():
    with pytest.raises(PlatformError) as info:
        resolve_interface(P1, "Gi0/0/0/0")
    text = str(info.value)
    assert text.startswith("no interface 'Gi0/0/0/0' on node 'P1' in the topology.")
    assert f"Its termination points are: {GI0}, {GI1}, Loopback0" in text
    with pytest.raises(PlatformError, match=r"\(none reported\)"):
        resolve_interface({"node-id": "X"}, GI0)


def test_policy_key_sends_router_ids():
    assert policy_key(RESOLVED_PE1, RESOLVED_PE2, 100) == KEY_PE1_PE2
    with pytest.raises(PlatformError, match="has no SR data"):
        policy_key(ResolvedNode("SW1", None, None), RESOLVED_PE2, 100)


def test_pcep_flag_c():
    assert pcep_flag_c(PCE_INITIATED) == 1
    assert pcep_flag_c(PCC_INITIATED) == 0
    assert pcep_flag_c({"policy-details": {}}) is None
    assert pcep_flag_c({}) is None


def test_write_outcome():
    assert write_outcome({"state": "success"}, "create", "k") == ("success", "")
    degraded = {"state": "degraded", "message": " m "}
    assert write_outcome(degraded, "create", "k") == ("degraded", "m")
    with pytest.raises(PlatformError) as info:
        write_outcome({"state": "failure", "message": DUPLICATE_MESSAGE}, "create", "k")
    assert str(info.value) == f"create failed for k: {DUPLICATE_MESSAGE}"
    with pytest.raises(PlatformError, match="failed for k: no message given"):
        write_outcome({"state": "failure"}, "create", "k")
    with pytest.raises(PlatformError, match="unexpected state"):
        write_outcome({}, "create", "k")


# --- pure helpers: build_policy_path (every branch) -----------------------------------


def test_explicit_hops_carry_both_address_and_sid_from_step_zero():
    assert explicit_hops([RESOLVED_P2, RESOLVED_PE2]) == WIRE_HOPS_P2_PE2
    with pytest.raises(PlatformError, match="no SR data"):
        explicit_hops([ResolvedNode("SW1", None, None)])


def test_build_policy_path_dynamic_defaults():
    assert build_policy_path() == {"path-optimization-objective": "igp-metric", "protected": True}


def test_build_policy_path_dynamic_with_every_option():
    assert build_policy_path(
        objective="TE_METRIC",
        protected=False,
        sid_algorithm=128,
        disjointness_type="srlg-node",
        association_group=7,
        association_sub_group=2,
    ) == {
        "path-optimization-objective": "te-metric",
        "protected": False,
        "sid-algorithm": 128,
        "disjointness": {
            "disjointness-type": "srlg-node",
            "association-group": 7,
            "association-sub-group": 2,
        },
    }


def test_build_policy_path_explicit_sends_only_the_hops():
    assert build_policy_path(path_type="Explicit", hops=[RESOLVED_P2, RESOLVED_PE2]) == {
        "hops": WIRE_HOPS_P2_PE2
    }


def test_build_policy_path_bandwidth():
    assert build_policy_path(path_type="bandwidth", bandwidth_mbps=100, objective="delay") == {
        "bandwidth": 100,
        "bw-path-optimization-objective": "delay",
    }
    assert build_policy_path(path_type="bandwidth", bandwidth_mbps=5, sid_algorithm=128) == {
        "bandwidth": 5,
        "bw-path-optimization-objective": "igp-metric",
        "bw-path-sid-algorithm": 128,
    }


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"path_type": "static"}, "Unknown path_type 'static'"),
        ({"objective": "latency"}, "Unknown objective 'latency'"),
        ({"disjointness_type": "link", "association_group": 1}, "Unknown disjointness_type 'link'"),
        ({"disjointness_type": "node"}, "disjointness_type needs association_group"),
        ({"association_group": 1}, "need disjointness_type"),
        ({"hops": [RESOLVED_P2]}, "hops apply only to path_type='explicit'"),
        ({"bandwidth_mbps": 10}, "bandwidth_mbps needs path_type='bandwidth'"),
        ({"path_type": "explicit"}, "path_type='explicit' needs hops"),
        (
            {"path_type": "explicit", "hops": [RESOLVED_P2], "sid_algorithm": 128},
            "sid_algorithm do\\(es\\) not apply to an explicit path",
        ),
        (
            {"path_type": "explicit", "hops": [RESOLVED_P2], "bandwidth_mbps": 10},
            "bandwidth_mbps do\\(es\\) not apply to an explicit path",
        ),
        ({"path_type": "bandwidth"}, "path_type='bandwidth' needs bandwidth_mbps"),
        ({"path_type": "bandwidth", "bandwidth_mbps": 1, "hops": [RESOLVED_P2]}, "hops apply only"),
        (
            {"path_type": "bandwidth", "bandwidth_mbps": 1, "disjointness_type": "node",
             "association_group": 1},
            "disjointness applies only to a dynamic path",
        ),
    ],
)  # fmt: skip
def test_build_policy_path_rejects_invalid_combinations(kwargs, match):
    with pytest.raises(PlatformError, match=match):
        build_policy_path(**kwargs)


def test_url_builders():
    assert coe_url("sr-policies-on-node") == (
        "/crosswork/nbi/optimization/v3/restconf/operations/"
        "cisco-crosswork-optimization-engine-operations:sr-policies-on-node"
    )
    assert srp_url("sr-policy-create") == (
        "/crosswork/nbi/optimization/v3/restconf/operations/"
        "cisco-crosswork-optimization-engine-sr-policy-operations:sr-policy-create"
    )


# --- cnc_list_sr_policies_on_nodes ---------------------------------------------------


@respx.mock
async def test_list_on_nodes_markdown_sends_node_ids(reads):
    networks = mock_networks()
    route = respx.post(coe("sr-policies-on-node")).mock(return_value=ok(ON_NODE_OUT))
    text = await call_tool_text(
        reads, "cnc_list_sr_policies_on_nodes", {"nodes": "pe1, 10.0.0.2", "relation": "source"}
    )
    assert networks.calls[0].request.headers["Accept"] == YANG_JSON
    assert route.call_count == 1
    assert_yang_post(route)
    # Host names on the wire (a router-id was translated), the verified filter spelling.
    assert sent(route) == {
        "input": {"nodes": [{"node": "PE1"}, {"node": "P1"}], "filter": "nodes-as-source"}
    }
    assert text.startswith("# SR policies on PE1, P1 (filter nodes-as-source)")
    assert "## PE1 (10.0.0.1) (2 policies)" in text
    assert "- 10.0.0.1 -> 10.0.0.3 color 100" in text
    assert "- 10.0.0.3 -> 10.0.0.1 color 100" in text
    assert (
        "## P1 (10.0.0.2) (0 policies)\n- (none)\n  message: No SR policies found for node P1"
    ) in text


@respx.mock
async def test_list_on_nodes_default_relation_and_json(reads):
    mock_networks()
    route = respx.post(coe("sr-policies-on-node")).mock(return_value=ok(ON_NODE_OUT))
    text = await call_tool_text(
        reads, "cnc_list_sr_policies_on_nodes", {"nodes": "PE1", "response_format": "json"}
    )
    assert sent(route)["input"]["filter"] == "nodes-as-source-or-destination"
    assert json.loads(text) == ON_NODE_OUT[f"{COE}:output"]


@respx.mock
async def test_list_on_nodes_unknown_node_is_error_before_the_rpc(reads):
    mock_networks()
    route = respx.post(coe("sr-policies-on-node")).mock(return_value=ok(ON_NODE_OUT))
    text = await call_tool_text(reads, "cnc_list_sr_policies_on_nodes", {"nodes": "PE1,PE9"})
    assert text.startswith("Error: no node 'PE9' in the topology")
    assert "cnc_list_topology_nodes" in text
    assert route.call_count == 0


@respx.mock
async def test_list_on_nodes_bad_relation_is_error_before_any_call(reads):
    networks = mock_networks()
    text = await call_tool_text(
        reads, "cnc_list_sr_policies_on_nodes", {"nodes": "PE1", "relation": "via"}
    )
    assert text.startswith("Error: Unknown relation 'via'")
    assert networks.call_count == 0


@respx.mock
async def test_list_on_nodes_empty_500_renders_the_coe_hint(reads):
    mock_networks()
    route = respx.post(coe("sr-policies-on-node")).mock(return_value=EMPTY_500)
    text = await call_tool_text(reads, "cnc_list_sr_policies_on_nodes", {"nodes": "PE1"})
    assert route.call_count == 1  # a write-shaped POST: never auto-retried
    assert text == f"Error: {COE_EMPTY_500_HINT}"
    assert "answered 500 with an empty body" in text


def test_coe_empty_500_hint_is_self_contained_and_names_the_input_causes():
    """The verified meaning: bad INPUT first, backend-absent second — and never the generic
    "retrying will not help, the feature is absent" verdict that would send an agent away
    from fixing its own input."""
    assert EMPTY_500_EXPLANATION not in COE_EMPTY_500_HINT
    assert "not available on this deployment" not in COE_EMPTY_500_HINT
    for cause in (
        "unknown node or interface name",
        "router-id where a host name belongs",
        "host name where a router-id belongs",
        "explicit hop without its SID",
        "absent or down",
    ):
        assert cause in COE_EMPTY_500_HINT, cause
    for check in ("cnc_get_topology_node", "cnc_list_node_interfaces", "cnc_list_providers"):
        assert check in COE_EMPTY_500_HINT, check


@respx.mock
async def test_list_on_nodes_status_error_inside_200_is_error(reads):
    mock_networks()
    respx.post(coe("sr-policies-on-node")).mock(return_value=ok(STATUS_ERROR_OUT))
    text = await call_tool_text(reads, "cnc_list_sr_policies_on_nodes", {"nodes": "PE1"})
    assert text == "Error: sr-policies-on-node failed: failed to export network: Abort"


@respx.mock
async def test_list_on_nodes_no_networks_is_error(reads):
    mock_networks(NO_NETWORKS)
    route = respx.post(coe("sr-policies-on-node")).mock(return_value=ok(ON_NODE_OUT))
    text = await call_tool_text(reads, "cnc_list_sr_policies_on_nodes", {"nodes": "PE1"})
    assert text.startswith("Error: the topology NBI reports no networks yet")
    assert route.call_count == 0


@respx.mock
async def test_list_on_nodes_unknown_network_lists_the_present_ones(reads):
    mock_networks()
    text = await call_tool_text(
        reads, "cnc_list_sr_policies_on_nodes", {"nodes": "PE1", "network": "other"}
    )
    assert text.startswith("Error: no network 'other' on the topology NBI. Networks present: "
                           "Default-network.")  # fmt: skip


# --- cnc_list_sr_policies_on_interface -----------------------------------------------


@respx.mock
async def test_list_on_interface_markdown_sends_exact_tp_id(reads):
    mock_networks()
    route = respx.post(coe("sr-policies-on-interface")).mock(return_value=ok(ON_INTERFACE_OUT))
    text = await call_tool_text(
        reads,
        "cnc_list_sr_policies_on_interface",
        {"node": "10.0.0.2", "interface": "gigabitethernet0/0/0/0"},
    )
    assert_yang_post(route)
    assert sent(route) == {"input": {"interfaces": [{"node": "P1", "interface": GI0}]}}
    assert text.startswith(f"# SR policies on P1:{GI0}")
    assert f"## P1:{GI0} (1 policies)\n- 10.0.0.3 -> 10.0.0.1 color 100" in text


@respx.mock
async def test_list_on_interface_json(reads):
    mock_networks()
    respx.post(coe("sr-policies-on-interface")).mock(return_value=ok(ON_INTERFACE_OUT))
    text = await call_tool_text(
        reads,
        "cnc_list_sr_policies_on_interface",
        {"node": "P1", "interface": GI0, "response_format": "json"},
    )
    assert json.loads(text) == ON_INTERFACE_OUT[f"{COE}:output"]


@respx.mock
async def test_list_on_interface_unknown_interface_lists_them_and_skips_the_rpc(reads):
    mock_networks()
    route = respx.post(coe("sr-policies-on-interface")).mock(return_value=ok(ON_INTERFACE_OUT))
    text = await call_tool_text(
        reads, "cnc_list_sr_policies_on_interface", {"node": "P1", "interface": "Gi0/0/0/0"}
    )
    assert text.startswith("Error: no interface 'Gi0/0/0/0' on node 'P1' in the topology.")
    assert f"{GI0}, {GI1}, Loopback0" in text and "cnc_list_node_interfaces" in text
    assert route.call_count == 0


@respx.mock
async def test_list_on_interface_unknown_node_is_error(reads):
    mock_networks()
    route = respx.post(coe("sr-policies-on-interface")).mock(return_value=ok(ON_INTERFACE_OUT))
    text = await call_tool_text(
        reads, "cnc_list_sr_policies_on_interface", {"node": "P9", "interface": GI0}
    )
    assert text.startswith("Error: no node 'P9' in the topology")
    assert route.call_count == 0


@respx.mock
async def test_list_on_interface_empty_500_renders_the_coe_hint(reads):
    mock_networks()
    respx.post(coe("sr-policies-on-interface")).mock(return_value=EMPTY_500)
    text = await call_tool_text(
        reads, "cnc_list_sr_policies_on_interface", {"node": "P1", "interface": GI0}
    )
    assert text.startswith(f"Error: {COE_EMPTY_500_HINT}")


# --- cnc_get_sr_policy_routes --------------------------------------------------------


@respx.mock
async def test_get_routes_markdown_sends_router_ids_for_hostnames(reads):
    mock_networks()
    route = respx.post(coe("sr-policy-routes")).mock(return_value=ok(ROUTES_OUT))
    text = await call_tool_text(
        reads, "cnc_get_sr_policy_routes", {"headend": "PE1", "endpoint": "pe2", "color": 100}
    )
    assert_yang_post(route)
    assert sent(route) == {"input": {"sr-policies": [KEY_PE1_PE2]}}
    assert text.startswith(
        "# IGP route of SR policy PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 100 (4 interfaces)"
    )
    assert f"- PE1:{GI0} (share 0.5)\n- PE1:{GI1} (share 0.5)\n- P1:{GI1} (share 0.5)" in text
    assert "share = interface-use" in text


@respx.mock
async def test_get_routes_json_and_router_id_input(reads):
    mock_networks()
    route = respx.post(coe("sr-policy-routes")).mock(return_value=ok(ROUTES_OUT))
    text = await call_tool_text(
        reads,
        "cnc_get_sr_policy_routes",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100, "response_format": "json"},
    )
    assert sent(route) == {"input": {"sr-policies": [KEY_PE1_PE2]}}
    assert json.loads(text) == ROUTES_OUT[f"{COE}:output"]


@respx.mock
async def test_get_routes_computation_failure_is_error(reads):
    mock_networks()
    respx.post(coe("sr-policy-routes")).mock(return_value=ok(ROUTES_FAILURE_OUT))
    text = await call_tool_text(
        reads, "cnc_get_sr_policy_routes", {"headend": "PE1", "endpoint": "PE2", "color": 999}
    )
    assert text == (
        "Error: no route could be computed for SR policy PE1 (10.0.0.1) -> PE2 (10.0.0.3) "
        "color 999 (the policy may not exist — check cnc_list_sr_policies)"
    )


@respx.mock
async def test_get_routes_no_results_is_error(reads):
    mock_networks()
    respx.post(coe("sr-policy-routes")).mock(return_value=ok(coe_out(results=[])))
    text = await call_tool_text(
        reads, "cnc_get_sr_policy_routes", {"headend": "PE1", "endpoint": "PE2", "color": 100}
    )
    assert text.startswith("Error: the Optimization Engine returned no result for the route of")


@respx.mock
async def test_get_routes_node_without_sr_data_is_error_before_the_rpc(reads):
    mock_networks()
    route = respx.post(coe("sr-policy-routes")).mock(return_value=ok(ROUTES_OUT))
    text = await call_tool_text(
        reads, "cnc_get_sr_policy_routes", {"headend": "SW1", "endpoint": "PE2", "color": 100}
    )
    assert text.startswith("Error: node 'SW1' has no SR data in the topology (no TE router-id)")
    assert route.call_count == 0


# --- cnc_get_sr_policy_metrics -------------------------------------------------------


@respx.mock
async def test_get_metrics_markdown(reads):
    mock_networks()
    route = respx.post(coe("sr-policy-metrics")).mock(return_value=ok(METRICS_OUT))
    text = await call_tool_text(
        reads, "cnc_get_sr_policy_metrics", {"headend": "PE1", "endpoint": "PE2", "color": 100}
    )
    assert_yang_post(route)
    assert sent(route) == {"input": {"sr-policies": [KEY_PE1_PE2]}}
    assert text.startswith("# Path metrics of SR policy PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 100")
    assert "- igp-metric=20 te-metric=20 delay=20" in text


@respx.mock
async def test_get_metrics_json(reads):
    mock_networks()
    respx.post(coe("sr-policy-metrics")).mock(return_value=ok(METRICS_OUT))
    text = await call_tool_text(
        reads,
        "cnc_get_sr_policy_metrics",
        {"headend": "PE1", "endpoint": "PE2", "color": 100, "response_format": "json"},
    )
    assert json.loads(text) == METRICS_OUT[f"{COE}:output"]


@respx.mock
async def test_get_metrics_computation_failure_is_error(reads):
    mock_networks()
    respx.post(coe("sr-policy-metrics")).mock(return_value=ok(METRICS_FAILURE_OUT))
    text = await call_tool_text(
        reads, "cnc_get_sr_policy_metrics", {"headend": "PE1", "endpoint": "PE2", "color": 999}
    )
    assert text.startswith("Error: no metrics could be computed for SR policy PE1 (10.0.0.1)")
    assert "check cnc_list_sr_policies" in text


@respx.mock
async def test_get_metrics_empty_500_renders_the_coe_hint(reads):
    mock_networks()
    respx.post(coe("sr-policy-metrics")).mock(return_value=EMPTY_500)
    text = await call_tool_text(
        reads, "cnc_get_sr_policy_metrics", {"headend": "PE1", "endpoint": "PE2", "color": 100}
    )
    assert text.startswith(f"Error: {COE_EMPTY_500_HINT}")


@respx.mock
async def test_get_metrics_unknown_node_is_error_before_the_rpc(reads):
    mock_networks()
    route = respx.post(coe("sr-policy-metrics")).mock(return_value=ok(METRICS_OUT))
    text = await call_tool_text(
        reads, "cnc_get_sr_policy_metrics", {"headend": "PE1", "endpoint": "PE9", "color": 100}
    )
    assert text.startswith("Error: no node 'PE9' in the topology")
    assert route.call_count == 0


# --- cnc_preview_sr_policy_route -----------------------------------------------------


@respx.mock
async def test_preview_with_hops_sends_address_and_sid_from_step_zero(reads):
    mock_networks()
    route = respx.post(coe("sr-policy-route-preview")).mock(return_value=ok(PREVIEW_OUT))
    text = await call_tool_text(
        reads,
        "cnc_preview_sr_policy_route",
        {"headend": "PE1", "endpoint": "PE2", "hops": "P2, 10.0.0.3"},
    )
    assert_yang_post(route)
    assert sent(route) == {
        "input": {
            "head-end": "10.0.0.1",
            "end-point": "10.0.0.3",
            "sr-policy-path": {"hops": WIRE_HOPS_P2_PE2},
        }
    }
    assert text.startswith(
        "# Route preview PE1 (10.0.0.1) -> PE2 (10.0.0.3) via P2 (10.0.0.4) > PE2 (10.0.0.3) "
        "(2 interfaces)"
    )
    assert f"- PE1:{GI1} (share 1)\n- P2:{GI0} (share 1)" in text
    assert "Nothing was created." in text


@respx.mock
async def test_preview_without_hops_sends_an_empty_path(reads):
    mock_networks()
    route = respx.post(coe("sr-policy-route-preview")).mock(return_value=ok(PREVIEW_OUT))
    text = await call_tool_text(
        reads,
        "cnc_preview_sr_policy_route",
        {"headend": "PE1", "endpoint": "PE2", "response_format": "json"},
    )
    assert sent(route) == {
        "input": {"head-end": "10.0.0.1", "end-point": "10.0.0.3", "sr-policy-path": {}}
    }
    assert json.loads(text) == PREVIEW_OUT[f"{COE}:output"]


@respx.mock
async def test_preview_failure_is_error(reads):
    mock_networks()
    respx.post(coe("sr-policy-route-preview")).mock(return_value=ok(PREVIEW_FAILURE_OUT))
    text = await call_tool_text(
        reads, "cnc_preview_sr_policy_route", {"headend": "PE1", "endpoint": "PE2", "hops": "P2"}
    )
    assert text.startswith(
        "Error: no path could be computed from PE1 (10.0.0.1) to PE2 (10.0.0.3) via P2 (10.0.0.4)"
    )


@respx.mock
async def test_preview_hop_without_sr_data_is_error_before_the_rpc(reads):
    mock_networks()
    route = respx.post(coe("sr-policy-route-preview")).mock(return_value=ok(PREVIEW_OUT))
    text = await call_tool_text(
        reads, "cnc_preview_sr_policy_route", {"headend": "PE1", "endpoint": "PE2", "hops": "SW1"}
    )
    assert text.startswith("Error: node 'SW1' has no SR data in the topology")
    assert route.call_count == 0


@respx.mock
async def test_preview_unknown_hop_is_error_before_the_rpc(reads):
    mock_networks()
    route = respx.post(coe("sr-policy-route-preview")).mock(return_value=ok(PREVIEW_OUT))
    text = await call_tool_text(
        reads, "cnc_preview_sr_policy_route", {"headend": "PE1", "endpoint": "PE2", "hops": "P2,P7"}
    )
    assert text.startswith("Error: no node 'P7' in the topology")
    assert route.call_count == 0


@respx.mock
async def test_preview_hop_whose_router_id_has_no_algorithm_zero_sid_is_refused(reads):
    """The review's silent mispairing (Loopback1's SID sent with Loopback0's address) is now an
    error before the RPC — never a hop whose address and SID do not belong together."""
    unsigned_loopback0 = sr_node("PE6", 6)
    l3 = unsigned_loopback0[L3_NODE]
    l3["prefix"] = [
        {"prefix": "10.0.0.6/32"},
        {"prefix": "10.0.1.6/32", SR_MPLS: [{"algorithm-value": 0, "sid": 16016}]},
    ]
    mock_networks(
        {
            "ietf-network-state:networks": {
                "network": [{"network-id": "Default-network", "node": [*NODES, unsigned_loopback0]}]
            }
        }
    )
    route = respx.post(coe("sr-policy-route-preview")).mock(return_value=ok(PREVIEW_OUT))
    text = await call_tool_text(
        reads, "cnc_preview_sr_policy_route", {"headend": "PE1", "endpoint": "PE2", "hops": "PE6"}
    )
    assert text.startswith(
        "Error: node 'PE6' has no SR data in the topology (no algorithm-0 prefix-SID for "
        "10.0.0.6/32)"
    )
    assert route.call_count == 0


@respx.mock
async def test_preview_node_with_several_router_ids_sends_the_named_ipv4_one(reads):
    """router-id [IPv6, IPv4]: the head-end and the hop go on the wire as the IPv4 address the
    caller named (or the first IPv4 one), with that address's own /32 SID."""
    dual = sr_node("PE6", 6)
    dual[L3_NODE]["router-id"] = ["2001:db8::6", "10.0.0.6"]
    mock_networks(
        {
            "ietf-network-state:networks": {
                "network": [{"network-id": "Default-network", "node": [*NODES, dual]}]
            }
        }
    )
    route = respx.post(coe("sr-policy-route-preview")).mock(return_value=ok(PREVIEW_OUT))
    await call_tool_text(
        reads,
        "cnc_preview_sr_policy_route",
        {"headend": "10.0.0.6", "endpoint": "PE2", "hops": "PE6,PE2"},
    )
    assert sent(route) == {
        "input": {
            "head-end": "10.0.0.6",
            "end-point": "10.0.0.3",
            "sr-policy-path": {
                "hops": [
                    {"step": 0, "hop": {"node-ipv4-address": "10.0.0.6", "node-ipv4-sid": 16006}},
                    {"step": 1, "hop": {"node-ipv4-address": "10.0.0.3", "node-ipv4-sid": 16003}},
                ]
            },
        }
    }


# --- cnc_dryrun_sr_policy ------------------------------------------------------------

DRYRUN_ARGS = {"headend": "PE1", "endpoint": "PE2"}


@respx.mock
async def test_dryrun_explicit_markdown_and_body(reads):
    mock_networks()
    route = respx.post(srp("sr-policy-dryrun")).mock(return_value=ok(DRYRUN_SUCCESS))
    text = await call_tool_text(
        reads,
        "cnc_dryrun_sr_policy",
        {"headend": "PE1", "endpoint": "PE2", "path_type": "explicit", "hops": "P2,PE2"},
    )
    assert_yang_post(route)
    assert sent(route) == {
        "input": {
            "head-end": "10.0.0.1",
            "end-point": "10.0.0.3",
            "sr-policy-path": {"hops": WIRE_HOPS_P2_PE2},
        }
    }
    assert text.startswith("# SR policy dry run PE1 (10.0.0.1) -> PE2 (10.0.0.3): success")
    assert "- path: explicit hops P2 (10.0.0.4/16004) > PE2 (10.0.0.3/16003)" in text
    assert (
        "Segment list (2 hops):\n- step 0: node-ipv4 10.0.0.4 sid 16004\n"
        "- step 1: node-ipv4 10.0.0.3 sid 16003"
    ) in text
    assert f"IGP route (2 interfaces):\n- PE1:{GI1}\n- P2:{GI0}" in text
    assert "Nothing was created" in text


@respx.mock
async def test_dryrun_dynamic_body_with_constraints(reads):
    mock_networks()
    route = respx.post(srp("sr-policy-dryrun")).mock(return_value=ok(DRYRUN_SUCCESS))
    text = await call_tool_text(
        reads,
        "cnc_dryrun_sr_policy",
        {
            "headend": "10.0.0.1",
            "endpoint": "PE2",
            "objective": "delay",
            "protected": False,
            "sid_algorithm": 128,
            "disjointness_type": "node",
            "association_group": 5,
            "response_format": "json",
        },
    )
    assert sent(route) == {
        "input": {
            "head-end": "10.0.0.1",
            "end-point": "10.0.0.3",
            "sr-policy-path": {
                "path-optimization-objective": "delay",
                "protected": False,
                "sid-algorithm": 128,
                "disjointness": {"disjointness-type": "node", "association-group": 5},
            },
        }
    }
    assert json.loads(text) == DRYRUN_SUCCESS[f"{SRP}:output"]


@respx.mock
async def test_dryrun_bandwidth_failure_surfaces_the_platform_message(reads):
    mock_networks()
    route = respx.post(srp("sr-policy-dryrun")).mock(return_value=ok(DRYRUN_BWOD))
    text = await call_tool_text(
        reads,
        "cnc_dryrun_sr_policy",
        {"headend": "PE1", "endpoint": "PE2", "path_type": "bandwidth", "bandwidth_mbps": 100},
    )
    assert sent(route)["input"]["sr-policy-path"] == {
        "bandwidth": 100,
        "bw-path-optimization-objective": "igp-metric",
    }
    assert text == f"Error: dry run failed for PE1 (10.0.0.1) -> PE2 (10.0.0.3): {BWOD_MESSAGE}"


@respx.mock
async def test_dryrun_no_path_failure_is_error(reads):
    mock_networks()
    respx.post(srp("sr-policy-dryrun")).mock(return_value=ok(DRYRUN_NO_PATH))
    text = await call_tool_text(reads, "cnc_dryrun_sr_policy", {"headend": "PE1", "endpoint": "P3"})
    assert text == (
        f"Error: dry run failed for PE1 (10.0.0.1) -> P3 (10.0.0.99): {NO_PATH_MESSAGE.strip()}"
    )


@respx.mock
async def test_dryrun_degraded_is_success_with_message(reads):
    mock_networks()
    respx.post(srp("sr-policy-dryrun")).mock(return_value=ok(DRYRUN_DEGRADED))
    text = await call_tool_text(reads, "cnc_dryrun_sr_policy", DRYRUN_ARGS)
    assert not text.startswith("Error:")
    assert text.startswith("# SR policy dry run PE1 (10.0.0.1) -> PE2 (10.0.0.3): degraded")
    assert "- message: Path computed with relaxed constraints" in text
    assert "Segment list (0 hops):\n- (none reported)" in text


@respx.mock
async def test_dryrun_invalid_combination_is_error_before_the_rpc(reads):
    mock_networks()
    route = respx.post(srp("sr-policy-dryrun")).mock(return_value=ok(DRYRUN_SUCCESS))
    text = await call_tool_text(
        reads, "cnc_dryrun_sr_policy", {"headend": "PE1", "endpoint": "PE2", "hops": "P2"}
    )
    assert text.startswith("Error: hops apply only to path_type='explicit'")
    assert route.call_count == 0


@respx.mock
async def test_dryrun_empty_500_renders_the_coe_hint(reads):
    mock_networks()
    respx.post(srp("sr-policy-dryrun")).mock(return_value=EMPTY_500)
    text = await call_tool_text(reads, "cnc_dryrun_sr_policy", DRYRUN_ARGS)
    assert text.startswith(f"Error: {COE_EMPTY_500_HINT}")


@respx.mock
async def test_dryrun_unknown_node_is_error_before_the_rpc(reads):
    mock_networks()
    route = respx.post(srp("sr-policy-dryrun")).mock(return_value=ok(DRYRUN_SUCCESS))
    text = await call_tool_text(
        reads, "cnc_dryrun_sr_policy", {"headend": "PE9", "endpoint": "PE2"}
    )
    assert text.startswith("Error: no node 'PE9' in the topology")
    assert route.call_count == 0


# --- cnc_get_sr_policy_path_notification_state ---------------------------------------


@respx.mock
async def test_get_notification_state_sends_no_body(reads):
    route = respx.post(coe("get-interface-sr-policy-paths-notification-state")).mock(
        return_value=ok(NOTIFICATIONS_ENABLED)
    )
    text = await call_tool_text(reads, "cnc_get_sr_policy_path_notification_state", {})
    request = route.calls[0].request
    assert request.content == b""
    assert request.headers["Accept"] == YANG_JSON
    assert text.startswith("SR policy path notifications are enabled.")
    assert '"enabled": true' in text


@respx.mock
async def test_get_notification_state_disabled(reads):
    respx.post(coe("get-interface-sr-policy-paths-notification-state")).mock(
        return_value=ok(NOTIFICATIONS_DISABLED)
    )
    text = await call_tool_text(reads, "cnc_get_sr_policy_path_notification_state", {})
    assert text.startswith("SR policy path notifications are disabled.")


@respx.mock
async def test_get_notification_state_empty_500_renders_the_coe_hint(reads):
    respx.post(coe("get-interface-sr-policy-paths-notification-state")).mock(return_value=EMPTY_500)
    text = await call_tool_text(reads, "cnc_get_sr_policy_path_notification_state", {})
    assert text.startswith(f"Error: {COE_EMPTY_500_HINT}")


@respx.mock
async def test_get_notification_state_status_error_inside_200_is_error(reads):
    respx.post(coe("get-interface-sr-policy-paths-notification-state")).mock(
        return_value=ok(STATUS_ERROR_OUT)
    )
    text = await call_tool_text(reads, "cnc_get_sr_policy_path_notification_state", {})
    assert text == (
        "Error: get-interface-sr-policy-paths-notification-state failed: failed to export "
        "network: Abort"
    )


# --- cnc_create_sr_policy ------------------------------------------------------------

CREATE_ARGS = {
    "headend": "PE1",
    "endpoint": "pe2",
    "color": 200,
    "path_name": "mcp-dyn-200",
    "description": "created by mcp",
}


@respx.mock
async def test_create_dynamic_sends_router_ids_and_reports_the_outcome(writes):
    mock_networks()
    route = respx.post(srp("sr-policy-create")).mock(return_value=ok(CREATE_SUCCESS))
    text = await call_tool_text(writes, "cnc_create_sr_policy", CREATE_ARGS)
    assert_yang_post(route)
    assert sent(route) == {
        "input": {
            "sr-policies": [
                {
                    "head-end": "10.0.0.1",
                    "end-point": "10.0.0.3",
                    "color": 200,
                    "path-name": "mcp-dyn-200",
                    "description": "created by mcp",
                    "sr-policy-path": {
                        "path-optimization-objective": "igp-metric",
                        "protected": True,
                    },
                }
            ]
        }
    }
    data = json.loads(text)
    assert data["headend"] == "10.0.0.1" and data["headend_node"] == "PE1"
    assert data["endpoint"] == "10.0.0.3" and data["endpoint_node"] == "PE2"
    assert data["color"] == 200 and data["path_name"] == "mcp-dyn-200"
    assert data["state"] == "success" and data["message"] == ""
    assert data["path"] == "dynamic, objective igp-metric, protected=True"
    assert data["next"].startswith("The policy is PCE-initiated and appears on the headend")
    assert "cnc_wait_for_sr_policy_oper_state" in data["next"]


@respx.mock
async def test_create_explicit_with_binding_sid(writes):
    mock_networks()
    route = respx.post(srp("sr-policy-create")).mock(return_value=ok(CREATE_SUCCESS))
    text = await call_tool_text(
        writes,
        "cnc_create_sr_policy",
        {
            "headend": "PE1",
            "endpoint": "PE2",
            "color": 200,
            "path_name": "mcp-exp-200",
            "path_type": "explicit",
            "hops": "10.0.0.4,PE2",
            "binding_sid": 15001,
        },
    )
    entry = sent(route)["input"]["sr-policies"][0]
    assert entry == {
        "head-end": "10.0.0.1",
        "end-point": "10.0.0.3",
        "color": 200,
        "path-name": "mcp-exp-200",
        "binding-sid": 15001,
        "sr-policy-path": {"hops": WIRE_HOPS_P2_PE2},
    }
    assert "description" not in entry
    assert json.loads(text)["path"] == "explicit hops P2 (10.0.0.4/16004) > PE2 (10.0.0.3/16003)"


@respx.mock
async def test_create_duplicate_is_error_with_the_platform_message(writes):
    mock_networks()
    respx.post(srp("sr-policy-create")).mock(return_value=ok(CREATE_DUPLICATE))
    text = await call_tool_text(
        writes, "cnc_create_sr_policy", {**CREATE_ARGS, "color": 100, "path_name": "dup"}
    )
    assert text == (
        f"Error: create failed for PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 100: {DUPLICATE_MESSAGE}"
    )


@respx.mock
async def test_create_no_permission_is_error_with_the_platform_message(writes):
    mock_networks()
    respx.post(srp("sr-policy-create")).mock(return_value=ok(CREATE_NO_PERMISSION))
    text = await call_tool_text(writes, "cnc_create_sr_policy", {**CREATE_ARGS, "headend": "P3"})
    assert text == (
        "Error: create failed for P3 (10.0.0.99) -> PE2 (10.0.0.3) color 200: "
        f"{NO_PERMISSION_MESSAGE}"
    )


@respx.mock
async def test_create_unknown_headend_is_error_before_the_rpc(writes):
    mock_networks()
    route = respx.post(srp("sr-policy-create")).mock(return_value=ok(CREATE_SUCCESS))
    text = await call_tool_text(writes, "cnc_create_sr_policy", {**CREATE_ARGS, "headend": "PE9"})
    assert text.startswith("Error: no node 'PE9' in the topology")
    assert route.call_count == 0


@respx.mock
async def test_create_blank_path_name_is_error_before_any_call(writes):
    networks = mock_networks()
    text = await call_tool_text(writes, "cnc_create_sr_policy", {**CREATE_ARGS, "path_name": "  "})
    assert text.startswith("Error: path_name is empty")
    assert "SR Policy name is empty." in text
    assert networks.call_count == 0


@respx.mock
async def test_create_degraded_is_success_with_note(writes):
    mock_networks()
    respx.post(srp("sr-policy-create")).mock(
        return_value=ok(write_result("10.0.0.1", "10.0.0.3", 200, "degraded", "relaxed"))
    )
    text = await call_tool_text(writes, "cnc_create_sr_policy", CREATE_ARGS)
    data = json.loads(text)
    assert data["state"] == "degraded" and data["message"] == "relaxed"
    assert data["note"].startswith("The platform reports the policy as DEGRADED")


@respx.mock
async def test_create_empty_500_renders_the_coe_hint_and_is_not_retried(make_settings):
    mock_networks()
    route = respx.post(srp("sr-policy-create")).mock(return_value=EMPTY_500)
    mcp = build(make_settings(enable_writes=True, max_retries=3))
    text = await call_tool_text(mcp, "cnc_create_sr_policy", CREATE_ARGS)
    assert route.call_count == 1
    assert text.startswith(f"Error: {COE_EMPTY_500_HINT}")


@respx.mock
async def test_create_no_results_is_error(writes):
    mock_networks()
    respx.post(srp("sr-policy-create")).mock(return_value=ok(srp_out(results=[])))
    text = await call_tool_text(writes, "cnc_create_sr_policy", CREATE_ARGS)
    assert text.startswith("Error: the Optimization Engine returned no result for create of")


@respx.mock
async def test_create_204_without_a_body_is_an_error_that_says_to_verify(writes):
    """The 7.2 document lists a bodiless 204 (never seen live): the outcome is unknown, so the
    tool must neither claim success nor tell the agent to blindly re-send."""
    mock_networks()
    respx.post(srp("sr-policy-create")).mock(return_value=httpx.Response(204))
    text = await call_tool_text(writes, "cnc_create_sr_policy", CREATE_ARGS)
    assert text.startswith(
        "Error: the Optimization Engine returned no result for create of PE1 (10.0.0.1) -> "
        "PE2 (10.0.0.3) color 200 (status=None, message=None, state=None)"
    )
    assert "may or may not have been applied" in text
    assert "cnc_get_sr_policy" in text


# --- cnc_update_sr_policy ------------------------------------------------------------


@respx.mock
async def test_update_sends_modify_with_the_full_path(writes):
    mock_networks()
    route = respx.post(srp("sr-policy-modify")).mock(return_value=ok(MODIFY_SUCCESS))
    text = await call_tool_text(
        writes,
        "cnc_update_sr_policy",
        {
            "headend": "PE1",
            "endpoint": "PE2",
            "color": 200,
            "path_name": "mcp-exp-200",
            "path_type": "explicit",
            "hops": "P2,PE2",
        },
    )
    assert_yang_post(route)
    assert sent(route) == {
        "input": {
            "sr-policies": [
                {
                    "head-end": "10.0.0.1",
                    "end-point": "10.0.0.3",
                    "color": 200,
                    "path-name": "mcp-exp-200",
                    "sr-policy-path": {"hops": WIRE_HOPS_P2_PE2},
                }
            ]
        }
    }
    data = json.loads(text)
    assert data["state"] == "success"
    assert data["next"].startswith("The PCE re-signals the policy with the new path")


@respx.mock
async def test_update_unknown_policy_is_error_with_the_platform_message(writes):
    mock_networks()
    respx.post(srp("sr-policy-modify")).mock(return_value=ok(MODIFY_UNKNOWN))
    text = await call_tool_text(
        writes,
        "cnc_update_sr_policy",
        {"headend": "PE1", "endpoint": "PE2", "color": 555, "path_name": "x"},
    )
    assert text == (
        "Error: modify failed for PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 555: "
        f"{UNKNOWN_POLICY_MESSAGE}"
    )


@respx.mock
async def test_update_unknown_endpoint_is_error_before_the_rpc(writes):
    mock_networks()
    route = respx.post(srp("sr-policy-modify")).mock(return_value=ok(MODIFY_SUCCESS))
    text = await call_tool_text(
        writes,
        "cnc_update_sr_policy",
        {"headend": "PE1", "endpoint": "PE9", "color": 200, "path_name": "x"},
    )
    assert text.startswith("Error: no node 'PE9' in the topology")
    assert route.call_count == 0


# --- cnc_delete_sr_policy ------------------------------------------------------------

DELETE_ARGS = {"headend": "PE1", "endpoint": "PE2", "color": 200}


@respx.mock
async def test_delete_pce_initiated_reads_then_deletes(writes):
    mock_networks()
    read = respx.get(policy_url("10.0.0.1", "10.0.0.3", 200)).mock(
        return_value=ok(keyed(PCE_INITIATED))
    )
    route = respx.post(srp("sr-policy-delete")).mock(return_value=ok(DELETE_SUCCESS))
    text = await call_tool_text(writes, "cnc_delete_sr_policy", DELETE_ARGS)
    assert read.call_count == 1
    assert read.calls[0].request.headers["Accept"] == YANG_JSON
    assert_yang_post(route)
    assert sent(route) == {
        "input": {"sr-policies": [{"head-end": "10.0.0.1", "end-point": "10.0.0.3", "color": 200}]}
    }
    data = json.loads(text)
    assert data["state"] == "success" and data["pcep_flag_c"] == 1 and data["forced"] is False
    assert data["reported"] is True
    assert data["headend_node"] == "PE1" and data["endpoint"] == "10.0.0.3"
    assert "cnc_get_sr_policy" in data["next"] and "note" not in data


@respx.mock
async def test_delete_pce_initiated_with_force_is_not_marked_forced(writes):
    """force is only 'used' when a refusal had to be bypassed."""
    mock_networks()
    respx.get(policy_url("10.0.0.1", "10.0.0.3", 200)).mock(return_value=ok(keyed(PCE_INITIATED)))
    respx.post(srp("sr-policy-delete")).mock(return_value=ok(DELETE_SUCCESS))
    text = await call_tool_text(writes, "cnc_delete_sr_policy", {**DELETE_ARGS, "force": True})
    data = json.loads(text)
    assert data["forced"] is False and data["pcep_flag_c"] == 1 and "note" not in data


@respx.mock
async def test_delete_refuses_pcc_initiated_without_force(writes):
    mock_networks()
    respx.get(policy_url("10.0.0.1", "10.0.0.3", 100)).mock(return_value=ok(keyed(PCC_INITIATED)))
    route = respx.post(srp("sr-policy-delete")).mock(return_value=ok(DELETE_SUCCESS))
    text = await call_tool_text(writes, "cnc_delete_sr_policy", {**DELETE_ARGS, "color": 100})
    # verified live: the COE's Config DB holds only PCE-initiated policies
    assert text == (
        "Error: SR policy PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 100 is PCC-initiated (configured "
        "on PE1); it is not in the Optimization Engine's Config DB, so a PCE delete cannot "
        "remove it (the platform answers 'SR policy not found in Config DB'). Remove it from "
        "the router's configuration instead, or pass force=true to send the delete anyway."
    )
    assert route.call_count == 0


@respx.mock
async def test_delete_pcc_initiated_with_force_proceeds_with_a_note(writes):
    mock_networks()
    respx.get(policy_url("10.0.0.1", "10.0.0.3", 100)).mock(return_value=ok(keyed(PCC_INITIATED)))
    route = respx.post(srp("sr-policy-delete")).mock(
        return_value=ok(write_result("10.0.0.1", "10.0.0.3", 100, "success"))
    )
    text = await call_tool_text(
        writes, "cnc_delete_sr_policy", {**DELETE_ARGS, "color": 100, "force": True}
    )
    assert route.call_count == 1
    assert sent(route)["input"]["sr-policies"][0]["color"] == 100
    data = json.loads(text)
    assert data["forced"] is True and data["pcep_flag_c"] == 0 and data["reported"] is True
    assert data["note"].startswith("The policy was PCC-initiated")


@respx.mock
async def test_delete_missing_policy_is_error_and_nothing_is_sent(writes):
    mock_networks()
    respx.get(policy_url("10.0.0.1", "10.0.0.3", 200)).mock(return_value=DATA_MISSING_409)
    route = respx.post(srp("sr-policy-delete")).mock(return_value=ok(DELETE_SUCCESS))
    text = await call_tool_text(writes, "cnc_delete_sr_policy", DELETE_ARGS)
    assert text.startswith(
        "Error: no SR policy PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 200 is reported by the SR-PCE "
        "feed; nothing was deleted."
    )
    # The way out for a policy the NBI does not report (no report-all, feed down) is named.
    assert "report-all" in text and "pass force=true" in text
    assert route.call_count == 0


@respx.mock
async def test_delete_not_reported_with_force_sends_the_delete(writes):
    """A PCE-initiated policy the PCC does not report (no report-all, the seconds after a
    create, the gRPC feed down) is exactly what sr-policy-delete removes: force must reach it."""
    mock_networks()
    read = respx.get(policy_url("10.0.0.1", "10.0.0.3", 200)).mock(return_value=DATA_MISSING_409)
    route = respx.post(srp("sr-policy-delete")).mock(return_value=ok(DELETE_SUCCESS))
    text = await call_tool_text(writes, "cnc_delete_sr_policy", {**DELETE_ARGS, "force": True})
    assert read.call_count == 1 and route.call_count == 1
    assert_yang_post(route)
    assert sent(route) == {
        "input": {"sr-policies": [{"head-end": "10.0.0.1", "end-point": "10.0.0.3", "color": 200}]}
    }
    data = json.loads(text)
    assert data["state"] == "success"
    assert data["reported"] is False and data["pcep_flag_c"] is None and data["forced"] is True
    assert data["note"].startswith("The policy was not reported by the SR-PCE feed")
    assert "cnc_list_sr_policies_on_nodes" in data["note"]


@respx.mock
async def test_delete_not_reported_with_force_surfaces_the_platform_failure(writes):
    """An unknown key with force: the COE's own verdict is reported, not the tool's guess."""
    mock_networks()
    respx.get(policy_url("10.0.0.1", "10.0.0.3", 200)).mock(return_value=DATA_MISSING_409)
    respx.post(srp("sr-policy-delete")).mock(
        return_value=ok(write_result("10.0.0.1", "10.0.0.3", 200, "failure", "Policy not found"))
    )
    text = await call_tool_text(writes, "cnc_delete_sr_policy", {**DELETE_ARGS, "force": True})
    assert text == (
        "Error: delete failed for PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 200: Policy not found"
    )


@respx.mock
async def test_delete_answer_without_the_key_counts_as_missing(writes):
    mock_networks()
    respx.get(policy_url("10.0.0.1", "10.0.0.3", 200)).mock(return_value=ok(keyed(PCC_INITIATED)))
    route = respx.post(srp("sr-policy-delete")).mock(return_value=ok(DELETE_SUCCESS))
    text = await call_tool_text(writes, "cnc_delete_sr_policy", DELETE_ARGS)
    assert "nothing was deleted" in text
    assert route.call_count == 0


NO_PCEP_INFO = {
    **PCE_INITIATED,
    "policy-details": {
        k: v for k, v in PCE_INITIATED["policy-details"].items() if k != "pcep-info"
    },
}


@respx.mock
async def test_delete_refuses_a_policy_without_pcep_flag_without_force(writes):
    """Judgement call pinned: an absent pcep-flag-c means 'origin unknown', which is a refusal
    (the PCE can only withdraw what it initiated), not a pass."""
    mock_networks()
    respx.get(policy_url("10.0.0.1", "10.0.0.3", 200)).mock(return_value=ok(keyed(NO_PCEP_INFO)))
    route = respx.post(srp("sr-policy-delete")).mock(return_value=ok(DELETE_SUCCESS))
    text = await call_tool_text(writes, "cnc_delete_sr_policy", DELETE_ARGS)
    assert text.startswith(
        "Error: SR policy PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 200 carries no "
        "pcep-info.pcep-flag-c on the topology NBI, so the tool cannot tell whether the PCE "
        "initiated it"
    )
    assert "nothing was deleted" in text and "force=true" in text
    assert route.call_count == 0


@respx.mock
async def test_delete_policy_without_pcep_flag_with_force_proceeds_with_a_note(writes):
    mock_networks()
    respx.get(policy_url("10.0.0.1", "10.0.0.3", 200)).mock(return_value=ok(keyed(NO_PCEP_INFO)))
    route = respx.post(srp("sr-policy-delete")).mock(return_value=ok(DELETE_SUCCESS))
    text = await call_tool_text(writes, "cnc_delete_sr_policy", {**DELETE_ARGS, "force": True})
    assert route.call_count == 1
    data = json.loads(text)
    assert data["reported"] is True and data["pcep_flag_c"] is None and data["forced"] is True
    assert data["note"].startswith("The policy carried no pcep-flag-c")


@respx.mock
async def test_delete_refuses_an_unrecognised_pcep_flag_value_without_force(writes):
    odd = nbi_policy("10.0.0.1", "10.0.0.3", 200, flag_c=2)
    mock_networks()
    respx.get(policy_url("10.0.0.1", "10.0.0.3", 200)).mock(return_value=ok(keyed(odd)))
    route = respx.post(srp("sr-policy-delete")).mock(return_value=ok(DELETE_SUCCESS))
    text = await call_tool_text(writes, "cnc_delete_sr_policy", DELETE_ARGS)
    assert "carries pcep-flag-c 2 on the topology NBI" in text
    assert route.call_count == 0


@respx.mock
async def test_delete_failure_result_is_error(writes):
    mock_networks()
    respx.get(policy_url("10.0.0.1", "10.0.0.3", 200)).mock(return_value=ok(keyed(PCE_INITIATED)))
    respx.post(srp("sr-policy-delete")).mock(return_value=ok(DELETE_FAILURE))
    text = await call_tool_text(writes, "cnc_delete_sr_policy", DELETE_ARGS)
    assert text == (
        "Error: delete failed for PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 200: Policy delete failed"
    )


@respx.mock
async def test_delete_read_failure_is_error(make_settings):
    mock_networks()
    respx.get(policy_url("10.0.0.1", "10.0.0.3", 200)).mock(
        return_value=httpx.Response(403, json={"message": "Unauthorized request"})
    )
    route = respx.post(srp("sr-policy-delete")).mock(return_value=ok(DELETE_SUCCESS))
    mcp = build(make_settings(enable_writes=True, max_retries=0))
    text = await call_tool_text(mcp, "cnc_delete_sr_policy", DELETE_ARGS)
    assert text.startswith("Error: API request failed with status 403")
    assert route.call_count == 0


@respx.mock
async def test_delete_unknown_node_is_error_before_any_policy_read(writes):
    mock_networks()
    read = respx.get(policy_url("10.0.0.1", "10.0.0.3", 200)).mock(
        return_value=ok(keyed(PCE_INITIATED))
    )
    text = await call_tool_text(writes, "cnc_delete_sr_policy", {**DELETE_ARGS, "endpoint": "PE9"})
    assert text.startswith("Error: no node 'PE9' in the topology")
    assert read.call_count == 0


# --- cnc_set_sr_policy_path_notifications --------------------------------------------


@respx.mock
async def test_set_notifications_sends_the_flag_then_rereads(writes):
    setter = respx.post(coe("set-interface-sr-policy-paths-notification-state")).mock(
        return_value=ok(SET_ACCEPTED)
    )
    getter = respx.post(coe("get-interface-sr-policy-paths-notification-state")).mock(
        return_value=ok(NOTIFICATIONS_DISABLED)
    )
    text = await call_tool_text(writes, "cnc_set_sr_policy_path_notifications", {"enabled": False})
    assert_yang_post(setter)
    assert sent(setter) == {"input": {"enabled": False}}
    assert getter.call_count == 1 and getter.calls[0].request.content == b""
    assert text.startswith("SR policy path notifications are now disabled.")
    assert '"enabled": false' in text


@respx.mock
async def test_set_notifications_reread_disagreeing_is_error(writes):
    respx.post(coe("set-interface-sr-policy-paths-notification-state")).mock(
        return_value=ok(SET_ACCEPTED)
    )
    respx.post(coe("get-interface-sr-policy-paths-notification-state")).mock(
        return_value=ok(NOTIFICATIONS_DISABLED)
    )
    text = await call_tool_text(writes, "cnc_set_sr_policy_path_notifications", {"enabled": True})
    assert text.startswith(
        "Error: the Optimization Engine accepted the change but still reports the notifications "
        "disabled (wanted enabled)."
    )


@respx.mock
async def test_set_notifications_status_error_is_error(writes):
    respx.post(coe("set-interface-sr-policy-paths-notification-state")).mock(
        return_value=ok(STATUS_ERROR_OUT)
    )
    getter = respx.post(coe("get-interface-sr-policy-paths-notification-state")).mock(
        return_value=ok(NOTIFICATIONS_ENABLED)
    )
    text = await call_tool_text(writes, "cnc_set_sr_policy_path_notifications", {"enabled": True})
    assert text.startswith("Error: set-interface-sr-policy-paths-notification-state failed:")
    assert getter.call_count == 0


# --- cnc_wait_for_sr_policy_oper_state -----------------------------------------------

WAIT_ARGS = {"headend": "PE1", "endpoint": "PE2", "color": 200}


@respx.mock
async def test_wait_reaches_up_after_polling_through_a_409(reads, fake_clock):
    mock_networks()
    route = mock_policy(
        DATA_MISSING_409,
        ok(keyed(nbi_policy("10.0.0.1", "10.0.0.3", 200, flag_c=1, oper="DOWN"))),
        ok(keyed(PCE_INITIATED)),
    )
    text = await call_tool_text(
        reads,
        "cnc_wait_for_sr_policy_oper_state",
        {**WAIT_ARGS, "timeout_seconds": 60, "interval_seconds": 5},
    )
    assert route.call_count == 3
    assert route.calls[0].request.headers["Accept"] == YANG_JSON
    assert text.startswith("SR policy PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 200 is UP after 10s.")
    data = json.loads(text.split("\n", 1)[1])
    assert data["reported"] is True and data["oper_state"] == "UP" and data["pcep_flag_c"] == 1
    assert data["paths"] == [
        {
            "path_name": "mcp-dyn-200",
            "path_type": "PT-DYNAMIC",
            "preference": 100,
            "oper_state": "UP",
        }
    ]


@respx.mock
async def test_wait_times_out_non_error_while_never_reported(reads, fake_clock):
    mock_networks()
    route = mock_policy(DATA_MISSING_409)
    text = await call_tool_text(
        reads,
        "cnc_wait_for_sr_policy_oper_state",
        {**WAIT_ARGS, "timeout_seconds": 10, "interval_seconds": 5},
    )
    assert route.call_count == 3  # t=0, 5 and 10: the 409s keep polling until the budget is gone
    assert not text.startswith("Error:")
    assert text.startswith(
        "SR policy PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 200 not UP after 10s; current: not "
        "reported."
    )
    assert "PCEP initiate" in text
    assert json.loads(text.split("\n", 1)[1]) == {"reported": False}


@respx.mock
async def test_wait_times_out_non_error_with_the_current_state(reads, fake_clock):
    mock_networks()
    mock_policy(ok(keyed(nbi_policy("10.0.0.1", "10.0.0.3", 200, flag_c=1, oper="DOWN"))))
    text = await call_tool_text(
        reads,
        "cnc_wait_for_sr_policy_oper_state",
        {**WAIT_ARGS, "timeout_seconds": 5, "interval_seconds": 5},
    )
    assert text.startswith(
        "SR policy PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 200 not UP after 5s; current: DOWN."
    )
    assert '"oper_state": "DOWN"' in text


@respx.mock
async def test_wait_for_down_target(reads, fake_clock):
    mock_networks()
    route = mock_policy(ok(keyed(nbi_policy("10.0.0.1", "10.0.0.3", 200, flag_c=1, oper="DOWN"))))
    text = await call_tool_text(
        reads, "cnc_wait_for_sr_policy_oper_state", {**WAIT_ARGS, "target": "down"}
    )
    assert route.call_count == 1
    assert text.startswith("SR policy PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 200 is DOWN after 0s.")


@respx.mock
async def test_wait_bad_target_is_error_before_any_call(reads):
    networks = mock_networks()
    text = await call_tool_text(
        reads, "cnc_wait_for_sr_policy_oper_state", {**WAIT_ARGS, "target": "ACTIVE"}
    )
    assert text.startswith("Error: oper_state must be one of UP, DOWN")
    assert networks.call_count == 0


@respx.mock
async def test_wait_unknown_node_is_error_before_polling(reads, fake_clock):
    mock_networks()
    route = mock_policy(ok(keyed(PCE_INITIATED)))
    text = await call_tool_text(
        reads, "cnc_wait_for_sr_policy_oper_state", {**WAIT_ARGS, "headend": "PE9"}
    )
    assert text.startswith("Error: no node 'PE9' in the topology")
    assert route.call_count == 0


@respx.mock
async def test_wait_poll_failure_is_error(make_settings, fake_clock):
    mock_networks()
    error = {"errors": {"error": [{"error-tag": "invalid-value", "error-message": "bad"}]}}
    mock_policy(httpx.Response(400, json=error))
    mcp = build(make_settings(max_retries=0))
    text = await call_tool_text(mcp, "cnc_wait_for_sr_policy_oper_state", WAIT_ARGS)
    assert text.startswith("Error: API request failed with status 400")
