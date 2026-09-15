"""TE-state tools end-to-end through MCPServer (schema validation included).

The module is registered directly (not through build_server) so the test does
not depend on tools/__init__.py's module list. All HTTP is mocked with respx.
Fixtures are the payloads verified live on Crosswork 7.2 (2026-09-13, SR-PCE
gRPC feed up, see the platform notes): the ``sr-policies`` container with the
two PE1<->PE2 color-100 policies (verbatim shape — ``pce-controlled`` a JSON
boolean, ``update-time`` an epoch-ms string, hops under ``segment-list`` and
``hop``), the keyed ``policy`` answer, the ``sr-policy-pm`` and ``igp-link-pm``
entries (string-typed numbers), the ``409 data-missing`` document every
missing entry answers, and ``{}`` for the empty ``p2mp-policies`` /
``rsvp-te-tunnels`` containers. The P2MP / RSVP sample entries used for the
rendering tests follow the 7.2 OpenAPI documents (nothing was available live).

SRv6 (2026-09-15): the lab is SR-MPLS only, so the SRv6 fixtures below —
IPv6 policy keys, ``srv6-binding-sid``, ``IPV6-NODE-SID`` / ``IPV6-ADJ-SID``
hops with their ``srv6-node-sid`` / ``srv6-adjacency-sid`` objects, and the
topology's ``ipv6-router-id`` leaf-list — follow the 7.2
``segment_routing_policy_details`` / topology documents (wire spelling: the
case container bare, RFC 7951; one variant uses the document's module-prefixed
spelling) and have never been observed on the wire. What IS verified live: an
IPv6 policy key percent-encoded as ``2001%3Adb8%3A%3A1`` is type-checked by
the NBI and answers 409 ``data-missing`` when absent, on ``policy`` and
``sr-policy-pm`` alike (the 409 fixture is the same document).
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from mcp.server.mcpserver import MCPServer

from cnc_mcp.auth import StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.config import Settings
from cnc_mcp.errors import PlatformError
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import te_state
from cnc_mcp.tools.te_state import (
    active_path,
    active_tunnel_path,
    as_bool,
    canonical_ip,
    end_label,
    ends_text,
    entries_matching,
    find_node,
    has_pm_telemetry,
    hop_is_srv6,
    hop_srv6_sid,
    hop_text,
    hops_text,
    igp_link_pm_url,
    ipv6_key_pair,
    is_invalid_key,
    is_ip_address,
    is_ipv6,
    key_matches,
    matches_policy_filter,
    node_key_ids,
    node_router_id,
    node_te_router_ids,
    node_text,
    normalize_dataplane,
    normalize_oper_state,
    p2mp_policy_url,
    path_hops,
    pcep_flag_c,
    policy_bsid,
    policy_dataplane,
    policy_hops,
    policy_origin,
    policy_origin_line,
    router_id_names,
    rsvp_pm_url,
    rsvp_tunnel_url,
    select_router_id,
    sid_structure_text,
    sr_policy_pm_url,
    sr_policy_summary,
    sr_policy_url,
    srv6_binding_sid,
    srv6_sid_text,
)
from tests.conftest import BASE_URL, call_tool_text

TE_DATA = f"{BASE_URL}/crosswork/nbi/topology/v3/restconf/data"
NETWORKS_URL = f"{TE_DATA}/ietf-network-state:networks"
SR_POLICIES_URL = f"{TE_DATA}/cisco-crosswork-segment-routing-policy:sr-policies"
P2MP_POLICIES_URL = f"{TE_DATA}/cisco-crosswork-segment-routing-p2mp-policy:p2mp-policies"
RSVP_TUNNELS_URL = f"{TE_DATA}/cisco-crosswork-rsvp-te-tunnel:rsvp-te-tunnels"
PM = f"{TE_DATA}/cisco-crosswork-performance-metrics"
IGP_LINK_PM_URL = f"{PM}:igp-links-performance-metrics/igp-link-pm"
SR_POLICY_PM_URL = f"{PM}:sr-policies-performance-metrics/sr-policy-pm"
RSVP_PM_URL = f"{PM}:rsvp-policies-performance-metrics/rsvp-policy-pm"
YANG_JSON = "application/yang-data+json"

# The verified encodings: multi-part keys comma-joined, the link id with %20 / %3A / %2F.
PE1_PE2_KEY = "10.0.0.1,10.0.0.3,100"
LINK_ID = "P2 : GigabitEthernet0/0/0/0 : PE2 : GigabitEthernet0/0/0/1 : ISIS_IPV4_L2"
LINK_ID_ENCODED = (
    "P2%20%3A%20GigabitEthernet0%2F0%2F0%2F0%20%3A%20PE2%20%3A%20"
    "GigabitEthernet0%2F0%2F0%2F1%20%3A%20ISIS_IPV4_L2"
)
L2_LINK_ID = "P2 : GigabitEthernet0/0/0/0 : PE2 : GigabitEthernet0/0/0/1 : ETHERNET"


def policy(headend: str, endpoint: str, label: int, update_time: str) -> dict:
    """One SR policy exactly as the live ``sr-policies`` container listed it."""
    hop = {"type": "IPV4-NODE-SID", "local-ip-addr": endpoint, "label": label}
    return {
        "headend": headend,
        "endpoint": endpoint,
        "color": 100,
        "policy-details": {
            "pcep-info": {"pcep-flag-c": 0},
            "path": [
                {
                    "optimization-metric": {"metric-type": "IGP-METRIC", "metric-value": 20},
                    "segment-list": [{"weight": 1, "hop": [hop]}],
                    "preference": 100,
                    "oper-state": "UP",
                    "constraints": {"sid-algorithm": 0},
                    "hop": [hop],
                    "path-type": "PT-DYNAMIC",
                    "path-name": "CNC-DYN-100",
                }
            ],
            "binding-sid": 24005,
            "update-time": update_time,
            "pce-controlled": True,
            "pcc-address": headend,
        },
        "admin-state": "UP",
        "oper-state": "UP",
        "sr-policy-type": "REGULAR",
    }


PE2_POLICY = policy("10.0.0.3", "10.0.0.1", 16001, "1789293963860")
PE1_POLICY = policy("10.0.0.1", "10.0.0.3", 16003, "1789293787548")
# Verified: the container GET (PE2's policy listed first, as live).
SR_POLICIES = {
    "cisco-crosswork-segment-routing-policy:sr-policies": {"policy": [PE2_POLICY, PE1_POLICY]}
}
# Verified: the keyed GET answers the bare list key with one entry.
SR_POLICY_KEYED = {"cisco-crosswork-segment-routing-policy:policy": [PE1_POLICY]}

# --- SRv6 (7.2 document shapes; never observed live — the lab has no SRv6) ---------
# The policy key is the nodes' IPv6 TE router-ids; the BSID is the srv6-binding-sid
# container; a hop's sid-value choice case sits directly in the hop, bare (RFC 7951).
SID_STRUCTURE = {"lb-length": 32, "ln-length": 16, "func-length": 16, "arg-length": 0}
SRV6_NODE_HOP = {
    "type": "IPV6-NODE-SID",
    "local-ip-addr": "2001:db8::3",
    "srv6-node-sid": {
        "sid": "fc00:0:3::",
        "endpoint-behavior": "uN",
        "algorithm": 0,
        "srv6-sid-structure": SID_STRUCTURE,
    },
}
# A protected (TI-LFA) adjacency: the hop's protected-flag and the SID object's own
# protected leaf agree, as the document shape has them (the renderer ORs the two).
SRV6_ADJ_HOP = {
    "type": "IPV6-ADJ-SID",
    "local-ip-addr": "2001:db8:1::1",
    "remote-ip-addr": "2001:db8:1::2",
    "protected-flag": True,
    "srv6-adjacency-sid": {
        "sid": "fc00:0:1:e000::",
        "endpoint-behavior": "uA",
        "protected": True,
        "flags": 0,
        "algorithm": 0,
        "weight": 0,
        "srv6-sid-structure": SID_STRUCTURE,
    },
}
SRV6_BSID = {
    "sid": "fc00:0:1:1::",
    "endpoint-behavior": "uB6.Insert.Red",
    "srv6-sid-structure": SID_STRUCTURE,
}
PE1_V6, PE2_V6 = "2001:db8::1", "2001:db8::3"
SRV6_POLICY = {
    "headend": PE1_V6,
    "endpoint": PE2_V6,
    "color": 6001,
    "policy-details": {
        "pcep-info": {"pcep-flag-c": 0},
        "srv6-binding-sid": SRV6_BSID,
        "path": [
            {
                "optimization-metric": {"metric-type": "IGP-METRIC", "metric-value": 20},
                "segment-list": [{"weight": 1, "hop": [SRV6_NODE_HOP, SRV6_ADJ_HOP]}],
                "preference": 100,
                "oper-state": "UP",
                "constraints": {"sid-algorithm": 0},
                "hop": [SRV6_NODE_HOP, SRV6_ADJ_HOP],
                "path-type": "PT-DYNAMIC",
                "path-name": "srte_c_6001_ep_2001:db8::3",
            }
        ],
        "update-time": "1789293787548",
        "pce-controlled": True,
        "pcc-address": PE1_V6,
    },
    "admin-state": "UP",
    "oper-state": "UP",
    "sr-policy-type": "REGULAR",
}
# The verified URL form of an IPv6 key: ':' percent-encoded inside each part.
PE1_PE2_V6_KEY = "2001%3Adb8%3A%3A1,2001%3Adb8%3A%3A3,6001"
SRV6_POLICY_KEYED = {"cisco-crosswork-segment-routing-policy:policy": [SRV6_POLICY]}
MIXED_POLICIES = {
    "cisco-crosswork-segment-routing-policy:sr-policies": {
        "policy": [PE2_POLICY, PE1_POLICY, SRV6_POLICY]
    }
}
# Verified: string-typed numbers, int delay.
IGP_LINK_PM = {
    "cisco-crosswork-performance-metrics:igp-link-pm": [
        {
            "link-id": LINK_ID,
            "source": {"source-node": "P2", "source-tp": "GigabitEthernet0/0/0/0"},
            "destination": {"dest-tp": "GigabitEthernet0/0/0/1", "dest-node": "PE2"},
            "max-bandwidth-kbps": "1000000",
            "bandwidth-utilization-kbps": "1",
            "interfaces": {
                "TX-Errors": "0",
                "Throughput": "0.000141605327371508",
                "TX-packet-drops": "0",
                "Bandwidth": "1000000000",
            },
            "delay": 10,
        }
    ]
}
SR_POLICY_PM = {
    "cisco-crosswork-performance-metrics:sr-policy-pm": [
        {
            "headend": "10.0.0.1",
            "endpoint": "10.0.0.3",
            "color": 100,
            "delay": 20,
            "bandwidth-utilization-kbps": "0",
        }
    ]
}
EMPTY: dict = {}  # verified: p2mp-policies and rsvp-te-tunnels answer {} when empty

# The topology ``networks`` collection the host-name resolver reads (the verified
# member names, reduced to what name -> router-id resolution needs): PE1 / P1 / PE2
# with their router-ids, plus an LLDP-only node the SR-PCE feed does not know as SR.
L3_NODE = "ietf-l3-unicast-topology-state:l3-node-attributes"


def topo_node(node_id: str, router_id: str) -> dict:
    return {"node-id": node_id, L3_NODE: {"name": node_id, "router-id": [router_id]}}


TOPO_NODES = [
    topo_node("PE1", "10.0.0.1"),
    topo_node("P1", "10.0.0.2"),
    topo_node("PE2", "10.0.0.3"),
    {"node-id": "SW1"},
]
NETWORKS = {
    "ietf-network-state:networks": {
        "network": [{"network-id": "Default-network", "node": TOPO_NODES}]
    }
}
# The same nodes once the SRv6 underlay is up (7.2 document shape, absent on the lab):
# the PEs carry the IPv6 TE router-id leaf-list next to the IPv4 router-id; P1 does not.
IPV6_ROUTER_ID = "cisco-crosswork-l3-te-topology:ipv6-router-id"


def topo_node_v6(node_id: str, router_id: str, ipv6_router_id: str) -> dict:
    node = topo_node(node_id, router_id)
    node[L3_NODE][IPV6_ROUTER_ID] = [ipv6_router_id]
    return node


TOPO_NODES_V6 = [
    topo_node_v6("PE1", "10.0.0.1", PE1_V6),
    topo_node("P1", "10.0.0.2"),
    topo_node_v6("PE2", "10.0.0.3", PE2_V6),
    {"node-id": "SW1"},
]
NETWORKS_V6 = {
    "ietf-network-state:networks": {
        "network": [{"network-id": "Default-network", "node": TOPO_NODES_V6}]
    }
}
# The PM entry with NAPM telemetry present (7.2 document shape — no SR-PM probe was
# available live): delay is then measured and the modelled caveat must not appear.
SR_POLICY_PM_TELEMETRY = {
    "cisco-crosswork-performance-metrics:sr-policy-pm": [
        {
            **SR_POLICY_PM["cisco-crosswork-performance-metrics:sr-policy-pm"][0],
            "delay-telemetry": 1234,
            "jitter-telemetry": 12,
        }
    ]
}

# Verified: every missing keyed entry (and the unkeyed PM containers) answers this.
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
# Verified: a wrong module prefix answers 400 unknown-element (bare ``errors`` key).
UNKNOWN_ELEMENT_400 = httpx.Response(
    400,
    json={
        "errors": {
            "error": [
                {
                    "error-tag": "unknown-element",
                    "error-message": "Failed to lookup for module with name 'x'.",
                    "error-type": "protocol",
                }
            ]
        }
    },
)
# A plain 404 (no RESTCONF document): malformed / unrouted URL, never not-found.
BARE_404 = httpx.Response(404, text="404 page not found")
# A 404 carrying a RESTCONF document: the NSO proxy's not-found spelling, which
# restconf.is_not_found accepts — NEVER observed on the topology NBI, whose only
# not-found is 409 data-missing, so the tools must not read it as "no such object".
RESTCONF_404 = httpx.Response(
    404,
    json={
        "errors": {
            "error": [
                {
                    "error-tag": "invalid-value",
                    "error-message": "uri keypath not found",
                    "error-type": "application",
                }
            ]
        }
    },
)
# A 200 whose body is not JSON (a proxy / login page in the way).
HTML_200 = httpx.Response(
    200, text="<html><body>login</body></html>", headers={"Content-Type": "text/html"}
)
# Verified: a host name where a router-id key part belongs (policy=PE1,PE2,100).
INVALID_VALUE_400 = httpx.Response(
    400,
    json={
        "errors": {
            "error": [
                {
                    "error-tag": "invalid-value",
                    "error-message": (
                        "Invalid value 'PE1' for (http://cisco.com/ns/yang/"
                        "cisco-crosswork-segment-routing-policy?revision=2025-04-21)headend"
                    ),
                    "error-type": "protocol",
                }
            ]
        }
    },
)

# Spec-shaped samples (segment_routing_point_to_multi_point_tree_sid_policy_details_7_2_0.json
# and rsvp_te_lsp_details_7_2_0.json) — NOT verified live; used for the renderers only.
P2MP_POLICY = {
    "name": "tree-100",
    "root-address": "10.0.0.1",
    "pcc-address": "10.0.0.1",
    "pce-address": "10.0.0.5",
    "initiation-type": "PCE-INITIATED",
    "admin-state": "UP",
    "oper-state": "UP",
    "tree-id": 524289,
    "destination": [{"destination-address": "10.0.0.3"}, {"destination-address": "10.0.0.4"}],
    "candidate-path": [
        {
            "name": "tree-100-cp",
            "oper-state": "UP",
            "path-type": "DYNAMIC",
            "label": 15100,
            "metric-type": "IGP-METRIC",
            "preference": 100,
            "programming-state": "NONE",
            "path-constraints": {"frr-protected": "true"},
            "p2mp-node": [
                {
                    "hostname": "PE1",
                    "node-ip-address": "10.0.0.1",
                    "role": "INGRESS",
                    "next-hop": [
                        {
                            "local-address": "10.1.1.1",
                            "remote-address": "10.1.1.2",
                            "label": 15100,
                            "next-hop-node-name": "P1",
                            "next-hop-node-address": "10.0.0.2",
                        }
                    ],
                },
                {"hostname": "PE2", "node-ip-address": "10.0.0.3", "role": "EGRESS"},
            ],
        }
    ],
    "vendor-extra": "kept",
}
P2MP_POLICIES = {
    "cisco-crosswork-segment-routing-p2mp-policy:p2mp-policies": {"p2mp-policy": [P2MP_POLICY]}
}
RSVP_TUNNEL = {
    "headend": "10.0.0.1",
    "endpoint": "10.0.0.3",
    "tunnel-id": 7,
    "description": "t7",
    "admin-state": "UP",
    "oper-state": "UP",
    "rsvp-te-tunnel-type": "OTHER",
    "tunnel-details": {
        "binding-label": 24010,
        "signaled-bandwidth-mbps": 50,
        "setup-priority": 7,
        "hold-priority": 7,
        "pce-controlled": "false",
        "pcc-address": "10.0.0.1",
        "pcep-info": {"pcep-flag-d": "false"},
        "update-time": 1789293787548,
        "path": [
            {
                "path-name": "t7-path",
                "path-type": "PT-EXPLICIT",
                "path-oper-state": "ACTIVE",
                "optimization-metric": {"metric-type": "TE-METRIC", "metric-value": 30},
                "constraints": {"affinity": {"exclude-any": 0}},
                "ero-hop": [
                    {"index": 1, "ip-address": "10.1.1.2", "te-hop-type": "strict"},
                    {"index": 2, "ip-address": "10.1.2.2", "te-hop-type": "strict"},
                ],
                "rro-hop": [
                    {"index": 1, "node-id": "P1", "ip-address": "10.0.0.2"},
                    {"index": 2, "node-id": "PE2", "ip-address": "10.0.0.3"},
                ],
            }
        ],
    },
}
RSVP_TUNNELS = {"cisco-crosswork-rsvp-te-tunnel:rsvp-te-tunnels": {"rsvp-te-tunnel": [RSVP_TUNNEL]}}
RSVP_PM = {
    "cisco-crosswork-performance-metrics:rsvp-policy-pm": [
        {
            "headend": "10.0.0.1",
            "endpoint": "10.0.0.3",
            "tunnel-id": 7,
            "delay": 30,
            "bandwidth-utilization-kbps": 12,
        }
    ]
}


def build(settings: Settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    te_state.register(mcp, ctx)
    return mcp


def ok(body: dict) -> httpx.Response:
    return httpx.Response(200, json=body)


def mock_lists(
    policies: dict = SR_POLICIES, p2mp: dict = EMPTY, rsvp: dict = EMPTY
) -> tuple[respx.Route, respx.Route, respx.Route]:
    return (
        respx.get(SR_POLICIES_URL).mock(return_value=ok(policies)),
        respx.get(P2MP_POLICIES_URL).mock(return_value=ok(p2mp)),
        respx.get(RSVP_TUNNELS_URL).mock(return_value=ok(rsvp)),
    )


def mock_networks(body: dict = NETWORKS) -> respx.Route:
    return respx.get(NETWORKS_URL).mock(return_value=ok(body))


TOOLS = {
    "cnc_list_sr_policies",
    "cnc_get_sr_policy",
    "cnc_list_p2mp_policies",
    "cnc_get_p2mp_policy",
    "cnc_list_rsvp_te_tunnels",
    "cnc_get_rsvp_te_tunnel",
    "cnc_get_link_performance_metrics",
    "cnc_get_sr_policy_performance_metrics",
    "cnc_get_rsvp_tunnel_performance_metrics",
    "cnc_get_te_summary",
}


# --- registration / annotations ----------------------------------------------


async def test_all_tools_are_read_only_and_registered_without_writes(make_settings):
    tools = {t.name: t for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert set(tools) == TOOLS
    for name, tool in tools.items():
        assert tool.annotations.read_only_hint is True, name
        assert tool.annotations.idempotent_hint is True, name
        assert tool.annotations.destructive_hint is False, name
    # Flat parameters, never a wrapped model.
    props = tools["cnc_list_sr_policies"].input_schema["properties"]
    assert set(props) == {
        "headend", "endpoint", "color", "oper_state", "pce_controlled", "dataplane", "network",
        "response_format",
    }  # fmt: skip
    assert "'sr-mpls' or 'srv6'" in props["dataplane"]["description"]
    assert set(tools["cnc_get_sr_policy"].input_schema["required"]) == {
        "headend", "endpoint", "color"
    }  # fmt: skip
    # The SR policy tools take a host name or a router-id; RSVP tools router-ids only.
    for name in ("cnc_get_sr_policy", "cnc_get_sr_policy_performance_metrics"):
        description = tools[name].input_schema["properties"]["headend"]["description"]
        assert "host name" in description and "router-id" in description, name
        assert "network" in tools[name].input_schema["properties"], name
    assert (
        "NOT the host name"
        in (tools["cnc_get_rsvp_te_tunnel"].input_schema["properties"]["headend"]["description"])
    )
    assert tools["cnc_get_te_summary"].input_schema.get("properties", {}) == {}
    # The PM tools take the key and nothing else (the containers cannot be listed).
    assert set(tools["cnc_get_link_performance_metrics"].input_schema["required"]) == {"link_id"}


# --- pure helpers ------------------------------------------------------------


def test_urls_encode_every_key_part():
    base = "/crosswork/nbi/topology/v3/restconf/data"
    assert sr_policy_url("10.0.0.1", "10.0.0.3", 100) == (
        f"{base}/cisco-crosswork-segment-routing-policy:sr-policies/policy={PE1_PE2_KEY}"
    )
    assert p2mp_policy_url("tree a/b") == (
        f"{base}/cisco-crosswork-segment-routing-p2mp-policy:p2mp-policies/p2mp-policy=tree%20a%2Fb"
    )
    assert rsvp_tunnel_url("10.0.0.1", "10.0.0.3", 7).endswith(
        "/rsvp-te-tunnel=10.0.0.1,10.0.0.3,7"
    )
    assert igp_link_pm_url(LINK_ID).endswith(f"/igp-link-pm={LINK_ID_ENCODED}")
    assert sr_policy_pm_url("10.0.0.1", "10.0.0.3", 100).endswith(f"/sr-policy-pm={PE1_PE2_KEY}")
    assert rsvp_pm_url("10.0.0.1", "10.0.0.3", 7).endswith("/rsvp-policy-pm=10.0.0.1,10.0.0.3,7")
    # IPv6 router-ids: ':' is encoded inside a key part, the joining comma is not.
    assert sr_policy_url("2001:db8::1", "2001:db8::3", 5).endswith(
        "/policy=2001%3Adb8%3A%3A1,2001%3Adb8%3A%3A3,5"
    )


def test_as_bool_accepts_json_and_string_booleans():
    assert as_bool(True) is True and as_bool(False) is False  # the live JSON boolean
    assert as_bool("true") is True and as_bool("False") is False  # the document's string
    assert as_bool(1) is True and as_bool(0) is False
    assert as_bool(None) is None and as_bool("maybe") is None and as_bool({}) is None


def test_is_invalid_key_only_for_400_invalid_value():
    assert is_invalid_key(400, INVALID_VALUE_400.json()) is True
    assert is_invalid_key(400, UNKNOWN_ELEMENT_400.json()) is False
    assert is_invalid_key(409, INVALID_VALUE_400.json()) is False  # status must be 400
    assert is_invalid_key(400, None) is False and is_invalid_key(400, {"errors": {}}) is False


def test_normalize_oper_state():
    assert normalize_oper_state("up") == "UP" and normalize_oper_state(" Down ") == "DOWN"
    assert normalize_oper_state(None) is None and normalize_oper_state("  ") is None
    with pytest.raises(PlatformError, match="oper_state must be one of UP, DOWN"):
        normalize_oper_state("sideways")


def test_hop_text_handles_live_and_document_shapes():
    assert hop_text({"type": "IPV4-NODE-SID", "local-ip-addr": "10.0.0.3", "label": 16003}) == (
        "16003(IPV4-NODE-SID/10.0.0.3)"
    )
    documented = {
        "type": "IPV4-ADJ-SID",
        "sid-value": {"label": 24003},
        "local-address": {"ipv4": "10.1.1.1"},
        "remote-address": {"ipv4": "10.1.1.2"},
        "protected-flag": "true",
    }
    assert hop_text(documented) == "24003(IPV4-ADJ-SID/10.1.1.1->10.1.1.2)[protected]"
    assert hop_text({}) == "?(?/?)"
    assert hops_text([]) == "-" and hops_text(None) == "-"
    assert hops_text([{"label": 1, "type": "A"}, {"label": 2, "type": "B"}]) == "1(A/?) > 2(B/?)"


def test_hop_text_renders_the_srv6_document_shapes():
    """The sid-value choice's SRv6 cases (7.2 document; never observed live): the SID string
    replaces the label and the endpoint behaviour follows the address; ``[protected]`` from
    the adjacency SID's own ``protected`` leaf as well as the hop's ``protected-flag``."""
    assert hop_text(SRV6_NODE_HOP) == "fc00:0:3::(IPV6-NODE-SID/2001:db8::3 uN)"
    assert hop_text(SRV6_ADJ_HOP) == (
        "fc00:0:1:e000::(IPV6-ADJ-SID/2001:db8:1::1->2001:db8:1::2 uA)[protected]"
    )
    assert hop_srv6_sid(SRV6_NODE_HOP) == ("srv6-node-sid", SRV6_NODE_HOP["srv6-node-sid"])
    assert hop_srv6_sid(SRV6_ADJ_HOP)[0] == "srv6-adjacency-sid"
    assert hop_srv6_sid({"type": "IPV4-NODE-SID", "label": 16003}) is None
    assert hop_srv6_sid({"srv6-node-sid": {}}) is None  # an empty container is no SID
    # The document's module-prefixed spelling, wrapped in its sid-value object, reads the same.
    prefixed = {
        "type": "IPV6-NODE-SID",
        "local-address": {"local-ip-addr": "2001:db8::3"},
        "sid-value": {
            "cisco-crosswork-segment-routing-policy:srv6-node-sid": {
                "cisco-crosswork-segment-routing-policy:sid": "fc00:0:3::",
                "cisco-crosswork-segment-routing-policy:endpoint-behavior": "uN",
            }
        },
    }
    assert hop_text(prefixed) == "fc00:0:3::(IPV6-NODE-SID/2001:db8::3 uN)"
    assert hop_srv6_sid(prefixed)[0] == "srv6-node-sid"
    # IPV6-LINK-LOCAL-ADJ-SID carries the *-link-local-id case leaves instead of *-ip-addr.
    link_local = {
        "type": "IPV6-LINK-LOCAL-ADJ-SID",
        "local-ipv6-router-id": PE1_V6,
        "local-unnumbered-id": 5,
        "remote-ipv6-router-id": "2001:db8::2",
        "remote-unnumbered-id": 7,
        "srv6-adjacency-sid": {"sid": "fc00:0:1:e001::", "endpoint-behavior": "uA"},
    }
    assert hop_text(link_local) == (
        "fc00:0:1:e001::(IPV6-LINK-LOCAL-ADJ-SID/2001:db8::1#5->2001:db8::2#7 uA)"
    )
    # The same case inside the document's local-address / remote-address wrapper objects
    # (the OpenAPI oneOf: {local-ip-addr} | {local-ipv6-router-id, local-ipv4-router-id,
    # local-unnumbered-id}) keeps its '#<unnumbered-id>' — and an unnumbered-id of 0 (a
    # uint32 ifIndex) is a value, not an absence.
    wrapped_link_local = {
        "type": "IPV6-LINK-LOCAL-ADJ-SID",
        "local-address": {"local-ipv6-router-id": PE1_V6, "local-unnumbered-id": 5},
        "remote-address": {"remote-ipv6-router-id": "2001:db8::2", "remote-unnumbered-id": 0},
        "sid-value": {"srv6-adjacency-sid": {"sid": "fc00:0:1:e001::", "endpoint-behavior": "uA"}},
    }
    assert hop_text(wrapped_link_local) == (
        "fc00:0:1:e001::(IPV6-LINK-LOCAL-ADJ-SID/2001:db8::1#5->2001:db8::2#0 uA)"
    )
    assert hop_text({"type": "IPV6-LINK-LOCAL-ADJ-SID", "local-unnumbered-id": 0}) == (
        "?(IPV6-LINK-LOCAL-ADJ-SID/0)"
    )
    assert hop_text({"type": "IPV6-LINK-LOCAL-ADJ-SID", "local-ipv4-router-id": "10.0.0.1"}) == (
        "?(IPV6-LINK-LOCAL-ADJ-SID/10.0.0.1)"
    )
    # The IPv6 router-id wins over the IPv4 one when both are present; an empty wrapper or
    # empty leaves are absent ('?'), never rendered as '' or 'None'.
    both_ids = {
        "type": "IPV6-LINK-LOCAL-ADJ-SID",
        "local-ipv6-router-id": PE1_V6,
        "local-ipv4-router-id": "10.0.0.1",
        "local-unnumbered-id": 3,
    }
    assert hop_text(both_ids) == "?(IPV6-LINK-LOCAL-ADJ-SID/2001:db8::1#3)"
    assert hop_text(
        {"type": "X", "local-address": {}, "remote-address": {"remote-ip-addr": ""}}
    ) == ("?(X/?)")
    # An IPV6-* hop without any SID object still renders (no crash, '?' for the SID).
    assert hop_text({"type": "IPV6-NODE-SID", "local-ip-addr": PE2_V6}) == (
        "?(IPV6-NODE-SID/2001:db8::3)"
    )
    # [protected] is the OR of the hop's protected-flag and the adjacency SID's own
    # protected leaf: either alone marks the hop, neither leaves it unmarked.
    flag_only = {
        "type": "IPV6-ADJ-SID",
        "protected-flag": True,
        "srv6-adjacency-sid": {"sid": "a::"},
    }
    container_only = {
        "type": "IPV6-ADJ-SID",
        "srv6-adjacency-sid": {"sid": "a::", "protected": "true"},
    }
    neither = {
        "type": "IPV6-ADJ-SID",
        "protected-flag": False,
        "srv6-adjacency-sid": {"sid": "a::", "protected": False},
    }
    assert hop_text(flag_only) == "a::(IPV6-ADJ-SID/?)[protected]"
    assert hop_text(container_only) == "a::(IPV6-ADJ-SID/?)[protected]"
    assert hop_text(neither) == "a::(IPV6-ADJ-SID/?)"
    # hop_is_srv6: the SID object, or an IPV6-* type with no MPLS label (an OE-built
    # SR-MPLS policy over IPv6 carries node-ipv6-sid LABELS, which are SR-MPLS). It is the
    # per-hop rule policy_dataplane applies once no hop carries a label or a SID object.
    assert hop_is_srv6(SRV6_NODE_HOP) and hop_is_srv6({"type": "IPV6-NODE-SID"})
    assert not hop_is_srv6({"type": "IPV6-NODE-SID", "label": 16003})
    assert not hop_is_srv6({"type": "IPV4-NODE-SID", "label": 16003}) and not hop_is_srv6("x")


def test_srv6_sid_text_and_structure():
    assert srv6_sid_text(SRV6_BSID) == "fc00:0:1:1:: behavior=uB6.Insert.Red structure=32/16/16/0"
    assert srv6_sid_text(SRV6_ADJ_HOP["srv6-adjacency-sid"]) == (
        "fc00:0:1:e000:: behavior=uA structure=32/16/16/0 algorithm=0 flags=0 weight=0 "
        "protected=True"
    )
    # Unknown leaves are appended, nothing is dropped; absent parts render '-'.
    assert srv6_sid_text({"sid": "fc00::", "vendor": 1}) == "fc00:: behavior=- structure=- vendor=1"
    assert srv6_sid_text({}) == "-" and srv6_sid_text(None) == "-"
    assert sid_structure_text({}) == "-"
    assert sid_structure_text({"srv6-sid-structure": {"lb-length": 32}}) == "32/-/-/-"
    assert sid_structure_text({"x:srv6-sid-structure": SID_STRUCTURE}) == "32/16/16/0"


def test_policy_dataplane_is_derived_in_order():
    """No dataplane leaf exists on the read NBI: srv6 for the SRv6 shapes, else sr-mpls for
    an MPLS BSID / label, else srv6 for IPV6-* hop types or IPv6 keys, else sr-mpls."""
    assert policy_dataplane(PE1_POLICY) == "sr-mpls" and policy_dataplane(PE2_POLICY) == "sr-mpls"
    assert policy_dataplane(SRV6_POLICY) == "srv6"
    assert srv6_binding_sid(SRV6_POLICY) == SRV6_BSID and srv6_binding_sid(PE1_POLICY) is None
    # The BSID alone, in either prefix spelling.
    only_bsid = {"headend": "10.0.0.1", "policy-details": {"srv6-binding-sid": SRV6_BSID}}
    assert policy_dataplane(only_bsid) == "srv6"
    prefixed = {
        "policy-details": {"cisco-crosswork-segment-routing-policy:srv6-binding-sid": SRV6_BSID}
    }
    assert policy_dataplane(prefixed) == "srv6" and srv6_binding_sid(prefixed) == SRV6_BSID
    assert policy_dataplane({"policy-details": {"srv6-binding-sid": {}}}) == "sr-mpls"  # empty
    # A hop SID object alone (flat hop[] or segment-list[].hop[]).
    hop_only = {"policy-details": {"path": [{"hop": [SRV6_NODE_HOP]}]}}
    assert policy_dataplane(hop_only) == "srv6"
    seg_only = {"policy-details": {"path": [{"segment-list": [{"hop": [SRV6_ADJ_HOP]}]}]}}
    assert policy_dataplane(seg_only) == "srv6"
    assert policy_hops(seg_only) == [SRV6_ADJ_HOP] and policy_hops({}) == []
    assert len(policy_hops(SRV6_POLICY)) == 4  # segment-list hops + the flat hop list
    # An MPLS label wins over an IPv6 hop type / IPv6 addressing: the OE RPCs build
    # SR-MPLS policies with node-ipv6-sid LABELS over an IPv6 IGP.
    ipv6_mpls = {
        "headend": PE1_V6,
        "endpoint": PE2_V6,
        "policy-details": {
            "binding-sid": 24007,
            "path": [{"hop": [{"type": "IPV6-NODE-SID", "label": 16003}]}],
        },
    }
    assert policy_dataplane(ipv6_mpls) == "sr-mpls"
    label_only = {"headend": PE1_V6, "policy-details": {"path": [{"hop": [{"label": 16003}]}]}}
    assert policy_dataplane(label_only) == "sr-mpls"
    # Then the hop type, then the key's address family, then the default.
    typed_hop = {"type": "ipv6-adj-sid"}
    typed = {"headend": "10.0.0.1", "policy-details": {"path": [{"hop": [typed_hop]}]}}
    assert policy_dataplane(typed) == "srv6"
    assert policy_dataplane({"headend": PE1_V6, "endpoint": PE2_V6}) == "srv6"
    assert policy_dataplane({"headend": "10.0.0.1", "endpoint": PE2_V6}) == "srv6"
    assert policy_dataplane({"headend": "10.0.0.1", "endpoint": "10.0.0.3"}) == "sr-mpls"
    assert policy_dataplane({}) == "sr-mpls"


def test_policy_bsid_falls_back_to_the_srv6_sid():
    assert policy_bsid(PE1_POLICY) == 24005
    assert policy_bsid(SRV6_POLICY) == "fc00:0:1:1::"
    no_sid = {"policy-details": {"srv6-binding-sid": {"endpoint-behavior": "uB6"}}}
    assert policy_bsid(no_sid) == "-"
    assert policy_bsid({}) == "-"
    # Both present (not expected on the wire): the MPLS label is the binding-sid leaf.
    both = {"policy-details": {"binding-sid": 24005, "srv6-binding-sid": SRV6_BSID}}
    assert policy_bsid(both) == 24005 and policy_dataplane(both) == "srv6"


def test_normalize_dataplane():
    assert normalize_dataplane("srv6") == "srv6" and normalize_dataplane(" SRv6 ") == "srv6"
    assert normalize_dataplane("sr-mpls") == "sr-mpls" and normalize_dataplane("MPLS") == "sr-mpls"
    assert normalize_dataplane("srmpls") == "sr-mpls"
    assert normalize_dataplane(None) is None and normalize_dataplane("  ") is None
    with pytest.raises(PlatformError, match="dataplane must be one of sr-mpls, srv6"):
        normalize_dataplane("ipv6")


def test_ipv6_router_ids_resolve_to_host_names_and_key_pairs():
    """The topology's ``cisco-crosswork-l3-te-topology:ipv6-router-id`` leaf-list (absent on
    the lab; 7.2 document shape) is the key an SRv6 policy carries: every resolver maps it
    to the host name alongside the IPv4 router-id."""
    assert is_ipv6(PE1_V6) and not is_ipv6("10.0.0.1") and not is_ipv6("PE1") and not is_ipv6(None)
    assert node_te_router_ids(TOPO_NODES_V6[0]) == ["10.0.0.1", PE1_V6]
    assert node_te_router_ids(TOPO_NODES_V6[1]) == ["10.0.0.2"]
    assert node_te_router_ids({"node-id": "SW1"}) == []
    # The bare (RFC 7951) spelling of the leaf-list reads the same; duplicates collapse.
    bare = {"node-id": "X", L3_NODE: {"router-id": ["10.0.0.9"], "ipv6-router-id": ["fc00::9"]}}
    assert node_te_router_ids(bare) == ["10.0.0.9", "fc00::9"]
    assert node_te_router_ids({L3_NODE: {"router-id": ["10.0.0.9", "10.0.0.9"]}}) == ["10.0.0.9"]
    names = router_id_names(TOPO_NODES_V6)
    assert names == {
        "10.0.0.1": "PE1", PE1_V6: "PE1", "10.0.0.2": "P1", "10.0.0.3": "PE2", PE2_V6: "PE2"
    }  # fmt: skip
    assert node_text(PE2_V6, names) == "PE2 (2001:db8::3)"
    assert end_label("pe1", PE1_V6, names) == "PE1 (2001:db8::1)"
    # find_node by the IPv6 router-id; node_router_id keeps the verified IPv4 default and
    # prefers the IPv6 router-id only when asked (the other end was an IPv6 literal).
    assert find_node(TOPO_NODES_V6, PE2_V6)["node-id"] == "PE2"
    assert node_router_id(TOPO_NODES_V6, "PE1") == "10.0.0.1"
    assert node_router_id(TOPO_NODES_V6, "PE1", prefer_ipv6=True) == PE1_V6
    assert node_router_id(TOPO_NODES_V6, "P1", prefer_ipv6=True) == "10.0.0.2"  # no IPv6 one
    assert node_router_id(TOPO_NODES_V6, PE1_V6) == PE1_V6  # the literal itself
    assert select_router_id([PE1_V6, "10.0.0.1"], "PE1") == "10.0.0.1"
    assert select_router_id([PE1_V6, "10.0.0.1"], "PE1", prefer_ipv6=True) == PE1_V6
    assert select_router_id([], "PE1") is None
    # The list filter's match set: every router-id of the node; a literal is itself.
    assert node_key_ids(TOPO_NODES_V6, "pe1") == ["10.0.0.1", PE1_V6]
    assert node_key_ids(TOPO_NODES_V6, "10.0.0.3") == ["10.0.0.3"]
    assert node_key_ids([], PE2_V6) == [PE2_V6]  # no topology needed for a literal
    with pytest.raises(PlatformError, match="no node 'PE9' in the topology"):
        node_key_ids(TOPO_NODES_V6, "PE9")
    with pytest.raises(PlatformError, match="node 'SW1' has no TE router-id"):
        node_key_ids(TOPO_NODES_V6, "SW1")
    assert ends_text(["10.0.0.1", PE1_V6], names) == "PE1 (10.0.0.1, 2001:db8::1)"
    assert ends_text(["10.0.0.1"], names) == "PE1 (10.0.0.1)"
    assert ends_text(["10.0.0.8", "fc00::8"], names) == "10.0.0.8, fc00::8"
    # The GET tools' one retry after a 409: the IPv6 pair of two host-name ends.
    assert ipv6_key_pair(TOPO_NODES_V6, "PE1", "pe2", "10.0.0.1", "10.0.0.3") == (PE1_V6, PE2_V6)
    assert ipv6_key_pair(TOPO_NODES, "PE1", "PE2", "10.0.0.1", "10.0.0.3") is None  # no IPv6
    assert ipv6_key_pair(None, "PE1", "PE2", "10.0.0.1", "10.0.0.3") is None  # nothing read
    assert ipv6_key_pair(TOPO_NODES_V6, "PE1", "P1", "10.0.0.1", "10.0.0.2") is None
    assert ipv6_key_pair(TOPO_NODES_V6, "PE1", "PE2", PE1_V6, PE2_V6) is None  # unchanged
    # An IPv4 literal on either end fixes the family: no retry; an IPv6 literal keeps its value.
    assert ipv6_key_pair(TOPO_NODES_V6, "PE1", "10.0.0.3", "10.0.0.1", "10.0.0.3") is None
    assert ipv6_key_pair(TOPO_NODES_V6, "PE1", PE2_V6, "10.0.0.1", PE2_V6) == (PE1_V6, PE2_V6)
    assert ipv6_key_pair(TOPO_NODES_V6, "PE9", "PE2", "10.0.0.1", "10.0.0.3") is None


def test_ip_literals_are_canonicalised_once():
    """An IPv6 address has many spellings and every comparison here is textual, so a literal
    an agent types is normalised to the RFC 5952 form (what IOS-XR / Crosswork emit) before
    it becomes a filter or a wire key; the topology's wire text is kept but deduplicated on
    the same form."""
    assert canonical_ip("2001:0db8::1") == PE1_V6 and canonical_ip("2001:DB8:0:0::1") == PE1_V6
    assert canonical_ip(" 10.0.0.1 ") == "10.0.0.1" and canonical_ip("PE1") == "PE1"
    assert canonical_ip("") == "" and canonical_ip(" pe1 ") == "pe1"  # non-IP text as given
    # The list filter's match set and the GET tools' key: canonical.
    assert node_key_ids([], "2001:0db8::1") == [PE1_V6]
    assert node_key_ids([], "2001:DB8::1") == [PE1_V6]
    # The topology side keeps the wire spelling but two spellings of one address are one id.
    upper = {
        "node-id": "X",
        L3_NODE: {"router-id": ["10.0.0.9"], "ipv6-router-id": ["2001:DB8::9"]},
    }
    upper[L3_NODE]["ipv6-router-id"].append("2001:db8::9")
    assert node_te_router_ids(upper) == ["10.0.0.9", "2001:DB8::9"]
    # find_node and the filter compare in the canonical form, both directions.
    assert find_node(TOPO_NODES_V6, "2001:DB8:0:0::1")["node-id"] == "PE1"
    assert find_node([upper], "2001:db8::9")["node-id"] == "X"
    no_filter = dict(headend=None, endpoint=None, color=None, oper_state=None, pce_controlled=None)
    assert matches_policy_filter(SRV6_POLICY, **{**no_filter, "headend": "2001:0DB8::1"})
    upper_key = {**SRV6_POLICY, "headend": "2001:DB8:0:0::1"}
    assert matches_policy_filter(upper_key, **{**no_filter, "headend": [PE1_V6]})
    assert not matches_policy_filter(upper_key, **{**no_filter, "headend": "2001:db8::2"})


def test_matches_policy_filter_accepts_router_id_sets_and_dataplane():
    no_filter = dict(headend=None, endpoint=None, color=None, oper_state=None, pce_controlled=None)
    # A host name resolves to its node's IPv4 AND IPv6 router-ids: both of PE1's policies match.
    pe1 = ["10.0.0.1", PE1_V6]
    assert matches_policy_filter(PE1_POLICY, **{**no_filter, "headend": pe1})
    assert matches_policy_filter(SRV6_POLICY, **{**no_filter, "headend": pe1})
    assert not matches_policy_filter(PE2_POLICY, **{**no_filter, "headend": pe1})
    assert matches_policy_filter(SRV6_POLICY, **{**no_filter, "endpoint": [PE2_V6.upper()]})
    assert not matches_policy_filter(SRV6_POLICY, **{**no_filter, "endpoint": "10.0.0.3"})
    assert matches_policy_filter(SRV6_POLICY, **{**no_filter, "dataplane": "srv6"})
    assert not matches_policy_filter(SRV6_POLICY, **{**no_filter, "dataplane": "sr-mpls"})
    assert matches_policy_filter(PE1_POLICY, **{**no_filter, "dataplane": "sr-mpls"})
    assert not matches_policy_filter(PE1_POLICY, **{**no_filter, "dataplane": "srv6"})


def test_path_hops_prefers_flat_hop_list_then_first_segment_list():
    path = PE1_POLICY["policy-details"]["path"][0]
    assert path_hops(path) == path["hop"]
    only_segment_lists = {"segment-list": [{"weight": 1, "hop": [{"label": 5}]}]}
    assert path_hops(only_segment_lists) == [{"label": 5}]
    assert path_hops({}) == []


def test_active_path_is_highest_preference_up_path_else_first():
    down_200 = {"path-name": "a", "oper-state": "DOWN", "preference": 200}
    up_100 = {"path-name": "b", "oper-state": "UP", "preference": 100}
    up_150 = {"path-name": "c", "oper-state": "up", "preference": "150"}
    assert active_path([down_200, up_100, up_150]) is up_150
    assert active_path([down_200]) is down_200
    assert active_path([]) is None
    active = {"path-oper-state": "ACTIVE"}
    up = {"path-oper-state": "UP"}
    assert active_tunnel_path([up, active]) is active
    assert active_tunnel_path([{"path-oper-state": "DOWN"}, up]) is up
    assert active_tunnel_path([{"path-oper-state": "DOWN"}])["path-oper-state"] == "DOWN"
    assert active_tunnel_path([]) is None


def test_matches_policy_filter():
    no_filter = dict(headend=None, endpoint=None, color=None, oper_state=None, pce_controlled=None)
    assert matches_policy_filter(PE1_POLICY, **no_filter)
    assert matches_policy_filter(PE1_POLICY, **{**no_filter, "headend": "10.0.0.1"})
    assert not matches_policy_filter(PE1_POLICY, **{**no_filter, "headend": "10.0.0.3"})
    assert matches_policy_filter(PE1_POLICY, **{**no_filter, "endpoint": "10.0.0.3"})
    assert matches_policy_filter(PE1_POLICY, **{**no_filter, "color": 100})
    assert not matches_policy_filter(PE1_POLICY, **{**no_filter, "color": 200})
    assert matches_policy_filter(PE1_POLICY, **{**no_filter, "oper_state": "UP"})
    assert not matches_policy_filter(PE1_POLICY, **{**no_filter, "oper_state": "DOWN"})
    assert matches_policy_filter(PE1_POLICY, **{**no_filter, "pce_controlled": True})
    assert not matches_policy_filter(PE1_POLICY, **{**no_filter, "pce_controlled": False})
    # A policy without a readable pce-controlled value matches neither True nor False.
    bare = {"headend": "1", "endpoint": "2", "color": "7"}
    assert not matches_policy_filter(bare, **{**no_filter, "pce_controlled": False})
    assert matches_policy_filter(bare, **{**no_filter, "color": 7})  # numeric string on the wire


def test_key_matches_is_int_str_tolerant_in_both_directions():
    assert key_matches(100, 100) and key_matches("10.0.0.1", "10.0.0.1")
    assert key_matches(100, "100")  # int on the wire, string key (the URL form)
    assert key_matches("100", 100)  # string on the wire, int tool argument
    assert key_matches("7", 7) and key_matches(7, "7")
    assert not key_matches(100, 101) and not key_matches("100", 101)
    assert not key_matches("10.0.0.1", "10.0.0.3")
    assert not key_matches("PE1", "pe1")  # exact, case-sensitive
    assert not key_matches(None, 100) and not key_matches(None, None)


def test_entries_matching_checks_every_key_field():
    items = [PE2_POLICY, PE1_POLICY]
    keys = {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100}
    assert entries_matching(items, keys) == [PE1_POLICY]
    assert entries_matching(items, {**keys, "color": 999}) == []
    assert entries_matching(items, {**keys, "color": "100"}) == [PE1_POLICY]  # str/int tolerant
    assert entries_matching([], keys) == []
    assert entries_matching([None, "x", 7], keys) == []  # non-dict entries dropped
    # An entry missing a key field never matches.
    assert entries_matching([{"headend": "10.0.0.1", "endpoint": "10.0.0.3"}], keys) == []


def test_entries_matching_accepts_string_key_leaves_against_int_arguments():
    # The direction select_key does not cover: this NBI serialises numeric leaves as
    # strings (update-time, max-bandwidth-kbps live), so a stringified tunnel-id /
    # color on the wire must still match the tool's int argument.
    string_tunnel = {**RSVP_TUNNEL, "tunnel-id": "7"}
    keys = {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "tunnel-id": 7}
    assert entries_matching([string_tunnel], keys) == [string_tunnel]
    assert entries_matching([string_tunnel], {**keys, "tunnel-id": 8}) == []
    string_color = {**PE1_POLICY, "color": "100"}
    policy_keys = {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100}
    assert entries_matching([PE2_POLICY, string_color], policy_keys) == [string_color]
    assert entries_matching([PE2_POLICY, string_color], {**policy_keys, "color": 101}) == []


def test_sr_policy_summary_counts():
    down = {**PE1_POLICY, "oper-state": "DOWN", "sr-policy-type": "CIRCUIT-STYLE"}
    not_delegated = {
        **PE2_POLICY,
        "policy-details": {**PE2_POLICY["policy-details"], "pce-controlled": "false"},
    }
    summary = sr_policy_summary([PE1_POLICY, PE2_POLICY, down, not_delegated])
    assert summary == {
        "total": 4,
        "up": 3,
        "down": 1,
        "pce_controlled": 3,
        "by_type": {"REGULAR": 3, "CIRCUIT-STYLE": 1},
        "by_dataplane": {"sr-mpls": 4, "srv6": 0},
        "down_policies": ["10.0.0.1 -> 10.0.0.3 color 100"],
    }
    empty = sr_policy_summary([])
    assert empty["total"] == 0 and empty["by_type"] == {}
    # Both dataplane keys are always present, so the dimension shows on an SR-MPLS-only
    # network; an SRv6 policy (spec-shaped) counts under srv6 and keys its DOWN entry by
    # the IPv6 router-ids.
    assert empty["by_dataplane"] == {"sr-mpls": 0, "srv6": 0}
    srv6_down = {**SRV6_POLICY, "oper-state": "DOWN"}
    mixed = sr_policy_summary([PE1_POLICY, PE2_POLICY, srv6_down])
    assert mixed["by_dataplane"] == {"sr-mpls": 2, "srv6": 1}
    assert mixed["down_policies"] == ["2001:db8::1 -> 2001:db8::3 color 6001"]


def test_is_ip_address_is_the_no_lookup_fast_path():
    assert (
        is_ip_address("10.0.0.1") and is_ip_address(" 10.0.0.3 ") and is_ip_address("2001:db8::1")
    )
    assert not is_ip_address("PE1") and not is_ip_address("10.0.0.1x") and not is_ip_address("")


def test_node_router_id_resolves_names_case_insensitively_and_passes_router_ids():
    assert node_router_id(TOPO_NODES, "PE2") == "10.0.0.3"
    assert node_router_id(TOPO_NODES, "pe1") == "10.0.0.1"
    assert node_router_id(TOPO_NODES, "10.0.0.2") == "10.0.0.2"
    with pytest.raises(PlatformError, match="no node 'PE9' in the topology"):
        node_router_id(TOPO_NODES, "PE9")
    # An LLDP-only node (no l3-node-attributes) cannot key an SR policy.
    with pytest.raises(PlatformError, match="node 'SW1' has no TE router-id in the topology"):
        node_router_id(TOPO_NODES, "SW1")


def test_end_label_shows_both_spellings_only_when_a_name_was_resolved():
    assert end_label("PE2", "10.0.0.3") == "PE2 (10.0.0.3)"
    assert end_label("10.0.0.3", "10.0.0.3") == "10.0.0.3"
    assert end_label(" 10.0.0.3 ", "10.0.0.3") == "10.0.0.3"
    # With a name map the topology's own node id wins over the caller's spelling, and a
    # router-id given as such is named too (round 2: names known -> names shown).
    names = router_id_names(TOPO_NODES)
    assert end_label("pe2", "10.0.0.3", names) == "PE2 (10.0.0.3)"
    assert end_label("10.0.0.1", "10.0.0.1", names) == "PE1 (10.0.0.1)"
    assert end_label("10.0.0.9", "10.0.0.9", names) == "10.0.0.9"
    # A non-canonical spelling of the router-id itself is not a host name (live 2026-09-15:
    # it rendered '2001:0DB8::1 (2001:db8::1)' before this rule).
    assert end_label("2001:0DB8::1", PE1_V6) == PE1_V6
    assert end_label("2001:db8:0:0::1", PE1_V6, {}) == PE1_V6


def test_router_id_names_and_node_text_come_from_the_topology_nodes_alone():
    # The node record carries node-id (= host_name) and its router-ids: no inventory call.
    names = router_id_names(TOPO_NODES)
    assert names == {"10.0.0.1": "PE1", "10.0.0.2": "P1", "10.0.0.3": "PE2"}
    assert router_id_names(None) == {} and router_id_names([{"node-id": "SW1"}]) == {}
    assert node_text("10.0.0.3", names) == "PE2 (10.0.0.3)"
    assert node_text("10.0.0.9", names) == "10.0.0.9"  # unknown router-id: as is
    assert node_text("10.0.0.3", None) == "10.0.0.3" and node_text(None, names) == "?"
    # A node whose router-id equals its id (no separate name) is not doubled up.
    assert node_text("10.0.0.7", {"10.0.0.7": "10.0.0.7"}) == "10.0.0.7"


def test_policy_origin_from_pcep_flag_c_independent_of_pce_controlled():
    # Verified live: the lab's router-configured policies are pcep-flag-c 0 + pce-controlled
    # true (delegated); a policy created through the PCE carries pcep-flag-c 1.
    assert pcep_flag_c(PE1_POLICY) == 0 and policy_origin(PE1_POLICY) == "PCC-initiated"
    pce_made = {**PE1_POLICY, "policy-details": {**PE1_POLICY["policy-details"]}}
    pce_made["policy-details"]["pcep-info"] = {"pcep-flag-c": "1"}
    assert pcep_flag_c(pce_made) == 1 and policy_origin(pce_made) == "PCE-initiated"
    bare = {k: v for k, v in PE1_POLICY.items() if k != "policy-details"}
    assert pcep_flag_c(bare) is None and policy_origin(bare) == "unknown"
    assert policy_origin_line(PE1_POLICY) == (
        "- origin: PCC-initiated (pcep-flag-c 0: configured on the head-end router); delegated "
        "to the PCE for (re)optimisation (pce-controlled true) — a router-configured policy "
        "the PCE may re-optimise"
    )
    assert policy_origin_line(pce_made).startswith(
        "- origin: PCE-initiated (pcep-flag-c 1: instantiated by the SR-PCE over PCEP); "
        "delegated to the PCE"
    )
    assert policy_origin_line(bare) == (
        "- origin: unknown (no pcep-flag-c reported); delegation unknown (no pce-controlled "
        "reported)"
    )


def test_has_pm_telemetry_only_for_a_present_napm_key():
    assert not has_pm_telemetry({"delay": 20, "bandwidth-utilization-kbps": "0"})
    assert not has_pm_telemetry({"delay": 20, "delay-telemetry": ""})
    assert has_pm_telemetry({"delay": 20, "delay-telemetry": 1234})
    assert has_pm_telemetry({"liveness-telemetry": "UP"})


# --- cnc_list_sr_policies ----------------------------------------------------


@respx.mock
async def test_list_sr_policies_markdown_url_accept_and_lines(settings):
    """Round 3: with no headend/endpoint filter the tool reads the topology once (one
    extra GET) so the rows answer in host names — 'PE1 (10.0.0.1)' — instead of sending
    the agent to cnc_list_topology_nodes for the translation."""
    route = respx.get(SR_POLICIES_URL).mock(return_value=ok(SR_POLICIES))
    networks = mock_networks()
    text = await call_tool_text(build(settings), "cnc_list_sr_policies", {})
    request = route.calls[0].request
    assert str(request.url) == SR_POLICIES_URL
    assert request.method == "GET" and request.headers["Accept"] == YANG_JSON
    assert networks.call_count == 1
    assert "# SR policies (2 of 2, no filter)" in text
    # The verified SR-MPLS rows, exactly as before plus the derived dataplane column.
    assert (
        "- **PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 100** admin=UP oper=UP type=REGULAR "
        "dataplane=sr-mpls bsid=24005 origin=PCC-initiated pce-controlled=True pcc=10.0.0.1 "
        "| active path: CNC-DYN-100 pref=100 PT-DYNAMIC metric=IGP-METRIC:20 "
        "hops=16003(IPV4-NODE-SID/10.0.0.3) updated=2026-09-13T"
    ) in text
    assert (
        "- **PE2 (10.0.0.3) -> PE1 (10.0.0.1) color 100** admin=UP oper=UP type=REGULAR "
        "dataplane=sr-mpls bsid=24005 origin=PCC-initiated pce-controlled=True pcc=10.0.0.3 "
        "| active path: CNC-DYN-100 pref=100 PT-DYNAMIC metric=IGP-METRIC:20 "
        "hops=16001(IPV4-NODE-SID/10.0.0.1) updated="
    ) in text
    assert "dataplane=srv6" not in text
    # The dataplane legend and where SRv6 policies come from (the OE RPCs are SR-MPLS only).
    assert "Dataplane is derived (the NBI has no dataplane leaf)" in text
    assert "cnc_create_sr_policy_service" in text and "SR-MPLS only" in text
    assert "- **10.0.0.1 -> 10.0.0.3 color 100**" not in text
    assert "host names are shown next to the TE router-ids" in text
    assert "resolved through the topology nodes" in text and "cnc_get_sr_policy" in text
    # The origin/delegation legend, so an agent does not have to infer it (scenario 3).
    assert "1 = PCE-initiated" in text and "0 = PCC-initiated" in text
    assert "router-configured policy delegated to the PCE" in text


@respx.mock
async def test_list_sr_policies_unfiltered_falls_back_to_router_ids_when_topology_fails(
    settings,
):
    """The policy list is the answer; the host names are decoration. A topology read that
    fails (here: an empty networks container -> PlatformError) degrades the rows to
    router-ids with a footer saying so, never to an Error."""
    respx.get(SR_POLICIES_URL).mock(return_value=ok(SR_POLICIES))
    networks = mock_networks({})
    text = await call_tool_text(build(settings), "cnc_list_sr_policies", {})
    assert networks.call_count == 1
    assert not text.startswith("Error:")
    assert "# SR policies (2 of 2, no filter)" in text
    assert "- **10.0.0.1 -> 10.0.0.3 color 100** admin=UP" in text
    assert "Host names could not be resolved (the topology NBI reports no networks yet" in text
    assert "cnc_list_topology_nodes maps them" in text
    assert "a host-name filter here shows host names next to the router-ids" in text
    # A non-end filter alone (color) is still "no headend/endpoint filter": names resolved.
    mock_networks()
    text = await call_tool_text(build(settings), "cnc_list_sr_policies", {"color": 100})
    assert networks.call_count == 2
    assert "# SR policies (2 of 2, color=100)" in text
    assert "- **PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 100**" in text


@respx.mock
async def test_list_sr_policies_host_name_footer_is_sanitised_through_format_error(
    make_settings, monkeypatch
):
    """The fallback catches ANY exception from the topology read, so its footer must go
    through format_error() like every other text that reaches the agent: a PlatformError
    keeps its message, anything else (a shape error in the unwrap helpers, a stray
    assertion) renders as the generic "Unexpected <Type> ..." rather than raw Python text."""
    respx.get(SR_POLICIES_URL).mock(return_value=ok(SR_POLICIES))

    async def broken(client, network):  # the signature is the contract
        raise KeyError("raw parser text that must not leak")

    monkeypatch.setattr(te_state, "fetch_topology_nodes", broken)
    text = await call_tool_text(build(make_settings()), "cnc_list_sr_policies", {})
    assert not text.startswith("Error:")
    assert "- **10.0.0.1 -> 10.0.0.3 color 100** admin=UP" in text
    assert (
        "Host names could not be resolved (Unexpected KeyError while calling the platform "
        "API); the rows show TE router-ids only — cnc_list_topology_nodes maps them."
    ) in text
    assert "raw parser text" not in text
    # A transport failure keeps the client's hint (it arrives as a PlatformError).
    monkeypatch.undo()
    respx.get(NETWORKS_URL).mock(side_effect=httpx.ConnectError("boom"))
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_list_sr_policies", {})
    assert not text.startswith("Error:")
    assert "Host names could not be resolved (Could not reach the platform (ConnectError)." in text
    assert "Check base_url, network reachability, and the verify_tls setting)" in text


@respx.mock
async def test_list_sr_policies_filters_by_host_name_through_the_topology(settings):
    networks = mock_networks()
    respx.get(SR_POLICIES_URL).mock(return_value=ok(SR_POLICIES))
    text = await call_tool_text(
        build(settings), "cnc_list_sr_policies", {"headend": "pe2", "endpoint": "PE1"}
    )
    assert networks.call_count == 1
    # Round 2: the nodes read to resolve the names double as the router-id -> host name
    # map, so the header and the rows carry both spellings (the node ids exactly).
    assert "# SR policies (1 of 2, headend=PE2 (10.0.0.3), endpoint=PE1 (10.0.0.1))" in text
    assert "- **PE2 (10.0.0.3) -> PE1 (10.0.0.1) color 100**" in text
    assert "10.0.0.1 -> 10.0.0.3 color 100" not in text
    assert "host names are shown next to the TE router-ids" in text
    # A router-id filter never reads the topology (the fast path every earlier caller took),
    # so nothing can be named: the rows stay router-ids only and the footer says how.
    text = await call_tool_text(build(settings), "cnc_list_sr_policies", {"headend": "10.0.0.3"})
    assert networks.call_count == 1
    assert "# SR policies (1 of 2, headend=10.0.0.3)" in text
    assert "- **10.0.0.3 -> 10.0.0.1 color 100**" in text
    assert "a host-name filter here shows host names" in text
    text = await call_tool_text(
        build(settings), "cnc_list_sr_policies", {"headend": "10.0.0.3", "response_format": "json"}
    )
    assert networks.call_count == 1
    assert json.loads(text)["filter"]["headend"] == "10.0.0.3"


@respx.mock
async def test_list_sr_policies_unknown_host_name_is_error_before_the_policy_read(settings):
    mock_networks()
    policies = respx.get(SR_POLICIES_URL).mock(return_value=ok(SR_POLICIES))
    text = await call_tool_text(build(settings), "cnc_list_sr_policies", {"headend": "PE9"})
    assert text.startswith("Error: no node 'PE9' in the topology")
    assert policies.call_count == 0


@respx.mock
async def test_list_sr_policies_json_is_raw_entries(settings):
    # The json view never reads the topology (raw entries, router-ids). The networks route
    # IS mocked and asserted uncalled: a read that failed would be swallowed by the
    # host-name fallback (a footer, not an Error), so an unmocked route proves nothing.
    networks = mock_networks()
    respx.get(SR_POLICIES_URL).mock(return_value=ok(SR_POLICIES))
    text = await call_tool_text(
        build(settings), "cnc_list_sr_policies", {"response_format": "json"}
    )
    assert networks.call_count == 0
    data = json.loads(text)
    assert data["count"] == 2 and data["total"] == 2
    assert data["items"] == [PE2_POLICY, PE1_POLICY]
    assert data["filter"] == {
        "headend": None, "endpoint": None, "color": None, "oper_state": None,
        "pce_controlled": None, "dataplane": None,
    }  # fmt: skip


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        ({"headend": "10.0.0.1"}, ["10.0.0.1"]),
        ({"endpoint": "10.0.0.1"}, ["10.0.0.3"]),
        ({"color": 100}, ["10.0.0.3", "10.0.0.1"]),
        ({"color": 200}, []),
        ({"oper_state": "up"}, ["10.0.0.3", "10.0.0.1"]),
        ({"oper_state": "DOWN"}, []),
        ({"pce_controlled": True}, ["10.0.0.3", "10.0.0.1"]),
        ({"pce_controlled": False}, []),
        ({"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100}, ["10.0.0.1"]),
    ],
)
@respx.mock
async def test_list_sr_policies_filters_client_side(settings, args, expected):
    route = respx.get(SR_POLICIES_URL).mock(return_value=ok(SR_POLICIES))
    text = await call_tool_text(
        build(settings), "cnc_list_sr_policies", {**args, "response_format": "json"}
    )
    assert str(route.calls[0].request.url) == SR_POLICIES_URL  # no server-side filter exists
    data = json.loads(text)
    assert [p["headend"] for p in data["items"]] == expected
    assert data["total"] == 2 and data["count"] == len(expected)


@respx.mock
async def test_list_sr_policies_no_match_is_not_error(settings):
    # With nothing to name, the topology is not read at all. The networks route is mocked
    # and asserted uncalled (an attempted read that failed would NOT surface as an Error —
    # the host-name fallback degrades it to a footer — so leaving it unmocked proves nothing).
    networks = mock_networks()
    respx.get(SR_POLICIES_URL).mock(return_value=ok(SR_POLICIES))
    text = await call_tool_text(build(settings), "cnc_list_sr_policies", {"oper_state": "down"})
    assert networks.call_count == 0
    assert not text.startswith("Error:")
    assert "Host names could not be resolved" not in text
    assert "# SR policies (0 of 2, oper_state=DOWN)" in text
    assert "No SR policies match the filter (oper_state=DOWN); 2 are reported in total." in text


@respx.mock
async def test_list_sr_policies_bad_oper_state_is_error_before_any_call(settings):
    route = respx.get(SR_POLICIES_URL).mock(return_value=ok(SR_POLICIES))
    text = await call_tool_text(build(settings), "cnc_list_sr_policies", {"oper_state": "ACTIVE"})
    assert text.startswith("Error: oper_state must be one of UP, DOWN")
    assert route.call_count == 0


@respx.mock
async def test_list_sr_policies_empty_container_is_not_error(settings):
    networks = mock_networks()  # mocked and asserted uncalled: nothing to name, no read
    respx.get(SR_POLICIES_URL).mock(return_value=ok(EMPTY))
    text = await call_tool_text(build(settings), "cnc_list_sr_policies", {})
    assert text.startswith("No SR policies are reported by the SR-PCE feed.")
    assert "report-all" in text and not text.startswith("Error:")
    text = await call_tool_text(
        build(settings), "cnc_list_sr_policies", {"response_format": "json"}
    )
    assert networks.call_count == 0
    assert json.loads(text) == {
        "count": 0,
        "total": 0,
        "filter": {
            "headend": None,
            "endpoint": None,
            "color": None,
            "oper_state": None,
            "pce_controlled": None,
            "dataplane": None,
        },
        "items": [],
    }


@respx.mock
async def test_list_sr_policies_api_error_is_string(make_settings):
    respx.get(SR_POLICIES_URL).mock(return_value=UNKNOWN_ELEMENT_400)
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_list_sr_policies", {})
    assert text.startswith("Error:") and "400" in text and "unknown-element" in text


@respx.mock
async def test_list_sr_policies_policy_without_details_says_no_path_reported(settings):
    # A policy with no policy-details (or an empty path list) renders a line, not a crash.
    bare = {k: v for k, v in PE1_POLICY.items() if k != "policy-details"}
    no_paths = {**PE2_POLICY, "policy-details": {"pce-controlled": True, "path": []}}
    respx.get(SR_POLICIES_URL).mock(
        return_value=ok(
            {"cisco-crosswork-segment-routing-policy:sr-policies": {"policy": [bare, no_paths]}}
        )
    )
    mock_networks()
    text = await call_tool_text(build(settings), "cnc_list_sr_policies", {})
    assert not text.startswith("Error:") and "# SR policies (2 of 2, no filter)" in text
    # Nothing to derive a dataplane from but the IPv4 keys: sr-mpls.
    assert (
        "- **PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 100** admin=UP oper=UP type=REGULAR "
        "dataplane=sr-mpls bsid=- origin=unknown pce-controlled=None pcc=- | no path reported "
        "updated=-"
    ) in text
    assert (
        "- **PE2 (10.0.0.3) -> PE1 (10.0.0.1) color 100** admin=UP oper=UP type=REGULAR "
        "dataplane=sr-mpls bsid=- origin=unknown pce-controlled=True pcc=- | no path reported "
        "updated=-"
    ) in text


@respx.mock
async def test_list_sr_policies_dataplane_srv6_matches_nothing_on_the_sr_mpls_lab(settings):
    """Today's lab: the two verified SR-MPLS policies and no SRv6 one, so dataplane='srv6'
    is a normal empty answer that says where SRv6 policies would come from."""
    networks = mock_networks()
    route = respx.get(SR_POLICIES_URL).mock(return_value=ok(SR_POLICIES))
    text = await call_tool_text(build(settings), "cnc_list_sr_policies", {"dataplane": "SRv6"})
    assert route.call_count == 1 and networks.call_count == 0  # nothing to name, no read
    assert not text.startswith("Error:")
    assert "# SR policies (0 of 2, dataplane=srv6)" in text
    assert "No SR policies match the filter (dataplane=srv6); 2 are reported in total." in text
    assert "SRv6 policies come from the NSO SR-TE CFP only in 7.2" in text
    text = await call_tool_text(
        build(settings), "cnc_list_sr_policies", {"dataplane": "mpls", "response_format": "json"}
    )
    data = json.loads(text)
    assert data["count"] == 2 and data["filter"]["dataplane"] == "sr-mpls"
    text = await call_tool_text(
        build(settings), "cnc_list_sr_policies", {"dataplane": "srv6", "response_format": "json"}
    )
    data = json.loads(text)
    assert data["count"] == 0 and data["total"] == 2 and data["items"] == []


@respx.mock
async def test_list_sr_policies_dataplane_srv6_with_other_filter_does_not_claim_none_exist(
    settings,
):
    """'none is reported' is a claim about the whole container: when an SRv6 policy IS
    reported (PE1 -> PE2 colour 6001) and a second filter term excluded it, the empty
    answer must say so, not that the network has no SRv6 policy."""
    networks = mock_networks(NETWORKS_V6)
    respx.get(SR_POLICIES_URL).mock(return_value=ok(MIXED_POLICIES))
    text = await call_tool_text(
        build(settings), "cnc_list_sr_policies", {"headend": "P1", "dataplane": "srv6"}
    )
    assert networks.call_count == 1 and not text.startswith("Error:")
    assert "# SR policies (0 of 3, headend=P1 (10.0.0.2), dataplane=srv6)" in text
    assert "No SR policies match the filter (headend=P1 (10.0.0.2), dataplane=srv6)" in text
    assert "none is reported by the SR-PCE feed" not in text
    assert (
        "1 SRv6 policy is reported in total; none matches the other filter terms "
        "(headend=P1 (10.0.0.2))."
    ) in text
    # Two SRv6 policies, excluded by oper_state: the plural form, no topology read.
    two = {
        "cisco-crosswork-segment-routing-policy:sr-policies": {
            "policy": [PE1_POLICY, SRV6_POLICY, {**SRV6_POLICY, "color": 6002}]
        }
    }
    respx.get(SR_POLICIES_URL).mock(return_value=ok(two))
    text = await call_tool_text(
        build(settings), "cnc_list_sr_policies", {"oper_state": "down", "dataplane": "srv6"}
    )
    assert networks.call_count == 1
    assert "# SR policies (0 of 3, oper_state=DOWN, dataplane=srv6)" in text
    assert "none is reported by the SR-PCE feed" not in text
    assert (
        "2 SRv6 policies are reported in total; none matches the other filter terms "
        "(oper_state=DOWN)."
    ) in text
    # Only the dataplane filter, on a container without any SRv6 policy: the "none is
    # reported" sentence is the right one (the SR-MPLS lab today).
    respx.get(SR_POLICIES_URL).mock(return_value=ok(SR_POLICIES))
    text = await call_tool_text(
        build(settings), "cnc_list_sr_policies", {"headend": "P1", "dataplane": "srv6"}
    )
    assert "none is reported by the SR-PCE feed" in text
    assert "none matches the other filter terms" not in text


@respx.mock
async def test_list_sr_policies_renders_an_srv6_policy_and_filters_by_dataplane(settings):
    """Spec-shaped (awaits the underlay): an SRv6 policy keyed by the IPv6 TE router-ids,
    named through the topology's ipv6-router-id leaf-list, its SRv6 BSID in the bsid column
    and its hops as <sid>(<type>/<address> <behavior>)."""
    mock_networks(NETWORKS_V6)
    respx.get(SR_POLICIES_URL).mock(return_value=ok(MIXED_POLICIES))
    text = await call_tool_text(build(settings), "cnc_list_sr_policies", {})
    assert "# SR policies (3 of 3, no filter)" in text
    assert (
        "- **PE1 (2001:db8::1) -> PE2 (2001:db8::3) color 6001** admin=UP oper=UP type=REGULAR "
        "dataplane=srv6 bsid=fc00:0:1:1:: origin=PCC-initiated pce-controlled=True "
        "pcc=2001:db8::1 | active path: srte_c_6001_ep_2001:db8::3 pref=100 PT-DYNAMIC "
        "metric=IGP-METRIC:20 hops=fc00:0:3::(IPV6-NODE-SID/2001:db8::3 uN) > "
        "fc00:0:1:e000::(IPV6-ADJ-SID/2001:db8:1::1->2001:db8:1::2 uA)[protected] "
        "updated=2026-09-13T"
    ) in text
    # The SR-MPLS rows are untouched by the IPv6 names (the IPv4 router-id still names PE1).
    assert "- **PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 100** admin=UP" in text
    assert "dataplane=sr-mpls bsid=24005" in text
    text = await call_tool_text(build(settings), "cnc_list_sr_policies", {"dataplane": "srv6"})
    assert "# SR policies (1 of 3, dataplane=srv6)" in text
    assert "color 6001" in text and "color 100" not in text
    text = await call_tool_text(
        build(settings), "cnc_list_sr_policies", {"dataplane": "SR-MPLS", "response_format": "json"}
    )
    data = json.loads(text)
    assert data["count"] == 2 and [p["color"] for p in data["items"]] == [100, 100]
    # An IPv6 literal filters the SRv6 policy directly (no topology read).
    text = await call_tool_text(
        build(settings), "cnc_list_sr_policies", {"endpoint": PE2_V6, "response_format": "json"}
    )
    data = json.loads(text)
    assert data["count"] == 1 and data["items"] == [SRV6_POLICY]
    assert data["filter"]["endpoint"] == PE2_V6


@respx.mock
async def test_list_sr_policies_host_name_filter_matches_ipv4_and_ipv6_keys(settings):
    """A host name resolves to EVERY TE router-id of its node, so 'PE1' lists PE1's SR-MPLS
    (IPv4-keyed) and SRv6 (IPv6-keyed) policies together; the header and the json filter
    show the whole match set."""
    networks = mock_networks(NETWORKS_V6)
    respx.get(SR_POLICIES_URL).mock(return_value=ok(MIXED_POLICIES))
    text = await call_tool_text(build(settings), "cnc_list_sr_policies", {"headend": "pe1"})
    assert networks.call_count == 1
    assert "# SR policies (2 of 3, headend=PE1 (10.0.0.1, 2001:db8::1))" in text
    assert "- **PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 100**" in text
    assert "- **PE1 (2001:db8::1) -> PE2 (2001:db8::3) color 6001**" in text
    assert "- **PE2 (10.0.0.3) -> PE1 (10.0.0.1) color 100**" not in text
    text = await call_tool_text(
        build(settings),
        "cnc_list_sr_policies",
        {"headend": "PE1", "endpoint": "PE2", "dataplane": "srv6", "response_format": "json"},
    )
    data = json.loads(text)
    assert data["count"] == 1 and data["items"] == [SRV6_POLICY]
    assert data["filter"]["headend"] == ["10.0.0.1", PE1_V6]
    assert data["filter"]["endpoint"] == ["10.0.0.3", PE2_V6]
    # A node with only an IPv4 router-id keeps the single-string filter value (as before).
    text = await call_tool_text(
        build(settings), "cnc_list_sr_policies", {"headend": "P1", "response_format": "json"}
    )
    assert json.loads(text)["filter"]["headend"] == "10.0.0.2"


@respx.mock
async def test_list_sr_policies_bad_dataplane_is_error_before_any_call(settings):
    route = respx.get(SR_POLICIES_URL).mock(return_value=ok(SR_POLICIES))
    text = await call_tool_text(build(settings), "cnc_list_sr_policies", {"dataplane": "ipv6"})
    assert text.startswith("Error: dataplane must be one of sr-mpls, srv6")
    assert route.call_count == 0


# --- cnc_get_sr_policy -------------------------------------------------------


@respx.mock
async def test_get_sr_policy_markdown_url_and_paths(settings):
    route = respx.get(f"{SR_POLICIES_URL}/policy={PE1_PE2_KEY}").mock(
        return_value=ok(SR_POLICY_KEYED)
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100},
    )
    request = route.calls[0].request
    assert str(request.url) == f"{SR_POLICIES_URL}/policy={PE1_PE2_KEY}"
    assert request.headers["Accept"] == YANG_JSON
    assert text.startswith("# SR policy 10.0.0.1 -> 10.0.0.3 color 100")
    assert "- admin-state=UP oper-state=UP type=REGULAR dataplane=sr-mpls description=-" in text
    assert (
        "- binding-sid=24005 pce-controlled=True pcc-address=10.0.0.1 delegated-pce=- msd=- "
        "updated=2026-09-13T"
    ) in text
    assert "srv6-binding-sid" not in text
    assert "- pcep-info: pcep-flag-c=0" in text
    # Origin vs delegation spelled out (scenario 3: the agent had to infer it).
    assert (
        "- origin: PCC-initiated (pcep-flag-c 0: configured on the head-end router); delegated "
        "to the PCE for (re)optimisation (pce-controlled true) — a router-configured policy "
        "the PCE may re-optimise"
    ) in text
    assert "Paths (1):" in text
    assert ("- **CNC-DYN-100** pref=100 PT-DYNAMIC oper=UP metric=IGP-METRIC:20 computed=-") in text
    assert "  constraints: sid-algorithm=0" in text
    assert "  segment-list 1 (weight 1): 16003(IPV4-NODE-SID/10.0.0.3)" in text


@respx.mock
async def test_get_sr_policy_router_id_input_never_reads_the_topology(settings):
    # The fast path: an IP literal goes on the wire as given — no networks GET at all.
    networks = mock_networks()
    respx.get(f"{SR_POLICIES_URL}/policy={PE1_PE2_KEY}").mock(return_value=ok(SR_POLICY_KEYED))
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100},
    )
    assert text.startswith("# SR policy 10.0.0.1 -> 10.0.0.3 color 100")
    assert networks.call_count == 0


@respx.mock
async def test_get_sr_policy_accepts_host_names_and_sends_router_ids(settings):
    # Scenario 10: every other SR-TE tool took PE2/PE1; this one forced a topology detour.
    networks = mock_networks()
    route = respx.get(f"{SR_POLICIES_URL}/policy={PE1_PE2_KEY}").mock(
        return_value=ok(SR_POLICY_KEYED)
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": "pe1", "endpoint": "PE2", "color": 100, "response_format": "json"},
    )
    assert networks.call_count == 1 and route.call_count == 1
    assert networks.calls[0].request.headers["Accept"] == YANG_JSON
    assert json.loads(text) == PE1_POLICY
    # Mixed spellings resolve too; once the topology was read for one name, the not-found
    # message names BOTH ends from it (round 2: names known -> names shown).
    respx.get(f"{SR_POLICIES_URL}/policy=10.0.0.3,10.0.0.1,300").mock(return_value=DATA_MISSING_409)
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": "PE2", "endpoint": "10.0.0.1", "color": 300},
    )
    assert text.startswith("Error: no SR policy PE2 (10.0.0.3) -> PE1 (10.0.0.1) color 300")
    assert "cnc_list_sr_policies" in text
    # The markdown header carries both spellings too, in the topology's exact node ids.
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": "pe1", "endpoint": "10.0.0.3", "color": 100},
    )
    assert text.startswith("# SR policy PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 100")


@respx.mock
async def test_get_sr_policy_unknown_host_name_is_error_before_the_policy_read(settings):
    mock_networks()
    route = respx.get(f"{SR_POLICIES_URL}/policy={PE1_PE2_KEY}").mock(
        return_value=ok(SR_POLICY_KEYED)
    )
    text = await call_tool_text(
        build(settings), "cnc_get_sr_policy", {"headend": "PE9", "endpoint": "PE2", "color": 100}
    )
    assert text.startswith("Error: no node 'PE9' in the topology")
    assert "cnc_list_topology_nodes" in text
    assert route.call_count == 0
    # An LLDP-only node has no router-id to key a policy with.
    text = await call_tool_text(
        build(settings), "cnc_get_sr_policy", {"headend": "SW1", "endpoint": "PE2", "color": 100}
    )
    assert text.startswith("Error: node 'SW1' has no TE router-id in the topology")
    assert route.call_count == 0


@respx.mock
async def test_get_sr_policy_blank_name_is_error_before_any_call(settings):
    networks = mock_networks()
    text = await call_tool_text(
        build(settings), "cnc_get_sr_policy", {"headend": " ", "endpoint": "PE2", "color": 100}
    )
    assert text.startswith("Error: headend and endpoint must not be blank")
    assert networks.call_count == 0


@respx.mock
async def test_get_sr_policy_unknown_network_lists_the_present_ones(settings):
    mock_networks()
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": "PE1", "endpoint": "PE2", "color": 100, "network": "other"},
    )
    assert text.startswith(
        "Error: no network 'other' on the topology NBI. Networks present: Default-network."
    )


@respx.mock
async def test_get_sr_policy_json_is_the_entry_and_unknown_keys_fall_through(settings):
    extra = {**PE1_POLICY, "vendor-flag": "x"}
    extra["policy-details"] = {**PE1_POLICY["policy-details"], "msd": 10}
    respx.get(f"{SR_POLICIES_URL}/policy={PE1_PE2_KEY}").mock(
        return_value=ok({"cisco-crosswork-segment-routing-policy:policy": [extra]})
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100, "response_format": "json"},
    )
    assert json.loads(text) == extra
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100},
    )
    assert "msd=10" in text and "- other: vendor-flag=x" in text


@respx.mock
async def test_get_sr_policy_409_is_not_found_with_hint(settings):
    respx.get(f"{SR_POLICIES_URL}/policy=10.0.0.1,10.0.0.3,999").mock(return_value=DATA_MISSING_409)
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 999},
    )
    assert text.startswith("Error: no SR policy 10.0.0.1 -> 10.0.0.3 color 999")
    assert "cnc_list_sr_policies" in text and "not host names" in text and "report-all" in text


@respx.mock
async def test_get_sr_policy_bare_404_is_not_reported_as_not_found(settings):
    respx.get(f"{SR_POLICIES_URL}/policy={PE1_PE2_KEY}").mock(return_value=BARE_404)
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100},
    )
    assert text.startswith("Error:") and "404" in text
    assert "no SR policy" not in text
    assert "never that the object is missing" in text


@respx.mock
async def test_get_sr_policy_404_with_restconf_document_is_not_not_found(settings):
    # The NSO proxy's not-found spelling (404 + RESTCONF document) has never been observed on
    # the topology NBI, whose not-found is 409 data-missing only: it must not be read as
    # "no such object" but fall through to the 404 explanation with the platform detail.
    respx.get(f"{SR_POLICIES_URL}/policy={PE1_PE2_KEY}").mock(return_value=RESTCONF_404)
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100},
    )
    assert text.startswith("Error: API request failed with status 404")
    assert "no SR policy" not in text and "is reported by the SR-PCE feed" not in text
    assert "never that the object is missing" in text
    assert "RESTCONF invalid-value: uri keypath not found" in text


@respx.mock
async def test_get_sr_policy_non_json_200_is_error(settings):
    respx.get(f"{SR_POLICIES_URL}/policy={PE1_PE2_KEY}").mock(return_value=HTML_200)
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100},
    )
    assert text == ("Error: The topology NBI returned a non-JSON response where JSON was expected.")


@respx.mock
async def test_get_sr_policy_string_color_on_the_wire_matches_int_argument(settings):
    # color arrived as an int live, but this NBI serialises other numeric leaves as strings;
    # a "color": "100" entry must still be the requested policy, not "no such object".
    string_color = {**PE1_POLICY, "color": "100"}
    respx.get(f"{SR_POLICIES_URL}/policy={PE1_PE2_KEY}").mock(
        return_value=ok({"cisco-crosswork-segment-routing-policy:policy": [string_color]})
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100, "response_format": "json"},
    )
    assert json.loads(text) == string_color
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100},
    )
    assert text.startswith("# SR policy 10.0.0.1 -> 10.0.0.3 color 100")


@respx.mock
async def test_get_sr_policy_without_policy_details_reports_no_path(settings):
    bare = {k: v for k, v in PE1_POLICY.items() if k != "policy-details"}
    respx.get(f"{SR_POLICIES_URL}/policy={PE1_PE2_KEY}").mock(
        return_value=ok({"cisco-crosswork-segment-routing-policy:policy": [bare]})
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100},
    )
    assert text.startswith("# SR policy 10.0.0.1 -> 10.0.0.3 color 100")
    assert (
        "- binding-sid=- pce-controlled=None pcc-address=- delegated-pce=- msd=- updated=-" in text
    )
    assert "- pcep-info: -" in text
    assert "Paths (0):" in text and "- (no path reported)" in text


@respx.mock
async def test_get_sr_policy_ipv6_literal_keys_are_percent_encoded_and_render_srv6(settings):
    """Verified live: an IPv6 key goes on the wire as policy=2001%3Adb8%3A%3A1,... and the NBI
    type-checks it as a key (409 data-missing when absent). The SRv6 rendering itself is the
    7.2 document shape — never observed live."""
    networks = mock_networks(NETWORKS_V6)
    route = respx.get(f"{SR_POLICIES_URL}/policy={PE1_PE2_V6_KEY}").mock(
        return_value=ok(SRV6_POLICY_KEYED)
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": PE1_V6, "endpoint": PE2_V6, "color": 6001},
    )
    assert str(route.calls[0].request.url) == f"{SR_POLICIES_URL}/policy={PE1_PE2_V6_KEY}"
    assert networks.call_count == 0  # IP literals: the fast path, no topology read
    assert text.startswith("# SR policy 2001:db8::1 -> 2001:db8::3 color 6001")
    assert "- admin-state=UP oper-state=UP type=REGULAR dataplane=srv6 description=-" in text
    # A non-canonical spelling of the same literal goes on the wire canonical (the only
    # route mocked) and passes the client-side key re-check against the wire entry.
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": "2001:0DB8::1", "endpoint": "2001:db8:0:0::3", "color": 6001},
    )
    assert route.call_count == 2 and networks.call_count == 0
    assert text.startswith("# SR policy 2001:db8::1 -> 2001:db8::3 color 6001")
    assert "- binding-sid=- pce-controlled=True pcc-address=2001:db8::1" in text
    assert "- srv6-binding-sid: fc00:0:1:1:: behavior=uB6.Insert.Red structure=32/16/16/0" in text
    assert "- other:" not in text  # the SRv6 BSID is rendered, not a leftover
    assert (
        "  segment-list 1 (weight 1): fc00:0:3::(IPV6-NODE-SID/2001:db8::3 uN) > "
        "fc00:0:1:e000::(IPV6-ADJ-SID/2001:db8:1::1->2001:db8:1::2 uA)[protected]"
    ) in text
    # The document's module-prefixed BSID spelling renders the same and is not "other".
    prefixed = {
        **SRV6_POLICY,
        "policy-details": {
            k: v for k, v in SRV6_POLICY["policy-details"].items() if k != "srv6-binding-sid"
        },
    }
    prefixed["policy-details"]["cisco-crosswork-segment-routing-policy:srv6-binding-sid"] = (
        SRV6_BSID
    )
    respx.get(f"{SR_POLICIES_URL}/policy={PE1_PE2_V6_KEY}").mock(
        return_value=ok({"cisco-crosswork-segment-routing-policy:policy": [prefixed]})
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": PE1_V6, "endpoint": PE2_V6, "color": 6001},
    )
    assert "- srv6-binding-sid: fc00:0:1:1:: behavior=uB6.Insert.Red" in text
    assert "- other:" not in text and "dataplane=srv6" in text
    # A 409 on an IPv6 literal key is "no SR policy", with the IPv6 key rule.
    respx.get(f"{SR_POLICIES_URL}/policy=2001%3Adb8%3A%3A1,2001%3Adb8%3A%3A3,6002").mock(
        return_value=DATA_MISSING_409
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": PE1_V6, "endpoint": PE2_V6, "color": 6002},
    )
    assert text.startswith("Error: no SR policy 2001:db8::1 -> 2001:db8::3 color 6002")
    assert "an SRv6 policy is keyed by the IPv6 TE router-ids" in text
    assert networks.call_count == 0


@respx.mock
async def test_get_sr_policy_host_names_retry_the_ipv6_key_after_a_409(settings):
    """Spec-only until an SRv6 policy exists: 'PE1' / 'PE2' resolve to the IPv4 router-ids
    first (the verified path); when that key answers 409 and both nodes carry an
    ipv6-router-id, the IPv6 pair is tried once — and finds the SRv6 policy."""
    networks = mock_networks(NETWORKS_V6)
    v4 = respx.get(f"{SR_POLICIES_URL}/policy=10.0.0.1,10.0.0.3,6001").mock(
        return_value=DATA_MISSING_409
    )
    v6 = respx.get(f"{SR_POLICIES_URL}/policy={PE1_PE2_V6_KEY}").mock(
        return_value=ok(SRV6_POLICY_KEYED)
    )
    text = await call_tool_text(
        build(settings), "cnc_get_sr_policy", {"headend": "PE1", "endpoint": "pe2", "color": 6001}
    )
    assert networks.call_count == 1 and v4.call_count == 1 and v6.call_count == 1
    assert text.startswith("# SR policy PE1 (2001:db8::1) -> PE2 (2001:db8::3) color 6001")
    assert "dataplane=srv6" in text
    # An IPv4 key that exists never makes the second request (the verified path is unchanged).
    v4_100 = respx.get(f"{SR_POLICIES_URL}/policy={PE1_PE2_KEY}").mock(
        return_value=ok(SR_POLICY_KEYED)
    )
    text = await call_tool_text(
        build(settings), "cnc_get_sr_policy", {"headend": "PE1", "endpoint": "PE2", "color": 100}
    )
    assert v4_100.call_count == 1 and v6.call_count == 1
    assert text.startswith("# SR policy PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 100")
    # Both keys absent: one error naming both — leading with the key the resolver chose
    # (the everyday case is a wrong colour on an SR-MPLS policy), the IPv6 pair as "tried
    # as well" — then nothing more is tried.
    v6_9 = respx.get(f"{SR_POLICIES_URL}/policy=2001%3Adb8%3A%3A1,2001%3Adb8%3A%3A3,9").mock(
        return_value=DATA_MISSING_409
    )
    v4_9 = respx.get(f"{SR_POLICIES_URL}/policy=10.0.0.1,10.0.0.3,9").mock(
        return_value=DATA_MISSING_409
    )
    text = await call_tool_text(
        build(settings), "cnc_get_sr_policy", {"headend": "PE1", "endpoint": "PE2", "color": 9}
    )
    assert v4_9.call_count == 1 and v6_9.call_count == 1
    assert text.startswith("Error: no SR policy PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 9")
    assert (
        "The IPv6 router-id key 2001:db8::1 -> 2001:db8::3 (the key an SRv6 policy would "
        "carry) was tried as well and is absent too."
    ) in text
    assert "IPv4 router-id key" not in text  # the first pair is not labelled by family
    assert "cnc_list_sr_policies" in text
    # A node without an IPv6 router-id (P1) means no retry: the plain not-found, one request.
    v4_p1 = respx.get(f"{SR_POLICIES_URL}/policy=10.0.0.1,10.0.0.2,9").mock(
        return_value=DATA_MISSING_409
    )
    text = await call_tool_text(
        build(settings), "cnc_get_sr_policy", {"headend": "PE1", "endpoint": "P1", "color": 9}
    )
    assert v4_p1.call_count == 1
    assert text.startswith("Error: no SR policy PE1 (10.0.0.1) -> P1 (10.0.0.2) color 9")
    assert "was tried as well" not in text


@respx.mock
async def test_get_sr_policy_host_name_next_to_an_ipv6_literal_resolves_to_the_ipv6_key(
    settings,
):
    # A policy's two keys share an address family: with one end an IPv6 literal, the host
    # name resolves straight to the node's IPv6 router-id (one request, no retry).
    networks = mock_networks(NETWORKS_V6)
    route = respx.get(f"{SR_POLICIES_URL}/policy={PE1_PE2_V6_KEY}").mock(
        return_value=ok(SRV6_POLICY_KEYED)
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": "PE1", "endpoint": PE2_V6, "color": 6001, "response_format": "json"},
    )
    assert networks.call_count == 1 and route.call_count == 1
    assert json.loads(text) == SRV6_POLICY
    # On today's lab (no ipv6-router-id anywhere) the same call falls back to the node's
    # IPv4 router-id — a mixed key the NBI answers 409 for — and is reported as not found.
    mock_networks()
    mixed = respx.get(f"{SR_POLICIES_URL}/policy=10.0.0.1,2001%3Adb8%3A%3A3,6001").mock(
        return_value=DATA_MISSING_409
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": "PE1", "endpoint": PE2_V6, "color": 6001},
    )
    assert mixed.call_count == 1
    assert text.startswith("Error: no SR policy PE1 (10.0.0.1) -> 2001:db8::3 color 6001")


@respx.mock
async def test_get_rsvp_te_tunnel_hostname_key_400_explains_router_id_rule(settings):
    # The NBI's 400 invalid-value for a host name where a router-id belongs (verified on
    # policy=PE1,PE2,100). The SR policy tools now resolve host names before the GET, so the
    # RSVP tunnel tool (router-ids only, nothing was available live to verify names with)
    # is where a host name still reaches the NBI — the explanation must survive there.
    respx.get(f"{RSVP_TUNNELS_URL}/rsvp-te-tunnel=PE1,PE2,7").mock(return_value=INVALID_VALUE_400)
    text = await call_tool_text(
        build(settings),
        "cnc_get_rsvp_te_tunnel",
        {"headend": "PE1", "endpoint": "PE2", "tunnel_id": 7},
    )
    assert text.startswith("Error:") and "400" in text and "Invalid value 'PE1'" in text
    assert "must be TE router-ids (IP addresses such as 10.0.0.1), not host names" in text
    assert "no RSVP-TE tunnel" not in text


@respx.mock
async def test_get_sr_policy_other_409_is_a_plain_error(settings):
    respx.get(f"{SR_POLICIES_URL}/policy={PE1_PE2_KEY}").mock(
        return_value=httpx.Response(
            409, json={"errors": {"error": [{"error-tag": "lock-denied", "error-message": "x"}]}}
        )
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100},
    )
    assert text.startswith("Error:") and "409" in text and "no SR policy" not in text


@respx.mock
async def test_get_sr_policy_rechecks_the_key_client_side(settings):
    # The key ignored (whole list back): the right entry is picked; a key nobody carries
    # is reported missing even though the GET answered 200.
    respx.get(f"{SR_POLICIES_URL}/policy={PE1_PE2_KEY}").mock(
        return_value=ok({"cisco-crosswork-segment-routing-policy:policy": [PE2_POLICY, PE1_POLICY]})
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100, "response_format": "json"},
    )
    assert json.loads(text) == PE1_POLICY
    respx.get(f"{SR_POLICIES_URL}/policy=10.0.0.9,10.0.0.3,100").mock(
        return_value=ok({"cisco-crosswork-segment-routing-policy:policy": [PE1_POLICY]})
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy",
        {"headend": "10.0.0.9", "endpoint": "10.0.0.3", "color": 100},
    )
    assert text.startswith("Error: no SR policy 10.0.0.9 -> 10.0.0.3 color 100")


@respx.mock
async def test_get_sr_policy_server_error_is_string(make_settings):
    respx.get(f"{SR_POLICIES_URL}/policy={PE1_PE2_KEY}").mock(
        return_value=httpx.Response(500, text="")
    )
    text = await call_tool_text(
        build(make_settings(max_retries=0)),
        "cnc_get_sr_policy",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100},
    )
    assert text.startswith("Error:") and "500" in text and "no SR policy" not in text


# --- cnc_list_p2mp_policies / cnc_get_p2mp_policy ----------------------------


@respx.mock
async def test_list_p2mp_policies_empty_is_not_error(settings):
    route = respx.get(P2MP_POLICIES_URL).mock(return_value=ok(EMPTY))
    text = await call_tool_text(build(settings), "cnc_list_p2mp_policies", {})
    request = route.calls[0].request
    assert str(request.url) == P2MP_POLICIES_URL and request.headers["Accept"] == YANG_JSON
    assert text.startswith("No P2MP (Tree-SID) policies are reported")
    assert "the platform reports none" in text and not text.startswith("Error:")
    text = await call_tool_text(
        build(settings), "cnc_list_p2mp_policies", {"response_format": "json"}
    )
    assert json.loads(text) == {"count": 0, "items": []}


@respx.mock
async def test_list_p2mp_policies_renders_document_shape(settings):
    respx.get(P2MP_POLICIES_URL).mock(return_value=ok(P2MP_POLICIES))
    text = await call_tool_text(build(settings), "cnc_list_p2mp_policies", {})
    assert "# P2MP (Tree-SID) policies (1)" in text
    assert (
        "- **tree-100** root=10.0.0.1 tree-id=524289 admin=UP oper=UP initiation=PCE-INITIATED "
        "pcc=10.0.0.1 pce=10.0.0.5 destinations=2 [10.0.0.3, 10.0.0.4] candidate-paths=1 "
        'other={"vendor-extra":"kept"}'
    ) in text
    text = await call_tool_text(
        build(settings), "cnc_list_p2mp_policies", {"response_format": "json"}
    )
    assert json.loads(text) == {"count": 1, "items": [P2MP_POLICY]}


@respx.mock
async def test_list_p2mp_policies_api_error_is_string(make_settings):
    respx.get(P2MP_POLICIES_URL).mock(return_value=UNKNOWN_ELEMENT_400)
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_list_p2mp_policies", {})
    assert text.startswith("Error:") and "400" in text


@respx.mock
async def test_get_p2mp_policy_markdown_encodes_name(settings):
    route = respx.get(f"{P2MP_POLICIES_URL}/p2mp-policy=tree%20100%2Fa").mock(
        return_value=ok(
            {
                "cisco-crosswork-segment-routing-p2mp-policy:p2mp-policy": [
                    {**P2MP_POLICY, "name": "tree 100/a"}
                ]
            }
        )
    )
    text = await call_tool_text(build(settings), "cnc_get_p2mp_policy", {"name": "tree 100/a"})
    request = route.calls[0].request
    assert str(request.url) == f"{P2MP_POLICIES_URL}/p2mp-policy=tree%20100%2Fa"
    assert request.headers["Accept"] == YANG_JSON
    assert text.startswith("# P2MP (Tree-SID) policy tree 100/a")
    assert "Candidate paths (1):" in text
    assert (
        "- **tree-100-cp** DYNAMIC oper=UP label=15100 metric=IGP-METRIC pref=100 programming=NONE"
    ) in text
    assert "  constraints: frr-protected=true" in text
    assert "  nodes (2):" in text
    assert (
        "  - PE1 (10.0.0.1) role=INGRESS next-hops: 10.1.1.1->10.1.1.2 label=15100 to P1(10.0.0.2)"
    ) in text
    assert "  - PE2 (10.0.0.3) role=EGRESS next-hops: -" in text


@respx.mock
async def test_get_p2mp_policy_json_and_409(settings):
    respx.get(f"{P2MP_POLICIES_URL}/p2mp-policy=tree-100").mock(
        return_value=ok({"cisco-crosswork-segment-routing-p2mp-policy:p2mp-policy": [P2MP_POLICY]})
    )
    text = await call_tool_text(
        build(settings), "cnc_get_p2mp_policy", {"name": "tree-100", "response_format": "json"}
    )
    assert json.loads(text) == P2MP_POLICY
    respx.get(f"{P2MP_POLICIES_URL}/p2mp-policy=nope").mock(return_value=DATA_MISSING_409)
    text = await call_tool_text(build(settings), "cnc_get_p2mp_policy", {"name": "nope"})
    assert text.startswith("Error: no P2MP (Tree-SID) policy named 'nope'")
    assert "cnc_list_p2mp_policies" in text


@respx.mock
async def test_get_p2mp_policy_bare_404_is_not_not_found(settings):
    respx.get(f"{P2MP_POLICIES_URL}/p2mp-policy=tree-100").mock(return_value=BARE_404)
    text = await call_tool_text(build(settings), "cnc_get_p2mp_policy", {"name": "tree-100"})
    assert text.startswith("Error:") and "404" in text and "no P2MP" not in text


# --- cnc_list_rsvp_te_tunnels / cnc_get_rsvp_te_tunnel -----------------------


@respx.mock
async def test_list_rsvp_te_tunnels_empty_is_not_error(settings):
    route = respx.get(RSVP_TUNNELS_URL).mock(return_value=ok(EMPTY))
    text = await call_tool_text(build(settings), "cnc_list_rsvp_te_tunnels", {})
    request = route.calls[0].request
    assert str(request.url) == RSVP_TUNNELS_URL and request.headers["Accept"] == YANG_JSON
    assert text.startswith("No RSVP-TE tunnels are reported") and not text.startswith("Error:")
    text = await call_tool_text(
        build(settings), "cnc_list_rsvp_te_tunnels", {"response_format": "json"}
    )
    assert json.loads(text) == {"count": 0, "items": []}


@respx.mock
async def test_list_rsvp_te_tunnels_renders_document_shape(settings):
    respx.get(RSVP_TUNNELS_URL).mock(return_value=ok(RSVP_TUNNELS))
    text = await call_tool_text(build(settings), "cnc_list_rsvp_te_tunnels", {})
    assert "# RSVP-TE tunnels (1)" in text
    assert (
        "- **10.0.0.1 -> 10.0.0.3 tunnel-id 7** admin=UP oper=UP type=OTHER binding-label=24010 "
        "bw-mbps=50 prio=7/7 pce-controlled=False pcc=10.0.0.1 | active path: t7-path "
        "PT-EXPLICIT oper=ACTIVE metric=TE-METRIC:30 rro=P1(10.0.0.2) > PE2(10.0.0.3) "
        "updated=2026-09-13T"
    ) in text
    text = await call_tool_text(
        build(settings), "cnc_list_rsvp_te_tunnels", {"response_format": "json"}
    )
    assert json.loads(text) == {"count": 1, "items": [RSVP_TUNNEL]}


@respx.mock
async def test_list_rsvp_te_tunnels_api_error_is_string(make_settings):
    respx.get(RSVP_TUNNELS_URL).mock(return_value=httpx.Response(503, text="unavailable"))
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_list_rsvp_te_tunnels", {})
    assert text.startswith("Error:") and "503" in text


@respx.mock
async def test_get_rsvp_te_tunnel_markdown_url_and_hops(settings):
    route = respx.get(f"{RSVP_TUNNELS_URL}/rsvp-te-tunnel=10.0.0.1,10.0.0.3,7").mock(
        return_value=ok({"cisco-crosswork-rsvp-te-tunnel:rsvp-te-tunnel": [RSVP_TUNNEL]})
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_rsvp_te_tunnel",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "tunnel_id": 7},
    )
    request = route.calls[0].request
    assert str(request.url) == f"{RSVP_TUNNELS_URL}/rsvp-te-tunnel=10.0.0.1,10.0.0.3,7"
    assert request.headers["Accept"] == YANG_JSON
    assert text.startswith("# RSVP-TE tunnel 10.0.0.1 -> 10.0.0.3 tunnel-id 7")
    assert "- admin-state=UP oper-state=UP type=OTHER description=t7" in text
    assert (
        "- binding-label=24010 signaled-bandwidth-mbps=50 setup/hold-priority=7/7 "
        "pce-controlled=False pcc-address=10.0.0.1 delegated-pce=- updated=2026-09-13T"
    ) in text
    assert "- pcep-info: pcep-flag-d=false" in text
    assert "Paths (1):" in text
    assert "- **t7-path** PT-EXPLICIT oper=ACTIVE metric=TE-METRIC:30 computed=-" in text
    assert '  constraints: affinity={"exclude-any":0}' in text
    assert "  ERO: 10.1.1.2[strict] > 10.1.2.2[strict]" in text
    assert "  RRO: P1(10.0.0.2) > PE2(10.0.0.3)" in text


@respx.mock
async def test_get_rsvp_te_tunnel_json_409_and_404(settings):
    url = f"{RSVP_TUNNELS_URL}/rsvp-te-tunnel=10.0.0.1,10.0.0.3,7"
    respx.get(url).mock(
        return_value=ok({"cisco-crosswork-rsvp-te-tunnel:rsvp-te-tunnel": [RSVP_TUNNEL]})
    )
    args = {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "tunnel_id": 7}
    text = await call_tool_text(
        build(settings), "cnc_get_rsvp_te_tunnel", {**args, "response_format": "json"}
    )
    assert json.loads(text) == RSVP_TUNNEL
    respx.get(f"{RSVP_TUNNELS_URL}/rsvp-te-tunnel=10.0.0.1,10.0.0.3,1").mock(
        return_value=DATA_MISSING_409
    )
    text = await call_tool_text(build(settings), "cnc_get_rsvp_te_tunnel", {**args, "tunnel_id": 1})
    assert text.startswith("Error: no RSVP-TE tunnel 10.0.0.1 -> 10.0.0.3 tunnel-id 1")
    assert "cnc_list_rsvp_te_tunnels" in text
    respx.get(url).mock(return_value=BARE_404)
    text = await call_tool_text(build(settings), "cnc_get_rsvp_te_tunnel", args)
    assert text.startswith("Error:") and "404" in text and "no RSVP-TE tunnel" not in text
    respx.get(url).mock(return_value=RESTCONF_404)
    text = await call_tool_text(build(settings), "cnc_get_rsvp_te_tunnel", args)
    assert text.startswith("Error: API request failed with status 404")
    assert "no RSVP-TE tunnel" not in text and "never that the object is missing" in text


@respx.mock
async def test_get_rsvp_te_tunnel_string_tunnel_id_on_the_wire_matches_int_argument(settings):
    # The RSVP shape is spec-only (none on the lab) and this NBI serialises uint64 leaves as
    # strings live, so "tunnel-id": "7" is realistic; it must match tunnel_id=7.
    string_tunnel = {**RSVP_TUNNEL, "tunnel-id": "7"}
    respx.get(f"{RSVP_TUNNELS_URL}/rsvp-te-tunnel=10.0.0.1,10.0.0.3,7").mock(
        return_value=ok({"cisco-crosswork-rsvp-te-tunnel:rsvp-te-tunnel": [string_tunnel]})
    )
    args = {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "tunnel_id": 7}
    text = await call_tool_text(
        build(settings), "cnc_get_rsvp_te_tunnel", {**args, "response_format": "json"}
    )
    assert json.loads(text) == string_tunnel
    text = await call_tool_text(build(settings), "cnc_get_rsvp_te_tunnel", args)
    assert text.startswith("# RSVP-TE tunnel 10.0.0.1 -> 10.0.0.3 tunnel-id 7")
    assert "no RSVP-TE tunnel" not in text


# --- cnc_get_link_performance_metrics ----------------------------------------


@respx.mock
async def test_get_link_performance_metrics_encodes_link_id(settings):
    route = respx.get(f"{IGP_LINK_PM_URL}={LINK_ID_ENCODED}").mock(return_value=ok(IGP_LINK_PM))
    text = await call_tool_text(
        build(settings), "cnc_get_link_performance_metrics", {"link_id": LINK_ID}
    )
    request = route.calls[0].request
    assert str(request.url) == f"{IGP_LINK_PM_URL}={LINK_ID_ENCODED}"
    assert request.url.raw_path.decode().endswith(f"/igp-link-pm={LINK_ID_ENCODED}")
    assert request.headers["Accept"] == YANG_JSON
    assert text.startswith(f"# Performance metrics for link {LINK_ID}")
    assert "- P2 GigabitEthernet0/0/0/0 -> PE2 GigabitEthernet0/0/0/1" in text
    assert (
        "- max-bandwidth-kbps=1000000 bandwidth-utilization-kbps=1 delay-us=10 "
        "delay-telemetry-us=- jitter-telemetry-us=-"
    ) in text
    assert (
        "- interfaces: Throughput=0.000141605327371508 Bandwidth=1000000000 TX-Errors=0 "
        "TX-packet-drops=0 RX-Errors=- RX-packet-drops=-"
    ) in text


@respx.mock
async def test_get_link_performance_metrics_json_is_the_entry(settings):
    respx.get(f"{IGP_LINK_PM_URL}={LINK_ID_ENCODED}").mock(return_value=ok(IGP_LINK_PM))
    text = await call_tool_text(
        build(settings),
        "cnc_get_link_performance_metrics",
        {"link_id": LINK_ID, "response_format": "json"},
    )
    assert json.loads(text) == IGP_LINK_PM["cisco-crosswork-performance-metrics:igp-link-pm"][0]


@respx.mock
async def test_get_link_performance_metrics_l2_link_409_explains_igp_only(settings):
    encoded = LINK_ID_ENCODED.replace("ISIS_IPV4_L2", "ETHERNET")
    respx.get(f"{IGP_LINK_PM_URL}={encoded}").mock(return_value=DATA_MISSING_409)
    text = await call_tool_text(
        build(settings), "cnc_get_link_performance_metrics", {"link_id": L2_LINK_ID}
    )
    assert text.startswith(f"Error: no performance metrics for link '{L2_LINK_ID}'")
    assert "ISIS_IPV4_L2" in text and "not ETHERNET links" in text
    assert "cnc_list_topology_links" in text


@respx.mock
async def test_get_link_performance_metrics_bare_404_is_not_not_found(settings):
    respx.get(f"{IGP_LINK_PM_URL}={LINK_ID_ENCODED}").mock(return_value=BARE_404)
    text = await call_tool_text(
        build(settings), "cnc_get_link_performance_metrics", {"link_id": LINK_ID}
    )
    assert text.startswith("Error:") and "404" in text
    assert "no performance metrics" not in text


# --- cnc_get_sr_policy_performance_metrics -----------------------------------


@respx.mock
async def test_get_sr_policy_performance_metrics_markdown_and_url(settings):
    route = respx.get(f"{SR_POLICY_PM_URL}={PE1_PE2_KEY}").mock(return_value=ok(SR_POLICY_PM))
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy_performance_metrics",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100},
    )
    request = route.calls[0].request
    assert str(request.url) == f"{SR_POLICY_PM_URL}={PE1_PE2_KEY}"
    assert request.headers["Accept"] == YANG_JSON
    assert text.startswith("# Performance metrics for SR policy 10.0.0.1 -> 10.0.0.3 color 100")
    # Scenario 2: without NAPM/SR-PM telemetry the delay is modelled (verified live: equal to
    # the COE's sr-policy-metrics delay), and the rendering must say so on the value itself.
    assert "- delay-us=20 (modelled — no NAPM/SR-PM telemetry present" in text
    assert "cnc_get_sr_policy_metrics" in text and "cnc_get_lsp_delay" in text
    assert (
        "- bandwidth-utilization-kbps=0 delay-telemetry-us=- jitter-telemetry-us=- liveness=-"
    ) in text
    assert "while they are absent, delay-us is modelled" in text


@respx.mock
async def test_get_sr_policy_performance_metrics_with_telemetry_has_no_modelled_caveat(settings):
    respx.get(f"{SR_POLICY_PM_URL}={PE1_PE2_KEY}").mock(return_value=ok(SR_POLICY_PM_TELEMETRY))
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy_performance_metrics",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100},
    )
    assert "- delay-us=20\n" in text and "modelled" not in text.split("\n")[2]
    assert "delay-telemetry-us=1234 jitter-telemetry-us=12 liveness=-" in text


@respx.mock
async def test_get_sr_policy_performance_metrics_accepts_host_names(settings):
    networks = mock_networks()
    route = respx.get(f"{SR_POLICY_PM_URL}={PE1_PE2_KEY}").mock(return_value=ok(SR_POLICY_PM))
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy_performance_metrics",
        {"headend": "PE1", "endpoint": "PE2", "color": 100},
    )
    assert networks.call_count == 1 and route.call_count == 1
    assert text.startswith(
        "# Performance metrics for SR policy PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 100"
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy_performance_metrics",
        {"headend": "PE9", "endpoint": "PE2", "color": 100},
    )
    assert text.startswith("Error: no node 'PE9' in the topology")
    assert route.call_count == 1


@respx.mock
async def test_get_sr_policy_performance_metrics_ipv6_key_is_encoded_and_retried(settings):
    """Verified live: sr-policy-pm=2001%3Adb8%3A%3A1,... is type-checked as a key (409 when
    absent). The IPv6 retry after a 409 on host names mirrors cnc_get_sr_policy (spec-only)."""
    networks = mock_networks(NETWORKS_V6)
    v6_entry = {
        "cisco-crosswork-performance-metrics:sr-policy-pm": [
            {
                "headend": PE1_V6,
                "endpoint": PE2_V6,
                "color": 6001,
                "delay": 20,
                "bandwidth-utilization-kbps": "0",
            }
        ]
    }
    route = respx.get(f"{SR_POLICY_PM_URL}={PE1_PE2_V6_KEY}").mock(return_value=ok(v6_entry))
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy_performance_metrics",
        {"headend": PE1_V6, "endpoint": PE2_V6, "color": 6001},
    )
    assert str(route.calls[0].request.url) == f"{SR_POLICY_PM_URL}={PE1_PE2_V6_KEY}"
    assert networks.call_count == 0
    assert text.startswith(
        "# Performance metrics for SR policy 2001:db8::1 -> 2001:db8::3 color 6001"
    )
    assert "- delay-us=20 (modelled" in text
    # Host names: the IPv4 key first, then the IPv6 pair once; the title names the key
    # that answered.
    v4 = respx.get(f"{SR_POLICY_PM_URL}=10.0.0.1,10.0.0.3,6001").mock(return_value=DATA_MISSING_409)
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy_performance_metrics",
        {"headend": "PE1", "endpoint": "PE2", "color": 6001},
    )
    assert networks.call_count == 1 and v4.call_count == 1 and route.call_count == 2
    assert text.startswith(
        "# Performance metrics for SR policy PE1 (2001:db8::1) -> PE2 (2001:db8::3) color 6001"
    )
    # Both absent: the error leads with the key the resolver chose and names the IPv6 pair
    # as tried as well.
    respx.get(f"{SR_POLICY_PM_URL}={PE1_PE2_V6_KEY}").mock(return_value=DATA_MISSING_409)
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy_performance_metrics",
        {"headend": "PE1", "endpoint": "PE2", "color": 6001},
    )
    assert text.startswith(
        "Error: no performance metrics for SR policy PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 6001"
    )
    assert (
        "The IPv6 router-id key 2001:db8::1 -> 2001:db8::3 (the key an SRv6 policy would "
        "carry) was tried as well and is absent too."
    ) in text


@respx.mock
async def test_get_sr_policy_performance_metrics_json_and_409(settings):
    respx.get(f"{SR_POLICY_PM_URL}={PE1_PE2_KEY}").mock(return_value=ok(SR_POLICY_PM))
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy_performance_metrics",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100, "response_format": "json"},
    )
    assert json.loads(text) == SR_POLICY_PM["cisco-crosswork-performance-metrics:sr-policy-pm"][0]
    respx.get(f"{SR_POLICY_PM_URL}=10.0.0.1,10.0.0.3,999").mock(return_value=DATA_MISSING_409)
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy_performance_metrics",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 999},
    )
    assert text.startswith(
        "Error: no performance metrics for SR policy 10.0.0.1 -> 10.0.0.3 color 999"
    )
    assert "cnc_list_sr_policies" in text


@respx.mock
async def test_get_rsvp_tunnel_performance_metrics_hostname_key_400_explains_rule(settings):
    # As for the tunnel get: the SR policy PM tool resolves host names first, so the NBI's 400
    # invalid-value explanation is exercised through the router-id-only RSVP PM tool.
    respx.get(f"{RSVP_PM_URL}=PE1,PE2,7").mock(return_value=INVALID_VALUE_400)
    text = await call_tool_text(
        build(settings),
        "cnc_get_rsvp_tunnel_performance_metrics",
        {"headend": "PE1", "endpoint": "PE2", "tunnel_id": 7},
    )
    assert text.startswith("Error:") and "400" in text
    assert "not host names" in text and "no performance metrics" not in text


@respx.mock
async def test_get_sr_policy_performance_metrics_bare_404_is_not_not_found(settings):
    respx.get(f"{SR_POLICY_PM_URL}={PE1_PE2_KEY}").mock(return_value=BARE_404)
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy_performance_metrics",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100},
    )
    assert text.startswith("Error:") and "404" in text and "no performance metrics" not in text


# --- cnc_get_rsvp_tunnel_performance_metrics ---------------------------------


@respx.mock
async def test_get_rsvp_tunnel_performance_metrics_markdown_json_and_409(settings):
    route = respx.get(f"{RSVP_PM_URL}=10.0.0.1,10.0.0.3,7").mock(return_value=ok(RSVP_PM))
    args = {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "tunnel_id": 7}
    text = await call_tool_text(build(settings), "cnc_get_rsvp_tunnel_performance_metrics", args)
    request = route.calls[0].request
    assert str(request.url) == f"{RSVP_PM_URL}=10.0.0.1,10.0.0.3,7"
    assert request.headers["Accept"] == YANG_JSON
    assert text.startswith(
        "# Performance metrics for RSVP-TE tunnel 10.0.0.1 -> 10.0.0.3 tunnel-id 7"
    )
    # The shared renderer, RSVP flavour: no *-telemetry key -> the delay is caveated, but only
    # as a PRESUMPTION — nothing about RSVP was verified live (no tunnel was available), so the
    # SR policy's "verified live ... equal to cnc_get_sr_policy_metrics" sentence must not
    # leak into a tunnel entry; the only cross-reference is cnc_get_lsp_delay (tunnel_id).
    assert "- delay-us=30 (presumed modelled, as for SR policies — UNVERIFIED" in text
    assert "no RSVP-TE tunnel was available live" in text
    assert "cnc_get_lsp_delay (with tunnel_id" in text
    assert "verified live" not in text and "cnc_get_sr_policy_metrics" not in text
    assert "delay-us is presumed modelled (see above), not measured." in text
    assert "- bandwidth-utilization-kbps=12" in text
    text = await call_tool_text(
        build(settings),
        "cnc_get_rsvp_tunnel_performance_metrics",
        {**args, "response_format": "json"},
    )
    assert json.loads(text) == RSVP_PM["cisco-crosswork-performance-metrics:rsvp-policy-pm"][0]
    respx.get(f"{RSVP_PM_URL}=10.0.0.1,10.0.0.3,1").mock(return_value=DATA_MISSING_409)
    text = await call_tool_text(
        build(settings), "cnc_get_rsvp_tunnel_performance_metrics", {**args, "tunnel_id": 1}
    )
    assert text.startswith(
        "Error: no performance metrics for RSVP-TE tunnel 10.0.0.1 -> 10.0.0.3 tunnel-id 1"
    )
    assert "cnc_list_rsvp_te_tunnels" in text


@respx.mock
async def test_get_rsvp_tunnel_performance_metrics_bare_404_is_not_not_found(settings):
    respx.get(f"{RSVP_PM_URL}=10.0.0.1,10.0.0.3,7").mock(return_value=BARE_404)
    text = await call_tool_text(
        build(settings),
        "cnc_get_rsvp_tunnel_performance_metrics",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "tunnel_id": 7},
    )
    assert text.startswith("Error:") and "404" in text and "no performance metrics" not in text


@respx.mock
async def test_get_rsvp_tunnel_performance_metrics_string_tunnel_id_matches_int_argument(
    settings,
):
    # The PM numbers are strings live (bandwidth-utilization-kbps); a stringified tunnel-id
    # key must still be the requested entry.
    entry = {
        **RSVP_PM["cisco-crosswork-performance-metrics:rsvp-policy-pm"][0],
        "tunnel-id": "7",
    }
    respx.get(f"{RSVP_PM_URL}=10.0.0.1,10.0.0.3,7").mock(
        return_value=ok({"cisco-crosswork-performance-metrics:rsvp-policy-pm": [entry]})
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_rsvp_tunnel_performance_metrics",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "tunnel_id": 7, "response_format": "json"},
    )
    assert json.loads(text) == entry


@respx.mock
async def test_get_sr_policy_performance_metrics_404_with_restconf_document_is_not_not_found(
    settings,
):
    respx.get(f"{SR_POLICY_PM_URL}={PE1_PE2_KEY}").mock(return_value=RESTCONF_404)
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy_performance_metrics",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100},
    )
    assert text.startswith("Error: API request failed with status 404")
    assert "no performance metrics" not in text and "never that the object is missing" in text


# --- cnc_get_te_summary ------------------------------------------------------


@respx.mock
async def test_get_te_summary_counts_the_lab_state(settings):
    policies, p2mp, rsvp = mock_lists()
    text = await call_tool_text(build(settings), "cnc_get_te_summary", {})
    assert policies.call_count == 1 and p2mp.call_count == 1 and rsvp.call_count == 1
    for route in (policies, p2mp, rsvp):
        assert route.calls[0].request.headers["Accept"] == YANG_JSON
    data = json.loads(text)
    assert data["sr_policies"] == {
        "total": 2,
        "up": 2,
        "down": 0,
        "pce_controlled": 2,
        "by_type": {"REGULAR": 2},
        "by_dataplane": {"sr-mpls": 2, "srv6": 0},
        "down_policies": [],
    }
    assert data["p2mp_policies"] == 0 and data["rsvp_te_tunnels"] == 0
    assert data["summary"] == (
        "2 SR policies, all UP (2 PCE-controlled; 2 SR-MPLS, 0 SRv6); 0 P2MP (Tree-SID) "
        "policies; 0 RSVP-TE tunnels."
    )


@respx.mock
async def test_get_te_summary_with_down_policy_and_other_containers(settings):
    down = {**PE2_POLICY, "oper-state": "DOWN"}
    mock_lists(
        policies={
            "cisco-crosswork-segment-routing-policy:sr-policies": {"policy": [PE1_POLICY, down]}
        },
        p2mp=P2MP_POLICIES,
        rsvp=RSVP_TUNNELS,
    )
    data = json.loads(await call_tool_text(build(settings), "cnc_get_te_summary", {}))
    assert data["sr_policies"]["down"] == 1 and data["sr_policies"]["up"] == 1
    assert data["sr_policies"]["down_policies"] == ["10.0.0.3 -> 10.0.0.1 color 100"]
    assert data["p2mp_policies"] == 1 and data["rsvp_te_tunnels"] == 1
    assert data["summary"].startswith(
        "2 SR policies, 1 DOWN (2 PCE-controlled; 2 SR-MPLS, 0 SRv6); 1 P2MP"
    )


@respx.mock
async def test_get_te_summary_counts_srv6_policies_by_dataplane(settings):
    # Spec-shaped: an SRv6 policy (srv6-binding-sid, IPV6-* hops, IPv6 keys) next to the
    # two verified SR-MPLS ones — awaits the underlay for a live confirmation.
    mock_lists(policies=MIXED_POLICIES)
    data = json.loads(await call_tool_text(build(settings), "cnc_get_te_summary", {}))
    assert data["sr_policies"]["total"] == 3
    assert data["sr_policies"]["by_dataplane"] == {"sr-mpls": 2, "srv6": 1}
    assert data["summary"].startswith("3 SR policies, all UP (3 PCE-controlled; 2 SR-MPLS, 1 SRv6)")


@respx.mock
async def test_get_te_summary_all_empty(settings):
    mock_lists(policies=EMPTY)
    data = json.loads(await call_tool_text(build(settings), "cnc_get_te_summary", {}))
    assert data["sr_policies"]["total"] == 0 and data["sr_policies"]["by_type"] == {}
    assert data["sr_policies"]["by_dataplane"] == {"sr-mpls": 0, "srv6": 0}
    assert data["summary"].startswith("no SR policies (0 PCE-controlled; 0 SR-MPLS, 0 SRv6)")


@respx.mock
async def test_get_te_summary_api_error_is_string(make_settings):
    mock_lists()
    respx.get(RSVP_TUNNELS_URL).mock(return_value=UNKNOWN_ELEMENT_400)
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_get_te_summary", {})
    assert text.startswith("Error:") and "400" in text
