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
    entries_matching,
    hop_text,
    hops_text,
    igp_link_pm_url,
    is_invalid_key,
    key_matches,
    matches_policy_filter,
    normalize_oper_state,
    p2mp_policy_url,
    path_hops,
    rsvp_pm_url,
    rsvp_tunnel_url,
    sr_policy_pm_url,
    sr_policy_summary,
    sr_policy_url,
)
from tests.conftest import BASE_URL, call_tool_text

TE_DATA = f"{BASE_URL}/crosswork/nbi/topology/v3/restconf/data"
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
        "headend", "endpoint", "color", "oper_state", "pce_controlled", "response_format"
    }  # fmt: skip
    assert set(tools["cnc_get_sr_policy"].input_schema["required"]) == {
        "headend", "endpoint", "color"
    }  # fmt: skip
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
        "down_policies": ["10.0.0.1 -> 10.0.0.3 color 100"],
    }
    assert sr_policy_summary([])["total"] == 0 and sr_policy_summary([])["by_type"] == {}


# --- cnc_list_sr_policies ----------------------------------------------------


@respx.mock
async def test_list_sr_policies_markdown_url_accept_and_lines(settings):
    route = respx.get(SR_POLICIES_URL).mock(return_value=ok(SR_POLICIES))
    text = await call_tool_text(build(settings), "cnc_list_sr_policies", {})
    request = route.calls[0].request
    assert str(request.url) == SR_POLICIES_URL
    assert request.method == "GET" and request.headers["Accept"] == YANG_JSON
    assert "# SR policies (2 of 2, no filter)" in text
    assert (
        "- **10.0.0.1 -> 10.0.0.3 color 100** admin=UP oper=UP type=REGULAR bsid=24005 "
        "pce-controlled=True pcc=10.0.0.1 | active path: CNC-DYN-100 pref=100 PT-DYNAMIC "
        "metric=IGP-METRIC:20 hops=16003(IPV4-NODE-SID/10.0.0.3) updated=2026-09-13T"
    ) in text
    assert (
        "- **10.0.0.3 -> 10.0.0.1 color 100** admin=UP oper=UP type=REGULAR bsid=24005 "
        "pce-controlled=True pcc=10.0.0.3 | active path: CNC-DYN-100 pref=100 PT-DYNAMIC "
        "metric=IGP-METRIC:20 hops=16001(IPV4-NODE-SID/10.0.0.1) updated="
    ) in text
    assert "TE router-ids" in text and "cnc_get_sr_policy" in text


@respx.mock
async def test_list_sr_policies_json_is_raw_entries(settings):
    respx.get(SR_POLICIES_URL).mock(return_value=ok(SR_POLICIES))
    text = await call_tool_text(
        build(settings), "cnc_list_sr_policies", {"response_format": "json"}
    )
    data = json.loads(text)
    assert data["count"] == 2 and data["total"] == 2
    assert data["items"] == [PE2_POLICY, PE1_POLICY]
    assert data["filter"] == {
        "headend": None, "endpoint": None, "color": None, "oper_state": None, "pce_controlled": None
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
    respx.get(SR_POLICIES_URL).mock(return_value=ok(SR_POLICIES))
    text = await call_tool_text(build(settings), "cnc_list_sr_policies", {"oper_state": "down"})
    assert not text.startswith("Error:")
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
    respx.get(SR_POLICIES_URL).mock(return_value=ok(EMPTY))
    text = await call_tool_text(build(settings), "cnc_list_sr_policies", {})
    assert text.startswith("No SR policies are reported by the SR-PCE feed.")
    assert "report-all" in text and not text.startswith("Error:")
    text = await call_tool_text(
        build(settings), "cnc_list_sr_policies", {"response_format": "json"}
    )
    assert json.loads(text) == {
        "count": 0,
        "total": 0,
        "filter": {
            "headend": None,
            "endpoint": None,
            "color": None,
            "oper_state": None,
            "pce_controlled": None,
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
    text = await call_tool_text(build(settings), "cnc_list_sr_policies", {})
    assert not text.startswith("Error:") and "# SR policies (2 of 2, no filter)" in text
    assert (
        "- **10.0.0.1 -> 10.0.0.3 color 100** admin=UP oper=UP type=REGULAR bsid=- "
        "pce-controlled=None pcc=- | no path reported updated=-"
    ) in text
    assert (
        "- **10.0.0.3 -> 10.0.0.1 color 100** admin=UP oper=UP type=REGULAR bsid=- "
        "pce-controlled=True pcc=- | no path reported updated=-"
    ) in text


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
    assert "- admin-state=UP oper-state=UP type=REGULAR description=-" in text
    assert (
        "- binding-sid=24005 pce-controlled=True pcc-address=10.0.0.1 delegated-pce=- msd=- "
        "updated=2026-09-13T"
    ) in text
    assert "- pcep-info: pcep-flag-c=0" in text
    assert "Paths (1):" in text
    assert ("- **CNC-DYN-100** pref=100 PT-DYNAMIC oper=UP metric=IGP-METRIC:20 computed=-") in text
    assert "  constraints: sid-algorithm=0" in text
    assert "  segment-list 1 (weight 1): 16003(IPV4-NODE-SID/10.0.0.3)" in text


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
async def test_get_sr_policy_hostname_key_400_explains_router_id_rule(settings):
    respx.get(f"{SR_POLICIES_URL}/policy=PE1,PE2,100").mock(return_value=INVALID_VALUE_400)
    text = await call_tool_text(
        build(settings), "cnc_get_sr_policy", {"headend": "PE1", "endpoint": "PE2", "color": 100}
    )
    assert text.startswith("Error:") and "400" in text and "Invalid value 'PE1'" in text
    assert "must be TE router-ids (IP addresses such as 10.0.0.1), not host names" in text
    assert "no SR policy" not in text


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
    assert (
        "- delay-us=20 bandwidth-utilization-kbps=0 delay-telemetry-us=- jitter-telemetry-us=- "
        "liveness=-"
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
async def test_get_sr_policy_performance_metrics_hostname_key_400_explains_rule(settings):
    respx.get(f"{SR_POLICY_PM_URL}=PE1,PE2,100").mock(return_value=INVALID_VALUE_400)
    text = await call_tool_text(
        build(settings),
        "cnc_get_sr_policy_performance_metrics",
        {"headend": "PE1", "endpoint": "PE2", "color": 100},
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
    assert "- delay-us=30 bandwidth-utilization-kbps=12" in text
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
        "down_policies": [],
    }
    assert data["p2mp_policies"] == 0 and data["rsvp_te_tunnels"] == 0
    assert data["summary"] == (
        "2 SR policies, all UP (2 PCE-controlled); 0 P2MP (Tree-SID) policies; 0 RSVP-TE tunnels."
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
    assert data["summary"].startswith("2 SR policies, 1 DOWN (2 PCE-controlled); 1 P2MP")


@respx.mock
async def test_get_te_summary_all_empty(settings):
    mock_lists(policies=EMPTY)
    data = json.loads(await call_tool_text(build(settings), "cnc_get_te_summary", {}))
    assert data["sr_policies"]["total"] == 0 and data["sr_policies"]["by_type"] == {}
    assert data["summary"].startswith("no SR policies (0 PCE-controlled)")


@respx.mock
async def test_get_te_summary_api_error_is_string(make_settings):
    mock_lists()
    respx.get(RSVP_TUNNELS_URL).mock(return_value=UNKNOWN_ELEMENT_400)
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_get_te_summary", {})
    assert text.startswith("Error:") and "400" in text
