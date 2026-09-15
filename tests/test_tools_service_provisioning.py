"""Service provisioning tools end-to-end through MCPServer (schema validation included).

The module is registered directly (not through build_server) so the test does
not depend on tools/__init__.py's module list. All HTTP is mocked with respx.
Fixtures mirror the shapes verified live on Crosswork 7.2's NSO proxy
(2026-09-13, see the platform notes): the ``?dry-run=native`` result, the
``ietf-restconf:errors`` documents for the unknown head-end / referenced SID
list / unknown element / TSDN validation / out-of-sync / keypath-not-found
cases, the nano plan, and the verified PUT / PATCH bodies. The SRv6 shapes
(2026-09-15) were verified in ``?dry-run=native`` only — the lab has no SRv6
underlay yet — through the tools themselves: the ``srv6`` bodies, the CLI
they render and the CFPs' SRv6 refusals, verbatim.
"""

from __future__ import annotations

import ast
import inspect
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
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import service_provisioning
from cnc_mcp.tools.service_provisioning import (
    ServiceTarget,
    build_l3vpn_body,
    build_odn_template_body,
    build_sr_policy_body,
    dry_run_devices,
    explain_write_failure,
    generic_kind,
    key_of,
    list_identity,
    locator_name,
    normalize_yang_path,
    parse_endpoints,
    parse_labels,
    plan_layer_note,
    plan_line,
    plan_path_of,
    require_ip,
    resolve_type_path,
    summarize_plan,
    validate_service_body,
)
from tests.conftest import BASE_URL, call_tool_text

YANG_JSON = "application/yang-data+json"
DATA = f"{BASE_URL}/crosswork/proxy/nso/restconf/data"
SR_TE = f"{DATA}/cisco-sr-te-cfp:sr-te"
# The verified PUT paths carry the module prefix on the list segment; the plan paths do not
# (CAT's ``plan-yang-path`` spelling, and the form the verified proxy plan GETs used).
ODN_TEMPLATES = f"{SR_TE}/cisco-sr-te-cfp-sr-odn:odn/cisco-sr-te-cfp-sr-odn:odn-template"
ODN_PLANS = f"{SR_TE}/cisco-sr-te-cfp-sr-odn:odn/odn-template-plan"
POLICIES = f"{SR_TE}/cisco-sr-te-cfp-sr-policies:policies"
POLICY = f"{POLICIES}/cisco-sr-te-cfp-sr-policies:policy"
POLICY_PLAN = f"{POLICIES}/policy-plan"
SID_LIST = f"{POLICIES}/cisco-sr-te-cfp-sr-policies:sid-list"
SID_LIST_PLAN = f"{POLICIES}/sid-list-plan"
L3VPN = f"{DATA}/ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service"
L3VPN_PLAN = f"{DATA}/ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service-plan"
L2VPN = f"{DATA}/ietf-l2vpn-ntw:l2vpn-ntw/vpn-services/vpn-service"
CS_POLICY = f"{DATA}/cisco-cs-sr-te-cfp:cs-sr-te-policy"
CS_POLICY_PLAN = f"{DATA}/cisco-cs-sr-te-cfp:cs-sr-te-policy-plan"
CONNECTOR = f"{BASE_URL}/crosswork/cat/nso-connector/v1/api"

# --- verified wire shapes --------------------------------------------------------------

# PUT ...?dry-run=native -> 201 with the CLI NSO would push (DELETE -> 200, ``no`` lines).
POLICY_CLI = (
    "segment-routing\n traffic-eng\n  policy srte_c_91_ep_10.0.0.3\n   color 91 end-point "
    "ipv4 10.0.0.3\n   candidate-paths\n    preference 100\n     dynamic\n      pce\n      !\n"
    "      metric\n       type igp\n      !\n     !\n    !\n   !\n  !\n !\n!\n"
)
DRY_RUN_CREATE = {"dry-run-result": {"native": {"device": [{"name": "PE1", "data": POLICY_CLI}]}}}
# An ODN template renders ``on-demand color <color>`` (not a ``policy`` block).
ODN_CLI = (
    "segment-routing\n traffic-eng\n  on-demand color 90\n   dynamic\n    pce\n    !\n"
    "    metric\n     type igp\n    !\n   !\n  !\n !\n!\n"
)
DRY_RUN_ODN = {"dry-run-result": {"native": {"device": [{"name": "PE1", "data": ODN_CLI}]}}}
DRY_RUN_DELETE = {
    "dry-run-result": {
        "native": {
            "device": [
                {
                    "name": "PE1",
                    "data": "segment-routing\n traffic-eng\n  no policy srte_c_91_ep_10.0.0.3\n",
                }
            ]
        }
    }
}
DRY_RUN_NO_CHANGE = {"dry-run-result": {"native": {"device": []}}}

# --- SRv6 (every shape below verified 2026-09-15 in ?dry-run=native through the tools
# themselves; the lab has no SRv6 underlay, so these are CFP validation + NED rendering) ---

# The SRv6 test services carry the color / tail-end the live dry runs used, so each CLI
# fixture below is paired with a request that actually produced it (policy color 600 on
# tail-end 2001:db8::3, ODN color 601 on PE1+PE2).
SRV6_POLICY_NAME = "mcp-pol-600"
SRV6_ODN_NAME = "mcp-odn-601"
# cnc_create_sr_policy_service(tail_end='2001:db8::3', color=600, srv6_locator='LOC1').
SRV6_POLICY_CLI = (
    "segment-routing\n traffic-eng\n  policy srte_c_600_ep_2001:db8::3\n   srv6\n"
    "    locator LOC1 binding-sid dynamic behavior ub6-insert-reduced\n   !\n"
    "   color 600 end-point ipv6 2001:db8::3\n   candidate-paths\n    preference 100\n"
    "     dynamic\n      pce\n      !\n      metric\n       type igp\n      !\n     !\n    !\n"
    "   !\n  !\n !\n!\n"
)
DRY_RUN_SRV6_POLICY = {
    "dry-run-result": {"native": {"device": [{"name": "PE1", "data": SRV6_POLICY_CLI}]}}
}
# cnc_create_odn_template(color=601, head_ends='PE1,PE2', srv6_locator='LOC1') — both PEs.
SRV6_ODN_CLI = (
    "segment-routing\n traffic-eng\n  on-demand color 601\n   srv6\n"
    "    locator LOC1 binding-sid dynamic behavior ub6-insert-reduced\n   exit\n   dynamic\n"
    "    pce\n    exit\n    metric\n     type igp\n    exit\n   exit\n  exit\n !\n!\n"
)
DRY_RUN_SRV6_ODN = {
    "dry-run-result": {
        "native": {
            "device": [
                {"name": "PE1", "data": SRV6_ODN_CLI},
                {"name": "PE2", "data": SRV6_ODN_CLI},
            ]
        }
    }
}
# cnc_create_l3vpn_service(srv6_locator='LOC1') on PE1 — the MPLS rendering plus the one
# ``segment-routing srv6`` block under the BGP VRF address-family.
SRV6_L3VPN_CLI = (
    "vrf mcp-l3vpn-1\n address-family ipv4 unicast\n  import route-target\n   1:1\n"
    "   65091:91\n  exit\n  export route-target\n   1:1\n   65091:91\n  exit\n exit\nexit\n"
    "interface Loopback 91\n description T-SDN Interface\n vrf mcp-l3vpn-1\n"
    " ipv4 address 10.91.1.1 255.255.255.252\n no shutdown\nexit\nrouter bgp 65000\n"
    " vrf mcp-l3vpn-1\n  rd 65091:91\n  address-family ipv4 unicast\n   segment-routing srv6\n"
    "    locator LOC1\n    alloc mode per-vrf\n   exit\n  exit\n exit\nexit\n"
)
DRY_RUN_SRV6_L3VPN = {
    "dry-run-result": {"native": {"device": [{"name": "PE1", "data": SRV6_L3VPN_CLI}]}}
}
SRV6_BLOCK = {"locator": {"locator-name": "LOC1"}}
L3VPN_SRV6_BLOCK = {"address-family": [{"name": "ietf-vpn-common:ipv4", "locator-name": "LOC1"}]}


def restconf_error(status: int, tag: str, message: str, path: str | None = None) -> httpx.Response:
    entry: dict[str, Any] = {
        "error-type": "application",
        "error-tag": tag,
        "error-message": message,
    }
    if path:
        entry["error-path"] = path
    return httpx.Response(status, json={"ietf-restconf:errors": {"error": [entry]}})


# 400 invalid-value "illegal reference .../head-end{NOPE}/name" — the head-end is not an NSO device.
BAD_HEAD_END = restconf_error(
    400,
    "invalid-value",
    "illegal reference /cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/"
    "policy{mcp-pol-91}/head-end{NOPE}/name",
)
# The L3NM equivalent: the deviated model makes vpn-node-id a leafref into NSO's dispatch-map,
# so an unknown PE is an illegal reference ending in ``vpn-node{X}/vpn-node-id``.
BAD_VPN_NODE = restconf_error(
    400,
    "invalid-value",
    "illegal reference /ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service{mcp-l3vpn-1}/"
    "vpn-nodes/vpn-node{NOPE}/vpn-node-id",
)
# 400 invalid-value "illegal reference .../explicit/sid-list{mcp-sl-1}/name" — a policy still
# references the SID list (on DELETE) / the SID list does not exist (on PUT).
SID_LIST_REFERENCED = restconf_error(
    400,
    "invalid-value",
    "illegal reference /cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/"
    "policy{mcp-pol-93}/path{100}/explicit/sid-list{mcp-sl-1}/name",
)
# 400 unknown-element "unknown element: bogus in ..." — the body has a node the model lacks.
UNKNOWN_ELEMENT = restconf_error(
    400,
    "unknown-element",
    "unknown element: bogus in /cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/"
    "policy{mcp-pol-91}",
)
# 400 malformed-message with the multi-line CFP validation verdict.
TSDN_415 = restconf_error(
    400,
    "malformed-message",
    "STATUS_CODE: TSDN-L3VPN-415\nREASON: BGP routing process is not configured on the device\n"
    "CATEGORY: validation",
)
# 502 operation-failed — the head-end is out of sync with NSO's CDB.
OUT_OF_SYNC = restconf_error(
    502, "operation-failed", "Network Element Driver: device PE1: out of sync"
)
# 404 with a RESTCONF error document — the one 404 that means "not found" on this gateway.
NOT_FOUND = restconf_error(404, "invalid-value", "uri keypath not found")
# The verified PATCH 404: a PATCH never creates.
PATCH_NONEXISTENT = restconf_error(
    404,
    "invalid-value",
    "patch to a nonexistent resource",
    "/cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/policy[name='mcp-pol-91']",
)
# The SR-TE CFP's SRv6 refusals, verbatim (2026-09-15, dry run). The two ``must`` rules
# pairing an IPv6 tail-end / source-address with the srv6 container are 400 invalid-value;
# the ``when "not(../srv6)"`` leaves and the mandatory locator-name are 400 malformed-message.
# Every live document carried error-path ``<list>[name='<key>']`` beside the error-message
# ``<list>{<key>}...`` (the scout appendix), so the fixtures do too.
_POLICY_LIST = "/cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/policy"
_ODN_LIST = "/cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/odn-template"
_L3VPN_LIST = "/ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service"


def policy_cfp_error(tag: str, rest: str, name: str = SRV6_POLICY_NAME) -> httpx.Response:
    """A verified SR-TE CFP verdict on ``policy{name}``: 400 with the message ``<list>{name}
    <rest>`` and the error-path ``<list>[name='<name>']`` the live documents carry."""
    return restconf_error(
        400, tag, f"{_POLICY_LIST}{{{name}}}{rest}", f"{_POLICY_LIST}[name='{name}']"
    )


def odn_cfp_error(tag: str, rest: str, name: str = SRV6_ODN_NAME) -> httpx.Response:
    """The ODN-template counterpart of :func:`policy_cfp_error`."""
    return restconf_error(400, tag, f"{_ODN_LIST}{{{name}}}{rest}", f"{_ODN_LIST}[name='{name}']")


SRV6_NEEDS_IPV6_TAIL = policy_cfp_error(
    "invalid-value", " : tail-end must be IPv6 address for SRv6 TE policy"
)
SRV6_REQUIRED_BY_TAIL = policy_cfp_error(
    "invalid-value", " : SRv6 TE policy must be configured if tail-end is IPv6 address"
)
SRV6_REQUIRED_BY_SOURCE = odn_cfp_error(
    "invalid-value", " : SRv6 TE policy must be configured if source-address is IPv6 address"
)
SRV6_WHEN_BINDING_SID = policy_cfp_error(
    "malformed-message", "/binding-sid: the 'when' expression \"not(../srv6)\" failed"
)
SRV6_WHEN_BANDWIDTH = policy_cfp_error(
    "malformed-message", "/bandwidth: the 'when' expression \"not(../srv6)\" failed"
)
SRV6_WHEN_ODN_BANDWIDTH = odn_cfp_error(
    "malformed-message", "/bandwidth: the 'when' expression \"not(../srv6)\" failed"
)
SRV6_WHEN_EXPLICIT = policy_cfp_error(
    "malformed-message", "/path{100}/explicit: the 'when' expression \"not(../srv6)\" failed"
)
SRV6_LOCATOR_NO_NAME = policy_cfp_error(
    "malformed-message", "/srv6/locator/locator-name is not configured"
)
# The L3NM's ``min-elements 1`` on the srv6 address-family list (an empty srv6 container).
L3NM_SRV6_EMPTY = restconf_error(
    400,
    "malformed-message",
    "too few /l3vpn-ntw/vpn-services/vpn-service{mcp-l3vpn-1}/vpn-instance-profiles/"
    "vpn-instance-profile{p1}/cisco-l3nm:srv6/address-family, 0 configured, at least 1 must "
    "be configured",
    f"{_L3VPN_LIST}[vpn-id='mcp-l3vpn-1']",
)
# The SR-TE-style flat locator-name on the L3NM — an ordinary unknown-element.
L3NM_SRV6_FLAT = restconf_error(
    400,
    "unknown-element",
    "unknown element: locator-name in /l3nm:l3vpn-ntw/l3nm:vpn-services/l3nm:vpn-service"
    "[l3nm:vpn-id='mcp-l3vpn-1']/l3nm:vpn-instance-profiles/l3nm:vpn-instance-profile"
    "[l3nm:profile-id='p1']/cisco-l3nm:srv6/cisco-l3nm:locator-name",
    f"{_L3VPN_LIST}[vpn-id='mcp-l3vpn-1']",
)
# The proxy's answer to a body that is not application/yang-data+json.
PROXY_415 = restconf_error(415, "malformed-message", "Unsupported media type: application/json")
# Some other RESTCONF failure without a dedicated text.
ACCESS_DENIED = restconf_error(403, "access-denied", "access denied")
NATS_500 = httpx.Response(500, json={"error": "NATS request failed"})
CREATED = httpx.Response(201)
NO_CONTENT = httpx.Response(204)


def nano_plan(list_key: str, name: str, head_end_states: list[tuple[str, str]]) -> dict:
    """The verified nano-plan GET body: a self component plus one head-end component."""
    return {
        list_key: [
            {
                "name": name,
                "plan": {
                    "component": [
                        {
                            "type": "tailf-ncs:self",
                            "name": "self",
                            "state": [
                                {"name": "tailf-ncs:init", "status": "reached", "when": "t1"},
                                {"name": "tailf-ncs:ready", "status": "reached", "when": "t2"},
                            ],
                            "back-track": False,
                        },
                        {
                            "type": ("cisco-sr-te-cfp-sr-policies-nano-plan-services:head-end"),
                            "name": "PE1",
                            "state": [
                                {
                                    "name": f"tailf-ncs:{s}"
                                    if s in ("init", "ready")
                                    else (f"cisco-sr-te-cfp-sr-policies-nano-plan-services:{s}"),
                                    "status": status,
                                    "when": "t",
                                }
                                for s, status in head_end_states
                            ],
                            "back-track": False,
                        },
                    ]
                },
            }
        ]
    }


READY_STATES = [("init", "reached"), ("config-apply", "reached"), ("ready", "reached")]
FAILED_STATES = [("init", "reached"), ("config-apply", "failed"), ("ready", "not-reached")]
POLICY_PLAN_READY = nano_plan("cisco-sr-te-cfp-sr-policies:policy-plan", "mcp-pol-91", READY_STATES)
POLICY_PLAN_FAILED = nano_plan(
    "cisco-sr-te-cfp-sr-policies:policy-plan", "mcp-pol-91", FAILED_STATES
)
ODN_PLAN_READY = nano_plan("cisco-sr-te-cfp-sr-odn:odn-template-plan", "mcp-odn-90", READY_STATES)
L3VPN_PLAN_READY = nano_plan("ietf-l3vpn-ntw:vpn-service-plan", "mcp-l3vpn-1", READY_STATES)
SRV6_POLICY_PLAN_READY = nano_plan(
    "cisco-sr-te-cfp-sr-policies:policy-plan", SRV6_POLICY_NAME, READY_STATES
)
SRV6_ODN_PLAN_READY = nano_plan(
    "cisco-sr-te-cfp-sr-odn:odn-template-plan", SRV6_ODN_NAME, READY_STATES
)

# Verified PUT bodies.
ODN_BODY = {
    "cisco-sr-te-cfp-sr-odn:odn-template": [
        {
            "name": "mcp-odn-90",
            "color": 90,
            "head-end": [{"name": "PE1"}],
            "dynamic": {"metric-type": "igp", "pce": {}},
        }
    ]
}
POLICY_BODY = {
    "cisco-sr-te-cfp-sr-policies:policy": [
        {
            "name": "mcp-pol-91",
            "head-end": [{"name": "PE1"}],
            "tail-end": "10.0.0.3",
            "color": 91,
            "path": [{"preference": 100, "dynamic": {"metric-type": "igp", "pce": {}}}],
        }
    ]
}
EXPLICIT_POLICY_BODY = {
    "cisco-sr-te-cfp-sr-policies:policy": [
        {
            "name": "mcp-pol-93",
            "head-end": [{"name": "PE1"}],
            "tail-end": "10.0.0.3",
            "color": 93,
            "path": [{"preference": 100, "explicit": {"sid-list": [{"name": "mcp-sl-1"}]}}],
        }
    ]
}
PATCH_BODY = {"cisco-sr-te-cfp-sr-policies:policy": [{"name": "mcp-pol-91", "bandwidth": 1000}]}
SID_LIST_BODY = {
    "cisco-sr-te-cfp-sr-policies:sid-list": [
        {
            "name": "mcp-sl-1",
            "sid": [{"index": 1, "mpls": {"label": 16003}}, {"index": 2, "mpls": {"label": 16002}}],
        }
    ]
}
L3VPN_ENDPOINTS = [
    {
        "node": "PE1",
        "interface": "Loopback91",
        "address": "10.91.1.1",
        "prefix_length": 30,
        "local_as": 65000,
    }
]
L3VPN_BODY = {
    "ietf-l3vpn-ntw:vpn-service": [
        {
            "vpn-id": "mcp-l3vpn-1",
            "vpn-service-topology": "ietf-vpn-common:any-to-any",
            "vpn-instance-profiles": {
                "vpn-instance-profile": [
                    {
                        "profile-id": "p1",
                        "rd": "0:65091:91",
                        "address-family": [
                            {
                                "address-family": "ietf-vpn-common:ipv4",
                                "vpn-targets": {
                                    "vpn-target": [
                                        {
                                            "id": 1,
                                            "route-targets": [{"route-target": "0:65091:91"}],
                                            "route-target-type": "both",
                                        }
                                    ]
                                },
                            }
                        ],
                    }
                ]
            },
            "vpn-nodes": {
                "vpn-node": [
                    {
                        "vpn-node-id": "PE1",
                        "local-as": 65000,
                        "active-vpn-instance-profiles": {
                            "vpn-instance-profile": [{"profile-id": "p1"}]
                        },
                        "vpn-network-accesses": {
                            "vpn-network-access": [
                                {
                                    "id": "1",
                                    "interface-id": "Loopback91",
                                    "ip-connection": {
                                        "ipv4": {"local-address": "10.91.1.1", "prefix-length": 30}
                                    },
                                }
                            ]
                        },
                    }
                ]
            },
        }
    ]
}
CS_BODY = {"cisco-cs-sr-te-cfp:cs-sr-te-policy": [{"name": "mcp-cs-1", "color": 200}]}

# The documented (unverified) NSO-connector reply.
RESYNC_OK = {
    "syncResponse": {
        "syncDescription": "Succeeded, full sync was executed in the background",
        "syncStatus": "SUCCESS",
    },
    "status": "OK",
}

ODN_ARGS = {"name": "mcp-odn-90", "color": 90, "head_ends": "PE1"}
POLICY_ARGS = {"name": "mcp-pol-91", "head_end": "PE1", "tail_end": "10.0.0.3", "color": 91}
L3VPN_ARGS = {
    "vpn_id": "mcp-l3vpn-1",
    "route_distinguisher": "0:65091:91",
    "route_target": "0:65091:91",
    "endpoints": json.dumps(L3VPN_ENDPOINTS),
}
# The SRv6 forms: an IPv6 tail-end plus the locator (policy), the locator alone (ODN, L3VPN) —
# the very requests the live dry runs behind SRV6_POLICY_CLI / SRV6_ODN_CLI were made with.
SRV6_POLICY_ARGS = {
    "name": SRV6_POLICY_NAME,
    "head_end": "PE1",
    "tail_end": "2001:db8::3",
    "color": 600,
    "srv6_locator": "LOC1",
}
SRV6_POLICY_URL = f"{POLICY}={SRV6_POLICY_NAME}"
SRV6_POLICY_PLAN_URL = f"{POLICY_PLAN}={SRV6_POLICY_NAME}"
SRV6_POLICY_BODY = {
    "cisco-sr-te-cfp-sr-policies:policy": [
        {
            "name": SRV6_POLICY_NAME,
            "head-end": [{"name": "PE1"}],
            "tail-end": "2001:db8::3",
            "color": 600,
            "path": [{"preference": 100, "dynamic": {"metric-type": "igp", "pce": {}}}],
            "srv6": SRV6_BLOCK,
        }
    ]
}
SRV6_ODN_ARGS = {
    "name": SRV6_ODN_NAME,
    "color": 601,
    "head_ends": "PE1,PE2",
    "srv6_locator": "LOC1",
}
SRV6_ODN_URL = f"{ODN_TEMPLATES}={SRV6_ODN_NAME}"
SRV6_ODN_PLAN_URL = f"{ODN_PLANS}={SRV6_ODN_NAME}"
SRV6_ODN_BODY = {
    "cisco-sr-te-cfp-sr-odn:odn-template": [
        {
            "name": SRV6_ODN_NAME,
            "color": 601,
            "head-end": [{"name": "PE1"}, {"name": "PE2"}],
            "dynamic": {"metric-type": "igp", "pce": {}},
            "srv6": SRV6_BLOCK,
        }
    ]
}
SRV6_L3VPN_ARGS = {**L3VPN_ARGS, "srv6_locator": "LOC1"}

WRITE_TOOLS = {
    "cnc_create_odn_template",
    "cnc_delete_odn_template",
    "cnc_create_sr_policy_service",
    "cnc_update_sr_policy_service",
    "cnc_delete_sr_policy_service",
    "cnc_create_sid_list",
    "cnc_delete_sid_list",
    "cnc_create_l3vpn_service",
    "cnc_delete_vpn_service",
    "cnc_provision_service",
    "cnc_delete_service",
    "cnc_resync_service_inventory",
}
# Deletes, plus every PUT-based tool: a PUT of an existing name replaces the entry wholesale
# (the verified 204), which CLAUDE.md classes as an overwrite. The PATCH tool merges and the
# resync rewrites only Crosswork's inventory: neither is destructive.
DESTRUCTIVE_TOOLS = {
    "cnc_delete_odn_template",
    "cnc_delete_sr_policy_service",
    "cnc_delete_sid_list",
    "cnc_delete_vpn_service",
    "cnc_delete_service",
    "cnc_create_odn_template",
    "cnc_create_sr_policy_service",
    "cnc_create_sid_list",
    "cnc_create_l3vpn_service",
    "cnc_provision_service",
}


def build(settings: Settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    service_provisioning.register(mcp, ctx)
    return mcp


@pytest.fixture
def writes(make_settings) -> MCPServer:
    """Writes enabled, no retries: a 5xx answer is the answer."""
    return build(make_settings(enable_writes=True, max_retries=0))


@pytest.fixture
def writes_retrying(make_settings) -> MCPServer:
    return build(make_settings(enable_writes=True, max_retries=3))


def sent(route: respx.Route, index: int = -1) -> dict:
    """The JSON body of the route's last (by default) request — respx hands back the same
    route object when a URL is mocked again, so its calls accumulate across re-mocks."""
    return json.loads(route.calls[index].request.content)


def request_of(route: respx.Route, index: int = -1) -> httpx.Request:
    return route.calls[index].request


def assert_yang_write(route: respx.Route, method: str, *, dry_run: bool = False) -> None:
    request = request_of(route)
    assert request.method == method
    assert request.headers["Content-Type"] == YANG_JSON
    assert request.headers["Accept"] == YANG_JSON
    assert dict(request.url.params) == ({"dry-run": "native"} if dry_run else {})


def assert_yang_delete(route: respx.Route, *, dry_run: bool = False) -> None:
    request = request_of(route)
    assert request.method == "DELETE"
    assert request.headers["Accept"] == YANG_JSON
    assert "Content-Type" not in request.headers
    assert not request.content
    assert dict(request.url.params) == ({"dry-run": "native"} if dry_run else {})


# --- registration / gating ------------------------------------------------------------


async def test_every_tool_is_a_write_hidden_unless_enabled(make_settings):
    names = {t.name for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert names == set()
    names = {t.name for t in await build(make_settings(enable_writes=True)).list_tools()}
    assert names == WRITE_TOOLS


async def test_annotations(make_settings):
    tools = {t.name: t for t in await build(make_settings(enable_writes=True)).list_tools()}
    for name in WRITE_TOOLS:
        assert tools[name].annotations.read_only_hint is False, name
        assert tools[name].annotations.idempotent_hint is True, name
        assert tools[name].annotations.destructive_hint is (name in DESTRUCTIVE_TOOLS), name


def test_no_write_opts_into_retries():
    """PUT/DELETE keep the client's idempotent default, PATCH/POST are sent once: no call in
    the module may pass retryable=True (checked on the AST, not the text)."""
    tree = ast.parse(inspect.getsource(service_provisioning))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "retryable":
                    assert not (isinstance(kw.value, ast.Constant) and kw.value.value is True)


async def test_every_write_tool_has_dry_run_except_resync(make_settings):
    tools = {t.name: t for t in await build(make_settings(enable_writes=True)).list_tools()}
    for name in WRITE_TOOLS - {"cnc_resync_service_inventory"}:
        props = tools[name].input_schema["properties"]
        assert props["dry_run"]["default"] is False, name
        assert "dry-run" in props["dry_run"]["description"], name
    assert "dry_run" not in tools["cnc_resync_service_inventory"].input_schema["properties"]


async def test_flat_schema_examples(make_settings):
    tools = {t.name: t for t in await build(make_settings(enable_writes=True)).list_tools()}
    props = tools["cnc_create_sr_policy_service"].input_schema["properties"]
    assert "10.0.0.3" in props["tail_end"]["description"]
    assert props["color"]["minimum"] == 1 and props["color"]["maximum"] == 4294967295
    assert "$ref" not in json.dumps(tools["cnc_create_l3vpn_service"].input_schema)


async def test_srv6_locator_schema_on_the_three_creates(make_settings):
    """srv6_locator is a flat, optional, typed string on the policy, ODN and L3VPN creates
    (default blank = SR-MPLS / MPLS), with the locator example in its description; the
    L3VPN endpoints description names the per-node key."""
    tools = {t.name: t for t in await build(make_settings(enable_writes=True)).list_tools()}
    for name in (
        "cnc_create_sr_policy_service",
        "cnc_create_odn_template",
        "cnc_create_l3vpn_service",
    ):
        props = tools[name].input_schema["properties"]
        assert props["srv6_locator"]["default"] == "", name
        assert props["srv6_locator"]["maxLength"] == 64, name
        assert "LOC1" in props["srv6_locator"]["description"], name
        assert "srv6_locator" not in tools[name].input_schema.get("required", []), name
    policy = tools["cnc_create_sr_policy_service"].input_schema["properties"]
    assert "2001:db8::3" in policy["tail_end"]["description"]
    assert "IPv6 tail_end" in policy["srv6_locator"]["description"]
    assert "SR-MPLS only" in policy["binding_sid"]["description"]
    l3vpn = tools["cnc_create_l3vpn_service"].input_schema["properties"]
    assert '"srv6_locator": "LOC1"' in l3vpn["endpoints"]["description"]
    assert "srv6_locator" not in tools["cnc_update_sr_policy_service"].input_schema["properties"]
    assert "'2001:DB8:0:0::3' becomes '2001:db8::3'" in policy["tail_end"]["description"]


async def test_srv6_docstrings_say_what_was_not_verified(make_settings):
    """The tool descriptions keep the unverified facts marked as such: auto-route's when-rule
    was never exercised (no tool sends it), the SR-MPLS -> SRv6 conversion by PATCH was not
    tested, and the bare ``"srv6": {}`` form is dry-run rendered only (device behaviour not)."""
    tools = {t.name: t for t in await build(make_settings(enable_writes=True)).list_tools()}

    def flat(name: str) -> str:
        return " ".join(tools[name].description.split())

    policy = flat("cnc_create_sr_policy_service")
    assert (
        "the YANG puts the same when-rule on ``auto-route``, not exercised — no tool sends it"
        in policy
    )
    assert "converts a committed SR-MPLS policy was NOT tested" in policy
    assert (
        'bare presence form ``"srv6": {}``' in policy and "device behaviour not verified" in policy
    )
    assert "'2001:DB8:0:0::3' -> 2001:db8::3, dry-run verified" in policy.replace("``", "")
    odn = flat("cnc_create_odn_template")
    assert 'bare presence form ``"srv6": {}``' in odn and "cnc_provision_service" in odn
    update = flat("cnc_update_sr_policy_service")
    assert "it cannot add ``srv6`` or change the tail-end" in update
    assert "was NOT tested" in update and "not a merge at all" not in update
    assert (
        'a PATCH never creates — ``404 invalid-value "patch to a nonexistent resource"``' in update
    )


# --- pure helpers ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "given, expected",
    [
        (
            "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=x",
            "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=x",
        ),
        (
            "/ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=x/",
            "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=x",
        ),
        ("data/cisco-cs-sr-te-cfp:cs-sr-te-policy=a", "cisco-cs-sr-te-cfp:cs-sr-te-policy=a"),
        (
            "/restconf/data/cisco-cs-sr-te-cfp:cs-sr-te-policy=a",
            "cisco-cs-sr-te-cfp:cs-sr-te-policy=a",
        ),
        (
            "/crosswork/proxy/nso/restconf/data/cisco-cs-sr-te-cfp:cs-sr-te-policy=a",
            "cisco-cs-sr-te-cfp:cs-sr-te-policy=a",
        ),
        ("  cisco-cs-sr-te-cfp:cs-sr-te-policy=a%2Fb ", "cisco-cs-sr-te-cfp:cs-sr-te-policy=a%2Fb"),
    ],
)
def test_normalize_yang_path(given, expected):
    assert normalize_yang_path(given) == expected


@pytest.mark.parametrize("bad", ["", "/", "data/", "a:b=c?dry-run=native", "a:b=c d", "a:b#x"])
def test_normalize_yang_path_refuses(bad):
    with pytest.raises(PlatformError):
        normalize_yang_path(bad)


def test_plan_path_rule():
    # The verified PUT paths repeat the module prefix on the list segment; the plan path drops
    # it — CAT's plan-yang-path spelling, and the form the verified proxy plan GETs used.
    odn = "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn"
    assert plan_path_of(f"{odn}/cisco-sr-te-cfp-sr-odn:odn-template=n") == (
        f"{odn}/odn-template-plan=n"
    )
    policies = "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies"
    assert plan_path_of(f"{policies}/cisco-sr-te-cfp-sr-policies:policy=n") == (
        f"{policies}/policy-plan=n"
    )
    assert plan_path_of(f"{policies}/cisco-sr-te-cfp-sr-policies:sid-list=n") == (
        f"{policies}/sid-list-plan=n"
    )
    # A prefix that differs from the parent's module (an augmenting module) is kept.
    assert plan_path_of("cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/x:odn-template=n") == (
        "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/x:odn-template-plan=n"
    )
    assert plan_path_of("ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=mcp") == (
        "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service-plan=mcp"
    )
    # A single-segment (top-level) list keeps its prefix: there is no ancestor to inherit from.
    assert plan_path_of("cisco-cs-sr-te-cfp:cs-sr-te-policy=a%2Fb") == (
        "cisco-cs-sr-te-cfp:cs-sr-te-policy-plan=a%2Fb"
    )
    assert plan_path_of("ietf-l3vpn-ntw:l3vpn-ntw/vpn-services") is None


def test_list_identity_and_key():
    assert list_identity("ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=x") == (
        "ietf-l3vpn-ntw",
        "vpn-service",
    )
    assert list_identity("cisco-sr-te-cfp:sr-te/m:policies/m:policy=x") == ("m", "policy")
    assert list_identity("plain/path=x") == ("", "path")
    assert key_of("a:b/c=odd%20name%2F1") == "odd name/1"
    assert key_of("a:b/c") is None
    assert generic_kind("ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=x") == "vpn-service"
    assert generic_kind("ietf-network-slice-service:network-slice-services/slice-service=x") == (
        "slice-service"
    )
    assert generic_kind("cisco-cs-sr-te-cfp:cs-sr-te-policy=x") == "cs-sr-te-policy service"


def test_parse_labels():
    assert parse_labels("16003, 16002,") == [16003, 16002]
    with pytest.raises(PlatformError, match="not an MPLS label"):
        parse_labels("16003,abc")
    with pytest.raises(PlatformError, match="outside the MPLS label range"):
        parse_labels("1048576")
    with pytest.raises(PlatformError, match="labels is empty"):
        parse_labels(" , ")


def test_parse_endpoints_accepts_a_single_object_and_defaults():
    [ep] = parse_endpoints(
        '{"node": "PE1", "interface": "Gi0/0/0/1.91", "address": "10.91.1.1", '
        '"prefix_length": "30"}'
    )
    assert ep == {
        "node": "PE1",
        "interface": "Gi0/0/0/1.91",
        "address": "10.91.1.1",
        "prefix_length": 30,
    }


@pytest.mark.parametrize(
    "text, fragment",
    [
        ("nope", "not valid JSON"),
        ("[]", "non-empty JSON list"),
        ("[1]", "endpoints[1] is not an object"),
        (
            '[{"node": "PE1", "interface": "Lo1", "address": "10.0.0.1"}]',
            "missing required key(s) prefix_length",
        ),
        (
            '[{"node": "PE1", "interface": "Lo1", "address": "10.0.0.1", "prefix-length": 30}]',
            "unknown key(s) prefix-length",
        ),
        (
            '[{"node": "PE1", "interface": "Lo1", "address": "PE1", "prefix_length": 30}]',
            "address 'PE1' is not an IPv4 address",
        ),
        (
            '[{"node": "PE1", "interface": "Lo1", "address": "10.0.0.1", "prefix_length": 33}]',
            "prefix_length 33 is outside 0..32",
        ),
        (
            '[{"node": "PE1", "interface": "Lo1", "address": "10.0.0.1", "prefix_length": 30, '
            '"local_as": "x"}]',
            "local_as 'x' must be an integer",
        ),
    ],
)
def test_parse_endpoints_refusals_name_the_key(text, fragment):
    with pytest.raises(PlatformError) as exc:
        parse_endpoints(text)
    assert fragment in str(exc.value)


def test_l3vpn_body_merges_endpoints_on_the_same_node():
    body = build_l3vpn_body(
        "v",
        "0:1:1",
        "0:1:1",
        [
            {"node": "PE1", "interface": "Lo1", "address": "10.1.1.1", "prefix_length": 30},
            {
                "node": "PE2",
                "interface": "Lo1",
                "address": "10.1.1.5",
                "prefix_length": 30,
                "id": "a",
            },
            {"node": "PE1", "interface": "Lo2", "address": "10.1.1.9", "prefix_length": 30},
        ],
        "hub-spoke",
        "p1",
    )
    service = body["ietf-l3vpn-ntw:vpn-service"][0]
    assert service["vpn-service-topology"] == "ietf-vpn-common:hub-spoke"
    nodes = service["vpn-nodes"]["vpn-node"]
    assert [n["vpn-node-id"] for n in nodes] == ["PE1", "PE2"]
    assert "local-as" not in nodes[0]
    accesses = nodes[0]["vpn-network-accesses"]["vpn-network-access"]
    assert [a["id"] for a in accesses] == ["1", "2"]
    assert nodes[1]["vpn-network-accesses"]["vpn-network-access"][0]["id"] == "a"


def test_l3vpn_body_refuses_conflicting_local_as():
    with pytest.raises(PlatformError, match="different local_as"):
        build_l3vpn_body(
            "v",
            "0:1:1",
            "0:1:1",
            [
                {
                    "node": "PE1",
                    "interface": "Lo1",
                    "address": "10.1.1.1",
                    "prefix_length": 30,
                    "local_as": 1,
                },
                {
                    "node": "PE1",
                    "interface": "Lo2",
                    "address": "10.1.1.5",
                    "prefix_length": 30,
                    "local_as": 2,
                },
            ],
            "any-to-any",
            "p1",
        )


# --- SRv6 helpers (dry-run verified shapes; see the module docstring) ---


def test_require_ip_canonicalises_ipv6_and_refuses_zone_ids():
    """IPv4 passes through as given; IPv6 comes back lowercase and compressed — the spelling
    NSO renders into ``srte_c_<color>_ep_<tail-end>`` (dry-run verified); a zone id, which
    ipaddress would accept, is refused before anything is sent."""
    assert require_ip(" 10.0.0.3 ", "tail_end") == "10.0.0.3"
    assert require_ip("2001:DB8:0:0::3", "tail_end") == "2001:db8::3"
    assert require_ip("2001:0db8:0000:0000:0000:0000:0000:0003", "tail_end") == "2001:db8::3"
    assert require_ip("fc00:0:3::1", "tail_end") == "fc00:0:3::1"
    for bad, fragment in (
        ("2001:db8::3%eth0", "carries a zone id"),
        ("PE2", "is not an IP address"),
        ("10.0.0.3/32", "is not an IP address"),
        ("", "is not an IP address"),
    ):
        with pytest.raises(PlatformError) as exc:
            require_ip(bad, "tail_end")
        assert fragment in str(exc.value) and "tail_end" in str(exc.value)


def test_locator_name():
    assert locator_name(" LOC1 ", "srv6_locator") == "LOC1"
    assert locator_name("a" * 64, "srv6_locator") == "a" * 64
    for bad in ("", "   ", "LOC 1", "a" * 65, "LOC\t1"):
        with pytest.raises(PlatformError, match="must be an SRv6 locator name of 1..64"):
            locator_name(bad, "srv6_locator")


def test_parse_endpoints_srv6_locator_is_per_node_and_optional():
    text = json.dumps(
        [
            {**L3VPN_ENDPOINTS[0], "srv6_locator": " LOC1 "},
            {**L3VPN_ENDPOINTS[0], "node": "PE2", "srv6_locator": ""},
            {**L3VPN_ENDPOINTS[0], "node": "PE3"},
        ]
    )
    first, second, third = parse_endpoints(text)
    assert first["srv6_locator"] == "LOC1"
    assert "srv6_locator" not in second and "srv6_locator" not in third
    with pytest.raises(PlatformError, match=r"endpoints\[1\]\.srv6_locator 'LOC 1' must be"):
        parse_endpoints(json.dumps([{**L3VPN_ENDPOINTS[0], "srv6_locator": "LOC 1"}]))


def test_srv6_block_is_the_locator_only():
    """behavior (only ub6-insert-reduced) and binding-sid-type (only srv6-dynamic) are the
    model's single-value defaults and must never be sent."""
    body = build_sr_policy_body(
        "p", "PE1", "2001:db8::3", 600, 100, "dynamic", "igp", True, "", 0, 0, " LOC1 "
    )
    entry = body["cisco-sr-te-cfp-sr-policies:policy"][0]
    assert entry["srv6"] == {"locator": {"locator-name": "LOC1"}}
    assert entry["tail-end"] == "2001:db8::3"
    assert entry["path"] == [{"preference": 100, "dynamic": {"metric-type": "igp", "pce": {}}}]
    assert "bandwidth" not in entry and "binding-sid" not in entry
    odn = build_odn_template_body("o", 601, ["PE1", "PE2"], "igp", True, 0, 0, 0, "LOC1")
    assert odn["cisco-sr-te-cfp-sr-odn:odn-template"][0]["srv6"] == SRV6_BLOCK
    # An SR-MPLS body is unchanged: no srv6 key at all.
    plain = build_sr_policy_body("p", "PE1", "10.0.0.3", 91, 100, "dynamic", "igp", True, "", 0, 0)
    assert "srv6" not in plain["cisco-sr-te-cfp-sr-policies:policy"][0]


@pytest.mark.parametrize(
    "kwargs, fragment",
    [
        # srv6 + IPv4 tail-end: the CFP's "tail-end must be IPv6 address for SRv6 TE policy".
        ({"tail_end": "10.0.0.3", "srv6_locator": "LOC1"}, "needs an IPv6 tail_end"),
        # IPv6 tail-end without srv6: "SRv6 TE policy must be configured if tail-end is IPv6".
        ({"tail_end": "2001:db8::3"}, "tail_end '2001:db8::3' is IPv6, which makes this an SRv6"),
        # the when "not(../srv6)" leaves
        (
            {"tail_end": "2001:db8::3", "srv6_locator": "LOC1", "path_type": "explicit"},
            "srv6_locator needs path_type='dynamic'",
        ),
        (
            {"tail_end": "2001:db8::3", "srv6_locator": "LOC1", "bandwidth_kbps": 1000},
            "bandwidth_kbps cannot be set on an SRv6 policy",
        ),
        (
            {"tail_end": "2001:db8::3", "srv6_locator": "LOC1", "binding_sid": 15600},
            "binding_sid cannot be set on an SRv6 policy",
        ),
        (
            {
                "tail_end": "2001:db8::3",
                "srv6_locator": "LOC1",
                "bandwidth_kbps": 1,
                "binding_sid": 16,
            },
            "bandwidth_kbps and binding_sid cannot be set on an SRv6 policy",
        ),
        ({"tail_end": "2001:db8::3", "srv6_locator": "LOC 1"}, "must be an SRv6 locator name"),
    ],
)
def test_build_sr_policy_body_srv6_preflight(kwargs, fragment):
    defaults = {
        "name": "p",
        "head_end": "PE1",
        "tail_end": "10.0.0.3",
        "color": 600,
        "preference": 100,
        "path_type": "dynamic",
        "metric_type": "igp",
        "delegate_to_pce": True,
        "sid_list": "",
        "bandwidth_kbps": 0,
        "binding_sid": 0,
        "srv6_locator": "",
    }
    with pytest.raises(PlatformError) as exc:
        build_sr_policy_body(**{**defaults, **kwargs})
    assert fragment in str(exc.value)


def test_build_odn_template_body_srv6_refuses_bandwidth():
    with pytest.raises(PlatformError, match="srv6_locator and bandwidth_kbps are incompatible"):
        build_odn_template_body("o", 601, ["PE1"], "igp", True, 1000, 0, 0, "LOC1")


def test_l3vpn_body_srv6_service_wide_and_node_override():
    """Profile-level locator for every PE, a node-level entry for the PE whose endpoint gives
    one (the node entry wins on the CFP — verified d3), nothing on nodes without either."""
    body = build_l3vpn_body(
        "v",
        "0:1:1",
        "0:1:1",
        [
            {"node": "PE1", "interface": "Lo1", "address": "10.1.1.1", "prefix_length": 30},
            {
                "node": "PE2",
                "interface": "Lo1",
                "address": "10.1.1.5",
                "prefix_length": 30,
                "srv6_locator": "LOC2",
            },
            {
                "node": "PE2",
                "interface": "Lo2",
                "address": "10.1.1.9",
                "prefix_length": 30,
                "srv6_locator": "LOC2",  # the same name twice is fine
            },
        ],
        "any-to-any",
        "p1",
        "LOC1",
    )
    service = body["ietf-l3vpn-ntw:vpn-service"][0]
    profile = service["vpn-instance-profiles"]["vpn-instance-profile"][0]
    assert profile["cisco-l3vpn-ntw:srv6"] == L3VPN_SRV6_BLOCK
    assert list(profile) == ["profile-id", "rd", "address-family", "cisco-l3vpn-ntw:srv6"]
    pe1, pe2 = service["vpn-nodes"]["vpn-node"]
    assert pe1["active-vpn-instance-profiles"]["vpn-instance-profile"] == [{"profile-id": "p1"}]
    assert pe2["active-vpn-instance-profiles"]["vpn-instance-profile"] == [
        {
            "profile-id": "p1",
            "cisco-l3vpn-ntw:srv6": {
                "address-family": [{"name": "ietf-vpn-common:ipv4", "locator-name": "LOC2"}]
            },
        }
    ]
    assert len(pe2["vpn-network-accesses"]["vpn-network-access"]) == 2
    # Node-level only: no srv6 on the profile.
    body = build_l3vpn_body(
        "v",
        "0:1:1",
        "0:1:1",
        [
            {
                "node": "PE1",
                "interface": "Lo1",
                "address": "10.1.1.1",
                "prefix_length": 30,
                "srv6_locator": "LOC1",
            }
        ],
        "any-to-any",
        "p1",
    )
    service = body["ietf-l3vpn-ntw:vpn-service"][0]
    assert "cisco-l3vpn-ntw:srv6" not in service["vpn-instance-profiles"]["vpn-instance-profile"][0]
    node = service["vpn-nodes"]["vpn-node"][0]
    active = node["active-vpn-instance-profiles"]["vpn-instance-profile"][0]
    assert active["cisco-l3vpn-ntw:srv6"] == L3VPN_SRV6_BLOCK
    # No srv6 anywhere: the verified MPLS body, byte for byte.
    assert (
        build_l3vpn_body(
            "mcp-l3vpn-1", "0:65091:91", "0:65091:91", L3VPN_ENDPOINTS, "any-to-any", "p1"
        )
        == L3VPN_BODY
    )


def test_l3vpn_body_refuses_conflicting_srv6_locator_on_one_node():
    with pytest.raises(PlatformError, match="different srv6_locator values"):
        build_l3vpn_body(
            "v",
            "0:1:1",
            "0:1:1",
            [
                {
                    "node": "PE1",
                    "interface": "Lo1",
                    "address": "10.1.1.1",
                    "prefix_length": 30,
                    "srv6_locator": "LOC1",
                },
                {
                    "node": "PE1",
                    "interface": "Lo2",
                    "address": "10.1.1.5",
                    "prefix_length": 30,
                    "srv6_locator": "LOC2",
                },
            ],
            "any-to-any",
            "p1",
        )
    with pytest.raises(PlatformError, match="srv6_locator 'LOC 1' must be"):
        build_l3vpn_body("v", "0:1:1", "0:1:1", L3VPN_ENDPOINTS, "any-to-any", "p1", "LOC 1")


@pytest.mark.parametrize(
    "response, method, expected",
    [
        (
            SRV6_NEEDS_IPV6_TAIL,
            "PUT",
            "an SRv6 policy (the srv6 container / srv6_locator) needs an IPv6 tail-end",
        ),
        (
            SRV6_REQUIRED_BY_TAIL,
            "PUT",
            "an IPv6 tail-end makes this an SRv6 policy, and the SR-TE CFP then requires",
        ),
        (
            SRV6_REQUIRED_BY_SOURCE,
            "PUT",
            "an IPv6 source-address makes this an SRv6 ODN template, and the SR-TE CFP then",
        ),
        (
            SRV6_WHEN_BINDING_SID,
            "PATCH",
            "binding_sid is not allowed on an SRv6 policy or template",
        ),
        (SRV6_WHEN_BANDWIDTH, "PATCH", "bandwidth_kbps is not allowed on an SRv6 policy"),
        (SRV6_WHEN_ODN_BANDWIDTH, "PUT", "bandwidth_kbps is not allowed on an SRv6 policy"),
        (
            SRV6_WHEN_EXPLICIT,
            "PUT",
            "an explicit path (path_type='explicit' / sid_list) is not allowed on an SRv6",
        ),
        (
            SRV6_LOCATOR_NO_NAME,
            "PUT",
            "the srv6 locator container needs its mandatory locator-name: give srv6_locator",
        ),
        (
            L3NM_SRV6_EMPTY,
            "PUT",
            "the L3NM srv6 container needs at least one address-family entry",
        ),
        (
            L3NM_SRV6_FLAT,
            "PUT",
            "the body has a node the model does not know: unknown element: locator-name in",
        ),
        (PATCH_NONEXISTENT, "PATCH", "no SR policy service 'x' (names are exact"),
    ],
)
def test_explain_write_failure_srv6_rules(response, method, expected):
    target = ServiceTarget("SR policy service", "x", "p")
    text = explain_write_failure(
        response.status_code, response.json(), method=method, target=target
    )
    assert text.startswith(expected), text
    assert "when" in text or "srv6" in text.lower() or "exact" in text


def test_explain_write_failure_srv6_rules_do_not_swallow_other_texts():
    """An invalid-value / malformed-message that is not an SRv6 rule keeps its own mapping."""
    target = ServiceTarget("SR policy service", "x", "p")
    assert explain_write_failure(400, BAD_HEAD_END.json(), method="PUT", target=target).startswith(
        "head-end 'NOPE' is not an NSO device"
    )
    assert explain_write_failure(400, TSDN_415.json(), method="PUT", target=target).startswith(
        "the function pack rejected the service"
    )
    other = restconf_error(400, "malformed-message", "something else entirely")
    assert explain_write_failure(400, other.json(), method="PUT", target=target).startswith(
        "The RESTCONF service rejected the request"
    )


@pytest.mark.parametrize(
    "text, fragment",
    [
        ("nope", "not valid JSON"),
        ("[]", "must be a JSON object"),
        ("{}", "exactly one top-level key"),
        ('{"a:b": [{}], "c:d": [{}]}', "exactly one top-level key"),
        ('{"policy": [{}]}', "must be module-prefixed"),
        ('{"m:policy": {}}', "list holding exactly one object"),
        ('{"m:policy": [{}, {}]}', "list holding exactly one object"),
        ('{"m:sid-list": [{}]}', "does not match the list the yang_path addresses ('policy')"),
    ],
)
def test_validate_service_body_refusals(text, fragment):
    with pytest.raises(PlatformError) as exc:
        validate_service_body(text, "cisco-sr-te-cfp:sr-te/m:policies/m:policy=x")
    assert fragment in str(exc.value)


def test_validate_service_body_ok():
    key, body = validate_service_body(
        json.dumps(CS_BODY), "cisco-cs-sr-te-cfp:cs-sr-te-policy=mcp-cs-1"
    )
    assert key == "cisco-cs-sr-te-cfp:cs-sr-te-policy" and body == CS_BODY


@pytest.mark.parametrize(
    "given, expected",
    [
        ("policy", "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/policy"),
        ("SR_Policy", "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/policy"),
        ("odn-template", "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/odn-template"),
        ("cs-sr-te-policy", "cisco-cs-sr-te-cfp:cs-sr-te-policy"),
        ("ietf-l3vpn", "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service"),
        ("l3vpn", "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service"),
        ("ietf-l2vpn", "ietf-l2vpn-ntw:l2vpn-ntw/vpn-services/vpn-service"),
        ("slice-service", "ietf-network-slice-service:network-slice-services/slice-service"),
        ("tunnel", "ietf-te:te/tunnels/tunnel"),
        (
            "{urn:ietf:params:xml:ns:yang:ietf-l3vpn-ntw}vpn-service",
            "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service",
        ),
        (
            "{urn:ietf:params:xml:ns:yang:ietf-l2vpn-ntw}vpn-service",
            "ietf-l2vpn-ntw:l2vpn-ntw/vpn-services/vpn-service",
        ),
        (
            "{http://cisco.com/ns/nso/fp/examples/cisco-sr-te-cfp-sr-odn}odn-template",
            "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/odn-template",
        ),
        ("/custom:root/list/", "custom:root/list"),
    ],
)
def test_resolve_type_path(given, expected):
    assert resolve_type_path(given) == expected


@pytest.mark.parametrize("bad", ["", "vpn-service", "widgets"])
def test_resolve_type_path_refuses(bad):
    with pytest.raises(PlatformError):
        resolve_type_path(bad)


def test_summarize_plan_ready_and_failed():
    ready = summarize_plan(POLICY_PLAN_READY, "cisco-sr-te-cfp-sr-policies", "policy")
    assert ready["status"] == "ready"
    assert ready["components"][0] == {
        "type": "self",
        "name": "self",
        "reached": "ready",
        "failed": None,
        "states": ["init=reached", "ready=reached"],
    }
    assert ready["components"][1]["type"] == "head-end"
    assert ready["components"][1]["name"] == "PE1"
    assert ready["components"][1]["states"] == [
        "init=reached",
        "config-apply=reached",
        "ready=reached",
    ]
    failed = summarize_plan(POLICY_PLAN_FAILED, "cisco-sr-te-cfp-sr-policies", "policy")
    assert failed["status"] == "failed"
    assert failed["components"][1]["failed"] == "config-apply"
    assert failed["components"][1]["reached"] == "init"
    # An unexpected module prefix on the plan key is still found by its ``-plan`` suffix.
    assert summarize_plan(ODN_PLAN_READY, "wrong-module", "odn-template")["status"] == "ready"
    assert summarize_plan({}, "m", "policy") is None
    assert summarize_plan(None, "m", "policy") is None


def test_summarize_plan_plan_level_failed_and_error_info():
    """tailf-ncs-plan's plan-level ``failed`` (type empty -> ``[null]`` in JSON) and
    ``error-info.message`` are surfaced even when no component state is marked failed."""
    data = json.loads(json.dumps(POLICY_PLAN_READY))
    plan = data["cisco-sr-te-cfp-sr-policies:policy-plan"][0]["plan"]
    plan["failed"] = [None]
    plan["error-info"] = {"message": "Python cb_nano_create error", "log-entry": "x"}
    summary = summarize_plan(data, "cisco-sr-te-cfp-sr-policies", "policy")
    assert summary["failed"] is True
    assert summary["error"] == "Python cb_nano_create error"
    assert summary["status"] == "ready"  # the states themselves all reached
    line = plan_line(summary)
    assert line.startswith("Plan: ready (Python cb_nano_create error) — self: init=reached")
    # Without a message there is no ``error`` key and the line carries no parenthesis.
    plan["error-info"] = {"log-entry": "x"}
    summary = summarize_plan(data, "cisco-sr-te-cfp-sr-policies", "policy")
    assert "error" not in summary and summary["failed"] is True
    assert plan_line(summary).startswith("Plan: ready — self:")
    assert plan_line(None, "nothing there") == "Plan: nothing there."


def test_plan_line_names_the_cat_status_of_the_nano_plan_word():
    """The 'Plan:' line is NSO nano-plan vocabulary; each one names the CAT plan status the
    services tools use for the same service (verified: 'ready' there is 'completed' here)."""
    ready = summarize_plan(POLICY_PLAN_READY, "cisco-sr-te-cfp-sr-policies", "policy")
    line = plan_line(ready)
    assert line.startswith(
        "Plan: ready — self: init=reached, ready=reached; head-end PE1: init=reached, "
        "config-apply=reached, ready=reached. (NSO nano-plan states; CAT plan status: "
        "'completed'"
    )
    assert "'ready' accepted as its alias" in line
    failed = summarize_plan(POLICY_PLAN_FAILED, "cisco-sr-te-cfp-sr-policies", "policy")
    assert "CAT plan status: 'failed'" in plan_line(failed)
    assert plan_layer_note("in-progress").startswith(
        "(NSO nano-plan states; CAT plan status: 'in-progress'"
    )
    # A note-only line (no plan) carries no vocabulary note.
    assert plan_line(None) == "Plan: not available."


def test_dry_run_devices():
    assert dry_run_devices(DRY_RUN_CREATE)[0].device == "PE1"
    assert dry_run_devices(DRY_RUN_CREATE)[0].cli == POLICY_CLI.rstrip()
    assert dry_run_devices(DRY_RUN_NO_CHANGE) == []
    assert dry_run_devices({"dry-run-result": {"native": {}}}) == []
    assert dry_run_devices({}) is None
    assert dry_run_devices(None) is None


def test_explain_write_failure_falls_back_to_the_generic_restconf_text():
    target = ServiceTarget("SID list", "x", "p")
    text = explain_write_failure(415, PROXY_415.json(), method="PUT", target=target)
    assert "application/yang-data+json" in text
    assert explain_write_failure(500, {"error": "x"}, method="PUT", target=target) is None
    # A 404 keypath on PUT is not "no such entry" (a PUT creates): generic text.
    put_404 = explain_write_failure(404, NOT_FOUND.json(), method="PUT", target=target)
    assert put_404.startswith("The RESTCONF service rejected the request")
    assert "uri keypath not found" in put_404


# --- cnc_create_odn_template ----------------------------------------------------------


@respx.mock
async def test_create_odn_template_created_with_plan(writes):
    put = respx.put(f"{ODN_TEMPLATES}=mcp-odn-90").mock(return_value=CREATED)
    plan = respx.get(f"{ODN_PLANS}=mcp-odn-90").mock(
        return_value=httpx.Response(200, json=ODN_PLAN_READY)
    )
    text = await call_tool_text(writes, "cnc_create_odn_template", ODN_ARGS)
    assert_yang_write(put, "PUT")
    assert sent(put) == ODN_BODY
    assert plan.call_count == 1
    assert request_of(plan).headers["Accept"] == YANG_JSON
    assert "Content-Type" not in request_of(plan).headers
    assert text.startswith("Created ODN template 'mcp-odn-90': NSO committed the service (PUT")
    assert "-> 201" in text
    assert (
        "Plan: ready — self: init=reached, ready=reached; head-end PE1: init=reached, "
        "config-apply=reached, ready=reached." in text
    )
    # The line names its CAT equivalent (the two plan vocabularies), but a ready plan gets
    # no "wait for it" hint.
    assert "(NSO nano-plan states; CAT plan status: 'completed'" in text
    assert "Wait for it with cnc_wait_for_service_plan" not in text
    assert "Next: " in text and "cnc_delete_odn_template" in text
    assert "cnc_list_services / cnc_get_service show the template" in text


@respx.mock
async def test_create_odn_template_replaced_on_204_and_all_options(writes):
    put = respx.put(f"{ODN_TEMPLATES}=mcp-odn-90").mock(return_value=NO_CONTENT)
    respx.get(f"{ODN_PLANS}=mcp-odn-90").mock(return_value=httpx.Response(200, json=ODN_PLAN_READY))
    text = await call_tool_text(
        writes,
        "cnc_create_odn_template",
        {
            **ODN_ARGS,
            "head_ends": "PE1, PE2,PE1",
            "metric_type": "latency",
            "delegate_to_pce": False,
            "bandwidth_kbps": 5000,
            "maximum_sid_depth": 5,
            "flex_algo": 128,
        },
    )
    assert sent(put) == {
        "cisco-sr-te-cfp-sr-odn:odn-template": [
            {
                "name": "mcp-odn-90",
                "color": 90,
                "head-end": [{"name": "PE1"}, {"name": "PE2"}],
                "dynamic": {"metric-type": "latency", "flex-alg": 128},
                "bandwidth": 5000,
                "maximum-sid-depth": 5,
            }
        ]
    }
    assert text.startswith("Replaced ODN template 'mcp-odn-90': it already existed")
    assert "idempotent" in text


@respx.mock
async def test_create_odn_template_dry_run_renders_cli_and_commits_nothing(writes):
    put = respx.put(f"{ODN_TEMPLATES}=mcp-odn-90").mock(
        return_value=httpx.Response(201, json=DRY_RUN_ODN)
    )
    plan = respx.get(f"{ODN_PLANS}=mcp-odn-90").mock(
        return_value=httpx.Response(200, json=ODN_PLAN_READY)
    )
    text = await call_tool_text(writes, "cnc_create_odn_template", {**ODN_ARGS, "dry_run": True})
    assert_yang_write(put, "PUT", dry_run=True)
    assert sent(put) == ODN_BODY
    assert plan.call_count == 0
    assert text.startswith(
        "Dry run only — nothing was committed. NSO would push this to create ODN template "
        "'mcp-odn-90':"
    )
    assert "### PE1\n```\nsegment-routing\n traffic-eng\n  on-demand color 90\n   dynamic" in text
    assert text.rstrip().endswith("```")  # the trailing newline of the CLI is trimmed


@respx.mock
async def test_create_odn_template_plan_missing_is_not_an_error(writes):
    respx.put(f"{ODN_TEMPLATES}=mcp-odn-90").mock(return_value=CREATED)
    respx.get(f"{ODN_PLANS}=mcp-odn-90").mock(return_value=NOT_FOUND)
    text = await call_tool_text(writes, "cnc_create_odn_template", ODN_ARGS)
    assert text.startswith("Created ODN template 'mcp-odn-90'")
    assert "Plan: not available yet (GET .../cisco-sr-te-cfp:sr-te/" in text and "-> 404)" in text
    # The hints carry CAT's own plan-yang-path spelling (no module prefix on the plan segment),
    # the string cnc_wait_for_service_plan / cnc_get_service_plan feed to get-service-plan-data.
    plan_path = "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/odn-template-plan=mcp-odn-90"
    assert f"cnc_get_service_plan(plan_yang_path='{plan_path}', detail=true)" in text
    assert f"Wait for it with cnc_wait_for_service_plan(plan_yang_path='{plan_path}')." in text
    assert "cisco-sr-te-cfp-sr-odn:odn-template-plan" not in text


@respx.mock
async def test_create_odn_template_plan_in_progress_gets_the_wait_hint(writes):
    respx.put(f"{ODN_TEMPLATES}=mcp-odn-90").mock(return_value=CREATED)
    in_progress = nano_plan(
        "cisco-sr-te-cfp-sr-odn:odn-template-plan",
        "mcp-odn-90",
        [("init", "reached"), ("config-apply", "not-reached"), ("ready", "not-reached")],
    )
    in_progress["cisco-sr-te-cfp-sr-odn:odn-template-plan"][0]["plan"]["component"][0]["state"][1][
        "status"
    ] = "not-reached"
    respx.get(f"{ODN_PLANS}=mcp-odn-90").mock(return_value=httpx.Response(200, json=in_progress))
    text = await call_tool_text(writes, "cnc_create_odn_template", ODN_ARGS)
    assert "Plan: in-progress — self: init=reached, ready=not-reached; head-end PE1: " in text
    assert "Wait for it with cnc_wait_for_service_plan(plan_yang_path=" in text


@respx.mock
async def test_create_odn_template_plan_read_failure_does_not_hide_the_commit(writes):
    respx.put(f"{ODN_TEMPLATES}=mcp-odn-90").mock(return_value=CREATED)
    respx.get(f"{ODN_PLANS}=mcp-odn-90").mock(return_value=NATS_500)
    text = await call_tool_text(writes, "cnc_create_odn_template", ODN_ARGS)
    assert text.startswith("Created ODN template 'mcp-odn-90'")
    assert "Plan: could not be read (GET" in text and "-> 500)" in text


@respx.mock
async def test_create_odn_template_unknown_head_end(writes):
    respx.put(f"{ODN_TEMPLATES}=mcp-odn-90").mock(return_value=BAD_HEAD_END)
    text = await call_tool_text(
        writes, "cnc_create_odn_template", {**ODN_ARGS, "head_ends": "NOPE"}
    )
    assert text.startswith(
        "Error: head-end 'NOPE' is not an NSO device (list NSO's devices with cnc_list_nso_devices"
    )


@respx.mock
async def test_create_odn_template_out_of_sync(writes):
    respx.put(f"{ODN_TEMPLATES}=mcp-odn-90").mock(return_value=OUT_OF_SYNC)
    text = await call_tool_text(writes, "cnc_create_odn_template", ODN_ARGS)
    assert text == (
        "Error: NSO considers PE1 out of sync — run cnc_nso_device_action(action='sync-from', "
        "host_name='PE1') then retry."
    )


@respx.mock
async def test_create_odn_template_dry_run_out_of_sync_is_reported_the_same(writes):
    respx.put(f"{ODN_TEMPLATES}=mcp-odn-90").mock(return_value=OUT_OF_SYNC)
    text = await call_tool_text(writes, "cnc_create_odn_template", {**ODN_ARGS, "dry_run": True})
    assert text.startswith("Error: NSO considers PE1 out of sync")


@respx.mock
async def test_create_odn_template_dry_run_without_result_is_an_error_that_says_nothing_committed(
    writes,
):
    respx.put(f"{ODN_TEMPLATES}=mcp-odn-90").mock(return_value=httpx.Response(200, json={"odd": 1}))
    text = await call_tool_text(writes, "cnc_create_odn_template", {**ODN_ARGS, "dry_run": True})
    assert text.startswith("Error: NSO answered 200 to the dry run but without a dry-run-result")
    assert "nothing was committed" in text


@respx.mock
async def test_create_odn_template_generic_failures(writes):
    respx.put(f"{ODN_TEMPLATES}=mcp-odn-90").mock(return_value=ACCESS_DENIED)
    text = await call_tool_text(writes, "cnc_create_odn_template", ODN_ARGS)
    assert text.startswith("Error: The RESTCONF service rejected the request")
    assert "RESTCONF access-denied: access denied" in text
    respx.put(f"{ODN_TEMPLATES}=mcp-odn-90").mock(return_value=NATS_500)
    text = await call_tool_text(writes, "cnc_create_odn_template", ODN_ARGS)
    assert text.startswith("Error: API request failed with status 500")
    respx.put(f"{ODN_TEMPLATES}=mcp-odn-90").mock(return_value=PROXY_415)
    text = await call_tool_text(writes, "cnc_create_odn_template", ODN_ARGS)
    assert "application/yang-data+json" in text


@respx.mock
@pytest.mark.parametrize(
    "args, fragment",
    [
        ({"head_ends": " , "}, "head_ends is empty"),
        ({"metric_type": "cost"}, "Unknown metric_type 'cost'"),
        ({"flex_algo": 5}, "flex_algo 5 is outside 128..255"),
        # SRv6: bandwidth is when "not(../srv6)" on the ODN model; the locator name is typed.
        (
            {"srv6_locator": "LOC1", "bandwidth_kbps": 1000},
            "srv6_locator and bandwidth_kbps are incompatible",
        ),
        ({"srv6_locator": "LOC 1"}, "srv6_locator 'LOC 1' must be an SRv6 locator name"),
    ],
)
async def test_create_odn_template_client_side_refusals_send_nothing(writes, args, fragment):
    put = respx.put(f"{ODN_TEMPLATES}=mcp-odn-90").mock(return_value=CREATED)
    text = await call_tool_text(writes, "cnc_create_odn_template", {**ODN_ARGS, **args})
    assert text.startswith("Error: ") and fragment in text
    assert put.call_count == 0


@respx.mock
async def test_create_odn_template_srv6_dry_run_renders_the_verified_cli(writes):
    """srv6_locator -> ``"srv6": {"locator": {"locator-name": ...}}`` and nothing else (the
    single-value behavior / binding-sid-type enums stay at their defaults); the dry run
    renders the ``srv6 / locator LOC1 binding-sid dynamic behavior ub6-insert-reduced`` block
    on every head-end (verified 2026-09-15)."""
    put = respx.put(SRV6_ODN_URL).mock(return_value=httpx.Response(201, json=DRY_RUN_SRV6_ODN))
    plan = respx.get(SRV6_ODN_PLAN_URL).mock(return_value=NO_CONTENT)
    text = await call_tool_text(
        writes,
        "cnc_create_odn_template",
        {**SRV6_ODN_ARGS, "head_ends": "PE1, PE2", "dry_run": True, "srv6_locator": " LOC1 "},
    )
    assert_yang_write(put, "PUT", dry_run=True)
    assert sent(put) == SRV6_ODN_BODY
    assert "behavior" not in json.dumps(sent(put)) and "binding-sid-type" not in json.dumps(
        sent(put)
    )
    assert plan.call_count == 0
    assert text.startswith("Dry run only — nothing was committed.")
    assert "on-demand color 601\n   srv6\n    locator LOC1 binding-sid dynamic" in text
    assert text.count("locator LOC1 binding-sid dynamic behavior ub6-insert-reduced") == 2
    assert "### PE1\n" in text and "### PE2\n" in text


@respx.mock
async def test_create_odn_template_srv6_committed_and_other_options_kept(writes):
    put = respx.put(SRV6_ODN_URL).mock(return_value=CREATED)
    respx.get(SRV6_ODN_PLAN_URL).mock(return_value=httpx.Response(200, json=SRV6_ODN_PLAN_READY))
    text = await call_tool_text(
        writes,
        "cnc_create_odn_template",
        {
            **SRV6_ODN_ARGS,
            "metric_type": "latency",
            "delegate_to_pce": False,
            "maximum_sid_depth": 5,
            "flex_algo": 128,
        },
    )
    entry = sent(put)["cisco-sr-te-cfp-sr-odn:odn-template"][0]
    assert entry["srv6"] == SRV6_BLOCK
    assert entry["dynamic"] == {"metric-type": "latency", "flex-alg": 128}
    assert entry["maximum-sid-depth"] == 5 and "bandwidth" not in entry
    assert text.startswith(f"Created ODN template '{SRV6_ODN_NAME}'") and "Plan: ready" in text


@respx.mock
async def test_create_odn_template_srv6_cfp_refusal_is_explained(writes):
    """The CFP's own when-rule verdict (a newer CFP, or a body the pre-flight did not
    catch) maps to the same text as the pre-flight."""
    put = respx.put(SRV6_ODN_URL).mock(return_value=SRV6_WHEN_ODN_BANDWIDTH)
    text = await call_tool_text(writes, "cnc_create_odn_template", SRV6_ODN_ARGS)
    assert put.call_count == 1
    assert text.startswith(
        "Error: bandwidth_kbps is not allowed on an SRv6 policy or template (the model's when "
        '"not(../srv6)"'
    )


@respx.mock
async def test_create_odn_template_encodes_the_key(writes):
    put = respx.put(f"{ODN_TEMPLATES}=odd%20name%2F1").mock(return_value=CREATED)
    respx.get(f"{ODN_PLANS}=odd%20name%2F1").mock(return_value=NO_CONTENT)
    text = await call_tool_text(
        writes, "cnc_create_odn_template", {**ODN_ARGS, "name": "odd name/1"}
    )
    assert put.call_count == 1
    assert request_of(put).url.raw_path.endswith(b"odn-template=odd%20name%2F1")
    assert text.startswith("Created ODN template 'odd name/1'")
    assert "Plan: not available yet" in text and "-> 204)" in text


# --- cnc_delete_odn_template ----------------------------------------------------------


@respx.mock
async def test_delete_odn_template(writes):
    delete = respx.delete(f"{ODN_TEMPLATES}=mcp-odn-90").mock(return_value=NO_CONTENT)
    plan = respx.get(f"{ODN_PLANS}=mcp-odn-90").mock(return_value=NO_CONTENT)
    text = await call_tool_text(writes, "cnc_delete_odn_template", {"name": "mcp-odn-90"})
    assert_yang_delete(delete)
    assert plan.call_count == 0
    assert text.startswith(
        "Deleted ODN template 'mcp-odn-90': NSO removed it and any device configuration it "
        "rendered (DELETE"
    )
    assert "-> 204" in text


@respx.mock
async def test_delete_odn_template_dry_run(writes):
    delete = respx.delete(f"{ODN_TEMPLATES}=mcp-odn-90").mock(
        return_value=httpx.Response(200, json=DRY_RUN_DELETE)
    )
    text = await call_tool_text(
        writes, "cnc_delete_odn_template", {"name": "mcp-odn-90", "dry_run": True}
    )
    assert_yang_delete(delete, dry_run=True)
    assert "NSO would push this to delete ODN template 'mcp-odn-90'" in text
    assert "no policy srte_c_91_ep_10.0.0.3" in text


@respx.mock
async def test_delete_odn_template_not_found(writes):
    respx.delete(f"{ODN_TEMPLATES}=mcp-odn-90").mock(return_value=NOT_FOUND)
    text = await call_tool_text(writes, "cnc_delete_odn_template", {"name": "mcp-odn-90"})
    assert text == "Error: no ODN template 'mcp-odn-90' (names are exact and case-sensitive)."


# --- cnc_create_sr_policy_service -----------------------------------------------------


@respx.mock
async def test_create_sr_policy_service_dynamic(writes):
    put = respx.put(f"{POLICY}=mcp-pol-91").mock(return_value=CREATED)
    plan = respx.get(f"{POLICY_PLAN}=mcp-pol-91").mock(
        return_value=httpx.Response(200, json=POLICY_PLAN_READY)
    )
    text = await call_tool_text(writes, "cnc_create_sr_policy_service", POLICY_ARGS)
    assert_yang_write(put, "PUT")
    assert sent(put) == POLICY_BODY
    assert plan.call_count == 1
    assert text.startswith("Created SR policy service 'mcp-pol-91': NSO committed the service")
    assert "Plan: ready" in text
    assert "srte_c_91_ep_10.0.0.3" in text
    assert "cnc_get_sr_policy(headend=<head-end router-id>, endpoint='10.0.0.3', color=91)" in text


@respx.mock
async def test_create_sr_policy_service_explicit_with_options(writes):
    put = respx.put(f"{POLICY}=mcp-pol-93").mock(return_value=CREATED)
    plan = respx.get(f"{POLICY_PLAN}=mcp-pol-93").mock(return_value=NO_CONTENT)
    text = await call_tool_text(
        writes,
        "cnc_create_sr_policy_service",
        {
            "name": "mcp-pol-93",
            "head_end": "PE1",
            "tail_end": "10.0.0.3",
            "color": 93,
            "path_type": "explicit",
            "sid_list": "mcp-sl-1",
            "bandwidth_kbps": 1000,
            "binding_sid": 15001,
        },
    )
    expected = json.loads(json.dumps(EXPLICIT_POLICY_BODY))
    expected["cisco-sr-te-cfp-sr-policies:policy"][0]["bandwidth"] = 1000
    expected["cisco-sr-te-cfp-sr-policies:policy"][0]["binding-sid"] = 15001
    assert sent(put) == expected
    # The plan is read (and the wait hint spelled) at CAT's ``.../policies/policy-plan=<n>``.
    assert plan.call_count == 1
    assert (
        "cnc_wait_for_service_plan(plan_yang_path='cisco-sr-te-cfp:sr-te/"
        "cisco-sr-te-cfp-sr-policies:policies/policy-plan=mcp-pol-93')" in text
    )


@respx.mock
async def test_create_sr_policy_service_local_dynamic_and_preference(writes):
    put = respx.put(f"{POLICY}=mcp-pol-91").mock(return_value=CREATED)
    respx.get(f"{POLICY_PLAN}=mcp-pol-91").mock(return_value=NO_CONTENT)
    await call_tool_text(
        writes,
        "cnc_create_sr_policy_service",
        {**POLICY_ARGS, "delegate_to_pce": False, "metric_type": "te", "preference": 200},
    )
    assert sent(put)["cisco-sr-te-cfp-sr-policies:policy"][0]["path"] == [
        {"preference": 200, "dynamic": {"metric-type": "te"}}
    ]


@respx.mock
async def test_create_sr_policy_service_dry_run(writes):
    put = respx.put(f"{POLICY}=mcp-pol-91").mock(
        return_value=httpx.Response(201, json=DRY_RUN_CREATE)
    )
    text = await call_tool_text(
        writes, "cnc_create_sr_policy_service", {**POLICY_ARGS, "dry_run": True}
    )
    assert_yang_write(put, "PUT", dry_run=True)
    assert "policy srte_c_91_ep_10.0.0.3" in text and text.startswith("Dry run only")


@respx.mock
async def test_create_sr_policy_service_plan_failed(writes):
    respx.put(f"{POLICY}=mcp-pol-91").mock(return_value=CREATED)
    respx.get(f"{POLICY_PLAN}=mcp-pol-91").mock(
        return_value=httpx.Response(200, json=POLICY_PLAN_FAILED)
    )
    text = await call_tool_text(writes, "cnc_create_sr_policy_service", POLICY_ARGS)
    assert text.startswith("Created SR policy service 'mcp-pol-91'")
    assert (
        "Plan: failed — self: init=reached, ready=reached; head-end PE1: init=reached, "
        "config-apply=failed, ready=not-reached." in text
    )


@respx.mock
@pytest.mark.parametrize(
    "response, expected",
    [
        (BAD_HEAD_END, "Error: head-end 'NOPE' is not an NSO device"),
        (
            SID_LIST_REFERENCED,
            "Error: SID list 'mcp-sl-1' does not exist — create it first with cnc_create_sid_list",
        ),
        (
            UNKNOWN_ELEMENT,
            "Error: the body has a node the model does not know: unknown element: bogus in ",
        ),
        (OUT_OF_SYNC, "Error: NSO considers PE1 out of sync — run cnc_nso_device_action("),
    ],
)
async def test_create_sr_policy_service_verified_errors(writes, response, expected):
    put = respx.put(f"{POLICY}=mcp-pol-91").mock(return_value=response)
    plan = respx.get(f"{POLICY_PLAN}=mcp-pol-91").mock(return_value=NO_CONTENT)
    text = await call_tool_text(writes, "cnc_create_sr_policy_service", POLICY_ARGS)
    assert text.startswith(expected)
    assert put.call_count == 1 and plan.call_count == 0


@respx.mock
@pytest.mark.parametrize(
    "args, fragment",
    [
        ({"path_type": "explicit"}, "path_type='explicit' needs sid_list"),
        ({"sid_list": "mcp-sl-1"}, "sid_list only applies to path_type='explicit'"),
        ({"tail_end": "PE2"}, "tail_end 'PE2' is not an IP address"),
        # ipaddress accepts a zone id; no tail-end does (and NSO would key the policy on it).
        (
            {"tail_end": "2001:db8::3%eth0", "srv6_locator": "LOC1"},
            "tail_end '2001:db8::3%eth0' carries a zone id",
        ),
        ({"path_type": "static"}, "Unknown path_type 'static'"),
        ({"binding_sid": 5}, "binding_sid 5 is outside 16..1048575"),
        # SRv6 pre-flight: each rule is a verified CFP 400, refused before anything is sent.
        (
            {"srv6_locator": "LOC1"},  # IPv4 tail_end
            "srv6_locator makes this an SRv6 policy, and an SRv6 policy needs an IPv6 tail_end",
        ),
        (
            {"tail_end": "2001:db8::3"},  # no locator
            "tail_end '2001:db8::3' is IPv6, which makes this an SRv6 policy",
        ),
        (
            # ... and the same refusal names the one SRv6 shape the tool cannot express.
            {"tail_end": "2001:db8::3"},
            'For the router\'s default locator (the bare presence form "srv6": {} — dry-run '
            "verified, device behaviour not) send the body through cnc_provision_service.",
        ),
        (
            {
                "tail_end": "2001:db8::3",
                "srv6_locator": "LOC1",
                "path_type": "explicit",
                "sid_list": "mcp-sl-1",
            },
            "srv6_locator needs path_type='dynamic'",
        ),
        (
            {"tail_end": "2001:db8::3", "srv6_locator": "LOC1", "bandwidth_kbps": 1000},
            "bandwidth_kbps cannot be set on an SRv6 policy",
        ),
        (
            {"tail_end": "2001:db8::3", "srv6_locator": "LOC1", "binding_sid": 15600},
            "binding_sid cannot be set on an SRv6 policy",
        ),
        (
            {"tail_end": "2001:db8::3", "srv6_locator": "LOC 1"},
            "srv6_locator 'LOC 1' must be an SRv6 locator name",
        ),
    ],
)
async def test_create_sr_policy_service_client_side_refusals(writes, args, fragment):
    put = respx.put(f"{POLICY}=mcp-pol-91").mock(return_value=CREATED)
    text = await call_tool_text(writes, "cnc_create_sr_policy_service", {**POLICY_ARGS, **args})
    assert text.startswith("Error: ") and fragment in text
    assert put.call_count == 0


@respx.mock
async def test_create_sr_policy_service_srv6_dry_run_renders_the_verified_cli(writes):
    """An IPv6 tail-end plus srv6_locator: the body carries ``srv6/locator/locator-name``
    beside an ordinary dynamic path (``srv6-dynamic`` is not a path type), and the dry run
    renders ``policy srte_c_600_ep_2001:db8::3 / srv6 / locator LOC1 binding-sid dynamic
    behavior ub6-insert-reduced / color 600 end-point ipv6 ...`` (verified 2026-09-15)."""
    put = respx.put(SRV6_POLICY_URL).mock(
        return_value=httpx.Response(201, json=DRY_RUN_SRV6_POLICY)
    )
    plan = respx.get(SRV6_POLICY_PLAN_URL).mock(return_value=NO_CONTENT)
    text = await call_tool_text(
        writes, "cnc_create_sr_policy_service", {**SRV6_POLICY_ARGS, "dry_run": True}
    )
    assert_yang_write(put, "PUT", dry_run=True)
    assert sent(put) == SRV6_POLICY_BODY
    assert plan.call_count == 0
    assert text.startswith("Dry run only — nothing was committed.")
    assert "policy srte_c_600_ep_2001:db8::3\n   srv6\n    locator LOC1 binding-sid dynamic" in text
    assert "color 600 end-point ipv6 2001:db8::3" in text


@respx.mock
async def test_create_sr_policy_service_srv6_committed_hint_names_the_locator(writes):
    put = respx.put(SRV6_POLICY_URL).mock(return_value=CREATED)
    respx.get(SRV6_POLICY_PLAN_URL).mock(
        return_value=httpx.Response(200, json=SRV6_POLICY_PLAN_READY)
    )
    text = await call_tool_text(
        writes,
        "cnc_create_sr_policy_service",
        {**SRV6_POLICY_ARGS, "delegate_to_pce": False, "metric_type": "latency"},
    )
    entry = sent(put)["cisco-sr-te-cfp-sr-policies:policy"][0]
    assert entry["srv6"] == SRV6_BLOCK
    assert entry["path"] == [{"preference": 100, "dynamic": {"metric-type": "latency"}}]
    assert text.startswith(f"Created SR policy service '{SRV6_POLICY_NAME}'")
    assert "Plan: ready" in text
    assert "SRv6 policy srte_c_600_ep_2001:db8::3 with locator LOC1" in text
    assert "NSO checked neither" in text
    assert "endpoint='2001:db8::3', color=600" in text
    # The SR-MPLS hint (bandwidth / binding-sid updates) does not apply to an SRv6 policy.
    assert "Change bandwidth / binding-sid with cnc_update_sr_policy_service" not in text


@respx.mock
async def test_create_sr_policy_service_canonicalises_the_ipv6_tail_end(writes):
    """NSO renders the tail-end canonical (dry-run verified: '2001:DB8:0:0::3' became
    ``policy srte_c_620_ep_2001:db8::3 / end-point ipv6 2001:db8::3``), so the tool sends
    that spelling and names it in the hint — the body, the CFP policy name and the
    cnc_get_sr_policy endpoint agree. IPv4 passes through unchanged."""
    put = respx.put(SRV6_POLICY_URL).mock(return_value=CREATED)
    respx.get(SRV6_POLICY_PLAN_URL).mock(
        return_value=httpx.Response(200, json=SRV6_POLICY_PLAN_READY)
    )
    text = await call_tool_text(
        writes,
        "cnc_create_sr_policy_service",
        {**SRV6_POLICY_ARGS, "tail_end": " 2001:DB8:0:0::3 ", "color": 620},
    )
    entry = sent(put)["cisco-sr-te-cfp-sr-policies:policy"][0]
    assert entry["tail-end"] == "2001:db8::3" and entry["color"] == 620
    assert "SRv6 policy srte_c_620_ep_2001:db8::3 with locator LOC1" in text
    assert "endpoint='2001:db8::3', color=620" in text
    assert "2001:DB8" not in text
    # The SR-MPLS hint carries the IPv4 tail-end as given.
    put = respx.put(f"{POLICY}=mcp-pol-91").mock(return_value=CREATED)
    respx.get(f"{POLICY_PLAN}=mcp-pol-91").mock(return_value=NO_CONTENT)
    text = await call_tool_text(
        writes, "cnc_create_sr_policy_service", {**POLICY_ARGS, "tail_end": " 10.0.0.3 "}
    )
    assert sent(put) == POLICY_BODY
    assert "policy srte_c_91_ep_10.0.0.3;" in text and "endpoint='10.0.0.3', color=91" in text


@respx.mock
@pytest.mark.parametrize(
    "response, expected",
    [
        (
            SRV6_NEEDS_IPV6_TAIL,
            "Error: an SRv6 policy (the srv6 container / srv6_locator) needs an IPv6 tail-end",
        ),
        (
            SRV6_REQUIRED_BY_TAIL,
            "Error: an IPv6 tail-end makes this an SRv6 policy, and the SR-TE CFP then requires "
            "the srv6 container",
        ),
        (
            SRV6_WHEN_EXPLICIT,
            "Error: an explicit path (path_type='explicit' / sid_list) is not allowed on an "
            "SRv6 policy or template",
        ),
        (SRV6_WHEN_BINDING_SID, "Error: binding_sid is not allowed on an SRv6 policy"),
        (
            SRV6_LOCATOR_NO_NAME,
            "Error: the srv6 locator container needs its mandatory locator-name",
        ),
    ],
)
async def test_create_sr_policy_service_srv6_cfp_refusals_are_explained(writes, response, expected):
    """The CFP's verified SRv6 verdicts (the pre-flight keeps the tool from sending those
    shapes; a newer CFP or cnc_provision_service can still meet them) map to the hints."""
    put = respx.put(SRV6_POLICY_URL).mock(return_value=response)
    plan = respx.get(SRV6_POLICY_PLAN_URL).mock(return_value=NO_CONTENT)
    text = await call_tool_text(writes, "cnc_create_sr_policy_service", SRV6_POLICY_ARGS)
    assert text.startswith(expected), text
    assert put.call_count == 1 and plan.call_count == 0


# --- cnc_update_sr_policy_service -----------------------------------------------------


@respx.mock
async def test_update_sr_policy_service_merges_bandwidth(writes):
    patch = respx.patch(f"{POLICY}=mcp-pol-91").mock(return_value=NO_CONTENT)
    plan = respx.get(f"{POLICY_PLAN}=mcp-pol-91").mock(
        return_value=httpx.Response(200, json=POLICY_PLAN_READY)
    )
    text = await call_tool_text(
        writes, "cnc_update_sr_policy_service", {"name": "mcp-pol-91", "bandwidth_kbps": 1000}
    )
    assert_yang_write(patch, "PATCH")
    assert sent(patch) == PATCH_BODY
    assert plan.call_count == 1
    assert text.startswith(
        "Updated SR policy service 'mcp-pol-91': NSO merged the given leaves and re-deployed (PATCH"
    )
    assert "-> 204" in text and "Plan: ready" in text


@respx.mock
async def test_update_sr_policy_service_both_leaves_and_dry_run(writes):
    patch = respx.patch(f"{POLICY}=mcp-pol-91").mock(
        return_value=httpx.Response(200, json=DRY_RUN_CREATE)
    )
    text = await call_tool_text(
        writes,
        "cnc_update_sr_policy_service",
        {"name": "mcp-pol-91", "bandwidth_kbps": 2000, "binding_sid": 15001, "dry_run": True},
    )
    assert_yang_write(patch, "PATCH", dry_run=True)
    assert sent(patch) == {
        "cisco-sr-te-cfp-sr-policies:policy": [
            {"name": "mcp-pol-91", "bandwidth": 2000, "binding-sid": 15001}
        ]
    }
    assert "NSO would push this to update SR policy service 'mcp-pol-91'" in text


@respx.mock
async def test_update_sr_policy_service_nothing_given_sends_nothing(writes):
    patch = respx.patch(f"{POLICY}=mcp-pol-91").mock(return_value=NO_CONTENT)
    text = await call_tool_text(writes, "cnc_update_sr_policy_service", {"name": "mcp-pol-91"})
    assert text.startswith("Error: Nothing to update: give bandwidth_kbps and/or binding_sid")
    assert patch.call_count == 0


@respx.mock
async def test_update_sr_policy_service_not_found_and_out_of_sync(writes):
    respx.patch(f"{POLICY}=mcp-pol-91").mock(return_value=NOT_FOUND)
    text = await call_tool_text(
        writes, "cnc_update_sr_policy_service", {"name": "mcp-pol-91", "bandwidth_kbps": 1}
    )
    assert text == "Error: no SR policy service 'mcp-pol-91' (names are exact and case-sensitive)."
    # The verified PATCH 404 ("patch to a nonexistent resource"): a PATCH never creates.
    respx.patch(f"{POLICY}=mcp-pol-91").mock(return_value=PATCH_NONEXISTENT)
    text = await call_tool_text(
        writes, "cnc_update_sr_policy_service", {"name": "mcp-pol-91", "bandwidth_kbps": 1}
    )
    assert text == "Error: no SR policy service 'mcp-pol-91' (names are exact and case-sensitive)."
    respx.patch(f"{POLICY}=mcp-pol-91").mock(return_value=OUT_OF_SYNC)
    text = await call_tool_text(
        writes, "cnc_update_sr_policy_service", {"name": "mcp-pol-91", "bandwidth_kbps": 1}
    )
    assert text.startswith("Error: NSO considers PE1 out of sync")


@respx.mock
async def test_update_sr_policy_service_on_an_srv6_policy_is_refused_by_the_cfp(writes):
    """bandwidth and binding-sid are when "not(../srv6)": a PATCH of either onto an SRv6
    policy gets the CFP's when-rule verdict, mapped to the same hint as the pre-flight."""
    patch = respx.patch(SRV6_POLICY_URL).mock(return_value=SRV6_WHEN_BANDWIDTH)
    text = await call_tool_text(
        writes,
        "cnc_update_sr_policy_service",
        {"name": SRV6_POLICY_NAME, "bandwidth_kbps": 1000},
    )
    assert patch.call_count == 1
    assert text.startswith(
        "Error: bandwidth_kbps is not allowed on an SRv6 policy or template (the model's when "
        '"not(../srv6)"'
    )
    respx.patch(SRV6_POLICY_URL).mock(return_value=SRV6_WHEN_BINDING_SID)
    text = await call_tool_text(
        writes, "cnc_update_sr_policy_service", {"name": SRV6_POLICY_NAME, "binding_sid": 15600}
    )
    assert text.startswith("Error: binding_sid is not allowed on an SRv6 policy or template")
    # The locator is not a PATCHable leaf of this tool: the "nothing to update" text says so.
    text = await call_tool_text(writes, "cnc_update_sr_policy_service", {"name": SRV6_POLICY_NAME})
    assert "or the SRv6 locator, re-create the service with cnc_create_sr_policy_service" in text


# --- cnc_delete_sr_policy_service -----------------------------------------------------


@respx.mock
async def test_delete_sr_policy_service(writes):
    delete = respx.delete(f"{POLICY}=mcp-pol-91").mock(return_value=NO_CONTENT)
    text = await call_tool_text(writes, "cnc_delete_sr_policy_service", {"name": "mcp-pol-91"})
    assert_yang_delete(delete)
    assert text.startswith("Deleted SR policy service 'mcp-pol-91': NSO removed it")
    assert "cnc_delete_sid_list" in text


@respx.mock
async def test_delete_sr_policy_service_dry_run_and_not_found(writes):
    delete = respx.delete(f"{POLICY}=mcp-pol-91").mock(
        return_value=httpx.Response(200, json=DRY_RUN_DELETE)
    )
    text = await call_tool_text(
        writes, "cnc_delete_sr_policy_service", {"name": "mcp-pol-91", "dry_run": True}
    )
    assert_yang_delete(delete, dry_run=True)
    assert "no policy srte_c_91_ep_10.0.0.3" in text
    respx.delete(f"{POLICY}=mcp-pol-91").mock(return_value=NOT_FOUND)
    text = await call_tool_text(writes, "cnc_delete_sr_policy_service", {"name": "mcp-pol-91"})
    assert text.startswith("Error: no SR policy service 'mcp-pol-91'")


# --- cnc_create_sid_list / cnc_delete_sid_list ------------------------------------------


@respx.mock
async def test_create_sid_list(writes):
    put = respx.put(f"{SID_LIST}=mcp-sl-1").mock(return_value=CREATED)
    plan = respx.get(f"{SID_LIST_PLAN}=mcp-sl-1").mock(return_value=NOT_FOUND)
    text = await call_tool_text(
        writes, "cnc_create_sid_list", {"name": "mcp-sl-1", "labels": "16003,16002"}
    )
    assert_yang_write(put, "PUT")
    assert sent(put) == SID_LIST_BODY
    assert plan.call_count == 1
    assert text.startswith("Created SID list 'mcp-sl-1': NSO committed the service (PUT")
    assert "Plan: not available yet" in text
    assert "cnc_create_sr_policy_service(path_type='explicit', sid_list='mcp-sl-1', ...)" in text


@respx.mock
async def test_create_sid_list_dry_run_no_change(writes):
    put = respx.put(f"{SID_LIST}=mcp-sl-1").mock(
        return_value=httpx.Response(201, json=DRY_RUN_NO_CHANGE)
    )
    text = await call_tool_text(
        writes,
        "cnc_create_sid_list",
        {"name": "mcp-sl-1", "labels": "16003,16002", "dry_run": True},
    )
    assert_yang_write(put, "PUT", dry_run=True)
    assert text.startswith("Dry run only — nothing was committed.")
    assert "No device changes" in text


@respx.mock
async def test_create_sid_list_bad_labels_send_nothing(writes):
    put = respx.put(f"{SID_LIST}=mcp-sl-1").mock(return_value=CREATED)
    text = await call_tool_text(
        writes, "cnc_create_sid_list", {"name": "mcp-sl-1", "labels": "16003,x"}
    )
    assert text.startswith("Error: labels: 'x' is not an MPLS label")
    assert put.call_count == 0


@respx.mock
async def test_delete_sid_list_still_referenced(writes):
    delete = respx.delete(f"{SID_LIST}=mcp-sl-1").mock(return_value=SID_LIST_REFERENCED)
    text = await call_tool_text(writes, "cnc_delete_sid_list", {"name": "mcp-sl-1"})
    assert_yang_delete(delete)
    assert text.startswith(
        "Error: SID list mcp-sl-1 is still referenced by a policy — delete the policy first "
        "(cnc_delete_sr_policy_service)"
    )


@respx.mock
async def test_delete_sid_list_ok_and_not_found(writes):
    respx.delete(f"{SID_LIST}=mcp-sl-1").mock(return_value=NO_CONTENT)
    text = await call_tool_text(writes, "cnc_delete_sid_list", {"name": "mcp-sl-1"})
    assert text.startswith("Deleted SID list 'mcp-sl-1'")
    respx.delete(f"{SID_LIST}=mcp-sl-1").mock(return_value=NOT_FOUND)
    text = await call_tool_text(writes, "cnc_delete_sid_list", {"name": "mcp-sl-1"})
    assert text == "Error: no SID list 'mcp-sl-1' (names are exact and case-sensitive)."


# --- cnc_create_l3vpn_service ---------------------------------------------------------


@respx.mock
async def test_create_l3vpn_service_verified_body(writes):
    put = respx.put(f"{L3VPN}=mcp-l3vpn-1").mock(return_value=CREATED)
    plan = respx.get(f"{L3VPN_PLAN}=mcp-l3vpn-1").mock(
        return_value=httpx.Response(200, json=L3VPN_PLAN_READY)
    )
    text = await call_tool_text(writes, "cnc_create_l3vpn_service", L3VPN_ARGS)
    assert_yang_write(put, "PUT")
    assert sent(put) == L3VPN_BODY
    assert plan.call_count == 1
    assert text.startswith("Created L3VPN service 'mcp-l3vpn-1': NSO committed the service")
    assert "Plan: ready" in text and "cnc_delete_vpn_service(layer='l3')" in text
    assert "cnc_get_vpn_service(vpn_id='mcp-l3vpn-1')" in text


@respx.mock
async def test_create_l3vpn_service_topology_and_profile(writes):
    put = respx.put(f"{L3VPN}=mcp-l3vpn-1").mock(return_value=NO_CONTENT)
    respx.get(f"{L3VPN_PLAN}=mcp-l3vpn-1").mock(return_value=NO_CONTENT)
    text = await call_tool_text(
        writes,
        "cnc_create_l3vpn_service",
        {**L3VPN_ARGS, "topology": "Hub_Spoke", "profile_id": "gold"},
    )
    service = sent(put)["ietf-l3vpn-ntw:vpn-service"][0]
    assert service["vpn-service-topology"] == "ietf-vpn-common:hub-spoke"
    assert service["vpn-instance-profiles"]["vpn-instance-profile"][0]["profile-id"] == "gold"
    node = service["vpn-nodes"]["vpn-node"][0]
    assert node["active-vpn-instance-profiles"]["vpn-instance-profile"] == [{"profile-id": "gold"}]
    assert text.startswith("Replaced L3VPN service 'mcp-l3vpn-1'")


@respx.mock
async def test_create_l3vpn_service_tsdn_validation_with_bgp_hint(writes):
    put = respx.put(f"{L3VPN}=mcp-l3vpn-1").mock(return_value=TSDN_415)
    text = await call_tool_text(writes, "cnc_create_l3vpn_service", {**L3VPN_ARGS, "dry_run": True})
    assert put.call_count == 1
    assert text == (
        "Error: the function pack rejected the service: BGP routing process is not configured "
        "on the device (TSDN-L3VPN-415) — the head-end has no BGP routing process: give "
        "local_as on its endpoints (the CFP then renders 'router bgp <as>' itself) or "
        "configure 'router bgp <asn>' on the device first."
    )


@respx.mock
async def test_create_l3vpn_service_other_tsdn_code_without_bgp_hint(writes):
    respx.put(f"{L3VPN}=mcp-l3vpn-1").mock(
        return_value=restconf_error(
            400,
            "malformed-message",
            "STATUS_CODE: TSDN-L3VPN-407\nREASON: Duplicate RD\nCATEGORY: validation",
        )
    )
    text = await call_tool_text(writes, "cnc_create_l3vpn_service", L3VPN_ARGS)
    assert text == "Error: the function pack rejected the service: Duplicate RD (TSDN-L3VPN-407)"


@respx.mock
async def test_create_l3vpn_service_unknown_element_and_head_end(writes):
    respx.put(f"{L3VPN}=mcp-l3vpn-1").mock(
        return_value=restconf_error(
            400, "unknown-element", "unknown element: static-addresses in /ietf-l3vpn-ntw:l3vpn-ntw"
        )
    )
    text = await call_tool_text(writes, "cnc_create_l3vpn_service", L3VPN_ARGS)
    assert text.startswith(
        "Error: the body has a node the model does not know: unknown element: static-addresses"
    )
    # An unknown endpoints[].node: the deviated L3NM's vpn-node-id leafref fails, and the
    # illegal-reference path ends in vpn-node{NOPE}/vpn-node-id (no head-end{...}/name here).
    respx.put(f"{L3VPN}=mcp-l3vpn-1").mock(return_value=BAD_VPN_NODE)
    text = await call_tool_text(
        writes,
        "cnc_create_l3vpn_service",
        {**L3VPN_ARGS, "endpoints": json.dumps([{**L3VPN_ENDPOINTS[0], "node": "NOPE"}])},
    )
    assert text.startswith(
        "Error: vpn-node 'NOPE' is not an NSO device (list NSO's devices with cnc_list_nso_devices"
    )
    assert "illegal reference" not in text


@respx.mock
@pytest.mark.parametrize(
    "args, fragment",
    [
        ({"endpoints": "{oops"}, "endpoints is not valid JSON"),
        (
            {"endpoints": '[{"node": "PE1"}]'},
            "missing required key(s) interface, address, prefix_length",
        ),
        (
            {
                "endpoints": (
                    '[{"node": "PE1", "interface": "Lo1", "address": "10.0.0.1", '
                    '"prefix_length": 30, "vlan": 5}]'
                )
            },
            "unknown key(s) vlan",
        ),
        ({"topology": "mesh"}, "Unknown topology 'mesh'"),
        # SRv6: typed locator names, one per node.
        ({"srv6_locator": "LOC 1"}, "srv6_locator 'LOC 1' must be an SRv6 locator name"),
        (
            {"endpoints": json.dumps([{**L3VPN_ENDPOINTS[0], "srv6_locator": "a" * 65}])},
            "endpoints[1].srv6_locator",
        ),
        (
            {
                "endpoints": json.dumps(
                    [
                        {**L3VPN_ENDPOINTS[0], "srv6_locator": "LOC1"},
                        {**L3VPN_ENDPOINTS[0], "interface": "Loopback92", "srv6_locator": "LOC2"},
                    ]
                )
            },
            "endpoints on node 'PE1' give different srv6_locator values ('LOC1' and 'LOC2')",
        ),
    ],
)
async def test_create_l3vpn_service_client_side_refusals(writes, args, fragment):
    put = respx.put(f"{L3VPN}=mcp-l3vpn-1").mock(return_value=CREATED)
    text = await call_tool_text(writes, "cnc_create_l3vpn_service", {**L3VPN_ARGS, **args})
    assert text.startswith("Error: ") and fragment in text
    assert put.call_count == 0


@respx.mock
async def test_create_l3vpn_service_srv6_service_wide_dry_run_renders_the_verified_cli(writes):
    """srv6_locator puts ``cisco-l3vpn-ntw:srv6 {address-family [{name ipv4, locator-name}]}``
    on the vpn-instance-profile (nothing on the nodes); the dry run renders the MPLS CLI plus
    ``segment-routing srv6 / locator LOC1 / alloc mode per-vrf`` under the BGP VRF
    address-family (verified 2026-09-15)."""
    put = respx.put(f"{L3VPN}=mcp-l3vpn-1").mock(
        return_value=httpx.Response(201, json=DRY_RUN_SRV6_L3VPN)
    )
    plan = respx.get(f"{L3VPN_PLAN}=mcp-l3vpn-1").mock(return_value=NO_CONTENT)
    text = await call_tool_text(
        writes, "cnc_create_l3vpn_service", {**SRV6_L3VPN_ARGS, "dry_run": True}
    )
    assert_yang_write(put, "PUT", dry_run=True)
    expected = json.loads(json.dumps(L3VPN_BODY))
    expected["ietf-l3vpn-ntw:vpn-service"][0]["vpn-instance-profiles"]["vpn-instance-profile"][0][
        "cisco-l3vpn-ntw:srv6"
    ] = L3VPN_SRV6_BLOCK
    assert sent(put) == expected
    assert plan.call_count == 0
    assert text.startswith("Dry run only — nothing was committed.")
    assert (
        "  address-family ipv4 unicast\n   segment-routing srv6\n    locator LOC1\n"
        "    alloc mode per-vrf\n" in text
    )


@respx.mock
async def test_create_l3vpn_service_srv6_node_override_and_committed_hint(writes):
    """An endpoint's srv6_locator lands on that node's active-vpn-instance-profile entry —
    the node entry wins on the CFP (verified: profile LOC1 + PE2 LOC2 -> PE1 LOC1, PE2 LOC2)."""
    put = respx.put(f"{L3VPN}=mcp-l3vpn-1").mock(return_value=CREATED)
    respx.get(f"{L3VPN_PLAN}=mcp-l3vpn-1").mock(
        return_value=httpx.Response(200, json=L3VPN_PLAN_READY)
    )
    endpoints = [
        L3VPN_ENDPOINTS[0],
        {**L3VPN_ENDPOINTS[0], "node": "PE2", "address": "10.91.2.1", "srv6_locator": "LOC2"},
    ]
    text = await call_tool_text(
        writes,
        "cnc_create_l3vpn_service",
        {**SRV6_L3VPN_ARGS, "endpoints": json.dumps(endpoints)},
    )
    service = sent(put)["ietf-l3vpn-ntw:vpn-service"][0]
    profile = service["vpn-instance-profiles"]["vpn-instance-profile"][0]
    assert profile["cisco-l3vpn-ntw:srv6"] == L3VPN_SRV6_BLOCK
    pe1, pe2 = service["vpn-nodes"]["vpn-node"]
    assert pe1["active-vpn-instance-profiles"]["vpn-instance-profile"] == [{"profile-id": "p1"}]
    assert pe2["active-vpn-instance-profiles"]["vpn-instance-profile"] == [
        {
            "profile-id": "p1",
            "cisco-l3vpn-ntw:srv6": {
                "address-family": [{"name": "ietf-vpn-common:ipv4", "locator-name": "LOC2"}]
            },
        }
    ]
    assert text.startswith("Created L3VPN service 'mcp-l3vpn-1'") and "Plan: ready" in text
    assert "Next: the VRF is bound to SRv6" in text and "NSO checked nothing" in text
    assert "cnc_delete_vpn_service(layer='l3')" in text
    # Node-level only (no service-wide locator): the profile stays plain, the hint still fires.
    text = await call_tool_text(
        writes,
        "cnc_create_l3vpn_service",
        {**L3VPN_ARGS, "endpoints": json.dumps([{**L3VPN_ENDPOINTS[0], "srv6_locator": "LOC1"}])},
    )
    service = sent(put)["ietf-l3vpn-ntw:vpn-service"][0]
    assert "cisco-l3vpn-ntw:srv6" not in service["vpn-instance-profiles"]["vpn-instance-profile"][0]
    node = service["vpn-nodes"]["vpn-node"][0]
    assert (
        node["active-vpn-instance-profiles"]["vpn-instance-profile"][0]["cisco-l3vpn-ntw:srv6"]
        == L3VPN_SRV6_BLOCK
    )
    assert "Next: the VRF is bound to SRv6" in text
    # The MPLS form keeps its MPLS hint.
    text = await call_tool_text(writes, "cnc_create_l3vpn_service", L3VPN_ARGS)
    assert sent(put) == L3VPN_BODY
    assert text.startswith("Created L3VPN service") and "bound to SRv6" not in text


@respx.mock
async def test_create_l3vpn_service_srv6_cfp_refusals_are_explained(writes):
    """The L3NM's verified SRv6 verdicts: an empty srv6 container (min-elements 1 on its
    address-family list) and the SR-TE-style flat locator-name (a plain unknown-element)."""
    put = respx.put(f"{L3VPN}=mcp-l3vpn-1").mock(return_value=L3NM_SRV6_EMPTY)
    text = await call_tool_text(writes, "cnc_create_l3vpn_service", SRV6_L3VPN_ARGS)
    assert put.call_count == 1
    assert text.startswith(
        "Error: the L3NM srv6 container needs at least one address-family entry "
        '({"address-family": [{"name": "ietf-vpn-common:ipv4", "locator-name": ...}]})'
    )
    respx.put(f"{L3VPN}=mcp-l3vpn-1").mock(return_value=L3NM_SRV6_FLAT)
    text = await call_tool_text(writes, "cnc_create_l3vpn_service", SRV6_L3VPN_ARGS)
    assert text.startswith(
        "Error: the body has a node the model does not know: unknown element: locator-name in"
    )


# --- cnc_delete_vpn_service -----------------------------------------------------------


@respx.mock
async def test_delete_vpn_service_l3_default_and_l2(writes):
    l3 = respx.delete(f"{L3VPN}=mcp-l3vpn-1").mock(return_value=NO_CONTENT)
    text = await call_tool_text(writes, "cnc_delete_vpn_service", {"vpn_id": "mcp-l3vpn-1"})
    assert_yang_delete(l3)
    assert text.startswith("Deleted L3VPN service 'mcp-l3vpn-1'")
    l2 = respx.delete(f"{L2VPN}=mcp-l2vpn-1").mock(return_value=NO_CONTENT)
    text = await call_tool_text(
        writes, "cnc_delete_vpn_service", {"vpn_id": "mcp-l2vpn-1", "layer": "L2"}
    )
    assert_yang_delete(l2)
    assert text.startswith("Deleted L2VPN service 'mcp-l2vpn-1'")


@respx.mock
async def test_delete_vpn_service_not_found_bad_layer_and_dry_run(writes):
    respx.delete(f"{L3VPN}=mcp-l3vpn-1").mock(return_value=NOT_FOUND)
    text = await call_tool_text(writes, "cnc_delete_vpn_service", {"vpn_id": "mcp-l3vpn-1"})
    assert text == "Error: no L3VPN service 'mcp-l3vpn-1' (names are exact and case-sensitive)."
    delete = respx.delete(f"{L2VPN}=x").mock(return_value=NO_CONTENT)
    text = await call_tool_text(writes, "cnc_delete_vpn_service", {"vpn_id": "x", "layer": "l4"})
    assert text.startswith("Error: Unknown layer 'l4'. Use one of: l3, l2.")
    assert delete.call_count == 0
    delete = respx.delete(f"{L3VPN}=mcp-l3vpn-1").mock(
        return_value=httpx.Response(200, json=DRY_RUN_DELETE)
    )
    text = await call_tool_text(
        writes, "cnc_delete_vpn_service", {"vpn_id": "mcp-l3vpn-1", "dry_run": True}
    )
    assert_yang_delete(delete, dry_run=True)
    assert text.startswith("Dry run only")


# --- cnc_provision_service / cnc_delete_service -----------------------------------------


@respx.mock
async def test_provision_service_put_with_prefix_normalisation(writes):
    put = respx.put(f"{CS_POLICY}=mcp-cs-1").mock(return_value=CREATED)
    plan = respx.get(f"{CS_POLICY_PLAN}=mcp-cs-1").mock(return_value=NOT_FOUND)
    text = await call_tool_text(
        writes,
        "cnc_provision_service",
        {
            "yang_path": (
                "/crosswork/proxy/nso/restconf/data/cisco-cs-sr-te-cfp:cs-sr-te-policy=mcp-cs-1"
            ),
            "body_json": json.dumps(CS_BODY),
        },
    )
    assert_yang_write(put, "PUT")
    assert sent(put) == CS_BODY
    assert plan.call_count == 1
    assert text.startswith("Created cs-sr-te-policy service 'mcp-cs-1': NSO committed the service")
    assert "Plan: not available yet" in text
    assert "cnc_delete_service(yang_path='cisco-cs-sr-te-cfp:cs-sr-te-policy=mcp-cs-1')" in text


@respx.mock
async def test_provision_service_patch_and_dry_run(writes):
    patch = respx.patch(f"{L3VPN}=mcp-l3vpn-1").mock(
        return_value=httpx.Response(200, json=DRY_RUN_CREATE)
    )
    body = {
        "ietf-l3vpn-ntw:vpn-service": [
            {"vpn-id": "mcp-l3vpn-1", "vpn-service-topology": "ietf-vpn-common:hub-spoke"}
        ]
    }
    text = await call_tool_text(
        writes,
        "cnc_provision_service",
        {
            "yang_path": "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=mcp-l3vpn-1",
            "body_json": json.dumps(body),
            "method": "PATCH",
            "dry_run": True,
        },
    )
    assert_yang_write(patch, "PATCH", dry_run=True)
    assert sent(patch) == body
    assert "NSO would push this to update vpn-service 'mcp-l3vpn-1'" in text


@respx.mock
async def test_provision_service_committed_patch_reads_the_plan(writes):
    patch = respx.patch(f"{L3VPN}=mcp-l3vpn-1").mock(return_value=NO_CONTENT)
    plan = respx.get(f"{L3VPN_PLAN}=mcp-l3vpn-1").mock(
        return_value=httpx.Response(200, json=L3VPN_PLAN_READY)
    )
    text = await call_tool_text(
        writes,
        "cnc_provision_service",
        {
            "yang_path": "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=mcp-l3vpn-1",
            "body_json": json.dumps({"ietf-l3vpn-ntw:vpn-service": [{"vpn-id": "mcp-l3vpn-1"}]}),
            "method": "patch",
        },
    )
    assert patch.call_count == 1 and plan.call_count == 1
    assert text.startswith("Updated vpn-service 'mcp-l3vpn-1'")
    assert "Plan: ready" in text


@respx.mock
@pytest.mark.parametrize(
    "args, fragment",
    [
        ({"body_json": "nope"}, "body_json is not valid JSON"),
        ({"body_json": '{"cs-sr-te-policy": [{}]}'}, "must be module-prefixed"),
        (
            {"body_json": '{"cisco-cs-sr-te-cfp:cs-sr-te-policy": {}}'},
            "list holding exactly one object",
        ),
        (
            {"body_json": '{"cisco-cs-sr-te-cfp:policy": [{}]}'},
            "does not match the list the yang_path addresses",
        ),
        (
            {"yang_path": "cisco-cs-sr-te-cfp:cs-sr-te-policy=x?dry-run=native"},
            "must be a bare data path",
        ),
        ({"yang_path": "/"}, "yang_path is empty"),
        ({"method": "post"}, "Unknown method 'post'"),
    ],
)
async def test_provision_service_client_side_refusals(writes, args, fragment):
    put = respx.put(f"{CS_POLICY}=mcp-cs-1").mock(return_value=CREATED)
    text = await call_tool_text(
        writes,
        "cnc_provision_service",
        {
            "yang_path": "cisco-cs-sr-te-cfp:cs-sr-te-policy=mcp-cs-1",
            "body_json": json.dumps(CS_BODY),
            **args,
        },
    )
    assert text.startswith("Error: ") and fragment in text
    assert put.call_count == 0


@respx.mock
async def test_provision_service_verified_errors_apply(writes):
    respx.put(f"{CS_POLICY}=mcp-cs-1").mock(return_value=OUT_OF_SYNC)
    text = await call_tool_text(
        writes,
        "cnc_provision_service",
        {
            "yang_path": "cisco-cs-sr-te-cfp:cs-sr-te-policy=mcp-cs-1",
            "body_json": json.dumps(CS_BODY),
        },
    )
    assert text.startswith("Error: NSO considers PE1 out of sync")


@respx.mock
async def test_provision_service_srv6_rules_apply_to_hand_built_bodies(writes):
    """The escape hatch is where the CFP's SRv6 verdicts actually reach an agent (the dedicated
    tools refuse those shapes before sending): an ODN template with an IPv6 source-address and
    no srv6 container (verified c6), and a policy with srv6 beside an IPv4 tail-end (a1)."""
    odn_body = json.loads(json.dumps(ODN_BODY))
    odn_body["cisco-sr-te-cfp-sr-odn:odn-template"][0]["source-address"] = "2001:db8::1"
    put = respx.put(f"{ODN_TEMPLATES}=mcp-odn-90").mock(
        return_value=odn_cfp_error(
            "invalid-value",
            " : SRv6 TE policy must be configured if source-address is IPv6 address",
            name="mcp-odn-90",
        )
    )
    text = await call_tool_text(
        writes,
        "cnc_provision_service",
        {
            "yang_path": (
                "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/"
                "cisco-sr-te-cfp-sr-odn:odn-template=mcp-odn-90"
            ),
            "body_json": json.dumps(odn_body),
            "dry_run": True,
        },
    )
    assert put.call_count == 1
    assert text.startswith(
        "Error: an IPv6 source-address makes this an SRv6 ODN template, and the SR-TE CFP then "
        "requires the srv6 container ('SRv6 TE policy must be configured if source-address is "
        "IPv6 address'): give srv6_locator"
    )
    policy_body = json.loads(json.dumps(POLICY_BODY))
    policy_body["cisco-sr-te-cfp-sr-policies:policy"][0]["srv6"] = SRV6_BLOCK
    respx.put(f"{POLICY}=mcp-pol-91").mock(
        return_value=policy_cfp_error(
            "invalid-value",
            " : tail-end must be IPv6 address for SRv6 TE policy",
            name="mcp-pol-91",
        )
    )
    text = await call_tool_text(
        writes,
        "cnc_provision_service",
        {
            "yang_path": (
                "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/"
                "cisco-sr-te-cfp-sr-policies:policy=mcp-pol-91"
            ),
            "body_json": json.dumps(policy_body),
            "dry_run": True,
        },
    )
    assert text.startswith(
        "Error: an SRv6 policy (the srv6 container / srv6_locator) needs an IPv6 tail-end"
    )


@respx.mock
@pytest.mark.parametrize("method", ["put", "patch"])
async def test_provision_service_refuses_an_unkeyed_path(writes, method):
    """A PUT to the bare list would replace every entry of it in one commit: refused before
    anything is sent, exactly like cnc_delete_service refuses to delete a whole list."""
    put = respx.put(f"{DATA}/cisco-cs-sr-te-cfp:cs-sr-te-policy").mock(return_value=NO_CONTENT)
    patch = respx.patch(f"{DATA}/cisco-cs-sr-te-cfp:cs-sr-te-policy").mock(return_value=NO_CONTENT)
    text = await call_tool_text(
        writes,
        "cnc_provision_service",
        {
            "yang_path": "data/cisco-cs-sr-te-cfp:cs-sr-te-policy/",
            "body_json": json.dumps(CS_BODY),
            "method": method,
        },
    )
    assert text.startswith(
        "Error: yang_path 'cisco-cs-sr-te-cfp:cs-sr-te-policy' has no key: this tool writes one "
        "service entry ('<list>=<key>'), never a whole list"
    )
    assert put.call_count == 0 and patch.call_count == 0


@respx.mock
async def test_delete_service_dry_run(writes):
    delete = respx.delete(f"{CS_POLICY}=mcp-cs-1").mock(
        return_value=httpx.Response(200, json=DRY_RUN_DELETE)
    )
    text = await call_tool_text(
        writes,
        "cnc_delete_service",
        {"yang_path": "cisco-cs-sr-te-cfp:cs-sr-te-policy=mcp-cs-1", "dry_run": True},
    )
    assert_yang_delete(delete, dry_run=True)
    assert text.startswith(
        "Dry run only — nothing was committed. NSO would push this to delete cs-sr-te-policy "
        "service 'mcp-cs-1':"
    )
    assert "no policy srte_c_91_ep_10.0.0.3" in text


@respx.mock
async def test_delete_service(writes):
    delete = respx.delete(f"{CS_POLICY}=mcp-cs-1").mock(return_value=NO_CONTENT)
    text = await call_tool_text(
        writes,
        "cnc_delete_service",
        {"yang_path": "data/cisco-cs-sr-te-cfp:cs-sr-te-policy=mcp-cs-1"},
    )
    assert_yang_delete(delete)
    assert text.startswith("Deleted cs-sr-te-policy service 'mcp-cs-1': NSO removed it")


@respx.mock
async def test_delete_service_refusals_and_errors(writes):
    delete = respx.delete(f"{DATA}/cisco-cs-sr-te-cfp:cs-sr-te-policy").mock(
        return_value=NO_CONTENT
    )
    text = await call_tool_text(
        writes, "cnc_delete_service", {"yang_path": "cisco-cs-sr-te-cfp:cs-sr-te-policy"}
    )
    assert text.startswith("Error: yang_path 'cisco-cs-sr-te-cfp:cs-sr-te-policy' has no key")
    assert delete.call_count == 0
    respx.delete(f"{CS_POLICY}=mcp-cs-1").mock(return_value=NOT_FOUND)
    text = await call_tool_text(
        writes, "cnc_delete_service", {"yang_path": "cisco-cs-sr-te-cfp:cs-sr-te-policy=mcp-cs-1"}
    )
    assert (
        text == "Error: no cs-sr-te-policy service 'mcp-cs-1' (names are exact and case-sensitive)."
    )
    respx.delete(f"{SID_LIST}=mcp-sl-1").mock(return_value=SID_LIST_REFERENCED)
    text = await call_tool_text(
        writes,
        "cnc_delete_service",
        {
            "yang_path": (
                "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/"
                "cisco-sr-te-cfp-sr-policies:sid-list=mcp-sl-1"
            )
        },
    )
    assert text.startswith("Error: SID list mcp-sl-1 is still referenced by a policy")


# --- retry behaviour on the wire -----------------------------------------------------


@respx.mock
async def test_patch_is_sent_once_on_503(writes_retrying):
    route = respx.patch(f"{POLICY}=mcp-pol-91").mock(return_value=httpx.Response(503, text="busy"))
    text = await call_tool_text(
        writes_retrying, "cnc_update_sr_policy_service", {"name": "mcp-pol-91", "bandwidth_kbps": 1}
    )
    assert route.call_count == 1
    assert text.startswith("Error: API request failed with status 503")


@respx.mock
async def test_put_and_delete_keep_the_idempotent_retry_default(writes_retrying):
    put = respx.put(f"{SID_LIST}=mcp-sl-1").mock(return_value=httpx.Response(503, text="busy"))
    text = await call_tool_text(
        writes_retrying, "cnc_create_sid_list", {"name": "mcp-sl-1", "labels": "16003"}
    )
    assert put.call_count == 4 and text.startswith("Error: API request failed with status 503")
    delete = respx.delete(f"{SID_LIST}=mcp-sl-1").mock(
        return_value=httpx.Response(503, text="busy")
    )
    text = await call_tool_text(writes_retrying, "cnc_delete_sid_list", {"name": "mcp-sl-1"})
    assert delete.call_count == 4 and text.startswith("Error: API request failed with status 503")


@respx.mock
async def test_out_of_sync_502_is_retried_on_put_and_delete_but_not_patch(writes_retrying):
    """The cost of keeping the idempotent default: NSO's out-of-sync answer is a 502, so a
    PUT/DELETE against an out-of-sync head-end is re-attempted max_retries more times (four
    commit attempts at the default of 3, each failing identically) before the precise text
    is reported. PATCH is sent once."""
    put = respx.put(f"{ODN_TEMPLATES}=mcp-odn-90").mock(return_value=OUT_OF_SYNC)
    text = await call_tool_text(writes_retrying, "cnc_create_odn_template", ODN_ARGS)
    assert put.call_count == 4
    assert text == (
        "Error: NSO considers PE1 out of sync — run cnc_nso_device_action(action='sync-from', "
        "host_name='PE1') then retry."
    )
    delete = respx.delete(f"{ODN_TEMPLATES}=mcp-odn-90").mock(return_value=OUT_OF_SYNC)
    text = await call_tool_text(writes_retrying, "cnc_delete_odn_template", {"name": "mcp-odn-90"})
    assert delete.call_count == 4 and text.startswith("Error: NSO considers PE1 out of sync")
    patch = respx.patch(f"{POLICY}=mcp-pol-91").mock(return_value=OUT_OF_SYNC)
    text = await call_tool_text(
        writes_retrying, "cnc_update_sr_policy_service", {"name": "mcp-pol-91", "bandwidth_kbps": 1}
    )
    assert patch.call_count == 1 and text.startswith("Error: NSO considers PE1 out of sync")


@respx.mock
async def test_resync_post_is_sent_once_on_503(writes_retrying):
    route = respx.post(f"{CONNECTOR}/fullResync").mock(
        return_value=httpx.Response(503, text="busy")
    )
    text = await call_tool_text(writes_retrying, "cnc_resync_service_inventory", {})
    assert route.call_count == 1
    assert text.startswith("Error: API request failed with status 503")


# --- cnc_resync_service_inventory -----------------------------------------------------


@respx.mock
async def test_resync_full(writes):
    route = respx.post(f"{CONNECTOR}/fullResync").mock(
        return_value=httpx.Response(200, json=RESYNC_OK)
    )
    text = await call_tool_text(writes, "cnc_resync_service_inventory", {})
    request = request_of(route)
    assert dict(request.url.params) == {"force": "false"}
    assert not request.content
    assert request.headers["Accept"] == "application/json"
    data = json.loads(text)
    assert data["scope"] == "full" and data["force"] is False
    assert data["sync_status"] == "SUCCESS" and data["status"] == "OK"
    assert data["description"].startswith("Succeeded, full sync")
    assert data["note"].startswith("unverified live")


@respx.mock
async def test_resync_type_with_force_and_label_alias(writes):
    route = respx.post(f"{CONNECTOR}/typeResync").mock(
        return_value=httpx.Response(200, json=RESYNC_OK)
    )
    text = await call_tool_text(
        writes, "cnc_resync_service_inventory", {"service_type": "l2vpn", "force": True}
    )
    assert dict(request_of(route).url.params) == {
        "typePath": "ietf-l2vpn-ntw:l2vpn-ntw/vpn-services/vpn-service",
        "force": "true",
    }
    data = json.loads(text)
    assert data["scope"] == "type" and data["force"] is True
    assert data["type_path"] == "ietf-l2vpn-ntw:l2vpn-ntw/vpn-services/vpn-service"


@respx.mock
async def test_resync_service_parses_a_string_typed_reply(writes):
    reply = {
        "syncResponse": {
            "syncDescription": (
                "Succeeded, service sync was executed in the background for type= "
                "ietf-l2vpn-ntw:l2vpn-ntw/vpn-services/vpn-service, and serviceName= "
                "L2VPN_NM-ELAN-270"
            ),
            "syncStatus": "SUCCESS",
        },
        "status": "OK",
    }
    route = respx.post(f"{CONNECTOR}/serviceResync").mock(
        return_value=httpx.Response(
            200, json=json.dumps(reply)
        )  # the document types it as a string
    )
    text = await call_tool_text(
        writes,
        "cnc_resync_service_inventory",
        {
            "service_type": "{urn:ietf:params:xml:ns:yang:ietf-l2vpn-ntw}vpn-service",
            "service_name": "L2VPN_NM-ELAN-270",
        },
    )
    assert dict(request_of(route).url.params) == {
        "typePath": "ietf-l2vpn-ntw:l2vpn-ntw/vpn-services/vpn-service",
        "serviceName": "L2VPN_NM-ELAN-270",
    }
    data = json.loads(text)
    assert data["scope"] == "service" and data["service_name"] == "L2VPN_NM-ELAN-270"
    assert "force" not in data
    assert data["sync_status"] == "SUCCESS"


@respx.mock
async def test_resync_failure_status_is_an_error(writes):
    respx.post(f"{CONNECTOR}/fullResync").mock(
        return_value=httpx.Response(
            200,
            json={
                "syncResponse": {"syncDescription": "NSO unreachable", "syncStatus": "FAILED"},
                "status": "OK",
            },
        )
    )
    text = await call_tool_text(writes, "cnc_resync_service_inventory", {})
    assert text == "Error: the NSO-connector reported FAILED: NSO unreachable"


@respx.mock
async def test_resync_client_side_refusals_send_nothing(writes):
    full = respx.post(f"{CONNECTOR}/fullResync").mock(
        return_value=httpx.Response(200, json=RESYNC_OK)
    )
    kind = respx.post(f"{CONNECTOR}/typeResync").mock(
        return_value=httpx.Response(200, json=RESYNC_OK)
    )
    text = await call_tool_text(writes, "cnc_resync_service_inventory", {"service_name": "x"})
    assert text.startswith("Error: service_name needs service_type")
    text = await call_tool_text(writes, "cnc_resync_service_inventory", {"service_type": "widgets"})
    assert text.startswith("Error: Unknown service_type 'widgets'")
    assert full.call_count == 0 and kind.call_count == 0


@respx.mock
async def test_resync_unrouted_404_is_an_api_error(writes):
    respx.post(f"{CONNECTOR}/fullResync").mock(
        return_value=httpx.Response(404, json={"path": "/crosswork/sso/login/x", "status": 404})
    )
    text = await call_tool_text(writes, "cnc_resync_service_inventory", {})
    assert text.startswith("Error: API request failed with status 404. This path is not routed")
