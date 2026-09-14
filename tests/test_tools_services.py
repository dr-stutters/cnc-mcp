"""Service inventory tools end-to-end through MCPServer (schema validation included).

The module is registered directly (not through build_server) so the test does
not depend on tools/__init__.py's module list. All HTTP is mocked with respx.
Fixtures mirror the shapes verified live on Crosswork 7.2 (2026-09-13, see the
platform notes): the CAT RPC envelopes (``cat-inventory-rpc:input`` /
``cat-inventory-rpc:output`` with an unprefixed ``<rpc>-response`` key), the
``get-all-services`` answer with and without ``collection-data``, plan data
found / ``unknown``, the empty ``{"cat-inventory-rpc:output": {}}``
association, the CAT NBI's ``409 data-missing`` (bare ``errors`` key), the NSO
proxy's ``404 ietf-restconf:errors``, an ODN template object and its nano
plan, and the function-pack deployment manager's plain-JSON answers. The VPN
operational-data fixtures are Cisco's own capture of the CAT GET (the
service-inventory example of the CNC API examples): ``vpn-id``, ``status``
and the discovered underlay only — no topology, no nodes.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from mcp.server.mcpserver import MCPServer

from cnc_mcp import polling
from cnc_mcp.auth import StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.config import Settings
from cnc_mcp.errors import PlatformError
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import services
from cnc_mcp.tools.services import (
    PLAN_LIST_OF,
    SERVICE_TYPE_LABELS,
    SERVICE_TYPES,
    cat_rpc_body,
    cat_rpc_response,
    host_name_query,
    is_plan_path,
    looks_like_ip_address,
    nodes_with_host_name,
    normalize_plan_status,
    normalize_yang_path,
    nso_node_id_of,
    per_node_bookkeeping,
    plan_data_lines,
    plan_not_found,
    plan_path_of,
    resolve_plan_path,
    service_path_of,
    service_type_label,
    service_type_qname,
    te_router_id_of,
    te_router_id_query,
    transport_ref,
    vpn_service_line,
)
from tests.conftest import BASE_URL, call_tool_text

CAT = f"{BASE_URL}/crosswork/nbi/cat-inventory/v1/restconf"
CAT_RPC = f"{CAT}/operations/cat-inventory-rpc"
CAT_DATA = f"{CAT}/data"
NSO_DATA = f"{BASE_URL}/crosswork/proxy/nso/restconf/data"
FP = f"{BASE_URL}/crosswork/cat/cat-fp-deployment-manager-service/v1/twophasecommitrunner"
NODES_QUERY_URL = f"{BASE_URL}/crosswork/inventory/v1/nodes/query"
YANG_JSON = "application/yang-data+json"

ODN_QNAME = "{http://cisco.com/ns/nso/cfp/cisco-tsdn-sr-te-sr-odn}odn-template"
POLICY_QNAME = "{http://cisco.com/ns/nso/cfp/cisco-ts-sr-policies}policy"
L3VPN_QNAME = "{urn:ietf:params:xml:ns:yang:ietf-l3vpn-ntw}vpn-service"
ODN_PATH = "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/odn-template=mcp-odn-90"
ODN_PLAN_PATH = "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/odn-template-plan=mcp-odn-90"
ODN_LIST_PATH = "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/odn-template"
CS_PATH = "cisco-cs-sr-te-cfp:cs-sr-te-policy=cs1"
CS_PLAN_PATH = "cisco-cs-sr-te-cfp:cs-sr-te-plan=cs1"  # the FP-documented plan list (YANG l.651)
L3VPN_PATH = "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=mcp-l3vpn-91"
L3VPN_LIST_URL = f"{CAT_DATA}/ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service"
L2VPN_LIST_URL = f"{CAT_DATA}/ietf-l2vpn-ntw:l2vpn-ntw/vpn-services/vpn-service"
# Service list -> plan list, as the FP deployment manager's packagesInfo documents them
# (and as the CFP YANG defines them); only the first two follow the <list>-plan rule.
FP_PLAN_LISTS = {
    "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/policy": (
        "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/policy-plan"
    ),
    ODN_LIST_PATH: f"{ODN_LIST_PATH}-plan",
    "cisco-cs-sr-te-cfp:cs-sr-te-policy": "cisco-cs-sr-te-cfp:cs-sr-te-plan",
    "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service": (
        "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/cisco-l3vpn-ntw:vpn-service-plan"
    ),
    "ietf-l2vpn-ntw:l2vpn-ntw/vpn-services/vpn-service": (
        "ietf-l2vpn-ntw:l2vpn-ntw/vpn-services/cisco-l2vpn-ntw:vpn-service-plan"
    ),
    "ietf-network-slice-service:network-slice-services/slice-service": (
        "ietf-network-slice-service:network-slice-services/"
        "cisco-network-slice-service:slice-service-plan"
    ),
    "ietf-te:te/tunnels/tunnel": "ietf-te:te/tunnels/cisco-te:tunnel-plan",
}


def rpc_url(rpc: str) -> str:
    return f"{CAT_RPC}:{rpc}"


def output(rpc: str, response: dict) -> dict:
    """The verified CAT answer: ``cat-inventory-rpc:output`` with an UNPREFIXED response key."""
    return {"cat-inventory-rpc:output": {f"{rpc}-response": response}}


# Verified: the 7 types of a 7.2 instance (QName + label).
SERVICE_TYPES_RESPONSE = output(
    "get-available-service-types",
    {
        "service-type-info": [
            {"service-type": POLICY_QNAME, "service-type-label": "policy"},
            {"service-type": ODN_QNAME, "service-type-label": "odn-template"},
            {
                "service-type": "{http://cisco.com/ns/nso/cfp/cisco-cs-sr-te-cfp}cs-sr-te-policy",
                "service-type-label": "cs-sr-te-policy",
            },
            {"service-type": L3VPN_QNAME, "service-type-label": "vpn-service"},
            {
                "service-type": "{urn:ietf:params:xml:ns:yang:ietf-l2vpn-ntw}vpn-service",
                "service-type-label": "vpn-service",
            },
            {
                "service-type": (
                    "{urn:ietf:params:xml:ns:yang:ietf-network-slice-service}slice-service"
                ),
                "service-type-label": "slice-service",
            },
            {
                "service-type": "{urn:ietf:params:xml:ns:yang:ietf-te}tunnel",
                "service-type-label": "tunnel",
            },
        ]
    },
)
# Verified: count is an int on the wire. Only the populated type here (the renderer must
# cope with an answer that omits the zero types, although the live RPC lists them).
COUNTS_ONE = output(
    "get-services-count",
    {
        "services-count-per-type": [{"service-type": ODN_QNAME, "count": 1}],
        "total-services-count": 1,
    },
)
# A tolerated shape: no per-type list at all.
COUNTS_ZERO = output("get-services-count", {"total-services-count": 0})
# Verified live 2026-09-14 on the empty lab inventory: EVERY type is listed at count 0.
COUNTS_ZERO_ALL_TYPES = output(
    "get-services-count",
    {
        "services-count-per-type": [
            {"service-type": info["service-type"], "count": 0}
            for info in SERVICE_TYPES_RESPONSE["cat-inventory-rpc:output"][
                "get-available-service-types-response"
            ]["service-type-info"]
        ],
        "total-services-count": 0,
    },
)
# The same shape with one populated type (the zero rows fold into one line).
COUNTS_MIXED = output(
    "get-services-count",
    {
        "services-count-per-type": [
            {"service-type": e["service-type"], "count": 2 if e["service-type"] == ODN_QNAME else 0}
            for e in COUNTS_ZERO_ALL_TYPES["cat-inventory-rpc:output"][
                "get-services-count-response"
            ]["services-count-per-type"]
        ],
        "total-services-count": 2,
    },
)
ODN_INFO = {
    "service-name": "mcp-odn-90",
    "service-type": ODN_QNAME,
    "yang-path": ODN_PATH,
    "plan-yang-path": ODN_PLAN_PATH,
}
ALL_SERVICES = output(
    "get-all-services",
    {
        "collection-data": {"service-info": [ODN_INFO]},
        "collection-header": {"offset": 0, "count": 1},
    },
)
# Verified: no match -> NO collection-data, just the header with count 0.
NO_SERVICES = output("get-all-services", {"collection-header": {"offset": 0, "count": 0}})
PLAN_COMPLETED = output(
    "get-service-plan-data",
    {
        "service-plan-data": [
            {
                "yang-path": ODN_PLAN_PATH,
                "status": "completed",
                "creation-time": "2026-09-13T10:15:02.000+00:00",
                "last-updated-time": "2026-09-13T10:15:04.000+00:00",
            }
        ]
    },
)
PLAN_IN_PROGRESS = output(
    "get-service-plan-data",
    {
        "service-plan-data": [
            {
                "yang-path": ODN_PLAN_PATH,
                "status": "in-progress",
                "creation-time": "2026-09-13T10:15:02.000+00:00",
                "last-updated-time": "2026-09-13T10:15:02.000+00:00",
            }
        ]
    },
)
PLAN_FAILED = output(
    "get-service-plan-data",
    {
        "service-plan-data": [
            {
                "yang-path": ODN_PLAN_PATH,
                "status": "failed",
                "creation-time": "2026-09-13T10:15:02.000+00:00",
                "last-updated-time": "2026-09-13T10:15:09.000+00:00",
                "error-info": {"message": "Network Element Driver: device PE1: out of sync"},
            }
        ]
    },
)
# Verified: an unknown plan path is HTTP 200 with status unknown (not an error).
PLAN_UNKNOWN = output(
    "get-service-plan-data",
    {
        "service-plan-data": [
            {
                "yang-path": ODN_PLAN_PATH,
                "status": "unknown",
                "error-info": {"message": "service plan data not found"},
            }
        ]
    },
)
# Verified: an empty association is just the output container.
EMPTY_OUTPUT: dict = {"cat-inventory-rpc:output": {}}
SUB_COUNT_ZERO = output("get-sub-service-count", {"sub-service-count": 0})
SUB_PATHS_EMPTY = output("get-sub-service-paths", {"collection-header": {"offset": 0, "count": 0}})
SUB_COUNT_TWO = output("get-sub-service-count", {"sub-service-count": 2})
SUB_PATHS_TWO = output(
    "get-sub-service-paths",
    {
        "collection-header": {"offset": 0, "count": 2},
        "sub-service-path": [
            "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=mcp-l3vpn-91/vpn-nodes/vpn-node=PE1",
            "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=mcp-l3vpn-91/vpn-nodes/vpn-node=PE2",
        ],
    },
)
SERVICES_ON_TRANSPORT = output(
    "get-associated-services-for-transport", {"service-path": [L3VPN_PATH]}
)

# Verified: the ODN template as the proxy returns it (NSO bookkeeping + the CFP body).
ODN_TEMPLATE = {
    "cisco-sr-te-cfp-sr-odn:odn-template": [
        {
            "name": "mcp-odn-90",
            "modified": {"devices": ["PE1"], "services": []},
            "directly-modified": {"devices": ["PE1"], "services": []},
            "plan-location": "/cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/odn-template-plan",
            "created": "2026-09-13T10:15:02.145+00:00",
            "last-modified": "2026-09-13T10:15:02.145+00:00",
            "last-run": "2026-09-13T10:15:02.145+00:00",
            "head-end": [{"name": "PE1"}],
            "color": 90,
            "dynamic": {"metric-type": "igp", "pce": {}},
        }
    ]
}
# Verified: the nano plan of the ODN template.
ODN_PLAN = {
    "cisco-sr-te-cfp-sr-odn:odn-template-plan": [
        {
            "name": "mcp-odn-90",
            "plan": {
                "component": [
                    {
                        "type": "tailf-ncs:self",
                        "name": "self",
                        "state": [
                            {
                                "name": "tailf-ncs:init",
                                "status": "reached",
                                "when": "2026-09-13T10:15:02.145+00:00",
                            },
                            {
                                "name": "tailf-ncs:ready",
                                "status": "reached",
                                "when": "2026-09-13T10:15:04.021+00:00",
                            },
                        ],
                        "back-track": False,
                    },
                    {
                        "type": "cisco-sr-te-cfp-sr-odn-nano-plan-services:head-end",
                        "name": "PE1",
                        "state": [
                            {
                                "name": "tailf-ncs:init",
                                "status": "reached",
                                "when": "2026-09-13T10:15:02.145+00:00",
                            },
                            {
                                "name": "tailf-ncs:ready",
                                "status": "reached",
                                "when": "2026-09-13T10:15:04.021+00:00",
                            },
                        ],
                        "back-track": False,
                    },
                ]
            },
        }
    ]
}
# A circuit-style policy as the proxy would return it (the list is top-level in the module).
CS_POLICY = {"cisco-cs-sr-te-cfp:cs-sr-te-policy": [{"name": "cs1", "color": 5}]}
CS_PLAN_COMPLETED = output(
    "get-service-plan-data",
    {
        "service-plan-data": [
            {
                "yang-path": CS_PLAN_PATH,
                "status": "completed",
                "creation-time": "2026-09-13T12:00:00.000+00:00",
                "last-updated-time": "2026-09-13T12:00:03.000+00:00",
            }
        ]
    },
)
# Two entries, as an UNKEYED list GET on the proxy answers.
ODN_TEMPLATES_TWO = {
    "cisco-sr-te-cfp-sr-odn:odn-template": [{"name": "a", "color": 1}, {"name": "b", "color": 2}]
}
# Verified: a missing keyed entry on the proxy answers 404 WITH a RESTCONF document.
PROXY_404 = httpx.Response(
    404,
    json={
        "ietf-restconf:errors": {
            "error": [
                {
                    "error-type": "application",
                    "error-tag": "invalid-value",
                    "error-message": "uri keypath not found",
                }
            ]
        }
    },
)
# Verified: the CAT NBI's not-found (and its "no VPN services at all") answer — bare ``errors``.
DATA_MISSING_409 = httpx.Response(
    409,
    json={
        "errors": {
            "error": [
                {
                    "error-type": "application",
                    "error-tag": "data-missing",
                    "error-message": "Data does not exist",
                }
            ]
        }
    },
)
# Verified: the CAT RPCs reject a non-numeric limit / a filter on get-services-count.
MALFORMED_400 = httpx.Response(
    400,
    json={
        "errors": {
            "error": [
                {
                    "error-type": "protocol",
                    "error-tag": "malformed-message",
                    "error-message": (
                        "Schema node with name service-type-filters was not found under "
                        "(urn:cisco:params:xml:ns:yang:cat-inventory-rpc)get-services-count-request"
                    ),
                }
            ]
        }
    },
)
NATS_500 = httpx.Response(500, json={"error": "NATS request failed"})
# A 404 carrying a RESTCONF document on the CAT NBI: NOT a not-found there (only the proxy
# spells not-found that way); the CAT NBI's own spelling is 409 data-missing.
CAT_404_WITH_DOC = httpx.Response(
    404,
    json={"errors": {"error": [{"error-tag": "invalid-value", "error-message": "some other 404"}]}},
)

# Inventory nodes as nodes/query returns them (the fields the head-end lookup reads).
PE1_UUID = "3c8a1f5e-9b2d-4e7a-8c6f-1d2e3f4a5b6c"


def inventory_node(host: str, te_router_id: str, nso_node_id: str | None = None) -> dict:
    node = {
        "uuid": PE1_UUID,
        "host_name": host,
        "routing_info": {"te_router_id": te_router_id, "global_isis_system_id": "0000.0000.0001"},
    }
    if nso_node_id is not None:
        node["providers_family"] = {
            "ROBOT_PROVIDER_NSO": {
                "providers": {"nso": {"provider_name": "nso", "provider_node_id": nso_node_id}}
            }
        }
    return node


PE1_NODE = {"data": [inventory_node("PE1", "10.0.0.1", "PE1")], "total_count": 5, "result_count": 1}
# The filter was not honoured: the unfiltered set came back (client-side matching must cope).
ALL_NODES = {
    "data": [inventory_node("P1", "10.0.0.2"), inventory_node("PE1", "10.0.0.1", "PE1")],
    "total_count": 2,
    "result_count": 2,
}
NO_NODES: dict = {}  # verified: an empty match is a bare {} with no data key

# Cisco's own capture of the CAT operational-data GET (cnc-api-examples, service-inventory/
# output/l3vpn/service-oper-data-0-5.json): vpn-id + status + discovered underlay ONLY — the
# topology and the nodes are config intent and never appear here.
L3VPN_SERVICE = {
    "ietf-l3vpn-ntw:vpn-service": [
        {
            "vpn-id": "l3vpn-with-odn-90",
            "status": {"oper-status": {"status": "ietf-vpn-common:op-unknown"}},
            "underlay-transport": {
                "cisco-l3vpn-ntw:discovered-underlay-transport": {
                    "sr-policy-ref": [
                        {"headend": "PE-C", "color": 90, "endpoint": "100.100.100.5"},
                        {"headend": "PE-A", "color": 90, "endpoint": "100.100.100.7"},
                        {"headend": "PE-B", "color": 90, "endpoint": "100.100.100.7"},
                        {"headend": "PE-C", "color": 90, "endpoint": "100.100.100.6"},
                        {"headend": "PE-A", "color": 90, "endpoint": "100.100.100.6"},
                        {"headend": "PE-B", "color": 90, "endpoint": "100.100.100.5"},
                    ]
                }
            },
        }
    ]
}
# Cisco's L2 capture: an RSVP-TE-carried service, keys in a different order.
L2VPN_SERVICES = {
    "ietf-l2vpn-ntw:vpn-service": [
        {
            "vpn-id": "l2vpn-with-explicit-sr-policy",
            "underlay-transport": {
                "cisco-l2vpn-ntw:discovered-underlay-transport": {
                    "sr-policy-ref": [
                        {"headend": "PE-C", "color": 220, "endpoint": "100.100.100.5"},
                        {"headend": "PE-A", "color": 220, "endpoint": "100.100.100.7"},
                    ]
                }
            },
            "status": {"oper-status": {"status": "ietf-vpn-common:op-unknown"}},
        },
        {
            "vpn-id": "l2vpn-with-rsvp-te-tunnel",
            "underlay-transport": {
                "cisco-l2vpn-ntw:discovered-underlay-transport": {
                    "te-tunnel-ref": [
                        {
                            "tunnel-id": "1110",
                            "source": "100.100.100.5",
                            "destination": "100.100.100.6",
                        },
                        {
                            "tunnel-id": "1110",
                            "source": "100.100.100.6",
                            "destination": "100.100.100.5",
                        },
                    ]
                }
            },
            "status": {"oper-status": {"status": "ietf-vpn-common:op-unknown"}},
        },
    ]
}
# Should an entry ever carry the config-intent containers, they are rendered (not the norm).
L3VPN_SERVICE_WITH_NODES = {
    "ietf-l3vpn-ntw:vpn-service": [
        {
            "vpn-id": "mcp-l3vpn-91",
            "vpn-service-topology": "ietf-vpn-common:any-to-any",
            "vpn-nodes": {
                "vpn-node": [
                    {
                        "vpn-node-id": "PE1",
                        "local-as": 65000,
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
                    },
                    {"vpn-node-id": "PE2", "local-as": 65000},
                ]
            },
            "status": {
                "oper-status": {
                    "status": "ietf-vpn-common:op-up",
                    "last-change": "2026-09-13T11:00:00Z",
                }
            },
        }
    ]
}
# The L3VPN as the NSO proxy holds it (seen live 2026-09-14): NSO's bookkeeping sits on
# each vpn-node — the vpn-service itself carries none of created / last-modified /
# last-run / modified / plan-location.
L3VPN_NSO_OBJECT = {
    "ietf-l3vpn-ntw:vpn-service": [
        {
            "vpn-id": "mcp-l3vpn-91",
            "vpn-service-topology": "ietf-vpn-common:any-to-any",
            "vpn-instance-profiles": {
                "vpn-instance-profile": [{"profile-id": "p1", "rd": "0:65091:91"}]
            },
            "vpn-nodes": {
                "vpn-node": [
                    {
                        "vpn-node-id": "PE1",
                        "modified": {"devices": ["PE1"], "services": []},
                        "directly-modified": {"devices": ["PE1"], "services": []},
                        "plan-location": (
                            "/ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/"
                            "cisco-l3vpn-ntw:vpn-service-plan"
                        ),
                        "created": "2026-09-14T01:40:11.301+00:00",
                        "last-modified": "2026-09-14T01:40:11.301+00:00",
                        "last-run": "2026-09-14T01:40:11.301+00:00",
                        "local-as": 65000,
                    },
                    {
                        "vpn-node-id": "PE2",
                        "modified": {"devices": ["PE2"], "services": []},
                        "plan-location": (
                            "/ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/"
                            "cisco-l3vpn-ntw:vpn-service-plan"
                        ),
                        "created": "2026-09-14T01:40:11.301+00:00",
                        "last-modified": "2026-09-14T01:40:11.301+00:00",
                        "last-run": "2026-09-14T01:40:11.301+00:00",
                        "local-as": 65000,
                    },
                ]
            },
        }
    ]
}
# Verified 2026-09-14: GET vpn-service=<id>?content=nonconfig answers the node with its
# status only (the /status/oper-status sub-path answers 409 even for a live service).
OPER_STATUS = {
    "ietf-l3vpn-ntw:vpn-service": [
        {
            "vpn-id": "mcp-l3vpn-91",
            "status": {
                "oper-status": {
                    "status": "ietf-vpn-common:op-up",
                    "last-change": "2026-09-13T11:00:00Z",
                }
            },
        }
    ]
}
OPER_STATUS_UNKNOWN = {
    "ietf-l3vpn-ntw:vpn-service": [
        {
            "vpn-id": "smoke-l3vpn-1",
            "status": {"oper-status": {"status": "ietf-vpn-common:op-unknown"}},
        }
    ]
}
# The document spells the augment's leaves with their module prefix; both spellings are read.
UNDERLAY = {
    "cisco-l3vpn-ntw:discovered-underlay-transport": {
        "cisco-l3vpn-ntw:sr-policy-ref": [
            {
                "cisco-l3vpn-ntw:headend": "PE1",
                "cisco-l3vpn-ntw:color": 91,
                "cisco-l3vpn-ntw:endpoint": "10.0.0.3",
            }
        ],
        "te-tunnel-ref": [{"tunnel-id": "1", "source": "10.0.0.1", "destination": "10.0.0.3"}],
    }
}

# Verified: the function-pack deployment manager (plain JSON).
DEPLOYMENT_INFO = {
    "deploymentInfo": {
        "deploymentState": "DEPLOYED",
        "etcdCfpArchiveVersion": "7.2.43",
        "etcdPodVersion": "7.2.43",
        "deploymentTime": "2026-09-01T08:00:00Z",
    }
}
PACKAGES = {
    "packagesInfo": [
        {
            "namespace": "http://cisco.com/ns/nso/cfp/cisco-ts-sr-policies",
            "service-layer": "TRANSPORT",
            "resources": [
                {
                    "path": "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/sid-list",
                    "resourceIdField": "name",
                    "resourceIdFields": ["name"],
                    "scope": "SERVICE",
                    "label": "SID-List",
                    "additionalTargetTopics": [],
                }
            ],
            "model-version": "2022-01-12",
            "service-path": "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/policy",
            "plan-path": "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/policy-plan",
        },
        {
            "namespace": "http://cisco.com/ns/nso/cfp/cisco-tsdn-sr-te-sr-odn",
            "service-layer": "TRANSPORT",
            "resources": [],
            "model-version": "2022-01-12",
            "service-path": "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/odn-template",
            "plan-path": "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/odn-template-plan",
        },
    ]
}


def build(settings: Settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    services.register(mcp, ctx)
    return mcp


def ok(body: dict) -> httpx.Response:
    return httpx.Response(200, json=body)


def sent(route: respx.Route, index: int = 0) -> dict:
    return json.loads(route.calls[index].request.content)


def assert_yang(request: httpx.Request, *, body: bool) -> None:
    assert request.headers["Accept"] == YANG_JSON
    if body:
        assert request.headers["Content-Type"] == YANG_JSON


def mock_rpc(rpc: str, *responses: dict | httpx.Response) -> respx.Route:
    """The RPC answering the given bodies in order; the last one repeats forever."""
    replies = [r if isinstance(r, httpx.Response) else ok(r) for r in responses]

    def answer(_request: httpx.Request) -> httpx.Response:
        return replies.pop(0) if len(replies) > 1 else replies[0]

    return respx.post(rpc_url(rpc)).mock(side_effect=answer)


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


TOOLS = {
    "cnc_list_service_types",
    "cnc_get_service_counts",
    "cnc_list_services",
    "cnc_get_service",
    "cnc_get_service_plan",
    "cnc_wait_for_service_plan",
    "cnc_list_vpn_services",
    "cnc_get_vpn_service",
    "cnc_get_vpn_service_health",
    "cnc_get_vpn_underlay_transport",
    "cnc_list_sub_services",
    "cnc_find_services_on_transport",
    "cnc_list_function_packs",
}


# --- registration --------------------------------------------------------------


async def test_all_tools_are_read_only(make_settings):
    tools = {t.name: t for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert set(tools) == TOOLS
    for name, tool in tools.items():
        assert tool.annotations.read_only_hint is True, name
        assert tool.annotations.idempotent_hint is True, name
        assert tool.annotations.destructive_hint is False, name
    # Flat schemas: the only $def is the shared ResponseFormat enum, never an argument model.
    for name, tool in tools.items():
        assert set(tool.input_schema.get("$defs", {})) <= {"ResponseFormat"}, name


# --- pure helpers ---------------------------------------------------------------


def test_service_type_table_has_the_seven_types():
    assert SERVICE_TYPE_LABELS == (
        "policy",
        "odn-template",
        "cs-sr-te-policy",
        "ietf-l3vpn",
        "ietf-l2vpn",
        "slice-service",
        "tunnel",
    )
    assert {t.qname for t in SERVICE_TYPES} == {
        i["service-type"]
        for i in SERVICE_TYPES_RESPONSE["cat-inventory-rpc:output"][
            "get-available-service-types-response"
        ]["service-type-info"]
    }


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("odn-template", ODN_QNAME),
        (" ODN_Template ", ODN_QNAME),
        ("odn", ODN_QNAME),
        ("policy", POLICY_QNAME),
        ("sr-policy", POLICY_QNAME),
        ("l3vpn", L3VPN_QNAME),
        ("ietf-l3vpn", L3VPN_QNAME),
        (ODN_QNAME, ODN_QNAME),
        ("{urn:example}custom", "{urn:example}custom"),
    ],
)
def test_service_type_qname_accepts_labels_aliases_and_qnames(value, expected):
    assert service_type_qname(value) == expected


@pytest.mark.parametrize("value", ["vpn", "", "{broken", "{}"])
def test_service_type_qname_rejects_unknown(value):
    with pytest.raises(PlatformError):
        service_type_qname(value)


def test_service_type_label():
    assert service_type_label(ODN_QNAME) == "odn-template"
    assert service_type_label(L3VPN_QNAME) == "ietf-l3vpn"
    assert service_type_label("{urn:example}custom") == "custom"
    assert service_type_label(None) == "?"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (ODN_PATH, ODN_PATH),
        (f"/{ODN_PATH}", ODN_PATH),
        (f"data/{ODN_PATH}", ODN_PATH),
        (f"/crosswork/proxy/nso/restconf/data/{ODN_PATH}", ODN_PATH),
        (f"https://cnc.example/crosswork/proxy/nso/restconf/data/{ODN_PATH}/", ODN_PATH),
    ],
)
def test_normalize_yang_path(value, expected):
    assert normalize_yang_path(value) == expected


def test_normalize_yang_path_refuses_blank():
    with pytest.raises(PlatformError, match="yang_path is empty"):
        normalize_yang_path("  / ")


def test_plan_path_rule():
    assert plan_path_of(ODN_PATH) == ODN_PLAN_PATH
    assert plan_path_of(ODN_PLAN_PATH) == ODN_PLAN_PATH
    assert plan_path_of(f"/{ODN_PATH}") == ODN_PLAN_PATH
    assert (
        plan_path_of("cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/policy=p91")
        == "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/policy-plan=p91"
    )
    assert service_path_of(ODN_PLAN_PATH) == ODN_PATH
    assert service_path_of(ODN_PATH) == ODN_PATH
    assert is_plan_path(ODN_PLAN_PATH) and not is_plan_path(ODN_PATH)
    with pytest.raises(PlatformError, match="not a keyed service path"):
        plan_path_of("cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn")


def test_plan_path_table_matches_the_fp_deployment_manager():
    """The seven pairs are the deployment manager's documented service-path / plan-path."""
    assert PLAN_LIST_OF == FP_PLAN_LISTS
    for service_list, plan_list in FP_PLAN_LISTS.items():
        assert resolve_plan_path(f"{service_list}=x") == (f"{plan_list}=x", True)
        assert plan_path_of(f"{plan_list}=x") == f"{plan_list}=x"  # a plan path is left alone
        assert service_path_of(f"{plan_list}=x") == f"{service_list}=x"
        assert service_path_of(f"{service_list}=x") == f"{service_list}=x"
        assert is_plan_path(f"{plan_list}=x") and not is_plan_path(f"{service_list}=x")
    # The ones the <list>-plan rule got wrong before the table existed.
    assert plan_path_of(CS_PATH) == CS_PLAN_PATH
    assert plan_path_of(L3VPN_PATH) == (
        "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/cisco-l3vpn-ntw:vpn-service-plan=mcp-l3vpn-91"
    )
    assert (
        plan_path_of("ietf-te:te/tunnels/tunnel=t1") == "ietf-te:te/tunnels/cisco-te:tunnel-plan=t1"
    )
    # The module-qualified spelling the verified PUTs used finds the same entry.
    assert (
        plan_path_of(
            "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/cisco-sr-te-cfp-sr-odn:odn-template=x"
        )
        == f"{ODN_LIST_PATH}-plan=x"
    )
    # An unknown list falls back to the sibling guess and says so.
    assert resolve_plan_path("acme:things/thing=1") == ("acme:things/thing-plan=1", False)
    assert resolve_plan_path("acme:things/thing-plan=1") == ("acme:things/thing-plan=1", False)
    assert service_path_of("acme:things/thing-plan=1") == "acme:things/thing=1"


def test_plan_data_lines_wording_depends_on_whether_the_service_was_read():
    unknown = PLAN_UNKNOWN["cat-inventory-rpc:output"]["get-service-plan-data-response"][
        "service-plan-data"
    ][0]
    assert "does not exist or was never committed" in plan_data_lines(unknown, ODN_PLAN_PATH)[0]
    line = plan_data_lines(unknown, ODN_PLAN_PATH, service_exists=True)[0]
    assert "does not exist" not in line and "has not indexed the service yet" in line


def test_headend_lookup_helpers():
    assert looks_like_ip_address("10.0.0.1") and looks_like_ip_address(" 2001:db8::1 ")
    assert not looks_like_ip_address("PE1") and not looks_like_ip_address("")
    # Cisco's example: a nested routing_info.te_router_id filter, plus the verified paging.
    assert te_router_id_query("10.0.0.1") == {
        "filter": {"routing_info": {"te_router_id": "10.0.0.1"}},
        "filterData": {"PageSize": 200, "PageNum": 0, "Criteria": ""},
    }
    assert nso_node_id_of(inventory_node("PE1", "10.0.0.1", "nso-pe1")) == "nso-pe1"
    assert nso_node_id_of(inventory_node("PE1", "10.0.0.1")) == "PE1"  # host_name fallback
    as_list = inventory_node("PE1", "10.0.0.1")
    as_list["providers_family"] = {
        "ROBOT_PROVIDER_NSO": {"providers": [{"provider_node_id": "from-list"}]}
    }
    assert nso_node_id_of(as_list) == "from-list"
    assert nso_node_id_of({}) is None
    # The endpoint side: host name -> te_router_id (the verified host_name filter + paging).
    assert host_name_query("PE2") == {
        "filter": {"host_name": "PE2"},
        "filterData": {"PageSize": 200, "PageNum": 0, "Criteria": ""},
    }
    nodes = [inventory_node("P1", "10.0.0.2"), inventory_node("PE2", "10.0.0.3")]
    assert nodes_with_host_name(nodes, " pe2 ") == [nodes[1]]  # case-insensitive, trimmed
    assert nodes_with_host_name(nodes, "PE*") == []  # no wildcard guessing client-side
    assert te_router_id_of(nodes[1]) == "10.0.0.3"
    assert te_router_id_of({"host_name": "X", "routing_info": {"te_router_id": ""}}) is None
    assert te_router_id_of({"host_name": "X"}) is None


def test_vpn_service_line_never_invents_config_intent():
    entry = L3VPN_SERVICE["ietf-l3vpn-ntw:vpn-service"][0]
    line = vpn_service_line(entry)
    assert line == (
        "- **l3vpn-with-odn-90** oper-status=op-unknown underlay: 6 SR policies, 0 RSVP-TE tunnels"
    )
    assert "nodes=" not in line and "topology=" not in line
    with_nodes = L3VPN_SERVICE_WITH_NODES["ietf-l3vpn-ntw:vpn-service"][0]
    assert vpn_service_line(with_nodes) == (
        "- **mcp-l3vpn-91** oper-status=op-up last-change=2026-09-13T11:00:00Z underlay: "
        "0 SR policies, 0 RSVP-TE tunnels topology=any-to-any nodes=2 [PE1, PE2]"
    )


def test_cat_rpc_body_and_response():
    assert cat_rpc_body("get-available-service-types", None) == {"cat-inventory-rpc:input": {}}
    assert cat_rpc_body("get-services-count", {}) == {
        "cat-inventory-rpc:input": {"cat-inventory-rpc:get-services-count-request": {}}
    }
    assert cat_rpc_response(COUNTS_ONE, "get-services-count")["total-services-count"] == 1
    assert cat_rpc_response(EMPTY_OUTPUT, "get-associated-services-for-transport") == {}
    assert cat_rpc_response(None, "x") == {}
    # A module-prefixed response key is tolerated too.
    prefixed = {"cat-inventory-rpc:output": {"cat-inventory-rpc:x-response": {"a": 1}}}
    assert cat_rpc_response(prefixed, "x") == {"a": 1}


def test_plan_not_found_and_status():
    entry = PLAN_UNKNOWN["cat-inventory-rpc:output"]["get-service-plan-data-response"][
        "service-plan-data"
    ][0]
    assert plan_not_found(entry)
    assert plan_not_found(None)
    done = PLAN_COMPLETED["cat-inventory-rpc:output"]["get-service-plan-data-response"][
        "service-plan-data"
    ][0]
    assert not plan_not_found(done)
    assert normalize_plan_status(" Completed ") == "completed"
    assert normalize_plan_status("in_progress") == "in-progress"
    # The nano-plan word the create tools print is an alias of the CAT status.
    assert normalize_plan_status("ready") == "completed"
    with pytest.raises(PlatformError, match="Unknown plan status"):
        normalize_plan_status("done")
    # A nano-plan component state is refused with both vocabularies spelled out.
    with pytest.raises(PlatformError, match="nano-plan component states, not CAT plan"):
        normalize_plan_status("config-apply")


def test_transport_ref():
    assert transport_ref(
        headend="PE1", color=100, endpoint="10.0.0.3", tunnel_id="", source="", destination=""
    ) == {"sr-policy-ref": {"headend": "PE1", "color": "100", "endpoint": "10.0.0.3"}}
    assert transport_ref(
        headend="", color=0, endpoint="", tunnel_id="1", source="10.0.0.1", destination="10.0.0.3"
    ) == {"te-tunnel-ref": {"tunnel-id": "1", "source": "10.0.0.1", "destination": "10.0.0.3"}}
    with pytest.raises(PlatformError, match="missing: color, endpoint"):
        transport_ref(headend="PE1", color=0, endpoint="", tunnel_id="", source="", destination="")
    with pytest.raises(PlatformError, match="missing: destination"):
        transport_ref(
            headend="", color=0, endpoint="", tunnel_id="1", source="10.0.0.1", destination=""
        )
    with pytest.raises(PlatformError, match="nothing was sent"):
        transport_ref(headend="", color=0, endpoint="", tunnel_id="", source="", destination="")


# --- cnc_list_service_types -----------------------------------------------------


@respx.mock
async def test_list_service_types(settings):
    route = mock_rpc("get-available-service-types", SERVICE_TYPES_RESPONSE)
    text = await call_tool_text(build(settings), "cnc_list_service_types", {})
    request = route.calls[0].request
    assert_yang(request, body=True)
    assert sent(route) == {"cat-inventory-rpc:input": {}}
    assert "# CAT service types (7)" in text
    assert "**odn-template**" in text and ODN_QNAME in text
    assert "**ietf-l3vpn** (CAT label 'vpn-service')" in text


@respx.mock
async def test_list_service_types_json_and_error(settings):
    mock_rpc("get-available-service-types", SERVICE_TYPES_RESPONSE)
    text = await call_tool_text(
        build(settings), "cnc_list_service_types", {"response_format": "json"}
    )
    payload = json.loads(text)
    assert payload["count"] == 7 and payload["items"][1]["label"] == "odn-template"
    respx.post(rpc_url("get-available-service-types")).mock(return_value=NATS_500)
    text = await call_tool_text(build(settings), "cnc_list_service_types", {})
    assert text.startswith("Error:") and "500" in text


# --- cnc_get_service_counts -----------------------------------------------------


@respx.mock
async def test_get_service_counts(settings):
    route = mock_rpc("get-services-count", COUNTS_ONE)
    text = await call_tool_text(build(settings), "cnc_get_service_counts", {})
    assert_yang(route.calls[0].request, body=True)
    # Verified: the RPC takes NO filters — the empty request container is what is sent.
    assert sent(route) == {
        "cat-inventory-rpc:input": {"cat-inventory-rpc:get-services-count-request": {}}
    }
    assert "(1 total)" in text and "**odn-template**: 1" in text


@respx.mock
async def test_get_service_counts_zero_is_not_an_error(settings):
    mock_rpc("get-services-count", COUNTS_ZERO)
    text = await call_tool_text(build(settings), "cnc_get_service_counts", {})
    assert text.startswith("No services are provisioned.")
    assert text.endswith("The RPC listed no service types.")
    text = await call_tool_text(
        build(settings), "cnc_get_service_counts", {"response_format": "json"}
    )
    assert json.loads(text) == {"total": 0, "per_type": []}


@respx.mock
async def test_get_service_counts_live_zero_case_lists_every_type_at_zero(settings):
    """Verified live 2026-09-14: an empty inventory answers all seven types at 0 — the
    markdown stays the documented 'No services are provisioned.' line (naming the types),
    never a table of zeros; the JSON keeps the rows exactly as the RPC listed them."""
    mock_rpc("get-services-count", COUNTS_ZERO_ALL_TYPES)
    text = await call_tool_text(build(settings), "cnc_get_service_counts", {})
    assert text.startswith("No services are provisioned.")
    assert "CAT knows 7 service types, all at 0: policy, odn-template, cs-sr-te-policy" in text
    assert "(0 total)" not in text and "**policy**: 0" not in text
    text = await call_tool_text(
        build(settings), "cnc_get_service_counts", {"response_format": "json"}
    )
    payload = json.loads(text)
    assert payload["total"] == 0 and len(payload["per_type"]) == 7
    assert {e["count"] for e in payload["per_type"]} == {0}


@respx.mock
async def test_get_service_counts_folds_the_zero_types_into_one_line(settings):
    mock_rpc("get-services-count", COUNTS_MIXED)
    text = await call_tool_text(build(settings), "cnc_get_service_counts", {})
    assert "(2 total)" in text and "- **odn-template**: 2 (" in text
    assert "- types with no services (6): policy, cs-sr-te-policy, ietf-l3vpn" in text
    assert "**policy**: 0" not in text


@respx.mock
async def test_get_service_counts_error(settings):
    mock_rpc("get-services-count", MALFORMED_400)
    text = await call_tool_text(build(settings), "cnc_get_service_counts", {})
    assert text.startswith("Error:") and "malformed-message" in text


# --- cnc_list_services -----------------------------------------------------------


@respx.mock
async def test_list_services_no_filter_sends_only_the_header(settings):
    route = mock_rpc("get-all-services", ALL_SERVICES)
    text = await call_tool_text(build(settings), "cnc_list_services", {"limit": 10})
    assert_yang(route.calls[0].request, body=True)
    body = sent(route)
    # Verified: limit MUST be a numeric string; no query-criteria without a filter.
    assert body == {
        "cat-inventory-rpc:input": {
            "cat-inventory-rpc:get-all-services-request": {
                "collection-header": {"offset": 0, "limit": "10"}
            }
        }
    }
    assert "**mcp-odn-90** type=odn-template" in text
    assert f"yang-path={ODN_PATH}" in text and f"plan={ODN_PLAN_PATH}" in text
    assert "call again" not in text  # 1 < limit 10: no more pages


@respx.mock
async def test_list_services_filters_and_paging(settings):
    route = mock_rpc("get-all-services", ALL_SERVICES)
    text = await call_tool_text(
        build(settings),
        "cnc_list_services",
        {
            "service_type": "odn-template, policy",
            "exclude_types": "l3vpn",
            "name_prefix": "mcp",
            "offset": 5,
            "limit": 1,
            "response_format": "json",
        },
    )
    request = sent(route)["cat-inventory-rpc:input"]["cat-inventory-rpc:get-all-services-request"]
    assert request["collection-header"] == {"offset": 5, "limit": "1"}
    assert request["query-criteria"] == {
        "service-type-filters": {
            "includes": {"service-type": [ODN_QNAME, POLICY_QNAME]},
            "excludes": {"service-type": [L3VPN_QNAME]},
        },
        "service-name-filters": {"start-with": "mcp", "case-sensitive": "false"},
    }
    payload = json.loads(text)
    assert payload["count"] == 1 and payload["offset"] == 5
    assert payload["has_more"] is True and payload["next_offset"] == 6  # full page heuristic
    assert payload["items"][0]["label"] == "odn-template"
    assert payload["collection_header"] == {"offset": 0, "count": 1}
    assert payload["filter"]["service_type"] == ["odn-template", "policy"]


@respx.mock
async def test_list_services_case_sensitive_prefix(settings):
    route = mock_rpc("get-all-services", ALL_SERVICES)
    await call_tool_text(
        build(settings), "cnc_list_services", {"name_prefix": "MCP", "case_sensitive": True}
    )
    request = sent(route)["cat-inventory-rpc:input"]["cat-inventory-rpc:get-all-services-request"]
    assert request["query-criteria"] == {
        "service-name-filters": {"start-with": "MCP", "case-sensitive": "true"}
    }


@respx.mock
async def test_list_services_empty_is_not_an_error(settings):
    mock_rpc("get-all-services", NO_SERVICES)
    text = await call_tool_text(build(settings), "cnc_list_services", {"service_type": "policy"})
    assert text.startswith("No services match (service_type=['policy']")
    text = await call_tool_text(build(settings), "cnc_list_services", {"response_format": "json"})
    payload = json.loads(text)
    assert payload["items"] == [] and payload["has_more"] is False


@respx.mock
async def test_list_services_unknown_label_sends_nothing(settings):
    route = mock_rpc("get-all-services", ALL_SERVICES)
    text = await call_tool_text(build(settings), "cnc_list_services", {"service_type": "vpn"})
    assert text.startswith("Error: Unknown service type 'vpn'")
    assert "odn-template" in text and "ietf-l3vpn" in text
    assert not route.called


@respx.mock
async def test_list_services_error(settings):
    mock_rpc("get-all-services", NATS_500)
    text = await call_tool_text(build(settings), "cnc_list_services", {})
    assert text.startswith("Error:") and "500" in text


# --- cnc_get_service --------------------------------------------------------------


@respx.mock
async def test_get_service_with_plan(settings):
    get = respx.get(f"{NSO_DATA}/{ODN_PATH}").mock(return_value=ok(ODN_TEMPLATE))
    plan = mock_rpc("get-service-plan-data", PLAN_COMPLETED)
    text = await call_tool_text(build(settings), "cnc_get_service", {"yang_path": ODN_PATH})
    assert_yang(get.calls[0].request, body=False)
    assert "Content-Type" not in get.calls[0].request.headers
    assert sent(plan) == {
        "cat-inventory-rpc:input": {
            "cat-inventory-rpc:get-service-plan-data-request": {
                "service-plan-yang-path": [ODN_PLAN_PATH]
            }
        }
    }
    assert text.startswith(f"# Service mcp-odn-90 ({ODN_PATH})")
    assert "created=2026-09-13T10:15:02.145+00:00" in text
    assert "modified: devices=PE1 services=(none)" in text
    assert f"plan {ODN_PLAN_PATH}: status **completed**" in text
    assert '"color": 90' in text and '"head-end"' in text
    assert '"plan-location"' not in text.split("Service body")[1]  # bookkeeping split out


@respx.mock
async def test_get_service_accepts_prefixed_paths_and_skips_plan(settings):
    get = respx.get(f"{NSO_DATA}/{ODN_PATH}").mock(return_value=ok(ODN_TEMPLATE))
    plan = mock_rpc("get-service-plan-data", PLAN_COMPLETED)
    text = await call_tool_text(
        build(settings),
        "cnc_get_service",
        {
            "yang_path": f"/crosswork/proxy/nso/restconf/data/{ODN_PATH}",
            "include_plan": False,
            "response_format": "json",
        },
    )
    assert get.called and not plan.called
    payload = json.loads(text)
    assert payload["yang_path"] == ODN_PATH and payload["plan_yang_path"] is None
    assert payload["service"]["name"] == "mcp-odn-90" and payload["plan"] is None


@respx.mock
async def test_get_service_plan_unknown_is_shown_not_raised(settings):
    respx.get(f"{NSO_DATA}/{ODN_PATH}").mock(return_value=ok(ODN_TEMPLATE))
    mock_rpc("get-service-plan-data", PLAN_UNKNOWN)
    text = await call_tool_text(build(settings), "cnc_get_service", {"yang_path": ODN_PATH})
    assert "no plan data" in text and not text.startswith("Error")


@respx.mock
async def test_get_service_not_found(settings):
    respx.get(f"{NSO_DATA}/{ODN_PATH}").mock(return_value=PROXY_404)
    plan = mock_rpc("get-service-plan-data", PLAN_UNKNOWN)
    text = await call_tool_text(build(settings), "cnc_get_service", {"yang_path": ODN_PATH})
    assert text.startswith(f"Error: no service at {ODN_PATH}")
    assert "cnc_list_services" in text
    assert not plan.called


@respx.mock
async def test_get_service_bare_404_is_a_routing_error(settings):
    respx.get(f"{NSO_DATA}/{ODN_PATH}").mock(return_value=httpx.Response(404, text="nope"))
    text = await call_tool_text(build(settings), "cnc_get_service", {"yang_path": ODN_PATH})
    assert text.startswith("Error: API request failed with status 404")


@respx.mock
async def test_get_service_refuses_an_unkeyed_list_path(settings):
    """An unkeyed path would make the proxy answer the whole list; only one entry could be
    shown, so it is refused before anything is sent (as the docstring promises)."""
    get = respx.get(f"{NSO_DATA}/{ODN_LIST_PATH}").mock(return_value=ok(ODN_TEMPLATES_TWO))
    plan = mock_rpc("get-service-plan-data", PLAN_COMPLETED)
    text = await call_tool_text(build(settings), "cnc_get_service", {"yang_path": ODN_LIST_PATH})
    assert text.startswith("Error:") and "not a keyed service path" in text
    assert not get.called and not plan.called


@respx.mock
async def test_get_service_cs_sr_te_policy_uses_the_documented_plan_list(settings):
    """cs-sr-te-policy's plan is the top-level cs-sr-te-plan list, not a cs-sr-te-policy-plan."""
    respx.get(f"{NSO_DATA}/{CS_PATH}").mock(return_value=ok(CS_POLICY))
    plan = mock_rpc("get-service-plan-data", CS_PLAN_COMPLETED)
    text = await call_tool_text(build(settings), "cnc_get_service", {"yang_path": CS_PATH})
    request = sent(plan)["cat-inventory-rpc:input"]
    assert request["cat-inventory-rpc:get-service-plan-data-request"] == {
        "service-plan-yang-path": [CS_PLAN_PATH]
    }
    assert text.startswith(f"# Service cs1 ({CS_PATH})")
    assert f"plan {CS_PLAN_PATH}: status **completed**" in text
    text = await call_tool_text(
        build(settings), "cnc_get_service", {"yang_path": CS_PATH, "response_format": "json"}
    )
    payload = json.loads(text)
    assert payload["plan_yang_path"] == CS_PLAN_PATH and payload["plan_path_known"] is True
    assert payload["plan"]["status"] == "completed"


@respx.mock
async def test_get_service_l3vpn_shows_the_per_node_bookkeeping(settings):
    """An L3NM service keeps NSO's bookkeeping on each vpn-node: the header shows one line
    per node instead of 'created=- last-modified=- ...' (agent scenario 2026-09-14)."""
    respx.get(f"{NSO_DATA}/{L3VPN_PATH}").mock(return_value=ok(L3VPN_NSO_OBJECT))
    mock_rpc("get-service-plan-data", PLAN_COMPLETED)
    text = await call_tool_text(build(settings), "cnc_get_service", {"yang_path": L3VPN_PATH})
    assert text.startswith(f"# Service mcp-l3vpn-91 ({L3VPN_PATH})")
    assert "created=- last-modified=-" not in text
    assert "- NSO bookkeeping per vpn-node" in text
    assert (
        "- vpn-node PE1: created=2026-09-14T01:40:11.301+00:00 "
        "last-modified=2026-09-14T01:40:11.301+00:00 last-run=2026-09-14T01:40:11.301+00:00 "
        "plan-location=/ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/cisco-l3vpn-ntw:vpn-service-plan"
    ) in text
    assert "  - modified: devices=PE1 services=(none) directly-modified: devices=PE1" in text
    assert "- vpn-node PE2: created=2026-09-14T01:40:11.301+00:00" in text
    assert "  - modified: devices=PE2 services=(none)\n" in text
    # The body is still the object as NSO holds it (per-node keys untouched).
    body = text.split("Service body as NSO holds it:")[1]
    assert '"plan-location"' in body and '"local-as": 65000' in body
    # Helper contract: nothing is invented for a node without bookkeeping.
    assert per_node_bookkeeping({"vpn-nodes": {"vpn-node": [{"vpn-node-id": "PE9"}]}}) == []
    assert per_node_bookkeeping({"name": "x"}) == []


@respx.mock
async def test_get_service_plan_unknown_wording_does_not_deny_the_service(settings):
    """The service was just read from NSO, so 'no plan data' must not claim it does not exist."""
    respx.get(f"{NSO_DATA}/{CS_PATH}").mock(return_value=ok(CS_POLICY))
    mock_rpc("get-service-plan-data", PLAN_UNKNOWN)
    text = await call_tool_text(build(settings), "cnc_get_service", {"yang_path": CS_PATH})
    assert not text.startswith("Error")
    assert "no plan data in CAT for this path" in text and "does not exist" not in text


@respx.mock
async def test_get_service_unknown_list_marks_the_plan_path_as_a_guess(settings):
    path = "acme:things/thing=1"
    respx.get(f"{NSO_DATA}/{path}").mock(return_value=ok({"acme:thing": [{"name": "1"}]}))
    plan = mock_rpc("get-service-plan-data", PLAN_UNKNOWN)
    text = await call_tool_text(build(settings), "cnc_get_service", {"yang_path": path})
    request = sent(plan)["cat-inventory-rpc:input"]
    assert request["cat-inventory-rpc:get-service-plan-data-request"] == {
        "service-plan-yang-path": ["acme:things/thing-plan=1"]
    }
    assert "only a <list>-plan guess" in text and not text.startswith("Error")
    text = await call_tool_text(
        build(settings), "cnc_get_service", {"yang_path": path, "response_format": "json"}
    )
    payload = json.loads(text)
    assert payload["plan_path_known"] is False and "guess" in payload["plan_note"]


@respx.mock
async def test_get_service_plan_note_is_printed_in_markdown(settings):
    """A CAT failure on the plan read must not hide the service, and the note must be shown
    in the markdown output too (not only in the JSON payload)."""
    respx.get(f"{NSO_DATA}/{ODN_PATH}").mock(return_value=ok(ODN_TEMPLATE))
    mock_rpc("get-service-plan-data", NATS_500)
    text = await call_tool_text(build(settings), "cnc_get_service", {"yang_path": ODN_PATH})
    assert text.startswith(f"# Service mcp-odn-90 ({ODN_PATH})")
    assert f"- plan {ODN_PLAN_PATH}: plan status unavailable:" in text and "500" in text
    text = await call_tool_text(
        build(settings), "cnc_get_service", {"yang_path": ODN_PATH, "response_format": "json"}
    )
    payload = json.loads(text)
    assert payload["plan"] is None and payload["plan_note"].startswith("plan status unavailable")


# --- cnc_get_service_plan ---------------------------------------------------------


@respx.mock
async def test_get_service_plan_from_service_path(settings):
    plan = mock_rpc("get-service-plan-data", PLAN_COMPLETED)
    text = await call_tool_text(
        build(settings), "cnc_get_service_plan", {"plan_yang_path": ODN_PATH}
    )
    body = sent(plan)["cat-inventory-rpc:input"]["cat-inventory-rpc:get-service-plan-data-request"]
    assert body == {"service-plan-yang-path": [ODN_PLAN_PATH]}
    assert text.startswith(f"# Service plan {ODN_PLAN_PATH}")
    assert "status **completed**" in text and "Nano-plan" not in text


@respx.mock
async def test_get_service_plan_detail_renders_components(settings):
    mock_rpc("get-service-plan-data", PLAN_FAILED)
    get = respx.get(f"{NSO_DATA}/{ODN_PLAN_PATH}").mock(return_value=ok(ODN_PLAN))
    text = await call_tool_text(
        build(settings), "cnc_get_service_plan", {"plan_yang_path": ODN_PLAN_PATH, "detail": True}
    )
    assert_yang(get.calls[0].request, body=False)
    assert "status **failed**" in text
    assert "error-info: Network Element Driver: device PE1: out of sync" in text
    assert "Nano-plan components (2):" in text
    assert "- **self** self: init=reached@2026-09-13T10:15:02.145+00:00 ready=reached@" in text
    assert "- **head-end** PE1:" in text


@respx.mock
async def test_get_service_plan_unknown_is_not_an_error(settings):
    mock_rpc("get-service-plan-data", PLAN_UNKNOWN)
    text = await call_tool_text(
        build(settings), "cnc_get_service_plan", {"plan_yang_path": ODN_PLAN_PATH}
    )
    assert text.startswith(f"No plan data for {ODN_PLAN_PATH}")
    text = await call_tool_text(
        build(settings),
        "cnc_get_service_plan",
        {"plan_yang_path": ODN_PLAN_PATH, "response_format": "json"},
    )
    payload = json.loads(text)
    assert payload["found"] is False and payload["plan_data"] is None


@respx.mock
async def test_get_service_plan_detail_404_means_no_plan(settings):
    mock_rpc("get-service-plan-data", PLAN_UNKNOWN)
    respx.get(f"{NSO_DATA}/{ODN_PLAN_PATH}").mock(return_value=PROXY_404)
    text = await call_tool_text(
        build(settings), "cnc_get_service_plan", {"plan_yang_path": ODN_PLAN_PATH, "detail": True}
    )
    assert text.startswith("No plan data for")
    # CAT unknown but NSO still holds the plan (lingering after a delete): the plan is shown.
    respx.get(f"{NSO_DATA}/{ODN_PLAN_PATH}").mock(return_value=ok(ODN_PLAN))
    text = await call_tool_text(
        build(settings), "cnc_get_service_plan", {"plan_yang_path": ODN_PLAN_PATH, "detail": True}
    )
    assert "Nano-plan components (2):" in text


@respx.mock
async def test_get_service_plan_errors(settings):
    route = mock_rpc("get-service-plan-data", NATS_500)
    text = await call_tool_text(
        build(settings), "cnc_get_service_plan", {"plan_yang_path": "cisco-sr-te-cfp:sr-te"}
    )
    assert text.startswith("Error:") and "not a keyed service path" in text
    assert not route.called
    text = await call_tool_text(
        build(settings), "cnc_get_service_plan", {"plan_yang_path": ODN_PLAN_PATH}
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_wait_for_service_plan ----------------------------------------------------


@respx.mock
async def test_wait_for_service_plan_reaches_completed(settings, fake_clock):
    route = mock_rpc("get-service-plan-data", PLAN_IN_PROGRESS, PLAN_COMPLETED)
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_service_plan",
        {"plan_yang_path": ODN_PATH, "timeout_seconds": 60, "interval_seconds": 5},
    )
    assert route.call_count == 2
    assert text.startswith(f"Service plan {ODN_PLAN_PATH} is completed after 5s.")
    assert '"status": "completed"' in text


@respx.mock
async def test_wait_for_service_plan_timeout_is_not_an_error(settings, fake_clock):
    mock_rpc("get-service-plan-data", PLAN_IN_PROGRESS)
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_service_plan",
        {"plan_yang_path": ODN_PLAN_PATH, "timeout_seconds": 10, "interval_seconds": 5},
    )
    assert not text.startswith("Error")
    assert text.startswith(f"Service plan {ODN_PLAN_PATH} not completed after")
    assert "current status: in-progress" in text


@respx.mock
async def test_wait_for_service_plan_unknown_keeps_polling(settings, fake_clock):
    mock_rpc("get-service-plan-data", PLAN_UNKNOWN)
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_service_plan",
        {"plan_yang_path": ODN_PLAN_PATH, "timeout_seconds": 5, "interval_seconds": 5},
    )
    assert not text.startswith("Error") and "no plan data yet" in text
    # ... unless 'unknown' is the target (waiting for a delete to finish).
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_service_plan",
        {"plan_yang_path": ODN_PLAN_PATH, "target": "unknown"},
    )
    assert text.startswith(f"Service plan {ODN_PLAN_PATH} is unknown after 0s.")


@respx.mock
async def test_wait_for_service_plan_failed_is_an_error(settings, fake_clock):
    mock_rpc("get-service-plan-data", PLAN_FAILED)
    text = await call_tool_text(
        build(settings), "cnc_wait_for_service_plan", {"plan_yang_path": ODN_PLAN_PATH}
    )
    assert text.startswith(f"Error: service plan {ODN_PLAN_PATH} FAILED")
    assert "device PE1: out of sync" in text


@respx.mock
async def test_wait_for_service_plan_bad_target_sends_nothing(settings):
    route = mock_rpc("get-service-plan-data", PLAN_COMPLETED)
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_service_plan",
        {"plan_yang_path": ODN_PLAN_PATH, "target": "done"},
    )
    assert text.startswith("Error: Unknown plan status 'done'. Use one of the CAT plan statuses")
    assert "'ready' is accepted as an alias of 'completed'" in text
    assert not route.called


@respx.mock
async def test_wait_for_service_plan_accepts_ready_as_completed(settings, fake_clock):
    """The create tools print 'Plan: ready' (NSO nano-plan); CAT calls the same service
    'completed' — target='ready' must not be rejected (agent scenario 2026-09-14)."""
    route = mock_rpc("get-service-plan-data", PLAN_COMPLETED)
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_service_plan",
        {"plan_yang_path": ODN_PLAN_PATH, "target": "ready"},
    )
    assert route.call_count == 1
    assert text.startswith(f"Service plan {ODN_PLAN_PATH} is completed after 0s.")


# --- cnc_list_vpn_services --------------------------------------------------------


@respx.mock
async def test_list_vpn_services_l3(settings):
    route = respx.get(L3VPN_LIST_URL).mock(return_value=ok(L3VPN_SERVICE))
    text = await call_tool_text(
        build(settings), "cnc_list_vpn_services", {"offset": 0, "limit": 10}
    )
    request = route.calls[0].request
    assert_yang(request, body=False)
    # Verified 2026-09-14: content=nonconfig is what makes the batch GET answer at all.
    assert dict(request.url.params) == {"offset": "0", "limit": "10", "content": "nonconfig"}
    assert "# L3 VPN services (1 on this page, offset 0)" in text
    # Cisco's real payload: oper-status and the discovered underlay, never "nodes=0".
    assert (
        "- **l3vpn-with-odn-90** oper-status=op-unknown underlay: 6 SR policies, 0 RSVP-TE tunnels"
        in text
    )
    assert "nodes=" not in text and "topology=" not in text
    assert "cnc_get_service(yang_path=" in text  # where the nodes / accesses actually are


@respx.mock
async def test_list_vpn_services_l2_renders_cisco_capture(settings):
    respx.get(L2VPN_LIST_URL).mock(return_value=ok(L2VPN_SERVICES))
    text = await call_tool_text(build(settings), "cnc_list_vpn_services", {"layer": "l2"})
    assert "# L2 VPN services (2 on this page, offset 0)" in text
    assert (
        "- **l2vpn-with-explicit-sr-policy** oper-status=op-unknown underlay: 2 SR policies, "
        "0 RSVP-TE tunnels" in text
    )
    assert (
        "- **l2vpn-with-rsvp-te-tunnel** oper-status=op-unknown underlay: 0 SR policies, "
        "2 RSVP-TE tunnels" in text
    )


@respx.mock
async def test_list_vpn_services_l2_and_409_means_none(settings):
    route = respx.get(L2VPN_LIST_URL).mock(return_value=DATA_MISSING_409)
    text = await call_tool_text(build(settings), "cnc_list_vpn_services", {"layer": "l2"})
    assert route.called
    assert text.startswith("No L2 VPN services.")
    text = await call_tool_text(
        build(settings), "cnc_list_vpn_services", {"layer": "L2", "response_format": "json"}
    )
    payload = json.loads(text)
    assert payload["layer"] == "l2" and payload["items"] == [] and payload["has_more"] is False


@respx.mock
async def test_list_vpn_services_errors(settings):
    route = respx.get(L3VPN_LIST_URL).mock(return_value=NATS_500)
    text = await call_tool_text(build(settings), "cnc_list_vpn_services", {"layer": "l4"})
    assert text.startswith("Error: Unknown VPN layer 'l4'")
    assert not route.called
    text = await call_tool_text(build(settings), "cnc_list_vpn_services", {})
    assert text.startswith("Error:") and "500" in text


# --- cnc_get_vpn_service ------------------------------------------------------------


@respx.mock
async def test_get_vpn_service(settings):
    route = respx.get(f"{L3VPN_LIST_URL}=l3vpn%20with%2Fodn").mock(return_value=ok(L3VPN_SERVICE))
    text = await call_tool_text(
        build(settings), "cnc_get_vpn_service", {"vpn_id": "l3vpn with/odn"}
    )
    assert_yang(route.calls[0].request, body=False)  # encode_key on the id (verified rule)
    assert text.startswith("# L3 VPN service l3vpn-with-odn-90")
    # The discovered underlay IS in the payload and is rendered in full ...
    assert "Discovered underlay transport:" in text and "SR policies (6):" in text
    assert "- headend=PE-C color=90 endpoint=100.100.100.5" in text
    assert "- headend=PE-B color=90 endpoint=100.100.100.7" in text
    assert "RSVP-TE tunnels (0):" in text
    # ... while the nodes are NOT (config intent): no "Nodes (0)", a pointer instead.
    assert "Nodes (" not in text
    assert (
        "cnc_get_service(yang_path='ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/"
        "vpn-service=l3vpn-with-odn-90')" in text
    )


@respx.mock
async def test_get_vpn_service_renders_nodes_only_when_present(settings):
    respx.get(f"{L3VPN_LIST_URL}=mcp-l3vpn-91").mock(return_value=ok(L3VPN_SERVICE_WITH_NODES))
    text = await call_tool_text(build(settings), "cnc_get_vpn_service", {"vpn_id": "mcp-l3vpn-91"})
    assert "Nodes (2):" in text
    assert "- **PE1** local-as=65000 accesses=1" in text
    assert "  - access 1 interface=Loopback91 10.91.1.1/30" in text
    assert "- **PE2** local-as=65000 accesses=0" in text
    assert "This is Crosswork's operational view only" not in text


@respx.mock
async def test_get_vpn_service_json_and_not_found(settings):
    respx.get(f"{L3VPN_LIST_URL}=l3vpn-with-odn-90").mock(return_value=ok(L3VPN_SERVICE))
    text = await call_tool_text(
        build(settings),
        "cnc_get_vpn_service",
        {"vpn_id": "l3vpn-with-odn-90", "response_format": "json"},
    )
    assert json.loads(text)["vpn-id"] == "l3vpn-with-odn-90"
    respx.get(f"{L3VPN_LIST_URL}=nope").mock(return_value=DATA_MISSING_409)
    text = await call_tool_text(build(settings), "cnc_get_vpn_service", {"vpn_id": "nope"})
    assert text.startswith("Error: no L3 VPN service 'nope'")


@respx.mock
async def test_get_vpn_service_cat_404_is_never_a_not_found(settings):
    """On the CAT NBI only 409 data-missing means "no such service"; a 404 — even one carrying
    a RESTCONF document — is a malformed / unrouted URL and is reported as that status."""
    respx.get(f"{L3VPN_LIST_URL}=zz").mock(return_value=CAT_404_WITH_DOC)
    text = await call_tool_text(build(settings), "cnc_get_vpn_service", {"vpn_id": "zz"})
    assert text.startswith("Error: API request failed with status 404")
    assert "409" not in text.split("never that the object is missing")[0]
    assert "a missing entry answers 409 data-missing" in text
    # The proxy keeps its own spelling: a 404 with a document IS a not-found there.
    respx.get(f"{NSO_DATA}/{ODN_PATH}").mock(return_value=PROXY_404)
    text = await call_tool_text(build(settings), "cnc_get_service", {"yang_path": ODN_PATH})
    assert text.startswith(f"Error: no service at {ODN_PATH}")


# --- cnc_get_vpn_service_health -----------------------------------------------------


@respx.mock
async def test_get_vpn_service_health(settings):
    route = respx.get(f"{L3VPN_LIST_URL}=mcp-l3vpn-91").mock(return_value=ok(OPER_STATUS))
    text = await call_tool_text(
        build(settings), "cnc_get_vpn_service_health", {"vpn_id": "mcp-l3vpn-91"}
    )
    assert_yang(route.calls[0].request, body=False)
    assert dict(route.calls[0].request.url.params) == {"content": "nonconfig"}
    assert text.startswith(
        "L3 VPN service mcp-l3vpn-91: oper-status op-up (last change 2026-09-13T11:00:00Z)"
    )
    assert '"status": "ietf-vpn-common:op-up"' in text
    respx.get(f"{L3VPN_LIST_URL}=smoke-l3vpn-1").mock(return_value=ok(OPER_STATUS_UNKNOWN))
    text = await call_tool_text(
        build(settings), "cnc_get_vpn_service_health", {"vpn_id": "smoke-l3vpn-1"}
    )
    assert text.startswith("L3 VPN service smoke-l3vpn-1: oper-status op-unknown")
    assert "last change" not in text


@respx.mock
async def test_get_vpn_service_health_not_found(settings):
    respx.get(f"{L2VPN_LIST_URL}=nope").mock(return_value=DATA_MISSING_409)
    text = await call_tool_text(
        build(settings), "cnc_get_vpn_service_health", {"vpn_id": "nope", "layer": "l2"}
    )
    assert text.startswith("Error: no L2 VPN service 'nope'")


@respx.mock
async def test_get_vpn_service_health_error(settings):
    respx.get(f"{L3VPN_LIST_URL}=mcp-l3vpn-91").mock(return_value=MALFORMED_400)
    text = await call_tool_text(
        build(settings), "cnc_get_vpn_service_health", {"vpn_id": "mcp-l3vpn-91"}
    )
    assert text.startswith("Error:") and "malformed-message" in text


# --- cnc_get_vpn_underlay_transport --------------------------------------------------


@respx.mock
async def test_get_vpn_underlay_transport(settings):
    url = (
        f"{L3VPN_LIST_URL}=mcp-l3vpn-91/underlay-transport/"
        "cisco-l3vpn-ntw:discovered-underlay-transport"
    )
    route = respx.get(url).mock(return_value=ok(UNDERLAY))
    text = await call_tool_text(
        build(settings), "cnc_get_vpn_underlay_transport", {"vpn_id": "mcp-l3vpn-91"}
    )
    assert_yang(route.calls[0].request, body=False)
    assert "SR policies (1):" in text and "- headend=PE1 color=91 endpoint=10.0.0.3" in text
    assert "RSVP-TE tunnels (1):" in text
    assert "- tunnel-id=1 source=10.0.0.1 destination=10.0.0.3" in text
    text = await call_tool_text(
        build(settings),
        "cnc_get_vpn_underlay_transport",
        {"vpn_id": "mcp-l3vpn-91", "response_format": "json"},
    )
    payload = json.loads(text)
    assert payload["found"] is True and len(payload["sr_policy_refs"]) == 1


@respx.mock
async def test_get_vpn_underlay_transport_409_is_ambiguous_not_an_error(settings):
    url = f"{L2VPN_LIST_URL}=nope/underlay-transport/cisco-l2vpn-ntw:discovered-underlay-transport"
    route = respx.get(url).mock(return_value=DATA_MISSING_409)
    text = await call_tool_text(
        build(settings), "cnc_get_vpn_underlay_transport", {"vpn_id": "nope", "layer": "l2"}
    )
    assert route.called
    assert text.startswith("No discovered underlay transport for L2 VPN service 'nope'")
    assert "EITHER no such VPN service OR nothing discovered" in text


@respx.mock
async def test_get_vpn_underlay_transport_error(settings):
    url = (
        f"{L3VPN_LIST_URL}=mcp-l3vpn-91/underlay-transport/"
        "cisco-l3vpn-ntw:discovered-underlay-transport"
    )
    respx.get(url).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(settings), "cnc_get_vpn_underlay_transport", {"vpn_id": "mcp-l3vpn-91"}
    )
    assert text.startswith("Error:") and "500" in text
    text = await call_tool_text(
        build(settings),
        "cnc_get_vpn_underlay_transport",
        {"vpn_id": "mcp-l3vpn-91", "response_format": "json"},
    )
    assert text.startswith("Error:")


# --- cnc_list_sub_services ------------------------------------------------------------


@respx.mock
async def test_list_sub_services(settings):
    count = mock_rpc("get-sub-service-count", SUB_COUNT_TWO)
    paths = mock_rpc("get-sub-service-paths", SUB_PATHS_TWO)
    text = await call_tool_text(
        build(settings),
        "cnc_list_sub_services",
        {"service_yang_path": f"/{L3VPN_PATH}", "limit": 10},
    )
    assert_yang(count.calls[0].request, body=True)
    assert sent(count) == {
        "cat-inventory-rpc:input": {
            "cat-inventory-rpc:get-sub-service-count-request": {"service-instance-path": L3VPN_PATH}
        }
    }
    assert sent(paths) == {
        "cat-inventory-rpc:input": {
            "cat-inventory-rpc:get-sub-service-paths-request": {
                "collection-header": {"offset": 0, "limit": "10"},
                "service-instance-path": L3VPN_PATH,
            }
        }
    }
    assert text.startswith(f"# Sub-services of {L3VPN_PATH} (2 in total, 2 on this page")
    assert "vpn-node=PE1" in text and "vpn-node=PE2" in text


@respx.mock
async def test_list_sub_services_empty_is_not_an_error(settings):
    mock_rpc("get-sub-service-count", SUB_COUNT_ZERO)
    mock_rpc("get-sub-service-paths", SUB_PATHS_EMPTY)
    text = await call_tool_text(
        build(settings), "cnc_list_sub_services", {"service_yang_path": ODN_PATH}
    )
    assert text.startswith(f"No sub-services under {ODN_PATH} (sub-service-count 0)")
    text = await call_tool_text(
        build(settings),
        "cnc_list_sub_services",
        {"service_yang_path": ODN_PATH, "response_format": "json"},
    )
    payload = json.loads(text)
    assert payload["sub_service_count"] == 0 and payload["items"] == []


@respx.mock
async def test_list_sub_services_blank_path_sends_nothing(settings):
    count = mock_rpc("get-sub-service-count", SUB_COUNT_ZERO)
    paths = mock_rpc("get-sub-service-paths", SUB_PATHS_EMPTY)
    text = await call_tool_text(
        build(settings), "cnc_list_sub_services", {"service_yang_path": " / "}
    )
    assert text.startswith("Error: yang_path is empty")
    assert not count.called and not paths.called


@respx.mock
async def test_list_sub_services_error(settings):
    mock_rpc("get-sub-service-count", NATS_500)
    text = await call_tool_text(
        build(settings), "cnc_list_sub_services", {"service_yang_path": L3VPN_PATH}
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_find_services_on_transport ---------------------------------------------------


@respx.mock
async def test_find_services_on_transport_sr_policy(settings):
    route = mock_rpc("get-associated-services-for-transport", SERVICES_ON_TRANSPORT)
    text = await call_tool_text(
        build(settings),
        "cnc_find_services_on_transport",
        {"headend": "PE1", "color": 91, "endpoint": "10.0.0.3"},
    )
    assert_yang(route.calls[0].request, body=True)
    # Verified: color is a STRING on the wire.
    assert sent(route) == {
        "cat-inventory-rpc:input": {
            "cat-inventory-rpc:get-associated-services-for-transport-request": {
                "sr-policy-ref": {"headend": "PE1", "color": "91", "endpoint": "10.0.0.3"}
            }
        }
    }
    assert text.startswith("# Services on SR policy PE1 color 91 -> 10.0.0.3 (1)")
    assert f"- {L3VPN_PATH}" in text


@respx.mock
async def test_find_services_on_transport_tunnel_and_empty(settings):
    route = mock_rpc("get-associated-services-for-transport", EMPTY_OUTPUT)
    text = await call_tool_text(
        build(settings),
        "cnc_find_services_on_transport",
        {"tunnel_id": "1", "source": "10.0.0.1", "destination": "10.0.0.3"},
    )
    assert sent(route)["cat-inventory-rpc:input"][
        "cat-inventory-rpc:get-associated-services-for-transport-request"
    ] == {"te-tunnel-ref": {"tunnel-id": "1", "source": "10.0.0.1", "destination": "10.0.0.3"}}
    assert text.startswith("No service uses that transport (RSVP-TE tunnel 1 10.0.0.1 -> 10.0.0.3)")
    text = await call_tool_text(
        build(settings),
        "cnc_find_services_on_transport",
        {"headend": "PE1", "color": 91, "endpoint": "10.0.0.3", "response_format": "json"},
    )
    assert json.loads(text) == {
        "transport": {"sr-policy-ref": {"headend": "PE1", "color": "91", "endpoint": "10.0.0.3"}},
        "count": 0,
        "service_paths": [],
    }


@respx.mock
async def test_find_services_on_transport_resolves_a_router_id_headend(settings):
    """The RPC's headend is the NSO device name; a router-id (what cnc_list_sr_policies
    reports) is mapped through the inventory first — the resolved NAME goes on the wire."""
    nodes = respx.post(NODES_QUERY_URL).mock(return_value=ok(PE1_NODE))
    route = mock_rpc("get-associated-services-for-transport", SERVICES_ON_TRANSPORT)
    text = await call_tool_text(
        build(settings),
        "cnc_find_services_on_transport",
        {"headend": "10.0.0.1", "color": 91, "endpoint": "10.0.0.3"},
    )
    assert sent(nodes) == {
        "filter": {"routing_info": {"te_router_id": "10.0.0.1"}},
        "filterData": {"PageSize": 200, "PageNum": 0, "Criteria": ""},
    }
    assert sent(route)["cat-inventory-rpc:input"][
        "cat-inventory-rpc:get-associated-services-for-transport-request"
    ] == {"sr-policy-ref": {"headend": "PE1", "color": "91", "endpoint": "10.0.0.3"}}
    assert text.startswith(
        "# Services on SR policy PE1 color 91 -> 10.0.0.3 (headend resolved from router-id "
        "10.0.0.1) (1)"
    )
    # A device name is sent as given — no inventory lookup.
    text = await call_tool_text(
        build(settings),
        "cnc_find_services_on_transport",
        {"headend": "PE1", "color": 91, "endpoint": "10.0.0.3", "response_format": "json"},
    )
    assert nodes.call_count == 1
    payload = json.loads(text)
    assert payload["transport"]["sr-policy-ref"]["headend"] == "PE1"
    assert "headend_resolved_from" not in payload


@respx.mock
async def test_find_services_on_transport_router_id_lookup_is_checked_client_side(settings):
    """An inventory filter Crosswork does not honour returns every node: the match is still
    made on routing_info.te_router_id, and the NSO provider_node_id wins over host_name."""
    respx.post(NODES_QUERY_URL).mock(return_value=ok(ALL_NODES))
    route = mock_rpc("get-associated-services-for-transport", EMPTY_OUTPUT)
    text = await call_tool_text(
        build(settings),
        "cnc_find_services_on_transport",
        {"headend": "10.0.0.1", "color": 91, "endpoint": "10.0.0.3", "response_format": "json"},
    )
    payload = json.loads(text)
    assert payload["transport"]["sr-policy-ref"]["headend"] == "PE1"
    assert payload["headend_resolved_from"] == "10.0.0.1" and payload["count"] == 0
    assert route.called


@respx.mock
async def test_find_services_on_transport_unresolvable_router_id_sends_nothing(settings):
    respx.post(NODES_QUERY_URL).mock(return_value=ok(NO_NODES))
    route = mock_rpc("get-associated-services-for-transport", SERVICES_ON_TRANSPORT)
    text = await call_tool_text(
        build(settings),
        "cnc_find_services_on_transport",
        {"headend": "10.0.0.9", "color": 91, "endpoint": "10.0.0.3"},
    )
    assert text.startswith("Error: no inventory device has te_router_id 10.0.0.9")
    assert "host_name" in text
    assert not route.called
    # Two devices claiming the same router-id is ambiguous, not a guess.
    twins = {"data": [inventory_node("PE1", "10.0.0.1"), inventory_node("PE1b", "10.0.0.1")]}
    respx.post(NODES_QUERY_URL).mock(return_value=ok(twins))
    text = await call_tool_text(
        build(settings),
        "cnc_find_services_on_transport",
        {"headend": "10.0.0.1", "color": 91, "endpoint": "10.0.0.3"},
    )
    assert text.startswith("Error: te_router_id 10.0.0.1 belongs to 2 inventory devices")
    assert not route.called
    # An inventory failure during the lookup is an error too.
    respx.post(NODES_QUERY_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(settings),
        "cnc_find_services_on_transport",
        {"headend": "10.0.0.1", "color": 91, "endpoint": "10.0.0.3"},
    )
    assert text.startswith("Error:") and "500" in text
    assert not route.called


PE2_NODE = {"data": [inventory_node("PE2", "10.0.0.3")], "total_count": 5, "result_count": 1}


@respx.mock
async def test_find_services_on_transport_resolves_a_host_name_endpoint(settings):
    """The RPC's endpoint is the policy endpoint IP (the tail-end's TE router-id); a host
    name is mapped through the inventory's host_name filter first — the router-id goes on
    the wire, and the label / JSON say where it came from (agent scenario 2026-09-14)."""
    nodes = respx.post(NODES_QUERY_URL).mock(return_value=ok(PE2_NODE))
    route = mock_rpc("get-associated-services-for-transport", SERVICES_ON_TRANSPORT)
    text = await call_tool_text(
        build(settings),
        "cnc_find_services_on_transport",
        {"headend": "PE1", "color": 91, "endpoint": "PE2"},
    )
    assert sent(nodes) == {
        "filter": {"host_name": "PE2"},
        "filterData": {"PageSize": 200, "PageNum": 0, "Criteria": ""},
    }
    assert sent(route)["cat-inventory-rpc:input"][
        "cat-inventory-rpc:get-associated-services-for-transport-request"
    ] == {"sr-policy-ref": {"headend": "PE1", "color": "91", "endpoint": "10.0.0.3"}}
    assert text.startswith(
        "# Services on SR policy PE1 color 91 -> 10.0.0.3 (endpoint resolved from host name "
        "PE2) (1)"
    )
    text = await call_tool_text(
        build(settings),
        "cnc_find_services_on_transport",
        {"headend": "PE1", "color": 91, "endpoint": "pe2", "response_format": "json"},
    )
    payload = json.loads(text)
    assert payload["transport"]["sr-policy-ref"]["endpoint"] == "10.0.0.3"
    assert payload["endpoint_resolved_from"] == "pe2"
    assert "headend_resolved_from" not in payload


@respx.mock
async def test_find_services_on_transport_resolves_both_ends(settings):
    """Router-id headend + host-name endpoint: two inventory lookups, both mapped."""

    def answer(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        return ok(PE2_NODE if "host_name" in body["filter"] else PE1_NODE)

    nodes = respx.post(NODES_QUERY_URL).mock(side_effect=answer)
    route = mock_rpc("get-associated-services-for-transport", EMPTY_OUTPUT)
    text = await call_tool_text(
        build(settings),
        "cnc_find_services_on_transport",
        {"headend": "10.0.0.1", "color": 91, "endpoint": "PE2", "response_format": "json"},
    )
    assert nodes.call_count == 2
    payload = json.loads(text)
    assert payload["transport"] == {
        "sr-policy-ref": {"headend": "PE1", "color": "91", "endpoint": "10.0.0.3"}
    }
    assert payload["headend_resolved_from"] == "10.0.0.1"
    assert payload["endpoint_resolved_from"] == "PE2"
    assert payload["count"] == 0 and route.called


@respx.mock
async def test_find_services_on_transport_unknown_endpoint_is_an_error_not_an_empty_match(
    settings,
):
    """A name the inventory does not know must not reach the RPC (where the wrong form
    silently matches nothing and reads like 'no service uses that transport')."""
    respx.post(NODES_QUERY_URL).mock(return_value=ok(NO_NODES))
    route = mock_rpc("get-associated-services-for-transport", EMPTY_OUTPUT)
    text = await call_tool_text(
        build(settings),
        "cnc_find_services_on_transport",
        {"headend": "PE1", "color": 100, "endpoint": "PE9"},
    )
    assert text.startswith("Error: unknown endpoint 'PE9'")
    assert "TE router-id" in text and "cnc_list_topology_nodes" in text
    assert not route.called
    # The filter was not honoured (unfiltered set): still matched client-side, no match.
    respx.post(NODES_QUERY_URL).mock(return_value=ok(ALL_NODES))
    text = await call_tool_text(
        build(settings),
        "cnc_find_services_on_transport",
        {"headend": "PE1", "color": 100, "endpoint": "PE9"},
    )
    assert text.startswith("Error: unknown endpoint 'PE9'") and not route.called
    # A known device without a te_router_id cannot be mapped either.
    bare = {"data": [{"uuid": PE1_UUID, "host_name": "PE2"}], "result_count": 1}
    respx.post(NODES_QUERY_URL).mock(return_value=ok(bare))
    text = await call_tool_text(
        build(settings),
        "cnc_find_services_on_transport",
        {"headend": "PE1", "color": 100, "endpoint": "PE2"},
    )
    assert text.startswith("Error: endpoint 'PE2' is an inventory device without a te_router_id")
    assert "cnc_update_device" in text and not route.called
    # Two devices with the same host name is ambiguous, not a guess.
    twins = {"data": [inventory_node("PE2", "10.0.0.3"), inventory_node("pe2", "10.0.0.7")]}
    respx.post(NODES_QUERY_URL).mock(return_value=ok(twins))
    text = await call_tool_text(
        build(settings),
        "cnc_find_services_on_transport",
        {"headend": "PE1", "color": 100, "endpoint": "PE2"},
    )
    assert text.startswith("Error: endpoint 'PE2' matches 2 inventory devices")
    assert not route.called
    # An inventory failure during the lookup is an error too.
    respx.post(NODES_QUERY_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(settings),
        "cnc_find_services_on_transport",
        {"headend": "PE1", "color": 100, "endpoint": "PE2"},
    )
    assert text.startswith("Error:") and "500" in text and not route.called


@respx.mock
async def test_find_services_on_transport_incomplete_ref_sends_nothing(settings):
    route = mock_rpc("get-associated-services-for-transport", SERVICES_ON_TRANSPORT)
    text = await call_tool_text(
        build(settings), "cnc_find_services_on_transport", {"headend": "PE1", "color": 91}
    )
    assert text.startswith("Error: An SR policy reference needs headend, color and endpoint")
    text = await call_tool_text(build(settings), "cnc_find_services_on_transport", {})
    assert text.startswith("Error: Give either an SR policy")
    assert not route.called


@respx.mock
async def test_find_services_on_transport_error(settings):
    mock_rpc("get-associated-services-for-transport", NATS_500)
    text = await call_tool_text(
        build(settings),
        "cnc_find_services_on_transport",
        {"headend": "PE1", "color": 91, "endpoint": "10.0.0.3"},
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_list_function_packs -----------------------------------------------------------


@respx.mock
async def test_list_function_packs(settings):
    info = respx.get(f"{FP}/getDeploymentInfo").mock(return_value=ok(DEPLOYMENT_INFO))
    packages = respx.get(f"{FP}/packages").mock(return_value=ok(PACKAGES))
    text = await call_tool_text(build(settings), "cnc_list_function_packs", {})
    for route in (info, packages):
        request = route.calls[0].request
        assert request.headers["Accept"] == "application/json"  # plain JSON, no YANG headers
        assert "Content-Type" not in request.headers
    assert "deploymentState=DEPLOYED etcdCfpArchiveVersion=7.2.43" in text
    assert "Packages (2):" in text
    assert (
        "- **http://cisco.com/ns/nso/cfp/cisco-ts-sr-policies** (service type 'policy') "
        "model-version=2022-01-12 service-layer=TRANSPORT" in text
    )
    assert (
        "  - SID-List: cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/sid-list " in text
    )
    assert "(service type 'odn-template')" in text


@respx.mock
async def test_list_function_packs_json_and_error(settings):
    respx.get(f"{FP}/getDeploymentInfo").mock(return_value=ok(DEPLOYMENT_INFO))
    respx.get(f"{FP}/packages").mock(return_value=ok(PACKAGES))
    text = await call_tool_text(
        build(settings), "cnc_list_function_packs", {"response_format": "json"}
    )
    payload = json.loads(text)
    assert payload["deployment"]["deploymentState"] == "DEPLOYED"
    assert len(payload["packages"]) == 2
    respx.get(f"{FP}/getDeploymentInfo").mock(
        return_value=httpx.Response(404, text="404 page not found")
    )
    text = await call_tool_text(build(settings), "cnc_list_function_packs", {})
    assert text.startswith("Error: API request failed with status 404")
