"""Composite ("one call") tools end-to-end through the FULL server.

The server is built with ``build_server`` so every sibling tool a composite calls is
registered and answers through its own verified code path; only HTTP is mocked
(respx). Each composite gets a happy path (the verdict and the sub-tools hit), a
partial-failure path (one route answering 500 -> that section unavailable, the
verdict still produced, no "Error:" prefix on the whole answer), the JSON shape, and —
for the write composites — the gating and the stop-on-failed-commit rule. The drift
guard at the end checks every argument name a composite forwards
(``composite.SIBLING_CALLS``) against the sibling's published input schema, and that
every sub-call the composites actually made is declared there.

Fixtures reuse the verified wire shapes of the sibling modules' own tests (device
records, alarms, EMF nodes, the topology collection, COE / CAT RPC outputs, NSO proxy
answers); addresses and names are documentation ones, not a lab's.
"""

from __future__ import annotations

import json
import logging
import re
import time
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import respx
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from cnc_mcp import polling
from cnc_mcp.auth import StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.config import Settings
from cnc_mcp.safety import AppContext
from cnc_mcp.server import build_server
from cnc_mcp.tools import composite
from cnc_mcp.tools.composite import (
    ALARM_SCAN_LIMIT,
    CHECKING_TRANSIENT_SECONDS,
    COMPOSITE_TOOLS,
    MAX_POLICY_SERVICE_READS,
    OAM_MPLS_ONLY,
    OPTIONAL_WRITE_SIBLINGS,
    PM_FRESH_HOURS,
    REACHABILITY_CADENCE_SECONDS,
    SIBLING_CALLS,
    SRV6_PM_TEMPLATE,
    TRIAGE_LIMIT,
    WRITE_COMPOSITES,
    WRITE_SIBLINGS,
    Call,
    Composer,
    chronic_history,
    device_findings,
    device_lines,
    endpoint_locators,
    endpoint_nodes,
    field_of,
    first_two_nodes,
    hop_text_for,
    is_advisory,
    is_xr,
    link_srv6_facts,
    locator_rows,
    mentions,
    microservice_for,
    node_srv6_facts,
    onbox_endpoint,
    onbox_srv6_text,
    parse_payload,
    pm_freshness_lines,
    pod_of,
    policy_service_candidates,
    policy_service_matches,
    route_lines,
    srv6_devices_with_block,
    srv6_dry_run_text,
    summary_endx_coverage,
    summary_locator_coverage,
    vpn_parts,
)
from cnc_mcp.tools.te_state import sr_policy_pm_url, sr_policy_url
from tests.conftest import BASE_URL, call_tool_text

# --- URLs (one per sibling code path the composites exercise) ---------------------------

INVENTORY = f"{BASE_URL}/crosswork/inventory/v1"
NODES_QUERY = f"{INVENTORY}/nodes/query"
NODES_COUNT = f"{INVENTORY}/nodes/count"
OPER_SUMMARY = f"{INVENTORY}/nodes/operstatesummary"
REACH_SUMMARY = f"{INVENTORY}/nodes/reachabilitysummary"
LICENSE_COUNT = f"{INVENTORY}/sysoids/licensetype/count/query"
COLLECTION_SUMMARY = f"{INVENTORY}/networkelement/collectionstatussummary/query"
PROVIDERS_QUERY = f"{INVENTORY}/providers/query"
CHECK_SYNC = f"{INVENTORY}/nso/check-sync"
ALARMS_QUERY = f"{BASE_URL}/crosswork/alarms/v1/query"
EVENTS_QUERY = f"{BASE_URL}/crosswork/alarms/v1/event/query"
RTM_ALARMS = f"{BASE_URL}/crosswork/alarm/restconf/data/v2/rtm:alarm"
EMS_NODE = f"{BASE_URL}/crosswork/inventory/restconf/data/v2/resource-physical:node"
TOPOLOGY_DATA = f"{BASE_URL}/crosswork/nbi/topology/v3/restconf/data"
NETWORKS_URL = f"{TOPOLOGY_DATA}/ietf-network-state:networks"
NODE_PE1_URL = f"{NETWORKS_URL}/network=Default-network/node=PE1"
SR_POLICIES_URL = f"{TOPOLOGY_DATA}/cisco-crosswork-segment-routing-policy:sr-policies"
P2MP_URL = f"{TOPOLOGY_DATA}/cisco-crosswork-segment-routing-p2mp-policy:p2mp-policies"
RSVP_URL = f"{TOPOLOGY_DATA}/cisco-crosswork-rsvp-te-tunnel:rsvp-te-tunnels"
PM_URL = (
    f"{TOPOLOGY_DATA}/cisco-crosswork-performance-metrics:sr-policies-performance-metrics/"
    "sr-policy-pm"
)
CONFIG_BACKUP = f"{BASE_URL}/crosswork/config/v1/config-backup"
STATISTICS_URL = f"{BASE_URL}/crosswork/performance/v1/dashboards/statistics"
NPM = f"{BASE_URL}/crosswork/optima-analytics/api/v1"
PLATFORM = f"{BASE_URL}/crosswork/platform/v2"
CLUSTER_SUMMARY_URL = f"{PLATFORM}/cluster/summary/list"
INFRA_SUMMARY_URL = f"{PLATFORM}/cluster/infra/summary"
APP_HEALTH_URL = f"{PLATFORM}/cluster/app/health/list"
MICROSERVICES_URL = f"{PLATFORM}/cluster/microservice/list/query"
DG_QUERY_URL = f"{BASE_URL}/crosswork/dg-manager/v2/dg/query"
COLLECTION = f"{BASE_URL}/crosswork/collection/v1"
COLLECTION_COUNT = f"{COLLECTION}/collectionjob/count/query"
COLLECTION_JOB_SUMMARY = f"{COLLECTION}/collectionjob/summary/query"
COLLECTION_STATE = f"{COLLECTION}/collectionjob/state/query"
OPERATIONS = f"{BASE_URL}/crosswork/nbi/optimization/v3/restconf/operations"
COE = "cisco-crosswork-optimization-engine-operations"
SRP = "cisco-crosswork-optimization-engine-sr-policy-operations"
OAM = "cisco-crosswork-optimization-engine-oam-operations"
CAT_RPC = f"{BASE_URL}/crosswork/nbi/cat-inventory/v1/restconf/operations/cat-inventory-rpc"
CAT_DATA = f"{BASE_URL}/crosswork/nbi/cat-inventory/v1/restconf/data"
NSO_DATA = f"{BASE_URL}/crosswork/proxy/nso/restconf/data"
L3VPN_LIST = "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service"
L3VPN_PLAN_LIST = "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service-plan"
L3VPN_CAT_PLAN_LIST = "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/cisco-l3vpn-ntw:vpn-service-plan"
PROBE_STATUS_URL = f"{BASE_URL}/crosswork/probemgr/v1/probeStatusReport"

PE1_UUID = "2a9b7c1e-0f3d-4b8a-9c6e-1d2f3a4b5c6d"
PE2_UUID = "ec35be58-de93-49e5-891b-a1c4a11c72e4"
P1_UUID = "7f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f"
REACHABLE = "CONN_STATE_REACHABLE"
UNREACHABLE = "CONN_STATE_UNREACHABLE"
GI0 = "GigabitEthernet0/0/0/0"
GI1 = "GigabitEthernet0/0/0/1"
VPN_ID = "doc-l3vpn-1"
L3VPN_PATH = f"{L3VPN_LIST}={VPN_ID}"
QUERY_ID = "SPQ-324616899"
NATS_500 = httpx.Response(500, json={"error": "NATS request failed"})


def rpc(module: str, name: str) -> str:
    return f"{OPERATIONS}/{module}:{name}"


def out(module: str, **fields: Any) -> dict:
    return {f"{module}:output": fields}


def cat(name: str, response: dict) -> dict:
    return {"cat-inventory-rpc:output": {f"{name}-response": response}}


def ok(body: Any) -> httpx.Response:
    return httpx.Response(200, json=body)


# --- inventory ------------------------------------------------------------------------


# Fixture epoch stamps: ONE_DAY_AGO keeps ages stable across runs (relative to now).
NOW_EPOCH = int(time.time())
ONE_DAY_AGO = str(NOW_EPOCH - 86400)
ONE_DAY_AGO_MS = str((NOW_EPOCH - 86400) * 1000)


def transport(
    kind: str, port: int, state: str = REACHABLE, error: str = "", stamp: str = ONE_DAY_AGO
) -> dict:
    return {
        "type": f"ROBOT_MSVC_TRANS_{kind}",
        "ipaddrs": [
            {"inet_af": "ROBOT_INET_ADDR_TYPE_v4", "inet_addr": "192.0.2.11", "mask": "24"}
        ],
        "port": port,
        "timeout": "0",
        "reachability_state": state,
        "reachability_state_upd_time": stamp,
        "error": error,
    }


def device(
    uuid: str,
    host: str,
    router_id: str,
    *,
    reach: str = REACHABLE,
    oper: str = "ROBOT_OPER_STATE_OK",
    nso_state: str | None = "SYNCED",
    transports: list[dict] | None = None,
    errors: list[str] | None = None,
) -> dict:
    record: dict[str, Any] = {
        "uuid": uuid,
        "host_name": host,
        "node_ip": {"inet_af": "ROBOT_INET_ADDR_TYPE_v4", "inet_addr": "192.0.2.11", "mask": "24"},
        "admin_state": "ROBOT_ADMIN_STATE_UP",
        "reachability_state": reach,
        "operational_state": oper,
        "reachability_check": "REACH_CHECK_ENABLE",
        "profile": "lab-xrd",
        "dg_name": "dg-pool-1",
        "connectivity_info": transports
        if transports is not None
        else [transport("SNMP", 161), transport("SSH", 22)],
        "product_info": {"device_type": "NODE_TYPE_ROUTER", "capability": ["SNMP", "YANG_CLI"]},
        "routing_info": {"te_router_id": router_id, "global_isis_system_id": "0000.0000.0001"},
        "providers_family": {
            "ROBOT_PROVIDER_NSO": {
                "providers": {"nso": {"provider_name": "nso", "provider_node_id": host}}
            }
        },
        "tag_names": [],
        "uptime": "0w1d14h4m30s",
        "last_upd_time": ONE_DAY_AGO,
        "reachability_state_upd_time": ONE_DAY_AGO,
        "state_map": {
            "1": {"value": "UP", "last_updated_time": ONE_DAY_AGO},
            "2": {"value": "UP", "last_updated_time": ONE_DAY_AGO},
        },
        "errors": errors or [],
    }
    if nso_state is not None:
        record["nso_state"] = nso_state
        record["NsoMsg"] = ""
    return record


PE1 = device(PE1_UUID, "PE1", "10.0.0.1")
PE2 = device(PE2_UUID, "PE2", "10.0.0.3")
P1 = device(P1_UUID, "P1", "10.0.0.2")
P2_UUID = "1b44ade3-0000-4000-8000-00000000p2p2"
CDG_TEXT = "[Device: 192.0.2.14] Reachability request did not receive any response from CDG"


def stuck_checking(uuid: str, host: str, router_id: str, *, age_seconds: int) -> dict:
    """A device the way P2 looked live on 2026-09-14: REACHABLE, admin UP, but
    ROBOT_OPER_STATE_CHECKING with only the key-0 placeholder in its state_map
    (as cnc_list_devices sends it: no ``element``), stamped ``age_seconds`` ago; the
    transports' REACHABLE stamps are older still; the record's errors carry the
    CDG no-response texts."""
    # Stamped against the clock at CALL time, not import time: a "(2m ago)" assertion must
    # hold however long the rest of the suite ran before this test.
    now = int(time.time())
    stamp = str(now - age_seconds)
    older = str(now - age_seconds - 6 * 3600)
    record = device(
        uuid,
        host,
        router_id,
        oper="ROBOT_OPER_STATE_CHECKING",
        transports=[transport("SNMP", 161, stamp=older), transport("SSH", 22, stamp=older)],
        errors=[f"Major - {CDG_TEXT}"],
    )
    record["state_map"] = {
        "0": {"value": "UP", "last_updated_time": stamp, "next_check_time": stamp}
    }
    record["last_upd_time"] = stamp
    record["reachability_state_upd_time"] = older
    return record


P2_STUCK = stuck_checking(P2_UUID, "P2", "10.0.0.4", age_seconds=6 * 3600)


def mock_nodes(*records: dict) -> respx.Route:
    """nodes/query: a uuid filter answers that record; a host_name filter the matching
    record(s) ('*' = all); each answer's nso_timestamp advances so a check-sync poll
    always sees a fresher reading than the pre-check one and settles at once."""
    stamp = {"n": 1789300000}

    def answer(request: httpx.Request) -> httpx.Response:
        stamp["n"] += 1
        body = json.loads(request.content)
        filters = body.get("filter") or {}
        rows = list(records)
        if filters.get("uuid"):
            rows = [r for r in rows if r["uuid"] == filters["uuid"]]
        elif filters.get("host_name") and filters["host_name"] != "*":
            wanted = filters["host_name"].lower()
            rows = [r for r in rows if r["host_name"].lower() == wanted]
        elif (filters.get("routing_info") or {}).get("te_router_id"):
            wanted_id = filters["routing_info"]["te_router_id"]
            rows = [r for r in rows if r["routing_info"]["te_router_id"] == wanted_id]
        rows = [{**r, "nso_timestamp": str(stamp["n"])} if "nso_state" in r else r for r in rows]
        if not rows:
            return ok({"total_count": len(records)})
        return ok({"data": rows, "result_count": len(rows), "total_count": len(records)})

    return respx.post(NODES_QUERY).mock(side_effect=answer)


# --- alarms / events ----------------------------------------------------------------------


def alarm(alarm_id: str, state: str, obj: str, text: str, **extra: Any) -> dict:
    row = {
        "AlarmId": alarm_id,
        "AlarmCategory": "System",
        "State": state,
        "Acknowledge": False,
        "Description": text,
        "object_id": obj,
        "object_description": obj,
        "origin_app_id": "capp-infra:DLM",
        "origin_service_id": "dlm",
        "event_type": 1001,
        "events_count": 1,
        "Created": "1789200000000",
        "Updated": "1789200000000",
        "Events": [
            {
                "EventId": f"{alarm_id}-e1",
                "EventSeverity": state,
                "Description": text,
                "Timestamp": "1789200000000",
                "EventCategory": "System",
                "alarm_id": alarm_id,
            }
        ],
    }
    row.update(extra)
    return row


PE1_ALARM = alarm("a-pe1", "Major", f"Device PE1 ({PE1_UUID})", "Device PE1 is unreachable")
PE10_ALARM = alarm("a-pe10", "Critical", "Device PE10 (x)", "Device PE10 is unreachable")
INFO_ALARM = alarm("a-info", "Info", "Collection", "pipeline health updating: HEALTHY")
# A pod-health alarm as seen live: 0 events, no Events key, unchanged for weeks.
STALE_ALARM = {
    "AlarmId": "a-stale",
    "AlarmCategory": "System",
    "State": "Major",
    "Acknowledge": False,
    "Description": "cwm-api-service is down.",
    "object_id": "cwm-solutions-inventory",
    "object_description": "cwm-api-service",
    "origin_app_id": "capp-cwm-solutions",
    "origin_service_id": "cwm-api-service-57b9448ffb-c8zxt",
    "event_type": 0,
    "events_count": 0,
    "Created": "1700000000000",
    "Updated": "1700000000000",
}
# A cleared alarm as the platform sends it: Description is the CLEARING event's text and
# the fault it cleared lives only in Events[] (verified live, see cnc_search_alarms).
CLEARED_ALARM = alarm(
    "a-clear",
    "Clear",
    "Device P1 (p1)",
    "Device P1 is reachable",
    events_count=2,
    Events=[
        {
            "EventId": "a-clear-e2",
            "EventSeverity": "Clear",
            "Description": "Device P1 is reachable",
            "Timestamp": "1789200000000",
            "EventCategory": "System",
            "alarm_id": "a-clear",
        },
        {
            "EventId": "a-clear-e1",
            "EventSeverity": "Major",
            "Description": "Device P1 is unreachable",
            "Timestamp": "1789100000000",
            "EventCategory": "System",
            "alarm_id": "a-clear",
        },
    ],
)


def mock_alarms(*rows: dict) -> respx.Route:
    """alarms/v1/query honouring openAlarmsOnly and the 'limit N page M' criteria the
    sibling pages with (a short page ends its fetch)."""

    def answer(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        shown = [r for r in rows if not (body.get("openAlarmsOnly") and r["State"] == "Clear")]
        found = re.search(r"limit (\d+) page (\d+)", str(body.get("criteria") or ""))
        if found:
            size, page = int(found.group(1)), int(found.group(2))
            shown = shown[page * size : (page + 1) * size]
        return ok({"state": "Success", "alarms": shown})

    return respx.post(ALARMS_QUERY).mock(side_effect=answer)


EVENT_PE1 = {
    "EventId": "e-1",
    "alarm_id": "a-pe1",
    "EventSeverity": "Major",
    "EventCategory": "System",
    "Description": "SNMP timeout",
    "Timestamp": "1789200000000",
    "object_description": f"Device PE1 ({PE1_UUID})",
    "origin_app_id": "capp-infra:DLM",
    "event_type": 1001,
}
EVENT_OTHER = {**EVENT_PE1, "EventId": "e-2", "object_description": "Device P1 (p1)"}
EVENTS = {"state": "Success", "events": [EVENT_PE1, EVENT_OTHER]}

EMPTY_RTM = {
    "com.response-message": {
        "com.header": {"com.firstIndex": 0, "com.lastIndex": -1, "com.iteratorId": 0}
    }
}
RTM_MAJOR = {
    "com.response-message": {
        "com.header": {"com.firstIndex": 0, "com.lastIndex": 0, "com.iteratorId": 5},
        "com.data": {
            "alm.alarm": [
                {
                    "alm.uuid": "6a664005-0b24-43a7-aafa-64a399140209",
                    "alm.type": "device",
                    "alm.perceived-severity": "major",
                    "alm.description": "Nbr 192.0.2.41 on GigabitEthernet0/1/7 from 2WAY to DOWN",
                    "alm.category": "OSPF",
                    "alm.source-object-name": "GigabitEthernet0/1/7",
                    "alm.node-ref": "PE1",
                    "alm.ack-state": "acknowledged",
                    "alm.system-update-time-iso8601": "2026-09-13T10:01:10.981Z",
                }
            ]
        },
    }
}

# --- EMF node --------------------------------------------------------------------------


def ems_node(lifecycle: str = "MANAGED_AND_SYNCHRONIZED", comm: str = "Reachable") -> dict:
    return {
        "com.response-message": {
            "com.header": {"com.firstIndex": 0, "com.lastIndex": 0, "com.iteratorId": 0},
            "com.data": {
                "nd.node": [
                    {
                        "nd.fdn": "MD=CISCO_EMS!ND=PE1",
                        "nd.name": "PE1",
                        "nd.management-address": "192.0.2.11",
                        "nd.lifecycle-state": lifecycle,
                        "nd.communication-state": comm,
                        "nd.collection-status": '<status><general code="SUCCESS"/></status>',
                        "nd.collection-time": "2026-09-13T08:12:41.117Z",
                        "nd.last-boot-time": "2026-09-12T13:40:05.000Z",
                        "nd.software-type": "IOS XR",
                        "nd.software-version": "24.3.1",
                        "nd.sys-up-time": "0d18h32m16s",
                        "nd.uuid": PE1_UUID,
                    }
                ]
            },
        }
    }


# --- topology ---------------------------------------------------------------------------

TP_LIST = "ietf-network-topology-state:termination-point"
TP_ATTRS = "cisco-crosswork-topology-state:termination-point-attributes"
L3_NODE = "ietf-l3-unicast-topology-state:l3-node-attributes"
SR_MPLS = "ietf-sr-mpls-topology-state:sr-mpls"
PCEP = "cisco-crosswork-l3-te-topology:node-pcep-sessions"
LINK_LIST = "ietf-network-topology-state:link"
SPF_ALGORITHM = "ietf-segment-routing-common:prefix-sid-algorithm-shortest-path"


def tp(tp_id: str) -> dict:
    return {
        "tp-id": tp_id,
        TP_ATTRS: {"l2-termination-point-attributes": {"encapsulation-type": "ethernet"}},
    }


def sr_node(node_id: str, index: int, pcep: bool = False) -> dict:
    router_id = f"10.0.0.{index}"
    attrs: dict[str, Any] = {
        "name": node_id,
        "router-id": [router_id],
        SR_MPLS: {"srgb": [{"lower-bound": 16000, "upper-bound": 23999}], "msd": 10},
        "prefix": [
            {
                "prefix": f"{router_id}/32",
                SR_MPLS: [
                    {
                        "algorithm-value": 0,
                        "algorithm": SPF_ALGORITHM,
                        "value-type": "index",
                        "is-node": True,
                        "start-sid": index,
                    }
                ],
            }
        ],
    }
    if pcep:
        attrs[PCEP] = [
            {
                "pcc-address": router_id,
                "pce-address": "10.0.0.5",
                "capability-sr": True,
                "capability-update": True,
                "stateful": True,
                "msd": 10,
                "capability-instantiate": True,
            }
        ]
    return {"node-id": node_id, TP_LIST: [tp(GI0), tp(GI1), tp("Loopback0")], L3_NODE: attrs}


TOPO_PE1 = sr_node("PE1", 1, pcep=True)
TOPO_P1 = sr_node("P1", 2)
TOPO_PE2 = sr_node("PE2", 3, pcep=True)
TOPO_PCE = sr_node("PCE", 5)  # the PCE is itself an IS-IS node (router-id 10.0.0.5)
ISIS_LINK = {
    "link-id": f"PE1 : {GI0} : P1 : {GI0} : ISIS_IPV4_L2",
    "source": {"source-node": "PE1", "source-tp": GI0},
    "destination": {"dest-node": "P1", "dest-tp": GI0},
}
NETWORK = {
    "network-id": "Default-network",
    "node": [TOPO_PE1, TOPO_P1, TOPO_PE2, TOPO_PCE],
    LINK_LIST: [ISIS_LINK],
}
NETWORKS = {"ietf-network-state:networks": {"network": [NETWORK]}}
NODE_PE1_KEYED = {"ietf-network-state:node": [TOPO_PE1]}


def nbi_policy(flag_c: int = 1, oper: str = "UP") -> dict:
    hop = {"type": "IPV4-NODE-SID", "local-ip-addr": "10.0.0.3", "label": 16003}
    return {
        "headend": "10.0.0.1",
        "endpoint": "10.0.0.3",
        "color": 100,
        "policy-details": {
            "pcep-info": {"pcep-flag-c": flag_c},
            "path": [
                {
                    "optimization-metric": {"metric-type": "IGP-METRIC", "metric-value": 20},
                    "segment-list": [{"weight": 1, "hop": [hop]}],
                    "preference": 100,
                    "oper-state": oper,
                    "hop": [hop],
                    "path-type": "PT-DYNAMIC",
                    "path-name": "doc-dyn-100",
                }
            ],
            "binding-sid": 24005,
            "update-time": "1789293787548",
            "pce-controlled": True,
            "pcc-address": "10.0.0.1",
        },
        "admin-state": "UP",
        "oper-state": oper,
        "sr-policy-type": "REGULAR",
    }


def policy_url(color: int) -> str:
    return f"{SR_POLICIES_URL}/policy=10.0.0.1,10.0.0.3,{color}"


def keyed_policy(policy: dict) -> dict:
    return {"cisco-crosswork-segment-routing-policy:policy": [policy]}


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
KEY_PE1_PE2 = {"head-end": "10.0.0.1", "end-point": "10.0.0.3", "color": 100}
ROUTE = [
    {"node": "PE1", "interface": GI0, "interface-use": "1"},
    {"node": "P1", "interface": GI1, "interface-use": "1"},
]
ROUTES_OUT = out(
    COE,
    status="accepted",
    results=[{**KEY_PE1_PE2, "path-computation-status": "success", "igp-route": ROUTE}],
)
METRICS_OUT = out(
    COE,
    status="accepted",
    results=[
        {
            **KEY_PE1_PE2,
            "path-computation-status": "success",
            "igp-metric": 20,
            "te-metric": 20,
            "delay": 20,
        }
    ],
)
UTILIZATIONS = [
    {"tst": "2026-09-13T12:01:36Z", "util": 0.0},
    {"tst": "2026-09-13T12:06:36Z", "util": 2.5},
]
MAX_UTIL = {
    "maxUtilization": 2.5,
    "success": True,
    "message": "Successfully found Maximum Utilization",
}
LSP_DELAY = [
    {
        "preferenceId": 100,
        "minimumDelay": 2,
        "maximumDelay": 8,
        "averageDelay": 5,
        "delayVariance": 6,
        "tst": "2026-09-13T12:01:36Z",
    }
]
MAX_DELAY = {"maxDelay": 5, "success": True, "message": "Successfully found Maximum Average Delay"}
SERVICES_ON_TRANSPORT = cat("get-associated-services-for-transport", {"service-path": [L3VPN_PATH]})
POLICY_SERVICE_PATH = (
    "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/policy=doc-pol-100"
)
POLICY_SERVICES = cat(
    "get-all-services",
    {
        "collection-data": {
            "service-info": [
                {
                    "service-name": "doc-pol-100",
                    "service-type": "{http://cisco.com/ns/nso/cfp/cisco-ts-sr-policies}policy",
                    "yang-path": POLICY_SERVICE_PATH,
                    "plan-yang-path": POLICY_SERVICE_PATH.replace("policy=", "policy-plan="),
                }
            ]
        },
        "collection-header": {"offset": 0, "count": 1},
    },
)
POLICY_SERVICE = {
    "cisco-sr-te-cfp-sr-policies:policy": [
        {
            "name": "doc-pol-100",
            "head-end": [{"name": "PE1"}],
            "tail-end": "10.0.0.3",
            "color": 100,
            "path": [{"preference": 100, "dynamic": {"metric-type": "igp", "pce": {}}}],
        }
    ]
}
# NSO's CDB copy of PE1's segment-routing subtree (verified live 2026-09-14; the shape
# tests/test_tools_nso.py checks cnc_get_nso_device_config against).
NSO_SR_CONFIG_URL = (
    f"{NSO_DATA}/tailf-ncs:devices/device=PE1/config/tailf-ned-cisco-ios-xr:segment-routing"
)
NSO_CONFIG_SR = {
    "tailf-ned-cisco-ios-xr:segment-routing": {
        "traffic-eng": {
            "policy": [
                {
                    "name": "doc-dyn-100",
                    "color": {"value": 100, "end-point": {"ipv4": "10.0.0.3"}},
                    "candidate-paths": {
                        "preference": [
                            {"id": 100, "dynamic": {"pcep": {}, "metric": {"type": "igp"}}}
                        ]
                    },
                }
            ],
            "pcc": {
                "source-address": {"ipv4": "10.0.0.1"},
                "pce": {"address": {"ipv4": [{"address": "10.0.0.5"}]}},
                "report-all": [None],
            },
        }
    }
}
POLICY_QNAME = "{http://cisco.com/ns/nso/cfp/cisco-ts-sr-policies}policy"
POLICY_LIST = "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/policy"
L3VPN_QNAME = "{urn:ietf:params:xml:ns:yang:ietf-l3vpn-ntw}vpn-service"


def service_info(name: str, qname: str, yang_path: str) -> dict:
    return {
        "service-name": name,
        "service-type": qname,
        "yang-path": yang_path,
        "plan-yang-path": yang_path.replace("policy=", "policy-plan=").replace(
            L3VPN_LIST, L3VPN_CAT_PLAN_LIST
        ),
    }


def all_services(*infos: dict) -> dict:
    """A get-all-services answer; with no info the collection-data container is absent
    (verified live: that is how CAT says 'no match')."""
    response: dict[str, Any] = {"collection-header": {"offset": 0, "count": len(infos)}}
    if infos:
        response["collection-data"] = {"service-info": list(infos)}
    return cat("get-all-services", response)


def policy_service_object(name: str, color: int, headend: str, tail: str) -> dict:
    return {
        "cisco-sr-te-cfp-sr-policies:policy": [
            {
                "name": name,
                "head-end": [{"name": headend}],
                "tail-end": tail,
                "color": color,
                "path": [{"preference": 100, "dynamic": {"metric-type": "igp", "pce": {}}}],
            }
        ]
    }


# --- platform / health ----------------------------------------------------------------------


def health(obj_name: str, total: int, healthy: int, degraded: int = 0, down: int = 0) -> dict:
    state = "Healthy" if degraded == 0 and down == 0 else "Degraded"
    return {
        "state": state,
        "total": total,
        "healthy": healthy,
        "degraded": degraded,
        "down": down,
        "obj_name": obj_name,
        "availability": "Not protected",
    }


CLUSTER_SUMMARY = {
    "cluster_summary": {
        "health_summary": health("", 1, 1),
        "cluster_id": "day0-cluster",
        "crosswork_ip_model": "IPV4",
    }
}
INFRA_SUMMARY = {"name": "capp-infra", "health_summary": health("capp-infra", 37, 37)}
APP_HEALTH = {
    "app_health_summary": [
        {"health_summary": health("capp-infra", 37, 37), "recommendation": "None"},
        {"health_summary": health("capp-coe", 12, 12), "recommendation": "None"},
        {"health_summary": health("capp-cwm-solutions", 8, 8), "recommendation": "None"},
    ]
}
APP_HEALTH_DEGRADED = {
    "app_health_summary": [
        {"health_summary": health("capp-infra", 37, 37), "recommendation": "None"},
        {"health_summary": health("capp-cwm-solutions", 8, 7, degraded=1), "recommendation": "x"},
    ]
}
MS_HEALTHY = {
    "Name": "cwm-api-service",
    "health_state": "Healthy",
    "up_time": "207d 11h 30m 10s",
    "recommendation": "None",
    "description": "",
    "is_dynamic": False,
    "micro_service_action": {"actions": []},
    "Version": "7.2.0",
    "version_history": [],
}
MS_DOWN = {**MS_HEALTHY, "health_state": "Down", "up_time": "0d 0h 2m 5s"}
GATEWAY = {
    "duuid": "3d95eb05-0000-4000-8000-0000000cdg01",
    "name": "EMBEDDED_DEF_CDG",
    "configData": {
        "adminState": "AS_UP",
        "role": "ASSIGNED",
        "poolId": "ce5c70f5-0000-4000-8000-0000000pool1",
        "vdgUuid": "ce5c70f5-0000-4000-8000-00000000ccg9",
    },
    "operationalData": {
        "operState": "OS_UP",
        "operStateDetails": [{"componentName": "embeddedCollectors", "state": "CS_UP"}],
        "createdTime": "1757600000000000000",
        "lastUpdatedTime": "1757700000",
    },
}
ACCEPTED = {"request_result": "ACCEPTED", "error": {"error": ""}}
DLM_CONTEXT = {
    "application_id": "cw.dlminvmgr0",
    "context_id": "dlm/cli-collector/group/te-tunnel-id/subscription",
}
COLLECTION_COUNTS = {
    "job_count": "1",
    "input_collection_count": "5",
    "output_collection_count": "5",
    "input_error_collection_count": "0",
    "output_error_collection_count": "0",
    "control_error_count": "0",
    "device_count": "5",
    "result": ACCEPTED,
}
COLLECTION_JOBS = {
    "collection_job_status_list": [
        {
            "application_context": DLM_CONTEXT,
            "creation_time": "1757750400000",
            "deletion_time": "0",
            "progress": 100,
            "status": "READY",
            "phase": "ACTIVE",
            "collector_type": "CLI_COLLECTOR",
            "job_error": {"error": ""},
        }
    ],
    "result": ACCEPTED,
}
COLLECTION_STATES = {
    "collection_life_cycle_states": [
        {
            "life_cycle_state": "SUCCESS_LIFE_CYCLE_STATE",
            "application_context": DLM_CONTEXT,
            "creation_time": "1757750400000",
            "state_evaluation_time": "1757754000000",
        }
    ],
    "result": ACCEPTED,
}
PCE_PROVIDER = {
    "uuid": "4f1c2d3e-0000-4000-8000-00000000pce1",
    "name": "lab-pce",
    "family": "ROBOT_PROVIDER_XTC",
    "profile": "lab-xrd",
    "reachability_state": REACHABLE,
    "connectivity_info": [],
    "properties": {},
}
NSO_PROVIDER = {
    **PCE_PROVIDER,
    "uuid": "4f1c2d3e-0000-4000-8000-00000000nso1",
    "name": "nso",
    "family": "ROBOT_PROVIDER_NSO",
}
SR_POLICIES = {"cisco-crosswork-segment-routing-policy:sr-policies": {"policy": [nbi_policy()]}}

# --- services ------------------------------------------------------------------------------


def plan_data(status: str, **extra: Any) -> dict:
    return cat(
        "get-service-plan-data",
        {
            "service-plan-data": [
                {
                    "yang-path": f"{L3VPN_CAT_PLAN_LIST}={VPN_ID}",
                    "status": status,
                    "creation-time": "2026-09-13T10:15:02.000+00:00",
                    "last-updated-time": "2026-09-13T10:15:04.000+00:00",
                    **extra,
                }
            ]
        },
    )


PLAN_COMPLETED = plan_data("completed")
PLAN_IN_PROGRESS = plan_data("in-progress")
PLAN_FAILED = plan_data("failed", **{"error-info": {"message": "device PE1: out of sync"}})
L3VPN_NSO_OBJECT = {
    "ietf-l3vpn-ntw:vpn-service": [
        {
            "vpn-id": VPN_ID,
            "vpn-service-topology": "ietf-vpn-common:any-to-any",
            "modified": {"devices": ["PE1", "PE2"], "services": []},
            "created": "2026-09-14T01:40:11.301+00:00",
            "last-modified": "2026-09-14T01:40:11.301+00:00",
            "last-run": "2026-09-14T01:40:11.301+00:00",
            "vpn-nodes": {"vpn-node": [{"vpn-node-id": "PE1"}, {"vpn-node-id": "PE2"}]},
        }
    ]
}


def nano_plan(states: list[tuple[str, str]]) -> dict:
    component = lambda kind, name: {  # noqa: E731
        "type": f"tailf-ncs:{kind}",
        "name": name,
        "state": [{"name": f"tailf-ncs:{s}", "status": st, "when": "t"} for s, st in states],
    }
    return {
        "cisco-l3vpn-ntw:vpn-service-plan": [
            {
                "name": VPN_ID,
                "plan": {"component": [component("self", "self"), component("head-end", "PE1")]},
            }
        ]
    }


READY = [("init", "reached"), ("config-apply", "reached"), ("ready", "reached")]
OPER_STATUS = {
    "ietf-l3vpn-ntw:vpn-service": [
        {
            "vpn-id": VPN_ID,
            "status": {
                "oper-status": {
                    "status": "ietf-vpn-common:op-up",
                    "last-change": "2026-09-13T11:00:00Z",
                }
            },
        }
    ]
}
UNDERLAY = {
    "cisco-l3vpn-ntw:discovered-underlay-transport": {
        "sr-policy-ref": [{"headend": "PE1", "color": 100, "endpoint": "10.0.0.3"}]
    }
}
SUB_COUNT = cat("get-sub-service-count", {"sub-service-count": 2})
SUB_PATHS = cat(
    "get-sub-service-paths",
    {
        "collection-header": {"offset": 0, "count": 2},
        "sub-service-path": [
            f"{L3VPN_PATH}/vpn-nodes/vpn-node=PE1",
            f"{L3VPN_PATH}/vpn-nodes/vpn-node=PE2",
        ],
    },
)
NO_PROBE_500 = httpx.Response(
    500,
    json={
        "serviceId": L3VPN_PATH,
        "status": 0,
        "enableReactivate": False,
        "error": "service has no active probe session",
    },
)
L3VPN_CLI = "vrf doc-l3vpn-1\n address-family ipv4 unicast\n  import route-target\n   0:65091:91\n"
DRY_RUN_L3VPN = {
    "dry-run-result": {
        "native": {
            "device": [{"name": "PE1", "data": L3VPN_CLI}, {"name": "PE2", "data": L3VPN_CLI}]
        }
    }
}
L3VPN_ENDPOINTS = json.dumps(
    [
        {
            "node": "PE1",
            "interface": "Loopback91",
            "address": "10.91.1.1",
            "prefix_length": 30,
            "local_as": 65000,
        },
        {
            "node": "PE2",
            "interface": "Loopback91",
            "address": "10.91.1.5",
            "prefix_length": 30,
            "local_as": 65000,
        },
    ]
)
L3VPN_ARGS = {
    "vpn_id": VPN_ID,
    "route_distinguisher": "0:65091:91",
    "route_target": "0:65091:91",
    "endpoints": L3VPN_ENDPOINTS,
}


def service_route(status: int, message: str, **overrides: Any) -> dict:
    route = {
        "query-id": QUERY_ID,
        "status": status,
        "status-message": message,
        "create-time": "1789324616899.0",
        "update-time": "1789324616899.0",
        "yang-path": L3VPN_PATH,
        "service-name": VPN_ID,
        "service-type": "ietf-l3vpn",
        "head-end-node-uuid": PE1_UUID,
        "head-end-node-name": "PE1",
        "head-end-te-router-id": "10.0.0.1",
        "tail-end-node-uuid": PE2_UUID,
        "tail-end-node-name": "PE2",
        "tail-end-te-router-id": "10.0.0.3",
        "available-path-count": 0,
        "transport-type": 0,
        "response-result": "valid",
    }
    route.update(overrides)
    return route


TRACE_REGISTERED = service_route(3, "Path trace registered for calculation")
TRACE_COMPLETED = service_route(
    4,
    "Path trace completed",
    **{
        "available-path-count": 1,
        "path-info-list": [
            {
                "path": "1",
                "path-info": {
                    "source": "10.0.0.1",
                    "destination": "10.0.0.3",
                    "next-hop": "10.1.2.2",
                    "out-interface": GI0,
                    "device-uuids": [PE1_UUID, P1_UUID, PE2_UUID],
                    "path-details": "16002 16003",
                    "path-status": "success",
                },
            }
        ],
    },
)
DRYRUN_SUCCESS = out(
    SRP,
    state="success",
    **{
        "segment-list-hops": [
            {"step": 0, "sid": 16003, "ip-address": "10.0.0.3", "type": "node-ipv4"}
        ],
        "igp-route": [{"node": "PE1", "interface": GI0}, {"node": "P1", "interface": GI1}],
    },
)
CREATE_SUCCESS = out(
    SRP,
    results=[
        {
            "head-end": "10.0.0.1",
            "end-point": "10.0.0.3",
            "color": 200,
            "state": "success",
            "message": "",
        }
    ],
)
CREATE_DUPLICATE = out(
    SRP,
    results=[
        {
            "head-end": "10.0.0.1",
            "end-point": "10.0.0.3",
            "color": 200,
            "state": "failure",
            "message": "An SR Policy with same color, headend and endpoint already exists.",
        }
    ],
)


# --- harness --------------------------------------------------------------------------------


class _FakeClock:
    """Stands in for ``time`` and ``asyncio`` inside cnc_mcp.polling so no wait tool sleeps."""

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


async def build(settings: Settings) -> MCPServer:
    """The FULL server (every sibling registered) plus the composites, registered here
    only while tools/__init__.py does not list the module yet."""
    mcp = build_server(settings)
    names = {t.name for t in await mcp.list_tools()}
    if "cnc_investigate_device" not in names:
        ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
        composite.register(mcp, ctx)
    return mcp


async def reads(make_settings) -> MCPServer:
    return await build(make_settings(max_retries=0))


async def writes(make_settings) -> MCPServer:
    return await build(make_settings(max_retries=0, enable_writes=True))


def audit(text: str) -> list[str]:
    """The 'Calls made' lines of a markdown answer."""
    tail = text.split("## Calls made", 1)[1]
    return [line[2:] for line in tail.strip().split("\n") if line.startswith("- ")]


def verdict_of(text: str) -> str:
    for line in text.split("\n"):
        if line.startswith("## VERDICT: "):
            return line[len("## VERDICT: ") :]
    raise AssertionError(f"no VERDICT line in:\n{text[:500]}")


def statistics_row(host: str, uuid: str, interface: str, **metrics: float) -> dict:
    return {
        "keys": {"hostname": host, "interfaceName": interface, "device": uuid},
        "metrics": metrics or {"ifInErrorsRate": 0.0, "ifInDiscardsRate": 0.0},
    }


def mock_statistics(*, rows: list[dict] | None = None, fresh_rows: int = 1) -> respx.Route:
    """dashboards/statistics as the platform answers it: ``rows`` are the device's
    CEPMINTERFACE rows in the window (default one all-zero row), so the error scan
    (pageSize 200) gets them all with ``records`` = their count — the sibling drops the
    zero ones client-side and still reports ``records`` (verified live: records 6,
    count 0 on a clean device) — and the one-hour freshness probe (pageSize 1,
    timeInterval PM_FRESH_HOURS) gets ``fresh_rows`` of the same rows. Any other
    pageSize-1 window answers from the same row set (a regression re-adding the
    full-window probe shows up as a third audit line, not as a mismatch)."""
    all_rows = list(rows) if rows is not None else [statistics_row("PE1", PE1_UUID, GI0)]

    def answer(request: httpx.Request) -> httpx.Response:
        params = request.url.params
        if params.get("pageSize") == "1":
            one_hour = params.get("timeInterval") == str(PM_FRESH_HOURS)
            count = fresh_rows if one_hour else len(all_rows)
            entries = all_rows[:1] if count else []
            return ok({"schema": "CEPMINTERFACE", "page": 1, "records": count, "entries": entries})
        return ok(
            {"schema": "CEPMINTERFACE", "page": 1, "records": len(all_rows), "entries": all_rows}
        )

    return respx.get(STATISTICS_URL).mock(side_effect=answer)


def mock_investigation(
    record: dict = PE1, *, alarms: tuple[dict, ...] = (PE1_ALARM, PE10_ALARM, INFO_ALARM)
) -> dict[str, respx.Route]:
    """Every route cnc_investigate_device hits, answering a healthy PE1 unless a caller
    overrides a route afterwards (the topology / backup routes follow the record)."""
    return {
        "nodes": mock_nodes(record, PE2, P1),
        "collection": respx.get(COLLECTION_SUMMARY).mock(
            return_value=ok(
                {"inprogress": 0, "warning": 0, "failed": 0, "completed": 3, "maintenance": 0}
            )
        ),
        "alarms": mock_alarms(*alarms),
        "device_alarms": respx.get(RTM_ALARMS).mock(return_value=ok(EMPTY_RTM)),
        "events": respx.post(EVENTS_QUERY).mock(return_value=ok(EVENTS)),
        "ems": respx.get(EMS_NODE).mock(return_value=ok(ems_node())),
        "check_sync": respx.post(CHECK_SYNC).mock(
            return_value=ok(
                {"job_id": "j-1", "state": "JOB_ACCEPTED", "type": "NSO device check sync"}
            )
        ),
        "topology": respx.get(
            f"{NETWORKS_URL}/network=Default-network/node={record['host_name']}"
        ).mock(return_value=ok(NODE_PE1_KEYED)),
        "backups": respx.get(f"{CONFIG_BACKUP}/{record['uuid']}").mock(
            return_value=ok(
                {
                    "backup_config": [
                        {
                            "name": "Initial_Version",
                            "backedup_at": "2026-09-13T08:00:00Z",
                            "trigger": "DEVICE_ADD",
                            "status": "SUCCESS",
                            "complianceStatus": "COMPLIANT",
                            "pinned": False,
                            "tag": [],
                        }
                    ]
                }
            )
        ),
        "statistics": mock_statistics(),
    }


# --- registration / gating ------------------------------------------------------------------


async def test_read_composites_registered_and_write_composites_gated(make_settings):
    names = {t.name for t in await (await reads(make_settings)).list_tools()}
    assert set(COMPOSITE_TOOLS) - set(WRITE_COMPOSITES) <= names
    assert not (set(WRITE_COMPOSITES) & names)
    tools = {t.name: t for t in await (await writes(make_settings)).list_tools()}
    assert set(COMPOSITE_TOOLS) <= set(tools)
    for name in COMPOSITE_TOOLS:
        assert tools[name].description and "Sub-tools called" in tools[name].description, name
        assert tools[name].input_schema.get("additionalProperties") is False, name
    for name in set(COMPOSITE_TOOLS) - set(WRITE_COMPOSITES):
        assert tools[name].annotations.read_only_hint is True, name
    assert tools["cnc_provision_l3vpn_e2e"].annotations.read_only_hint is False
    assert tools["cnc_provision_l3vpn_e2e"].annotations.destructive_hint is True
    assert tools["cnc_provision_l3vpn_e2e"].annotations.idempotent_hint is True
    assert tools["cnc_create_sr_policy_e2e"].annotations.read_only_hint is False
    assert tools["cnc_create_sr_policy_e2e"].annotations.destructive_hint is False


# --- pure helpers ---------------------------------------------------------------------------


def test_parse_payload_finds_json_after_headlines_and_markdown():
    assert parse_payload('{"a": 1}') == {"a": 1}
    assert parse_payload('5 devices: 4 ok\n{"total": 5}') == {"total": 5}
    assert parse_payload('# Cluster health\n\n| a | b |\n\n{\n  "state": "Healthy"\n}') == {
        "state": "Healthy"
    }
    assert parse_payload('Trace registered\n- head-end: PE1 {x}\n{"query_id": "q"}') == {
        "query_id": "q"
    }
    assert parse_payload("No backups for PE1.") is None
    assert parse_payload("") is None
    assert parse_payload("[1, 2]") == [1, 2]


def test_mentions_is_whole_word_and_case_insensitive():
    assert mentions("PE1", "Device pe1 is unreachable")
    assert not mentions("PE1", "Device PE10 is unreachable")
    assert mentions("PE1", None, f"Device PE1 ({PE1_UUID})")
    assert not mentions("", "anything")


def test_device_findings_rules():
    reasons, notes, unreachable = device_findings(PE1)
    assert (reasons, notes, unreachable) == ([], [], False)
    down = device(
        PE1_UUID,
        "PE1",
        "10.0.0.1",
        reach=UNREACHABLE,
        transports=[transport("SSH", 22, UNREACHABLE, "timeout")],
    )
    reasons, _, unreachable = device_findings(down)
    assert unreachable and "reachability_state CONN_STATE_UNREACHABLE" in reasons
    assert "transport SSH CONN_STATE_UNREACHABLE (timeout)" in reasons
    checking = device(
        PE1_UUID, "PE1", "10.0.0.1", reach="CONN_STATE_UNKNOWN", oper="ROBOT_OPER_STATE_CHECKING"
    )
    # CHECKING is a note while the newest DLM stamp is younger than the transient window ...
    young = datetime.fromtimestamp(int(ONE_DAY_AGO) + 120, tz=UTC)
    reasons, notes, unreachable = device_findings(checking, young)
    assert not reasons and not unreachable
    assert "operational_state CHECKING since" in notes[0] and "transient" in notes[0]
    assert "reachability_state CONN_STATE_UNKNOWN" in notes[0]
    # ... and a reason (a stall) once it is older, dated from that stamp.
    reasons, notes, unreachable = device_findings(checking)
    assert not notes and not unreachable
    assert re.match(r"operational_state CHECKING for 1d\dh: the DLM has not returned", reasons[0])
    assert "reachability_state CONN_STATE_UNKNOWN" in reasons[0]
    in_flight = device(PE1_UUID, "PE1", "10.0.0.1", nso_state="CHECK_SYNC_STARTED")
    reasons, notes, _ = device_findings(in_flight)
    assert not reasons and "in flight" in notes[0]
    failed = device(PE1_UUID, "PE1", "10.0.0.1", nso_state="CONNECT_FAILED", errors=["boom"])
    failed["state_map"]["3"] = {"element": "CLOCK_DRIFT", "value": "DOWN", "info": "drift 40s"}
    reasons, _, _ = device_findings(failed)
    assert "nso_state CONNECT_FAILED" in reasons and "device error: boom" in reasons
    assert "CLOCK_DRIFT check DOWN (drift 40s)" in reasons


def test_device_lines_render_the_placeholder_state_map_and_stamp_ages():
    now = datetime.now(UTC)
    lines = device_lines(P2_STUCK, now)
    state_map = [line for line in lines if line.startswith("- state_map:")][0]
    assert state_map.startswith(
        "- state_map: no completed check recorded (key-0 placeholder only since "
    )
    assert "UNSUPPORTED" not in state_map and "0=UP" not in state_map
    transports = [line for line in lines if line.startswith("- transports:")][0]
    assert re.search(r"SNMP:161=CONN_STATE_REACHABLE \(stamped 12h\d+m ago\)", transports)
    assert "not a live probe" in transports
    uptime = [line for line in lines if line.startswith("- uptime ")][0]
    assert "stamped at the last completed reachability check, none recorded; not live" in uptime
    # A completed state_map lists each check with its stamp; uptime is dated by check 1.
    lines = device_lines(PE1, now)
    state_map = [line for line in lines if line.startswith("- state_map:")][0]
    assert re.search(r"- state_map: 1=UP \(checked \S+ \(1d\dh ago\)\), 2=UP", state_map)
    uptime = [line for line in lines if line.startswith("- uptime ")][0]
    assert re.search(r"reachability check \S+ \(1d\dh ago\); not live", uptime)
    # The transient window the CHECKING rule keys on: two reachability cadences (the
    # 1200 s seen live), so a first check landing on the next cadence tick — up to one
    # cadence of legitimate CHECKING — is never a STALL.
    assert REACHABILITY_CADENCE_SECONDS == 1200
    assert CHECKING_TRANSIENT_SECONDS == 2 * REACHABILITY_CADENCE_SECONDS == 40 * 60


def test_checking_for_one_cadence_is_transient_not_a_stall():
    """A device whose first check waits for the next 1200 s tick is CHECKING for up to
    20 min legitimately: at 19 min it is still a note, past two cadences a reason."""
    at_one_cadence = stuck_checking(P2_UUID, "P2", "10.0.0.4", age_seconds=19 * 60)
    at_one_cadence["errors"] = []
    reasons, notes, _ = device_findings(at_one_cadence)
    assert reasons == [] and len(notes) == 1 and "check cycle is in progress" in notes[0]
    stalled = stuck_checking(P2_UUID, "P2", "10.0.0.4", age_seconds=CHECKING_TRANSIENT_SECONDS + 60)
    stalled["errors"] = []
    reasons, notes, _ = device_findings(stalled)
    assert notes == [] and len(reasons) == 1
    assert reasons[0].startswith("operational_state CHECKING for 41m: no REACHABILITY")


def test_chronic_history_relates_live_alarms_to_their_recent_clears():
    now = datetime.now(UTC)
    live = [cdg_alarm("open", 3600, events=4)]
    same_text = cdg_alarm("c-same", 7200, cleared=True)
    same_text["Description"] = CDG_TEXT  # the clearing event repeated the fault text
    cleared = [
        cdg_alarm("c1", 5 * 3600, cleared=True),
        same_text,
        cdg_alarm("c-old", 80 * 3600, cleared=True),  # outside the 48 h window
    ]
    lines, notes = chronic_history(live, cleared, now)
    assert lines[0] == "- 2 cleared alarm(s) naming the device in the last 48 h"
    assert lines[1].startswith(f"- '{CDG_TEXT}': cleared 2 time(s) since ")
    assert lines[1].endswith("(cleared by: 'Device was detached.' x1, '(same text)' x1)")
    assert len(notes) == 1 and notes[0].startswith(f"chronic: '{CDG_TEXT}' has been raised 3 times")
    # Nothing recent: one plain line, no note; a live alarm with a different text: no note.
    assert chronic_history(live, [cleared[2]], now) == (["- none in the last 48 h"], [])
    assert chronic_history([PE1_ALARM], cleared[:2], now)[1] == []


def test_field_of_reads_prefixed_keys():
    assert field_of({"alm.perceived-severity": "major"}, "perceived-severity") == "major"
    assert field_of({"cisco-l3vpn-ntw:headend": "PE1"}, "headend") == "PE1"
    assert field_of({"headend": "PE1"}, "headend") == "PE1"
    assert field_of({}, "headend") is None


def test_policy_service_matches_by_colour_and_end():
    service = POLICY_SERVICE["cisco-sr-te-cfp-sr-policies:policy"][0]
    assert policy_service_matches(service, "pe1", 100, set())
    assert policy_service_matches(service, "10.0.0.1", 100, {"10.0.0.3"})
    assert not policy_service_matches(service, "PE1", 101, {"10.0.0.3"})
    assert not policy_service_matches(service, "PE2", 100, {"10.0.0.9"})


def test_policy_service_candidates_puts_the_likely_twin_first():
    infos = [{"service-name": n} for n in ("other-1", "pe1-to-pe2", "other-2", "doc-pol-100")]
    ordered = [i["service-name"] for i in policy_service_candidates(infos, 100, {"PE1"})]
    assert ordered == ["pe1-to-pe2", "doc-pol-100", "other-1", "other-2"]
    assert policy_service_candidates(infos, 7, set()) == infos  # nothing likely: as listed
    assert policy_service_candidates([], 100, {"PE1"}) == []


def test_microservice_for_prefers_the_longest_prefix():
    rows = [{"Name": "cwm"}, {"Name": "cwm-api-service"}, {"Name": "other"}]
    assert microservice_for("cwm-api-service-57b9448ffb-c8zxt", rows) == {"Name": "cwm-api-service"}
    assert microservice_for("cwm-api-service", rows) == {"Name": "cwm-api-service"}
    assert microservice_for("nothing", rows) is None


def test_vpn_parts():
    assert vpn_parts(L3VPN_PATH) == ("l3", VPN_ID)
    assert vpn_parts("ietf-l2vpn-ntw:l2vpn-ntw/vpn-services/vpn-service=x/vpn-nodes") == ("l2", "x")
    assert vpn_parts("cisco-sr-te-cfp:sr-te/odn/odn-template=t") is None


# --- cnc_investigate_device -------------------------------------------------------------


@respx.mock
async def test_investigate_device_healthy(make_settings, fake_clock):
    routes = mock_investigation(alarms=(PE10_ALARM, INFO_ALARM))
    text = await call_tool_text(
        await reads(make_settings), "cnc_investigate_device", {"host_name": "PE1"}
    )
    assert not text.startswith("Error:")
    assert verdict_of(text) == "HEALTHY"
    assert "PE1 is healthy: 0 reason(s)" in text
    for name in (
        "collection",
        "alarms",
        "device_alarms",
        "events",
        "ems",
        "check_sync",
        "topology",
        "backups",
        "statistics",
    ):
        assert routes[name].called, name
    # The Critical alarm naming PE10 is not "naming PE1" (whole-word match).
    assert "Device PE10" not in text.split("## Open Crosswork alarms")[1].split("##")[0]
    calls = audit(text)
    assert calls[0] == "cnc_get_device(host_name='PE1') -> ok"
    assert all(line.endswith("-> ok") for line in calls), calls
    # The error scan (only_nonzero) then the one-hour freshness probe (page_size 1).
    assert "cnc_get_performance_statistics(schema='CEPMINTERFACE'" in calls[-2]
    assert f"device_uuid='{PE1_UUID}'" in calls[-2] and "only_nonzero=True" in calls[-2]
    assert calls[-1].startswith("cnc_get_performance_statistics(schema='CEPMINTERFACE', ")
    assert f"hours={PM_FRESH_HOURS}, only_nonzero=False, page_size=1" in calls[-1]
    assert (
        "- no interface reported errors or discards in the last 24 h (collection is producing "
        f"samples: 1+ CEPMINTERFACE row(s) in the last {PM_FRESH_HOURS} h)" in text
    )
    assert "## Inventory collection status (inventory-wide counts)" in text
    assert "not this device's status" in text
    assert "## Cleared alarm history naming the device (last 48 h)" in text
    assert "- none in the last 48 h" in text
    assert re.search(r"SNMP:161=CONN_STATE_REACHABLE \(stamped 1d\dh ago\)", text)
    assert "uptime sources: the inventory record's DLM uptime is stamped" in text
    # Sections are headed by the tool behind them so an agent can drill in.
    assert "## Inventory record — cnc_get_device" in text
    assert "## NSO check-sync (fresh) — cnc_check_nso_device_sync" in text
    assert "- PE1: in-sync (nso_state SYNCED" in text
    assert "1 PCEP session(s)" in text


@respx.mock
async def test_investigate_device_healthy_means_no_serious_alarm(make_settings, fake_clock):
    """The verified Major alarm naming PE1 makes the device degraded — check both ways."""
    mock_investigation(alarms=(INFO_ALARM,))
    text = await call_tool_text(
        await reads(make_settings), "cnc_investigate_device", {"host_name": "PE1"}
    )
    assert verdict_of(text) == "HEALTHY"
    respx.reset()
    mock_investigation(alarms=(PE1_ALARM,))
    text = await call_tool_text(
        await reads(make_settings), "cnc_investigate_device", {"host_name": "PE1"}
    )
    assert verdict_of(text) == "DEGRADED"
    assert "1 open Critical/Major Crosswork alarm(s) name PE1: Device PE1 is unreachable" in text


@respx.mock
async def test_investigate_device_alarm_scan_is_not_capped_before_the_word_filter(
    make_settings, fake_clock
):
    """cnc_search_alarms matches the host as a SUBSTRING and caps the newest-updated
    matches BEFORE the composite's whole-word filter: 25 newer alarms about PE10..PE34
    must not push the older Major alarm naming PE1 out of the scan."""
    newer = [
        alarm(
            f"a-pe{n}",
            "Minor",
            f"Device PE{n} (x)",
            f"Device PE{n} is flapping",
            Updated=str(1789200000000 + n * 1000),
        )
        for n in range(10, 35)
    ]
    routes = mock_investigation(alarms=(*newer, PE1_ALARM))
    text = await call_tool_text(
        await reads(make_settings), "cnc_investigate_device", {"host_name": "PE1"}
    )
    assert verdict_of(text) == "DEGRADED"
    assert "1 open Critical/Major Crosswork alarm(s) name PE1: Device PE1 is unreachable" in text
    assert "Device PE10" not in text.split("## Open Crosswork alarms")[1].split("##")[0]
    assert (
        f"cnc_search_alarms(text='PE1', open_only=True, limit={ALARM_SCAN_LIMIT}, "
        "response_format='json') -> ok" in audit(text)
    )
    assert "alarm scan incomplete" not in text
    # Beyond the sibling's cap the scan IS incomplete, and the answer says so instead of
    # reporting the device clean.
    respx.reset()
    flood = [
        alarm(
            f"a-pe{n}",
            "Minor",
            f"Device PE{n} (x)",
            f"Device PE{n} is flapping",
            Updated=str(1789200000000 + n * 1000),
        )
        for n in range(1000, 1000 + ALARM_SCAN_LIMIT)
    ]
    routes = mock_investigation(alarms=(*flood, PE1_ALARM))
    text = await call_tool_text(
        await reads(make_settings), "cnc_investigate_device", {"host_name": "PE1"}
    )
    assert verdict_of(text) == "HEALTHY"
    assert (
        f"- alarm scan incomplete: {ALARM_SCAN_LIMIT + 1} open alarms contain 'PE1', only the "
        f"{ALARM_SCAN_LIMIT} most recently updated were checked" in text
    )
    assert "Notes:" in text and "older alarms naming PE1 may be missing" in text
    assert routes["alarms"].call_count >= 3  # 501 alarms paged 200 at a time by the sibling


@respx.mock
async def test_investigate_device_stale_serious_alarm_is_a_note_not_degraded(
    make_settings, fake_clock
):
    """A Major alarm naming the device with 0 events and no update for 7+ days is listed
    '(stale?)' and noted, never degraded — the same rule as cnc_network_health_report."""
    stale_pe1 = {
        **STALE_ALARM,
        "AlarmId": "a-stale-pe1",
        "Description": "Device PE1 is unreachable",
        "object_description": f"Device PE1 ({PE1_UUID})",
        "object_id": PE1_UUID,
    }
    mock_investigation(alarms=(stale_pe1, INFO_ALARM))
    text = await call_tool_text(
        await reads(make_settings), "cnc_investigate_device", {"host_name": "PE1"}
    )
    assert verdict_of(text) == "HEALTHY"
    assert "Reasons:" not in text
    assert "- (stale?) [Major] Device PE1 (" in text
    assert (
        "- 1 open alarm(s) naming PE1 have 0 events and no update for 7+ days: listed as "
        "possibly stale, not counted against the device" in text
    )
    # The same alarm with a recent event is live, so it degrades the device.
    respx.reset()
    mock_investigation(alarms=({**stale_pe1, "events_count": 1}, INFO_ALARM))
    text = await call_tool_text(
        await reads(make_settings), "cnc_investigate_device", {"host_name": "PE1"}
    )
    assert verdict_of(text) == "DEGRADED"
    assert "(stale?)" not in text


@respx.mock
async def test_investigate_device_by_uuid(make_settings, fake_clock):
    """The uuid selector: the record read by uuid gives the host name every name-keyed
    section needs, and the uuid-keyed ones use the uuid directly."""
    routes = mock_investigation(alarms=(INFO_ALARM,))
    text = await call_tool_text(
        await reads(make_settings), "cnc_investigate_device", {"uuid": PE1_UUID}
    )
    assert not text.startswith("Error:")
    assert verdict_of(text) == "HEALTHY"
    assert "PE1 is healthy: 0 reason(s)" in text
    assert f"# Device investigation: {PE1_UUID}" in text
    for name, route in routes.items():
        assert route.called, name
    calls = audit(text)
    assert calls[0] == f"cnc_get_device(uuid='{PE1_UUID}') -> ok"
    assert all(line.endswith("-> ok") for line in calls), calls
    assert "cnc_search_alarms(text='PE1'" in calls[2]
    assert "cnc_get_ems_node(name='PE1', response_format='json') -> ok" in calls
    assert f"cnc_check_nso_device_sync(uuid='{PE1_UUID}', wait_seconds=30) -> ok" in calls
    assert f"cnc_list_device_backups(uuid='{PE1_UUID}', response_format='json') -> ok" in calls
    assert json.loads(routes["nodes"].calls[0].request.content)["filter"] == {"uuid": PE1_UUID}


@respx.mock
async def test_investigate_device_degraded_and_unreachable_reasons(make_settings, fake_clock):
    mock_investigation(alarms=(INFO_ALARM,))
    respx.get(EMS_NODE).mock(
        return_value=ok(ems_node("MANAGED_BUT_NEVERSYNCHRONIZED", "Unreachable"))
    )
    respx.get(RTM_ALARMS).mock(return_value=ok(RTM_MAJOR))
    respx.get(STATISTICS_URL).mock(
        return_value=ok(
            {
                "schema": "CEPMINTERFACE",
                "page": 1,
                "records": 2,
                "entries": [
                    {
                        "keys": {"hostname": "PE1", "interfaceName": GI0, "device": PE1_UUID},
                        "metrics": {"ifInErrorsRate": 0.0, "ifInDiscardsRate": 0.0},
                    },
                    {
                        "keys": {"hostname": "PE1", "interfaceName": GI1, "device": PE1_UUID},
                        "metrics": {"ifInErrorsRate": 0.25, "ifInDiscardsRate": 0.0},
                    },
                ],
            }
        )
    )
    text = await call_tool_text(
        await reads(make_settings), "cnc_investigate_device", {"host_name": "PE1", "hours": 6}
    )
    assert verdict_of(text) == "DEGRADED"
    assert "EMF lifecycle-state MANAGED_BUT_NEVERSYNCHRONIZED" in text
    assert "EMF communication-state Unreachable" in text
    assert "1 critical/major device alarm(s): Nbr 192.0.2.41" in text
    assert f"interface errors/discards in the last 6 h: {GI1}: ifInErrorsRate=0.25" in text
    assert GI0 not in text.split("## Interface errors")[1].split("##")[0]
    respx.reset()
    mock_investigation(
        device(
            PE1_UUID,
            "PE1",
            "10.0.0.1",
            reach=UNREACHABLE,
            transports=[transport("SSH", 22, UNREACHABLE, "timeout")],
        ),
        alarms=(INFO_ALARM,),
    )
    text = await call_tool_text(
        await reads(make_settings), "cnc_investigate_device", {"host_name": "PE1"}
    )
    assert verdict_of(text) == "UNREACHABLE"
    assert "- transport SSH CONN_STATE_UNREACHABLE (timeout)" in text


@respx.mock
async def test_investigate_device_partial_failure_keeps_the_verdict(make_settings, fake_clock):
    routes = mock_investigation(alarms=(INFO_ALARM,))
    routes["ems"].mock(return_value=NATS_500)
    routes["topology"].mock(return_value=httpx.Response(503, json={}))
    text = await call_tool_text(
        await reads(make_settings), "cnc_investigate_device", {"host_name": "PE1"}
    )
    assert not text.startswith("Error:")
    assert verdict_of(text) == "HEALTHY"
    assert "2 section(s) unavailable" in text
    assert "Sections unavailable (not covered by the verdict):" in text
    assert "EMF node (config management view): unavailable — Error:" in text
    assert "Topology node (SR-PCE feed): unavailable — Error:" in text
    calls = audit(text)
    assert any(c.startswith("cnc_get_ems_node(") and c.endswith("-> error") for c in calls)
    assert any(c.startswith("cnc_get_topology_node(") and c.endswith("-> error") for c in calls)
    assert routes["backups"].called  # the playbook went on after the failures


@respx.mock
async def test_investigate_device_unknown_record_is_unknown_not_error(make_settings, fake_clock):
    routes = mock_investigation()
    routes["nodes"].mock(return_value=NATS_500)
    text = await call_tool_text(
        await reads(make_settings), "cnc_investigate_device", {"uuid": PE1_UUID}
    )
    assert not text.startswith("Error:")
    assert verdict_of(text) == "UNKNOWN"
    assert "the inventory record could not be read" in text
    # With uuid only and no record, the name-keyed sections are not attempted ...
    assert not routes["ems"].called and not routes["alarms"].called
    # ... but the uuid-keyed statistics still are.
    assert routes["statistics"].called


@respx.mock
async def test_investigate_device_skips_check_sync_without_nso(make_settings, fake_clock):
    routes = mock_investigation(
        device(PE1_UUID, "PE1", "10.0.0.1", nso_state=None), alarms=(INFO_ALARM,)
    )
    text = await call_tool_text(
        await reads(make_settings), "cnc_investigate_device", {"host_name": "PE1"}
    )
    assert verdict_of(text) == "HEALTHY"
    assert "NSO check-sync (fresh): skipped — the device has no nso_state" in text
    assert not routes["check_sync"].called


@respx.mock
async def test_investigate_device_json_shape(make_settings, fake_clock):
    mock_investigation(alarms=(INFO_ALARM,))
    text = await call_tool_text(
        await reads(make_settings),
        "cnc_investigate_device",
        {"host_name": "PE1", "response_format": "json"},
    )
    payload = json.loads(text)
    assert set(payload) == {"verdict", "sections", "calls"}
    assert payload["verdict"]["status"] == "healthy"
    assert set(payload["verdict"]) == {"status", "headline", "reasons", "notes", "missing"}
    assert payload["sections"]["device"]["tool"] == "cnc_get_device"
    assert payload["sections"]["device"]["data"]["host_name"] == "PE1"
    assert payload["sections"]["alarms"]["data"] == {"count": 0, "items": []}
    assert payload["calls"][0] == {
        "tool": "cnc_get_device",
        "arguments": {"host_name": "PE1"},
        "ok": True,
    }
    assert all(c["ok"] for c in payload["calls"])


def cdg_alarm(alarm_id: str, created_ago: int, *, cleared: bool = False, events: int = 1) -> dict:
    """The CDG no-response alarm naming P2 as seen live: open with a growing event
    count, or cleared by 'Device was detached.' (the fault text then lives only in the
    Events list) — stamped ``created_ago`` seconds before now."""
    created = (NOW_EPOCH - created_ago) * 1000
    closed = created + 600 * 1000
    if not cleared:
        return alarm(
            alarm_id,
            "Major",
            f"Device P2 ({P2_UUID})",
            CDG_TEXT,
            object_id=P2_UUID,
            events_count=events,
            Created=str(created),
            Updated=str(created),
        )
    return alarm(
        alarm_id,
        "Clear",
        f"Device P2 ({P2_UUID})",
        "Device was detached.",
        object_id=P2_UUID,
        events_count=2,
        Created=str(created),
        Updated=str(closed),
        Closed=str(closed),
        Events=[
            {
                "EventId": f"{alarm_id}-e2",
                "EventSeverity": "Clear",
                "Description": "Device was detached.",
                "Timestamp": str(closed),
                "EventCategory": "System",
                "alarm_id": alarm_id,
            },
            {
                "EventId": f"{alarm_id}-e1",
                "EventSeverity": "Major",
                "Description": CDG_TEXT,
                "Timestamp": str(created),
                "EventCategory": "System",
                "alarm_id": alarm_id,
            },
        ],
    )


@respx.mock
async def test_investigate_device_stuck_checking_stale_pm_and_chronic_alarms(
    make_settings, fake_clock
):
    """The P2 case from the 2026-09-14 agent scenarios: REACHABLE but stuck in
    ROBOT_OPER_STATE_CHECKING for hours with only the key-0 placeholder in its
    state_map, no CEPMINTERFACE samples since the re-attach, and the CDG no-response
    alarm raised again after every 'Device was detached.' clear. Each of those is a
    named finding, not a clean bill of health."""
    live = cdg_alarm("a-cdg-open", 5 * 3600, events=16)
    history = [
        cdg_alarm("a-cdg-c1", 9 * 3600, cleared=True),
        cdg_alarm("a-cdg-c2", 20 * 3600, cleared=True),
        cdg_alarm("a-cdg-c3", 30 * 3600, cleared=True),
        cdg_alarm("a-cdg-old", 80 * 3600, cleared=True),  # outside the 48 h window
    ]
    routes = mock_investigation(P2_STUCK, alarms=(live, INFO_ALARM, *history))
    # Two all-zero rows in the window (records 2, count 0 after only_nonzero), none in
    # the last hour.
    routes["statistics"] = mock_statistics(
        rows=[statistics_row("P2", P2_UUID, GI0), statistics_row("P2", P2_UUID, GI1)],
        fresh_rows=0,
    )
    text = await call_tool_text(
        await reads(make_settings), "cnc_investigate_device", {"host_name": "P2"}
    )
    assert not text.startswith("Error:")
    assert verdict_of(text) == "DEGRADED"
    # (2) the CHECKING stall is a REASON dated from the placeholder / last_upd_time stamps,
    # and the record's REACHABLE stamps are named for what they are.
    assert re.search(
        r"- operational_state CHECKING for 6h\d+m: no REACHABILITY / DISCOVERY / CLOCK_DRIFT "
        r"check has completed since \S+ \(6h\d+m ago\) — the state_map still holds only the "
        r"key-0 placeholder",
        text,
    )
    assert re.search(
        r"reachability_state CONN_STATE_REACHABLE \(the REACHABLE stamps date from "
        r"\S+ \(12h\d+m ago\)\)",
        text,
    )
    assert re.search(
        r"- state_map: no completed check recorded \(key-0 placeholder only since "
        r"\S+ \(6h\d+m ago\)\)",
        text,
    )
    assert "UNSUPPORTED=UP" not in text and "0=UP" not in text
    assert re.search(r"SNMP:161=CONN_STATE_REACHABLE \(stamped 12h\d+m ago\)", text)
    # (3) an empty only_nonzero scan with no row in the last hour but rows in the window
    # is a stale-collection REASON, not "no errors".
    assert f"- interface PM stale: no CEPMINTERFACE samples in the last {PM_FRESH_HOURS} h" in text
    assert "although the last 24 h have rows" in text
    assert "no interface reported errors or discards" not in text
    calls = audit(text)
    # The window's row count comes from the scan's own ``records``: two calls, never a
    # third full-window probe.
    probes = [c for c in calls if c.startswith("cnc_get_performance_statistics(")]
    assert len(probes) == 2
    assert "hours=24, only_nonzero=True, page_size=200" in probes[0]
    assert f"hours={PM_FRESH_HOURS}, only_nonzero=False, page_size=1" in probes[1]
    # (7c) REACHABLE stamps older than the live no-response alarm are said to predate it.
    assert re.search(
        r"- the transports read REACHABLE but their stamps \(\S+ \(12h\d+m ago\)\) predate "
        r"the live 'did not receive any response' alarm\(s\) \(raised \S+ \(5h\d+m ago\)\)",
        text,
    )
    # (7a) the cleared history turns the newest instance into a chronic, masked fault.
    assert "## Cleared alarm history naming the device (last 48 h) — cnc_search_alarms" in text
    assert "- 3 cleared alarm(s) naming the device in the last 48 h" in text
    assert f"- '{CDG_TEXT}': cleared 3 time(s) since" in text
    assert "(cleared by: 'Device was detached.' x3)" in text
    assert (
        f"- chronic: '{CDG_TEXT}' has been raised 4 times since" in text
        and "3 instance(s) were cleared in the last 48 h (by 'Device was detached.' x3), so the "
        "open one is a recurring fault masked by the clears, not a new event"
        in text
    )
    assert "a-cdg-old" not in text.split("## Cleared alarm history")[1].split("## ")[0]
    assert (
        "cnc_search_alarms(text='P2', open_only=False, limit=500, response_format='json') -> ok"
        in calls
    )
    assert "1 open Critical/Major Crosswork alarm(s) name P2" in text
    assert f"device error: Major - {CDG_TEXT}" in text


@respx.mock
async def test_investigate_device_young_checking_is_a_transient_note(make_settings, fake_clock):
    young = stuck_checking(P2_UUID, "P2", "10.0.0.4", age_seconds=120)
    young["errors"] = []
    mock_investigation(young, alarms=(INFO_ALARM,))
    text = await call_tool_text(
        await reads(make_settings), "cnc_investigate_device", {"host_name": "P2"}
    )
    assert verdict_of(text) == "HEALTHY"
    assert "Reasons:" not in text
    assert re.search(
        r"- operational_state CHECKING since \S+ \(2m ago\): the DLM's check cycle is in "
        r"progress — transient after onboarding, a PATCH or a re-attach",
        text,
    )
    assert "no completed check recorded (key-0 placeholder only since" in text


@respx.mock
async def test_investigate_device_no_pm_samples_is_not_a_clean_window(make_settings, fake_clock):
    """No CEPMINTERFACE row anywhere in the window: a note that says 'no samples', never
    the 'no errors' line; a failed freshness probe leaves the question open and says so."""
    routes = mock_investigation(alarms=(INFO_ALARM,))
    routes["statistics"] = mock_statistics(rows=[], fresh_rows=0)
    text = await call_tool_text(
        await reads(make_settings), "cnc_investigate_device", {"host_name": "PE1", "hours": 6}
    )
    assert verdict_of(text) == "HEALTHY"
    assert (
        "- NO interface PM samples in the last 6 h: interface collection for this device is "
        "not producing data" in text
    )
    assert "'no errors' cannot be claimed" in text and "Notes:" in text
    assert "no interface reported errors or discards" not in text
    probes = [c for c in audit(text) if c.startswith("cnc_get_performance_statistics(")]
    assert len(probes) == 2
    # The freshness probe failing: the ambiguity is stated instead of resolved either way.
    respx.reset()
    routes = mock_investigation(alarms=(INFO_ALARM,))

    def flaky(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("pageSize") == "1":
            return NATS_500
        return ok({"schema": "CEPMINTERFACE", "page": 1, "records": 0, "entries": []})

    routes["statistics"].mock(side_effect=flaky)
    text = await call_tool_text(
        await reads(make_settings), "cnc_investigate_device", {"host_name": "PE1"}
    )
    assert verdict_of(text) == "HEALTHY"
    assert "- freshness probe unavailable — Error:" in text
    assert "an empty only_nonzero scan cannot tell 'no errors' from 'no samples'" in text
    assert "no interface reported errors or discards" not in text
    # With errors in the scan and fresh rows, the section reports both.
    respx.reset()
    routes = mock_investigation(alarms=(INFO_ALARM,))
    routes["statistics"] = mock_statistics(
        rows=[statistics_row("PE1", PE1_UUID, GI1, ifInErrorsRate=0.25)], fresh_rows=1
    )
    text = await call_tool_text(
        await reads(make_settings), "cnc_investigate_device", {"host_name": "PE1"}
    )
    assert verdict_of(text) == "DEGRADED"
    assert f"- {GI1}: ifInErrorsRate=0.25" in text
    assert "- collection is producing samples: 1+ CEPMINTERFACE row(s) in the last 1 h" in text
    assert len([c for c in audit(text) if c.startswith("cnc_get_performance_statistics(")]) == 2


def test_pm_freshness_lines_never_reports_an_unknown_window_count_as_a_finding():
    """No row in the last hour and NO window count (the scan's ``records`` unreadable):
    the question stays open — never the 'NO interface PM samples' note, never the
    stale-collection reason."""
    reasons: list[str] = []
    notes: list[str] = []
    probe = Call("cnc_get_performance_statistics", {}, True, "{}", {})
    lines = pm_freshness_lines([], 0, None, 24, reasons, notes, probe)
    assert reasons == []
    assert len(lines) == 1 and len(notes) == 1
    assert "'stale' cannot be told from 'no samples'" in lines[0]
    assert "NO interface PM samples" not in lines[0] and "NO interface PM samples" not in notes[0]
    assert "interface PM stale" not in lines[0]
    # The platform's own count of 0 rows is the no-samples note, as before.
    reasons, notes = [], []
    lines = pm_freshness_lines([], 0, 0, 24, reasons, notes, probe)
    assert reasons == [] and "NO interface PM samples in the last 24 h" in lines[0]
    # Rows in the window (the scan's records) but none in the last hour: the stall reason.
    reasons, notes = [], []
    lines = pm_freshness_lines([], 0, 6, 24, reasons, notes, probe)
    assert len(reasons) == 1 and reasons[0].startswith("interface PM stale")


async def test_investigate_device_selector_rules(make_settings):
    mcp = await reads(make_settings)
    assert (await call_tool_text(mcp, "cnc_investigate_device", {})).startswith(
        "Error: Pass exactly one"
    )
    text = await call_tool_text(
        mcp, "cnc_investigate_device", {"host_name": "PE1", "uuid": PE1_UUID}
    )
    assert text.startswith("Error: Pass exactly one")


# --- cnc_network_health_report ------------------------------------------------------------


def mock_health_report(*, alarms: tuple[dict, ...] = (INFO_ALARM,)) -> dict[str, respx.Route]:
    return {
        "count": respx.get(NODES_COUNT).mock(return_value=ok({"number_of_nodes": 3})),
        "oper": respx.get(OPER_SUMMARY).mock(return_value=ok({"ok": 3})),
        "reach": respx.get(REACH_SUMMARY).mock(return_value=ok({"reachable": 3})),
        "licenses": respx.get(LICENSE_COUNT).mock(
            return_value=ok({"LicenseTypeCount": {"Type A": 3}})
        ),
        "collection": respx.get(COLLECTION_SUMMARY).mock(
            return_value=ok(
                {"inprogress": 0, "warning": 0, "failed": 0, "completed": 3, "maintenance": 0}
            )
        ),
        "cluster": respx.get(CLUSTER_SUMMARY_URL).mock(return_value=ok(CLUSTER_SUMMARY)),
        "infra": respx.get(INFRA_SUMMARY_URL).mock(return_value=ok(INFRA_SUMMARY)),
        "apps": respx.get(APP_HEALTH_URL).mock(return_value=ok(APP_HEALTH)),
        "gateways": respx.post(DG_QUERY_URL).mock(return_value=ok({"data": [GATEWAY]})),
        "coll_count": respx.post(COLLECTION_COUNT).mock(return_value=ok(COLLECTION_COUNTS)),
        "coll_summary": respx.post(COLLECTION_JOB_SUMMARY).mock(return_value=ok(COLLECTION_JOBS)),
        "coll_state": respx.post(COLLECTION_STATE).mock(return_value=ok(COLLECTION_STATES)),
        "providers": respx.post(PROVIDERS_QUERY).mock(
            return_value=ok(
                {"data": [PCE_PROVIDER, NSO_PROVIDER], "total_count": 2, "result_count": 2}
            )
        ),
        "networks": respx.get(NETWORKS_URL).mock(return_value=ok(NETWORKS)),
        "sr_policies": respx.get(SR_POLICIES_URL).mock(return_value=ok(SR_POLICIES)),
        "p2mp": respx.get(P2MP_URL).mock(return_value=ok({})),
        "rsvp": respx.get(RSVP_URL).mock(return_value=ok({})),
        "alarms": mock_alarms(*alarms),
        "device_alarms": respx.get(RTM_ALARMS).mock(return_value=ok(EMPTY_RTM)),
        "nodes": mock_nodes(PE1, PE2, P1),
    }


@respx.mock
async def test_network_health_report_green(make_settings):
    routes = mock_health_report()
    text = await call_tool_text(await reads(make_settings), "cnc_network_health_report", {})
    assert not text.startswith("Error:")
    assert verdict_of(text) == "GREEN"
    assert "Network health GREEN: 0 red, 0 amber finding(s)." in text
    for name, route in routes.items():
        assert route.called, name
    calls = audit(text)
    assert calls[0] == "cnc_get_device_summary() -> ok"
    # Each State is read with the sibling's maximum limit, never a smaller private cap.
    assert ALARM_SCAN_LIMIT == 500
    assert (
        f"cnc_search_alarms(state='Critical', open_only=True, limit={ALARM_SCAN_LIMIT}, "
        "response_format='json') -> ok" in calls
    )
    assert (
        f"cnc_search_alarms(state='Major', open_only=True, limit={ALARM_SCAN_LIMIT}, "
        "response_format='json') -> ok" in calls
    )
    assert "most recently updated were classified" not in text
    assert calls[-1] == "cnc_check_device_nso_state(host_name='*', response_format='json') -> ok"
    assert all(c.endswith("-> ok") for c in calls), calls
    assert "1 SR policies, all UP" in text
    assert "- lab-pce (XTC): CONN_STATE_REACHABLE" in text


@respx.mock
async def test_network_health_report_red_and_amber_with_stale_alarms_separated(make_settings):
    routes = mock_health_report(alarms=(PE10_ALARM, STALE_ALARM, PE1_ALARM))
    routes["apps"].mock(return_value=ok(APP_HEALTH_DEGRADED))
    routes["providers"].mock(
        return_value=ok(
            {
                "data": [{**PCE_PROVIDER, "reachability_state": UNREACHABLE}, NSO_PROVIDER],
                "total_count": 2,
                "result_count": 2,
            }
        )
    )
    routes["reach"].mock(return_value=ok({"reachable": 2, "unreachable": 1}))
    routes["sr_policies"].mock(
        return_value=ok(
            {
                "cisco-crosswork-segment-routing-policy:sr-policies": {
                    "policy": [nbi_policy(oper="DOWN")]
                }
            }
        )
    )
    routes["nodes"].mock(
        return_value=ok(
            {
                "data": [{**PE1, "nso_state": "CONNECT_FAILED", "nso_timestamp": "1789300001"}],
                "result_count": 1,
                "total_count": 1,
            }
        )
    )
    text = await call_tool_text(await reads(make_settings), "cnc_network_health_report", {})
    assert verdict_of(text) == "RED"
    assert "- RED: provider lab-pce (ROBOT_PROVIDER_XTC) CONN_STATE_UNREACHABLE" in text
    assert "- RED: 1 live open Critical alarm(s): Device PE10 is unreachable" in text
    assert "- AMBER: 1 device(s) unreachable/degraded" in text
    assert "- AMBER: applications with degraded/down pods: capp-cwm-solutions" in text
    assert "- AMBER: 1 SR policy(ies) DOWN:" in text
    assert "- AMBER: devices not SYNCED with NSO: PE1 CONNECT_FAILED" in text
    # The stale Major alarm is listed separately and never colours the verdict.
    assert "- AMBER: 1 live open Major alarm(s): Device PE1 is unreachable" in text
    assert "(stale?) [Major] cwm-api-service — cwm-api-service is down." in text
    assert (
        "1 open alarm(s) with 0 events and no update for 7+ days are listed as possibly stale"
        in text
    )


@respx.mock
async def test_network_health_report_partial_failure(make_settings):
    routes = mock_health_report()
    routes["cluster"].mock(return_value=NATS_500)
    routes["gateways"].mock(return_value=NATS_500)
    text = await call_tool_text(await reads(make_settings), "cnc_network_health_report", {})
    assert not text.startswith("Error:")
    assert verdict_of(text) == "GREEN"
    assert "2 section(s) unavailable" in text
    assert "Crosswork cluster health: unavailable — Error:" in text
    assert "Data Gateways: unavailable — Error:" in text
    assert "cnc_get_cluster_health() -> error" in audit(text)
    assert routes["nodes"].called  # the last section still ran


@respx.mock
async def test_network_health_report_json_shape(make_settings):
    mock_health_report()
    payload = json.loads(
        await call_tool_text(
            await reads(make_settings), "cnc_network_health_report", {"response_format": "json"}
        )
    )
    assert payload["verdict"]["status"] == "green" and payload["verdict"]["missing"] == []
    assert payload["sections"]["te"]["data"]["sr_policies"]["total"] == 1
    assert payload["sections"]["cluster"]["status"] == "ok"
    assert [c["tool"] for c in payload["calls"]][:3] == [
        "cnc_get_device_summary",
        "cnc_get_device_collection_summary",
        "cnc_get_cluster_health",
    ]


BACKUP_ADVISORY = alarm(
    "a-backup",
    "Critical",
    "DLM Service",
    "Please make sure to take a data backup once all the devices have been onboarded. Kindly "
    "acknowledge/clear this alarm manually once done.",
    origin_app_id="capp-infra:DLM",
)
RESERVATION_ADVISORY = alarm(
    "a-reservation",
    "Critical",
    "Disabling Enforce pod reservation is not recommended for production use",
    "Disabling Enforce pod reservation is not recommended for production use",
)
CERTIFICATE_ADVISORY = alarm(
    "a-certs",
    "Info",
    "Crosswork kubernetes certificate management",
    "Crosswork kubernetes certificates will expire in 329 days",
)


def test_is_advisory_matches_the_housekeeping_texts_only():
    assert is_advisory(BACKUP_ADVISORY)
    assert is_advisory(RESERVATION_ADVISORY)
    assert is_advisory(CERTIFICATE_ADVISORY)
    assert not is_advisory(PE10_ALARM) and not is_advisory(INFO_ALARM)
    assert not is_advisory(STALE_ALARM)
    # A recurring alarm (2+ events) is a live fault whatever its text says.
    assert not is_advisory({**BACKUP_ADVISORY, "events_count": 2})
    assert not is_advisory({**BACKUP_ADVISORY, "State": "Clear"})
    # Only the future-tense certificate REMINDER is an advisory: a certificate that HAS
    # expired is an outage (a first-raise Critical has exactly one event, so the event
    # count cannot tell them apart).
    for text in (
        "Device certificate has expired; SSH collection failed for PE1",
        "SR-PCE provider certificates expired",
        "Crosswork kubernetes certificates expired 3 days ago",
    ):
        expired = alarm("a-expired", "Critical", "Certificate manager", text)
        assert not is_advisory(expired), text
    assert is_advisory(
        alarm("a-soon", "Info", "cert", "Crosswork kubernetes certificate will expire in 7 days")
    )


@respx.mock
async def test_network_health_report_names_stuck_checking_devices(make_settings):
    """A device in operational_state CHECKING is named, with its stall age, from one
    cnc_list_devices read; stalled for 40+ minutes (two reachability cadences) it is an
    AMBER finding, younger it is a transient note — never a count-only '(transient)'
    line."""
    routes = mock_health_report()
    routes["oper"].mock(return_value=ok({"ok": 2, "checking": 1}))
    routes["nodes"] = mock_nodes(PE1, PE2, P2_STUCK)
    text = await call_tool_text(await reads(make_settings), "cnc_network_health_report", {})
    assert verdict_of(text) == "AMBER"
    assert re.search(
        r"- AMBER: 1 device\(s\) stuck in operational_state CHECKING for more than 40 min: "
        r"P2 \(6h\d+m\) — no DLM check cycle has completed since the stamp shown",
        text,
    )
    assert "(transient)" not in text
    assert "## Devices in operational_state CHECKING — cnc_list_devices" in text
    assert re.search(
        r"- P2: operational_state CHECKING for 6h\d+m: no REACHABILITY / DISCOVERY / CLOCK_DRIFT "
        r"check has completed since .* — cnc_investigate_device\(host_name='P2'\)",
        text,
    )
    assert "cnc_list_devices(page_size=100, response_format='json') -> ok" in audit(text)
    respx.reset()
    routes = mock_health_report()
    routes["oper"].mock(return_value=ok({"ok": 2, "checking": 1}))
    young = stuck_checking(P2_UUID, "P2", "10.0.0.4", age_seconds=120)
    routes["nodes"] = mock_nodes(PE1, PE2, young)
    text = await call_tool_text(await reads(make_settings), "cnc_network_health_report", {})
    assert verdict_of(text) == "GREEN"
    assert (
        "- 1 device(s) still CHECKING (transient, check cycle started less than 40 min ago): "
        "P2 (2m)" in text
    )
    # One cadence in (the first check may land on the next 1200 s tick): still transient.
    respx.reset()
    routes = mock_health_report()
    routes["oper"].mock(return_value=ok({"ok": 2, "checking": 1}))
    one_cadence_in = stuck_checking(P2_UUID, "P2", "10.0.0.4", age_seconds=19 * 60)
    routes["nodes"] = mock_nodes(PE1, PE2, one_cadence_in)
    text = await call_tool_text(await reads(make_settings), "cnc_network_health_report", {})
    assert verdict_of(text) == "GREEN"
    assert "stuck in operational_state CHECKING" not in text and "P2 (19m)" in text
    # No CHECKING device: no device listing is read at all.
    respx.reset()
    routes = mock_health_report()
    text = await call_tool_text(await reads(make_settings), "cnc_network_health_report", {})
    assert not any(c.startswith("cnc_list_devices(") for c in audit(text))
    # The listing failing: the count is still reported, honestly.
    respx.reset()
    routes = mock_health_report()
    routes["oper"].mock(return_value=ok({"ok": 2, "checking": 1}))
    routes["nodes"].mock(return_value=NATS_500)
    text = await call_tool_text(await reads(make_settings), "cnc_network_health_report", {})
    assert "- 1 device(s) in operational_state CHECKING — names unavailable (Error:" in text


@respx.mock
async def test_network_health_report_advisories_cap_the_verdict_at_amber(make_settings):
    """The one-shot housekeeping Criticals (data-backup reminder, pod-reservation warning)
    are advisories: their own section and an AMBER finding, never RED; a real live
    Critical still turns the report RED."""
    mock_health_report(alarms=(BACKUP_ADVISORY, RESERVATION_ADVISORY, INFO_ALARM))
    text = await call_tool_text(await reads(make_settings), "cnc_network_health_report", {})
    assert verdict_of(text) == "AMBER"
    assert "RED:" not in text
    assert (
        "- AMBER: 2 advisory Critical alarm(s) (housekeeping, never RED): Please make sure to "
        "take a data backup" in text
    )
    assert "- 0 live, 2 advisory (housekeeping), 0 possibly stale" in text
    assert "## Advisory / housekeeping alarms — acknowledge and clear — cnc_search_alarms" in text
    assert "- [Critical] DLM Service — Please make sure to take a data backup" in text
    assert "- (advisory) [Critical] DLM Service" in text
    assert "they colour the verdict AMBER at most" in text
    respx.reset()
    mock_health_report(alarms=(BACKUP_ADVISORY, PE10_ALARM))
    text = await call_tool_text(await reads(make_settings), "cnc_network_health_report", {})
    assert verdict_of(text) == "RED"
    assert "- RED: 1 live open Critical alarm(s): Device PE10 is unreachable" in text
    assert "- AMBER: 1 advisory Critical alarm(s)" in text


@respx.mock
async def test_network_health_report_says_when_a_state_exceeds_one_alarm_fetch(make_settings):
    """More open Major alarms than one cnc_search_alarms fetch returns (its 500 cap): the
    extra ones are not silently dropped — the section and a note say how many were
    classified and point at cnc_alarm_triage, which reads them all."""
    majors = [
        alarm(f"a-major-{n}", "Major", f"Device PE{n} (u{n})", f"Device PE{n} is unreachable")
        for n in range(ALARM_SCAN_LIMIT + 3)
    ]
    mock_health_report(alarms=(PE10_ALARM, *majors))
    # A cap wide enough for the 500 classified lines: this test is about the sibling's
    # limit, not finalize()'s size cap.
    mcp = await build(make_settings(max_retries=0, max_response_chars=2_000_000))
    text = await call_tool_text(mcp, "cnc_network_health_report", {})
    assert verdict_of(text) == "RED"
    assert f"- AMBER: {ALARM_SCAN_LIMIT} live open Major alarm(s)" in text
    line = (
        f"{ALARM_SCAN_LIMIT + 3} open Major alarms, only the {ALARM_SCAN_LIMIT} most recently "
        "updated were classified (cnc_alarm_triage reads them all)"
    )
    assert f"- {line}" in text.split("Notes:")[1].split("\n\n")[0]
    # The Critical set (one alarm) is complete: no such line for it.
    assert "open Critical alarms, only the" not in text
    payload = json.loads(
        await call_tool_text(mcp, "cnc_network_health_report", {"response_format": "json"})
    )
    assert payload["sections"]["alarms_major"]["summary"][-1] == f"- {line}"
    assert line in payload["verdict"]["notes"]
    assert not any("open Critical alarms" in n for n in payload["verdict"]["notes"])


# --- cnc_explain_sr_policy ------------------------------------------------------------------


def mock_policy(policy: dict | None = None, *, missing: bool = False) -> dict[str, respx.Route]:
    """Every route cnc_explain_sr_policy hits for PE1 -> PE2 colour 100; ``policy`` is
    the NBI entry (a PCE-initiated UP policy by default), ``missing`` answers the
    verified 409 data-missing instead."""
    routes = {
        "networks": respx.get(NETWORKS_URL).mock(return_value=ok(NETWORKS)),
        "routes": respx.post(rpc(COE, "sr-policy-routes")).mock(return_value=ok(ROUTES_OUT)),
        "metrics": respx.post(rpc(COE, "sr-policy-metrics")).mock(return_value=ok(METRICS_OUT)),
        "pm": respx.get(f"{PM_URL}=10.0.0.1,10.0.0.3,100").mock(return_value=ok(SR_POLICY_PM)),
        "util": respx.post(f"{NPM}/lsp/utilizations").mock(return_value=ok(UTILIZATIONS)),
        "max_util": respx.post(f"{NPM}/lsp/max/utilization").mock(return_value=ok(MAX_UTIL)),
        "delay": respx.post(f"{NPM}/lsp/delay").mock(return_value=ok(LSP_DELAY)),
        "max_delay": respx.post(f"{NPM}/lsp/max/delay").mock(return_value=ok(MAX_DELAY)),
        "variance": respx.post(f"{NPM}/lsp/delayVariance").mock(return_value=ok([])),
        "loss": respx.post(f"{NPM}/lsp/loss").mock(return_value=ok([])),
        "transport": respx.post(f"{CAT_RPC}:get-associated-services-for-transport").mock(
            return_value=ok(SERVICES_ON_TRANSPORT)
        ),
        "nodes": mock_nodes(PE1, PE2, P1),
        "services": respx.post(f"{CAT_RPC}:get-all-services").mock(
            return_value=ok(POLICY_SERVICES)
        ),
        "service": respx.get(f"{NSO_DATA}/{POLICY_SERVICE_PATH}").mock(
            return_value=ok(POLICY_SERVICE)
        ),
        "onbox": respx.get(NSO_SR_CONFIG_URL).mock(return_value=ok(NSO_CONFIG_SR)),
    }
    if not missing:
        routes["policy"] = respx.get(policy_url(100)).mock(
            return_value=ok(keyed_policy(policy or nbi_policy()))
        )
    else:
        routes["policy"] = respx.get(policy_url(100)).mock(
            return_value=httpx.Response(
                409,
                json={
                    "ietf-restconf:errors": {
                        "error": [{"error-tag": "data-missing", "error-message": "no policy"}]
                    }
                },
            )
        )
    return routes


@respx.mock
async def test_explain_sr_policy_pce_initiated(make_settings):
    routes = mock_policy()
    text = await call_tool_text(
        await reads(make_settings),
        "cnc_explain_sr_policy",
        {"headend": "PE1", "endpoint": "PE2", "color": 100},
    )
    assert not text.startswith("Error:")
    assert verdict_of(text) == "UP"
    assert "SR policy PE1 -> PE2 color 100 is up." in text
    assert "- created by: PCE-initiated (pcep-flag-c 1" in text
    assert "- delegated to the PCE" in text
    assert f"- 1 service(s) ride it: {L3VPN_PATH}" in text
    assert (
        "- computation success: single path (every interface share 1.0): "
        "PE1 GigabitEthernet0/0/0/0 -> P1 GigabitEthernet0/0/0/1" in text
    )
    assert "igp-metric 20, te-metric 20, delay 20" in text
    assert "MODELLED by the PCE" in text and "modelled figure" in text
    assert "- measured util: 2 sample(s)" in text and "util avg 1.25" in text
    assert "- measured averageDelay: 1 sample(s)" in text
    assert "- platform maximum: 5 (Successfully found Maximum Average Delay)" in text
    # The NBI section names the router-ids through the topology node map, and reports the
    # constraints block and the update time the prompt asks for.
    assert "- PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 100: admin UP, oper UP" in text
    assert "hops 16003@PE2 (10.0.0.3)" in text
    assert "  constraints: none reported" in text
    assert (
        "- updated 2026-09-13T10:03:07Z (" in text and "update-time: the PCC's last report" in text
    )
    assert "- 4 router-id(s) named: P1 10.0.0.2, PCE 10.0.0.5, PE1 10.0.0.1, PE2 10.0.0.3" in text
    # PCE-initiated: NSO did not configure it, so neither the CAT policy services nor the
    # head-end's on-box configuration are read.
    assert "NSO-configured policy service (CAT): skipped — the policy is PCE-initiated" in text
    assert "On-box SR-TE configuration (NSO CDB copy of the head-end): skipped" in text
    assert not routes["services"].called and not routes["service"].called
    assert not routes["onbox"].called
    for name in ("networks", "policy", "routes", "metrics", "pm", "util", "delay", "transport"):
        assert routes[name].called, name
    calls = audit(text)
    assert calls[0] == (
        "cnc_list_topology_nodes(network='Default-network', page_size=500, "
        "response_format='json') -> ok"
    )
    assert (
        calls[1] == "cnc_get_sr_policy(headend='PE1', endpoint='PE2', color=100, "
        "network='Default-network', response_format='json') -> ok"
    )
    assert all(c.endswith("-> ok") for c in calls), calls


@respx.mock
async def test_explain_sr_policy_pcc_initiated_finds_the_nso_twin(make_settings):
    routes = mock_policy(nbi_policy(flag_c=0))
    text = await call_tool_text(
        await reads(make_settings),
        "cnc_explain_sr_policy",
        {"headend": "PE1", "endpoint": "10.0.0.3", "color": 100, "hours": 2},
    )
    assert verdict_of(text) == "UP"
    assert "PCC-initiated (pcep-flag-c 0" in text
    assert f"- provisioned by NSO as {POLICY_SERVICE_PATH}" in text
    assert (
        f"- matches {POLICY_SERVICE_PATH}: head-end ['PE1'], tail-end 10.0.0.3, color 100" in text
    )
    assert routes["services"].called and routes["service"].called
    assert (
        f"cnc_get_service(yang_path='{POLICY_SERVICE_PATH}', include_plan=False, "
        "response_format='json') -> ok" in audit(text)
    )


def mock_many_policy_services(routes: dict[str, respx.Route], names: list[str]) -> None:
    """``names`` policy services in CAT, none of them the twin of PE1 -> PE2 colour 100
    except 'doc-pol-100' (the verified POLICY_SERVICE object) when it is listed."""
    routes["services"].mock(
        return_value=ok(
            all_services(*(service_info(n, POLICY_QNAME, f"{POLICY_LIST}={n}") for n in names))
        )
    )
    for n in names:
        if n != "doc-pol-100":
            respx.get(f"{NSO_DATA}/{POLICY_LIST}={n}").mock(
                return_value=ok(policy_service_object(n, 999, "PE9", "10.0.0.9"))
            )


@respx.mock
async def test_explain_sr_policy_reads_the_likely_twin_first_among_many(make_settings):
    """13 policy services, the twin listed last: it is read first because its name
    mentions the colour, so the cap on reads does not hide it."""
    routes = mock_policy(nbi_policy(flag_c=0))
    others = [f"other-pol-{n:02d}" for n in range(1, 13)]
    mock_many_policy_services(routes, [*others, "doc-pol-100"])
    text = await call_tool_text(
        await reads(make_settings),
        "cnc_explain_sr_policy",
        {"headend": "PE1", "endpoint": "PE2", "color": 100},
    )
    assert f"- provisioned by NSO as {POLICY_SERVICE_PATH}" in text
    assert "- 13 policy service(s) in CAT" in text
    reads_made = [c for c in audit(text) if c.startswith("cnc_get_service(")]
    assert len(reads_made) == 1 and POLICY_SERVICE_PATH in reads_made[0]


@respx.mock
async def test_explain_sr_policy_never_claims_out_of_nso_when_services_went_unread(
    make_settings,
):
    routes = mock_policy(nbi_policy(flag_c=0))
    names = [f"other-pol-{n:02d}" for n in range(1, 14)]
    mock_many_policy_services(routes, names)
    text = await call_tool_text(
        await reads(make_settings),
        "cnc_explain_sr_policy",
        {"headend": "PE1", "endpoint": "PE2", "color": 100, "response_format": "json"},
    )
    payload = json.loads(text)
    section = payload["sections"]["policy_service"]
    assert section["data"] == {
        "policy_services": 13,
        "read": MAX_POLICY_SERVICE_READS,
        "match": None,
    }
    assert (
        f"- no match among the {MAX_POLICY_SERVICE_READS} of 13 policy services read"
        in section["summary"][-1]
    )
    assert "outside NSO" not in json.dumps(section["summary"])
    assert any("an NSO origin is not ruled out" in n for n in payload["verdict"]["notes"])
    assert "provisioned by NSO" not in json.dumps(payload["verdict"]["reasons"])
    assert sum(1 for c in payload["calls"] if c["tool"] == "cnc_get_service") == 10
    # Every policy service read and none matching: the definitive claim is allowed.
    respx.reset()
    routes = mock_policy(nbi_policy(flag_c=0))
    mock_many_policy_services(routes, names[:3])
    text = await call_tool_text(
        await reads(make_settings),
        "cnc_explain_sr_policy",
        {"headend": "PE1", "endpoint": "PE2", "color": 100},
    )
    assert (
        "- none of the 3 CAT policy service(s) matches this head-end/colour: the policy was "
        "configured on the router outside NSO" in text
    )
    assert "not ruled out" not in text


@respx.mock
async def test_explain_sr_policy_not_reported_and_partial_failure(make_settings):
    routes = mock_policy(missing=True)
    routes["routes"].mock(return_value=httpx.Response(500))
    routes["util"].mock(return_value=NATS_500)
    text = await call_tool_text(
        await reads(make_settings),
        "cnc_explain_sr_policy",
        {"headend": "PE1", "endpoint": "PE2", "color": 100},
    )
    assert not text.startswith("Error:")
    assert verdict_of(text) == "NOT-REPORTED"
    assert "the SR-PCE feed does not report SR policy PE1 -> PE2 color 100" in text
    assert "SR policy (topology NBI): unavailable — Error: no SR policy" in text
    assert "Computed route (Optimization Engine): unavailable — Error:" in text
    assert "Measured utilization (NPM, last 6 h): unavailable — Error:" in text
    assert (
        "cnc_get_sr_policy_metrics(headend='PE1', endpoint='PE2', color=100, "
        "network='Default-network', response_format='json') -> ok" in audit(text)
    )


@respx.mock
async def test_explain_sr_policy_json_shape(make_settings):
    mock_policy()
    payload = json.loads(
        await call_tool_text(
            await reads(make_settings),
            "cnc_explain_sr_policy",
            {"headend": "PE1", "endpoint": "PE2", "color": 100, "response_format": "json"},
        )
    )
    assert payload["verdict"]["status"] == "up"
    assert payload["sections"]["policy"]["data"]["policy-details"]["pce-controlled"] is True
    assert payload["sections"]["services"]["data"]["service_paths"] == [L3VPN_PATH]
    assert payload["sections"]["policy_service"]["status"] == "skipped"
    assert payload["sections"]["onbox_config"]["status"] == "skipped"
    assert payload["sections"]["nodes"]["data"] == {
        "10.0.0.1": "PE1",
        "10.0.0.2": "P1",
        "10.0.0.3": "PE2",
        "10.0.0.5": "PCE",
    }
    assert [c["tool"] for c in payload["calls"]] == [
        "cnc_list_topology_nodes",
        "cnc_get_sr_policy",
        "cnc_get_sr_policy_routes",
        "cnc_get_sr_policy_metrics",
        "cnc_get_sr_policy_performance_metrics",
        "cnc_get_lsp_utilization",
        "cnc_get_lsp_delay",
        "cnc_find_services_on_transport",
    ]


ECMP_ROUTE = [
    {"node": "PE1", "interface": GI0, "interface-use": "0.5"},
    {"node": "PE1", "interface": GI1, "interface-use": "0.5"},
    {"node": "P1", "interface": GI1, "interface-use": "0.5"},
    {"node": "P2", "interface": GI0, "interface-use": "0.5"},
]


def test_route_lines_renders_an_ecmp_set_not_a_chain():
    """igp-route is the set of interfaces the traffic uses: shares below 1 mean an ECMP
    split, rendered per node; only an all-share-1 route is a '->' chain."""
    lines = route_lines(
        {"results": [{"path-computation-status": "success", "igp-route": ECMP_ROUTE}]}
    )
    assert lines[0] == (
        "- computation success: ECMP split — 4 interfaces at share 0.5 across 3 node(s): "
        f"PE1 {GI0}, {GI1}; P1 {GI1}; P2 {GI0}"
    )
    assert "->" not in lines[0]
    assert lines[1].startswith("  share = interface-use, the fraction of the policy's traffic")
    single = route_lines({"results": [{"path-computation-status": "success", "igp-route": ROUTE}]})
    assert single == [
        f"- computation success: single path (every interface share 1.0): PE1 {GI0} -> P1 {GI1}"
    ]
    assert route_lines({"results": [{"path-computation-status": "failure"}]}) == [
        "- computation failure: no route"
    ]


@respx.mock
async def test_explain_sr_policy_ecmp_route_onbox_origin_and_resolved_delay_caveat(
    make_settings,
):
    """A PCC-initiated policy with no CAT twin: the route is an ECMP set, the head-end's
    on-box configuration (NSO's CDB copy) is the origin evidence and names the PCE, the
    NBI lines carry host names and the constraints, and the empty delay series is
    explained by the utilization series on the same key."""
    routes = mock_policy(nbi_policy(flag_c=0))
    routes["services"].mock(return_value=ok(all_services()))
    routes["routes"].mock(
        return_value=ok(
            out(
                COE,
                status="accepted",
                results=[
                    {**KEY_PE1_PE2, "path-computation-status": "success", "igp-route": ECMP_ROUTE}
                ],
            )
        )
    )
    routes["delay"].mock(return_value=ok([]))
    routes["max_delay"].mock(
        return_value=ok(
            {
                "maxDelay": 0.0,
                "success": True,
                "message": "Maximum Average Delay for given LSP not present..returning default "
                "delay!",
            }
        )
    )
    policy = nbi_policy(flag_c=0)
    policy["policy-details"]["path"][0]["constraints"] = {"sid-algorithm": 0}
    routes["policy"].mock(return_value=ok(keyed_policy(policy)))
    text = await call_tool_text(
        await reads(make_settings),
        "cnc_explain_sr_policy",
        {"headend": "PE1", "endpoint": "PE2", "color": 100},
    )
    assert not text.startswith("Error:")
    assert verdict_of(text) == "UP"
    # (5) the ECMP set, grouped by node, with the sibling's share explanation.
    assert (
        "- computation success: ECMP split — 4 interfaces at share 0.5 across 3 node(s): "
        f"PE1 {GI0}, {GI1}; P1 {GI1}; P2 {GI0}" in text
    )
    assert f"{GI1} (use 0.5) -> P1" not in text
    # (6) host names inside the NBI section, the constraints block, the update time.
    assert "- PE1 (10.0.0.1) -> PE2 (10.0.0.3) color 100" in text
    assert "hops 16003@PE2 (10.0.0.3)" in text
    assert (
        "  constraints: sid-algorithm 0; no affinity / disjointness / bandwidth / protection "
        "constraint" in text
    )
    assert "- updated 2026-09-13T10:03:07Z (" in text
    # (6) the delay caveat is resolved by the utilization series on the same key.
    assert (
        "- no measured averageDelay samples in the window — the key is valid (the utilization "
        "series on the same key has samples), so SR-PM delay probes are not configured on the "
        "head-end for this policy" in text
    )
    assert "an unknown key answers the same empty list" not in text
    assert "- no NPM delay samples although the utilization series has data on the same key" in text
    # (6) the on-box configuration is the origin evidence and names the PCE.
    assert routes["onbox"].called
    assert (
        "## On-box SR-TE configuration (NSO CDB copy of the head-end) — cnc_get_nso_device_config"
        in text
    )
    assert (
        "- on-box policy 'doc-dyn-100' color 100 end-point PE2 (10.0.0.3): candidate path(s) "
        "preference 100 dynamic pcep metric igp" in text
    )
    assert "- PCEP peer(s) configured on PE1 (pcc pce address): PCE (10.0.0.5)" in text
    assert (
        "- this is NSO's CDB copy as of its last sync-from, not a live read of the router" in text
    )
    assert (
        "- created by: PCC-initiated (pcep-flag-c 0): configured on the head-end router PE1 "
        "outside NSO's service layer — on-box policy 'doc-dyn-100' (preference 100 dynamic pcep "
        "metric igp) in NSO's copy of its configuration" in text
    )
    assert "- delegated to the PCE at PCE (10.0.0.5) (the head-end's configured PCEP peer)" in text
    assert "CLI or another controller" not in text
    assert "cnc_get_nso_device_config(host_name='PE1', subtree='segment-routing') -> ok" in audit(
        text
    )
    # A router-id head-end resolves to the host name NSO keys devices by; a failed NSO read
    # leaves the origin unverified rather than claiming an on-box policy.
    respx.reset()
    routes = mock_policy(nbi_policy(flag_c=0))
    routes["services"].mock(return_value=ok(all_services()))
    routes["onbox"].mock(return_value=NATS_500)
    text = await call_tool_text(
        await reads(make_settings),
        "cnc_explain_sr_policy",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100},
    )
    assert verdict_of(text) == "UP"
    # An SR-MPLS policy keeps the caller's spelling on the CAT RPC (only an SRv6 policy
    # needs the host name there): the audit line is byte-identical to before.
    assert (
        "cnc_find_services_on_transport(headend='10.0.0.1', color=100, endpoint='10.0.0.3', "
        "response_format='json') -> ok" in audit(text)
    )
    assert "On-box SR-TE configuration (NSO CDB copy of the head-end): unavailable — Error:" in text
    assert (
        "- created by: PCC-initiated (pcep-flag-c 0): configured on the head-end router PE1 — "
        "by NSO/CAT if a policy service matches, else on the box (unverified)" in text
    )
    assert (
        "cnc_get_nso_device_config(host_name='PE1', subtree='segment-routing') -> error"
        in audit(text)
    )
    # No matching on-box policy in NSO's copy: said so, with the stale-copy caveat.
    respx.reset()
    routes = mock_policy(nbi_policy(flag_c=0))
    routes["services"].mock(return_value=ok(all_services()))
    routes["onbox"].mock(
        return_value=ok({"tailf-ned-cisco-ios-xr:segment-routing": {"traffic-eng": {}}})
    )
    text = await call_tool_text(
        await reads(make_settings),
        "cnc_explain_sr_policy",
        {"headend": "PE1", "endpoint": "PE2", "color": 100},
    )
    assert (
        "- no on-box SR-TE policy with color 100 to PE2 (10.0.0.3) in NSO's copy of PE1's "
        "configuration (the copy may be stale — cnc_check_nso_device_sync; or the policy came "
        "from another controller)" in text
    )
    assert "by neither NSO/CAT nor (per NSO's CDB copy) the box's own configuration" in text
    assert "- PCEP peer(s) configured on PE1 (pcc pce address): none configured" in text


@respx.mock
async def test_explain_sr_policy_without_the_topology_node_list(make_settings):
    """The node list failing leaves every router-id unresolved (and says so) and skips
    the on-box read when the head-end was given as a router-id."""
    routes = mock_policy(nbi_policy(flag_c=0))
    routes["services"].mock(return_value=ok(all_services()))
    routes["networks"].mock(return_value=NATS_500)
    text = await call_tool_text(
        await reads(make_settings),
        "cnc_explain_sr_policy",
        {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "color": 100},
    )
    assert not text.startswith("Error:")
    assert verdict_of(text) == "UP"
    assert "- router-ids are shown unresolved: the topology node list was unavailable" in text
    assert "- 10.0.0.1 -> 10.0.0.3 color 100: admin UP" in text
    assert (
        "On-box SR-TE configuration (NSO CDB copy of the head-end): skipped — the head-end's "
        "host name is unknown (router-id 10.0.0.1 not in the topology node list)" in text
    )
    assert not routes["onbox"].called


# --- cnc_alarm_triage ------------------------------------------------------------------

INSTALLED_APP_IDS_URL = f"{PLATFORM}/capp/installedapplicationid/query"
APP_IDS = ["capp-infra", "capp-coe", "capp-cwm-solutions"]
MS_ROBOT_ORCH = {**MS_HEALTHY, "Name": "robot-orch"}
MS_OPTIMA_LCM_DOWN = {**MS_DOWN, "Name": "optima-lcm"}
# The optima-lcm-0 pod-health alarm as seen live 2026-09-14: it is ABOUT optima-lcm-0
# (object_id; microservice optima-lcm, application capp-coe) but was RAISED by
# robot-orch in capp-infra (origin_service_id / origin_app_id).
OPTIMA_STALE_ALARM = {
    **STALE_ALARM,
    "AlarmId": "a-optima",
    "Description": "optima-lcm-0 health is down.",
    "object_id": "optima-lcm-0",
    "object_description": "optima-lcm-0 health is down.",
    "origin_app_id": "capp-infra",
    "origin_service_id": "robot-orch-6ff95ffb65-cxjdg",
}
APP_HEALTH_COE_DEGRADED = {
    "app_health_summary": [
        {"health_summary": health("capp-infra", 37, 37), "recommendation": "None"},
        {"health_summary": health("capp-coe", 12, 11, down=1), "recommendation": "x"},
        {"health_summary": health("capp-cwm-solutions", 8, 8), "recommendation": "None"},
    ]
}


def mock_microservices(by_app: dict[str, list[dict]]) -> dict[str, respx.Route]:
    """The unscoped cnc_list_microservices wire path: the installed application ids,
    then one microservice query per application (answered from ``by_app``)."""

    def answer(request: httpx.Request) -> httpx.Response:
        app = json.loads(request.content)["req_id"]
        return ok({"micro_service": by_app.get(app, [])})

    return {
        "app_ids": respx.post(INSTALLED_APP_IDS_URL).mock(
            return_value=ok({"installed_application_ids": {"application_ids": APP_IDS}, **ACCEPTED})
        ),
        "microservices": respx.post(MICROSERVICES_URL).mock(side_effect=answer),
    }


def test_pod_of_names_the_subject_pod_never_the_reporter():
    assert pod_of(OPTIMA_STALE_ALARM) == "optima-lcm-0"
    assert pod_of(STALE_ALARM) == "cwm-api-service"
    assert pod_of(fat_alarm(3, stale=True)) == "pod-3"
    worker = {"Description": "cwm-worker-2 health is Down.", "object_id": "x"}
    assert pod_of(worker) == "cwm-worker-2"
    # No pod-health fault text: object_id, then object_description's first token.
    assert pod_of({"Description": "Collection pipeline degraded", "object_id": "dlm"}) == "dlm"
    assert pod_of({"Description": "?", "object_description": "cwm-api-service health"}) == (
        "cwm-api-service"
    )
    assert pod_of({"origin_service_id": "robot-orch-6ff95ffb65-cxjdg"}) == ""


@respx.mock
async def test_alarm_triage_buckets_and_stale_cross_check(make_settings):
    alarms = mock_alarms(PE10_ALARM, STALE_ALARM, INFO_ALARM, CLEARED_ALARM)
    cluster = respx.get(CLUSTER_SUMMARY_URL).mock(return_value=ok(CLUSTER_SUMMARY))
    respx.get(INFRA_SUMMARY_URL).mock(return_value=ok(INFRA_SUMMARY))
    respx.get(APP_HEALTH_URL).mock(return_value=ok(APP_HEALTH))
    micro = mock_microservices({"capp-infra": [MS_ROBOT_ORCH], "capp-cwm-solutions": [MS_HEALTHY]})
    rtm = respx.get(RTM_ALARMS).mock(return_value=ok(RTM_MAJOR))
    text = await call_tool_text(await reads(make_settings), "cnc_alarm_triage", {})
    assert not text.startswith("Error:")
    assert verdict_of(text) == "ACT-NOW"
    assert "2 alarm(s) to act on, 1 possibly stale, 0 advisory, 1 informational." in text
    assert "### Act now (2)" in text
    assert "### Advisory / housekeeping — acknowledge and clear (0)" in text
    assert "Notes:" not in text  # every open alarm was read: nothing to caveat
    assert "- [Critical] Device PE10 (x) — Device PE10 is unreachable (a-pe10, ack=False" in text
    assert "- device alarm [major] PE1 GigabitEthernet0/1/7 — Nbr 192.0.2.41" in text
    assert "### Possibly stale (1)" in text
    assert (
        "cwm-api-service is down. (a-stale, ack=False, events=0, created=" in text
        and "— evidence: cluster health: capp-cwm-solutions Healthy 8/8 pods healthy; "
        "microservice cwm-api-service (capp-cwm-solutions) is Healthy (up 207d 11h 30m 10s)"
        in text
    )
    assert "### Informational (1)" in text and "pipeline health updating: HEALTHY" in text
    assert (
        "cnc_acknowledge_alarm(alarm_id=...)" in text
        and "cnc_annotate_alarm(alarm_id=..., note=...)" in text
    )
    # One alarm fetch (open only), the cross-check calls, the device alarms — no cleared search.
    assert (
        alarms.call_count == 1
        and json.loads(alarms.calls[0].request.content)["openAlarmsOnly"] is True
    )
    assert cluster.called and rtm.called
    # One cluster-wide microservice listing (every installed application), not one per
    # origin application.
    assert micro["app_ids"].call_count == 1
    queried = [json.loads(c.request.content)["req_id"] for c in micro["microservices"].calls]
    assert sorted(queried) == sorted(APP_IDS)
    assert "## Microservices (cluster-wide) — cnc_list_microservices" in text
    assert "- 2 microservice(s), 0 not Healthy" in text
    assert "cnc_list_microservices(page_size=500, response_format='json') -> ok" in audit(text)
    assert "app_id=" not in text


@respx.mock
async def test_alarm_triage_stale_alarm_with_unhealthy_pod_is_act_now(make_settings):
    mock_alarms(STALE_ALARM)
    respx.get(CLUSTER_SUMMARY_URL).mock(return_value=ok(CLUSTER_SUMMARY))
    respx.get(INFRA_SUMMARY_URL).mock(return_value=ok(INFRA_SUMMARY))
    respx.get(APP_HEALTH_URL).mock(return_value=ok(APP_HEALTH_DEGRADED))
    mock_microservices({"capp-cwm-solutions": [MS_DOWN]})
    respx.get(RTM_ALARMS).mock(return_value=ok(EMPTY_RTM))
    text = await call_tool_text(await reads(make_settings), "cnc_alarm_triage", {})
    assert verdict_of(text) == "ACT-NOW"
    assert (
        "STILL UNHEALTHY: cluster health: capp-cwm-solutions Degraded 7/8 pods healthy; "
        "microservice cwm-api-service (capp-cwm-solutions) is Down" in text
    )
    assert "### Possibly stale (0)" in text
    assert "- cwm-api-service (capp-cwm-solutions): Down up 0d 0h 2m 5s" in text


@respx.mock
async def test_alarm_triage_cross_checks_the_subject_pod_not_the_reporting_pod(make_settings):
    """The live optima-lcm-0 alarm: its origin application (capp-infra, robot-orch) is
    Healthy, but the pod it is ABOUT (optima-lcm in capp-coe) is Down — the alarm must
    be filed 'STILL UNHEALTHY' on optima-lcm's evidence, never 'possibly stale' on
    robot-orch's."""
    mock_alarms(OPTIMA_STALE_ALARM)
    respx.get(CLUSTER_SUMMARY_URL).mock(return_value=ok(CLUSTER_SUMMARY))
    respx.get(INFRA_SUMMARY_URL).mock(return_value=ok(INFRA_SUMMARY))
    respx.get(APP_HEALTH_URL).mock(return_value=ok(APP_HEALTH_COE_DEGRADED))
    mock_microservices({"capp-infra": [MS_ROBOT_ORCH], "capp-coe": [MS_OPTIMA_LCM_DOWN]})
    respx.get(RTM_ALARMS).mock(return_value=ok(EMPTY_RTM))
    text = await call_tool_text(await reads(make_settings), "cnc_alarm_triage", {})
    assert verdict_of(text) == "ACT-NOW"
    assert "### Possibly stale (0)" in text
    assert (
        "optima-lcm-0 health is down. (a-optima, ack=False, events=0, created=" in text
        and "— STILL UNHEALTHY: cluster health: capp-coe Degraded 11/12 pods healthy; "
        "microservice optima-lcm (capp-coe) is Down (up 0d 0h 2m 5s)"
        in text
    )
    assert "robot-orch" not in text.split("### Act now")[1].split("### ")[0]
    assert "capp-infra Healthy" not in text.split("### Act now")[1].split("### ")[0]
    # The same alarm once optima-lcm recovered: possibly stale, on optima-lcm's evidence.
    respx.reset()
    mock_alarms(OPTIMA_STALE_ALARM)
    respx.get(CLUSTER_SUMMARY_URL).mock(return_value=ok(CLUSTER_SUMMARY))
    respx.get(INFRA_SUMMARY_URL).mock(return_value=ok(INFRA_SUMMARY))
    respx.get(APP_HEALTH_URL).mock(return_value=ok(APP_HEALTH))
    mock_microservices(
        {"capp-infra": [MS_ROBOT_ORCH], "capp-coe": [{**MS_HEALTHY, "Name": "optima-lcm"}]}
    )
    respx.get(RTM_ALARMS).mock(return_value=ok(EMPTY_RTM))
    text = await call_tool_text(await reads(make_settings), "cnc_alarm_triage", {})
    assert verdict_of(text) == "STALE-ONLY"
    assert (
        "— evidence: cluster health: capp-coe Healthy 12/12 pods healthy; microservice "
        "optima-lcm (capp-coe) is Healthy" in text
    )
    # A subject no microservice matches is said so, without borrowing another app's health.
    respx.reset()
    mock_alarms(OPTIMA_STALE_ALARM)
    respx.get(CLUSTER_SUMMARY_URL).mock(return_value=ok(CLUSTER_SUMMARY))
    respx.get(INFRA_SUMMARY_URL).mock(return_value=ok(INFRA_SUMMARY))
    respx.get(APP_HEALTH_URL).mock(return_value=ok(APP_HEALTH))
    mock_microservices({"capp-infra": [MS_ROBOT_ORCH]})
    respx.get(RTM_ALARMS).mock(return_value=ok(EMPTY_RTM))
    text = await call_tool_text(await reads(make_settings), "cnc_alarm_triage", {})
    assert verdict_of(text) == "STALE-ONLY"
    assert (
        "— evidence: no microservice named like 'optima-lcm-0' on the cluster (cluster Healthy)"
        in text
    )
    assert "capp-infra" not in text.split("### Possibly stale")[1].split("### ")[0]


@respx.mock
async def test_alarm_triage_partial_failure_and_cleared_section(make_settings):
    mock_alarms(STALE_ALARM, CLEARED_ALARM)
    respx.get(CLUSTER_SUMMARY_URL).mock(return_value=NATS_500)
    respx.get(INFRA_SUMMARY_URL).mock(return_value=ok(INFRA_SUMMARY))
    respx.get(APP_HEALTH_URL).mock(return_value=ok(APP_HEALTH))
    respx.post(INSTALLED_APP_IDS_URL).mock(return_value=NATS_500)
    respx.post(MICROSERVICES_URL).mock(return_value=NATS_500)
    respx.get(RTM_ALARMS).mock(return_value=ok(EMPTY_RTM))
    text = await call_tool_text(
        await reads(make_settings), "cnc_alarm_triage", {"include_cleared": True}
    )
    assert not text.startswith("Error:")
    assert verdict_of(text) == "STALE-ONLY"
    assert "Cluster health (stale-alarm cross-check): unavailable — Error:" in text
    assert "Microservices (cluster-wide): unavailable — Error:" in text
    assert "— evidence: 0 events, unchanged for 7+ days" in text
    assert "## Recently cleared alarms — cnc_search_alarms" in text
    # The sibling's rendering (fault.alarm_line): the fault that was cleared, then the
    # clearing text — never the clearing text alone as the description.
    assert (
        "- [Clear] Device P1 (p1) — [Major] Device P1 is unreachable | cleared: "
        "Device P1 is reachable (a-clear, ack=False, events=2, created=" in text
    )
    assert "— Device P1 is reachable (a-clear" not in text
    assert (
        "cnc_search_alarms(state='Clear', open_only=False, limit=30, response_format='json') -> ok"
        in audit(text)
    )


@respx.mock
async def test_alarm_triage_json_shape(make_settings):
    mock_alarms(PE10_ALARM)
    respx.get(RTM_ALARMS).mock(return_value=ok(EMPTY_RTM))
    payload = json.loads(
        await call_tool_text(
            await reads(make_settings), "cnc_alarm_triage", {"response_format": "json"}
        )
    )
    assert payload["verdict"]["status"] == "act-now"
    triage = payload["sections"]["triage"]["data"]
    assert set(triage) == {"act_now", "possibly_stale", "advisory", "informational"}
    assert payload["sections"]["alarms"]["data"]["by_state"] == {"Critical": 1}
    assert len(triage["act_now"]) == 1 and triage["possibly_stale"] == []
    assert [c["tool"] for c in payload["calls"]] == ["cnc_search_alarms", "cnc_list_device_alarms"]


def fat_alarm(n: int, *, stale: bool = False) -> dict:
    """An open alarm the size of a live one (~2.6 KB: a Description plus a 10-event
    history), Major, 'stale' ones with 0 events and a 2026-08 stamp."""
    events = [
        {
            "EventId": f"a-fat-{n}-e{i}",
            "EventSeverity": "Major",
            "Description": f"Device PE{n} lost its SNMP session to the collector, attempt {i} "
            "of the reachability check did not receive any response in time",
            "Timestamp": str(1789200000000 + i * 1000),
            "EventCategory": "System",
            "alarm_id": f"a-fat-{n}",
            "origin_app_id": "capp-infra:DLM",
        }
        for i in range(10)
    ]
    if stale:
        return {
            **STALE_ALARM,
            "AlarmId": f"a-fat-{n}",
            "Description": f"pod-{n} health is down.",
            "object_description": f"pod-{n}",
            "origin_service_id": f"pod-{n}-57b9448ffb-c8zxt",
        }
    return alarm(
        f"a-fat-{n}",
        "Major",
        f"Device PE{n} (uuid-{n})",
        f"Device PE{n} lost its SNMP session to the collector",
        events_count=10,
        Events=events,
        Updated=str(1789200000000 + n * 1000),
    )


@respx.mock
async def test_alarm_triage_reads_every_open_alarm_under_the_size_cap(make_settings):
    """Regression for the 2026-09-14 finding: 32 fat open alarms (five of them stale)
    under a 40,000-character response cap — the triage must count all 32 and run the
    stale-alarm cross-check, not read the 15 that fit and call it '>200 alarms'."""
    rows = [fat_alarm(n, stale=n >= 27) for n in range(32)]
    assert len(json.dumps(rows)) > 40000  # the whole set is well over the cap
    alarms = mock_alarms(*rows)
    cluster = respx.get(CLUSTER_SUMMARY_URL).mock(return_value=ok(CLUSTER_SUMMARY))
    respx.get(INFRA_SUMMARY_URL).mock(return_value=ok(INFRA_SUMMARY))
    respx.get(APP_HEALTH_URL).mock(return_value=ok(APP_HEALTH))
    mock_microservices({"capp-cwm-solutions": [MS_HEALTHY]})
    respx.get(RTM_ALARMS).mock(return_value=ok(EMPTY_RTM))
    mcp = await build(make_settings(max_retries=0, max_response_chars=40000))
    text = await call_tool_text(mcp, "cnc_alarm_triage", {})
    assert not text.startswith("Error:")
    assert verdict_of(text) == "ACT-NOW"
    assert "27 alarm(s) to act on, 5 possibly stale, 0 advisory, 0 informational." in text
    assert "- 32 open alarm(s): Major 32" in text
    assert "exceed the" not in text and "size-capped" not in text
    assert cluster.called  # the cross-check ran because the stale alarms were read
    assert alarms.call_count == 1  # one fetch (the 32 fit in one 200-row page)


@respx.mock
async def test_alarm_triage_reads_per_state_beyond_the_search_limit(make_settings):
    """More open alarms than one cnc_search_alarms fetch returns (its 500 cap — the
    sibling's maximum, which the triage asks for): the set is re-read per State and
    merged, and the note says exactly what was read. 205 open alarms fit in one fetch."""
    assert TRIAGE_LIMIT == ALARM_SCAN_LIMIT == 500
    rows = [
        alarm(f"a-many-{n}", state, f"obj-{n}", f"text {n}", Updated=str(1789200000000 + n * 1000))
        for n, state in enumerate(
            ["Critical"] * 3 + ["Major"] * 2 + ["Minor"] * 30 + ["Warning"] * 20 + ["Info"] * 450
        )
    ]
    assert len(rows) == 505
    alarms = mock_alarms(*rows)
    respx.get(RTM_ALARMS).mock(return_value=ok(EMPTY_RTM))
    mcp = await build(make_settings(max_retries=0, max_response_chars=2_000_000))
    text = await call_tool_text(mcp, "cnc_alarm_triage", {})
    assert verdict_of(text) == "ACT-NOW"
    assert "5 alarm(s) to act on, 0 possibly stale, 0 advisory, 500 informational." in text
    assert "- 505 open alarm(s): Critical 3, Info 450, Major 2, Minor 30, Warning 20" in text
    assert (
        "- 505 open alarms exceed the 500-alarm cap of one cnc_search_alarms fetch: re-read per "
        "State (Critical 3, Major 2, Minor 30, Warning 20, Info 450) — 505 open alarms read" in text
    )
    assert "re-read per State, all 505 open alarms read" in text
    assert "NOT fully read" not in text and "most recently updated were read" not in text
    assert "per-fetch limit" not in text  # the cap is the composite's ask, not a sibling limit
    calls = audit(text)
    assert calls[0] == (
        f"cnc_search_alarms(open_only=True, limit={TRIAGE_LIMIT}, response_format='json') -> ok"
    )
    assert [c for c in calls if "state='Info'" in c] == [
        f"cnc_search_alarms(state='Info', open_only=True, limit={TRIAGE_LIMIT}, "
        "response_format='json') -> ok"
    ]
    assert alarms.call_count == 6 * 3  # six fetches, each paging 200 + 200 + a short page
    # 205 open alarms (the old 200 cap's regression case) are one complete fetch now.
    respx.reset()
    alarms = mock_alarms(*rows[:205])
    respx.get(RTM_ALARMS).mock(return_value=ok(EMPTY_RTM))
    text = await call_tool_text(mcp, "cnc_alarm_triage", {})
    assert "- 205 open alarm(s): Critical 3, Info 150, Major 2, Minor 30, Warning 20" in text
    assert "Notes:" not in text and "re-read" not in text
    assert alarms.call_count == 1 * 2  # one fetch: a full 200-row page + a short page
    # One State alone over the cap: that State is reported as partially read, with its total.
    respx.reset()
    rows = [
        alarm(f"a-info-{n}", "Info", f"obj-{n}", f"text {n}", Updated=str(1789200000000 + n))
        for n in range(503)
    ] + [PE10_ALARM]
    mock_alarms(*rows)
    respx.get(RTM_ALARMS).mock(return_value=ok(EMPTY_RTM))
    text = await call_tool_text(mcp, "cnc_alarm_triage", {})
    assert "- 501 open alarm(s): Critical 1, Info 500" in text
    assert (
        "- open alarms NOT fully read — Info: 500 of 503 open alarms read (the 500 most "
        "recently updated — cnc_search_alarms state='Info' for the rest)" in text
    )


@respx.mock
async def test_alarm_triage_advisories_are_their_own_bucket(make_settings):
    mock_alarms(BACKUP_ADVISORY, CERTIFICATE_ADVISORY, INFO_ALARM)
    respx.get(RTM_ALARMS).mock(return_value=ok(EMPTY_RTM))
    text = await call_tool_text(await reads(make_settings), "cnc_alarm_triage", {})
    assert verdict_of(text) == "ADVISORY-ONLY"
    assert "0 alarm(s) to act on, 0 possibly stale, 2 advisory, 1 informational." in text
    assert "### Act now (0)" in text
    assert "### Advisory / housekeeping — acknowledge and clear (2)" in text
    assert "- [Critical] DLM Service — Please make sure to take a data backup" in text
    assert "- [Info] Crosswork kubernetes certificate management" in text
    assert (
        "(one-shot housekeeping alarms: do what they ask once, then cnc_acknowledge_alarm" in text
    )
    assert "Reasons:" not in text
    # The same backup reminder with a second event is a live Critical again.
    respx.reset()
    mock_alarms({**BACKUP_ADVISORY, "events_count": 2}, PE10_ALARM)
    respx.get(RTM_ALARMS).mock(return_value=ok(EMPTY_RTM))
    payload = json.loads(
        await call_tool_text(
            await reads(make_settings), "cnc_alarm_triage", {"response_format": "json"}
        )
    )
    assert payload["verdict"]["status"] == "act-now"
    triage = payload["sections"]["triage"]["data"]
    assert len(triage["act_now"]) == 2 and triage["advisory"] == []


# --- cnc_explain_service -----------------------------------------------------------------


def mock_service(plan: dict = PLAN_COMPLETED) -> dict[str, respx.Route]:
    return {
        "service": respx.get(f"{NSO_DATA}/{L3VPN_PATH}").mock(return_value=ok(L3VPN_NSO_OBJECT)),
        "plan_data": respx.post(f"{CAT_RPC}:get-service-plan-data").mock(return_value=ok(plan)),
        "nano_plan": respx.get(f"{NSO_DATA}/{L3VPN_CAT_PLAN_LIST}={VPN_ID}").mock(
            return_value=ok(nano_plan(READY))
        ),
        "health": respx.get(f"{CAT_DATA}/{L3VPN_PATH}").mock(return_value=ok(OPER_STATUS)),
        "underlay": respx.get(
            f"{CAT_DATA}/{L3VPN_PATH}/underlay-transport/cisco-l3vpn-ntw:discovered-underlay-transport"
        ).mock(return_value=ok(UNDERLAY)),
        "sub_count": respx.post(f"{CAT_RPC}:get-sub-service-count").mock(
            return_value=ok(SUB_COUNT)
        ),
        "sub_paths": respx.post(f"{CAT_RPC}:get-sub-service-paths").mock(
            return_value=ok(SUB_PATHS)
        ),
        "probe": respx.post(PROBE_STATUS_URL).mock(return_value=NO_PROBE_500),
    }


@respx.mock
async def test_explain_service_deployed_vpn(make_settings):
    routes = mock_service()
    text = await call_tool_text(
        await reads(make_settings), "cnc_explain_service", {"vpn_id": VPN_ID}
    )
    assert not text.startswith("Error:")
    assert verdict_of(text) == "DEPLOYED"
    assert f"{L3VPN_PATH}: deployed." in text
    assert "- CAT plan status: completed" in text
    assert "- oper-status: op-up" in text
    assert "- underlay: 1 SR policy(ies), 0 RSVP-TE tunnel(s)" in text
    assert "- monitoring: no active probe session" in text
    assert "- SR policy PE1 color 100 -> 10.0.0.3 (cnc_explain_sr_policy)" in text
    assert "- self self: init=reached, config-apply=reached, ready=reached" in text
    assert f"- {L3VPN_PATH}/vpn-nodes/vpn-node=PE2" in text
    for name, route in routes.items():
        assert route.called, name
    calls = audit(text)
    assert (
        calls[0] == f"cnc_get_service(yang_path='{L3VPN_PATH}', include_plan=True, "
        "response_format='json') -> ok"
    )
    assert f"cnc_get_probe_status(service_id='{L3VPN_PATH}') -> ok" in calls


@respx.mock
async def test_explain_service_failed_plan_and_partial_failure(make_settings):
    routes = mock_service(PLAN_FAILED)
    routes["nano_plan"].mock(
        return_value=ok(
            nano_plan([("init", "reached"), ("config-apply", "failed"), ("ready", "not-reached")])
        )
    )
    routes["underlay"].mock(return_value=NATS_500)
    text = await call_tool_text(
        await reads(make_settings), "cnc_explain_service", {"yang_path": L3VPN_PATH}
    )
    assert not text.startswith("Error:")
    assert verdict_of(text) == "FAILED"
    assert "- CAT plan: failed — device PE1: out of sync" in text
    assert "- nano-plan component PE1 has a failed state" in text
    assert "Discovered underlay transport (CAT): unavailable — Error:" in text
    assert "- underlay: unknown" in text


@respx.mock
async def test_explain_service_non_vpn_and_json_shape(make_settings):
    odn = "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/odn-template=doc-odn-90"
    respx.get(f"{NSO_DATA}/{odn}").mock(
        return_value=ok(
            {
                "cisco-sr-te-cfp-sr-odn:odn-template": [
                    {"name": "doc-odn-90", "color": 90, "head-end": [{"name": "PE1"}]}
                ]
            }
        )
    )
    respx.post(f"{CAT_RPC}:get-service-plan-data").mock(
        return_value=ok(
            cat(
                "get-service-plan-data",
                {"service-plan-data": [{"yang-path": odn, "status": "in-progress"}]},
            )
        )
    )
    respx.get(f"{NSO_DATA}/{odn.replace('odn-template=', 'odn-template-plan=')}").mock(
        return_value=httpx.Response(204)
    )
    payload = json.loads(
        await call_tool_text(
            await reads(make_settings),
            "cnc_explain_service",
            {"yang_path": odn, "response_format": "json"},
        )
    )
    assert payload["verdict"]["status"] == "in-progress"
    assert "not a VPN service" in payload["verdict"]["notes"][0]
    assert set(payload["sections"]) == {"service", "plan"}
    assert [c["tool"] for c in payload["calls"]] == ["cnc_get_service", "cnc_get_service_plan"]


async def test_explain_service_selector_rules(make_settings):
    mcp = await reads(make_settings)
    assert (await call_tool_text(mcp, "cnc_explain_service", {})).startswith(
        "Error: Pass exactly one of yang_path, vpn_id or name."
    )
    text = await call_tool_text(mcp, "cnc_explain_service", {"vpn_id": "x", "name": "x"})
    assert text.startswith("Error: Pass exactly one")
    text = await call_tool_text(mcp, "cnc_explain_service", {"vpn_id": "x", "layer": "l4"})
    assert text.startswith("Error: Unknown VPN layer")


@respx.mock
async def test_explain_service_by_name_resolves_through_the_inventory(make_settings):
    """A bare name (an ODN template, a policy, a VPN — any type) is looked up with
    cnc_list_services and the exact service-name match gives the yang-path."""
    routes = mock_service()
    listing = respx.post(f"{CAT_RPC}:get-all-services").mock(
        return_value=ok(
            all_services(
                service_info(f"{VPN_ID}-copy", L3VPN_QNAME, f"{L3VPN_LIST}={VPN_ID}-copy"),
                service_info(VPN_ID, L3VPN_QNAME, L3VPN_PATH),
            )
        )
    )
    text = await call_tool_text(
        await reads(make_settings), "cnc_explain_service", {"name": VPN_ID.upper()}
    )
    assert not text.startswith("Error:")
    assert verdict_of(text) == "DEPLOYED"
    assert f"# Service {VPN_ID.upper()}" in text
    assert f"- '{VPN_ID.upper()}' is {VPN_ID} (ietf-l3vpn): {L3VPN_PATH}" in text
    assert "- oper-status: op-up" in text
    for name, route in routes.items():
        assert route.called, name
    body = json.loads(listing.calls[0].request.content)["cat-inventory-rpc:input"]
    request = body["cat-inventory-rpc:get-all-services-request"]
    assert request["query-criteria"]["service-name-filters"] == {
        "start-with": VPN_ID.upper(),
        "case-sensitive": "false",
    }
    calls = audit(text)
    assert calls[0] == (
        f"cnc_list_services(name_prefix='{VPN_ID.upper()}', limit=500, response_format='json') "
        "-> ok"
    )
    assert calls[1].startswith(f"cnc_get_service(yang_path='{L3VPN_PATH}'")


@respx.mock
async def test_explain_service_by_name_not_found_ambiguous_and_lookup_failure(make_settings):
    mcp = await reads(make_settings)
    listing = respx.post(f"{CAT_RPC}:get-all-services").mock(
        return_value=ok(all_services(service_info("doc-odn-90x", POLICY_QNAME, "p=x")))
    )
    service = respx.get(url__startswith=NSO_DATA).mock(return_value=ok({}))
    text = await call_tool_text(mcp, "cnc_explain_service", {"name": "doc-odn-90"})
    assert not text.startswith("Error:")
    assert verdict_of(text) == "NOT-FOUND"
    assert (
        "No service named 'doc-odn-90' in the CAT inventory; 1 service name(s) start with it"
        in text
    )
    assert "- doc-odn-90x (policy): p=x" in text
    assert not service.called  # nothing else is read
    assert [c.split("(")[0] for c in audit(text)] == ["cnc_list_services"]
    # Two services of different types share the name: the caller picks a yang_path.
    listing.mock(
        return_value=ok(
            all_services(
                service_info("dup", POLICY_QNAME, f"{POLICY_LIST}=dup"),
                service_info("dup", L3VPN_QNAME, f"{L3VPN_LIST}=dup"),
            )
        )
    )
    payload = json.loads(
        await call_tool_text(mcp, "cnc_explain_service", {"name": "dup", "response_format": "json"})
    )
    assert payload["verdict"]["status"] == "ambiguous"
    assert "call again with the yang_path" in payload["verdict"]["headline"]
    assert payload["sections"]["lookup"]["summary"][0] == (
        "- 'dup' names 2 services of different types:"
    )
    assert list(payload["sections"]) == ["lookup"]
    # The same name listed twice for the same path (a paging overlap) is not ambiguous.
    listing.mock(
        return_value=ok(
            all_services(
                service_info("dup", POLICY_QNAME, f"{POLICY_LIST}=dup"),
                service_info("dup", POLICY_QNAME, f"{POLICY_LIST}=dup"),
            )
        )
    )
    respx.post(f"{CAT_RPC}:get-service-plan-data").mock(
        return_value=ok(cat("get-service-plan-data", {}))
    )
    text = await call_tool_text(mcp, "cnc_explain_service", {"name": "dup"})
    assert (
        verdict_of(text) == "UNKNOWN" and f"cnc_get_service(yang_path='{POLICY_LIST}=dup'" in text
    )
    # The inventory listing itself failing: the verdict is unknown, the section unavailable.
    listing.mock(return_value=NATS_500)
    text = await call_tool_text(mcp, "cnc_explain_service", {"name": "doc-odn-90"})
    assert not text.startswith("Error:")
    assert verdict_of(text) == "UNKNOWN"
    assert "'doc-odn-90' could not be looked up: Error:" in text
    assert "Service lookup (CAT inventory): unavailable — Error:" in text


# --- cnc_provision_l3vpn_e2e ------------------------------------------------------------


def mock_provisioning(commit: httpx.Response | None = None) -> dict[str, respx.Route]:
    """The PUT answers the dry run (``?dry-run=native``) with the rendered CLI and the
    commit with ``commit`` (201 Created by default); everything after it succeeds."""

    def put(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("dry-run") == "native":
            return httpx.Response(201, json=DRY_RUN_L3VPN)
        return commit if commit is not None else httpx.Response(201)

    return {
        "put": respx.put(f"{NSO_DATA}/{L3VPN_PATH}").mock(side_effect=put),
        "nano_plan": respx.get(f"{NSO_DATA}/{L3VPN_PLAN_LIST}={VPN_ID}").mock(
            return_value=ok(nano_plan(READY))
        ),
        "plan_data": respx.post(f"{CAT_RPC}:get-service-plan-data").mock(
            return_value=ok(PLAN_COMPLETED)
        ),
        "health": respx.get(f"{CAT_DATA}/{L3VPN_PATH}").mock(return_value=ok(OPER_STATUS)),
        "nodes": mock_nodes(PE1, PE2, P1),
        "start": respx.post(rpc(OAM, "set-oam-trace-route-by-calc")).mock(
            return_value=ok(out(OAM, **TRACE_REGISTERED))
        ),
        "trace": respx.post(rpc(OAM, "get-oam-trace-route-by-query-id")).mock(
            return_value=ok(out(OAM, **TRACE_COMPLETED))
        ),
    }


@respx.mock
async def test_provision_l3vpn_e2e_deployed_with_trace(make_settings, fake_clock):
    routes = mock_provisioning()
    text = await call_tool_text(await writes(make_settings), "cnc_provision_l3vpn_e2e", L3VPN_ARGS)
    assert not text.startswith("Error:")
    assert verdict_of(text) == "DEPLOYED"
    assert "committed by NSO, plan completed, oper-status op-up, trace ok" in text
    assert f"cnc_delete_vpn_service(vpn_id='{VPN_ID}', layer='l3')" in text
    # The dry run's CLI is in the answer, and it was sent with ?dry-run=native first.
    assert "Dry run only — nothing was committed" in text and "vrf doc-l3vpn-1" in text
    assert routes["put"].call_count == 2
    assert routes["put"].calls[0].request.url.params.get("dry-run") == "native"
    assert "dry-run" not in routes["put"].calls[1].request.url.params
    assert "- dry run: ok (CLI rendered below, nothing committed)" in text
    assert "- commit: ok — Created L3VPN service" in text
    assert "- plan: completed — Service plan" in text
    assert "- verify: in the CAT inventory, oper-status op-up" in text
    assert "- trace: Trace route SPQ-324616899 finished after 0s: completed (4)" in text
    body = json.loads(routes["start"].calls[0].request.content)["input"]
    assert body["head-end-node-uuid"] == PE1_UUID and body["tail-end-node-uuid"] == PE2_UUID
    calls = audit(text)
    assert calls[0].startswith("cnc_create_l3vpn_service(vpn_id='doc-l3vpn-1'") and calls[
        0
    ].endswith("dry_run=True) -> ok")
    assert calls[1].endswith("dry_run=False) -> ok")
    assert (
        f"cnc_wait_for_service_plan(plan_yang_path='{L3VPN_PATH}', target='completed', "
        "timeout_seconds=120) -> ok" in calls
    )
    assert (
        "cnc_get_device(host_name='PE1') -> ok" in calls
        and "cnc_get_device(host_name='PE2') -> ok" in calls
    )
    assert f"cnc_wait_for_oam_trace_route(query_id='{QUERY_ID}', timeout_seconds=90) -> ok" in calls
    # Long arguments are shortened in the audit list.
    assert "..." in calls[0] and len(calls[0]) < 400


@respx.mock
async def test_provision_l3vpn_e2e_stops_on_failed_commit(make_settings, fake_clock):
    routes = mock_provisioning(
        commit=httpx.Response(
            400,
            json={
                "ietf-restconf:errors": {
                    "error": [
                        {
                            "error-tag": "malformed-message",
                            "error-message": "STATUS_CODE: TSDN-L3VPN-407\nREASON: Duplicate RD\n"
                            "CATEGORY: validation",
                        }
                    ]
                }
            },
        )
    )
    text = await call_tool_text(await writes(make_settings), "cnc_provision_l3vpn_e2e", L3VPN_ARGS)
    assert not text.startswith("Error:")
    assert verdict_of(text) == "FAILED"
    assert (
        "Stopped at the commit of 'doc-l3vpn-1': NSO rejected it, so nothing was deployed. "
        "Nothing was deleted or rolled back." in text
    )
    assert (
        "- commit: FAILED — Error: the function pack rejected the service: Duplicate RD "
        "(TSDN-L3VPN-407)" in text
    )
    assert routes["put"].call_count == 2
    for name in ("plan_data", "health", "start", "trace"):
        assert not routes[name].called, name
    calls = audit(text)
    assert len(calls) == 2
    assert calls[0].startswith(
        "cnc_create_l3vpn_service(vpn_id='doc-l3vpn-1', route_distinguisher='0:65091:91'"
    )
    assert calls[0].endswith("topology='any-to-any', profile_id='p1', dry_run=True) -> ok")
    assert calls[1].endswith("topology='any-to-any', profile_id='p1', dry_run=False) -> error")


@respx.mock
async def test_provision_l3vpn_e2e_failed_dry_run_commits_nothing(make_settings, fake_clock):
    routes = mock_provisioning()
    routes["put"].mock(
        return_value=httpx.Response(
            400,
            json={
                "ietf-restconf:errors": {
                    "error": [
                        {
                            "error-tag": "malformed-message",
                            "error-message": "STATUS_CODE: TSDN-L3VPN-415\nREASON: BGP routing "
                            "process is not configured on the device\nCATEGORY: validation",
                        }
                    ]
                }
            },
        )
    )
    text = await call_tool_text(await writes(make_settings), "cnc_provision_l3vpn_e2e", L3VPN_ARGS)
    assert verdict_of(text) == "FAILED"
    assert "Stopped at the dry run; nothing was committed" in text
    assert routes["put"].call_count == 1


@respx.mock
async def test_provision_l3vpn_e2e_unverified_when_plan_lags_and_trace_fails(
    make_settings, fake_clock
):
    routes = mock_provisioning()
    routes["plan_data"].mock(return_value=ok(PLAN_IN_PROGRESS))
    routes["trace"].mock(
        return_value=ok(out(OAM, **service_route(5, "gNMI session not established")))
    )
    text = await call_tool_text(
        await writes(make_settings), "cnc_provision_l3vpn_e2e", {**L3VPN_ARGS, "wait_seconds": 10}
    )
    assert not text.startswith("Error:")
    assert verdict_of(text) == "DEPLOYED-UNVERIFIED"
    assert "- plan: not completed within 10 s — Service plan" in text
    assert (
        "- trace: the platform's verdict is FAILED — Trace route SPQ-324616899 FAILED after 0s"
        in text
    )
    assert "re-check with cnc_wait_for_service_plan" in text
    payload = json.loads(
        await call_tool_text(
            await writes(make_settings),
            "cnc_provision_l3vpn_e2e",
            {**L3VPN_ARGS, "trace": False, "response_format": "json"},
        )
    )
    assert payload["verdict"]["status"] == "deployed-unverified"
    assert payload["sections"]["trace"] == {
        "title": "OAM trace route",
        "tool": "cnc_start_oam_trace_route",
        "status": "skipped",
        "summary": [],
        "error": "trace=false",
    }
    assert payload["sections"]["dry_run"]["text"].startswith("Dry run only")


@respx.mock
async def test_provision_l3vpn_e2e_copes_with_an_absent_sibling(make_settings, fake_clock):
    """A sibling missing from the server (here: removed after registration) is an
    'unavailable' step, not a crash — the audit line says which tool was missing."""
    routes = mock_provisioning()
    mcp = await writes(make_settings)
    mcp.remove_tool("cnc_wait_for_service_plan")
    text = await call_tool_text(mcp, "cnc_provision_l3vpn_e2e", {**L3VPN_ARGS, "trace": False})
    assert not text.startswith("Error:")
    assert verdict_of(text) == "FAILED"
    assert "- plan: FAILED — Error: cnc_wait_for_service_plan: Unknown tool" in text
    assert routes["health"].called  # the verification still ran


@respx.mock
async def test_provision_l3vpn_e2e_skips_the_trace_when_the_oam_tool_is_not_registered(
    make_settings, fake_clock
):
    """The trace is optional (trace=false exists), so the playbook is offered with OAM
    writes off — CNC_MCP_WRITE_AREAS without 'oam' — and then says the trace was
    skipped instead of failing the verdict on an 'Unknown tool'."""
    routes = mock_provisioning()
    mcp = build_server(
        make_settings(
            max_retries=0, enable_writes=True, write_areas="composite, service_provisioning"
        )
    )
    names = {t.name for t in await mcp.list_tools()}
    assert "cnc_provision_l3vpn_e2e" in names and "cnc_start_oam_trace_route" not in names
    text = await call_tool_text(mcp, "cnc_provision_l3vpn_e2e", L3VPN_ARGS)
    assert not text.startswith("Error:")
    assert verdict_of(text) == "DEPLOYED"
    assert "plan completed, oper-status op-up, trace skipped (tool not registered)" in text
    assert (
        "- trace: skipped — cnc_start_oam_trace_route is not registered on this server (OAM "
        "writes are off: CNC_MCP_WRITE_AREAS or CNC_MCP_DISABLED_TOOLS), so no trace was run"
        in text
    )
    assert "enable OAM writes and run cnc_start_oam_trace_route yourself" in text
    assert "OAM trace route: skipped — cnc_start_oam_trace_route is not registered" in text
    assert not routes["start"].called and not routes["nodes"].called
    assert "Unknown tool" not in text
    calls = audit(text)
    assert not any(c.startswith(("cnc_get_device(", "cnc_start_oam_trace_route(")) for c in calls)
    # The same server, disabled by name rather than by area.
    respx.reset()
    routes = mock_provisioning()
    mcp = build_server(
        make_settings(max_retries=0, enable_writes=True, disabled_tools="cnc_start_oam_trace_route")
    )
    payload = json.loads(
        await call_tool_text(
            mcp, "cnc_provision_l3vpn_e2e", {**L3VPN_ARGS, "response_format": "json"}
        )
    )
    assert payload["verdict"]["status"] == "deployed"
    assert payload["sections"]["trace"]["status"] == "skipped"
    assert payload["sections"]["trace"]["error"].startswith(
        "cnc_start_oam_trace_route is not registered on this server"
    )
    assert not routes["start"].called
    # trace=false still reads trace=false, not the missing tool.
    text = await call_tool_text(mcp, "cnc_provision_l3vpn_e2e", {**L3VPN_ARGS, "trace": False})
    assert "OAM trace route: skipped — trace=false" in text
    assert "not registered" not in text


@respx.mock
async def test_provision_l3vpn_e2e_rejects_wait_seconds_the_sibling_would_reject(
    make_settings, fake_clock
):
    """cnc_wait_for_service_plan takes timeout_seconds 5..600: a wait_seconds outside
    that is refused by the composite's own schema, before the dry run — never after the
    commit, where a failed wait would report a committed, converging service as FAILED."""
    routes = mock_provisioning()
    mcp = await writes(make_settings)
    for value in (0, 4, 601):
        with pytest.raises(ToolError) as info:
            await call_tool_text(
                mcp, "cnc_provision_l3vpn_e2e", {**L3VPN_ARGS, "wait_seconds": value}
            )
        assert "wait_seconds" in str(info.value)
    assert not routes["put"].called
    # The bounds are usable end to end.
    text = await call_tool_text(
        mcp, "cnc_provision_l3vpn_e2e", {**L3VPN_ARGS, "wait_seconds": 5, "trace": False}
    )
    assert verdict_of(text) == "DEPLOYED"
    assert (
        f"cnc_wait_for_service_plan(plan_yang_path='{L3VPN_PATH}', target='completed', "
        "timeout_seconds=5) -> ok" in audit(text)
    )


# --- cnc_create_sr_policy_e2e ----------------------------------------------------------


def mock_sr_policy_creation(oper: str = "UP") -> dict[str, respx.Route]:
    return {
        "networks": respx.get(NETWORKS_URL).mock(return_value=ok(NETWORKS)),
        "dryrun": respx.post(rpc(SRP, "sr-policy-dryrun")).mock(return_value=ok(DRYRUN_SUCCESS)),
        "create": respx.post(rpc(SRP, "sr-policy-create")).mock(return_value=ok(CREATE_SUCCESS)),
        "policy": respx.get(policy_url(200)).mock(
            return_value=ok(keyed_policy({**nbi_policy(oper=oper), "color": 200}))
        ),
        "routes": respx.post(rpc(COE, "sr-policy-routes")).mock(return_value=ok(ROUTES_OUT)),
    }


SR_ARGS = {"headend": "PE1", "endpoint": "PE2", "color": 200, "path_name": "doc-dyn-200"}


@respx.mock
async def test_create_sr_policy_e2e_created_and_up(make_settings, fake_clock):
    routes = mock_sr_policy_creation()
    text = await call_tool_text(
        await writes(make_settings), "cnc_create_sr_policy_e2e", {**SR_ARGS, "description": "doc"}
    )
    assert not text.startswith("Error:")
    assert verdict_of(text) == "CREATED-UP"
    assert "SR policy PE1 -> PE2 color 200 (doc-dyn-200) was created and is UP." in text
    assert "cnc_delete_sr_policy(headend='PE1', endpoint='PE2', color=200)" in text
    assert "- route: PE1 GigabitEthernet0/0/0/0 -> P1 GigabitEthernet0/0/0/1" in text
    assert "- segment list: 16003@10.0.0.3" in text
    for name, route in routes.items():
        assert route.called, name
    assert routes["dryrun"].calls[0].request.url.path.endswith("sr-policy-dryrun")
    assert routes["dryrun"].called and routes["create"].called
    created = json.loads(routes["create"].calls[0].request.content)["input"]["sr-policies"][0]
    assert created["head-end"] == "10.0.0.1" and created["color"] == 200
    assert created["description"] == "doc"
    calls = audit(text)
    assert calls[0].startswith(
        "cnc_dryrun_sr_policy(headend='PE1', endpoint='PE2', path_type='dynamic'"
    )
    assert calls[1].startswith(
        "cnc_create_sr_policy(headend='PE1', endpoint='PE2', color=200, path_name='doc-dyn-200', "
        "description='doc'"
    )
    assert (
        "cnc_wait_for_sr_policy_oper_state(headend='PE1', endpoint='PE2', color=200, "
        "target='UP', timeout_seconds=60, network='Default-network') -> ok" in calls
    )
    assert all(c.endswith("-> ok") for c in calls), calls


@respx.mock
async def test_create_sr_policy_e2e_rejects_values_the_siblings_would_reject(
    make_settings, fake_clock
):
    """wait_seconds below cnc_wait_for_sr_policy_oper_state's minimum (5) and a path_name
    longer than cnc_create_sr_policy's 64 characters are refused before the dry run —
    not discovered after the policy was created."""
    routes = mock_sr_policy_creation()
    mcp = await writes(make_settings)
    with pytest.raises(ToolError) as info:
        await call_tool_text(mcp, "cnc_create_sr_policy_e2e", {**SR_ARGS, "wait_seconds": 0})
    assert "wait_seconds" in str(info.value)
    with pytest.raises(ToolError) as info:
        await call_tool_text(mcp, "cnc_create_sr_policy_e2e", {**SR_ARGS, "path_name": "p" * 65})
    assert "path_name" in str(info.value)
    assert not routes["dryrun"].called and not routes["create"].called
    text = await call_tool_text(
        mcp, "cnc_create_sr_policy_e2e", {**SR_ARGS, "wait_seconds": 5, "path_name": "p" * 64}
    )
    assert verdict_of(text) == "CREATED-UP"


@respx.mock
async def test_create_sr_policy_e2e_stops_on_failed_create(make_settings, fake_clock):
    routes = mock_sr_policy_creation()
    routes["create"].mock(return_value=ok(CREATE_DUPLICATE))
    text = await call_tool_text(await writes(make_settings), "cnc_create_sr_policy_e2e", SR_ARGS)
    assert not text.startswith("Error:")
    assert verdict_of(text) == "FAILED"
    assert "Stopped at the create of PE1 -> PE2 color 200: the PCE rejected it." in text
    assert "- create: FAILED — Error: create failed for" in text
    assert not routes["policy"].called and not routes["routes"].called
    assert [c.split("(")[0] for c in audit(text)] == [
        "cnc_dryrun_sr_policy",
        "cnc_create_sr_policy",
    ]


@respx.mock
async def test_create_sr_policy_e2e_failed_dry_run_creates_nothing(make_settings, fake_clock):
    routes = mock_sr_policy_creation()
    routes["dryrun"].mock(
        return_value=ok(
            out(SRP, state="failure", message="No path found for the given constraints. ")
        )
    )
    text = await call_tool_text(await writes(make_settings), "cnc_create_sr_policy_e2e", SR_ARGS)
    assert verdict_of(text) == "FAILED"
    assert "Stopped at the dry run; no policy was created" in text
    assert not routes["create"].called


@respx.mock
async def test_create_sr_policy_e2e_not_up_and_json_shape(make_settings, fake_clock):
    routes = mock_sr_policy_creation(oper="DOWN")
    routes["routes"].mock(return_value=httpx.Response(500))
    text = await call_tool_text(
        await writes(make_settings), "cnc_create_sr_policy_e2e", {**SR_ARGS, "wait_seconds": 6}
    )
    assert not text.startswith("Error:")
    assert verdict_of(text) == "CREATED-NOT-UP"
    assert "- oper-state: not UP within 6 s — SR policy" in text
    assert "- route: unavailable — Error:" in text
    payload = json.loads(
        await call_tool_text(
            await writes(make_settings),
            "cnc_create_sr_policy_e2e",
            {**SR_ARGS, "wait_seconds": 6, "response_format": "json"},
        )
    )
    assert payload["verdict"]["status"] == "created-not-up"
    assert payload["sections"]["routes"]["status"] == "unavailable"
    assert payload["sections"]["dry_run"]["data"]["state"] == "success"
    assert [c["tool"] for c in payload["calls"]] == [
        "cnc_dryrun_sr_policy",
        "cnc_create_sr_policy",
        "cnc_wait_for_sr_policy_oper_state",
        "cnc_get_sr_policy_routes",
    ]


async def test_composer_turns_a_rejected_argument_value_into_a_failed_call(make_settings):
    """A sibling rejecting an argument VALUE (schema validation raises the SDK's
    ToolError) is a failed sub-call — 'Error: <tool>: ...' — never an exception out of
    the composite, and nothing is sent."""
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(ALARMS_QUERY).mock(return_value=ok({"state": "Success", "alarms": []}))
        composer = Composer(await reads(make_settings))
        call = await composer.call("cnc_search_alarms", limit=0, response_format="json")
        assert not call.ok and call.data is None
        assert call.error is not None and call.error.startswith("Error: cnc_search_alarms:")
        assert "limit" in call.error and "greater than or equal to 1" in call.error
        assert call.audit() == "cnc_search_alarms(limit=0, response_format='json') -> error"
        assert not route.called
        good = await composer.call("cnc_search_alarms", limit=1, response_format="json")
        assert good.ok and route.called
        assert [c.ok for c in composer.calls] == [False, True]


# --- drift guard ----------------------------------------------------------------------------


async def test_every_forwarded_argument_exists_on_the_sibling_schema(make_settings):
    """The parameter names the composites forward must exist on the siblings' input
    schemas — the test that keeps composites from drifting when a sibling changes."""
    tools = {t.name: t for t in await (await writes(make_settings)).list_tools()}
    assert set(SIBLING_CALLS) == set(COMPOSITE_TOOLS)
    for composite_name, siblings in SIBLING_CALLS.items():
        assert siblings, composite_name
        for sibling, arguments in siblings.items():
            assert sibling in tools, f"{composite_name} calls unknown tool {sibling}"
            accepted = set(tools[sibling].input_schema.get("properties", {}))
            unknown = arguments - accepted
            assert not unknown, (
                f"{composite_name} -> {sibling}: {sorted(unknown)} not in {sorted(accepted)}"
            )
            required = set(tools[sibling].input_schema.get("required") or [])
            missing = required - arguments
            assert not missing, (
                f"{composite_name} -> {sibling}: required {sorted(missing)} never sent"
            )


# Composite parameters forwarded to a sibling under ANOTHER name (same-named ones are
# matched automatically below).
FORWARDED_AS = {
    ("cnc_provision_l3vpn_e2e", "wait_seconds"): ("cnc_wait_for_service_plan", "timeout_seconds"),
    ("cnc_create_sr_policy_e2e", "wait_seconds"): (
        "cnc_wait_for_sr_policy_oper_state",
        "timeout_seconds",
    ),
}
BOUND_KEYS = ("minimum", "maximum", "maxLength")


def schema_bounds(prop: dict[str, Any]) -> dict[str, Any]:
    """The numeric / length bounds of one property (an Optional's non-null branch)."""
    for alternative in prop.get("anyOf") or []:
        if alternative.get("type") != "null":
            prop = {**prop, **alternative}
            break
    return {k: prop[k] for k in BOUND_KEYS if k in prop}


async def test_every_forwarded_argument_is_at_least_as_constrained_as_the_sibling(
    make_settings,
):
    """A composite parameter whose value is passed on to a sibling must not accept a
    value the sibling's schema rejects: the sibling's validation error would surface
    mid-playbook — after a commit, for the write composites — as a failed step. Checks
    minimum / maximum / maxLength for every composite parameter that shares a forwarded
    sibling argument's name, plus the renamed ones in FORWARDED_AS (minLength is not
    compared: the composites' optional selectors default to '' and are checked in code)."""
    tools = {t.name: t for t in await (await writes(make_settings)).list_tools()}
    checked = 0
    for composite_name, siblings in SIBLING_CALLS.items():
        own = tools[composite_name].input_schema.get("properties", {})
        for sibling, arguments in siblings.items():
            theirs = tools[sibling].input_schema.get("properties", {})
            pairs = [(a, a) for a in arguments if a in own]
            pairs += [
                (mine, arg)
                for (comp, mine), (sib, arg) in FORWARDED_AS.items()
                if comp == composite_name and sib == sibling
            ]
            for mine, theirs_name in pairs:
                assert theirs_name in theirs, (composite_name, mine, sibling, theirs_name)
                mine_bounds = schema_bounds(own[mine])
                their_bounds = schema_bounds(theirs[theirs_name])
                for key, limit in their_bounds.items():
                    assert key in mine_bounds, (
                        f"{composite_name}.{mine} has no {key} but {sibling}.{theirs_name} "
                        f"has {key}={limit}"
                    )
                    ok_bound = (
                        mine_bounds[key] >= limit if key == "minimum" else mine_bounds[key] <= limit
                    )
                    assert ok_bound, (
                        f"{composite_name}.{mine} {key}={mine_bounds[key]} is looser than "
                        f"{sibling}.{theirs_name} {key}={limit}"
                    )
                checked += 1
    assert checked >= len(FORWARDED_AS) + 20  # the same-name pairs are the bulk of it


@respx.mock
async def test_every_sub_call_made_is_declared_in_sibling_calls(make_settings, fake_clock):
    """The other direction of the drift guard: run every composite and check that each
    sub-call it makes is declared in SIBLING_CALLS with exactly the arguments sent."""

    def check(composite_name: str, text: str) -> None:
        payload = json.loads(text)
        declared = SIBLING_CALLS[composite_name]
        assert payload["calls"], composite_name
        for call in payload["calls"]:
            assert call["tool"] in declared, f"{composite_name}: undeclared sub-call {call['tool']}"
            extra = set(call["arguments"]) - declared[call["tool"]]
            assert not extra, (
                f"{composite_name} -> {call['tool']}: undeclared arguments {sorted(extra)}"
            )
        # Every sub-call answered: a value the sibling rejects (its schema, its own
        # validation) shows up here as ok=false with the sibling's error text.
        failed = [c for c in payload["calls"] if not c["ok"]]
        assert not failed, f"{composite_name}: sub-calls failed: {failed}"
        assert payload["verdict"]["missing"] == [], composite_name

    mock_investigation(alarms=(INFO_ALARM,))
    mcp = await writes(make_settings)
    check(
        "cnc_investigate_device",
        await call_tool_text(
            mcp, "cnc_investigate_device", {"host_name": "PE1", "response_format": "json"}
        ),
    )
    respx.reset()
    mock_health_report()
    check(
        "cnc_network_health_report",
        await call_tool_text(mcp, "cnc_network_health_report", {"response_format": "json"}),
    )
    respx.reset()
    mock_policy(nbi_policy(flag_c=0))
    check(
        "cnc_explain_sr_policy",
        await call_tool_text(
            mcp,
            "cnc_explain_sr_policy",
            {"headend": "PE1", "endpoint": "PE2", "color": 100, "response_format": "json"},
        ),
    )
    respx.reset()
    mock_alarms(PE10_ALARM, STALE_ALARM)
    respx.get(CLUSTER_SUMMARY_URL).mock(return_value=ok(CLUSTER_SUMMARY))
    respx.get(INFRA_SUMMARY_URL).mock(return_value=ok(INFRA_SUMMARY))
    respx.get(APP_HEALTH_URL).mock(return_value=ok(APP_HEALTH))
    mock_microservices({"capp-cwm-solutions": [MS_HEALTHY]})
    respx.get(RTM_ALARMS).mock(return_value=ok(EMPTY_RTM))
    check(
        "cnc_alarm_triage",
        await call_tool_text(
            mcp, "cnc_alarm_triage", {"include_cleared": True, "response_format": "json"}
        ),
    )
    respx.reset()
    mock_service()
    respx.post(f"{CAT_RPC}:get-all-services").mock(
        return_value=ok(all_services(service_info(VPN_ID, L3VPN_QNAME, L3VPN_PATH)))
    )
    check(
        "cnc_explain_service",
        await call_tool_text(
            mcp, "cnc_explain_service", {"vpn_id": VPN_ID, "response_format": "json"}
        ),
    )
    check(
        "cnc_explain_service",
        await call_tool_text(
            mcp, "cnc_explain_service", {"name": VPN_ID, "response_format": "json"}
        ),
    )
    respx.reset()
    mock_readiness()
    check(
        "cnc_srv6_readiness",
        await call_tool_text(mcp, "cnc_srv6_readiness", {"response_format": "json"}),
    )
    respx.reset()
    mock_provisioning()
    check(
        "cnc_provision_l3vpn_e2e",
        await call_tool_text(
            mcp, "cnc_provision_l3vpn_e2e", {**L3VPN_ARGS, "response_format": "json"}
        ),
    )
    check(
        "cnc_provision_l3vpn_e2e",
        await call_tool_text(
            mcp,
            "cnc_provision_l3vpn_e2e",
            {**L3VPN_ARGS, "srv6_locator": "LOC1", "response_format": "json"},
        ),
    )
    respx.reset()
    mock_sr_policy_creation()
    check(
        "cnc_create_sr_policy_e2e",
        await call_tool_text(
            mcp, "cnc_create_sr_policy_e2e", {**SR_ARGS, "response_format": "json"}
        ),
    )


# --- dry_run on the write composites --------------------------------------------------------


@respx.mock
async def test_provision_l3vpn_e2e_dry_run_stops_after_the_dry_run(make_settings, fake_clock):
    routes = mock_provisioning()
    mcp = await writes(make_settings)
    text = await call_tool_text(mcp, "cnc_provision_l3vpn_e2e", {**L3VPN_ARGS, "dry_run": True})
    assert not text.startswith("Error:")
    assert verdict_of(text) == "DRY-RUN"
    assert (
        f"Dry run only for '{VPN_ID}': the device CLI NSO would push is rendered below; "
        "nothing was committed. Call again with dry_run=false to provision it." in text
    )
    assert "- dry run: ok (CLI rendered below, nothing committed)" in text
    assert "- commit: not attempted (dry_run=true)" in text
    assert "Dry run only — nothing was committed" in text and "vrf doc-l3vpn-1" in text
    assert "Commit (NSO): skipped — dry_run=true" in text
    assert "Service plan convergence: skipped — dry_run=true" in text
    assert "OAM trace route: skipped — dry_run=true" in text
    # Exactly one sub-call, the ?dry-run=native PUT; nothing after it ran.
    assert routes["put"].call_count == 1
    assert routes["put"].calls[0].request.url.params.get("dry-run") == "native"
    for name in ("nano_plan", "plan_data", "health", "start", "trace"):
        assert not routes[name].called, name
    calls = audit(text)
    assert len(calls) == 1 and calls[0].endswith("dry_run=True) -> ok")
    payload = json.loads(
        await call_tool_text(
            mcp,
            "cnc_provision_l3vpn_e2e",
            {**L3VPN_ARGS, "dry_run": True, "trace": False, "response_format": "json"},
        )
    )
    assert payload["verdict"]["status"] == "dry-run"
    assert payload["verdict"]["reasons"] == [
        "dry run: ok (CLI rendered below, nothing committed)",
        "commit: not attempted (dry_run=true)",
    ]
    assert payload["sections"]["dry_run"]["status"] == "ok"
    assert payload["sections"]["dry_run"]["text"].startswith("Dry run only")
    assert payload["sections"]["commit"] == {
        "title": "Commit (NSO)",
        "tool": "cnc_create_l3vpn_service",
        "status": "skipped",
        "summary": [],
        "error": "dry_run=true",
    }
    assert payload["sections"]["trace"]["error"] == "trace=false"
    assert [c["tool"] for c in payload["calls"]] == ["cnc_create_l3vpn_service"]
    assert payload["calls"][0]["arguments"]["dry_run"] is True
    assert routes["put"].call_count == 2


@respx.mock
async def test_create_sr_policy_e2e_dry_run_stops_after_the_dry_run(make_settings, fake_clock):
    routes = mock_sr_policy_creation()
    mcp = await writes(make_settings)
    text = await call_tool_text(mcp, "cnc_create_sr_policy_e2e", {**SR_ARGS, "dry_run": True})
    assert not text.startswith("Error:")
    assert verdict_of(text) == "DRY-RUN"
    assert (
        "Dry run only for PE1 -> PE2 color 200: the route the PCE would compute is shown "
        "below; no policy was created. Call again with dry_run=false to create it." in text
    )
    assert "- dry run: success" in text and "- create: not attempted (dry_run=true)" in text
    assert "- route: PE1 GigabitEthernet0/0/0/0 -> P1 GigabitEthernet0/0/0/1" in text
    assert "Create (PCE-initiated): skipped — dry_run=true" in text
    assert "Oper-state convergence: skipped — dry_run=true" in text
    assert "Computed route: skipped — dry_run=true" in text
    assert routes["dryrun"].called
    for name in ("create", "policy", "routes"):
        assert not routes[name].called, name
    assert [c.split("(")[0] for c in audit(text)] == ["cnc_dryrun_sr_policy"]
    payload = json.loads(
        await call_tool_text(
            mcp, "cnc_create_sr_policy_e2e", {**SR_ARGS, "dry_run": True, "response_format": "json"}
        )
    )
    assert payload["verdict"]["status"] == "dry-run"
    assert payload["sections"]["dry_run"]["data"]["state"] == "success"
    assert payload["sections"]["create"]["status"] == "skipped"
    assert payload["sections"]["create"]["error"] == "dry_run=true"
    assert [c["tool"] for c in payload["calls"]] == ["cnc_dryrun_sr_policy"]
    assert not routes["create"].called


@respx.mock
async def test_create_sr_policy_e2e_dry_run_failed_dry_run_is_still_failed(
    make_settings, fake_clock
):
    routes = mock_sr_policy_creation()
    routes["dryrun"].mock(
        return_value=ok(
            out(SRP, state="failure", message="No path found for the given constraints. ")
        )
    )
    text = await call_tool_text(
        await writes(make_settings), "cnc_create_sr_policy_e2e", {**SR_ARGS, "dry_run": True}
    )
    assert verdict_of(text) == "FAILED"
    assert "Stopped at the dry run; no policy was created" in text
    assert not routes["create"].called


@respx.mock
async def test_global_dry_run_mode_forces_the_playbooks_to_preview(make_settings, fake_clock):
    """With CNC_MCP_DRY_RUN=true the playbooks are called WITHOUT dry_run and still never
    reach their commit stage: the wrapper forces dry_run=true on the playbook itself."""
    routes = mock_provisioning()
    mcp = await build(make_settings(max_retries=0, enable_writes=True, dry_run=True))
    text = await call_tool_text(mcp, "cnc_provision_l3vpn_e2e", {**L3VPN_ARGS, "dry_run": False})
    assert text.startswith(
        "DRY-RUN MODE (CNC_MCP_DRY_RUN=true): nothing was committed — the answer below is the "
        f"preview.\n\n# L3VPN provisioning: {VPN_ID}"
    )
    assert verdict_of(text) == "DRY-RUN"
    # The headline names the real next step: under the server-wide mode "dry_run=false"
    # would be forced back to true, so it points at the variable instead.
    assert "nothing can be committed until the operator unsets it; then call again" in text
    assert "Call again with dry_run=false" not in text
    assert routes["put"].call_count == 1
    assert routes["put"].calls[0].request.url.params.get("dry-run") == "native"
    for name in ("nano_plan", "plan_data", "health", "start", "trace"):
        assert not routes[name].called, name
    # The sibling's own answer inside the section carries the banner too (it ran through
    # its own wrapper), and the audit shows the one forced call.
    assert text.count("DRY-RUN MODE (CNC_MCP_DRY_RUN=true)") == 2
    assert audit(text) == [audit(text)[0]] and audit(text)[0].endswith("dry_run=True) -> ok")
    # A JSON answer is not banner-prefixed (it must stay parseable).
    payload = json.loads(
        await call_tool_text(
            mcp, "cnc_provision_l3vpn_e2e", {**L3VPN_ARGS, "response_format": "json"}
        )
    )
    assert payload["verdict"]["status"] == "dry-run"
    assert [c["tool"] for c in payload["calls"]] == ["cnc_create_l3vpn_service"]
    assert all(c.request.url.params.get("dry-run") == "native" for c in routes["put"].calls)
    respx.reset()
    routes = mock_sr_policy_creation()
    text = await call_tool_text(mcp, "cnc_create_sr_policy_e2e", SR_ARGS)
    assert text.startswith("DRY-RUN MODE (CNC_MCP_DRY_RUN=true)")
    assert verdict_of(text) == "DRY-RUN"
    assert "until the operator unsets it; then call again to create it." in text
    assert routes["dryrun"].called and not routes["create"].called
    tools = {t.name: t for t in await mcp.list_tools()}
    for name in WRITE_COMPOSITES:
        assert tools[name].description.endswith(
            "DRY-RUN MODE is active on this server: dry_run is forced to true — the tool only "
            "previews; nothing is committed."
        ), name


# --- registration needs the write siblings --------------------------------------------------


async def test_write_siblings_are_the_write_tools_the_playbooks_call(make_settings):
    """WRITE_SIBLINGS (what a playbook's registration requires) is the write sibling
    that commits; OPTIONAL_WRITE_SIBLINGS the writes it can skip with a note (the L3VPN
    trace). Together they are exactly the siblings in SIBLING_CALLS that are write
    tools, and the commit sibling is always required."""
    tools = {t.name: t for t in await (await writes(make_settings)).list_tools()}
    assert set(WRITE_SIBLINGS) == set(WRITE_COMPOSITES) == set(OPTIONAL_WRITE_SIBLINGS)
    for composite_name in WRITE_COMPOSITES:
        required = set(WRITE_SIBLINGS[composite_name])
        optional = set(OPTIONAL_WRITE_SIBLINGS[composite_name])
        write_siblings = {
            sibling
            for sibling in SIBLING_CALLS[composite_name]
            if tools[sibling].annotations.read_only_hint is False
        }
        assert required and not (required & optional), composite_name
        assert required | optional == write_siblings, composite_name
        assert required <= write_siblings, composite_name
    assert WRITE_SIBLINGS["cnc_provision_l3vpn_e2e"] == ("cnc_create_l3vpn_service",)
    assert OPTIONAL_WRITE_SIBLINGS["cnc_provision_l3vpn_e2e"] == ("cnc_start_oam_trace_route",)
    assert WRITE_SIBLINGS["cnc_create_sr_policy_e2e"] == ("cnc_create_sr_policy",)


async def test_write_playbooks_are_skipped_when_a_write_sibling_is_not_registered(
    make_settings, caplog
):
    with caplog.at_level(logging.INFO, logger="cnc_mcp.safety"):
        mcp = build_server(make_settings(enable_writes=True, write_areas="composite"))
    names = {t.name for t in await mcp.list_tools()}
    assert set(COMPOSITE_TOOLS) - set(WRITE_COMPOSITES) <= names
    assert not (set(WRITE_COMPOSITES) & names)
    assert (
        "Tool cnc_provision_l3vpn_e2e not registered (needs cnc_create_l3vpn_service "
        "(area service_provisioning))" in caplog.text
    )
    assert (
        "Tool cnc_create_sr_policy_e2e not registered (needs cnc_create_sr_policy "
        "(area sr_te_operations))" in caplog.text
    )
    # The L3VPN playbook needs its commit sibling's area only (the OAM trace is optional:
    # an operator keeping OAM writes off still gets the playbook); the SR one its own.
    mcp = build_server(
        make_settings(enable_writes=True, write_areas="composite, service_provisioning, oam")
    )
    names = {t.name for t in await mcp.list_tools()}
    assert "cnc_provision_l3vpn_e2e" in names and "cnc_create_sr_policy_e2e" not in names
    mcp = build_server(
        make_settings(enable_writes=True, write_areas="composite, service_provisioning")
    )
    names = {t.name for t in await mcp.list_tools()}
    assert "cnc_provision_l3vpn_e2e" in names and "cnc_start_oam_trace_route" not in names
    mcp = build_server(make_settings(enable_writes=True, write_areas="composite, oam"))
    assert "cnc_provision_l3vpn_e2e" not in {t.name for t in await mcp.list_tools()}
    mcp = build_server(make_settings(enable_writes=True, write_areas="composite,sr_te_operations"))
    names = {t.name for t in await mcp.list_tools()}
    assert "cnc_create_sr_policy_e2e" in names and "cnc_provision_l3vpn_e2e" not in names
    # A disabled write sibling has the same effect.
    mcp = build_server(make_settings(enable_writes=True, disabled_tools="cnc_create_sr_policy"))
    names = {t.name for t in await mcp.list_tools()}
    assert "cnc_create_sr_policy_e2e" not in names and "cnc_provision_l3vpn_e2e" in names


# --- SRv6: cnc_srv6_readiness, the SRv6 branches of the other playbooks ---------------------
#
# The SRv6 topology / policy members are the 7.2 document's shapes in RFC 7951 wire spelling
# (the list that enters the srv6 module prefixed, its children bare) — never observed live:
# the lab is SR-MPLS only (verified 2026-09-15, where cnc_srv6_readiness answered NONE).

POLICIES_URL = f"{BASE_URL}/crosswork/performance/v1/policies"
SRV6_NODE_SID = "cisco-crosswork-srv6-topology-state:srv6-node-sid"
SRV6_ADJ_SID = "cisco-crosswork-srv6-topology-state:srv6-adjacency-sid"
ISIS_NODE = "cisco-crosswork-isis-topology:isis-node-attributes"
ISIS_LINK_ATTRS = "cisco-crosswork-isis-topology:isis-link-attributes"
L3_LINK = "ietf-l3-unicast-topology-state:l3-link-attributes"
IPV6_ROUTER_ID = "cisco-crosswork-l3-te-topology:ipv6-router-id"
SRV6_NETWORK_TYPES = {
    "ietf-l3-unicast-topology-state:l3-unicast-topology": {
        "ietf-sr-mpls-topology-state:sr-mpls": {},
        "cisco-crosswork-srv6-topology-state:srv6": {},
    }
}
SID_STRUCTURE = {"lb-length": 32, "ln-length": 16, "func-length": 16, "arg-length": 0}


def pm_policy(policy_id: int, template: str, schema: str, name: str) -> dict:
    """A GET policies entry in the verified shape (tests/test_tools_performance.py)."""
    return {
        "monitoringPolicy": {
            "id": policy_id,
            "policyTemplate": template,
            "name": name,
            "description": "",
            "schemasInterval": {schema: 300},
            "devices": "",
            "deviceGroups": "",
            "portGroups": "",
            "tag": "",
            "thresholds": {},
            "active": True,
            "creationTimestamp": 1789171200000,
            "lastChangedTimestamp": 1789171200000,
        },
        "policyCollectionStatus": "OK",
    }


PM_POLICIES = [
    pm_policy(2, "SRPOLICY", "SRPOLICY", "Default LSP traffic"),
    pm_policy(1, "INTERFACE", "CEPMINTERFACE", "Default interface health"),
]
PM_POLICY_SRV6 = pm_policy(7, SRV6_PM_TEMPLATE, SRV6_PM_TEMPLATE, "Locator traffic")


def xr(record: dict, software_type: str = "IOS XR") -> dict:
    """The record with the inventory's software family (product_info.software_type "IOS XR"
    on every lab router, verified live 2026-09-15)."""
    return {
        **record,
        "product_info": {
            **record["product_info"],
            "software_type": software_type,
            "product_family": "Cisco XR Routers" if "XR" in software_type else "Other",
        },
    }


XR_PE1, XR_PE2, XR_P1 = xr(PE1), xr(PE2), xr(P1)


def srv6_node(node_id: str, index: int, *, sids: bool = True, pcep: bool = False) -> dict:
    """An SR-MPLS node that also advertises an SRv6 node SID (uN, uSID F3216) under its IS-IS
    instance and carries an IPv6 TE router-id — or, with sids=False, the SR-MPLS-only node
    with the IPv6 router-id but no srv6-node-sid (a locator not yet configured)."""
    node = sr_node(node_id, index, pcep=pcep)
    isis: dict[str, Any] = {"level": "level-2", "system-id": f"0000.0000.000{index}"}
    if sids:
        isis[SRV6_NODE_SID] = [
            {
                "sid": f"fc00:0:{index}::",
                "endpoint-behavior": "uN",
                "algorithm": 0,
                "srv6-sid-structure": SID_STRUCTURE,
            }
        ]
    node[L3_NODE] = {**node[L3_NODE], ISIS_NODE: [isis], IPV6_ROUTER_ID: [f"2001:db8::{index}"]}
    return node


def srv6_link(src: str, src_if: str, dst: str, dst_if: str, *, endx: bool = True) -> dict:
    link_id = f"{src} : {src_if} : {dst} : {dst_if} : ISIS_IPV4_L2"
    isis: dict[str, Any] = {"level": 2, "net": {"system-id": "0000.0000.0001"}}
    if endx:
        isis[SRV6_ADJ_SID] = [
            {
                "sid": "fc00:0:1:e000::",
                "endpoint-behavior": "uA",
                "protected": False,
                "flags": 0,
                "algorithm": 0,
                "weight": 0,
                "srv6-sid-structure": SID_STRUCTURE,
            }
        ]
    return {
        "link-id": link_id,
        "source": {"source-node": src, "source-tp": src_if},
        "destination": {"dest-node": dst, "dest-tp": dst_if},
        L3_LINK: {"name": link_id, "metric1": "10", ISIS_LINK_ATTRS: isis},
    }


def srv6_network(*, gaps: bool = False) -> dict:
    """A network where every node advertises a locator and every adjacency an End.X SID —
    or, with gaps, P1 without a locator and the P1 -> PE2 direction without End.X."""
    return {
        "network-id": "Default-network",
        "network-types": SRV6_NETWORK_TYPES,
        "node": [
            srv6_node("PE1", 1, pcep=True),
            srv6_node("P1", 2, sids=not gaps),
            srv6_node("PE2", 3, pcep=True),
        ],
        LINK_LIST: [
            srv6_link("PE1", GI0, "P1", GI0),
            srv6_link("P1", GI0, "PE1", GI0),
            srv6_link("P1", GI1, "PE2", GI0, endx=not gaps),
            srv6_link("PE2", GI0, "P1", GI1),
            {
                "link-id": f"PE1 : {GI0} : P1 : {GI0} : ETHERNET",
                "source": {"source-node": "PE1", "source-tp": GI0},
                "destination": {"dest-node": "P1", "dest-tp": GI0},
            },
        ],
    }


def networks_of(network: dict) -> dict:
    return {"ietf-network-state:networks": {"network": [network]}}


# The SRv6 policy of tests/test_tools_te_state.py: IPv6 keys, an srv6-binding-sid, SRv6 hops.
PE1_V6, PE2_V6 = "2001:db8::1", "2001:db8::3"
SRV6_HOP = {
    "type": "IPV6-NODE-SID",
    "local-ip-addr": PE2_V6,
    "srv6-node-sid": {
        "sid": "fc00:0:3::",
        "endpoint-behavior": "uN",
        "algorithm": 0,
        "srv6-sid-structure": SID_STRUCTURE,
    },
}
SRV6_POLICY = {
    "headend": PE1_V6,
    "endpoint": PE2_V6,
    "color": 6001,
    "policy-details": {
        "pcep-info": {"pcep-flag-c": 0},
        "srv6-binding-sid": {
            "sid": "fc00:0:1:1::",
            "endpoint-behavior": "uB6.Insert.Red",
            "srv6-sid-structure": SID_STRUCTURE,
        },
        "path": [
            {
                "optimization-metric": {"metric-type": "IGP-METRIC", "metric-value": 20},
                "segment-list": [{"weight": 1, "hop": [SRV6_HOP]}],
                "preference": 100,
                "oper-state": "UP",
                "constraints": {"sid-algorithm": 0},
                "hop": [SRV6_HOP],
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
SR_POLICIES_MIXED = {
    "cisco-crosswork-segment-routing-policy:sr-policies": {"policy": [nbi_policy(), SRV6_POLICY]}
}


def mock_readiness(
    network: dict = NETWORK,
    *,
    sr_policies: dict = SR_POLICIES,
    pm_policies: list[dict] = PM_POLICIES,
    devices: tuple[dict, ...] = (XR_PE1, XR_PE2, XR_P1),
) -> dict[str, respx.Route]:
    """Every route cnc_srv6_readiness hits: the SR-MPLS-only lab by default."""
    return {
        "networks": respx.get(NETWORKS_URL).mock(return_value=ok(networks_of(network))),
        "sr_policies": respx.get(SR_POLICIES_URL).mock(return_value=ok(sr_policies)),
        "pm_policies": respx.get(POLICIES_URL).mock(return_value=ok(pm_policies)),
        "nodes": mock_nodes(*devices),
    }


@respx.mock
async def test_srv6_readiness_none_on_the_sr_mpls_only_lab(make_settings):
    """The verdict the lab gives today (verified live 2026-09-15): NONE, with the router-side
    instruction, every section read and every router IOS XR."""
    routes = mock_readiness()
    text = await call_tool_text(await reads(make_settings), "cnc_srv6_readiness", {})
    assert not text.startswith("Error:")
    assert verdict_of(text) == "NONE"
    assert (
        "SRv6 readiness NONE — the underlay is SR-MPLS only: configure segment-routing srv6 "
        "locators + IS-IS IPv6 on the routers" in text
    )
    assert "carries the locators, End SIDs and End.X SIDs automatically" in text
    assert (
        "- no SRv6 anywhere in the topology: network-types carries no srv6 presence, 0 of 4 "
        "SR-capable node(s) advertise an srv6-node-sid (no locator to derive), no link "
        "carries an End.X SID" in text
    )
    assert "- 0 SRv6 SR policies (every policy is SR-MPLS)" in text
    assert f"- no {SRV6_PM_TEMPLATE} performance policy (not needed until locators exist)" in text
    assert "- all 3 inventoried router(s) are IOS XR — the family that runs SRv6 here" in text
    assert "cnc_create_performance_policy(template='SRV6LOCATOR')" in text
    # The sections: summary counters, no locator row, per node / per adjacency, policies.
    assert (
        "- network-types srv6 presence: absent (SR-MPLS-capable nodes: 4 — the summary exposes "
        "no sr-mpls network-type flag)" in text
    )
    assert "- 4 node(s), 4 SR-MPLS-capable, 0 SRv6-capable (srv6-node-sid)" in text
    assert "- none: no node advertises an srv6-node-sid, so no locator can be derived" in text
    assert "- PE1: dataplane sr-mpls, 0 SRv6 node SID(s), IPv6 router-id -" in text
    assert "- 1 IGP adjacency(ies) (directed, one per direction) of 1 link(s); 0 carry" in text
    assert f"- without End.X: PE1 : {GI0} : P1 : {GI0} : ISIS_IPV4_L2" in text
    assert "- 0 SRv6 policy(ies) of 1 SR policies" in text
    assert "none of the 2 performance policy(ies) uses the SRV6LOCATOR template" in text
    assert "- 3 device(s), 3 IOS XR (the SRv6-capable family here): P1, PE1, PE2" in text
    calls = audit(text)
    assert [c.split("(")[0] for c in calls] == [
        "cnc_get_topology_summary",
        "cnc_list_srv6_locators",
        "cnc_list_topology_nodes",
        "cnc_list_topology_links",
        "cnc_list_sr_policies",
        "cnc_list_performance_policies",
        "cnc_list_devices",
    ]
    assert all(c.endswith("-> ok") for c in calls), calls
    assert "cnc_list_sr_policies(dataplane='srv6', network='Default-network'" in calls[4]
    assert routes["networks"].called and routes["pm_policies"].called


@respx.mock
async def test_srv6_readiness_ready_with_the_document_shaped_srv6_topology(make_settings):
    mock_readiness(
        srv6_network(), sr_policies=SR_POLICIES_MIXED, pm_policies=[*PM_POLICIES, PM_POLICY_SRV6]
    )
    text = await call_tool_text(await reads(make_settings), "cnc_srv6_readiness", {})
    assert not text.startswith("Error:")
    assert verdict_of(text) == "READY"
    assert (
        "SRv6 readiness READY: 3 node(s) advertise SRv6 locators; every SR-capable IOS XR node "
        "has a locator, every IGP adjacency an End.X SID, a SRV6LOCATOR policy collects." in text
    )
    assert "has not been exercised against a live SRv6 feed yet" in text
    assert "- locators: 3 of 3 SR-capable IOS XR node(s) advertise an SRv6 locator" in text
    assert "- End.X: 4 of 4 IGP adjacency(ies) carry an srv6-adjacency-sid" in text
    assert "- SRv6 SR policies: 1" in text
    assert f"- performance: 1 {SRV6_PM_TEMPLATE} policy(ies)" in text
    # The locator rows come from the sibling (derived: SID masked to block + node bits).
    assert "- PE1: fc00:0:1::/48 format uSID F3216, algorithms 0, behaviors uN, 1 SID(s)" in text
    assert "- network-types srv6 presence: present (SR-MPLS-capable nodes: 3" in text
    assert "- PE1: dataplane both, 1 SRv6 node SID(s) (fc00:0:1::), IPv6 router-id 2001:db8::1" in (
        text
    )
    assert f"- PE1 : {GI0} : P1 : {GI0} : ISIS_IPV4_L2: End.X fc00:0:1:e000::" in text
    assert "- 2001:db8::1 -> 2001:db8::3 color 6001: oper UP, bsid fc00:0:1:1::" in text
    assert "- Locator traffic (id 7): active, collection OK, SRV6LOCATOR every 300 s" in text


@respx.mock
async def test_srv6_readiness_partial_names_the_gaps_and_skips_non_xr_routers(make_settings):
    """P1 has no locator and one direction of P1 <-> PE2 no End.X; there is no SRV6LOCATOR
    policy; PE2 is not IOS XR in the inventory, so it is never counted as missing."""
    mock_readiness(
        srv6_network(gaps=True),
        sr_policies=SR_POLICIES_MIXED,
        devices=(XR_PE1, xr(PE2, "IOS XE"), XR_P1),
    )
    text = await call_tool_text(await reads(make_settings), "cnc_srv6_readiness", {})
    assert verdict_of(text) == "PARTIAL"
    assert (
        "SRv6 readiness PARTIAL: 2 node(s) advertise SRv6 locators; 1 node(s) without a "
        "locator, 1 adjacency(ies) without End.X, SRV6LOCATOR policy missing." in text
    )
    assert (
        "- locators: 1 of 2 SR-capable IOS XR node(s) advertise an SRv6 locator "
        "(srv6-node-sid); missing on P1; not expected on non-XR PE2" in text
    )
    assert (
        "- End.X: 3 of 4 IGP adjacency(ies) carry an srv6-adjacency-sid; missing on "
        f"P1 : {GI1} : PE2 : {GI0} : ISIS_IPV4_L2" in text
    )
    assert (
        f"- performance: 0 {SRV6_PM_TEMPLATE} policy(ies) — missing: "
        f"cnc_create_performance_policy(template='{SRV6_PM_TEMPLATE}', ...)" in text
    )
    assert "- not IOS XR, so not expected to advertise SRv6: PE2 (IOS XE)" in text
    assert "- P1: dataplane sr-mpls, 0 SRv6 node SID(s), IPv6 router-id 2001:db8::2" in text
    assert "- not IOS XR (not expected to advertise SRv6): PE2 (IOS XE)" in text


@respx.mock
async def test_srv6_readiness_partial_failure_json_shape_and_unknown(make_settings):
    routes = mock_readiness()
    routes["pm_policies"].mock(return_value=httpx.Response(500))
    mcp = await reads(make_settings)
    payload = json.loads(
        await call_tool_text(mcp, "cnc_srv6_readiness", {"response_format": "json"})
    )
    assert payload["verdict"]["status"] == "none"
    assert len(payload["verdict"]["missing"]) == 1
    assert payload["verdict"]["missing"][0].startswith("SRV6LOCATOR performance policy (Error:")
    assert "status 500" in payload["verdict"]["missing"][0]
    assert not any("performance policy" in r for r in payload["verdict"]["reasons"])
    assert set(payload["sections"]) == {
        "topology",
        "locators",
        "nodes",
        "links",
        "policies",
        "pm_policy",
        "devices",
    }
    assert payload["sections"]["pm_policy"]["status"] == "unavailable"
    assert payload["sections"]["nodes"]["data"][0] == {
        "name": "PE1",
        "l3": True,
        "sr_mpls": True,
        "srv6_sids": [],
        "ipv6_router_ids": [],
    }
    assert payload["sections"]["links"]["data"] == {
        "adjacencies": 1,
        "with_endx": 0,
        "without_endx": [f"PE1 : {GI0} : P1 : {GI0} : ISIS_IPV4_L2"],
    }
    assert payload["sections"]["topology"]["data"]["srv6_network_type"] is False
    assert [c["tool"] for c in payload["calls"]][:2] == [
        "cnc_get_topology_summary",
        "cnc_list_srv6_locators",
    ]
    # Nothing about the topology readable: unknown, never a guessed NONE.
    routes["networks"].mock(return_value=httpx.Response(500))
    text = await call_tool_text(mcp, "cnc_srv6_readiness", {})
    assert not text.startswith("Error:")
    assert verdict_of(text) == "UNKNOWN"
    assert "neither the topology summary nor the node list could be read" in text
    assert "Topology summary (SR-PCE feed): unavailable — Error:" in text


def test_srv6_readiness_helpers_read_both_prefix_spellings():
    # RFC 7951 wire spelling (prefixed list, bare children) and the document's fully
    # prefixed one both parse; an LLDP-only node has no L3 data.
    wire = srv6_node("PE1", 1)
    facts = node_srv6_facts(wire)
    assert facts == {
        "name": "PE1",
        "l3": True,
        "sr_mpls": True,
        "srv6_sids": ["fc00:0:1::"],
        "ipv6_router_ids": ["2001:db8::1"],
    }
    spec = json.loads(
        json.dumps(wire)
        .replace('"sid"', '"cisco-crosswork-srv6-topology-state:sid"')
        .replace('"endpoint-behavior"', '"cisco-crosswork-srv6-topology-state:endpoint-behavior"')
    )
    assert node_srv6_facts(spec)["srv6_sids"] == ["fc00:0:1::"]
    assert node_srv6_facts({"node-id": "SW1", TP_LIST: [tp(GI0)]}) == {
        "name": "SW1",
        "l3": False,
        "sr_mpls": False,
        "srv6_sids": [],
        "ipv6_router_ids": [],
    }
    link = link_srv6_facts(srv6_link("PE1", GI0, "P1", GI0))
    assert link["l3"] and link["srv6_adj_sids"] == ["fc00:0:1:e000::"]
    bare = link_srv6_facts(srv6_link("PE1", GI0, "P1", GI0, endx=False))
    assert bare["l3"] and bare["srv6_adj_sids"] == []
    # An IS-IS link without l3-link-attributes (the shallow shape) still counts as an
    # adjacency by its id suffix; an Ethernet link never does.
    assert link_srv6_facts(ISIS_LINK)["l3"] is True
    assert link_srv6_facts({"link-id": f"PE1 : {GI0} : P1 : {GI0} : ETHERNET"})["l3"] is False
    assert locator_rows({"count": 1, "items": [{"node": "PE1"}]}) == [{"node": "PE1"}]
    assert locator_rows([{"node": "P1"}]) == [{"node": "P1"}]
    assert locator_rows({"items": []}) == [] and locator_rows("x") == []
    assert is_xr(XR_PE1) and is_xr(xr(PE1, "IOS-XR")) and not is_xr(PE1)
    assert not is_xr(xr(PE1, "IOS XE"))


def test_summary_coverage_helpers():
    """The fallbacks for an unread node / link list: the summary's node_dataplanes counters
    give the exact SR-MPLS-only gap (else sr_capable - srv6_capable, floored at 0); the
    link counts give the non-Ethernet adjacencies against srv6_adjacency_links."""
    counts = {
        "sr_capable_nodes": 3,
        "srv6_capable_nodes": 2,
        "node_dataplanes": {"sr-mpls": 1, "srv6": 0, "both": 2, "none": 4},
        "links": {"total": 5, "isis_ipv4_l2": 4, "ethernet": 1, "other": 0},
        "srv6_adjacency_links": 3,
    }
    assert summary_locator_coverage(counts) == (3, 1)
    assert summary_endx_coverage(counts) == (4, 1)
    # Without node_dataplanes: the difference of the two node counts, never negative
    # (an SRv6-only node has no sr-mpls container).
    assert summary_locator_coverage({"sr_capable_nodes": 3, "srv6_capable_nodes": 2}) == (3, 1)
    assert summary_locator_coverage({"sr_capable_nodes": 1, "srv6_capable_nodes": 2}) == (1, 0)
    assert summary_locator_coverage({"nodes": 3}) is None
    assert summary_locator_coverage(None) is None
    assert summary_endx_coverage({"links": {"isis_ipv4_l2": 2, "other": 1}}) == (3, 3)
    assert summary_endx_coverage({"links": {"total": 5}}) is None
    assert summary_endx_coverage(None) is None


@respx.mock
async def test_srv6_readiness_keeps_a_node_the_inventory_page_lacks_in_the_expected_set(
    make_settings,
):
    """P1 advertises no locator and is absent from the inventory page (a second page, or a
    node never onboarded): its family is UNKNOWN, not non-XR, so it stays expected and the
    verdict is PARTIAL — never a READY that drops it from the count."""
    network = srv6_network()
    network["node"][1] = srv6_node("P1", 2, sids=False)
    mock_readiness(
        network,
        sr_policies=SR_POLICIES_MIXED,
        pm_policies=[*PM_POLICIES, PM_POLICY_SRV6],
        devices=(XR_PE1, XR_PE2),
    )
    text = await call_tool_text(await reads(make_settings), "cnc_srv6_readiness", {})
    assert not text.startswith("Error:")
    assert verdict_of(text) == "PARTIAL"
    assert (
        "SRv6 readiness PARTIAL: 2 node(s) advertise SRv6 locators; 1 node(s) without a "
        "locator, 0 adjacency(ies) without End.X, SRV6LOCATOR policy present." in text
    )
    assert (
        "- locators: 2 of 3 SR-capable IOS XR node(s) advertise an SRv6 locator (srv6-node-sid); "
        "missing on P1; family unknown for P1 (not in the inventory page read), counted as "
        "expected" in text
    )
    assert "not expected on non-XR" not in text
    assert "- all 2 inventoried router(s) are IOS XR — the family that runs SRv6 here" in text
    assert "- 2 device(s), 2 IOS XR (the SRv6-capable family here): PE1, PE2" in text


@respx.mock
async def test_srv6_readiness_never_ready_on_the_summary_alone_when_the_listings_fail(
    make_settings,
):
    """The node and link listings answer 500 while the summary counts gaps (3 SR-capable /
    2 SRv6-capable nodes, 4 IS-IS adjacencies / 3 with End.X): the gaps come from the
    summary's counts and the verdict is PARTIAL; with no gap in the summary it is READY
    but says 'per the summary's counts', never 'every node / adjacency'; with the summary
    unread too the coverage is UNKNOWN and the verdict PARTIAL."""

    routes = mock_readiness(
        sr_policies=SR_POLICIES_MIXED, pm_policies=[*PM_POLICIES, PM_POLICY_SRV6]
    )

    def listings_fail(network: dict, *, fail: set[int]) -> None:
        """The networks GET (1 summary, 2 locators, 3 nodes, 4 links) answers 500 on the
        call numbers in ``fail``."""
        calls = {"n": 0}

        def answer(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] in fail:
                return httpx.Response(500)
            return ok(networks_of(network))

        routes["networks"].mock(side_effect=answer)

    listings_fail(srv6_network(gaps=True), fail={3, 4})  # summary, locators ok; nodes, links 500
    mcp = await reads(make_settings)
    text = await call_tool_text(mcp, "cnc_srv6_readiness", {})
    assert not text.startswith("Error:")
    assert verdict_of(text) == "PARTIAL"
    assert (
        "SRv6 readiness PARTIAL: 2 node(s) advertise SRv6 locators; 1 node(s) without a "
        "locator per the summary, 1 adjacency(ies) without End.X per the summary, "
        "SRV6LOCATOR policy present." in text
    )
    assert (
        "- locators: 2 of 3 SR-capable node(s) advertise an SRv6 locator per the summary's "
        "counts — 1 without one (the node list was unavailable, so they cannot be named and "
        "non-XR routers cannot be excluded)" in text
    )
    assert (
        "- End.X: 3 of 4 IGP adjacency(ies) carry an srv6-adjacency-sid per the summary's "
        "counts — 1 without one (the link list was unavailable, so they cannot be named)" in text
    )
    assert "every SR-capable IOS XR node has a locator" not in text
    assert "every IGP adjacency an End.X SID" not in text
    assert "Per-node SRv6 state (topology nodes): unavailable — Error:" in text
    assert "End.X coverage (topology links): unavailable — Error:" in text
    # No gap in the summary: READY, worded on the counts that were actually read.
    listings_fail(srv6_network(), fail={3, 4})
    text = await call_tool_text(mcp, "cnc_srv6_readiness", {})
    assert verdict_of(text) == "READY"
    assert (
        "SRv6 readiness READY: 3 node(s) advertise SRv6 locators; no SR-capable node without a "
        "locator per the summary's counts (the node list was unavailable), no IGP adjacency "
        "without End.X per the summary's counts (the link list was unavailable), a "
        "SRV6LOCATOR policy collects." in text
    )
    assert "every SR-capable IOS XR node has a locator" not in text
    assert "- locators: 3 of 3 SR-capable node(s) advertise an SRv6 locator per the summary" in (
        text
    )
    # Summary AND listings unread, locator rows present: the coverage is unknown -> PARTIAL.
    listings_fail(srv6_network(), fail={1, 3, 4})
    payload = json.loads(
        await call_tool_text(mcp, "cnc_srv6_readiness", {"response_format": "json"})
    )
    assert payload["verdict"]["status"] == "partial"
    assert (
        "; ? node(s) without a locator (coverage unknown), ? adjacency(ies) without End.X "
        "(coverage unknown), SRV6LOCATOR policy present." in payload["verdict"]["headline"]
    )
    assert any(
        r.startswith("locators: coverage UNKNOWN — 3 node(s) are known to advertise one")
        for r in payload["verdict"]["reasons"]
    )
    assert any(r.startswith("End.X: coverage UNKNOWN") for r in payload["verdict"]["reasons"])
    assert payload["sections"]["topology"]["status"] == "unavailable"
    assert payload["sections"]["locators"]["status"] == "ok"
    # The link listing alone showing End.X SIDs (summary unread, no node SID / policy /
    # locator row) is SRv6 evidence: never NONE with 'no link carries an End.X SID'.
    network = srv6_network()
    for node in network["node"]:
        node[L3_NODE][ISIS_NODE][0].pop(SRV6_NODE_SID, None)
    routes["sr_policies"].mock(return_value=ok(SR_POLICIES))  # every policy SR-MPLS
    listings_fail(network, fail={1})
    text = await call_tool_text(mcp, "cnc_srv6_readiness", {})
    assert verdict_of(text) == "PARTIAL"
    assert "no link carries an End.X SID" not in text
    assert "SRv6 readiness PARTIAL: 0 node(s) advertise SRv6 locators; 3 node(s) without" in text
    assert "- End.X: 4 of 4 IGP adjacency(ies) carry an srv6-adjacency-sid" in text


@respx.mock
async def test_srv6_readiness_notes_every_first_page_only_check(make_settings):
    """More than one page of topology nodes, links and inventory devices: each section and
    the notes say only the first page was checked, and a topology node absent from the
    inventory page is 'family unknown', still expected."""
    network = srv6_network()
    network["node"].extend({"node-id": f"SW{i}", TP_LIST: [tp(GI0)]} for i in range(498))
    network[LINK_LIST].extend(
        {
            "link-id": f"SW{i} : {GI0} : SW{i + 1} : {GI0} : ETHERNET",
            "source": {"source-node": f"SW{i}", "source-tp": GI0},
            "destination": {"dest-node": f"SW{i + 1}", "dest-tp": GI0},
        }
        for i in range(497)
    )
    routes = mock_readiness(
        network, sr_policies=SR_POLICIES_MIXED, pm_policies=[*PM_POLICIES, PM_POLICY_SRV6]
    )
    routes["nodes"].mock(
        return_value=ok({"data": [XR_PE1, XR_PE2], "result_count": 150, "total_count": 150})
    )
    text = await call_tool_text(await reads(make_settings), "cnc_srv6_readiness", {})
    assert not text.startswith("Error:")
    assert verdict_of(text) == "READY"
    assert "- more than 500 nodes: only the first page was checked" in text
    assert "- more than 500 links: only the first page was checked" in text
    assert (
        "- more than 100 devices: only the first page was checked (a topology node absent "
        "from it has an unknown family)" in text
    )
    assert (
        "- only the first 500 topology nodes were checked (cnc_list_topology_nodes page=1, ...)"
        in text
    )
    assert (
        "- only the first 500 topology links were checked (cnc_list_topology_links page=1, ...)"
        in text
    )
    assert (
        "- only the first 100 inventory devices were checked for their family (cnc_list_devices "
        "page=1, ...); a topology node absent from that page has an unknown family and is "
        "counted as expected to advertise SRv6" in text
    )
    assert (
        "- locators: 3 of 3 SR-capable IOS XR node(s) advertise an SRv6 locator (srv6-node-sid); "
        "family unknown for P1 (not in the inventory page read — only the first page was), "
        "counted as expected" in text
    )


@respx.mock
async def test_provision_l3vpn_e2e_srv6_locator_dry_run_renders_the_block(
    make_settings, fake_clock
):
    """srv6_locator is forwarded to the create tool (verified by NSO dry run 2026-09-15:
    the CLI gains 'segment-routing srv6 / locator <name> / alloc mode per-vrf' per PE)
    and the dry-run step counts the rendered blocks; nothing is committed."""
    routes = mock_provisioning()
    srv6_cli = (
        L3VPN_CLI + "router bgp 65000\n vrf doc-l3vpn-1\n  rd 65091:91\n  address-family "
        "ipv4 unicast\n   segment-routing srv6\n    locator LOC1\n    alloc mode per-vrf\n"
        "   exit\n  exit\n exit\nexit\n"
    )

    def put(request: httpx.Request) -> httpx.Response:
        assert request.url.params.get("dry-run") == "native"
        body = json.loads(request.content)["ietf-l3vpn-ntw:vpn-service"][0]
        profile = body["vpn-instance-profiles"]["vpn-instance-profile"][0]
        assert profile["cisco-l3vpn-ntw:srv6"] == {
            "address-family": [{"name": "ietf-vpn-common:ipv4", "locator-name": "LOC1"}]
        }
        return httpx.Response(
            201,
            json={
                "dry-run-result": {
                    "native": {
                        "device": [
                            {"name": "PE1", "data": srv6_cli},
                            {"name": "PE2", "data": srv6_cli},
                        ]
                    }
                }
            },
        )

    routes["put"].mock(side_effect=put)
    mcp = await writes(make_settings)
    text = await call_tool_text(
        mcp, "cnc_provision_l3vpn_e2e", {**L3VPN_ARGS, "srv6_locator": "LOC1", "dry_run": True}
    )
    assert not text.startswith("Error:")
    assert verdict_of(text) == "DRY-RUN"
    assert (
        f"Dry run only for '{VPN_ID}' (SRv6 transport, locator LOC1): the device CLI NSO would "
        "push is rendered below; nothing was committed." in text
    )
    assert (
        "- dry run: ok (CLI rendered below, nothing committed); SRv6: 'segment-routing srv6 / "
        "alloc mode per-vrf' rendered 2 time(s), locator LOC1" in text
    )
    assert "    locator LOC1\n" in text
    assert routes["put"].call_count == 1
    for name in ("nano_plan", "plan_data", "health", "start", "trace"):
        assert not routes[name].called, name
    calls = audit(text)
    assert len(calls) == 1 and calls[0].endswith(
        "profile_id='p1', srv6_locator='LOC1', dry_run=True) -> ok"
    )
    # The MPLS rendering of the same playbook is untouched: no srv6_locator on the wire,
    # no transport in the headline.
    respx.reset()
    routes = mock_provisioning()
    text = await call_tool_text(mcp, "cnc_provision_l3vpn_e2e", {**L3VPN_ARGS, "dry_run": True})
    assert f"Dry run only for '{VPN_ID}': the device CLI" in text
    assert "srv6_locator" not in text and "SRv6" not in text
    body = json.loads(routes["put"].calls[0].request.content)["ietf-l3vpn-ntw:vpn-service"][0]
    assert "cisco-l3vpn-ntw:srv6" not in json.dumps(body)


@respx.mock
async def test_provision_l3vpn_e2e_srv6_notes_a_missing_block_and_skips_the_oam_trace(
    make_settings, fake_clock
):
    """The dry run's CLI carries no srv6 block although srv6_locator was given -> a note
    (do not commit); and the committed path never runs the MPLS-only OAM trace for an
    SRv6 VPN — the step and the headline say why."""
    routes = mock_provisioning()  # the plain MPLS CLI: no 'segment-routing srv6' block
    mcp = await writes(make_settings)
    text = await call_tool_text(
        mcp, "cnc_provision_l3vpn_e2e", {**L3VPN_ARGS, "srv6_locator": "LOC1", "dry_run": True}
    )
    assert verdict_of(text) == "DRY-RUN"
    assert "SRv6: NO 'segment-routing srv6' block in the rendered CLI" in text
    assert (
        "- srv6_locator 'LOC1' was given but the dry-run CLI carries no 'segment-routing srv6' "
        "block" in text
    )
    text = await call_tool_text(
        mcp, "cnc_provision_l3vpn_e2e", {**L3VPN_ARGS, "srv6_locator": "LOC1"}
    )
    assert not text.startswith("Error:")
    assert verdict_of(text) == "DEPLOYED"
    assert (
        f"L3VPN '{VPN_ID}' deployed (SRv6 transport, locator LOC1): committed by NSO, plan "
        "completed, oper-status op-up, trace skipped (MPLS OAM only — no SRv6 trace on 7.2)."
        in text
    )
    assert f"- trace: skipped — {OAM_MPLS_ONLY}" in text
    assert f"OAM trace route: skipped — {OAM_MPLS_ONLY}" in text
    assert "cnc_get_srv6_locator_statistics once an SRV6LOCATOR performance policy" in text
    assert not routes["start"].called and not routes["trace"].called
    assert routes["put"].call_count == 3  # the dry-run call above, then dry run + commit
    assert [c.request.url.params.get("dry-run") for c in routes["put"].calls] == [
        "native",
        "native",
        None,
    ]
    calls = audit(text)
    assert not any(c.startswith(("cnc_get_device(", "cnc_start_oam_trace_route(")) for c in calls)
    # A per-endpoint locator alone makes the VPN SRv6 too.
    endpoints = json.loads(L3VPN_ENDPOINTS)
    endpoints[0]["srv6_locator"] = "LOC1"
    payload = json.loads(
        await call_tool_text(
            mcp,
            "cnc_provision_l3vpn_e2e",
            {**L3VPN_ARGS, "endpoints": json.dumps(endpoints), "response_format": "json"},
        )
    )
    assert payload["verdict"]["status"] == "deployed"
    assert payload["sections"]["trace"]["status"] == "skipped"
    assert payload["sections"]["trace"]["error"] == OAM_MPLS_ONLY
    assert "SRv6 transport, locator per endpoint" in payload["verdict"]["headline"]


@respx.mock
async def test_provision_l3vpn_e2e_srv6_notes_the_block_on_fewer_pes_than_endpoints(
    make_settings, fake_clock
):
    """NSO renders the SRv6 block for PE1 only (PE2 has no BGP process, say): the dry-run
    step says 'on 1 of 2 PE(s)' and a NOTE names PE2 and says do not commit."""
    routes = mock_provisioning()
    srv6_cli = (
        L3VPN_CLI + "router bgp 65000\n vrf doc-l3vpn-1\n  address-family ipv4 unicast\n"
        "   segment-routing srv6\n    locator LOC1\n    alloc mode per-vrf\n"
    )
    routes["put"].mock(
        return_value=httpx.Response(
            201,
            json={
                "dry-run-result": {
                    "native": {
                        "device": [
                            {"name": "PE1", "data": srv6_cli},
                            {"name": "PE2", "data": L3VPN_CLI},
                        ]
                    }
                }
            },
        )
    )
    text = await call_tool_text(
        await writes(make_settings),
        "cnc_provision_l3vpn_e2e",
        {**L3VPN_ARGS, "srv6_locator": "LOC1", "dry_run": True},
    )
    assert not text.startswith("Error:")
    assert verdict_of(text) == "DRY-RUN"
    assert (
        "- dry run: ok (CLI rendered below, nothing committed); SRv6: 'segment-routing srv6 / "
        "alloc mode per-vrf' rendered 1 time(s), locator LOC1, on 1 of 2 PE(s)" in text
    )
    assert (
        "- the 'segment-routing srv6' block is rendered on 1 of 2 endpoint PE(s) — missing for "
        "PE2 (no BGP process / local_as on that endpoint, an address-family the profile lacks, "
        "or no CLI rendered for it); do not commit before cnc_create_l3vpn_service(dry_run=true) "
        "shows the block on every PE" in text
    )
    assert routes["put"].call_count == 1


def test_srv6_dry_run_text_and_endpoint_locators():
    cli = "router bgp 1\n vrf x\n  address-family ipv4 unicast\n   segment-routing srv6\n"
    cli += "    locator LOC1\n    alloc mode per-vrf\n"
    suffix, notes = srv6_dry_run_text(cli + cli, "LOC1")
    assert suffix == (
        "; SRv6: 'segment-routing srv6 / alloc mode per-vrf' rendered 2 time(s), locator LOC1"
    )
    assert notes == []
    # Another locator than asked (a per-node override) is a note, not a failure.
    suffix, notes = srv6_dry_run_text(cli, "LOC9")
    assert "locator LOC1" in suffix and len(notes) == 1 and "'LOC9'" in notes[0]
    # No locator line: the router-global locator applies (the verified CFP rendering).
    suffix, notes = srv6_dry_run_text(cli.replace("    locator LOC1\n", ""), "")
    assert "locator (none: the router-global locator applies)" in suffix and notes == []
    suffix, notes = srv6_dry_run_text("vrf x\n", "LOC1")
    assert suffix == "; SRv6: NO 'segment-routing srv6' block in the rendered CLI"
    assert len(notes) == 1 and "do not commit" in notes[0]
    # Per-PE coverage: the create tool's dry-run text has one "### <device>" section per
    # PE; the block on one of two endpoint PEs is a note naming the PE without it.
    two_pe = f"### PE1\n```\n{cli}```\n\n### PE2\n```\nrouter bgp 1\n vrf x\n```"
    assert srv6_devices_with_block(two_pe) == {"PE1"}
    assert srv6_devices_with_block(cli) is None  # a bare CLI: no per-device sections
    suffix, notes = srv6_dry_run_text(two_pe, "LOC1", ["PE1", "PE2"])
    assert suffix.endswith("rendered 1 time(s), locator LOC1, on 1 of 2 PE(s)")
    assert notes == [
        "the 'segment-routing srv6' block is rendered on 1 of 2 endpoint PE(s) — missing for "
        "PE2 (no BGP process / local_as on that endpoint, an address-family the profile "
        "lacks, or no CLI rendered for it); do not commit before "
        "cnc_create_l3vpn_service(dry_run=true) shows the block on every PE"
    ]
    # Both PEs covered: no note, no "on N of M" suffix; a PE the dry run does not render
    # at all (no section) counts as missing too.
    both = f"### PE1\n```\n{cli}```\n\n### PE2\n```\n{cli}```"
    suffix, notes = srv6_dry_run_text(both, "LOC1", ["PE1", "PE2"])
    assert "on 2 of 2" not in suffix and notes == []
    suffix, notes = srv6_dry_run_text(both, "LOC1", ["PE1", "PE2", "PE3"])
    assert "on 2 of 3 PE(s)" in suffix and "missing for PE3" in notes[0]
    # A bare CLI (no sections) falls back to comparing block count with PE count.
    suffix, notes = srv6_dry_run_text(cli, "LOC1", ["PE1", "PE2"])
    assert "on 1 of 2 PE(s)" in suffix and "rendered on 1 of 2 endpoint PE(s) (" in notes[0]
    assert endpoint_locators(json.dumps([{"node": "PE1", "srv6_locator": "LOC1"}]))
    assert not endpoint_locators(L3VPN_ENDPOINTS) and not endpoint_locators("not json")
    # A single endpoint object (cnc_create_l3vpn_service accepts one as a one-entry list)
    # is read like a list, for the locator and for the node names.
    single = json.dumps({"node": "PE1", "interface": "Loopback91", "srv6_locator": "LOC1"})
    assert endpoint_locators(single)
    assert endpoint_nodes(single) == ["PE1"] and first_two_nodes(single) == ["PE1"]
    assert endpoint_nodes(L3VPN_ENDPOINTS) == ["PE1", "PE2"]
    assert endpoint_nodes("not json") == [] and first_two_nodes("[1, 2]") == []


# --- cnc_explain_sr_policy: an SRv6 policy keyed by IPv6 TE router-ids -----------------------

POLICY_SERVICE_V6_PATH = (
    "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/policy=doc-srv6-6001"
)
POLICY_SERVICES_V6 = cat(
    "get-all-services",
    {
        "collection-data": {
            "service-info": [
                {
                    "service-name": "doc-srv6-6001",
                    "service-type": POLICY_QNAME,
                    "yang-path": POLICY_SERVICE_V6_PATH,
                    "plan-yang-path": POLICY_SERVICE_V6_PATH.replace("policy=", "policy-plan="),
                }
            ]
        },
        "collection-header": {"offset": 0, "count": 1},
    },
)
POLICY_SERVICE_V6 = {
    "cisco-sr-te-cfp-sr-policies:policy": [
        {
            "name": "doc-srv6-6001",
            "head-end": [{"name": "PE1"}],
            "tail-end": PE2_V6,
            "color": 6001,
            "srv6": {"locator": {"locator-name": "LOC1"}},
            "path": [{"preference": 100, "dynamic": {"metric-type": "igp", "pce": {}}}],
        }
    ]
}
# NSO's CDB copy of an SRv6 on-box policy: the ipv4 analogue's nesting with end-point ipv6
# and the srv6 / locator container the CFP renders (NED JSON spelling assumed, unverified).
NSO_CONFIG_SRV6 = {
    "tailf-ned-cisco-ios-xr:segment-routing": {
        "traffic-eng": {
            "policy": [
                {
                    "name": "srte_c_6001_ep_2001:db8::3",
                    "srv6": {"locator": {"name": "LOC1", "binding-sid": {"dynamic": {}}}},
                    "color": {"value": 6001, "end-point": {"ipv6": PE2_V6}},
                    "candidate-paths": {
                        "preference": [
                            {"id": 100, "dynamic": {"pcep": {}, "metric": {"type": "igp"}}}
                        ]
                    },
                }
            ],
            "pcc": {"pce": {"address": {"ipv4": [{"address": "10.0.0.5"}]}}},
        }
    }
}


def mock_srv6_policy() -> dict[str, respx.Route]:
    return {
        "networks": respx.get(NETWORKS_URL).mock(return_value=ok(networks_of(srv6_network()))),
        "policy": respx.get(f"{BASE_URL}{sr_policy_url(PE1_V6, PE2_V6, 6001)}").mock(
            return_value=ok(keyed_policy(SRV6_POLICY))
        ),
        "routes": respx.post(rpc(COE, "sr-policy-routes")).mock(return_value=ok(ROUTES_OUT)),
        "metrics": respx.post(rpc(COE, "sr-policy-metrics")).mock(return_value=ok(METRICS_OUT)),
        "pm": respx.get(f"{BASE_URL}{sr_policy_pm_url(PE1_V6, PE2_V6, 6001)}").mock(
            return_value=ok(
                {
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
            )
        ),
        "util": respx.post(f"{NPM}/lsp/utilizations").mock(return_value=ok([])),
        "max_util": respx.post(f"{NPM}/lsp/max/utilization").mock(return_value=ok({})),
        "delay": respx.post(f"{NPM}/lsp/delay").mock(return_value=ok([])),
        "max_delay": respx.post(f"{NPM}/lsp/max/delay").mock(return_value=ok({})),
        "variance": respx.post(f"{NPM}/lsp/delayVariance").mock(return_value=ok([])),
        "loss": respx.post(f"{NPM}/lsp/loss").mock(return_value=ok([])),
        "transport": respx.post(f"{CAT_RPC}:get-associated-services-for-transport").mock(
            return_value=ok({"cat-inventory-rpc:output": {}})
        ),
        "nodes": mock_nodes(PE1, PE2, P1),
        "services": respx.post(f"{CAT_RPC}:get-all-services").mock(
            return_value=ok(POLICY_SERVICES_V6)
        ),
        "service": respx.get(f"{NSO_DATA}/{POLICY_SERVICE_V6_PATH}").mock(
            return_value=ok(POLICY_SERVICE_V6)
        ),
        "onbox": respx.get(NSO_SR_CONFIG_URL).mock(return_value=ok(NSO_CONFIG_SRV6)),
    }


@respx.mock
async def test_explain_sr_policy_srv6_policy_keyed_by_ipv6_router_ids(make_settings):
    """An SRv6 policy (7.2 document shapes, never seen live): IPv6 keys resolve to host
    names through the nodes' ipv6-router-id, the dataplane line says srv6 and why, the
    hop renders its SID and behaviour, the measurements use the IPv6 keys with the
    'unverified' note, the CAT twin and the on-box policy name the locator, and the
    riding-services RPC gets the head-end's host name (its IPv4-only inventory lookup
    would not match an IPv6 key)."""
    routes = mock_srv6_policy()
    text = await call_tool_text(
        await reads(make_settings),
        "cnc_explain_sr_policy",
        {"headend": PE1_V6, "endpoint": PE2_V6, "color": 6001},
    )
    assert not text.startswith("Error:")
    assert verdict_of(text) == "UP"
    assert f"SR policy {PE1_V6} -> {PE2_V6} color 6001 is up." in text
    assert (
        "- dataplane srv6 (SRv6: binding SID / hops are SRv6 SIDs — 7.2 document shapes, not "
        "yet observed live)" in text
    )
    assert "- PE1 (2001:db8::1) -> PE2 (2001:db8::3) color 6001: admin UP, oper UP" in text
    assert "binding-sid fc00:0:1:1::" in text
    assert "- dataplane: srv6 (srv6-binding-sid present, srv6-node-sid / srv6-adjacency-sid" in (
        text
    )
    assert "hops fc00:0:3:: uN@PE2 (2001:db8::3)" in text
    assert "SRv6 policy: keyed by the nodes' IPv6 TE router-ids (2001:db8::1 -> 2001:db8::3)" in (
        text
    )
    assert "UNVERIFIED until an SRv6 policy exists on a lab" in text
    assert "the OE is SR-MPLS only), so they do not describe this policy's SRv6 path" in text
    assert f"- matches {POLICY_SERVICE_V6_PATH}: head-end ['PE1'], tail-end {PE2_V6}" in text
    assert (
        "- on-box policy 'srte_c_6001_ep_2001:db8::3' color 6001 end-point PE2 (2001:db8::3): "
        "candidate path(s) preference 100 dynamic pcep metric igp; srv6 locator LOC1" in text
    )
    assert f"- provisioned by NSO as {POLICY_SERVICE_V6_PATH}" in text
    # The measurements were keyed by the record's IPv6 router-ids; the CAT RPC by host name.
    assert json.loads(routes["util"].calls[0].request.content)["peerAddress"] == PE1_V6
    assert json.loads(routes["util"].calls[0].request.content)["destAddress"] == PE2_V6
    rpc_input = json.loads(routes["transport"].calls[0].request.content)["cat-inventory-rpc:input"]
    reference = rpc_input["cat-inventory-rpc:get-associated-services-for-transport-request"]
    assert reference["sr-policy-ref"]["headend"] == "PE1"
    assert reference["sr-policy-ref"]["endpoint"] == PE2_V6
    calls = audit(text)
    assert (
        f"cnc_get_lsp_utilization(headend='{PE1_V6}', endpoint='{PE2_V6}', color=6001, "
        "network='Default-network', hours=6, response_format='json') -> ok" in calls
    )
    assert f"cnc_find_services_on_transport(headend='PE1', color=6001, endpoint='{PE2_V6}'" in (
        "\n".join(calls)
    )
    assert all(c.endswith("-> ok") for c in calls), calls
    # The SR-MPLS policy keeps its exact rendering (the reason line names the dataplane).
    respx.reset()
    mock_policy()
    text = await call_tool_text(
        await reads(make_settings),
        "cnc_explain_sr_policy",
        {"headend": "PE1", "endpoint": "PE2", "color": 100},
    )
    assert "- dataplane sr-mpls (SR-MPLS: MPLS binding SID and labelled hops)" in text
    assert "- dataplane: sr-mpls (MPLS binding-sid / labelled hops — derived" in text
    assert "hops 16003@PE2 (10.0.0.3)" in text and "binding-sid 24005" in text
    assert "UNVERIFIED" not in text


def test_srv6_explain_helpers():
    names = {"2001:db8::3": "PE2", "10.0.0.3": "PE2"}
    assert hop_text_for(SRV6_HOP, names) == "fc00:0:3:: uN@PE2 (2001:db8::3)"
    assert (
        hop_text_for({"type": "IPV4-NODE-SID", "local-ip-addr": "10.0.0.3", "label": 16003}, names)
        == "16003@PE2 (10.0.0.3)"
    )
    # The document's fully prefixed spelling and the link-local case.
    prefixed = {
        "type": "IPV6-LINK-LOCAL-ADJ-SID",
        "local-ipv6-router-id": "2001:db8::3",
        "cisco-crosswork-segment-routing-policy:srv6-adjacency-sid": {"sid": "fc00:0:3:e000::"},
    }
    assert hop_text_for(prefixed, names) == "fc00:0:3:e000::@PE2 (2001:db8::3)"
    onbox = NSO_CONFIG_SRV6["tailf-ned-cisco-ios-xr:segment-routing"]["traffic-eng"]["policy"][0]
    assert onbox_endpoint(onbox) == PE2_V6
    assert onbox_srv6_text(onbox) == "; srv6 locator LOC1"
    mpls = NSO_CONFIG_SR["tailf-ned-cisco-ios-xr:segment-routing"]["traffic-eng"]["policy"][0]
    assert onbox_endpoint(mpls) == "10.0.0.3" and onbox_srv6_text(mpls) == ""
    assert onbox_srv6_text({"srv6": {"locator": {"locator-name": "L2"}}}) == "; srv6 locator L2"
    assert onbox_srv6_text({"srv6": {}}) == "; srv6 locator ?"
