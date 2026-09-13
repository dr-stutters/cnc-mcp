"""Data Gateway tools end-to-end through MCPServer (schema validation included).

The module is registered directly (not through build_server) so the test does
not depend on tools/__init__.py's module list. All HTTP is mocked with respx.
Fixtures mirror the shapes verified live on the embedded Data Gateway
(2026-09-13, see the platform notes) — field names, casing and wrappers.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from cnc_mcp.auth import StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.config import Settings
from cnc_mcp.errors import PlatformError
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import data_gateway
from cnc_mcp.tools.data_gateway import (
    epoch_iso,
    flatten_param_value,
    name_matches,
    parse_uuid_list,
)
from tests.conftest import BASE_URL, call_tool_text

DG_BASE = f"{BASE_URL}/crosswork/dg-manager"
DG_QUERY_URL = f"{DG_BASE}/v2/dg/query"
POOL_QUERY_URL = f"{DG_BASE}/v2/hapool/query"
LOAD_METRICS_URL = f"{DG_BASE}/v1/device/load-metrics/query"
OUTAGES_URL = f"{DG_BASE}/v1/device/outage-history/query"
VITALS_URL = f"{DG_BASE}/v1/vitals/query"
GLOBAL_PARAMS_URL = f"{DG_BASE}/v1/command/global-parameter/query"
DESTINATIONS_URL = f"{DG_BASE}/v1/destinations/query"
SYSTEM_FILES_URL = f"{DG_BASE}/v1/system-files/query"
CUSTOM_FILES_URL = f"{DG_BASE}/v2/custom-files/query"
MAPPING_URL = f"{BASE_URL}/crosswork/inventory/v1/dg/devicemapping"

DUUID = "3d95eb05-0000-4000-8000-0000000cdg01"
VDG_UUID = "ce5c70f5-0000-4000-8000-00000000ccg9"
PUUID = "ce5c70f5-0000-4000-8000-0000000pool1"
DEVICE_UUID = "0a1b2c3d-0000-4000-8000-00000000dev1"

# Verified: POST v2/dg/query {"filterData":{"Criteria":"select * from RobotDataGateway"}}
DG_QUERY_BODY = {"filterData": {"Criteria": "select * from RobotDataGateway"}}
# Verified: POST v2/hapool/query {"criteria":"select * from HAPool"} (filterData -> 400)
POOL_QUERY_BODY = {"criteria": "select * from HAPool"}

GATEWAY = {
    "duuid": DUUID,
    "name": "EMBEDDED_DEF_CDG",
    "configData": {
        "adminState": "AS_UP",
        "role": "ASSIGNED",
        "poolId": PUUID,
        "vdgUuid": VDG_UUID,
        "profile": {"cpu": 8, "memory": 31, "nics": 3},
        "profileType": "VM_PROFILE_STANDARD",
        "interfaces": [
            {
                "name": "eth0",
                "mac": "00:50:56:ae:bb:cf",
                "ipAddr": [
                    {
                        "inetAf": "ROBOT_INET_ADDR_TYPE_v4",
                        "inetAddr": "198.18.134.219",
                        "mask": "24",
                    }
                ],
            }
        ],
        "tags": [],
    },
    "operationalData": {
        "operState": "OS_UP",
        "operStateDetails": [
            {"componentName": "embeddedCollectors", "state": "CS_UP", "imageTag": "7.2.0"}
        ],
        "createdTime": "1757600000000000000",
        "lastUpdatedTime": "1757700000",
    },
}
SECOND_GATEWAY = {
    **GATEWAY,
    "duuid": "5fa2f708-0000-4000-8000-0000000cdg02",
    "name": "cdg-772.example.test",
    "configData": {
        **GATEWAY["configData"],
        "vdgUuid": "ee3d203f-0000-4000-8000-00000000vdg2",
        "poolId": "6d044acf-0000-4000-8000-0000000pool2",
    },
}
ONE_GATEWAY = {"data": [GATEWAY]}
TWO_GATEWAYS = {"data": [GATEWAY, SECOND_GATEWAY], "totalCount": 2}

POOL = {
    "puuid": PUUID,
    "name": "EMBEDDED_DEF_POOL",
    "ipaddrs": [
        {
            "gateway": "198.18.134.1",
            "inetaddrs": [
                {
                    "inetAf": "ROBOT_INET_ADDR_TYPE_v4",
                    "inetAddr": "198.18.134.219",
                    "mask": "24",
                    "gateway": "198.18.134.1",
                }
            ],
        }
    ],
    "pdgUuids": [DUUID],
    "protectionStatus": "NOT_PLANNED",
    "gateway": "198.18.134.1",
    "balanced": True,
}
POOLS = {"data": [POOL], "totalCount": 1}

LOAD_METRICS = {
    "cdgLoadMetrics": [
        {
            "loadMetricsId": "44810b95-29ca-4114-a152-0b4804798c7b",
            "cdgId": DUUID,
            "timestamp": "1757700000",
            "collectorLoadMetrics": [
                {
                    "loadMetricsId": "44810b95-29ca-4114-a152-0b4804798c7b",
                    "collectorName": "CLI-COLLECTOR",
                    "loadScore": 20,
                    "noOfDelayedCadence": 1,
                    "noOfSkippingCadence": 0,
                    "dispatchQueueSize": 3,
                    "noOfJobsReceived": 12,
                    "noOfStatusSent": 12,
                    "noOfFailedDestinations": 0,
                    "usedGcHeapMemoryKb": 269655,
                    "totalGcHeapMemoryKb": 405504,
                    "usedContainerMemoryMb": 884.8,
                    "allocatedContainerMemoryMb": 9216,
                    "containerMemoryPercentage": 9.6,
                    "containerCpuPercentage": 0.02,
                    "collectorLoadMetricsId": "151682",
                },
                {
                    "loadMetricsId": "44810b95-29ca-4114-a152-0b4804798c7b",
                    "collectorName": "SNMP-COLLECTOR",
                    "loadScore": 24,
                    "noOfDelayedCadence": 0,
                    "noOfSkippingCadence": 0,
                    "dispatchQueueSize": 0,
                    "noOfJobsReceived": 0,
                    "noOfStatusSent": 0,
                    "noOfFailedDestinations": 0,
                    "usedGcHeapMemoryKb": 1103151,
                    "totalGcHeapMemoryKb": 3420160,
                    "usedContainerMemoryMb": 3897.344,
                    "allocatedContainerMemoryMb": 10240,
                    "containerMemoryPercentage": 38.06,
                    "containerCpuPercentage": 1.54,
                    "collectorLoadMetricsId": "151680",
                },
            ],
        }
    ]
}

OUTAGE = {
    "outageHistoryUuid": "83bcd908-f400-4476-b6de-903a1b3e4515",
    "startTimestamp": "1726007872866288723",
    "endTimestamp": "0",
    "state": "UP",
    "vdgId": VDG_UUID,
    "pdgId": DUUID,
    "vitalsSnapshot": {"components": []},
    "message": "",
}

# Verified: the embedded DG answers vitals/query with this 500 for duuid and vdgUuid alike.
VITALS_NOT_FOUND = httpx.Response(
    500, json={"error": f"vitals for Data Gateway ID with '{DUUID}' not found"}
)
VITALS_OK = {
    "components": [
        {
            "name": "cli-collector",
            "status": "RUNNING",
            "cpuUsage": 0.06,
            "memPercent": 5.66,
            "memory": {"baseUnit": "Megabytes", "used": 364.5, "free": 6077.8},
            "thresholdCpu": "NORMAL",
            "thresholdMemory": "NORMAL",
            "tag": "7.2.0",
        }
    ]
}

GLOBAL_PARAMS = {
    "globalParameters": [
        {"key": "SNMP_TRAP_PORT", "value": {"uint32Value": 31062}},
        {"key": "RESYNC_ENGINE_DETAILS", "value": {"boolValue": False}},
        {"key": "SYSLOG_UDP_PORT", "value": {"uint32Value": 31066}},
    ]
}

DESTINATION = {
    "uuid": "c2a8fba8-8363-3d22-b0c2-a9e449693fae",
    "name": "CW_KAFKA_DESTINATION",
    "connectivity_info": [
        {
            "type": "ROBOT_MSVC_TRANS_KAFKA",
            "ipaddrs": [
                {"inet_af": "ROBOT_INET_ADDR_TYPE_v4", "inet_addr": "198.18.134.219", "mask": "24"}
            ],
            "port": 9092,
        }
    ],
    "family": "ROBOT_PROVIDER_DESTINATION",
    "properties": {
        "AUTH_TYPE": "mutual",
        "BATCH_SIZE_CONFIG": "6400000",
        "COMPRESSION_TYPE_CONFIG": "snappy",
        "DESTINATION_TYPE": "destination_type_kafka",
        "DISPATCH_SOURCE": "datagateway",
        "ENCODING": "gpbkv",
        "IS_SECURITY_ENABLED": "true",
        "IS_SYSTEM_DEFINED": "true",
    },
}
DESTINATIONS = {"data": [DESTINATION]}

SYSTEM_FILES = {
    "data": [
        {
            "fileName": "system-cli-device-packages.tar.gz",
            "modifiedTime": 1706443550,
            "bundleType": "SYSTEM",
            "fileType": "DEVICE_PACKAGE",
            "collectorType": "CLI",
            "notes": "System CLI device package",
            "appName": "",
            "downloadUrl": "",
        },
        {
            "fileName": "common_yang_models.tar.gz",
            "modifiedTime": 1706443546,
            "bundleType": "SYSTEM",
            "fileType": "MIB_PACKAGE",
            "collectorType": "SNMP",
            "notes": "System SNMP MIB-Package",
            "appName": "",
            "downloadUrl": "",
        },
    ],
    "total_count": 2,
}

NATS_500 = httpx.Response(500, json={"error": "NATS request failed"})
UNMARSHAL_400 = httpx.Response(
    400,
    json={
        "error": (
            'unable to unmarshal payload to proto, err: unknown field "filterData" '
            "in robotapi.HAPoolGetReq"
        )
    },
)


def job(state: str = "JOB_COMPLETED", **extra) -> dict:
    env = {
        "job_id": "job-dg-1",
        "state": state,
        "type": "1 device(s) mapped successfully",
        "completion_time": "1757700000",
        "creation_time": "1757700000",
        "created_by": "admin",
        "impacted": [f"{DEVICE_UUID} PE1 198.18.140.11"],
    }
    env.update(extra)
    return env


def build(settings: Settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    data_gateway.register(mcp, ctx)
    return mcp


def sent(route: respx.Route, index: int = 0) -> dict:
    return json.loads(route.calls[index].request.content)


READ_TOOLS = {
    "cnc_list_data_gateways",
    "cnc_get_data_gateway",
    "cnc_list_data_gateway_pools",
    "cnc_get_data_gateway_load_metrics",
    "cnc_list_data_gateway_outages",
    "cnc_get_data_gateway_health",
    "cnc_get_data_gateway_global_parameters",
    "cnc_list_data_destinations",
    "cnc_list_data_gateway_files",
}


# --- registration / gating ---------------------------------------------------


async def test_write_tools_hidden_unless_enabled(make_settings):
    names = {t.name for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert names == READ_TOOLS
    names = {t.name for t in await build(make_settings(enable_writes=True)).list_tools()}
    assert names == READ_TOOLS | {"cnc_map_devices_to_data_gateway"}


async def test_annotations(make_settings):
    tools = {t.name: t for t in await build(make_settings(enable_writes=True)).list_tools()}
    for name in READ_TOOLS:
        assert tools[name].annotations.read_only_hint is True, name
        assert tools[name].annotations.idempotent_hint is True, name
    mapping = tools["cnc_map_devices_to_data_gateway"].annotations
    assert mapping.read_only_hint is False
    assert mapping.destructive_hint is False
    assert mapping.idempotent_hint is True


# --- cnc_list_data_gateways --------------------------------------------------


@respx.mock
async def test_list_data_gateways_markdown_and_body(settings):
    route = respx.post(DG_QUERY_URL).mock(return_value=httpx.Response(200, json=ONE_GATEWAY))
    text = await call_tool_text(build(settings), "cnc_list_data_gateways", {})
    assert sent(route) == DG_QUERY_BODY
    assert f"**EMBEDDED_DEF_CDG** ({DUUID})" in text
    assert f"vdg={VDG_UUID} pool={PUUID} admin=AS_UP oper=OS_UP role=ASSIGNED" in text
    assert "profile=8c/31G/3nic" in text
    assert "embeddedCollectors: CS_UP" in text
    assert "1 shown, matching 1, collection 1" in text


@respx.mock
async def test_list_data_gateways_json_envelope_and_client_side_name_filter(settings):
    route = respx.post(DG_QUERY_URL).mock(return_value=httpx.Response(200, json=TWO_GATEWAYS))
    text = await call_tool_text(
        build(settings),
        "cnc_list_data_gateways",
        {"name": "embedded*", "response_format": "json"},
    )
    assert sent(route) == DG_QUERY_BODY  # the filter never reaches the wire
    data = json.loads(text)
    assert data["count"] == 1 and data["total"] == 1 and data["collection_total"] == 2
    assert data["page"] == 0 and data["has_more"] is False and data["next_page"] is None
    assert data["items"] == [GATEWAY]


@respx.mock
async def test_list_data_gateways_empty(settings):
    respx.post(DG_QUERY_URL).mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(build(settings), "cnc_list_data_gateways", {})
    assert "No Data Gateways matched" in text and not text.startswith("Error:")


@respx.mock
async def test_list_data_gateways_api_error_is_string(make_settings):
    respx.post(DG_QUERY_URL).mock(return_value=NATS_500)
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_list_data_gateways", {})
    assert text.startswith("Error:") and "500" in text and "malformed request body" in text


# --- cnc_get_data_gateway ----------------------------------------------------


@respx.mock
async def test_get_data_gateway_by_duuid(settings):
    route = respx.post(DG_QUERY_URL).mock(return_value=httpx.Response(200, json=TWO_GATEWAYS))
    text = await call_tool_text(build(settings), "cnc_get_data_gateway", {"duuid": DUUID})
    assert sent(route) == DG_QUERY_BODY
    assert json.loads(text) == GATEWAY


@respx.mock
async def test_get_data_gateway_by_name_is_case_insensitive(settings):
    respx.post(DG_QUERY_URL).mock(return_value=httpx.Response(200, json=TWO_GATEWAYS))
    text = await call_tool_text(
        build(settings), "cnc_get_data_gateway", {"name": "cdg-772.EXAMPLE.test"}
    )
    assert json.loads(text)["duuid"] == SECOND_GATEWAY["duuid"]


@respx.mock
async def test_get_data_gateway_not_found_names_list_tool(settings):
    respx.post(DG_QUERY_URL).mock(return_value=httpx.Response(200, json=ONE_GATEWAY))
    text = await call_tool_text(build(settings), "cnc_get_data_gateway", {"name": "ghost"})
    assert text.startswith("Error:") and "No Data Gateway with name 'ghost'" in text
    assert "cnc_list_data_gateways" in text


@pytest.mark.parametrize("args", [{}, {"duuid": DUUID, "name": "EMBEDDED_DEF_CDG"}])
@respx.mock
async def test_get_data_gateway_requires_exactly_one_selector(settings, args):
    route = respx.post(DG_QUERY_URL).mock(return_value=httpx.Response(200, json=ONE_GATEWAY))
    text = await call_tool_text(build(settings), "cnc_get_data_gateway", args)
    assert text.startswith("Error:") and "exactly one" in text
    assert route.call_count == 0


@respx.mock
async def test_get_data_gateway_api_error_is_string(make_settings):
    respx.post(DG_QUERY_URL).mock(return_value=UNMARSHAL_400)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_data_gateway", {"duuid": DUUID}
    )
    assert text.startswith("Error:") and "400" in text
    assert "rejects unknown fields" in text


# --- cnc_list_data_gateway_pools ---------------------------------------------


@respx.mock
async def test_list_pools_markdown_and_criteria_body(settings):
    route = respx.post(POOL_QUERY_URL).mock(return_value=httpx.Response(200, json=POOLS))
    text = await call_tool_text(build(settings), "cnc_list_data_gateway_pools", {})
    assert sent(route) == POOL_QUERY_BODY
    assert "filterData" not in route.calls[0].request.content.decode()
    assert f"**EMBEDDED_DEF_POOL** ({PUUID})" in text
    assert "protection=NOT_PLANNED balanced=True gateway=198.18.134.1 pdgs=1" in text
    assert "vips=198.18.134.219" in text


@respx.mock
async def test_list_pools_v1_ipaddr_fallback_and_fqdn_vips(settings):
    # The documented v1 shape (ipaddrs[].ipaddr.inet_addr) and an fqdn entry are read
    # alongside the verified v2 shape (ipaddrs[].inetaddrs[].inetAddr); junk is skipped.
    pool = {
        **POOL,
        "puuid": "6d044acf-0000-4000-8000-0000000pool2",
        "name": "STANDALONE_POOL",
        "ipaddrs": [
            {"ipaddr": {"inet_af": "ROBOT_INET_ADDR_TYPE_v4", "inet_addr": "10.0.0.5"}},
            {"fqdn": "cdg-vip.example.test"},
            {"inetaddrs": [{"inetAddr": "10.0.0.6"}], "fqdn": ""},
            {"ipaddr": {"inet_addr": ""}},  # empty address -> ignored
            "not-a-dict",
        ],
    }
    respx.post(POOL_QUERY_URL).mock(
        return_value=httpx.Response(200, json={"data": [pool], "totalCount": 1})
    )
    text = await call_tool_text(build(settings), "cnc_list_data_gateway_pools", {})
    assert "**STANDALONE_POOL** (6d044acf-0000-4000-8000-0000000pool2)" in text
    assert "vips=10.0.0.5, cdg-vip.example.test, 10.0.0.6" in text


def test_pool_vips_helper_shapes():
    assert data_gateway._pool_vips({"ipaddrs": [{"ipaddr": {"inet_addr": "10.1.1.1"}}]}) == [
        "10.1.1.1"
    ]
    assert data_gateway._pool_vips({"ipaddrs": [{"fqdn": "vip.example.test"}]}) == [
        "vip.example.test"
    ]
    assert data_gateway._pool_vips({"ipaddrs": []}) == []
    assert data_gateway._pool_vips({}) == []


@respx.mock
async def test_list_pools_json(settings):
    respx.post(POOL_QUERY_URL).mock(return_value=httpx.Response(200, json=POOLS))
    text = await call_tool_text(
        build(settings), "cnc_list_data_gateway_pools", {"response_format": "json"}
    )
    data = json.loads(text)
    assert data["total"] == 1 and data["count"] == 1 and data["items"] == [POOL]


@respx.mock
async def test_list_pools_unmarshal_400_is_error_string(make_settings):
    respx.post(POOL_QUERY_URL).mock(return_value=UNMARSHAL_400)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_list_data_gateway_pools", {}
    )
    assert text.startswith("Error:") and "400" in text and "rejects unknown fields" in text


# --- cnc_get_data_gateway_load_metrics ---------------------------------------


@respx.mock
async def test_load_metrics_markdown_and_body(settings):
    route = respx.post(LOAD_METRICS_URL).mock(return_value=httpx.Response(200, json=LOAD_METRICS))
    text = await call_tool_text(
        build(settings), "cnc_get_data_gateway_load_metrics", {"duuid": DUUID}
    )
    assert sent(route) == {"queryParams": [{"field": "DGID", "value": {"valueStr": DUUID}}]}
    assert "CLI-COLLECTOR: loadScore=20 delayed=1 skipping=0 queue=3" in text
    assert "SNMP-COLLECTOR: loadScore=24 delayed=0 skipping=0 queue=0" in text
    assert "2025-09-12T18:00:00Z" in text  # timestamp "1757700000" rendered as ISO


@respx.mock
async def test_load_metrics_json_returns_whole_structure(settings):
    respx.post(LOAD_METRICS_URL).mock(return_value=httpx.Response(200, json=LOAD_METRICS))
    text = await call_tool_text(
        build(settings),
        "cnc_get_data_gateway_load_metrics",
        {"duuid": DUUID, "response_format": "json"},
    )
    assert json.loads(text) == LOAD_METRICS


@respx.mock
async def test_load_metrics_empty_is_not_error(settings):
    respx.post(LOAD_METRICS_URL).mock(return_value=httpx.Response(200, json={"cdgLoadMetrics": []}))
    text = await call_tool_text(
        build(settings), "cnc_get_data_gateway_load_metrics", {"duuid": DUUID}
    )
    assert "No load metrics reported" in text and not text.startswith("Error:")


@respx.mock
async def test_load_metrics_api_error_is_string(make_settings):
    respx.post(LOAD_METRICS_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)),
        "cnc_get_data_gateway_load_metrics",
        {"duuid": DUUID},
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_list_data_gateway_outages -------------------------------------------


@respx.mock
async def test_outages_empty_body_and_message(settings):
    route = respx.post(OUTAGES_URL).mock(return_value=httpx.Response(200, json={"data": []}))
    text = await call_tool_text(build(settings), "cnc_list_data_gateway_outages", {"duuid": DUUID})
    assert sent(route) == {
        "queryParams": [
            {"field": "DGID", "value": {"valueStr": DUUID}},
            {"field": "VDGID", "value": {"valueStr": ""}},
            {"field": "DAYS", "value": {"valueStr": "14"}},
        ]
    }
    assert "No outages in the last 14 days" in text and not text.startswith("Error:")


@respx.mock
async def test_outages_with_records_and_vdg(settings):
    route = respx.post(OUTAGES_URL).mock(return_value=httpx.Response(200, json={"data": [OUTAGE]}))
    text = await call_tool_text(
        build(settings),
        "cnc_list_data_gateway_outages",
        {"duuid": DUUID, "vdg_uuid": VDG_UUID, "days": 30},
    )
    body = sent(route)
    assert body["queryParams"][1] == {"field": "VDGID", "value": {"valueStr": VDG_UUID}}
    assert body["queryParams"][2] == {"field": "DAYS", "value": {"valueStr": "30"}}
    assert "UP from 2024-09-10T22:37:52Z to ongoing" in text
    assert OUTAGE["outageHistoryUuid"] in text


@respx.mock
async def test_outages_json(settings):
    respx.post(OUTAGES_URL).mock(return_value=httpx.Response(200, json={"data": [OUTAGE]}))
    text = await call_tool_text(
        build(settings),
        "cnc_list_data_gateway_outages",
        {"duuid": DUUID, "response_format": "json"},
    )
    data = json.loads(text)
    assert data["days"] == 14 and data["count"] == 1 and data["items"] == [OUTAGE]


@respx.mock
async def test_outages_days_out_of_range_rejected_by_schema(settings):
    # ge/le constraints on ``days`` are enforced by the input schema, before the tool runs.
    route = respx.post(OUTAGES_URL).mock(return_value=httpx.Response(200, json={"data": []}))
    with pytest.raises(ToolError, match="days"):
        await call_tool_text(
            build(settings), "cnc_list_data_gateway_outages", {"duuid": DUUID, "days": 91}
        )
    assert route.call_count == 0


@respx.mock
async def test_outages_api_error_is_string(make_settings):
    respx.post(OUTAGES_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_list_data_gateway_outages", {"duuid": DUUID}
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_get_data_gateway_health ---------------------------------------------


@respx.mock
async def test_health_embedded_not_found_is_informational(settings):
    route = respx.post(VITALS_URL).mock(return_value=VITALS_NOT_FOUND)
    text = await call_tool_text(build(settings), "cnc_get_data_gateway_health", {"duuid": DUUID})
    assert sent(route) == {"queryParams": [{"field": "DGID", "value": {"valueStr": DUUID}}]}
    assert route.call_count == 1  # a POST 500 is never auto-retried
    assert not text.startswith("Error:")
    assert f"No health vitals are available for gateway {DUUID}" in text
    assert "cnc_get_data_gateway_load_metrics" in text


@respx.mock
async def test_health_other_500_is_error(make_settings):
    respx.post(VITALS_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_data_gateway_health", {"duuid": DUUID}
    )
    assert text.startswith("Error:") and "500" in text and "NATS request failed" in text


@pytest.mark.parametrize(
    "body",
    [
        {"error": "NATS request failed: subject not found"},
        {"error": "handler not found for vitals"},
        {"error": "Data Gateway ID not found"},  # close, but not the verified marker text
    ],
)
@respx.mock
async def test_health_500_with_unrelated_not_found_body_is_error(make_settings, body):
    # Only the verified "vitals for Data Gateway ID with '...' not found" body means
    # "embedded gateway, no vitals"; any other 500 is a real failure and must say Error.
    respx.post(VITALS_URL).mock(return_value=httpx.Response(500, json=body))
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_data_gateway_health", {"duuid": DUUID}
    )
    assert text.startswith("Error:") and "500" in text
    assert "No health vitals are available" not in text


@respx.mock
async def test_health_not_found_marker_is_case_insensitive(settings):
    respx.post(VITALS_URL).mock(
        return_value=httpx.Response(
            500, json={"error": f"Vitals for Data Gateway ID with '{VDG_UUID}' NOT FOUND"}
        )
    )
    text = await call_tool_text(build(settings), "cnc_get_data_gateway_health", {"duuid": VDG_UUID})
    assert not text.startswith("Error:")
    assert f"No health vitals are available for gateway {VDG_UUID}" in text


@respx.mock
async def test_health_2xx_empty_body_is_empty_object(settings):
    respx.post(VITALS_URL).mock(return_value=httpx.Response(200, content=b""))
    text = await call_tool_text(build(settings), "cnc_get_data_gateway_health", {"duuid": DUUID})
    assert not text.startswith("Error:")
    assert json.loads(text) == {}


@respx.mock
async def test_health_2xx_non_json_body_is_error(settings):
    respx.post(VITALS_URL).mock(return_value=httpx.Response(200, content=b"<html>proxy</html>"))
    text = await call_tool_text(build(settings), "cnc_get_data_gateway_health", {"duuid": DUUID})
    assert text.startswith("Error:") and "non-JSON" in text


@respx.mock
async def test_health_400_is_error(make_settings):
    respx.post(VITALS_URL).mock(
        return_value=httpx.Response(400, json={"error": "body doesn't contain dgID"})
    )
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_data_gateway_health", {"duuid": DUUID}
    )
    assert text.startswith("Error:") and "400" in text and "dgID" in text


@respx.mock
async def test_health_success_returns_body_as_is(settings):
    respx.post(VITALS_URL).mock(return_value=httpx.Response(200, json=VITALS_OK))
    text = await call_tool_text(build(settings), "cnc_get_data_gateway_health", {"duuid": DUUID})
    assert json.loads(text) == VITALS_OK


# --- cnc_get_data_gateway_global_parameters ----------------------------------


@respx.mock
async def test_global_parameters_markdown_sorted_and_empty_body(settings):
    route = respx.post(GLOBAL_PARAMS_URL).mock(return_value=httpx.Response(200, json=GLOBAL_PARAMS))
    text = await call_tool_text(build(settings), "cnc_get_data_gateway_global_parameters", {})
    assert sent(route) == {}
    assert "- RESYNC_ENGINE_DETAILS = False" in text
    assert "- SNMP_TRAP_PORT = 31062" in text
    assert text.index("RESYNC_ENGINE_DETAILS") < text.index("SNMP_TRAP_PORT")
    assert text.index("SNMP_TRAP_PORT") < text.index("SYSLOG_UDP_PORT")


@respx.mock
async def test_global_parameters_json_flattens_wrappers(settings):
    respx.post(GLOBAL_PARAMS_URL).mock(return_value=httpx.Response(200, json=GLOBAL_PARAMS))
    text = await call_tool_text(
        build(settings),
        "cnc_get_data_gateway_global_parameters",
        {"response_format": "json"},
    )
    assert json.loads(text) == {
        "parameters": {
            "SNMP_TRAP_PORT": 31062,
            "RESYNC_ENGINE_DETAILS": False,
            "SYSLOG_UDP_PORT": 31066,
        }
    }


@respx.mock
async def test_global_parameters_unmarshal_400_is_error(make_settings):
    respx.post(GLOBAL_PARAMS_URL).mock(
        return_value=httpx.Response(
            400,
            json={
                "error": 'unable to unmarshal payload to proto, err: unknown field "data" '
                "in robotapi.GlobalParameterQueryReq"
            },
        )
    )
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_data_gateway_global_parameters", {}
    )
    assert text.startswith("Error:") and "400" in text and "rejects unknown fields" in text


# --- cnc_list_data_destinations ----------------------------------------------


@respx.mock
async def test_list_destinations_markdown_and_body(settings):
    route = respx.post(DESTINATIONS_URL).mock(return_value=httpx.Response(200, json=DESTINATIONS))
    text = await call_tool_text(build(settings), "cnc_list_data_destinations", {})
    assert sent(route) == {"limit": 100, "filter": {}}
    assert f"**CW_KAFKA_DESTINATION** ({DESTINATION['uuid']}) kafka 198.18.134.219:9092" in text
    assert "family=ROBOT_PROVIDER_DESTINATION encoding=gpbkv (system-defined)" in text


@respx.mock
async def test_list_destinations_json(settings):
    # Spec-shaped: a total_count is reported, so has_more comes from it.
    respx.post(DESTINATIONS_URL).mock(
        return_value=httpx.Response(200, json={**DESTINATIONS, "total_count": 1})
    )
    text = await call_tool_text(
        build(settings), "cnc_list_data_destinations", {"response_format": "json"}
    )
    data = json.loads(text)
    assert data["count"] == 1 and data["total"] == 1 and data["has_more"] is False
    assert data["items"] == [DESTINATION]


@respx.mock
async def test_list_destinations_json_verified_shape_without_total_count(settings):
    # Verified live: {"data": [...]} and nothing else — no total_count key at all.
    respx.post(DESTINATIONS_URL).mock(return_value=httpx.Response(200, json=DESTINATIONS))
    text = await call_tool_text(
        build(settings), "cnc_list_data_destinations", {"response_format": "json"}
    )
    data = json.loads(text)
    assert data["count"] == 1 and data["total"] is None and data["collection_total"] is None
    assert data["has_more"] is False and data["next_page"] is None
    assert data["items"] == [DESTINATION]


def _many_destinations(n: int) -> dict:
    # Small records so 100 of them stay well under the response-size cap.
    return {
        "data": [
            {"uuid": f"dest-{i:04d}", "name": f"EXT_{i}", "family": "ROBOT_PROVIDER_DESTINATION"}
            for i in range(n)
        ]
    }


@respx.mock
async def test_list_destinations_at_cap_without_total_count_reports_has_more(settings):
    # 100 items back with no total_count: the listing hit the hard cap, which must be
    # signalled (has_more true + the cap note) even though the platform reports no count.
    respx.post(DESTINATIONS_URL).mock(
        return_value=httpx.Response(200, json=_many_destinations(100))
    )
    text = await call_tool_text(
        build(settings), "cnc_list_data_destinations", {"response_format": "json"}
    )
    data = json.loads(text)
    assert data["count"] == 100 and data["total"] is None
    assert data["has_more"] is True and data["next_page"] == 1

    text = await call_tool_text(build(settings), "cnc_list_data_destinations", {})
    assert "100 shown, collection ?" in text
    assert "capped at 100 destinations" in text and "hit the cap" in text


@respx.mock
async def test_list_destinations_below_cap_without_total_count_has_no_cap_note(settings):
    respx.post(DESTINATIONS_URL).mock(return_value=httpx.Response(200, json=_many_destinations(99)))
    text = await call_tool_text(build(settings), "cnc_list_data_destinations", {})
    assert "99 shown" in text and "capped at 100" not in text


@respx.mock
async def test_list_destinations_api_error_is_string(make_settings):
    respx.post(DESTINATIONS_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_list_data_destinations", {}
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_list_data_gateway_files ---------------------------------------------


@respx.mock
async def test_list_system_files_markdown_and_row_paging(settings):
    route = respx.post(SYSTEM_FILES_URL).mock(return_value=httpx.Response(200, json=SYSTEM_FILES))
    text = await call_tool_text(
        build(settings), "cnc_list_data_gateway_files", {"page_size": 10, "page": 2}
    )
    assert sent(route) == {"startRow": 20, "endRow": 30}
    assert "**system-cli-device-packages.tar.gz** type=DEVICE_PACKAGE collector=CLI" in text
    assert "bundle=SYSTEM app=- modified=2024-01-28T12:05:50Z — System CLI device package" in text
    assert "**common_yang_models.tar.gz** type=MIB_PACKAGE collector=SNMP" in text


@respx.mock
async def test_list_custom_files_json_envelope(settings):
    route = respx.post(CUSTOM_FILES_URL).mock(
        return_value=httpx.Response(200, json={"data": [], "total_count": 0})
    )
    text = await call_tool_text(
        build(settings),
        "cnc_list_data_gateway_files",
        {"kind": "custom", "response_format": "json"},
    )
    assert sent(route) == {"startRow": 0, "endRow": 20}
    data = json.loads(text)
    assert data["total"] == 0 and data["count"] == 0 and data["has_more"] is False
    assert data["page"] == 0 and data["page_size"] == 20


@respx.mock
async def test_list_files_without_total_count_pages_by_fullness(settings):
    respx.post(SYSTEM_FILES_URL).mock(
        return_value=httpx.Response(200, json={"data": SYSTEM_FILES["data"]})
    )
    text = await call_tool_text(
        build(settings),
        "cnc_list_data_gateway_files",
        {"page_size": 2, "response_format": "json"},
    )
    data = json.loads(text)
    assert data["total"] is None and data["has_more"] is True and data["next_page"] == 1


@respx.mock
async def test_list_files_unknown_kind_skips_api(settings):
    route = respx.post(SYSTEM_FILES_URL).mock(return_value=httpx.Response(200, json=SYSTEM_FILES))
    text = await call_tool_text(build(settings), "cnc_list_data_gateway_files", {"kind": "mibs"})
    assert text.startswith("Error:") and "Unknown file kind 'mibs'" in text
    assert "system" in text and "custom" in text
    assert route.call_count == 0


@respx.mock
async def test_list_files_api_error_is_string(make_settings):
    respx.post(SYSTEM_FILES_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_list_data_gateway_files", {}
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_map_devices_to_data_gateway -----------------------------------------


@respx.mock
async def test_map_devices_explicit_vdg_body(make_settings):
    dg_route = respx.post(DG_QUERY_URL).mock(return_value=httpx.Response(200, json=ONE_GATEWAY))
    route = respx.put(MAPPING_URL).mock(return_value=httpx.Response(200, json=job()))
    text = await call_tool_text(
        build(make_settings(enable_writes=True, username="admin")),
        "cnc_map_devices_to_data_gateway",
        {
            "device_uuids": f"{DEVICE_UUID}, 4e5f6a7b-0000-4000-8000-00000000dev2",
            "operation": "update",
            "vdg_uuid": VDG_UUID,
        },
    )
    assert dg_route.call_count == 0  # no lookup when vdg_uuid is given
    assert sent(route) == {
        "dgDeviceMappings": [
            {
                "cdg_duuid": VDG_UUID,
                "mapping_oper": "UPDATE_OPER",
                "device_uuid": [DEVICE_UUID, "4e5f6a7b-0000-4000-8000-00000000dev2"],
            }
        ],
        "user": "admin",
    }
    data = json.loads(text)
    assert data["state"] == "JOB_COMPLETED"
    assert data["impacted_objects"] == [{"uuid": DEVICE_UUID, "name": "PE1", "ip": "198.18.140.11"}]


@respx.mock
async def test_map_devices_default_vdg_from_single_gateway(make_settings):
    dg_route = respx.post(DG_QUERY_URL).mock(return_value=httpx.Response(200, json=ONE_GATEWAY))
    route = respx.put(MAPPING_URL).mock(return_value=httpx.Response(200, json=job()))
    text = await call_tool_text(
        build(make_settings(enable_writes=True, username="admin")),
        "cnc_map_devices_to_data_gateway",
        {"device_uuids": DEVICE_UUID},
    )
    assert sent(dg_route) == DG_QUERY_BODY
    assert sent(route) == {
        "dgDeviceMappings": [
            {"cdg_duuid": VDG_UUID, "mapping_oper": "ADD_OPER", "device_uuid": [DEVICE_UUID]}
        ],
        "user": "admin",
    }
    assert json.loads(text)["state"] == "JOB_COMPLETED"


@respx.mock
async def test_map_devices_omits_user_under_token_auth(make_settings):
    # API_TOKEN auth configures no username: the optional ``user`` attribution field
    # must be left out rather than sent as "".
    route = respx.put(MAPPING_URL).mock(return_value=httpx.Response(200, json=job()))
    settings = make_settings(enable_writes=True)
    assert settings.username == "" and settings.api_token
    text = await call_tool_text(
        build(settings),
        "cnc_map_devices_to_data_gateway",
        {"device_uuids": DEVICE_UUID, "vdg_uuid": VDG_UUID},
    )
    body = sent(route)
    assert "user" not in body
    assert body == {
        "dgDeviceMappings": [
            {"cdg_duuid": VDG_UUID, "mapping_oper": "ADD_OPER", "device_uuid": [DEVICE_UUID]}
        ]
    }
    assert json.loads(text)["state"] == "JOB_COMPLETED"


@respx.mock
async def test_map_devices_sends_user_when_username_configured_with_token(make_settings):
    # Token auth plus CNC_MCP_USERNAME: the username is used purely for attribution.
    route = respx.put(MAPPING_URL).mock(return_value=httpx.Response(200, json=job()))
    settings = make_settings(enable_writes=True, username="operator")
    assert settings.api_token  # still token auth, not CAS
    await call_tool_text(
        build(settings),
        "cnc_map_devices_to_data_gateway",
        {"device_uuids": DEVICE_UUID, "vdg_uuid": VDG_UUID},
    )
    assert sent(route)["user"] == "operator"


@respx.mock
async def test_map_devices_two_gateways_without_vdg_is_error(make_settings):
    respx.post(DG_QUERY_URL).mock(return_value=httpx.Response(200, json=TWO_GATEWAYS))
    route = respx.put(MAPPING_URL).mock(return_value=httpx.Response(200, json=job()))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_map_devices_to_data_gateway",
        {"device_uuids": DEVICE_UUID, "operation": "remove"},
    )
    assert text.startswith("Error:") and "2 Data Gateways exist" in text
    assert VDG_UUID in text and SECOND_GATEWAY["configData"]["vdgUuid"] in text
    assert route.call_count == 0


@respx.mock
async def test_map_devices_failed_job_carries_platform_reason(make_settings):
    respx.put(MAPPING_URL).mock(
        return_value=httpx.Response(
            200,
            json=job(
                "JOB_FAILED",
                type="1 device(s) mapping failed",
                error=(
                    f"Device mapping cannot be performed for device {DEVICE_UUID} because "
                    "invalid dg ID is requested"
                ),
            ),
        )
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_map_devices_to_data_gateway",
        {"device_uuids": DEVICE_UUID, "operation": "ADD_OPER", "vdg_uuid": VDG_UUID},
    )
    assert text.startswith("Error:") and "JOB_FAILED" in text and "invalid dg ID" in text


@pytest.mark.parametrize(
    ("args", "marker"),
    [
        ({"device_uuids": " , ", "vdg_uuid": VDG_UUID}, "device_uuids is empty"),
        (
            {"device_uuids": ",".join(f"dev-{i}" for i in range(51)), "vdg_uuid": VDG_UUID},
            "Too many devices",
        ),
        (
            {"device_uuids": DEVICE_UUID, "operation": "delete", "vdg_uuid": VDG_UUID},
            "Unknown mapping operation",
        ),
    ],
)
@respx.mock
async def test_map_devices_validation_errors_skip_api(make_settings, args, marker):
    route = respx.put(MAPPING_URL).mock(return_value=httpx.Response(200, json=job()))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_map_devices_to_data_gateway", args
    )
    assert text.startswith("Error:") and marker in text
    assert route.call_count == 0


@respx.mock
async def test_map_devices_500_is_error_string(make_settings):
    respx.put(MAPPING_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=0)),
        "cnc_map_devices_to_data_gateway",
        {"device_uuids": DEVICE_UUID, "vdg_uuid": VDG_UUID},
    )
    assert text.startswith("Error:") and "500" in text and "malformed request body" in text


# --- helpers -----------------------------------------------------------------


def test_name_matches():
    assert name_matches("embedded_def_cdg", "EMBEDDED_DEF_CDG")
    assert name_matches("*cdg", "EMBEDDED_DEF_CDG")
    assert name_matches("*def*", "EMBEDDED_DEF_CDG")
    assert not name_matches("cdg", "EMBEDDED_DEF_CDG")  # no substring match without '*'
    assert not name_matches("embedded_def_cd?", "EMBEDDED_DEF_CDG")  # '?' is literal
    assert not name_matches("x", None)


def test_flatten_param_value():
    assert flatten_param_value({"uint32Value": 31062}) == 31062
    assert flatten_param_value({"boolValue": False}) is False
    assert flatten_param_value({"a": 1, "b": 2}) == {"a": 1, "b": 2}
    assert flatten_param_value("raw") == "raw"


def test_epoch_iso_infers_units():
    assert epoch_iso("1757700000") == "2025-09-12T18:00:00Z"  # seconds
    assert epoch_iso(1757700000) == "2025-09-12T18:00:00Z"
    assert epoch_iso("1757700000000") == "2025-09-12T18:00:00Z"  # milliseconds
    assert epoch_iso("1757700000000000") == "2025-09-12T18:00:00Z"  # microseconds
    assert epoch_iso(1757700000000000) == "2025-09-12T18:00:00Z"
    assert epoch_iso("1757700000000000000") == "2025-09-12T18:00:00Z"  # nanoseconds
    assert epoch_iso("0") == "-" and epoch_iso(None) == "-" and epoch_iso("") == "-"
    assert epoch_iso("-5") == "-"
    assert epoch_iso("soon") == "soon"


def test_epoch_iso_unit_boundaries():
    # The first value of each larger unit is 10**8 s (1973-03-03), read in that unit;
    # one below the microsecond threshold is still read as milliseconds (year 5138).
    assert epoch_iso(10**11) == "1973-03-03T09:46:40Z"  # first millisecond value
    assert epoch_iso(10**14) == "1973-03-03T09:46:40Z"  # first microsecond value
    assert epoch_iso(10**17) == "1973-03-03T09:46:40Z"  # first nanosecond value
    assert epoch_iso(10**14 - 1) == "5138-11-16T09:46:39Z"  # ms, not us


def test_parse_uuid_list():
    assert parse_uuid_list(" a , b,,c ") == ["a", "b", "c"]
    with pytest.raises(PlatformError, match="empty"):
        parse_uuid_list(" , ")
    with pytest.raises(PlatformError, match="at most 50"):
        parse_uuid_list(",".join(str(i) for i in range(51)))
