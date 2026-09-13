"""Performance monitoring + NPM tools end-to-end through MCPServer (schema validation
included).

The module is registered directly (not through build_server) so the test does
not depend on tools/__init__.py's module list. All HTTP is mocked with respx.
Fixtures mirror the answers verified live on Crosswork 7.2 (2026-09-13, see
the platform notes "Performance monitoring" and "NPM / Optima analytics"):
the two built-in policies, the deployment-history entry, a devices page with
and without ``total_count``, the policy templates, retention, health
settings, statistics with plain and ``{unit, value}`` metrics, top-N, the
summary series, the Spring 400 envelopes, and the NPM sample / max / empty
answers.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest
import respx
from mcp.server.mcpserver import MCPServer

from cnc_mcp.auth import StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.config import Settings
from cnc_mcp.errors import PlatformError
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import performance
from cnc_mcp.tools.performance import (
    KNOWN_SCHEMAS,
    NPM_EMPTY_CAVEAT,
    TOP_N_SCHEMAS,
    device_uuid_key,
    error_envelope,
    interface_key,
    keys_label,
    lsp_key,
    lsp_label,
    max_text,
    npm_time,
    num_text,
    parse_collection_status,
    parse_iso_time,
    parse_metric_token,
    parse_reachability,
    parse_schema,
    performance_error,
    performance_time,
    router_id,
    series_stats,
    summary_rows,
    time_window,
)
from tests.conftest import BASE_URL, call_tool_text

PERF = f"{BASE_URL}/crosswork/performance/v1"
NPM_BASE = f"{BASE_URL}/crosswork/optima-analytics/api/v1"
POLICIES_URL = f"{PERF}/policies"
TEMPLATES_URL = f"{PERF}/policies/policy-templates"
RETENTION_ALL_URL = f"{PERF}/dataretention/all"
RETENTION_DEFAULT_URL = f"{PERF}/dataretention/default"
HEALTH_URL = f"{PERF}/dashboards/healthsettings"
STATISTICS_URL = f"{PERF}/dashboards/statistics"
TOPN_URL = f"{PERF}/dashboards/topn"
TOPN_COLUMNS_URL = f"{PERF}/dashboards/topn/columns"
SUMMARY_URL = f"{PERF}/dashboards/summary"

GROUP_UUID = "5f0d1c2b-3a4e-4f6d-8b9c-0a1b2c3d4e5f"
PE1_UUID = "2a9b7c1e-0f3d-4b8a-9c6e-1d2f3a4b5c6d"
PE2_UUID = "7c3e5a1d-9b2f-4e8c-a6d4-3f1b2c9d8e7a"
GIG0_ENCODED = "GigabitEthernet0%2F0%2F0%2F0"

# --- performance fixtures (shapes verbatim from the notes) --------------------

INTERFACE_TEMPLATE = {
    "policyTemplate": "INTERFACE",
    "schemasInterval": {
        "CEPMINTERFACE": {"defaultInterval": 300, "pollingIntervals": [0, 300, 900, 1800, 3600]},
        "CEPMCRC": {"defaultInterval": 0, "pollingIntervals": [0, 300, 900, 1800, 3600]},
    },
    "schemasFieldMetadata": {
        "CEPMINTERFACE": {
            "ifInBitsRate": {"min": "0", "unitType": "BITS_PER_SECOND", "TCAEnabled": True},
            "ifOutBitsRate": {"min": "0", "unitType": "BITS_PER_SECOND", "TCAEnabled": True},
            "ifInUtilization": {
                "min": "0",
                "max": "100",
                "unitType": "PERCENTAGE",
                "TCAEnabled": True,
            },
        },
        "CEPMCRC": {
            "crc": {"min": "0", "unitType": "NUMBER", "TCAEnabled": True},
            "crcPercentage": {
                "min": "0",
                "max": "100",
                "unitType": "PERCENTAGE",
                "TCAEnabled": True,
            },
        },
    },
    "schemaDisplayMap": {"CEPMINTERFACE": "Interface", "CEPMCRC": "CRC"},
    "portGroupSupported": True,
}
SRPOLICY_TEMPLATE = {
    "policyTemplate": "SRPOLICY",
    "schemasInterval": {
        "SRPOLICY": {"defaultInterval": 300, "pollingIntervals": [0, 300, 900, 1800, 3600]}
    },
    "schemasFieldMetadata": {
        "SRPOLICY": {
            "outBitRate": {"min": "0", "unitType": "BITS_PER_SECOND", "TCAEnabled": True},
            "outPktsRate": {"min": "0", "unitType": "PACKETS_PER_SECOND", "TCAEnabled": True},
        }
    },
    "schemaDisplayMap": {"SRPOLICY": "LSP traffic"},
    "portGroupSupported": False,
}
DEVICE_HEALTH_TEMPLATE = {
    "policyTemplate": "deviceHealth",
    "schemasInterval": {
        "CPU": {"defaultInterval": 300, "pollingIntervals": [0, 300, 900, 1800, 3600]},
        "MEMORY": {"defaultInterval": 300, "pollingIntervals": [0, 300, 900, 1800, 3600]},
    },
    "schemasFieldMetadata": {
        "CPU": {"cpuUtilization": {"min": "0", "max": "100", "unitType": "PERCENTAGE"}},
        "MEMORY": {"memoryUtilization": {"min": "0", "max": "100", "unitType": "PERCENTAGE"}},
    },
    "schemaDisplayMap": {"CPU": "CPU", "MEMORY": "Memory"},
    "portGroupSupported": False,
}
POLICY_INTERFACE = {
    "monitoringPolicy": {
        "id": 1,
        "policyTemplate": "INTERFACE",
        "name": "Default interface health",
        "description": "Default interface health monitoring policy",
        "schemasInterval": {"CEPMINTERFACE": 300, "CEPMCRC": 0},
        "devices": "",
        "deviceGroups": GROUP_UUID,
        "portGroups": "",
        "tag": "",
        "thresholds": {},
        "active": True,
        "creationTimestamp": 1789171200000,
        "lastChangedTimestamp": 1789171200000,
    },
    "monitoringPolicyTemplate": INTERFACE_TEMPLATE,
    "policyCollectionStatus": "OK",
}
POLICY_LSP = {
    "monitoringPolicy": {
        "id": 2,
        "policyTemplate": "SRPOLICY",
        "name": "Default LSP traffic",
        "description": "Default LSP traffic monitoring policy",
        "schemasInterval": {"SRPOLICY": 300},
        "devices": "",
        "deviceGroups": GROUP_UUID,
        "portGroups": "",
        "tag": "",
        "thresholds": {},
        "active": True,
        "creationTimestamp": 1789171200000,
        "lastChangedTimestamp": 1789257600000,
    },
    "monitoringPolicyTemplate": SRPOLICY_TEMPLATE,
    "policyCollectionStatus": "OK",
}
POLICIES = [POLICY_LSP, POLICY_INTERFACE]
HISTORY = [
    {
        "id": 1,
        "lastActivatedTimestamp": 1789171200000,
        "devices": "",
        "deviceGroups": "All Locations",
        "portGroups": "",
    }
]
DEVICE_PE1 = {
    "selected": True,
    "reachabilityState": "CONN_STATE_REACHABLE",
    "adminState": "ROBOT_ADMIN_STATE_UP",
    "hostName": "PE1",
    "ipAddress": "10.0.0.1",
    "productType": "Cisco XRd Virtual Router",
    "collectionStatus": "ACTIVE",
    "uuid": PE1_UUID,
    "lastUpdateTime": 1789300800,
    "gatewayName": "EMBEDDED_DEF_POOL-1",
}
DEVICE_PE2 = {
    **DEVICE_PE1,
    "hostName": "PE2",
    "ipAddress": "10.0.0.2",
    "uuid": PE2_UUID,
    "collectionStatus": "NOTPOLLING",
    "comments": [{"type": "POLLED_BY_ANOTHER_POLICY", "argument": "Default interface health"}],
}
DEVICES_PAGE = {"data": [DEVICE_PE1, DEVICE_PE2]}  # unfiltered: NO total_count (verified)
DEVICES_FILTERED = {"data": [DEVICE_PE1], "total_count": 1}
TEMPLATES = {
    "SRPOLICY": SRPOLICY_TEMPLATE,
    "INTERFACE": INTERFACE_TEMPLATE,
    "deviceHealth": DEVICE_HEALTH_TEMPLATE,
}
RETENTION_ALL = {
    "DeviceEnvTemp": {
        "rawDataRetentionPeriod": 24,
        "hourlyDataRetentionPeriod": 168,
        "dailyDataRetentionPeriod": 744,
        "weeklyDataRetentionPeriod": 9072,
        "policyType": "deviceHealth",
        "schemaName": "ENVTEMP",
        "hasAggrOption": True,
    },
    "Interface": {
        "rawDataRetentionPeriod": 24,
        "hourlyDataRetentionPeriod": 168,
        "dailyDataRetentionPeriod": 744,
        "weeklyDataRetentionPeriod": 9072,
        "policyType": "INTERFACE",
        "schemaName": "CEPMINTERFACE",
        "hasAggrOption": False,
    },
}
RETENTION_DEFAULT = {
    "rawDataRetentionPeriod": 24,
    "hourlyDataRetentionPeriod": 168,
    "dailyDataRetentionPeriod": 744,
    "weeklyDataRetentionPeriod": 9072,
}
HEALTH_SETTINGS = {
    "INTERFACE": {
        "CEPMINTERFACE_ifAdminUpOperUp": {
            "metric": "ifAdminUpOperUp",
            "schemaName": "CEPMINTERFACE",
            "policy": "INTERFACE",
            "categories": [
                {"level": "HEALTHY", "min": 99.0, "max": 100.0},
                {"level": "MINOR", "min": 75.0, "max": 99.0},
                {"level": "CRITICAL", "min": 0.0, "max": 75.0},
            ],
            "unit": "PERCENTAGE",
            "possibleUnits": ["PERCENTAGE"],
            "min": 0.0,
            "categoryType": "RANGE",
            "editable": True,
        },
        "CEPMINTERFACE_ifInUtilization": {
            "metric": "ifInUtilization",
            "schemaName": "CEPMINTERFACE",
            "policy": "INTERFACE",
            "categories": [
                {"level": "HEALTHY", "min": 0.0, "max": 50.0},
                {"level": "MINOR", "min": 50.0, "max": 75.0},
                {"level": "MAJOR", "min": 75.0, "max": 90.0},
                {"level": "CRITICAL", "min": 90.0, "max": 100.0},
            ],
            "unit": "PERCENTAGE",
            "possibleUnits": ["PERCENTAGE"],
            "min": 0.0,
            "categoryType": "RANGE",
            "editable": True,
        },
    },
    "deviceHealth": {
        "CPU_cpuUtilization": {
            "metric": "cpuUtilization",
            "schemaName": "CPU",
            "policy": "deviceHealth",
            "categories": [
                {"level": "HEALTHY", "min": 0.0, "max": 60.0},
                {"level": "MAJOR", "min": 60.0, "max": 100.0},
            ],
            "unit": "PERCENTAGE",
            "possibleUnits": ["PERCENTAGE"],
            "min": 0.0,
            "categoryType": "RANGE",
            "editable": True,
        }
    },
}
STATISTICS = {
    "schema": "CEPMINTERFACE",
    "page": 1,
    "records": 2,
    "entries": [
        {
            "keys": {
                "hostname": "PE1",
                "interfaceName": "GigabitEthernet0/0/0/0",
                "device": PE1_UUID,
            },
            "metrics": {"ifInBitsRate": 1234.5, "ifOutBitsRate": 0.0},
        },
        {
            "keys": {
                "hostname": "PE1",
                "interfaceName": "GigabitEthernet0/0/0/1",
                "device": PE1_UUID,
            },
            "metrics": {"ifInBitsRate": 42, "ifOutBitsRate": 7.25},
        },
    ],
}
STATISTICS_UNITS = {
    "schema": "SRPOLICY",
    "page": 1,
    "records": 1,
    "entries": [
        {
            "keys": {
                "hostname": "PE1",
                "name": "srte_c_100_ep_10.0.0.3",
                "color": 0,
                "endpoint": "",
                "device": PE1_UUID,
            },
            "metrics": {"outBitRate": {"unit": "KBITS_PER_SECOND", "value": 12.5}},
        }
    ],
}
STATISTICS_EMPTY = {"schema": "CPU", "page": 1, "records": 0, "entries": []}
TOPN = [
    {
        "metricName": "ifInUtilization",
        "entries": [
            {
                "keys": {
                    "hostname": "PE1",
                    "interfaceName": "GigabitEthernet0/0/0/0",
                    "device": PE1_UUID,
                },
                "average": 0.5,
                "maximum": 1.25,
                "minimum": 0.0,
                "unit": "PERCENTAGE",
                "trendURLParameters": f"device={PE1_UUID}&interfaceName={GIG0_ENCODED}",
                "severity": "HEALTHY",
            },
            {
                "keys": {
                    "hostname": "PE2",
                    "interfaceName": "GigabitEthernet0/0/0/0",
                    "device": PE2_UUID,
                },
                "average": 0.25,
                "maximum": 0.5,
                "minimum": 0.0,
                "unit": "PERCENTAGE",
                "trendURLParameters": f"device={PE2_UUID}&interfaceName={GIG0_ENCODED}",
            },
        ],
    }
]
TOPN_COLUMNS = [
    {
        "schemaName": "CEPMINTERFACE",
        "keyToDisplayNameList": [
            {"key": "hostname", "displayName": "Device name"},
            {"key": "interfaceName", "displayName": "Interface name"},
        ],
    },
    {
        "schemaName": "CPU",
        "keyToDisplayNameList": [
            {"key": "hostname", "displayName": "Device name"},
            {"key": "cpuName", "displayName": "CPU name"},
        ],
    },
]
SUMMARY = [
    {
        "metricName": "ifInUtilization",
        "metricUnit": "PERCENTAGE",
        "averageSeries": [
            {"value": 0.5, "timestamp": "2026-09-13T00:00:00Z"},
            {"value": 0.75, "timestamp": "2026-09-13T02:00:00Z"},
        ],
        "minimumSeries": [
            {"value": 0.0, "timestamp": "2026-09-13T00:00:00Z"},
            {"value": 0.1, "timestamp": "2026-09-13T02:00:00Z"},
        ],
        "maximumSeries": [
            {"value": 1.0, "timestamp": "2026-09-13T00:00:00Z"},
            {"value": 2.0, "timestamp": "2026-09-13T02:00:00Z"},
        ],
    }
]
SUMMARY_EMPTY = [
    {
        "metricName": "cpuUtilization",
        "metricUnit": "PERCENTAGE",
        "averageSeries": [],
        "minimumSeries": [],
        "maximumSeries": [],
    }
]


def envelope(code: str, details: str, *parameters: object, status: int = 400) -> dict:
    """The Spring error envelope verified live (``message`` is a CODE)."""
    return {
        "timestamp": "13-09-2026 05:43:07",
        "code": status,
        "status": "Bad Request" if status == 400 else "Internal Server Error",
        "message": code,
        "details": details,
        "parameters": list(parameters),
    }


MISSING_POLICY_ID = envelope("MISSING_POLICY_ID", "Given policy ID doesn't exist", 999)
MISSING_POLICY_HISTORY = envelope(
    "MISSING_POLICY_HISTORY", "Given policy ID doesn't have a deployment history", 999
)
INVALID_SCHEMA = envelope("INVALID_SCHEMA", "Given schema doesn't exist", "BOGUS")
INVALID_COMBO = envelope(
    "INVALID_SCHEMA_METRIC_COMBO",
    "Policy CEPMINTERFACE or metric nope do not exist",
    "CEPMINTERFACE",
    "nope",
)
MISSING_TIME = envelope("MISSING_TIME_DETAILS", "Missing 'from' AND/OR 'to' OR 'timeInterval'")
UNITS_500 = envelope(
    "Method parameter 'units': Failed to convert value of type 'java.lang.String' to required "
    "type 'java.lang.Boolean'",
    "",
    status=500,
)

# --- NPM fixtures ----------------------------------------------------------------

FROM = "2026-09-13T12:00:00Z"
TO = "2026-09-13T18:00:00Z"
LSP_KEY_SR = {
    "lspType": "SR",
    "peerAddress": "10.0.0.1",
    "destAddress": "10.0.0.3",
    "color": "100",
    "from": FROM,
    "to": TO,
}
LSP_KEY_RSVP = {
    "lspType": "RSVP",
    "peerAddress": "10.0.0.1",
    "destAddress": "10.0.0.3",
    "tunnelId": "11",
    "from": FROM,
    "to": TO,
}
INTERFACE_KEY = {
    "device_uuid": PE1_UUID,
    "int_name": "GigabitEthernet0/0/0/0",
    "from": FROM,
    "to": TO,
}
UTILIZATIONS = [
    {"tst": "2026-09-13T12:01:36Z", "util": 0.0},
    {"tst": "2026-09-13T12:06:36Z", "util": 2.5},
]
MAX_UTIL = {
    "maxUtilization": 2.5,
    "success": True,
    "message": "Successfully found Maximum Utilization",
}
MAX_UTIL_ZERO = {
    "maxUtilization": 0.0,
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
MAX_DELAY_NONE = {
    "maxDelay": 0.0,
    "success": False,
    "message": "Maximum Average Delay for given Interface not present..returning default delay!",
}
DELAY_VARIANCE = [{"delayVariance": 6, "tst": "2026-09-13T12:01:36Z"}]
INTERFACE_DELAYS = [
    {
        "minimumDelay": 2,
        "maximumDelay": 8,
        "averageDelay": 5,
        "delayVariance": 6,
        "tst": "2026-09-13T12:01:36Z",
    }
]
NPM_500 = httpx.Response(
    500,
    json={
        "type": "about:blank",
        "title": "Internal Server Error",
        "status": 500,
        "detail": "Failed to map json to class interface java.util.Map",
    },
)

TOOLS = {
    "cnc_list_performance_policies",
    "cnc_get_performance_policy",
    "cnc_get_performance_policy_history",
    "cnc_list_performance_policy_devices",
    "cnc_list_performance_policy_templates",
    "cnc_get_performance_retention",
    "cnc_get_performance_health_settings",
    "cnc_get_performance_statistics",
    "cnc_get_performance_top_n",
    "cnc_list_performance_top_n_columns",
    "cnc_get_performance_summary",
    "cnc_get_lsp_utilization",
    "cnc_get_lsp_delay",
    "cnc_get_interface_delay",
}


def build(settings: Settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    performance.register(mcp, ctx)
    return mcp


def sent(route: respx.Route, index: int = 0) -> dict:
    return json.loads(route.calls[index].request.content)


def params_of(route: respx.Route, index: int = 0) -> dict[str, str]:
    return dict(route.calls[index].request.url.params)


def get(url: str, body: object, status: int = 200) -> respx.Route:
    return respx.get(url).mock(return_value=httpx.Response(status, json=body))


def post(url: str, body: object, status: int = 200) -> respx.Route:
    return respx.post(url).mock(return_value=httpx.Response(status, json=body))


# --- registration -------------------------------------------------------------


async def test_all_tools_are_reads_visible_without_writes(make_settings):
    mcp = build(make_settings(enable_writes=False))
    tools = {t.name: t for t in await mcp.list_tools()}
    assert set(tools) == TOOLS
    for name, tool in tools.items():
        assert tool.annotations.read_only_hint is True, name
        assert tool.annotations.idempotent_hint is True, name
        assert tool.annotations.destructive_hint is False, name


async def test_paging_is_one_based_and_flat(make_settings):
    tools = {t.name: t for t in await build(make_settings()).list_tools()}
    for name in (
        "cnc_list_performance_policy_devices",
        "cnc_get_performance_statistics",
        "cnc_get_performance_top_n",
    ):
        props = tools[name].input_schema["properties"]
        assert props["page"]["default"] == 1 and props["page"]["minimum"] == 1, name
        assert props["page_size"]["minimum"] == 1, name


async def test_lsp_tools_use_the_shared_te_key_names(make_settings):
    """headend / endpoint / color / tunnel_id — the names cnc_list_sr_policies and
    cnc_get_sr_policy_performance_metrics use, so their output chains without remapping."""
    tools = {t.name: t for t in await build(make_settings()).list_tools()}
    for name in ("cnc_get_lsp_utilization", "cnc_get_lsp_delay"):
        schema = tools[name].input_schema
        props = schema["properties"]
        assert set(schema["required"]) == {"headend", "endpoint", "from_time", "to_time"}, name
        assert "headend_router_id" not in props and "endpoint_router_id" not in props, name
        assert "NOT the host name" in props["headend"]["description"], name
        assert props["color"]["default"] == 0 and "refused" in props["color"]["description"], name
        assert props["tunnel_id"]["default"] == "", name


# --- pure helpers ---------------------------------------------------------------


def test_parse_iso_time_accepts_utc_with_optional_millis_and_refuses_the_rest():
    assert parse_iso_time("2026-09-13T12:00:00Z", "from_time") == datetime(
        2026, 9, 13, 12, 0, 0, tzinfo=UTC
    )
    assert parse_iso_time(" 2026-09-13T12:00:00.250Z ", "x").microsecond == 250000
    for bad in ("", "2026-09-13", "2026-09-13T12:00:00", "2026-09-13T12:00:00+00:00", "now"):
        with pytest.raises(PlatformError, match="must be an ISO-8601 UTC timestamp"):
            parse_iso_time(bad, "from_time")
    with pytest.raises(PlatformError, match="not a real date/time"):
        parse_iso_time("2026-02-30T12:00:00Z", "to_time")


def test_time_window_orders_and_formats_for_both_services():
    start, end = time_window("2026-09-13T12:00:00Z", "2026-09-13T18:00:00.500Z")
    assert performance_time(start) == "2026-09-13T12:00:00.000Z"
    assert performance_time(end) == "2026-09-13T18:00:00.500Z"
    assert npm_time(start) == "2026-09-13T12:00:00Z" and npm_time(end) == "2026-09-13T18:00:00Z"
    with pytest.raises(PlatformError, match="to_time must be after from_time"):
        time_window("2026-09-13T12:00:00Z", "2026-09-13T12:00:00Z")


def test_parse_metric_token_upper_cases_the_schema_and_gates_top_n():
    assert parse_metric_token(" cepminterface_ifInUtilization ", top_n=True) == (
        "CEPMINTERFACE_ifInUtilization"
    )
    # A metric with an underscore keeps everything after the first one.
    assert parse_metric_token("CPU_cpu_total", top_n=False) == "CPU_cpu_total"
    with pytest.raises(PlatformError, match="<SCHEMA>_<metric> token"):
        parse_metric_token("ifInUtilization", top_n=True)
    with pytest.raises(PlatformError, match="<SCHEMA>_<metric> token"):
        parse_metric_token("CEPMINTERFACE_", top_n=False)
    with pytest.raises(PlatformError, match="not a top-N schema/metric") as info:
        parse_metric_token("SRPOLICY_outBitRate", top_n=True)
    assert "Nothing was sent" in str(info.value) and "OTUCONTROLLERSINFO" in str(info.value)
    # The summary dashboard is not gated (only the shape is checked).
    assert parse_metric_token("SRPOLICY_outBitRate", top_n=False) == "SRPOLICY_outBitRate"
    assert len(TOP_N_SCHEMAS) == 13 and set(TOP_N_SCHEMAS) < set(KNOWN_SCHEMAS)


def test_parse_schema_and_filters():
    assert parse_schema(" cepminterface ") == "CEPMINTERFACE"
    with pytest.raises(PlatformError, match="schema is required"):
        parse_schema("  ")
    assert parse_reachability("reachable") == "CONN_STATE_REACHABLE"
    assert parse_reachability("CONN_STATE_DEGRADED") == "CONN_STATE_DEGRADED"
    assert parse_reachability("") is None
    with pytest.raises(PlatformError, match="Unknown reachability_state 'up'"):
        parse_reachability("up")
    assert parse_collection_status("notpolling") == "NOTPOLLING"
    assert parse_collection_status("") is None
    with pytest.raises(PlatformError, match="Unknown collection_status 'polling'"):
        parse_collection_status("polling")


def test_router_id_refuses_host_names():
    assert router_id(" 10.0.0.1 ", "headend") == "10.0.0.1"
    with pytest.raises(PlatformError, match="headend must be a TE router-id") as info:
        router_id("PE1", "headend")
    assert "cnc_list_sr_policies" in str(info.value)


def test_lsp_key_is_sr_with_a_string_color_or_rsvp_with_a_tunnel_id():
    start, end = time_window(FROM, TO)
    assert lsp_key("10.0.0.1", "10.0.0.3", 100, "", start, end) == LSP_KEY_SR
    assert lsp_key("10.0.0.1", "10.0.0.3", 100, " 11 ", start, end) == LSP_KEY_RSVP
    assert lsp_label(LSP_KEY_SR) == "SR LSP 10.0.0.1 -> 10.0.0.3 color 100"
    assert lsp_label(LSP_KEY_RSVP) == "RSVP LSP 10.0.0.1 -> 10.0.0.3 tunnel 11"
    # Color 0 is not an SR policy color: refused for SR, irrelevant for RSVP.
    with pytest.raises(PlatformError, match="color is required for an SR policy") as info:
        lsp_key("10.0.0.1", "10.0.0.3", 0, "", start, end)
    assert "cnc_list_sr_policies" in str(info.value) and "Nothing was sent" in str(info.value)
    assert lsp_key("10.0.0.1", "10.0.0.3", 0, "11", start, end) == LSP_KEY_RSVP
    with pytest.raises(PlatformError, match="endpoint must be a TE router-id"):
        lsp_key("10.0.0.1", "PE3", 100, "", start, end)


def test_interface_key_needs_a_real_inventory_uuid():
    start, end = time_window(FROM, TO)
    assert interface_key(PE1_UUID, "GigabitEthernet0/0/0/0", start, end) == INTERFACE_KEY
    # Any uuid spelling is accepted and sent canonical (as oam.validate_device_uuid does).
    assert device_uuid_key(f" {{{PE1_UUID.upper()}}} ") == PE1_UUID
    assert device_uuid_key(f"urn:uuid:{PE1_UUID}") == PE1_UUID
    assert device_uuid_key(PE1_UUID.replace("-", "")) == PE1_UUID
    for bad in ("PE1", "10.0.0.1", "not-a-uuid"):
        with pytest.raises(
            PlatformError, match="device_uuid must be the device's inventory uuid"
        ) as info:
            device_uuid_key(bad)
        assert f"cnc_get_device(host_name='{bad}')" in str(info.value)
        assert "cnc_list_devices" in str(info.value) and "Nothing was sent" in str(info.value)
    with pytest.raises(PlatformError, match="both required"):
        interface_key(PE1_UUID, " ", start, end)
    with pytest.raises(PlatformError, match="both required"):
        interface_key("", "GigabitEthernet0/0/0/0", start, end)


def test_error_envelope_and_performance_error():
    response = httpx.Response(400, json=MISSING_POLICY_ID)
    assert error_envelope(response) == {
        "code": "MISSING_POLICY_ID",
        "details": "Given policy ID doesn't exist",
        "parameters": [999],
    }
    # A sentence in ``message`` (the 500 type-conversion failure) is NOT a code.
    assert error_envelope(httpx.Response(500, json=UNITS_500)) is None
    assert error_envelope(httpx.Response(500, text="boom")) is None
    err = performance_error(response, {"MISSING_POLICY_ID": ("no performance policy 999", "List.")})
    assert str(err) == "no performance policy 999 (MISSING_POLICY_ID). List."
    assert str(performance_error(response, {"MISSING_POLICY_ID": "gone"})) == (
        "gone (MISSING_POLICY_ID)."
    )
    # An enveloped code without a hint renders the platform's details.
    assert str(performance_error(response)) == (
        "Given policy ID doesn't exist (MISSING_POLICY_ID)."
    )
    generic = str(performance_error(httpx.Response(500, json=UNITS_500)))
    assert generic.startswith("API request failed with status 500.") and "units" in generic


def test_rendering_helpers():
    assert num_text(0.0) == "0" and num_text(7.25) == "7.25" and num_text(42) == "42"
    assert (
        num_text(1234.56789) == "1234.5679" and num_text(None) == "-" and num_text(True) == "true"
    )
    assert keys_label(STATISTICS["entries"][0]["keys"]) == "PE1 GigabitEthernet0/0/0/0"
    assert (
        keys_label(STATISTICS_UNITS["entries"][0]["keys"]) == "PE1 srte_c_100_ep_10.0.0.3 color=0"
    )
    assert keys_label({}) == "?"
    assert summary_rows(SUMMARY[0]) == [
        {"timestamp": "2026-09-13T00:00:00Z", "average": 0.5, "minimum": 0.0, "maximum": 1.0},
        {"timestamp": "2026-09-13T02:00:00Z", "average": 0.75, "minimum": 0.1, "maximum": 2.0},
    ]
    assert summary_rows(SUMMARY_EMPTY[0]) == []
    assert series_stats(UTILIZATIONS, "util") == {
        "count": 2,
        "first_at": "2026-09-13T12:01:36Z",
        "last_at": "2026-09-13T12:06:36Z",
        "average": 1.25,
        "minimum": 0.0,
        "maximum": 2.5,
        "last": 2.5,
    }
    assert series_stats([], "util") == {"count": 0, "first_at": None, "last_at": None}
    assert max_text(MAX_UTIL, "maxUtilization", "max utilization") == (
        "max utilization (platform): 2.5 — Successfully found Maximum Utilization"
    )
    assert max_text(MAX_DELAY_NONE, "maxDelay", "max average delay") == (
        "max average delay (platform): no data (Maximum Average Delay for given Interface not "
        "present..returning default delay!)"
    )
    assert max_text(None, "maxDelay", "max average delay") == (
        "max average delay (platform): not reported"
    )


# --- cnc_list_performance_policies ----------------------------------------------


@respx.mock
async def test_list_policies_markdown(settings):
    route = get(POLICIES_URL, POLICIES)
    text = await call_tool_text(build(settings), "cnc_list_performance_policies", {})
    assert route.call_count == 1
    lines = text.split("\n")
    assert lines[0] == "# 2 performance monitoring policies"
    assert lines[2] == (
        "- **Default LSP traffic** (id 2, template SRPOLICY): active, collection OK; SRPOLICY "
        f"every 300 s; device groups {GROUP_UUID}; changed 2026-09-13T00:00:00Z"
    )
    assert lines[3] == (
        "- **Default interface health** (id 1, template INTERFACE): active, collection OK; "
        f"CEPMINTERFACE every 300 s, CEPMCRC off; device groups {GROUP_UUID}; changed "
        "2026-09-12T00:00:00Z"
    )
    assert "cnc_get_performance_policy(policy_id)" in text


@respx.mock
async def test_list_policies_json(settings):
    get(POLICIES_URL, POLICIES)
    text = await call_tool_text(
        build(settings), "cnc_list_performance_policies", {"response_format": "json"}
    )
    data = json.loads(text)
    assert data["count"] == 2 and [p["id"] for p in data["policies"]] == [2, 1]
    assert data["policies"][1] == {
        "id": 1,
        "name": "Default interface health",
        "description": "Default interface health monitoring policy",
        "template": "INTERFACE",
        "active": True,
        "collection_status": "OK",
        "schemas_interval": {"CEPMINTERFACE": 300, "CEPMCRC": 0},
        "devices": [],
        "device_groups": [GROUP_UUID],
        "port_groups": [],
        "tag": "",
        "thresholds": {},
        "created_at": "2026-09-12T00:00:00Z",
        "last_changed_at": "2026-09-12T00:00:00Z",
    }


@respx.mock
async def test_list_policies_empty_and_api_error(make_settings):
    get(POLICIES_URL, [])
    text = await call_tool_text(build(make_settings()), "cnc_list_performance_policies", {})
    assert text == "No performance monitoring policies."
    respx.get(POLICIES_URL).mock(
        return_value=httpx.Response(403, json={"error": "Unauthorized request"})
    )
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_list_performance_policies", {}
    )
    assert text.startswith("Error:") and "403" in text


# --- cnc_get_performance_policy ---------------------------------------------------


@respx.mock
async def test_get_policy_markdown_lists_the_template_metrics(settings):
    route = get(f"{POLICIES_URL}/1", POLICY_INTERFACE)
    text = await call_tool_text(build(settings), "cnc_get_performance_policy", {"policy_id": 1})
    assert route.call_count == 1
    assert text.startswith("# Performance policy 1: Default interface health\n\n")
    assert "- template INTERFACE; active; collection status OK\n" in text
    assert "- polling: CEPMINTERFACE every 300 s, CEPMCRC off\n" in text
    assert f"- scope: device groups {GROUP_UUID}\n" in text
    assert "- created 2026-09-12T00:00:00Z; last changed 2026-09-12T00:00:00Z\n" in text
    assert "- thresholds: none\n" in text
    assert "## Template INTERFACE schemas and metrics\n" in text
    assert (
        "- CEPMINTERFACE (Interface) — default 300 s, allowed 0/300/900/1800/3600 s: "
        "ifInBitsRate (BITS_PER_SECOND), ifOutBitsRate (BITS_PER_SECOND), ifInUtilization "
        "(PERCENTAGE)\n"
    ) in text
    assert text.endswith(
        "- CEPMCRC (CRC) — default 0 s, allowed 0/300/900/1800/3600 s: crc (NUMBER), "
        "crcPercentage (PERCENTAGE)"
    )


@respx.mock
async def test_get_policy_json_is_the_raw_object_even_when_wrapped_in_a_list(settings):
    get(f"{POLICIES_URL}/2", [POLICY_LSP])
    text = await call_tool_text(
        build(settings), "cnc_get_performance_policy", {"policy_id": 2, "response_format": "json"}
    )
    assert json.loads(text) == POLICY_LSP


@respx.mock
async def test_get_policy_unknown_id_is_missing_policy_id(settings):
    get(f"{POLICIES_URL}/999", MISSING_POLICY_ID, 400)
    text = await call_tool_text(build(settings), "cnc_get_performance_policy", {"policy_id": 999})
    assert text.startswith("Error: no performance policy 999 (MISSING_POLICY_ID).")
    assert "cnc_list_performance_policies" in text


@respx.mock
async def test_get_policy_empty_answer_is_not_found(settings):
    get(f"{POLICIES_URL}/3", {})
    text = await call_tool_text(build(settings), "cnc_get_performance_policy", {"policy_id": 3})
    assert text.startswith("Error: no performance policy 3: the platform answered no policy object")


# --- cnc_get_performance_policy_history ----------------------------------------


@respx.mock
async def test_get_policy_history(settings):
    route = get(f"{POLICIES_URL}/1/deployment-history", HISTORY)
    text = await call_tool_text(
        build(settings), "cnc_get_performance_policy_history", {"policy_id": 1}
    )
    assert route.call_count == 1
    assert text == (
        "# Deployment history of performance policy 1\n\n"
        "- activated 2026-09-12T00:00:00Z: device groups All Locations"
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_performance_policy_history",
        {"policy_id": 1, "response_format": "json"},
    )
    assert json.loads(text) == {
        "policy_id": 1,
        "count": 1,
        "history": [
            {
                "id": 1,
                "last_activated_at": "2026-09-12T00:00:00Z",
                "devices": [],
                "device_groups": ["All Locations"],
                "port_groups": [],
            }
        ],
    }


@respx.mock
async def test_get_policy_history_empty_and_unknown(settings):
    get(f"{POLICIES_URL}/2/deployment-history", [])
    text = await call_tool_text(
        build(settings), "cnc_get_performance_policy_history", {"policy_id": 2}
    )
    assert text == "No deployment history for policy 2."
    get(f"{POLICIES_URL}/999/deployment-history", MISSING_POLICY_HISTORY, 400)
    text = await call_tool_text(
        build(settings), "cnc_get_performance_policy_history", {"policy_id": 999}
    )
    assert text.startswith(
        "Error: no deployment history for policy 999 (unknown policy?) (MISSING_POLICY_HISTORY)."
    )


# --- cnc_list_performance_policy_devices ---------------------------------------


@respx.mock
async def test_list_policy_devices_unfiltered_page_has_unknown_total(settings):
    route = get(f"{POLICIES_URL}/devices/1", DEVICES_PAGE)
    text = await call_tool_text(
        build(settings),
        "cnc_list_performance_policy_devices",
        {"policy_id": 1, "page_size": 2, "page": 1},
    )
    assert params_of(route) == {"pageSize": "2", "page": "1"}
    lines = text.split("\n")
    assert lines[0] == "# Devices of performance policy 1 (page 1, 2 shown, total unknown)"
    assert lines[2] == (
        f"- **PE1** 10.0.0.1 ({PE1_UUID}): CONN_STATE_REACHABLE / ROBOT_ADMIN_STATE_UP, "
        "collection ACTIVE, Cisco XRd Virtual Router, gateway EMBEDDED_DEF_POOL-1, updated "
        "2026-09-13T12:00:00Z"
    )
    assert lines[3].endswith(
        "collection NOTPOLLING, Cisco XRd Virtual Router, gateway EMBEDDED_DEF_POOL-1, updated "
        "2026-09-13T12:00:00Z [POLLED_BY_ANOTHER_POLICY Default interface health]"
    )
    # A full page with no total_count: more may exist (heuristic).
    assert lines[-1] == "(more may exist: call again with page=2)"


@respx.mock
async def test_list_policy_devices_filtered_json_carries_total_count(settings):
    route = get(f"{POLICIES_URL}/devices/1", DEVICES_FILTERED)
    text = await call_tool_text(
        build(settings),
        "cnc_list_performance_policy_devices",
        {
            "policy_id": 1,
            "host_name": "PE1",
            "ip_address": "10.0.0.1",
            "reachability_state": "reachable",
            "collection_status": "active",
            "response_format": "json",
        },
    )
    assert params_of(route) == {
        "pageSize": "50",
        "page": "1",
        "hostName": "PE1",
        "ipAddress": "10.0.0.1",
        "reachabilityState": "CONN_STATE_REACHABLE",
        "collectionStatus": "ACTIVE",
    }
    data = json.loads(text)
    assert data["policy_id"] == 1 and data["total"] == 1 and data["count"] == 1
    assert data["page"] == 1 and data["page_size"] == 50
    assert data["has_more"] is False and data["next_page"] is None
    assert data["items"][0] == {
        "host_name": "PE1",
        "ip_address": "10.0.0.1",
        "uuid": PE1_UUID,
        "reachability_state": "CONN_STATE_REACHABLE",
        "admin_state": "ROBOT_ADMIN_STATE_UP",
        "collection_status": "ACTIVE",
        "product_type": "Cisco XRd Virtual Router",
        "gateway_name": "EMBEDDED_DEF_POOL-1",
        "last_update_at": "2026-09-13T12:00:00Z",
        "selected": True,
        "comments": [],
    }


@respx.mock
async def test_list_policy_devices_empty_bad_filter_and_unknown_policy(settings):
    route = get(f"{POLICIES_URL}/devices/1", {"data": [], "total_count": 0})
    text = await call_tool_text(
        build(settings),
        "cnc_list_performance_policy_devices",
        {"policy_id": 1, "host_name": "ghost"},
    )
    assert text.startswith("No devices for policy 1 matching hostName=ghost on page 1.")
    text = await call_tool_text(
        build(settings),
        "cnc_list_performance_policy_devices",
        {"policy_id": 1, "collection_status": "polling"},
    )
    assert text.startswith("Error: Unknown collection_status 'polling'") and route.call_count == 1
    get(f"{POLICIES_URL}/devices/999", MISSING_POLICY_ID, 400)
    text = await call_tool_text(
        build(settings), "cnc_list_performance_policy_devices", {"policy_id": 999}
    )
    assert text.startswith("Error: no performance policy 999 (MISSING_POLICY_ID).")


# --- cnc_list_performance_policy_templates -------------------------------------


@respx.mock
async def test_list_policy_templates(settings):
    route = get(TEMPLATES_URL, TEMPLATES)
    text = await call_tool_text(build(settings), "cnc_list_performance_policy_templates", {})
    assert route.call_count == 1
    assert text.startswith(
        "# 3 performance policy templates\n\n## SRPOLICY (port groups not supported)\n"
    )
    assert (
        "- SRPOLICY (LSP traffic) — default 300 s, allowed 0/300/900/1800/3600 s: outBitRate "
        "(BITS_PER_SECOND), outPktsRate (PACKETS_PER_SECOND)\n"
    ) in text
    assert "\n## INTERFACE (port groups supported)\n- CEPMINTERFACE (Interface)" in text
    assert "\n## deviceHealth (port groups not supported)\n- CPU (CPU) — default 300 s" in text
    assert "top-N covers only: " + ", ".join(TOP_N_SCHEMAS) in text


@respx.mock
async def test_list_policy_templates_json(settings):
    get(TEMPLATES_URL, TEMPLATES)
    text = await call_tool_text(
        build(settings), "cnc_list_performance_policy_templates", {"response_format": "json"}
    )
    data = json.loads(text)
    assert data["count"] == 3
    device_health = data["templates"][2]
    assert device_health["template"] == "deviceHealth"
    assert device_health["port_group_supported"] is False
    assert device_health["schemas"] == {
        "CPU": {
            "cpuUtilization": {"unit": "PERCENTAGE", "min": "0", "max": "100", "tca_enabled": None}
        },
        "MEMORY": {
            "memoryUtilization": {
                "unit": "PERCENTAGE",
                "min": "0",
                "max": "100",
                "tca_enabled": None,
            }
        },
    }
    assert device_health["schemas_interval"]["CPU"]["defaultInterval"] == 300


@respx.mock
async def test_list_policy_templates_api_error(make_settings):
    route = respx.get(TEMPLATES_URL).mock(
        return_value=httpx.Response(403, json={"error": "Unauthorized request"})
    )
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_list_performance_policy_templates", {}
    )
    assert text.startswith("Error:") and "403" in text and route.call_count == 1


# --- cnc_get_performance_retention ---------------------------------------------


@respx.mock
async def test_get_retention(settings):
    all_route = get(RETENTION_ALL_URL, RETENTION_ALL)
    default_route = get(RETENTION_DEFAULT_URL, RETENTION_DEFAULT)
    text = await call_tool_text(build(settings), "cnc_get_performance_retention", {})
    assert all_route.call_count == 1 and default_route.call_count == 1
    lines = text.split("\n")
    assert lines[0] == "# Performance data retention (hours)"
    assert lines[2] == "Default: raw 24, hourly 168, daily 744, weekly 9072"
    assert lines[4].startswith("| display name | schema | policy type | raw |")
    assert lines[6] == "| DeviceEnvTemp | ENVTEMP | deviceHealth | 24 | 168 | 744 | 9072 | yes |"
    assert lines[7] == "| Interface | CEPMINTERFACE | INTERFACE | 24 | 168 | 744 | 9072 | no |"


@respx.mock
async def test_get_retention_json(settings):
    get(RETENTION_ALL_URL, RETENTION_ALL)
    get(RETENTION_DEFAULT_URL, RETENTION_DEFAULT)
    text = await call_tool_text(
        build(settings), "cnc_get_performance_retention", {"response_format": "json"}
    )
    data = json.loads(text)
    assert data["default"] == RETENTION_DEFAULT and data["count"] == 2
    assert data["schemas"][1] == {
        "display_name": "Interface",
        "schema": "CEPMINTERFACE",
        "policy_type": "INTERFACE",
        "raw_hours": 24,
        "hourly_hours": 168,
        "daily_hours": 744,
        "weekly_hours": 9072,
        "has_aggregation_option": False,
    }


@respx.mock
async def test_get_retention_fails_when_either_gathered_get_fails(make_settings):
    # dataretention/default answers a Spring 500 while /all succeeds: the tool is an error,
    # never a half-rendered answer (and a 500 with a sentence is the generic http_error).
    all_route = get(RETENTION_ALL_URL, RETENTION_ALL)
    default_route = respx.get(RETENTION_DEFAULT_URL).mock(
        return_value=httpx.Response(
            500,
            json=envelope("Request method 'GET' is not supported", "", status=500),
        )
    )
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_performance_retention", {}
    )
    assert text.startswith("Error: API request failed with status 500.")
    assert "not supported" in text
    assert all_route.call_count == 1 and default_route.call_count == 1
    # And the other way round.
    respx.get(RETENTION_ALL_URL).mock(
        return_value=httpx.Response(403, json={"error": "Unauthorized request"})
    )
    get(RETENTION_DEFAULT_URL, RETENTION_DEFAULT)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_performance_retention", {}
    )
    assert text.startswith("Error:") and "403" in text


# --- cnc_get_performance_health_settings ---------------------------------------


@respx.mock
async def test_get_health_settings(settings):
    route = get(HEALTH_URL, HEALTH_SETTINGS)
    text = await call_tool_text(build(settings), "cnc_get_performance_health_settings", {})
    assert route.call_count == 1
    assert text.startswith("# Performance health settings (2 template(s))\n\n## INTERFACE\n")
    assert (
        "- CEPMINTERFACE_ifInUtilization (PERCENTAGE): HEALTHY 0-50 | MINOR 50-75 | MAJOR 75-90 "
        "| CRITICAL 90-100\n"
    ) in text
    assert text.endswith(
        "## deviceHealth\n- CPU_cpuUtilization (PERCENTAGE): HEALTHY 0-60 | MAJOR 60-100"
    )


@respx.mock
async def test_get_health_settings_template_filter(settings):
    get(HEALTH_URL, HEALTH_SETTINGS)
    text = await call_tool_text(
        build(settings),
        "cnc_get_performance_health_settings",
        {"template": "devicehealth", "response_format": "json"},
    )
    assert json.loads(text) == {"deviceHealth": HEALTH_SETTINGS["deviceHealth"]}
    text = await call_tool_text(
        build(settings), "cnc_get_performance_health_settings", {"template": "QOS"}
    )
    assert text == (
        "Error: no health settings for template 'QOS'; templates: INTERFACE, deviceHealth."
    )


@respx.mock
async def test_get_health_settings_api_error(make_settings):
    route = respx.get(HEALTH_URL).mock(
        return_value=httpx.Response(403, json={"error": "Unauthorized request"})
    )
    text = await call_tool_text(
        build(make_settings(max_retries=0)),
        "cnc_get_performance_health_settings",
        {"template": "INTERFACE"},
    )
    assert text.startswith("Error:") and "403" in text and route.call_count == 1


# --- cnc_get_performance_statistics --------------------------------------------


@respx.mock
async def test_get_statistics_by_hours(settings):
    route = get(STATISTICS_URL, STATISTICS)
    text = await call_tool_text(
        build(settings), "cnc_get_performance_statistics", {"schema": "cepminterface"}
    )
    assert params_of(route) == {
        "schema": "CEPMINTERFACE",
        "timeInterval": "24",
        "units": "false",
        "pageSize": "50",
        "page": "1",
    }
    assert text == (
        "# CEPMINTERFACE statistics — last 24 h, page 1 (2 rows)\n\n"
        "- PE1 GigabitEthernet0/0/0/0: ifInBitsRate=1234.5, ifOutBitsRate=0\n"
        "- PE1 GigabitEthernet0/0/0/1: ifInBitsRate=42, ifOutBitsRate=7.25"
    )


@respx.mock
async def test_get_statistics_window_metrics_device_and_units(settings):
    route = get(STATISTICS_URL, STATISTICS_UNITS)
    text = await call_tool_text(
        build(settings),
        "cnc_get_performance_statistics",
        {
            "schema": "SRPOLICY",
            "metrics": "outBitRate, outPktsRate",
            "device_uuid": PE1_UUID,
            "from_time": "2026-09-13T00:00:00Z",
            "to_time": "2026-09-13T12:00:00Z",
            "with_units": True,
            "page_size": 1,
            "page": 1,
        },
    )
    assert params_of(route) == {
        "schema": "SRPOLICY",
        "from": "2026-09-13T00:00:00.000Z",
        "to": "2026-09-13T12:00:00.000Z",
        "metrics": "outBitRate,outPktsRate",
        "device": PE1_UUID,
        "units": "true",
        "pageSize": "1",
        "page": "1",
    }
    assert text == (
        "# SRPOLICY statistics — 2026-09-13T00:00:00.000Z to 2026-09-13T12:00:00.000Z, page 1 "
        f"(1 rows; metrics outBitRate, outPktsRate; device {PE1_UUID})\n\n"
        "- PE1 srte_c_100_ep_10.0.0.3 color=0: outBitRate=12.5 KBITS_PER_SECOND\n\n"
        "(page full: more may exist, call again with page=2)"
    )


@respx.mock
async def test_get_statistics_json(settings):
    get(STATISTICS_URL, STATISTICS)
    text = await call_tool_text(
        build(settings),
        "cnc_get_performance_statistics",
        {"schema": "CEPMINTERFACE", "hours": 6, "response_format": "json"},
    )
    data = json.loads(text)
    assert data["schema"] == "CEPMINTERFACE" and data["window"] == {"hours": 6}
    assert data["records"] == 2 and data["has_more"] is False and data["next_page"] is None
    assert data["entries"] == STATISTICS["entries"]


@respx.mock
async def test_get_statistics_no_records_is_not_an_error(settings):
    get(STATISTICS_URL, STATISTICS_EMPTY)
    text = await call_tool_text(
        build(settings), "cnc_get_performance_statistics", {"schema": "CPU", "page": 3}
    )
    assert text.startswith("No CPU statistics for last 24 h (page 3).")
    assert "cnc_list_performance_policies" in text


@respx.mock
async def test_get_statistics_unknown_schema_lists_the_known_ones(settings):
    get(STATISTICS_URL, INVALID_SCHEMA, 400)
    text = await call_tool_text(
        build(settings), "cnc_get_performance_statistics", {"schema": "bogus"}
    )
    assert text.startswith("Error: unknown performance schema 'BOGUS' (INVALID_SCHEMA).")
    assert "Schemas on 7.2: " + ", ".join(KNOWN_SCHEMAS) in text


@respx.mock
async def test_get_statistics_time_errors(settings):
    route = get(STATISTICS_URL, MISSING_TIME, 400)
    text = await call_tool_text(
        build(settings),
        "cnc_get_performance_statistics",
        {"schema": "CEPMINTERFACE", "from_time": "2026-09-13T00:00:00Z"},
    )
    assert text.startswith("Error: pass both from_time and to_time") and route.call_count == 0
    text = await call_tool_text(
        build(settings),
        "cnc_get_performance_statistics",
        {"schema": "CEPMINTERFACE", "from_time": "yesterday", "to_time": "2026-09-13T00:00:00Z"},
    )
    assert text.startswith("Error: from_time must be an ISO-8601 UTC timestamp")
    assert route.call_count == 0
    text = await call_tool_text(
        build(settings), "cnc_get_performance_statistics", {"schema": "CEPMINTERFACE"}
    )
    assert text.startswith("Error: the platform needs a time window (MISSING_TIME_DETAILS).")
    assert route.call_count == 1


@respx.mock
async def test_get_statistics_conversion_500_is_generic(make_settings):
    get(STATISTICS_URL, UNITS_500, 500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)),
        "cnc_get_performance_statistics",
        {"schema": "CEPMINTERFACE"},
    )
    assert text.startswith("Error: API request failed with status 500.") and "units" in text


# --- cnc_get_performance_top_n ---------------------------------------------------


@respx.mock
async def test_get_top_n(settings):
    route = get(TOPN_URL, TOPN)
    text = await call_tool_text(
        build(settings),
        "cnc_get_performance_top_n",
        {
            "metric": "CEPMINTERFACE_ifInUtilization",
            "from_time": "2026-09-13T00:00:00Z",
            "to_time": "2026-09-13T12:00:00Z",
            "sort": "-value",
            "severity": "healthy",
            "device_groups": "All Locations",
        },
    )
    assert params_of(route) == {
        "metric": "CEPMINTERFACE_ifInUtilization",
        "from": "2026-09-13T00:00:00.000Z",
        "to": "2026-09-13T12:00:00.000Z",
        "pageSize": "10",
        "page": "1",
        "sort": "-value",
        "severity": "HEALTHY",
        "deviceGroups": "All Locations",
    }
    assert text == (
        "# Top 10 CEPMINTERFACE_ifInUtilization (2026-09-13T00:00:00.000Z to "
        "2026-09-13T12:00:00.000Z, sort -value, severity HEALTHY, device groups All Locations)\n\n"
        "- PE1 GigabitEthernet0/0/0/0: avg 0.5, min 0, max 1.25 PERCENTAGE, HEALTHY\n"
        "- PE2 GigabitEthernet0/0/0/0: avg 0.25, min 0, max 0.5 PERCENTAGE"
    )


@respx.mock
async def test_get_top_n_json_and_empty(settings):
    route = get(TOPN_URL, TOPN)
    args = {
        "metric": "cpu_cpuUtilization",
        "from_time": "2026-09-13T00:00:00Z",
        "to_time": "2026-09-13T12:00:00Z",
        "page_size": 5,
        "page": 2,
    }
    text = await call_tool_text(
        build(settings), "cnc_get_performance_top_n", {**args, "response_format": "json"}
    )
    assert params_of(route)["metric"] == "CPU_cpuUtilization"
    assert params_of(route)["pageSize"] == "5" and params_of(route)["page"] == "2"
    data = json.loads(text)
    assert data["metric"] == "CPU_cpuUtilization" and data["count"] == 2
    assert data["results"] == TOPN and data["sort"] is None and data["device_groups"] == []
    get(TOPN_URL, [])
    text = await call_tool_text(build(settings), "cnc_get_performance_top_n", args)
    assert text.startswith(
        "No top-N entries for CPU_cpuUtilization between 2026-09-13T00:00:00.000Z and "
        "2026-09-13T12:00:00.000Z on page 2:"
    )


@respx.mock
async def test_get_top_n_unknown_schema_is_refused_before_the_request(settings):
    route = get(TOPN_URL, TOPN)
    text = await call_tool_text(
        build(settings),
        "cnc_get_performance_top_n",
        {
            "metric": "SRPOLICY_outBitRate",
            "from_time": "2026-09-13T00:00:00Z",
            "to_time": "2026-09-13T12:00:00Z",
        },
    )
    assert route.call_count == 0
    assert text.startswith(
        "Error: 'SRPOLICY_outBitRate' is not a top-N schema/metric — the token is "
        "<SCHEMA>_<exact metric name> and top-N covers only the schemas of "
        "cnc_list_performance_top_n_columns (" + ", ".join(TOP_N_SCHEMAS) + ")"
    )


@respx.mock
async def test_get_top_n_unknown_metric_is_the_platform_400(settings):
    get(TOPN_URL, INVALID_COMBO, 400)
    text = await call_tool_text(
        build(settings),
        "cnc_get_performance_top_n",
        {
            "metric": "CEPMINTERFACE_nope",
            "from_time": "2026-09-13T00:00:00Z",
            "to_time": "2026-09-13T12:00:00Z",
        },
    )
    assert text.startswith(
        "Error: 'CEPMINTERFACE_nope' is not a top-N schema/metric — the token is "
        "<SCHEMA>_<exact metric name> and top-N covers only the schemas of "
        "cnc_list_performance_top_n_columns ("
    )
    assert "(INVALID_SCHEMA_METRIC_COMBO)." in text


@respx.mock
async def test_get_top_n_bad_time_is_refused(settings):
    route = get(TOPN_URL, TOPN)
    text = await call_tool_text(
        build(settings),
        "cnc_get_performance_top_n",
        {
            "metric": "CEPMINTERFACE_ifInUtilization",
            "from_time": "2026-09-13T12:00:00Z",
            "to_time": "2026-09-13T00:00:00Z",
        },
    )
    assert text.startswith("Error: to_time must be after from_time") and route.call_count == 0


# --- cnc_list_performance_top_n_columns ----------------------------------------


@respx.mock
async def test_list_top_n_columns(settings):
    route = get(TOPN_COLUMNS_URL, TOPN_COLUMNS)
    text = await call_tool_text(build(settings), "cnc_list_performance_top_n_columns", {})
    assert route.call_count == 1
    assert text.startswith(
        "# 2 top-N schemas\n\n"
        "- CEPMINTERFACE: hostname (Device name), interfaceName (Interface name)\n"
        "- CPU: hostname (Device name), cpuName (CPU name)\n"
    )
    text = await call_tool_text(
        build(settings), "cnc_list_performance_top_n_columns", {"response_format": "json"}
    )
    assert json.loads(text) == TOPN_COLUMNS


@respx.mock
async def test_list_top_n_columns_api_error(make_settings):
    route = respx.get(TOPN_COLUMNS_URL).mock(
        return_value=httpx.Response(
            500, json=envelope("Something went wrong on the server", "", status=500)
        )
    )
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_list_performance_top_n_columns", {}
    )
    assert text.startswith("Error: API request failed with status 500.")
    assert route.call_count == 1


# --- cnc_get_performance_summary -------------------------------------------------


@respx.mock
async def test_get_summary(settings):
    route = get(SUMMARY_URL, SUMMARY)
    text = await call_tool_text(
        build(settings),
        "cnc_get_performance_summary",
        {
            "metric": "CEPMINTERFACE_ifInUtilization",
            "from_time": "2026-09-13T00:00:00Z",
            "to_time": "2026-09-13T04:00:00Z",
        },
    )
    assert params_of(route) == {
        "metric": "CEPMINTERFACE_ifInUtilization",
        "from": "2026-09-13T00:00:00.000Z",
        "to": "2026-09-13T04:00:00.000Z",
    }
    assert text == (
        "# ifInUtilization summary (PERCENTAGE), 2026-09-13T00:00:00.000Z to "
        "2026-09-13T04:00:00.000Z, 2 bucket(s)\n\n"
        "- 2026-09-13T00:00:00Z: avg 0.5, min 0, max 1\n"
        "- 2026-09-13T02:00:00Z: avg 0.75, min 0.1, max 2"
    )


@respx.mock
async def test_get_summary_json_and_empty_series(settings):
    get(SUMMARY_URL, SUMMARY_EMPTY)
    args = {
        "metric": "CPU_cpuUtilization",
        "from_time": "2026-09-13T00:00:00Z",
        "to_time": "2026-09-13T04:00:00Z",
    }
    text = await call_tool_text(
        build(settings), "cnc_get_performance_summary", {**args, "response_format": "json"}
    )
    data = json.loads(text)
    assert data["metric"] == "CPU_cpuUtilization"
    assert data["results"] == [
        {"metricName": "cpuUtilization", "metricUnit": "PERCENTAGE", "rows": []}
    ]
    text = await call_tool_text(build(settings), "cnc_get_performance_summary", args)
    assert text.startswith(
        "No summary data for CPU_cpuUtilization between 2026-09-13T00:00:00.000Z and "
        "2026-09-13T04:00:00.000Z:"
    )
    get(SUMMARY_URL, [])
    text = await call_tool_text(build(settings), "cnc_get_performance_summary", args)
    assert text.startswith("No summary data for CPU_cpuUtilization")


@respx.mock
async def test_get_summary_platform_400_and_bad_token(settings):
    route = get(SUMMARY_URL, INVALID_COMBO, 400)
    args = {"from_time": "2026-09-13T00:00:00Z", "to_time": "2026-09-13T04:00:00Z"}
    text = await call_tool_text(
        build(settings), "cnc_get_performance_summary", {**args, "metric": "CEPMINTERFACE_nope"}
    )
    assert text.startswith(
        "Error: 'CEPMINTERFACE_nope' is not a schema/metric the summary dashboard knows"
    )
    assert "(INVALID_SCHEMA_METRIC_COMBO)." in text
    text = await call_tool_text(
        build(settings), "cnc_get_performance_summary", {**args, "metric": "ifInUtilization"}
    )
    assert text.startswith("Error: metric must be a <SCHEMA>_<metric> token")
    assert route.call_count == 1


# --- cnc_get_lsp_utilization -----------------------------------------------------


@respx.mock
async def test_get_lsp_utilization_sr(settings):
    samples = post(f"{NPM_BASE}/lsp/utilizations", UTILIZATIONS)
    maximum = post(f"{NPM_BASE}/lsp/max/utilization", MAX_UTIL)
    text = await call_tool_text(
        build(settings),
        "cnc_get_lsp_utilization",
        {
            "headend": "10.0.0.1",
            "endpoint": "10.0.0.3",
            "color": 100,
            "from_time": FROM,
            "to_time": TO,
        },
    )
    assert sent(samples) == LSP_KEY_SR and sent(maximum) == LSP_KEY_SR
    assert sent(samples)["color"] == "100"  # a STRING on the wire (verified)
    assert text == (
        "# Utilization of SR LSP 10.0.0.1 -> 10.0.0.3 color 100, 2026-09-13T12:00:00Z to "
        "2026-09-13T18:00:00Z\n\n"
        "- max utilization (platform): 2.5 — Successfully found Maximum Utilization\n"
        "- 2 sample(s) (2026-09-13T12:01:36Z to 2026-09-13T12:06:36Z): util avg 1.25, min 0, "
        "max 2.5, last 2.5\n\n"
        "## Samples (2 sample(s))\n"
        "- 2026-09-13T12:01:36Z: util 0\n"
        "- 2026-09-13T12:06:36Z: util 2.5"
    )


@respx.mock
async def test_get_lsp_utilization_rsvp_json(settings):
    samples = post(f"{NPM_BASE}/lsp/utilizations", UTILIZATIONS)
    post(f"{NPM_BASE}/lsp/max/utilization", MAX_UTIL)
    text = await call_tool_text(
        build(settings),
        "cnc_get_lsp_utilization",
        {
            "headend": "10.0.0.1",
            "endpoint": "10.0.0.3",
            "tunnel_id": "11",
            "from_time": "2026-09-13T12:00:00.000Z",
            "to_time": TO,
            "response_format": "json",
        },
    )
    assert sent(samples) == LSP_KEY_RSVP
    data = json.loads(text)
    assert data["lsp"] == LSP_KEY_RSVP and data["max"] == MAX_UTIL
    assert data["samples"] == UTILIZATIONS and data["stats"]["count"] == 2


@respx.mock
async def test_get_lsp_utilization_empty_carries_the_caveat(settings):
    samples = post(f"{NPM_BASE}/lsp/utilizations", [])
    post(f"{NPM_BASE}/lsp/max/utilization", MAX_UTIL_ZERO)
    text = await call_tool_text(
        build(settings),
        "cnc_get_lsp_utilization",
        {
            "headend": "10.0.0.1",
            "endpoint": "10.0.0.9",
            "color": 200,
            "from_time": FROM,
            "to_time": TO,
        },
    )
    assert text.startswith(
        "No LSP utilization samples for SR LSP 10.0.0.1 -> 10.0.0.9 color 200 between "
        "2026-09-13T12:00:00Z and 2026-09-13T18:00:00Z (an unknown key answers the same empty "
        "list). " + NPM_EMPTY_CAVEAT
    )
    assert "cnc_list_sr_policies" in text and "cnc_list_rsvp_te_tunnels" in text
    assert sent(samples)["color"] == "200"


@respx.mock
async def test_get_lsp_utilization_refuses_color_0_for_sr(settings):
    """No SR policy has color 0 and NPM would answer the same [] for it: the default
    color without a tunnel_id is an error before anything is sent (json form too)."""
    samples = post(f"{NPM_BASE}/lsp/utilizations", [])
    maximum = post(f"{NPM_BASE}/lsp/max/utilization", MAX_UTIL_ZERO)
    args = {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "from_time": FROM, "to_time": TO}
    for extra in ({}, {"color": 0}, {"response_format": "json"}):
        text = await call_tool_text(build(settings), "cnc_get_lsp_utilization", {**args, **extra})
        assert text.startswith("Error: color is required for an SR policy"), extra
        assert "cnc_list_sr_policies" in text and "Nothing was sent" in text, extra
    assert samples.call_count == 0 and maximum.call_count == 0
    # A tunnel_id switches to RSVP, where the color is irrelevant.
    text = await call_tool_text(
        build(settings), "cnc_get_lsp_utilization", {**args, "tunnel_id": "11"}
    )
    assert text.startswith("No LSP utilization samples for RSVP LSP 10.0.0.1 -> 10.0.0.3 tunnel 11")
    assert sent(samples) == LSP_KEY_RSVP


@respx.mock
async def test_get_lsp_utilization_host_name_and_api_error(make_settings):
    samples = post(f"{NPM_BASE}/lsp/utilizations", UTILIZATIONS)
    text = await call_tool_text(
        build(make_settings()),
        "cnc_get_lsp_utilization",
        {
            "headend": "PE1",
            "endpoint": "10.0.0.3",
            "from_time": FROM,
            "to_time": TO,
        },
    )
    assert text.startswith("Error: headend must be a TE router-id")
    assert samples.call_count == 0
    respx.post(f"{NPM_BASE}/lsp/utilizations").mock(return_value=NPM_500)
    respx.post(f"{NPM_BASE}/lsp/max/utilization").mock(return_value=NPM_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)),
        "cnc_get_lsp_utilization",
        {
            "headend": "10.0.0.1",
            "endpoint": "10.0.0.3",
            "color": 100,
            "from_time": FROM,
            "to_time": TO,
        },
    )
    assert text.startswith("Error: API request failed with status 500.")


# --- cnc_get_lsp_delay -----------------------------------------------------------


@respx.mock
async def test_get_lsp_delay(settings):
    delay = post(f"{NPM_BASE}/lsp/delay", LSP_DELAY)
    maximum = post(f"{NPM_BASE}/lsp/max/delay", MAX_DELAY)
    variance = post(f"{NPM_BASE}/lsp/delayVariance", DELAY_VARIANCE)
    loss = post(f"{NPM_BASE}/lsp/loss", [])
    text = await call_tool_text(
        build(settings),
        "cnc_get_lsp_delay",
        {
            "headend": "10.0.0.1",
            "endpoint": "10.0.0.3",
            "color": 100,
            "from_time": FROM,
            "to_time": TO,
        },
    )
    for route in (delay, maximum, variance, loss):
        assert sent(route) == LSP_KEY_SR
    assert text.startswith(
        "# Delay and loss of SR LSP 10.0.0.1 -> 10.0.0.3 color 100, 2026-09-13T12:00:00Z to "
        "2026-09-13T18:00:00Z\n\n"
        "- max average delay (platform): 5 — Successfully found Maximum Average Delay\n"
        "- delay: 1 sample(s) (2026-09-13T12:01:36Z to 2026-09-13T12:01:36Z): averageDelay avg 5, "
        "min 5, max 5, last 5\n\n"
        "## Delay (1 sample(s))\n"
        "- 2026-09-13T12:01:36Z: preferenceId 100, minimumDelay 2, maximumDelay 8, averageDelay 5, "
        "delayVariance 6\n\n"
        "## Delay variance (1 sample(s))\n"
        "- 2026-09-13T12:01:36Z: delayVariance 6\n\n"
        "## Loss (0 sample(s))\n"
        "(no samples)\n\n"
        "(An empty series: " + NPM_EMPTY_CAVEAT
    )


@respx.mock
async def test_get_lsp_delay_all_empty_and_json(settings):
    post(f"{NPM_BASE}/lsp/delay", [])
    post(f"{NPM_BASE}/lsp/max/delay", MAX_DELAY_NONE)
    post(f"{NPM_BASE}/lsp/delayVariance", [])
    post(f"{NPM_BASE}/lsp/loss", [])
    args = {
        "headend": "10.0.0.1",
        "endpoint": "10.0.0.3",
        "tunnel_id": "11",
        "from_time": FROM,
        "to_time": TO,
    }
    text = await call_tool_text(build(settings), "cnc_get_lsp_delay", args)
    assert text.startswith(
        "No LSP delay, delay-variance or loss samples for RSVP LSP 10.0.0.1 -> 10.0.0.3 tunnel 11 "
        "between 2026-09-13T12:00:00Z and 2026-09-13T18:00:00Z (an unknown key answers the same "
        "empty lists). " + NPM_EMPTY_CAVEAT
    )
    assert text.endswith(
        "Max average delay (platform): no data (Maximum Average Delay for given "
        "Interface not present..returning default delay!)."
    )
    text = await call_tool_text(
        build(settings), "cnc_get_lsp_delay", {**args, "response_format": "json"}
    )
    assert json.loads(text) == {
        "lsp": LSP_KEY_RSVP,
        "max_delay": MAX_DELAY_NONE,
        "delay": [],
        "delay_variance": [],
        "loss": [],
    }


@respx.mock
async def test_get_lsp_delay_host_name_color_0_and_api_error(make_settings):
    routes = [
        post(f"{NPM_BASE}/lsp/delay", LSP_DELAY),
        post(f"{NPM_BASE}/lsp/max/delay", MAX_DELAY),
        post(f"{NPM_BASE}/lsp/delayVariance", DELAY_VARIANCE),
        post(f"{NPM_BASE}/lsp/loss", []),
    ]
    good = {"headend": "10.0.0.1", "endpoint": "10.0.0.3", "from_time": FROM, "to_time": TO}
    # A host name is refused before any of the four POSTs is sent.
    text = await call_tool_text(
        build(make_settings()), "cnc_get_lsp_delay", {**good, "headend": "PE1", "color": 100}
    )
    assert text.startswith("Error: headend must be a TE router-id")
    assert "cnc_list_sr_policies" in text
    text = await call_tool_text(
        build(make_settings()), "cnc_get_lsp_delay", {**good, "endpoint": "PE3", "color": 100}
    )
    assert text.startswith("Error: endpoint must be a TE router-id")
    # So is the default color 0 without a tunnel_id.
    text = await call_tool_text(build(make_settings()), "cnc_get_lsp_delay", good)
    assert text.startswith("Error: color is required for an SR policy")
    for route in routes:
        assert route.call_count == 0
    # An NPM failure (the problem+json 500) is an error, not an empty answer.
    for route in routes:
        route.mock(return_value=NPM_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_lsp_delay", {**good, "color": 100}
    )
    assert text.startswith("Error: API request failed with status 500.")
    assert "Failed to map json" in text


# --- cnc_get_interface_delay -----------------------------------------------------


@respx.mock
async def test_get_interface_delay(settings):
    delays = post(f"{NPM_BASE}/interface/delays", INTERFACE_DELAYS)
    maximum = post(f"{NPM_BASE}/interface/max/delay", MAX_DELAY)
    loss = post(f"{NPM_BASE}/interface/loss", [{"loss": 0.5, "tst": "2026-09-13T12:01:36Z"}])
    text = await call_tool_text(
        build(settings),
        "cnc_get_interface_delay",
        {
            "device_uuid": PE1_UUID,
            "interface": "GigabitEthernet0/0/0/0",
            "from_time": FROM,
            "to_time": TO,
        },
    )
    for route in (delays, maximum, loss):
        assert sent(route) == INTERFACE_KEY
    assert text == (
        f"# Delay and loss of GigabitEthernet0/0/0/0 on {PE1_UUID}, 2026-09-13T12:00:00Z to "
        "2026-09-13T18:00:00Z\n\n"
        "- max average delay (platform): 5 — Successfully found Maximum Average Delay\n"
        "- delay: 1 sample(s) (2026-09-13T12:01:36Z to 2026-09-13T12:01:36Z): averageDelay avg 5, "
        "min 5, max 5, last 5\n\n"
        "## Delay (1 sample(s))\n"
        "- 2026-09-13T12:01:36Z: minimumDelay 2, maximumDelay 8, averageDelay 5, "
        "delayVariance 6\n\n"
        "## Loss (1 sample(s))\n"
        "- 2026-09-13T12:01:36Z: loss 0.5"
    )


@respx.mock
async def test_get_interface_delay_empty_json_and_missing_interface(settings):
    delays = post(f"{NPM_BASE}/interface/delays", [])
    post(f"{NPM_BASE}/interface/max/delay", MAX_DELAY_NONE)
    post(f"{NPM_BASE}/interface/loss", [])
    args = {
        "device_uuid": PE1_UUID,
        "interface": "GigabitEthernet0/0/0/0",
        "from_time": FROM,
        "to_time": TO,
    }
    text = await call_tool_text(build(settings), "cnc_get_interface_delay", args)
    assert text.startswith(
        f"No delay or loss samples for GigabitEthernet0/0/0/0 on {PE1_UUID} between "
        "2026-09-13T12:00:00Z and 2026-09-13T18:00:00Z (an unknown uuid or interface name answers "
        "the same empty lists). " + NPM_EMPTY_CAVEAT
    )
    assert "returning default delay!" in text
    text = await call_tool_text(
        build(settings), "cnc_get_interface_delay", {**args, "response_format": "json"}
    )
    assert json.loads(text) == {
        "interface": INTERFACE_KEY,
        "max_delay": MAX_DELAY_NONE,
        "delay": [],
        "loss": [],
    }
    text = await call_tool_text(
        build(settings), "cnc_get_interface_delay", {**args, "interface": "  "}
    )
    assert text.startswith("Error: device_uuid") and "both required" in text
    assert delays.call_count == 2


@respx.mock
async def test_get_interface_delay_refuses_a_host_name_and_reports_api_errors(make_settings):
    routes = [
        post(f"{NPM_BASE}/interface/delays", INTERFACE_DELAYS),
        post(f"{NPM_BASE}/interface/max/delay", MAX_DELAY),
        post(f"{NPM_BASE}/interface/loss", []),
    ]
    args = {"interface": "GigabitEthernet0/0/0/0", "from_time": FROM, "to_time": TO}
    # A host name or IP where the inventory uuid belongs never reaches NPM (which would
    # answer the indistinguishable [] — verified live: the service never validates).
    for bad in ("PE1", "10.0.0.1"):
        text = await call_tool_text(
            build(make_settings()), "cnc_get_interface_delay", {**args, "device_uuid": bad}
        )
        assert text.startswith("Error: device_uuid must be the device's inventory uuid"), bad
        assert f"cnc_get_device(host_name='{bad}')" in text and "Nothing was sent" in text
    for route in routes:
        assert route.call_count == 0
    # Any uuid spelling is accepted and sent canonical.
    text = await call_tool_text(
        build(make_settings()),
        "cnc_get_interface_delay",
        {**args, "device_uuid": f"{{{PE1_UUID.upper()}}}", "response_format": "json"},
    )
    assert json.loads(text)["interface"] == INTERFACE_KEY
    for route in routes:
        assert sent(route) == INTERFACE_KEY
    # An NPM failure is an error, not an empty answer.
    for route in routes:
        route.mock(return_value=NPM_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)),
        "cnc_get_interface_delay",
        {**args, "device_uuid": PE1_UUID},
    )
    assert text.startswith("Error: API request failed with status 500.")
