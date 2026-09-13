"""Fault tools end-to-end through MCPServer (schema validation included).

The module is registered directly (not through build_server) so the test does
not depend on tools/__init__.py's module list. All HTTP is mocked with respx.
Fixtures mirror the shapes verified live on Crosswork 7.2 (2026-09-13, see the
platform notes "Fault APIs"): the alarms/v1 alarm with AckHist/Notes, the event,
the lifecycle {state, Message} answers, the alarm/v1 settings, severity-config
items, recommended-action and suppression-policy documents, and the EMPTY
rtm:alarm envelope (com.lastIndex -1, no com.data).
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
from cnc_mcp.tools import fault
from cnc_mcp.tools.fault import (
    ALARM_STATES,
    ALL_ALARMS_CRITERIA,
    canonical,
    check_lifecycle,
    check_query,
    filter_alarms,
    filter_event_types,
    filter_events,
    find_alarm,
)
from tests.conftest import BASE_URL, call_tool_text

ALARMS_V1 = f"{BASE_URL}/crosswork/alarms/v1"
ALARM_V1 = f"{BASE_URL}/crosswork/alarm/v1"
QUERY_URL = f"{ALARMS_V1}/query"
EVENTS_URL = f"{ALARMS_V1}/event/query"
ACK_URL = f"{ALARMS_V1}/ack"
NOTE_URL = f"{ALARMS_V1}/note"
CLEAR_URL = f"{ALARMS_V1}/clear"
SETTINGS_URL = f"{ALARM_V1}/settings"
GNMI_URL = f"{ALARM_V1}/gnmi/settings"
MANAGER_URL = f"{ALARM_V1}/manager/settings"
SEVERITY_URL = f"{ALARM_V1}/severity-config"
RECOMMENDED_URL = f"{ALARM_V1}/recommended-action"
POLICY_URL = f"{ALARM_V1}/suppressionpolicy"
RTM_URL = f"{BASE_URL}/crosswork/alarm/restconf/data/v2/rtm:alarm"

NATS_500 = httpx.Response(500, json={"error": "NATS request failed"})

ALARM_ID = "5b7d0a2e-3c1f-4e8a-9b6d-2f1e0c9a8b7d"
P2_UUID = "c4e1f0a2-7b3d-4c5e-8f9a-0b1c2d3e4f5a"

# Verified alarm shape (alarms/v1/query), with AckHist and Notes.
ALARM = {
    "AlarmId": ALARM_ID,
    "AlarmCategory": "System",
    "State": "Major",
    "Acknowledge": False,
    "Description": "Device P2 is unreachable",
    "object_id": P2_UUID,
    "object_description": f"Device P2 ({P2_UUID})",
    "origin_app_id": "capp-infra:DLM",
    "origin_service_id": "dlm",
    "event_type": 1001,
    "events_count": 2,
    "Created": "1757750400000",
    "Updated": "1757754000000",
    "Events": [
        {
            "EventId": "e-1",
            "EventSeverity": "Major",
            "Description": "SNMP timeout",
            "Timestamp": "1757750400000",
            "EventCategory": "System",
            "alarm_id": ALARM_ID,
            "Flagging": False,
        },
        {
            "EventId": "e-2",
            "EventSeverity": "Major",
            "Description": "SSH timeout",
            "Timestamp": "1757754000000",
            "EventCategory": "System",
            "alarm_id": ALARM_ID,
            "Flagging": False,
        },
    ],
    "AckHist": [
        {"CreatedBy": "admin", "Description": "Ack", "Timestamp": "1757751000000"},
        {"CreatedBy": "admin", "Description": "UnAck", "Timestamp": "1757752000000"},
    ],
    "Notes": [
        {"CreatedBy": "admin", "Description": "checked by ops", "Timestamp": "1757753000000"}
    ],
}
ALARM_ACKED = {
    "AlarmId": "a-2",
    "AlarmCategory": "System",
    "State": "Critical",
    "Acknowledge": True,
    "Description": "Collection job failed",
    "object_id": "cdg-1",
    "object_description": "Data Gateway dg-01",
    "origin_app_id": "capp-infra:CDG",
    "origin_service_id": "cdg",
    "event_type": 2002,
    "events_count": 1,
    "Created": "1757740000000",
    "Updated": "1757740000000",
    "Events": [],
    "AckHist": [{"CreatedBy": "admin", "Description": "Ack", "Timestamp": "1757741000000"}],
    "Notes": [],
}
ALARM_CLEARED = {
    "AlarmId": "a-3",
    "AlarmCategory": "System",
    "State": "Clear",
    "Acknowledge": False,
    "Description": "Device P1 is unreachable",
    "object_id": "p1",
    "object_description": "Device P1 (p1)",
    "origin_app_id": "capp-infra:DLM",
    "origin_service_id": "dlm",
    "event_type": 1001,
    "events_count": 2,
    "Created": "1757700000000",
    "Updated": "1757760000000",
    "Events": [],
    "AckHist": [],
    "Notes": [],
}
ALL_ALARMS = {"state": "Success", "alarms": [ALARM_ACKED, ALARM, ALARM_CLEARED]}

# Verified event shape (alarms/v1/event/query).
EVENT = {
    "EventId": "e-1",
    "alarm_id": ALARM_ID,
    "EventSeverity": "Major",
    "EventCategory": "System",
    "Description": "SNMP timeout",
    "Timestamp": "1757750400000",
    "object_description": f"Device P2 ({P2_UUID})",
    "origin_app_id": "capp-infra:DLM",
    "event_type": 1001,
}
EVENT_CLEAR = {
    "EventId": "e-9",
    "alarm_id": "a-3",
    "EventSeverity": "Clear",
    "EventCategory": "System",
    "Description": "Device P1 is reachable",
    "Timestamp": "1757760000000",
    "object_description": "Device P1 (p1)",
    "origin_app_id": "capp-infra:DLM",
    "event_type": 1001,
}

# Verified alarm/v1 settings documents.
SETTINGS = {
    "deleteOldAlertDays": 30,
    "networkAlertAgeout": 7,
    "systemAlertAgeout": 7,
    "auditAlertAgeout": 90,
    "securityAlertAgeout": 90,
    "nonSecurityAlertAgeout": 30,
    "syslogCollectionJobEnable": True,
    "trapCollectionJobEnable": False,
    "deleteAllEvents": False,
}
GNMI = {"Cisco Systems": False}
MANAGER = {
    "alarmManager/Cisco IOS XR": True,
    "alarmManager/Cisco NX-OS": False,
    "alarmManager/Cisco IOS XE": True,
}
SEVERITY_ITEMS = {
    "items": [
        {
            "severity": "Major",
            "defaultCategory": "BGP",
            "name": "BGP-5-ADJCHANGE_DOWN",
            "eventTypeName": "BGP-5-ADJCHANGE_DOWN",
            "revert": "15",
        },
        {
            "severity": "Clear",
            "defaultCategory": "BGP",
            "name": "BGP-5-ADJCHANGE_UP",
            "eventTypeName": "BGP-5-ADJCHANGE_UP",
        },
        {
            "severity": "Critical",
            "defaultCategory": "Interface",
            "name": "LINK-3-UPDOWN_DOWN",
            "eventTypeName": "LINK-3-UPDOWN_DOWN",
        },
    ]
}
RECOMMENDATION = {
    "defaultexplaination": "A BGP neighbor session went down.",
    "defaultrecommendedaction": "Check the neighbor and the link.",
    "erroreventype": "",
    "explaination": "",
    "nextstepupdate": "",
    "recommendedaction": "",
}
POLICY = {
    "policyname": "suppress-bgp-flaps",
    "description": "Planned maintenance",
    "action": "suppressAlarm",
    "deviceGroups": ["g-1", "g-2"],
    "criteria": "eventType in [BGP-5-ADJCHANGE_DOWN,BGP-5-ADJCHANGE_UP]",
    "inputType": "ap",
}

# Verified live: rtm:alarm on a lab with no device alarms — lastIndex -1, no com.data.
EMPTY_RTM = {
    "com.response-message": {
        "com.header": {"com.firstIndex": 0, "com.lastIndex": -1, "com.iteratorId": 0}
    }
}
# Documented device alarm (restconf_fault_ap_is_7_2_0.json GetDeviceAlarmJson, trimmed).
RTM_ALARM = {
    "com.response-message": {
        "com.header": {"com.firstIndex": 0, "com.lastIndex": 0, "com.iteratorId": 5},
        "com.data": {
            "alm.alarm": [
                {
                    "alm.alarm-identifier": {
                        "alm.event-identifier": "6a664005-0b24-43a7-aafa-64a399140209",
                        "alm.resource-object-ref": "MD=CISCO_EMS!ND=NCS4200-42!FTP=name=Gi0/1/7",
                        "alm.probable-cause": "OSPFv3-5-ADJCHG_DOWN",
                    },
                    "alm.uuid": "6a664005-0b24-43a7-aafa-64a399140209",
                    "alm.type": "device",
                    "alm.perceived-severity": "major",
                    "alm.description": "Nbr 192.168.0.41 on GigabitEthernet0/1/7 from 2WAY to DOWN",
                    "alm.category": "OSPF",
                    "alm.source-object-name": "GigabitEthernet0/1/7",
                    "alm.node-ref": "NCS4200-42",
                    "alm.ack-state": "acknowledged",
                    "alm.system-update-time-iso8601": "2024-10-04T10:01:10.981Z",
                    "alm.probable-cause": "OSPFv3-5-ADJCHG_DOWN",
                }
            ]
        },
    }
}

READ_TOOLS = {
    "cnc_get_alarm",
    "cnc_search_alarms",
    "cnc_list_events",
    "cnc_list_device_alarms",
    "cnc_get_alarm_settings",
    "cnc_get_alarm_manager_settings",
    "cnc_list_event_types",
    "cnc_get_event_type_recommendation",
    "cnc_list_alarm_suppression_policies",
}
WRITE_TOOLS = {
    "cnc_acknowledge_alarm",
    "cnc_annotate_alarm",
    "cnc_clear_alarm",
    "cnc_create_alarm_suppression_policy",
    "cnc_delete_alarm_suppression_policy",
}


def build(settings: Settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    fault.register(mcp, ctx)
    return mcp


def writable(make_settings, **overrides) -> MCPServer:
    return build(make_settings(enable_writes=True, **overrides))


def sent(route: respx.Route, index: int = 0) -> dict:
    return json.loads(route.calls[index].request.content)


def mock_all_alarms(body: dict | None = None) -> respx.Route:
    return respx.post(QUERY_URL).mock(return_value=httpx.Response(200, json=body or ALL_ALARMS))


# --- registration / gating ---------------------------------------------------


async def test_write_tools_hidden_unless_enabled(make_settings):
    names = {t.name for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert names == READ_TOOLS
    names = {t.name for t in await writable(make_settings).list_tools()}
    assert names == READ_TOOLS | WRITE_TOOLS


async def test_annotations(make_settings):
    tools = {t.name: t for t in await writable(make_settings).list_tools()}
    for name in READ_TOOLS:
        assert tools[name].annotations.read_only_hint is True, name
        assert tools[name].annotations.idempotent_hint is True, name
        assert tools[name].annotations.destructive_hint is False, name
    for name in WRITE_TOOLS:
        assert tools[name].annotations.read_only_hint is False, name
    ann = {n: tools[n].annotations for n in WRITE_TOOLS}
    # Every accepted ack is recorded in AckHist and a repeated ack is unverified live.
    assert ann["cnc_acknowledge_alarm"].idempotent_hint is False
    assert ann["cnc_acknowledge_alarm"].destructive_hint is False
    assert ann["cnc_annotate_alarm"].idempotent_hint is False
    assert ann["cnc_clear_alarm"].destructive_hint is True
    assert ann["cnc_clear_alarm"].idempotent_hint is True
    assert ann["cnc_create_alarm_suppression_policy"].idempotent_hint is False
    assert ann["cnc_create_alarm_suppression_policy"].destructive_hint is False
    assert ann["cnc_delete_alarm_suppression_policy"].destructive_hint is True
    assert ann["cnc_delete_alarm_suppression_policy"].idempotent_hint is True


# --- pure helpers ------------------------------------------------------------


def test_find_alarm_is_exact_and_case_insensitive():
    assert find_alarm(ALL_ALARMS["alarms"], ALARM_ID.upper()) is ALARM
    assert find_alarm(ALL_ALARMS["alarms"], ALARM_ID[:8]) is None
    assert find_alarm([None, "junk"], ALARM_ID) is None


def test_filter_alarms_sorts_newest_updated_first():
    assert [a["AlarmId"] for a in filter_alarms(ALL_ALARMS["alarms"])] == ["a-3", ALARM_ID, "a-2"]
    assert [a["AlarmId"] for a in filter_alarms(ALL_ALARMS["alarms"], acknowledged=True)] == ["a-2"]
    assert [a["AlarmId"] for a in filter_alarms(ALL_ALARMS["alarms"], text="p2 (")] == [ALARM_ID]


def test_canonical_is_case_insensitive_and_blank_is_none():
    assert canonical("critical", ALARM_STATES, "alarm state") == "Critical"
    assert canonical("  MAJOR ", ALARM_STATES, "alarm state") == "Major"
    assert canonical(None, ALARM_STATES, "alarm state") is None
    assert canonical("   ", ALARM_STATES, "alarm state") is None
    with pytest.raises(PlatformError, match="Unknown alarm state 'Severe'. Use one of: Critical"):
        canonical("Severe", ALARM_STATES, "alarm state")


def test_check_query_accepts_success_and_rejects_the_rest():
    assert check_query(ALL_ALARMS, "Alarm query") is ALL_ALARMS
    assert check_query({"state": "Success"}, "Event query") == {"state": "Success"}
    assert check_query([], "Alarm query") == {}  # a non-dict body is treated as empty
    with pytest.raises(PlatformError, match="Alarm query failed: state Failure.*bad criteria"):
        check_query({"state": "Failure", "Message": "bad criteria"}, "Alarm query")
    with pytest.raises(PlatformError, match="Input Request is invalid"):
        check_query({"error": "Fail", "code": 0, "message": "Input Request is invalid"}, "Ack")


def test_filter_events_severity_category_and_text():
    events = [EVENT, EVENT_CLEAR, "junk", None]
    assert filter_events(events) == [EVENT, EVENT_CLEAR]
    assert filter_events(events, severity="clear") == [EVENT_CLEAR]
    assert filter_events(events, category="SYSTEM", text="p1 (p1)") == [EVENT_CLEAR]
    assert filter_events(events, text="snmp") == [EVENT]
    assert filter_events(events, severity="major", text="reachable") == []


def test_filter_event_types_category_name_and_severity():
    items = SEVERITY_ITEMS["items"]
    assert [i["name"] for i in filter_event_types(items, category="bgp")] == [
        "BGP-5-ADJCHANGE_DOWN",
        "BGP-5-ADJCHANGE_UP",
    ]
    assert [i["name"] for i in filter_event_types(items, name="updown")] == ["LINK-3-UPDOWN_DOWN"]
    assert [i["name"] for i in filter_event_types(items, severity="clear")] == [
        "BGP-5-ADJCHANGE_UP"
    ]
    assert filter_event_types([*items, None], category="bgp", severity="critical") == []


def test_check_lifecycle_verified_answers():
    assert check_lifecycle({"state": "Success", "Message": "admin"}, "Ack")["Message"] == "admin"
    with pytest.raises(PlatformError, match="Alarm is already cleared\\.$"):
        check_lifecycle({"state": "Fail", "Message": "Alarm is already cleared. "}, "Clear")
    with pytest.raises(PlatformError, match="Input Request is invalid"):
        check_lifecycle({"error": "Fail", "code": 0, "message": "Input Request is invalid"}, "Ack")
    with pytest.raises(PlatformError, match="did not return a state envelope"):
        check_lifecycle({"ok": True}, "Ack")


# --- cnc_get_alarm -----------------------------------------------------------


@respx.mock
async def test_get_alarm_uses_the_no_limit_criteria_and_renders_history(settings):
    route = mock_all_alarms()
    text = await call_tool_text(build(settings), "cnc_get_alarm", {"alarm_id": ALARM_ID})
    assert sent(route) == {"openAlarmsOnly": False, "criteria": ALL_ALARMS_CRITERIA}
    assert ALL_ALARMS_CRITERIA == "select * from alarm"
    assert f"# Alarm {ALARM_ID}" in text
    assert "- State: Major (category System)" in text
    assert "- Acknowledged: False" in text
    assert f"- Object: Device P2 ({P2_UUID}) (object_id {P2_UUID})" in text
    assert "- Created: 2025-09-13T08:00:00Z — Updated: 2025-09-13T09:00:00Z" in text
    assert "- Events: 2" in text and "[Major] SNMP timeout (e-1, 2025-09-13T08:00:00Z)" in text
    assert "## Acknowledgement history (2)" in text
    assert "- 2025-09-13T08:10:00Z admin: Ack" in text
    assert "- 2025-09-13T08:26:40Z admin: UnAck" in text
    assert "## Notes (1)" in text and "admin: checked by ops" in text


@respx.mock
async def test_get_alarm_json_is_the_raw_alarm_and_finds_cleared_ones(settings):
    mock_all_alarms()
    text = await call_tool_text(
        build(settings), "cnc_get_alarm", {"alarm_id": "A-3", "response_format": "json"}
    )
    assert json.loads(text) == ALARM_CLEARED


@respx.mock
async def test_get_alarm_unknown_id_is_not_found_error(settings):
    mock_all_alarms()
    text = await call_tool_text(build(settings), "cnc_get_alarm", {"alarm_id": "nope"})
    assert text == "Error: no alarm 'nope' (list with cnc_list_alarms)"


@respx.mock
async def test_get_alarm_non_success_state_is_error(settings):
    mock_all_alarms({"state": "Failure", "Message": "bad criteria"})
    text = await call_tool_text(build(settings), "cnc_get_alarm", {"alarm_id": ALARM_ID})
    assert text.startswith("Error:") and "bad criteria" in text


@respx.mock
async def test_get_alarm_singular_base_error_document_is_error(settings):
    mock_all_alarms({"error": "Fail", "code": 0, "message": "Input Request is invalid"})
    text = await call_tool_text(build(settings), "cnc_get_alarm", {"alarm_id": ALARM_ID})
    assert text.startswith("Error:") and "Input Request is invalid" in text


@respx.mock
async def test_get_alarm_http_error_is_string(make_settings):
    respx.post(QUERY_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_alarm", {"alarm_id": ALARM_ID}
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_search_alarms -------------------------------------------------------


@respx.mock
async def test_search_alarms_filters_sorts_and_caps_client_side(settings):
    route = mock_all_alarms()
    text = await call_tool_text(
        build(settings), "cnc_search_alarms", {"text": "UNREACHABLE", "open_only": False}
    )
    assert sent(route) == {"openAlarmsOnly": False, "criteria": ALL_ALARMS_CRITERIA}
    lines = [line for line in text.splitlines() if line.startswith("- [")]
    # Newest Updated first: the cleared P1 alarm (Updated 1757760000000) before P2.
    assert lines == [
        "- [Clear] Device P1 (p1) — Device P1 is unreachable (a-3, ack=False, "
        "updated=2025-09-13T10:40:00Z)",
        f"- [Major] Device P2 ({P2_UUID}) — Device P2 is unreachable ({ALARM_ID}, ack=False, "
        "updated=2025-09-13T09:00:00Z)",
    ]
    assert "2 shown of 2 matches, 3 fetched, open and cleared" in text


@respx.mock
async def test_search_alarms_default_scope_state_and_ack_filters(settings):
    route = mock_all_alarms()
    text = await call_tool_text(
        build(settings),
        "cnc_search_alarms",
        {"state": "critical", "acknowledged": True, "category": "system", "limit": 1},
    )
    assert sent(route) == {"openAlarmsOnly": True, "criteria": ALL_ALARMS_CRITERIA}
    assert "- [Critical] Data Gateway dg-01 — Collection job failed (a-2, ack=True" in text
    assert ALARM_ID not in text and "a-3" not in text


@respx.mock
async def test_search_alarms_limit_caps_and_reports_the_rest(settings):
    mock_all_alarms()
    text = await call_tool_text(
        build(settings), "cnc_search_alarms", {"limit": 1, "response_format": "json"}
    )
    data = json.loads(text)
    assert data["total"] == 3 and data["count"] == 1 and data["truncated"] is True
    assert data["fetched"] == 3 and data["items"][0]["AlarmId"] == "a-3"


@respx.mock
async def test_search_alarms_no_match_is_not_an_error(settings):
    mock_all_alarms()
    text = await call_tool_text(build(settings), "cnc_search_alarms", {"text": "zzz"})
    assert not text.startswith("Error:") and "No alarms matched" in text


@respx.mock
async def test_search_alarms_unknown_state_is_error_without_a_call(settings):
    route = mock_all_alarms()
    text = await call_tool_text(build(settings), "cnc_search_alarms", {"state": "Severe"})
    assert text.startswith("Error: Unknown alarm state 'Severe'") and "Critical" in text
    assert route.call_count == 0


@respx.mock
async def test_search_alarms_http_error_is_string(make_settings):
    respx.post(QUERY_URL).mock(return_value=NATS_500)
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_search_alarms", {})
    assert text.startswith("Error:") and "500" in text


# --- cnc_list_events ---------------------------------------------------------


@respx.mock
async def test_list_events_criteria_paging_and_markdown(settings):
    route = respx.post(EVENTS_URL).mock(
        return_value=httpx.Response(200, json={"state": "Success", "events": [EVENT, EVENT_CLEAR]})
    )
    text = await call_tool_text(build(settings), "cnc_list_events", {"limit": 2, "page": 3})
    assert sent(route) == {"criteria": "select * from event limit 2 page 3"}
    assert (
        f"- [Major] Device P2 ({P2_UUID}) — SNMP timeout (e-1, alarm {ALARM_ID}, "
        "2025-09-13T08:00:00Z)"
    ) in text
    assert "- [Clear] Device P1 (p1) — Device P1 is reachable (e-9, alarm a-3, " in text
    assert "repeat with page=4" in text  # 2 of 2: page came back full


@respx.mock
async def test_list_events_filters_apply_within_the_page(settings):
    respx.post(EVENTS_URL).mock(
        return_value=httpx.Response(200, json={"state": "Success", "events": [EVENT, EVENT_CLEAR]})
    )
    text = await call_tool_text(
        build(settings), "cnc_list_events", {"severity": "clear", "response_format": "json"}
    )
    data = json.loads(text)
    assert data["count"] == 1 and data["fetched"] == 2 and data["items"][0]["EventId"] == "e-9"
    assert data["has_more"] is False and data["page"] == 0 and data["page_size"] == 50
    text = await call_tool_text(
        build(settings), "cnc_list_events", {"text": "nothing-here", "category": "System"}
    )
    assert not text.startswith("Error:")
    assert "No events in this page matched the filters (later pages may)." in text


@respx.mock
async def test_list_events_empty_and_failure_states(settings):
    respx.post(EVENTS_URL).mock(return_value=httpx.Response(200, json={"state": "Success"}))
    text = await call_tool_text(build(settings), "cnc_list_events", {})
    assert not text.startswith("Error:") and "No events returned." in text
    respx.post(EVENTS_URL).mock(
        return_value=httpx.Response(200, json={"state": "Failure", "Message": "boom"})
    )
    text = await call_tool_text(build(settings), "cnc_list_events", {})
    assert text.startswith("Error:") and "boom" in text


async def test_list_events_schema_rejects_out_of_range_paging(settings):
    with pytest.raises(ToolError, match="limit"):
        await call_tool_text(build(settings), "cnc_list_events", {"limit": 101})
    with pytest.raises(ToolError, match="page"):
        await call_tool_text(build(settings), "cnc_list_events", {"page": -1})


# --- cnc_list_device_alarms (rtm:alarm) --------------------------------------


@respx.mock
async def test_list_device_alarms_emf_headers_params_and_empty_envelope(settings):
    route = respx.get(RTM_URL).mock(return_value=httpx.Response(200, json=EMPTY_RTM))
    text = await call_tool_text(
        build(settings),
        "cnc_list_device_alarms",
        {"node_fdn": "MD=CISCO_EMS!ND=PE1", "severity": "Major", "limit": 25, "offset": 50},
    )
    request = route.calls[0].request
    assert request.headers.get_list("Accept") == ["application/json"]
    assert request.url.params[".startIndex"] == "50"
    assert request.url.params[".maxCount"] == "25"
    assert request.url.params["nd-ref"] == "MD=CISCO_EMS!ND=PE1"
    assert request.url.params["perceived-severity"] == "major"
    assert "alarmtype" not in request.url.params  # device is the platform default
    assert not text.startswith("Error:")
    assert text.startswith("No device alarms are reported by the EMF fault manager")
    assert "node MD=CISCO_EMS!ND=PE1" in text and "severity major" in text and "offset 50" in text


@respx.mock
async def test_list_device_alarms_defaults_and_json_envelope(settings):
    route = respx.get(RTM_URL).mock(return_value=httpx.Response(200, json=EMPTY_RTM))
    text = await call_tool_text(
        build(settings), "cnc_list_device_alarms", {"response_format": "json"}
    )
    params = route.calls[0].request.url.params
    assert dict(params) == {".startIndex": "0", ".maxCount": "50"}
    data = json.loads(text)
    assert data["count"] == 0 and data["items"] == [] and data["has_more"] is False
    assert data["last_index"] == -1 and data["next_start_index"] is None


@respx.mock
async def test_list_device_alarms_renders_documented_alarm(settings):
    respx.get(RTM_URL).mock(return_value=httpx.Response(200, json=RTM_ALARM))
    text = await call_tool_text(build(settings), "cnc_list_device_alarms", {})
    assert "# Device alarms (1 shown from offset 0)" in text
    assert (
        "- [major] NCS4200-42 GigabitEthernet0/1/7 — Nbr 192.168.0.41 on GigabitEthernet0/1/7 "
        "from 2WAY to DOWN (6a664005-0b24-43a7-aafa-64a399140209; category OSPF; type device; "
        "ack acknowledged; cause OSPFv3-5-ADJCHG_DOWN; updated 2024-10-04T10:01:10.981Z)"
    ) in text
    assert "More available" not in text  # 1 < 50


@respx.mock
async def test_list_device_alarms_alarm_type_is_sent_only_when_not_the_default(settings):
    route = respx.get(RTM_URL).mock(return_value=httpx.Response(200, json=EMPTY_RTM))
    text = await call_tool_text(
        build(settings), "cnc_list_device_alarms", {"alarm_type": "Network"}
    )
    assert dict(route.calls[0].request.url.params) == {
        ".startIndex": "0",
        ".maxCount": "50",
        "alarmtype": "network",
    }
    assert text.startswith("No network alarms are reported by the EMF fault manager")
    await call_tool_text(build(settings), "cnc_list_device_alarms", {"alarm_type": "DEVICE"})
    assert "alarmtype" not in route.calls[1].request.url.params
    respx.get(RTM_URL).mock(return_value=httpx.Response(200, json=RTM_ALARM))
    text = await call_tool_text(build(settings), "cnc_list_device_alarms", {"alarm_type": "system"})
    assert "# System alarms (1 shown from offset 0)" in text


@respx.mock
async def test_list_device_alarms_unknown_alarm_type_is_error_without_a_call(settings):
    route = respx.get(RTM_URL).mock(return_value=httpx.Response(200, json=EMPTY_RTM))
    text = await call_tool_text(build(settings), "cnc_list_device_alarms", {"alarm_type": "audit"})
    assert text == "Error: Unknown alarm type 'audit'. Use one of: device, network, system."
    assert route.call_count == 0


@respx.mock
async def test_list_device_alarms_xml_fallback_is_explained(settings):
    respx.get(RTM_URL).mock(
        return_value=httpx.Response(
            200,
            text='<?xml version="1.0"?><response-message/>',
            headers={"Content-Type": "application/xml"},
        )
    )
    text = await call_tool_text(build(settings), "cnc_list_device_alarms", {})
    assert text.startswith("Error:") and "Accept: application/json" in text


@respx.mock
async def test_list_device_alarms_unknown_severity_is_error_without_a_call(settings):
    route = respx.get(RTM_URL).mock(return_value=httpx.Response(200, json=EMPTY_RTM))
    text = await call_tool_text(build(settings), "cnc_list_device_alarms", {"severity": "Severe"})
    assert text.startswith("Error: Unknown perceived severity 'Severe'") and "cleared" in text
    assert route.call_count == 0


async def test_list_device_alarms_schema_caps_limit_at_emf_maximum(settings):
    with pytest.raises(ToolError, match="limit"):
        await call_tool_text(build(settings), "cnc_list_device_alarms", {"limit": 101})


@respx.mock
async def test_list_device_alarms_http_error_is_string(make_settings):
    respx.get(RTM_URL).mock(return_value=httpx.Response(403, text="Unauthorized request"))
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_list_device_alarms", {})
    assert text.startswith("Error:") and "403" in text


# --- cnc_get_alarm_settings --------------------------------------------------


@respx.mock
async def test_get_alarm_settings_reads_both_documents(settings):
    a = respx.get(SETTINGS_URL).mock(return_value=httpx.Response(200, json=SETTINGS))
    b = respx.get(GNMI_URL).mock(return_value=httpx.Response(200, json=GNMI))
    text = await call_tool_text(build(settings), "cnc_get_alarm_settings", {})
    assert a.call_count == 1 and b.call_count == 1
    assert "- networkAlertAgeout: 7" in text and "- deleteOldAlertDays: 30" in text
    assert "- syslog collection job enabled: True" in text
    assert "- trap collection job enabled: False" in text
    assert "- Cisco Systems: False" in text
    text = await call_tool_text(
        build(settings), "cnc_get_alarm_settings", {"response_format": "json"}
    )
    assert json.loads(text) == {"retention": SETTINGS, "gnmi": GNMI}


@respx.mock
async def test_get_alarm_settings_tolerates_gnmi_failure(make_settings):
    respx.get(SETTINGS_URL).mock(return_value=httpx.Response(200, json=SETTINGS))
    respx.get(GNMI_URL).mock(return_value=httpx.Response(404, text="404 page not found"))
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_get_alarm_settings", {})
    assert not text.startswith("Error:") and "- not available: API request failed" in text


@respx.mock
async def test_get_alarm_settings_error_is_string(make_settings):
    respx.get(SETTINGS_URL).mock(return_value=NATS_500)
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_get_alarm_settings", {})
    assert text.startswith("Error:") and "500" in text


# --- cnc_get_alarm_manager_settings ------------------------------------------


@respx.mock
async def test_get_alarm_manager_settings_markdown_and_enabled_only(settings):
    respx.get(MANAGER_URL).mock(return_value=httpx.Response(200, json=MANAGER))
    text = await call_tool_text(build(settings), "cnc_get_alarm_manager_settings", {})
    assert "# Alarm manager per device type (2 on, 1 off)" in text
    assert text.index("- Cisco IOS XE") < text.index("- Cisco IOS XR") < text.index("- Cisco NX-OS")
    assert "## Alarm manager OFF" in text
    text = await call_tool_text(
        build(settings), "cnc_get_alarm_manager_settings", {"enabled_only": True}
    )
    assert "Cisco NX-OS" not in text and "1 device type(s) have it off" in text


@respx.mock
async def test_get_alarm_manager_settings_json_is_raw(settings):
    respx.get(MANAGER_URL).mock(return_value=httpx.Response(200, json=MANAGER))
    text = await call_tool_text(
        build(settings), "cnc_get_alarm_manager_settings", {"response_format": "json"}
    )
    assert json.loads(text) == MANAGER
    text = await call_tool_text(
        build(settings),
        "cnc_get_alarm_manager_settings",
        {"response_format": "json", "enabled_only": True},
    )
    assert json.loads(text) == {k: v for k, v in MANAGER.items() if v}


@respx.mock
async def test_get_alarm_manager_settings_error_is_string(make_settings):
    respx.get(MANAGER_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_alarm_manager_settings", {}
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_list_event_types ----------------------------------------------------


@respx.mock
async def test_list_event_types_filters_and_autoclear(settings):
    route = respx.get(SEVERITY_URL).mock(return_value=httpx.Response(200, json=SEVERITY_ITEMS))
    text = await call_tool_text(build(settings), "cnc_list_event_types", {"category": "bgp"})
    assert route.call_count == 1
    assert "- BGP-5-ADJCHANGE_DOWN [BGP] severity=Major autoclear=15 min" in text
    assert "- BGP-5-ADJCHANGE_UP [BGP] severity=Clear autoclear=never" in text
    assert "LINK-3-UPDOWN_DOWN" not in text
    assert "2 shown of 2 matching, 3 in the catalogue" in text


@respx.mock
async def test_list_event_types_name_severity_and_paging(settings):
    respx.get(SEVERITY_URL).mock(return_value=httpx.Response(200, json=SEVERITY_ITEMS))
    text = await call_tool_text(
        build(settings),
        "cnc_list_event_types",
        {"name": "updown", "severity": "critical", "response_format": "json"},
    )
    data = json.loads(text)
    assert data["total"] == 1 and data["items"][0]["name"] == "LINK-3-UPDOWN_DOWN"
    assert data["collection_total"] == 3
    text = await call_tool_text(
        build(settings), "cnc_list_event_types", {"limit": 2, "page": 0, "response_format": "json"}
    )
    data = json.loads(text)
    assert data["count"] == 2 and data["has_more"] is True and data["next_page"] == 1
    text = await call_tool_text(build(settings), "cnc_list_event_types", {"name": "zzz"})
    assert not text.startswith("Error:") and "No event types matched." in text


@respx.mock
async def test_list_event_types_error_is_string(make_settings):
    respx.get(SEVERITY_URL).mock(return_value=NATS_500)
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_list_event_types", {})
    assert text.startswith("Error:") and "500" in text


# --- cnc_get_event_type_recommendation ---------------------------------------


@respx.mock
async def test_get_event_type_recommendation_defaults(settings):
    route = respx.get(RECOMMENDED_URL).mock(return_value=httpx.Response(200, json=RECOMMENDATION))
    text = await call_tool_text(
        build(settings), "cnc_get_event_type_recommendation", {"event_type": "BGP-5-ADJCHANGE_DOWN"}
    )
    assert route.calls[0].request.url.params["eventType"] == "BGP-5-ADJCHANGE_DOWN"
    assert "# Event type BGP-5-ADJCHANGE_DOWN" in text
    assert "- Explanation: A BGP neighbor session went down." in text
    assert "- Recommended action: Check the neighbor and the link." in text
    assert "- Source: platform defaults" in text


@respx.mock
async def test_get_event_type_recommendation_custom_overrides(settings):
    custom = {
        **RECOMMENDATION,
        "recommendedaction": "Open a ticket with NOC",
        "nextstepupdate": "x",
    }
    respx.get(RECOMMENDED_URL).mock(return_value=httpx.Response(200, json=custom))
    text = await call_tool_text(
        build(settings), "cnc_get_event_type_recommendation", {"event_type": "BGP-5-ADJCHANGE_DOWN"}
    )
    assert "- Recommended action: Open a ticket with NOC" in text
    assert "- Source: custom text set on this instance" in text
    assert "- Default recommended action: Check the neighbor and the link." in text
    assert "- Next step: x" in text


@respx.mock
async def test_get_event_type_recommendation_unknown_is_not_found(settings):
    respx.get(RECOMMENDED_URL).mock(
        return_value=httpx.Response(
            400, json={"responseResult": "Invalid input : EventType does not exist : NOPE-1"}
        )
    )
    text = await call_tool_text(
        build(settings), "cnc_get_event_type_recommendation", {"event_type": "NOPE-1"}
    )
    assert text == "Error: no event type 'NOPE-1' (find names with cnc_list_event_types)"


@respx.mock
async def test_get_event_type_recommendation_other_400_is_generic_error(settings):
    respx.get(RECOMMENDED_URL).mock(
        return_value=httpx.Response(
            400, json={"responseResult": "Invalid input : EventType is null"}
        )
    )
    text = await call_tool_text(
        build(settings), "cnc_get_event_type_recommendation", {"event_type": "X"}
    )
    assert text.startswith("Error: API request failed with status 400") and "is null" in text


# --- cnc_list_alarm_suppression_policies -------------------------------------


@respx.mock
async def test_list_suppression_policies_markdown_json_and_empty(settings):
    respx.get(POLICY_URL).mock(return_value=httpx.Response(200, json={"data": [POLICY]}))
    text = await call_tool_text(build(settings), "cnc_list_alarm_suppression_policies", {})
    assert "# Alarm suppression policies (1)" in text
    assert (
        "- **suppress-bgp-flaps** — action suppressAlarm, criteria "
        "`eventType in [BGP-5-ADJCHANGE_DOWN,BGP-5-ADJCHANGE_UP]`, device groups: 2 "
        "— Planned maintenance"
    ) in text
    text = await call_tool_text(
        build(settings), "cnc_list_alarm_suppression_policies", {"response_format": "json"}
    )
    assert json.loads(text) == {"count": 1, "items": [POLICY]}
    respx.get(POLICY_URL).mock(return_value=httpx.Response(200, json={"data": []}))
    text = await call_tool_text(build(settings), "cnc_list_alarm_suppression_policies", {})
    assert text == "No alarm suppression policies are configured."


@respx.mock
async def test_list_suppression_policies_error_is_string(make_settings):
    respx.get(POLICY_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_list_alarm_suppression_policies", {}
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_acknowledge_alarm ---------------------------------------------------


@respx.mock
async def test_acknowledge_alarm_resolves_then_puts(make_settings):
    query = mock_all_alarms()
    put = respx.put(ACK_URL).mock(
        return_value=httpx.Response(200, json={"state": "Success", "Message": "admin"})
    )
    text = await call_tool_text(
        writable(make_settings),
        "cnc_acknowledge_alarm",
        {"alarm_id": ALARM_ID, "note": "INC-1234"},
    )
    assert sent(query) == {"openAlarmsOnly": False, "criteria": ALL_ALARMS_CRITERIA}
    assert sent(put) == {"alarmId": ALARM_ID, "ack": True, "note": "INC-1234"}
    assert text.startswith(f"Alarm {ALARM_ID} acknowledged. The flag settles within a few seconds")
    assert "re-read with cnc_get_alarm" in text
    data = json.loads(text.split("\n\n", 1)[1])
    assert data["acknowledge"] is True and data["note"] == "INC-1234"
    assert data["before"] == {
        "state": "Major",
        "acknowledged": False,
        "description": "Device P2 is unreachable",
        "object_description": f"Device P2 ({P2_UUID})",
    }
    assert data["response"] == {"state": "Success", "Message": "admin"}


@respx.mock
async def test_unacknowledge_without_note_omits_the_key(make_settings):
    mock_all_alarms()
    put = respx.put(ACK_URL).mock(
        return_value=httpx.Response(200, json={"state": "Success", "Message": "admin"})
    )
    text = await call_tool_text(
        writable(make_settings),
        "cnc_acknowledge_alarm",
        {"alarm_id": "a-2", "acknowledge": False},
    )
    assert sent(put) == {"alarmId": "a-2", "ack": False}
    assert text.startswith("Alarm a-2 un-acknowledged.")


@respx.mock
async def test_acknowledge_unknown_alarm_is_error_without_a_write(make_settings):
    mock_all_alarms()
    put = respx.put(ACK_URL).mock(return_value=httpx.Response(200, json={"state": "Success"}))
    text = await call_tool_text(
        writable(make_settings), "cnc_acknowledge_alarm", {"alarm_id": "nope"}
    )
    assert text == "Error: no alarm 'nope' (list with cnc_list_alarms)"
    assert put.call_count == 0


@respx.mock
async def test_unacknowledge_of_unacknowledged_alarm_is_refused_without_a_write(make_settings):
    mock_all_alarms()
    put = respx.put(ACK_URL).mock(return_value=httpx.Response(200, json={"state": "Success"}))
    text = await call_tool_text(
        writable(make_settings),
        "cnc_acknowledge_alarm",
        {"alarm_id": ALARM_ID, "acknowledge": False},
    )
    assert text.startswith(f"Error: alarm {ALARM_ID} is not acknowledged (per the pre-flight read)")
    assert "cannot unacknowledge it." in text and "re-read with cnc_get_alarm and retry" in text
    assert put.call_count == 0


@respx.mock
async def test_unacknowledge_state_fail_is_error_with_message(make_settings):
    # The pre-flight read says acknowledged (a-2) but the platform still refuses —
    # the verified Fail answer must surface verbatim.
    mock_all_alarms()
    respx.put(ACK_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "state": "Fail",
                "Message": "Alarm was not acknowledged, cannot unacknowledge it. ",
            },
        )
    )
    text = await call_tool_text(
        writable(make_settings),
        "cnc_acknowledge_alarm",
        {"alarm_id": "a-2", "acknowledge": False},
    )
    assert text == (
        "Error: Un-acknowledge alarm a-2 failed: "
        "Alarm was not acknowledged, cannot unacknowledge it."
    )


@respx.mock
async def test_acknowledge_platform_no_match_fail_is_error(make_settings):
    mock_all_alarms()
    respx.put(ACK_URL).mock(
        return_value=httpx.Response(
            200, json={"state": "Fail", "Message": "No matching alarms were found for query:null"}
        )
    )
    text = await call_tool_text(
        writable(make_settings), "cnc_acknowledge_alarm", {"alarm_id": ALARM_ID}
    )
    assert text.startswith("Error:") and "No matching alarms were found" in text


@respx.mock
async def test_acknowledge_http_error_is_string(make_settings):
    mock_all_alarms()
    respx.put(ACK_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        writable(make_settings, max_retries=0), "cnc_acknowledge_alarm", {"alarm_id": ALARM_ID}
    )
    assert text.startswith("Error:") and "500" in text


# --- lifecycle wire safety (ack / note / clear) ------------------------------

LIFECYCLE_OK = {"state": "Success", "Message": "admin"}


@pytest.mark.parametrize(
    ("tool", "url", "arguments"),
    [
        ("cnc_acknowledge_alarm", ACK_URL, {}),
        ("cnc_annotate_alarm", NOTE_URL, {"note": "x"}),
        ("cnc_clear_alarm", CLEAR_URL, {}),
    ],
)
@respx.mock
async def test_lifecycle_writes_send_the_platform_spelling_of_the_id(
    make_settings, tool, url, arguments
):
    """find_alarm matches case-insensitively; the PUT must carry the resolved AlarmId."""
    mock_all_alarms()
    put = respx.put(url).mock(return_value=httpx.Response(200, json=LIFECYCLE_OK))
    text = await call_tool_text(
        writable(make_settings), tool, {"alarm_id": ALARM_ID.upper(), **arguments}
    )
    assert sent(put)["alarmId"] == ALARM_ID
    assert not text.startswith("Error:")
    assert ALARM_ID.upper() not in text  # the caller's spelling is never echoed
    assert json.loads(text.split("\n\n", 1)[1])["alarm_id"] == ALARM_ID


@pytest.mark.parametrize(
    ("tool", "url", "arguments"),
    [
        ("cnc_acknowledge_alarm", ACK_URL, {}),
        ("cnc_annotate_alarm", NOTE_URL, {"note": "x"}),
    ],
)
@respx.mock
async def test_ack_and_note_lost_response_is_not_retried(make_settings, tool, url, arguments):
    """A ReadTimeout after the platform may have stored the ack/note must NOT be re-sent
    (each accepted call is recorded: AckHist entry / permanent note)."""
    mock_all_alarms()
    put = respx.put(url).mock(
        side_effect=[httpx.ReadTimeout("read timed out"), httpx.Response(200, json=LIFECYCLE_OK)]
    )
    text = await call_tool_text(
        writable(make_settings, max_retries=3), tool, {"alarm_id": ALARM_ID, **arguments}
    )
    assert put.call_count == 1
    assert text.startswith("Error: Could not reach the platform (ReadTimeout)")
    assert "may already have been applied" in text


@respx.mock
async def test_clear_lost_response_is_retried_because_a_repeat_is_refused_by_the_platform(
    make_settings,
):
    """clear keeps the client's PUT auto-retry: a second clear is answered
    Fail "Alarm is already cleared." (verified live), never applied twice."""
    mock_all_alarms()
    put = respx.put(CLEAR_URL).mock(
        side_effect=[httpx.ReadTimeout("read timed out"), httpx.Response(200, json=LIFECYCLE_OK)]
    )
    text = await call_tool_text(
        writable(make_settings, max_retries=3), "cnc_clear_alarm", {"alarm_id": ALARM_ID}
    )
    assert put.call_count == 2
    assert text.startswith(f"Alarm {ALARM_ID} cleared.")


# --- cnc_annotate_alarm ------------------------------------------------------


@respx.mock
async def test_annotate_alarm_puts_note_and_says_permanent(make_settings):
    mock_all_alarms()
    put = respx.put(NOTE_URL).mock(
        return_value=httpx.Response(200, json={"state": "Success", "Message": "admin"})
    )
    text = await call_tool_text(
        writable(make_settings),
        "cnc_annotate_alarm",
        {"alarm_id": ALARM_ID, "note": "  Root cause: fibre cut  "},
    )
    assert sent(put) == {"alarmId": ALARM_ID, "note": "Root cause: fibre cut"}
    assert text.startswith(f"Note added to alarm {ALARM_ID} (notes are permanent).")
    data = json.loads(text.split("\n\n", 1)[1])
    assert data["note"] == "Root cause: fibre cut" and data["before"]["state"] == "Major"


@respx.mock
async def test_annotate_unknown_alarm_is_error_without_a_write(make_settings):
    mock_all_alarms()
    put = respx.put(NOTE_URL).mock(return_value=httpx.Response(200, json={"state": "Success"}))
    text = await call_tool_text(
        writable(make_settings), "cnc_annotate_alarm", {"alarm_id": "nope", "note": "x"}
    )
    assert text == "Error: no alarm 'nope' (list with cnc_list_alarms)"
    assert put.call_count == 0


@respx.mock
async def test_annotate_state_fail_is_error(make_settings):
    mock_all_alarms()
    respx.put(NOTE_URL).mock(
        return_value=httpx.Response(200, json={"state": "Fail", "Message": "Note too long"})
    )
    text = await call_tool_text(
        writable(make_settings), "cnc_annotate_alarm", {"alarm_id": ALARM_ID, "note": "x"}
    )
    assert text == f"Error: Annotate alarm {ALARM_ID} failed: Note too long"


async def test_annotate_schema_requires_a_note(make_settings):
    with pytest.raises(ToolError, match="note"):
        await call_tool_text(
            writable(make_settings), "cnc_annotate_alarm", {"alarm_id": ALARM_ID, "note": ""}
        )


@respx.mock
async def test_annotate_blank_note_is_error_without_a_read_or_write(make_settings):
    query = mock_all_alarms()
    put = respx.put(NOTE_URL).mock(return_value=httpx.Response(200, json={"state": "Success"}))
    text = await call_tool_text(
        writable(make_settings), "cnc_annotate_alarm", {"alarm_id": ALARM_ID, "note": "   "}
    )
    assert text == "Error: The note must not be blank."
    assert query.call_count == 0 and put.call_count == 0


# --- cnc_clear_alarm ---------------------------------------------------------


@respx.mock
async def test_clear_alarm_puts_and_reports(make_settings):
    mock_all_alarms()
    put = respx.put(CLEAR_URL).mock(
        return_value=httpx.Response(200, json={"state": "Success", "Message": "admin"})
    )
    text = await call_tool_text(
        writable(make_settings), "cnc_clear_alarm", {"alarm_id": ALARM_ID, "note": "fixed"}
    )
    assert sent(put) == {"alarmId": ALARM_ID, "note": "fixed"}
    assert text.startswith(f"Alarm {ALARM_ID} cleared.")
    data = json.loads(text.split("\n\n", 1)[1])
    assert data["before"]["state"] == "Major" and data["response"]["state"] == "Success"


@respx.mock
async def test_clear_alarm_without_note_omits_the_key(make_settings):
    mock_all_alarms()
    put = respx.put(CLEAR_URL).mock(
        return_value=httpx.Response(200, json={"state": "Success", "Message": "admin"})
    )
    await call_tool_text(writable(make_settings), "cnc_clear_alarm", {"alarm_id": ALARM_ID})
    assert sent(put) == {"alarmId": ALARM_ID}


@respx.mock
async def test_clear_already_cleared_is_error_with_message(make_settings):
    mock_all_alarms()
    respx.put(CLEAR_URL).mock(
        return_value=httpx.Response(
            200, json={"state": "Fail", "Message": "Alarm is already cleared. "}
        )
    )
    text = await call_tool_text(writable(make_settings), "cnc_clear_alarm", {"alarm_id": "a-3"})
    assert text == "Error: Clear alarm a-3 failed: Alarm is already cleared."


@respx.mock
async def test_clear_unknown_alarm_is_error_without_a_write(make_settings):
    mock_all_alarms()
    put = respx.put(CLEAR_URL).mock(return_value=httpx.Response(200, json={"state": "Success"}))
    text = await call_tool_text(writable(make_settings), "cnc_clear_alarm", {"alarm_id": "nope"})
    assert text == "Error: no alarm 'nope' (list with cnc_list_alarms)"
    assert put.call_count == 0


# --- cnc_create_alarm_suppression_policy -------------------------------------


@respx.mock
async def test_create_suppression_policy_body_and_success(make_settings):
    post = respx.post(POLICY_URL).mock(
        return_value=httpx.Response(200, json={"Message": "Success", "status": "Success"})
    )
    text = await call_tool_text(
        writable(make_settings),
        "cnc_create_alarm_suppression_policy",
        {
            "name": "suppress-bgp-flaps",
            "criteria": "eventType in [BGP-5-ADJCHANGE_DOWN]",
            "action": "suppressevent",
            "description": "Planned maintenance",
            "device_groups": "g-1, g-2,,",
        },
    )
    assert sent(post) == {
        "policyname": "suppress-bgp-flaps",
        "description": "Planned maintenance",
        "action": "suppressEvent",
        "deviceGroups": ["g-1", "g-2"],
        "criteria": "eventType in [BGP-5-ADJCHANGE_DOWN]",
    }
    assert text.startswith("Suppression policy 'suppress-bgp-flaps' created.")
    data = json.loads(text.split("\n\n", 1)[1])
    assert data["response"] == {"Message": "Success", "status": "Success"}
    assert data["policy"]["deviceGroups"] == ["g-1", "g-2"]


@respx.mock
async def test_create_suppression_policy_defaults(make_settings):
    post = respx.post(POLICY_URL).mock(
        return_value=httpx.Response(200, json={"Message": "Success", "status": "Success"})
    )
    await call_tool_text(
        writable(make_settings),
        "cnc_create_alarm_suppression_policy",
        {"name": "p", "criteria": "eventType in [A]"},
    )
    assert sent(post) == {
        "policyname": "p",
        "description": "",
        "action": "suppressAlarm",
        "deviceGroups": [],
        "criteria": "eventType in [A]",
    }


@respx.mock
async def test_create_suppression_policy_duplicate_400_adds_hint(make_settings):
    respx.post(POLICY_URL).mock(
        return_value=httpx.Response(
            400,
            json={"Message": "Failed to create policy rule suppress-bgp-flaps", "status": "Failed"},
        )
    )
    text = await call_tool_text(
        writable(make_settings),
        "cnc_create_alarm_suppression_policy",
        {"name": "suppress-bgp-flaps", "criteria": "eventType in [A]"},
    )
    assert text.startswith("Error: API request failed with status 400")
    assert "Failed to create policy rule suppress-bgp-flaps" in text
    assert "a policy with that name may already exist" in text


@respx.mock
async def test_create_suppression_policy_200_with_failed_status_is_error(make_settings):
    """The status field, not the HTTP code, is the verdict (alarm/v1 idiom)."""
    respx.post(POLICY_URL).mock(
        return_value=httpx.Response(
            200, json={"Message": "Failed to create policy rule p", "status": "Failed"}
        )
    )
    text = await call_tool_text(
        writable(make_settings),
        "cnc_create_alarm_suppression_policy",
        {"name": "p", "criteria": "eventType in [A]"},
    )
    assert text == "Error: Create suppression policy 'p' failed: Failed to create policy rule p"


@respx.mock
async def test_create_suppression_policy_unknown_action_is_error_without_a_call(make_settings):
    post = respx.post(POLICY_URL).mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(
        writable(make_settings),
        "cnc_create_alarm_suppression_policy",
        {"name": "p", "criteria": "eventType in [A]", "action": "drop"},
    )
    assert text.startswith("Error: Unknown suppression action 'drop'") and "suppressAlarm" in text
    assert post.call_count == 0


@respx.mock
async def test_create_suppression_policy_other_error_is_string(make_settings):
    respx.post(POLICY_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        writable(make_settings, max_retries=0),
        "cnc_create_alarm_suppression_policy",
        {"name": "p", "criteria": "eventType in [A]"},
    )
    assert text.startswith("Error:") and "500" in text and "already exist" not in text


# --- cnc_delete_alarm_suppression_policy -------------------------------------


@respx.mock
async def test_delete_suppression_policy_quotes_the_name(make_settings):
    route = respx.delete(f"{POLICY_URL}/bgp%20flaps%2Fold").mock(
        return_value=httpx.Response(
            200, json={"Message": "Alarm Policy deleted successfully", "status": "Success"}
        )
    )
    text = await call_tool_text(
        writable(make_settings), "cnc_delete_alarm_suppression_policy", {"name": "bgp flaps/old"}
    )
    assert route.call_count == 1
    assert text.startswith("Suppression policy 'bgp flaps/old' deleted.")
    assert "Alarm Policy deleted successfully" in text


@respx.mock
async def test_delete_suppression_policy_unknown_is_not_found(make_settings):
    respx.delete(f"{POLICY_URL}/nope").mock(
        return_value=httpx.Response(
            400, json={"Message": "Failed to delete Alarm Policy", "status": "Failed"}
        )
    )
    text = await call_tool_text(
        writable(make_settings), "cnc_delete_alarm_suppression_policy", {"name": "nope"}
    )
    assert text == "Error: no suppression policy 'nope' (or it could not be deleted)"


@respx.mock
async def test_delete_suppression_policy_200_with_failed_status_is_error(make_settings):
    respx.delete(f"{POLICY_URL}/p").mock(
        return_value=httpx.Response(
            200, json={"Message": "Failed to delete Alarm Policy", "status": "Failed"}
        )
    )
    text = await call_tool_text(
        writable(make_settings), "cnc_delete_alarm_suppression_policy", {"name": "p"}
    )
    assert text == "Error: Delete suppression policy 'p' failed: Failed to delete Alarm Policy"


@respx.mock
async def test_delete_suppression_policy_other_error_is_string(make_settings):
    respx.delete(f"{POLICY_URL}/p").mock(return_value=NATS_500)
    text = await call_tool_text(
        writable(make_settings, max_retries=0), "cnc_delete_alarm_suppression_policy", {"name": "p"}
    )
    assert text.startswith("Error:") and "500" in text
