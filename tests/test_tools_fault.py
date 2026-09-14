"""Fault tools end-to-end through MCPServer (schema validation included).

The module is registered directly (not through build_server) so the test does
not depend on tools/__init__.py's module list. All HTTP is mocked with respx.
Fixtures mirror the shapes verified live on Crosswork 7.2 (2026-09-13 and
2026-09-14, see the platform notes "Fault APIs" / "Alarm ordering"): the
alarms/v1 alarm with AckHist (date-only, unordered) and Notes (epoch ms), the
Cleared alarm whose Description is the clearing event's text (Events newest
first), the event, the lifecycle {state, Message} answers, the alarm/v1 settings,
severity-config items, recommended-action and suppression-policy documents,
and the EMPTY rtm:alarm envelope (com.lastIndex -1, no com.data).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

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
    ACK_HIST_NOTE,
    ALARM_FETCH_PAGE,
    ALARM_SORTS,
    ALARM_STATES,
    STALE_ALARM_DAYS,
    ack_hist_lines,
    age_text,
    alarm_criteria,
    alarm_line,
    alarm_markdown,
    alarm_text,
    canonical,
    check_lifecycle,
    check_query,
    event_count,
    fault_event,
    fault_event_label,
    filter_alarms,
    filter_event_types,
    filter_events,
    find_alarm,
    history_stamp,
    is_cleared,
    is_stale,
    sort_alarms,
    stale_alarm_footer,
)
from tests.conftest import BASE_URL, call_tool_text

# Fixed "now" for the age/stale helpers: 2025-09-14T12:00:00Z (the fixtures are dated
# 2025-09-12/13, so ages are a day or two; the STALE alarm below is weeks older).
NOW = datetime(2025, 9, 14, 12, 0, 0, tzinfo=UTC)

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
    # AckHist timestamps are DATE-ONLY strings on the wire and the entries come back
    # in no stable order (verified live 2026-09-14) — the renderer shows per-day
    # counts. Notes carry epoch ms and are listed newest first.
    "AckHist": [
        {"CreatedBy": "admin", "Description": "Ack", "Timestamp": "2025-09-13 00:00:00.0"},
        {"CreatedBy": "admin", "Description": "UnAck", "Timestamp": "2025-09-13 00:00:00.0"},
    ],
    "Notes": [
        {
            "CreatedBy": "admin",
            "Description": "Alarm unacknowledged",
            "Timestamp": "1757753100000",
        },
        {"CreatedBy": "admin", "Description": "checked by ops", "Timestamp": "1757753000000"},
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
    "AckHist": [{"CreatedBy": "admin", "Description": "Ack", "Timestamp": "2025-09-13 00:00:00.0"}],
    "Notes": [],
}
# A pod-health alarm as seen live 2026-09-14 (dates shifted to the fixture year): open,
# events_count 0, NO "Events" key at all, unchanged for weeks — Crosswork never
# auto-clears these. Created/Updated 2025-08-07 15:30/16:00Z = 37.9 days before NOW.
ALARM_STALE = {
    "AlarmId": "a-stale",
    "AlarmCategory": "System",
    "State": "Major",
    "Acknowledge": False,
    "Description": "cwm-api-service is down.",
    "object_id": "cwm-solutions-inventory",
    "object_description": "cwm-api-service",
    "origin_app_id": "capp-cwm-solutions",
    "origin_service_id": "cwm-solutions-inventory-57b9448ffb-c8zxt",
    "event_type": 0,
    "events_count": 0,
    "Created": "1754580624000",
    "Updated": "1754582426000",
}
# A cleared alarm as the platform sends it (verified live 2026-09-14 on all 105 lab
# alarms): Events newest first, and the top-level Description is the NEWEST event's
# text — here the CLEARING event's — so the fault lives only in the Major event.
ALARM_CLEARED = {
    "AlarmId": "a-3",
    "AlarmCategory": "System",
    "State": "Clear",
    "Acknowledge": False,
    "Description": "Device P1 is reachable",
    "object_id": "p1",
    "object_description": "Device P1 (p1)",
    "origin_app_id": "capp-infra:DLM",
    "origin_service_id": "dlm",
    "event_type": 1001,
    "events_count": 2,
    "Created": "1757700000000",
    "Updated": "1757760000000",
    "Events": [
        {
            "EventId": "e-9",
            "EventSeverity": "Clear",
            "Description": "Device P1 is reachable",
            "Timestamp": "1757760000000",
            "EventCategory": "System",
            "alarm_id": "a-3",
            "Flagging": False,
        },
        {
            "EventId": "e-8",
            "EventSeverity": "Major",
            "Description": "Device P1 is unreachable",
            "Timestamp": "1757700000000",
            "EventCategory": "System",
            "alarm_id": "a-3",
            "Flagging": False,
        },
    ],
    "AckHist": [],
    "Notes": [],
}
# A cleared pod-health alarm as seen live: events_count 0, no "Events" key, and a
# Description ("<pod> is healthy.") that no longer says what the fault was.
ALARM_CLEARED_NO_EVENTS = {
    "AlarmId": "a-4",
    "AlarmCategory": "System",
    "State": "Clear",
    "Acknowledge": False,
    "Description": "cwm-solutions-automation-0 is healthy.",
    "object_id": "cwm-solutions-automation",
    "object_description": "cwm-solutions-automation-0 health is down.",
    "origin_app_id": "capp-cwm-solutions",
    "origin_service_id": "cwm-solutions-automation-0",
    "event_type": 0,
    "events_count": 0,
    "Created": "1754580624000",
    "Updated": "1754582426000",
}
PE2_UUID = "ec35be58-de93-49e5-891b-a1c4a11c72e4"
# The live NSO-onboarding shape (alarm 6ddc88ed on PE2, read 2026-09-14; dates shifted
# to the fixture year): Major fault -> Info progress row -> Clear -> Clear (re-clear).
# The newest NON-Clear event is the Info row "Node was onboarded on NSO.", which is not
# the fault — the renderers must show the Major text.
ALARM_CLEARED_INFO = {
    "AlarmId": "6ddc88ed-d679-4d4d-9c9a-a9f879550fee",
    "AlarmCategory": "System",
    "State": "Clear",
    "Acknowledge": False,
    "Description": "NSO device is in sync.",
    "object_id": PE2_UUID,
    "object_description": f"Device PE2 ({PE2_UUID})",
    "origin_app_id": "capp-infra:DLM",
    "origin_service_id": "dlm",
    "event_type": 1002,
    "events_count": 4,
    "Created": "1757751000000",
    "Updated": "1757825000000",
    "Events": [
        {
            "EventId": "e-14",
            "EventSeverity": "Clear",
            "Description": "NSO device is in sync.",
            "Timestamp": "1757825000000",
            "EventCategory": "System",
            "alarm_id": "6ddc88ed-d679-4d4d-9c9a-a9f879550fee",
            "Flagging": False,
        },
        {
            "EventId": "e-13",
            "EventSeverity": "Clear",
            "Description": "NSO device is in sync.",
            "Timestamp": "1757751033000",
            "EventCategory": "System",
            "alarm_id": "6ddc88ed-d679-4d4d-9c9a-a9f879550fee",
            "Flagging": False,
        },
        {
            "EventId": "e-12",
            "EventSeverity": "Info",
            "Description": "Node was onboarded on NSO.",
            "Timestamp": "1757751023000",
            "EventCategory": "System",
            "alarm_id": "6ddc88ed-d679-4d4d-9c9a-a9f879550fee",
            "Flagging": False,
        },
        {
            "EventId": "e-11",
            "EventSeverity": "Major",
            "Description": "Failed to onboard the node on NSO. NSO Reported Error: Node does "
            "not have a software type yet.",
            "Timestamp": "1757751000000",
            "EventCategory": "System",
            "alarm_id": "6ddc88ed-d679-4d4d-9c9a-a9f879550fee",
            "Flagging": False,
        },
    ],
    "AckHist": [],
    "Notes": [],
}
# A cleared alarm with Info events only (live: the "pipeline" alarm d74ea1a5, Info
# "pipeline health updating: HEALTHY" x13 -> Clear "confirm health"): with no
# fault-severity event the newest Info event is the best available fault text.
ALARM_CLEARED_INFO_ONLY = {
    "AlarmId": "a-info",
    "AlarmCategory": "System",
    "State": "Clear",
    "Acknowledge": False,
    "Description": "confirm health",
    "object_id": "pipeline",
    "object_description": "pipeline",
    "origin_app_id": "capp-infra",
    "origin_service_id": "pipeline",
    "event_type": 0,
    "events_count": 2,
    "Created": "1757751100000",
    "Updated": "1757751200000",
    "Events": [
        {
            "EventId": "e-22",
            "EventSeverity": "Clear",
            "Description": "confirm health",
            "Timestamp": "1757751200000",
        },
        {
            "EventId": "e-21",
            "EventSeverity": "Info",
            "Description": "pipeline health updating: HEALTHY",
            "Timestamp": "1757751100000",
        },
    ],
    "AckHist": [],
    "Notes": [],
}
ALL_ALARMS = {"state": "Success", "alarms": [ALARM_ACKED, ALARM, ALARM_CLEARED]}
ALL_WITH_STALE = {"state": "Success", "alarms": [ALARM_ACKED, ALARM_STALE, ALARM, ALARM_CLEARED]}

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


PAGE0_OPEN = {"openAlarmsOnly": True, "criteria": alarm_criteria(ALARM_FETCH_PAGE, 0)}
PAGE0_ALL = {"openAlarmsOnly": False, "criteria": alarm_criteria(ALARM_FETCH_PAGE, 0)}


def mock_all_alarms(body: dict | None = None) -> respx.Route:
    """The alarms/v1 query: like the platform, ``openAlarmsOnly: true`` answers only the
    alarms whose State is not Clear; an explicit ``body`` is answered verbatim."""

    def answer(request: httpx.Request) -> httpx.Response:
        if body is not None:
            return httpx.Response(200, json=body)
        if json.loads(request.content).get("openAlarmsOnly"):
            rows = [a for a in ALL_ALARMS["alarms"] if a["State"] != "Clear"]
            return httpx.Response(200, json={"state": "Success", "alarms": rows})
        return httpx.Response(200, json=ALL_ALARMS)

    return respx.post(QUERY_URL).mock(side_effect=answer)


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


def test_sort_alarms_created_desc_and_platform_order():
    """The platform order is not newest-first (verified live 2026-09-14): every order
    is applied client-side. Created: P2 (09-13 08:00) > a-2 (09-13 05:06) > a-3 (09-12)."""
    alarms = ALL_ALARMS["alarms"]
    ids = lambda rows: [a["AlarmId"] for a in rows]  # noqa: E731
    assert ids(sort_alarms(alarms, "created_desc")) == [ALARM_ID, "a-2", "a-3"]
    assert ids(sort_alarms(alarms, "updated_desc")) == ["a-3", ALARM_ID, "a-2"]
    assert ids(sort_alarms(alarms, "platform")) == ["a-2", ALARM_ID, "a-3"]
    assert ids(filter_alarms(alarms, sort="created_desc")) == [ALARM_ID, "a-2", "a-3"]
    assert ids(filter_alarms(alarms, sort="platform")) == ["a-2", ALARM_ID, "a-3"]
    assert ALARM_SORTS == ("updated_desc", "created_desc", "platform")
    with pytest.raises(
        PlatformError, match="Unknown sort order 'newest'. Use one of: updated_desc"
    ):
        canonical("newest", ALARM_SORTS, "sort order")


def test_age_text_units_and_unparseable():
    assert age_text("1757750400000", NOW) == "1d"  # 2025-09-13T08:00Z -> 28 h
    assert age_text(str(int(NOW.timestamp() * 1000) - 5 * 3600 * 1000), NOW) == "5h"
    assert age_text(str(int(NOW.timestamp() * 1000) - 12 * 60 * 1000), NOW) == "12m"
    assert age_text(str(int(NOW.timestamp() * 1000) - 30 * 1000), NOW) == "<1m"
    assert age_text(str(int(NOW.timestamp() * 1000) + 60 * 1000), NOW) == "<1m"  # clock skew
    assert age_text("1754580624000", NOW) == "37d"
    assert age_text(None, NOW) == "-" and age_text("", NOW) == "-" and age_text("x", NOW) == "-"
    assert age_text("0", NOW) == "-"


def test_event_count_and_is_stale():
    assert event_count(ALARM) == 2
    assert event_count(ALARM_STALE) == 0  # events_count 0 and no Events key at all
    assert event_count({"Events": [{"EventId": "e"}]}) == 1 and event_count({}) == 0
    assert is_stale(ALARM_STALE, NOW) is True
    assert is_stale(ALARM, NOW) is False  # has events
    assert is_stale({**ALARM_STALE, "State": "Clear"}, NOW) is False  # cleared
    assert is_stale({**ALARM_STALE, "Updated": str(int(NOW.timestamp() * 1000))}, NOW) is False
    edge = str(int((NOW.timestamp() - STALE_ALARM_DAYS * 86400) * 1000))
    assert is_stale({**ALARM_STALE, "Updated": edge}, NOW) is True
    assert is_stale({**ALARM_STALE, "Updated": str(int(edge) + 1000)}, NOW) is False
    assert is_stale({**ALARM_STALE, "Updated": None, "Created": None}, NOW) is False


def test_history_stamp_date_only_epoch_and_raw():
    assert history_stamp("2026-09-14 00:00:00.0") == "2026-09-14 (date only)"
    assert history_stamp("2026-09-14T00:00:00") == "2026-09-14 (date only)"
    assert history_stamp("1757753000000") == "2025-09-13T08:43:20Z"
    assert history_stamp("2026-09-14 02:16:17.0") == "2026-09-14 02:16:17.0"  # verbatim
    assert history_stamp(None) == "-"


def test_alarm_line_and_stale_footer():
    assert alarm_line(ALARM_STALE, NOW) == (
        "- [Major] cwm-api-service — cwm-api-service is down. (a-stale, ack=False, events=0, "
        "created=2025-08-07T15:30:24Z, updated=2025-08-07T16:00:26Z, age=37d)"
    )
    assert alarm_line({}, NOW) == "- [?] ? — ? (?, ack=?, events=0, created=-, updated=-, age=-)"
    assert stale_alarm_footer([ALARM, ALARM_ACKED], NOW) == []
    footer = stale_alarm_footer([ALARM, ALARM_STALE], NOW)
    assert footer[0] == ""
    # The verb agrees with the count, and the hint is generic: the heuristic fires on
    # ANY open 0-event alarm, so the pod-health check is scoped to "<pod> is down.".
    assert footer[1].startswith(
        f"Stale-alarm check: 1 of the alarms shown has 0 events and no update for "
        f"{STALE_ALARM_DAYS}+ days. Possibly stale — Crosswork does not auto-clear such alarms "
        "(verified live 2026-09-14 on pod-health alarms)."
    )
    assert (
        'For "<pod> is down." alarms confirm with cnc_get_cluster_health / '
        "cnc_list_microservices(app_id=...); for any other alarm verify the underlying "
        "condition before reporting it as current."
    ) in footer[1]
    two = stale_alarm_footer([ALARM_STALE, {**ALARM_STALE, "AlarmId": "a-stale-2"}], NOW)
    assert two[1].startswith("Stale-alarm check: 2 of the alarms shown have 0 events")


def test_fault_event_is_the_newest_fault_severity_event_by_timestamp():
    """The platform keeps the NEWEST event's text in Description (verified live
    2026-09-14 on all 105 lab alarms), so a Cleared alarm's fault is the newest
    fault-severity event — chosen by Timestamp, not list position."""
    assert fault_event(ALARM_CLEARED)["EventId"] == "e-8"
    shuffled = {**ALARM_CLEARED, "Events": list(reversed(ALARM_CLEARED["Events"]))}
    assert fault_event(shuffled)["EventId"] == "e-8"
    # Several non-Clear events (live: "Fetch ssh keys failed" then "NSO connect ... failed"
    # then the clear): the newest fault wins, whatever the list order.
    older_fault = {
        "EventId": "e-7",
        "EventSeverity": "Major",
        "Description": "Fetch ssh keys failed.",
        "Timestamp": "1757690000000",
    }
    many = {**ALARM_CLEARED, "Events": [older_fault, *ALARM_CLEARED["Events"]]}
    assert fault_event(many)["EventId"] == "e-8"
    assert fault_event(ALARM_CLEARED_NO_EVENTS) is None
    only_clear = {**ALARM_CLEARED, "Events": ALARM_CLEARED["Events"][:1]}
    assert fault_event(only_clear) is None
    assert fault_event({**ALARM, "Events": [{}, "junk"]}) == {}  # tolerant of odd rows
    assert is_cleared(ALARM_CLEARED) and is_cleared({"State": " clear "})
    assert not is_cleared(ALARM) and not is_cleared({})


def test_fault_event_skips_info_events():
    """Live (2026-09-14, alarms 6ddc88ed PE2 / 72395fe4 PCE): Major "Failed to onboard
    ..." -> Info "Node was onboarded on NSO." -> Clear. The Info row is the newest
    non-Clear event but NOT the fault — the Major event must win, whatever the list
    order and whichever severity case the platform uses."""
    assert fault_event(ALARM_CLEARED_INFO)["EventId"] == "e-11"
    shuffled = {**ALARM_CLEARED_INFO, "Events": list(reversed(ALARM_CLEARED_INFO["Events"]))}
    assert fault_event(shuffled)["EventId"] == "e-11"
    lowered = {
        **ALARM_CLEARED_INFO,
        "Events": [
            {**e, "EventSeverity": e["EventSeverity"].lower()} for e in ALARM_CLEARED_INFO["Events"]
        ],
    }
    assert fault_event(lowered)["EventId"] == "e-11"
    # Every fault severity beats a newer Info row; the newest fault-severity event wins.
    for severity in ("Critical", "Minor", "Warning"):
        alarm = {
            **ALARM_CLEARED_INFO,
            "Events": [
                {**ALARM_CLEARED_INFO["Events"][3], "EventSeverity": severity},
                *ALARM_CLEARED_INFO["Events"][:3],
            ],
        }
        assert fault_event(alarm)["EventSeverity"] == severity
    newer_fault = {
        "EventId": "e-15",
        "EventSeverity": "Warning",
        "Description": "Still onboarding.",
        "Timestamp": "1757751030000",
    }
    assert (
        fault_event({**ALARM_CLEARED_INFO, "Events": [newer_fault, *ALARM_CLEARED_INFO["Events"]]})[
            "EventId"
        ]
        == "e-15"
    )
    assert fault_event_label(ALARM_CLEARED_INFO["Events"][3]) == "newest fault-severity event"
    # Fallback: with no fault-severity event at all (live: Info -> Clear alarms such as
    # "pipeline health updating: HEALTHY"), the newest Info event is the best there is.
    assert fault_event(ALARM_CLEARED_INFO_ONLY)["EventId"] == "e-21"
    assert fault_event_label(ALARM_CLEARED_INFO_ONLY["Events"][1]) == (
        "newest non-Clear event — no Critical/Major/Minor/Warning event recorded"
    )


def test_alarm_text_renders_the_fault_of_a_cleared_alarm():
    # Open alarm: Description verbatim (it IS the newest event's text).
    assert alarm_text(ALARM) == "Device P2 is unreachable"
    # Cleared with events: "[sev] fault | cleared: <Description>".
    assert alarm_text(ALARM_CLEARED) == (
        "[Major] Device P1 is unreachable | cleared: Device P1 is reachable"
    )
    # The clearing event repeats the fault text (live: the gluster volume alarms).
    same = {**ALARM_CLEARED, "Description": "Device P1 is unreachable"}
    assert alarm_text(same) == "[Major] Device P1 is unreachable | cleared: (same text)"
    # Cleared pod-health alarm: no Events at all, so the fault is unrecoverable.
    assert alarm_text(ALARM_CLEARED_NO_EVENTS) == (
        "cwm-solutions-automation-0 is healthy. | original fault not recorded (0 events)"
    )
    only_clear = {**ALARM_CLEARED, "Events": ALARM_CLEARED["Events"][:1], "events_count": 1}
    assert alarm_text(only_clear) == (
        "Device P1 is reachable | original fault not recorded (no non-Clear event among 1)"
    )
    assert alarm_line(ALARM_CLEARED, NOW) == (
        "- [Clear] Device P1 (p1) — [Major] Device P1 is unreachable | cleared: Device P1 is "
        "reachable (a-3, ack=False, events=2, created=2025-09-12T18:00:00Z, "
        "updated=2025-09-13T10:40:00Z, age=1d)"
    )


def test_alarm_text_names_the_major_fault_not_the_info_row():
    """The live NSO-onboarding alarms (Major -> Info -> Clear) must render the Major
    fault: "[Info] Node was onboarded on NSO." hid the real fault before."""
    assert alarm_text(ALARM_CLEARED_INFO) == (
        "[Major] Failed to onboard the node on NSO. NSO Reported Error: Node does not have a "
        "software type yet. | cleared: NSO device is in sync."
    )
    assert alarm_line(ALARM_CLEARED_INFO, NOW) == (
        f"- [Clear] Device PE2 ({PE2_UUID}) — [Major] Failed to onboard the node on NSO. NSO "
        "Reported Error: Node does not have a software type yet. | cleared: NSO device is in "
        "sync. (6ddc88ed-d679-4d4d-9c9a-a9f879550fee, ack=False, events=4, "
        "created=2025-09-13T08:10:00Z, updated=2025-09-14T04:43:20Z, age=1d)"
    )
    assert "[Info]" not in alarm_line(ALARM_CLEARED_INFO, NOW)
    # Detail view: the Fault line is the Major event, labelled as the fault-severity pick.
    text = alarm_markdown(ALARM_CLEARED_INFO, NOW)
    assert (
        "- Fault: [Major] Failed to onboard the node on NSO. NSO Reported Error: Node does "
        "not have a software type yet. (newest fault-severity event, 2025-09-13T08:10:00Z)"
    ) in text
    assert "- Fault: [Info]" not in text
    # The text filter matches the Major text (cnc_search_alarms text='failed to onboard').
    assert filter_alarms([ALARM_CLEARED_INFO, ALARM_CLEARED], text="failed to onboard") == [
        ALARM_CLEARED_INFO
    ]
    assert filter_alarms([ALARM_CLEARED_INFO], text="software type yet") == [ALARM_CLEARED_INFO]
    # Info-only cleared alarm: the Info row is all there is, and the detail view says so.
    assert alarm_text(ALARM_CLEARED_INFO_ONLY) == (
        "[Info] pipeline health updating: HEALTHY | cleared: confirm health"
    )
    assert (
        "- Fault: [Info] pipeline health updating: HEALTHY (newest non-Clear event — no "
        "Critical/Major/Minor/Warning event recorded, 2025-09-13T08:11:40Z)"
    ) in alarm_markdown(ALARM_CLEARED_INFO_ONLY, NOW)


def test_ack_hist_lines_are_per_day_counts_whatever_the_platform_order():
    """AckHist rows come back in no stable order (verified live 2026-09-14: the same
    alarm answered UnAck, UnAck, Ack, Ack, UnAck, Ack — two consecutive UnAcks are
    impossible), so the rendering is a per-day tally that cannot imply a sequence."""
    rows = [
        {"CreatedBy": "mcp-admin", "Description": "UnAck", "Timestamp": "2026-09-14 00:00:00.0"},
        {"CreatedBy": "mcp-admin", "Description": "UnAck", "Timestamp": "2026-09-14 00:00:00.0"},
        {"CreatedBy": "mcp-admin", "Description": "Ack", "Timestamp": "2026-09-14 00:00:00.0"},
        {"CreatedBy": "ops", "Description": "Ack", "Timestamp": "2026-09-14 00:00:00.0"},
        {"CreatedBy": "mcp-admin", "Description": "UnAck", "Timestamp": "2026-09-13 00:00:00.0"},
        {"CreatedBy": "mcp-admin", "Description": "Ack", "Timestamp": "2026-09-13 00:00:00.0"},
    ]
    expected = [
        "- 2026-09-14 (date only): 2 Ack, 2 UnAck — by mcp-admin, ops",
        "- 2026-09-13 (date only): 1 Ack, 1 UnAck — by mcp-admin",
    ]
    # Identical text whatever order the platform used: newest day first, Ack before UnAck.
    assert ack_hist_lines(rows) == expected
    assert ack_hist_lines(list(reversed(rows))) == expected
    # An epoch-ms stamp (never seen live) is rendered ISO; missing fields degrade to '?'.
    assert ack_hist_lines([{"Timestamp": "1757753000000"}]) == [
        "- 2025-09-13T08:43:20Z: 1 ? — by ?"
    ]
    assert ack_hist_lines([]) == []


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
async def test_get_alarm_pages_open_alarms_first_and_renders_history(settings):
    route = mock_all_alarms()
    text = await call_tool_text(build(settings), "cnc_get_alarm", {"alarm_id": ALARM_ID})
    # An open alarm is found in the open-only scope: one page, no second pass.
    assert route.call_count == 1 and sent(route) == PAGE0_OPEN
    assert alarm_criteria(ALARM_FETCH_PAGE, 0) == "select * from alarm limit 200 page 0"
    assert f"# Alarm {ALARM_ID}" in text
    assert "- State: Major (category System)" in text
    assert "- Acknowledged: False" in text
    assert f"- Object: Device P2 ({P2_UUID}) (object_id {P2_UUID})" in text
    assert "- Created: 2025-09-13T08:00:00Z (age " in text
    assert ") — Updated: 2025-09-13T09:00:00Z (" in text and " ago)" in text
    assert "- Events: 2" in text and "[Major] SNMP timeout (e-1, 2025-09-13T08:00:00Z)" in text
    assert "Stale-alarm check" not in text  # it has events
    assert "## Acknowledgement history (2)" in text
    assert "(AckHist is a per-day tally only:" in text
    assert "no stable order" in text and "verified live 2026-09-14" in text
    assert (
        "a note-less ack/un-ack writes the platform note 'Alarm acknowledged' / "
        "'Alarm unacknowledged', an ack with a note stores that note instead."
    ) in text
    # The Notes are NOT sold as a complete ack timeline: an accepted ack was observed
    # live (e564077d, 2026-09-14 03:31Z) leaving no note, so the note says the AckHist
    # count may exceed the ack notes and that the mechanism is unverified.
    assert "NOT guaranteed complete" in text
    assert "alarm e564077d, 2026-09-14 03:31Z" in text
    assert "AckHist count may exceed its ack notes" in text and "unverified" in text
    for claim in ("exact and complete", "every accepted", "the ack/un-ack timeline"):
        assert claim not in text
    # AckHist is rendered as per-day COUNTS (date-only stamps, never a bogus ISO time),
    # not as rows: the platform's row order is meaningless (verified live 2026-09-14).
    assert "- 2025-09-13 (date only): 1 Ack, 1 UnAck — by admin" in text
    assert "admin: Ack" not in text and "admin: UnAck" not in text
    assert "## Notes (2, newest first, permanent)" in text
    assert text.index("- 2025-09-13T08:45:00Z admin: Alarm unacknowledged") < text.index(
        "- 2025-09-13T08:43:20Z admin: checked by ops"
    )


def test_alarm_markdown_sorts_notes_newest_first_and_flags_stale_alarms():
    reversed_notes = {**ALARM, "Notes": list(reversed(ALARM["Notes"]))}
    text = alarm_markdown(reversed_notes, NOW)
    assert text.index("Alarm unacknowledged") < text.index("checked by ops")
    text = alarm_markdown(ALARM_STALE, NOW)
    assert (
        "- Created: 2025-08-07T15:30:24Z (age 37d) — Updated: 2025-08-07T16:00:26Z (37d ago)"
        in (text)
    )
    assert "- Events: 0" in text
    assert (
        "- Stale-alarm check: 0 events and no update for 37d. Possibly stale — Crosswork does "
        "not auto-clear such alarms (verified live 2026-09-14 on pod-health alarms). For "
        '"<pod> is down." alarms confirm with cnc_get_cluster_health / '
        "cnc_list_microservices(app_id=...); for any other alarm verify the underlying "
        "condition before reporting it as current."
    ) in text
    assert "## Acknowledgement history (0)\n- none" in text
    assert "## Notes (0, newest first, permanent)\n- none" in text


def test_alarm_markdown_ack_tally_exceeding_the_notes_is_explained():
    """The live e564077d shape (read 2026-09-14 03:56Z): 3 Ack + 3 UnAck on 09-14 in
    AckHist against only 2 ack-time notes ('agent test', 'agent2 test') plus 3 'Alarm
    unacknowledged' — the 03:31:53Z ack (accepted, sent with a note) left no note. The
    renderer must show both lists as they are and say the Notes may be short."""
    alarm = {
        **ALARM,
        "AlarmId": "e564077d-91ca-49ad-bd29-42701ba9400c",
        "AckHist": [
            {"CreatedBy": "mcp-admin", "Description": what, "Timestamp": "2026-09-14 00:00:00.0"}
            for what in ("UnAck", "UnAck", "Ack", "Ack", "UnAck", "Ack")
        ],
        "Notes": [
            {"CreatedBy": "mcp-admin", "Description": "agent test", "Timestamp": "1789352160494"},
            {
                "CreatedBy": "mcp-admin",
                "Description": "Alarm unacknowledged",
                "Timestamp": "1789352177848",
            },
            {
                "CreatedBy": "mcp-admin",
                "Description": "cnc-mcp smoke note",
                "Timestamp": "1789356713308",
            },
            {
                "CreatedBy": "mcp-admin",
                "Description": "Alarm unacknowledged",
                "Timestamp": "1789356713407",
            },
            {"CreatedBy": "mcp-admin", "Description": "agent2 test", "Timestamp": "1789357701613"},
            {
                "CreatedBy": "mcp-admin",
                "Description": "Alarm unacknowledged",
                "Timestamp": "1789357727723",
            },
        ],
    }
    text = alarm_markdown(alarm, NOW)
    assert "- 2026-09-14 (date only): 3 Ack, 3 UnAck — by mcp-admin" in text
    assert "## Notes (6, newest first, permanent)" in text
    assert text.count("Alarm unacknowledged") == 3 + ACK_HIST_NOTE.count("Alarm unacknowledged")
    assert "Alarm acknowledged'" in ACK_HIST_NOTE  # the note-less ack fact stays
    assert "cnc-mcp smoke ack" not in text  # the ack that left nothing
    # Nothing in the rendering claims the Notes are the complete ack timeline.
    assert "NOT guaranteed complete" in text
    assert "exact and complete" not in text and "the ack/un-ack timeline" not in text


@respx.mock
async def test_get_alarm_markdown_shows_the_fault_of_a_cleared_alarm(settings):
    """A Cleared alarm's Description is the clearing event's text, so the detail view
    names the fault (newest fault-severity event) on its own line."""
    mock_all_alarms()
    text = await call_tool_text(build(settings), "cnc_get_alarm", {"alarm_id": "a-3"})
    assert "- State: Clear (category System)" in text
    assert (
        "- Description: Device P1 is reachable (the clearing event's text — the platform's "
        "Description is always the newest event's)"
    ) in text
    assert (
        "- Fault: [Major] Device P1 is unreachable (newest fault-severity event, "
        "2025-09-12T18:00:00Z)"
    ) in text
    # Events are listed as sent (newest first).
    assert text.index("[Clear] Device P1 is reachable (e-9,") < text.index(
        "[Major] Device P1 is unreachable (e-8,"
    )
    assert "Stale-alarm check" not in text
    # An open alarm keeps the plain Description line.
    text = await call_tool_text(build(settings), "cnc_get_alarm", {"alarm_id": ALARM_ID})
    assert "- Description: Device P2 is unreachable\n" in text and "- Fault:" not in text


def test_alarm_markdown_cleared_alarm_without_events_says_so():
    text = alarm_markdown(ALARM_CLEARED_NO_EVENTS, NOW)
    assert "- Description: cwm-solutions-automation-0 is healthy. (the clearing event" in text
    assert "- Fault: not recorded (0 events)" in text
    assert "Stale-alarm check" not in text  # cleared alarms are never flagged stale


@respx.mock
async def test_get_alarm_names_the_major_fault_of_an_nso_onboarding_alarm(settings):
    """cnc_get_alarm on the live Major -> Info -> Clear shape (6ddc88ed) shows the
    Major fault, not the Info progress row, in both markdown and (raw) JSON."""
    mock_all_alarms({"state": "Success", "alarms": [ALARM_CLEARED_INFO, ALARM]})
    text = await call_tool_text(
        build(settings), "cnc_get_alarm", {"alarm_id": "6ddc88ed-d679-4d4d-9c9a-a9f879550fee"}
    )
    assert "- Description: NSO device is in sync. (the clearing event's text" in text
    assert (
        "- Fault: [Major] Failed to onboard the node on NSO. NSO Reported Error: Node does "
        "not have a software type yet. (newest fault-severity event, 2025-09-13T08:10:00Z)"
    ) in text
    assert "- Fault: [Info]" not in text
    # The Info row is still listed among the events, newest first.
    assert (
        text.index("[Clear] NSO device is in sync. (e-14,")
        < text.index("[Info] Node was onboarded on NSO. (e-12,")
        < text.index("software type yet. (e-11,")
    )
    data = json.loads(
        await call_tool_text(
            build(settings),
            "cnc_get_alarm",
            {"alarm_id": "6ddc88ed-d679-4d4d-9c9a-a9f879550fee", "response_format": "json"},
        )
    )
    assert data == ALARM_CLEARED_INFO


@respx.mock
async def test_get_alarm_json_is_the_raw_alarm_and_finds_cleared_ones(settings):
    route = mock_all_alarms()
    text = await call_tool_text(
        build(settings), "cnc_get_alarm", {"alarm_id": "A-3", "response_format": "json"}
    )
    assert json.loads(text) == ALARM_CLEARED
    # Not open -> second pass over open+cleared (page 0 of each scope).
    assert route.call_count == 2
    assert sent(route, 0) == PAGE0_OPEN and sent(route, 1) == PAGE0_ALL


def synthetic_alarms(start: int, count: int, state: str = "Info") -> list[dict]:
    return [
        {
            "AlarmId": f"syn-{n}",
            "AlarmCategory": "System",
            "State": state,
            "Acknowledge": False,
            "Description": f"synthetic {n}",
            "object_description": "obj",
            "events_count": 1,
            "Created": str(1757750400000 + n),
            "Updated": str(1757750400000 + n),
        }
        for n in range(start, start + count)
    ]


def mock_paged_alarms(pages: list[list[dict]]) -> respx.Route:
    """Answer ``limit N page M`` with pages[M] (empty beyond the last), any scope."""

    def answer(request: httpx.Request) -> httpx.Response:
        criteria = json.loads(request.content)["criteria"]
        assert criteria.startswith(f"select * from alarm limit {ALARM_FETCH_PAGE} page ")
        page = int(criteria.rsplit(" ", 1)[1])
        rows = pages[page] if page < len(pages) else []
        return httpx.Response(200, json={"state": "Success", "alarms": rows})

    return respx.post(QUERY_URL).mock(side_effect=answer)


@respx.mock
async def test_alarm_fetch_pages_until_a_short_page_and_dedupes(settings):
    """The no-limit criteria caps at 100 rows (verified live 2026-09-14), so the
    collection is paged with limit 200 until a page comes back short; a row repeated
    across pages is kept once."""
    full = synthetic_alarms(0, ALARM_FETCH_PAGE)
    route = mock_paged_alarms([full, [full[0], *synthetic_alarms(ALARM_FETCH_PAGE, 3), ALARM]])
    text = await call_tool_text(
        build(settings),
        "cnc_search_alarms",
        {"open_only": False, "limit": 1, "response_format": "json"},
    )
    data = json.loads(text)
    assert route.call_count == 2  # page 1 was short -> no page 2
    assert sent(route, 0)["criteria"] == alarm_criteria(ALARM_FETCH_PAGE, 0)
    assert sent(route, 1)["criteria"] == alarm_criteria(ALARM_FETCH_PAGE, 1)
    assert data["fetched"] == ALARM_FETCH_PAGE + 4 and data["total"] == ALARM_FETCH_PAGE + 4
    assert data["items"][0]["AlarmId"] == ALARM_ID  # newest Updated, found on page 1


@respx.mock
async def test_get_alarm_beyond_the_first_page_is_found(settings):
    """The live failure mode: an open alarm that the capped no-limit read dropped."""
    route = mock_paged_alarms([synthetic_alarms(0, ALARM_FETCH_PAGE), [ALARM]])
    text = await call_tool_text(build(settings), "cnc_get_alarm", {"alarm_id": ALARM_ID})
    assert f"# Alarm {ALARM_ID}" in text and route.call_count == 2
    text = await call_tool_text(
        build(settings), "cnc_search_alarms", {"text": "P2 is unreachable", "limit": 5}
    )
    assert ALARM_ID in text and f"{ALARM_FETCH_PAGE + 1} fetched" in text


@respx.mock
async def test_alarm_fetch_runaway_guard_stops_and_warns(settings, monkeypatch, caplog):
    monkeypatch.setattr(fault, "ALARM_FETCH_MAX_PAGES", 2)
    full = synthetic_alarms(0, ALARM_FETCH_PAGE)
    route = mock_paged_alarms([full, full, full, full])
    with caplog.at_level("WARNING", logger="cnc_mcp.tools.fault"):
        text = await call_tool_text(
            build(settings),
            "cnc_search_alarms",
            {"open_only": False, "limit": 1, "response_format": "json"},
        )
    assert route.call_count == 2
    assert json.loads(text)["fetched"] == ALARM_FETCH_PAGE  # the repeated page was deduped
    assert "alarm fetch stopped after 2 pages" in caplog.text


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
    assert route.call_count == 1 and sent(route) == PAGE0_ALL
    lines = [line for line in text.splitlines() if line.startswith("- [")]
    # Newest Updated first: the cleared P1 alarm (Updated 1757760000000) before P2. Every
    # line carries state, ack flag, event count, created/updated ISO and the age (the age
    # depends on the wall clock, so it is checked by shape only). The cleared alarm's
    # Description is the clearing event's text ("Device P1 is reachable"), so it matched
    # "UNREACHABLE" through its fault event and the line shows the fault before the
    # clear text.
    assert len(lines) == 2
    assert lines[0].startswith(
        "- [Clear] Device P1 (p1) — [Major] Device P1 is unreachable | cleared: Device P1 is "
        "reachable (a-3, ack=False, events=2, "
        "created=2025-09-12T18:00:00Z, updated=2025-09-13T10:40:00Z, age="
    )
    assert lines[1].startswith(
        f"- [Major] Device P2 ({P2_UUID}) — Device P2 is unreachable ({ALARM_ID}, ack=False, "
        "events=2, created=2025-09-13T08:00:00Z, updated=2025-09-13T09:00:00Z, age="
    )
    assert all(line.endswith("d)") for line in lines)  # the fixtures are a year old
    assert "2 shown of 2 matches, 3 fetched, open and cleared, sort updated_desc" in text
    assert "Stale-alarm check" not in text


@respx.mock
async def test_search_alarms_matches_and_renders_cleared_alarms_by_fault_text(settings):
    body = {"state": "Success", "alarms": [ALARM_CLEARED_NO_EVENTS, ALARM_CLEARED, ALARM]}
    mock_all_alarms(body)
    # "reachable" is in the clear text of a-3 and in the fault text of a-3 and P2 —
    # the cleared pod-health alarm (no Events) does not match.
    text = await call_tool_text(
        build(settings), "cnc_search_alarms", {"text": "is unreachable", "open_only": False}
    )
    lines = [line for line in text.splitlines() if line.startswith("- [")]
    assert [line.split(", ack=")[0].rsplit("(", 1)[1] for line in lines] == ["a-3", ALARM_ID]
    # The cleared pod-health alarm renders its clear text and says the fault is gone.
    text = await call_tool_text(
        build(settings), "cnc_search_alarms", {"state": "clear", "open_only": False}
    )
    assert (
        "- [Clear] cwm-solutions-automation-0 health is down. — cwm-solutions-automation-0 is "
        "healthy. | original fault not recorded (0 events) (a-4, ack=False, events=0, "
    ) in text
    assert "Stale-alarm check" not in text  # cleared, so never flagged stale
    assert "- [Clear] Device P1 (p1) — [Major] Device P1 is unreachable | cleared: " in text


@respx.mock
async def test_search_alarms_finds_and_renders_the_major_fault_behind_an_info_row(settings):
    """Live 2026-09-14: cnc_search_alarms(text='failed to onboard', open_only=False)
    missed the NSO-onboarding alarms because their newest non-Clear event is the Info
    row "Node was onboarded on NSO." — the Major fault must be matched and rendered."""
    pce = {
        **ALARM_CLEARED_INFO,
        "AlarmId": "72395fe4-fc89-46ce-abf7-5eb030cdf739",
        "object_description": "Device PCE (73a30c7a-8e61-4b38-afc8-f2ac88537ee0)",
        "Updated": "1757751040000",
    }
    mock_all_alarms(
        {"state": "Success", "alarms": [ALARM_CLEARED_INFO_ONLY, pce, ALARM_CLEARED_INFO, ALARM]}
    )
    text = await call_tool_text(
        build(settings), "cnc_search_alarms", {"text": "failed to onboard", "open_only": False}
    )
    lines = [line for line in text.splitlines() if line.startswith("- [")]
    assert [line.split(", ack=")[0].rsplit("(", 1)[1] for line in lines] == [
        "6ddc88ed-d679-4d4d-9c9a-a9f879550fee",
        "72395fe4-fc89-46ce-abf7-5eb030cdf739",
    ]
    assert (
        f"- [Clear] Device PE2 ({PE2_UUID}) — [Major] Failed to onboard the node on NSO. NSO "
        "Reported Error: Node does not have a software type yet. | cleared: NSO device is in "
        "sync. (6ddc88ed-"
    ) in text
    assert "[Info] Node was onboarded on NSO." not in text
    # The Info-only cleared alarm keeps its Info row as the (only available) fault text.
    text = await call_tool_text(
        build(settings), "cnc_search_alarms", {"state": "clear", "open_only": False}
    )
    assert (
        "- [Clear] pipeline — [Info] pipeline health updating: HEALTHY | cleared: confirm "
        "health (a-info, ack=False, events=2, "
    ) in text


@respx.mock
async def test_search_alarms_sort_parameter(settings):
    route = mock_all_alarms()
    text = await call_tool_text(
        build(settings),
        "cnc_search_alarms",
        {"open_only": False, "sort": "created_desc", "response_format": "json"},
    )
    data = json.loads(text)
    assert data["sort"] == "created_desc"
    assert [a["AlarmId"] for a in data["items"]] == [ALARM_ID, "a-2", "a-3"]
    text = await call_tool_text(
        build(settings), "cnc_search_alarms", {"open_only": False, "sort": "PLATFORM"}
    )
    assert "sort platform)" in text
    lines = [line for line in text.splitlines() if line.startswith("- [")]
    assert [line.split(", ack=")[0].rsplit("(", 1)[1] for line in lines] == ["a-2", ALARM_ID, "a-3"]
    assert route.call_count == 2
    text = await call_tool_text(build(settings), "cnc_search_alarms", {"sort": "newest"})
    assert text.startswith("Error: Unknown sort order 'newest'. Use one of: updated_desc")
    assert route.call_count == 2  # rejected before any call


@respx.mock
async def test_search_alarms_flags_stale_pod_health_alarms(settings):
    mock_all_alarms(ALL_WITH_STALE)
    text = await call_tool_text(build(settings), "cnc_search_alarms", {"state": "Major"})
    assert (
        "- [Major] cwm-api-service — cwm-api-service is down. (a-stale, ack=False, events=0, "
        in (text)
    )
    assert text.rstrip().endswith(
        "Stale-alarm check: 1 of the alarms shown has 0 events and no update for "
        f"{STALE_ALARM_DAYS}+ days. Possibly stale — Crosswork does not auto-clear such alarms "
        '(verified live 2026-09-14 on pod-health alarms). For "<pod> is down." alarms confirm '
        "with cnc_get_cluster_health / cnc_list_microservices(app_id=...); for any other alarm "
        "verify the underlying condition before reporting it as current."
    )
    # The footer counts only the alarms SHOWN (limit applies first).
    text = await call_tool_text(
        build(settings), "cnc_search_alarms", {"state": "Major", "sort": "created_desc", "limit": 1}
    )
    assert "a-stale" not in text and "Stale-alarm check" not in text
    assert "1 more matched; raise limit or narrow." in text


@respx.mock
async def test_search_alarms_default_scope_state_and_ack_filters(settings):
    route = mock_all_alarms()
    text = await call_tool_text(
        build(settings),
        "cnc_search_alarms",
        {"state": "critical", "acknowledged": True, "category": "system", "limit": 1},
    )
    assert route.call_count == 1 and sent(route) == PAGE0_OPEN
    assert "- [Critical] Data Gateway dg-01 — Collection job failed (a-2, ack=True" in text
    assert ALARM_ID not in text and "a-3" not in text


@respx.mock
async def test_search_alarms_limit_caps_and_reports_the_rest(settings):
    mock_all_alarms()
    text = await call_tool_text(
        build(settings),
        "cnc_search_alarms",
        {"open_only": False, "limit": 1, "response_format": "json"},
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
    assert query.call_count == 1 and sent(query) == PAGE0_OPEN
    assert sent(put) == {"alarmId": ALARM_ID, "ack": True, "note": "INC-1234"}
    assert text.startswith(f"Alarm {ALARM_ID} acknowledged. The flag settles within a few seconds")
    assert "re-read with cnc_get_alarm" in text
    # The permanent residue is spelled out (no delete API for AckHist entries or notes).
    assert (
        "Residue: an AckHist 'Ack' entry, the note 'INC-1234' as a Notes entry — permanent, "
        "no delete API."
    ) in text.split("\n\n", 1)[0]
    # With a note the platform stores only that note (observed live): no platform note.
    assert "platform note" not in text.split("\n\n", 1)[0]
    assert "Alarm unacknowledged" not in text.split("\n\n", 1)[0]
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
    # An un-ack makes the platform append its own permanent note (verified live).
    assert (
        "Residue: an AckHist 'UnAck' entry, the platform note 'Alarm unacknowledged' — "
        "permanent, no delete API."
    ) in text.split("\n\n", 1)[0]


@respx.mock
async def test_acknowledge_without_note_reports_the_platform_note(make_settings):
    """A note-less ack is NOT note-free: the platform appends 'Alarm acknowledged'
    (observed live on the 2026-09-13 scout alarm — the text appears in no script or
    test, yet sits in the Notes between two 'Alarm unacknowledged' entries)."""
    mock_all_alarms()
    put = respx.put(ACK_URL).mock(
        return_value=httpx.Response(200, json={"state": "Success", "Message": "admin"})
    )
    text = await call_tool_text(
        writable(make_settings), "cnc_acknowledge_alarm", {"alarm_id": ALARM_ID}
    )
    assert sent(put) == {"alarmId": ALARM_ID, "ack": True}
    head = text.split("\n\n", 1)[0]
    assert head.startswith(f"Alarm {ALARM_ID} acknowledged.")
    assert (
        "Residue: an AckHist 'Ack' entry, the platform note 'Alarm acknowledged' — "
        "permanent, no delete API."
    ) in head
    assert "Alarm unacknowledged" not in head
    assert json.loads(text.split("\n\n", 1)[1])["note"] is None


@respx.mock
async def test_unacknowledge_with_note_reports_the_note_and_hedges_the_platform_note(
    make_settings,
):
    """Every live un-ack was note-less, so whether a user note replaces the platform's
    'Alarm unacknowledged' (as it does for an ack) is unverified — say so."""
    mock_all_alarms()
    put = respx.put(ACK_URL).mock(
        return_value=httpx.Response(200, json={"state": "Success", "Message": "admin"})
    )
    text = await call_tool_text(
        writable(make_settings),
        "cnc_acknowledge_alarm",
        {"alarm_id": "a-2", "acknowledge": False, "note": "handing back"},
    )
    assert sent(put) == {"alarmId": "a-2", "ack": False, "note": "handing back"}
    head = text.split("\n\n", 1)[0]
    assert (
        "Residue: an AckHist 'UnAck' entry, the note 'handing back' as a Notes entry "
        "(whether the platform also adds 'Alarm unacknowledged' next to a user note is "
        "unverified) — permanent, no delete API."
    ) in head
    assert "the platform note" not in head


async def test_alarm_tool_docstrings_state_the_verified_facts(make_settings):
    """The agent-facing descriptions carry the live-verified ordering / residue facts."""
    tools = {t.name: t.description or "" for t in await writable(make_settings).list_tools()}
    events = tools["cnc_list_events"]
    assert "newest first" in events and "verified live 2026-09-14" in events
    assert "Timestamp descending" in events
    search = tools["cnc_search_alarms"]
    assert "NOT newest-first" in search and "sort='created_desc'" in search
    # The stale-alarm advice is generic (the heuristic is), with the pod-health check
    # scoped to "<pod> is down." alarms.
    for doc in (search, tools["cnc_get_alarm"]):
        flat = " ".join(doc.split())  # docstrings wrap mid-phrase
        assert "does not auto-clear such alarms" in flat
        assert 'For "<pod> is down." alarms' in flat and "cnc_get_cluster_health" in flat
        assert "verify the underlying condition" in flat
        assert "does not auto-clear pod-health alarms" not in flat
    assert "DATE-ONLY" in tools["cnc_get_alarm"]
    assert '"Alarm acknowledged" / "Alarm unacknowledged"' in tools["cnc_get_alarm"]
    ack = tools["cnc_acknowledge_alarm"]
    assert "PERMANENT RESIDUE" in ack and "Alarm unacknowledged" in ack and "DATE-ONLY" in ack
    # AckHist order is unstable live (agent round 2026-09-14): no tool may call it
    # chronological; the Notes' epoch-ms timestamps date the calls that left a note.
    for doc in (tools["cnc_get_alarm"], ack):
        assert "chronolog" not in doc.lower() and "UNORDERED" in doc
        assert "no stable order" in " ".join(doc.split()) and "Notes" in doc
    assert "per-day counts" in tools["cnc_get_alarm"]
    # The Notes are NOT claimed to be a complete ack timeline: an accepted ack was
    # observed live (e564077d, 2026-09-14 03:31Z) leaving no note, and the mechanism
    # is unverified — both docstrings say so and neither asserts completeness.
    for doc in (tools["cnc_get_alarm"], ack):
        flat = " ".join(doc.split())
        assert "e564077d" in flat and "2026-09-14 03:31Z" in flat and "UNVERIFIED" in flat
        assert "AckHist" in flat and "may exceed" in flat and "write-phase smoke" in flat
        for claim in (
            "are complete",
            "exact and complete",
            "every accepted call leaves",
            "every accepted ack/un-ack leaves",
            "no note-free ack",
            "the ack/un-ack timeline",
        ):
            assert claim not in flat
    assert "NOT a complete ack timeline" in " ".join(tools["cnc_get_alarm"].split())
    # A Cleared alarm's Description is the clearing event's text: both listings and the
    # detail view say so and render the fault — the newest FAULT-SEVERITY event, never
    # an Info row (live: the NSO-onboarding alarms' "Node was onboarded on NSO.").
    for name in ("cnc_search_alarms", "cnc_get_alarm"):
        flat = " ".join(tools[name].split())
        assert "CLEARED ALARMS" in flat and "verified live 2026-09-14" in flat
        assert "newest fault-severity event" in flat and "CLEARING event's text" in flat
        assert "Critical/Major/Minor/Warning" in flat and "Info" in flat
        assert "Node was onboarded on NSO." in flat
        assert "newest non-Clear event" not in flat
    assert "| cleared: " in " ".join(search.split())
    assert "original fault not recorded (0 events)" in " ".join(search.split())
    # Page-size naming is kept stable (agents' schemas) but spelled out: 'limit' is the
    # page size of the paged alarm tools and a plain cap in the search tool.
    schema = {t.name: t.input_schema for t in await writable(make_settings).list_tools()}
    for name in ("cnc_list_events", "cnc_list_device_alarms", "cnc_list_event_types"):
        assert "this tool's page size" in schema[name]["properties"]["limit"]["description"]
        assert "page_size" not in schema[name]["properties"]
    search_limit = schema["cnc_search_alarms"]["properties"]["limit"]["description"]
    assert (
        "not a page size" in search_limit
        and "page" not in schema["cnc_search_alarms"]["properties"]
    )
    assert "limit (this tool's page size" in " ".join(tools["cnc_list_events"].split())
    assert "limit (this tool's page size" in " ".join(tools["cnc_list_device_alarms"].split())
    assert "NOT a page size" in " ".join(search.split())
    # A note-less ack stores the platform note 'Alarm acknowledged' (observed live);
    # the old "unverified (every live ack carried one)" claim is gone.
    assert "Alarm acknowledged" in ack and "with a note only that note is stored" in ack
    assert "every live ack carried one" not in ack
    assert "un-ack WITH a note" in ack and "UNVERIFIED" in ack
    annotate = tools["cnc_annotate_alarm"]
    assert "permanent" in annotate.lower() and '"Alarm acknowledged"' in annotate
    schema = {t.name: t.input_schema for t in await writable(make_settings).list_tools()}
    assert schema["cnc_search_alarms"]["properties"]["sort"]["default"] == "updated_desc"
    note_doc = schema["cnc_acknowledge_alarm"]["properties"]["note"]["description"]
    assert "PERMANENT" in note_doc and "Omitting it does NOT avoid a note" in note_doc


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
