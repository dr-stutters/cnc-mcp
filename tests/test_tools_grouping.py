"""Grouping tools end-to-end through MCPServer (schema validation included).

The module is registered directly (not through build_server) so the test does
not depend on tools/__init__.py's module list. All HTTP is mocked with respx.
Fixtures: the ``device/rule/conditions`` document as verified live on
Crosswork 7.2 (2026-09-13, see the platform notes "Grouping") and the bare
uuid list of ``group/root/<classifiers>/uuid``; the hierarchy, group-details
and group-devices documents follow the 7.2 OpenAPI examples (the lab has no
device groups, so those were not exercised with real uuids).
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
from cnc_mcp.tools import grouping
from cnc_mcp.tools.grouping import (
    DEFAULT_CLASSIFIERS,
    DEFAULT_DEVICE_END,
    DEFAULT_DEVICE_START,
    MAX_DEVICE_END,
    as_count,
    check_result,
    condition_kind,
    condition_line,
    conditions_of,
    count_groups,
    csv_path_segment,
    device_line,
    device_page,
    group_details_url,
    group_devices_url,
    group_line,
    group_tree_lines,
    has_children,
    hierarchies_url,
    hierarchy_entries,
    operator_names,
    root_groups_url,
    root_uuids,
    split_csv,
)
from tests.conftest import BASE_URL, call_tool_text

GROUPING = f"{BASE_URL}/crosswork/grouping/v1/grouping"
DEVICE_CONDITIONS_URL = f"{GROUPING}/device/rule/conditions"
PORT_CONDITIONS_URL = f"{GROUPING}/ports/rule/conditions"
ROOT_URL = f"{GROUPING}/group/root/PortType,UserDefinedPorts/uuid"

PORT_TYPE_UUID = "efc42cda-6ce5-4a47-ad96-d1e08a16b228"
USER_PORTS_UUID = "9ac87805-69a9-403c-9fda-a0d892f362a8"
GROUP_UUID = "f76ef571-dda1-49cc-aeb4-d98b2aac06b0"
PARENT_UUID = "e2305b86-6a2c-425d-abb1-bd0660656e86"
DEVICE_UUID = "d4f18380-dd49-469d-97c7-857ea51f74a6"

OPERATORS = [
    {"operatorName": name}
    for name in (
        "SO_Matches",
        "SO_NotMatches",
        "SO_Contains",
        "SO_NotContains",
        "SO_StartWith",
        "SO_EndWith",
        "SO_Equals",
        "SO_NotEquals",
        "SO_InRange",
    )
]
# Verified live: every device attribute is STRING with the nine SO_* operators.
DEVICE_CONDITIONS = {
    "conditions": [
        {"attributeName": name, "type": "STRING", "operators": OPERATORS}
        for name in ("node_ip", "description", "hostname", "product_type", "software_type")
    ]
}
PORT_CONDITIONS = {
    "conditions": [
        {
            "attributeName": "name",
            "type": "STRING",
            "operators": [{"operatorName": "SO_Matches"}, {"operatorName": "SO_NotMatches"}],
        },
        {"attributeName": "speed", "type": "STRING", "operators": [{"operatorName": "SO_Equals"}]},
    ]
}
# Verified live: a bare JSON list of uuids (2 on the lab for the port classifiers).
ROOT_UUIDS = [PORT_TYPE_UUID, USER_PORTS_UUID]
# 7.2 OpenAPI example of GET groups/<uuids> (brief view).
HIERARCHY_BRIEF = [
    {"uuid": PORT_TYPE_UUID, "name": "Port Type", "classifier": "PortType"},
    {"uuid": USER_PORTS_UUID, "name": "User Defined", "classifier": "UserDefinedPorts"},
]
# What direct=true can answer: the parent and its direct children only, no grandchildren.
HIERARCHY_DIRECT = [
    {
        "uuid": PARENT_UUID,
        "name": "All Locations",
        "classifier": "LocationDevices",
        "discoveryType": "StaticSystem",
        "nodeType": "Group",
        "childrenCount": 2,
        "children": [
            {
                "uuid": GROUP_UUID,
                "name": "Test",
                "classifier": "LocationDevices",
                "discoveryType": "Static",
                "nodeType": "Group",
                "parentUuid": PARENT_UUID,
                "parentName": "All Locations",
                "childrenCount": 1,
            },
            {
                "uuid": "66666666-7777-8888-9999-000000000000",
                "name": "Unassigned",
                "classifier": "LocationDevices",
                "description": "Devices with no location",
                "childrenCount": 0,
            },
        ],
    }
]
# GroupDTO with nested grandchildren (document shape; not observed live) — what
# direct=false (the entire hierarchy) can answer.
HIERARCHY_TREE = [
    {
        "uuid": PARENT_UUID,
        "name": "All Locations",
        "classifier": "LocationDevices",
        "discoveryType": "StaticSystem",
        "nodeType": "Group",
        "childrenCount": 2,
        "children": [
            {
                "uuid": GROUP_UUID,
                "name": "Test",
                "classifier": "LocationDevices",
                "discoveryType": "Static",
                "nodeType": "Group",
                "parentUuid": PARENT_UUID,
                "parentName": "All Locations",
                "childrenCount": 1,
                "children": [
                    {
                        "uuid": "11111111-2222-3333-4444-555555555555",
                        "name": "Rack 1",
                        "classifier": "LocationDevices",
                        "discoveryType": "Dynamic",
                        "nodeType": "Group",
                        "childrenCount": 0,
                        "children": [],
                    }
                ],
            },
            {
                "uuid": "66666666-7777-8888-9999-000000000000",
                "name": "Unassigned",
                "classifier": "LocationDevices",
                "description": "Devices with no location",
                "childrenCount": 0,
            },
        ],
    }
]
# 7.2 OpenAPI example of GET group/<uuid>/details.
GROUP_DETAILS = {
    "status": "Success",
    "group": {
        "uuid": GROUP_UUID,
        "name": "Test",
        "description": "",
        "discoveryType": "Static",
        "nodeType": "Group",
        "classifier": "LocationDevices",
        "parentUuid": PARENT_UUID,
        "parentName": "All Locations",
        "childrenCount": 0,
        "operations": {
            "showMem": True,
            "addMem": True,
            "upd": True,
            "cpf": True,
            "mv": 1,
            "del": True,
            "subGrp": True,
        },
    },
}
# 7.2 OpenAPI example of GET device/<uuid>.
GROUP_DEVICES = {
    "status": "Success",
    "devices": [
        {
            "uuid": DEVICE_UUID,
            "attributes": {
                "product_family": "Routers",
                "node_ip": "0.0.0.0",
                "software_type": "",
                "description": "",
                "delete": False,
                "hostname": "",
                "product_type": "Cisco ASR 9006 Router",
                "contact": "",
                "last_update": 1741773113,
                "product_series": "Cisco ASR 9000 Series Aggregation Services Routers",
                "location": "",
                "software_version": "",
                "reachability": "CONN_STATE_REACHABLE",
                "discoveryType": "Static",
            },
        }
    ],
    "total": 1,
}
PE1_DEVICE = {
    "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "attributes": {
        "hostname": "PE1",
        "node_ip": "10.0.0.1",
        "product_type": "Cisco 8201 Router",
        "software_type": "IOS XR",
        "software_version": "7.11.2",
        "reachability": "CONN_STATE_REACHABLE",
        "discoveryType": "Dynamic",
        "last_update": 1757750400,
        "location": "Lab",
        "custom": {"role": "pe"},
    },
}

ALL_TOOLS = {
    "cnc_list_group_rule_conditions",
    "cnc_list_root_groups",
    "cnc_get_group_hierarchy",
    "cnc_get_group_details",
    "cnc_list_group_devices",
}


def build(settings: Settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    grouping.register(mcp, ctx)
    return mcp


# --- registration ------------------------------------------------------------


async def test_every_tool_is_a_read(make_settings):
    tools = {t.name: t for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert set(tools) == ALL_TOOLS
    for name, tool in tools.items():
        assert tool.annotations.read_only_hint is True, name
        assert tool.annotations.idempotent_hint is True, name
        assert tool.annotations.destructive_hint is False, name
    # Nothing new appears when writes are enabled: no write tools exist in this module.
    names = {t.name for t in await build(make_settings(enable_writes=True)).list_tools()}
    assert names == ALL_TOOLS


async def test_group_hierarchy_schema_states_the_inverted_platform_defaults(settings):
    # The 7.2 spec defaults are brief=false / direct=true; the tool defaults to the opposite
    # and must say so where the agent reads the schema.
    tools = {t.name: t for t in await build(settings).list_tools()}
    props = tools["cnc_get_group_hierarchy"].input_schema["properties"]
    assert props["brief"]["default"] is True and props["direct"]["default"] is False
    assert "platform's own default is the opposite (brief=false)" in props["brief"]["description"]
    assert "platform's own default is the opposite (direct=true)" in props["direct"]["description"]
    assert "brief=false&direct=true" in (tools["cnc_get_group_hierarchy"].description or "")
    props = tools["cnc_list_group_devices"].input_schema["properties"]
    assert props["start"]["default"] == 0 and props["end"]["default"] == 100


# --- pure helpers ------------------------------------------------------------


def test_condition_kind_is_case_insensitive_and_rejects_the_rest():
    assert condition_kind("device") == "device"
    assert condition_kind(" Port ") == "port"
    assert condition_kind("PORTS") == "port"
    with pytest.raises(PlatformError, match="Unknown rule-condition kind 'links'. Use one of"):
        condition_kind("links")
    with pytest.raises(PlatformError, match="Unknown rule-condition kind ''"):
        condition_kind("")


def test_split_csv_and_path_segment():
    assert split_csv(" PortType, UserDefinedPorts ,, ", "classifiers") == [
        "PortType",
        "UserDefinedPorts",
    ]
    with pytest.raises(PlatformError, match="classifiers must name at least one value"):
        split_csv(" , ,", "classifiers")
    assert csv_path_segment(["a b", "c/d"]) == "a%20b,c%2Fd"
    assert root_groups_url(["PortType", "UserDefinedPorts"]).endswith(
        "/group/root/PortType,UserDefinedPorts/uuid"
    )
    assert hierarchies_url([PORT_TYPE_UUID]).endswith(f"/groups/{PORT_TYPE_UUID}")
    assert group_details_url(GROUP_UUID).endswith(f"/group/{GROUP_UUID}/details")
    assert group_devices_url(GROUP_UUID).endswith(f"/device/{GROUP_UUID}")


def test_conditions_of_and_condition_line():
    assert len(conditions_of(DEVICE_CONDITIONS)) == 5
    assert conditions_of(DEVICE_CONDITIONS["conditions"]) == DEVICE_CONDITIONS["conditions"]
    assert conditions_of({"conditions": []}) == []
    assert conditions_of({"conditions": None}) == []  # Go's nil slice spelling of "none"
    # An error document, a dict without the list, an empty body and junk are never "no conditions".
    with pytest.raises(PlatformError, match="Rule-conditions read failed: boom"):
        conditions_of({"status": "Error", "error": "boom"})
    with pytest.raises(PlatformError, match=r'expected \{"conditions": \[\.\.\.\]\}, got: \{\}'):
        conditions_of({})
    with pytest.raises(PlatformError, match="answered an empty body"):
        conditions_of(None)
    with pytest.raises(PlatformError, match="got: junk"):
        conditions_of("junk")
    assert operator_names({"operators": [{"operatorName": "SO_Equals"}, "SO_InRange", {}, 3]}) == [
        "SO_Equals",
        "SO_InRange",
    ]
    line = condition_line(PORT_CONDITIONS["conditions"][0])
    assert line == "- name (STRING): SO_Matches, SO_NotMatches"
    assert condition_line({"attributeName": "x"}) == "- x (?): (no operators listed)"


def test_root_uuids_accepts_list_and_json_string_bodies():
    assert root_uuids(ROOT_UUIDS) == ROOT_UUIDS
    assert root_uuids(json.dumps(ROOT_UUIDS)) == ROOT_UUIDS  # the document's "string" schema
    assert root_uuids([]) == []
    assert root_uuids([PORT_TYPE_UUID, None, ""]) == [PORT_TYPE_UUID]
    with pytest.raises(PlatformError, match="expected a JSON list of uuids"):
        root_uuids({"uuids": ROOT_UUIDS})
    with pytest.raises(PlatformError, match="got text: not json"):
        root_uuids("not json")


def test_root_uuids_never_masks_an_error_as_empty():
    # Only [] is a genuine empty answer: an empty body is a distinct failure, and the
    # ResultDTO error envelope must surface the platform's text (like hierarchy_entries).
    with pytest.raises(PlatformError, match="Root-group read: the platform answered an empty body"):
        root_uuids(None)
    with pytest.raises(PlatformError, match="Root-group read failed: boom"):
        root_uuids({"status": "Error", "error": "boom"})
    with pytest.raises(PlatformError, match=r"expected a JSON list of uuids, got: \{\}"):
        root_uuids({})


def test_hierarchy_entries_tolerates_the_three_shapes():
    assert hierarchy_entries(HIERARCHY_BRIEF) == HIERARCHY_BRIEF
    assert hierarchy_entries(HIERARCHY_BRIEF[0]) == [HIERARCHY_BRIEF[0]]
    assert hierarchy_entries({"groups": HIERARCHY_BRIEF}) == HIERARCHY_BRIEF
    assert hierarchy_entries([]) == []
    assert hierarchy_entries({"groups": []}) == []
    assert hierarchy_entries([None, "x", *HIERARCHY_BRIEF]) == HIERARCHY_BRIEF


def test_hierarchy_entries_never_masks_an_error_as_empty():
    # The ResultDTO envelope the rest of the service uses must surface its text.
    with pytest.raises(PlatformError, match="Group hierarchy read failed: Group not found"):
        hierarchy_entries({"status": "Error", "error": "Group not found"})
    with pytest.raises(PlatformError, match="answered an empty body"):
        hierarchy_entries(None)
    with pytest.raises(PlatformError, match=r"expected a JSON list of groups, got: \{\}"):
        hierarchy_entries({})
    with pytest.raises(PlatformError, match="got: junk"):
        hierarchy_entries("junk")


def test_as_count_coerces_numeric_strings_and_rejects_the_rest():
    assert as_count(7) == 7
    assert as_count(0) == 0
    assert as_count("7") == 7  # the collection service's string-count idiom
    assert as_count(" 12 ") == 12
    assert as_count(True) is None  # a bool is not a count even though it is an int
    assert as_count(None) is None
    assert as_count("") is None
    assert as_count("many") is None
    assert as_count(-1) is None
    assert as_count("-1") is None


def test_device_page_never_lets_total_turn_has_more_off_on_a_full_window():
    three = [PE1_DEVICE, PE1_DEVICE, PE1_DEVICE]
    # Full window, total == count (the "total is this answer" reading): still has_more.
    page = device_page(three, 3, 3, 6)
    assert page["window_full"] is True and page["has_more"] is True
    assert page["next_offset"] == 6 and page["total"] == 3 and page["count"] == 3
    # Full window, no total: has_more from fullness alone.
    page = device_page(three, None, 0, 3)
    assert page["window_full"] is True and page["has_more"] is True and page["next_offset"] == 3
    # Short window, no total: nothing more.
    page = device_page([PE1_DEVICE], None, 0, 100)
    assert page["window_full"] is False and page["has_more"] is False
    assert page["next_offset"] is None
    # Short window, total == start + count: nothing more.
    page = device_page([PE1_DEVICE], 1, 0, 100)
    assert page["window_full"] is False and page["has_more"] is False
    # Short window, total claims more: has_more (unverified), next_offset skips nothing.
    page = device_page([PE1_DEVICE], 7, 0, 100)
    assert page["window_full"] is False and page["has_more"] is True and page["next_offset"] == 1
    # Empty window at start 0 with a positive total: has_more (the total is not trusted either way).
    page = device_page([], 3, 0, 100)
    assert page["has_more"] is True and page["next_offset"] == 0
    # The platform returned MORE than the window: still a full window, offset moves past all of it.
    page = device_page(three, 3, 0, 2)
    assert page["window_full"] is True and page["next_offset"] == 3


def test_group_tree_lines_indent_children_and_count_them():
    assert has_children(HIERARCHY_BRIEF) is False
    assert has_children(HIERARCHY_DIRECT) is True
    assert has_children(HIERARCHY_TREE) is True
    assert count_groups(HIERARCHY_BRIEF) == 2
    assert count_groups(HIERARCHY_DIRECT) == 3
    assert count_groups(HIERARCHY_TREE) == 4
    lines = group_tree_lines(HIERARCHY_TREE)
    assert lines[0].startswith(f"- **All Locations** ({PARENT_UUID}) classifier=LocationDevices")
    assert "discoveryType=StaticSystem nodeType=Group childrenCount=2" in lines[0]
    assert lines[1].startswith(f"  - **Test** ({GROUP_UUID})")
    assert f"parent=All Locations ({PARENT_UUID})" in lines[1]
    assert lines[2].startswith("    - **Rack 1** (11111111-2222-3333-4444-555555555555)")
    assert lines[3].startswith("  - **Unassigned** (66666666-7777-8888-9999-000000000000)")
    assert lines[3].endswith("childrenCount=0 — Devices with no location")
    assert group_line({"uuid": "u", "name": "n", "classifier": "c", "extra": 1}) == (
        '**n** (u) classifier=c other={"extra":1}'
    )


def test_check_result_status_handling():
    assert check_result(GROUP_DETAILS, "Group details read") is GROUP_DETAILS
    partial = {"status": "Partial", "devices": [], "error": "one member unresolved"}
    assert check_result(partial, "Group devices read") is partial
    with pytest.raises(PlatformError, match="Group details read failed: no such group"):
        check_result({"status": "Error", "error": "no such group"}, "Group details read")
    with pytest.raises(PlatformError, match="Group details read failed: no reason given"):
        check_result({"status": "Error"}, "Group details read")
    with pytest.raises(PlatformError, match=r"expected a JSON object, got: \[\]"):
        check_result([], "Group details read")
    with pytest.raises(PlatformError, match="answered an empty body where a JSON object"):
        check_result(None, "Group details read")


def test_device_line_renders_present_attributes_only():
    line = device_line(GROUP_DEVICES["devices"][0])
    assert line.startswith(f"- **(no hostname)** ({DEVICE_UUID}) ip=0.0.0.0 ")
    assert "type=Cisco ASR 9006 Router sw=- reachability=CONN_STATE_REACHABLE" in line
    assert "product_family=Routers discoveryType=Static updated=2025-03-12T09:51:53Z" in line
    assert "location=" not in line and "other=" not in line
    line = device_line(PE1_DEVICE)
    assert line.startswith("- **PE1** (aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee) ip=10.0.0.1 ")
    assert "type=Cisco 8201 Router sw=IOS XR 7.11.2 reachability=CONN_STATE_REACHABLE" in line
    assert "location=Lab" in line and 'other={"custom":{"role":"pe"}}' in line
    assert device_line({"uuid": "x"}) == "- **(no hostname)** (x) ip=- type=- sw=- reachability=-"


# --- cnc_list_group_rule_conditions -----------------------------------------


@respx.mock
async def test_list_rule_conditions_device_markdown(settings):
    route = respx.get(DEVICE_CONDITIONS_URL).mock(
        return_value=httpx.Response(200, json=DEVICE_CONDITIONS)
    )
    text = await call_tool_text(build(settings), "cnc_list_group_rule_conditions", {})
    assert route.called and str(route.calls[0].request.url) == DEVICE_CONDITIONS_URL
    assert "# Device group rule conditions (5)" in text
    assert (
        "- hostname (STRING): SO_Matches, SO_NotMatches, SO_Contains, SO_NotContains, "
        "SO_StartWith, SO_EndWith, SO_Equals, SO_NotEquals, SO_InRange"
    ) in text
    assert "- node_ip (STRING):" in text and "- software_type (STRING):" in text


@respx.mock
async def test_list_rule_conditions_port_json(settings):
    route = respx.get(PORT_CONDITIONS_URL).mock(
        return_value=httpx.Response(200, json=PORT_CONDITIONS)
    )
    text = await call_tool_text(
        build(settings),
        "cnc_list_group_rule_conditions",
        {"kind": "Port", "response_format": "json"},
    )
    assert str(route.calls[0].request.url) == PORT_CONDITIONS_URL
    payload = json.loads(text)
    assert payload["kind"] == "port" and payload["count"] == 2
    assert payload["items"] == PORT_CONDITIONS["conditions"]


@respx.mock
async def test_list_rule_conditions_unknown_kind_sends_nothing(settings):
    route = respx.get(DEVICE_CONDITIONS_URL).mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(
        build(settings), "cnc_list_group_rule_conditions", {"kind": "interface"}
    )
    assert text.startswith(
        "Error: Unknown rule-condition kind 'interface'. Use one of: device, port"
    )
    assert not route.called


@respx.mock
async def test_list_rule_conditions_empty_is_not_an_error(settings):
    respx.get(PORT_CONDITIONS_URL).mock(return_value=httpx.Response(200, json={"conditions": []}))
    text = await call_tool_text(build(settings), "cnc_list_group_rule_conditions", {"kind": "port"})
    assert text == "No port rule conditions are reported."


@respx.mock
async def test_list_rule_conditions_error_document_and_empty_body_are_errors(settings):
    respx.get(DEVICE_CONDITIONS_URL).mock(
        return_value=httpx.Response(200, json={"status": "Error", "error": "boom"})
    )
    text = await call_tool_text(build(settings), "cnc_list_group_rule_conditions", {})
    assert text == "Error: Rule-conditions read failed: boom"
    respx.get(DEVICE_CONDITIONS_URL).mock(return_value=httpx.Response(200, content=b""))
    text = await call_tool_text(build(settings), "cnc_list_group_rule_conditions", {})
    assert text.startswith("Error: Rule-conditions read: the platform answered an empty body")
    respx.get(DEVICE_CONDITIONS_URL).mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(build(settings), "cnc_list_group_rule_conditions", {})
    assert text.startswith('Error: Rule-conditions read: expected {"conditions": [...]}, got: {}')


@respx.mock
async def test_list_rule_conditions_500_is_an_http_error(settings):
    respx.get(DEVICE_CONDITIONS_URL).mock(return_value=httpx.Response(500, json={"error": "boom"}))
    text = await call_tool_text(build(settings), "cnc_list_group_rule_conditions", {})
    assert text.startswith("Error: API request failed with status 500.")
    assert "Platform said: boom" in text


# --- cnc_list_root_groups ---------------------------------------------------


@respx.mock
async def test_list_root_groups_default_classifiers(settings):
    route = respx.get(ROOT_URL).mock(return_value=httpx.Response(200, json=ROOT_UUIDS))
    text = await call_tool_text(build(settings), "cnc_list_root_groups", {})
    assert DEFAULT_CLASSIFIERS == "PortType,UserDefinedPorts"
    assert str(route.calls[0].request.url) == ROOT_URL
    assert "# Root groups for PortType, UserDefinedPorts (2)" in text
    assert f"- {PORT_TYPE_UUID}" in text and f"- {USER_PORTS_UUID}" in text
    assert "cnc_get_group_hierarchy expands these uuids" in text


@respx.mock
async def test_list_root_groups_json_and_string_body(settings):
    url = f"{GROUPING}/group/root/PortType/uuid"
    # The OpenAPI document types the body as a string holding a JSON list.
    route = respx.get(url).mock(return_value=httpx.Response(200, json=json.dumps([PORT_TYPE_UUID])))
    text = await call_tool_text(
        build(settings),
        "cnc_list_root_groups",
        {"classifiers": " PortType ", "response_format": "json"},
    )
    assert str(route.calls[0].request.url) == url
    assert json.loads(text) == {
        "classifiers": ["PortType"],
        "count": 1,
        "uuids": [PORT_TYPE_UUID],
    }


@respx.mock
async def test_list_root_groups_empty_list_is_not_an_error(settings):
    # Verified live: the device classifier guesses answer [] on the lab.
    url = f"{GROUPING}/group/root/DeviceGroup,Device,Devices/uuid"
    respx.get(url).mock(return_value=httpx.Response(200, json=[]))
    text = await call_tool_text(
        build(settings), "cnc_list_root_groups", {"classifiers": "DeviceGroup,Device,Devices"}
    )
    assert text.startswith("No root groups for classifiers DeviceGroup, Device, Devices")
    assert "verified names are PortType, UserDefinedPorts" in text
    assert not text.startswith("Error")


@respx.mock
async def test_list_root_groups_blank_classifiers_sends_nothing(settings):
    route = respx.get(url__regex=r".*").mock(return_value=httpx.Response(200, json=[]))
    text = await call_tool_text(build(settings), "cnc_list_root_groups", {"classifiers": " , "})
    assert text == "Error: classifiers must name at least one value (comma-separated)."
    assert not route.called


@respx.mock
async def test_list_root_groups_404_is_an_http_error(settings):
    respx.get(ROOT_URL).mock(return_value=httpx.Response(404, text="404 page not found"))
    text = await call_tool_text(build(settings), "cnc_list_root_groups", {})
    assert text.startswith("Error: API request failed with status 404.")
    assert "does not serve this path" in text


@respx.mock
async def test_list_root_groups_non_list_answer_is_an_error(settings):
    respx.get(ROOT_URL).mock(return_value=httpx.Response(200, json={"status": "Success"}))
    text = await call_tool_text(build(settings), "cnc_list_root_groups", {})
    assert text.startswith("Error: Root-group read: expected a JSON list of uuids")
    # A 200 with an EMPTY body is not "the platform answered an empty list".
    respx.get(ROOT_URL).mock(return_value=httpx.Response(200, content=b""))
    text = await call_tool_text(build(settings), "cnc_list_root_groups", {})
    assert text.startswith("Error: Root-group read: the platform answered an empty body")
    assert "empty list" not in text
    text = await call_tool_text(
        build(settings), "cnc_list_root_groups", {"response_format": "json"}
    )
    assert text.startswith("Error: Root-group read: the platform answered an empty body")


@respx.mock
async def test_list_root_groups_status_error_is_an_error(settings):
    # Mirrors test_get_group_hierarchy_status_error_is_an_error: the ResultDTO envelope
    # must surface the platform's text, not a raw dict repr.
    respx.get(ROOT_URL).mock(
        return_value=httpx.Response(200, json={"status": "Error", "error": "Unknown classifier"})
    )
    text = await call_tool_text(build(settings), "cnc_list_root_groups", {})
    assert text == "Error: Root-group read failed: Unknown classifier"


# --- cnc_get_group_hierarchy ------------------------------------------------


@respx.mock
async def test_get_group_hierarchy_flat_list_and_params(settings):
    url = f"{GROUPING}/groups/{PORT_TYPE_UUID},{USER_PORTS_UUID}"
    route = respx.get(url).mock(return_value=httpx.Response(200, json=HIERARCHY_BRIEF))
    text = await call_tool_text(
        build(settings),
        "cnc_get_group_hierarchy",
        {"group_uuids": f"{PORT_TYPE_UUID}, {USER_PORTS_UUID}"},
    )
    request = route.calls[0].request
    assert request.url.copy_with(query=None) == httpx.URL(url)
    assert dict(request.url.params) == {"brief": "true", "direct": "false"}
    assert (
        "# Group hierarchy (2 group(s), entire hierarchy, brief view, no sub-groups returned)"
        in text
    )
    assert f"- **Port Type** ({PORT_TYPE_UUID}) classifier=PortType" in text
    assert f"- **User Defined** ({USER_PORTS_UUID}) classifier=UserDefinedPorts" in text


@respx.mock
async def test_get_group_hierarchy_direct_and_full_view_is_one_level(settings):
    # direct=true can only answer direct children, so the fixture carries no grandchildren.
    url = f"{GROUPING}/groups/{PARENT_UUID}"
    route = respx.get(url).mock(return_value=httpx.Response(200, json=HIERARCHY_DIRECT))
    text = await call_tool_text(
        build(settings),
        "cnc_get_group_hierarchy",
        {"group_uuids": PARENT_UUID, "brief": False, "direct": True},
    )
    assert dict(route.calls[0].request.url.params) == {"brief": "false", "direct": "true"}
    assert "# Group hierarchy (3 group(s), direct sub-groups, full view, tree)" in text
    assert f"\n- **All Locations** ({PARENT_UUID})" in text
    assert f"\n  - **Test** ({GROUP_UUID})" in text and "childrenCount=1" in text
    assert "\n  - **Unassigned** (66666666-7777-8888-9999-000000000000)" in text
    assert "Rack 1" not in text and "\n    - " not in text


@respx.mock
async def test_get_group_hierarchy_entire_tree_with_full_view(settings):
    # direct=false (the tool's default) is what can answer a grandchild.
    url = f"{GROUPING}/groups/{PARENT_UUID}"
    route = respx.get(url).mock(return_value=httpx.Response(200, json=HIERARCHY_TREE))
    text = await call_tool_text(
        build(settings),
        "cnc_get_group_hierarchy",
        {"group_uuids": PARENT_UUID, "brief": False},
    )
    assert dict(route.calls[0].request.url.params) == {"brief": "false", "direct": "false"}
    assert "# Group hierarchy (4 group(s), entire hierarchy, full view, tree)" in text
    assert f"\n- **All Locations** ({PARENT_UUID})" in text
    assert f"\n  - **Test** ({GROUP_UUID})" in text
    assert "\n    - **Rack 1** (11111111-2222-3333-4444-555555555555)" in text
    assert "\n  - **Unassigned** (66666666-7777-8888-9999-000000000000)" in text


@respx.mock
async def test_get_group_hierarchy_json(settings):
    respx.get(f"{GROUPING}/groups/{PARENT_UUID}").mock(
        return_value=httpx.Response(200, json=HIERARCHY_TREE)
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_group_hierarchy",
        {"group_uuids": PARENT_UUID, "response_format": "json"},
    )
    payload = json.loads(text)
    assert payload["count"] == 4 and payload["requested"] == [PARENT_UUID]
    assert payload["brief"] is True and payload["direct"] is False
    assert payload["items"] == HIERARCHY_TREE


@respx.mock
async def test_get_group_hierarchy_empty_is_not_an_error(settings):
    url = f"{GROUPING}/groups/{GROUP_UUID}"
    respx.get(url).mock(return_value=httpx.Response(200, json=[]))
    text = await call_tool_text(
        build(settings), "cnc_get_group_hierarchy", {"group_uuids": GROUP_UUID}
    )
    assert text.startswith(f"No groups were returned for uuids {GROUP_UUID}")
    assert "answered an empty list" in text
    respx.get(url).mock(return_value=httpx.Response(200, json={"groups": []}))
    text = await call_tool_text(
        build(settings), "cnc_get_group_hierarchy", {"group_uuids": GROUP_UUID}
    )
    assert text.startswith(f"No groups were returned for uuids {GROUP_UUID}")


@respx.mock
async def test_get_group_hierarchy_status_error_is_an_error(settings):
    # Mirrors test_get_group_details_status_error_is_an_error: the ResultDTO envelope
    # the rest of the service uses must not read as "no groups".
    respx.get(f"{GROUPING}/groups/nope").mock(
        return_value=httpx.Response(200, json={"status": "Error", "error": "Group not found"})
    )
    text = await call_tool_text(build(settings), "cnc_get_group_hierarchy", {"group_uuids": "nope"})
    assert text == "Error: Group hierarchy read failed: Group not found"


@respx.mock
async def test_get_group_hierarchy_empty_body_and_bad_shape_are_errors(settings):
    url = f"{GROUPING}/groups/{GROUP_UUID}"
    respx.get(url).mock(return_value=httpx.Response(200, content=b""))
    text = await call_tool_text(
        build(settings), "cnc_get_group_hierarchy", {"group_uuids": GROUP_UUID}
    )
    assert text.startswith("Error: Group hierarchy read: the platform answered an empty body")
    assert "empty list" not in text
    respx.get(url).mock(return_value=httpx.Response(200, json={"status": "Success"}))
    text = await call_tool_text(
        build(settings),
        "cnc_get_group_hierarchy",
        {"group_uuids": GROUP_UUID, "response_format": "json"},
    )
    assert text.startswith("Error: Group hierarchy read: expected a JSON list of groups, got:")


@respx.mock
async def test_get_group_hierarchy_blank_uuids_sends_nothing(settings):
    route = respx.get(url__regex=r".*").mock(return_value=httpx.Response(200, json=[]))
    text = await call_tool_text(build(settings), "cnc_get_group_hierarchy", {"group_uuids": ","})
    assert text == "Error: group_uuids must name at least one value (comma-separated)."
    assert not route.called


@respx.mock
async def test_get_group_hierarchy_500_is_an_http_error(settings):
    respx.get(f"{GROUPING}/groups/{GROUP_UUID}").mock(return_value=httpx.Response(500, text=""))
    text = await call_tool_text(
        build(settings), "cnc_get_group_hierarchy", {"group_uuids": GROUP_UUID}
    )
    assert text.startswith("Error: API request failed with status 500.")
    assert "EMPTY body" in text


# --- cnc_get_group_details --------------------------------------------------


@respx.mock
async def test_get_group_details_markdown(settings):
    url = f"{GROUPING}/group/{GROUP_UUID}/details"
    route = respx.get(url).mock(return_value=httpx.Response(200, json=GROUP_DETAILS))
    text = await call_tool_text(
        build(settings), "cnc_get_group_details", {"group_uuid": GROUP_UUID}
    )
    assert str(route.calls[0].request.url) == url
    assert f"# Group Test ({GROUP_UUID})" in text
    assert (
        f"- **Test** ({GROUP_UUID}) classifier=LocationDevices discoveryType=Static "
        f"nodeType=Group childrenCount=0 parent=All Locations ({PARENT_UUID})"
    ) in text
    assert '- operations: {"showMem":true,"addMem":true,"upd":true,"cpf":true,"mv":1' in text
    assert "Partial" not in text


@respx.mock
async def test_get_group_details_json_is_the_raw_document(settings):
    respx.get(f"{GROUPING}/group/{GROUP_UUID}/details").mock(
        return_value=httpx.Response(200, json=GROUP_DETAILS)
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_group_details",
        {"group_uuid": GROUP_UUID, "response_format": "json"},
    )
    assert json.loads(text) == GROUP_DETAILS


@respx.mock
async def test_get_group_details_status_error_is_an_error(settings):
    respx.get(f"{GROUPING}/group/nope/details").mock(
        return_value=httpx.Response(200, json={"status": "Error", "error": "Group not found"})
    )
    text = await call_tool_text(build(settings), "cnc_get_group_details", {"group_uuid": "nope"})
    assert text == "Error: Group details read failed: Group not found"


@respx.mock
async def test_get_group_details_partial_is_reported_in_the_result(settings):
    respx.get(f"{GROUPING}/group/{GROUP_UUID}/details").mock(
        return_value=httpx.Response(
            200, json={**GROUP_DETAILS, "status": "Partial", "error": "member count stale"}
        )
    )
    text = await call_tool_text(
        build(settings), "cnc_get_group_details", {"group_uuid": GROUP_UUID}
    )
    assert not text.startswith("Error")
    assert f"- **Test** ({GROUP_UUID}) classifier=LocationDevices" in text
    assert "- status: Partial — member count stale" in text


@respx.mock
async def test_get_group_details_without_a_group_object(settings):
    url = f"{GROUPING}/group/{GROUP_UUID}/details"
    respx.get(url).mock(return_value=httpx.Response(200, json={"status": "Success"}))
    text = await call_tool_text(
        build(settings), "cnc_get_group_details", {"group_uuid": GROUP_UUID}
    )
    assert text.startswith("# Group ? (?)")
    assert "The platform returned no group object in its answer." in text
    respx.get(url).mock(return_value=httpx.Response(200, content=b""))
    text = await call_tool_text(
        build(settings), "cnc_get_group_details", {"group_uuid": GROUP_UUID}
    )
    assert text.startswith("Error: Group details read: the platform answered an empty body")


@respx.mock
async def test_get_group_details_404_is_an_http_error(settings):
    respx.get(f"{GROUPING}/group/{GROUP_UUID}/details").mock(
        return_value=httpx.Response(404, json={"message": "not found"})
    )
    text = await call_tool_text(
        build(settings), "cnc_get_group_details", {"group_uuid": GROUP_UUID}
    )
    assert text.startswith("Error: API request failed with status 404.")
    assert "Platform said: not found" in text


# --- cnc_list_group_devices -------------------------------------------------


@respx.mock
async def test_list_group_devices_markdown_sends_the_default_window(settings):
    url = f"{GROUPING}/device/{GROUP_UUID}"
    body = {**GROUP_DEVICES, "devices": [*GROUP_DEVICES["devices"], PE1_DEVICE], "total": 2}
    route = respx.get(url).mock(return_value=httpx.Response(200, json=body))
    text = await call_tool_text(
        build(settings), "cnc_list_group_devices", {"group_uuid": GROUP_UUID}
    )
    request = route.calls[0].request
    # The document calls both start and end "essential", so the default call carries them.
    assert (DEFAULT_DEVICE_START, DEFAULT_DEVICE_END) == (0, 100)
    assert request.url.copy_with(query=None) == httpx.URL(url)
    assert dict(request.url.params) == {"start": "0", "end": "100"}
    assert f"# Devices in group {GROUP_UUID} (2; indexes 0-100)" in text
    assert f"- **(no hostname)** ({DEVICE_UUID}) ip=0.0.0.0 type=Cisco ASR 9006 Router" in text
    assert "- **PE1** (aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee) ip=10.0.0.1" in text
    assert "More available" not in text
    assert "The uuids are inventory node uuids" in text


@respx.mock
async def test_list_group_devices_json_with_paging_window(settings):
    url = f"{GROUPING}/device/{GROUP_UUID}"
    route = respx.get(url).mock(return_value=httpx.Response(200, json=GROUP_DEVICES))
    text = await call_tool_text(
        build(settings),
        "cnc_list_group_devices",
        {"group_uuid": GROUP_UUID, "start": 0, "end": 30, "response_format": "json"},
    )
    assert dict(route.calls[0].request.url.params) == {"start": "0", "end": "30"}
    payload = json.loads(text)
    assert payload["group_uuid"] == GROUP_UUID and payload["status"] == "Success"
    assert payload["start"] == 0 and payload["end"] == 30 and payload["offset"] == 0
    assert payload["count"] == 1 and payload["total"] == 1
    assert payload["has_more"] is False and payload["next_offset"] is None
    assert payload["window_full"] is False
    assert payload["items"] == GROUP_DEVICES["devices"]


@respx.mock
async def test_list_group_devices_string_total_is_coerced_and_pages(settings):
    # A numeric-string total (the sibling collection service's idiom) must count.
    url = f"{GROUPING}/device/{GROUP_UUID}"
    body = {"status": "Success", "devices": [PE1_DEVICE], "total": "7"}
    respx.get(url).mock(return_value=httpx.Response(200, json=body))
    text = await call_tool_text(
        build(settings), "cnc_list_group_devices", {"group_uuid": GROUP_UUID}
    )
    assert f"# Devices in group {GROUP_UUID} (1 of 7; indexes 0-100)" in text
    # A short window with a larger total is reported as unverified, never as a
    # "repeat with start=1, end=101" hint that re-requests the range just answered.
    assert (
        "Note: the platform reports total=7 but the window 0-100 was not full "
        "(1 device(s) answered) — what total counts is unverified on this build"
    ) in text
    assert "More available" not in text and "repeat with" not in text
    text = await call_tool_text(
        build(settings),
        "cnc_list_group_devices",
        {"group_uuid": GROUP_UUID, "start": 5, "end": 6, "response_format": "json"},
    )
    payload = json.loads(text)
    assert payload["total"] == 7 and payload["count"] == 1 and payload["offset"] == 5
    assert payload["has_more"] is True and payload["next_offset"] == 6
    assert payload["window_full"] is True


@respx.mock
async def test_list_group_devices_full_window_pages_even_when_total_equals_count(settings):
    # The spec's "total number of devices included in the result" may be this answer's
    # count, so a full window must never stop paging on total's say-so.
    url = f"{GROUPING}/device/{GROUP_UUID}"
    three = [PE1_DEVICE, PE1_DEVICE, PE1_DEVICE]
    respx.get(url).mock(
        return_value=httpx.Response(200, json={"status": "Success", "devices": three, "total": 3})
    )
    text = await call_tool_text(
        build(settings),
        "cnc_list_group_devices",
        {"group_uuid": GROUP_UUID, "start": 3, "end": 6},
    )
    assert f"# Devices in group {GROUP_UUID} (3; indexes 3-6)" in text
    assert (
        "Window full: more may be available — repeat with start=6, end=9 (the platform "
        "reports total=3, which would mean none, but what total counts is unverified"
    ) in text
    text = await call_tool_text(
        build(settings),
        "cnc_list_group_devices",
        {"group_uuid": GROUP_UUID, "start": 3, "end": 6, "response_format": "json"},
    )
    payload = json.loads(text)
    assert payload["count"] == 3 and payload["total"] == 3
    assert payload["has_more"] is True and payload["next_offset"] == 6
    assert payload["window_full"] is True
    # A full window whose total says more is a plain "More available".
    respx.get(url).mock(
        return_value=httpx.Response(200, json={"status": "Success", "devices": three, "total": 9})
    )
    text = await call_tool_text(
        build(settings),
        "cnc_list_group_devices",
        {"group_uuid": GROUP_UUID, "start": 0, "end": 3},
    )
    assert "More available: repeat with start=3, end=6." in text
    assert "Window full" not in text and "Note:" not in text
    # A bool or text total is not a count: no "of N", has_more falls back to a full window.
    respx.get(url).mock(
        return_value=httpx.Response(
            200, json={"status": "Success", "devices": [PE1_DEVICE], "total": True}
        )
    )
    text = await call_tool_text(
        build(settings),
        "cnc_list_group_devices",
        {"group_uuid": GROUP_UUID, "start": 0, "end": 1, "response_format": "json"},
    )
    payload = json.loads(text)
    assert payload["total"] is None and payload["has_more"] is True and payload["next_offset"] == 1


@respx.mock
async def test_list_group_devices_empty_and_partial(settings):
    url = f"{GROUPING}/device/{GROUP_UUID}"
    respx.get(url).mock(
        return_value=httpx.Response(200, json={"status": "Success", "devices": [], "total": 0})
    )
    text = await call_tool_text(
        build(settings), "cnc_list_group_devices", {"group_uuid": GROUP_UUID}
    )
    assert text == f"No devices are members of group {GROUP_UUID} in the index window 0-100."
    respx.get(url).mock(
        return_value=httpx.Response(200, json={"status": "Success", "devices": [], "total": 3})
    )
    text = await call_tool_text(
        build(settings),
        "cnc_list_group_devices",
        {"group_uuid": GROUP_UUID, "start": 50, "end": 60},
    )
    assert text == (
        f"No devices are members of group {GROUP_UUID} in the index window 50-60 "
        "(the platform reports a total of 3; try an earlier window)."
    )
    # There is no earlier window than 0: the unverified total is named, not "tried".
    text = await call_tool_text(
        build(settings), "cnc_list_group_devices", {"group_uuid": GROUP_UUID}
    )
    assert text == (
        f"No devices are members of group {GROUP_UUID} in the index window 0-100 "
        "(the platform reports a total of 3 yet answered none — what total counts is "
        "unverified on this build)."
    )
    respx.get(url).mock(
        return_value=httpx.Response(
            200,
            json={"status": "Partial", "devices": [PE1_DEVICE], "total": 5, "error": "3 pending"},
        )
    )
    text = await call_tool_text(
        build(settings), "cnc_list_group_devices", {"group_uuid": GROUP_UUID}
    )
    assert f"# Devices in group {GROUP_UUID} (1 of 5; indexes 0-100)" in text
    assert "Status Partial: 3 pending" in text


@respx.mock
async def test_list_group_devices_bad_window_sends_nothing(settings):
    route = respx.get(url__regex=r".*").mock(return_value=httpx.Response(200, json=GROUP_DEVICES))
    text = await call_tool_text(
        build(settings), "cnc_list_group_devices", {"group_uuid": GROUP_UUID, "start": 5, "end": 2}
    )
    assert text == "Error: end must be greater than start (e.g. start=0, end=100)."
    text = await call_tool_text(
        build(settings), "cnc_list_group_devices", {"group_uuid": GROUP_UUID, "start": 5, "end": 5}
    )
    assert text.startswith("Error: end must be greater than start")
    # The schema caps the window; an over-cap end is rejected before anything is sent.
    with pytest.raises(ToolError, match="end"):
        await call_tool_text(
            build(settings),
            "cnc_list_group_devices",
            {"group_uuid": GROUP_UUID, "start": 0, "end": MAX_DEVICE_END + 1},
        )
    assert not route.called


@respx.mock
async def test_list_group_devices_status_error_empty_body_and_http_500(settings):
    url = f"{GROUPING}/device/{GROUP_UUID}"
    respx.get(url).mock(
        return_value=httpx.Response(200, json={"status": "Error", "error": "group is a port group"})
    )
    text = await call_tool_text(
        build(settings), "cnc_list_group_devices", {"group_uuid": GROUP_UUID}
    )
    assert text == "Error: Group devices read failed: group is a port group"
    respx.get(url).mock(return_value=httpx.Response(200, content=b""))
    text = await call_tool_text(
        build(settings), "cnc_list_group_devices", {"group_uuid": GROUP_UUID}
    )
    assert text.startswith("Error: Group devices read: the platform answered an empty body")
    respx.get(url).mock(return_value=httpx.Response(500, json={"error": "NATS request failed"}))
    text = await call_tool_text(
        build(settings), "cnc_list_group_devices", {"group_uuid": GROUP_UUID}
    )
    assert text.startswith("Error: API request failed with status 500.")
    assert "NATS request failed" in text
