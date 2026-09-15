"""Grouping writes and the rule / port reads, end-to-end through MCPServer.

All HTTP is mocked with respx. Fixtures reproduce what Crosswork 7.2.0 answered
live on 2026-09-15 (see the module docstring of ``tools/grouping.py``): the
``ResultDTO`` echoes of ``POST/PUT/DELETE group``, ``POST/PUT/DELETE rule`` and
the member move / copy / remove calls, the HTTP-200 ``{"status": "Error",
"error": <code>}`` refusals, the ``rule/group`` and ``rule/classifier``
documents, the windowed ``port/<uuid>`` listing, and the Location tree the
member tools walk to find a device's leaf.
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
    MAX_RULE_CONDITIONS,
    canonical_choice,
    check_result,
    condition_text,
    conditions_payload,
    decode_conditions,
    error_hint,
    flatten_groups,
    match_devices,
    parse_rule_conditions,
    refuse_system_group,
    rule_kind_of,
    rule_line,
    rule_summary,
    rules_of,
    vocabulary_of,
)
from tests.conftest import BASE_URL, call_tool_text

GROUPING = f"{BASE_URL}/crosswork/grouping/v1/grouping"
LOCATION_ROOT = "bac76a9e-5d07-43bd-8199-353fbec19b09"
ALL_LOCATIONS = "7913c888-f691-4c08-ac71-55a35b236e49"
UNASSIGNED = "c820712b-460b-439f-b184-6fa159ae6a7c"
ALL_ACCESS = "21153ff8-4560-4062-977d-cea569c51cd1"
UDP_ROOT = "84b87b1c-8073-4ff3-afd3-db8d4a3f09c1"
GROUP = "22b69d42-4bd4-4636-bbce-ae2786ac5956"
ACCESS_GROUP = "e175a39e-5e6b-4ca0-80de-d6bb8cb02c99"
PORT_GROUP = "1b1b59ab-abda-4130-9b7d-d7151a898891"
RULE = "ec27154e-ece1-4a3d-a8cb-43c6e0f06d09"
PE1 = "af1986fa-e1cb-4f8c-aa83-4f05a00472e7"
PE2 = "ec35be58-de93-49e5-891b-a1c4a11c72e4"
P1 = "30f503cd-65cc-4cb6-b52f-d2b978e4278e"

SO_OPERATORS = [
    {"operatorName": n}
    for n in (
        "SO_Matches",
        "SO_NotMatches",
        "SO_Contains",
        "SO_NotContains",
        "SO_StartWith",
        "SO_EndWith",
        "SO_Equals",
        "SO_NotEquals",
        "SO_Blank",
    )
]
NO_OPERATORS = [
    {"operatorName": n} for n in ("NO_Equals", "NO_NotEquals", "NO_GreaterThan", "NO_LessThan")
]
DEVICE_CONDITIONS = {
    "conditions": [
        {"attributeName": "hostname", "type": "STRING", "operators": SO_OPERATORS},
        {"attributeName": "node_ip", "type": "STRING", "operators": SO_OPERATORS},
    ]
}
# Live 2026-09-15: port ``speed`` is NUMBER-typed with NO_* operators.
PORT_CONDITIONS = {
    "conditions": [
        {"attributeName": "name", "type": "STRING", "operators": SO_OPERATORS},
        {"attributeName": "speed", "type": "NUMBER", "operators": NO_OPERATORS},
    ]
}


def device(uuid: str, hostname: str) -> dict:
    return {"uuid": uuid, "attributes": {"hostname": hostname, "node_ip": "198.18.140.1"}}


def devices_doc(*members: tuple[str, str]) -> dict:
    return {
        "status": "Success",
        "devices": [device(u, h) for u, h in members],
        "total": len(members),
    }


def details(
    uuid: str = GROUP,
    name: str = "phase-d-static",
    classifier: str = "LocationDevices",
    discovery: str = "Static",
    description: str = "phase-d static group",
    parent: str | None = ALL_LOCATIONS,
) -> dict:
    group = {
        "uuid": uuid,
        "name": name,
        "description": description,
        "discoveryType": discovery,
        "nodeType": "Group",
        "classifier": classifier,
        "childrenCount": 0,
        "operations": {"showMem": True, "addMem": True, "upd": True, "del": True},
    }
    if parent:
        group["parentUuid"] = parent
        group["parentName"] = "All Locations"
    return {"status": "Success", "group": group}


def echo(uuid: str = GROUP, name: str = "phase-d-static", classifier: str = "LocationDevices"):
    return {
        "status": "Success",
        "group": {"uuid": uuid, "name": name, "nodeType": "Group", "classifier": classifier},
    }


def rule_doc(
    uuid: str = RULE,
    target: str = GROUP,
    conditions: list[dict] | None = None,
    active: bool = True,
    classifier: str = "LocationDevices",
) -> dict:
    conditions = conditions or [
        {
            "attributeName": "hostname",
            "value": "PE",
            "order": 1,
            "stringCondition": {"operator": "SO_StartWith"},
        }
    ]
    return {
        "uuid": uuid,
        "ordering": 0,
        "name": "phase-d-dynamic",
        "classifier": classifier,
        "active": active,
        # The platform stores the string pretty-printed with newlines.
        "conditions": json.dumps({"conditions": conditions}, indent=2),
        "targetGroupUuid": target,
    }


def error(code: str) -> dict:
    return {"status": "Error", "error": code}


# The Location tree as the member tools read it (brief, direct=false): childrenCount is
# the direct member count there.
LOCATION_TREE = [
    {
        "uuid": LOCATION_ROOT,
        "name": "Location",
        "children": [
            {
                "uuid": ALL_LOCATIONS,
                "name": "All Locations",
                "children": [
                    {"uuid": UNASSIGNED, "name": "Unassigned Devices", "childrenCount": 3},
                    {"uuid": GROUP, "name": "phase-d-static", "childrenCount": 1},
                ],
                "childrenCount": 0,
            }
        ],
    }
]
PORTS_DOC = {
    "status": "Success",
    "ports": [
        {
            "portUuid": "98f03242-78ab-46f4-9858-b28f557f2af1",
            "deviceUuid": PE2,
            "node_ip": "198.18.140.13",
            "hostName": "PE2",
            "portName": "Loopback0",
            "description": "",
            "speed": "0",
            "type": "Software Loopback",
            "delete": False,
            "discoveryType": "Dynamic",
        },
        {
            "portUuid": "ab073163-b962-48d1-9d00-358aeac87e32",
            "deviceUuid": PE1,
            "node_ip": "198.18.140.11",
            "hostName": "PE1",
            "portName": "Loopback0",
            "description": "",
            "speed": "0",
            "type": "Software Loopback",
            "delete": False,
            "discoveryType": "Dynamic",
        },
    ],
    "total": 5,
}


# Read live 2026-09-15: the platform-managed groups that are NOT StaticSystem. The
# PortType system groups (Software Loopback / MPLS Tunnel / Ethernet CSMACD, under the
# 'Port Type' root) and the TopologyTypeDevices auto-groups (AS > 65000 > IGP Domain > 0)
# are ``discoveryType: Dynamic`` with ``operations`` {showMem} or none — no upd / del.
PORT_TYPE_ROOT = "de45410e-14fc-4fb1-9510-31ce45f5e319"
SOFTWARE_LOOPBACK = "bbb78fef-03d7-40bd-a287-f5f4823c439b"
SOFTWARE_LOOPBACK_RULE = "8f69614b-83e2-4dd5-bbfc-3680e6a0c420"
IGP_DOMAIN_0 = "875386ab-d0d2-4386-9ef5-281aa2352584"
SOFTWARE_LOOPBACK_DETAILS = {
    "status": "Success",
    "group": {
        "uuid": SOFTWARE_LOOPBACK,
        "name": "Software Loopback",
        "discoveryType": "Dynamic",
        "nodeType": "Group",
        "classifier": "PortType",
        "parentUuid": PORT_TYPE_ROOT,
        "parentName": "Port Type",
        "childrenCount": 0,
        "operations": {"showMem": True},
    },
}
IGP_DOMAIN_0_DETAILS = {
    "status": "Success",
    "group": {
        "uuid": IGP_DOMAIN_0,
        "name": "0",
        "discoveryType": "Dynamic",
        "nodeType": "Group",
        "classifier": "TopologyTypeDevices",
        "parentUuid": "cdd57f2f-12fc-4f1d-af7d-df6cf14eb4c0",
        "parentName": "IGP Domain",
        "childrenCount": 0,
        "operations": None,
    },
}

WRITE_TOOLS = {
    "cnc_create_device_group",
    "cnc_update_device_group",
    "cnc_delete_device_group",
    "cnc_set_device_group_members",
    "cnc_move_group_members",
}


def build(settings: Settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    grouping.register(mcp, ctx)
    return mcp


@pytest.fixture
def wsettings(make_settings) -> Settings:
    return make_settings(enable_writes=True)


def body_of(route: respx.Route, index: int = 0) -> dict:
    return json.loads(route.calls[index].request.content)


# --- registration ------------------------------------------------------------


async def test_writes_are_gated_and_annotated(make_settings, wsettings):
    names = {t.name for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert not (WRITE_TOOLS & names)
    assert {"cnc_list_group_rules", "cnc_list_group_ports"} <= names
    tools = {t.name: t for t in await build(wsettings).list_tools()}
    assert WRITE_TOOLS <= set(tools)
    for name in WRITE_TOOLS:
        assert tools[name].annotations.read_only_hint is False, name
    # Delete, the PUT full-replace update (rule_conditions='[]' deletes the rule) and the
    # member change (mode 'replace' can empty a group) are destructive; create and the raw
    # move / copy are not.
    for name in (
        "cnc_delete_device_group",
        "cnc_update_device_group",
        "cnc_set_device_group_members",
    ):
        assert tools[name].annotations.destructive_hint is True, name
    for name in ("cnc_create_device_group", "cnc_move_group_members"):
        assert tools[name].annotations.destructive_hint is False, name
    assert tools["cnc_update_device_group"].annotations.idempotent_hint is True
    assert tools["cnc_set_device_group_members"].annotations.idempotent_hint is True
    assert tools["cnc_move_group_members"].annotations.idempotent_hint is False
    # Every str argument carries a length bound (CLAUDE.md Step 4).
    assert (
        tools["cnc_set_device_group_members"].input_schema["properties"]["mode"]["maxLength"] == 16
    )
    assert (
        tools["cnc_move_group_members"].input_schema["properties"]["operation"]["maxLength"] == 16
    )
    # JSON-carrying arguments are plain ``str`` (the SDK pre-parses JSON-looking strings
    # for any other annotation, which turned a '[...]' rule into a list live).
    for name in ("cnc_create_device_group", "cnc_update_device_group"):
        prop = tools[name].input_schema["properties"]["rule_conditions"]
        assert prop["type"] == "string", name


# --- pure helpers ------------------------------------------------------------


def test_parse_rule_conditions_validates_against_the_vocabulary():
    vocabulary = vocabulary_of(PORT_CONDITIONS["conditions"])
    assert vocabulary["speed"]["type"] == "NUMBER"
    wire = parse_rule_conditions(
        '[{"attribute": "name", "operator": "Contains", "value": "Loopback"}]', vocabulary
    )
    assert wire == [
        {
            "order": 1,
            "attributeName": "name",
            "value": "Loopback",
            "stringCondition": {"operator": "SO_Contains"},
        }
    ]
    # A NUMBER attribute takes the numericCondition key; the value is sent as a string;
    # the wire spellings and the {"conditions": [...]} wrapper are accepted as input.
    wire = parse_rule_conditions(
        '{"conditions": [{"attributeName": "speed", "value": 0, '
        '"numericCondition": {"operator": "equals"}}]}',
        vocabulary,
    )
    assert wire == [
        {
            "order": 1,
            "attributeName": "speed",
            "value": "0",
            "numericCondition": {"operator": "NO_Equals"},
        }
    ]
    assert parse_rule_conditions("[]", vocabulary) == []
    assert '"stringCondition":{"operator":"SO_Contains"}' in conditions_payload(
        parse_rule_conditions(
            '[{"attribute":"name","operator":"SO_Contains","value":"x"}]', vocabulary
        )
    )
    with pytest.raises(PlatformError, match="unknown attribute 'bogus'. Known: name, speed"):
        parse_rule_conditions(
            '[{"attribute": "bogus", "operator": "SO_Equals", "value": 1}]', vocabulary
        )
    with pytest.raises(PlatformError, match="unknown operator 'SO_Equals' for 'speed'. Known: NO_"):
        parse_rule_conditions(
            '[{"attribute": "speed", "operator": "SO_Equals", "value": 1}]', vocabulary
        )
    with pytest.raises(PlatformError, match="needs 'attribute', 'operator' and 'value'"):
        parse_rule_conditions('[{"attribute": "name", "operator": "SO_Equals"}]', vocabulary)
    with pytest.raises(PlatformError, match="must be a JSON list such as"):
        parse_rule_conditions("hostname starts with PE", vocabulary)
    with pytest.raises(PlatformError, match="must be a JSON list of condition objects"):
        parse_rule_conditions('"x"', vocabulary)
    with pytest.raises(PlatformError, match=r"rule_conditions\[0\] is not an object"):
        parse_rule_conditions("[3]", vocabulary)
    # Two conditions break the group's member listing live, so they are refused.
    assert MAX_RULE_CONDITIONS == 1
    with pytest.raises(PlatformError, match="at most 1 condition per rule"):
        parse_rule_conditions(
            '[{"attribute": "name", "operator": "SO_Equals", "value": 1}, '
            '{"attribute": "speed", "operator": "NO_Equals", "value": 0}]',
            vocabulary,
        )


def test_rule_rendering_and_error_hints():
    rule = rule_doc()
    assert decode_conditions(rule)[0]["attributeName"] == "hostname"
    assert decode_conditions({"conditions": "not json"}) == []
    assert decode_conditions({"conditions": {"conditions": [{"attributeName": "x"}]}}) == [
        {"attributeName": "x"}
    ]
    assert condition_text(decode_conditions(rule)[0]) == "hostname SO_StartWith 'PE'"
    assert condition_text(
        {"attributeName": "speed", "value": "0", "numericCondition": {"operator": "NO_Equals"}}
    ) == ("speed NO_Equals '0'")
    assert rule_summary({"conditions": "[]"}) == "(no conditions)"
    assert rule_line(rule) == (
        f"- **phase-d-dynamic** ({RULE}) active=True classifier=LocationDevices "
        f"target={GROUP}: hostname SO_StartWith 'PE'"
    )
    assert rules_of([rule], "x") == [rule]
    assert rules_of({"status": "Success", "rule": rule}, "x") == [rule]
    assert rules_of({"rules": []}, "x") == []
    with pytest.raises(PlatformError, match="x failed: boom"):
        rules_of({"status": "Error", "error": "boom"}, "x")
    with pytest.raises(PlatformError, match="empty body where a JSON list of rules was expected"):
        rules_of(None, "x")
    with pytest.raises(PlatformError, match="expected a JSON list of rules, got: 3"):
        rules_of(3, "x")
    assert error_hint("MEMBER_NOT_EXIST").startswith("a device named in the request is not")
    assert "at most one" in error_hint(
        "could not execute statement [ERROR: duplicate key value violates unique constraint "
        '"unq_target_group_uuid"'
    )
    assert error_hint("SOMETHING_ELSE") is None
    # Free text is matched by the LONGEST marker: 'GROUP_NOT_EXIST' is a substring of
    # 'TARGET_GROUP_NOT_EXIST' and must not win.
    assert error_hint("TARGET_GROUP_NOT_EXIST: no such target").startswith(
        "the rule's target group uuid does not exist"
    )
    assert error_hint("GROUP_NOT_EXIST (already deleted)").startswith("no group with that uuid")
    with pytest.raises(PlatformError, match="Delete group failed: GROUP_NOT_EXIST Hint: no group"):
        check_result(error("GROUP_NOT_EXIST"), "Delete group")
    assert canonical_choice(" devicEaccess ", ("LocationDevices", "DeviceAccess"), "c") == (
        "DeviceAccess"
    )
    with pytest.raises(PlatformError, match="Unknown c 'x'. Use one of: LocationDevices"):
        canonical_choice("x", ("LocationDevices",), "c")
    assert rule_kind_of("UserDefinedPorts") == "port"
    with pytest.raises(PlatformError, match="DeviceAccess cannot carry a rule"):
        rule_kind_of("DeviceAccess")


def test_refuse_system_group_keys_on_the_platforms_own_words():
    """StaticSystem, a non-creatable classifier and a missing operation flag each
    refuse; Dynamic alone never does (a rule-populated user port group is Dynamic)."""
    with pytest.raises(PlatformError, match="is a system group .discoveryType StaticSystem"):
        refuse_system_group(details(discovery="StaticSystem")["group"], "deleted")
    with pytest.raises(PlatformError, match=r"platform-managed PortType group .*cannot be deleted"):
        refuse_system_group(SOFTWARE_LOOPBACK_DETAILS["group"], "deleted")
    with pytest.raises(PlatformError, match="platform-managed TopologyTypeDevices group"):
        refuse_system_group(IGP_DOMAIN_0_DETAILS["group"], "changed")
    # A writable classifier whose operations lack the flag: refused for THAT action only.
    no_del = {**details()["group"], "operations": {"showMem": True, "upd": True}}
    with pytest.raises(PlatformError, match="lists no 'del' operation for it"):
        refuse_system_group(no_del, "deleted")
    refuse_system_group(no_del, "updated")
    none = {**details()["group"], "operations": None}
    with pytest.raises(PlatformError, match=r"no 'upd' operation for it \(operations: none\)"):
        refuse_system_group(none, "updated")
    # The three user-group shapes the lab creates all pass every gate.
    location = {**details()["group"], "discoveryType": "Dynamic"}
    location["operations"] = {
        "showMem": True,
        "addMem": True,
        "upd": True,
        "cpf": True,
        "mv": 1,
        "del": True,
        "subGrp": True,
    }
    access = details(ACCESS_GROUP, "phase-d-access", "DeviceAccess")["group"]
    access["operations"] = {"showMem": True, "upd": True, "del": True, "cpt": True, "subGrp": True}
    ports = details(PORT_GROUP, "phase-d-ports", "UserDefinedPorts")["group"]
    ports["operations"] = {"showMem": True, "upd": True, "addMem": True, "rule": True, "del": True}
    for group in (location, access, ports):
        for action in ("deleted", "updated", "changed"):
            refuse_system_group(group, action)


def test_match_devices_and_flatten_groups():
    members = [device(PE1, "PE1"), device(PE2, "PE2")]
    resolved, unresolved = match_devices(["pe1", PE2, "P9"], members)
    assert resolved["pe1"]["uuid"] == PE1 and resolved[PE2]["uuid"] == PE2
    assert unresolved == ["P9"]
    assert [g["name"] for g in flatten_groups(LOCATION_TREE)] == [
        "Location",
        "All Locations",
        "Unassigned Devices",
        "phase-d-static",
    ]


# --- reads: rules and ports -----------------------------------------------------


@respx.mock
async def test_list_group_rules_by_classifier_and_by_group(settings):
    respx.get(f"{GROUPING}/rule/classifier/LocationDevices").mock(
        return_value=httpx.Response(200, json=[rule_doc()])
    )
    text = await call_tool_text(build(settings), "cnc_list_group_rules", {})
    assert "# Rules of classifier LocationDevices (1)" in text
    assert f"- **phase-d-dynamic** ({RULE}) active=True" in text
    assert "hostname SO_StartWith 'PE'" in text
    respx.get(f"{GROUPING}/rule/group/{GROUP}").mock(
        return_value=httpx.Response(200, json={"status": "Success", "rule": rule_doc()})
    )
    text = await call_tool_text(
        build(settings), "cnc_list_group_rules", {"group_uuid": GROUP, "response_format": "json"}
    )
    payload = json.loads(text)
    assert payload["group_uuid"] == GROUP and payload["count"] == 1
    assert payload["items"][0]["conditions_decoded"][0]["value"] == "PE"
    # A static group: RULE_NOT_EXIST is a normal empty answer, not an error.
    respx.get(f"{GROUPING}/rule/group/{GROUP}").mock(
        return_value=httpx.Response(200, json=error("RULE_NOT_EXIST"))
    )
    text = await call_tool_text(build(settings), "cnc_list_group_rules", {"group_uuid": GROUP})
    assert text == (
        f"Group {GROUP} has no rule (a static group — or an unknown uuid: the platform "
        "answers RULE_NOT_EXIST for both; cnc_get_group_details confirms the group exists)."
    )
    respx.get(f"{GROUPING}/rule/classifier/UserDefinedPorts").mock(
        return_value=httpx.Response(200, json=[])
    )
    text = await call_tool_text(
        build(settings), "cnc_list_group_rules", {"classifier": "userdefinedports"}
    )
    assert text == "No rules exist for classifier UserDefinedPorts."


@respx.mock
async def test_list_group_rules_errors(settings):
    route = respx.get(f"{GROUPING}/rule/classifier/DeviceAccess")
    text = await call_tool_text(
        build(settings), "cnc_list_group_rules", {"classifier": "DeviceAccess"}
    )
    assert text.startswith(
        "Error: Unknown rule classifier 'DeviceAccess'. Use one of: LocationDevices"
    )
    assert not route.called
    respx.get(f"{GROUPING}/rule/group/{GROUP}").mock(
        return_value=httpx.Response(200, json=error("boom"))
    )
    text = await call_tool_text(build(settings), "cnc_list_group_rules", {"group_uuid": GROUP})
    assert text == f"Error: Group {GROUP} rule read failed: boom"
    respx.get(f"{GROUPING}/rule/classifier/PortType").mock(
        return_value=httpx.Response(500, json={"error": "NATS request failed"})
    )
    text = await call_tool_text(build(settings), "cnc_list_group_rules", {"classifier": "PortType"})
    assert text.startswith("Error: API request failed with status 500.")


@respx.mock
async def test_list_group_ports_markdown_and_json(settings):
    route = respx.get(f"{GROUPING}/port/{PORT_GROUP}").mock(
        return_value=httpx.Response(200, json=PORTS_DOC)
    )
    text = await call_tool_text(
        build(settings), "cnc_list_group_ports", {"group_uuid": PORT_GROUP, "start": 0, "end": 2}
    )
    assert dict(route.calls[0].request.url.params) == {"start": "0", "end": "2"}
    assert f"# Ports in group {PORT_GROUP} (2 of 5; indexes 0-2)" in text
    assert (
        "- **PE2:Loopback0** (98f03242-78ab-46f4-9858-b28f557f2af1) "
        f"device={PE2} ip=198.18.140.13 type=Software Loopback speed=0 discoveryType=Dynamic"
    ) in text
    assert "More available: repeat with start=2, end=4." in text
    text = await call_tool_text(
        build(settings),
        "cnc_list_group_ports",
        {"group_uuid": PORT_GROUP, "start": 0, "end": 2, "response_format": "json"},
    )
    payload = json.loads(text)
    assert payload["count"] == 2 and payload["total"] == 5 and payload["has_more"] is True
    assert payload["next_offset"] == 2 and payload["items"] == PORTS_DOC["ports"]
    # An empty port group answers no ``ports`` key at all (live).
    respx.get(f"{GROUPING}/port/{PORT_GROUP}").mock(
        return_value=httpx.Response(200, json={"status": "Success", "total": 0})
    )
    text = await call_tool_text(build(settings), "cnc_list_group_ports", {"group_uuid": PORT_GROUP})
    assert text.startswith(f"No ports are members of group {PORT_GROUP} in the index window 0-100")


@respx.mock
async def test_list_group_ports_errors(settings):
    route = respx.get(f"{GROUPING}/port/{PORT_GROUP}")
    text = await call_tool_text(
        build(settings), "cnc_list_group_ports", {"group_uuid": PORT_GROUP, "start": 5, "end": 5}
    )
    assert text == "Error: end must be greater than start (e.g. start=0, end=100)."
    assert not route.called
    # A multi-condition rule makes the platform answer 500 here (verified live).
    route.mock(return_value=httpx.Response(500, json={"error": "Internal Server Error"}))
    text = await call_tool_text(build(settings), "cnc_list_group_ports", {"group_uuid": PORT_GROUP})
    assert text.startswith("Error: API request failed with status 500.")
    route.mock(return_value=httpx.Response(200, json=error("GROUP_NOT_EXIST")))
    text = await call_tool_text(build(settings), "cnc_list_group_ports", {"group_uuid": PORT_GROUP})
    assert text.startswith("Error: Group ports read failed: GROUP_NOT_EXIST Hint: no group")


# --- create -----------------------------------------------------------------------


@respx.mock
async def test_create_device_group_resolves_all_locations_as_the_parent(wsettings):
    respx.get(f"{GROUPING}/group/root/LocationDevices/uuid").mock(
        return_value=httpx.Response(200, json=[LOCATION_ROOT])
    )
    tree = respx.get(f"{GROUPING}/groups/{LOCATION_ROOT}").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "uuid": LOCATION_ROOT,
                    "name": "Location",
                    "children": [{"uuid": ALL_LOCATIONS, "name": "All Locations"}],
                }
            ],
        )
    )
    create = respx.post(f"{GROUPING}/group").mock(
        return_value=httpx.Response(
            200,
            json={
                "status": "Success",
                "group": {
                    "uuid": GROUP,
                    "name": "phase-d-static",
                    "description": "phase-d static group",
                    "nodeType": "Group",
                    "classifier": "LocationDevices",
                },
            },
        )
    )
    text = await call_tool_text(
        build(wsettings),
        "cnc_create_device_group",
        {"name": " phase-d-static ", "description": "phase-d static group"},
    )
    assert dict(tree.calls[0].request.url.params) == {"brief": "true", "direct": "true"}
    assert body_of(create) == {
        "classifier": "LocationDevices",
        "name": "phase-d-static",
        "description": "phase-d static group",
        "parentUuid": ALL_LOCATIONS,
    }
    assert text.startswith(
        f"Group 'phase-d-static' ({GROUP}) created under All Locations ({ALL_LOCATIONS}) "
        "as a static LocationDevices group."
    )
    assert "cnc_set_device_group_members moves devices into it" in text
    payload = json.loads(text[text.index("{") :])
    assert payload["group"]["uuid"] == GROUP and payload["rule"] is None
    assert payload["parent"] == {"uuid": ALL_LOCATIONS, "name": "All Locations"}


@respx.mock
async def test_create_device_group_explicit_parent_and_platform_refusals(wsettings):
    root = respx.get(f"{GROUPING}/group/root/DeviceAccess/uuid")
    create = respx.post(f"{GROUPING}/group").mock(
        return_value=httpx.Response(200, json=echo(ACCESS_GROUP, "phase-d-access", "DeviceAccess"))
    )
    text = await call_tool_text(
        build(wsettings),
        "cnc_create_device_group",
        {"name": "phase-d-access", "classifier": "deviceaccess", "parent_uuid": ALL_ACCESS},
    )
    assert not root.called
    assert (
        body_of(create)["parentUuid"] == ALL_ACCESS
        and body_of(create)["classifier"] == "DeviceAccess"
    )
    assert f"created under parent ({ALL_ACCESS}) as a static DeviceAccess group." in text
    assert "copies devices into it" in text
    # HTTP 200 refusals carry their hint.
    create.mock(return_value=httpx.Response(200, json=error("NAME_ALREADY_EXIST")))
    text = await call_tool_text(
        build(wsettings), "cnc_create_device_group", {"name": "x", "parent_uuid": ALL_LOCATIONS}
    )
    assert text.startswith(
        "Error: Create group 'x' failed: NAME_ALREADY_EXIST Hint: a group with that name"
    )
    create.mock(return_value=httpx.Response(200, json=error("INVALID_PARENT_GROUP")))
    text = await call_tool_text(
        build(wsettings), "cnc_create_device_group", {"name": "x", "parent_uuid": "nope"}
    )
    assert "INVALID_PARENT_GROUP Hint: parent_uuid is not an existing group" in text
    create.mock(return_value=httpx.Response(400, json={"status": 400, "error": "Bad Request"}))
    text = await call_tool_text(
        build(wsettings), "cnc_create_device_group", {"name": "x", "parent_uuid": ALL_LOCATIONS}
    )
    assert text.startswith("Error: API request failed with status 400.")


@respx.mock
async def test_create_device_group_rejects_bad_input_before_sending(wsettings):
    create = respx.post(f"{GROUPING}/group")
    respx.get(f"{GROUPING}/device/rule/conditions").mock(
        return_value=httpx.Response(200, json=DEVICE_CONDITIONS)
    )
    text = await call_tool_text(
        build(wsettings), "cnc_create_device_group", {"name": "x", "classifier": "PortType"}
    )
    assert text.startswith(
        "Error: Unknown group classifier 'PortType'. Use one of: LocationDevices"
    )
    text = await call_tool_text(
        build(wsettings),
        "cnc_create_device_group",
        {
            "name": "x",
            "classifier": "DeviceAccess",
            "rule_conditions": '[{"attribute": "hostname"}]',
        },
    )
    assert text == (
        "Error: Groups of classifier DeviceAccess cannot carry a rule; rules exist for "
        "LocationDevices, UserDefinedPorts, PortType groups."
    )
    bad = '[{"attribute": "hostname", "operator": "SO_Bogus", "value": "PE"}]'
    text = await call_tool_text(
        build(wsettings), "cnc_create_device_group", {"name": "x", "rule_conditions": bad}
    )
    assert text.startswith("Error: rule_conditions[0]: unknown operator 'SO_Bogus' for 'hostname'")
    text = await call_tool_text(
        build(wsettings), "cnc_create_device_group", {"name": "x", "rule_conditions": "[]"}
    )
    assert text.startswith("Error: rule_conditions is an empty list")
    with pytest.raises(ToolError, match="name"):
        await call_tool_text(build(wsettings), "cnc_create_device_group", {"name": ""})
    assert not create.called


@respx.mock
async def test_create_port_group_with_a_numeric_rule(wsettings):
    respx.get(f"{GROUPING}/ports/rule/conditions").mock(
        return_value=httpx.Response(200, json=PORT_CONDITIONS)
    )
    respx.get(f"{GROUPING}/group/root/UserDefinedPorts/uuid").mock(
        return_value=httpx.Response(200, json=[UDP_ROOT])
    )
    respx.get(f"{GROUPING}/groups/{UDP_ROOT}").mock(
        return_value=httpx.Response(200, json=[{"uuid": UDP_ROOT, "name": "User Defined"}])
    )
    create = respx.post(f"{GROUPING}/group").mock(
        return_value=httpx.Response(200, json=echo(PORT_GROUP, "phase-d-ports", "UserDefinedPorts"))
    )
    numeric = [
        {
            "attributeName": "speed",
            "value": "0",
            "order": 1,
            "numericCondition": {"operator": "NO_Equals"},
        }
    ]
    rule = respx.post(f"{GROUPING}/rule").mock(
        return_value=httpx.Response(
            200,
            json={
                "status": "Success",
                "rule": rule_doc("88e1e620-540b-41ef-8c8f-d5f3beaa18ec", PORT_GROUP, numeric),
            },
        )
    )
    text = await call_tool_text(
        build(wsettings),
        "cnc_create_device_group",
        {
            "name": "phase-d-ports",
            "classifier": "UserDefinedPorts",
            "rule_conditions": '[{"attribute": "speed", "operator": "Equals", "value": 0}]',
        },
    )
    assert body_of(create)["parentUuid"] == UDP_ROOT
    sent = body_of(rule)
    assert sent["classifier"] == "UserDefinedPorts" and sent["targetGroupUuid"] == PORT_GROUP
    assert sent["name"] == "phase-d-ports" and sent["active"] is True and sent["ordering"] == 0
    assert isinstance(sent["conditions"], str)  # a JSON STRING, never an object
    assert json.loads(sent["conditions"]) == {"conditions": numeric}
    assert (
        f"created under User Defined ({UDP_ROOT}) as a rule-based UserDefinedPorts group." in text
    )
    assert "members come from its rule (cnc_list_group_ports" in text
    payload = json.loads(text[text.index("{") :])
    assert payload["rule"]["conditions_decoded"] == numeric


@respx.mock
async def test_create_device_group_rule_failure_deletes_the_group_again(wsettings):
    respx.get(f"{GROUPING}/device/rule/conditions").mock(
        return_value=httpx.Response(200, json=DEVICE_CONDITIONS)
    )
    respx.post(f"{GROUPING}/group").mock(return_value=httpx.Response(200, json=echo()))
    respx.post(f"{GROUPING}/rule").mock(
        return_value=httpx.Response(200, json=error("TARGET_GROUP_NOT_EXIST"))
    )
    delete = respx.delete(f"{GROUPING}/group/{GROUP}").mock(
        return_value=httpx.Response(200, json=echo())
    )
    conditions = '[{"attribute": "hostname", "operator": "SO_StartWith", "value": "PE"}]'
    text = await call_tool_text(
        build(wsettings),
        "cnc_create_device_group",
        {"name": "phase-d-static", "parent_uuid": ALL_LOCATIONS, "rule_conditions": conditions},
    )
    assert delete.called
    assert text.startswith(
        "Error: Create rule for group 'phase-d-static' failed: TARGET_GROUP_NOT_EXIST Hint: "
    )
    assert text.endswith(f"The group {GROUP} was deleted again.")
    delete.mock(return_value=httpx.Response(200, json=error("GROUP_NOT_EXIST")))
    text = await call_tool_text(
        build(wsettings),
        "cnc_create_device_group",
        {"name": "phase-d-static", "parent_uuid": ALL_LOCATIONS, "rule_conditions": conditions},
    )
    assert (
        f"The group {GROUP} could NOT be deleted again (GROUP_NOT_EXIST) — remove it with "
        "cnc_delete_device_group."
    ) in text
    # A transport failure on the rollback DELETE (the client raises once its retries are
    # spent, raise_on_error=False notwithstanding) must not mask the rule refusal: the
    # answer still names the rule error, the orphaned uuid and the way to remove it.
    delete.mock(side_effect=httpx.ConnectError("boom"))
    text = await call_tool_text(
        build(wsettings),
        "cnc_create_device_group",
        {"name": "phase-d-static", "parent_uuid": ALL_LOCATIONS, "rule_conditions": conditions},
    )
    assert text.startswith(
        "Error: Create rule for group 'phase-d-static' failed: TARGET_GROUP_NOT_EXIST Hint: "
    )
    assert f"The group {GROUP} could NOT be deleted again (Could not reach the platform" in text
    assert text.endswith("— remove it with cnc_delete_device_group.")
    delete.mock(return_value=httpx.Response(200, json=echo()))
    # A dynamic device group warns that 7.2.0 does not evaluate the rule.
    respx.post(f"{GROUPING}/rule").mock(
        return_value=httpx.Response(200, json={"status": "Success", "rule": rule_doc()})
    )
    text = await call_tool_text(
        build(wsettings),
        "cnc_create_device_group",
        {"name": "phase-d-static", "parent_uuid": ALL_LOCATIONS, "rule_conditions": conditions},
    )
    assert "as a rule-based LocationDevices group." in text
    assert "does NOT evaluate LocationDevices rules" in text


# --- update -----------------------------------------------------------------------


@respx.mock
async def test_update_device_group_resends_what_it_keeps(wsettings):
    get = respx.get(f"{GROUPING}/group/{GROUP}/details").mock(
        return_value=httpx.Response(200, json=details())
    )
    put = respx.put(f"{GROUPING}/group/{GROUP}").mock(return_value=httpx.Response(200, json=echo()))
    text = await call_tool_text(
        build(wsettings),
        "cnc_update_device_group",
        {"group_uuid": GROUP, "description": "phase-d UPDATED"},
    )
    # The PUT is a full replace: the current name and parent travel with the new description.
    assert body_of(put) == {
        "name": "phase-d-static",
        "description": "phase-d UPDATED",
        "parentUuid": ALL_LOCATIONS,
    }
    assert get.call_count == 2  # before (merge) and after (read-back)
    assert text.startswith(f"Group 'phase-d-static' ({GROUP}) updated: description set.")
    text = await call_tool_text(
        build(wsettings),
        "cnc_update_device_group",
        {
            "group_uuid": GROUP,
            "name": "renamed",
            "clear_description": True,
            "parent_uuid": UNASSIGNED,
        },
    )
    assert body_of(put, 1) == {"name": "renamed", "description": "", "parentUuid": UNASSIGNED}
    assert "renamed 'phase-d-static' -> 'renamed'; description cleared; moved under" in text
    # Nothing differs: no PUT.
    text = await call_tool_text(
        build(wsettings),
        "cnc_update_device_group",
        {"group_uuid": GROUP, "description": "phase-d static group"},
    )
    assert put.call_count == 2
    assert text.startswith(f"Group 'phase-d-static' ({GROUP}) is already as requested (no change).")


@respx.mock
async def test_update_device_group_rule_replace_create_remove_and_activate(wsettings):
    respx.get(f"{GROUPING}/group/{GROUP}/details").mock(
        return_value=httpx.Response(200, json=details())
    )
    respx.get(f"{GROUPING}/device/rule/conditions").mock(
        return_value=httpx.Response(200, json=DEVICE_CONDITIONS)
    )
    current = respx.get(f"{GROUPING}/rule/group/{GROUP}").mock(
        return_value=httpx.Response(200, json={"status": "Success", "rule": rule_doc()})
    )
    put_rule = respx.put(f"{GROUPING}/rule/{RULE}").mock(
        return_value=httpx.Response(200, json={"status": "Success", "rule": rule_doc(active=False)})
    )
    put_group = respx.put(f"{GROUPING}/group/{GROUP}")
    new = '[{"attribute": "node_ip", "operator": "Contains", "value": "198.18"}]'
    text = await call_tool_text(
        build(wsettings),
        "cnc_update_device_group",
        {"group_uuid": GROUP, "rule_conditions": new, "rule_active": False},
    )
    sent = body_of(put_rule)
    assert sent["uuid"] == RULE and sent["targetGroupUuid"] == GROUP
    assert sent["active"] is False and sent["name"] == "phase-d-dynamic"
    assert json.loads(sent["conditions"])["conditions"][0]["stringCondition"] == {
        "operator": "SO_Contains"
    }
    assert not put_group.called
    assert "updated: rule replaced: hostname SO_StartWith 'PE'; rule active=False." in text
    assert "does not evaluate LocationDevices rules" in text
    # Deactivate only: the current conditions are re-sent.
    text = await call_tool_text(
        build(wsettings), "cnc_update_device_group", {"group_uuid": GROUP, "rule_active": False}
    )
    sent = body_of(put_rule, 1)
    assert sent["active"] is False and json.loads(sent["conditions"]) == json.loads(
        rule_doc()["conditions"]
    )
    assert text.startswith(f"Group 'phase-d-static' ({GROUP}) updated: rule active=False.")
    # '[]' removes the rule.
    delete_rule = respx.delete(f"{GROUPING}/rule/{RULE}").mock(
        return_value=httpx.Response(200, json={"status": "Success"})
    )
    text = await call_tool_text(
        build(wsettings), "cnc_update_device_group", {"group_uuid": GROUP, "rule_conditions": "[]"}
    )
    assert delete_rule.called
    assert f"updated: rule {RULE} removed (the group is static now)." in text
    # No rule yet: conditions create one (POST), '[]' is a no-op, active alone is an error.
    current.mock(return_value=httpx.Response(200, json=error("RULE_NOT_EXIST")))
    post_rule = respx.post(f"{GROUPING}/rule").mock(
        return_value=httpx.Response(200, json={"status": "Success", "rule": rule_doc()})
    )
    text = await call_tool_text(
        build(wsettings), "cnc_update_device_group", {"group_uuid": GROUP, "rule_conditions": new}
    )
    sent = body_of(post_rule)
    assert "uuid" not in sent and sent["active"] is True and sent["name"] == "phase-d-static"
    assert "updated: rule created: hostname SO_StartWith 'PE'." in text
    text = await call_tool_text(
        build(wsettings), "cnc_update_device_group", {"group_uuid": GROUP, "rule_conditions": "[]"}
    )
    assert "is already as requested (no change)" in text
    text = await call_tool_text(
        build(wsettings), "cnc_update_device_group", {"group_uuid": GROUP, "rule_active": True}
    )
    assert text == (
        f"Error: Group {GROUP} has no rule to set active=True on; pass rule_conditions to "
        "create one."
    )


@respx.mock
async def test_update_device_group_refusals(wsettings):
    get = respx.get(f"{GROUPING}/group/{GROUP}/details").mock(
        return_value=httpx.Response(
            200, json=details(discovery="StaticSystem", name="Unassigned Devices")
        )
    )
    put = respx.put(f"{GROUPING}/group/{GROUP}")
    text = await call_tool_text(
        build(wsettings), "cnc_update_device_group", {"group_uuid": GROUP, "name": "x"}
    )
    assert text == (
        f"Error: Group 'Unassigned Devices' ({GROUP}) is a system group (discoveryType "
        "StaticSystem) and cannot be updated; only user groups can."
    )
    get.mock(return_value=httpx.Response(200, json=details()))
    text = await call_tool_text(
        build(wsettings),
        "cnc_update_device_group",
        {"group_uuid": GROUP, "description": "x", "clear_description": True},
    )
    assert text == "Error: Pass either description or clear_description=true, not both."
    assert not put.called
    put.mock(return_value=httpx.Response(200, json=error("RESERVED_GROUP_NAME")))
    text = await call_tool_text(
        build(wsettings), "cnc_update_device_group", {"group_uuid": GROUP, "name": "All Locations"}
    )
    assert text.startswith(
        f"Error: Update group {GROUP} failed: RESERVED_GROUP_NAME Hint: the name belongs"
    )
    get.mock(return_value=httpx.Response(200, json=error("GROUP_NOT_EXIST")))
    text = await call_tool_text(
        build(wsettings), "cnc_update_device_group", {"group_uuid": GROUP, "name": "x"}
    )
    assert text.startswith(
        f"Error: Group {GROUP} details read failed: GROUP_NOT_EXIST Hint: no group"
    )
    # A bad rule is rejected before the group PUT is sent.
    get.mock(return_value=httpx.Response(200, json=details()))
    respx.get(f"{GROUPING}/rule/group/{GROUP}").mock(
        return_value=httpx.Response(200, json=error("RULE_NOT_EXIST"))
    )
    respx.get(f"{GROUPING}/device/rule/conditions").mock(
        return_value=httpx.Response(200, json=DEVICE_CONDITIONS)
    )
    text = await call_tool_text(
        build(wsettings),
        "cnc_update_device_group",
        {
            "group_uuid": GROUP,
            "name": "renamed",
            "rule_conditions": '[{"attribute": "x", "operator": "SO_Equals", "value": 1}]',
        },
    )
    assert text.startswith("Error: rule_conditions[0]: unknown attribute 'x'")
    assert put.call_count == 1


@respx.mock
async def test_update_device_group_names_the_applied_group_change_when_the_rule_step_fails(
    wsettings,
):
    """Order on the wire: group PUT first, then the rule call. A platform refusal on the
    rule step after a successful PUT must say the rename already happened."""
    respx.get(f"{GROUPING}/group/{GROUP}/details").mock(
        return_value=httpx.Response(200, json=details())
    )
    respx.get(f"{GROUPING}/device/rule/conditions").mock(
        return_value=httpx.Response(200, json=DEVICE_CONDITIONS)
    )
    respx.get(f"{GROUPING}/rule/group/{GROUP}").mock(
        return_value=httpx.Response(200, json={"status": "Success", "rule": rule_doc()})
    )
    put_group = respx.put(f"{GROUPING}/group/{GROUP}").mock(
        return_value=httpx.Response(200, json=echo(name="renamed"))
    )
    put_rule = respx.put(f"{GROUPING}/rule/{RULE}").mock(
        return_value=httpx.Response(200, json=error("TARGET_GROUP_NOT_EXIST"))
    )
    new = '[{"attribute": "node_ip", "operator": "Contains", "value": "198.18"}]'
    text = await call_tool_text(
        build(wsettings),
        "cnc_update_device_group",
        {"group_uuid": GROUP, "name": "renamed", "rule_conditions": new},
    )
    assert put_group.called and put_rule.called
    assert text.startswith(
        f"Error: Update rule {RULE} failed: TARGET_GROUP_NOT_EXIST Hint: the rule's target "
        "group uuid does not exist."
    )
    assert text.endswith(
        "(the group change was already applied: renamed 'phase-d-static' -> 'renamed')"
    )
    # Without a group change the rule error is reported as-is.
    text = await call_tool_text(
        build(wsettings), "cnc_update_device_group", {"group_uuid": GROUP, "rule_conditions": new}
    )
    assert put_group.call_count == 1
    assert text == (
        f"Error: Update rule {RULE} failed: TARGET_GROUP_NOT_EXIST Hint: the rule's target "
        "group uuid does not exist."
    )
    # A DELETE of the rule that fails at the transport level is reported the same way.
    respx.delete(f"{GROUPING}/rule/{RULE}").mock(side_effect=httpx.ConnectError("boom"))
    text = await call_tool_text(
        build(wsettings),
        "cnc_update_device_group",
        {"group_uuid": GROUP, "description": "x", "rule_conditions": "[]"},
    )
    assert text.startswith("Error: Could not reach the platform (ConnectError)")
    assert text.endswith("(the group change was already applied: description set)")


# --- delete -----------------------------------------------------------------------


@respx.mock
async def test_delete_device_group_reports_released_members_and_rule(wsettings):
    respx.get(f"{GROUPING}/group/{GROUP}/details").mock(
        return_value=httpx.Response(200, json=details())
    )
    respx.get(f"{GROUPING}/device/{GROUP}").mock(
        return_value=httpx.Response(200, json=devices_doc((PE1, "PE1"), (PE2, "PE2")))
    )
    respx.get(f"{GROUPING}/rule/group/{GROUP}").mock(
        return_value=httpx.Response(200, json={"status": "Success", "rule": rule_doc()})
    )
    delete = respx.delete(f"{GROUPING}/group/{GROUP}").mock(
        return_value=httpx.Response(200, json=echo())
    )
    text = await call_tool_text(build(wsettings), "cnc_delete_device_group", {"group_uuid": GROUP})
    assert delete.called
    assert text.startswith(
        f"Group 'phase-d-static' ({GROUP}, LocationDevices) deleted; 2 member(s) released "
        f"(PE1, PE2) — they are back in Unassigned Devices; rule {RULE} deleted with it."
    )
    payload = json.loads(text[text.index("{") :])
    assert payload["deleted"] == echo()["group"]
    assert [m["hostname"] for m in payload["members_released"]] == ["PE1", "PE2"]
    assert payload["rule_deleted"]["uuid"] == RULE
    # A port group lists no devices and a DeviceAccess group no rule.
    respx.get(f"{GROUPING}/group/{PORT_GROUP}/details").mock(
        return_value=httpx.Response(
            200, json=details(PORT_GROUP, "phase-d-ports", "UserDefinedPorts")
        )
    )
    respx.get(f"{GROUPING}/rule/group/{PORT_GROUP}").mock(
        return_value=httpx.Response(200, json=error("RULE_NOT_EXIST"))
    )
    respx.delete(f"{GROUPING}/group/{PORT_GROUP}").mock(
        return_value=httpx.Response(200, json=echo(PORT_GROUP, "phase-d-ports", "UserDefinedPorts"))
    )
    text = await call_tool_text(
        build(wsettings), "cnc_delete_device_group", {"group_uuid": PORT_GROUP}
    )
    assert text.startswith(f"Group 'phase-d-ports' ({PORT_GROUP}, UserDefinedPorts) deleted.")


@respx.mock
async def test_delete_device_group_refusals(wsettings):
    get = respx.get(f"{GROUPING}/group/{UNASSIGNED}/details").mock(
        return_value=httpx.Response(
            200, json=details(UNASSIGNED, "Unassigned Devices", discovery="StaticSystem")
        )
    )
    delete = respx.delete(f"{GROUPING}/group/{UNASSIGNED}")
    text = await call_tool_text(
        build(wsettings), "cnc_delete_device_group", {"group_uuid": UNASSIGNED}
    )
    assert text.startswith(f"Error: Group 'Unassigned Devices' ({UNASSIGNED}) is a system group")
    assert not delete.called
    get.mock(return_value=httpx.Response(200, json=error("GROUP_NOT_EXIST")))
    text = await call_tool_text(
        build(wsettings), "cnc_delete_device_group", {"group_uuid": UNASSIGNED}
    )
    assert text.startswith(f"Error: Group {UNASSIGNED} details read failed: GROUP_NOT_EXIST Hint:")
    get.mock(return_value=httpx.Response(200, json=details(UNASSIGNED, "x", "DeviceAccess")))
    respx.get(f"{GROUPING}/device/{UNASSIGNED}").mock(
        return_value=httpx.Response(200, json=devices_doc())
    )
    delete.mock(return_value=httpx.Response(200, json=error("GROUP_NOT_EXIST")))
    text = await call_tool_text(
        build(wsettings), "cnc_delete_device_group", {"group_uuid": UNASSIGNED}
    )
    assert text.startswith(f"Error: Delete group {UNASSIGNED} failed: GROUP_NOT_EXIST Hint:")


@respx.mock
async def test_platform_managed_dynamic_groups_are_refused(wsettings):
    """The lab's 'Software Loopback' (PortType, Dynamic, operations {showMem}) and the
    'IGP Domain 0' auto-group (TopologyTypeDevices, Dynamic, no operations) are NOT
    StaticSystem; delete / update / set-members must still refuse them with nothing
    sent — the PortType group's rule classifies every Loopback port platform-wide."""
    respx.get(f"{GROUPING}/group/{SOFTWARE_LOOPBACK}/details").mock(
        return_value=httpx.Response(200, json=SOFTWARE_LOOPBACK_DETAILS)
    )
    respx.get(f"{GROUPING}/group/{IGP_DOMAIN_0}/details").mock(
        return_value=httpx.Response(200, json=IGP_DOMAIN_0_DETAILS)
    )
    rule_read = respx.get(f"{GROUPING}/rule/group/{SOFTWARE_LOOPBACK}")
    delete = respx.delete(url__regex=rf"{GROUPING}/group/.*")
    put_group = respx.put(url__regex=rf"{GROUPING}/group/[^/]+$")
    put_rule = respx.put(f"{GROUPING}/rule/{SOFTWARE_LOOPBACK_RULE}")
    delete_rule = respx.delete(url__regex=rf"{GROUPING}/rule/.*")
    remove = respx.put(url__regex=rf"{GROUPING}/group/.*/members")
    move = respx.post(url__regex=rf"{GROUPING}/group/member/.*")
    text = await call_tool_text(
        build(wsettings), "cnc_delete_device_group", {"group_uuid": SOFTWARE_LOOPBACK}
    )
    assert text == (
        f"Error: Group 'Software Loopback' ({SOFTWARE_LOOPBACK}) is a platform-managed "
        "PortType group (discoveryType Dynamic; the platform derives these groups and their "
        "rules) and cannot be deleted; only user groups of the LocationDevices, DeviceAccess, "
        "UserDefinedPorts classifiers can."
    )
    text = await call_tool_text(
        build(wsettings),
        "cnc_update_device_group",
        {
            "group_uuid": SOFTWARE_LOOPBACK,
            "name": "phase-d-hijack",
            "rule_conditions": '[{"attribute": "name", "operator": "SO_Contains", "value": "x"}]',
        },
    )
    assert "is a platform-managed PortType group" in text and "cannot be updated" in text
    text = await call_tool_text(
        build(wsettings),
        "cnc_set_device_group_members",
        {"group_uuid": SOFTWARE_LOOPBACK, "devices": "PE1"},
    )
    assert "is a platform-managed PortType group" in text and "cannot be changed" in text
    for tool, args in (
        ("cnc_delete_device_group", {"group_uuid": IGP_DOMAIN_0}),
        ("cnc_update_device_group", {"group_uuid": IGP_DOMAIN_0, "name": "x"}),
    ):
        text = await call_tool_text(build(wsettings), tool, args)
        assert (
            f"Error: Group '0' ({IGP_DOMAIN_0}) is a platform-managed TopologyTypeDevices" in text
        )
    text = await call_tool_text(
        build(wsettings),
        "cnc_set_device_group_members",
        {"group_uuid": IGP_DOMAIN_0, "devices": ""},
    )
    assert "is a platform-managed TopologyTypeDevices group" in text
    for route in (rule_read, delete, put_group, put_rule, delete_rule, remove, move):
        assert not route.called, route
    # A group of a writable classifier whose details carry no 'del' / 'upd' flag is refused
    # by the operations gate (the platform's own capability word), still with nothing sent.
    respx.get(f"{GROUPING}/group/{GROUP}/details").mock(
        return_value=httpx.Response(
            200, json={"status": "Success", "group": {**details()["group"], "operations": {}}}
        )
    )
    text = await call_tool_text(build(wsettings), "cnc_delete_device_group", {"group_uuid": GROUP})
    assert text == (
        f"Error: Group 'phase-d-static' ({GROUP}) cannot be deleted: the platform lists no "
        "'del' operation for it (operations: none), which marks it as platform-managed rather "
        "than a user group."
    )
    text = await call_tool_text(
        build(wsettings), "cnc_update_device_group", {"group_uuid": GROUP, "name": "x"}
    )
    assert "cannot be updated: the platform lists no 'upd' operation" in text
    assert not delete.called and not put_group.called


# --- members ----------------------------------------------------------------------


def mock_location_tree() -> None:
    respx.get(f"{GROUPING}/group/root/LocationDevices/uuid").mock(
        return_value=httpx.Response(200, json=[LOCATION_ROOT])
    )
    respx.get(f"{GROUPING}/groups/{LOCATION_ROOT}").mock(
        return_value=httpx.Response(200, json=LOCATION_TREE)
    )


@respx.mock
async def test_set_device_group_members_replace_removes_then_moves_from_the_leaf(wsettings):
    respx.get(f"{GROUPING}/group/{GROUP}/details").mock(
        return_value=httpx.Response(200, json=details())
    )
    members = respx.get(f"{GROUPING}/device/{GROUP}").mock(
        side_effect=[
            httpx.Response(200, json=devices_doc((PE1, "PE1"))),
            httpx.Response(200, json=devices_doc((PE2, "PE2"), (P1, "P1"))),
        ]
    )
    mock_location_tree()
    unassigned = respx.get(f"{GROUPING}/device/{UNASSIGNED}").mock(
        return_value=httpx.Response(200, json=devices_doc((P1, "P1"), (PE2, "PE2"), ("x", "PCE")))
    )
    remove = respx.put(f"{GROUPING}/group/{GROUP}/members").mock(
        return_value=httpx.Response(200, json={"status": "Success"})
    )
    move = respx.post(f"{GROUPING}/group/member/move").mock(
        return_value=httpx.Response(200, json={"status": "Success"})
    )
    text = await call_tool_text(
        build(wsettings),
        "cnc_set_device_group_members",
        {"group_uuid": GROUP, "devices": "pe2, P1 "},
    )
    assert body_of(remove) == {"references": [PE1]}
    assert body_of(move) == {
        "groupUuid": UNASSIGNED,
        "newGroupUuid": GROUP,
        "references": sorted([P1, PE2]),
    }
    assert unassigned.call_count == 1 and members.call_count == 2
    assert text.startswith(
        f"Group 'phase-d-static' ({GROUP}): added PE2, P1 (from Unassigned Devices); "
        "removed PE1 (back in Unassigned Devices); members now: PE2, P1."
    )
    payload = json.loads(text[text.index("{") :])
    assert payload["mode"] == "replace" and payload["kept"] == []
    assert payload["removed"] == [{"uuid": PE1, "hostname": "PE1"}]
    assert {a["hostname"] for a in payload["added"]} == {"P1", "PE2"}
    assert payload["added"][0]["from_group_name"] == "Unassigned Devices"


@respx.mock
async def test_set_device_group_members_add_remove_and_no_change(wsettings):
    respx.get(f"{GROUPING}/group/{ACCESS_GROUP}/details").mock(
        return_value=httpx.Response(
            200, json=details(ACCESS_GROUP, "phase-d-access", "DeviceAccess", parent=ALL_ACCESS)
        )
    )
    respx.get(f"{GROUPING}/device/{ACCESS_GROUP}").mock(
        side_effect=[
            httpx.Response(200, json=devices_doc((PE1, "PE1"))),
            httpx.Response(200, json=devices_doc((PE1, "PE1"), (P1, "P1"))),
            httpx.Response(200, json=devices_doc((PE1, "PE1"), (P1, "P1"))),
            httpx.Response(200, json=devices_doc((PE1, "PE1"), (P1, "P1"))),
            httpx.Response(200, json=devices_doc((P1, "P1"))),
        ]
    )
    mock_location_tree()
    respx.get(f"{GROUPING}/device/{UNASSIGNED}").mock(
        return_value=httpx.Response(200, json=devices_doc((P1, "P1")))
    )
    copy = respx.post(f"{GROUPING}/group/member/copy").mock(
        return_value=httpx.Response(200, json={"status": "Success"})
    )
    remove = respx.put(f"{GROUPING}/group/{ACCESS_GROUP}/members").mock(
        return_value=httpx.Response(200, json={"status": "Success"})
    )
    # add: a DeviceAccess target copies from the device's Location leaf.
    text = await call_tool_text(
        build(wsettings),
        "cnc_set_device_group_members",
        {"group_uuid": ACCESS_GROUP, "devices": "P1,PE1", "mode": "add"},
    )
    assert body_of(copy) == {
        "groupUuid": UNASSIGNED,
        "newGroupUuid": ACCESS_GROUP,
        "references": [P1],
    }
    assert not remove.called
    assert text.startswith(
        f"Group 'phase-d-access' ({ACCESS_GROUP}): copied in P1 (from Unassigned Devices); "
        "members now: PE1, P1."
    )
    # add again: nothing to do, nothing written.
    text = await call_tool_text(
        build(wsettings),
        "cnc_set_device_group_members",
        {"group_uuid": ACCESS_GROUP, "devices": "P1", "mode": "add"},
    )
    assert copy.call_count == 1
    assert text.startswith(
        f"Group 'phase-d-access' ({ACCESS_GROUP}) is already as requested (no change)."
    )
    # remove: one PUT; no "back in Unassigned" for an access group.
    text = await call_tool_text(
        build(wsettings),
        "cnc_set_device_group_members",
        {"group_uuid": ACCESS_GROUP, "devices": PE1, "mode": "REMOVE"},
    )
    assert body_of(remove) == {"references": [PE1]}
    assert text.startswith(
        f"Group 'phase-d-access' ({ACCESS_GROUP}): removed PE1; members now: P1."
    )


@respx.mock
async def test_set_device_group_members_refuses_before_writing(wsettings):
    get = respx.get(f"{GROUPING}/group/{GROUP}/details").mock(
        return_value=httpx.Response(200, json=details())
    )
    respx.get(f"{GROUPING}/device/{GROUP}").mock(
        return_value=httpx.Response(200, json=devices_doc((PE1, "PE1")))
    )
    mock_location_tree()
    respx.get(f"{GROUPING}/device/{UNASSIGNED}").mock(
        return_value=httpx.Response(200, json=devices_doc((P1, "P1")))
    )
    # The walk lists the counted leaves first and the uncounted root last (it holds
    # nothing on the lab); the target group itself (childrenCount 1) is visited too.
    root = respx.get(f"{GROUPING}/device/{LOCATION_ROOT}").mock(
        return_value=httpx.Response(200, json=devices_doc())
    )
    remove = respx.put(f"{GROUPING}/group/{GROUP}/members")
    move = respx.post(f"{GROUPING}/group/member/move")
    text = await call_tool_text(
        build(wsettings),
        "cnc_set_device_group_members",
        {"group_uuid": GROUP, "devices": "PE2", "mode": "remove"},
    )
    assert text == f"Error: not members of group {GROUP}: PE2 (current members: PE1)."
    text = await call_tool_text(
        build(wsettings),
        "cnc_set_device_group_members",
        {"group_uuid": GROUP, "devices": "PE1,nope", "mode": "add"},
    )
    assert text.startswith(
        "Error: no LocationDevices group holds: nope — unknown host names / uuids?"
    )
    assert root.call_count == 1
    text = await call_tool_text(
        build(wsettings),
        "cnc_set_device_group_members",
        {"group_uuid": GROUP, "devices": "", "mode": "add"},
    )
    assert text == "Error: devices must name at least one value (comma-separated)."
    text = await call_tool_text(
        build(wsettings),
        "cnc_set_device_group_members",
        {"group_uuid": GROUP, "devices": "PE1", "mode": "toggle"},
    )
    assert text.startswith("Error: Unknown mode 'toggle'. Use one of: replace, add, remove.")
    get.mock(
        return_value=httpx.Response(200, json=details(GROUP, "phase-d-ports", "UserDefinedPorts"))
    )
    text = await call_tool_text(
        build(wsettings),
        "cnc_set_device_group_members",
        {"group_uuid": GROUP, "devices": "PE1"},
    )
    assert text.startswith(
        f"Error: Group {GROUP} is a UserDefinedPorts group; its members are not devices"
    )
    get.mock(return_value=httpx.Response(200, json=details(discovery="StaticSystem")))
    text = await call_tool_text(
        build(wsettings),
        "cnc_set_device_group_members",
        {"group_uuid": GROUP, "devices": "PE1"},
    )
    assert "is a system group (discoveryType StaticSystem) and cannot be changed" in text
    assert not remove.called and not move.called
    # A platform refusal on the move carries its hint.
    get.mock(return_value=httpx.Response(200, json=details()))
    move.mock(return_value=httpx.Response(200, json=error("MEMBER_NOT_EXIST")))
    text = await call_tool_text(
        build(wsettings),
        "cnc_set_device_group_members",
        {"group_uuid": GROUP, "devices": "P1", "mode": "add"},
    )
    assert text.startswith(
        f"Error: Move members into group {GROUP} failed: MEMBER_NOT_EXIST Hint: a device named"
    )


@respx.mock
async def test_move_group_members_move_and_copy(wsettings):
    respx.get(f"{GROUPING}/group/{UNASSIGNED}/details").mock(
        return_value=httpx.Response(
            200, json=details(UNASSIGNED, "Unassigned Devices", discovery="StaticSystem")
        )
    )
    respx.get(f"{GROUPING}/device/{GROUP}").mock(
        return_value=httpx.Response(200, json=devices_doc((PE1, "PE1")))
    )
    respx.get(f"{GROUPING}/device/{UNASSIGNED}").mock(
        return_value=httpx.Response(200, json=devices_doc((P1, "P1"), (PE1, "PE1")))
    )
    move = respx.post(f"{GROUPING}/group/member/move").mock(
        return_value=httpx.Response(200, json={"status": "Success"})
    )
    text = await call_tool_text(
        build(wsettings),
        "cnc_move_group_members",
        {"source_group_uuid": GROUP, "target_group_uuid": UNASSIGNED, "devices": "pe1"},
    )
    assert body_of(move) == {"groupUuid": GROUP, "newGroupUuid": UNASSIGNED, "references": [PE1]}
    assert text.startswith(
        f"Moved PE1 from {GROUP} to 'Unassigned Devices' ({UNASSIGNED}); "
        "target members now: P1, PE1."
    )
    payload = json.loads(text[text.index("{") :])
    assert payload["operation"] == "move" and payload["response"] == {"status": "Success"}
    # copy: the other path, same body.
    respx.get(f"{GROUPING}/group/{ACCESS_GROUP}/details").mock(
        return_value=httpx.Response(
            200, json=details(ACCESS_GROUP, "phase-d-access", "DeviceAccess", parent=ALL_ACCESS)
        )
    )
    respx.get(f"{GROUPING}/device/{ACCESS_GROUP}").mock(
        return_value=httpx.Response(200, json=devices_doc((P1, "P1")))
    )
    copy = respx.post(f"{GROUPING}/group/member/copy").mock(
        return_value=httpx.Response(200, json={"status": "Success"})
    )
    text = await call_tool_text(
        build(wsettings),
        "cnc_move_group_members",
        {
            "source_group_uuid": UNASSIGNED,
            "target_group_uuid": ACCESS_GROUP,
            "devices": f"P1,{P1}",
            "operation": "copy",
        },
    )
    assert body_of(copy) == {
        "groupUuid": UNASSIGNED,
        "newGroupUuid": ACCESS_GROUP,
        "references": [P1],
    }
    assert text.startswith(f"Copied P1 from {UNASSIGNED} to 'phase-d-access' ({ACCESS_GROUP});")


@respx.mock
async def test_move_group_members_errors(wsettings):
    target = respx.get(f"{GROUPING}/group/{ACCESS_GROUP}/details").mock(
        return_value=httpx.Response(
            200, json=details(ACCESS_GROUP, "phase-d-access", "DeviceAccess", parent=ALL_ACCESS)
        )
    )
    respx.get(f"{GROUPING}/device/{UNASSIGNED}").mock(
        return_value=httpx.Response(200, json=devices_doc((P1, "P1")))
    )
    move = respx.post(f"{GROUPING}/group/member/move").mock(
        return_value=httpx.Response(200, json=error("INVALID_OPERATION"))
    )
    text = await call_tool_text(
        build(wsettings),
        "cnc_move_group_members",
        {"source_group_uuid": UNASSIGNED, "target_group_uuid": ACCESS_GROUP, "devices": "P1"},
    )
    assert text.startswith(
        "Error: Move members failed: INVALID_OPERATION Hint: the platform refuses this member "
        "operation"
    )
    text = await call_tool_text(
        build(wsettings),
        "cnc_move_group_members",
        {"source_group_uuid": UNASSIGNED, "target_group_uuid": ACCESS_GROUP, "devices": "PE9"},
    )
    assert text.startswith(
        f"Error: not members of the source group {UNASSIGNED}: PE9 — the source must be"
    )
    assert move.call_count == 1
    text = await call_tool_text(
        build(wsettings),
        "cnc_move_group_members",
        {
            "source_group_uuid": UNASSIGNED,
            "target_group_uuid": ACCESS_GROUP,
            "devices": "P1",
            "operation": "link",
        },
    )
    assert text.startswith("Error: Unknown member operation 'link'. Use one of: move, copy.")
    target.mock(return_value=httpx.Response(200, json=error("GROUP_NOT_EXIST")))
    text = await call_tool_text(
        build(wsettings),
        "cnc_move_group_members",
        {"source_group_uuid": UNASSIGNED, "target_group_uuid": ACCESS_GROUP, "devices": "P1"},
    )
    assert text.startswith(
        f"Error: Group {ACCESS_GROUP} details read failed: GROUP_NOT_EXIST Hint:"
    )


@respx.mock
async def test_move_group_members_refuses_a_non_device_target(wsettings):
    """A PortType / UserDefinedPorts / TopologyTypeDevices target is refused before the
    source is even listed; a StaticSystem LocationDevices target (Unassigned Devices) is
    fine — it is where a move puts a device back."""
    respx.get(f"{GROUPING}/group/{SOFTWARE_LOOPBACK}/details").mock(
        return_value=httpx.Response(200, json=SOFTWARE_LOOPBACK_DETAILS)
    )
    source = respx.get(f"{GROUPING}/device/{UNASSIGNED}")
    move = respx.post(url__regex=rf"{GROUPING}/group/member/.*")
    text = await call_tool_text(
        build(wsettings),
        "cnc_move_group_members",
        {"source_group_uuid": UNASSIGNED, "target_group_uuid": SOFTWARE_LOOPBACK, "devices": "P1"},
    )
    assert text == (
        f"Error: Group {SOFTWARE_LOOPBACK} is a PortType group; devices cannot be moved or "
        "copied into it (targets are LocationDevices / DeviceAccess groups)."
    )
    respx.get(f"{GROUPING}/group/{PORT_GROUP}/details").mock(
        return_value=httpx.Response(
            200, json=details(PORT_GROUP, "phase-d-ports", "UserDefinedPorts")
        )
    )
    text = await call_tool_text(
        build(wsettings),
        "cnc_move_group_members",
        {
            "source_group_uuid": UNASSIGNED,
            "target_group_uuid": PORT_GROUP,
            "devices": "P1",
            "operation": "copy",
        },
    )
    assert text.startswith(f"Error: Group {PORT_GROUP} is a UserDefinedPorts group; devices cannot")
    assert not source.called and not move.called
