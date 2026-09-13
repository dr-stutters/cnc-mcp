"""Inventory-extras tools end-to-end through MCPServer (schema validation included).

The module is registered directly (not through build_server) so the test does
not depend on tools/__init__.py's module list. All HTTP is mocked with respx.
Fixtures mirror the shapes verified live on Crosswork 7.2 (2026-09-13, see the
platform notes): the DLM summaries with zero counts ABSENT, the empty-body
config/policy/cadence reads, the node's ``tag_names`` / ``lock_status`` /
``geo_info.coordinates`` fields, the tag and geo job envelopes, and the
``locknodes`` answers (success with ``rc``, refusal with ``rc_msg`` only).
``nodes/query`` answers carry ``result_count`` on a host_name filter but NOT
on a uuid filter (verified) — uuid-selector tests use the ``UUID_NODE`` shape.
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
from cnc_mcp.tools import inventory_extras
from cnc_mcp.tools.inventory_extras import (
    OPER_STATE_KEYS,
    REACHABILITY_KEYS,
    SELECTOR_PAGE_SIZE,
    SKIPPED_LIST_LIMIT,
    cadence_line,
    check_lock_response,
    create_tag_hint,
    delete_tag_hint,
    device_tags_line,
    device_tags_view,
    geo_body,
    geo_coordinates_of,
    is_locked,
    lock_body,
    lock_hint,
    split_tags,
    summary_counts,
    summary_line,
    unlock_body,
)
from tests.conftest import BASE_URL, call_tool_text

INVENTORY = f"{BASE_URL}/crosswork/inventory/v1"
NODES_URL = f"{INVENTORY}/nodes"
NODES_QUERY_URL = f"{NODES_URL}/query"
COUNT_URL = f"{NODES_URL}/count"
OPER_URL = f"{NODES_URL}/operstatesummary"
REACH_URL = f"{NODES_URL}/reachabilitysummary"
LICENSE_URL = f"{INVENTORY}/sysoids/licensetype/count/query"
INV_CONFIG_URL = f"{INVENTORY}/inventoryconfig/query"
POLICIES_URL = f"{INVENTORY}/policies/query"
CADENCE_URL = f"{INVENTORY}/devicepackage/cadence/query"
TAGS_URL = f"{INVENTORY}/tags"
UNASSIGN_URL = f"{NODES_URL}/unassigntag"
GEO_URL = f"{INVENTORY}/nodesgeocoord"
LOCK_URL = f"{INVENTORY}/locknodes"

PE1_UUID = "2a9b7c1e-0f3d-4b8a-9c6e-1d2f3a4b5c6d"
P1_UUID = "7f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f"
LOCK_ID = "29a12334-fa9e-43c4-b82b-922a01a73940"
SYSTEM_TAGS = ("cli", "snmp", "reach-check")

# Verified node shape for a locked device.
LOCKED_STATUS = {
    "lock_id": LOCK_ID,
    "state": "LOCKED",
    "owner": "cnc-mcp",
    "start_time": "1757772000",
    "end_time": "1757772300",
}
# Verified geo_info.coordinates shape (robotapiDouble wrappers).
LONDON = {"latitude": {"value": 51.5}, "longitude": {"value": -0.12}}


def node(
    uuid: str,
    host: str,
    tag_names: tuple[str, ...] = SYSTEM_TAGS,
    lock_status: dict | None = None,
    coordinates: dict | None = None,
    oper: str = "ROBOT_OPER_STATE_OK",
) -> dict:
    """An inventory node as nodes/query returns it (verified keys)."""
    n = {
        "uuid": uuid,
        "host_name": host,
        "node_ip": {"inet_af": "ROBOT_INET_ADDR_TYPE_v4", "inet_addr": "198.18.140.11"},
        "admin_state": "ROBOT_ADMIN_STATE_UP",
        "reachability_state": "CONN_STATE_REACHABLE",
        "operational_state": oper,
        "profile": "cml-xrd",
        "tag_names": list(tag_names),
        # a cleared / never-set device reads an empty coordinates object (verified)
        "geo_info": {"coordinates": coordinates if coordinates is not None else {}},
        "errors": [],
    }
    if lock_status is not None:
        n["lock_status"] = lock_status
    return n


PE1 = node(PE1_UUID, "PE1", tag_names=SYSTEM_TAGS + ("site-a",))
P1 = node(P1_UUID, "P1")
PE1_LOCKED = node(PE1_UUID, "PE1", lock_status=LOCKED_STATUS, coordinates=LONDON)
PE1_CHECKING = node(PE1_UUID, "PE1", oper="ROBOT_OPER_STATE_CHECKING")
# A locked device carries ROBOT_OPER_STATE_LOCKED (OpenAPI robotapiRobotNodeOperationalState).
PE1_OPER_LOCKED = node(PE1_UUID, "PE1", lock_status=LOCKED_STATUS, oper="ROBOT_OPER_STATE_LOCKED")
# Verified: a host_name filter reports result_count ...
ONE_NODE = {"data": [PE1], "total_count": 5, "result_count": 1}
TWO_NODES = {"data": [PE1, P1], "total_count": 5, "result_count": 2}
# ... a uuid filter OMITS it (the count of matches is unknown to the client).
UUID_NODE = {"data": [PE1], "total_count": 5}
NO_NODES: dict = {}  # verified: an empty match is a bare {} with no data key


def many_nodes(count: int, start: int = 0, carriers: tuple[int, ...] = ()) -> list[dict]:
    """``count`` distinct devices D<start>.. ; those at the ``carriers`` offsets carry site-a."""
    return [
        node(
            f"uuid-{i:04d}",
            f"D{i:04d}",
            tag_names=SYSTEM_TAGS + (("site-a",) if (i - start) in carriers else ()),
        )
        for i in range(start, start + count)
    ]


# A FULL page (100 rows) with no result_count: what uuid='*' answers on a 250-device inventory.
FULL_PAGE_NO_COUNT = {"data": many_nodes(SELECTOR_PAGE_SIZE), "total_count": 250}


def query_of(selector: dict, page: int = 0) -> dict:
    """The exact nodes/query body the tools send for a selector (page ``page`` of 100)."""
    return {"filter": selector, "filterData": {"PageSize": 100, "PageNum": page, "Criteria": ""}}


# Verified summary answers: a zero count is ABSENT.
COUNT = {"number_of_nodes": 5}
OPER = {"ok": 4, "checking": 1}
REACH = {"reachable": 5}
LICENSES = {"LicenseTypeCount": {"Type A": 5, "Type B": 0, "Type C": 0, "Unlicensed": 0}}
INV_CONFIG = {"name": "default", "device": {"host_identifier": "HOSTNAME_AND_DOMAIN"}}
POLICIES = {
    "data": [
        {"name": "Default Policy", "invType": "INV_TYPE_NODE", "fields": [], "Type": "INDEPENDENT"}
    ],
    "total_count": 1,
}
CADENCE = {
    "JobToCadence": {"reach-check": 600, "show-clock": 1800, "snmp": 1200, "te-tunnel-id": 1200}
}

# Verified job envelopes.
TAG_CREATED = {
    "job_id": "3f7c1a2e-1111-4222-8333-444455556666",
    "state": "JOB_COMPLETED",
    "type": "1 tag(s) added successfully",
    "created_by": "admin",
    "impacted": [],
}
TAG_DUPLICATE = {
    "job_id": "3f7c1a2e-1111-4222-8333-444455556667",
    "state": "JOB_FAILED",
    "type": "1 tag(s) addition failed",
    "error": "The tag site-a already exists. Provide a unique name for the new tag.",
}
TAG_DELETED = {
    "job_id": "3f7c1a2e-1111-4222-8333-444455556668",
    "state": "JOB_COMPLETED",
    "type": "1 tag(s) deleted successfully",
}
TAG_IN_USE = {
    "job_id": "3f7c1a2e-1111-4222-8333-444455556669",
    "state": "JOB_FAILED",
    "type": "1 tag(s) deletion failed",
    "error": "Tag Name:site-a is in use and cannot be deleted.",
}
NSO_ADVISORY = (
    "Note, if device PE1 is used in NSO, any updates to it needs be done through NSO interface"
)
ASSIGN_WARNING = {
    "job_id": "5a6b7c8d-1111-4222-8333-444455557777",
    "state": "JOB_COMPLETED_WITH_WARNING",
    "type": "1 device(s) details patched successfully",
    "error": NSO_ADVISORY,
    "impacted": [f"{PE1_UUID} PE1 198.18.140.11"],
}
ASSIGN_FAILED = {
    "job_id": "5a6b7c8d-1111-4222-8333-444455557778",
    "state": "JOB_FAILED",
    "type": "1 device(s) details updation failed ",
    "error": "Tag ghost-tag does not exist",
}
UNASSIGN_DONE = {
    "job_id": "5a6b7c8d-1111-4222-8333-444455557779",
    "state": "JOB_COMPLETED",
    "type": "Unassign tags",
}
GEO_DONE = {
    "job_id": "9e8d7c6b-1111-4222-8333-444455558888",
    "state": "JOB_COMPLETED",
    "type": "UpdateGeoCoordinates geo coordinates for 1 nodes",
}
GEO_FAILED = {
    "job_id": "9e8d7c6b-1111-4222-8333-444455558889",
    "state": "JOB_FAILED",
    "type": "UpdateGeoCoordinates geo coordinates for 0 nodes",
    "error": "node not found",
}
# Verified locknodes answers.
LOCK_OK = {
    "rc": "NODE_REQ_SUCCESS",
    "rc_msg": "Operation success",
    "owner_cookie": "cnc-mcp",
    "lock_id": LOCK_ID,
    "start_time": "1757772000",
    "end_time": "1757772300",
}
LOCK_REFUSED = {
    "rc_msg": f"Node:{PE1_UUID} is allowed to lock only in Operational state:ROBOT_OPER_STATE_OK"
}
UNLOCK_OK = {"rc": "NODE_REQ_SUCCESS", "rc_msg": "Operation success", "owner_cookie": "cnc-mcp"}
UNLOCK_NOT_LOCKED = {"rc_msg": "Error Locking Node!"}
NATS_500 = httpx.Response(500, json={"error": "NATS request failed"})


def build(settings: Settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    inventory_extras.register(mcp, ctx)
    return mcp


def sent(route: respx.Route, index: int = 0) -> dict:
    return json.loads(route.calls[index].request.content)


def mock_nodes(body: dict) -> respx.Route:
    return respx.post(NODES_QUERY_URL).mock(return_value=httpx.Response(200, json=body))


def mock_node_pages(*bodies: dict) -> respx.Route:
    """nodes/query answering one body per call, in order (a paged scan)."""
    return respx.post(NODES_QUERY_URL).mock(
        side_effect=[httpx.Response(200, json=b) for b in bodies]
    )


def mock_summaries(
    count: dict = COUNT, oper: dict = OPER, reach: dict = REACH, licenses: dict = LICENSES
) -> dict[str, respx.Route]:
    return {
        "count": respx.get(COUNT_URL).mock(return_value=httpx.Response(200, json=count)),
        "oper": respx.get(OPER_URL).mock(return_value=httpx.Response(200, json=oper)),
        "reach": respx.get(REACH_URL).mock(return_value=httpx.Response(200, json=reach)),
        "lic": respx.get(LICENSE_URL).mock(return_value=httpx.Response(200, json=licenses)),
    }


READ_TOOLS = {
    "cnc_get_device_summary",
    "cnc_get_inventory_config",
    "cnc_get_collection_cadence",
    "cnc_get_device_tags",
}
WRITE_TOOLS = {
    "cnc_create_tag",
    "cnc_delete_tag",
    "cnc_assign_tags",
    "cnc_unassign_tags",
    "cnc_set_device_location",
    "cnc_clear_device_location",
    "cnc_lock_device",
    "cnc_unlock_device",
}


# --- registration / gating ---------------------------------------------------


async def test_write_tools_hidden_unless_enabled(make_settings):
    names = {t.name for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert names == READ_TOOLS
    names = {t.name for t in await build(make_settings(enable_writes=True)).list_tools()}
    assert names == READ_TOOLS | WRITE_TOOLS


async def test_annotations(make_settings):
    tools = {t.name: t for t in await build(make_settings(enable_writes=True)).list_tools()}
    for name in READ_TOOLS:
        assert tools[name].annotations.read_only_hint is True, name
        assert tools[name].annotations.idempotent_hint is True, name
    for name in WRITE_TOOLS:
        assert tools[name].annotations.read_only_hint is False, name
    destructive = {"cnc_delete_tag", "cnc_clear_device_location"}
    for name in WRITE_TOOLS:
        assert tools[name].annotations.destructive_hint is (name in destructive), name
    not_idempotent = {"cnc_create_tag", "cnc_lock_device"}
    for name in WRITE_TOOLS:
        assert tools[name].annotations.idempotent_hint is (name not in not_idempotent), name
    # Flat schemas: every argument is a top-level property (no $ref wrapper).
    props = tools["cnc_lock_device"].input_schema["properties"]
    assert set(props) == {"uuid", "host_name", "owner", "timeout_seconds"}
    assert (
        props["timeout_seconds"]["minimum"] == 10 and props["timeout_seconds"]["maximum"] == 86400
    )
    assert tools["cnc_set_device_location"].input_schema["properties"]["latitude"]["maximum"] == 90
    assert tools["cnc_get_device_summary"].input_schema.get("properties", {}) == {}


# --- pure helpers ------------------------------------------------------------


def test_split_tags():
    assert split_tags("site-a") == ["site-a"]
    assert split_tags(" site-a , ring-1,site-a,, ") == ["site-a", "ring-1"]
    with pytest.raises(PlatformError, match="tags is empty"):
        split_tags(" , ")


def test_summary_counts_fills_absent_keys_and_keeps_extras():
    assert summary_counts({"ok": 4, "checking": 1}, OPER_STATE_KEYS) == {
        "ok": 4, "checking": 1, "down": 0, "error": 0, "unmanaged": 0, "locked": 0, "deleting": 0,
    }  # fmt: skip
    assert summary_counts({"reachable": 5, "future": 2}, REACHABILITY_KEYS) == {
        "reachable": 5, "unreachable": 0, "degraded": 0, "unknown": 0, "future": 2,
    }  # fmt: skip
    assert summary_counts(None, REACHABILITY_KEYS) == {k: 0 for k in REACHABILITY_KEYS}
    assert summary_counts({"ok": "4", "down": True}, ("ok", "down")) == {"ok": 0, "down": 0}


def test_summary_line():
    oper = summary_counts(OPER, OPER_STATE_KEYS)
    reach = summary_counts(REACH, REACHABILITY_KEYS)
    assert summary_line(5, oper, reach, LICENSES["LicenseTypeCount"]) == (
        "5 devices: 4 ok / 1 checking; 5 reachable; licenses Type A 5"
    )
    empty = summary_line(
        0, summary_counts({}, OPER_STATE_KEYS), summary_counts({}, REACHABILITY_KEYS), {}
    )
    assert empty == "0 devices: no operational-state counts; no reachability counts; licenses none"
    assert summary_line(None, oper, reach, {}).startswith("unknown number of devices:")


def test_cadence_line():
    assert cadence_line(CADENCE["JobToCadence"]) == (
        "reach-check every 600 s, show-clock every 1800 s, snmp every 1200 s, "
        "te-tunnel-id every 1200 s"
    )
    assert cadence_line({}) == "no cadences reported"


def test_geo_coordinates_of_flattens_wrappers_and_treats_empty_as_none():
    assert geo_coordinates_of(PE1_LOCKED) == {"latitude": 51.5, "longitude": -0.12}
    assert geo_coordinates_of(PE1) is None  # coordinates {} (cleared / never set)
    assert geo_coordinates_of({}) is None
    with_alt = node("u", "X", coordinates={**LONDON, "altitude": {"value": 35}})
    assert geo_coordinates_of(with_alt) == {"latitude": 51.5, "longitude": -0.12, "altitude": 35}
    # bare numbers are tolerated on read even though the write form needs the wrapper
    assert geo_coordinates_of({"geo_info": {"coordinates": {"latitude": 1.5}}}) == {"latitude": 1.5}


def test_device_tags_view_and_is_locked():
    view = device_tags_view(PE1_LOCKED)
    assert view == {
        "host_name": "PE1",
        "uuid": PE1_UUID,
        "tag_names": list(SYSTEM_TAGS),
        "lock_status": LOCKED_STATUS,
        "geo_coordinates": {"latitude": 51.5, "longitude": -0.12},
    }
    assert is_locked(PE1_LOCKED) is True
    assert is_locked(PE1) is False
    assert is_locked(node("u", "X", lock_status={**LOCKED_STATUS, "state": "UNLOCKED"})) is False
    assert is_locked(node("u", "X", lock_status={"state": "LOCKED"})) is False  # no lock_id
    assert device_tags_view({"uuid": "u"})["tag_names"] == []


def test_device_tags_line_renders_every_lock_state():
    locked = device_tags_line(device_tags_view(PE1_LOCKED))
    assert locked == (
        f"**PE1** ({PE1_UUID}) tags: cli, snmp, reach-check; lock: LOCKED by cnc-mcp until "
        f"2025-09-13T14:05:00Z (lock_id {LOCK_ID}); location: 51.5, -0.12"
    )
    # a lock_status that is not LOCKED (released, or expired without a release) is named
    released = node(PE1_UUID, "PE1", lock_status={**LOCKED_STATUS, "state": "UNLOCKED"})
    assert "; lock: unlocked; location: none" in device_tags_line(device_tags_view(released))
    errored = node(PE1_UUID, "PE1", lock_status={**LOCKED_STATUS, "state": "ERRORED"})
    assert "; lock: errored; location: none" in device_tags_line(device_tags_view(errored))
    assert "; lock: unlocked;" in device_tags_line(device_tags_view(PE1))  # never locked
    with_alt = node("u", "X", coordinates={**LONDON, "altitude": {"value": 35}})
    assert device_tags_line(device_tags_view(with_alt)).endswith("51.5, -0.12, altitude 35")


def test_lock_hint_is_specific_to_the_operational_state():
    assert lock_hint("ROBOT_OPER_STATE_OK", PE1_UUID) == ""
    checking = lock_hint("ROBOT_OPER_STATE_CHECKING", PE1_UUID)
    assert "ROBOT_OPER_STATE_CHECKING" in checking and "wait for cnc_get_device" in checking
    locked = lock_hint("ROBOT_OPER_STATE_LOCKED", PE1_UUID)
    assert "already carries a device lock" in locked and "cnc_unlock_device" in locked
    assert "end_time" in locked and "wait for cnc_get_device" not in locked
    for admin in ("ROBOT_OPER_STATE_UNMANAGED", "ROBOT_OPER_STATE_ADMIN_DOWN"):
        hint = lock_hint(admin, PE1_UUID)
        assert admin in hint
        assert f"cnc_update_device(uuid='{PE1_UUID}', admin_state='up')" in hint
    others = ("ROBOT_OPER_STATE_ERROR", "ROBOT_OPER_STATE_UNKNOWN", "ROBOT_OPER_STATE_DELETING")
    for other in others:
        hint = lock_hint(other, PE1_UUID)
        assert f"The device is {other}" in hint
        assert "flips" not in hint and "admin_state" not in hint and "unlock" not in hint
    assert "unknown operational state" in lock_hint(None, PE1_UUID)


def test_tag_hints():
    dup = create_tag_hint("The tag site-a already exists. Provide a unique name.", "site-a")
    assert "cnc_list_tags" in dup and "'site-a'" in dup and "cnc_assign_tags" in dup
    assert create_tag_hint("something else", "x") == " List the existing tags with cnc_list_tags."
    in_use = delete_tag_hint("Tag Name:site-a is in use and cannot be deleted.", "site-a")
    assert "cnc_unassign_tags(tags='site-a', host_name='*')" in in_use
    assert f"up to {SELECTOR_PAGE_SIZE} per call" in in_use
    assert "cnc_list_tags" in delete_tag_hint("no such tag", "ghost")
    assert "cnc_unassign_tags" not in delete_tag_hint("no such tag", "ghost")


def test_wire_bodies():
    assert geo_body(PE1_UUID, 51.5, -0.12) == {
        "Operation": "UpdateGeoCoordinates",
        "node_uuid_to_geocoords": {
            PE1_UUID: {"latitude": {"value": 51.5}, "longitude": {"value": -0.12}}
        },
    }
    assert geo_body(PE1_UUID, 51.5, -0.12, 35.0)["node_uuid_to_geocoords"][PE1_UUID][
        "altitude"
    ] == {"value": 35.0}
    assert lock_body(PE1_UUID, "cnc-mcp", 300) == {
        "state": "LOCKED",
        "uuids": [PE1_UUID],
        "owner_cookie": "cnc-mcp",
        "timeout": "300",  # a string on the wire (verified)
    }
    assert unlock_body(PE1_UUID, "cnc-mcp", LOCK_ID) == {
        "state": "UNLOCKED",
        "uuids": [PE1_UUID],
        "owner_cookie": "cnc-mcp",
        "lock_id": LOCK_ID,
    }


def test_check_lock_response():
    assert check_lock_response(LOCK_OK, "Locking") is LOCK_OK
    with pytest.raises(PlatformError, match="Locking failed: Node:.*state:ROBOT_OPER_STATE_OK$"):
        check_lock_response(LOCK_REFUSED, "Locking")
    with pytest.raises(PlatformError, match=r"failed \(rc NODE_REQ_REJECTED\): busy"):
        check_lock_response({"rc": "NODE_REQ_REJECTED", "rc_msg": "busy"}, "Locking")
    with pytest.raises(PlatformError, match="no reason given tail"):
        check_lock_response({}, "Locking", " tail")
    with pytest.raises(PlatformError, match="did not return a lock response"):
        check_lock_response(["nope"], "Locking")


# --- cnc_get_device_summary --------------------------------------------------


@respx.mock
async def test_get_device_summary_four_gets_and_absent_counts_are_zero(settings):
    routes = mock_summaries()
    text = await call_tool_text(build(settings), "cnc_get_device_summary", {})
    assert all(r.call_count == 1 for r in routes.values())
    head, _, body = text.partition("\n")
    assert head == "5 devices: 4 ok / 1 checking; 5 reachable; licenses Type A 5"
    data = json.loads(body)
    assert data["total"] == 5
    assert data["operational_state"] == {
        "ok": 4, "checking": 1, "down": 0, "error": 0, "unmanaged": 0, "locked": 0, "deleting": 0,
    }  # fmt: skip
    assert data["reachability"] == {"reachable": 5, "unreachable": 0, "degraded": 0, "unknown": 0}
    assert data["license_types"] == LICENSES["LicenseTypeCount"]


@respx.mock
async def test_get_device_summary_empty_inventory(settings):
    mock_summaries(
        count={"number_of_nodes": 0}, oper={}, reach={}, licenses={"LicenseTypeCount": {}}
    )
    text = await call_tool_text(build(settings), "cnc_get_device_summary", {})
    assert text.startswith(
        "0 devices: no operational-state counts; no reachability counts; licenses none"
    )
    assert not text.startswith("Error:")


@respx.mock
async def test_get_device_summary_api_error_is_string(make_settings):
    mock_summaries()
    respx.get(REACH_URL).mock(
        return_value=httpx.Response(403, json={"error": "Unauthorized request"})
    )
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_get_device_summary", {})
    assert text.startswith("Error:") and "403" in text


# --- cnc_get_inventory_config ------------------------------------------------


@respx.mock
async def test_get_inventory_config_sends_empty_bodies(settings):
    config = respx.post(INV_CONFIG_URL).mock(return_value=httpx.Response(200, json=INV_CONFIG))
    policies = respx.post(POLICIES_URL).mock(return_value=httpx.Response(200, json=POLICIES))
    text = await call_tool_text(build(settings), "cnc_get_inventory_config", {})
    assert sent(config) == {} and sent(policies) == {}
    assert "# Inventory configuration 'default'" in text
    assert "- host identifier: HOSTNAME_AND_DOMAIN" in text
    assert "- unique-key policies (1):" in text
    assert "- **Default Policy**: INV_TYPE_NODE, INDEPENDENT, fields: -" in text
    data = json.loads(text[text.index("{") :])
    assert data == {
        "inventory_config": INV_CONFIG,
        "unique_policies": POLICIES["data"],
        "total_policies": 1,
    }


@respx.mock
async def test_get_inventory_config_no_policies(settings):
    respx.post(INV_CONFIG_URL).mock(return_value=httpx.Response(200, json=INV_CONFIG))
    respx.post(POLICIES_URL).mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(build(settings), "cnc_get_inventory_config", {})
    assert "- unique-key policies (0):\n- (none)" in text
    assert json.loads(text[text.index("{") :])["total_policies"] == 0


@respx.mock
async def test_get_inventory_config_api_error_is_string(make_settings):
    respx.post(INV_CONFIG_URL).mock(return_value=NATS_500)
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_get_inventory_config", {})
    assert text.startswith("Error:") and "500" in text and "malformed request body" in text


# --- cnc_get_collection_cadence ----------------------------------------------


@respx.mock
async def test_get_collection_cadence(settings):
    route = respx.post(CADENCE_URL).mock(return_value=httpx.Response(200, json=CADENCE))
    text = await call_tool_text(build(settings), "cnc_get_collection_cadence", {})
    assert sent(route) == {}
    lines = text.split("\n")
    assert lines[0] == (
        "reach-check every 600 s, show-clock every 1800 s, snmp every 1200 s, "
        "te-tunnel-id every 1200 s"
    )
    # show-clock has no same-named tag: the built-in is clock-drift-check (platform notes)
    assert lines[1] == (
        "(reach-check: reachability probe (tag reach-check); show-clock: clock-drift check "
        "(tag clock-drift-check); snmp: SNMP inventory collection (tag snmp); te-tunnel-id: "
        "TE tunnel-id collection (tag te-tunnel-id))"
    )
    assert json.loads(text[text.index("{") :]) == CADENCE


@respx.mock
async def test_get_collection_cadence_api_error_is_string(make_settings):
    respx.post(CADENCE_URL).mock(
        return_value=httpx.Response(403, json={"error": "Unauthorized request"})
    )
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_collection_cadence", {}
    )
    assert text.startswith("Error:") and "403" in text


# --- cnc_get_device_tags -----------------------------------------------------


@respx.mock
async def test_get_device_tags_by_host_name(settings):
    nodes = mock_nodes({"data": [PE1_LOCKED], "total_count": 5, "result_count": 1})
    text = await call_tool_text(build(settings), "cnc_get_device_tags", {"host_name": "PE1"})
    assert sent(nodes) == query_of({"host_name": "PE1"})
    head, _, body = text.partition("\n")
    assert head == (
        f"**PE1** ({PE1_UUID}) tags: cli, snmp, reach-check; lock: LOCKED by cnc-mcp until "
        f"2025-09-13T14:05:00Z (lock_id {LOCK_ID}); location: 51.5, -0.12"
    )
    assert json.loads(body) == device_tags_view(PE1_LOCKED)


@respx.mock
async def test_get_device_tags_by_uuid_unlocked_no_location(settings):
    nodes = mock_nodes(UUID_NODE)  # a uuid filter answers without result_count (verified)
    text = await call_tool_text(build(settings), "cnc_get_device_tags", {"uuid": PE1_UUID})
    assert sent(nodes) == query_of({"uuid": PE1_UUID})
    assert text.startswith(
        f"**PE1** ({PE1_UUID}) tags: cli, snmp, reach-check, site-a; lock: unlocked; location: none"
    )
    data = json.loads(text.partition("\n")[2])
    assert data["lock_status"] is None and data["geo_coordinates"] is None


@pytest.mark.parametrize("state", ["UNLOCKED", "ERRORED"])
@respx.mock
async def test_get_device_tags_renders_a_released_or_expired_lock(settings, state):
    status = {**LOCKED_STATUS, "state": state}
    mock_nodes({"data": [node(PE1_UUID, "PE1", lock_status=status)], "total_count": 5})
    text = await call_tool_text(build(settings), "cnc_get_device_tags", {"uuid": PE1_UUID})
    head, _, body = text.partition("\n")
    assert head == (
        f"**PE1** ({PE1_UUID}) tags: cli, snmp, reach-check; lock: {state.lower()}; location: none"
    )
    assert json.loads(body)["lock_status"] == status


@respx.mock
async def test_get_device_tags_zero_match_is_error(settings):
    mock_nodes(NO_NODES)
    text = await call_tool_text(build(settings), "cnc_get_device_tags", {"host_name": "ghost"})
    assert text.startswith("Error: no device matches host_name 'ghost'")


@respx.mock
async def test_get_device_tags_ambiguous_wildcard_is_error(settings):
    mock_nodes(TWO_NODES)
    text = await call_tool_text(build(settings), "cnc_get_device_tags", {"host_name": "P*"})
    assert text.startswith("Error: host_name 'P*' matched 2 devices (PE1, P1, ...)")


@pytest.mark.parametrize("args", [{}, {"uuid": PE1_UUID, "host_name": "PE1"}, {"host_name": " "}])
@respx.mock
async def test_get_device_tags_requires_exactly_one_selector(settings, args):
    nodes = mock_nodes(ONE_NODE)
    text = await call_tool_text(build(settings), "cnc_get_device_tags", args)
    assert text.startswith("Error:") and "exactly one" in text
    assert nodes.call_count == 0


# --- cnc_create_tag ----------------------------------------------------------


@respx.mock
async def test_create_tag_body_and_envelope(make_settings):
    route = respx.post(TAGS_URL).mock(return_value=httpx.Response(200, json=TAG_CREATED))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_create_tag", {"name": "site-a"}
    )
    assert sent(route) == {"tags": [{"name": "site-a", "category": "default"}]}
    data = json.loads(text)
    assert data["state"] == "JOB_COMPLETED" and data["job_id"] == TAG_CREATED["job_id"]
    assert data["tag"] == {"name": "site-a", "category": "default"}
    assert data["impacted_objects"] == []


@respx.mock
async def test_create_tag_custom_category(make_settings):
    route = respx.post(TAGS_URL).mock(return_value=httpx.Response(200, json=TAG_CREATED))
    await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_create_tag",
        {"name": " ring-1 ", "category": "topology"},
    )
    assert sent(route) == {"tags": [{"name": "ring-1", "category": "topology"}]}


@respx.mock
async def test_create_tag_duplicate_is_error(make_settings):
    respx.post(TAGS_URL).mock(return_value=httpx.Response(200, json=TAG_DUPLICATE))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_create_tag", {"name": "site-a"}
    )
    assert text.startswith("Error: Creating tag 'site-a' failed")
    assert "JOB_FAILED" in text and "The tag site-a already exists" in text
    # the runtime hint points at the tool that shows what exists (CLAUDE.md step 4)
    assert "list the existing tags with cnc_list_tags" in text


@respx.mock
async def test_create_tag_other_job_failure_has_generic_pointer(make_settings):
    respx.post(TAGS_URL).mock(
        return_value=httpx.Response(200, json={**TAG_DUPLICATE, "error": "invalid category"})
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_create_tag", {"name": "site-a"}
    )
    assert text.startswith("Error: Creating tag 'site-a' failed")
    assert text.endswith("invalid category List the existing tags with cnc_list_tags.")
    assert "cnc_assign_tags" not in text


@respx.mock
async def test_create_tag_post_is_not_retried_on_503(make_settings):
    route = respx.post(TAGS_URL).mock(return_value=httpx.Response(503, text="busy"))
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=2)), "cnc_create_tag", {"name": "x"}
    )
    assert text.startswith("Error:") and "503" in text
    assert route.call_count == 1


# --- cnc_delete_tag ----------------------------------------------------------


@respx.mock
async def test_delete_tag_body_and_envelope(make_settings):
    route = respx.delete(TAGS_URL).mock(return_value=httpx.Response(200, json=TAG_DELETED))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_delete_tag", {"name": "site-a"}
    )
    assert sent(route) == {"tags": [{"name": "site-a"}]}
    data = json.loads(text)
    assert data["state"] == "JOB_COMPLETED" and data["tag"] == {"name": "site-a"}


@respx.mock
async def test_delete_tag_in_use_is_error(make_settings):
    respx.delete(TAGS_URL).mock(return_value=httpx.Response(200, json=TAG_IN_USE))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_delete_tag", {"name": "site-a"}
    )
    assert text.startswith("Error: Deleting tag 'site-a' failed")
    assert "Tag Name:site-a is in use and cannot be deleted." in text
    # the free-before-delete sequence is repeated at runtime (CLAUDE.md step 4)
    assert "cnc_unassign_tags(tags='site-a', host_name='*')" in text
    assert "then delete it again" in text


@respx.mock
async def test_delete_tag_other_job_failure_has_generic_pointer(make_settings):
    respx.delete(TAGS_URL).mock(
        return_value=httpx.Response(200, json={**TAG_IN_USE, "error": "Tag ghost not found"})
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_delete_tag", {"name": "ghost"}
    )
    assert text.startswith("Error: Deleting tag 'ghost' failed")
    assert "Tag ghost not found" in text and "cnc_list_tags" in text
    assert "cnc_unassign_tags" not in text


@respx.mock
async def test_delete_tag_api_error_is_string(make_settings):
    respx.delete(TAGS_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=0)), "cnc_delete_tag", {"name": "x"}
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_assign_tags ---------------------------------------------------------


@respx.mock
async def test_assign_tags_resolves_then_patches_tag_objects(make_settings):
    nodes = mock_nodes(ONE_NODE)
    patch = respx.patch(NODES_URL).mock(return_value=httpx.Response(200, json=ASSIGN_WARNING))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_assign_tags",
        {"tags": "site-a, ring-1", "host_name": "PE1"},
    )
    assert sent(nodes) == query_of({"host_name": "PE1"})
    assert patch.call_count == 1
    assert sent(patch) == {
        "data": [{"uuid": PE1_UUID, "tags": [{"name": "site-a"}, {"name": "ring-1"}]}]
    }
    data = json.loads(text)
    assert data["state"] == "JOB_COMPLETED_WITH_WARNING"
    assert data["warning"] == NSO_ADVISORY  # the advisory is a success
    assert data["tags"] == ["site-a", "ring-1"]
    assert data["devices"] == [{"host_name": "PE1", "uuid": PE1_UUID}]
    assert data["impacted_objects"] == [{"uuid": PE1_UUID, "name": "PE1", "ip": "198.18.140.11"}]


@respx.mock
async def test_assign_tags_wildcard_builds_one_entry_per_device(make_settings):
    nodes = mock_nodes(TWO_NODES)
    patch = respx.patch(NODES_URL).mock(
        return_value=httpx.Response(
            200, json={**ASSIGN_WARNING, "type": "2 device(s) details patched successfully"}
        )
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_assign_tags",
        {"tags": "site-a", "host_name": "P*"},
    )
    assert sent(nodes) == query_of({"host_name": "P*"})
    assert sent(patch) == {
        "data": [
            {"uuid": PE1_UUID, "tags": [{"name": "site-a"}]},
            {"uuid": P1_UUID, "tags": [{"name": "site-a"}]},
        ]
    }
    data = json.loads(text)
    assert [d["host_name"] for d in data["devices"]] == ["PE1", "P1"]


@respx.mock
async def test_assign_tags_zero_match_refuses_and_never_patches(make_settings):
    mock_nodes(NO_NODES)
    patch = respx.patch(NODES_URL).mock(return_value=httpx.Response(200, json=ASSIGN_WARNING))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_assign_tags",
        {"tags": "site-a", "host_name": "ghost"},
    )
    assert text.startswith("Error: no device matches host_name 'ghost'")
    assert "nothing was changed" in text
    assert patch.call_count == 0


@respx.mock
async def test_assign_tags_more_matches_than_one_page_refuses(make_settings):
    mock_nodes({"data": [PE1, P1], "total_count": 500, "result_count": 250})
    patch = respx.patch(NODES_URL).mock(return_value=httpx.Response(200, json=ASSIGN_WARNING))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_assign_tags",
        {"tags": "site-a", "host_name": "*"},
    )
    assert text.startswith("Error: host_name '*' matches 250 devices, more than the 100")
    assert patch.call_count == 0


@respx.mock
async def test_assign_tags_full_page_without_result_count_refuses(make_settings):
    """uuid='*' on a 250-device inventory: 100 rows, no result_count (a uuid filter never
    reports it), total_count 250 — the match count is unknown, so nothing may be PATCHed."""
    nodes = mock_nodes(FULL_PAGE_NO_COUNT)
    patch = respx.patch(NODES_URL).mock(return_value=httpx.Response(200, json=ASSIGN_WARNING))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_assign_tags",
        {"tags": "site-a", "uuid": "*"},
    )
    assert nodes.call_count == 1
    assert text.startswith(
        "Error: uuid '*' fills a whole page of 100 devices and Crosswork did not report the "
        "match count (the inventory holds 250 devices)"
    )
    assert "nothing was changed" in text and "run it in batches" in text
    assert patch.call_count == 0


@respx.mock
async def test_assign_tags_by_uuid_without_result_count_still_patches_one_device(make_settings):
    mock_nodes(UUID_NODE)  # one row, no result_count: a complete match
    patch = respx.patch(NODES_URL).mock(return_value=httpx.Response(200, json=ASSIGN_WARNING))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_assign_tags",
        {"tags": "ring-1", "uuid": PE1_UUID},
    )
    assert sent(patch) == {"data": [{"uuid": PE1_UUID, "tags": [{"name": "ring-1"}]}]}
    assert json.loads(text)["devices"] == [{"host_name": "PE1", "uuid": PE1_UUID}]


@respx.mock
async def test_assign_tags_empty_tags_is_error_before_any_call(make_settings):
    nodes = mock_nodes(ONE_NODE)
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_assign_tags",
        {"tags": " , ", "host_name": "PE1"},
    )
    assert text.startswith("Error: tags is empty")
    assert nodes.call_count == 0


@respx.mock
async def test_assign_tags_job_failed_is_error(make_settings):
    mock_nodes(UUID_NODE)
    respx.patch(NODES_URL).mock(return_value=httpx.Response(200, json=ASSIGN_FAILED))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_assign_tags",
        {"tags": "ghost-tag", "uuid": PE1_UUID},
    )
    assert text.startswith("Error: Assigning tags ghost-tag to 1 device(s) failed")
    assert "JOB_FAILED" in text and "Tag ghost-tag does not exist" in text


@respx.mock
async def test_assign_tags_api_error_is_string(make_settings):
    mock_nodes(ONE_NODE)
    respx.patch(NODES_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=0)),
        "cnc_assign_tags",
        {"tags": "site-a", "host_name": "PE1"},
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_unassign_tags -------------------------------------------------------


@respx.mock
async def test_unassign_tags_sends_tag_names_not_objects(make_settings):
    nodes = mock_nodes(ONE_NODE)  # PE1 carries site-a
    put = respx.put(UNASSIGN_URL).mock(return_value=httpx.Response(200, json=UNASSIGN_DONE))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_unassign_tags",
        {"tags": "site-a", "host_name": "PE1"},
    )
    assert sent(nodes) == query_of({"host_name": "PE1"})
    assert sent(put) == {"data": [{"uuid": PE1_UUID, "tag_names": ["site-a"]}]}
    assert "tags" not in sent(put)["data"][0]  # the object form is a verified silent no-op
    data = json.loads(text)
    assert data["state"] == "JOB_COMPLETED" and data["type"] == "Unassign tags"
    assert data["tags"] == ["site-a"]
    assert data["devices"] == [
        {"host_name": "PE1", "uuid": PE1_UUID, "tag_names_removed": ["site-a"]}
    ]
    assert data["scanned"] == 1 and data["skipped_count"] == 0 and data["skipped"] == []


@respx.mock
async def test_unassign_tags_full_page_without_result_count_refuses(make_settings):
    """An exact (non-wildcard) selector reads one page; a full page with no result_count
    means the match may be incomplete — refused, nothing PUT. (uuid values do not carry
    '*' here, so the single-page path is the one exercised.)"""
    full = {"data": many_nodes(SELECTOR_PAGE_SIZE, carriers=(0, 1)), "total_count": 250}
    nodes = mock_nodes(full)
    put = respx.put(UNASSIGN_URL).mock(return_value=httpx.Response(200, json=UNASSIGN_DONE))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_unassign_tags",
        {"tags": "site-a", "uuid": "uuid-0000"},
    )
    assert nodes.call_count == 1
    assert text.startswith("Error: uuid 'uuid-0000' fills a whole page of 100 devices")
    assert "did not report the match count" in text
    assert put.call_count == 0


@respx.mock
async def test_unassign_tags_refuses_a_tag_the_device_does_not_carry(make_settings):
    mock_nodes(ONE_NODE)
    put = respx.put(UNASSIGN_URL).mock(return_value=httpx.Response(200, json=UNASSIGN_DONE))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_unassign_tags",
        {"tags": "site-a,ring-1", "host_name": "PE1"},
    )
    assert text.startswith(f"Error: device PE1 ({PE1_UUID}) does not carry tag(s) ring-1")
    assert "it carries: cli, snmp, reach-check, site-a" in text
    assert put.call_count == 0


@respx.mock
async def test_unassign_tags_wildcard_skips_devices_without_the_tag(make_settings):
    mock_nodes(TWO_NODES)  # PE1 carries site-a, P1 does not
    put = respx.put(UNASSIGN_URL).mock(return_value=httpx.Response(200, json=UNASSIGN_DONE))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_unassign_tags",
        {"tags": "site-a", "host_name": "*"},
    )
    assert sent(put) == {"data": [{"uuid": PE1_UUID, "tag_names": ["site-a"]}]}
    data = json.loads(text)
    assert data["devices"] == [
        {"host_name": "PE1", "uuid": PE1_UUID, "tag_names_removed": ["site-a"]}
    ]
    assert data["scanned"] == 2 and data["skipped_count"] == 1
    assert data["skipped"] == [{"host_name": "P1", "uuid": P1_UUID, "tag_names": list(SYSTEM_TAGS)}]


@respx.mock
async def test_unassign_tags_wildcard_scans_every_page_and_puts_only_carriers(make_settings):
    """host_name='*' on a 150-device inventory: two nodes/query pages (100 + 50, result_count
    150), one PUT naming the three carriers — the free-before-delete sequence works past
    100 devices."""
    counts = {"total_count": 150, "result_count": 150}
    page0 = {"data": many_nodes(100, carriers=(3, 77)), **counts}
    page1 = {"data": many_nodes(50, start=100, carriers=(20,)), **counts}
    nodes = mock_node_pages(page0, page1)
    put = respx.put(UNASSIGN_URL).mock(return_value=httpx.Response(200, json=UNASSIGN_DONE))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_unassign_tags",
        {"tags": "site-a", "host_name": "*"},
    )
    assert nodes.call_count == 2
    assert sent(nodes, 0) == query_of({"host_name": "*"}, page=0)
    assert sent(nodes, 1) == query_of({"host_name": "*"}, page=1)
    assert put.call_count == 1
    assert sent(put) == {
        "data": [
            {"uuid": "uuid-0003", "tag_names": ["site-a"]},
            {"uuid": "uuid-0077", "tag_names": ["site-a"]},
            {"uuid": "uuid-0120", "tag_names": ["site-a"]},
        ]
    }
    data = json.loads(text)
    assert data["state"] == "JOB_COMPLETED"
    assert [d["host_name"] for d in data["devices"]] == ["D0003", "D0077", "D0120"]
    assert data["scanned"] == 150 and data["skipped_count"] == 147
    assert len(data["skipped"]) == SKIPPED_LIST_LIMIT  # the list is capped, the count exact
    assert data["skipped"][0]["host_name"] == "D0000"


@respx.mock
async def test_unassign_tags_wildcard_scan_without_result_count_stops_at_the_empty_page(
    make_settings,
):
    """uuid='*' never reports result_count: the scan walks full pages until a short or
    empty one (past the end Crosswork answers a bare {})."""
    page0 = {"data": many_nodes(100, carriers=(99,)), "total_count": 200}
    page1 = {"data": many_nodes(100, start=100, carriers=(0,)), "total_count": 200}
    nodes = mock_node_pages(page0, page1, NO_NODES)
    put = respx.put(UNASSIGN_URL).mock(return_value=httpx.Response(200, json=UNASSIGN_DONE))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_unassign_tags",
        {"tags": "site-a", "uuid": "*"},
    )
    assert nodes.call_count == 3
    assert [sent(nodes, i)["filterData"]["PageNum"] for i in range(3)] == [0, 1, 2]
    assert sent(put) == {
        "data": [
            {"uuid": "uuid-0099", "tag_names": ["site-a"]},
            {"uuid": "uuid-0100", "tag_names": ["site-a"]},
        ]
    }
    assert json.loads(text)["scanned"] == 200


@respx.mock
async def test_unassign_tags_wildcard_with_more_carriers_than_one_write_refuses(make_settings):
    """The scan is unbounded (a read); the PUT is bounded at 100 carriers — nothing is sent."""
    counts = {"total_count": 101, "result_count": 101}
    page0 = {"data": many_nodes(100, carriers=tuple(range(100))), **counts}
    page1 = {"data": many_nodes(1, start=100, carriers=(0,)), **counts}
    nodes = mock_node_pages(page0, page1)
    put = respx.put(UNASSIGN_URL).mock(return_value=httpx.Response(200, json=UNASSIGN_DONE))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_unassign_tags",
        {"tags": "site-a", "host_name": "*"},
    )
    assert nodes.call_count == 2
    assert text.startswith(
        "Error: 101 of the 101 device(s) matching host_name '*' carry the tag(s) site-a, more "
        "than the 100 this tool unassigns in one call; nothing was changed."
    )
    assert "run it in batches" in text
    assert put.call_count == 0


@respx.mock
async def test_unassign_tags_wildcard_with_no_carrier_refuses(make_settings):
    mock_nodes(TWO_NODES)
    put = respx.put(UNASSIGN_URL).mock(return_value=httpx.Response(200, json=UNASSIGN_DONE))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_unassign_tags",
        {"tags": "ring-1", "host_name": "*"},
    )
    assert text.startswith(
        "Error: none of the 2 device(s) matching host_name '*' carries any of the tag(s) ring-1"
    )
    assert put.call_count == 0


@respx.mock
async def test_unassign_tags_zero_match_never_puts(make_settings):
    mock_nodes(NO_NODES)
    put = respx.put(UNASSIGN_URL).mock(return_value=httpx.Response(200, json=UNASSIGN_DONE))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_unassign_tags",
        {"tags": "site-a", "uuid": "nope"},
    )
    assert text.startswith("Error: no device matches uuid 'nope'")
    assert put.call_count == 0


@respx.mock
async def test_unassign_tags_job_failed_is_error(make_settings):
    mock_nodes(ONE_NODE)
    respx.put(UNASSIGN_URL).mock(
        return_value=httpx.Response(
            200,
            json={**UNASSIGN_DONE, "state": "JOB_FAILED", "error": "system tag cannot be removed"},
        )
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_unassign_tags",
        {"tags": "cli", "host_name": "PE1"},
    )
    assert text.startswith("Error: Unassigning tags cli from 1 device(s) failed")
    assert "system tag cannot be removed" in text


# --- cnc_set_device_location / cnc_clear_device_location ---------------------


@respx.mock
async def test_set_device_location_wraps_values(make_settings):
    nodes = mock_nodes(ONE_NODE)
    patch = respx.patch(GEO_URL).mock(return_value=httpx.Response(200, json=GEO_DONE))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_set_device_location",
        {"latitude": 51.5, "longitude": -0.12, "host_name": "PE1"},
    )
    assert sent(nodes) == query_of({"host_name": "PE1"})
    assert sent(patch) == {
        "Operation": "UpdateGeoCoordinates",
        "node_uuid_to_geocoords": {
            PE1_UUID: {"latitude": {"value": 51.5}, "longitude": {"value": -0.12}}
        },
    }
    data = json.loads(text)
    assert data["state"] == "JOB_COMPLETED"
    assert data["device"] == {"host_name": "PE1", "uuid": PE1_UUID}
    assert data["coordinates"] == {"latitude": 51.5, "longitude": -0.12}


@respx.mock
async def test_set_device_location_with_altitude(make_settings):
    mock_nodes(UUID_NODE)
    patch = respx.patch(GEO_URL).mock(return_value=httpx.Response(200, json=GEO_DONE))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_set_device_location",
        {"latitude": 51.5, "longitude": -0.12, "altitude": 35, "uuid": PE1_UUID},
    )
    coords = sent(patch)["node_uuid_to_geocoords"][PE1_UUID]
    assert coords["altitude"] == {"value": 35.0}
    assert json.loads(text)["coordinates"]["altitude"] == 35.0


async def test_set_device_location_rejects_out_of_range_before_any_call(make_settings):
    """Schema bounds (ge/le on the flat parameters) fail validation before any call."""
    with respx.mock:
        nodes = mock_nodes(ONE_NODE)
        mcp = build(make_settings(enable_writes=True))
        with pytest.raises(ToolError, match="latitude"):
            await call_tool_text(
                mcp,
                "cnc_set_device_location",
                {"latitude": 95, "longitude": 0, "host_name": "PE1"},
            )
        with pytest.raises(ToolError, match="longitude"):
            await call_tool_text(
                mcp,
                "cnc_set_device_location",
                {"latitude": 0, "longitude": -181, "host_name": "PE1"},
            )
        assert nodes.call_count == 0


@respx.mock
async def test_set_device_location_zero_match_and_ambiguous_never_patch(make_settings):
    patch = respx.patch(GEO_URL).mock(return_value=httpx.Response(200, json=GEO_DONE))
    mock_nodes(NO_NODES)
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_set_device_location",
        {"latitude": 1, "longitude": 2, "host_name": "ghost"},
    )
    assert text.startswith("Error: no device matches host_name 'ghost'")
    mock_nodes(TWO_NODES)
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_set_device_location",
        {"latitude": 1, "longitude": 2, "host_name": "P*"},
    )
    assert text.startswith("Error: host_name 'P*' matched 2 devices")
    assert patch.call_count == 0


@respx.mock
async def test_set_device_location_job_failed_is_error(make_settings):
    mock_nodes(ONE_NODE)
    respx.patch(GEO_URL).mock(return_value=httpx.Response(200, json=GEO_FAILED))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_set_device_location",
        {"latitude": 1, "longitude": 2, "host_name": "PE1"},
    )
    assert text.startswith(f"Error: Setting the location of device PE1 ({PE1_UUID}) failed")
    assert "node not found" in text


@respx.mock
async def test_set_device_location_nats_500_is_error(make_settings):
    mock_nodes(ONE_NODE)
    respx.patch(GEO_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=0)),
        "cnc_set_device_location",
        {"latitude": 1, "longitude": 2, "host_name": "PE1"},
    )
    assert text.startswith("Error:") and "500" in text and "malformed request body" in text


@respx.mock
async def test_clear_device_location_body(make_settings):
    mock_nodes({"data": [PE1_LOCKED], "result_count": 1})
    patch = respx.patch(GEO_URL).mock(
        return_value=httpx.Response(
            200, json={**GEO_DONE, "type": "RemoveGeoCoordinates geo coordinates for 1 nodes"}
        )
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_clear_device_location", {"host_name": "PE1"}
    )
    assert sent(patch) == {
        "Operation": "RemoveGeoCoordinates",
        "node_uuid_to_geocoords": {PE1_UUID: {}},
    }
    data = json.loads(text)
    assert data["state"] == "JOB_COMPLETED"
    assert data["device"] == {"host_name": "PE1", "uuid": PE1_UUID}
    assert data["previous_coordinates"] == {"latitude": 51.5, "longitude": -0.12}


@respx.mock
async def test_clear_device_location_zero_match_never_patches(make_settings):
    mock_nodes(NO_NODES)
    patch = respx.patch(GEO_URL).mock(return_value=httpx.Response(200, json=GEO_DONE))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_clear_device_location", {"uuid": "nope"}
    )
    assert text.startswith("Error: no device matches uuid 'nope'")
    assert patch.call_count == 0


@respx.mock
async def test_clear_device_location_job_failed_is_error(make_settings):
    mock_nodes(ONE_NODE)
    respx.patch(GEO_URL).mock(return_value=httpx.Response(200, json=GEO_FAILED))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_clear_device_location", {"host_name": "PE1"}
    )
    assert text.startswith(f"Error: Clearing the location of device PE1 ({PE1_UUID}) failed")


# --- cnc_lock_device ---------------------------------------------------------


@respx.mock
async def test_lock_device_body_and_answer(make_settings):
    nodes = mock_nodes(ONE_NODE)
    lock = respx.post(LOCK_URL).mock(return_value=httpx.Response(200, json=LOCK_OK))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_lock_device", {"host_name": "PE1"}
    )
    assert sent(nodes) == query_of({"host_name": "PE1"})
    assert sent(lock) == {
        "state": "LOCKED",
        "uuids": [PE1_UUID],
        "owner_cookie": "cnc-mcp",
        "timeout": "300",
    }
    assert isinstance(sent(lock)["timeout"], str)
    data = json.loads(text)
    assert data["device"] == {"host_name": "PE1", "uuid": PE1_UUID}
    assert data["rc"] == "NODE_REQ_SUCCESS" and data["lock_id"] == LOCK_ID
    assert data["owner_cookie"] == "cnc-mcp"
    assert data["start_time"] == "1757772000" and data["start_time_iso"] == "2025-09-13T14:00:00Z"
    assert data["end_time"] == "1757772300" and data["end_time_iso"] == "2025-09-13T14:05:00Z"
    assert (
        f"cnc_unlock_device(host_name='PE1', owner='cnc-mcp', lock_id='{LOCK_ID}')" in data["note"]
    )


@respx.mock
async def test_lock_device_custom_owner_and_timeout(make_settings):
    mock_nodes(UUID_NODE)
    lock = respx.post(LOCK_URL).mock(
        return_value=httpx.Response(200, json={**LOCK_OK, "owner_cookie": "maint-window"})
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_lock_device",
        {"uuid": PE1_UUID, "owner": "maint-window", "timeout_seconds": 3600},
    )
    assert sent(lock)["owner_cookie"] == "maint-window" and sent(lock)["timeout"] == "3600"
    assert "owner='maint-window'" in json.loads(text)["note"]


@respx.mock
async def test_lock_device_rc_msg_only_is_error_with_checking_hint(make_settings):
    mock_nodes({"data": [PE1_CHECKING], "result_count": 1})
    respx.post(LOCK_URL).mock(return_value=httpx.Response(200, json=LOCK_REFUSED))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_lock_device", {"host_name": "PE1"}
    )
    assert text.startswith(
        f"Error: Locking device PE1 ({PE1_UUID}, operational_state=ROBOT_OPER_STATE_CHECKING) "
        f"failed: Node:{PE1_UUID} is allowed to lock only in Operational state:ROBOT_OPER_STATE_OK"
    )
    assert "The device is ROBOT_OPER_STATE_CHECKING" in text
    assert "wait for cnc_get_device to read ROBOT_OPER_STATE_OK again and retry" in text


@respx.mock
async def test_lock_device_refusal_on_a_locked_device_says_already_locked(make_settings):
    """ROBOT_OPER_STATE_LOCKED never turns into OK by waiting: the hint names the held lock."""
    mock_nodes({"data": [PE1_OPER_LOCKED], "result_count": 1})
    respx.post(LOCK_URL).mock(
        return_value=httpx.Response(200, json={"rc_msg": f"Node:{PE1_UUID} already locked"})
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_lock_device", {"host_name": "PE1"}
    )
    assert text.startswith(
        f"Error: Locking device PE1 ({PE1_UUID}, operational_state=ROBOT_OPER_STATE_LOCKED) "
        f"failed: Node:{PE1_UUID} already locked The device is ROBOT_OPER_STATE_LOCKED: it "
        "already carries a device lock"
    )
    assert "cnc_unlock_device" in text and "expire at end_time" in text
    assert "wait for cnc_get_device" not in text and "flips" not in text


@pytest.mark.parametrize("oper", ["ROBOT_OPER_STATE_UNMANAGED", "ROBOT_OPER_STATE_ADMIN_DOWN"])
@respx.mock
async def test_lock_device_refusal_on_an_admin_down_device_points_at_update_device(
    make_settings, oper
):
    mock_nodes({"data": [node(PE1_UUID, "PE1", oper=oper)], "result_count": 1})
    respx.post(LOCK_URL).mock(return_value=httpx.Response(200, json=LOCK_REFUSED))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_lock_device", {"host_name": "PE1"}
    )
    assert f"operational_state={oper}) failed: Node:{PE1_UUID} is allowed to lock" in text
    assert f"The device is {oper}" in text
    assert f"cnc_update_device(uuid='{PE1_UUID}', admin_state='up')" in text
    assert "flips" not in text


@respx.mock
async def test_lock_device_refusal_on_an_error_device_just_names_the_state(make_settings):
    mock_nodes({"data": [node(PE1_UUID, "PE1", oper="ROBOT_OPER_STATE_ERROR")], "result_count": 1})
    respx.post(LOCK_URL).mock(return_value=httpx.Response(200, json=LOCK_REFUSED))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_lock_device", {"host_name": "PE1"}
    )
    assert text.endswith(
        "The device is ROBOT_OPER_STATE_ERROR; only ROBOT_OPER_STATE_OK can be locked "
        "(cnc_get_device shows the state and its errors)."
    )
    assert "flips" not in text and "admin_state" not in text and "cnc_unlock_device" not in text


@respx.mock
async def test_lock_device_refusal_on_an_ok_device_has_no_checking_hint(make_settings):
    mock_nodes(ONE_NODE)
    respx.post(LOCK_URL).mock(return_value=httpx.Response(200, json={"rc_msg": "already locked"}))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_lock_device", {"host_name": "PE1"}
    )
    assert text == (
        f"Error: Locking device PE1 ({PE1_UUID}, operational_state=ROBOT_OPER_STATE_OK) failed: "
        "already locked"
    )


@respx.mock
async def test_lock_device_zero_match_never_posts(make_settings):
    mock_nodes(NO_NODES)
    lock = respx.post(LOCK_URL).mock(return_value=httpx.Response(200, json=LOCK_OK))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_lock_device", {"host_name": "ghost"}
    )
    assert text.startswith("Error: no device matches host_name 'ghost'")
    assert lock.call_count == 0


async def test_lock_device_timeout_bounds_are_enforced_by_the_schema(make_settings):
    with respx.mock:
        nodes = mock_nodes(ONE_NODE)
        mcp = build(make_settings(enable_writes=True))
        for bad in (5, 86401):
            with pytest.raises(ToolError, match="timeout_seconds"):
                await call_tool_text(
                    mcp, "cnc_lock_device", {"host_name": "PE1", "timeout_seconds": bad}
                )
        assert nodes.call_count == 0


@respx.mock
async def test_lock_device_api_error_is_string(make_settings):
    mock_nodes(ONE_NODE)
    respx.post(LOCK_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=0)),
        "cnc_lock_device",
        {"host_name": "PE1"},
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_unlock_device -------------------------------------------------------


@respx.mock
async def test_unlock_device_reads_lock_id_from_the_device(make_settings):
    nodes = mock_nodes({"data": [PE1_LOCKED], "result_count": 1})
    unlock = respx.post(LOCK_URL).mock(return_value=httpx.Response(200, json=UNLOCK_OK))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_unlock_device", {"host_name": "PE1"}
    )
    assert sent(nodes) == query_of({"host_name": "PE1"})
    assert sent(unlock) == {
        "state": "UNLOCKED",
        "uuids": [PE1_UUID],
        "owner_cookie": "cnc-mcp",
        "lock_id": LOCK_ID,
    }
    data = json.loads(text)
    assert data["rc"] == "NODE_REQ_SUCCESS" and data["lock_id"] == LOCK_ID
    assert data["device"] == {"host_name": "PE1", "uuid": PE1_UUID}
    assert data["lock_status_before"] == LOCKED_STATUS


@respx.mock
async def test_unlock_device_explicit_lock_id_and_owner(make_settings):
    mock_nodes(UUID_NODE)  # not locked as far as the record says — an explicit lock_id still goes
    unlock = respx.post(LOCK_URL).mock(
        return_value=httpx.Response(200, json={**UNLOCK_OK, "owner_cookie": "maint-window"})
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_unlock_device",
        {"uuid": PE1_UUID, "owner": "maint-window", "lock_id": "abc-123"},
    )
    assert sent(unlock)["lock_id"] == "abc-123" and sent(unlock)["owner_cookie"] == "maint-window"
    data = json.loads(text)
    assert data["lock_id"] == "abc-123" and data["lock_status_before"] is None


@respx.mock
async def test_unlock_device_not_locked_is_error_before_any_post(make_settings):
    mock_nodes(ONE_NODE)
    unlock = respx.post(LOCK_URL).mock(return_value=httpx.Response(200, json=UNLOCK_NOT_LOCKED))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_unlock_device", {"host_name": "PE1"}
    )
    assert text.startswith(f"Error: device PE1 ({PE1_UUID}) is not locked (lock_status: none)")
    assert unlock.call_count == 0


@respx.mock
async def test_unlock_device_unlocked_state_is_error_before_any_post(make_settings):
    released = node(PE1_UUID, "PE1", lock_status={**LOCKED_STATUS, "state": "UNLOCKED"})
    mock_nodes({"data": [released], "result_count": 1})
    unlock = respx.post(LOCK_URL).mock(return_value=httpx.Response(200, json=UNLOCK_NOT_LOCKED))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_unlock_device", {"host_name": "PE1"}
    )
    assert text.startswith(f"Error: device PE1 ({PE1_UUID}) is not locked (lock_status: UNLOCKED)")
    assert unlock.call_count == 0


@respx.mock
async def test_unlock_device_foreign_owner_is_refused_before_any_post(make_settings):
    """A lock owned by another application (Change Automation's 'capp-nca' here) is not
    released under the default owner — the tool refuses; whether the platform would check
    owner_cookie is not verified, so nothing is sent."""
    foreign = node(PE1_UUID, "PE1", lock_status={**LOCKED_STATUS, "owner": "capp-nca"})
    mock_nodes({"data": [foreign], "result_count": 1})
    unlock = respx.post(LOCK_URL).mock(return_value=httpx.Response(200, json=UNLOCK_OK))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_unlock_device", {"host_name": "PE1"}
    )
    assert text.startswith(
        f"Error: device PE1 ({PE1_UUID}) is locked by 'capp-nca', not by 'cnc-mcp' "
        f"(lock_id {LOCK_ID}, until 2025-09-13T14:05:00Z); nothing was sent."
    )
    assert "Passing lock_id explicitly overrides this guard" in text
    assert unlock.call_count == 0
    # the explicit owner argument is what is compared, not the default
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_unlock_device",
        {"host_name": "PE1", "owner": "someone-else"},
    )
    assert text.startswith(
        f"Error: device PE1 ({PE1_UUID}) is locked by 'capp-nca', not by 'someone-else'"
    )
    assert unlock.call_count == 0


@respx.mock
async def test_unlock_device_foreign_owner_with_explicit_lock_id_is_sent(make_settings):
    """lock_id given explicitly is the deliberate override: the request goes out as given."""
    foreign = node(PE1_UUID, "PE1", lock_status={**LOCKED_STATUS, "owner": "capp-nca"})
    mock_nodes({"data": [foreign], "result_count": 1})
    unlock = respx.post(LOCK_URL).mock(
        return_value=httpx.Response(200, json={**UNLOCK_OK, "owner_cookie": "capp-nca"})
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_unlock_device",
        {"host_name": "PE1", "owner": "capp-nca", "lock_id": LOCK_ID},
    )
    assert sent(unlock) == {
        "state": "UNLOCKED",
        "uuids": [PE1_UUID],
        "owner_cookie": "capp-nca",
        "lock_id": LOCK_ID,
    }
    assert json.loads(text)["rc"] == "NODE_REQ_SUCCESS"


@respx.mock
async def test_unlock_device_own_lock_with_matching_owner_is_sent(make_settings):
    mine = node(PE1_UUID, "PE1", lock_status={**LOCKED_STATUS, "owner": "maint-window"})
    mock_nodes({"data": [mine], "result_count": 1})
    unlock = respx.post(LOCK_URL).mock(return_value=httpx.Response(200, json=UNLOCK_OK))
    await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_unlock_device",
        {"host_name": "PE1", "owner": "maint-window"},
    )
    assert sent(unlock)["owner_cookie"] == "maint-window" and sent(unlock)["lock_id"] == LOCK_ID


@respx.mock
async def test_unlock_device_platform_refusal_is_error_with_lock_context(make_settings):
    mock_nodes({"data": [PE1_LOCKED], "result_count": 1})  # owned by cnc-mcp, the default owner
    respx.post(LOCK_URL).mock(return_value=httpx.Response(200, json=UNLOCK_NOT_LOCKED))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_unlock_device", {"host_name": "PE1"}
    )
    assert text.startswith(f"Error: Unlocking device PE1 ({PE1_UUID}) failed: Error Locking Node!")
    assert f"(device lock_status: state=LOCKED, owner=cnc-mcp, lock_id={LOCK_ID})" in text


@respx.mock
async def test_unlock_device_zero_match_never_posts(make_settings):
    mock_nodes(NO_NODES)
    unlock = respx.post(LOCK_URL).mock(return_value=httpx.Response(200, json=UNLOCK_OK))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_unlock_device", {"host_name": "ghost"}
    )
    assert text.startswith("Error: no device matches host_name 'ghost'")
    assert unlock.call_count == 0


@respx.mock
async def test_unlock_device_api_error_is_string(make_settings):
    mock_nodes({"data": [PE1_LOCKED], "result_count": 1})
    respx.post(LOCK_URL).mock(
        return_value=httpx.Response(403, json={"error": "Unauthorized request"})
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=0)),
        "cnc_unlock_device",
        {"host_name": "PE1"},
    )
    assert text.startswith("Error:") and "403" in text
