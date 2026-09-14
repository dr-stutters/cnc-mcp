"""Device tools end-to-end through MCPServer (schema validation included).

The module is registered directly (not via ALL_MODULES) so these tests are
independent of the registry. Fixtures mirror shapes verified live on CNC.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from cnc_mcp import polling
from cnc_mcp.auth import StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.errors import PlatformError
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import devices
from tests.conftest import BASE_URL, call_tool_text

NODES = f"{BASE_URL}/crosswork/inventory/v1/nodes"
NODES_QUERY = f"{NODES}/query"
SUMMARY = f"{BASE_URL}/crosswork/inventory/v1/networkelement/collectionstatussummary/query"

PE1_UUID = "2a9b7c1e-0f3d-4b8a-9c6e-1d2f3a4b5c6d"
P1_UUID = "7f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f"


def node(uuid: str, host: str, ip: str, reach: str = "CONN_STATE_REACHABLE") -> dict:
    return {
        "uuid": uuid,
        "host_name": host,
        "node_ip": {"inet_af": "ROBOT_INET_ADDR_TYPE_v4", "inet_addr": ip, "mask": "18"},
        "admin_state": "ROBOT_ADMIN_STATE_UP",
        "reachability_state": reach,
        "operational_state": "ROBOT_OPER_STATE_OK",
        "reachability_check": "REACH_CHECK_ENABLE",
        "profile": "cml-xrd",
        "dg_name": "dg-1",
        "product_info": {"device_type": "NODE_TYPE_ROUTER", "capability": ["SNMP", "YANG_CLI"]},
        "routing_info": {"te_router_id": "10.0.0.1", "global_isis_system_id": "0000.0000.0001"},
        "tag_names": ["core"],
        "errors": [],
    }


PE1 = node(PE1_UUID, "PE1", "198.18.140.11")
P1 = node(P1_UUID, "P1", "198.18.140.12", reach="CONN_STATE_UNKNOWN")
TWO_NODES = {"data": [PE1, P1], "total_count": 5, "result_count": 3}
JOB_OK = {
    "job_id": "j-1",
    "state": "JOB_COMPLETED",
    "type": "1 device(s) added successfully",
    "impacted": [f"{PE1_UUID} PE1 198.18.140.11"],
}
JOB_FAILED = {
    "job_id": "j-2",
    "state": "JOB_FAILED",
    "type": "1 device(s) details updation failed ",
    "error": "Software Type needs to be configured",
}
NATS_500 = httpx.Response(500, json={"error": "NATS request failed"})


def build(settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    devices.register(mcp, ctx)
    return mcp


def sent_body(route: respx.Route, index: int = 0) -> dict:
    return json.loads(route.calls[index].request.content)


class _FakeClock:
    """Stands in for ``time`` and ``asyncio`` inside cnc_mcp.polling, and for
    ``asyncio`` inside cnc_mcp.tools.devices (the gNMI settles), so no test sleeps."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture
def fake_clock(monkeypatch) -> _FakeClock:
    clock = _FakeClock()
    monkeypatch.setattr(polling, "time", clock)
    monkeypatch.setattr(polling, "asyncio", clock)
    monkeypatch.setattr(devices, "asyncio", clock)
    return clock


# --- registration / gating ---------------------------------------------------


async def test_write_tools_hidden_by_default(make_settings):
    names = {t.name for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert {
        "cnc_list_devices",
        "cnc_get_device",
        "cnc_get_device_collection_summary",
        "cnc_wait_for_device_reachable",
    } <= names
    assert not (
        {"cnc_create_device", "cnc_update_device", "cnc_delete_device", "cnc_enable_device_gnmi"}
        & names
    )


async def test_write_tools_registered_and_annotated(make_settings):
    tools = {t.name: t for t in await build(make_settings(enable_writes=True)).list_tools()}
    assert tools["cnc_create_device"].annotations.read_only_hint is False
    assert tools["cnc_create_device"].annotations.destructive_hint is False
    assert tools["cnc_create_device"].annotations.idempotent_hint is False
    assert tools["cnc_update_device"].annotations.read_only_hint is False
    assert tools["cnc_update_device"].annotations.idempotent_hint is True
    assert tools["cnc_enable_device_gnmi"].annotations.read_only_hint is False
    assert tools["cnc_enable_device_gnmi"].annotations.destructive_hint is False
    assert tools["cnc_enable_device_gnmi"].annotations.idempotent_hint is True
    assert tools["cnc_delete_device"].annotations.destructive_hint is True
    assert tools["cnc_delete_device"].annotations.idempotent_hint is True
    assert tools["cnc_list_devices"].annotations.read_only_hint is True
    assert tools["cnc_wait_for_device_reachable"].annotations.read_only_hint is True
    assert tools["cnc_wait_for_device_reachable"].annotations.idempotent_hint is True


# --- cnc_list_devices ----------------------------------------------------------


@respx.mock
async def test_list_devices_markdown_and_body(settings):
    route = respx.post(NODES_QUERY).mock(return_value=httpx.Response(200, json=TWO_NODES))
    text = await call_tool_text(
        build(settings),
        "cnc_list_devices",
        {"host_name": "P*", "reachability": "reachable", "admin_state": "up", "page_size": 2},
    )
    assert sent_body(route) == {
        "filter": {
            "host_name": "P*",
            "reachability_state": "CONN_STATE_REACHABLE",
            "admin_state": "ROBOT_ADMIN_STATE_UP",
        },
        "filterData": {"PageSize": 2, "PageNum": 0, "Criteria": ""},
    }
    assert "# Devices (2 shown, total 3)" in text
    assert (
        f"**PE1** ({PE1_UUID}) ip=198.18.140.11 reach=reachable "
        "oper=ROBOT_OPER_STATE_OK admin=up profile=cml-xrd dg=dg-1"
    ) in text
    assert "reach=unknown" in text
    assert "More available: page=1." in text


@respx.mock
async def test_list_devices_json_envelope_pages_with_pagenum(settings):
    route = respx.post(NODES_QUERY).mock(
        return_value=httpx.Response(200, json={"data": [P1], "total_count": 5, "result_count": 3})
    )
    text = await call_tool_text(
        build(settings),
        "cnc_list_devices",
        {"credential_profile": "cml-xrd", "page_size": 2, "page": 1, "response_format": "json"},
    )
    body = sent_body(route)
    assert body["filter"] == {"profile": "cml-xrd"}
    assert body["filterData"] == {"PageSize": 2, "PageNum": 1, "Criteria": ""}
    assert "offset" not in body and "limit" not in body
    data = json.loads(text)
    assert data["total"] == 3 and data["collection_total"] == 5
    assert data["page"] == 1 and data["count"] == 1
    assert data["has_more"] is False and data["next_page"] is None
    assert data["items"][0]["uuid"] == P1_UUID


@respx.mock
async def test_list_devices_empty_inventory_is_bare_dict(settings):
    respx.post(NODES_QUERY).mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(build(settings), "cnc_list_devices", {})
    assert "# Devices (0 shown)" in text
    assert "no devices matched" in text
    assert "More available" not in text


@respx.mock
async def test_list_devices_unknown_enum_is_error_without_request(settings):
    route = respx.post(NODES_QUERY).mock(return_value=httpx.Response(200, json=TWO_NODES))
    text = await call_tool_text(build(settings), "cnc_list_devices", {"admin_state": "sideways"})
    assert text.startswith("Error:") and "down, unmanaged, up" in text
    assert not route.called


@respx.mock
async def test_list_devices_nats_500_is_error_string(make_settings):
    respx.post(NODES_QUERY).mock(return_value=NATS_500)
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_list_devices", {})
    assert text.startswith("Error:") and "500" in text
    assert "malformed request body" in text


@respx.mock
async def test_list_devices_query_post_is_retried_on_503(make_settings):
    """nodes/query is a read sent as POST: a gateway 503 must be retried like a GET."""
    route = respx.post(NODES_QUERY).mock(
        side_effect=[
            httpx.Response(503, text="Service Unavailable"),
            httpx.Response(200, json=TWO_NODES),
        ]
    )
    text = await call_tool_text(build(make_settings(max_retries=2)), "cnc_list_devices", {})
    assert route.call_count == 2
    assert not text.startswith("Error:")
    assert "# Devices (2 shown, total 3)" in text
    assert f"**PE1** ({PE1_UUID})" in text


@respx.mock
async def test_list_devices_transport_error_is_not_reported_as_a_write(make_settings):
    respx.post(NODES_QUERY).mock(side_effect=httpx.ConnectError("boom"))
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_list_devices", {})
    assert text.startswith("Error:") and "Could not reach the platform" in text
    assert "write" not in text
    assert "already have been applied" not in text


# --- cnc_get_device -------------------------------------------------------------


@respx.mock
async def test_get_device_by_uuid(settings):
    route = respx.post(NODES_QUERY).mock(
        return_value=httpx.Response(200, json={"data": [PE1], "total_count": 5})
    )
    text = await call_tool_text(build(settings), "cnc_get_device", {"uuid": PE1_UUID})
    assert sent_body(route) == {
        "filter": {"uuid": PE1_UUID},
        "filterData": {"PageSize": 2, "PageNum": 0, "Criteria": ""},
    }
    data = json.loads(text)
    assert data["host_name"] == "PE1"
    assert data["node_ip"]["inet_af"] == "ROBOT_INET_ADDR_TYPE_v4"


@respx.mock
async def test_get_device_by_host_name(settings):
    route = respx.post(NODES_QUERY).mock(
        return_value=httpx.Response(200, json={"data": [PE1], "total_count": 5, "result_count": 1})
    )
    text = await call_tool_text(build(settings), "cnc_get_device", {"host_name": "pe1"})
    assert sent_body(route)["filter"] == {"host_name": "pe1"}
    assert json.loads(text)["uuid"] == PE1_UUID


# Read live 2026-09-14 (PE2): state_map keyed by the numeric RobotNodeStateElement enum,
# no ``element`` leaf on the wire, epoch-second strings. ``uptime`` below is the value as of
# state_map["1"].last_updated_time (the reachability check refreshes it every 1200 s on the
# lab); ``last_upd_time`` is the record's last modification, ~30 h older, and does not move
# with it.
STATE_MAP = {
    "1": {"value": "UP", "last_updated_time": "1789352986", "next_check_time": "1789352986"},
    "2": {"value": "UP", "last_updated_time": "1789339778", "next_check_time": "1789339778"},
    "3": {"value": "UP", "last_updated_time": "1789352369", "next_check_time": "1789352369"},
}


@respx.mock
async def test_get_device_labels_state_map_keys_and_keeps_the_rest(settings):
    pe2 = {
        **node("ec35be58-0000-4000-8000-000000000002", "PE2", "198.18.140.13"),
        "state_map": {**STATE_MAP, "9": {"value": "UP"}, "4": "odd"},
        "uptime": "0w1d14h4m30s",
        "last_upd_time": "1789244994",
    }
    respx.post(NODES_QUERY).mock(return_value=httpx.Response(200, json={"data": [pe2]}))
    mcp = build(settings)
    text = await call_tool_text(mcp, "cnc_get_device", {"host_name": "PE2"})
    data = json.loads(text)
    assert data["state_map"]["1"] == {"element": "REACHABILITY", **STATE_MAP["1"]}
    assert data["state_map"]["2"] == {"element": "DISCOVERY", **STATE_MAP["2"]}
    assert data["state_map"]["3"] == {"element": "CLOCK_DRIFT", **STATE_MAP["3"]}
    # Outside the enum / not a dict: passed through untouched.
    assert data["state_map"]["9"] == {"value": "UP"} and data["state_map"]["4"] == "odd"
    # The snapshot fields are returned exactly as read (the docstring says what they mean).
    assert data["uptime"] == "0w1d14h4m30s" and data["last_upd_time"] == "1789244994"
    # The fixture itself was not mutated.
    assert "element" not in pe2["state_map"]["1"]
    # The docstring's provenance for ``uptime`` is the one verified live 2026-09-14: the
    # reachability check's timestamp, not last_upd_time; nd.sys-up-time is a snapshot too.
    tools = {t.name: t for t in await mcp.list_tools()}
    description = tools["cnc_get_device"].description or ""
    assert '``state_map["1"].last_updated_time``' in description
    assert "NOT tied to ``last_upd_time``" in description
    assert "``nd.sys-up-time`` is itself a snapshot as of ``nd.collection-time``" in description
    assert "snapshot captured by the last" not in description
    # Two live behaviours (2026-09-14) the docstring must explain: key 0 alone is the
    # not-checked-yet placeholder of a (re)attached device in ROBOT_OPER_STATE_CHECKING, and
    # next_check_time mirrors last_updated_time on 7.2 (it is not a schedule).
    assert "**key 0 alone**" in description and "ROBOT_OPER_STATE_CHECKING" in description
    assert 'means "not checked yet", not "unsupported device"' in description
    assert "``next_check_time`` **equals ``last_updated_time`` on every" in description
    # Whitespace-normalised so a reflow of the prose cannot break the assertion.
    assert "must not be read as a schedule" in " ".join(description.split())


@respx.mock
async def test_get_device_labels_the_lone_unsupported_placeholder(settings):
    # Seen live 2026-09-14 on P2 right after re-attach: only key 0, no 1/2/3, while the
    # operational_state was still ROBOT_OPER_STATE_CHECKING.
    p2 = {
        **node("ec35be58-0000-4000-8000-000000000004", "P2", "198.18.140.14"),
        "operational_state": "ROBOT_OPER_STATE_CHECKING",
        "reachability_state": "CONN_STATE_UNKNOWN",
        "state_map": {
            "0": {"value": "UP", "last_updated_time": "1789356493", "next_check_time": "1789356493"}
        },
    }
    respx.post(NODES_QUERY).mock(return_value=httpx.Response(200, json={"data": [p2]}))
    data = json.loads(await call_tool_text(build(settings), "cnc_get_device", {"host_name": "P2"}))
    assert data["state_map"] == {
        "0": {
            "element": "UNSUPPORTED",
            "value": "UP",
            "last_updated_time": "1789356493",
            "next_check_time": "1789356493",
        }
    }
    assert data["operational_state"] == "ROBOT_OPER_STATE_CHECKING"


def test_label_state_map_respects_a_platform_element_and_missing_maps():
    node_with_element = {"state_map": {"1": {"element": "X", "value": "UP"}}}
    assert devices.label_state_map(node_with_element)["state_map"]["1"]["element"] == "X"
    assert devices.label_state_map({"host_name": "PE1"}) == {"host_name": "PE1"}
    assert devices.label_state_map({"state_map": "?"}) == {"state_map": "?"}
    assert devices.STATE_MAP_ELEMENTS["5"] == "SYNC" and devices.STATE_MAP_ELEMENTS["0"] == (
        "UNSUPPORTED"
    )


@respx.mock
async def test_get_device_not_found(settings):
    respx.post(NODES_QUERY).mock(return_value=httpx.Response(200, json={"total_count": 5}))
    text = await call_tool_text(build(settings), "cnc_get_device", {"host_name": "PE9"})
    assert text.startswith("Error:") and "not found" in text


@respx.mock
async def test_get_device_ambiguous_wildcard(settings):
    respx.post(NODES_QUERY).mock(return_value=httpx.Response(200, json=TWO_NODES))
    text = await call_tool_text(build(settings), "cnc_get_device", {"host_name": "P*"})
    assert text.startswith("Error:") and "more than one" in text


@respx.mock
async def test_get_device_requires_exactly_one_selector(settings):
    route = respx.post(NODES_QUERY).mock(return_value=httpx.Response(200, json=TWO_NODES))
    mcp = build(settings)
    assert (await call_tool_text(mcp, "cnc_get_device", {})).startswith("Error:")
    both = {"uuid": PE1_UUID, "host_name": "PE1"}
    assert (await call_tool_text(mcp, "cnc_get_device", both)).startswith("Error:")
    assert not route.called


# --- cnc_get_device_collection_summary -----------------------------------------------


@respx.mock
async def test_collection_summary_is_a_get(settings):
    counts = {"inprogress": 0, "warning": 1, "failed": 0, "completed": 4, "maintenance": 0}
    route = respx.get(SUMMARY).mock(return_value=httpx.Response(200, json=counts))
    text = await call_tool_text(build(settings), "cnc_get_device_collection_summary", {})
    assert route.called
    assert json.loads(text) == counts


@respx.mock
async def test_collection_summary_error(make_settings):
    respx.get(SUMMARY).mock(return_value=httpx.Response(403, json={"error": "unauthorized"}))
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_device_collection_summary", {}
    )
    assert text.startswith("Error:") and "403" in text


# --- cnc_create_device -----------------------------------------------------------


@respx.mock
async def test_create_device_minimal_body(make_settings):
    route = respx.post(NODES).mock(return_value=httpx.Response(200, json=JOB_OK))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_create_device",
        {
            "host_name": "PE1",
            "ip_address": "198.18.140.11",
            "prefix_length": 18,
            "credential_profile": "cml-xrd",
            "te_router_id": "10.0.0.1",
            "isis_system_id": "0000.0000.0001",
        },
    )
    assert sent_body(route) == {
        "data": [
            {
                "host_name": "PE1",
                "profile": "cml-xrd",
                "reachability_check": "REACH_CHECK_ENABLE",
                "admin_state": "ROBOT_ADMIN_STATE_UP",
                "connectivity_info": [
                    {
                        "type": "ROBOT_MSVC_TRANS_SSH",
                        "ipaddrs": [{"inet_af": 0, "inet_addr": "198.18.140.11", "mask": "18"}],
                        "port": 22,
                        "timeout": 0,
                    },
                    {
                        "type": "ROBOT_MSVC_TRANS_SNMP",
                        "ipaddrs": [{"inet_af": 0, "inet_addr": "198.18.140.11", "mask": "18"}],
                        "port": 161,
                        "timeout": 0,
                    },
                ],
                "product_info": {
                    "device_type": "NODE_TYPE_ROUTER",
                    "capability": ["SNMP", "YANG_CLI"],
                },
                "routing_info": {
                    "te_router_id": "10.0.0.1",
                    "global_isis_system_id": "0000.0000.0001",
                },
            }
        ]
    }
    data = json.loads(text)
    assert data["state"] == "JOB_COMPLETED"
    assert data["impacted_objects"] == [{"uuid": PE1_UUID, "name": "PE1", "ip": "198.18.140.11"}]


@respx.mock
async def test_create_device_required_args_only_omits_routing_info_and_tags(make_settings):
    route = respx.post(NODES).mock(return_value=httpx.Response(200, json=JOB_OK))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_create_device",
        {
            "host_name": "PE1",
            "ip_address": "198.18.140.11",
            "prefix_length": 18,
            "credential_profile": "cml-xrd",
        },
    )
    body = sent_body(route)["data"][0]
    assert "routing_info" not in body
    assert "tags" not in body
    assert set(body) == {
        "host_name",
        "profile",
        "reachability_check",
        "admin_state",
        "connectivity_info",
        "product_info",
    }
    assert body["admin_state"] == "ROBOT_ADMIN_STATE_UP"
    assert json.loads(text)["state"] == "JOB_COMPLETED"


@respx.mock
async def test_create_device_port_overrides_and_options(make_settings):
    route = respx.post(NODES).mock(return_value=httpx.Response(200, json=JOB_OK))
    await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_create_device",
        {
            "host_name": "P1",
            "ip_address": "198.18.140.12",
            "prefix_length": 18,
            "credential_profile": "cml-xrd",
            "protocols": "SSH, netconf:8300, ROBOT_MSVC_TRANS_GNMI",
            "admin_state": "unmanaged",
            "reachability_check": False,
            "capabilities": "gnmi,yang_mdt,gnmi",
            "ospf_router_id": "10.0.0.2",
        },
    )
    body = sent_body(route)["data"][0]
    assert body["admin_state"] == "ROBOT_ADMIN_STATE_UNMANAGED"
    assert body["reachability_check"] == "REACH_CHECK_DISABLE"
    assert [(c["type"], c["port"]) for c in body["connectivity_info"]] == [
        ("ROBOT_MSVC_TRANS_SSH", 22),
        ("ROBOT_MSVC_TRANS_NETCONF", 8300),
        ("ROBOT_MSVC_TRANS_GNMI", 57400),
    ]
    assert body["product_info"]["capability"] == ["GNMI", "YANG_MDT"]
    assert body["routing_info"] == {"global_ospf_router_id": "10.0.0.2"}
    assert "tags" not in body  # tags cannot be set on create (verified live)


@respx.mock
async def test_create_device_rejects_bad_inputs_before_sending(make_settings):
    route = respx.post(NODES).mock(return_value=httpx.Response(200, json=JOB_OK))
    mcp = build(make_settings(enable_writes=True))
    base = {"host_name": "X", "prefix_length": 18, "credential_profile": "p"}
    bad_ip = await call_tool_text(mcp, "cnc_create_device", {**base, "ip_address": "PE1.lab"})
    assert bad_ip.startswith("Error:") and "not a valid IPv4 address" in bad_ip
    bad_proto = await call_tool_text(
        mcp, "cnc_create_device", {**base, "ip_address": "10.0.0.1", "protocols": "ssh,ftp"}
    )
    assert bad_proto.startswith("Error:") and "Unknown protocol 'ftp'" in bad_proto
    bad_port = await call_tool_text(
        mcp, "cnc_create_device", {**base, "ip_address": "10.0.0.1", "protocols": "ssh:abc"}
    )
    assert bad_port.startswith("Error:") and "not an integer" in bad_port
    assert not route.called


@respx.mock
async def test_create_device_rejects_ipv6_until_wire_value_verified(make_settings):
    """ipaddr() hard-codes inet_af=0 (IPv4); a v6 literal must not be sent with it."""
    route = respx.post(NODES).mock(return_value=httpx.Response(200, json=JOB_OK))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_create_device",
        {
            "host_name": "X",
            "ip_address": "2001:db8::1",
            "prefix_length": 32,
            "credential_profile": "p",
        },
    )
    assert text.startswith("Error:") and "IPv6" in text and "only IPv4" in text
    assert not route.called


@respx.mock
async def test_create_device_schema_rejects_v6_prefix_and_empty_admin_state(make_settings):
    """prefix_length is bounded 1-32 and admin_state min_length=1 in the input schema,
    so '128' can never reach the wire as mask '128' and '' can never become null."""
    route = respx.post(NODES).mock(return_value=httpx.Response(200, json=JOB_OK))
    mcp = build(make_settings(enable_writes=True))
    base = {"host_name": "X", "ip_address": "10.0.0.1", "credential_profile": "p"}
    with pytest.raises(ToolError, match="prefix_length"):
        await mcp.call_tool("cnc_create_device", {**base, "prefix_length": 128})
    with pytest.raises(ToolError, match="prefix_length"):
        await mcp.call_tool("cnc_create_device", {**base, "prefix_length": 0})
    with pytest.raises(ToolError, match="admin_state"):
        await mcp.call_tool("cnc_create_device", {**base, "prefix_length": 24, "admin_state": ""})
    assert not route.called


def test_connectivity_info_enforces_ipv4_prefix_range():
    """Defence in depth below the schema: the helper itself rejects a v6-sized prefix."""
    with pytest.raises(PlatformError, match="out of range for an IPv4 address"):
        devices._connectivity_info("ssh", "10.0.0.1", 33)
    with pytest.raises(PlatformError, match="out of range for an IPv4 address"):
        devices._connectivity_info("ssh", "10.0.0.1", 0)
    entries = devices._connectivity_info("ssh", "10.0.0.1", 32)
    assert entries[0]["ipaddrs"] == [{"inet_af": 0, "inet_addr": "10.0.0.1", "mask": "32"}]


@respx.mock
async def test_create_device_job_failed_is_error(make_settings):
    failed = {
        "job_id": "j-3",
        "state": "JOB_FAILED",
        "type": "1 device(s) addition failed",
        "error": "Credential profile 'nope' does not exist",
    }
    respx.post(NODES).mock(return_value=httpx.Response(200, json=failed))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_create_device",
        {
            "host_name": "PE1",
            "ip_address": "198.18.140.11",
            "prefix_length": 18,
            "credential_profile": "nope",
        },
    )
    assert text.startswith("Error:")
    assert "JOB_FAILED" in text and "does not exist" in text and "j-3" in text


# --- cnc_update_device -----------------------------------------------------------


@respx.mock
async def test_update_device_patches_only_given_fields(make_settings):
    job = {**JOB_OK, "type": "1 device(s) details patched successfully"}
    route = respx.patch(NODES).mock(return_value=httpx.Response(200, json=job))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_update_device",
        {
            "uuid": PE1_UUID,
            "admin_state": "unmanaged",
            "reachability_check": False,
            "credential_profile": "cml-xrd2",
            "te_router_id": "10.0.0.9",
        },
    )
    assert sent_body(route) == {
        "data": [
            {
                "uuid": PE1_UUID,
                "admin_state": "ROBOT_ADMIN_STATE_UNMANAGED",
                "reachability_check": "REACH_CHECK_DISABLE",
                "profile": "cml-xrd2",
                "routing_info": {"te_router_id": "10.0.0.9"},
            }
        ]
    }
    assert json.loads(text)["type"] == "1 device(s) details patched successfully"


@respx.mock
async def test_update_device_requires_a_change(make_settings):
    route = respx.patch(NODES).mock(return_value=httpx.Response(200, json=JOB_OK))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_update_device", {"uuid": PE1_UUID}
    )
    assert text.startswith("Error:") and "Nothing to update" in text
    assert not route.called


@respx.mock
async def test_update_device_job_failed_is_error(make_settings):
    respx.patch(NODES).mock(return_value=httpx.Response(200, json=JOB_FAILED))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_update_device",
        {"uuid": PE1_UUID, "admin_state": "down"},
    )
    assert text.startswith("Error:") and "Software Type" in text


# --- cnc_enable_device_gnmi --------------------------------------------------------

# connectivity_info entries in their READ shape (verified live): inet_af is a string,
# timeout reads back as a string, and every transport carries its own reachability.
SNMP_T = {
    "type": "ROBOT_MSVC_TRANS_SNMP",
    "ipaddrs": [{"inet_af": "ROBOT_INET_ADDR_TYPE_v4", "inet_addr": "198.18.140.11", "mask": "18"}],
    "port": 161,
    "timeout": "0",
    "reachability_state": "CONN_STATE_REACHABLE",
    "reachability_state_upd_time": "1789300000",
    "error": "",
}
SSH_T = {
    "type": "ROBOT_MSVC_TRANS_SSH",
    "ipaddrs": [{"inet_af": "ROBOT_INET_ADDR_TYPE_v4", "inet_addr": "198.18.140.11", "mask": "18"}],
    "port": 22,
    "timeout": "0",
    "reachability_state": "CONN_STATE_REACHABLE",
    "reachability_state_upd_time": "1789300000",
    "error": "",
}
GNMI_NEW = {
    "type": "ROBOT_MSVC_TRANS_GNMI",
    "ipaddrs": SSH_T["ipaddrs"],
    "port": 57400,
    "timeout": "30",
    "encoding_type": "JSON_IETF",
}
GNMI_UNKNOWN_T = {
    **GNMI_NEW,
    "reachability_state": "CONN_STATE_UNKNOWN",
    "error": "",
}
GNMI_REACHABLE_T = {**GNMI_UNKNOWN_T, "reachability_state": "CONN_STATE_REACHABLE"}
NSO_ADVISORY = (
    f"Note, if device {PE1_UUID} is used in NSO, any updates to it needs be done "
    "through NSO interface"
)
JOB_WARN = {
    "job_id": "j-7",
    "state": "JOB_COMPLETED_WITH_WARNING",
    "type": "1 device(s) details patched successfully",
    "error": NSO_ADVISORY,
    "impacted": [f"{PE1_UUID} PE1 198.18.140.11"],
}
JOB_ENCODING_REQUIRED = {
    "job_id": "j-8",
    "state": "JOB_FAILED",
    "type": "1 device(s) details updation failed ",
    "error": "Encoding Type is required for adding a GNMI protocol. Hostname: PE1.",
}
JOB_CAPABILITY_REFUSED = {
    "job_id": "j-9",
    "state": "JOB_FAILED",
    "type": "1 device(s) details updation failed ",
    "error": (
        "Capability cannot be changed while the node is attached to a VDG and in admin up "
        "state. Please change the admin state to down and then try again"
    ),
}


def pe1_with(transports: list[dict], capability: list[str] | None = None) -> dict:
    """PE1 as read back with the given transport list (SNMP before SSH on purpose)."""
    caps = capability if capability is not None else ["SNMP", "YANG_CLI"]
    return {
        **PE1,
        "connectivity_info": transports,
        "product_info": {"device_type": "NODE_TYPE_ROUTER", "capability": caps},
    }


def query_response(node: dict) -> httpx.Response:
    return httpx.Response(200, json={"data": [node], "total_count": 5, "result_count": 1})


ADMIN_DOWN_BODY = {"data": [{"uuid": PE1_UUID, "admin_state": "ROBOT_ADMIN_STATE_DOWN"}]}
ADMIN_UP_BODY = {"data": [{"uuid": PE1_UUID, "admin_state": "ROBOT_ADMIN_STATE_UP"}]}
ADD_GNMI_BODY = {
    "data": [
        {
            "uuid": PE1_UUID,
            "connectivity_info": [SNMP_T, SSH_T, GNMI_NEW],
            "product_info": {"capability": ["GNMI", "SNMP", "YANG_CLI"]},
        }
    ]
}


@respx.mock
async def test_enable_gnmi_happy_path_three_patches_then_polls(make_settings, fake_clock):
    query = respx.post(NODES_QUERY).mock(
        side_effect=[
            query_response(pe1_with([SNMP_T, SSH_T])),  # the pre-change read
            query_response(pe1_with([SNMP_T, SSH_T, GNMI_UNKNOWN_T], ["GNMI", "SNMP", "YANG_CLI"])),
            query_response(
                pe1_with([SNMP_T, SSH_T, GNMI_REACHABLE_T], ["GNMI", "SNMP", "YANG_CLI"])
            ),
        ]
    )
    patch = respx.patch(NODES).mock(return_value=httpx.Response(200, json=JOB_WARN))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_enable_device_gnmi",
        {"uuid": PE1_UUID, "wait_seconds": 90},
    )
    # The three PATCH bodies, in order: admin-down, transports verbatim + gNMI, admin-up.
    assert patch.call_count == 3
    assert sent_body(patch, 0) == ADMIN_DOWN_BODY
    assert sent_body(patch, 1) == ADD_GNMI_BODY
    assert sent_body(patch, 2) == ADMIN_UP_BODY
    gnmi_sent = sent_body(patch, 1)["data"][0]["connectivity_info"][2]
    assert gnmi_sent["encoding_type"] == "JSON_IETF" and gnmi_sent["timeout"] == "30"
    assert gnmi_sent["ipaddrs"] == SSH_T["ipaddrs"]
    # Polling: one read before, two after (UNKNOWN -> REACHABLE at t=10s).
    assert query.call_count == 3
    assert all(sent_body(query, i)["filter"] == {"uuid": PE1_UUID} for i in range(3))
    # The settles of the verified run (5s after admin-down, 3s after the transport PATCH)
    # precede the single 10s poll interval; nothing else sleeps.
    assert fake_clock.sleeps == [5, 3, 10]
    assert not text.startswith("Error:")
    assert text.startswith(
        f"Enabled gNMI on device PE1 ({PE1_UUID}): ROBOT_MSVC_TRANS_GNMI port 57400, "
        "encoding JSON_IETF plus the GNMI capability. The gNMI transport is reachable "
        "after 10s."
    )
    assert (
        "Steps: admin_down JOB_COMPLETED_WITH_WARNING, add_gnmi JOB_COMPLETED_WITH_WARNING, "
        "admin_up JOB_COMPLETED_WITH_WARNING." in text
    )
    assert "gnmi 198.18.140.11:57400 reach=reachable encoding=JSON_IETF" in text
    envelope = json.loads(text[text.index("{") :])
    assert envelope["changed"] is True and envelope["reachable"] is True
    assert envelope["waited_seconds"] == 10
    assert envelope["admin_state_before"] == "ROBOT_ADMIN_STATE_UP"
    assert envelope["admin_state_after"] == "ROBOT_ADMIN_STATE_UP"
    assert envelope["added"] == {"transport": True, "capability": True}
    assert envelope["gnmi"]["reachability_state"] == "CONN_STATE_REACHABLE"
    assert envelope["capability"] == ["GNMI", "SNMP", "YANG_CLI"]
    assert [t["type"] for t in envelope["connectivity_info"]] == [
        "ROBOT_MSVC_TRANS_SNMP",
        "ROBOT_MSVC_TRANS_SSH",
        "ROBOT_MSVC_TRANS_GNMI",
    ]
    for step in ("admin_down", "add_gnmi", "admin_up"):
        assert envelope["steps"][step] == {
            "ok": True,
            "job_id": "j-7",
            "state": "JOB_COMPLETED_WITH_WARNING",
            "warning": NSO_ADVISORY,
        }


@respx.mock
async def test_enable_gnmi_secure_port_and_encoding_options(make_settings, fake_clock):
    respx.post(NODES_QUERY).mock(
        side_effect=[
            query_response(pe1_with([SSH_T])),
            query_response(pe1_with([SSH_T, {**GNMI_REACHABLE_T, "type": "X"}])),
        ]
    )
    patch = respx.patch(NODES).mock(return_value=httpx.Response(200, json=JOB_WARN))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_enable_device_gnmi",
        {"uuid": PE1_UUID, "port": 9339, "encoding": "proto", "secure": True, "wait_seconds": 0},
    )
    assert sent_body(patch, 1)["data"][0]["connectivity_info"] == [
        SSH_T,
        {
            "type": "ROBOT_MSVC_TRANS_GNMI_SECURE",
            "ipaddrs": SSH_T["ipaddrs"],
            "port": 9339,
            "timeout": "30",
            "encoding_type": "PROTO",
        },
    ]
    assert not text.startswith("Error:")
    assert "ROBOT_MSVC_TRANS_GNMI_SECURE port 9339, encoding PROTO" in text


@respx.mock
async def test_enable_gnmi_transport_not_visible_yet_is_not_an_error(make_settings, fake_clock):
    """The verification read shows no gNMI entry at all (the platform has not surfaced it
    yet): reported as a non-error with gnmi null, not as 'not reachable'."""
    respx.post(NODES_QUERY).mock(
        side_effect=[
            query_response(pe1_with([SSH_T])),
            query_response(pe1_with([SSH_T])),  # read back unchanged
        ]
    )
    patch = respx.patch(NODES).mock(return_value=httpx.Response(200, json=JOB_WARN))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_enable_device_gnmi",
        {"uuid": PE1_UUID, "wait_seconds": 0},
    )
    assert patch.call_count == 3
    assert not text.startswith("Error:")
    assert (
        "The gNMI transport is not visible on the device yet after 0s (not an error): "
        "re-read with cnc_get_device." in text
    )
    assert "Not reachable yet" not in text
    envelope = json.loads(text[text.index("{") :])
    assert envelope["changed"] is True and envelope["reachable"] is False
    assert envelope["gnmi"] is None
    assert [t["type"] for t in envelope["connectivity_info"]] == ["ROBOT_MSVC_TRANS_SSH"]


@respx.mock
async def test_enable_gnmi_timeout_is_not_an_error(make_settings, fake_clock):
    """wait_seconds elapses with the transport still UNKNOWN -> a non-error status report."""
    after = pe1_with([SNMP_T, SSH_T, {**GNMI_UNKNOWN_T, "error": "connection refused"}])
    query = respx.post(NODES_QUERY).mock(
        side_effect=[query_response(pe1_with([SNMP_T, SSH_T]))] + [query_response(after)] * 5
    )
    respx.patch(NODES).mock(return_value=httpx.Response(200, json=JOB_WARN))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_enable_device_gnmi",
        {"uuid": PE1_UUID, "wait_seconds": 20},
    )
    assert query.call_count == 4  # pre-read + polls at t=0, 10, 20 (20s budget, 10s interval)
    assert not text.startswith("Error:")
    assert "Not reachable yet after 20s; current state CONN_STATE_UNKNOWN" in text
    assert "(error: connection refused)" in text
    envelope = json.loads(text[text.index("{") :])
    assert envelope["changed"] is True and envelope["reachable"] is False
    assert envelope["gnmi"]["error"] == "connection refused"


@respx.mock
async def test_enable_gnmi_wait_zero_reads_once_without_sleeping(make_settings, fake_clock):
    query = respx.post(NODES_QUERY).mock(
        side_effect=[
            query_response(pe1_with([SSH_T])),
            query_response(pe1_with([SSH_T, GNMI_UNKNOWN_T], ["GNMI", "SNMP", "YANG_CLI"])),
        ]
    )
    respx.patch(NODES).mock(return_value=httpx.Response(200, json=JOB_WARN))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_enable_device_gnmi",
        {"uuid": PE1_UUID, "wait_seconds": 0},
    )
    assert query.call_count == 2
    assert fake_clock.sleeps == [5, 3]  # only the two settles: no poll sleep
    assert not text.startswith("Error:")
    assert "Not reachable yet after 0s; current state CONN_STATE_UNKNOWN" in text


@respx.mock
async def test_enable_gnmi_already_present_short_circuits_without_patch(make_settings):
    query = respx.post(NODES_QUERY).mock(
        return_value=query_response(
            pe1_with([SNMP_T, SSH_T, GNMI_REACHABLE_T], ["GNMI", "SNMP", "YANG_CLI"])
        )
    )
    patch = respx.patch(NODES).mock(return_value=httpx.Response(200, json=JOB_WARN))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_enable_device_gnmi", {"uuid": PE1_UUID}
    )
    assert not patch.called
    assert query.call_count == 1
    assert not text.startswith("Error:")
    assert text.startswith(
        f"Device PE1 ({PE1_UUID}) already has gNMI (gnmi 198.18.140.11:57400 reach=reachable "
        "encoding=JSON_IETF) and the GNMI capability; nothing changed."
    )
    envelope = json.loads(text[text.index("{") :])
    assert envelope["changed"] is False and envelope["reachable"] is True
    assert envelope["gnmi"]["type"] == "ROBOT_MSVC_TRANS_GNMI"
    # The short-circuit envelope shows the state that made it a no-op.
    assert envelope["capability"] == ["GNMI", "SNMP", "YANG_CLI"]
    assert envelope["admin_state"] == "ROBOT_ADMIN_STATE_UP"


@respx.mock
async def test_enable_gnmi_secure_variant_also_counts_as_present(make_settings):
    secure = {**GNMI_REACHABLE_T, "type": "ROBOT_MSVC_TRANS_GNMI_SECURE"}
    respx.post(NODES_QUERY).mock(
        return_value=query_response(pe1_with([SSH_T, secure], ["GNMI", "SNMP", "YANG_CLI"]))
    )
    patch = respx.patch(NODES).mock(return_value=httpx.Response(200, json=JOB_WARN))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_enable_device_gnmi", {"uuid": PE1_UUID}
    )
    assert not patch.called
    # Rendered with a friendly name like every other transport, not the raw wire value.
    assert "already has gNMI (gnmi_secure 198.18.140.11:57400 reach=reachable" in text
    envelope = json.loads(text[text.index("{") :])
    assert envelope["gnmi"]["type"] == "ROBOT_MSVC_TRANS_GNMI_SECURE"  # JSON keeps the wire value


@respx.mock
async def test_enable_gnmi_adds_missing_capability_when_transport_present(
    make_settings, fake_clock
):
    """Transport present but product_info.capability lacks GNMI (they are independent in
    the UI): the same admin-down -> PATCH -> admin-up sequence runs, re-sending the
    transport list verbatim (no new entry, port/encoding ignored) with GNMI added to the
    capability list."""
    query = respx.post(NODES_QUERY).mock(
        side_effect=[
            query_response(pe1_with([SNMP_T, SSH_T, GNMI_REACHABLE_T], ["SNMP", "YANG_CLI"])),
            query_response(
                pe1_with([SNMP_T, SSH_T, GNMI_REACHABLE_T], ["GNMI", "SNMP", "YANG_CLI"])
            ),
        ]
    )
    patch = respx.patch(NODES).mock(return_value=httpx.Response(200, json=JOB_WARN))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_enable_device_gnmi",
        {"uuid": PE1_UUID, "port": 9339, "encoding": "PROTO", "wait_seconds": 0},
    )
    assert patch.call_count == 3
    assert sent_body(patch, 0) == ADMIN_DOWN_BODY
    assert sent_body(patch, 1) == {
        "data": [
            {
                "uuid": PE1_UUID,
                "connectivity_info": [SNMP_T, SSH_T, GNMI_REACHABLE_T],  # verbatim, no new entry
                "product_info": {"capability": ["GNMI", "SNMP", "YANG_CLI"]},
            }
        ]
    }
    assert sent_body(patch, 2) == ADMIN_UP_BODY
    assert query.call_count == 2
    assert not text.startswith("Error:")
    assert text.startswith(
        f"Enabled gNMI on device PE1 ({PE1_UUID}): the existing gnmi 198.18.140.11:57400 "
        "reach=reachable encoding=JSON_IETF transport was kept and the missing GNMI "
        "capability was added. The gNMI transport is reachable after 0s."
    )
    assert "already has gNMI" not in text
    envelope = json.loads(text[text.index("{") :])
    assert envelope["changed"] is True
    assert envelope["added"] == {"transport": False, "capability": True}
    assert envelope["capability"] == ["GNMI", "SNMP", "YANG_CLI"]
    assert set(envelope["steps"]) == {"admin_down", "add_gnmi", "admin_up"}


@respx.mock
async def test_enable_gnmi_admin_down_device_sends_only_the_transport_patch(
    make_settings, fake_clock
):
    """A device read admin-DOWN is not bounced: the capability refusal only applies to
    admin-up nodes, and the operator's admin state must survive the call."""
    down = {**pe1_with([SNMP_T, SSH_T]), "admin_state": "ROBOT_ADMIN_STATE_DOWN"}
    after = {
        **pe1_with([SNMP_T, SSH_T, GNMI_UNKNOWN_T], ["GNMI", "SNMP", "YANG_CLI"]),
        "admin_state": "ROBOT_ADMIN_STATE_DOWN",
    }
    query = respx.post(NODES_QUERY).mock(side_effect=[query_response(down), query_response(after)])
    patch = respx.patch(NODES).mock(return_value=httpx.Response(200, json=JOB_WARN))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_enable_device_gnmi",
        {"uuid": PE1_UUID, "wait_seconds": 90},
    )
    # Exactly one PATCH — the transport/capability one — and no admin-state PATCH at all.
    assert patch.call_count == 1
    assert sent_body(patch, 0) == ADD_GNMI_BODY
    assert "admin_state" not in sent_body(patch, 0)["data"][0]
    # No settles (nothing to settle after) and no polling: an admin-down device is not
    # collected, so wait_seconds=90 collapses to a single verification read.
    assert fake_clock.sleeps == []
    assert query.call_count == 2
    assert not text.startswith("Error:")
    assert "was admin-down before the call and was left admin-down" in text
    assert "no admin-state PATCH was sent" in text
    assert "current state CONN_STATE_UNKNOWN" in text
    assert "cnc_update_device" in text
    assert "Steps: add_gnmi JOB_COMPLETED_WITH_WARNING." in text
    envelope = json.loads(text[text.index("{") :])
    assert envelope["changed"] is True and envelope["reachable"] is False
    assert envelope["admin_state_before"] == "ROBOT_ADMIN_STATE_DOWN"
    assert envelope["admin_state_after"] == "ROBOT_ADMIN_STATE_DOWN"
    assert list(envelope["steps"]) == ["add_gnmi"]
    assert envelope["waited_seconds"] == 0


@respx.mock
async def test_enable_gnmi_admin_down_device_add_failure_names_the_untouched_state(
    make_settings, fake_clock
):
    down = {**pe1_with([SSH_T]), "admin_state": "ROBOT_ADMIN_STATE_DOWN"}
    respx.post(NODES_QUERY).mock(return_value=query_response(down))
    patch = respx.patch(NODES).mock(return_value=httpx.Response(200, json=JOB_ENCODING_REQUIRED))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_enable_device_gnmi", {"uuid": PE1_UUID}
    )
    assert patch.call_count == 1  # no admin-up "restore" for a device that was never bounced
    assert text.startswith("Error:")
    assert "Encoding Type is required" in text
    assert "was admin-down before the call and no admin-state PATCH was sent" in text
    assert "admin-up again" not in text


@respx.mock
@pytest.mark.parametrize("admin_state", ["ROBOT_ADMIN_STATE_UNMANAGED", None, "WEIRD"])
async def test_enable_gnmi_refuses_non_up_down_devices_before_writing(make_settings, admin_state):
    """An UNMANAGED (deliberately hidden) or unknown-state device is refused: bouncing it
    would leave it admin-UP, an unrequested state change."""
    node_read = {**pe1_with([SSH_T]), "admin_state": admin_state}
    if admin_state is None:
        del node_read["admin_state"]
    respx.post(NODES_QUERY).mock(return_value=query_response(node_read))
    patch = respx.patch(NODES).mock(return_value=httpx.Response(200, json=JOB_WARN))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_enable_device_gnmi", {"uuid": PE1_UUID}
    )
    assert not patch.called
    assert text.startswith("Error:")
    assert f"is admin_state {admin_state!r}" in text
    assert "only runs on an admin-up or admin-down device" in text
    assert "cnc_update_device admin_state='up'" in text
    assert "Nothing was changed" in text


@respx.mock
async def test_enable_gnmi_add_step_failure_still_sends_admin_up(make_settings, fake_clock):
    """Step 3 JOB_FAILED -> Error with the platform text verbatim, AND admin-up still sent."""
    query = respx.post(NODES_QUERY).mock(return_value=query_response(pe1_with([SNMP_T, SSH_T])))
    patch = respx.patch(NODES).mock(
        side_effect=[
            httpx.Response(200, json=JOB_WARN),
            httpx.Response(200, json=JOB_ENCODING_REQUIRED),
            httpx.Response(200, json=JOB_WARN),
        ]
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_enable_device_gnmi", {"uuid": PE1_UUID}
    )
    assert patch.call_count == 3
    assert sent_body(patch, 0) == ADMIN_DOWN_BODY
    assert sent_body(patch, 1) == ADD_GNMI_BODY
    assert sent_body(patch, 2) == ADMIN_UP_BODY
    assert query.call_count == 1  # no polling after a failed change
    assert text.startswith("Error:")
    assert "Encoding Type is required for adding a GNMI protocol. Hostname: PE1." in text
    assert "j-8" in text and "JOB_FAILED" in text
    assert "The device was set admin-up again" in text
    assert "admin_up JOB_COMPLETED_WITH_WARNING" in text


@respx.mock
async def test_enable_gnmi_capability_refusal_is_surfaced_verbatim(make_settings, fake_clock):
    respx.post(NODES_QUERY).mock(return_value=query_response(pe1_with([SSH_T])))
    patch = respx.patch(NODES).mock(
        side_effect=[
            httpx.Response(200, json=JOB_WARN),
            httpx.Response(200, json=JOB_CAPABILITY_REFUSED),
            httpx.Response(200, json=JOB_WARN),
        ]
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_enable_device_gnmi", {"uuid": PE1_UUID}
    )
    assert patch.call_count == 3
    assert text.startswith("Error:")
    assert "Capability cannot be changed while the node is attached to a VDG" in text


@respx.mock
async def test_enable_gnmi_add_and_admin_up_both_failing_says_device_is_down(
    make_settings, fake_clock
):
    respx.post(NODES_QUERY).mock(return_value=query_response(pe1_with([SSH_T])))
    patch = respx.patch(NODES).mock(
        side_effect=[
            httpx.Response(200, json=JOB_WARN),
            httpx.Response(200, json=JOB_ENCODING_REQUIRED),
            httpx.Response(200, json=JOB_FAILED),
        ]
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_enable_device_gnmi", {"uuid": PE1_UUID}
    )
    assert patch.call_count == 3
    assert text.startswith("Error:")
    assert "Encoding Type is required" in text
    assert "ALSO failed, so the device is now admin-down" in text
    assert "cnc_update_device with admin_state='up'" in text


@respx.mock
async def test_enable_gnmi_admin_up_failure_after_success_is_error(make_settings, fake_clock):
    query = respx.post(NODES_QUERY).mock(return_value=query_response(pe1_with([SSH_T])))
    patch = respx.patch(NODES).mock(
        side_effect=[
            httpx.Response(200, json=JOB_WARN),
            httpx.Response(200, json=JOB_WARN),
            httpx.Response(200, json=JOB_FAILED),
        ]
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_enable_device_gnmi", {"uuid": PE1_UUID}
    )
    assert patch.call_count == 3 and query.call_count == 1
    assert text.startswith("Error:")
    assert "gNMI was added" in text and "admin-up PATCH failed" in text
    assert "Software Type" in text  # the admin-up job's own reason
    assert "cnc_update_device with admin_state='up'" in text


@respx.mock
async def test_enable_gnmi_admin_down_failure_sends_nothing_else(make_settings, fake_clock):
    query = respx.post(NODES_QUERY).mock(return_value=query_response(pe1_with([SNMP_T, SSH_T])))
    patch = respx.patch(NODES).mock(return_value=httpx.Response(200, json=JOB_FAILED))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_enable_device_gnmi", {"uuid": PE1_UUID}
    )
    assert patch.call_count == 1
    assert sent_body(patch) == ADMIN_DOWN_BODY
    assert query.call_count == 1
    assert fake_clock.sleeps == []  # no settle after a refused admin-down
    assert text.startswith("Error:")
    assert "admin-down (gNMI step 1 of 3) failed" in text and "Software Type" in text
    # JOB_FAILED is an explicit rejection: the device's state is known to be unchanged.
    assert "the device is still admin-up and unchanged" in text
    assert "may already have been applied" not in text


@respx.mock
async def test_enable_gnmi_admin_down_503_names_the_step_and_possible_partial_apply(
    make_settings, fake_clock
):
    """An HTTP-level failure on the admin-down PATCH (retries exhausted) is not a
    rejection: the platform may have processed it, so the error names the step and tells
    the agent how to check and undo."""
    query = respx.post(NODES_QUERY).mock(return_value=query_response(pe1_with([SNMP_T, SSH_T])))
    patch = respx.patch(NODES).mock(return_value=httpx.Response(503, text="Service Unavailable"))
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=0)),
        "cnc_enable_device_gnmi",
        {"uuid": PE1_UUID},
    )
    assert patch.call_count == 1 and query.call_count == 1
    assert sent_body(patch) == ADMIN_DOWN_BODY
    assert text.startswith("Error:")
    assert f"Setting device PE1 ({PE1_UUID}) admin-down (gNMI step 1 of 3) failed:" in text
    assert "status 503" in text
    assert "Nothing else was sent, but the admin-down may already have been applied" in text
    assert "cnc_get_device" in text
    assert "cnc_update_device with admin_state='up' if it reads admin-down" in text


@respx.mock
async def test_enable_gnmi_admin_down_timeout_names_the_step_and_possible_partial_apply(
    make_settings, fake_clock
):
    query = respx.post(NODES_QUERY).mock(return_value=query_response(pe1_with([SNMP_T, SSH_T])))
    patch = respx.patch(NODES).mock(side_effect=httpx.ReadTimeout("read timed out"))
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=0)),
        "cnc_enable_device_gnmi",
        {"uuid": PE1_UUID},
    )
    assert patch.call_count == 1 and query.call_count == 1
    assert text.startswith("Error:")
    assert "admin-down (gNMI step 1 of 3) failed:" in text
    assert "Could not reach the platform (ReadTimeout)" in text
    assert "the admin-down may already have been applied" in text
    assert "cnc_update_device with admin_state='up' if it reads admin-down" in text


@respx.mock
async def test_enable_gnmi_add_step_unanswered_says_it_may_have_applied(make_settings, fake_clock):
    """A 503 (no retries) on the transport PATCH: admin-up is still sent, and the error
    does not claim 'nothing else changed' because the change may have been applied."""
    respx.post(NODES_QUERY).mock(return_value=query_response(pe1_with([SNMP_T, SSH_T])))
    patch = respx.patch(NODES).mock(
        side_effect=[
            httpx.Response(200, json=JOB_WARN),
            httpx.Response(503, text="Service Unavailable"),
            httpx.Response(200, json=JOB_WARN),
        ]
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=0)),
        "cnc_enable_device_gnmi",
        {"uuid": PE1_UUID},
    )
    assert patch.call_count == 3
    assert sent_body(patch, 2) == ADMIN_UP_BODY
    assert text.startswith("Error:")
    assert "Adding gNMI to device PE1" in text and "status 503" in text
    assert "may or may not have been applied: check with cnc_get_device" in text
    assert "The device was set admin-up again." in text
    assert "nothing else changed" not in text


@respx.mock
async def test_enable_gnmi_admin_up_is_retried_on_gateway_503(make_settings, fake_clock):
    """The admin-up PATCH carries absolute state, so a 503 is retried rather than leaving
    the device admin-down."""
    respx.post(NODES_QUERY).mock(
        side_effect=[
            query_response(pe1_with([SSH_T])),
            query_response(pe1_with([SSH_T, GNMI_REACHABLE_T], ["GNMI", "SNMP", "YANG_CLI"])),
        ]
    )
    patch = respx.patch(NODES).mock(
        side_effect=[
            httpx.Response(200, json=JOB_WARN),
            httpx.Response(200, json=JOB_WARN),
            httpx.Response(503, text="Service Unavailable"),
            httpx.Response(200, json=JOB_WARN),
        ]
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=2)),
        "cnc_enable_device_gnmi",
        {"uuid": PE1_UUID, "wait_seconds": 0},
    )
    assert patch.call_count == 4
    assert sent_body(patch, 2) == ADMIN_UP_BODY and sent_body(patch, 3) == ADMIN_UP_BODY
    assert not text.startswith("Error:")
    assert "The gNMI transport is reachable after 0s." in text


@respx.mock
async def test_enable_gnmi_bad_encoding_refused_before_any_call(make_settings):
    query = respx.post(NODES_QUERY).mock(return_value=query_response(pe1_with([SSH_T])))
    patch = respx.patch(NODES).mock(return_value=httpx.Response(200, json=JOB_WARN))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_enable_device_gnmi",
        {"uuid": PE1_UUID, "encoding": "protobuf"},
    )
    assert text.startswith("Error:") and "Unknown gNMI encoding 'protobuf'" in text
    assert "JSON_IETF" in text and "UNKNOWN_ENCODING_TYPE" in text
    assert not query.called and not patch.called


@respx.mock
async def test_enable_gnmi_schema_bounds_port_and_wait(make_settings):
    patch = respx.patch(NODES).mock(return_value=httpx.Response(200, json=JOB_WARN))
    mcp = build(make_settings(enable_writes=True))
    with pytest.raises(ToolError, match="port"):
        await mcp.call_tool("cnc_enable_device_gnmi", {"uuid": PE1_UUID, "port": 0})
    with pytest.raises(ToolError, match="wait_seconds"):
        await mcp.call_tool("cnc_enable_device_gnmi", {"uuid": PE1_UUID, "wait_seconds": -1})
    assert not patch.called


@respx.mock
async def test_enable_gnmi_without_ip_transport_refuses_before_writing(make_settings):
    fqdn_only = {
        "type": "ROBOT_MSVC_TRANS_SSH",
        "port": 22,
        "fqdn": {"host_name": "pe1", "domain_name": "lab.example"},
    }
    respx.post(NODES_QUERY).mock(return_value=query_response(pe1_with([fqdn_only])))
    patch = respx.patch(NODES).mock(return_value=httpx.Response(200, json=JOB_WARN))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_enable_device_gnmi", {"uuid": PE1_UUID}
    )
    assert text.startswith("Error:") and "no transport with an IP address" in text
    assert not patch.called


@respx.mock
async def test_enable_gnmi_copies_first_entrys_ipaddrs_when_no_ssh(make_settings, fake_clock):
    netconf = {**SNMP_T, "type": "ROBOT_MSVC_TRANS_NETCONF", "port": 830}
    respx.post(NODES_QUERY).mock(
        side_effect=[
            query_response(pe1_with([netconf, SNMP_T], ["SNMP"])),
            query_response(pe1_with([netconf, SNMP_T, GNMI_REACHABLE_T], ["GNMI", "SNMP"])),
        ]
    )
    patch = respx.patch(NODES).mock(return_value=httpx.Response(200, json=JOB_WARN))
    await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_enable_device_gnmi",
        {"uuid": PE1_UUID, "wait_seconds": 0},
    )
    body = sent_body(patch, 1)["data"][0]
    assert body["connectivity_info"] == [netconf, SNMP_T, GNMI_NEW]
    assert body["product_info"] == {"capability": ["GNMI", "SNMP"]}


@respx.mock
async def test_enable_gnmi_unknown_device_is_error_without_patch(make_settings):
    respx.post(NODES_QUERY).mock(return_value=httpx.Response(200, json={"total_count": 5}))
    patch = respx.patch(NODES).mock(return_value=httpx.Response(200, json=JOB_WARN))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_enable_device_gnmi", {"uuid": "nope"}
    )
    assert text.startswith("Error:") and "not found" in text
    assert not patch.called


@respx.mock
async def test_enable_gnmi_verification_read_failure_reports_the_successful_writes(
    make_settings, fake_clock
):
    respx.post(NODES_QUERY).mock(
        side_effect=[query_response(pe1_with([SSH_T])), NATS_500, NATS_500, NATS_500]
    )
    patch = respx.patch(NODES).mock(return_value=httpx.Response(200, json=JOB_WARN))
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=0)),
        "cnc_enable_device_gnmi",
        {"uuid": PE1_UUID, "wait_seconds": 0},
    )
    assert patch.call_count == 3
    assert text.startswith("Error:")
    assert "gNMI was added" in text and "admin-up again" in text
    assert "verification read failed" in text and "500" in text


# --- cnc_delete_device -----------------------------------------------------------


@respx.mock
async def test_delete_device_sends_json_body(make_settings):
    job = {**JOB_OK, "type": "1 device(s) deleted successfully"}
    route = respx.delete(NODES).mock(return_value=httpx.Response(200, json=job))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_delete_device", {"uuid": PE1_UUID}
    )
    assert sent_body(route) == {"data": [{"uuid": PE1_UUID}]}
    assert json.loads(text)["type"] == "1 device(s) deleted successfully"


@respx.mock
async def test_delete_device_nats_500_is_error(make_settings):
    respx.delete(NODES).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=0)),
        "cnc_delete_device",
        {"uuid": PE1_UUID},
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_wait_for_device_reachable ----------------------------------------------------


@respx.mock
async def test_wait_for_device_reachable_polls_until_reachable(settings, fake_clock):
    checking = {**P1, "operational_state": "ROBOT_OPER_STATE_CHECKING"}
    reachable = {**P1, "reachability_state": "CONN_STATE_REACHABLE"}
    route = respx.post(NODES_QUERY).mock(
        side_effect=[
            httpx.Response(200, json={"data": [checking], "total_count": 1}),
            httpx.Response(200, json={"data": [reachable], "total_count": 1}),
        ]
    )
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_device_reachable",
        {"uuid": P1_UUID, "timeout_seconds": 60, "interval_seconds": 5},
    )
    assert route.call_count == 2
    assert sent_body(route)["filter"] == {"uuid": P1_UUID}
    assert text.startswith(f"Device P1 ({P1_UUID}) is reachable after 5s.")
    assert '"reachability_state": "CONN_STATE_REACHABLE"' in text


@respx.mock
async def test_wait_for_device_reachable_timeout_is_not_an_error(settings, fake_clock):
    checking = {**P1, "operational_state": "ROBOT_OPER_STATE_CHECKING"}
    respx.post(NODES_QUERY).mock(
        return_value=httpx.Response(200, json={"data": [checking], "total_count": 1})
    )
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_device_reachable",
        {"host_name": "P1", "timeout_seconds": 10, "interval_seconds": 10},
    )
    assert not text.startswith("Error:")
    assert text.startswith(
        "Not reachable yet after 10s; current reachability_state=CONN_STATE_UNKNOWN, "
        "operational_state=ROBOT_OPER_STATE_CHECKING."
    )


@respx.mock
async def test_wait_for_device_reachable_missing_device_is_error(settings, fake_clock):
    respx.post(NODES_QUERY).mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(
        build(settings), "cnc_wait_for_device_reachable", {"host_name": "ghost"}
    )
    assert text.startswith("Error:") and "not found" in text


@respx.mock
async def test_wait_for_device_reachable_survives_a_gateway_503(make_settings, fake_clock):
    """find_device's nodes/query POST is retried, so one 503 does not abort the wait."""
    reachable = {**P1, "reachability_state": "CONN_STATE_REACHABLE"}
    route = respx.post(NODES_QUERY).mock(
        side_effect=[
            httpx.Response(503, text="Service Unavailable"),
            httpx.Response(200, json={"data": [reachable], "total_count": 1}),
        ]
    )
    text = await call_tool_text(
        build(make_settings(max_retries=2)),
        "cnc_wait_for_device_reachable",
        {"uuid": P1_UUID, "timeout_seconds": 60, "interval_seconds": 5},
    )
    assert route.call_count == 2
    assert text.startswith(f"Device P1 ({P1_UUID}) is reachable after 0s.")


@respx.mock
async def test_wait_for_device_reachable_api_failure_is_error(make_settings, fake_clock):
    respx.post(NODES_QUERY).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)),
        "cnc_wait_for_device_reachable",
        {"uuid": P1_UUID},
    )
    assert text.startswith("Error:") and "500" in text
