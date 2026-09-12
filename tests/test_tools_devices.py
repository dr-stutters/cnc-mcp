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


# --- registration / gating ---------------------------------------------------


async def test_write_tools_hidden_by_default(make_settings):
    names = {t.name for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert {
        "cnc_list_devices",
        "cnc_get_device",
        "cnc_get_device_collection_summary",
        "cnc_wait_for_device_reachable",
    } <= names
    assert not ({"cnc_create_device", "cnc_update_device", "cnc_delete_device"} & names)


async def test_write_tools_registered_and_annotated(make_settings):
    tools = {t.name: t for t in await build(make_settings(enable_writes=True)).list_tools()}
    assert tools["cnc_create_device"].annotations.read_only_hint is False
    assert tools["cnc_create_device"].annotations.destructive_hint is False
    assert tools["cnc_create_device"].annotations.idempotent_hint is False
    assert tools["cnc_update_device"].annotations.read_only_hint is False
    assert tools["cnc_update_device"].annotations.idempotent_hint is True
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
