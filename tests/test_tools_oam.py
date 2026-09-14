"""OAM tools end-to-end through MCPServer (schema validation included).

The module is registered directly (not through build_server) so the test does
not depend on tools/__init__.py's module list. All HTTP is mocked with respx.
The "verified" fixtures are verbatim what Crosswork 7.2 answered live on
2026-09-13 / 2026-09-14 (platform notes, "OAM RPCs" and "Service Health probe
manager"): the delete interval, the registered / running / failed trace-route
answers (the gNMI text, the no-uuid 'mpls oam' text and XR's 'mpls-lspv'
text), the status-4 "No path found between the selected devices" verdict with
0 paths (seen for the SHORT input form — yang-path + uuids, names and
router-ids echoed empty — on a policy service; the full form ended in status
5 on the lab), the status-6 "Route not found" answer with every string empty,
the list's zero counts, and the probe manager's 500 "no active probe session"
document. The populated shapes (a completed trace with paths, a 200 probe
report, the reactivate answer) follow the 7.2 documents and are marked as
such; so do the extrapolations from the verified answers (a probe-manager 500
document carrying another ``error``, the set RPC answering a terminal status
directly, and a FULL-form query — the one cnc_start_oam_trace_route registers
— ending in the status-4 zero-path verdict: ``NO_PATH`` combines the short
form's verified verdict with the full form's verified echo, a sequence never
observed live).
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx
from mcp.server.mcpserver import MCPServer

from cnc_mcp import polling
from cnc_mcp.auth import StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.config import Settings
from cnc_mcp.errors import PlatformError
from cnc_mcp.restconf import EMPTY_500_EXPLANATION
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import oam
from cnc_mcp.tools.oam import (
    NO_PATH_FOUND_MESSAGE,
    OAM_EMPTY_500_HINT,
    OAM_MODULE,
    PROBE_STATUS_NAMES,
    PROBEMGR_NOT_ROUTED_HINT,
    REACTIVATE_STATUS_NAMES,
    TraceEnd,
    canonical_service_type,
    check_oam_output,
    completed_without_paths,
    destination_text,
    device_name_map,
    device_text,
    end_text,
    enum_name,
    enum_word,
    hop_lines,
    is_mpls_oam_target,
    oam_epoch_ms,
    oam_time,
    path_device_uuids,
    path_line,
    probe_reports,
    probe_verdict_500,
    service_identity,
    service_type_of_list,
    split_service_path,
    start_summary,
    start_trace_body,
    status_word,
    trace_end_of_node,
    trace_status,
    validate_device_uuid,
    verdict_delay_text,
)
from tests.conftest import BASE_URL, call_tool_text

YANG_JSON = "application/yang-data+json"
OPERATIONS = f"{BASE_URL}/crosswork/nbi/optimization/v3/restconf/operations"
PROBE_STATUS_URL = f"{BASE_URL}/crosswork/probemgr/v1/probeStatusReport"
REACTIVATE_URL = f"{BASE_URL}/crosswork/probemgr/v1/reactivateProbe"
NODES_QUERY_URL = f"{BASE_URL}/crosswork/inventory/v1/nodes/query"


def rpc(name: str) -> str:
    return f"{OPERATIONS}/{OAM_MODULE}:{name}"


def out(**fields: Any) -> dict:
    return {f"{OAM_MODULE}:output": fields}


# --- verified fixtures (verbatim from the wire, 2026-09-13) --------------------------

DELETE_INTERVAL_OUT = out(**{"delete-interval": 1, "response-result": "valid"})
# The list's answer while a query was running / had failed: zero everywhere, no rows.
LIST_EMPTY_OUT = out(
    **{
        "total-count": 0,
        "total-completed-query-count": 0,
        "total-running-query-count": 0,
        "total-failed-query-count": 0,
        "response-result": "valid",
    }
)
QUERY_ID = "SPQ-324616899"
POLICY_PATH = "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/policy=mcp-oam-91"
PE1_UUID = "3d95eb05-1a2b-4c3d-8e4f-5a6b7c8d9e0f"
PE2_UUID = "ce5c70f5-9f8e-4d7c-8b6a-5f4e3d2c1b0a"
CREATE_TIME = "1789324616899.0"  # 2026-09-13T18:36:56Z
GNMI_TEXT = (
    "Unable to trace the path and request got timed out. Check below and try again: - Devices "
    "are running IOS-XR 7.3.2 or later - GNMI is enabled on the devices. - GNMI port of device "
    "in crosswork is configured as per the device. - GNMI connectivity type specified in "
    "Crosswork for the devices"
)
MPLS_OAM_TEXT = (
    "Path cannot be traced until the device configuration is completed, please check the "
    "device for enabling 'mpls oam' configuration.(Could not register collection job. Response "
    'result: request_result: REJECTED error { error: "empty device id item in list" })'
)
# XR's own error when the full-form trace runs on a head-end without 'mpls oam' (2026-09-14).
XR_MPLS_OAM_TEXT = (
    "Path cannot be traced until the device configuration is completed, please check the "
    "device for enabling 'mpls oam' configuration.('mpls-lspv' detected the 'resource not "
    "available' condition 'Failed to send a LWM message to the server')"
)


def service_route(status: int, message: str, **overrides: Any) -> dict:
    """A ServiceRoute as the RPCs echo it for a uuid-keyed query (names / router-ids empty)."""
    route = {
        "query-id": QUERY_ID,
        "status": status,
        "status-message": message,
        "create-time": CREATE_TIME,
        "update-time": CREATE_TIME,
        "yang-path": POLICY_PATH,
        "service-name": "",
        "service-type": "",
        "head-end-node-uuid": PE1_UUID,
        "head-end-node-name": "",
        "head-end-te-router-id": "",
        "tail-end-node-uuid": PE2_UUID,
        "tail-end-node-name": "",
        "tail-end-te-router-id": "",
        "available-path-count": 0,
        "transport-type": 0,
        "response-result": "valid",
    }
    route.update(overrides)
    return route


# The full-form inputs as the engine echoes them (verified 2026-09-14).
FULL_ECHO = {
    "service-name": "mcp-oam-91",
    "service-type": "policy",
    "head-end-node-name": "PE1",
    "head-end-te-router-id": "10.0.0.1",
    "tail-end-node-name": "PE2",
    "tail-end-te-router-id": "10.0.0.3",
}

REGISTERED = service_route(3, "Path trace registered for calculation")
FULL_REGISTERED = service_route(3, "Path trace registered for calculation", **FULL_ECHO)
RUNNING = service_route(
    3, "Path trace running for calculation", **{"update-time": "1789324620000.0"}
)
FAILED = service_route(5, GNMI_TEXT, **{"update-time": "1789324647000.0"})
FAILED_NO_UUID = service_route(5, MPLS_OAM_TEXT)
FAILED_XR_MPLS_OAM = service_route(
    5, XR_MPLS_OAM_TEXT, **FULL_ECHO, **{"update-time": "1789324627000.0"}
)
# Verified (2026-09-14): status 4 with zero paths ~10 s after registration (completed, not
# failed) — the SHORT form's answer, so names / router-ids are echoed empty.
NO_PATH_SHORT = service_route(4, NO_PATH_FOUND_MESSAGE, **{"update-time": "1789324627000.0"})
# EXTRAPOLATED: the same verdict on a FULL-form query (the form cnc_start_oam_trace_route
# sends). Never observed live — the verified full-form traces ended in status 5 (XR's
# 'mpls oam' text); this combines the verified verdict with the verified full-form echo.
NO_PATH = {**NO_PATH_SHORT, **FULL_ECHO}
# get-oam-trace-route-by-query-id for an unknown id: HTTP 200, status 6, every string "".
NOT_FOUND = {
    "query-id": "",
    "status": 6,
    "status-message": "Route not found for selected ID",
    "create-time": "",
    "update-time": "",
    "yang-path": "",
    "service-name": "",
    "service-type": "",
    "head-end-node-uuid": "",
    "head-end-node-name": "",
    "head-end-te-router-id": "",
    "tail-end-node-uuid": "",
    "tail-end-node-name": "",
    "tail-end-te-router-id": "",
    "available-path-count": 0,
    "transport-type": 0,
    "response-result": "valid",
}
# The COE's empty 500 (the backend absent — or, on other COE RPCs, unresolved input).
EMPTY_500 = httpx.Response(500)
# The probe manager's answer for a service without probes (HTTP 500 + a JSON document).
L3VPN_ID = "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=mcp-l3vpn-91"
NO_SESSION_DOC = {
    "serviceId": L3VPN_ID,
    "enableReactivate": False,
    "status": "PROBE_STATUS_UNKNOWN",
    "endpointStatus": [],
    "sessionStatus": [],
    "error": "service has no active probe session",
}
NO_SESSION_500 = httpx.Response(500, json=NO_SESSION_DOC)
# Go's plain-text 404 (verified: probemgr's unknown paths and the absent Service Health app).
GO_404 = httpx.Response(404, text="404 page not found\n", headers={"Content-Type": "text/plain"})


# Inventory nodes as nodes/query returns them (the fields the trace-end lookup reads).
def inventory_node(device_uuid: str, host: str, te_router_id: str | None) -> dict:
    node: dict[str, Any] = {
        "uuid": device_uuid,
        "host_name": host,
        "routing_info": {"global_isis_system_id": "0000.0000.0001"},
    }
    if te_router_id is not None:
        node["routing_info"]["te_router_id"] = te_router_id
    return node


PE1_NODE = inventory_node(PE1_UUID, "PE1", "10.0.0.1")
PE2_NODE = inventory_node(PE2_UUID, "PE2", "10.0.0.3")
PE2_NO_ROUTER_ID = inventory_node(PE2_UUID, "PE2", None)
# The verified empty answer: no "data" key at all, only the collection total.
NO_NODES = {"total_count": 5}


def node_query_body(device_uuid: str) -> dict:
    """The verified nodes/query grammar (devices.py's query_body) for one uuid."""
    return {
        "filter": {"uuid": device_uuid},
        "filterData": {"PageSize": 1, "PageNum": 0, "Criteria": ""},
    }


def node_answer(*nodes: dict) -> httpx.Response:
    return httpx.Response(
        200, json={"data": list(nodes), "result_count": len(nodes), "total_count": 5}
    )


def mock_nodes(*nodes: dict) -> respx.Route:
    """nodes/query answering, per request, the given node whose uuid the filter names —
    or the verified empty document for any other uuid."""
    by_uuid = {n["uuid"]: n for n in nodes}

    def answer(request: httpx.Request) -> httpx.Response:
        wanted = json.loads(request.content)["filter"].get("uuid")
        node = by_uuid.get(wanted)
        return node_answer(node) if node else httpx.Response(200, json=NO_NODES)

    return respx.post(NODES_QUERY_URL).mock(side_effect=answer)


PE1_END = TraceEnd(PE1_UUID, "PE1", "10.0.0.1")
PE2_END = TraceEnd(PE2_UUID, "PE2", "10.0.0.3")
# The FULL set-oam-trace-route-by-calc input (verified 2026-09-14 — the only form that
# makes the engine run the LSP trace).
FULL_START_BODY = {
    "input": {
        "yang-path": POLICY_PATH,
        "head-end-node-uuid": PE1_UUID,
        "tail-end-node-uuid": PE2_UUID,
        "service-type": "policy",
        "service-name": "mcp-oam-91",
        "head-end-node-name": "PE1",
        "tail-end-node-name": "PE2",
        "head-end-te-router-id": "10.0.0.1",
        "tail-end-te-router-id": "10.0.0.3",
    }
}

# --- document-shaped fixtures (7.2 OpenAPI; unverified live) ------------------------

P1_UUID = "7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
COMPLETED = service_route(
    4,
    "Path trace completed",
    **{
        "head-end-node-name": "PE1",
        "head-end-te-router-id": "10.0.0.1",
        "tail-end-node-name": "PE2",
        "tail-end-te-router-id": "10.0.0.3",
        "service-name": "mcp-oam-91",
        "service-type": "policy",
        "available-path-count": 1,
        "update-time": "1789324647000.0",
        "path-info-list": [
            {
                "path": "1",
                "path-info": {
                    "source": "10.0.0.1",
                    "destination": "10.0.0.3",
                    "next-hop": "10.1.2.2",
                    "out-interface": "GigabitEthernet0/0/0/0",
                    "device-uuids": [PE1_UUID, P1_UUID, PE2_UUID],
                    "path-details": "16002 16003",
                    "path-status": "success",
                },
            }
        ],
    },
)
LIST_WITH_ROWS_OUT = out(
    **{
        "total-count": 2,
        "total-completed-query-count": 1,
        "total-running-query-count": 0,
        "total-failed-query-count": 1,
        "response-result": "valid",
        "service-routes": [FAILED, {**COMPLETED, "query-id": "SPQ-324700000"}],
    }
)
PROBE_REPORT = {
    "serviceId": L3VPN_ID,
    "enableReactivate": True,
    "status": 3,
    "endpointStatus": [
        {
            "id": "def",
            "vpnNeId": "PE2",
            "agentVLAN": 22,
            "agentIPAddr": "30.1.3.252",
            "interfaceName": "GigabitEthernet0/0/0/1",
            "status": 2,
        },
        {
            "id": "abc",
            "vpnNeId": "PE1",
            "interfaceName": "GigabitEthernet0/0/0/1",
            "status": 3,
            "error": "agent unreachable",
        },
    ],
    "sessionStatus": [
        {
            "id": "0f701fff-91ec-557e-9cf1-737c67125d3c",
            "sender": "def",
            "reflector": "abc",
            "status": 3,
            "error": "reflector down",
        }
    ],
}
PROBE_200 = {"data": [PROBE_REPORT]}
REACTIVATE_OK = {"data": [{"status": 1}]}
REACTIVATE_UNKNOWN = {"data": [{"status": 0}]}
REACTIVATE_ERROR = {"data": [{"status": "RESP_STATUS_ERROR", "error": "no probe to reactivate"}]}

# Failure idiom inside HTTP 200.
RESULT_ERROR = {"response-result": "error", "status-message": "internal OAM error"}
RESULT_INVALID = {"response-result": "invalid"}


# --- harness ----------------------------------------------------------------------


def build(settings: Settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    oam.register(mcp, ctx)
    return mcp


@pytest.fixture
def writes(make_settings) -> MCPServer:
    return build(make_settings(enable_writes=True))


@pytest.fixture
def reads(settings) -> MCPServer:
    return build(settings)


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


def ok(body: Any) -> httpx.Response:
    return httpx.Response(200, json=body)


NO_CONTENT = httpx.Response(204)


def sent(route: respx.Route, index: int = 0) -> dict:
    return json.loads(route.calls[index].request.content)


def assert_yang_post(route: respx.Route, index: int = 0) -> None:
    request = route.calls[index].request
    assert request.method == "POST"
    assert request.headers["Content-Type"] == YANG_JSON
    assert request.headers["Accept"] == YANG_JSON


def assert_bodiless_post(route: respx.Route, index: int = 0) -> None:
    request = route.calls[index].request
    assert request.method == "POST"
    assert request.content == b""
    assert request.headers["Accept"] == YANG_JSON
    assert "Content-Type" not in request.headers


def assert_json_post(route: respx.Route, body: dict, index: int = 0) -> None:
    request = route.calls[index].request
    assert request.method == "POST"
    assert request.headers["Content-Type"] == "application/json"
    assert json.loads(request.content) == body


def mock_trace_route(*responses: httpx.Response) -> respx.Route:
    """The by-query-id RPC answering the responses in order; the last repeats forever."""
    replies = list(responses)

    def answer(_request: httpx.Request) -> httpx.Response:
        return replies.pop(0) if len(replies) > 1 else replies[0]

    return respx.post(rpc("get-oam-trace-route-by-query-id")).mock(side_effect=answer)


P1_NODE = inventory_node(P1_UUID, "P1", "10.0.0.2")
# The unfiltered inventory list the path rendering reads once (5 lab devices).
INVENTORY_LIST = {"data": [PE1_NODE, P1_NODE, PE2_NODE], "result_count": 3, "total_count": 3}
UNFILTERED_LIST_BODY = {
    "filter": {},
    "filterData": {"PageSize": 200, "PageNum": 0, "Criteria": ""},
}


def mock_inventory(*responses: httpx.Response) -> respx.Route:
    """nodes/query answering the responses in order (the last repeats) — the unfiltered
    device list behind the per-path host names."""
    replies = list(responses) or [httpx.Response(200, json=INVENTORY_LIST)]

    def answer(_request: httpx.Request) -> httpx.Response:
        return replies.pop(0) if len(replies) > 1 else replies[0]

    return respx.post(NODES_QUERY_URL).mock(side_effect=answer)


READ_TOOLS = {
    "cnc_get_oam_settings",
    "cnc_list_oam_trace_routes",
    "cnc_get_oam_trace_route",
    "cnc_wait_for_oam_trace_route",
    "cnc_get_probe_status",
}
WRITE_TOOLS = {"cnc_start_oam_trace_route", "cnc_reactivate_probe"}
START_ARGS = {
    "service_yang_path": POLICY_PATH,
    "headend_uuid": PE1_UUID,
    "endpoint_uuid": PE2_UUID,
}


# --- registration / gating -----------------------------------------------------------


async def test_write_tools_hidden_unless_enabled(make_settings):
    names = {t.name for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert names == READ_TOOLS
    names = {t.name for t in await build(make_settings(enable_writes=True)).list_tools()}
    assert names == READ_TOOLS | WRITE_TOOLS


async def test_annotations_and_flat_schemas(writes):
    tools = {t.name: t for t in await writes.list_tools()}
    for name in READ_TOOLS:
        assert tools[name].annotations.read_only_hint is True, name
        assert tools[name].annotations.idempotent_hint is True, name
        assert tools[name].annotations.destructive_hint is False, name
    for name in WRITE_TOOLS:
        assert tools[name].annotations.read_only_hint is False, name
        assert tools[name].annotations.idempotent_hint is False, name
        assert tools[name].annotations.destructive_hint is False, name
    assert set(tools["cnc_get_oam_settings"].input_schema["properties"]) == {"response_format"}
    listing = tools["cnc_list_oam_trace_routes"].input_schema
    assert "required" not in listing
    assert listing["properties"]["start_row"]["default"] == 0
    assert listing["properties"]["end_row"]["default"] == 50
    assert set(tools["cnc_get_oam_trace_route"].input_schema["required"]) == {"query_id"}
    wait = tools["cnc_wait_for_oam_trace_route"].input_schema
    assert set(wait["required"]) == {"query_id"}
    assert wait["properties"]["timeout_seconds"]["default"] == 90
    assert wait["properties"]["interval_seconds"]["default"] == 5
    start = tools["cnc_start_oam_trace_route"].input_schema
    assert set(start["required"]) == {"service_yang_path", "headend_uuid", "endpoint_uuid"}
    assert start["properties"]["service_type"]["default"] == ""
    assert start["properties"]["service_name"]["default"] == ""
    for name in ("cnc_get_probe_status", "cnc_reactivate_probe"):
        assert "service_id" in tools[name].input_schema["required"], name
    # Every argument is a flat scalar (the only $ref is the ResponseFormat enum).
    for tool in tools.values():
        for arg, prop in tool.input_schema["properties"].items():
            ref = prop.get("$ref") or "".join(str(a.get("$ref", "")) for a in prop.get("anyOf", []))
            assert ref in ("", "#/$defs/ResponseFormat"), f"{tool.name}.{arg}"


# --- pure helpers -------------------------------------------------------------------


def test_oam_time_renders_epoch_ms_strings():
    assert oam_time(CREATE_TIME) == "2026-09-13T18:36:56Z"
    assert oam_time(1789324616899) == "2026-09-13T18:36:56Z"
    assert oam_time("") == "-"
    assert oam_time(None) == "-"
    assert oam_time("0") == "-"
    assert oam_time("not-a-time") == "not-a-time"


def test_oam_epoch_ms_parses_the_decimal_strings():
    assert oam_epoch_ms(CREATE_TIME) == 1789324616899
    assert oam_epoch_ms(1789324616899) == 1789324616899
    for blank in ("", None, "0", "0.0", "-5", "not-a-time", "1e400"):
        assert oam_epoch_ms(blank) is None, blank


def test_verdict_delay_text_is_update_minus_create():
    # NO_PATH_SHORT: created ...616899, updated ...627000 -> 10.1 s, rendered whole.
    assert verdict_delay_text(NO_PATH_SHORT) == "; the verdict arrived 10s after registration"
    assert verdict_delay_text(REGISTERED) == "; the verdict arrived 0s after registration"
    # Missing / unparseable / backwards times give nothing rather than a wrong number.
    assert verdict_delay_text({**NO_PATH_SHORT, "update-time": ""}) == ""
    assert verdict_delay_text({**NO_PATH_SHORT, "create-time": "x"}) == ""
    assert verdict_delay_text({**NO_PATH_SHORT, "update-time": "1789324600000.0"}) == ""
    assert verdict_delay_text(NOT_FOUND) == ""


def test_trace_status_and_status_word():
    assert trace_status(REGISTERED) == 3
    assert trace_status({"status": "5"}) == 5
    assert trace_status({"status": True}) is None
    assert trace_status({}) is None
    assert status_word(3) == "in progress (3)"
    assert status_word(4) == "completed (4)"
    assert status_word(5) == "failed (5)"
    assert status_word(6) == "not found (6)"
    assert status_word(7) == "status 7"
    assert status_word(None) == "status unknown"


def test_check_oam_output():
    assert check_oam_output(REGISTERED, "x") is REGISTERED
    assert check_oam_output({}, "x") == {}
    with pytest.raises(PlatformError) as excinfo:
        check_oam_output(RESULT_ERROR, "get-oam-delete-interval")
    assert str(excinfo.value) == (
        "get-oam-delete-interval failed: response-result error: internal OAM error"
    )
    with pytest.raises(PlatformError, match="response-result invalid: no message given"):
        check_oam_output(RESULT_INVALID, "x")
    # The trace-route's integer status is never mistaken for the status-"error" idiom.
    assert check_oam_output({"status": 5, "response-result": "valid"}, "x")["status"] == 5


def test_validate_device_uuid():
    assert validate_device_uuid(f" {PE1_UUID} ", "headend_uuid") == PE1_UUID
    with pytest.raises(PlatformError) as excinfo:
        validate_device_uuid("PE1", "headend_uuid")
    text = str(excinfo.value)
    assert text.startswith("headend_uuid 'PE1' is not an inventory uuid")
    assert "empty device id item in list" in text
    assert "cnc_get_device(host_name='PE1')" in text
    with pytest.raises(PlatformError, match="endpoint_uuid '10.0.0.3' is not an inventory uuid"):
        validate_device_uuid("10.0.0.3", "endpoint_uuid")
    # A uuid with a stray character is not "almost a uuid": refused, spelled as given.
    with pytest.raises(PlatformError, match=f"headend_uuid '{PE1_UUID}x' is not an inventory"):
        validate_device_uuid(f"{PE1_UUID}x", "headend_uuid")


NON_CANONICAL_UUIDS = [
    pytest.param(f"{{{PE1_UUID}}}", id="braces"),
    pytest.param(f"urn:uuid:{PE1_UUID}", id="urn-lower"),
    pytest.param(f"URN:UUID:{PE1_UUID.upper()}", id="urn-upper"),
    pytest.param(PE1_UUID.upper(), id="upper-hex"),
    pytest.param(PE1_UUID.replace("-", ""), id="32-hex"),
    pytest.param(PE1_UUID.replace("-", "").upper(), id="32-hex-upper"),
    pytest.param(f"  {{{PE1_UUID.upper()}}}  ", id="braces-upper-padded"),
]


@pytest.mark.parametrize("spelling", NON_CANONICAL_UUIDS)
def test_validate_device_uuid_canonicalises_every_spelling(spelling):
    assert validate_device_uuid(spelling, "headend_uuid") == PE1_UUID


def test_split_service_path():
    assert split_service_path(POLICY_PATH) == (
        "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/policy",
        "mcp-oam-91",
    )
    assert split_service_path("cisco-cs-sr-te-cfp:cs-sr-te-policy=cs1") == (
        "cisco-cs-sr-te-cfp:cs-sr-te-policy",
        "cs1",
    )
    # The key is returned as spelled; a key containing '=' keeps its remainder.
    assert split_service_path("ietf-te:te/tunnels/tunnel=a%3Db=c")[1] == "a%3Db=c"
    with pytest.raises(PlatformError) as excinfo:
        split_service_path("cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies")
    assert str(excinfo.value).startswith(
        "'cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies' is not a keyed service path"
    )
    assert "cnc_list_services" in str(excinfo.value)


def test_service_type_of_list_covers_the_seven_documented_lists():
    expected = {
        "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/policy": "policy",
        "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/odn-template": "odn-template",
        "cisco-cs-sr-te-cfp:cs-sr-te-policy": "cs-sr-te-policy",
        "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service": "ietf-l3vpn",
        "ietf-l2vpn-ntw:l2vpn-ntw/vpn-services/vpn-service": "ietf-l2vpn",
        "ietf-network-slice-service:network-slice-services/slice-service": "slice-service",
        "ietf-te:te/tunnels/tunnel": "tunnel",
    }
    for list_path, label in expected.items():
        assert service_type_of_list(list_path) == label, list_path
    # The proxy's module-qualified spelling of the last segment finds the same entry.
    assert (
        service_type_of_list(
            "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/"
            "cisco-sr-te-cfp-sr-policies:policy"
        )
        == "policy"
    )
    assert service_type_of_list("cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policy") is None
    assert service_type_of_list("acme:things/thing") is None
    assert service_type_of_list("acme:thing") is None


def test_canonical_service_type():
    assert canonical_service_type(" policy ") == "policy"
    assert canonical_service_type("sr-policy") == "policy"
    assert canonical_service_type("L3VPN") == "ietf-l3vpn"
    assert canonical_service_type("{urn:ietf:params:xml:ns:yang:ietf-te}tunnel") == "tunnel"
    # Unknown labels / QNames are the escape hatch: sent as given.
    assert canonical_service_type("acme-thing") == "acme-thing"
    assert canonical_service_type("{urn:acme}thing") == "{urn:acme}thing"


def test_service_identity_derives_the_full_form_fields():
    assert service_identity(POLICY_PATH) == ("policy", "mcp-oam-91")
    assert service_identity("ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=mcp-l3vpn-91") == (
        "ietf-l3vpn",
        "mcp-l3vpn-91",
    )
    # The key is percent-decoded for service-name (the yang-path itself stays as given).
    assert service_identity("ietf-te:te/tunnels/tunnel=t%201%2F2") == ("tunnel", "t 1/2")
    # Overrides win; a known alias becomes the CAT label, anything else goes as given.
    assert service_identity(POLICY_PATH, service_type="sr-policy") == ("policy", "mcp-oam-91")
    assert service_identity(POLICY_PATH, service_name="other") == ("policy", "other")
    assert service_identity("acme:things/thing=x", service_type="acme") == ("acme", "x")
    # With both overrides the path need not even be keyed.
    assert service_identity("acme:things", "acme", "x") == ("acme", "x")


def test_service_identity_refuses_what_it_cannot_derive():
    with pytest.raises(PlatformError) as excinfo:
        service_identity("acme:things/thing=x")
    text = str(excinfo.value)
    assert text.startswith("cannot derive the service-type of 'acme:things/thing=x'")
    assert "'acme:things/thing'" in text
    assert "policy, odn-template" in text
    assert "service_type=" in text and "cnc_list_service_types" in text
    with pytest.raises(PlatformError, match="is not a keyed service path"):
        service_identity("acme:things")
    with pytest.raises(PlatformError, match="has an empty key after '='"):
        service_identity(f"{POLICY_PATH.rsplit('=', 1)[0]}=")
    # A service_type override alone still needs the key for the name.
    with pytest.raises(PlatformError, match="is not a keyed service path"):
        service_identity("acme:things", service_type="acme")


def test_trace_end_of_node():
    assert trace_end_of_node(PE1_NODE, PE1_UUID, "headend_uuid") == PE1_END
    with pytest.raises(PlatformError) as excinfo:
        trace_end_of_node(PE2_NO_ROUTER_ID, PE2_UUID, "endpoint_uuid")
    text = str(excinfo.value)
    assert text.startswith(f"endpoint_uuid PE2 ('{PE2_UUID}') has no te_router_id")
    assert f"cnc_update_device(uuid='{PE2_UUID}', te_router_id=" in text
    with pytest.raises(PlatformError, match="has no te_router_id"):
        trace_end_of_node({"uuid": PE2_UUID, "host_name": "PE2"}, PE2_UUID, "endpoint_uuid")
    with pytest.raises(PlatformError, match="has no host_name"):
        trace_end_of_node({"uuid": PE1_UUID, "routing_info": {}}, PE1_UUID, "headend_uuid")


def test_start_trace_body_is_the_full_form():
    assert start_trace_body(POLICY_PATH, "policy", "mcp-oam-91", PE1_END, PE2_END) == (
        FULL_START_BODY
    )
    assert "transport-type" not in FULL_START_BODY["input"]


def test_completed_without_paths():
    assert completed_without_paths(NO_PATH) is True
    assert completed_without_paths(COMPLETED) is False
    assert completed_without_paths(FAILED) is False
    assert completed_without_paths({**NO_PATH, "path-info-list": []}) is True


def test_start_summary_is_state_aware():
    registered = start_summary(REGISTERED, QUERY_ID)
    assert registered.startswith(
        f"OAM trace route registered: query-id {QUERY_ID}, in progress (3): Path trace "
        "registered for calculation."
    )
    assert f"Next: cnc_wait_for_oam_trace_route(query_id='{QUERY_ID}')" in registered
    failed = start_summary(FAILED_NO_UUID, QUERY_ID)
    assert failed.startswith(
        f"OAM trace route {QUERY_ID} was registered but FAILED immediately: {MPLS_OAM_TEXT}."
    )
    assert "Nothing to wait for" in failed
    assert "cnc_wait_for_oam_trace_route" not in failed
    assert "registered:" not in failed
    completed = start_summary(COMPLETED, QUERY_ID)
    assert completed.startswith(
        f"OAM trace route {QUERY_ID} completed immediately: completed (4): Path trace completed."
    )
    assert "cnc_wait_for_oam_trace_route" not in completed
    no_path = start_summary(NO_PATH, QUERY_ID)
    assert no_path.startswith(
        f"OAM trace route {QUERY_ID} completed immediately with 0 paths: completed (4): "
        f"{NO_PATH_FOUND_MESSAGE}."
    )
    assert "paths are below" not in no_path
    assert "cnc_wait_for_oam_trace_route" not in no_path
    other = start_summary({**REGISTERED, "status": 7, "status-message": "queued"}, QUERY_ID)
    assert other.startswith(f"OAM trace route {QUERY_ID} answered status 7: queued on registration")
    assert f"cnc_get_oam_trace_route(query_id='{QUERY_ID}')" in other
    assert "Next:" not in other


def test_probe_verdict_500_needs_a_document_at_500():
    assert probe_verdict_500(NO_SESSION_500, NO_SESSION_DOC) == NO_SESSION_DOC["error"]
    other = {**NO_SESSION_DOC, "error": "service not found"}
    assert probe_verdict_500(httpx.Response(500, json=other), other) == "service not found"
    # A 500 without a probe document is not a verdict (a bare error, HTML, nothing).
    bare = {"error": "NATS request failed: timeout"}
    assert probe_verdict_500(httpx.Response(500, json=bare), bare) == ""
    assert probe_verdict_500(httpx.Response(500, text="<html>oops</html>"), None) == ""
    assert probe_verdict_500(EMPTY_500, None) == ""
    # A document without an error, or a document on a non-500, is not a verdict either.
    silent = {**NO_SESSION_DOC, "error": ""}
    assert probe_verdict_500(httpx.Response(500, json=silent), silent) == ""
    assert probe_verdict_500(httpx.Response(200, json=other), other) == ""
    assert probe_verdict_500(httpx.Response(503, json=other), other) == ""


def test_end_text_prefers_name_then_uuid():
    assert end_text(REGISTERED, "head-end") == PE1_UUID
    assert end_text(COMPLETED, "head-end") == f"PE1 (uuid {PE1_UUID}, te-router-id 10.0.0.1)"
    assert end_text(NOT_FOUND, "tail-end") == "?"
    assert end_text({"tail-end-te-router-id": "10.0.0.3"}, "tail-end") == "10.0.0.3"


def test_path_line_renders_the_document_shape():
    assert path_line(COMPLETED["path-info-list"][0]) == (
        "- path 1: 10.0.0.1 -> 10.0.0.3 via next-hop 10.1.2.2 out-interface "
        f"GigabitEthernet0/0/0/0; path-status success; devices {PE1_UUID}, {P1_UUID}, "
        f"{PE2_UUID}\n    - hop: 16002 16003"
    )
    assert path_line({"path": "2"}) == "- path 2: ? -> ?"


# Verified live 2026-09-14: the head-end's LSP-ping traceroute of an L3VPN, one of the
# two ECMP paths PE1 -> P2 -> PE2 (the platform's own UI markup, hops split by newlines).
VERIFIED_PATH_DETAILS = (
    "#BOLD_WORD#Hop index:0 | #BOLD_WORD#Hop origin IP:10.0.0.1 | "
    "#BOLD_WORD#Hop destination IP:10.1.4.1 | #BOLD_WORD#MRU:1500 | #BOLD_WORD#Labels:[16003] | "
    "#BOLD_WORD#ret code:0 | #BOLD_WORD#multipaths:0\n"
    "#BOLD_WORD#Hop index:1 | #BOLD_WORD#Hop origin IP:10.1.4.1 | "
    "#BOLD_WORD#Hop destination IP:10.1.3.1 | #BOLD_WORD#MRU:1500 | "
    "#BOLD_WORD#Labels:[implicit-null] | #BOLD_WORD#ret code:8 | #BOLD_WORD#return char:L | "
    "#BOLD_WORD#multipaths:1\n"
    "#BOLD_WORD#Hop index:2 | #BOLD_WORD#Hop origin IP:10.1.3.1 | #BOLD_WORD#MRU:0 | "
    "#BOLD_WORD#ret code:3 | #BOLD_WORD#return char:! | #BOLD_WORD#multipaths:0\n"
)
VERIFIED_PATH = {
    "path": "Path 1",
    "path-info": {
        "out-interface": "GigabitEthernet0/0/0/1",
        "source": "10.0.0.1",
        "destination": "127.0.0.0",
        "path-details": VERIFIED_PATH_DETAILS,
        "device-uuids": [P1_UUID, PE2_UUID],
        "path-status": "found",
        "next-hop": "10.1.4.1",
    },
}


def test_hop_lines_parse_the_verified_markup():
    assert hop_lines(VERIFIED_PATH_DETAILS) == [
        "    - hop 0: origin IP 10.0.0.1, destination IP 10.1.4.1, MRU 1500, Labels [16003], "
        "ret code 0, multipaths 0",
        "    - hop 1: origin IP 10.1.4.1, destination IP 10.1.3.1, MRU 1500, "
        "Labels [implicit-null], ret code 8, return char L, multipaths 1",
        "    - hop 2: origin IP 10.1.3.1, MRU 0, ret code 3, return char !, multipaths 0",
    ]
    # an unparseable hop is kept verbatim (minus the markup), nothing is dropped
    assert hop_lines("#BOLD_WORD#free text\r\n\n") == ["    - hop: free text"]
    assert hop_lines("") == []


def test_path_line_renders_the_verified_success_shape():
    """Without a name map the uuids are shown as sent; the 127/8 destination is annotated
    as the LSP-ping target it is (verified: 'destination 127.0.0.0' on both ECMP paths)."""
    text = path_line(VERIFIED_PATH)
    assert text.startswith(
        "- path Path 1: 10.0.0.1 -> 127.0.0.0 (MPLS-OAM LSP-ping target, expected — not a "
        "router address) via next-hop 10.1.4.1 out-interface GigabitEthernet0/0/0/1; "
        f"path-status found; devices {P1_UUID}, {PE2_UUID}\n"
    )
    assert "#BOLD_WORD#" not in text
    assert text.count("\n    - hop ") == 3


def test_path_line_resolves_device_uuids_to_host_names():
    """With the inventory map (one list call per rendering) each uuid reads as
    '<host_name> (<uuid>)'; an unknown uuid stays a uuid; the map is case-insensitive."""
    names = {P1_UUID: "P1", PE2_UUID.upper(): "PE2"}
    text = path_line(VERIFIED_PATH, device_name_map([P1_NODE, PE2_NODE]))
    assert f"devices P1 ({P1_UUID}), PE2 ({PE2_UUID})\n" in text
    assert device_text(PE2_UUID.upper(), device_name_map([PE2_NODE])) == f"PE2 ({PE2_UUID.upper()})"
    assert device_text(P1_UUID, {}) == P1_UUID and device_text(P1_UUID, None) == P1_UUID
    assert device_name_map([{"uuid": P1_UUID}, {"host_name": "x"}, "junk"]) == {}
    assert device_name_map([P1_NODE]) == {P1_UUID: "P1"}
    assert names[P1_UUID] == "P1"  # the plain dict form is what the tools build
    # The helpers behind the map: which uuids a route needs, and the 127/8 check.
    route = {"path-info-list": [VERIFIED_PATH, COMPLETED["path-info-list"][0]]}
    assert path_device_uuids(route) == [P1_UUID, PE2_UUID, PE1_UUID]
    assert path_device_uuids({}) == [] and path_device_uuids(NO_PATH) == []
    assert is_mpls_oam_target("127.0.0.0") and is_mpls_oam_target("127.1.2.3")
    assert not is_mpls_oam_target("10.0.0.3") and not is_mpls_oam_target("")
    assert destination_text("10.0.0.3") == "10.0.0.3" and destination_text("") == "?"


def test_probe_enum_helpers():
    assert enum_word(3, PROBE_STATUS_NAMES) == "PROBE_STATUS_ERROR (3)"
    assert enum_word("PROBE_STATUS_SUCCESS", PROBE_STATUS_NAMES) == "PROBE_STATUS_SUCCESS"
    assert enum_word(9, PROBE_STATUS_NAMES) == "status 9"
    assert enum_word(None, PROBE_STATUS_NAMES) == "-"
    assert enum_word(True, PROBE_STATUS_NAMES) == "-"
    assert enum_name(1, REACTIVATE_STATUS_NAMES) == "RESP_STATUS_SUCCESS"
    assert enum_name("resp_status_error", REACTIVATE_STATUS_NAMES) == "RESP_STATUS_ERROR"
    assert enum_name(7, REACTIVATE_STATUS_NAMES) == ""
    assert enum_name(None, REACTIVATE_STATUS_NAMES) == ""


def test_probe_reports_accepts_wrapped_and_bare_documents():
    assert probe_reports(PROBE_200) == [PROBE_REPORT]
    assert probe_reports(NO_SESSION_DOC) == [NO_SESSION_DOC]
    assert probe_reports({"data": "nope"}) == []
    assert probe_reports([]) == []
    assert probe_reports(None) == []


def test_oam_empty_500_hint_is_self_contained():
    assert EMPTY_500_EXPLANATION not in OAM_EMPTY_500_HINT
    assert "absent or down" in OAM_EMPTY_500_HINT
    for check in ("cnc_list_providers", "cnc_list_services", "cnc_list_devices"):
        assert check in OAM_EMPTY_500_HINT, check


# --- cnc_get_oam_settings ------------------------------------------------------------


@respx.mock
async def test_get_oam_settings_sends_no_body_and_renders_the_verified_answer(reads):
    route = respx.post(rpc("get-oam-delete-interval")).mock(return_value=ok(DELETE_INTERVAL_OUT))
    text = await call_tool_text(reads, "cnc_get_oam_settings", {})
    assert route.call_count == 1
    assert_bodiless_post(route)
    assert text.startswith("Completed trace-route queries are deleted after 1 hour(s)")
    assert "cnc_get_oam_trace_route" in text


@respx.mock
async def test_get_oam_settings_json(reads):
    respx.post(rpc("get-oam-delete-interval")).mock(return_value=ok(DELETE_INTERVAL_OUT))
    text = await call_tool_text(reads, "cnc_get_oam_settings", {"response_format": "json"})
    assert json.loads(text) == {"delete-interval": 1, "response-result": "valid"}


@respx.mock
async def test_get_oam_settings_without_interval_is_not_an_error(reads):
    respx.post(rpc("get-oam-delete-interval")).mock(return_value=NO_CONTENT)
    text = await call_tool_text(reads, "cnc_get_oam_settings", {})
    assert text.startswith("The Optimization Engine reported no OAM delete-interval.")


@respx.mock
async def test_get_oam_settings_response_result_error_inside_200(reads):
    respx.post(rpc("get-oam-delete-interval")).mock(return_value=ok(out(**RESULT_ERROR)))
    text = await call_tool_text(reads, "cnc_get_oam_settings", {})
    assert text == (
        "Error: get-oam-delete-interval failed: response-result error: internal OAM error"
    )


@respx.mock
async def test_get_oam_settings_empty_500_is_the_coe_hint(reads):
    route = respx.post(rpc("get-oam-delete-interval")).mock(return_value=EMPTY_500)
    text = await call_tool_text(reads, "cnc_get_oam_settings", {})
    assert route.call_count == 1  # a POST: never auto-retried
    assert text == f"Error: {OAM_EMPTY_500_HINT}"


@respx.mock
async def test_get_oam_settings_http_error(reads):
    respx.post(rpc("get-oam-delete-interval")).mock(
        return_value=httpx.Response(403, json={"message": "Unauthorized request"})
    )
    text = await call_tool_text(reads, "cnc_get_oam_settings", {})
    assert text.startswith("Error: API request failed with status 403.")
    assert "Unauthorized request" in text


# --- cnc_list_oam_trace_routes --------------------------------------------------------


@respx.mock
async def test_list_trace_routes_empty_states_the_verified_caveat(reads):
    route = respx.post(rpc("get-oam-trace-route-by-query")).mock(return_value=ok(LIST_EMPTY_OUT))
    text = await call_tool_text(reads, "cnc_list_oam_trace_routes", {})
    assert route.call_count == 1
    assert_yang_post(route)
    assert sent(route) == {"input": {"start-row": 0, "end-row": 50}}
    assert text.startswith("# OAM trace-route queries (total 0: 0 completed, 0 running, 0 failed)")
    assert "No trace-route queries were listed for rows 0-50." in text
    assert "did not show queries created seconds earlier" in text
    assert "cnc_get_oam_trace_route" in text
    assert not text.startswith("Error:")


@respx.mock
async def test_list_trace_routes_sends_the_filter_and_window(reads):
    route = respx.post(rpc("get-oam-trace-route-by-query")).mock(return_value=ok(LIST_EMPTY_OUT))
    text = await call_tool_text(
        reads,
        "cnc_list_oam_trace_routes",
        {"start_row": 10, "end_row": 20, "filter_criteria": " SPQ-3 "},
    )
    assert sent(route) == {"input": {"start-row": 10, "end-row": 20, "filter-criteria": "SPQ-3"}}
    assert "rows 10-20 with filter 'SPQ-3'" in text


@respx.mock
async def test_list_trace_routes_renders_rows(reads):
    respx.post(rpc("get-oam-trace-route-by-query")).mock(return_value=ok(LIST_WITH_ROWS_OUT))
    text = await call_tool_text(reads, "cnc_list_oam_trace_routes", {})
    assert text.startswith("# OAM trace-route queries (total 2: 1 completed, 0 running, 1 failed)")
    assert (
        f"- {QUERY_ID} — failed (5): {GNMI_TEXT}; service {POLICY_PATH}; {PE1_UUID} -> "
        f"{PE2_UUID}; created 2026-09-13T18:36:56Z" in text
    )
    assert (
        f"- SPQ-324700000 — completed (4): Path trace completed; service {POLICY_PATH}; "
        f"PE1 (uuid {PE1_UUID}, te-router-id 10.0.0.1) -> PE2 (uuid {PE2_UUID}, te-router-id "
        "10.0.0.3); created 2026-09-13T18:36:56Z" in text
    )


@respx.mock
async def test_list_trace_routes_json_envelope(reads):
    respx.post(rpc("get-oam-trace-route-by-query")).mock(return_value=ok(LIST_WITH_ROWS_OUT))
    text = await call_tool_text(
        reads, "cnc_list_oam_trace_routes", {"end_row": 10, "response_format": "json"}
    )
    data = json.loads(text)
    assert data["total"] == 2 and data["count"] == 2 and data["offset"] == 0
    assert data["has_more"] is False and data["next_offset"] is None
    assert data["counts"] == {"completed": 1, "running": 0, "failed": 1}
    assert data["items"][0]["query-id"] == QUERY_ID
    assert "note" not in data


@respx.mock
async def test_list_trace_routes_json_empty_carries_the_note(reads):
    respx.post(rpc("get-oam-trace-route-by-query")).mock(return_value=ok(LIST_EMPTY_OUT))
    text = await call_tool_text(reads, "cnc_list_oam_trace_routes", {"response_format": "json"})
    data = json.loads(text)
    assert data["items"] == [] and data["total"] == 0
    assert "cnc_get_oam_trace_route" in data["note"]


@respx.mock
async def test_list_trace_routes_bad_window_is_error_before_any_call(reads):
    route = respx.post(rpc("get-oam-trace-route-by-query")).mock(return_value=ok(LIST_EMPTY_OUT))
    text = await call_tool_text(
        reads, "cnc_list_oam_trace_routes", {"start_row": 50, "end_row": 50}
    )
    assert text.startswith("Error: end_row must exceed start_row")
    assert route.call_count == 0


@respx.mock
async def test_list_trace_routes_response_result_invalid_inside_200(reads):
    respx.post(rpc("get-oam-trace-route-by-query")).mock(return_value=ok(out(**RESULT_INVALID)))
    text = await call_tool_text(reads, "cnc_list_oam_trace_routes", {})
    assert text == (
        "Error: get-oam-trace-route-by-query failed: response-result invalid: no message given"
    )


@respx.mock
async def test_list_trace_routes_empty_500_is_the_coe_hint(reads):
    respx.post(rpc("get-oam-trace-route-by-query")).mock(return_value=EMPTY_500)
    text = await call_tool_text(reads, "cnc_list_oam_trace_routes", {})
    assert text == f"Error: {OAM_EMPTY_500_HINT}"


# --- cnc_get_oam_trace_route ---------------------------------------------------------


@respx.mock
async def test_get_trace_route_registered(reads):
    route = mock_trace_route(ok(out(**REGISTERED)))
    text = await call_tool_text(reads, "cnc_get_oam_trace_route", {"query_id": QUERY_ID})
    assert route.call_count == 1
    assert_yang_post(route)
    assert sent(route) == {"input": {"query-id": QUERY_ID}}
    assert text.startswith(f"# OAM trace route {QUERY_ID} — in progress (3)")
    assert "- status: in progress (3): Path trace registered for calculation" in text
    assert f"- service: {POLICY_PATH}" in text
    assert f"- head-end: {PE1_UUID}" in text
    assert f"- tail-end: {PE2_UUID}" in text
    assert "- created: 2026-09-13T18:36:56Z; updated: 2026-09-13T18:36:56Z" in text
    assert "- available-path-count: 0" in text
    assert "transport-type" not in text
    assert "## Paths" not in text
    assert f"cnc_wait_for_oam_trace_route(query_id='{QUERY_ID}')" in text


@respx.mock
async def test_get_trace_route_failed_is_rendered_not_an_error(reads):
    mock_trace_route(ok(out(**FAILED)))
    text = await call_tool_text(reads, "cnc_get_oam_trace_route", {"query_id": QUERY_ID})
    assert not text.startswith("Error:")
    assert text.startswith(f"# OAM trace route {QUERY_ID} — failed (5)")
    assert f"- status: failed (5): {GNMI_TEXT}" in text
    assert "- created: 2026-09-13T18:36:56Z; updated: 2026-09-13T18:37:27Z" in text
    assert "A failed query is not re-run" in text


@respx.mock
async def test_get_trace_route_completed_renders_paths(reads):
    mock_trace_route(ok(out(**COMPLETED)))
    inventory = mock_inventory()
    text = await call_tool_text(reads, "cnc_get_oam_trace_route", {"query_id": QUERY_ID})
    assert text.startswith(f"# OAM trace route {QUERY_ID} — completed (4)")
    assert f"- service: {POLICY_PATH} (service-name mcp-oam-91, service-type policy)" in text
    assert f"- head-end: PE1 (uuid {PE1_UUID}, te-router-id 10.0.0.1)" in text
    assert "- available-path-count: 1" in text
    assert "## Paths (1)" in text
    assert "- path 1: 10.0.0.1 -> 10.0.0.3 via next-hop 10.1.2.2 out-interface" in text
    # ONE unfiltered inventory list resolved every per-path uuid to its host name.
    assert inventory.call_count == 1
    assert json.loads(inventory.calls[0].request.content) == UNFILTERED_LIST_BODY
    assert f"devices PE1 ({PE1_UUID}), P1 ({P1_UUID}), PE2 ({PE2_UUID})" in text
    assert "- device names:" not in text
    assert "cnc_get_device(uuid=...)" in text


# The verified L3VPN success (2026-09-14): two ECMP paths PE1 -> P2 -> PE2 / PE1 -> P1 -> PE2.
P2_UUID = "1b44ade3-5c6d-4e7f-8a9b-0c1d2e3f4a5b"
P2_NODE = inventory_node(P2_UUID, "P2", "10.0.0.4")
VERIFIED_SUCCESS = service_route(
    4,
    "Path trace Successful",
    **{
        "head-end-node-name": "PE1",
        "head-end-te-router-id": "10.0.0.1",
        "tail-end-node-name": "PE2",
        "tail-end-te-router-id": "10.0.0.3",
        "service-name": "agent-l3vpn-1",
        "service-type": "ietf-l3vpn",
        "yang-path": L3VPN_ID,
        "available-path-count": 2,
        "update-time": "1789324627000.0",
        "path-info-list": [
            {
                "path": "Path 1",
                "path-info": {**VERIFIED_PATH["path-info"], "device-uuids": [P2_UUID, PE2_UUID]},
            },
            {
                "path": "Path 0",
                "path-info": {
                    **VERIFIED_PATH["path-info"],
                    "out-interface": "GigabitEthernet0/0/0/0",
                    "next-hop": "10.1.1.2",
                    "device-uuids": [P1_UUID, PE2_UUID],
                },
            },
        ],
    },
)
FIVE_DEVICES = {
    "data": [PE1_NODE, P1_NODE, PE2_NODE, P2_NODE, inventory_node("a" * 32, "PCE", "10.0.0.5")],
    "result_count": 5,
    "total_count": 5,
}


@respx.mock
async def test_get_trace_route_verified_success_names_the_ecmp_legs(reads):
    """The agent scenario (2026-09-14): the two paths read as 'via P2' / 'via P1' without a
    cnc_get_device call per uuid, and the 127/8 target is explained."""
    mock_trace_route(ok(out(**VERIFIED_SUCCESS)))
    inventory = mock_inventory(httpx.Response(200, json=FIVE_DEVICES))
    text = await call_tool_text(reads, "cnc_get_oam_trace_route", {"query_id": QUERY_ID})
    assert inventory.call_count == 1
    assert "## Paths (2)" in text
    assert (
        "- path Path 1: 10.0.0.1 -> 127.0.0.0 (MPLS-OAM LSP-ping target, expected — not a "
        "router address) via next-hop 10.1.4.1 out-interface GigabitEthernet0/0/0/1; "
        f"path-status found; devices P2 ({P2_UUID}), PE2 ({PE2_UUID})\n"
    ) in text
    assert (
        "- path Path 0: 10.0.0.1 -> 127.0.0.0 (MPLS-OAM LSP-ping target, expected — not a "
        "router address) via next-hop 10.1.1.2 out-interface GigabitEthernet0/0/0/0; "
        f"path-status found; devices P1 ({P1_UUID}), PE2 ({PE2_UUID})\n"
    ) in text
    assert "    - hop 0: origin IP 10.0.0.1, destination IP 10.1.4.1, MRU 1500" in text
    assert "an L3VPN between PE1 and PE2 answered two paths" in text
    assert "devices = the transit device(s) then the tail-end" in text
    # JSON keeps the raw output and adds the resolved map.
    text = await call_tool_text(
        reads, "cnc_get_oam_trace_route", {"query_id": QUERY_ID, "response_format": "json"}
    )
    payload = json.loads(text)
    assert payload["path-info-list"][0]["path-info"]["device-uuids"] == [P2_UUID, PE2_UUID]
    assert payload["device-names"] == {P2_UUID: "P2", PE2_UUID: "PE2", P1_UUID: "P1"}


@respx.mock
async def test_get_trace_route_paths_survive_an_inventory_failure(reads):
    """The name lookup is auxiliary: a failed or incomplete inventory list leaves the uuids
    as sent and says so, never turning a completed trace into an error."""
    mock_trace_route(ok(out(**VERIFIED_SUCCESS)))
    mock_inventory(httpx.Response(500, json={"error": "NATS request failed"}))
    text = await call_tool_text(reads, "cnc_get_oam_trace_route", {"query_id": QUERY_ID})
    assert not text.startswith("Error:")
    assert f"devices {P2_UUID}, {PE2_UUID}" in text
    assert "- device names: not resolved (the inventory list failed:" in text
    # A uuid the inventory does not hold stays a uuid and is named on the note.
    mock_inventory(httpx.Response(200, json=INVENTORY_LIST))  # no P2
    text = await call_tool_text(reads, "cnc_get_oam_trace_route", {"query_id": QUERY_ID})
    assert f"devices {P2_UUID}, PE2 ({PE2_UUID})" in text
    assert f"- device names: 1 uuid(s) not in the inventory ({P2_UUID})" in text
    assert "cnc_get_device(uuid=...) may still know them" in text
    text = await call_tool_text(
        reads, "cnc_get_oam_trace_route", {"query_id": QUERY_ID, "response_format": "json"}
    )
    assert json.loads(text)["device-names"] == {P1_UUID: "P1", PE2_UUID: "PE2"}


@respx.mock
async def test_get_trace_route_without_paths_never_lists_the_inventory(reads):
    inventory = mock_inventory()
    mock_trace_route(ok(out(**RUNNING)))
    await call_tool_text(reads, "cnc_get_oam_trace_route", {"query_id": QUERY_ID})
    mock_trace_route(ok(out(**NO_PATH_SHORT)))
    text = await call_tool_text(
        reads, "cnc_get_oam_trace_route", {"query_id": QUERY_ID, "response_format": "json"}
    )
    assert inventory.call_count == 0
    assert "device-names" not in json.loads(text)


@respx.mock
async def test_get_trace_route_inventory_list_pages_only_while_there_is_more(reads):
    """total_count above one page -> a second page is read (verified paging grammar);
    the map merges both."""
    mock_trace_route(ok(out(**VERIFIED_SUCCESS)))
    page0 = {"data": [PE1_NODE, P1_NODE], "result_count": 201, "total_count": 201}
    page1 = {"data": [PE2_NODE, P2_NODE], "result_count": 201, "total_count": 201}
    inventory = mock_inventory(
        httpx.Response(200, json=page0),
        httpx.Response(200, json=page1),
        httpx.Response(200, json={}),
    )
    text = await call_tool_text(reads, "cnc_get_oam_trace_route", {"query_id": QUERY_ID})
    assert inventory.call_count == 2
    assert json.loads(inventory.calls[1].request.content)["filterData"]["PageNum"] == 1
    assert f"devices P2 ({P2_UUID}), PE2 ({PE2_UUID})" in text


@respx.mock
async def test_get_trace_route_inventory_list_counts_the_rows_that_arrived(reads):
    """A page shorter than the asked PageSize (200) while total_count says the inventory
    is bigger — a platform page cap below the asked size, undocumented and not seen on
    the 5-device lab — must fetch the next page: the walk counts delivered rows, never
    ``(page + 1) * PageSize``, so the devices past the cap are not reported as missing."""
    mock_trace_route(ok(out(**VERIFIED_SUCCESS)))
    page0 = {"data": [PE1_NODE, P1_NODE], "result_count": 4, "total_count": 4}  # 2 of 4
    page1 = {"data": [PE2_NODE, P2_NODE], "result_count": 4, "total_count": 4}
    inventory = mock_inventory(
        httpx.Response(200, json=page0),
        httpx.Response(200, json=page1),
        httpx.Response(200, json={}),
    )
    text = await call_tool_text(reads, "cnc_get_oam_trace_route", {"query_id": QUERY_ID})
    assert inventory.call_count == 2
    assert json.loads(inventory.calls[0].request.content)["filterData"]["PageNum"] == 0
    assert json.loads(inventory.calls[1].request.content)["filterData"]["PageNum"] == 1
    assert f"devices P2 ({P2_UUID}), PE2 ({PE2_UUID})" in text
    assert f"devices P1 ({P1_UUID}), PE2 ({PE2_UUID})" in text
    assert "not in the inventory" not in text


@respx.mock
async def test_get_trace_route_inventory_list_stops_once_every_path_device_is_named(reads):
    """The walk ends as soon as every uuid on the paths is resolved, even when total_count
    says more pages exist: the rest of the inventory is not needed for the rendering."""
    mock_trace_route(ok(out(**VERIFIED_SUCCESS)))
    page0 = {"data": [P1_NODE, P2_NODE, PE2_NODE], "result_count": 201, "total_count": 201}
    inventory = mock_inventory(
        httpx.Response(200, json=page0),
        httpx.Response(200, json={"data": [PE1_NODE], "result_count": 201, "total_count": 201}),
    )
    text = await call_tool_text(reads, "cnc_get_oam_trace_route", {"query_id": QUERY_ID})
    assert inventory.call_count == 1
    assert f"devices P2 ({P2_UUID}), PE2 ({PE2_UUID})" in text
    assert f"devices P1 ({P1_UUID}), PE2 ({PE2_UUID})" in text
    assert "- device names:" not in text


@respx.mock
async def test_get_trace_route_completed_with_no_path_is_a_verdict_not_an_error(reads):
    """The verified status-4 answer (short form, 2026-09-14): 'No path found between the
    selected devices', 0 paths, names / router-ids echoed empty, ~10 s after registration."""
    mock_trace_route(ok(out(**NO_PATH_SHORT)))
    text = await call_tool_text(reads, "cnc_get_oam_trace_route", {"query_id": QUERY_ID})
    assert not text.startswith("Error:")
    assert text.startswith(f"# OAM trace route {QUERY_ID} — completed (4)")
    assert f"- status: completed (4): {NO_PATH_FOUND_MESSAGE}" in text
    assert f"- service: {POLICY_PATH}\n" in text
    assert f"- head-end: {PE1_UUID}\n" in text
    assert f"- tail-end: {PE2_UUID}\n" in text
    assert "- created: 2026-09-13T18:36:56Z; updated: 2026-09-13T18:37:07Z" in text
    assert "- available-path-count: 0" in text
    assert "## Paths" not in text
    assert "Completed with ZERO paths — the engine's verdict, not a failure" in text
    # The footer hedges: verified only for the short form / policy, judged by timing.
    assert "verified only for the SHORT input form" in text
    assert "WITHOUT tracing anything" in text
    assert "answering status 4 has NOT been observed live" in text
    assert "the verdict arrived 10s after registration" in text
    assert "re-check that service-type is the CAT label" in text
    assert "A failed query is not re-run" not in text


@respx.mock
async def test_get_trace_route_full_form_no_path_shows_the_echo_and_the_timing_hint(reads):
    """EXTRAPOLATED: the zero-path verdict on a full-form query (never observed live — the
    verified full-form traces ended in status 5) renders the echoed inputs and the same
    timing-based hedge; without parseable times the delay clause is simply absent."""
    mock_trace_route(ok(out(**NO_PATH)), ok(out(**{**NO_PATH, "update-time": ""})))
    text = await call_tool_text(reads, "cnc_get_oam_trace_route", {"query_id": QUERY_ID})
    assert not text.startswith("Error:")
    assert f"- service: {POLICY_PATH} (service-name mcp-oam-91, service-type policy)" in text
    assert f"- head-end: PE1 (uuid {PE1_UUID}, te-router-id 10.0.0.1)" in text
    assert f"- tail-end: PE2 (uuid {PE2_UUID}, te-router-id 10.0.0.3)" in text
    assert "Completed with ZERO paths — the engine's verdict, not a failure" in text
    assert "(both times are shown above; the verdict arrived 10s after registration)" in text
    assert "only 'policy' is verified on the wire" in text
    text = await call_tool_text(reads, "cnc_get_oam_trace_route", {"query_id": QUERY_ID})
    assert "- created: 2026-09-13T18:36:56Z; updated: -" in text
    assert "(both times are shown above): a verdict within seconds" in text
    assert "the verdict arrived" not in text


@respx.mock
async def test_get_trace_route_json(reads):
    mock_trace_route(ok(out(**RUNNING)))
    text = await call_tool_text(
        reads, "cnc_get_oam_trace_route", {"query_id": QUERY_ID, "response_format": "json"}
    )
    assert json.loads(text) == RUNNING


@respx.mock
async def test_get_trace_route_unknown_id_is_not_found(reads):
    route = mock_trace_route(ok(out(**NOT_FOUND)))
    text = await call_tool_text(reads, "cnc_get_oam_trace_route", {"query_id": "nope"})
    assert sent(route) == {"input": {"query-id": "nope"}}
    assert text.startswith("Error: no trace-route query 'nope' (Route not found for selected ID)")
    assert "cnc_get_oam_settings" in text
    text = await call_tool_text(
        reads, "cnc_get_oam_trace_route", {"query_id": "nope", "response_format": "json"}
    )
    assert text.startswith("Error: no trace-route query 'nope'")


@respx.mock
async def test_get_trace_route_empty_output_is_an_error(reads):
    mock_trace_route(NO_CONTENT)
    text = await call_tool_text(reads, "cnc_get_oam_trace_route", {"query_id": QUERY_ID})
    assert text.startswith(
        f"Error: the Optimization Engine returned no trace-route data for query '{QUERY_ID}'"
    )


@respx.mock
async def test_get_trace_route_response_result_error(reads):
    mock_trace_route(ok(out(**RESULT_ERROR)))
    text = await call_tool_text(reads, "cnc_get_oam_trace_route", {"query_id": QUERY_ID})
    assert text == (
        "Error: get-oam-trace-route-by-query-id failed: response-result error: internal OAM error"
    )


@respx.mock
async def test_get_trace_route_empty_500_is_the_coe_hint(reads):
    route = mock_trace_route(EMPTY_500)
    text = await call_tool_text(reads, "cnc_get_oam_trace_route", {"query_id": QUERY_ID})
    assert route.call_count == 1
    assert text == f"Error: {OAM_EMPTY_500_HINT}"


@respx.mock
async def test_get_trace_route_non_json_body(reads):
    mock_trace_route(httpx.Response(200, text="<html>login</html>"))
    text = await call_tool_text(reads, "cnc_get_oam_trace_route", {"query_id": QUERY_ID})
    assert text == (
        "Error: The Optimization Engine returned a non-JSON response where YANG JSON was expected."
    )


# --- cnc_wait_for_oam_trace_route ----------------------------------------------------


@respx.mock
async def test_wait_failed_verdict_is_not_an_error(reads, fake_clock):
    route = mock_trace_route(ok(out(**REGISTERED)), ok(out(**RUNNING)), ok(out(**FAILED)))
    text = await call_tool_text(
        reads,
        "cnc_wait_for_oam_trace_route",
        {"query_id": QUERY_ID, "timeout_seconds": 90, "interval_seconds": 5},
    )
    assert route.call_count == 3
    assert sent(route, 2) == {"input": {"query-id": QUERY_ID}}
    assert not text.startswith("Error:")
    assert text.startswith(f"Trace route {QUERY_ID} FAILED after 10s: {GNMI_TEXT}")
    assert f"# OAM trace route {QUERY_ID} — failed (5)" in text
    assert "A failed query is not re-run" in text


@respx.mock
async def test_wait_completed_renders_the_paths(reads, fake_clock):
    route = mock_trace_route(ok(out(**RUNNING)), ok(out(**COMPLETED)))
    inventory = mock_inventory()
    text = await call_tool_text(reads, "cnc_wait_for_oam_trace_route", {"query_id": QUERY_ID})
    assert route.call_count == 2
    assert text.startswith(
        f"Trace route {QUERY_ID} finished after 5s: completed (4): Path trace completed"
    )
    assert "## Paths (1)" in text
    # The inventory is listed once, after the last poll — never per poll.
    assert inventory.call_count == 1
    assert f"devices PE1 ({PE1_UUID}), P1 ({P1_UUID}), PE2 ({PE2_UUID})" in text


@respx.mock
async def test_wait_verified_success_resolves_the_legs_once(reads, fake_clock):
    """The agent scenario's wait: registered -> running -> 'Path trace Successful' with the
    two ECMP legs, rendered with host names from ONE inventory list."""
    route = mock_trace_route(
        ok(out(**FULL_REGISTERED)), ok(out(**RUNNING)), ok(out(**VERIFIED_SUCCESS))
    )
    inventory = mock_inventory(httpx.Response(200, json=FIVE_DEVICES))
    text = await call_tool_text(reads, "cnc_wait_for_oam_trace_route", {"query_id": QUERY_ID})
    assert route.call_count == 3 and inventory.call_count == 1
    assert text.startswith(
        f"Trace route {QUERY_ID} finished after 10s: completed (4): Path trace Successful"
    )
    assert f"devices P2 ({P2_UUID}), PE2 ({PE2_UUID})" in text
    assert f"devices P1 ({P1_UUID}), PE2 ({PE2_UUID})" in text
    assert "127.0.0.0 (MPLS-OAM LSP-ping target, expected — not a router address)" in text


@respx.mock
async def test_wait_completed_with_no_path_says_so(reads, fake_clock):
    """The verified 2026-09-14 sequence (short form): registered -> running -> status 4 with
    0 paths ~10 s after registration."""
    route = mock_trace_route(ok(out(**REGISTERED)), ok(out(**RUNNING)), ok(out(**NO_PATH_SHORT)))
    text = await call_tool_text(reads, "cnc_wait_for_oam_trace_route", {"query_id": QUERY_ID})
    assert route.call_count == 3
    assert not text.startswith("Error:")
    assert text.startswith(
        f"Trace route {QUERY_ID} finished after 10s with 0 paths: completed (4): "
        f"{NO_PATH_FOUND_MESSAGE}"
    )
    assert f"# OAM trace route {QUERY_ID} — completed (4)" in text
    assert "Completed with ZERO paths" in text
    assert "verified only for the SHORT input form" in text


@respx.mock
async def test_wait_full_form_completed_with_no_path_is_rendered_the_same(reads, fake_clock):
    """EXTRAPOLATED: a full-form query (names / router-ids echoed) reaching the zero-path
    verdict — never observed live (the verified full-form traces ended in status 5)."""
    route = mock_trace_route(ok(out(**FULL_REGISTERED)), ok(out(**RUNNING)), ok(out(**NO_PATH)))
    text = await call_tool_text(reads, "cnc_wait_for_oam_trace_route", {"query_id": QUERY_ID})
    assert route.call_count == 3
    assert text.startswith(f"Trace route {QUERY_ID} finished after 10s with 0 paths: completed")
    assert f"- head-end: PE1 (uuid {PE1_UUID}, te-router-id 10.0.0.1)" in text
    assert "answering status 4 has NOT been observed live" in text
    assert "the verdict arrived 10s after registration" in text


@respx.mock
async def test_wait_xr_mpls_oam_failure_is_the_platform_verdict(reads, fake_clock):
    """The full-form trace on a head-end without 'mpls oam' (verified 2026-09-14)."""
    mock_trace_route(ok(out(**RUNNING)), ok(out(**FAILED_XR_MPLS_OAM)))
    text = await call_tool_text(reads, "cnc_wait_for_oam_trace_route", {"query_id": QUERY_ID})
    assert text.startswith(f"Trace route {QUERY_ID} FAILED after 5s: {XR_MPLS_OAM_TEXT}")
    assert "'mpls-lspv ... resource not available'" in text
    assert "cnc_enable_device_gnmi" in text


@respx.mock
async def test_wait_times_out_non_error_with_the_current_state(reads, fake_clock):
    route = mock_trace_route(ok(out(**RUNNING)))
    text = await call_tool_text(
        reads,
        "cnc_wait_for_oam_trace_route",
        {"query_id": QUERY_ID, "timeout_seconds": 10, "interval_seconds": 5},
    )
    assert route.call_count == 3  # t=0, 5 and 10
    assert not text.startswith("Error:")
    assert text.startswith(
        f"Trace route {QUERY_ID} not finished yet after 10s; current status: in progress (3): "
        "Path trace running for calculation."
    )
    assert "Call cnc_wait_for_oam_trace_route again" in text
    assert f"# OAM trace route {QUERY_ID} — in progress (3)" in text


@respx.mock
async def test_wait_unknown_id_is_not_found(reads, fake_clock):
    route = mock_trace_route(ok(out(**NOT_FOUND)))
    text = await call_tool_text(reads, "cnc_wait_for_oam_trace_route", {"query_id": "nope"})
    assert route.call_count == 1
    assert text.startswith("Error: no trace-route query 'nope' (Route not found for selected ID)")


@respx.mock
async def test_wait_api_failure_during_polling_is_an_error(reads, fake_clock):
    route = mock_trace_route(ok(out(**RUNNING)), EMPTY_500)
    text = await call_tool_text(reads, "cnc_wait_for_oam_trace_route", {"query_id": QUERY_ID})
    assert route.call_count == 2
    assert text == f"Error: {OAM_EMPTY_500_HINT}"


# --- cnc_get_probe_status ------------------------------------------------------------


@respx.mock
async def test_get_probe_status_no_session_500_is_not_an_error(reads):
    route = respx.post(PROBE_STATUS_URL).mock(return_value=NO_SESSION_500)
    text = await call_tool_text(reads, "cnc_get_probe_status", {"service_id": f" {L3VPN_ID} "})
    assert route.call_count == 1  # a POST: never auto-retried, even as a 500
    assert_json_post(route, {"serviceId": L3VPN_ID})
    assert not text.startswith("Error:")
    assert text.startswith(
        f"No active probe session for {L3VPN_ID} (Service Health status PROBE_STATUS_UNKNOWN)."
    )
    assert "capp-aa" in text
    assert "Platform said: service has no active probe session" in text


@respx.mock
async def test_get_probe_status_no_session_json(reads):
    respx.post(PROBE_STATUS_URL).mock(return_value=NO_SESSION_500)
    text = await call_tool_text(
        reads, "cnc_get_probe_status", {"service_id": L3VPN_ID, "response_format": "json"}
    )
    assert json.loads(text) == NO_SESSION_DOC


@respx.mock
async def test_get_probe_status_renders_the_document_shape(reads):
    respx.post(PROBE_STATUS_URL).mock(return_value=ok(PROBE_200))
    text = await call_tool_text(reads, "cnc_get_probe_status", {"service_id": L3VPN_ID})
    assert text.startswith(f"# Service Health probe status for {L3VPN_ID}")
    assert "- status: PROBE_STATUS_ERROR (3)" in text
    assert "- re-activation available: true" in text
    assert "## Endpoints (2)" in text
    assert (
        "- def — node PE2, interface GigabitEthernet0/0/0/1, agent 30.1.3.252 vlan 22: "
        "PROBE_STATUS_SUCCESS (2)" in text
    )
    assert (
        "- abc — node PE1, interface GigabitEthernet0/0/0/1: PROBE_STATUS_ERROR (3); error: "
        "agent unreachable" in text
    )
    assert "## Sessions (1)" in text
    assert (
        "- 0f701fff-91ec-557e-9cf1-737c67125d3c — sender def -> reflector abc: "
        "PROBE_STATUS_ERROR (3); error: reflector down" in text
    )
    assert f"cnc_reactivate_probe(service_id='{L3VPN_ID}')" in text


@respx.mock
async def test_get_probe_status_json_and_string_statuses(reads):
    report = {**PROBE_REPORT, "enableReactivate": False, "status": "PROBE_STATUS_SUCCESS"}
    respx.post(PROBE_STATUS_URL).mock(return_value=ok({"data": [report]}))
    text = await call_tool_text(
        reads, "cnc_get_probe_status", {"service_id": L3VPN_ID, "response_format": "json"}
    )
    assert json.loads(text) == {"data": [report]}
    text = await call_tool_text(reads, "cnc_get_probe_status", {"service_id": L3VPN_ID})
    assert "- status: PROBE_STATUS_SUCCESS\n" in text
    assert "- re-activation available: false" in text
    assert "cnc_reactivate_probe" not in text


@respx.mock
async def test_get_probe_status_empty_200_is_not_an_error(reads):
    respx.post(PROBE_STATUS_URL).mock(return_value=ok({"data": []}))
    text = await call_tool_text(reads, "cnc_get_probe_status", {"service_id": L3VPN_ID})
    assert text.startswith(f"The probe manager answered no probe report for {L3VPN_ID}.")


@respx.mock
async def test_get_probe_status_go_404_means_not_installed(reads):
    respx.post(PROBE_STATUS_URL).mock(return_value=GO_404)
    text = await call_tool_text(reads, "cnc_get_probe_status", {"service_id": L3VPN_ID})
    assert text == f"Error: {PROBEMGR_NOT_ROUTED_HINT}"
    assert "not installed" in text


@respx.mock
async def test_get_probe_status_verdict_500_is_refused_without_a_retry_hint(reads):
    """A 500 carrying the probe document with another error is the probe manager's
    verdict (the shape of the verified answer) — the same wording family as
    cnc_reactivate_probe's refusal, never the generic "try again" server-error hint."""
    doc = {**NO_SESSION_DOC, "error": "service not found"}
    route = respx.post(PROBE_STATUS_URL).mock(return_value=httpx.Response(500, json=doc))
    text = await call_tool_text(reads, "cnc_get_probe_status", {"service_id": L3VPN_ID})
    assert route.call_count == 1  # a POST: never auto-retried, even as a 500
    assert text.startswith(
        f"Error: the Service Health probe manager refused the probe report for '{L3VPN_ID}': "
        "service not found."
    )
    assert "status PROBE_STATUS_UNKNOWN" in text
    assert "cnc_list_services" in text
    assert "try again" not in text
    assert "server error" not in text
    assert "API request failed" not in text
    # The json form is refused the same way: there is no report to show.
    text = await call_tool_text(
        reads, "cnc_get_probe_status", {"service_id": L3VPN_ID, "response_format": "json"}
    )
    assert text.startswith("Error: the Service Health probe manager refused the probe report")


@respx.mock
async def test_get_probe_status_verdict_500_with_int_status(reads):
    doc = {**NO_SESSION_DOC, "status": 3, "error": "probe agent unreachable"}
    respx.post(PROBE_STATUS_URL).mock(return_value=httpx.Response(500, json=doc))
    text = await call_tool_text(reads, "cnc_get_probe_status", {"service_id": L3VPN_ID})
    assert text.startswith(
        f"Error: the Service Health probe manager refused the probe report for '{L3VPN_ID}': "
        "probe agent unreachable. The 500 carried a probe document (status "
        "PROBE_STATUS_ERROR (3))"
    )
    assert "try again" not in text


@respx.mock
async def test_get_probe_status_other_500_is_an_error(reads):
    """A 500 whose body is NOT a probe document stays a generic server error (retry hint)."""
    respx.post(PROBE_STATUS_URL).mock(
        return_value=httpx.Response(500, json={"error": "NATS request failed: timeout"})
    )
    text = await call_tool_text(reads, "cnc_get_probe_status", {"service_id": L3VPN_ID})
    assert text.startswith("Error: API request failed with status 500.")
    assert "NATS request failed" in text
    assert "refused the probe report" not in text


@respx.mock
async def test_get_probe_status_home_app_404_is_unrouted(reads):
    respx.post(PROBE_STATUS_URL).mock(
        return_value=httpx.Response(
            404, json={"path": "/crosswork/sso/login/x", "status": 404, "error": "Not Found"}
        )
    )
    text = await call_tool_text(reads, "cnc_get_probe_status", {"service_id": L3VPN_ID})
    assert text.startswith("Error: API request failed with status 404.")
    assert "not routed" in text


# --- cnc_start_oam_trace_route -------------------------------------------------------


@respx.mock
async def test_start_trace_route_resolves_the_ends_and_sends_the_full_body(writes):
    """The FULL form (verified 2026-09-14): service-type / service-name derived from the
    yang-path, node names and TE router-ids from two inventory lookups by uuid."""
    nodes = mock_nodes(PE1_NODE, PE2_NODE)
    route = respx.post(rpc("set-oam-trace-route-by-calc")).mock(
        return_value=ok(out(**FULL_REGISTERED))
    )
    text = await call_tool_text(writes, "cnc_start_oam_trace_route", START_ARGS)
    assert nodes.call_count == 2
    assert nodes.calls[0].request.method == "POST"
    assert sent(nodes, 0) == node_query_body(PE1_UUID)
    assert sent(nodes, 1) == node_query_body(PE2_UUID)
    assert route.call_count == 1
    assert_yang_post(route)
    assert sent(route) == FULL_START_BODY
    assert text.startswith(
        f"OAM trace route registered: query-id {QUERY_ID}, in progress (3): Path trace "
        "registered for calculation."
    )
    assert f"cnc_wait_for_oam_trace_route(query_id='{QUERY_ID}')" in text
    assert f"# OAM trace route {QUERY_ID} — in progress (3)" in text
    assert f"- head-end: PE1 (uuid {PE1_UUID}, te-router-id 10.0.0.1)" in text
    assert f"- service: {POLICY_PATH} (service-name mcp-oam-91, service-type policy)" in text
    handle = json.loads(text[text.rindex("{") :])
    assert handle == {
        "query_id": QUERY_ID,
        "status": 3,
        "status_word": "in progress (3)",
        "status_message": "Path trace registered for calculation",
    }


@respx.mock
async def test_start_trace_route_node_lookup_is_a_retried_read(writes):
    """nodes/query is a read: a transient 5xx is retried, unlike the set RPC."""
    replies = [
        httpx.Response(503),
        node_answer(PE1_NODE),
        node_answer(PE2_NODE),
    ]
    nodes = respx.post(NODES_QUERY_URL).mock(side_effect=lambda _r: replies.pop(0))
    route = respx.post(rpc("set-oam-trace-route-by-calc")).mock(
        return_value=ok(out(**FULL_REGISTERED))
    )
    text = await call_tool_text(writes, "cnc_start_oam_trace_route", START_ARGS)
    assert nodes.call_count == 3
    assert route.call_count == 1
    assert text.startswith("OAM trace route registered")


@respx.mock
async def test_start_trace_route_normalises_the_yang_path(writes):
    mock_nodes(PE1_NODE, PE2_NODE)
    route = respx.post(rpc("set-oam-trace-route-by-calc")).mock(
        return_value=ok(out(**FULL_REGISTERED))
    )
    await call_tool_text(
        writes,
        "cnc_start_oam_trace_route",
        {**START_ARGS, "service_yang_path": f"/crosswork/proxy/nso/restconf/data/{POLICY_PATH}"},
    )
    body = sent(route)["input"]
    assert body["yang-path"] == POLICY_PATH
    assert body["service-type"] == "policy" and body["service-name"] == "mcp-oam-91"


@respx.mock
async def test_start_trace_route_derives_type_and_decoded_name_per_list(writes):
    """Each documented list maps to its CAT label; the key is percent-decoded for the name
    while the yang-path itself goes as given."""
    mock_nodes(PE1_NODE, PE2_NODE)
    route = respx.post(rpc("set-oam-trace-route-by-calc")).mock(
        return_value=ok(out(**FULL_REGISTERED))
    )
    cases = {
        "ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=mcp-l3vpn-91": (
            "ietf-l3vpn",
            "mcp-l3vpn-91",
        ),
        "ietf-l2vpn-ntw:l2vpn-ntw/vpn-services/vpn-service=evpn%201": ("ietf-l2vpn", "evpn 1"),
        "cisco-cs-sr-te-cfp:cs-sr-te-policy=cs1": ("cs-sr-te-policy", "cs1"),
        "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-odn:odn/odn-template=odn-90": (
            "odn-template",
            "odn-90",
        ),
        "ietf-network-slice-service:network-slice-services/slice-service=s1": (
            "slice-service",
            "s1",
        ),
        "ietf-te:te/tunnels/tunnel=t1": ("tunnel", "t1"),
        # The proxy's module-qualified spelling of the list.
        "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/"
        "cisco-sr-te-cfp-sr-policies:policy=p1": ("policy", "p1"),
    }
    for index, (path, (label, name)) in enumerate(cases.items()):
        text = await call_tool_text(
            writes, "cnc_start_oam_trace_route", {**START_ARGS, "service_yang_path": path}
        )
        assert not text.startswith("Error:"), path
        body = sent(route, index)["input"]
        assert (body["yang-path"], body["service-type"], body["service-name"]) == (
            path,
            label,
            name,
        ), path


@respx.mock
async def test_start_trace_route_overrides_win(writes):
    nodes = mock_nodes(PE1_NODE, PE2_NODE)
    route = respx.post(rpc("set-oam-trace-route-by-calc")).mock(
        return_value=ok(out(**FULL_REGISTERED))
    )
    # A known alias is sent as its CAT label; the name as given.
    text = await call_tool_text(
        writes,
        "cnc_start_oam_trace_route",
        {**START_ARGS, "service_type": "sr-policy", "service_name": " mcp-other "},
    )
    assert not text.startswith("Error:")
    body = sent(route, 0)["input"]
    assert body["service-type"] == "policy" and body["service-name"] == "mcp-other"
    assert body["yang-path"] == POLICY_PATH
    # An unknown list is fine once service_type names it — sent verbatim.
    text = await call_tool_text(
        writes,
        "cnc_start_oam_trace_route",
        {**START_ARGS, "service_yang_path": "acme:things/thing=x%20y", "service_type": "acme"},
    )
    assert not text.startswith("Error:")
    body = sent(route, 1)["input"]
    assert body["service-type"] == "acme" and body["service-name"] == "x y"
    assert body["yang-path"] == "acme:things/thing=x%20y"
    assert nodes.call_count == 4


@respx.mock
async def test_start_trace_route_unresolvable_service_list_is_error_before_any_call(writes):
    nodes = mock_nodes(PE1_NODE, PE2_NODE)
    route = respx.post(rpc("set-oam-trace-route-by-calc")).mock(
        return_value=ok(out(**FULL_REGISTERED))
    )
    text = await call_tool_text(
        writes,
        "cnc_start_oam_trace_route",
        {**START_ARGS, "service_yang_path": "acme:things/thing=x"},
    )
    assert text.startswith("Error: cannot derive the service-type of 'acme:things/thing=x'")
    assert "service_type=" in text
    text = await call_tool_text(
        writes,
        "cnc_start_oam_trace_route",
        {
            **START_ARGS,
            "service_yang_path": "cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies",
        },
    )
    assert text.startswith(
        "Error: 'cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies' is not"
    )
    assert nodes.call_count == 0
    assert route.call_count == 0


@respx.mock
async def test_start_trace_route_missing_te_router_id_is_error_before_the_rpc(writes):
    nodes = mock_nodes(PE1_NODE, PE2_NO_ROUTER_ID)
    route = respx.post(rpc("set-oam-trace-route-by-calc")).mock(
        return_value=ok(out(**FULL_REGISTERED))
    )
    text = await call_tool_text(writes, "cnc_start_oam_trace_route", START_ARGS)
    assert text.startswith(f"Error: endpoint_uuid PE2 ('{PE2_UUID}') has no te_router_id")
    assert f"cnc_update_device(uuid='{PE2_UUID}', te_router_id=" in text
    assert nodes.call_count == 2
    assert route.call_count == 0


@respx.mock
async def test_start_trace_route_unknown_uuid_is_error_before_the_rpc(writes):
    nodes = mock_nodes(PE2_NODE)  # PE1's uuid is not in the inventory
    route = respx.post(rpc("set-oam-trace-route-by-calc")).mock(
        return_value=ok(out(**FULL_REGISTERED))
    )
    text = await call_tool_text(writes, "cnc_start_oam_trace_route", START_ARGS)
    assert text.startswith(f"Error: headend_uuid '{PE1_UUID}' is not an inventory device")
    assert "cnc_list_devices" in text
    assert nodes.call_count == 1  # the tail-end is not looked up after the head-end failed
    assert route.call_count == 0
    # An inventory filter that is not honoured (another device came back) is not a match.
    respx.post(NODES_QUERY_URL).mock(return_value=node_answer(PE2_NODE))
    text = await call_tool_text(writes, "cnc_start_oam_trace_route", START_ARGS)
    assert text.startswith(f"Error: headend_uuid '{PE1_UUID}' is not an inventory device")
    assert route.call_count == 0


@respx.mock
async def test_start_trace_route_node_lookup_http_error(writes):
    respx.post(NODES_QUERY_URL).mock(
        return_value=httpx.Response(403, json={"message": "Unauthorized request"})
    )
    route = respx.post(rpc("set-oam-trace-route-by-calc")).mock(
        return_value=ok(out(**FULL_REGISTERED))
    )
    text = await call_tool_text(writes, "cnc_start_oam_trace_route", START_ARGS)
    assert text.startswith("Error: API request failed with status 403.")
    assert route.call_count == 0


@respx.mock
async def test_start_trace_route_refuses_non_uuid_devices_before_any_call(writes):
    nodes = mock_nodes(PE1_NODE, PE2_NODE)
    route = respx.post(rpc("set-oam-trace-route-by-calc")).mock(
        return_value=ok(out(**FULL_REGISTERED))
    )
    text = await call_tool_text(
        writes, "cnc_start_oam_trace_route", {**START_ARGS, "headend_uuid": "PE1"}
    )
    assert text.startswith("Error: headend_uuid 'PE1' is not an inventory uuid")
    text = await call_tool_text(
        writes, "cnc_start_oam_trace_route", {**START_ARGS, "endpoint_uuid": "10.0.0.3"}
    )
    assert text.startswith("Error: endpoint_uuid '10.0.0.3' is not an inventory uuid")
    text = await call_tool_text(
        writes, "cnc_start_oam_trace_route", {**START_ARGS, "service_yang_path": " / "}
    )
    assert text.startswith("Error: yang_path is empty")
    assert nodes.call_count == 0
    assert route.call_count == 0


@respx.mock
@pytest.mark.parametrize("spelling", NON_CANONICAL_UUIDS)
async def test_start_trace_route_sends_every_uuid_spelling_canonical(writes, spelling):
    """Braces, urn:uuid: (either case), upper-case and 32-hex forms are accepted; the
    inventory is queried and the wire carries the canonical lower-case hyphenated uuid."""
    nodes = mock_nodes(PE1_NODE)
    route = respx.post(rpc("set-oam-trace-route-by-calc")).mock(
        return_value=ok(out(**FULL_REGISTERED))
    )
    text = await call_tool_text(
        writes,
        "cnc_start_oam_trace_route",
        {**START_ARGS, "headend_uuid": spelling, "endpoint_uuid": spelling},
    )
    assert not text.startswith("Error:")
    assert nodes.call_count == 2
    assert sent(nodes, 0)["filter"] == {"uuid": PE1_UUID}
    assert route.call_count == 1
    body = sent(route)["input"]
    assert body["head-end-node-uuid"] == PE1_UUID
    assert body["tail-end-node-uuid"] == PE1_UUID
    assert body["head-end-node-name"] == "PE1" and body["tail-end-node-name"] == "PE1"
    assert body["head-end-te-router-id"] == "10.0.0.1"
    # The spelling as given never reaches the wire.
    for call in (*nodes.calls, *route.calls):
        assert spelling.strip() not in call.request.content.decode()


@respx.mock
async def test_start_trace_route_terminal_answer_gives_no_wait_hint(writes):
    """The set RPC answering the verified no-uuid failure directly (status 5): the first
    line is the verdict, not "registered ... Next: wait"; the rendering's footer follows."""
    mock_nodes(PE1_NODE, PE2_NODE)
    route = respx.post(rpc("set-oam-trace-route-by-calc")).mock(
        return_value=ok(out(**FAILED_NO_UUID))
    )
    text = await call_tool_text(writes, "cnc_start_oam_trace_route", START_ARGS)
    assert route.call_count == 1
    assert not text.startswith("Error:")
    assert text.startswith(
        f"OAM trace route {QUERY_ID} was registered but FAILED immediately: {MPLS_OAM_TEXT}. "
        "Nothing to wait for"
    )
    first_line = text.split("\n", 1)[0]
    assert "cnc_wait_for_oam_trace_route" not in first_line
    assert "Next:" not in first_line
    assert f"# OAM trace route {QUERY_ID} — failed (5)" in text
    assert "A failed query is not re-run" in text


@respx.mock
async def test_start_trace_route_completed_answer_renders_the_paths(writes):
    mock_nodes(PE1_NODE, PE2_NODE)
    respx.post(rpc("set-oam-trace-route-by-calc")).mock(return_value=ok(out(**COMPLETED)))
    text = await call_tool_text(writes, "cnc_start_oam_trace_route", START_ARGS)
    assert text.startswith(
        f"OAM trace route {QUERY_ID} completed immediately: completed (4): Path trace completed."
    )
    assert "cnc_wait_for_oam_trace_route" not in text.split("\n", 1)[0]
    assert "## Paths (1)" in text


@respx.mock
async def test_start_trace_route_immediate_no_path_answer_is_rendered(writes):
    """EXTRAPOLATED: the set RPC answering the zero-path status 4 (live it was the short
    form's verdict, reached on polling) directly on registration: no wait hint, and the
    footer explains — and hedges — the zero-path verdict."""
    mock_nodes(PE1_NODE, PE2_NODE)
    respx.post(rpc("set-oam-trace-route-by-calc")).mock(return_value=ok(out(**NO_PATH)))
    text = await call_tool_text(writes, "cnc_start_oam_trace_route", START_ARGS)
    assert not text.startswith("Error:")
    assert text.startswith(
        f"OAM trace route {QUERY_ID} completed immediately with 0 paths: completed (4): "
        f"{NO_PATH_FOUND_MESSAGE}."
    )
    assert "cnc_wait_for_oam_trace_route" not in text.split("\n", 1)[0]
    assert "## Paths" not in text
    assert "Completed with ZERO paths" in text
    handle = json.loads(text[text.rindex("{") :])
    assert handle["status"] == 4 and handle["status_message"] == NO_PATH_FOUND_MESSAGE


@respx.mock
async def test_start_trace_route_without_query_id_is_an_error(writes):
    mock_nodes(PE1_NODE, PE2_NODE)
    respx.post(rpc("set-oam-trace-route-by-calc")).mock(
        return_value=ok(out(**{"response-result": "valid"}))
    )
    text = await call_tool_text(writes, "cnc_start_oam_trace_route", START_ARGS)
    assert text.startswith("Error: set-oam-trace-route-by-calc answered without a query-id")


@respx.mock
async def test_start_trace_route_response_result_error(writes):
    mock_nodes(PE1_NODE, PE2_NODE)
    respx.post(rpc("set-oam-trace-route-by-calc")).mock(return_value=ok(out(**RESULT_ERROR)))
    text = await call_tool_text(writes, "cnc_start_oam_trace_route", START_ARGS)
    assert text == (
        "Error: set-oam-trace-route-by-calc failed: response-result error: internal OAM error"
    )


@respx.mock
async def test_start_trace_route_empty_500_is_the_coe_hint_and_not_retried(writes):
    mock_nodes(PE1_NODE, PE2_NODE)
    route = respx.post(rpc("set-oam-trace-route-by-calc")).mock(return_value=EMPTY_500)
    text = await call_tool_text(writes, "cnc_start_oam_trace_route", START_ARGS)
    assert route.call_count == 1
    assert text == f"Error: {OAM_EMPTY_500_HINT}"


@respx.mock
async def test_start_then_wait_shows_the_no_uuid_failure_text(writes, fake_clock):
    """The verified sequence for a query registered without resolvable devices."""
    mock_nodes(PE1_NODE, PE2_NODE)
    respx.post(rpc("set-oam-trace-route-by-calc")).mock(return_value=ok(out(**REGISTERED)))
    mock_trace_route(ok(out(**FAILED_NO_UUID)))
    text = await call_tool_text(writes, "cnc_start_oam_trace_route", START_ARGS)
    assert text.startswith(f"OAM trace route registered: query-id {QUERY_ID}")
    text = await call_tool_text(writes, "cnc_wait_for_oam_trace_route", {"query_id": QUERY_ID})
    assert text.startswith(f"Trace route {QUERY_ID} FAILED after 0s: {MPLS_OAM_TEXT}")


@respx.mock
async def test_start_then_wait_shows_the_no_path_verdict(writes, fake_clock):
    """EXTRAPOLATED: the full form the tool sends -> status 4 with 0 paths. Live (2026-09-14,
    gNMI onboarded) the full form ended in status 5 (XR's 'mpls oam' text) and status 4 was
    the SHORT form's answer; this pairs the verified full-form echo with that verdict."""
    mock_nodes(PE1_NODE, PE2_NODE)
    start = respx.post(rpc("set-oam-trace-route-by-calc")).mock(
        return_value=ok(out(**FULL_REGISTERED))
    )
    mock_trace_route(ok(out(**RUNNING)), ok(out(**NO_PATH)))
    text = await call_tool_text(writes, "cnc_start_oam_trace_route", START_ARGS)
    assert sent(start) == FULL_START_BODY
    assert text.startswith(f"OAM trace route registered: query-id {QUERY_ID}")
    text = await call_tool_text(writes, "cnc_wait_for_oam_trace_route", {"query_id": QUERY_ID})
    assert text.startswith(
        f"Trace route {QUERY_ID} finished after 5s with 0 paths: completed (4): "
        f"{NO_PATH_FOUND_MESSAGE}"
    )


# --- cnc_reactivate_probe ------------------------------------------------------------


@respx.mock
async def test_reactivate_probe_success(writes):
    route = respx.post(REACTIVATE_URL).mock(return_value=ok(REACTIVATE_OK))
    text = await call_tool_text(writes, "cnc_reactivate_probe", {"service_id": L3VPN_ID})
    assert route.call_count == 1
    assert_json_post(route, {"serviceId": L3VPN_ID})
    assert text.startswith(
        f"Probe re-activation requested for {L3VPN_ID}: RESP_STATUS_SUCCESS (1)."
    )
    assert f"cnc_get_probe_status(service_id='{L3VPN_ID}')" in text


@respx.mock
async def test_reactivate_probe_unknown_status_is_an_error(writes):
    respx.post(REACTIVATE_URL).mock(return_value=ok(REACTIVATE_UNKNOWN))
    text = await call_tool_text(writes, "cnc_reactivate_probe", {"service_id": L3VPN_ID})
    assert text.startswith(
        f"Error: probe re-activation for '{L3VPN_ID}' was not confirmed: the probe manager "
        "answered RESP_STATUS_UNKNOWN (0) instead of RESP_STATUS_SUCCESS."
    )


@respx.mock
async def test_reactivate_probe_error_status_carries_the_platform_text(writes):
    respx.post(REACTIVATE_URL).mock(return_value=ok(REACTIVATE_ERROR))
    text = await call_tool_text(writes, "cnc_reactivate_probe", {"service_id": L3VPN_ID})
    assert text.startswith(
        f"Error: probe re-activation for '{L3VPN_ID}' failed: no probe to reactivate."
    )


@respx.mock
async def test_reactivate_probe_no_session_500_is_refused(writes):
    respx.post(REACTIVATE_URL).mock(return_value=NO_SESSION_500)
    text = await call_tool_text(writes, "cnc_reactivate_probe", {"service_id": L3VPN_ID})
    assert text.startswith(
        f"Error: probe re-activation for '{L3VPN_ID}' was refused by the Service Health probe "
        "manager: service has no active probe session."
    )


@respx.mock
async def test_reactivate_probe_go_404_means_not_installed(writes):
    respx.post(REACTIVATE_URL).mock(return_value=GO_404)
    text = await call_tool_text(writes, "cnc_reactivate_probe", {"service_id": L3VPN_ID})
    assert text == f"Error: {PROBEMGR_NOT_ROUTED_HINT}"


@respx.mock
async def test_reactivate_probe_http_error(writes):
    respx.post(REACTIVATE_URL).mock(
        return_value=httpx.Response(403, json={"message": "Unauthorized request"})
    )
    text = await call_tool_text(writes, "cnc_reactivate_probe", {"service_id": L3VPN_ID})
    assert text.startswith("Error: API request failed with status 403.")
