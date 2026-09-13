"""Physical-inventory (EMF RESTCONF) tools end-to-end through MCPServer (schema
validation included).

The module is registered directly (not through build_server) so the test does
not depend on tools/__init__.py's module list. All HTTP is mocked with respx.
Fixtures mirror the shapes verified live on Crosswork 7.2 (2026-09-13, platform
notes "EMF RESTCONF inventory"): the ``com.response-message`` envelope with
``nd.node`` objects carrying the verified ``nd.*`` field set (PE1 and P1 — the
recorded values are used where the notes record them, the rest are the lab's
shape), PE1's termination points (an IP CTP with ``tp.ip-tp``, a loopback CTP
and the port-layer FTP that XRd reports for the same interface), the EMPTY
envelope (``com.lastIndex -1``, no ``com.data``) and the verified ``rc.errors``
400 for an unknown ``ndFdn``. Every other ``rc.errors`` document is rendered by
the module itself (``emf_rejection``), so nothing here depends on how
``cnc_mcp.errors`` treats that spelling.
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
from cnc_mcp.tools import physical_inventory
from cnc_mcp.tools.physical_inventory import (
    LIFECYCLE_SYNCHRONIZED,
    LIST_LIMIT_MAX,
    SCAN_LIMIT,
    TP_TYPE_HELP,
    canonical_tp_type,
    collection_status_code,
    count_by,
    detail_lines,
    emf_body,
    emf_rejection,
    equipment_note,
    error_text,
    ip_prefix_of,
    label,
    name_from_unknown_node_message,
    node_fdn,
    node_line,
    node_name,
    node_name_from_fdn,
    node_selector,
    one_line,
    physical_count_text,
    rc_errors,
    rc_errors_text,
    software_of,
    strip_ns,
    tp_line,
    tp_scope,
    unknown_node_message,
)
from tests.conftest import BASE_URL, call_tool_text

EMF = f"{BASE_URL}/crosswork/inventory/restconf/data/v2"
NODE_URL = f"{EMF}/resource-physical:node"
TP_URL = f"{EMF}/resource-ems:termination-point"
CHASSIS_URL = f"{EMF}/resource-physical:chassis"
MODULE_URL = f"{EMF}/resource-physical:module"
EQUIPMENT_URL = f"{EMF}/resource-physical:equipment"

PE1_FDN = "MD=CISCO_EMS!ND=PE1"
P1_FDN = "MD=CISCO_EMS!ND=P1"
GI0_CTP_FDN = "MD=CISCO_EMS!ND=PE1!CTP=name=GigabitEthernet0/0/0/0;lr=lr-ip;ADDRESS=10.1.1.1"
GI0_FTP_FDN = "MD=CISCO_EMS!ND=PE1!FTP=name=GigabitEthernet0/0/0/0;lr=lr-gigabit-ethernet"
LO0_CTP_FDN = "MD=CISCO_EMS!ND=PE1!CTP=name=Loopback0;lr=lr-ip;ADDRESS=10.0.0.1"

# Verified nd.* field set of resource-physical:node (the notes record nd.fdn, nd.name,
# nd.lifecycle-state, nd.communication-state "Reachable", nd.software-type "IOS XR" and
# the collection-status XML form verbatim; other values are the lab's shape).
NODE_PE1 = {
    "nd.fdn": PE1_FDN,
    "nd.name": "PE1",
    "nd.management-address": "198.18.140.11",
    "nd.lifecycle-state": "MANAGED_AND_SYNCHRONIZED",
    "nd.communication-state": "Reachable",
    "nd.collection-status": '<status><general code="SUCCESS"/></status>',
    "nd.collection-time": "2026-09-13T08:12:41.117Z",
    "nd.creation-time": "2026-09-12T14:03:27.502Z",
    "nd.last-boot-time": "2026-09-12T13:40:05.000Z",
    "nd.description": (
        "Cisco IOS XR Software, Version 24.3.1 LNT\r\n"
        "Copyright (c) 2013-2024 by Cisco Systems, Inc."
    ),
    "nd.product-family": "Routers",
    "nd.product-series": "Cisco XRd Virtual Routers",
    "nd.product-type": "Cisco XRd Control Plane",
    "nd.product-vendor": "Cisco Systems",
    "nd.software-type": "IOS XR",
    "nd.software-version": "24.3.1",
    "nd.sys-object-id": "1.3.6.1.4.1.9.1.2919",
    "nd.sys-up-time": "0d18h32m16s",
    "nd.instanceId": 1023,
    "nd.uuid": "940d04d0-d72b-48cc-8f8e-a5510ec118f7",
    "nd.cluster-count": 0,
    "nd.satellite-count": 0,
}
NODE_P1 = {
    **NODE_PE1,
    "nd.fdn": P1_FDN,
    "nd.name": "P1",
    "nd.management-address": "198.18.140.12",
    "nd.lifecycle-state": "MANAGED_BUT_NEVERSYNCHRONIZED",
    "nd.communication-state": "Unreachable",
    "nd.collection-status": '<status><general code="FAILURE"/></status>',
    "nd.instanceId": 1024,
    "nd.uuid": "0b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e",
}

# Verified tp.* field set of resource-ems:termination-point (the notes record the CTP
# fdn form, tp.admin-state "com:admin-state-up", tp.type "CTP" and the tp.ip-tp keys).
TP_GI0_CTP = {
    "tp.fdn": GI0_CTP_FDN,
    "tp.discovered-name": "GigabitEthernet0/0/0/0",
    "tp.node-name": "PE1",
    "tp.description": "to P1 Gi0/0/0/0",
    "tp.admin-state": "com:admin-state-up",
    "tp.oper-state": "com:oper-state-up",
    "tp.layer-rate": "lr:lr-ip",
    "tp.type": "CTP",
    "tp.is-edge-point": True,
    "tp.duplex-mode": "FullDuplex",
    "tp.ip-tp": {
        "tp.ip-address": ["10.1.1.1"],
        "tp.subnet-mask": 30,
        "tp.ip-address-prefix": "10.1.1.1/30",
        "tp.cast-type": "IP_V4",
    },
}
TP_LO0_CTP = {
    "tp.fdn": LO0_CTP_FDN,
    "tp.discovered-name": "Loopback0",
    "tp.node-name": "PE1",
    "tp.admin-state": "com:admin-state-up",
    "tp.oper-state": "com:oper-state-up",
    "tp.layer-rate": "lr:lr-ip",
    "tp.type": "CTP",
    "tp.is-edge-point": True,
    "tp.ip-tp": {
        "tp.ip-address": ["10.0.0.1"],
        "tp.subnet-mask": 32,
        "tp.ip-address-prefix": "10.0.0.1/32",
        "tp.cast-type": "IP_V4",
    },
}
TP_GI0_FTP = {
    "tp.fdn": GI0_FTP_FDN,
    "tp.discovered-name": "GigabitEthernet0/0/0/0",
    "tp.node-name": "PE1",
    "tp.description": "to P1 Gi0/0/0/0",
    "tp.admin-state": "com:admin-state-up",
    "tp.oper-state": "com:oper-state-up",
    "tp.layer-rate": "lr:lr-gigabit-ethernet",
    "tp.type": "FTP",
    "tp.is-edge-point": False,
    "tp.duplex-mode": "FullDuplex",
}


def envelope(key: str, items: list[dict], first: int = 0, iterator: int | None = 0) -> dict:
    """A com.response-message page: lastIndex = first + len - 1, or the EMPTY shape."""
    if not items:
        return EMPTY
    header = {"com.firstIndex": first, "com.lastIndex": first + len(items) - 1}
    if iterator is not None:
        header["com.iteratorId"] = iterator
    return {"com.response-message": {"com.header": header, "com.data": {key: items}}}


# Verified empty answer: lastIndex -1 and NO com.data (unknown name/fdn; chassis, module
# and equipment on XRd; a page past the end).
EMPTY = {
    "com.response-message": {
        "com.header": {"com.firstIndex": 0, "com.lastIndex": -1, "com.iteratorId": 0}
    }
}
NODES = envelope("nd.node", [NODE_PE1, NODE_P1])
NODE_PE1_ONLY = envelope("nd.node", [NODE_PE1])
PE1_TPS = envelope("tp.termination-point", [TP_GI0_CTP, TP_LO0_CTP, TP_GI0_FTP])
PE1_CTPS = envelope("tp.termination-point", [TP_GI0_CTP, TP_LO0_CTP])
GI0_CTP_ONLY = envelope("tp.termination-point", [TP_GI0_CTP])
# Verified live: an unknown ndFdn answers 400 with the EMF "rc.errors" spelling.
UNKNOWN_NODE_400 = {
    "rc.errors": {
        "error": {
            "error-tag": "invalid-value",
            "error-app-tag": "FW.0089",
            "error-message": "Cannot find device with Node Name: nope",
        }
    }
}
XML_BODY = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<ns14:response-message xmlns:ns14="urn:cisco:params:xml:ns:yang:nrf-common:v1">'
    "<ns14:header><ns14:firstIndex>0</ns14:firstIndex></ns14:header></ns14:response-message>"
)

READ_TOOLS = {
    "cnc_list_ems_nodes",
    "cnc_get_ems_node",
    "cnc_list_ems_interfaces",
    "cnc_get_ems_interface",
    "cnc_get_ems_inventory_summary",
}


def build(settings: Settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    physical_inventory.register(mcp, ctx)
    return mcp


def xml_response() -> httpx.Response:
    return httpx.Response(200, text=XML_BODY, headers={"Content-Type": "application/xml"})


def assert_emf_request(request: httpx.Request, **params: str) -> None:
    """The verified dialect: exactly Accept: application/json and the given query."""
    assert request.method == "GET"
    assert request.headers.get_list("Accept") == ["application/json"]
    assert dict(request.url.params) == params


# --- registration / annotations ---------------------------------------------


async def test_all_tools_are_read_only_and_registered_without_writes(make_settings):
    names = {t.name for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert names == READ_TOOLS
    tools = {t.name: t for t in await build(make_settings(enable_writes=True)).list_tools()}
    assert set(tools) == READ_TOOLS
    for name in READ_TOOLS:
        assert tools[name].annotations.read_only_hint is True, name
        assert tools[name].annotations.idempotent_hint is True, name
        assert tools[name].annotations.destructive_hint is False, name


async def test_inputs_are_flat_parameters(make_settings):
    tools = {t.name: t for t in await build(make_settings()).list_tools()}
    schema = tools["cnc_list_ems_interfaces"].input_schema
    expected = {"node", "fdn", "tp_type", "limit", "offset", "response_format"}
    assert set(schema["properties"]) == expected
    # every argument is a top-level scalar; only the shared ResponseFormat enum is a $ref
    flat = {k: v for k, v in schema["properties"].items() if k != "response_format"}
    assert "$ref" not in json.dumps(flat)
    assert tools["cnc_get_ems_interface"].input_schema["required"] == ["fdn"]
    assert tools["cnc_get_ems_inventory_summary"].input_schema.get("properties", {}) == {}


# --- pure helpers ------------------------------------------------------------


def test_node_fdn_grammar_and_parsing():
    assert node_fdn("PE1") == "MD=CISCO_EMS!ND=PE1"
    assert node_fdn("  PE1 ") == "MD=CISCO_EMS!ND=PE1"
    assert node_name_from_fdn("MD=CISCO_EMS!ND=PE1") == "PE1"
    assert node_name_from_fdn(GI0_CTP_FDN) == "PE1"
    assert node_name_from_fdn("MD=CISCO_EMS") is None
    assert node_name_from_fdn(None) is None


def test_label_and_namespace_stripping():
    assert label("nd.management-address") == "management-address"
    assert label("tp.ip-address-prefix") == "ip-address-prefix"
    assert label(".startIndex") == ".startIndex"
    assert label("uuid") == "uuid"
    assert strip_ns("com:admin-state-up") == "admin-state-up"
    assert strip_ns("lr:lr-ip") == "lr-ip"
    assert strip_ns("ns22:lr-optical-channel") == "lr-optical-channel"
    assert strip_ns("FullDuplex") == "FullDuplex"
    assert strip_ns(None) is None
    assert strip_ns(30) == 30


def test_one_line_and_collection_status():
    assert one_line("a\r\nb   c") == "a b c"
    assert one_line(None) == "-"
    assert one_line(True) == "true"
    assert one_line("") == "-"
    assert collection_status_code('<status><general code="SUCCESS"/></status>') == "SUCCESS"
    assert collection_status_code("<status>collection pending</status>") == (
        "<status>collection pending</status>"
    )
    assert collection_status_code(None) == "-"
    assert collection_status_code("   ") == "-"


def test_node_name_falls_back_to_fdtn_name_then_fdn():
    assert node_name(NODE_PE1) == "PE1"
    assert node_name({"fdtn.name": "Rack 0", "nd.fdn": "MD=CISCO_EMS!ND=X"}) == "Rack 0"
    assert node_name({"nd.fdn": "MD=CISCO_EMS!ND=X"}) == "X"
    assert node_name({}) == "?"


def test_software_of_and_node_line():
    assert software_of(NODE_PE1) == "IOS XR 24.3.1"
    assert software_of({"nd.software-type": "IOS XR"}) == "IOS XR ?"
    assert software_of({}) == "? ?"
    line = node_line(NODE_PE1)
    assert line == (
        "- **PE1** 198.18.140.11 — MANAGED_AND_SYNCHRONIZED, Reachable; IOS XR 24.3.1; "
        "Cisco XRd Control Plane; up 0d18h32m16s; collected 2026-09-13T08:12:41.117Z; "
        "fdn MD=CISCO_EMS!ND=PE1"
    )


def test_ip_prefix_of_and_tp_line():
    assert ip_prefix_of(TP_GI0_CTP) == "10.1.1.1/30"
    assert ip_prefix_of(TP_GI0_FTP) is None
    assert ip_prefix_of({"tp.ip-tp": {"tp.ip-address": ["10.9.9.9"]}}) == "10.9.9.9"
    assert tp_line(TP_GI0_CTP) == (
        "- **GigabitEthernet0/0/0/0** CTP lr-ip; admin-state-up / oper-state-up; "
        'ip 10.1.1.1/30; FullDuplex; "to P1 Gi0/0/0/0"; fdn ' + GI0_CTP_FDN
    )
    assert tp_line(TP_GI0_FTP) == (
        "- **GigabitEthernet0/0/0/0** FTP lr-gigabit-ethernet; admin-state-up / "
        'oper-state-up; FullDuplex; "to P1 Gi0/0/0/0"; fdn ' + GI0_FTP_FDN
    )
    assert tp_line(TP_LO0_CTP) == (
        "- **Loopback0** CTP lr-ip; admin-state-up / oper-state-up; ip 10.0.0.1/32; fdn "
        + LO0_CTP_FDN
    )


def test_detail_lines_render_every_field_with_prefixes_dropped():
    lines = detail_lines(NODE_PE1)
    assert "- collection-status: SUCCESS" in lines
    assert "- management-address: 198.18.140.11" in lines
    assert (
        "- description: Cisco IOS XR Software, Version 24.3.1 LNT Copyright (c) 2013-2024 by "
        "Cisco Systems, Inc." in lines
    )
    assert "- cluster-count: 0" in lines
    assert len(lines) == len(NODE_PE1)
    tp = detail_lines(TP_GI0_CTP)
    assert "- admin-state: admin-state-up" in tp
    assert "- layer-rate: lr-ip" in tp
    assert "- is-edge-point: true" in tp
    assert "- ip-tp:" in tp
    assert "  - ip-address: 10.1.1.1" in tp
    assert "  - ip-address-prefix: 10.1.1.1/30" in tp
    nested = detail_lines(
        {
            "nd.equipment-list": {"eq.equipment": [{"eq.fdn": "x"}]},
            "nd.empty": [],
            "nd.deep": {"a": {"b": {"c": 1}}},
        }
    )
    assert "- equipment-list:" in nested
    assert "  - equipment: 1 entries (response_format='json' has them)" in nested
    assert "- empty: (none)" in nested
    assert '    - b: {"c": 1}' in nested


def test_count_by_sorts_by_count_then_name_and_counts_missing_as_unknown():
    counts = count_by(
        [NODE_PE1, NODE_P1, {**NODE_PE1, "nd.lifecycle-state": None}],
        lambda n: n.get("nd.lifecycle-state"),
    )
    assert list(counts.items()) == [
        ("?", 1),
        ("MANAGED_AND_SYNCHRONIZED", 1),
        ("MANAGED_BUT_NEVERSYNCHRONIZED", 1),
    ]
    assert count_by([], lambda n: n) == {}


def test_unknown_node_message_matches_the_verified_rc_errors_document():
    message = unknown_node_message(UNKNOWN_NODE_400)
    assert message == "Cannot find device with Node Name: nope"
    assert name_from_unknown_node_message(message) == "nope"
    # error as a list, matched on the app tag alone
    as_list = {"rc.errors": {"error": [{"error-app-tag": "fw.0089", "error-message": "gone"}]}}
    assert unknown_node_message(as_list) == "gone"
    # matched on the message alone
    by_text = {"rc.errors": {"error": {"error-message": "cannot find device with node name: x"}}}
    assert unknown_node_message(by_text) == "cannot find device with node name: x"
    assert unknown_node_message({"rc.errors": {"error": {"error-tag": "invalid-value"}}}) is None
    assert unknown_node_message({"errors": {"error": [{"error-message": "Cannot find"}]}}) is None
    assert unknown_node_message("nope") is None
    assert name_from_unknown_node_message("no colon here") is None


def test_rc_errors_reads_the_emf_document_shape():
    assert rc_errors(UNKNOWN_NODE_400) == [UNKNOWN_NODE_400["rc.errors"]["error"]]
    # a list-valued error is accepted; non-dict entries are skipped
    as_list = {"rc.errors": {"error": [{"error-tag": "a"}, "junk", {"error-tag": "b"}]}}
    assert rc_errors(as_list) == [{"error-tag": "a"}, {"error-tag": "b"}]
    for not_rc in (
        None,
        "x",
        {},
        {"rc.errors": "text"},
        {"rc.errors": {"error": "text"}},
        {"errors": {"error": [{"error-tag": "unknown-element"}]}},  # the NBI spelling
        {"ietf-restconf:errors": {"error": [{"error-tag": "malformed-message"}]}},
    ):
        assert rc_errors(not_rc) == [], not_rc


def test_rc_errors_text_and_emf_rejection_render_tag_app_tag_and_message():
    assert rc_errors_text(rc_errors(UNKNOWN_NODE_400)) == (
        "invalid-value [FW.0089]: Cannot find device with Node Name: nope"
    )
    assert rc_errors_text([{"error-tag": "invalid-value", "error-message": "bad"}]) == (
        "invalid-value: bad"
    )
    assert rc_errors_text([{"error-message": "x"}, {"error-tag": "t", "error-app-tag": "A.1"}]) == (
        "error: x; t [A.1]"
    )
    assert rc_errors_text([{}]) == "error"
    # the verified notification-service 500 shape
    err = emf_rejection(
        500,
        [
            {
                "error-tag": "operation-failed",
                "error-app-tag": "NOT.0029",
                "error-message": "The endpoint is not reachable.",
            }
        ],
    )
    text = str(err)
    assert text.startswith(
        "EMF RESTCONF rejected the request (HTTP 500): operation-failed [NOT.0029]: The "
        "endpoint is not reachable. The error-tag"
    )  # the message's own full stop is not doubled
    assert "ndFdn=" in text and "type=CTP|FTP|PTP" in text and "MD=CISCO_EMS!ND=<node>" in text
    # never the topology-NBI advice about YANG key types
    assert "router-id" not in text and "YANG" not in text


def test_error_text_drops_the_prefix():
    assert error_text(PlatformError("boom")) == "boom"
    assert error_text(httpx.TimeoutException("t")).startswith("Request to the platform timed out")


def test_emf_body_classifies_responses():
    ok = httpx.Response(200, json=EMPTY, request=httpx.Request("GET", NODE_URL))
    assert emf_body(ok) == EMPTY
    unknown = httpx.Response(400, json=UNKNOWN_NODE_400, request=httpx.Request("GET", TP_URL))
    with pytest.raises(PlatformError, match="the EMF has no node 'PE9' \\(list with"):
        emf_body(unknown, "PE9")
    with pytest.raises(PlatformError, match="the EMF has no node 'nope'"):
        emf_body(unknown)
    # any other rc.errors document is rendered HERE (not by errors.http_error, whose
    # invalid-value hint talks about the topology NBI's TE router-ids)
    other_400 = httpx.Response(
        400,
        json={
            "rc.errors": {
                "error": {
                    "error-tag": "invalid-value",
                    "error-app-tag": "FW.0001",
                    "error-message": "Unsupported filter attribute: foo",
                }
            }
        },
        request=httpx.Request("GET", TP_URL),
    )
    with pytest.raises(PlatformError) as info:
        emf_body(other_400)
    assert str(info.value).startswith(
        "EMF RESTCONF rejected the request (HTTP 400): invalid-value [FW.0001]: Unsupported "
        "filter attribute: foo. "
    )
    assert "router-id" not in str(info.value) and "API request failed" not in str(info.value)
    rc_500 = httpx.Response(
        500,
        json={"rc.errors": {"error": [{"error-tag": "operation-failed", "error-message": "x"}]}},
        request=httpx.Request("GET", TP_URL),
    )
    with pytest.raises(PlatformError, match=r"^EMF RESTCONF rejected the request \(HTTP 500\): "):
        emf_body(rc_500)
    # non-rc.errors failures keep the generic classification
    with pytest.raises(PlatformError, match="status 403"):
        emf_body(httpx.Response(403, text="Unauthorized", request=httpx.Request("GET", TP_URL)))
    with pytest.raises(PlatformError, match="status 500.*NATS"):
        emf_body(
            httpx.Response(
                500, json={"error": "NATS request failed"}, request=httpx.Request("GET", TP_URL)
            )
        )
    with pytest.raises(PlatformError, match="Accept: application/json"):
        emf_body(xml_response())


def test_selectors_and_tp_type():
    assert node_selector("PE1", None) == {"name": "PE1"}
    assert node_selector(None, " MD=CISCO_EMS!ND=PE1 ") == {"fdn": "MD=CISCO_EMS!ND=PE1"}
    with pytest.raises(PlatformError, match="exactly one"):
        node_selector(None, None)
    with pytest.raises(PlatformError, match="exactly one"):
        node_selector("PE1", "MD=CISCO_EMS!ND=PE1")
    assert tp_scope("PE1", None) == ("MD=CISCO_EMS!ND=PE1", "PE1")
    assert tp_scope(None, "MD=CISCO_EMS!ND=P1") == ("MD=CISCO_EMS!ND=P1", "P1")
    assert tp_scope(None, "garbage") == ("garbage", "garbage")
    assert tp_scope(None, None) == (None, None)
    with pytest.raises(PlatformError, match="at most one"):
        tp_scope("PE1", "MD=CISCO_EMS!ND=PE1")
    assert canonical_tp_type("ctp") == "CTP"
    assert canonical_tp_type(" FTP ") == "FTP"
    assert canonical_tp_type(None) is None
    assert canonical_tp_type("  ") is None
    with pytest.raises(PlatformError, match="Unknown termination-point type 'port'"):
        canonical_tp_type("port")


def test_equipment_note_only_when_everything_is_empty():
    assert "XRd" in equipment_note(0, 0, 0)
    assert equipment_note(1, 0, 0) == ""
    assert equipment_note(0, 0, None) == ""  # an unavailable collection proves nothing


def test_physical_count_text_reports_a_full_first_page_as_a_lower_bound():
    assert physical_count_text(0, False) == "0"
    assert physical_count_text(37, False) == "37"
    assert physical_count_text(100, True) == "100+"
    assert physical_count_text(None, False) == "?"


# --- cnc_list_ems_nodes ------------------------------------------------------


@respx.mock
async def test_list_ems_nodes_sends_the_verified_request_and_renders_markdown(settings):
    route = respx.get(NODE_URL).mock(return_value=httpx.Response(200, json=NODES))
    text = await call_tool_text(build(settings), "cnc_list_ems_nodes", {})
    assert_emf_request(route.calls[0].request, **{".startIndex": "0", ".maxCount": "50"})
    assert text.startswith("# EMF nodes (2 shown from offset 0)")
    assert node_line(NODE_PE1) in text
    assert "- **P1** 198.18.140.12 — MANAGED_BUT_NEVERSYNCHRONIZED, Unreachable;" in text
    assert "More available" not in text  # 2 < 50


@respx.mock
async def test_list_ems_nodes_name_filter_and_json_keeps_raw_keys(settings):
    route = respx.get(NODE_URL).mock(return_value=httpx.Response(200, json=NODE_PE1_ONLY))
    text = await call_tool_text(
        build(settings),
        "cnc_list_ems_nodes",
        {"name": "PE1", "limit": 10, "offset": 0, "response_format": "json"},
    )
    assert_emf_request(
        route.calls[0].request, **{".startIndex": "0", ".maxCount": "10", "name": "PE1"}
    )
    data = json.loads(text)
    assert data["count"] == 1 and data["items"] == [NODE_PE1]
    assert data["items"][0]["nd.management-address"] == "198.18.140.11"
    assert data["has_more"] is False and data["next_offset"] is None
    assert data["first_index"] == 0 and data["last_index"] == 0
    assert data["start_index"] == 0 and data["max_count"] == 10
    assert data["total"] is None


@respx.mock
async def test_list_ems_nodes_has_more_follows_last_index_vs_limit(settings):
    route = respx.get(NODE_URL).mock(return_value=httpx.Response(200, json=NODES))
    text = await call_tool_text(
        build(settings), "cnc_list_ems_nodes", {"limit": 2, "response_format": "json"}
    )
    assert_emf_request(route.calls[0].request, **{".startIndex": "0", ".maxCount": "2"})
    data = json.loads(text)
    assert data["last_index"] == 1 and data["has_more"] is True
    assert data["next_offset"] == 2 and data["next_start_index"] == 2
    text = await call_tool_text(build(settings), "cnc_list_ems_nodes", {"limit": 2})
    assert "More available: repeat with offset=2." in text


@respx.mock
async def test_list_ems_nodes_offset_is_sent_as_start_index(settings):
    route = respx.get(NODE_URL).mock(return_value=httpx.Response(200, json=EMPTY))
    text = await call_tool_text(build(settings), "cnc_list_ems_nodes", {"offset": 100, "limit": 25})
    assert_emf_request(route.calls[0].request, **{".startIndex": "100", ".maxCount": "25"})
    assert text == "The EMF reports no nodes at offset 100."


@respx.mock
async def test_list_ems_nodes_limit_above_100_walks_pages(make_settings):
    settings = make_settings(max_response_chars=10_000_000)
    page0 = envelope("nd.node", [dict(NODE_PE1, **{"nd.name": f"N{i}"}) for i in range(100)])
    page1 = envelope("nd.node", [NODE_P1], first=100)
    route = respx.get(NODE_URL).mock(
        side_effect=[httpx.Response(200, json=page0), httpx.Response(200, json=page1)]
    )
    text = await call_tool_text(
        build(settings), "cnc_list_ems_nodes", {"limit": 150, "response_format": "json"}
    )
    assert route.call_count == 2
    assert_emf_request(route.calls[0].request, **{".startIndex": "0", ".maxCount": "100"})
    assert_emf_request(route.calls[1].request, **{".startIndex": "100", ".maxCount": "50"})
    data = json.loads(text)
    assert data["count"] == 101 and data["items"][-1]["nd.name"] == "P1"
    assert data["has_more"] is False and data["next_offset"] is None
    assert data["first_index"] == 0 and data["last_index"] == 100


@respx.mock
async def test_list_ems_nodes_exactly_full_walk_reports_has_more(make_settings):
    settings = make_settings(max_response_chars=10_000_000)
    page0 = envelope("nd.node", [NODE_PE1] * 100)
    page1 = envelope("nd.node", [NODE_P1] * 100, first=100)
    route = respx.get(NODE_URL).mock(
        side_effect=[httpx.Response(200, json=page0), httpx.Response(200, json=page1)]
    )
    text = await call_tool_text(
        build(settings), "cnc_list_ems_nodes", {"limit": 200, "response_format": "json"}
    )
    assert route.call_count == 2
    data = json.loads(text)
    assert data["count"] == 200 and data["has_more"] is True and data["next_offset"] == 200


@respx.mock
async def test_list_ems_nodes_unknown_name_is_an_empty_answer_not_an_error(settings):
    route = respx.get(NODE_URL).mock(return_value=httpx.Response(200, json=EMPTY))
    text = await call_tool_text(build(settings), "cnc_list_ems_nodes", {"name": "nope"})
    assert route.calls[0].request.url.params["name"] == "nope"
    assert not text.startswith("Error:")
    assert text.startswith("The EMF has no node named 'nope'") and "cnc_list_devices" in text
    text = await call_tool_text(build(settings), "cnc_list_ems_nodes", {})
    assert text.startswith("The EMF reports no nodes:")


@respx.mock
async def test_list_ems_nodes_xml_fallback_is_explained(settings):
    respx.get(NODE_URL).mock(return_value=xml_response())
    text = await call_tool_text(build(settings), "cnc_list_ems_nodes", {})
    assert text.startswith("Error: Crosswork answered this EMF RESTCONF request with XML")
    assert "Accept: application/json" in text


@respx.mock
async def test_list_ems_nodes_http_error_is_string(make_settings):
    respx.get(NODE_URL).mock(return_value=httpx.Response(403, text="Unauthorized request"))
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_list_ems_nodes", {})
    assert text.startswith("Error:") and "403" in text


async def test_list_ems_nodes_schema_bounds(settings):
    with pytest.raises(ToolError, match="limit"):
        await call_tool_text(build(settings), "cnc_list_ems_nodes", {"limit": LIST_LIMIT_MAX + 1})
    with pytest.raises(ToolError, match="offset"):
        await call_tool_text(build(settings), "cnc_list_ems_nodes", {"offset": -1})


# --- cnc_get_ems_node --------------------------------------------------------


@respx.mock
async def test_get_ems_node_by_name_renders_every_field(settings):
    route = respx.get(NODE_URL).mock(return_value=httpx.Response(200, json=NODE_PE1_ONLY))
    text = await call_tool_text(build(settings), "cnc_get_ems_node", {"name": "PE1"})
    assert_emf_request(route.calls[0].request, name="PE1")
    assert text.startswith("# EMF node PE1 (MD=CISCO_EMS!ND=PE1)\n")
    for expected in (
        "- name: PE1",
        "- management-address: 198.18.140.11",
        "- lifecycle-state: MANAGED_AND_SYNCHRONIZED",
        "- communication-state: Reachable",
        "- collection-status: SUCCESS",
        "- collection-time: 2026-09-13T08:12:41.117Z",
        "- creation-time: 2026-09-12T14:03:27.502Z",
        "- last-boot-time: 2026-09-12T13:40:05.000Z",
        "- product-family: Routers",
        "- product-series: Cisco XRd Virtual Routers",
        "- product-type: Cisco XRd Control Plane",
        "- product-vendor: Cisco Systems",
        "- software-type: IOS XR",
        "- software-version: 24.3.1",
        "- sys-object-id: 1.3.6.1.4.1.9.1.2919",
        "- sys-up-time: 0d18h32m16s",
        "- uuid: 940d04d0-d72b-48cc-8f8e-a5510ec118f7",
    ):
        assert expected in text, expected
    assert "- description: Cisco IOS XR Software, Version 24.3.1 LNT Copyright" in text
    assert "nd." not in text.replace("MD=CISCO_EMS!ND=PE1", "")  # labels drop the prefix


@respx.mock
async def test_get_ems_node_by_fdn_json_is_the_raw_object(settings):
    route = respx.get(NODE_URL).mock(return_value=httpx.Response(200, json=NODE_PE1_ONLY))
    text = await call_tool_text(
        build(settings), "cnc_get_ems_node", {"fdn": PE1_FDN, "response_format": "json"}
    )
    assert_emf_request(route.calls[0].request, fdn=PE1_FDN)
    assert json.loads(text) == NODE_PE1


@respx.mock
async def test_get_ems_node_collection_status_without_code_shows_raw_text(settings):
    node = {**NODE_PE1, "nd.collection-status": "<status>pending</status>"}
    respx.get(NODE_URL).mock(return_value=httpx.Response(200, json=envelope("nd.node", [node])))
    text = await call_tool_text(build(settings), "cnc_get_ems_node", {"name": "PE1"})
    assert "- collection-status: <status>pending</status>" in text


@respx.mock
async def test_get_ems_node_unknown_is_not_found(settings):
    route = respx.get(NODE_URL).mock(return_value=httpx.Response(200, json=EMPTY))
    text = await call_tool_text(build(settings), "cnc_get_ems_node", {"name": "nope"})
    assert text == "Error: the EMF has no node 'nope' (list with cnc_list_ems_nodes)"
    text = await call_tool_text(build(settings), "cnc_get_ems_node", {"fdn": "MD=CISCO_EMS!ND=x"})
    assert text == "Error: the EMF has no node 'MD=CISCO_EMS!ND=x' (list with cnc_list_ems_nodes)"
    assert route.call_count == 2


@respx.mock
async def test_get_ems_node_selector_errors_before_any_request(settings):
    route = respx.get(NODE_URL).mock(return_value=httpx.Response(200, json=NODE_PE1_ONLY))
    text = await call_tool_text(build(settings), "cnc_get_ems_node", {})
    assert text.startswith("Error: Pass exactly one of 'name'")
    text = await call_tool_text(
        build(settings), "cnc_get_ems_node", {"name": "PE1", "fdn": PE1_FDN}
    )
    assert text.startswith("Error: Pass exactly one of 'name'")
    assert route.call_count == 0


@respx.mock
async def test_get_ems_node_ambiguous_name_lists_fdns(settings):
    respx.get(NODE_URL).mock(return_value=httpx.Response(200, json=NODES))
    text = await call_tool_text(build(settings), "cnc_get_ems_node", {"name": "PE1"})
    assert text.startswith("Error: name 'PE1' matches 2 EMF nodes (MD=CISCO_EMS!ND=PE1, ")
    assert "fdn='<nd.fdn>'" in text


@respx.mock
async def test_get_ems_node_xml_fallback_and_http_error(make_settings):
    respx.get(NODE_URL).mock(return_value=xml_response())
    text = await call_tool_text(build(make_settings()), "cnc_get_ems_node", {"name": "PE1"})
    assert text.startswith("Error:") and "Accept: application/json" in text
    respx.get(NODE_URL).mock(return_value=httpx.Response(500, json={"error": "boom"}))
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_ems_node", {"name": "PE1"}
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_list_ems_interfaces -------------------------------------------------


@respx.mock
async def test_list_ems_interfaces_by_node_name_builds_the_fdn(settings):
    route = respx.get(TP_URL).mock(return_value=httpx.Response(200, json=PE1_TPS))
    text = await call_tool_text(build(settings), "cnc_list_ems_interfaces", {"node": "PE1"})
    assert_emf_request(
        route.calls[0].request,
        **{".startIndex": "0", ".maxCount": "50", "ndFdn": "MD=CISCO_EMS!ND=PE1"},
    )
    assert text.startswith("# Termination points of PE1 (3 shown from offset 0)")
    assert tp_line(TP_GI0_CTP) in text
    assert tp_line(TP_LO0_CTP) in text
    assert tp_line(TP_GI0_FTP) in text
    assert "com:" not in text  # markdown strips the YANG prefixes
    assert "More available" not in text


@respx.mock
async def test_list_ems_interfaces_by_fdn_with_type_filter_and_json(settings):
    route = respx.get(TP_URL).mock(return_value=httpx.Response(200, json=PE1_CTPS))
    text = await call_tool_text(
        build(settings),
        "cnc_list_ems_interfaces",
        {"fdn": PE1_FDN, "tp_type": "ctp", "limit": 20, "offset": 40, "response_format": "json"},
    )
    assert_emf_request(
        route.calls[0].request,
        **{".startIndex": "40", ".maxCount": "20", "ndFdn": PE1_FDN, "type": "CTP"},
    )
    data = json.loads(text)
    assert data["count"] == 2 and data["items"] == [TP_GI0_CTP, TP_LO0_CTP]
    assert data["items"][0]["tp.admin-state"] == "com:admin-state-up"  # JSON stays raw
    assert data["items"][0]["tp.ip-tp"]["tp.ip-address-prefix"] == "10.1.1.1/30"
    assert data["has_more"] is False and data["start_index"] == 40 and data["max_count"] == 20


@respx.mock
async def test_list_ems_interfaces_has_more_from_last_index_vs_limit(settings):
    respx.get(TP_URL).mock(return_value=httpx.Response(200, json=PE1_TPS))
    text = await call_tool_text(
        build(settings), "cnc_list_ems_interfaces", {"node": "PE1", "limit": 3}
    )
    assert "More available: repeat with offset=3." in text
    text = await call_tool_text(
        build(settings),
        "cnc_list_ems_interfaces",
        {"node": "PE1", "limit": 3, "response_format": "json"},
    )
    data = json.loads(text)
    assert data["last_index"] == 2 and data["has_more"] is True and data["next_offset"] == 3


@respx.mock
async def test_list_ems_interfaces_unknown_node_400_is_not_found(settings):
    route = respx.get(TP_URL).mock(return_value=httpx.Response(400, json=UNKNOWN_NODE_400))
    text = await call_tool_text(build(settings), "cnc_list_ems_interfaces", {"node": "nope"})
    assert text == "Error: the EMF has no node 'nope' (list with cnc_list_ems_nodes)"
    assert route.calls[0].request.url.params["ndFdn"] == "MD=CISCO_EMS!ND=nope"
    # by fdn: the ND= part names the node
    text = await call_tool_text(
        build(settings), "cnc_list_ems_interfaces", {"fdn": "MD=CISCO_EMS!ND=nope"}
    )
    assert text == "Error: the EMF has no node 'nope' (list with cnc_list_ems_nodes)"


@respx.mock
async def test_list_ems_interfaces_other_rc_errors_400_is_rendered_by_the_module(settings):
    rejected = {
        "rc.errors": {
            "error": {
                "error-tag": "invalid-value",
                "error-app-tag": "FW.0012",
                "error-message": "Invalid value for attribute type",
            }
        }
    }
    respx.get(TP_URL).mock(return_value=httpx.Response(400, json=rejected))
    text = await call_tool_text(build(settings), "cnc_list_ems_interfaces", {"node": "PE1"})
    assert text.startswith(
        "Error: EMF RESTCONF rejected the request (HTTP 400): invalid-value [FW.0012]: Invalid "
        "value for attribute type. "
    )
    assert "router-id" not in text  # not the topology NBI's invalid-value hint


@respx.mock
async def test_list_ems_interfaces_known_node_without_matches_is_not_an_error(settings):
    respx.get(TP_URL).mock(return_value=httpx.Response(200, json=EMPTY))
    text = await call_tool_text(
        build(settings), "cnc_list_ems_interfaces", {"node": "PE1", "tp_type": "PTP"}
    )
    assert text == (
        "Node PE1 has no termination points of type PTP (list all types without tp_type)."
    )
    text = await call_tool_text(
        build(settings), "cnc_list_ems_interfaces", {"node": "PE1", "offset": 100}
    )
    assert text == "Node PE1 has no termination points at offset 100."


@respx.mock
async def test_list_ems_interfaces_unscoped_lists_the_whole_emf(settings):
    route = respx.get(TP_URL).mock(return_value=httpx.Response(200, json=EMPTY))
    text = await call_tool_text(build(settings), "cnc_list_ems_interfaces", {})
    assert_emf_request(route.calls[0].request, **{".startIndex": "0", ".maxCount": "50"})
    assert text == "The EMF holds no termination points."


@respx.mock
async def test_list_ems_interfaces_errors_before_any_request(settings):
    route = respx.get(TP_URL).mock(return_value=httpx.Response(200, json=PE1_TPS))
    text = await call_tool_text(
        build(settings), "cnc_list_ems_interfaces", {"node": "PE1", "fdn": PE1_FDN}
    )
    assert text.startswith("Error: Pass at most one of 'node'")
    text = await call_tool_text(
        build(settings), "cnc_list_ems_interfaces", {"node": "PE1", "tp_type": "port"}
    )
    assert text == (
        f"Error: Unknown termination-point type 'port'. Use one of: CTP, FTP, PTP ({TP_TYPE_HELP})."
    )
    # the classes are described by model, hedged with the XRd observation — FTP is not
    # sold as "physical ports"
    assert "PTP = physical ports (by model" in text and "on XRd every Ethernet port" in text
    assert "FTP = physical ports" not in text
    assert route.call_count == 0


@respx.mock
async def test_list_ems_interfaces_xml_fallback_and_http_error(make_settings):
    respx.get(TP_URL).mock(return_value=xml_response())
    text = await call_tool_text(build(make_settings()), "cnc_list_ems_interfaces", {"node": "PE1"})
    assert text.startswith("Error:") and "Accept: application/json" in text
    respx.get(TP_URL).mock(return_value=httpx.Response(403, text="Unauthorized request"))
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_list_ems_interfaces", {"node": "PE1"}
    )
    assert text.startswith("Error:") and "403" in text


@respx.mock
async def test_list_ems_interfaces_limit_above_100_walks_pages(make_settings):
    settings = make_settings(max_response_chars=10_000_000)
    page0 = envelope("tp.termination-point", [TP_GI0_CTP] * 100)
    page1 = envelope("tp.termination-point", [TP_GI0_FTP] * 20, first=100)
    route = respx.get(TP_URL).mock(
        side_effect=[httpx.Response(200, json=page0), httpx.Response(200, json=page1)]
    )
    text = await call_tool_text(
        build(settings),
        "cnc_list_ems_interfaces",
        {"node": "PE1", "limit": 500, "response_format": "json"},
    )
    assert route.call_count == 2
    assert_emf_request(
        route.calls[1].request,
        **{".startIndex": "100", ".maxCount": "100", "ndFdn": PE1_FDN},
    )
    data = json.loads(text)
    assert data["count"] == 120 and data["has_more"] is False


# --- cnc_get_ems_interface ---------------------------------------------------


@respx.mock
async def test_get_ems_interface_by_fdn(settings):
    route = respx.get(TP_URL).mock(return_value=httpx.Response(200, json=GI0_CTP_ONLY))
    text = await call_tool_text(build(settings), "cnc_get_ems_interface", {"fdn": GI0_CTP_FDN})
    assert_emf_request(route.calls[0].request, fdn=GI0_CTP_FDN)
    assert text.startswith(f"# Termination point GigabitEthernet0/0/0/0 on PE1 ({GI0_CTP_FDN})\n")
    assert "- type: CTP" in text
    assert "- admin-state: admin-state-up" in text
    assert "- oper-state: oper-state-up" in text
    assert "- layer-rate: lr-ip" in text
    assert "- ip-tp:" in text and "  - ip-address-prefix: 10.1.1.1/30" in text
    assert "  - subnet-mask: 30" in text and "  - cast-type: IP_V4" in text
    assert "- description: to P1 Gi0/0/0/0" in text
    text = await call_tool_text(
        build(settings), "cnc_get_ems_interface", {"fdn": GI0_CTP_FDN, "response_format": "json"}
    )
    assert json.loads(text) == TP_GI0_CTP


@respx.mock
async def test_get_ems_interface_not_found_and_unknown_node(settings):
    route = respx.get(TP_URL).mock(return_value=httpx.Response(200, json=EMPTY))
    text = await call_tool_text(build(settings), "cnc_get_ems_interface", {"fdn": GI0_FTP_FDN})
    assert text.startswith(f"Error: the EMF has no termination point with fdn '{GI0_FTP_FDN}'")
    assert "cnc_list_ems_interfaces" in text
    route.mock(return_value=httpx.Response(400, json=UNKNOWN_NODE_400))
    text = await call_tool_text(
        build(settings), "cnc_get_ems_interface", {"fdn": "MD=CISCO_EMS!ND=nope!FTP=name=x;lr=y"}
    )
    assert text == "Error: the EMF has no node 'nope' (list with cnc_list_ems_nodes)"


@respx.mock
async def test_get_ems_interface_blank_fdn_xml_and_http_error(make_settings):
    route = respx.get(TP_URL).mock(return_value=xml_response())
    text = await call_tool_text(build(make_settings()), "cnc_get_ems_interface", {"fdn": "   "})
    assert text.startswith("Error: fdn is empty")
    assert route.call_count == 0
    text = await call_tool_text(
        build(make_settings()), "cnc_get_ems_interface", {"fdn": GI0_CTP_FDN}
    )
    assert text.startswith("Error:") and "Accept: application/json" in text
    route.mock(return_value=httpx.Response(500, json={"error": "NATS request failed"}))
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_ems_interface", {"fdn": GI0_CTP_FDN}
    )
    assert text.startswith("Error:") and "500" in text


async def test_get_ems_interface_requires_fdn(settings):
    with pytest.raises(ToolError, match="fdn"):
        await call_tool_text(build(settings), "cnc_get_ems_interface", {})


# --- cnc_get_ems_inventory_summary -------------------------------------------


@respx.mock
async def test_get_ems_inventory_summary_counts_and_explains_empty_equipment(settings):
    nodes = respx.get(NODE_URL).mock(return_value=httpx.Response(200, json=NODES))
    chassis = respx.get(CHASSIS_URL).mock(return_value=httpx.Response(200, json=EMPTY))
    modules = respx.get(MODULE_URL).mock(return_value=httpx.Response(200, json=EMPTY))
    equipment = respx.get(EQUIPMENT_URL).mock(return_value=httpx.Response(200, json=EMPTY))
    text = await call_tool_text(build(settings), "cnc_get_ems_inventory_summary", {})
    for route in (nodes, chassis, modules, equipment):
        assert route.call_count == 1
        assert_emf_request(route.calls[0].request, **{".startIndex": "0", ".maxCount": "100"})
    head, _, body = text.partition("\n{")
    assert head.startswith("# EMF inventory: 2 nodes, 1 MANAGED_AND_SYNCHRONIZED\n")
    assert "- lifecycle state: MANAGED_AND_SYNCHRONIZED 1, MANAGED_BUT_NEVERSYNCHRONIZED 1" in head
    assert "- communication state: Reachable 1, Unreachable 1" in head
    assert "- software: IOS XR 24.3.1 2" in head
    assert (
        "- physical inventory: 0 chassis, 0 modules, 0 equipment entries (first page of 100 "
        "each; 100+ = the page was full)" in head
    )
    assert "XRd" in head and "no chassis, module or FRU inventory" in head
    assert "- not synchronized: P1 (MANAGED_BUT_NEVERSYNCHRONIZED)" in head
    assert "unavailable" not in head
    data = json.loads("{" + body)
    assert data == {
        "nodes": 2,
        "lifecycle_state": {"MANAGED_AND_SYNCHRONIZED": 1, "MANAGED_BUT_NEVERSYNCHRONIZED": 1},
        "communication_state": {"Reachable": 1, "Unreachable": 1},
        "software": {"IOS XR 24.3.1": 2},
        "not_synchronized": [
            {
                "name": "P1",
                "fdn": P1_FDN,
                "lifecycle_state": "MANAGED_BUT_NEVERSYNCHRONIZED",
                "communication_state": "Unreachable",
            }
        ],
        "chassis": 0,
        "modules": 0,
        "equipment": 0,
        "physical_more": [],
        "physical_unavailable": {},
        "note": None,
    }


@respx.mock
async def test_get_ems_inventory_summary_counts_equipment_across_sibling_lists(settings):
    respx.get(NODE_URL).mock(return_value=httpx.Response(200, json=NODE_PE1_ONLY))
    respx.get(CHASSIS_URL).mock(
        return_value=httpx.Response(
            200, json=envelope("eq.chassis", [{"eq.fdn": "c1"}, {"eq.fdn": "c2"}])
        )
    )
    respx.get(MODULE_URL).mock(
        return_value=httpx.Response(200, json=envelope("eq.module", [{"eq.fdn": "m1"}]))
    )
    # The documented equipment answer carries three sibling lists; lastIndex counts all.
    respx.get(EQUIPMENT_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "com.response-message": {
                    "com.header": {"com.firstIndex": 0, "com.lastIndex": 2},
                    "com.data": {
                        "eq.module": [{"eq.fdn": "m1"}],
                        "eq.equipment": [{"eq.fdn": "e1"}],
                        "eq.chassis": [{"eq.fdn": "c1"}],
                    },
                }
            },
        )
    )
    text = await call_tool_text(build(settings), "cnc_get_ems_inventory_summary", {})
    assert "- physical inventory: 2 chassis, 1 modules, 3 equipment entries" in text
    assert "XRd" not in text
    assert "not synchronized" not in text
    data = json.loads("{" + text.partition("\n{")[2])
    assert (data["chassis"], data["modules"], data["equipment"]) == (2, 1, 3)
    assert data["physical_more"] == [] and data["physical_unavailable"] == {}
    assert data["not_synchronized"] == []
    assert data["lifecycle_state"] == {LIFECYCLE_SYNCHRONIZED: 1}


@respx.mock
async def test_get_ems_inventory_summary_reads_one_physical_page_and_reports_a_full_one_as_more(
    settings,
):
    respx.get(NODE_URL).mock(return_value=httpx.Response(200, json=NODES))
    respx.get(CHASSIS_URL).mock(
        return_value=httpx.Response(200, json=envelope("eq.chassis", [{"eq.fdn": "c1"}]))
    )
    respx.get(MODULE_URL).mock(return_value=httpx.Response(200, json=EMPTY))
    # a hardware deployment: the equipment first page is full -> "100+", NO second page
    full = envelope("eq.equipment", [{"eq.fdn": f"e{i}"} for i in range(100)])
    equipment = respx.get(EQUIPMENT_URL).mock(return_value=httpx.Response(200, json=full))
    text = await call_tool_text(build(settings), "cnc_get_ems_inventory_summary", {})
    assert equipment.call_count == 1
    assert_emf_request(equipment.calls[0].request, **{".startIndex": "0", ".maxCount": "100"})
    assert "- physical inventory: 1 chassis, 0 modules, 100+ equipment entries" in text
    assert "XRd" not in text
    data = json.loads("{" + text.partition("\n{")[2])
    assert (data["chassis"], data["modules"], data["equipment"]) == (1, 0, 100)
    assert data["physical_more"] == ["equipment"]
    assert data["physical_unavailable"] == {}
    assert data["note"] is None


@respx.mock
async def test_get_ems_inventory_summary_walks_node_pages_and_notes_the_guard(settings):
    full = envelope("nd.node", [NODE_PE1] * 100)
    respx.get(NODE_URL).mock(return_value=httpx.Response(200, json=full))
    for url in (CHASSIS_URL, MODULE_URL, EQUIPMENT_URL):
        respx.get(url).mock(return_value=httpx.Response(200, json=EMPTY))
    text = await call_tool_text(build(settings), "cnc_get_ems_inventory_summary", {})
    node_route = respx.get(NODE_URL)
    assert node_route.call_count == SCAN_LIMIT // 100
    assert node_route.calls[-1].request.url.params[".startIndex"] == str(SCAN_LIMIT - 100)
    for url in (CHASSIS_URL, MODULE_URL, EQUIPMENT_URL):
        assert respx.get(url).call_count == 1  # the physical collections are never walked
    assert f"# EMF inventory: {SCAN_LIMIT} nodes" in text
    assert f"- note: The node count stops at the first {SCAN_LIMIT} objects" in text
    data = json.loads("{" + text.partition("\n{")[2])
    assert data["nodes"] == SCAN_LIMIT and data["note"].startswith("The node count stops")


@respx.mock
async def test_get_ems_inventory_summary_degrades_when_a_physical_collection_fails(make_settings):
    respx.get(NODE_URL).mock(return_value=httpx.Response(200, json=NODES))
    respx.get(CHASSIS_URL).mock(return_value=httpx.Response(403, text="Unauthorized request"))
    respx.get(MODULE_URL).mock(return_value=httpx.Response(200, json=EMPTY))
    respx.get(EQUIPMENT_URL).mock(
        return_value=httpx.Response(500, json={"error": "NATS request failed"})
    )
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_ems_inventory_summary", {}
    )
    # the node counts survive; the broken collections are reported, not fatal
    assert not text.startswith("Error:")
    head, _, body = text.partition("\n{")
    assert head.startswith("# EMF inventory: 2 nodes, 1 MANAGED_AND_SYNCHRONIZED\n")
    assert "- physical inventory: ? chassis, 0 modules, ? equipment entries" in head
    assert "- physical inventory unavailable: chassis (API request failed with status 403" in head
    assert "; equipment (API request failed with status 500" in head and "NATS" in head
    assert "XRd" not in head  # nothing can be concluded about virtual routers
    data = json.loads("{" + body)
    assert (data["chassis"], data["modules"], data["equipment"]) == (None, 0, None)
    assert set(data["physical_unavailable"]) == {"chassis", "equipment"}
    assert data["physical_unavailable"]["chassis"].startswith("API request failed with status 403")
    assert data["physical_more"] == []
    # the XML fallback on a physical collection degrades the same way
    respx.get(CHASSIS_URL).mock(return_value=xml_response())
    respx.get(EQUIPMENT_URL).mock(return_value=httpx.Response(200, json=EMPTY))
    text = await call_tool_text(build(make_settings()), "cnc_get_ems_inventory_summary", {})
    assert not text.startswith("Error:")
    assert "- physical inventory unavailable: chassis (Crosswork answered this EMF RESTCONF" in text


@respx.mock
async def test_get_ems_inventory_summary_node_walk_errors_are_fatal(make_settings):
    respx.get(NODE_URL).mock(return_value=xml_response())
    text = await call_tool_text(build(make_settings()), "cnc_get_ems_inventory_summary", {})
    assert text.startswith("Error:") and "Accept: application/json" in text
    respx.get(NODE_URL).mock(return_value=httpx.Response(403, text="Unauthorized request"))
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_ems_inventory_summary", {}
    )
    assert text.startswith("Error:") and "403" in text
