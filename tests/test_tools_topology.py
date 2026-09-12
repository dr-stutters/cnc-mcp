"""Topology tools end-to-end through MCPServer (schema validation included).

The module is registered directly (not via ALL_MODULES) so these tests are
independent of the registry's contents. Response fixtures mirror the shapes
observed live on 2026-09-12, including the ones that trip naive parsers:
past-the-end pages omit ``elements``, an unrecognised mapType answers an empty
body, and the service's body-rejection 500 is a Spring error with no NATS
marker.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from mcp.server.mcpserver import MCPServer

from cnc_mcp.auth import StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.crosswork import TOPOLOGY
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import topology
from cnc_mcp.tools.topology import split_edge_name
from tests.conftest import BASE_URL, call_tool_text

TOPO = f"{BASE_URL}{TOPOLOGY}"
MAP_BODY = {"mapType": "LOGICAL", "viewId": "topology-home-map", "params": {}}

PE1, P1, PE2 = "uuid-pe1", "uuid-p1", "uuid-pe2"

INIT = {"attributes": {"totalNodes": 5, "totalUnmappedNodes": 5, "maxLogicalNodes": 5000}}
NODES_SUMMARY = {
    "sections": [
        {
            "title": "Reachability",
            "type": "reachabilityState",
            "items": [
                {"count": 5, "value": "CONN_STATE_REACHABLE"},
                {"count": 0, "value": "CONN_STATE_UNREACHABLE"},
            ],
        },
        {"title": "Family", "type": "deviceFamily", "items": [{"count": 5, "value": "IOS XR"}]},
    ]
}
EDGES_SUMMARY = {
    "sections": [
        {
            "title": "State",
            "type": "status",
            "items": [
                {"count": 0, "value": "Down"},
                {"count": 0, "value": "Degraded"},
                {"count": 1, "value": "Up"},
            ],
        }
    ]
}

# The top-level attributes /nodes and /edges return next to the rows (and alone
# past the end of the collection).
DYNAMIC_MAPPING = {
    "dynamicMapping": {
        "linkType": {"LT_L2_ETHERNET": "L2 Ethernet", "LT_L3_OSPF_V2": "L3 OSPF IPv4"},
        "reachabilityState": {"CONN_STATE_REACHABLE": "Reachable"},
    }
}


def spring_500(endpoint: str) -> httpx.Response:
    """The topology service's body-rejection error (verified live): no NATS marker."""
    return httpx.Response(
        500,
        json={
            "status": 500,
            "error": "Internal Server Error",
            "path": f"/v1/topology-service/topology/{endpoint}",
        },
    )


def _node(uuid: str, name: str) -> dict:
    # Live /data nodes carry an icon image + checksum: pure noise for agents.
    return {
        "type": "Node",
        "uuid": uuid,
        "name": name,
        "attributes": {
            "label": name,
            "image": "data:image/svg+xml;base64,PHN2Zy8+",
            "checksum": "abc",
        },
    }


def _edge(
    uuid: str, src: str, dst: str, name: str = "GigabitEthernet0/0/0/0-GigabitEthernet0/0/0/0"
) -> dict:
    # Live /data edges carry only checksum + decoration: no endpoint names.
    return {
        "type": "Edge",
        "uuid": uuid,
        "name": name,
        "sourceNode": src,
        "targetNode": dst,
        "attributes": {"checksum": "def", "decoration": {"color": "#00ff00", "lineStyle": "solid"}},
    }


GRAPH = {
    "nodes": [_node(PE1, "PE1"), _node(P1, "P1"), _node(PE2, "PE2")],
    "edges": [
        _edge("edge-1", PE1, P1),
        _edge("edge-2", P1, PE2, "GigabitEthernet0/0/0/1-GigabitEthernet0/0/0/1"),
        _edge("edge-3", PE2, PE1, "Bundle-Ether1-Bundle-Ether1"),
    ],
    "attributes": {"totalNodes": 3},
}

NODE_ROWS = {
    "elements": [
        {
            "uuid": PE1,
            "attributes": {
                "name": "PE1",
                "nodeIp": "198.18.140.11",
                "teRouterId": "10.0.0.1",
                "reachabilityState": "CONN_STATE_REACHABLE",
                "productType": "Cisco XRd",
                "deviceFamily": "IOS XR",
                "lastUpdateTime": "2026-09-12T10:00:00Z",
            },
        },
        {"uuid": P1, "attributes": {"name": "P1", "nodeIp": "198.18.140.12"}},
    ],
    "totalCount": 5,
    "attributes": DYNAMIC_MAPPING,
}

EDGE_ROWS = {
    "elements": [
        {
            "uuid": "edge-1",
            "attributes": {
                "name": "GigabitEthernet0/0/0/0-GigabitEthernet0/0/0/0",
                "linkType": "L2 Ethernet",
                "status": "Up",
                "sourceNode-name": "PE1",
                "sourceNode-uuid": PE1,
                "sourceConnector-name": "GigabitEthernet0/0/0/0",
                "targetNode-name": "P1",
                "targetNode-uuid": P1,
                "targetConnector-name": "GigabitEthernet0/0/0/0",
                "targetConnector-uto-label": "0.00015% (1.5Kbps/1Gbps)",
                "targetConnector-uto-severity": "HEALTHY",
            },
        }
    ],
    "totalCount": 1,
    "attributes": DYNAMIC_MAPPING,
}

# Bodies every tool must treat as "nothing here", never as an error:
# bare {}, an empty body (request_json -> None), and the live past-the-end
# row-window shape (totalCount present, elements omitted).
EMPTY_BODIES = [
    pytest.param(httpx.Response(200, json={}), None, id="bare-dict"),
    pytest.param(httpx.Response(200, content=b""), None, id="empty-body"),
    pytest.param(
        httpx.Response(200, json={"totalCount": 5, "attributes": DYNAMIC_MAPPING}),
        5,
        id="past-the-end",
    ),
]


def build(settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    topology.register(mcp, ctx)
    return mcp


def sent(route: respx.Route, index: int = 0) -> dict:
    return json.loads(route.calls[index].request.content)


# --- cnc_get_topology_summary -------------------------------------------------


@respx.mock
async def test_get_topology_summary_combines_three_calls(settings):
    init = respx.post(f"{TOPO}/init").mock(return_value=httpx.Response(200, json=INIT))
    nodes = respx.post(f"{TOPO}/nodes/summary").mock(
        return_value=httpx.Response(200, json=NODES_SUMMARY)
    )
    edges = respx.post(f"{TOPO}/edges/summary").mock(
        return_value=httpx.Response(200, json=EDGES_SUMMARY)
    )
    text = await call_tool_text(build(settings), "cnc_get_topology_summary", {})
    assert sent(init) == MAP_BODY
    assert sent(nodes) == {"params": {}}
    assert sent(edges) == {"params": {}}
    data = json.loads(text)
    assert data["total_nodes"] == 5 and data["unmapped_nodes"] == 5
    assert data["max_logical_nodes"] == 5000
    assert data["reachability"] == {"CONN_STATE_REACHABLE": 5, "CONN_STATE_UNREACHABLE": 0}
    assert data["link_state"] == {"Down": 0, "Degraded": 0, "Up": 1}
    assert data["node_breakdowns"]["deviceFamily"] == {"IOS XR": 5}


@pytest.mark.parametrize(
    "response",
    [
        pytest.param(httpx.Response(200, json={}), id="bare-dict"),
        pytest.param(httpx.Response(200, content=b""), id="empty-body"),
    ],
)
@respx.mock
async def test_get_topology_summary_tolerates_empty_bodies(settings, response):
    for endpoint in ("init", "nodes/summary", "edges/summary"):
        respx.post(f"{TOPO}/{endpoint}").mock(return_value=response)
    text = await call_tool_text(build(settings), "cnc_get_topology_summary", {})
    assert not text.startswith("Error:")
    data = json.loads(text)
    assert data["total_nodes"] is None and data["unmapped_nodes"] is None
    assert data["reachability"] == {} and data["link_state"] == {}
    assert data["node_breakdowns"] == {} and data["link_breakdowns"] == {}


@respx.mock
async def test_get_topology_summary_body_rejection_is_not_retry_advice(make_settings):
    settings = make_settings(max_retries=0)
    route = respx.post(f"{TOPO}/init").mock(return_value=spring_500("init"))
    text = await call_tool_text(build(settings), "cnc_get_topology_summary", {})
    assert text.startswith("Error:")
    assert "500" in text and "rejected the request body" in text and "do not retry" in text
    assert "try again" not in text and "mid-deploy" not in text
    assert route.call_count == 1  # POST is not auto-retried on 5xx


# --- cnc_get_topology ---------------------------------------------------------


@respx.mock
async def test_get_topology_markdown_lists_nodes_and_links(settings):
    route = respx.post(f"{TOPO}/data").mock(return_value=httpx.Response(200, json=GRAPH))
    text = await call_tool_text(build(settings), "cnc_get_topology", {})
    assert sent(route) == MAP_BODY
    assert "3 nodes, 3 links" in text
    assert "## Nodes (3 shown, page 0, total 3)" in text
    assert f"**PE1** ({PE1})" in text
    assert "## Links (3 shown, page 0, total 3)" in text
    assert "- PE1:GigabitEthernet0/0/0/0 <-> P1:GigabitEthernet0/0/0/0 (edge-1)" in text
    assert "- P1:GigabitEthernet0/0/0/1 <-> PE2:GigabitEthernet0/0/0/1 (edge-2)" in text
    assert "- PE2:Bundle-Ether1 <-> PE1:Bundle-Ether1 (edge-3)" in text
    assert "More links" not in text and "More nodes" not in text


@respx.mock
async def test_get_topology_pages_links_client_side(settings):
    respx.post(f"{TOPO}/data").mock(return_value=httpx.Response(200, json=GRAPH))
    mcp = build(settings)
    first = json.loads(
        await call_tool_text(
            mcp, "cnc_get_topology", {"page_size": 2, "page": 0, "response_format": "json"}
        )
    )
    assert first["map_type"] == "LOGICAL"
    assert first["attributes"] == {"totalNodes": 3}
    assert first["nodes"]["total"] == 3 and first["nodes"]["count"] == 3
    links = first["links"]
    assert [e["uuid"] for e in links["items"]] == ["edge-1", "edge-2"]
    assert links["total"] == 3 and links["count"] == 2 and links["page_size"] == 2
    assert links["has_more"] is True and links["next_page"] == 1

    second = json.loads(
        await call_tool_text(
            mcp, "cnc_get_topology", {"page_size": 2, "page": 1, "response_format": "json"}
        )
    )
    links = second["links"]
    assert [e["uuid"] for e in links["items"]] == ["edge-3"]
    assert links["has_more"] is False and links["next_page"] is None


@respx.mock
async def test_get_topology_pages_nodes_client_side(settings):
    respx.post(f"{TOPO}/data").mock(return_value=httpx.Response(200, json=GRAPH))
    mcp = build(settings)
    first = json.loads(
        await call_tool_text(
            mcp,
            "cnc_get_topology",
            {"node_page_size": 2, "node_page": 0, "response_format": "json"},
        )
    )
    nodes = first["nodes"]
    assert [n["name"] for n in nodes["items"]] == ["PE1", "P1"]
    assert nodes["total"] == 3 and nodes["count"] == 2 and nodes["page_size"] == 2
    assert nodes["has_more"] is True and nodes["next_page"] == 1
    # Links on the page still resolve names beyond the node window.
    assert first["links"]["items"][1]["target"]["node_name"] == "PE2"

    text = await call_tool_text(mcp, "cnc_get_topology", {"node_page_size": 2, "node_page": 1})
    assert "## Nodes (1 shown, page 1, total 3)" in text
    assert f"**PE2** ({PE2})" in text and f"**PE1** ({PE1})" not in text
    assert "More nodes" not in text

    text = await call_tool_text(mcp, "cnc_get_topology", {"node_page_size": 2})
    assert "More nodes available: repeat with node_page=1." in text


@respx.mock
async def test_get_topology_json_is_compact_and_resolves_endpoints(settings):
    respx.post(f"{TOPO}/data").mock(return_value=httpx.Response(200, json=GRAPH))
    data = json.loads(
        await call_tool_text(build(settings), "cnc_get_topology", {"response_format": "json"})
    )
    assert data["nodes"]["items"][0] == {"uuid": PE1, "name": "PE1"}  # no image/checksum
    link = data["links"]["items"][2]
    assert link == {
        "uuid": "edge-3",
        "name": "Bundle-Ether1-Bundle-Ether1",
        "source": {"node_uuid": PE2, "node_name": "PE2", "interface": "Bundle-Ether1"},
        "target": {"node_uuid": PE1, "node_name": "PE1", "interface": "Bundle-Ether1"},
    }
    assert "attributes" not in link  # checksum/decoration dropped


@respx.mock
async def test_get_topology_large_graph_stays_valid_json(settings):
    """600 nodes with icon noise used to overflow the 40k cap even at page_size=1."""
    big = {
        "nodes": [_node(f"uuid-{i}", f"R{i}") for i in range(600)],
        "edges": [_edge(f"edge-{i}", f"uuid-{i}", f"uuid-{i + 1}") for i in range(599)],
        "attributes": {"totalNodes": 600},
    }
    respx.post(f"{TOPO}/data").mock(return_value=httpx.Response(200, json=big))
    text = await call_tool_text(
        build(settings), "cnc_get_topology", {"page_size": 1, "response_format": "json"}
    )
    assert "[Truncated" not in text and len(text) < settings.max_response_chars
    data = json.loads(text)
    assert data["nodes"]["total"] == 600 and data["nodes"]["count"] == 100  # default window
    assert data["nodes"]["has_more"] is True and data["nodes"]["next_page"] == 1
    assert data["links"]["total"] == 599 and data["links"]["count"] == 1
    assert data["links"]["items"][0]["target"]["node_name"] == "R1"


@pytest.mark.parametrize("value", ["geo", "GEO", " Geo "])
@respx.mock
async def test_get_topology_rejects_geo_without_calling_platform(settings, value):
    route = respx.post(f"{TOPO}/data").mock(return_value=spring_500("data"))
    text = await call_tool_text(build(settings), "cnc_get_topology", {"map_type": value})
    assert text.startswith("Error:")
    assert "500" in text and "GEO" in text and "map_type='logical'" in text
    assert "try again" not in text
    assert not route.called


@respx.mock
async def test_get_topology_rejects_unknown_map_type(settings):
    route = respx.post(f"{TOPO}/data").mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(build(settings), "cnc_get_topology", {"map_type": "physical"})
    assert text.startswith("Error:") and "map type" in text and "logical" in text
    assert not route.called


@respx.mock
async def test_get_topology_accepts_wire_value(settings):
    route = respx.post(f"{TOPO}/data").mock(return_value=httpx.Response(200, json=GRAPH))
    text = await call_tool_text(build(settings), "cnc_get_topology", {"map_type": "LOGICAL"})
    assert sent(route)["mapType"] == "LOGICAL"
    assert "3 nodes, 3 links" in text


@pytest.mark.parametrize(
    "response",
    [
        pytest.param(httpx.Response(200, json={}), id="bare-dict"),
        pytest.param(httpx.Response(200, content=b""), id="empty-body"),
        pytest.param(
            httpx.Response(200, json={"nodes": [], "edges": [], "attributes": {}}), id="empty-lists"
        ),
    ],
)
@respx.mock
async def test_get_topology_tolerates_empty_bodies(settings, response):
    respx.post(f"{TOPO}/data").mock(return_value=response)
    mcp = build(settings)
    text = await call_tool_text(mcp, "cnc_get_topology", {})
    assert not text.startswith("Error:")
    assert "0 nodes, 0 links" in text
    assert "SR-PCE" in text  # empty-topology hint
    data = json.loads(await call_tool_text(mcp, "cnc_get_topology", {"response_format": "json"}))
    assert data["nodes"]["items"] == [] and data["nodes"]["total"] == 0
    assert data["nodes"]["has_more"] is False
    assert data["links"]["items"] == [] and data["links"]["total"] == 0
    assert data["links"]["has_more"] is False


@respx.mock
async def test_get_topology_body_rejection_is_not_retry_advice(make_settings):
    settings = make_settings(max_retries=0)
    respx.post(f"{TOPO}/data").mock(return_value=spring_500("data"))
    text = await call_tool_text(build(settings), "cnc_get_topology", {})
    assert text.startswith("Error:") and "500" in text
    assert "rejected the request body" in text and "do not retry" in text
    assert f"{TOPOLOGY}/data" in text
    assert "try again" not in text


@respx.mock
async def test_get_topology_other_errors_use_generic_hints(make_settings):
    """Only the Spring body-rejection shape is special-cased; everything else is errors.py."""
    settings = make_settings(max_retries=0)
    mcp = build(settings)
    respx.post(f"{TOPO}/data").mock(return_value=httpx.Response(403, json={"error": "Forbidden"}))
    text = await call_tool_text(mcp, "cnc_get_topology", {})
    assert text.startswith("Error:") and "403" in text and "Permission denied" in text

    respx.post(f"{TOPO}/data").mock(return_value=httpx.Response(502, json={"error": "Bad Gateway"}))
    text = await call_tool_text(mcp, "cnc_get_topology", {})
    assert text.startswith("Error:") and "502" in text and "try again" in text
    assert "rejected the request body" not in text

    respx.post(f"{TOPO}/data").mock(return_value=httpx.Response(200, text="<html>login</html>"))
    text = await call_tool_text(mcp, "cnc_get_topology", {})
    assert text.startswith("Error:") and "non-JSON" in text


# --- cnc_list_topology_nodes --------------------------------------------------


@respx.mock
async def test_list_topology_nodes_row_window_and_envelope(settings):
    route = respx.post(f"{TOPO}/nodes").mock(return_value=httpx.Response(200, json=NODE_ROWS))
    text = await call_tool_text(
        build(settings),
        "cnc_list_topology_nodes",
        {"page_size": 30, "page": 2, "response_format": "json"},
    )
    assert sent(route) == {
        "viewId": "topology-home-map",
        "startRow": 60,
        "endRow": 90,
        "sortColumn": "name",
        "sortAscending": True,
        "params": {},
    }
    data = json.loads(text)
    assert data["total"] == 5 and data["collection_total"] == 5
    assert data["count"] == 2 and data["page"] == 2 and data["page_size"] == 30
    assert data["offset"] == 60
    assert data["has_more"] is False  # 60 + 2 >= 5
    first = data["items"][0]
    assert first["uuid"] == PE1 and first["name"] == "PE1"
    assert first["reachabilityState"] == "CONN_STATE_REACHABLE"


@respx.mock
async def test_list_topology_nodes_markdown_and_sort(settings):
    route = respx.post(f"{TOPO}/nodes").mock(return_value=httpx.Response(200, json=NODE_ROWS))
    text = await call_tool_text(
        build(settings),
        "cnc_list_topology_nodes",
        {"page_size": 2, "page": 0, "sort_by": "nodeIp", "sort_ascending": False},
    )
    body = sent(route)
    assert body["startRow"] == 0 and body["endRow"] == 2
    assert body["sortColumn"] == "nodeIp" and body["sortAscending"] is False
    assert f"**PE1** ({PE1})" in text
    assert "ip 198.18.140.11, TE router-id 10.0.0.1, CONN_STATE_REACHABLE, IOS XR" in text
    assert "repeat with page=1" in text  # 2 of 5 shown


@respx.mock
async def test_list_topology_nodes_rejects_unknown_sort_column(settings):
    route = respx.post(f"{TOPO}/nodes").mock(return_value=httpx.Response(200, json=NODE_ROWS))
    text = await call_tool_text(build(settings), "cnc_list_topology_nodes", {"sort_by": "bogus"})
    assert text.startswith("Error:") and "sort column" in text
    assert not route.called


@respx.mock
async def test_list_topology_nodes_empty_topology(settings):
    respx.post(f"{TOPO}/nodes").mock(
        return_value=httpx.Response(200, json={"elements": [], "totalCount": 0})
    )
    text = await call_tool_text(
        build(settings), "cnc_list_topology_nodes", {"response_format": "json"}
    )
    data = json.loads(text)
    assert data["items"] == [] and data["total"] == 0 and data["has_more"] is False


@pytest.mark.parametrize(("response", "total"), EMPTY_BODIES)
@respx.mock
async def test_list_topology_nodes_tolerates_empty_bodies(settings, response, total):
    respx.post(f"{TOPO}/nodes").mock(return_value=response)
    mcp = build(settings)
    text = await call_tool_text(
        mcp, "cnc_list_topology_nodes", {"page": 1, "page_size": 30, "response_format": "json"}
    )
    assert not text.startswith("Error:")
    data = json.loads(text)
    assert data["items"] == [] and data["total"] == total and data["has_more"] is False
    text = await call_tool_text(mcp, "cnc_list_topology_nodes", {"page": 1, "page_size": 30})
    assert not text.startswith("Error:") and "(no nodes" in text


@respx.mock
async def test_list_topology_nodes_body_rejection_is_not_retry_advice(make_settings):
    settings = make_settings(max_retries=0)
    respx.post(f"{TOPO}/nodes").mock(return_value=spring_500("nodes"))
    text = await call_tool_text(build(settings), "cnc_list_topology_nodes", {})
    assert text.startswith("Error:") and "500" in text and "do not retry" in text
    assert "try again" not in text


# --- cnc_list_topology_links --------------------------------------------------


@respx.mock
async def test_list_topology_links_row_window_and_markdown(settings):
    route = respx.post(f"{TOPO}/edges").mock(return_value=httpx.Response(200, json=EDGE_ROWS))
    text = await call_tool_text(
        build(settings), "cnc_list_topology_links", {"page_size": 10, "page": 3}
    )
    assert sent(route) == {
        "viewId": "topology-home-map",
        "startRow": 30,
        "endRow": 40,
        "params": {},
    }
    assert (
        "- Up L2 Ethernet: PE1:GigabitEthernet0/0/0/0 <-> P1:GigabitEthernet0/0/0/0 "
        "(util <- 0.00015% (1.5Kbps/1Gbps)) (edge-1)"
    ) in text


@respx.mock
async def test_list_topology_links_json_envelope(settings):
    respx.post(f"{TOPO}/edges").mock(return_value=httpx.Response(200, json=EDGE_ROWS))
    text = await call_tool_text(
        build(settings), "cnc_list_topology_links", {"response_format": "json"}
    )
    data = json.loads(text)
    assert data["total"] == 1 and data["count"] == 1 and data["has_more"] is False
    item = data["items"][0]
    assert item["uuid"] == "edge-1" and item["status"] == "Up"
    assert item["targetConnector-uto-severity"] == "HEALTHY"


@pytest.mark.parametrize(("response", "total"), EMPTY_BODIES)
@respx.mock
async def test_list_topology_links_tolerates_empty_bodies(settings, response, total):
    respx.post(f"{TOPO}/edges").mock(return_value=response)
    mcp = build(settings)
    text = await call_tool_text(
        mcp, "cnc_list_topology_links", {"page": 1, "page_size": 30, "response_format": "json"}
    )
    assert not text.startswith("Error:")
    data = json.loads(text)
    assert data["items"] == [] and data["total"] == total and data["has_more"] is False
    text = await call_tool_text(mcp, "cnc_list_topology_links", {"page": 1, "page_size": 30})
    assert not text.startswith("Error:") and "(no links" in text


@respx.mock
async def test_list_topology_links_body_rejection_is_not_retry_advice(make_settings):
    settings = make_settings(max_retries=0)
    respx.post(f"{TOPO}/edges").mock(return_value=spring_500("edges"))
    text = await call_tool_text(build(settings), "cnc_list_topology_links", {})
    assert text.startswith("Error:") and "500" in text and "do not retry" in text
    assert "try again" not in text


# --- helpers ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (
            "GigabitEthernet0/0/0/0-GigabitEthernet0/0/0/0",
            ("GigabitEthernet0/0/0/0", "GigabitEthernet0/0/0/0"),
        ),
        ("Bundle-Ether1-Bundle-Ether1", ("Bundle-Ether1", "Bundle-Ether1")),
        ("Bundle-Ether1-GigabitEthernet0/0/0/1", ("Bundle-Ether1", "GigabitEthernet0/0/0/1")),
        ("TenGigE0/0/0/0.100-TenGigE0/0/0/1.100", ("TenGigE0/0/0/0.100", "TenGigE0/0/0/1.100")),
        ("not an interface pair", ("not an interface pair", "")),
    ],
)
def test_split_edge_name(name, expected):
    assert split_edge_name(name) == expected
