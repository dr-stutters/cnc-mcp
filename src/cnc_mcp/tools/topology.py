"""Topology-service tools: the device graph CNC builds from LLDP and SR-PCE/BGP-LS.

Base path :data:`cnc_mcp.crosswork.TOPOLOGY`
(``/crosswork/topology/v1/topology-service/topology``). These endpoints do
NOT use the inventory ``*/query`` grammar (verified live 2026-09-12):

- ``POST .../init``, ``POST .../data``  -> ``{"mapType", "viewId", "params"}``;
  ``data`` returns the WHOLE graph with no server-side paging:
  ``{"nodes": [{"type": "Node", "uuid", "name", "attributes": {"label", "image",
  "checksum", ...}}], "edges": [{"type": "Edge", "uuid", "name": "<srcIf>-<dstIf>",
  "sourceNode": <uuid>, "targetNode": <uuid>, "attributes": {"checksum",
  "decoration": {"color", "lineStyle"}}}], "attributes": {"totalNodes", ...}}``.
  Edge attributes carry NO endpoint names — they come from ``name`` plus the
  node UUIDs. Only ``mapType`` ``LOGICAL`` works: ``GEO`` answers HTTP 500
  (see :data:`GEO_UNSUPPORTED`) and an unrecognised ``mapType`` answers an
  empty 200 body.
- ``POST .../nodes``, ``POST .../edges`` -> row-window paging with
  ``startRow``/``endRow`` (+ ``sortColumn``/``sortAscending`` for nodes);
  responses are ``{"elements": [{"uuid", "attributes": {...}}], "totalCount",
  "attributes": {"dynamicMapping": {...}}}``. Past the end of the collection
  the ``elements`` key is OMITTED (``{"totalCount": N, "attributes": {...}}``).
  ``attributes.dynamicMapping`` maps wire enums to display names (``linkType``
  e.g. ``LT_L3_OSPF_V2`` -> ``L3 OSPF IPv4``; also ``reachabilityState``,
  ``deviceFamily``, ``asev``).
- ``POST .../nodes/summary``, ``POST .../edges/summary`` -> ``{"params": {}}``;
  responses are ``{"sections": [{"title", "type", "items": [{"count", "value"}]}]}``.
- Errors: the topology service is a Spring app. A request body it cannot handle
  (unsupported ``mapType``, bad ``viewId``/``params``) answers
  ``500 {"status": 500, "error": "Internal Server Error", "path":
  "/v1/topology-service/..."}`` — deterministic, never a transient outage, and
  WITHOUT the inventory's ``NATS request failed`` marker. :func:`_post`
  translates it so agents are not told to "try again".

Every call uses the UI's ``viewId`` ``topology-home-map``. The UI also sends
``params.groupUuid`` and an ``overlays`` string; both are optional and omitted.

L3 links come from an SR-PCE provider (BGP-LS); without one the inventory
fills but the topology stays empty. L2 (LLDP) links come from device collection.
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.client import ApiClient
from cnc_mcp.crosswork import TOPOLOGY, page_envelope, wire_enum
from cnc_mcp.errors import PlatformError, format_error, http_error
from cnc_mcp.formatting import ResponseFormat, finalize, to_json
from cnc_mcp.safety import AppContext, register_tool

VIEW_ID = "topology-home-map"

# Only the logical map is reachable through the API shape captured so far. 'geo'
# is deliberately absent: POST .../data with {"mapType": "GEO"} answers HTTP 500
# (verified live 2026-09-12; init with GEO succeeds, groupUuid/overlays/bbox
# variants also 500/400). Re-add it once the UI's real GEO request is captured —
# it likely needs at least one node with a geographic location.
MAP_TYPES = {"logical": "LOGICAL"}

GEO_UNSUPPORTED = (
    "The geographic map is not available through this tool: on this platform "
    "POST .../topology/data with mapType GEO answers HTTP 500 for every request shape "
    "captured so far (no node has a geographic location and viewport parameters are "
    "not supported). Do not retry with 'geo'; use map_type='logical'."
)

_TOPOLOGY_500 = (
    "The topology service rejected the request body (HTTP 500 Internal Server Error from "
    "{path}). On this platform that is a deterministic rejection — an unsupported mapType, "
    "viewId or params value — not an outage, so do not retry the same call."
)

# Attribute keys returned for every node by POST .../nodes; the UI table sorts on
# these columns. Verified live to sort server-side: name, nodeIp, lastUpdateTime.
# The platform silently accepts an unknown sortColumn (order then undefined), so
# this whitelist is the only guard against a typo becoming a garbled order.
NODE_SORT_COLUMNS = {
    "name": "name",
    "nodeip": "nodeIp",
    "terouterid": "teRouterId",
    "reachabilitystate": "reachabilityState",
    "producttype": "productType",
    "devicefamily": "deviceFamily",
    "lastupdatetime": "lastUpdateTime",
}

# An interface name: letters (hyphens allowed, e.g. Bundle-Ether), then a digit
# and slot/port/subinterface characters (GigabitEthernet0/0/0/0, TenGigE0/0/0/1.100).
_IFACE_RE = re.compile(r"^[A-Za-z][A-Za-z-]*\d[\w/.:]*$")


def _map_body(map_type: str) -> dict[str, Any]:
    return {"mapType": map_type, "viewId": VIEW_ID, "params": {}}


def _rows_body(page_size: int, page: int) -> dict[str, Any]:
    start = page * page_size
    return {"viewId": VIEW_ID, "startRow": start, "endRow": start + page_size, "params": {}}


def _is_body_rejection(response: Any) -> bool:
    """Is this the topology service's Spring-style 500 for an unprocessable body?"""
    if response.status_code != 500:
        return False
    try:
        data = response.json()
    except ValueError:
        return False
    if not isinstance(data, dict):
        return False
    error = str(data.get("error") or "").strip().lower()
    path = str(data.get("path") or "")
    return error == "internal server error" or "/topology-service/" in path


async def _post(client: ApiClient, path: str, body: dict[str, Any]) -> Any:
    """POST to the topology service and parse the JSON body (empty body -> None).

    Same contract as ``ApiClient.request_json`` except that the service's
    body-rejection 500 (see the module docstring) is raised as a PlatformError
    that tells the agent NOT to retry, instead of the generic "busy; try again"
    hint that would otherwise apply to a 500.
    """
    response = await client.request("POST", path, json_body=body, raise_on_error=False)
    if _is_body_rejection(response):
        raise PlatformError(_TOPOLOGY_500.format(path=path))
    if not response.is_success:
        raise http_error(response)
    if not response.content:
        return None
    try:
        return response.json()
    except ValueError as e:
        raise PlatformError(
            "The topology service returned a non-JSON response where JSON was expected."
        ) from e


def _flatten(elements: Any) -> list[dict[str, Any]]:
    """``{"uuid", "attributes": {...}}`` -> ``{"uuid", ...attributes}`` per element."""
    out: list[dict[str, Any]] = []
    for el in elements if isinstance(elements, list) else []:
        if not isinstance(el, dict):
            continue
        attrs = el.get("attributes")
        item: dict[str, Any] = {"uuid": el.get("uuid")}
        if isinstance(attrs, dict):
            item.update(attrs)
        out.append(item)
    return out


def _total_count(data: Any) -> int | None:
    total = data.get("totalCount") if isinstance(data, dict) else None
    return total if isinstance(total, int) else None


def _section_counts(sections: Any) -> dict[str, dict[str, int]]:
    """``[{"type", "items": [{"count", "value"}]}]`` -> ``{type: {value: count}}``."""
    out: dict[str, dict[str, int]] = {}
    for section in sections if isinstance(sections, list) else []:
        if not isinstance(section, dict):
            continue
        key = str(section.get("type") or section.get("title") or "unknown")
        counts: dict[str, int] = {}
        for item in section.get("items") or []:
            if isinstance(item, dict) and "value" in item:
                counts[str(item["value"])] = int(item.get("count") or 0)
        out[key] = counts
    return out


def _pick_section(counts: dict[str, dict[str, int]], type_: str, title: str) -> dict[str, int]:
    """Look a section up by its type, falling back to its title."""
    return counts.get(type_) or counts.get(title) or {}


def split_edge_name(name: str) -> tuple[str, str]:
    """Split ``"<srcIf>-<dstIf>"`` into its two interface names.

    Interface names themselves may contain hyphens (``Bundle-Ether1``), so try
    every hyphen and keep the split where both halves look like interfaces.
    Falls back to ``(name, "")`` when no split qualifies.
    """
    for i, ch in enumerate(name):
        if ch != "-":
            continue
        left, right = name[:i], name[i + 1 :]
        if _IFACE_RE.match(left) and _IFACE_RE.match(right):
            return left, right
    return name, ""


def _node_label(node: dict[str, Any]) -> str:
    attrs = node.get("attributes") if isinstance(node.get("attributes"), dict) else {}
    return str(node.get("name") or attrs.get("label") or attrs.get("name") or "?")


def _compact_node(node: dict[str, Any]) -> dict[str, Any]:
    """``{uuid, name}`` only — /data node attributes are icon image/checksum noise."""
    return {"uuid": node.get("uuid"), "name": _node_label(node)}


def _compact_link(edge: dict[str, Any], names: dict[str, str]) -> dict[str, Any]:
    """A /data edge with both endpoints resolved (node UUID + name + interface).

    Live /data edges carry no endpoint names in ``attributes`` (only
    ``checksum``/``decoration``), so the interface names come from splitting
    ``name`` and the node names from the graph's node list.
    """
    src_if, dst_if = split_edge_name(str(edge.get("name") or ""))
    src_uuid = str(edge.get("sourceNode") or "")
    dst_uuid = str(edge.get("targetNode") or "")
    return {
        "uuid": edge.get("uuid"),
        "name": edge.get("name"),
        "source": {
            "node_uuid": src_uuid or None,
            "node_name": names.get(src_uuid, src_uuid or "?"),
            "interface": src_if,
        },
        "target": {
            "node_uuid": dst_uuid or None,
            "node_name": names.get(dst_uuid, dst_uuid or "?"),
            "interface": dst_if,
        },
    }


def _topology_markdown(map_type: str, node_env: dict[str, Any], link_env: dict[str, Any]) -> str:
    lines = [f"# Topology ({map_type}): {node_env['total']} nodes, {link_env['total']} links", ""]
    lines.append(
        f"## Nodes ({node_env['count']} shown, page {node_env['page']}, total {node_env['total']})"
    )
    if not node_env["total"]:
        lines.append("(no nodes — is an SR-PCE provider configured and reachable?)")
    for node in node_env["items"]:
        lines.append(f"- **{node['name']}** ({node.get('uuid') or '?'})")
    if node_env["has_more"]:
        lines.append(f"More nodes available: repeat with node_page={node_env['next_page']}.")
    lines.append("")
    lines.append(
        f"## Links ({link_env['count']} shown, page {link_env['page']}, total {link_env['total']})"
    )
    for link in link_env["items"]:
        src, dst = link["source"], link["target"]
        left = f"{src['node_name']}:{src['interface']}" if src["interface"] else src["node_name"]
        right = f"{dst['node_name']}:{dst['interface']}" if dst["interface"] else dst["node_name"]
        lines.append(f"- {left} <-> {right} ({link.get('uuid') or '?'})")
    if link_env["has_more"]:
        lines.append("")
        lines.append(f"More links available: repeat with page={link_env['next_page']}.")
    return "\n".join(lines)


def _nodes_markdown(items: list[dict[str, Any]], envelope: dict) -> str:
    lines = [f"# Topology nodes ({envelope['count']} shown, total {envelope['total']})", ""]
    if not items:
        lines.append("(no nodes — is an SR-PCE provider configured and reachable?)")
    for n in items:
        details = [
            f"ip {n['nodeIp']}" if n.get("nodeIp") else None,
            f"TE router-id {n['teRouterId']}" if n.get("teRouterId") else None,
            str(n.get("reachabilityState") or ""),
            str(n.get("deviceFamily") or n.get("productType") or ""),
        ]
        detail = ", ".join(d for d in details if d)
        lines.append(
            f"- **{n.get('name', '?')}** ({n.get('uuid', '?')})"
            + (f" — {detail}" if detail else "")
        )
    if envelope["has_more"]:
        lines.append("")
        lines.append(f"More available: repeat with page={envelope['next_page']}.")
    return "\n".join(lines)


def _links_markdown(items: list[dict[str, Any]], envelope: dict) -> str:
    lines = [f"# Topology links ({envelope['count']} shown, total {envelope['total']})", ""]
    if not items:
        lines.append("(no links — L3 links need an SR-PCE provider; L2 links need LLDP collection)")
    for e in items:
        src = f"{e.get('sourceNode-name', '?')}:{e.get('sourceConnector-name', '?')}"
        dst = f"{e.get('targetNode-name', '?')}:{e.get('targetConnector-name', '?')}"
        utils = [
            f"{e['sourceConnector-uto-label']} ->" if e.get("sourceConnector-uto-label") else None,
            f"<- {e['targetConnector-uto-label']}" if e.get("targetConnector-uto-label") else None,
        ]
        util = " ".join(u for u in utils if u)
        line = f"- {e.get('status', '?')} {e.get('linkType', '?')}: {src} <-> {dst}"
        if util:
            line += f" (util {util})"
        lines.append(line + f" ({e.get('uuid', '?')})")
    if envelope["has_more"]:
        lines.append("")
        lines.append(f"More available: repeat with page={envelope['next_page']}.")
    return "\n".join(lines)


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_topology_summary",
        title="Get Topology Summary",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_topology_summary() -> str:
        """Summarize the CNC topology: node/link totals and state breakdowns.

        Read-only. Combines three topology-service calls (``init``,
        ``nodes/summary``, ``edges/summary``) into one answer. Use it first to
        learn whether the topology is populated at all (an empty topology with
        a populated inventory usually means no reachable SR-PCE provider), then
        drill in with cnc_get_topology, cnc_list_topology_nodes or
        cnc_list_topology_links.

        Returns:
            str: JSON:
            {"total_nodes": int, "unmapped_nodes": int, "max_logical_nodes": int,
             "reachability": {"CONN_STATE_REACHABLE": 5, ...},
             "link_state": {"Up": 1, "Degraded": 0, "Down": 0},
             "node_breakdowns": {<section type>: {<value>: <count>}, ...},
             "link_breakdowns": {<section type>: {<value>: <count>}, ...}}
            ``unmapped_nodes`` counts nodes with no geographic location (they
            render on the logical map only). ``node_breakdowns`` carries every
            section the platform returned (e.g. device family) keyed by type.
            Counts are null and breakdowns empty when the platform returns an
            empty body (fresh, unpopulated topology).
            On failure: "Error: <actionable message>". An HTTP 500 "Internal Server
            Error" from /v1/topology-service/... means the service rejected the
            request body (mapType/viewId/params) — deterministic, do NOT retry.
            (It is not the inventory's "NATS request failed" signal.)
        """
        try:
            init = await _post(client, f"{TOPOLOGY}/init", _map_body(MAP_TYPES["logical"]))
            nodes = await _post(client, f"{TOPOLOGY}/nodes/summary", {"params": {}})
            edges = await _post(client, f"{TOPOLOGY}/edges/summary", {"params": {}})
            attrs = init.get("attributes") if isinstance(init, dict) else None
            attrs = attrs if isinstance(attrs, dict) else {}
            node_counts = _section_counts(nodes.get("sections") if isinstance(nodes, dict) else [])
            link_counts = _section_counts(edges.get("sections") if isinstance(edges, dict) else [])
            summary = {
                "total_nodes": attrs.get("totalNodes"),
                "unmapped_nodes": attrs.get("totalUnmappedNodes"),
                "max_logical_nodes": attrs.get("maxLogicalNodes"),
                "reachability": _pick_section(node_counts, "reachabilityState", "Reachability"),
                "link_state": _pick_section(link_counts, "status", "State"),
                "node_breakdowns": node_counts,
                "link_breakdowns": link_counts,
            }
            return finalize(to_json(summary), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_topology",
        title="Get Topology Graph",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_topology(
        map_type: Annotated[
            str,
            Field(
                description="Map to read. Only 'logical' (default; wire value 'LOGICAL') "
                "is supported — 'geo' is rejected because the platform answers HTTP 500 "
                "for it.",
                max_length=20,
            ),
        ] = "logical",
        page_size: Annotated[
            int, Field(description="Links per page (client-side paging).", ge=1, le=500)
        ] = 50,
        page: Annotated[int, Field(description="0-based page of links.", ge=0)] = 0,
        node_page_size: Annotated[
            int, Field(description="Nodes per page (client-side paging).", ge=1, le=1000)
        ] = 100,
        node_page: Annotated[int, Field(description="0-based page of nodes.", ge=0)] = 0,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the topology graph: one page of nodes plus one page of links (edges).

        Read-only. Crosswork returns the whole graph (up to ``maxLogicalNodes``,
        5000 on the lab instance) in one response with no server-side paging,
        so this tool re-downloads the graph on every call and pages BOTH lists
        client-side: ``page``/``page_size`` window the links, ``node_page``/
        ``node_page_size`` window the nodes. Each link carries both endpoints
        resolved (node UUID, node name, interface), so a links page is
        self-contained — you do not need the nodes page to read adjacency.
        Use it for node-to-node adjacency (e.g. "what is PE1 connected to?");
        for tabular attributes (IPs, reachability, link status/utilisation)
        prefer cnc_list_topology_nodes / cnc_list_topology_links. Keep page
        sizes modest: the response is capped at the configured size limit.

        Args:
            map_type: 'logical' only ('geo' is rejected with an explanation).
            page_size: links per page (1-500).
            page: 0-based page of links.
            node_page_size: nodes per page (1-1000).
            node_page: 0-based page of nodes.
            response_format: markdown (default) or json.

        Returns:
            str: Markdown listing nodes then "A:ifA <-> B:ifB" per link, or JSON:
            {"map_type": "LOGICAL", "attributes": {"totalNodes": int, ...},
             "nodes": {"total": int, "count": int, "page": int, "page_size": int,
                       "items": [{"uuid": str, "name": str}],
                       "has_more": bool, "next_page": int|null, ...},
             "links": {"total": int, "count": int, "page": int, "page_size": int,
                       "items": [{"uuid": str, "name": "<srcIf>-<dstIf>",
                                  "source": {"node_uuid": str, "node_name": str,
                                             "interface": str},
                                  "target": {"node_uuid": str, "node_name": str,
                                             "interface": str}}],
                       "has_more": bool, "next_page": int|null, ...}}
            Node icon/checksum attributes and edge decoration attributes (the
            only ``attributes`` the platform returns on /data) are dropped.
            On failure: "Error: <actionable message>". An HTTP 500 "Internal Server
            Error" from /v1/topology-service/... means the service rejected the
            request body (mapType/viewId/params) — deterministic, do NOT retry.
            (It is not the inventory's "NATS request failed" signal.)
        """
        try:
            if map_type.strip().lower() == "geo":
                raise PlatformError(GEO_UNSUPPORTED)
            wire_map = wire_enum(MAP_TYPES, map_type, "map type") or MAP_TYPES["logical"]
            data = await _post(client, f"{TOPOLOGY}/data", _map_body(wire_map))
            data = data if isinstance(data, dict) else {}
            raw_nodes = data.get("nodes") if isinstance(data.get("nodes"), list) else []
            raw_edges = data.get("edges") if isinstance(data.get("edges"), list) else []
            nodes = [_compact_node(n) for n in raw_nodes if isinstance(n, dict)]
            names = {str(n["uuid"]): n["name"] for n in nodes}
            node_start = node_page * node_page_size
            node_env = page_envelope(
                nodes[node_start : node_start + node_page_size],
                result_count=len(nodes),
                total_count=len(nodes),
                page_size=node_page_size,
                page=node_page,
            )
            start = page * page_size
            links = [
                _compact_link(e, names)
                for e in raw_edges[start : start + page_size]
                if isinstance(e, dict)
            ]
            link_env = page_envelope(
                links,
                result_count=len(raw_edges),
                total_count=len(raw_edges),
                page_size=page_size,
                page=page,
            )
            if response_format is ResponseFormat.JSON:
                out = {
                    "map_type": wire_map,
                    "attributes": data.get("attributes"),
                    "nodes": node_env,
                    "links": link_env,
                }
                return finalize(to_json(out), settings)
            return finalize(_topology_markdown(wire_map, node_env, link_env), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_topology_nodes",
        title="List Topology Nodes",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_topology_nodes(
        page_size: Annotated[
            int, Field(description="Rows per page (endRow - startRow).", ge=1, le=500)
        ] = 30,
        page: Annotated[int, Field(description="0-based page number.", ge=0)] = 0,
        sort_by: Annotated[
            str,
            Field(
                description="Column to sort on: 'name' (default), 'nodeIp', 'lastUpdateTime' "
                "(all three verified live), 'teRouterId', 'reachabilityState', "
                "'productType' or 'deviceFamily'.",
                max_length=40,
            ),
        ] = "name",
        sort_ascending: Annotated[
            bool, Field(description="Sort ascending (true, default) or descending.")
        ] = True,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the nodes on the topology map as a sorted, paged table.

        Read-only. Topology nodes are the devices CNC has placed on the map
        (fed by inventory + SR-PCE); their UUIDs match the inventory node
        UUIDs. Use this for per-node attributes (management IP, TE router-id,
        reachability, family); use cnc_get_topology for adjacency.

        Paging is a row window: startRow = page * page_size,
        endRow = startRow + page_size. Past the end the platform returns
        ``totalCount`` with no rows (reported as an empty page, not an error).
        No filtering is available on this endpoint — filter client-side or use
        the inventory tools. The platform silently accepts an unknown sort
        column (undefined order), so ``sort_by`` is validated here first.

        Args:
            page_size: rows per page (1-500).
            page: 0-based page number.
            sort_by: column to sort on (see the parameter description).
            sort_ascending: sort direction.
            response_format: markdown (default) or json.

        Returns:
            str: Markdown listing, or JSON:
            {"total": int, "count": int, "page": int, "page_size": int,
             "items": [{"uuid": str, "name": str, "nodeIp": str, "teRouterId": str,
                        "reachabilityState": "CONN_STATE_REACHABLE"|..., "productType": str,
                        "deviceFamily": str, "lastUpdateTime": str, ...}],
             "has_more": bool, "next_page": int|null, ...}
            Each item is the element's ``uuid`` merged with its ``attributes``.
            On failure: "Error: <actionable message>" (unknown sort column ->
            "Error: Unknown sort column ..."). An HTTP 500 "Internal Server
            Error" from /v1/topology-service/... means the service rejected the
            request body (viewId/params) — deterministic, do NOT retry.
            (It is not the inventory's "NATS request failed" signal.)
        """
        try:
            column = wire_enum(NODE_SORT_COLUMNS, sort_by, "sort column") or "name"
            body = _rows_body(page_size, page)
            body["sortColumn"] = column
            body["sortAscending"] = sort_ascending
            data = await _post(client, f"{TOPOLOGY}/nodes", body)
            items = _flatten(data.get("elements") if isinstance(data, dict) else None)
            total = _total_count(data)
            envelope = page_envelope(
                items, result_count=total, total_count=total, page_size=page_size, page=page
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(envelope), settings)
            return finalize(_nodes_markdown(items, envelope), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_topology_links",
        title="List Topology Links",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_topology_links(
        page_size: Annotated[
            int, Field(description="Rows per page (endRow - startRow).", ge=1, le=500)
        ] = 30,
        page: Annotated[int, Field(description="0-based page number.", ge=0)] = 0,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the links (edges) on the topology map with status and utilisation.

        Read-only. Each link carries its type (display name, e.g. "L2 Ethernet"
        for LT_L2_ETHERNET, "L3 ISIS IPv4 L1", "L3 OSPF IPv4", "L3 BGP EPE IPv4"),
        status (Up/Degraded/Down), both endpoint node names/UUIDs and interface
        names, and per-direction utilisation labels such as
        "0.00015% (1.5Kbps/1Gbps)" with a HEALTHY/... severity. L2 links come
        from LLDP collection; L3 links need an SR-PCE provider (BGP-LS).

        Paging is a row window: startRow = page * page_size,
        endRow = startRow + page_size. Past the end the platform returns
        ``totalCount`` with no rows (reported as an empty page, not an error).
        No filtering is available.

        Args:
            page_size: rows per page (1-500).
            page: 0-based page number.
            response_format: markdown (default) or json.

        Returns:
            str: Markdown "status linkType: srcNode:srcIf <-> dstNode:dstIf (util)"
            per link, or JSON:
            {"total": int, "count": int, "page": int, "page_size": int,
             "items": [{"uuid": str, "name": str, "linkType": "L2 Ethernet", "status": "Up",
                        "sourceNode-name": str, "sourceNode-uuid": str,
                        "sourceConnector-name": str, "targetNode-name": str,
                        "targetNode-uuid": str, "targetConnector-name": str,
                        "targetConnector-uto-label": str,
                        "targetConnector-uto-severity": "HEALTHY", ...}],
             "has_more": bool, "next_page": int|null, ...}
            Each item is the element's ``uuid`` merged with its ``attributes``.
            On failure: "Error: <actionable message>". An HTTP 500 "Internal Server
            Error" from /v1/topology-service/... means the service rejected the
            request body (viewId/params) — deterministic, do NOT retry.
            (It is not the inventory's "NATS request failed" signal.)
        """
        try:
            body = _rows_body(page_size, page)
            data = await _post(client, f"{TOPOLOGY}/edges", body)
            items = _flatten(data.get("elements") if isinstance(data, dict) else None)
            total = _total_count(data)
            envelope = page_envelope(
                items, result_count=total, total_count=total, page_size=page_size, page=page
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(envelope), settings)
            return finalize(_links_markdown(items, envelope), settings)
        except Exception as e:
            return format_error(e)
