"""Physical inventory — the EMF's RESTCONF view of nodes, termination points
(interfaces) and physical equipment on ``/crosswork/inventory/restconf/data/v2``.

Crosswork keeps two device inventories:

- The DLM (Device Lifecycle Management, ``/crosswork/inventory/v1``,
  cnc_list_devices / cnc_get_device) is the onboarding record: credentials,
  admin state, reachability, tags, uuids, jobs.
- The EMF (Element Management Functions) holds what was COLLECTED from a device
  once the DLM handed it over: node facts read over SNMP/CLI (software type and
  version, product family/series/type, sysObjectID, uptime, last boot), the
  termination points (interfaces) and the physical equipment (chassis, modules,
  FRUs); the EMF fault manager's device-alarm feed (cnc_list_device_alarms)
  is keyed on the same node FDNs. A device the EMF has not collected yet is
  absent here even though the DLM lists it; a node whose
  ``nd.lifecycle-state`` is ``MANAGED_AND_SYNCHRONIZED`` is one the EMF has
  collected (the only verified meaning of that state — the configuration
  backup / template tools key on the DLM device uuid, and no dependency
  between them and this state has been verified).

Everything the tools send and parse was verified live on Crosswork 7.2
(2026-09-13, platform notes "EMF RESTCONF inventory") unless a docstring says
otherwise:

- ``GET resource-physical:node`` lists every node; ``?name=<nd.name>`` and
  ``?fdn=<nd.fdn>`` filter it. An unknown name/fdn is a NORMAL empty answer
  (``com.lastIndex -1`` and no ``com.data``), not an error.
- ``GET resource-ems:termination-point?ndFdn=<node fdn>`` lists a node's
  termination points (``&type=CTP|FTP|PTP`` narrows the type). An unknown
  ndFdn is HTTP 400 ``{"rc.errors": {"error": {"error-tag": "invalid-value",
  "error-app-tag": "FW.0089", "error-message": "Cannot find device with Node
  Name: <name>"}}}`` — the ``rc.errors`` spelling — which the tools turn into
  "the EMF has no node ...". Every OTHER ``rc.errors`` document (any status;
  the notification service answers 500 ``rc.errors`` too) is rendered by this
  module as "EMF RESTCONF rejected the request (HTTP <status>): <error-tag>
  [<error-app-tag>]: <error-message>" — never through the generic RESTCONF
  hints in :mod:`cnc_mcp.errors`, which describe the topology NBI's YANG keys
  and would be wrong advice for an EMF filter/FDN problem.
- ``resource-physical:chassis`` / ``module`` / ``equipment`` answer EMPTY on
  the lab's XRd routers (containerised IOS XR exposes no physical entities).

FDN grammar (``nd.fdn`` / ``tp.fdn``): a node is ``MD=CISCO_EMS!ND=<nd.name>``
(management domain ``CISCO_EMS``, then the node name); a termination point
appends a ``!<type>=name=<if>;lr=<layer-rate>[;ADDRESS=<ip>]`` segment, e.g.
``MD=CISCO_EMS!ND=PE1!CTP=name=GigabitEthernet0/0/0/0;lr=lr-ip;ADDRESS=10.1.1.1``
for an IP CTP and ``...!FTP=name=GigabitEthernet0/0/0/0;lr=lr-gigabit-ethernet``
for the port-layer entry of the same interface on the lab. The same interface
name can appear once per layer (an IP CTP and its FTP/PTP port entry).

Termination-point classes (``tp.type`` / the ``type=`` filter): the model
behind this API (EPNM's TMF814-style inventory) distinguishes CTP (connection
termination point — the IP/sub-layer view, ``lr-ip``, carrying ``tp.ip-tp``),
PTP (physical termination point — the port itself) and FTP (floating
termination point — a logical interface not bound to one port; the spec's own
example is ``FTP=name=BVI101;lr=lr-bridge``). Verified on the lab: CTPs hold
the IP and loopback entries; on the XRd routers, which have no physical
entities, EVERY Ethernet port appears as an FTP and PTP answers empty. On
hardware routers expect ports under PTP and only BVIs/bundles/loopback-like
interfaces under FTP — not verified live, so filter on the interface name
rather than trusting one class when the hardware is unknown.

Dialect (:mod:`cnc_mcp.emf`): every request is a GET with EXACTLY
``Accept: application/json`` (:data:`cnc_mcp.emf.EMF_HEADERS`) — any other
Accept value makes the service answer XML with HTTP 200, which
:func:`cnc_mcp.emf.decode_json` reports as an Error instead of parsing. Paging
is ``?.startIndex=<0-based offset>&.maxCount=<1..100>`` with the position in
the body (``com.header`` ``com.firstIndex`` / ``com.lastIndex``; ``-1`` =
empty). A ``limit`` above 100 is served by walking several pages. Object keys
are the verbatim namespace-prefixed names (``nd.name``, ``tp.fdn``); JSON
output keeps them, markdown labels drop the prefix.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Annotated, Any

import httpx
from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.emf import (
    EMF_HEADERS,
    EMF_INVENTORY,
    MAX_COUNT,
    decode_json,
    page_envelope_from,
    page_params,
    unwrap,
)
from cnc_mcp.errors import PlatformError, format_error, http_error
from cnc_mcp.formatting import ResponseFormat, finalize, to_json
from cnc_mcp.safety import AppContext, register_tool

NODE_PATH = f"{EMF_INVENTORY}/resource-physical:node"
TP_PATH = f"{EMF_INVENTORY}/resource-ems:termination-point"
CHASSIS_PATH = f"{EMF_INVENTORY}/resource-physical:chassis"
MODULE_PATH = f"{EMF_INVENTORY}/resource-physical:module"
EQUIPMENT_PATH = f"{EMF_INVENTORY}/resource-physical:equipment"

# Management-domain prefix of every EMF FDN (verified: "MD=CISCO_EMS!ND=PE1").
EMS_DOMAIN = "MD=CISCO_EMS"
# Termination-point classes the `type=` filter accepts (spec). By model: CTP = the
# IP/connection layer, PTP = the physical port, FTP = a floating/logical interface
# (the spec's example is a BVI). Seen live on XRd: CTP and FTP only — every Ethernet
# port shows as an FTP there because virtual XR has no physical entities.
TP_TYPES = ("CTP", "FTP", "PTP")
TP_TYPE_HELP = (
    "CTP = IP/connection-layer termination points (lr-ip, tp.ip-tp holds the address); "
    "PTP = physical ports (by model; empty on the lab's virtual XRd routers); "
    "FTP = floating/logical interfaces such as BVIs and bundles (by model) — on XRd every "
    "Ethernet port appears here"
)
# The lifecycle state that means "collected" (RC_Node lifecycleState enum in the spec).
LIFECYCLE_SYNCHRONIZED = "MANAGED_AND_SYNCHRONIZED"
# The verified 400 for an unknown ndFdn: error-app-tag FW.0089 / "Cannot find device
# with Node Name: <name>" under the EMF's "rc.errors" spelling.
UNKNOWN_NODE_APP_TAG = "FW.0089"
UNKNOWN_NODE_MARKER = "cannot find device with node name"
# Objects a list tool returns per call at most; the EMF serves at most 100 per request
# (MAX_COUNT), so a larger limit walks several pages.
LIST_LIMIT_MAX = 500
# Upper bound on the pages one full scan walks (the summary): 100 x 100 = 10 000 objects.
SCAN_MAX_PAGES = 100
SCAN_LIMIT = SCAN_MAX_PAGES * MAX_COUNT
# Keys whose values carry a YANG namespace prefix ("com:admin-state-up", "lr:lr-ip");
# markdown drops the prefix, JSON keeps it.
NS_VALUE_KEYS = frozenset({"tp.admin-state", "tp.oper-state", "tp.layer-rate", "tp.directionality"})

_KEY_PREFIX_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*\.(?=.)")
_VALUE_PREFIX_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*:(?=.)")
_STATUS_CODE_RE = re.compile(r'code\s*=\s*"([^"]*)"')
_ND_SEGMENT_RE = re.compile(r"(?:^|!)ND=([^!]+)")
_MESSAGE_NAME_RE = re.compile(r"Node Name:\s*(.+?)\s*$")
_WS_RE = re.compile(r"\s+")


# --- pure helpers ------------------------------------------------------------


def node_fdn(name: str) -> str:
    """``'PE1'`` -> ``'MD=CISCO_EMS!ND=PE1'`` (the verified node FDN grammar)."""
    return f"{EMS_DOMAIN}!ND={name.strip()}"


def node_name_from_fdn(fdn: str | None) -> str | None:
    """The ``ND=`` segment of an EMF FDN (node or termination point), else None."""
    if not isinstance(fdn, str):
        return None
    match = _ND_SEGMENT_RE.search(fdn)
    return match.group(1).strip() if match else None


def label(key: Any) -> str:
    """Markdown label for a prefixed key: ``'nd.management-address'`` -> ``'management-address'``
    (the prefix is dropped only in labels; JSON output keeps the verbatim keys)."""
    return _KEY_PREFIX_RE.sub("", key, count=1) if isinstance(key, str) else str(key)


def strip_ns(value: Any) -> Any:
    """``'com:admin-state-up'`` -> ``'admin-state-up'``, ``'lr:lr-ip'`` -> ``'lr-ip'``.

    Only for the namespace-qualified state/rate strings (see :data:`NS_VALUE_KEYS`);
    non-strings and strings without a ``<prefix>:`` come back unchanged.
    """
    return _VALUE_PREFIX_RE.sub("", value, count=1) if isinstance(value, str) else value


def one_line(value: Any) -> str:
    """A scalar as one line of markdown (whitespace collapsed; None -> '-')."""
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "true" if value else "false"
    return _WS_RE.sub(" ", str(value)).strip() or "-"


def collection_status_code(value: Any) -> str:
    """The ``code`` attribute of the ``nd.collection-status`` XML snippet, else the raw text.

    Documented shape: ``<status><general code="SUCCESS"/></status>``.
    """
    if not isinstance(value, str) or not value.strip():
        return "-"
    match = _STATUS_CODE_RE.search(value)
    return match.group(1) if match else one_line(value)


def node_name(node: dict[str, Any]) -> str:
    """``nd.name`` (verified key); ``fdtn.name`` is the documented spelling on
    equipment objects and is accepted as a fallback; last resort the FDN's ND= part."""
    for key in ("nd.name", "fdtn.name"):
        value = node.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return node_name_from_fdn(node.get("nd.fdn")) or "?"


def software_of(node: dict[str, Any]) -> str:
    """``'IOS XR 24.3.1'`` from ``nd.software-type`` / ``nd.software-version`` ('?' parts)."""
    stype = one_line(node.get("nd.software-type"))
    version = one_line(node.get("nd.software-version"))
    return f"{stype if stype != '-' else '?'} {version if version != '-' else '?'}"


def node_line(node: dict[str, Any]) -> str:
    """One markdown line per node for the list tool."""
    states = (
        f"{one_line(node.get('nd.lifecycle-state'))}, "
        f"{one_line(node.get('nd.communication-state'))}"
    )
    parts = [
        states,
        software_of(node),
        one_line(node.get("nd.product-type")),
        f"up {one_line(node.get('nd.sys-up-time'))}",
        f"collected {one_line(node.get('nd.collection-time'))}",
        f"fdn {one_line(node.get('nd.fdn'))}",
    ]
    return f"- **{node_name(node)}** {one_line(node.get('nd.management-address'))} — " + "; ".join(
        parts
    )


def ip_prefix_of(tp: dict[str, Any]) -> str | None:
    """``tp.ip-tp.tp.ip-address-prefix`` when the termination point carries an IP."""
    ip_tp = tp.get("tp.ip-tp")
    if not isinstance(ip_tp, dict):
        return None
    prefix = ip_tp.get("tp.ip-address-prefix")
    if isinstance(prefix, str) and prefix.strip():
        return prefix.strip()
    addresses = ip_tp.get("tp.ip-address")
    if isinstance(addresses, list) and addresses:
        return ", ".join(str(a) for a in addresses)
    return None


def tp_line(tp: dict[str, Any]) -> str:
    """One markdown line per termination point for the list tool."""
    parts = [
        f"{one_line(tp.get('tp.type'))} {one_line(strip_ns(tp.get('tp.layer-rate')))}",
        f"{one_line(strip_ns(tp.get('tp.admin-state')))} / "
        f"{one_line(strip_ns(tp.get('tp.oper-state')))}",
    ]
    prefix = ip_prefix_of(tp)
    if prefix:
        parts.append(f"ip {prefix}")
    if tp.get("tp.duplex-mode"):
        parts.append(one_line(tp.get("tp.duplex-mode")))
    description = one_line(tp.get("tp.description"))
    if description != "-":
        parts.append(f'"{description}"')
    parts.append(f"fdn {one_line(tp.get('tp.fdn'))}")
    return f"- **{one_line(tp.get('tp.discovered-name'))}** " + "; ".join(parts)


def render_value(key: Any, value: Any, depth: int = 0) -> list[str]:
    """Markdown bullet(s) for one field: scalars on the label's line, dicts as nested
    bullets (two levels), lists of scalars comma-joined, lists of objects counted."""
    indent = "  " * depth
    name = label(key)
    if key == "nd.collection-status":
        return [f"{indent}- {name}: {collection_status_code(value)}"]
    if key in NS_VALUE_KEYS:
        value = strip_ns(value)
    if isinstance(value, dict):
        if not value:
            return [f"{indent}- {name}: {{}}"]
        if depth >= 2:
            return [f"{indent}- {name}: {json.dumps(value, default=str)}"]
        lines = [f"{indent}- {name}:"]
        for sub_key, sub_value in value.items():
            lines.extend(render_value(sub_key, sub_value, depth + 1))
        return lines
    if isinstance(value, list):
        if not value:
            return [f"{indent}- {name}: (none)"]
        if all(not isinstance(v, dict | list) for v in value):
            return [f"{indent}- {name}: {', '.join(one_line(v) for v in value)}"]
        return [f"{indent}- {name}: {len(value)} entries (response_format='json' has them)"]
    return [f"{indent}- {name}: {one_line(value)}"]


def detail_lines(obj: dict[str, Any]) -> list[str]:
    """Every field of an EMF object as markdown bullets, prefixes stripped from labels."""
    lines: list[str] = []
    for key, value in obj.items():
        lines.extend(render_value(key, value))
    return lines


def count_by(items: list[dict[str, Any]], key_fn: Any) -> dict[str, int]:
    """``{value: count}`` sorted by count (desc) then value; missing values count as '?'."""
    counter: Counter[str] = Counter()
    for item in items:
        value = key_fn(item)
        counter[one_line(value) if value not in (None, "") else "?"] += 1
    return dict(sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])))


def counts_text(counts: dict[str, int]) -> str:
    return ", ".join(f"{name} {n}" for name, n in counts.items()) or "none"


def rc_errors(data: Any) -> list[dict[str, Any]]:
    """The ``error`` entries of an EMF ``rc.errors`` document, else an empty list.

    The EMF RESTCONF services spell their error document ``{"rc.errors":
    {"error": {...}}}`` (verified live: the inventory's FW.0089 400 and the
    notification service's NOT.* 400/500s) — ``error`` is a single object, not
    the RFC 8040 list; a list is accepted too. Non-dict entries are skipped.
    """
    if not isinstance(data, dict):
        return []
    block = data.get("rc.errors")
    if not isinstance(block, dict):
        return []
    entries = block.get("error")
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, list):
        return []
    return [e for e in entries if isinstance(e, dict)]


def rc_errors_text(entries: list[dict[str, Any]]) -> str:
    """``invalid-value [FW.0089]: Cannot find device with Node Name: nope`` per entry ('; ')."""
    parts = []
    for entry in entries:
        tag = one_line(entry.get("error-tag"))
        text = tag if tag != "-" else "error"
        app_tag = one_line(entry.get("error-app-tag"))
        if app_tag != "-":
            text += f" [{app_tag}]"
        message = one_line(entry.get("error-message"))
        if message != "-":
            text += f": {message}"
        parts.append(text)
    return "; ".join(parts)


def emf_rejection(status: int, entries: list[dict[str, Any]]) -> PlatformError:
    """The PlatformError for an ``rc.errors`` answer that is not the unknown-node case.

    Rendered here on purpose: the generic RESTCONF hints in
    :mod:`cnc_mcp.errors` describe the topology NBI's YANG keys (TE router-ids,
    colors) and would misdirect an agent whose EMF filter or FDN is wrong.
    """
    detail = rc_errors_text(entries).rstrip(".")
    return PlatformError(
        f"EMF RESTCONF rejected the request (HTTP {status}): {detail}. "
        "The error-tag / error-app-tag / error-message are the EMF service's own; check the "
        "query parameter names and values this tool sent (name=, fdn=, ndFdn=, "
        f"type={'|'.join(TP_TYPES)}, .startIndex/.maxCount 1..{MAX_COUNT}) and the FDN "
        "grammar MD=CISCO_EMS!ND=<node>[!<CTP|FTP|PTP>=name=<if>;lr=<rate>[;ADDRESS=<ip>]]."
    )


def unknown_node_message(data: Any) -> str | None:
    """The ``error-message`` of the verified unknown-ndFdn 400, else None.

    Matches the EMF ``rc.errors`` document (``error`` a single object, or a list)
    on ``error-app-tag`` FW.0089 or the "Cannot find device with Node Name" text.
    """
    for entry in rc_errors(data):
        message = str(entry.get("error-message") or "")
        if (
            str(entry.get("error-app-tag") or "").upper() == UNKNOWN_NODE_APP_TAG
            or UNKNOWN_NODE_MARKER in message.lower()
        ):
            return message or "Cannot find device"
    return None


def name_from_unknown_node_message(message: str) -> str | None:
    """``'Cannot find device with Node Name: nope'`` -> ``'nope'``."""
    match = _MESSAGE_NAME_RE.search(message or "")
    return match.group(1) if match else None


def no_node_error(name: str) -> PlatformError:
    return PlatformError(f"the EMF has no node '{name}' (list with cnc_list_ems_nodes)")


def error_text(e: Exception) -> str:
    """:func:`format_error`'s message without its ``Error: `` prefix (for partial results)."""
    text = format_error(e)
    return text.removeprefix("Error: ")


def emf_body(response: httpx.Response, node_label: str | None = None) -> Any:
    """The decoded body of an EMF RESTCONF answer, or the PlatformError it means.

    Non-success answers are classified from their body, in this order:

    1. an ``rc.errors`` document saying the node is unknown (verified: HTTP 400,
       ``error-app-tag`` FW.0089 for an unknown ``ndFdn``) becomes "the EMF has
       no node '<name>'" — ``node_label`` names the node the caller asked for,
       else the name is taken from the message;
    2. any other ``rc.errors`` document, whatever the status, becomes
       :func:`emf_rejection` ("EMF RESTCONF rejected the request (HTTP <n>):
       <error-tag> [<error-app-tag>]: <error-message>");
    3. everything else goes through :func:`cnc_mcp.errors.http_error` (403 ->
       privilege/path hint, 500 NATS, home-app fallback, ...).

    A 200 with an XML body raises the Accept-header explanation.
    """
    if not response.is_success:
        try:
            data = response.json()
        except ValueError:
            data = None
        message = unknown_node_message(data)
        if message is not None:
            raise no_node_error(node_label or name_from_unknown_node_message(message) or "?")
        entries = rc_errors(data)
        if entries:
            raise emf_rejection(response.status_code, entries)
        raise http_error(response)
    return decode_json(response.text)


def node_selector(name: str | None, fdn: str | None) -> dict[str, str]:
    """Exactly one of name / fdn (non-blank) -> the ``resource-physical:node`` filter."""
    name_value = (name or "").strip()
    fdn_value = (fdn or "").strip()
    if bool(name_value) == bool(fdn_value):
        raise PlatformError(
            "Pass exactly one of 'name' (the EMF node name, e.g. 'PE1') or 'fdn' "
            "(e.g. 'MD=CISCO_EMS!ND=PE1') to select the node."
        )
    return {"name": name_value} if name_value else {"fdn": fdn_value}


def tp_scope(node: str | None, fdn: str | None) -> tuple[str | None, str | None]:
    """``(ndFdn, node label)`` for the termination-point list: at most one of
    node (a name, turned into its FDN) / fdn; neither -> unscoped (None, None)."""
    node_value = (node or "").strip()
    fdn_value = (fdn or "").strip()
    if node_value and fdn_value:
        raise PlatformError(
            "Pass at most one of 'node' (the EMF node name, e.g. 'PE1') or 'fdn' "
            "(its FDN, e.g. 'MD=CISCO_EMS!ND=PE1'), not both."
        )
    if node_value:
        return node_fdn(node_value), node_value
    if fdn_value:
        return fdn_value, node_name_from_fdn(fdn_value) or fdn_value
    return None, None


def canonical_tp_type(value: str | None) -> str | None:
    """'ctp' -> 'CTP'; None/blank -> None; anything else -> PlatformError (nothing sent)."""
    if value is None or not value.strip():
        return None
    wanted = value.strip().upper()
    if wanted in TP_TYPES:
        return wanted
    raise PlatformError(
        f"Unknown termination-point type '{value}'. Use one of: {', '.join(TP_TYPES)} "
        f"({TP_TYPE_HELP})."
    )


def equipment_note(chassis: int | None, modules: int | None, equipment: int | None) -> str:
    """Why the physical-entity counts may be zero (verified on the lab's XRd routers).

    Only when all three counts are known and 0; a count that is unavailable
    (None) or non-zero says nothing about virtual routers.
    """
    if chassis != 0 or modules != 0 or equipment != 0:
        return ""
    return (
        "The EMF collected no physical entities: containerised/virtual IOS XR (XRd, the "
        "lab's routers) exposes no chassis, module or FRU inventory, so all three "
        "collections are empty there; hardware routers fill them from their entity "
        "inventory after collection (documented, not seen live)."
    )


def physical_count_text(count: int | None, full: bool) -> str:
    """``'0'``, ``'37'`` or ``'100+'`` (a full first page) — ``'?'`` when unavailable."""
    if count is None:
        return "?"
    return f"{count}+" if full else str(count)


def summary_head(payload: dict[str, Any]) -> str:
    total = payload["nodes"]
    synced = payload["lifecycle_state"].get(LIFECYCLE_SYNCHRONIZED, 0)
    return f"# EMF inventory: {total} nodes, {synced} {LIFECYCLE_SYNCHRONIZED}"


# --- tools -------------------------------------------------------------------


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    async def get_page(
        path: str,
        params: dict[str, Any],
        start_index: int,
        max_count: int,
        node_label: str | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, int | None]]:
        """One EMF page: ``GET path?.startIndex&.maxCount&<filters>`` with EMF_HEADERS."""
        query: dict[str, Any] = {**page_params(start_index, max_count), **params}
        response = await client.request(
            "GET", path, headers=EMF_HEADERS, params=query, raise_on_error=False
        )
        items, header = unwrap(emf_body(response, node_label))
        return [i for i in items if isinstance(i, dict)], header

    async def get_filtered(
        path: str, params: dict[str, Any], node_label: str | None = None
    ) -> list[dict[str, Any]]:
        """A keyed lookup (``?name=`` / ``?fdn=``) without paging — the verified request."""
        response = await client.request(
            "GET", path, headers=EMF_HEADERS, params=params, raise_on_error=False
        )
        items, _ = unwrap(emf_body(response, node_label))
        return [i for i in items if isinstance(i, dict)]

    async def get_many(
        path: str,
        params: dict[str, Any],
        start_index: int,
        wanted: int,
        node_label: str | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, int | None]]:
        """Up to ``wanted`` objects from ``start_index``, in pages of at most MAX_COUNT.

        A single page comes back with its real ``com.header`` (so the envelope's
        has_more follows lastIndex vs the limit exactly as the EMF reports it);
        several pages are merged under one synthetic header spanning them all,
        so :func:`page_envelope_from` reports has_more when the last page was
        full. The walk stops at a short page, at ``wanted`` objects, or after
        SCAN_MAX_PAGES pages (a guard against a platform that keeps answering
        full pages). Advances by the number of objects received, which is
        right whether the header positions are absolute or page-relative.
        """
        items: list[dict[str, Any]] = []
        header: dict[str, int | None] = {
            "first_index": None,
            "last_index": None,
            "iterator_id": None,
        }
        first_header: dict[str, int | None] | None = None
        start = start_index
        pages = 0
        while len(items) < wanted and pages < SCAN_MAX_PAGES:
            count = min(MAX_COUNT, wanted - len(items))
            page_items, header = await get_page(path, params, start, count, node_label)
            pages += 1
            if first_header is None:
                first_header = header
            items.extend(page_items)
            if len(page_items) < count:
                break  # a short (or empty: lastIndex -1) page ends the walk
            start += len(page_items)
        if pages <= 1:
            return items, first_header or header
        first = first_header["first_index"] if first_header else None
        first = first if first is not None else 0
        return items, {
            "first_index": first,
            "last_index": first + len(items) - 1 if items else -1,
            "iterator_id": header.get("iterator_id"),
        }

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_ems_nodes",
        title="List EMF Nodes",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_ems_nodes(
        name: Annotated[
            str | None,
            Field(
                description=(
                    "Exact EMF node name to filter on (sent as ?name=), e.g. 'PE1'. No "
                    "wildcard; omit to list every node the EMF holds."
                ),
                max_length=253,
            ),
        ] = None,
        limit: Annotated[
            int,
            Field(
                description=(
                    f"Nodes to return, 1..{LIST_LIMIT_MAX} (e.g. 50). The EMF serves at most "
                    f"{MAX_COUNT} per request; a larger limit walks several pages."
                ),
                ge=1,
                le=LIST_LIMIT_MAX,
            ),
        ] = 50,
        offset: Annotated[
            int, Field(description="0-based object offset (.startIndex), e.g. 0.", ge=0)
        ] = 0,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the nodes the EMF (Element Management Functions) has collected:
        management address, lifecycle and communication state, software type and
        version, product type, uptime, last collection time and FDN.

        Read-only; ``GET /crosswork/inventory/restconf/data/v2/resource-physical:node``
        with ``.startIndex``/``.maxCount`` paging and ``?name=<name>`` when a name
        is given (verified live). This is the EMF's view — what was actually
        collected from each device over SNMP/CLI — and is DISTINCT from the DLM
        inventory (cnc_list_devices: the onboarding record with credentials,
        admin state, reachability and tags). A device the DLM lists but the EMF
        has not collected yet is absent here; use cnc_list_devices for "is it
        onboarded / reachable" and this tool for "what did Crosswork learn from
        it". ``nd.lifecycle-state`` MANAGED_AND_SYNCHRONIZED means the EMF
        collected the device (verified: every collected lab node reads it);
        MANAGED_BUT_NEVERSYNCHRONIZED / MANAGED_BUT_OUTOFSYNC /
        MANAGED_BUT_LOSSOFCONNECTIVITY (documented enum) mean collection has
        not happened or failed (nd.collection-status says why, see
        cnc_get_ems_node). Do not infer more from the state: the configuration
        backup / template tools key on the DLM device uuid and no dependency
        on this state has been verified. ``nd.communication-state``
        (Reachable, ...) is the EMF's own reachability. ``nd.fdn``
        (``MD=CISCO_EMS!ND=<name>``) is the key every other EMF call takes
        (termination points; the device-alarm feed's nd-ref).
        Unknown name -> a normal empty answer, not an error. Sends exactly
        ``Accept: application/json`` (anything else makes the EMF answer XML).

        Args:
            name: exact node name filter (e.g. 'PE1'); omit for all nodes.
            limit / offset: page size (1..500) and 0-based start index.

        Returns:
            str: Markdown "- **PE1** 198.18.140.11 — MANAGED_AND_SYNCHRONIZED,
            Reachable; IOS XR 24.3.1; <product-type>; up <sys-up-time>;
            collected <time>; fdn MD=CISCO_EMS!ND=PE1" lines, or JSON:
            {"total": null, "count": int, "offset": int,
             "items": [{"nd.fdn", "nd.name", "nd.management-address",
                        "nd.lifecycle-state", "nd.communication-state",
                        "nd.software-type", "nd.software-version", "nd.product-type",
                        "nd.sys-up-time", "nd.collection-time", ...verbatim nd.* keys}],
             "has_more": bool, "next_offset": int|null, "first_index", "last_index",
             "iterator_id", "start_index", "max_count", "next_start_index"}
            An empty page is not an error ("The EMF has no node named 'x' ...").
            On failure: "Error: ..." (403 -> the account lacks the inventory
            read privilege; an XML body -> the Accept header explanation).
        """
        try:
            params: dict[str, Any] = {}
            if name and name.strip():
                params["name"] = name.strip()
            items, header = await get_many(NODE_PATH, params, offset, limit)
            envelope = page_envelope_from(items, header, offset, limit)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(envelope), settings)
            if not items:
                if params:
                    message = (
                        f"The EMF has no node named '{params['name']}' (exact match; list "
                        "every EMF node without a name, or check the DLM inventory with "
                        "cnc_list_devices — a device the EMF has not collected is absent "
                        "here)."
                    )
                elif offset:
                    message = f"The EMF reports no nodes at offset {offset}."
                else:
                    message = (
                        "The EMF reports no nodes: nothing has been collected yet (the DLM "
                        "inventory is cnc_list_devices)."
                    )
                return finalize(message, settings)
            scope = f", name '{params['name']}'" if params else ""
            lines = [f"# EMF nodes ({len(items)} shown from offset {offset}{scope})", ""]
            lines.extend(node_line(n) for n in items)
            if envelope.get("has_more"):
                lines.extend(["", f"More available: repeat with offset={envelope['next_offset']}."])
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_ems_node",
        title="Get EMF Node",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_ems_node(
        name: Annotated[
            str | None,
            Field(description="Exact EMF node name (sent as ?name=), e.g. 'PE1'.", max_length=253),
        ] = None,
        fdn: Annotated[
            str | None,
            Field(
                description="Node FDN (sent as ?fdn=), e.g. 'MD=CISCO_EMS!ND=PE1'.",
                max_length=500,
            ),
        ] = None,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get everything the EMF collected about one node: description (the
        device's version banner), product family/series/type/vendor, software
        type/version, sysObjectID, management address, lifecycle and
        communication state, collection status/time, creation and last-boot
        times, uptime, FDN and uuid.

        Read-only; ``GET .../resource-physical:node?name=<name>`` or
        ``?fdn=<fdn>`` (both verified live). Pass exactly one selector. An
        unknown node is a normal empty answer on the wire (``com.lastIndex -1``)
        and is reported here as "Error: the EMF has no node '<x>' (list with
        cnc_list_ems_nodes)". The spec says names are not unique; when several
        nodes share the name the tool refuses and lists their FDNs so you can
        pick one with fdn=. ``nd.collection-status`` is an XML snippet
        (``<status><general code="SUCCESS"/></status>``): markdown shows its
        code, JSON the raw text. Use it to check why a device is not
        MANAGED_AND_SYNCHRONIZED, to read the exact software version the EMF
        saw, or to get the FDN for cnc_list_ems_interfaces /
        cnc_list_device_alarms. For the DLM record (credentials, admin state,
        tags) use cnc_get_device.

        Returns:
            str: Markdown "# EMF node PE1 (MD=CISCO_EMS!ND=PE1)" followed by one
            "- <field>: <value>" line per nd.* field (prefix dropped from the
            labels; nested lists such as equipment-list are counted), or JSON:
            the node object with its verbatim keys ({"nd.fdn", "nd.name",
            "nd.management-address", "nd.lifecycle-state",
            "nd.communication-state", "nd.collection-status", "nd.collection-time",
            "nd.creation-time", "nd.last-boot-time", "nd.description",
            "nd.product-family", "nd.product-series", "nd.product-type",
            "nd.product-vendor", "nd.software-type", "nd.software-version",
            "nd.sys-object-id", "nd.sys-up-time", "nd.instanceId", "nd.uuid", ...}).
            "Error: Pass exactly one of 'name' or 'fdn' ..." (nothing sent),
            "Error: the EMF has no node '<x>' ..." when nothing matches, "Error:
            name '<x>' matches N EMF nodes ..." when ambiguous, "Error: ..." on
            an API failure.
        """
        try:
            selector = node_selector(name, fdn)
            key, value = next(iter(selector.items()))
            nodes = await get_filtered(NODE_PATH, selector, node_label=value)
            if not nodes:
                raise no_node_error(value)
            if len(nodes) > 1:
                fdns = ", ".join(one_line(n.get("nd.fdn")) for n in nodes[:10])
                raise PlatformError(
                    f"{key} '{value}' matches {len(nodes)} EMF nodes ({fdns}); select one "
                    "with fdn='<nd.fdn>'."
                )
            node = nodes[0]
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(node), settings)
            lines = [f"# EMF node {node_name(node)} ({one_line(node.get('nd.fdn'))})", ""]
            lines.extend(detail_lines(node))
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_ems_interfaces",
        title="List EMF Termination Points",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_ems_interfaces(
        node: Annotated[
            str | None,
            Field(
                description=(
                    "EMF node NAME whose termination points to list, e.g. 'PE1' (turned into "
                    "ndFdn=MD=CISCO_EMS!ND=PE1). Alternative to fdn."
                ),
                max_length=253,
            ),
        ] = None,
        fdn: Annotated[
            str | None,
            Field(
                description=(
                    "Node FDN to scope on (sent as ?ndFdn=), e.g. 'MD=CISCO_EMS!ND=PE1'. "
                    "Alternative to node."
                ),
                max_length=500,
            ),
        ] = None,
        tp_type: Annotated[
            str | None,
            Field(
                description=(
                    "Termination-point type filter (sent as ?type=): 'CTP' (IP/connection "
                    "layer: IP and loopback entries), 'PTP' (physical ports by model; empty "
                    "on virtual XRd) or 'FTP' (floating/logical interfaces by model; on XRd "
                    "every Ethernet port shows here). E.g. 'CTP'."
                ),
                max_length=8,
            ),
        ] = None,
        limit: Annotated[
            int,
            Field(
                description=(
                    f"Termination points to return, 1..{LIST_LIMIT_MAX} (e.g. 50). The EMF "
                    f"serves at most {MAX_COUNT} per request; a larger limit walks pages."
                ),
                ge=1,
                le=LIST_LIMIT_MAX,
            ),
        ] = 50,
        offset: Annotated[
            int, Field(description="0-based object offset (.startIndex), e.g. 0.", ge=0)
        ] = 0,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List a node's termination points (interfaces) as the EMF collected
        them: name, type, layer rate, admin/oper state, description, IP prefix,
        duplex mode and FDN.

        Read-only; ``GET .../resource-ems:termination-point?ndFdn=<node fdn>``
        (verified live) with ``&type=CTP|FTP|PTP`` when tp_type is given and
        ``.startIndex``/``.maxCount`` paging. Give the node by NAME (node='PE1'
        builds the FDN ``MD=CISCO_EMS!ND=PE1``) or by fdn (from cnc_list_ems_nodes);
        with neither the whole EMF's termination points are listed (documented,
        not verified live). Types, by the TMF814-style model behind this API:
        CTP = connection termination point, the IP/sub-layer view (``lr-ip``,
        ``tp.ip-tp`` holds the address/prefix — verified: IP and loopback
        entries); PTP = physical termination point, the port itself; FTP =
        floating termination point, a logical interface not bound to one port
        (the spec's example is ``FTP=name=BVI101;lr=lr-bridge``). Verified on
        the lab's XRd routers, which expose no physical entities: EVERY
        Ethernet port appears as an FTP and PTP answers empty — so on virtual
        XR filter FTP for ports; on hardware routers expect ports under PTP and
        BVIs/bundles under FTP (not verified live), or match on the interface
        name across all types. The same interface name can appear once per
        layer — GigabitEthernet0/0/0/0 as a CTP (its IP) and as an FTP/PTP (the
        port) — so filter with tp_type when you want one view. An unknown
        node is HTTP 400 on the wire ("Cannot find device with Node Name",
        error-app-tag FW.0089) and is reported as "Error: the EMF has no node
        '<name>' (list with cnc_list_ems_nodes)"; any other EMF rejection
        (an unsupported filter, a malformed FDN) is "Error: EMF RESTCONF
        rejected the request (HTTP <n>): <error-tag> [<error-app-tag>]:
        <error-message>". A known node with no termination points of the
        requested type is a normal empty answer.
        ``tp.admin-state`` / ``tp.oper-state`` / ``tp.layer-rate`` carry YANG
        prefixes on the wire (``com:admin-state-up``, ``lr:lr-ip``): markdown
        drops them, JSON keeps them. For the DLM/topology view of interfaces
        use the topology tools; this is what the device itself reported.

        Args:
            node: EMF node name (e.g. 'PE1'), or
            fdn: node FDN (e.g. 'MD=CISCO_EMS!ND=PE1') — at most one of the two.
            tp_type: CTP | PTP | FTP (case-insensitive); omit for every type.
            limit / offset: page size (1..500) and 0-based start index.

        Returns:
            str: Markdown "- **GigabitEthernet0/0/0/0** CTP lr-ip; admin-state-up /
            oper-state-up; ip 10.1.1.1/30; FullDuplex; "<description>"; fdn
            MD=CISCO_EMS!ND=PE1!CTP=name=GigabitEthernet0/0/0/0;lr=lr-ip;ADDRESS=10.1.1.1"
            lines, or JSON:
            {"total": null, "count": int, "offset": int,
             "items": [{"tp.fdn", "tp.discovered-name", "tp.node-name", "tp.type",
                        "tp.layer-rate", "tp.admin-state", "tp.oper-state",
                        "tp.description", "tp.is-edge-point", "tp.duplex-mode",
                        "tp.ip-tp": {"tp.ip-address": [str], "tp.subnet-mask": int,
                                     "tp.ip-address-prefix": str, "tp.cast-type": str}?,
                        ...verbatim tp.* keys}],
             "has_more": bool, "next_offset": int|null, "first_index", "last_index",
             "iterator_id", "start_index", "max_count", "next_start_index"}
            "Error: the EMF has no node '<x>' ..." for an unknown node; "Error:
            Unknown termination-point type ..." / "Error: Pass at most one of
            'node' or 'fdn'" (nothing sent); "Error: ..." on an API failure.
        """
        try:
            nd_fdn, node_label = tp_scope(node, fdn)
            wanted_type = canonical_tp_type(tp_type)
            params: dict[str, Any] = {}
            if nd_fdn:
                params["ndFdn"] = nd_fdn
            if wanted_type:
                params["type"] = wanted_type
            items, header = await get_many(TP_PATH, params, offset, limit, node_label)
            envelope = page_envelope_from(items, header, offset, limit)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(envelope), settings)
            scope = f" of {node_label}" if node_label else " in the EMF"
            type_text = f" of type {wanted_type}" if wanted_type else ""
            if not items:
                where = f" at offset {offset}" if offset else ""
                subject = f"Node {node_label} has" if node_label else "The EMF holds"
                return finalize(
                    f"{subject} no termination points{type_text}{where}"
                    f"{' (list all types without tp_type)' if wanted_type else ''}.",
                    settings,
                )
            lines = [
                f"# Termination points{scope} ({len(items)} shown from offset {offset}{type_text})",
                "",
            ]
            lines.extend(tp_line(tp) for tp in items)
            if envelope.get("has_more"):
                lines.extend(["", f"More available: repeat with offset={envelope['next_offset']}."])
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_ems_interface",
        title="Get EMF Termination Point",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_ems_interface(
        fdn: Annotated[
            str,
            Field(
                description=(
                    "Termination-point FDN (sent as ?fdn=), e.g. "
                    "'MD=CISCO_EMS!ND=PE1!CTP=name=GigabitEthernet0/0/0/0;lr=lr-ip;"
                    "ADDRESS=10.1.1.1' (from cnc_list_ems_interfaces)."
                ),
                min_length=1,
                max_length=1000,
            ),
        ],
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one termination point (interface) by its FDN, with every field
        the EMF collected for it.

        Read-only; ``GET .../resource-ems:termination-point?fdn=<fdn>``. NOT
        verified live: the 7.2 spec lists ``fdn`` as a filter of this endpoint
        ("to retrieve a single terminationPoint") and the node endpoint's
        ``?fdn=`` works the same way, but this exact request has not been sent
        to a live instance. An empty answer is treated as not found. Get the
        FDN from cnc_list_ems_interfaces (``tp.fdn``) — the grammar is
        ``MD=CISCO_EMS!ND=<node>!<CTP|PTP|FTP>=name=<if>;lr=<rate>[;ADDRESS=<ip>]``
        and the ADDRESS part is required for IP CTPs. If the platform answers
        the unknown-node 400 for the FDN's ND= part, the error names that
        node; any other ``rc.errors`` rejection is reported verbatim as "EMF
        RESTCONF rejected the request (HTTP <n>): ...". Prefer
        cnc_list_ems_interfaces with tp_type when you only know
        the interface name. ``tp.admin-state`` / ``tp.oper-state`` /
        ``tp.layer-rate`` prefixes (``com:``, ``lr:``) are dropped in markdown
        and kept in JSON.

        Returns:
            str: Markdown "# Termination point <name> on <node> (<fdn>)" and one
            "- <field>: <value>" line per tp.* field (ip-tp as nested bullets),
            or JSON: the termination-point object with its verbatim keys.
            "Error: the EMF has no termination point with fdn '<x>' ..." when
            nothing matches; "Error: the EMF has no node '<x>' ..." when the
            platform rejects the node; "Error: ..." on an API failure.
        """
        try:
            wanted = fdn.strip()
            if not wanted:
                raise PlatformError("fdn is empty: pass a tp.fdn from cnc_list_ems_interfaces.")
            node_label = node_name_from_fdn(wanted) or wanted
            tps = await get_filtered(TP_PATH, {"fdn": wanted}, node_label=node_label)
            if not tps:
                raise PlatformError(
                    f"the EMF has no termination point with fdn '{wanted}' (list a node's "
                    "termination points with cnc_list_ems_interfaces; the FDN must be the "
                    "verbatim tp.fdn, ADDRESS part included for IP CTPs)."
                )
            tp = tps[0]
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(tp), settings)
            on_node = tp.get("tp.node-name") or node_label
            head = (
                f"# Termination point {one_line(tp.get('tp.discovered-name'))} on "
                f"{one_line(on_node)} ({one_line(tp.get('tp.fdn'))})"
            )
            lines = [head, ""]
            lines.extend(detail_lines(tp))
            if len(tps) > 1:
                lines.extend(["", f"Note: the fdn matched {len(tps)} objects; the first is shown."])
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    async def first_page_count(path: str) -> tuple[int | None, bool, str | None]:
        """``(objects on the first page, page was full, error)`` for one physical collection.

        One ``GET path?.startIndex=0&.maxCount=100`` — never a walk: the
        physical collections are only a rough size indicator here, and a full
        walk of ``:equipment`` on a hardware deployment would be hundreds of
        sequential requests through the rate-limited gateway. A failure
        (HTTP error, XML fallback, transport) is returned as text, not raised,
        so one broken collection does not lose the node counts.
        """
        try:
            items, _ = await get_page(path, {}, 0, MAX_COUNT)
        except Exception as e:  # degrade this collection to "unavailable", keep the rest
            return None, False, error_text(e)
        return len(items), len(items) >= MAX_COUNT, None

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_ems_inventory_summary",
        title="Get EMF Inventory Summary",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_ems_inventory_summary() -> str:
        """Count what the EMF has collected: nodes by lifecycle state,
        communication state and software type/version, plus the size of the
        physical inventory (chassis, modules, equipment entries).

        Read-only. Walks ``GET .../resource-physical:node`` (every page, up to
        10 000 nodes — the health signal) and reads ONE page of 100 from each
        of ``GET .../resource-physical:chassis`` / ``:module`` / ``:equipment``
        (verified paths; the EMF reports no totals, so a full first page is
        reported as "100+" rather than walked — on a hardware deployment the
        equipment collection alone can be hundreds of entities per chassis,
        and every request goes through the rate-limited Tyk gateway). A
        physical collection that fails (403, 500, XML fallback, ...) is
        reported as unavailable with its error while the node counts still
        come back; only a failure of the node walk itself is an Error. Use it
        as the collection health check of the EMF before drilling in with
        cnc_list_ems_nodes / cnc_get_ems_node: a node not
        MANAGED_AND_SYNCHRONIZED has not been (fully) collected by the EMF
        (verified meaning; the configuration backup / template tools key on
        the DLM device uuid and no dependency on this state has been
        verified). On the lab's XRd routers all three physical counts are 0 —
        containerised/virtual IOS XR exposes no chassis, module or FRU
        inventory (verified ``com.lastIndex -1`` on each); hardware routers
        fill them from their entity inventory after collection. The equipment
        count covers every entity the equipment endpoint returns (its
        documented answer carries chassis, module and equipment lists side by
        side). Compare with cnc_get_device_summary (the DLM's counts): a device
        in the DLM but not here has not reached the EMF yet.

        Returns:
            str: Markdown ("# EMF inventory: 5 nodes, 5 MANAGED_AND_SYNCHRONIZED",
            then "- lifecycle state: ...", "- communication state: ...",
            "- software: IOS XR 24.3.1 5", "- physical inventory: 0 chassis, 0
            modules, 100+ equipment entries (first page of 100 each)", why when
            all are 0, "- physical inventory unavailable: chassis (<error>)"
            when a collection failed) followed by JSON:
            {"nodes": int,
             "lifecycle_state": {"<state>": int}, "communication_state": {"<state>": int},
             "software": {"<type> <version>": int},
             "not_synchronized": [{"name", "fdn", "lifecycle_state", "communication_state"}],
             "chassis": int|null, "modules": int|null, "equipment": int|null,
             "physical_more": ["equipment", ...]   (first page full: real count >= value),
             "physical_unavailable": {"chassis": "<error text>", ...},
             "note": str|null}   (a node walk that hit the 10 000-object guard is noted)
            On failure of the node walk: "Error: ..." (403 -> the account lacks
            the inventory read privilege; an XML body -> the Accept header
            explanation).
        """
        try:
            nodes, _ = await get_many(NODE_PATH, {}, 0, SCAN_LIMIT)
            physical: dict[str, tuple[int | None, bool, str | None]] = {}
            for what, path in (
                ("chassis", CHASSIS_PATH),
                ("modules", MODULE_PATH),
                ("equipment", EQUIPMENT_PATH),
            ):
                physical[what] = await first_page_count(path)
            counts = {what: result[0] for what, result in physical.items()}
            more = [what for what, result in physical.items() if result[1]]
            unavailable = {
                what: result[2] for what, result in physical.items() if result[2] is not None
            }
            lifecycle = count_by(nodes, lambda n: n.get("nd.lifecycle-state"))
            communication = count_by(nodes, lambda n: n.get("nd.communication-state"))
            software = count_by(nodes, software_of)
            not_synced = [
                {
                    "name": node_name(n),
                    "fdn": n.get("nd.fdn"),
                    "lifecycle_state": n.get("nd.lifecycle-state"),
                    "communication_state": n.get("nd.communication-state"),
                }
                for n in nodes
                if n.get("nd.lifecycle-state") != LIFECYCLE_SYNCHRONIZED
            ]
            note = (
                f"The node count stops at the first {SCAN_LIMIT} objects (the walk's "
                "guard); the real number may be higher."
                if len(nodes) >= SCAN_LIMIT
                else None
            )
            payload: dict[str, Any] = {
                "nodes": len(nodes),
                "lifecycle_state": lifecycle,
                "communication_state": communication,
                "software": software,
                "not_synchronized": not_synced,
                "chassis": counts["chassis"],
                "modules": counts["modules"],
                "equipment": counts["equipment"],
                "physical_more": more,
                "physical_unavailable": unavailable,
                "note": note,
            }
            physical_text = ", ".join(
                f"{physical_count_text(counts[what], what in more)} {noun}"
                for what, noun in (
                    ("chassis", "chassis"),
                    ("modules", "modules"),
                    ("equipment", "equipment entries"),
                )
            )
            lines = [
                summary_head(payload),
                "",
                f"- lifecycle state: {counts_text(lifecycle)}",
                f"- communication state: {counts_text(communication)}",
                f"- software: {counts_text(software)}",
                f"- physical inventory: {physical_text} (first page of {MAX_COUNT} each; "
                f"{MAX_COUNT}+ = the page was full)",
            ]
            why = equipment_note(counts["chassis"], counts["modules"], counts["equipment"])
            if why:
                lines.append(f"  {why}")
            if unavailable:
                failed = "; ".join(f"{what} ({error})" for what, error in unavailable.items())
                lines.append(f"- physical inventory unavailable: {failed}")
            if not_synced:
                names = ", ".join(
                    f"{n['name']} ({n['lifecycle_state'] or '?'})" for n in not_synced[:10]
                )
                extra = f", ... ({len(not_synced)} total)" if len(not_synced) > 10 else ""
                lines.append(f"- not synchronized: {names}{extra}")
            if note:
                lines.append(f"- note: {note}")
            lines.extend(["", to_json(payload)])
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)
