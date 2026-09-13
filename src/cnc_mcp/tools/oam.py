"""OAM tools — Optimization Engine trace routes and Service Health probe status.

What an OAM trace route is. The Crosswork Optimization Engine (COE) exposes an
**OAM** function on its optimization NBI: given a provisioned service (its
NSO ``yang-path``) and the inventory uuids of its head-end and tail-end
devices, the engine asks the head-end — over **gNMI**, through a collection
job on the Data Gateway — to trace the service's actual forwarding path (MPLS
OAM ``traceroute sr-mpls`` style) and stores the result as a **trace-route
query**: ``query-id`` (``SPQ-<digits>``), an integer ``status`` with a
``status-message``, the echoed inputs, ``create-time`` / ``update-time`` and,
once complete, ``path-info-list[]`` — one entry per discovered path with
source, destination, next-hop, out-interface, the device uuids on the path,
``path-details`` and ``path-status``. Queries are asynchronous (register,
then poll) and are deleted automatically after the OAM **delete interval**
(hours; cnc_get_oam_settings).

Wire facts (verified live on Crosswork 7.2, 2026-09-13 — platform notes,
"OAM RPCs"). All are RPCs on :data:`cnc_mcp.restconf.OPTIMIZATION_NBI`
(``POST .../operations/cisco-crosswork-optimization-engine-oam-operations:
<rpc>``, ``application/yang-data+json``), answering ``{"<module>:output":
{... "response-result": "valid"}}``:

- ``get-oam-delete-interval`` (NO body) -> ``{"delete-interval": 1,
  "response-result": "valid"}``.
- ``get-oam-trace-route-by-query`` ``{"input": {"start-row", "end-row"[,
  "filter-criteria", "sort-column", "sort-ascending"]}}`` ->
  ``total-count``, ``total-completed-query-count``,
  ``total-running-query-count``, ``total-failed-query-count`` and, per the
  document, ``service-routes[]`` (``service-route[]`` tolerated). **The list
  answered total-count 0 even while a query created seconds earlier was
  running or failed** — it never showed the queries, whatever filter or row
  window was sent — so the per-id read is the reliable one.
- ``get-oam-trace-route-by-query-id`` ``{"input": {"query-id"}}`` -> the
  ServiceRoute. An unknown id is answered **HTTP 200 with status 6**,
  ``status-message "Route not found for selected ID"`` and every string
  empty — not an error on the wire; the tools report it as one.
- ``set-oam-trace-route-by-calc`` ``{"input": {"yang-path",
  "head-end-node-uuid", "tail-end-node-uuid"}}`` -> status 3 "Path trace
  registered for calculation" with the new ``query-id``; polling then shows
  status 3 "Path trace running for calculation" and, ~30 s later, the
  verdict. Only **inventory uuids** identify the devices: node names
  (``head-end-node-name``) and TE router-ids are accepted (status 3) but the
  query fails within a second with status 5 "Path cannot be traced until the
  device configuration is completed, please check the device for enabling
  'mpls oam' configuration.(Could not register collection job ... empty device
  id item in list)". ``transport-type`` 1/2/3 fails with "Invalid Transport
  Type" — it is never sent (0 / absent).
- Status codes seen: **3** registered / running, **5** failed (the reason is
  the ``status-message``), **6** unknown query-id. A completed trace
  presumably carries **4** (unverified: no trace could complete on the lab)
  and the ``path-info-list``. Times are epoch-milliseconds sent as decimal
  STRINGS (``"1789324616899.0"``), rendered ISO-8601 here.

The lab limits. The lab devices are managed over SNMP + SSH only — no gNMI
connectivity type in the inventory — so every trace there fails with status 5
"Unable to trace the path and request got timed out. Check below and try
again: - Devices are running IOS-XR 7.3.2 or later - GNMI is enabled on the
devices. - GNMI port of device in crosswork is configured as per the device.
- GNMI connectivity type specified in Crosswork for the devices". That text is
the platform's verdict on the network, not an API failure, and the tools
return it without an ``Error:`` prefix. The empty-500 rule of the other COE
modules applies (a bare HTTP 500 with an empty body), but on the OAM RPCs
every verified bad-input answer is an HTTP 200 (status 5 / 6), so an empty
500 here points first at an absent or down Optimization Engine backend
(:data:`OAM_EMPTY_500_HINT`).

Service Health probe manager (``/crosswork/probemgr/v1``, plain JSON —
verified live 2026-09-13). Service Health (the ``capp-aa`` application)
monitors L2/L3 VPN services with Y.1731 / TWAMP **probes** between the service
endpoints; the probe manager reports, per service, the probe status, each
endpoint's probe agent and each sender->reflector session. ``POST
probeStatusReport {"serviceId": "<service instance path>"}`` answers **HTTP
500** with a JSON document ``{"serviceId", "enableReactivate": false,
"status": "PROBE_STATUS_UNKNOWN", "endpointStatus": [], "sessionStatus": [],
"error": "service has no active probe session"}`` when the service has no
probes — reported here as a plain non-error "no active probe session". The
populated ``200 {"data": [{serviceId, enableReactivate, status,
endpointStatus[], sessionStatus[]}]}`` shape and ``POST reactivateProbe`` ->
``{"data": [{"status": 1}]}`` follow the 7.2 document only (UNVERIFIED live).
Service Health itself is **not installed on single-VM builds** (its own
``/crosswork/aa/...`` paths answer Go's ``404 page not found``), so probe
status is always "no active probe session" there; a Go ``404 page not found``
from the probe manager path itself means the probe manager is absent or the
path is not routed on the build.

Not exposed: ``set-oam-delete-interval`` (not exercised live).
"""

from __future__ import annotations

import uuid as uuid_lib
from typing import Annotated, Any

import httpx
from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.errors import PlatformError, format_error, http_error
from cnc_mcp.formatting import ResponseFormat, epoch_iso, finalize, pagination_envelope, to_json
from cnc_mcp.polling import wait_until
from cnc_mcp.restconf import (
    OPTIMIZATION_NBI,
    YANG_ACCEPT,
    YANG_HEADERS,
    explain_empty_500,
    rpc_body,
    rpc_output,
    rpc_path,
)
from cnc_mcp.safety import AppContext, register_tool
from cnc_mcp.tools.lcm_csm import dict_list, first_reason, text_of
from cnc_mcp.tools.services import normalize_yang_path

# The YANG module of every OAM RPC (verified live 2026-09-13).
OAM_MODULE = "cisco-crosswork-optimization-engine-oam-operations"
RPC_GET_DELETE_INTERVAL = "get-oam-delete-interval"
RPC_LIST_TRACE_ROUTES = "get-oam-trace-route-by-query"
RPC_GET_TRACE_ROUTE = "get-oam-trace-route-by-query-id"
RPC_START_TRACE_ROUTE = "set-oam-trace-route-by-calc"

# Service Health probe manager (Go/JSON; verified routed on the lab).
PROBEMGR = "/crosswork/probemgr/v1"
PROBE_STATUS_URL = f"{PROBEMGR}/probeStatusReport"
REACTIVATE_PROBE_URL = f"{PROBEMGR}/reactivateProbe"

# Trace-route status codes. 3, 5 and 6 verified live; 4 is the presumed "completed"
# (no trace could complete on the lab). Anything else is shown as "status <n>".
TRACE_IN_PROGRESS = 3
TRACE_COMPLETED = 4
TRACE_FAILED = 5
TRACE_NOT_FOUND = 6
TRACE_STATUS_WORDS: dict[int, str] = {
    TRACE_IN_PROGRESS: "in progress",
    TRACE_COMPLETED: "completed",
    TRACE_FAILED: "failed",
    TRACE_NOT_FOUND: "not found",
}
NOT_FOUND_MESSAGE = "Route not found for selected ID"

# Probe manager enums (7.2 document). Ints are mapped by proto enum order — the
# document's example carries ints where the schema says strings (unverified).
PROBE_STATUS_NAMES = (
    "PROBE_STATUS_UNKNOWN",
    "PROBE_STATUS_PENDING",
    "PROBE_STATUS_SUCCESS",
    "PROBE_STATUS_ERROR",
)
REACTIVATE_STATUS_NAMES = ("RESP_STATUS_UNKNOWN", "RESP_STATUS_SUCCESS", "RESP_STATUS_ERROR")
PROBE_STATUS_UNKNOWN = PROBE_STATUS_NAMES[0]
PROBE_STATUS_SUCCESS = PROBE_STATUS_NAMES[2]
PROBE_STATUS_ERROR = PROBE_STATUS_NAMES[3]
REACTIVATE_SUCCESS = REACTIVATE_STATUS_NAMES[1]
REACTIVATE_ERROR = REACTIVATE_STATUS_NAMES[2]
# Body markers (verified live): the probe manager's "no probes" 500 and Go's plain 404.
NO_PROBE_SESSION_MARKER = "no active probe session"
GO_NOT_FOUND_MARKER = "404 page not found"

OAM_EMPTY_500_HINT = (
    "the Optimization Engine answered 500 with an EMPTY body. On this platform that is the "
    "answer of a COE backend that is absent or down, and on other COE RPCs also how the engine "
    "rejects input it cannot resolve — but every verified bad-input answer of the OAM RPCs is "
    "an HTTP 200 (an unknown query-id is status 6, a device it cannot resolve fails the query "
    "with status 5), so suspect the backend first: cnc_list_providers and "
    "cnc_get_topology_summary show whether the Optimization Engine / SR-PCE feed is up, and "
    "retrying with the same inputs will not help. If those are healthy, re-check the inputs "
    "(cnc_list_services for the service yang-path, cnc_list_devices for the inventory uuids, "
    "the query-id exactly as cnc_start_oam_trace_route returned it)."
)
PROBEMGR_NOT_ROUTED_HINT = (
    "Service Health probe manager is not installed / the path is not routed on this build: "
    "/crosswork/probemgr/v1 answered Go's plain '404 page not found'. Service Health (the "
    "capp-aa application) is optional and absent on single-VM builds; cnc_list_applications "
    "shows what is installed."
)

_RESPONSE_FORMAT_DESC = "'markdown' for human-readable output, 'json' for the raw RPC output."
_QUERY_ID_DESC = (
    "The trace-route query id as cnc_start_oam_trace_route returned it (e.g. 'SPQ-324616899')."
)
_SERVICE_ID_DESC = (
    "The service instance path (the yang-path cnc_list_services returns, relative to the NSO "
    "proxy's /data/), e.g. 'ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=mcp-l3vpn-91'."
)
_YANG_PATH_DESC = (
    "The service's yang-path as cnc_list_services returns it (e.g. "
    "'cisco-sr-te-cfp:sr-te/cisco-sr-te-cfp-sr-policies:policies/policy=mcp-policy-91' — the "
    "verified form; a leading '/' or the full proxy '/data/' prefix is accepted)."
)
_UUID_DESC = (
    "inventory uuid of the device (e.g. '3d95eb05-6f2a-4c1e-9b7d-0a1b2c3d4e5f'; "
    "cnc_get_device(host_name=...) shows it). Only uuids resolve the device — a node name or "
    "router-id registers a query that fails within a second. Any uuid spelling is accepted and "
    "sent in the canonical lower-case hyphenated form."
)


# --- pure helpers -----------------------------------------------------------------


def oam_time(value: Any) -> str:
    """``"1789324616899.0"`` -> ``2026-09-13T18:36:56Z``; ``-`` when blank/zero; raw text
    when unparseable. The OAM RPCs send epoch-milliseconds as decimal strings."""
    text = str(value).strip() if value not in (None, "") else ""
    if not text:
        return "-"
    try:
        return epoch_iso(int(float(text)))
    except (ValueError, OverflowError):
        return text


def trace_status(route: dict[str, Any]) -> int | None:
    """The integer ``status`` of a ServiceRoute (an int, or a digit string), else ``None``."""
    value = route.get("status")
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def status_word(code: int | None) -> str:
    """``in progress (3)`` for a known code, ``status <n>`` for an unknown one."""
    if code is None:
        return "status unknown"
    word = TRACE_STATUS_WORDS.get(code)
    return f"{word} ({code})" if word else f"status {code}"


def check_oam_output(output: dict[str, Any], what: str) -> dict[str, Any]:
    """Raise PlatformError for an OAM RPC that reports failure inside HTTP 200.

    The OAM module's idiom is ``response-result`` ``valid`` | ``invalid`` |
    ``error`` (its ``status`` leaf is the trace-route's integer state, not a
    verdict, so :func:`cnc_mcp.restconf.check_rpc_output` is not applied). A
    missing field is success. Returns ``output`` unchanged on success.
    """
    result = text_of(output.get("response-result")).lower()
    if result and result != "valid":
        reason = first_reason(output, "status-message", "message", "reason", "error-description")
        raise PlatformError(
            f"{what} failed: response-result {result}: {reason or 'no message given'}"
        )
    return output


def not_found_error(query_id: str, route: dict[str, Any]) -> PlatformError:
    """The error for status 6 — the platform's "Route not found for selected ID" answer."""
    message = text_of(route.get("status-message")) or NOT_FOUND_MESSAGE
    return PlatformError(
        f"no trace-route query '{query_id}' ({message}). Either the id is wrong (they look "
        "like 'SPQ-324616899', as cnc_start_oam_trace_route returns them) or the query was "
        "auto-deleted after the OAM delete interval (cnc_get_oam_settings)."
    )


def validate_device_uuid(value: str, what: str) -> str:
    """The inventory uuid in its canonical spelling; PlatformError when it is not a uuid.

    Verified live: the OAM RPC resolves devices by inventory uuid only — a
    node name or TE router-id is accepted (status 3) and then fails the query
    within a second ("empty device id item in list"), leaving a dead query
    behind — so anything that is not a uuid is refused before sending. Any
    uuid spelling is accepted (braces, a ``urn:uuid:`` prefix in either case,
    upper-case hex, the 32-hex form) and **sent canonical** — lower-case,
    hyphenated, as the inventory (cnc_get_device / cnc_list_devices) shows it
    — so an alternative spelling never reaches the wire.
    """
    text = value.strip()
    try:
        canonical = str(uuid_lib.UUID(text.lower()))
    except ValueError:
        raise PlatformError(
            f"{what} '{text}' is not an inventory uuid. The OAM trace route resolves devices "
            "by inventory uuid only (a node name or router-id registers a query that fails "
            "within a second with 'empty device id item in list'); cnc_get_device(host_name="
            f"'{text}') or cnc_list_devices shows the uuid."
        ) from None
    return canonical


def enum_word(value: Any, names: tuple[str, ...]) -> str:
    """A probe-manager enum as text: strings as-is, ints by enum order (``NAME (n)``)."""
    if isinstance(value, bool) or value in (None, ""):
        return "-"
    if isinstance(value, int):
        return f"{names[value]} ({value})" if 0 <= value < len(names) else f"status {value}"
    return str(value).strip()


def enum_name(value: Any, names: tuple[str, ...]) -> str:
    """The enum NAME alone (``PROBE_STATUS_ERROR``) for a string or an int, ``""`` otherwise."""
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        return names[value] if 0 <= value < len(names) else ""
    return str(value).strip().upper() if isinstance(value, str) else ""


def probe_reports(data: Any) -> list[dict[str, Any]]:
    """The ProbeStatusResponse documents of a probe-manager answer.

    The document wraps them as ``{"data": [...]}``; the verified 500 carries
    one bare document, so a bare dict with a ``status`` or ``serviceId`` is
    accepted as a single report.
    """
    if isinstance(data, dict):
        if isinstance(data.get("data"), list):
            return dict_list(data["data"])
        if "status" in data or "serviceId" in data:
            return [data]
    return []


def is_go_not_found(response: httpx.Response) -> bool:
    """True for Go's plain-text ``404 page not found`` (verified: probemgr's unknown paths)."""
    return response.status_code == 404 and GO_NOT_FOUND_MARKER in response.text.lower()


def probe_error_text(data: Any) -> str:
    """The ``error`` string of a probe-manager document, ``""`` when absent."""
    return text_of(data.get("error")) if isinstance(data, dict) else ""


def is_no_probe_session(response: httpx.Response, data: Any) -> bool:
    """True for the verified "service has no active probe session" 500 document."""
    return response.status_code == 500 and NO_PROBE_SESSION_MARKER in probe_error_text(data).lower()


def probe_verdict_500(response: httpx.Response, data: Any) -> str:
    """The ``error`` of a 500 that carries a ProbeStatusResponse document, else ``""``.

    The probe manager answers its verdicts (the verified "service has no
    active probe session"; by the same shape "service not found" and the
    like) as HTTP 500 with the document ``{"serviceId", "status",
    "enableReactivate", ..., "error"}`` — a decision about the service, not a
    server fault, so it must not carry the generic "try again" hint. A 500
    whose body is NOT such a document (a bare ``{"error": "NATS request
    failed: timeout"}``, an HTML gateway page) stays a generic HTTP error.
    """
    if response.status_code != 500 or not probe_reports(data):
        return ""
    return probe_error_text(data)


def str_list(value: Any) -> list[str]:
    """The string entries of a list value; ``[]`` for anything else (absent lists included)."""
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def parse_json(response: httpx.Response) -> Any:
    """The JSON body, ``None`` when empty or not JSON (never raises)."""
    if not response.content:
        return None
    try:
        return response.json()
    except ValueError:
        return None


# --- markdown renderers ------------------------------------------------------------


def end_text(route: dict[str, Any], prefix: str) -> str:
    """``PE1 (uuid ..., te-router-id 10.0.0.1)`` for ``head-end`` / ``tail-end``; blanks skipped."""
    name = text_of(route.get(f"{prefix}-node-name"))
    device_uuid = text_of(route.get(f"{prefix}-node-uuid"))
    router_id = text_of(route.get(f"{prefix}-te-router-id"))
    label = name or device_uuid or router_id or "?"
    details = []
    if device_uuid and label != device_uuid:
        details.append(f"uuid {device_uuid}")
    if router_id and label != router_id:
        details.append(f"te-router-id {router_id}")
    return label + (f" ({', '.join(details)})" if details else "")


def service_text(route: dict[str, Any]) -> str:
    """``<yang-path> (service-name X, service-type Y)`` — blanks skipped, ``-`` when none."""
    path = text_of(route.get("yang-path")) or "-"
    extras = []
    for key in ("service-name", "service-type"):
        value = text_of(route.get(key))
        if value:
            extras.append(f"{key} {value}")
    return path + (f" ({', '.join(extras)})" if extras else "")


def status_line(route: dict[str, Any]) -> str:
    """``in progress (3): Path trace running for calculation`` (message omitted when blank)."""
    message = text_of(route.get("status-message"))
    return status_word(trace_status(route)) + (f": {message}" if message else "")


def path_line(entry: dict[str, Any]) -> str:
    """One ``path-info-list[]`` entry (document shape, unverified live)."""
    info = entry.get("path-info") if isinstance(entry.get("path-info"), dict) else {}
    hops = f"{text_of(info.get('source')) or '?'} -> {text_of(info.get('destination')) or '?'}"
    next_hop = text_of(info.get("next-hop"))
    if next_hop:
        hops += f" via next-hop {next_hop}"
    out_interface = text_of(info.get("out-interface"))
    if out_interface:
        hops += f" out-interface {out_interface}"
    parts = [f"- path {text_of(entry.get('path')) or '?'}: {hops}"]
    status = text_of(info.get("path-status"))
    if status:
        parts.append(f"path-status {status}")
    devices = str_list(info.get("device-uuids"))
    if devices:
        parts.append("devices " + ", ".join(devices))
    details = text_of(info.get("path-details"))
    if details:
        parts.append(f"details {details}")
    return "; ".join(parts)


def route_lines(route: dict[str, Any]) -> list[str]:
    """The field lines of one ServiceRoute, then its ``## Paths`` section when any."""
    lines = [
        f"- status: {status_line(route)}",
        f"- service: {service_text(route)}",
        f"- head-end: {end_text(route, 'head-end')}",
        f"- tail-end: {end_text(route, 'tail-end')}",
        f"- created: {oam_time(route.get('create-time'))}; updated: "
        f"{oam_time(route.get('update-time'))}",
    ]
    count = route.get("available-path-count")
    lines.append(f"- available-path-count: {'-' if count in (None, '') else count}")
    transport = route.get("transport-type")
    if transport not in (None, "", 0):
        lines.append(f"- transport-type: {transport}")
    paths = dict_list(route.get("path-info-list"))
    if paths:
        lines.extend(["", f"## Paths ({len(paths)})"])
        lines.extend(path_line(p) for p in paths)
    return lines


def route_footer(route: dict[str, Any], query_id: str) -> str:
    """The next-step hint that fits the route's state."""
    code = trace_status(route)
    if code == TRACE_IN_PROGRESS:
        return (
            f"The trace is still running: cnc_wait_for_oam_trace_route(query_id='{query_id}') "
            "polls until it finishes (about 30 s to a verdict on the verified build)."
        )
    if code == TRACE_FAILED:
        return (
            "The status-message is the platform's verdict (typically: no gNMI connectivity "
            "type configured for the devices in Crosswork, or 'mpls oam' missing on the "
            "IOS-XR device). A failed query is not re-run — fix the cause and start a new "
            "trace with cnc_start_oam_trace_route."
        )
    return (
        "Each path entry names the source, destination, next-hop and out-interface the "
        "head-end reported; device uuids resolve with cnc_get_device(uuid=...). The query is "
        "auto-deleted after the OAM delete interval (cnc_get_oam_settings)."
    )


def start_summary(route: dict[str, Any], query_id: str) -> str:
    """The first line of cnc_start_oam_trace_route, fitted to the state the set RPC answered.

    Verified: the RPC answers status 3 (registered) and the verdict arrives
    on polling. Should it ever answer a terminal state directly — 5 (the
    "empty device id item in list" failure arrives within a second, so a slow
    RPC could carry it), the presumed 4, or anything else — there is nothing
    to wait for, so the "Next: wait" hint is only given for status 3.
    """
    code = trace_status(route)
    if code == TRACE_IN_PROGRESS:
        return (
            f"OAM trace route registered: query-id {query_id}, {status_line(route)}. "
            f"Next: cnc_wait_for_oam_trace_route(query_id='{query_id}') (about 30 s to a "
            "verdict on the verified build)."
        )
    if code == TRACE_FAILED:
        message = text_of(route.get("status-message")) or "no status-message given"
        return (
            f"OAM trace route {query_id} was registered but FAILED immediately: {message}. "
            "Nothing to wait for — a failed query is not re-run; fix the cause and start a new "
            "trace with cnc_start_oam_trace_route."
        )
    if code == TRACE_COMPLETED:
        return (
            f"OAM trace route {query_id} completed immediately: {status_line(route)}. The "
            "paths are below; nothing to wait for."
        )
    return (
        f"OAM trace route {query_id} answered {status_line(route)} on registration. "
        f"cnc_get_oam_trace_route(query_id='{query_id}') re-reads it; "
        "cnc_wait_for_oam_trace_route only waits while the status is in progress (3)."
    )


def route_markdown(route: dict[str, Any], query_id: str) -> str:
    lines = [f"# OAM trace route {query_id} — {status_word(trace_status(route))}", ""]
    lines.extend(route_lines(route))
    lines.extend(["", route_footer(route, query_id)])
    return "\n".join(lines)


def route_row(route: dict[str, Any]) -> str:
    """One list row: id, status + message, service, ends, creation time."""
    query_id = text_of(route.get("query-id")) or "?"
    return (
        f"- {query_id} — {status_line(route)}; service {text_of(route.get('yang-path')) or '-'}; "
        f"{end_text(route, 'head-end')} -> {end_text(route, 'tail-end')}; created "
        f"{oam_time(route.get('create-time'))}"
    )


def list_routes_of(output: dict[str, Any]) -> list[dict[str, Any]]:
    """``service-routes[]`` (the document) or ``service-route[]`` (the notes' spelling)."""
    return dict_list(output.get("service-routes", output.get("service-route")))


def count_of(output: dict[str, Any], key: str) -> int | None:
    value = output.get(key)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value)
    return None


def endpoint_line(entry: dict[str, Any]) -> str:
    """One ``endpointStatus[]`` entry (document shape, unverified live)."""
    text = (
        f"- {text_of(entry.get('id')) or '?'} — node {text_of(entry.get('vpnNeId')) or '?'}, "
        f"interface {text_of(entry.get('interfaceName')) or '?'}"
    )
    agent = text_of(entry.get("agentIPAddr"))
    if agent:
        text += f", agent {agent}"
    vlan = entry.get("agentVLAN")
    if vlan not in (None, ""):
        text += f" vlan {vlan}"
    text += f": {enum_word(entry.get('status'), PROBE_STATUS_NAMES)}"
    error = text_of(entry.get("error"))
    return text + (f"; error: {error}" if error else "")


def session_line(entry: dict[str, Any]) -> str:
    """One ``sessionStatus[]`` entry (document shape, unverified live)."""
    text = (
        f"- {text_of(entry.get('id')) or '?'} — sender {text_of(entry.get('sender')) or '?'} -> "
        f"reflector {text_of(entry.get('reflector')) or '?'}: "
        f"{enum_word(entry.get('status'), PROBE_STATUS_NAMES)}"
    )
    error = text_of(entry.get("error"))
    return text + (f"; error: {error}" if error else "")


def probe_report_markdown(report: dict[str, Any], service_id: str) -> str:
    service = text_of(report.get("serviceId")) or service_id
    reactivate = report.get("enableReactivate") is True
    lines = [
        f"# Service Health probe status for {service}",
        "",
        f"- status: {enum_word(report.get('status'), PROBE_STATUS_NAMES)}",
        f"- re-activation available: {'true' if reactivate else 'false'}",
    ]
    error = text_of(report.get("error"))
    if error:
        lines.append(f"- error: {error}")
    endpoints = dict_list(report.get("endpointStatus"))
    sessions = dict_list(report.get("sessionStatus"))
    lines.extend(["", f"## Endpoints ({len(endpoints)})"])
    lines.extend(endpoint_line(e) for e in endpoints)
    if not endpoints:
        lines.append("- (none reported)")
    lines.extend(["", f"## Sessions ({len(sessions)})"])
    lines.extend(session_line(s) for s in sessions)
    if not sessions:
        lines.append("- (none reported)")
    lines.append("")
    if reactivate:
        lines.append(
            f"The probe reports an error state that can be re-activated: "
            f"cnc_reactivate_probe(service_id='{service}') (a write tool)."
        )
    else:
        lines.append(
            "Endpoint and session statuses follow the 7.2 document (PROBE_STATUS_PENDING / "
            "SUCCESS / ERROR); this populated shape has not been verified live."
        )
    return "\n".join(lines)


# --- registration ------------------------------------------------------------------


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    async def call_rpc(rpc: str, body: dict[str, Any] | None) -> dict[str, Any]:
        """POST one OAM RPC and return its checked ``output`` container.

        ``body`` is the ``{"input": {...}}`` envelope, sent with
        :data:`YANG_HEADERS`; ``None`` sends no body at all (only ``Accept``
        — the verified form of ``get-oam-delete-interval``). Never
        auto-retried (POST: a resent ``set-oam-trace-route-by-calc`` would
        register a second query). A bare 500 with an empty body is reported as
        :data:`OAM_EMPTY_500_HINT`; any other failure through
        :func:`cnc_mcp.errors.http_error`; a failure inside HTTP 200 through
        :func:`check_oam_output`.
        """
        url = rpc_path(OPTIMIZATION_NBI, OAM_MODULE, rpc)
        headers = YANG_HEADERS if body is not None else YANG_ACCEPT
        response = await client.request(
            "POST", url, json_body=body, headers=headers, raise_on_error=False
        )
        if not response.is_success:
            if explain_empty_500(response.status_code, response.text):
                raise PlatformError(OAM_EMPTY_500_HINT)
            raise http_error(response)
        data: Any = None
        if response.content:
            try:
                data = response.json()
            except ValueError as e:
                raise PlatformError(
                    "The Optimization Engine returned a non-JSON response where YANG JSON was "
                    "expected."
                ) from e
        return check_oam_output(rpc_output(data, OAM_MODULE), rpc)

    async def fetch_trace_route(query_id: str) -> dict[str, Any]:
        """The ServiceRoute of one query (status 6 included — callers decide); an empty
        output is an error (the document's "204 No response" carries nothing to show)."""
        route = await call_rpc(RPC_GET_TRACE_ROUTE, rpc_body(**{"query-id": query_id}))
        if not route:
            raise PlatformError(
                f"the Optimization Engine returned no trace-route data for query '{query_id}' "
                "(empty output). Retry; if it persists the OAM backend is not answering."
            )
        return route

    async def probemgr_post(url: str, service_id: str) -> tuple[httpx.Response, Any]:
        """POST ``{"serviceId": ...}`` to the probe manager; the response and its JSON body.

        Only Go's plain ``404 page not found`` is turned into an error here
        (:data:`PROBEMGR_NOT_ROUTED_HINT`); the callers interpret every other
        status because the verified "no probes" answer is a 500 with a JSON
        document. Not auto-retried (POST).
        """
        response = await client.request(
            "POST", url, json_body={"serviceId": service_id}, raise_on_error=False
        )
        if is_go_not_found(response):
            raise PlatformError(PROBEMGR_NOT_ROUTED_HINT)
        return response, parse_json(response)

    # --- reads ----------------------------------------------------------------------

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_oam_settings",
        title="Get OAM Settings",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_oam_settings(
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the OAM settings of the Optimization Engine: the delete interval after which
        completed trace-route queries are removed.

        Read-only. ``POST .../operations/cisco-crosswork-optimization-engine-
        oam-operations:get-oam-delete-interval`` with NO body (verified live —
        only ``Accept`` is sent) answers ``{"delete-interval": <hours>,
        "response-result": "valid"}`` (1 hour on the lab). Use it to know how
        long a query-id from cnc_start_oam_trace_route stays readable with
        cnc_get_oam_trace_route. Changing it (``set-oam-delete-interval``) is
        not exposed.

        Args:
            response_format: markdown (one sentence) or json (the raw RPC
                ``output``).

        Returns:
            str: "Completed trace-route queries are deleted after <n> hour(s)
            (OAM delete-interval)." or the JSON ``output`` {"delete-interval",
            "response-result"}. A plain note when the platform reported no
            delete-interval (not an error). "Error: get-oam-delete-interval
            failed: response-result <x>: ..." when the RPC reports a failure
            inside 200; "Error: the Optimization Engine answered 500 with an
            EMPTY body ..." (the backend is absent — this RPC has no input to
            get wrong); "Error: ..." on any other API failure.
        """
        try:
            output = await call_rpc(RPC_GET_DELETE_INTERVAL, None)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(output), settings)
            hours = output.get("delete-interval")
            if hours in (None, ""):
                return finalize(
                    "The Optimization Engine reported no OAM delete-interval. Raw output: "
                    f"{to_json(output)}",
                    settings,
                )
            return finalize(
                f"Completed trace-route queries are deleted after {hours} hour(s) (OAM "
                "delete-interval). A query-id from cnc_start_oam_trace_route stays readable "
                "with cnc_get_oam_trace_route until then.",
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_oam_trace_routes",
        title="List OAM Trace Routes",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_oam_trace_routes(
        start_row: Annotated[
            int, Field(description="First row of the window (0-based, e.g. 0).", ge=0)
        ] = 0,
        end_row: Annotated[
            int,
            Field(description="Last row of the window (e.g. 50); must exceed start_row.", ge=1),
        ] = 50,
        filter_criteria: Annotated[
            str,
            Field(
                description=(
                    "Optional filter text sent as the RPC's filter-criteria (its grammar is "
                    "undocumented; '' sends none, e.g. 'SPQ-324616899')."
                ),
                max_length=500,
            ),
        ] = "",
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the OAM trace-route queries the Optimization Engine holds, with the platform's
        completed / running / failed counts.

        Read-only. ``POST .../operations/cisco-crosswork-optimization-engine-
        oam-operations:get-oam-trace-route-by-query`` with ``{"input":
        {"start-row", "end-row"[, "filter-criteria"]}}`` (verified live)
        answers ``total-count``, ``total-completed-query-count``,
        ``total-running-query-count``, ``total-failed-query-count`` and the
        rows (``service-routes[]`` per the document; absent when none). CAVEAT
        (verified): **the platform's list did not show queries created seconds
        earlier on the verified build** — it answered total-count 0 while a
        query was running and again after it had failed, whatever row window
        or filter was sent — so an empty answer does not mean no query exists.
        Use cnc_get_oam_trace_route with the query-id from
        cnc_start_oam_trace_route for the reliable read. Whether ``end-row``
        is inclusive is unverified; the JSON envelope's ``limit`` is
        ``end_row - start_row``.

        Args:
            start_row: first row (0-based). end_row: last row; must exceed
                start_row. filter_criteria: optional filter text (omitted when
                blank).
            response_format: markdown or json.

        Returns:
            str: Markdown "# OAM trace-route queries (total N: a completed, b
            running, c failed)" with one "- <query-id> — <status>: <message>;
            service <yang-path>; <head-end> -> <tail-end>; created <time>" row
            each, or JSON {"total", "count", "offset", "items": [ServiceRoute],
            "has_more", "next_offset", "counts": {"completed", "running",
            "failed"}, "note"?}. With no rows the markdown states the caveat
            above (not an error). "Error: end_row must exceed start_row" before
            any call; "Error: get-oam-trace-route-by-query failed:
            response-result <x>: ..." for a failure inside 200; "Error: the
            Optimization Engine answered 500 with an EMPTY body ..." for a
            bare empty 500; "Error: ..." on any other API failure.
        """
        try:
            if end_row <= start_row:
                raise PlatformError(
                    f"end_row must exceed start_row (got start_row={start_row}, "
                    f"end_row={end_row}); e.g. start_row=0, end_row=50."
                )
            criteria = filter_criteria.strip() or None
            body = rpc_body(
                **{"start-row": start_row, "end-row": end_row, "filter-criteria": criteria}
            )
            output = await call_rpc(RPC_LIST_TRACE_ROUTES, body)
            rows = list_routes_of(output)
            total = count_of(output, "total-count")
            counts = {
                "completed": count_of(output, "total-completed-query-count"),
                "running": count_of(output, "total-running-query-count"),
                "failed": count_of(output, "total-failed-query-count"),
            }
            note = (
                "The platform's list did not show queries created seconds earlier on the "
                "verified build (total-count 0 while one was running / failed); use "
                "cnc_get_oam_trace_route with the query-id from cnc_start_oam_trace_route."
            )
            if response_format is ResponseFormat.JSON:
                envelope = pagination_envelope(
                    rows, total=total, offset=start_row, limit=end_row - start_row
                )
                envelope["counts"] = counts
                if not rows:
                    envelope["note"] = note
                return finalize(to_json(envelope), settings)
            shown = "-" if total is None else total
            summary = ", ".join(f"{'-' if v is None else v} {k}" for k, v in counts.items())
            lines = [f"# OAM trace-route queries (total {shown}: {summary})", ""]
            if rows:
                lines.extend(route_row(r) for r in rows)
                lines.extend(
                    ["", "cnc_get_oam_trace_route(query_id) shows a query's paths and message."]
                )
            else:
                lines.append(
                    f"No trace-route queries were listed for rows {start_row}-{end_row}"
                    + (f" with filter '{criteria}'" if criteria else "")
                    + f". NOTE: {note}"
                )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_oam_trace_route",
        title="Get OAM Trace Route",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_oam_trace_route(
        query_id: Annotated[str, Field(description=_QUERY_ID_DESC, min_length=1, max_length=128)],
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one OAM trace-route query: its status and message, the service and devices it
        traces, timestamps and — once complete — the discovered paths.

        Read-only. ``POST .../operations/cisco-crosswork-optimization-engine-
        oam-operations:get-oam-trace-route-by-query-id`` with ``{"input":
        {"query-id": "<id>"}}`` (verified live) answers the ServiceRoute:
        ``status`` 3 = registered / running ("Path trace registered|running for
        calculation"), 5 = failed (the ``status-message`` is the reason —
        on the lab always the gNMI-connectivity text), 6 = unknown query-id
        (answered as HTTP 200 with "Route not found for selected ID" and
        every string empty — reported here as an error), presumably 4 =
        completed (unverified) with ``path-info-list[] {path, path-info
        {source, destination, next-hop, out-interface, device-uuids[],
        path-details, path-status}}``; ``yang-path`` / ``service-name`` /
        ``service-type``; ``head-end-*`` / ``tail-end-*`` node name, uuid
        and TE router-id (the echoed inputs — names and router-ids are empty
        when only uuids were sent); ``create-time`` / ``update-time``
        (epoch-ms strings, rendered ISO-8601); ``available-path-count``.
        This is the reliable read: the list RPC does not show fresh queries.
        For a running query prefer cnc_wait_for_oam_trace_route.

        Args:
            query_id: the query id (e.g. 'SPQ-324616899').
            response_format: markdown or json (the raw RPC ``output``).

        Returns:
            str: Markdown "# OAM trace route <id> — <status word> (<n>)" with
            "- status: ...: <message>", "- service: ...", "- head-end / tail-end:
            <name or uuid> (...)", "- created ...; updated ...",
            "- available-path-count: N", a "## Paths (N)" section when any,
            and a next-step hint; or the JSON ``output``. "Error: no
            trace-route query '<id>' (Route not found for selected ID) ..." for
            status 6; "Error: get-oam-trace-route-by-query-id failed:
            response-result <x>: ..." for a failure inside 200; "Error: the
            Optimization Engine answered 500 with an EMPTY body ..." for a bare
            empty 500; "Error: ..." on any other API failure.
        """
        try:
            route = await fetch_trace_route(query_id)
            if trace_status(route) == TRACE_NOT_FOUND:
                raise not_found_error(query_id, route)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(route), settings)
            shown_id = text_of(route.get("query-id")) or query_id
            return finalize(route_markdown(route, shown_id), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_wait_for_oam_trace_route",
        title="Wait For OAM Trace Route",
        read_only=True,
        idempotent=True,
    )
    async def cnc_wait_for_oam_trace_route(
        query_id: Annotated[str, Field(description=_QUERY_ID_DESC, min_length=1, max_length=128)],
        timeout_seconds: Annotated[
            int,
            Field(description="Give up after this many seconds (e.g. 90).", ge=1, le=900),
        ] = 90,
        interval_seconds: Annotated[
            int, Field(description="Seconds between polls (e.g. 5).", ge=1, le=60)
        ] = 5,
    ) -> str:
        """Poll an OAM trace-route query until it leaves the registered/running state (3) or
        the timeout elapses, then report the verdict.

        Read-only. Calls ``get-oam-trace-route-by-query-id`` every
        ``interval_seconds`` (the read of cnc_get_oam_trace_route) until
        ``status`` is anything but 3. On the verified build a trace took ~30 s
        to reach its verdict (there: status 5 with the gNMI-connectivity
        text). Use it right after cnc_start_oam_trace_route instead of calling
        cnc_get_oam_trace_route in a loop.

        Args:
            query_id: the query id (e.g. 'SPQ-324616899').
            timeout_seconds: total budget (default 90).
            interval_seconds: poll interval (default 5).

        Returns:
            str: "Trace route <id> finished after <t>s: <status word> (<n>)
            ..." followed by the full rendering of cnc_get_oam_trace_route
            (paths included) when it completed; "Trace route <id> FAILED after
            <t>s: <status-message>" plus the rendering when status 5 — the
            platform's verdict on the network, NOT an error (no "Error:"
            prefix); a timeout is not an error either: "Trace route <id> not
            finished yet after <t>s; current status: in progress (3): ..." —
            call again to keep waiting. "Error: no trace-route query '<id>'
            ..." for status 6 (unknown id, or already auto-deleted); "Error:
            ..." on any API failure during polling.
        """
        try:
            finished, route, elapsed = await wait_until(
                lambda: fetch_trace_route(query_id),
                lambda r: trace_status(r) != TRACE_IN_PROGRESS,
                timeout_seconds=timeout_seconds,
                interval_seconds=interval_seconds,
            )
            code = trace_status(route)
            if code == TRACE_NOT_FOUND:
                raise not_found_error(query_id, route)
            shown_id = text_of(route.get("query-id")) or query_id
            rendering = route_markdown(route, shown_id)
            if not finished:
                return finalize(
                    f"Trace route {shown_id} not finished yet after {elapsed:.0f}s; current "
                    f"status: {status_line(route)}. Call cnc_wait_for_oam_trace_route again "
                    f"to keep waiting.\n\n{rendering}",
                    settings,
                )
            if code == TRACE_FAILED:
                message = text_of(route.get("status-message")) or "no status-message given"
                return finalize(
                    f"Trace route {shown_id} FAILED after {elapsed:.0f}s: {message}\n\n{rendering}",
                    settings,
                )
            return finalize(
                f"Trace route {shown_id} finished after {elapsed:.0f}s: {status_line(route)}"
                f"\n\n{rendering}",
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_probe_status",
        title="Get Service Health Probe Status",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_probe_status(
        service_id: Annotated[
            str, Field(description=_SERVICE_ID_DESC, min_length=1, max_length=1000)
        ],
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the Service Health probe status of one VPN service: overall probe state, each
        endpoint's probe agent and each sender->reflector session.

        Read-only. ``POST /crosswork/probemgr/v1/probeStatusReport {"serviceId":
        "<service instance path>"}`` (plain JSON). Verified live: a service
        without probes is answered **HTTP 500** with the document
        ``{"serviceId", "enableReactivate": false, "status":
        "PROBE_STATUS_UNKNOWN", "endpointStatus": [], "sessionStatus": [],
        "error": "service has no active probe session"}`` — reported here as
        a plain non-error "no active probe session". The populated answer
        follows the 7.2 document (UNVERIFIED live): ``{"data": [{serviceId,
        enableReactivate, status PROBE_STATUS_PENDING|SUCCESS|ERROR,
        endpointStatus[] {id, vpnNeId, agentVLAN, agentIPAddr, interfaceName,
        status, error?}, sessionStatus[] {id, sender, reflector, status,
        error?}}]}`` (the document's example carries ints for the statuses;
        they are mapped by enum order). ``enableReactivate: true`` means the
        probe is in an error state cnc_reactivate_probe can re-activate.
        Service Health (capp-aa) is not installed on single-VM builds, where
        every service answers "no active probe session"; a Go ``404 page not
        found`` from the probe manager itself means it is absent / the path
        is not routed on the build.

        Args:
            service_id: the service instance path (yang-path), e.g.
                'ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=mcp-l3vpn-91'.
            response_format: markdown or json (the raw document(s)).

        Returns:
            str: "No active probe session for <service> (Service Health status
            PROBE_STATUS_UNKNOWN) ..." (not an error) when the service has no
            probes; otherwise Markdown "# Service Health probe status for
            <service>" with "- status", "- re-activation available", "##
            Endpoints (N)" and "## Sessions (N)" sections, or the JSON
            document. "Error: the Service Health probe manager refused the
            probe report for '<service>': <error> ..." (no retry hint) when a
            500 carries a probe document with another ``error`` (the probe
            manager's verdict on the service, e.g. "service not found" — the
            same shape as the verified "no active probe session" answer);
            "Error: Service Health probe manager is not installed / the path
            is not routed ..." for Go's 404; "Error: ..." on any other API
            failure (a 500 without a probe document included).
        """
        try:
            service = service_id.strip()
            response, data = await probemgr_post(PROBE_STATUS_URL, service)
            if is_no_probe_session(response, data):
                if response_format is ResponseFormat.JSON:
                    return finalize(to_json(data), settings)
                status = text_of(data.get("status")) or PROBE_STATUS_UNKNOWN
                return finalize(
                    f"No active probe session for {service} (Service Health status {status}). "
                    "The service has no Service Health probes: probe monitoring is enabled per "
                    "service in Service Health, and on single-VM builds the application "
                    "(capp-aa) is not installed at all, so every service answers this. Platform "
                    f"said: {probe_error_text(data)}",
                    settings,
                )
            verdict = probe_verdict_500(response, data)
            if verdict:
                raise PlatformError(
                    f"the Service Health probe manager refused the probe report for '{service}': "
                    f"{verdict}. The 500 carried a probe document (status "
                    f"{enum_word(data.get('status'), PROBE_STATUS_NAMES)}), so this is the "
                    "probe manager's verdict on the service, not a server fault — re-check the "
                    "service id (cnc_list_services shows the instance paths) rather than "
                    "retrying with the same one."
                )
            if not response.is_success:
                raise http_error(response)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(data), settings)
            reports = probe_reports(data)
            if not reports:
                return finalize(
                    f"The probe manager answered no probe report for {service}. Raw answer: "
                    f"{to_json(data)}",
                    settings,
                )
            return finalize(
                "\n\n".join(probe_report_markdown(r, service) for r in reports), settings
            )
        except Exception as e:
            return format_error(e)

    # --- writes ---------------------------------------------------------------------

    @register_tool(
        mcp,
        ctx,
        name="cnc_start_oam_trace_route",
        title="Start OAM Trace Route",
        read_only=False,
        destructive=False,
        idempotent=False,
    )
    async def cnc_start_oam_trace_route(
        service_yang_path: Annotated[
            str, Field(description=_YANG_PATH_DESC, min_length=1, max_length=1000)
        ],
        headend_uuid: Annotated[
            str, Field(description=f"Head-end {_UUID_DESC}", min_length=1, max_length=64)
        ],
        endpoint_uuid: Annotated[
            str, Field(description=f"Tail-end {_UUID_DESC}", min_length=1, max_length=64)
        ],
    ) -> str:
        """Start an OAM trace route of a service between its head-end and tail-end devices
        — asynchronous: poll the returned query-id with cnc_wait_for_oam_trace_route.

        Write (registers a query; changes no network configuration). ``POST
        .../operations/cisco-crosswork-optimization-engine-oam-operations:
        set-oam-trace-route-by-calc`` with ``{"input": {"yang-path":
        "<service>", "head-end-node-uuid": "<uuid>", "tail-end-node-uuid":
        "<uuid>"}}`` (verified live on a CFP SR policy service) answers the
        new ServiceRoute: ``query-id`` (e.g. 'SPQ-324616899'), status 3
        "Path trace registered for calculation", the echoed inputs and
        ``available-path-count`` 0. Verified rules: only **inventory uuids**
        resolve the devices (a node name or TE router-id registers a query
        that fails within a second with "... 'mpls oam' ... empty device id
        item in list") — non-uuid values are refused before sending, and any
        uuid spelling (braces, urn:uuid:, upper-case, 32-hex) is sent in the
        canonical lower-case hyphenated form the inventory shows;
        ``transport-type`` is never sent (1/2/3 fail with "Invalid Transport
        Type"). Preconditions for a trace to complete: the devices need a
        **gNMI connectivity type** configured in Crosswork (the lab has SNMP +
        SSH only and every trace there fails with the platform's gNMI text)
        and IOS-XR 7.3.2+ with ``mpls oam`` enabled. The query is auto-deleted
        after the OAM delete interval (cnc_get_oam_settings). Not retried on
        transport errors: a resend would register a second query.

        Args:
            service_yang_path: the service's yang-path from cnc_list_services.
            headend_uuid, endpoint_uuid: inventory uuids of the head-end and
                tail-end devices (cnc_get_device shows them).

        Returns:
            str: "OAM trace route registered: query-id <id>, in progress (3):
            <message>. Next: cnc_wait_for_oam_trace_route(query_id='<id>')."
            (the verified answer) followed by the rendering of
            cnc_get_oam_trace_route and a JSON handle ``{"query_id",
            "status", "status_word", "status_message"}`` for chaining into
            the wait/get tools. Should the RPC answer a terminal state
            directly, the first line fits it and gives no wait hint: "OAM
            trace route <id> was registered but FAILED immediately: <message>.
            Nothing to wait for ..." for status 5 (not an "Error:" — the
            platform's verdict), "OAM trace route <id> completed immediately:
            ..." for status 4, "... answered status <n> on registration ..."
            otherwise.
            "Error: headend_uuid '<x>' is not an inventory uuid ..." / "Error:
            yang_path is empty ..." before any call; "Error:
            set-oam-trace-route-by-calc failed: response-result <x>: ..." for a
            failure inside 200; "Error: the Optimization Engine answered 500
            with an EMPTY body ..." for a bare empty 500; "Error: ..." on any
            other API failure.
        """
        try:
            yang_path = normalize_yang_path(service_yang_path)
            head = validate_device_uuid(headend_uuid, "headend_uuid")
            tail = validate_device_uuid(endpoint_uuid, "endpoint_uuid")
            body = rpc_body(
                **{"yang-path": yang_path, "head-end-node-uuid": head, "tail-end-node-uuid": tail}
            )
            route = await call_rpc(RPC_START_TRACE_ROUTE, body)
            query_id = text_of(route.get("query-id"))
            if not query_id:
                raise PlatformError(
                    "set-oam-trace-route-by-calc answered without a query-id; the trace was "
                    f"not registered. Raw output: {to_json(route)}"
                )
            handle = {
                "query_id": query_id,
                "status": trace_status(route),
                "status_word": status_word(trace_status(route)),
                "status_message": text_of(route.get("status-message")) or None,
            }
            return finalize(
                f"{start_summary(route, query_id)}\n\n{route_markdown(route, query_id)}\n\n"
                f"{to_json(handle)}",
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_reactivate_probe",
        title="Reactivate Service Health Probe",
        read_only=False,
        destructive=False,
        idempotent=False,
    )
    async def cnc_reactivate_probe(
        service_id: Annotated[
            str, Field(description=_SERVICE_ID_DESC, min_length=1, max_length=1000)
        ],
    ) -> str:
        """Re-activate the Service Health probe of a VPN service whose probe is in an error
        state.

        Write. ``POST /crosswork/probemgr/v1/reactivateProbe {"serviceId":
        "<service instance path>"}`` (plain JSON) answers ``{"data":
        [{"status": 1}]}`` — ``Status`` RESP_STATUS_UNKNOWN (0) |
        RESP_STATUS_SUCCESS (1) | RESP_STATUS_ERROR (2), plus ``error`` — per
        the 7.2 document; UNVERIFIED live (no service with probes exists on
        the lab). Only meaningful when cnc_get_probe_status reported
        ``enableReactivate: true`` (the probe manager's "re-activate button"
        flag) — that is documented, not enforced here: the platform decides.
        A service without probes is expected to be refused the way
        probeStatusReport refuses it (500 "service has no active probe
        session"), reported as an error here since nothing was re-activated.
        Not retried on transport errors (POST).

        Args:
            service_id: the service instance path (yang-path), e.g.
                'ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service=mcp-l3vpn-91'.

        Returns:
            str: "Probe re-activation requested for <service>: RESP_STATUS_
            SUCCESS (1). Follow with cnc_get_probe_status ..." on success.
            "Error: probe re-activation for '<service>' failed: <error>" for
            RESP_STATUS_ERROR, "Error: ... was not confirmed: RESP_STATUS_
            UNKNOWN (0) ..." when the platform answered without a success
            status; "Error: probe re-activation for '<service>' was refused by
            the Service Health probe manager: <error>" for a 500 with a
            message; "Error: Service Health probe manager is not installed /
            the path is not routed ..." for Go's 404; "Error: ..." on any other
            API failure.
        """
        try:
            service = service_id.strip()
            response, data = await probemgr_post(REACTIVATE_PROBE_URL, service)
            if not response.is_success:
                error = probe_error_text(data)
                if response.status_code == 500 and error:
                    raise PlatformError(
                        f"probe re-activation for '{service}' was refused by the Service Health "
                        f"probe manager: {error}. cnc_get_probe_status shows whether the service "
                        "has probes at all and whether enableReactivate is true."
                    )
                raise http_error(response)
            reports = probe_reports(data)
            report = reports[0] if reports else {}
            name = enum_name(report.get("status"), REACTIVATE_STATUS_NAMES)
            shown = enum_word(report.get("status"), REACTIVATE_STATUS_NAMES)
            error = probe_error_text(report)
            said = f": {error}" if error else ""
            if name == REACTIVATE_SUCCESS:
                return finalize(
                    f"Probe re-activation requested for {service}: {shown}{said}. Follow with "
                    f"cnc_get_probe_status(service_id='{service}') — the sessions move through "
                    "PROBE_STATUS_PENDING before SUCCESS. (Answer shape per the 7.2 document, "
                    "not yet verified live.)",
                    settings,
                )
            if name == REACTIVATE_ERROR:
                raise PlatformError(
                    f"probe re-activation for '{service}' failed: {error or shown}. "
                    "cnc_get_probe_status shows the endpoint / session errors."
                )
            raise PlatformError(
                f"probe re-activation for '{service}' was not confirmed: the probe manager "
                f"answered {shown}{said} instead of RESP_STATUS_SUCCESS. Re-check with "
                f"cnc_get_probe_status(service_id='{service}'). Raw answer: {to_json(data)}"
            )
        except Exception as e:
            return format_error(e)
