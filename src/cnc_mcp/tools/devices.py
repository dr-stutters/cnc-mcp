"""Network devices (inventory nodes) — Crosswork ``/crosswork/inventory/v1/nodes``.

Everything here mirrors behaviour verified live against Crosswork Network
Controller:

- Devices are read with ``POST nodes/query`` and a ``filter``/``filterData``
  body (see :mod:`cnc_mcp.crosswork`). Paging is ``PageSize``/``PageNum``;
  a top-level ``offset`` is silently ignored by the platform. These query
  POSTs are reads, so they are sent with ``retryable=True`` (the client only
  auto-retries 5xx/transport errors for idempotent methods by default).
- Only IPv4 management addresses are accepted on create: ``ipaddr()`` sends
  ``inet_af: 0``, which is the verified IPv4 wire value; the IPv6 value has
  not been observed live.
- Filter values are exact-match, case-insensitive, ``*`` wildcard. Unknown
  filter *field names* are silently ignored (the whole collection comes back),
  so only the field names known-good for this endpoint are ever sent:
  ``host_name``, ``uuid``, ``admin_state``, ``reachability_state``, ``profile``.
- Every write (POST create, PATCH update, DELETE) answers with a job envelope;
  a rejected write is HTTP 200 with ``state != JOB_COMPLETED``. All writes go
  through :func:`cnc_mcp.crosswork.check_job`. The collection URL is the only
  form — ``/nodes/{uuid}`` does not exist (500) — so DELETE carries a JSON body.
- gNMI onboarding (verified live 2026-09-14 on admin-up devices) is a three-PATCH
  sequence — admin-down, transport list + capability, admin-up — because a
  capability change is refused while the node is admin-up and attached to a Data
  Gateway. ``cnc_enable_device_gnmi`` performs it and restores the admin state it
  READ: an admin-up device is bounced down and back up, an admin-down device gets
  only the transport/capability PATCH (no admin-state PATCH at all), and an
  unmanaged device is refused before anything is written. The verified run
  paused 5 s after the admin-down and 3 s after the transport PATCH; the tool
  keeps those settles (see :data:`GNMI_SETTLE_AFTER_DOWN`) because whether the
  capability PATCH is accepted the instant the admin-down job answers is
  UNVERIFIED.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.crosswork import (
    ADMIN_STATES,
    CAPABILITIES,
    DEFAULT_PORTS,
    INVENTORY,
    REACHABILITY_STATES,
    TRANSPORTS,
    check_job,
    ipaddr,
    page_envelope,
    query_body,
    unwrap,
    wire_enum,
)
from cnc_mcp.errors import PlatformError, format_error
from cnc_mcp.formatting import ResponseFormat, finalize, to_json
from cnc_mcp.polling import wait_until
from cnc_mcp.safety import AppContext, register_tool

NODES = f"{INVENTORY}/nodes"
NODES_QUERY = f"{NODES}/query"
COLLECTION_SUMMARY = f"{INVENTORY}/networkelement/collectionstatussummary/query"

REACHABLE = REACHABILITY_STATES["reachable"]
REACH_CHECK = {True: "REACH_CHECK_ENABLE", False: "REACH_CHECK_DISABLE"}
ADMIN_UP = ADMIN_STATES["up"]
ADMIN_DOWN = ADMIN_STATES["down"]

# gNMI transport (verified live 2026-09-14): ``encoding_type`` is a REQUIRED field of the
# transport entry — without it the PATCH answers JOB_FAILED "Encoding Type is required for
# adding a GNMI protocol". Enum from the DLM inventory spec (robotapiEncodingType).
GNMI_ENCODINGS = (
    "UNKNOWN_ENCODING_TYPE",
    "ASCII",
    "BYTES",
    "PROTO",
    "JSON",
    "JSON_IETF",
    "XML",
    "YANG",
)
GNMI_TRANSPORT = TRANSPORTS["gnmi"]  # ROBOT_MSVC_TRANS_GNMI (plaintext gRPC)
# The TLS variant, named in the DLM spec enum only: it has NOT been onboarded live (every
# verified run used the plain transport), so it is kept out of crosswork.TRANSPORTS /
# cnc_create_device and offered here behind ``secure=True`` as an unverified shape.
GNMI_TRANSPORT_SECURE = "ROBOT_MSVC_TRANS_GNMI_SECURE"
GNMI_TRANSPORTS = {GNMI_TRANSPORT, GNMI_TRANSPORT_SECURE}
GNMI_CAPABILITY = CAPABILITIES["gnmi"]
GNMI_TRANSPORT_TIMEOUT = "30"  # a string on the wire, as sent in the verified body
SSH_TRANSPORT = TRANSPORTS["ssh"]
GNMI_POLL_INTERVAL = 10
# Settles between the gNMI PATCHes, copied from the live-verified run (2026-09-14): it
# slept 5 s after the admin-down and 3 s after the transport PATCH. Whether the capability
# PATCH is accepted the instant the admin-down job answers is UNVERIFIED (Data Gateway
# detachment is asynchronous), so the verified timing is kept. ``asyncio.sleep`` is looked
# up on this module's ``asyncio`` at call time so tests can fake the clock.
GNMI_SETTLE_AFTER_DOWN = 5
GNMI_SETTLE_AFTER_ADD = 3

# The node's ``state_map`` (read live 2026-09-14) is keyed by the NUMERIC value of the DLM's
# RobotNodeStateElement enum; each entry is {"value": "UP"|..., "last_updated_time",
# "next_check_time" (epoch s), "info"?}. The spec's ``robotapiCurrentState`` carries an
# ``element`` leaf naming the check, but the live record omits it — cnc_get_device fills it
# in from this table so the keys are readable. PE2 showed keys 1, 2, 3 = reachability /
# discovery / clock-drift, all UP; 4 and 5 were not present on the lab's devices. Key 0
# (UNSUPPORTED) is the placeholder a freshly (re)attached device carries ALONE — seen live
# 2026-09-14 on P2 right after re-attach, operational_state ROBOT_OPER_STATE_CHECKING:
# {"0": {"element": "UNSUPPORTED", "value": "UP", ...}} and no 1/2/3 until the DLM's first
# check cycle ran. ``next_check_time`` equals ``last_updated_time`` on every element on
# 7.2 (re-read live 2026-09-14) — it is not a schedule.
STATE_MAP_ELEMENTS = {
    "0": "UNSUPPORTED",
    "1": "REACHABILITY",
    "2": "DISCOVERY",
    "3": "CLOCK_DRIFT",
    "4": "LOCK",
    "5": "SYNC",
}

_TRANSPORT_NAMES = {wire: name for name, wire in TRANSPORTS.items()}
# For rendering only: the secure gNMI variant gets a friendly name like every other
# transport without becoming an accepted ``protocols`` value for cnc_create_device.
_DISPLAY_TRANSPORTS = {**TRANSPORTS, "gnmi_secure": GNMI_TRANSPORT_SECURE}


class _PatchNotAnswered(PlatformError):
    """A workflow PATCH got no job envelope back (HTTP error after retries, or a
    transport failure/timeout). Unlike a JOB_FAILED answer, the platform may already
    have applied the change, so the caller's error text must say so."""


def _short(table: dict[str, str], value: Any) -> Any:
    """Wire enum -> friendly name for markdown (unknown values pass through)."""
    for name, wire in table.items():
        if wire == value:
            return name
    return value


def _split_csv(value: str | None) -> list[str]:
    return [token.strip() for token in (value or "").split(",") if token.strip()]


def _connectivity_info(protocols: str, ip_address: str, prefix_length: int) -> list[dict]:
    """Parse 'ssh,snmp,netconf:830' into Crosswork connectivity_info entries.

    IPv4 only: ``ipaddr()`` hard-codes ``inet_af`` to 0, the verified IPv4 wire
    value, and the IPv6 value has not been verified live.
    """
    try:
        ipaddress.IPv4Address(ip_address)
    except ValueError:
        try:
            ipaddress.IPv6Address(ip_address)
        except ValueError:
            raise PlatformError(
                f"ip_address '{ip_address}' is not a valid IPv4 address (e.g. '198.18.140.11')."
            ) from None
        raise PlatformError(
            f"ip_address '{ip_address}' is IPv6; only IPv4 management addresses are "
            "supported (the IPv6 inet_af wire value has not been verified on this platform)."
        ) from None
    if not 1 <= prefix_length <= 32:
        raise PlatformError(
            f"prefix_length {prefix_length} is out of range for an IPv4 address (1-32)."
        )
    entries: list[dict] = []
    seen: set[str] = set()
    for token in _split_csv(protocols):
        name, _, port_text = token.partition(":")
        name = name.strip()
        if not name:
            raise PlatformError(f"Malformed protocol entry '{token}'; use 'ssh' or 'netconf:830'.")
        wire = wire_enum(TRANSPORTS, name, "protocol")
        friendly = _TRANSPORT_NAMES[wire]  # type: ignore[index]  # wire_enum returned str
        if port_text.strip():
            try:
                port = int(port_text.strip())
            except ValueError:
                raise PlatformError(
                    f"Port '{port_text}' for protocol '{friendly}' is not an integer."
                ) from None
            if not 0 <= port <= 65535:
                raise PlatformError(f"Port {port} for protocol '{friendly}' is out of range.")
        else:
            port = DEFAULT_PORTS[friendly]
        if wire in seen:
            raise PlatformError(f"Protocol '{friendly}' is listed more than once.")
        seen.add(wire)  # type: ignore[arg-type]
        entries.append(
            {
                "type": wire,
                "ipaddrs": [ipaddr(ip_address, prefix_length)],
                "port": port,
                "timeout": 0,
            }
        )
    if not entries:
        raise PlatformError("protocols must name at least one protocol, e.g. 'ssh,snmp'.")
    return entries


def _capabilities(capabilities: str) -> list[str]:
    out: list[str] = []
    for token in _split_csv(capabilities):
        wire = wire_enum(CAPABILITIES, token, "capability")
        if wire and wire not in out:
            out.append(wire)
    if not out:
        raise PlatformError("capabilities must name at least one capability, e.g. 'snmp,yang_cli'.")
    return out


def _routing_info(
    te_router_id: str | None, isis_system_id: str | None, ospf_router_id: str | None
) -> dict[str, str]:
    candidates = {
        "te_router_id": te_router_id,
        "global_isis_system_id": isis_system_id,
        "global_ospf_router_id": ospf_router_id,
    }
    return {k: v.strip() for k, v in candidates.items() if v and v.strip()}


def _selector(uuid: str | None, host_name: str | None) -> dict[str, str]:
    """Exactly one of uuid / host_name -> the nodes/query filter for it."""
    if bool(uuid) == bool(host_name):
        raise PlatformError("Pass exactly one of 'uuid' or 'host_name' to identify the device.")
    return {"uuid": uuid} if uuid else {"host_name": host_name}  # type: ignore[dict-item]


def _node_ip(node: dict) -> Any:
    node_ip = node.get("node_ip")
    if isinstance(node_ip, dict):
        return node_ip.get("inet_addr", "?")
    return "?"


def _devices_markdown(nodes: list[dict], envelope: dict) -> str:
    total = envelope["total"]
    header = f"# Devices ({envelope['count']} shown"
    header += f", total {total})" if total is not None else ")"
    lines = [header, ""]
    for n in nodes:
        lines.append(
            f"- **{n.get('host_name', '?')}** ({n.get('uuid', '?')}) ip={_node_ip(n)} "
            f"reach={_short(REACHABILITY_STATES, n.get('reachability_state'))} "
            f"oper={n.get('operational_state', '?')} "
            f"admin={_short(ADMIN_STATES, n.get('admin_state'))} "
            f"profile={n.get('profile', '?')} dg={n.get('dg_name') or '-'}"
        )
    if not nodes:
        lines.append("(no devices matched)")
    if envelope["has_more"]:
        lines.append("")
        lines.append(f"More available: page={envelope['next_page']}.")
    return "\n".join(lines)


def label_state_map(node: dict) -> dict:
    """A copy of ``node`` whose ``state_map`` entries carry the spec's ``element`` name.

    Each entry keyed ``"1"`` .. ``"5"`` gains ``"element": "REACHABILITY"`` etc.
    (:data:`STATE_MAP_ELEMENTS`) unless the platform already sent one; the
    epoch fields are left exactly as read. A key outside the enum, or a
    non-dict entry, is passed through untouched. The input is not mutated.
    """
    state_map = node.get("state_map")
    if not isinstance(state_map, dict):
        return node
    labelled: dict[str, Any] = {}
    for key, entry in state_map.items():
        element = STATE_MAP_ELEMENTS.get(str(key))
        if isinstance(entry, dict) and element and "element" not in entry:
            labelled[key] = {"element": element, **entry}
        else:
            labelled[key] = entry
    return {**node, "state_map": labelled}


def _node_summary(node: dict) -> dict[str, Any]:
    return {
        "uuid": node.get("uuid"),
        "host_name": node.get("host_name"),
        "ip": _node_ip(node),
        "reachability_state": node.get("reachability_state"),
        "operational_state": node.get("operational_state"),
        "admin_state": node.get("admin_state"),
        "dg_name": node.get("dg_name"),
        "errors": node.get("errors"),
    }


def _transports(node: dict) -> list[dict]:
    """The node's ``connectivity_info`` entries, exactly as read (dict entries only)."""
    return [e for e in node.get("connectivity_info") or [] if isinstance(e, dict)]


def _gnmi_transport(node: dict) -> dict | None:
    """The node's gNMI transport entry (plain or secure), or None."""
    for entry in _transports(node):
        if entry.get("type") in GNMI_TRANSPORTS:
            return entry
    return None


def _capability_list(node: dict) -> list[str]:
    """The node's ``product_info.capability`` strings, exactly as read (may be empty)."""
    product_info = node.get("product_info")
    caps = product_info.get("capability") if isinstance(product_info, dict) else None
    return [c for c in caps or [] if isinstance(c, str)]


def _gnmi_encoding(encoding: str) -> str:
    """Validate a gNMI encoding_type client-side (case-insensitive) -> wire value."""
    key = encoding.strip().upper()
    if key not in GNMI_ENCODINGS:
        raise PlatformError(
            f"Unknown gNMI encoding '{encoding}'. Use one of: {', '.join(GNMI_ENCODINGS)}."
        )
    return key


def _gnmi_source_ipaddrs(transports: list[dict]) -> list[Any]:
    """The ``ipaddrs`` the new gNMI transport copies: the SSH entry's, else the first
    entry's that carries any. Verbatim from the read — the live-verified body re-sent
    the read shape (``inet_af`` as a string) and Crosswork accepted it."""
    ordered = sorted(transports, key=lambda e: e.get("type") != SSH_TRANSPORT)  # stable
    for entry in ordered:
        ipaddrs = entry.get("ipaddrs")
        if isinstance(ipaddrs, list) and ipaddrs:
            return ipaddrs
    raise PlatformError(
        "The device has no transport with an IP address to copy for gNMI (connectivity_info "
        "is empty or FQDN-only). Add an SSH transport with an IP address first; nothing was "
        "changed."
    )


def _transport_host(entry: dict) -> Any:
    ipaddrs = entry.get("ipaddrs")
    if isinstance(ipaddrs, list) and ipaddrs and isinstance(ipaddrs[0], dict):
        return ipaddrs[0].get("inet_addr", "?")
    fqdn = entry.get("fqdn")
    if isinstance(fqdn, dict) and fqdn.get("host_name"):
        domain = fqdn.get("domain_name")
        return f"{fqdn['host_name']}.{domain}" if domain else fqdn["host_name"]
    return "?"


def _transport_line(entry: dict) -> str:
    """``<protocol> <host>:<port> reach=<state>`` for one connectivity_info entry."""
    line = (
        f"{_short(_DISPLAY_TRANSPORTS, entry.get('type'))} {_transport_host(entry)}:"
        f"{entry.get('port', '?')} reach="
        f"{_short(REACHABILITY_STATES, entry.get('reachability_state', 'unknown'))}"
    )
    if entry.get("encoding_type"):
        line += f" encoding={entry['encoding_type']}"
    return line


def _gnmi_brief(entry: dict | None) -> dict[str, Any] | None:
    if entry is None:
        return None
    return {
        "type": entry.get("type"),
        "port": entry.get("port"),
        "encoding_type": entry.get("encoding_type"),
        "reachability_state": entry.get("reachability_state"),
        "error": entry.get("error") or None,
    }


def _job_brief(job: dict) -> dict[str, Any]:
    """The part of a successful job envelope worth reporting per workflow step."""
    brief: dict[str, Any] = {"ok": True, "job_id": job.get("job_id"), "state": job.get("state")}
    if job.get("warning"):
        brief["warning"] = job["warning"]
    return brief


def _failed_step(e: Exception) -> dict[str, Any]:
    return {"ok": False, "error": format_error(e).removeprefix("Error: ")}


def _step_state(step: dict[str, Any]) -> str:
    return str(step.get("state")) if step.get("ok") else f"FAILED ({step.get('error')})"


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    async def find_device(selector: dict[str, str]) -> dict:
        """One device by uuid or host_name; PlatformError when none/ambiguous."""
        data = await client.request_json(
            "POST",
            NODES_QUERY,
            json_body=query_body(selector, page_size=2, page=0),
            retryable=True,  # a read: safe to re-send on 5xx / transport errors
        )
        nodes, _, _ = unwrap(data, "data")
        key, value = next(iter(selector.items()))
        if not nodes:
            raise PlatformError(
                f"Device with {key} '{value}' not found. Filters are exact-match "
                "(case-insensitive, '*' wildcard); list devices with cnc_list_devices."
            )
        if len(nodes) > 1:
            names = ", ".join(str(n.get("host_name")) for n in nodes)
            raise PlatformError(
                f"{key} '{value}' matched more than one device ({names}, ...). "
                "Narrow the selector or use the uuid."
            )
        return nodes[0]

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_devices",
        title="List Devices",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_devices(
        host_name: Annotated[
            str | None,
            Field(
                description=(
                    "Filter by host name: exact match, case-insensitive, '*' wildcard "
                    "(e.g. 'PE1' or 'PE*'). No substring match without '*'."
                ),
                max_length=253,
            ),
        ] = None,
        reachability: Annotated[
            str | None,
            Field(
                description=(
                    "Filter by reachability: 'reachable', 'unreachable', 'degraded' or "
                    "'unknown' (or the wire value, e.g. 'CONN_STATE_REACHABLE')."
                ),
                max_length=40,
            ),
        ] = None,
        admin_state: Annotated[
            str | None,
            Field(
                description=(
                    "Filter by admin state: 'up', 'down' or 'unmanaged' (or the wire "
                    "value, e.g. 'ROBOT_ADMIN_STATE_UP')."
                ),
                max_length=40,
            ),
        ] = None,
        credential_profile: Annotated[
            str | None,
            Field(
                description="Filter by credential profile name (e.g. 'cml-xrd'); '*' wildcard.",
                max_length=100,
            ),
        ] = None,
        page_size: Annotated[
            int, Field(description="Devices per page (e.g. 20).", ge=1, le=100)
        ] = 20,
        page: Annotated[int, Field(description="0-based page number.", ge=0)] = 0,
        response_format: Annotated[
            ResponseFormat,
            Field(
                description="'markdown' for a one-line-per-device summary, 'json' for all fields."
            ),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List network devices (inventory nodes) with optional filters and paging.

        Read-only. Use it to discover device uuids/host names before calling
        cnc_get_device, cnc_update_device or cnc_delete_device. Filters AND
        together. Unmanaged devices are hidden in the CNC UI's default table
        but are returned here.

        Args:
            host_name, reachability, admin_state, credential_profile: exact-match
                filters (case-insensitive, '*' wildcard). Enum filters accept
                friendly or wire values.
            page_size, page: paging (page is 0-based).
            response_format: 'markdown' (default) or 'json'.

        Returns:
            str: Markdown, one line per device:
            "**host_name** (uuid) ip=... reach=... oper=... admin=... profile=... dg=..."
            plus "More available: page=N." when another page exists. Or JSON:
            {"total": int|null, "count": int, "page": int, "page_size": int,
             "has_more": bool, "next_page": int|null, "collection_total": int|null,
             "items": [<full node objects>]}
            'total' is the number of matches for the filter (absent when zero
            matched); 'collection_total' is the size of the whole inventory.
            On failure: "Error: <actionable message>" (unknown enum value ->
            the accepted values are listed; 500 'NATS request failed' -> the
            platform could not parse the request).
        """
        try:
            filters = {
                "host_name": host_name,
                "reachability_state": wire_enum(REACHABILITY_STATES, reachability, "reachability"),
                "admin_state": wire_enum(ADMIN_STATES, admin_state, "admin_state"),
                "profile": credential_profile,
            }
            data = await client.request_json(
                "POST",
                NODES_QUERY,
                json_body=query_body(filters, page_size=page_size, page=page),
                retryable=True,  # a read: safe to re-send on 5xx / transport errors
            )
            nodes, result_count, total_count = unwrap(data, "data")
            envelope = page_envelope(
                nodes,
                result_count=result_count,
                total_count=total_count,
                page_size=page_size,
                page=page,
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(envelope), settings)
            return finalize(_devices_markdown(nodes, envelope), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_device",
        title="Get Device Details",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_device(
        uuid: Annotated[
            str | None,
            Field(
                description="Device uuid (e.g. '2a9b7c1e-0f3d-4b8a-9c6e-1d2f3a4b5c6d').",
                max_length=100,
            ),
        ] = None,
        host_name: Annotated[
            str | None,
            Field(
                description="Device host name, exact match, case-insensitive (e.g. 'PE1').",
                max_length=253,
            ),
        ] = None,
    ) -> str:
        """Get the full inventory record of one device by uuid or host name.

        Read-only. Pass exactly one selector. Returns every field Crosswork
        holds for the node: uuid, host_name, node_ip, admin_state,
        reachability_state, operational_state, reachability_check, profile,
        connectivity_info, product_info, routing_info, tag_names, dg_name/dg_uuid,
        nso_state, nso_timestamp, state_map, uptime, errors, creation_time,
        last_upd_time, ...

        Note the read/write asymmetry: node_ip.inet_af reads as a string
        ('ROBOT_INET_ADDR_TYPE_v4') but is the integer 0 in write bodies, so do
        not feed this object straight back into a write.

        ``state_map`` (verified live 2026-09-14) is the DLM's per-check state,
        keyed by the numeric RobotNodeStateElement enum: 1 = REACHABILITY,
        2 = DISCOVERY (inventory collection), 3 = CLOCK_DRIFT, 4 = LOCK,
        5 = SYNC (0 = UNSUPPORTED). This tool adds the spec's ``element`` name
        to each entry because the live record omits it. Two live behaviours
        to read it by (verified live 2026-09-14): (a) **key 0 alone** —
        ``{"0": {"element": "UNSUPPORTED", "value": "UP", ...}}`` with no
        REACHABILITY / DISCOVERY / CLOCK_DRIFT entry — is the placeholder a
        freshly added or re-attached device shows while its
        ``operational_state`` is ROBOT_OPER_STATE_CHECKING (seen on P2 right
        after re-attach): the DLM's first check cycle has not run yet, so it
        means "not checked yet", not "unsupported device"; the real entries
        replace it once the checks complete (cnc_wait_for_device_reachable).
        (b) ``next_check_time`` **equals ``last_updated_time`` on every
        element on 7.2** — it is NOT a next-run time and must not be read as
        a schedule; the reachability cadence (1200 s on the lab) is only
        inferable from successive ``last_updated_time`` readings.
        ``uptime`` (e.g. "0w1d14h4m30s") is NOT live and is NOT tied to ``last_upd_time``
        (verified live 2026-09-14, PE2 polled over 25 min): it is refreshed by
        the DLM reachability check, so its as-of time is
        ``state_map["1"].last_updated_time`` (a 1200 s cadence on the lab —
        ``uptime`` advanced 20 min per check while ``last_upd_time``, the
        record's last modification, stayed ~30 h old). It can therefore lag a
        reboot by up to one reachability interval. For the reboot instant use
        cnc_get_ems_node(name=<host_name>) ``nd.last-boot-time``; its
        ``nd.sys-up-time`` is itself a snapshot as of ``nd.collection-time``
        (the last EMS inventory collection — ~4 h stale on the lab, i.e.
        STALER than this ``uptime``), not a live reading. The two sources need
        not agree: on the lab PE2's ``uptime`` implied a boot ~27 h before
        its ``nd.last-boot-time``.

        Returns:
            str: JSON object of the node as Crosswork returns it, plus the
            ``element`` label in each ``state_map`` entry:
            "state_map": {"1": {"element": "REACHABILITY", "value": "UP",
                                "last_updated_time": "<epoch s>",
                                "next_check_time": "<same as last_updated_time>",
                                "info"?: str},
                          "2": {"element": "DISCOVERY", ...},
                          "3": {"element": "CLOCK_DRIFT", ...}, ...}
            (only the checks the DLM runs for the device are present — PE2 on
            the lab showed 1, 2 and 3; a device still in
            ROBOT_OPER_STATE_CHECKING shows only {"0": {"element":
            "UNSUPPORTED", ...}}). "Error: ..." (not found -> no device
            matched the selector; ambiguous -> a wildcard host_name matched
            several devices, use the uuid).
        """
        try:
            node = await find_device(_selector(uuid, host_name))
            return finalize(to_json(label_state_map(node)), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_device_collection_summary",
        title="Get Device Collection Status Summary",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_device_collection_summary() -> str:
        """Count devices by collection status across the whole inventory.

        Read-only. This is the "Collection status" widget of the Network Devices
        page: how many devices are in progress, completed, warning, failed or in
        maintenance for inventory collection. Use it as a quick health check
        before drilling into individual devices with cnc_list_devices.

        Returns:
            str: JSON with flat integer counts:
            {"inprogress": int, "warning": int, "failed": int, "completed": int,
             "maintenance": int}
            On failure: "Error: ...".
        """
        try:
            data = await client.request_json("GET", COLLECTION_SUMMARY)
            return finalize(to_json(data if data is not None else {}), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_create_device",
        title="Add Device",
        read_only=False,
        destructive=False,
        idempotent=False,
    )
    async def cnc_create_device(
        host_name: Annotated[
            str,
            Field(
                description="Host name for the device (e.g. 'PE1').", min_length=1, max_length=253
            ),
        ],
        ip_address: Annotated[
            str,
            Field(
                description=(
                    "IPv4 management address CNC connects to (e.g. '198.18.140.11'). "
                    "IPv6 is not supported by this tool (its wire encoding is unverified)."
                ),
                min_length=1,
                max_length=15,
            ),
        ],
        prefix_length: Annotated[
            int,
            Field(
                description="IPv4 prefix length of the management address, 1-32 (e.g. 18 "
                "for a /18). Required by the platform; the UI rejects /0.",
                ge=1,
                le=32,
            ),
        ],
        credential_profile: Annotated[
            str,
            Field(
                description="Name of an existing credential profile (e.g. 'cml-xrd').",
                min_length=1,
                max_length=100,
            ),
        ],
        protocols: Annotated[
            str,
            Field(
                description=(
                    "Comma-separated transports to enable, from: ssh, snmp, http, https, "
                    "netconf, telnet, tcp, gnmi, grpc. Default ports apply (ssh 22, snmp 161, "
                    "netconf 830, gnmi/grpc 57400, ...); override with 'name:port' "
                    "(e.g. 'ssh,snmp,netconf:830')."
                ),
                min_length=1,
                max_length=200,
            ),
        ] = "ssh,snmp",
        admin_state: Annotated[
            str,
            Field(
                description="'up', 'down' or 'unmanaged' (or the wire value).",
                min_length=1,
                max_length=40,
            ),
        ] = "up",
        reachability_check: Annotated[
            bool, Field(description="Whether CNC should probe the device's reachability.")
        ] = True,
        capabilities: Annotated[
            str,
            Field(
                description=(
                    "Comma-separated device capabilities, from: snmp, yang_cli, yang_mdt, "
                    "gnmi (e.g. 'snmp,yang_cli')."
                ),
                min_length=1,
                max_length=100,
            ),
        ] = "snmp,yang_cli",
        te_router_id: Annotated[
            str | None,
            Field(
                description="TE router-id / loopback (e.g. '10.0.0.1'). This is how CNC "
                "correlates the device with its SR-PCE topology node.",
                max_length=45,
            ),
        ] = None,
        isis_system_id: Annotated[
            str | None,
            Field(description="IS-IS system id (e.g. '0000.0000.0001').", max_length=40),
        ] = None,
        ospf_router_id: Annotated[
            str | None,
            Field(description="OSPF router-id (e.g. '10.0.0.1').", max_length=45),
        ] = None,
        device_type: Annotated[
            str,
            Field(
                description="product_info.device_type wire value; 'NODE_TYPE_ROUTER' is the "
                "only value verified on this platform.",
                min_length=1,
                max_length=50,
            ),
        ] = "NODE_TYPE_ROUTER",
    ) -> str:
        """Add a network device to the CNC inventory.

        WRITE operation — only registered when *_ENABLE_WRITES=true. The POST is
        not auto-retried, so a lost response cannot add the device twice.

        Ordering rules (verified live):
        - The credential profile must exist FIRST: check with
          cnc_list_credential_profiles and create it with
          cnc_create_credential_profile if needed.
        - ip_address must be IPv4 and prefix_length 1-32: the platform requires
          the prefix (the UI rejects '/00') and only the IPv4 address encoding
          has been verified on this platform.
        - Set te_router_id to the device's TE router-id/loopback: it is how CNC
          correlates this inventory record with the SR-PCE topology node. Without
          it the device appears in inventory but is not linked on the topology map.
        - A freshly added device reads reachability 'CONN_STATE_UNKNOWN' and
          operational 'ROBOT_OPER_STATE_CHECKING' until its first check; use
          cnc_wait_for_device_reachable to wait for it. Collection only happens
          once the device is attached to a Data Gateway (dg_name).

        Tags cannot be set on create (verified: a 'tags' list of names is
        rejected with 500, a list of objects is accepted but ignored). Crosswork
        derives system tags from the capabilities ('cli', 'snmp', 'mdt' — visible
        as tag_names in cnc_get_device); user tags are assigned separately.

        Args:
            host_name, ip_address, prefix_length, credential_profile: required.
            protocols: transports with optional ports ('ssh,snmp,netconf:830').
            admin_state, reachability_check, capabilities, device_type: see fields.
            te_router_id, isis_system_id, ospf_router_id: routing_info (optional).

        Returns:
            str: JSON job envelope
            {"job_id": str, "state": "JOB_COMPLETED", "type": "1 device(s) added
             successfully", "impacted": ["<uuid> <host_name> <ip>"],
             "impacted_objects": [{"uuid", "name", "ip"}], ...}
            The new device's uuid is impacted_objects[0].uuid.
            On failure: "Error: ..." — a rejected add is HTTP 200 with
            state JOB_FAILED and the platform's reason (e.g. unknown credential
            profile, duplicate host name/IP); 500 'NATS request failed' means the
            platform could not parse the body.
        """
        try:
            node: dict[str, Any] = {
                "host_name": host_name,
                "profile": credential_profile,
                "reachability_check": REACH_CHECK[reachability_check],
                "admin_state": wire_enum(ADMIN_STATES, admin_state, "admin_state"),
                "connectivity_info": _connectivity_info(protocols, ip_address, prefix_length),
                "product_info": {
                    "device_type": device_type,
                    "capability": _capabilities(capabilities),
                },
            }
            routing = _routing_info(te_router_id, isis_system_id, ospf_router_id)
            if routing:
                node["routing_info"] = routing
            result = await client.request_json("POST", NODES, json_body={"data": [node]})
            job = check_job(result, f"Adding device '{host_name}'")
            return finalize(to_json(job), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_update_device",
        title="Update Device",
        read_only=False,
        destructive=False,
        idempotent=True,
    )
    async def cnc_update_device(
        uuid: Annotated[
            str,
            Field(
                description="uuid of the device to update (from cnc_list_devices).",
                min_length=1,
                max_length=100,
            ),
        ],
        admin_state: Annotated[
            str | None,
            Field(description="New admin state: 'up', 'down' or 'unmanaged'.", max_length=40),
        ] = None,
        reachability_check: Annotated[
            bool | None, Field(description="Enable (true) or disable (false) reachability probing.")
        ] = None,
        credential_profile: Annotated[
            str | None,
            Field(
                description="Switch to this existing credential profile (e.g. 'cml-xrd').",
                max_length=100,
            ),
        ] = None,
        te_router_id: Annotated[
            str | None,
            Field(
                description="New TE router-id (e.g. '10.0.0.1'). Only the ids you pass "
                "change; the others in routing_info are kept (verified merge semantics).",
                max_length=45,
            ),
        ] = None,
        isis_system_id: Annotated[
            str | None,
            Field(
                description="New IS-IS system id (e.g. '0000.0000.0001'). Pass together with "
                "the other routing ids (see docstring).",
                max_length=40,
            ),
        ] = None,
        ospf_router_id: Annotated[
            str | None,
            Field(
                description="New OSPF router-id (e.g. '10.0.0.1'). Pass together with the "
                "other routing ids (see docstring).",
                max_length=45,
            ),
        ] = None,
    ) -> str:
        """Partially update a device: admin state, reachability check, credential
        profile and/or routing identifiers.

        WRITE operation — only registered when *_ENABLE_WRITES=true. Only the
        fields you pass are sent (PATCH). At least one change is required.

        Why PATCH: Crosswork's PUT is a full replace and, with anything less than
        the complete object, answers HTTP 200 with state JOB_FAILED
        ("Software Type needs to be configured"). PATCH applies partial bodies
        cleanly and is what this tool uses. Path-parameter forms (/nodes/{uuid})
        do not exist on this platform.

        Routing ids are sent as a partial nested object ({"routing_info": {...}})
        and Crosswork MERGES it (verified live): passing only te_router_id
        changes that id and leaves isis_system_id / ospf_router_id as they were.

        Typical uses: set admin_state='unmanaged' to pause management (unmanaged
        devices disappear from the UI's default table but remain in inventory),
        or fix te_router_id so the device correlates with its SR-PCE topology node.

        Returns:
            str: JSON job envelope ({"job_id", "state": "JOB_COMPLETED",
            "type": "1 device(s) details patched successfully", "impacted",
            "impacted_objects", ...}), or "Error: ..." (JOB_FAILED -> the
            platform's reason; unknown uuid -> the job reports it).
        """
        try:
            changes: dict[str, Any] = {}
            if admin_state:
                changes["admin_state"] = wire_enum(ADMIN_STATES, admin_state, "admin_state")
            if reachability_check is not None:
                changes["reachability_check"] = REACH_CHECK[reachability_check]
            if credential_profile:
                changes["profile"] = credential_profile
            routing = _routing_info(te_router_id, isis_system_id, ospf_router_id)
            if routing:
                changes["routing_info"] = routing
            if not changes:
                raise PlatformError(
                    "Nothing to update: pass at least one of admin_state, reachability_check, "
                    "credential_profile, te_router_id, isis_system_id or ospf_router_id."
                )
            body = {"data": [{"uuid": uuid, **changes}]}
            result = await client.request_json("PATCH", NODES, json_body=body)
            job = check_job(result, f"Updating device {uuid}")
            return finalize(to_json(job), settings)
        except Exception as e:
            return format_error(e)

    async def patch_node(changes: dict[str, Any], what: str) -> dict[str, Any]:
        """One ``PATCH nodes`` step of a workflow, validated through check_job.

        retryable=True: each body carries absolute state (an admin_state value or
        the complete transport list), so re-sending it after a lost response or a
        gateway 5xx cannot double-apply anything — and the admin-up step in
        particular must not be abandoned on a transient error.

        Raises :class:`_PatchNotAnswered` when no job envelope came back at all
        (retries exhausted on a 5xx, or a transport error/timeout): the platform
        may still have applied the change. A JOB_FAILED answer raises the plain
        PlatformError from check_job — the platform rejected it, nothing changed.
        """
        try:
            result = await client.request_json(
                "PATCH", NODES, json_body={"data": [changes]}, retryable=True
            )
        except Exception as e:
            raise _PatchNotAnswered(format_error(e).removeprefix("Error: ")) from e
        return check_job(result, what)

    @register_tool(
        mcp,
        ctx,
        name="cnc_enable_device_gnmi",
        title="Enable gNMI on a Device",
        read_only=False,
        destructive=False,
        idempotent=True,
    )
    async def cnc_enable_device_gnmi(
        uuid: Annotated[
            str,
            Field(
                description="uuid of the device to enable gNMI on (from cnc_list_devices).",
                min_length=1,
                max_length=100,
            ),
        ],
        port: Annotated[
            int,
            Field(description="gRPC/gNMI port the router listens on (e.g. 57400).", ge=1, le=65535),
        ] = 57400,
        encoding: Annotated[
            str,
            Field(
                description=(
                    "gNMI encoding_type: one of UNKNOWN_ENCODING_TYPE, ASCII, BYTES, PROTO, "
                    "JSON, JSON_IETF, XML, YANG (e.g. 'JSON_IETF', the value verified on IOS-XR)."
                ),
                min_length=1,
                max_length=30,
            ),
        ] = "JSON_IETF",
        secure: Annotated[
            bool,
            Field(
                description=(
                    "false (default) adds ROBOT_MSVC_TRANS_GNMI (plaintext gRPC, 'grpc port "
                    "57400 no-tls'; the variant verified live). true adds "
                    "ROBOT_MSVC_TRANS_GNMI_SECURE (TLS) — UNVERIFIED live: the wire value is "
                    "from the DLM spec enum only, no device has been onboarded with it."
                )
            ),
        ] = False,
        wait_seconds: Annotated[
            int,
            Field(
                description=(
                    "After the change, poll until the gNMI transport reports "
                    "CONN_STATE_REACHABLE for up to this many seconds (e.g. 90; it typically "
                    "takes about 60). 0 = one verification read, no waiting. Ignored (one "
                    "read) for a device that is admin-down, which is not collected."
                ),
                ge=0,
                le=600,
            ),
        ] = 90,
    ) -> str:
        """Add a gNMI transport and the GNMI capability to an existing device.

        WRITE workflow — only registered when *_ENABLE_WRITES=true. Idempotent:
        a device that already has BOTH a gNMI transport (plain or secure) AND
        the GNMI capability is reported as "already has gNMI" and left untouched.
        A device with the transport but not the capability (the two are set
        independently in the UI) gets the capability added; a device with the
        capability but no transport gets the transport added. Use it to onboard
        gNMI-based collection (SR-policy PM over gNMI, OAM path traces) on a
        device that was added with SSH/SNMP only; do not use it to change the
        port or encoding of an existing gNMI transport (an existing transport is
        kept verbatim and port/encoding/secure are ignored).

        PRECONDITIONS (verified live 2026-09-14):
        - The device's credential profile must already hold a gNMI credential
          (a user_pass entry of type ROBOT_USERPASS_GNMI) — check with
          cnc_get_credential_profile and add it with cnc_update_credential_profile
          first. Without it the transport is added but stays unreachable.
        - The router must serve gRPC on the port ('grpc port 57400 no-tls' on
          IOS-XR for the default, plaintext transport).
        - The device must be admin-up or admin-down. An UNMANAGED device (or an
          unknown admin_state) is refused before anything is written: set it up
          or down first with cnc_update_device admin_state='up'|'down'.
        - An admin-up device is admin-down for roughly ten seconds during the
          change, so collection pauses briefly; do not run it on a device
          mid-deployment.

        What it does (the ordering rule is enforced by the platform: a capability
        change is refused while the node is admin-up and attached to a Data
        Gateway — "Capability cannot be changed while the node is attached to a
        VDG and in admin up state..."):
        1. Reads the device (nodes/query). Stops without writing when gNMI is
           fully present, when the device is neither admin-up nor admin-down, or
           when a transport must be added and no existing transport carries an
           IP address to copy (the SSH entry's ipaddrs are used, else the first
           entry's).
        2. Admin-up device only: PATCH admin_state ROBOT_ADMIN_STATE_DOWN, then
           settle 5 s (the timing of the verified run). An admin-down device
           skips this step — the refusal only applies to admin-up nodes — and
           its admin state is never touched.
        3. PATCH connectivity_info = the existing entries verbatim (+ the new
           {type, ipaddrs, port, timeout "30", encoding_type} entry when the
           transport is missing) and product_info.capability = existing ∪
           {"GNMI"}.
        4. Admin-up device only: settle 3 s, then PATCH admin_state
           ROBOT_ADMIN_STATE_UP — ALWAYS sent once step 2 succeeded, even when
           step 3 failed, so the device is restored to the admin state it was
           read in. Both outcomes are reported.
        5. Admin-up device: if wait_seconds > 0, polls the node until the gNMI
           transport's reachability_state is CONN_STATE_REACHABLE or the time
           is up. Admin-down device: one verification read, no waiting (the
           transport is not checked while the device is admin-down).
        Each PATCH normally answers JOB_COMPLETED_WITH_WARNING with the NSO
        advisory ("Note, if device <uuid> is used in NSO, any updates to it needs
        be done through NSO interface") — that is a success.

        Returns:
            str: A summary ("Enabled gNMI on <host> (<uuid>) ...") with the job
            state of each step sent, the transport list after the change and the
            gNMI transport's final reachability, then a JSON envelope:
            {"uuid", "host_name", "changed": bool, "reachable": bool,
             "waited_seconds": int, "admin_state_before", "admin_state_after",
             "added": {"transport": bool, "capability": bool},
             "gnmi": {"type", "port", "encoding_type", "reachability_state",
             "error"}, "steps": {"admin_down"?, "add_gnmi", "admin_up"?:
             {"ok", "job_id", "state", "warning"} | {"ok": false, "error"}},
             "capability": [...], "connectivity_info": [...]}
            (admin_down/admin_up appear only for an admin-up device).
            "already has gNMI (...)" (changed false, no PATCH sent; the envelope
            carries "capability" and "admin_state"), "not reachable yet after
            Ns; current state ..." (the transport was added; call cnc_get_device
            later or check the gNMI credential and the router's grpc config) and
            "left admin-down ... not checked" are NOT errors.
            "Error: ..." when the device is not found / is unmanaged / has no IP
            transport (nothing sent); when the admin-down PATCH fails — a
            JOB_FAILED answer means nothing changed, while an HTTP/transport
            failure (no job answer) means the admin-down MAY have been applied,
            so the message says to check cnc_get_device and run cnc_update_device
            admin_state='up' if it is down; when the transport PATCH fails — the
            platform's reason verbatim, e.g. "Encoding Type is required for adding
            a GNMI protocol" or the capability/VDG refusal — together with the
            outcome of the admin-up PATCH that was still sent; or when the
            admin-up PATCH fails (the device is then admin-down: run
            cnc_update_device admin_state='up').
        """
        try:
            encoding_wire = _gnmi_encoding(encoding)
            gnmi_type = GNMI_TRANSPORT_SECURE if secure else GNMI_TRANSPORT
            selector = {"uuid": uuid}
            node = await find_device(selector)
            host = node.get("host_name")
            label = f"{host} ({uuid})"
            transports = _transports(node)
            existing_caps = _capability_list(node)
            has_capability = GNMI_CAPABILITY in existing_caps
            existing = _gnmi_transport(node)
            admin_before = node.get("admin_state")
            if existing is not None and has_capability:
                head = (
                    f"Device {label} already has gNMI ({_transport_line(existing)}) and the "
                    f"{GNMI_CAPABILITY} capability; nothing changed."
                )
                envelope = {
                    "uuid": uuid,
                    "host_name": host,
                    "changed": False,
                    "reachable": existing.get("reachability_state") == REACHABLE,
                    "admin_state": admin_before,
                    "gnmi": _gnmi_brief(existing),
                    "capability": existing_caps,
                    "connectivity_info": transports,
                }
                return finalize(f"{head}\n{to_json(envelope)}", settings)
            # The admin-state bounce is only needed — and only verified — for an admin-up
            # device: the refusal is about "admin up state", and an admin-down device's
            # state must not be changed behind the operator's back.
            if admin_before == ADMIN_UP:
                bounce = True
            elif admin_before == ADMIN_DOWN:
                bounce = False
            else:
                raise PlatformError(
                    f"Device {label} is admin_state {admin_before!r}; cnc_enable_device_gnmi "
                    "only runs on an admin-up or admin-down device (an unmanaged device is "
                    "not collected, and bouncing it through admin-down has not been verified). "
                    "Set it with cnc_update_device admin_state='up' (or 'down') first. "
                    "Nothing was changed."
                )
            if existing is None:
                ipaddrs = _gnmi_source_ipaddrs(transports)
                new_entry = {
                    "type": gnmi_type,
                    "ipaddrs": ipaddrs,
                    "port": port,
                    "timeout": GNMI_TRANSPORT_TIMEOUT,
                    "encoding_type": encoding_wire,
                }
                connectivity = [*transports, new_entry]
                change = f"{gnmi_type} port {port}, encoding {encoding_wire}"
                if not has_capability:
                    change += f" plus the {GNMI_CAPABILITY} capability"
            else:
                # Transport present, capability missing: re-send the transport list
                # verbatim (the verified body shape) with the capability added.
                connectivity = transports
                change = (
                    f"the existing {_transport_line(existing)} transport was kept and the "
                    f"missing {GNMI_CAPABILITY} capability was added"
                )
            capability = sorted(set(existing_caps) | {GNMI_CAPABILITY})
            add_what = (
                f"Adding the gNMI transport to device {label} (gNMI step 2 of 3)"
                if bounce
                else f"Adding gNMI to device {label} (the only step: it is already admin-down)"
            )

            steps: dict[str, dict[str, Any]] = {}
            if bounce:
                # Step 2 — a failure here means nothing else is sent.
                down_what = f"Setting device {label} admin-down (gNMI step 1 of 3)"
                try:
                    steps["admin_down"] = _job_brief(
                        await patch_node({"uuid": uuid, "admin_state": ADMIN_DOWN}, down_what)
                    )
                except _PatchNotAnswered as e:
                    raise PlatformError(
                        f"{down_what} failed: {str(e).rstrip('.')}. Nothing else was sent, but "
                        "the admin-down may already have been applied: check the device with "
                        "cnc_get_device and run cnc_update_device with admin_state='up' if it "
                        "reads admin-down."
                    ) from e
                except PlatformError as e:  # JOB_FAILED: rejected, so the state is unchanged
                    raise PlatformError(
                        f"{str(e).rstrip('.')}. Nothing else was sent; the platform rejected "
                        "the change, so the device is still admin-up and unchanged."
                    ) from e
                await asyncio.sleep(GNMI_SETTLE_AFTER_DOWN)
            # Step 3 — captured, never raised: the admin-up step must follow regardless.
            add_error: Exception | None = None
            try:
                steps["add_gnmi"] = _job_brief(
                    await patch_node(
                        {
                            "uuid": uuid,
                            "connectivity_info": connectivity,
                            "product_info": {"capability": capability},
                        },
                        add_what,
                    )
                )
            except Exception as e:
                add_error = e
                steps["add_gnmi"] = _failed_step(e)
            # Step 4 — always attempted once the device went admin-down.
            up_error: Exception | None = None
            if bounce:
                await asyncio.sleep(GNMI_SETTLE_AFTER_ADD)
                try:
                    steps["admin_up"] = _job_brief(
                        await patch_node(
                            {"uuid": uuid, "admin_state": ADMIN_UP},
                            f"Setting device {label} admin-up (gNMI step 3 of 3)",
                        )
                    )
                except Exception as e:
                    up_error = e
                    steps["admin_up"] = _failed_step(e)

            states = ", ".join(f"{name} {_step_state(step)}" for name, step in steps.items())
            if add_error is not None or up_error is not None:
                if add_error is not None:
                    reason = str(steps["add_gnmi"]["error"]).rstrip(".")
                    problem = f"Adding gNMI to device {label} failed: {reason}."
                    unanswered = isinstance(add_error, _PatchNotAnswered)
                    if unanswered:
                        problem += (
                            " No job answer came back, so the transport/capability change "
                            "may or may not have been applied: check with cnc_get_device."
                        )
                    if not bounce:
                        problem += (
                            " The device was admin-down before the call and no admin-state "
                            "PATCH was sent."
                        )
                    elif up_error is None:
                        problem += " The device was set admin-up again"
                        problem += "." if unanswered else " (nothing else changed)."
                    else:
                        problem += (
                            " The follow-up admin-up PATCH ALSO failed, so the device is now "
                            "admin-down: run cnc_update_device with admin_state='up'."
                        )
                else:
                    problem = (
                        f"gNMI was added to device {label} but the admin-up PATCH failed, so the "
                        "device is now admin-down: run cnc_update_device with admin_state='up' "
                        "(collection stays paused until then)."
                    )
                raise PlatformError(f"{problem} Steps: {states}. {to_json({'steps': steps})}")

            # Step 5 — wait_seconds=0 makes wait_until do exactly one verification read;
            # an admin-down device is not collected, so waiting on it would be pointless.
            effective_wait = wait_seconds if bounce else 0
            try:
                finished, after, elapsed = await wait_until(
                    lambda: find_device(selector),
                    lambda n: (_gnmi_transport(n) or {}).get("reachability_state") == REACHABLE,
                    timeout_seconds=effective_wait,
                    interval_seconds=GNMI_POLL_INTERVAL,
                )
            except Exception as e:
                restored = "it is admin-up again" if bounce else "it was left admin-down as found"
                raise PlatformError(
                    f"gNMI was added to device {label} and {restored} (steps: {states}), but "
                    f"the verification read failed: {format_error(e).removeprefix('Error: ')} "
                    "Re-read with cnc_get_device."
                ) from e
            gnmi_after = _gnmi_transport(after)
            after_transports = _transports(after)
            after_caps = (
                _capability_list(after)
                if isinstance(after.get("product_info"), dict)
                else capability
            )
            head = f"Enabled gNMI on device {label}: {change}. "
            if finished:
                head += f"The gNMI transport is reachable after {elapsed:.0f}s."
            elif not bounce:
                current = gnmi_after.get("reachability_state") if gnmi_after else "not visible yet"
                head += (
                    "The device was admin-down before the call and was left admin-down (no "
                    "admin-state PATCH was sent), so the transport's reachability was not "
                    f"waited for; current state {current}. Not an error: set admin_state='up' "
                    "with cnc_update_device when it should be collected again, then check "
                    "with cnc_get_device."
                )
            elif gnmi_after is None:
                head += (
                    f"The gNMI transport is not visible on the device yet after {elapsed:.0f}s "
                    "(not an error): re-read with cnc_get_device."
                )
            else:
                head += (
                    f"Not reachable yet after {elapsed:.0f}s; current state "
                    f"{gnmi_after.get('reachability_state')}"
                )
                if gnmi_after.get("error"):
                    head += f" (error: {gnmi_after['error']})"
                head += (
                    ". Not an error: it typically takes about 60s. Check again with "
                    "cnc_get_device (connectivity_info[].reachability_state); if it stays "
                    "unreachable, verify the profile's ROBOT_USERPASS_GNMI credential and the "
                    "router's grpc configuration."
                )
            lines = [
                head,
                f"Steps: {states}.",
                "Transports after: "
                + ("; ".join(_transport_line(t) for t in after_transports) or "(none read back)"),
            ]
            envelope = {
                "uuid": uuid,
                "host_name": host,
                "changed": True,
                "reachable": finished,
                "waited_seconds": round(elapsed),
                "admin_state_before": admin_before,
                "admin_state_after": after.get("admin_state"),
                "added": {"transport": existing is None, "capability": not has_capability},
                "gnmi": _gnmi_brief(gnmi_after),
                "steps": steps,
                "capability": after_caps,
                "connectivity_info": after_transports,
            }
            return finalize("\n".join(lines) + "\n" + to_json(envelope), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_device",
        title="Delete Device",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_device(
        uuid: Annotated[
            str,
            Field(
                description="uuid of the device to delete (from cnc_list_devices).",
                min_length=1,
                max_length=100,
            ),
        ],
    ) -> str:
        """Permanently remove a device from the CNC inventory.

        DESTRUCTIVE write — only registered when *_ENABLE_WRITES=true. Verify
        the target with cnc_get_device first; the device's collected data and
        its place on the topology map go with it. Crosswork deletes through the
        collection URL with a JSON body ({"data": [{"uuid": ...}]}); there is no
        /nodes/{uuid} form.

        Returns:
            str: JSON job envelope ({"job_id", "state": "JOB_COMPLETED",
            "type": "1 device(s) deleted successfully", "impacted", ...}), or
            "Error: ..." (JOB_FAILED -> the platform's reason, e.g. the uuid
            does not exist or the device is still referenced by a service).
        """
        try:
            result = await client.request_json(
                "DELETE", NODES, json_body={"data": [{"uuid": uuid}]}
            )
            job = check_job(result, f"Deleting device {uuid}")
            return finalize(to_json(job), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_wait_for_device_reachable",
        title="Wait for Device to Become Reachable",
        read_only=True,
        idempotent=True,
    )
    async def cnc_wait_for_device_reachable(
        uuid: Annotated[
            str | None,
            Field(
                description="Device uuid (from cnc_create_device's impacted_objects).",
                max_length=100,
            ),
        ] = None,
        host_name: Annotated[
            str | None,
            Field(description="Device host name, exact match (e.g. 'PE1').", max_length=253),
        ] = None,
        timeout_seconds: Annotated[
            int, Field(description="How long to wait in total (e.g. 180).", ge=10, le=900)
        ] = 180,
        interval_seconds: Annotated[
            int, Field(description="Seconds between polls (e.g. 10).", ge=1, le=60)
        ] = 10,
    ) -> str:
        """Poll a device until its reachability_state is CONN_STATE_REACHABLE.

        Read-only convergence wait. Call it right after cnc_create_device (or
        after fixing credentials / admin state) instead of polling
        cnc_get_device in a loop. Pass exactly one of uuid / host_name. A new
        device typically moves UNKNOWN/CHECKING -> REACHABLE within a minute or
        two once it is attached to a Data Gateway.

        Returns:
            str: On success: "Device <host> (<uuid>) is reachable after Ns." plus a
            JSON summary (reachability_state, operational_state, dg_name, errors).
            On timeout (NOT an error): "Not reachable yet after Ns; current
            reachability_state=..., operational_state=..." plus the same
            summary — call again to keep waiting, or inspect 'errors' / dg_name.
            "Error: ..." only for API failures or when no device matches.
        """
        try:
            selector = _selector(uuid, host_name)
            finished, node, elapsed = await wait_until(
                lambda: find_device(selector),
                lambda n: n.get("reachability_state") == REACHABLE,
                timeout_seconds=timeout_seconds,
                interval_seconds=interval_seconds,
            )
            summary = to_json(_node_summary(node))
            if finished:
                head = (
                    f"Device {node.get('host_name')} ({node.get('uuid')}) is reachable "
                    f"after {elapsed:.0f}s."
                )
            else:
                head = (
                    f"Not reachable yet after {elapsed:.0f}s; current "
                    f"reachability_state={node.get('reachability_state')}, "
                    f"operational_state={node.get('operational_state')}. Call again to keep "
                    "waiting, or check the credential profile, admin state and Data Gateway "
                    "attachment (dg_name)."
                )
            return finalize(f"{head}\n{summary}", settings)
        except Exception as e:
            return format_error(e)
