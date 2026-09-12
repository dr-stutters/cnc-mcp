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
"""

from __future__ import annotations

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

_TRANSPORT_NAMES = {wire: name for name, wire in TRANSPORTS.items()}


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
        nso_state, errors, creation_time, last_upd_time, ...

        Note the read/write asymmetry: node_ip.inet_af reads as a string
        ('ROBOT_INET_ADDR_TYPE_v4') but is the integer 0 in write bodies, so do
        not feed this object straight back into a write.

        Returns:
            str: JSON object of the node, or "Error: ..." (not found -> no device
            matched the selector; ambiguous -> a wildcard host_name matched
            several devices, use the uuid).
        """
        try:
            node = await find_device(_selector(uuid, host_name))
            return finalize(to_json(node), settings)
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
