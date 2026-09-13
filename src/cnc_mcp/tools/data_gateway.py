"""Data Gateway tools — the Crosswork Data Gateway (CDG) collection engine.

A Data Gateway is the collection engine that devices are attached to: it runs
the CLI / SNMP / MDT / gNMI / NETCONF / syslog collectors that give Crosswork
reachability, inventory and telemetry for a device. Nothing is collected from a
device until it is mapped to a gateway. On single-VM deployments (the lab this
module was verified on) the gateway is *embedded*: one physical gateway named
``EMBEDDED_DEF_CDG`` in the HA pool ``EMBEDDED_DEF_POOL``, with a single
``embeddedCollectors`` component.

UUID relationships (verified live 2026-09-13):

- ``duuid`` — the physical gateway id (``cnc_list_data_gateways``); it is the
  ``DGID`` every dg-manager metrics/health/outage query takes.
- ``configData.vdgUuid`` — the *virtual* gateway id. **A device's ``dg_uuid``
  (``cnc_get_device``) equals the gateway's ``vdgUuid``**, not its ``duuid``
  and not the pool ``puuid``; the device-mapping API takes the ``vdgUuid`` as
  ``cdg_duuid``.
- ``configData.poolId`` / pool ``puuid`` — the HA pool the gateway belongs to
  (``cnc_list_data_gateway_pools``). A device's ``dg_name`` is the pool name
  plus ``-1`` (``EMBEDDED_DEF_POOL-1``).

Wire facts this module encodes (dg-manager, ``/crosswork/dg-manager``):

- every read is JSON-over-POST and **the service rejects unknown body fields**
  with ``400 unable to unmarshal payload to proto`` — bodies here are exactly
  the verified ones, and two grammars coexist inside the service
  (``dg/query`` takes ``filterData.Criteria``, ``hapool/query`` takes a bare
  ``criteria`` — :func:`cnc_mcp.crosswork.dg_query_body` picks per table);
- no server-side paging was observed on ``dg/query`` / ``hapool/query`` (the
  whole collection comes back); the file queries page with ``startRow`` /
  ``endRow``;
- the embedded gateway answers ``vitals/query`` with ``500 … not found`` —
  embedded gateways expose no health vitals (``cnc_get_data_gateway_health``
  turns that into an informational answer, not an error);
- device mapping is an *inventory* write (``PUT
  /crosswork/inventory/v1/dg/devicemapping``) answering a job envelope; on a
  single embedded gateway an unmapped device is re-mapped automatically within
  seconds, so removals do not stick (see ``cnc_map_devices_to_data_gateway``).

Everything here was verified on an embedded Data Gateway only; multi-gateway
(standalone CDG VM, HA pool with several gateways) behaviour follows the same
documented shapes but was not exercised live.

NOT in scope of this module: ping/traceroute and the other OAM commands
(``command/ping``, ``command/query`` answer ``500 … no responders available``
on the embedded gateway), gateway create/delete/admin-state changes, HA pool
CRUD, and software-file upload/download.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.client import ApiClient
from cnc_mcp.crosswork import INVENTORY, check_job, dg_query_body, page_envelope, unwrap, wire_enum
from cnc_mcp.errors import PlatformError, format_error, http_error
from cnc_mcp.formatting import ResponseFormat, finalize, to_json
from cnc_mcp.safety import AppContext, register_tool

DG_BASE = "/crosswork/dg-manager"
DG_QUERY_URL = f"{DG_BASE}/v2/dg/query"
POOL_QUERY_URL = f"{DG_BASE}/v2/hapool/query"
LOAD_METRICS_URL = f"{DG_BASE}/v1/device/load-metrics/query"
OUTAGE_HISTORY_URL = f"{DG_BASE}/v1/device/outage-history/query"
VITALS_URL = f"{DG_BASE}/v1/vitals/query"
GLOBAL_PARAMS_URL = f"{DG_BASE}/v1/command/global-parameter/query"
DESTINATIONS_URL = f"{DG_BASE}/v1/destinations/query"
SYSTEM_FILES_URL = f"{DG_BASE}/v1/system-files/query"
CUSTOM_FILES_URL = f"{DG_BASE}/v2/custom-files/query"
DEVICE_MAPPING_URL = f"{INVENTORY}/dg/devicemapping"

# The verified destinations body: {"limit": 100, "filter": {}} (no offset field exists).
DESTINATIONS_LIMIT = 100

# Device-mapping operations (verified: DELETE_OPER answers 500 NATS; the enum is these three).
MAPPING_OPERATIONS = {"add": "ADD_OPER", "remove": "REMOVE_OPER", "update": "UPDATE_OPER"}
MAX_MAPPING_DEVICES = 50

FILE_KINDS = {"system": SYSTEM_FILES_URL, "custom": CUSTOM_FILES_URL}

_MAPPING_CHOICES = ", ".join(MAPPING_OPERATIONS)
_FILE_KIND_CHOICES = ", ".join(FILE_KINDS)
_TRANSPORT_PREFIX = "ROBOT_MSVC_TRANS_"


def query_param(field: str, value: str) -> dict[str, Any]:
    """One dg-manager ``queryParams`` entry: ``{"field": F, "value": {"valueStr": V}}``."""
    return {"field": field, "value": {"valueStr": value}}


def name_matches(pattern: str, value: Any) -> bool:
    """Case-insensitive exact match where ``*`` in ``pattern`` is a wildcard.

    Mirrors the inventory filter semantics (exact, case-insensitive, ``*``
    anywhere) so agents get the same behaviour they see on nodes/providers;
    ``?`` and ``%`` are literal characters, not wildcards.
    """
    if not isinstance(value, str):
        return False
    regex = ".*".join(re.escape(part) for part in pattern.strip().split("*"))
    return re.fullmatch(regex, value, re.IGNORECASE) is not None


def flatten_param_value(wrapper: Any) -> Any:
    """Unwrap a global-parameter typed value (``{"uint32Value": 31062}`` -> ``31062``).

    The wrapper holds exactly one typed field (``uint32Value``, ``boolValue``,
    ``stringValue``, ...). Anything else is returned unchanged so an unexpected
    shape is still visible rather than lost.
    """
    if isinstance(wrapper, dict) and len(wrapper) == 1:
        return next(iter(wrapper.values()))
    return wrapper


def epoch_iso(value: Any) -> str:
    """Render an epoch timestamp as ISO-8601 UTC, whatever unit dg-manager used.

    dg-manager mixes units per field (``createdTime`` in nanoseconds,
    ``lastUpdatedTime`` in seconds, file ``modifiedTime`` in seconds, outage
    timestamps in nanoseconds) and sends them as ints or numeric strings; the
    unit is inferred from the magnitude. ``0``/empty/unparseable -> ``-`` /
    the raw text.
    """
    if value in (None, ""):
        return "-"
    try:
        n = int(str(value).strip())
    except ValueError:
        return str(value)
    if n <= 0:
        return "-"
    seconds: float = n
    for threshold, divisor in ((10**17, 10**9), (10**14, 10**6), (10**11, 10**3)):
        if n >= threshold:
            seconds = n / divisor
            break
    try:
        return datetime.fromtimestamp(seconds, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return str(value)


def _total_count(data: Any) -> int | None:
    """dg-manager spells the collection size ``totalCount`` (v2) or ``total_count`` (files)."""
    if not isinstance(data, dict):
        return None
    for key in ("totalCount", "total_count"):
        value = data.get(key)
        if isinstance(value, int):
            return value
    return None


def _is_vitals_not_found(body_text: str) -> bool:
    """True only for the verified embedded-gateway vitals answer.

    dg-manager answers ``500 {"error": "vitals for Data Gateway ID with '<id>'
    not found"}`` when a gateway has no vitals (verified live on the embedded
    gateway). Any other 500 — including ones that happen to contain the words
    'not found' elsewhere, such as a NATS subject error — is a real failure and
    must stay on the error path.
    """
    lowered = body_text.lower()
    return "vitals for data gateway id" in lowered and "not found" in lowered


def _transport_label(wire: Any) -> str:
    """``ROBOT_MSVC_TRANS_KAFKA`` -> ``kafka``; unknown values pass through."""
    if not isinstance(wire, str) or not wire:
        return "?"
    return wire.removeprefix(_TRANSPORT_PREFIX).lower()


def _gateway_lines(gateway: dict[str, Any]) -> list[str]:
    """Markdown for one gateway: summary line plus one sub-line per component."""
    config = gateway.get("configData") if isinstance(gateway.get("configData"), dict) else {}
    oper = (
        gateway.get("operationalData") if isinstance(gateway.get("operationalData"), dict) else {}
    )
    profile = config.get("profile") if isinstance(config.get("profile"), dict) else {}
    lines = [
        f"- **{gateway.get('name', '?')}** ({gateway.get('duuid', '?')}) "
        f"vdg={config.get('vdgUuid') or '-'} pool={config.get('poolId') or '-'} "
        f"admin={config.get('adminState') or '?'} oper={oper.get('operState') or '?'} "
        f"role={config.get('role') or '?'} "
        f"profile={profile.get('cpu', '?')}c/{profile.get('memory', '?')}G/"
        f"{profile.get('nics', '?')}nic"
    ]
    for detail in oper.get("operStateDetails") or []:
        if not isinstance(detail, dict):
            continue
        line = f"  - {detail.get('componentName', '?')}: {detail.get('state', '?')}"
        if detail.get("imageTag"):
            line += f" (image {detail['imageTag']})"
        lines.append(line)
    return lines


def _gateways_markdown(gateways: list[dict[str, Any]], envelope: dict[str, Any]) -> str:
    lines = [
        f"# Data Gateways ({envelope['count']} shown, matching {envelope['total']}, "
        f"collection {envelope['collection_total']})",
        "",
    ]
    if not gateways:
        lines.append("No Data Gateways matched.")
    for gateway in gateways:
        lines.extend(_gateway_lines(gateway))
    lines.append("")
    lines.append(
        "A device's dg_uuid is the gateway's vdg (vdgUuid); its dg_name is the pool name + '-1'."
    )
    return "\n".join(lines)


def _pool_vips(pool: dict[str, Any]) -> list[str]:
    """Virtual IPs / FQDNs of a pool, from the v2 shape (``ipaddrs[].inetaddrs[].inetAddr``,
    verified) with the documented v1 shape (``ipaddrs[].ipaddr.inet_addr``) as a fallback."""
    vips: list[str] = []
    for entry in pool.get("ipaddrs") or []:
        if not isinstance(entry, dict):
            continue
        for addr in entry.get("inetaddrs") or []:
            if isinstance(addr, dict) and addr.get("inetAddr"):
                vips.append(str(addr["inetAddr"]))
        legacy = entry.get("ipaddr")
        if isinstance(legacy, dict) and legacy.get("inet_addr"):
            vips.append(str(legacy["inet_addr"]))
        if isinstance(entry.get("fqdn"), str) and entry["fqdn"]:
            vips.append(entry["fqdn"])
    return vips


def _pools_markdown(pools: list[dict[str, Any]], total: int | None) -> str:
    lines = [f"# Data Gateway Pools ({len(pools)} shown, collection {total})", ""]
    if not pools:
        lines.append("No Data Gateway pools found.")
    for pool in pools:
        pdgs = pool.get("pdgUuids") if isinstance(pool.get("pdgUuids"), list) else []
        vips = ", ".join(_pool_vips(pool)) or "-"
        lines.append(
            f"- **{pool.get('name', '?')}** ({pool.get('puuid', '?')}) "
            f"protection={pool.get('protectionStatus') or '?'} "
            f"balanced={pool.get('balanced', '?')} gateway={pool.get('gateway') or '-'} "
            f"pdgs={len(pdgs)} vips={vips}"
        )
    return "\n".join(lines)


def _load_metrics_markdown(duuid: str, entries: list[dict[str, Any]]) -> str:
    lines = [f"# Load metrics for Data Gateway {duuid}", ""]
    if not entries:
        lines.append(f"No load metrics reported for gateway {duuid}.")
    for entry in entries:
        lines.append(
            f"Sample {entry.get('loadMetricsId', '?')} at {epoch_iso(entry.get('timestamp'))} "
            f"(cdgId {entry.get('cdgId', '?')})"
        )
        collectors = entry.get("collectorLoadMetrics") or []
        if not collectors:
            lines.append("- no collector metrics in this sample")
        for c in collectors:
            if not isinstance(c, dict):
                continue
            lines.append(
                f"- {c.get('collectorName', '?')}: loadScore={c.get('loadScore', '?')} "
                f"delayed={c.get('noOfDelayedCadence', '?')} "
                f"skipping={c.get('noOfSkippingCadence', '?')} "
                f"queue={c.get('dispatchQueueSize', '?')}"
            )
        lines.append("")
    return "\n".join(lines).rstrip()


def _outages_markdown(duuid: str, days: int, outages: list[dict[str, Any]]) -> str:
    lines = [f"# Outage history for Data Gateway {duuid} (last {days} days)", ""]
    if not outages:
        lines.append(f"No outages in the last {days} days.")
    for o in outages:
        end = o.get("endTimestamp")
        end_text = "ongoing" if str(end).strip() in ("", "0", "None") else epoch_iso(end)
        line = (
            f"- {o.get('state', '?')} from {epoch_iso(o.get('startTimestamp'))} to {end_text} "
            f"(vdg {o.get('vdgId') or '-'}, pdg {o.get('pdgId') or '-'}, "
            f"id {o.get('outageHistoryUuid', '?')})"
        )
        if o.get("message"):
            line += f": {o['message']}"
        lines.append(line)
    return "\n".join(lines)


def _destination_endpoints(destination: dict[str, Any]) -> str:
    parts: list[str] = []
    for entry in destination.get("connectivity_info") or []:
        if not isinstance(entry, dict):
            continue
        hosts = [
            str(a["inet_addr"])
            for a in entry.get("ipaddrs") or []
            if isinstance(a, dict) and a.get("inet_addr")
        ]
        fqdn = entry.get("fqdn")
        if isinstance(fqdn, dict):
            host = ".".join(p for p in (fqdn.get("host_name"), fqdn.get("domain_name")) if p)
            if host:
                hosts.append(host)
        host_text = ",".join(hosts) or "?"
        port = entry.get("port")
        parts.append(
            f"{_transport_label(entry.get('type'))} {host_text}:{port}"
            if port not in (None, "")
            else f"{_transport_label(entry.get('type'))} {host_text}"
        )
    return "; ".join(parts) or "no endpoints"


def _destinations_markdown(destinations: list[dict[str, Any]], envelope: dict[str, Any]) -> str:
    lines = [
        f"# Data Destinations ({envelope['count']} shown, collection "
        f"{envelope['collection_total'] if envelope['collection_total'] is not None else '?'})",
        "",
    ]
    if not destinations:
        lines.append("No data destinations found.")
    for d in destinations:
        props = d.get("properties") if isinstance(d.get("properties"), dict) else {}
        line = (
            f"- **{d.get('name', '?')}** ({d.get('uuid', '?')}) {_destination_endpoints(d)} "
            f"family={d.get('family') or '?'} encoding={props.get('ENCODING') or '-'}"
        )
        if str(props.get("IS_SYSTEM_DEFINED", "")).lower() == "true":
            line += " (system-defined)"
        lines.append(line)
    if envelope["has_more"]:
        lines.append("")
        lines.append(
            f"The query is capped at {DESTINATIONS_LIMIT} destinations and this listing hit the "
            "cap; the platform may hold more than are shown here."
        )
    return "\n".join(lines)


def _files_markdown(kind: str, files: list[dict[str, Any]], envelope: dict[str, Any]) -> str:
    total = envelope["total"] if envelope["total"] is not None else "unknown"
    lines = [
        f"# Data Gateway {kind} files ({envelope['count']} shown, total {total}; "
        f"page {envelope['page']})",
        "",
    ]
    if not files:
        lines.append(f"No {kind} files on this page.")
    for f in files:
        line = (
            f"- **{f.get('fileName', '?')}** type={f.get('fileType') or '?'} "
            f"collector={f.get('collectorType') or '?'} bundle={f.get('bundleType') or '?'} "
            f"app={f.get('appName') or '-'} modified={epoch_iso(f.get('modifiedTime'))}"
        )
        if f.get("notes"):
            line += f" — {f['notes']}"
        lines.append(line)
    if envelope["has_more"]:
        lines.append("")
        lines.append(f"More available: repeat with page={envelope['next_page']}.")
    return "\n".join(lines)


def _global_parameters(data: Any) -> dict[str, Any]:
    """``{"globalParameters": [{"key", "value": {<typed>}}]}`` -> ``{key: value}``."""
    params: dict[str, Any] = {}
    entries = data.get("globalParameters") if isinstance(data, dict) else None
    for entry in entries or []:
        if isinstance(entry, dict) and isinstance(entry.get("key"), str):
            params[entry["key"]] = flatten_param_value(entry.get("value"))
    return params


def parse_uuid_list(text: str) -> list[str]:
    """Split a comma-separated UUID list, trimming blanks; 1..MAX_MAPPING_DEVICES entries."""
    uuids = [part.strip() for part in text.split(",") if part.strip()]
    if not uuids:
        raise PlatformError(
            "device_uuids is empty: give one or more device UUIDs separated by commas "
            "(from cnc_list_devices)."
        )
    if len(uuids) > MAX_MAPPING_DEVICES:
        raise PlatformError(
            f"Too many devices ({len(uuids)}): map at most {MAX_MAPPING_DEVICES} per call."
        )
    return uuids


async def fetch_gateways(client: ApiClient) -> tuple[list[dict[str, Any]], int | None]:
    """All Data Gateways from ``dg/query`` (no server paging observed) plus ``totalCount``."""
    data = await client.request_json("POST", DG_QUERY_URL, json_body=dg_query_body("gateways"))
    items, _, _ = unwrap(data, "data")
    return [g for g in items if isinstance(g, dict)], _total_count(data)


def _default_vdg_uuid(gateways: list[dict[str, Any]]) -> str:
    """The single gateway's ``vdgUuid``; an error when there is not exactly one candidate."""
    candidates: list[tuple[str, str]] = []
    for g in gateways:
        config = g.get("configData") if isinstance(g.get("configData"), dict) else {}
        vdg = config.get("vdgUuid")
        if isinstance(vdg, str) and vdg:
            candidates.append((str(g.get("name", "?")), vdg))
    if len(candidates) == 1:
        return candidates[0][1]
    if not candidates:
        raise PlatformError(
            "No Data Gateway with a vdgUuid was found, so there is nothing to map devices to. "
            "Check cnc_list_data_gateways."
        )
    listing = "; ".join(f"{name} -> {vdg}" for name, vdg in candidates)
    raise PlatformError(
        f"{len(candidates)} Data Gateways exist, so vdg_uuid must be given explicitly "
        f"(the vdgUuid from cnc_list_data_gateways): {listing}."
    )


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_data_gateways",
        title="List Data Gateways",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_data_gateways(
        name: Annotated[
            str | None,
            Field(
                description=(
                    "Gateway name filter, applied client-side: exact match, case-insensitive, "
                    "'*' is a wildcard (e.g. 'EMBEDDED_DEF_CDG' or '*cdg*')."
                ),
                max_length=200,
            ),
        ] = None,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the Crosswork Data Gateways (the collection engines devices attach to).

        Read-only. A Data Gateway runs the collectors (CLI, SNMP, MDT, gNMI,
        NETCONF, syslog) that give Crosswork reachability, inventory and
        telemetry for a device; nothing is collected from a device until it is
        mapped to one. Single-VM deployments have one embedded gateway
        (``EMBEDDED_DEF_CDG`` in pool ``EMBEDDED_DEF_POOL``) whose only
        component is ``embeddedCollectors``.

        Use this to find gateway ids before the per-gateway tools:
        - ``duuid`` (physical gateway id) is what cnc_get_data_gateway_load_metrics,
          cnc_list_data_gateway_outages and cnc_get_data_gateway_health take;
        - ``configData.vdgUuid`` (virtual gateway id) is what a device's
          ``dg_uuid`` (cnc_get_device) equals and what
          cnc_map_devices_to_data_gateway takes; a device's ``dg_name`` is the
          pool name + '-1' (``EMBEDDED_DEF_POOL-1``);
        - ``configData.poolId`` is the pool ``puuid`` (cnc_list_data_gateway_pools).

        The whole collection comes back in one call (no server paging was
        observed); ``name`` filters it client-side.

        Args:
            name: exact/wildcard name filter (case-insensitive).
            response_format: markdown (one line per gateway — name, duuid, vdg,
                pool, admin/oper state, role, VM profile — plus one sub-line per
                component 'name: state') or json.

        Returns:
            str: Markdown listing, or JSON:
            {"total": int, "count": int, "page": 0, "page_size": int,
             "items": [{"duuid", "name",
                        "configData": {"adminState": "AS_UP"|..., "role",
                                       "poolId", "vdgUuid",
                                       "profile": {"cpu", "memory", "nics"},
                                       "profileType", "interfaces": [...],
                                       "tags", ...},
                        "operationalData": {"operState": "OS_UP"|...,
                                            "operStateDetails": [{"componentName",
                                                                  "state": "CS_UP"|...,
                                                                  "imageTag"}],
                                            "createdTime" (ns), "lastUpdatedTime" (s)}}],
             "has_more": false, "next_page": null, "collection_total": int, ...}
            On failure: "Error: <actionable message>" (400 'unable to unmarshal
            payload to proto' -> the body carried a field dg-manager does not
            know; 500 'NATS request failed' -> malformed request rather than an
            outage).
        """
        try:
            gateways, total = await fetch_gateways(client)
            collection_total = total if total is not None else len(gateways)
            if name is not None and name.strip():
                gateways = [g for g in gateways if name_matches(name, g.get("name"))]
            envelope = page_envelope(
                gateways,
                result_count=len(gateways),
                total_count=collection_total,
                page_size=len(gateways),
                page=0,
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(envelope), settings)
            return finalize(_gateways_markdown(gateways, envelope), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_data_gateway",
        title="Get Data Gateway Details",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_data_gateway(
        duuid: Annotated[
            str | None,
            Field(
                description=(
                    "Physical gateway UUID (duuid) exactly as returned by cnc_list_data_gateways "
                    "(e.g. '3d95eb05-...'). Give either duuid or name, not both."
                ),
                max_length=100,
            ),
        ] = None,
        name: Annotated[
            str | None,
            Field(
                description=(
                    "Exact gateway name, case-insensitive (e.g. 'EMBEDDED_DEF_CDG'). No "
                    "wildcards; use cnc_list_data_gateways to search. Give either duuid or "
                    "name, not both."
                ),
                max_length=200,
            ),
        ] = None,
    ) -> str:
        """Get the full record of one Data Gateway, by duuid or by exact name.

        Read-only. Exactly one of ``duuid`` / ``name`` must be given. Use it to
        read a gateway's ids (``duuid``, ``configData.vdgUuid``,
        ``configData.poolId``), its admin/operational state, VM profile,
        interfaces (``configData.interfaces[].ipAddr[]``) and per-component
        states (``operationalData.operStateDetails``). The gateway collection
        is fetched whole (``dg/query`` has no verified filter grammar beyond
        ``select * from RobotDataGateway``) and matched client-side.

        Returns:
            str: JSON object with every gateway field as dg-manager returns it
            (see cnc_list_data_gateways for the shape; ``createdTime`` is
            epoch nanoseconds and ``lastUpdatedTime`` epoch seconds). "Error:
            ..." when neither or both selectors are given, when no gateway
            matches (verify with cnc_list_data_gateways), or on an API failure.
        """
        try:
            if bool(duuid) == bool(name):
                raise PlatformError("Give exactly one of 'duuid' or 'name'.")
            gateways, _ = await fetch_gateways(client)
            if duuid:
                wanted = duuid.strip()
                field = "duuid"
                found = [g for g in gateways if g.get("duuid") == wanted]
            else:
                wanted = str(name).strip()
                field = "name"
                found = [
                    g
                    for g in gateways
                    if isinstance(g.get("name"), str) and g["name"].lower() == wanted.lower()
                ]
            if not found:
                raise PlatformError(
                    f"No Data Gateway with {field} '{wanted}'. Names must match exactly "
                    "(case-insensitive, no wildcards); find gateways with "
                    "cnc_list_data_gateways."
                )
            return finalize(to_json(found[0]), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_data_gateway_pools",
        title="List Data Gateway Pools",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_data_gateway_pools(
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the Data Gateway HA pools (the groups gateways serve devices from).

        Read-only. Devices are mapped to a *pool's* virtual gateway rather than
        to a physical gateway; a pool lists its physical gateways in
        ``pdgUuids`` (their ``duuid``s) and its virtual IPs in ``ipaddrs``.
        ``protectionStatus`` says whether a standby gateway protects the pool
        (``NOT_PLANNED`` on the embedded single-gateway deployment). A device's
        ``dg_name`` is the pool name + '-1'.

        Sends the verified ``{"criteria": "select * from HAPool"}`` body to
        ``POST /crosswork/dg-manager/v2/hapool/query`` (this endpoint rejects
        the ``filterData`` grammar that ``dg/query`` uses). The whole
        collection comes back in one call.

        Args:
            response_format: markdown (one line per pool: name, puuid,
                protection status, balanced flag, gateway address, number of
                physical gateways, VIPs) or json.

        Returns:
            str: Markdown listing, or JSON:
            {"total": int|null, "count": int, "items": [{"puuid", "name",
             "ipaddrs": [{"gateway", "inetaddrs": [{"inetAf", "inetAddr",
             "mask", "gateway"}]}], "pdgUuids": [duuid, ...],
             "protectionStatus": "NOT_PLANNED"|..., "gateway",
             "balanced": bool}]}
            ``total`` is dg-manager's ``totalCount``. On failure: "Error: ..."
            (400 'unable to unmarshal payload to proto' -> wrong body grammar;
            500 'NATS request failed' -> malformed request).
        """
        try:
            data = await client.request_json(
                "POST", POOL_QUERY_URL, json_body=dg_query_body("pools")
            )
            items, _, _ = unwrap(data, "data")
            pools = [p for p in items if isinstance(p, dict)]
            total = _total_count(data)
            if response_format is ResponseFormat.JSON:
                return finalize(
                    to_json({"total": total, "count": len(pools), "items": pools}), settings
                )
            return finalize(_pools_markdown(pools, total), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_data_gateway_load_metrics",
        title="Get Data Gateway Load Metrics",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_data_gateway_load_metrics(
        duuid: Annotated[
            str,
            Field(
                description=(
                    "Physical gateway UUID (duuid) from cnc_list_data_gateways "
                    "(e.g. '3d95eb05-...')."
                ),
                min_length=1,
                max_length=100,
            ),
        ],
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the per-collector load metrics of one Data Gateway.

        Read-only. Each collector (CLI, SNMP, MDT, gNMI, NETCONF, syslog — the
        embedded gateway reports names like ``CLI-COLLECTOR``) carries a
        ``loadScore`` (higher = busier) and the counters behind it: delayed and
        skipped collection cadences, dispatch queue depth, jobs received,
        failed destinations, heap and container CPU/memory usage. Use it to
        tell whether a gateway is keeping up with its collection jobs; for
        the gateway's overall up/down state use cnc_get_data_gateway
        (``operState``), and for container vitals cnc_get_data_gateway_health
        (not available on embedded gateways).

        Sends ``{"queryParams": [{"field": "DGID", "value": {"valueStr":
        duuid}}]}`` to ``POST /crosswork/dg-manager/v1/device/load-metrics/query``.

        Args:
            duuid: the physical gateway id (``DGID``), not the vdgUuid.
            response_format: markdown (one line per collector: loadScore,
                delayed/skipping cadences, queue size) or json (the whole
                structure with every counter).

        Returns:
            str: Markdown, or JSON exactly as dg-manager returns it:
            {"cdgLoadMetrics": [{"loadMetricsId", "cdgId", "timestamp" (s),
             "collectorLoadMetrics": [{"collectorName", "loadScore",
             "noOfDelayedCadence", "noOfSkippingCadence", "dispatchQueueSize",
             "noOfJobsReceived", "noOfStatusSent", "noOfFailedDestinations",
             "usedGcHeapMemoryKb", "totalGcHeapMemoryKb",
             "usedContainerMemoryMb", "allocatedContainerMemoryMb",
             "containerMemoryPercentage", "containerCpuPercentage", ...}]}]}
            An empty ``cdgLoadMetrics`` (unknown duuid, or no sample yet) is
            reported as "No load metrics", not an error. On failure: "Error:
            ..." (400 'unable to unmarshal payload to proto' -> body rejected;
            500 'NATS request failed' -> malformed request).
        """
        try:
            target = duuid.strip()
            body = {"queryParams": [query_param("DGID", target)]}
            data = await client.request_json("POST", LOAD_METRICS_URL, json_body=body)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(data if data is not None else {}), settings)
            entries, _, _ = unwrap(data, "cdgLoadMetrics")
            entries = [e for e in entries if isinstance(e, dict)]
            return finalize(_load_metrics_markdown(target, entries), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_data_gateway_outages",
        title="List Data Gateway Outages",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_data_gateway_outages(
        duuid: Annotated[
            str,
            Field(
                description=(
                    "Physical gateway UUID (duuid) from cnc_list_data_gateways "
                    "(e.g. '3d95eb05-...')."
                ),
                min_length=1,
                max_length=100,
            ),
        ],
        vdg_uuid: Annotated[
            str,
            Field(
                description=(
                    "Virtual gateway UUID (configData.vdgUuid) to scope the history to; "
                    "leave empty (the default) to query by the physical gateway only."
                ),
                max_length=100,
            ),
        ] = "",
        days: Annotated[
            int, Field(description="How many days back to look (e.g. 14).", ge=1, le=90)
        ] = 14,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the outage history of one Data Gateway over the last N days.

        Read-only. Each record is a state transition of the gateway (``state``
        ``UP``/``DOWN``..., ``startTimestamp``/``endTimestamp`` in epoch
        nanoseconds, ``endTimestamp`` ``"0"`` while ongoing) with the gateway
        ids involved and, when available, a ``vitalsSnapshot`` and ``message``.
        An empty history is the normal answer for a healthy gateway.

        Sends ``{"queryParams": [DGID, VDGID, DAYS]}`` (``DAYS`` as a string,
        ``VDGID`` may be empty) to ``POST
        /crosswork/dg-manager/v1/device/outage-history/query`` — the three
        params are always sent, in that order, as verified live.

        Args:
            duuid: the physical gateway id (``DGID``).
            vdg_uuid: optional virtual gateway id (``VDGID``); empty by default.
            days: look-back window, 1..90 (``DAYS``).
            response_format: markdown (one line per record) or json.

        Returns:
            str: Markdown, or JSON:
            {"duuid": str, "vdg_uuid": str, "days": int, "count": int,
             "items": [{"outageHistoryUuid", "startTimestamp", "endTimestamp",
                        "state", "vdgId", "pdgId", "vitalsSnapshot", "message"}]}
            "No outages in the last N days." when the history is empty. On
            failure: "Error: ..." (400 'unable to unmarshal payload to proto'
            -> body rejected; 500 'NATS request failed' -> malformed request).
        """
        try:
            target = duuid.strip()
            body = {
                "queryParams": [
                    query_param("DGID", target),
                    query_param("VDGID", vdg_uuid.strip()),
                    query_param("DAYS", str(days)),
                ]
            }
            data = await client.request_json("POST", OUTAGE_HISTORY_URL, json_body=body)
            items, _, _ = unwrap(data, "data")
            outages = [o for o in items if isinstance(o, dict)]
            if response_format is ResponseFormat.JSON:
                payload = {
                    "duuid": target,
                    "vdg_uuid": vdg_uuid.strip(),
                    "days": days,
                    "count": len(outages),
                    "items": outages,
                }
                return finalize(to_json(payload), settings)
            return finalize(_outages_markdown(target, days, outages), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_data_gateway_health",
        title="Get Data Gateway Health",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_data_gateway_health(
        duuid: Annotated[
            str,
            Field(
                description=(
                    "Physical gateway UUID (duuid) from cnc_list_data_gateways "
                    "(e.g. '3d95eb05-...')."
                ),
                min_length=1,
                max_length=100,
            ),
        ],
    ) -> str:
        """Get the container vitals (health) of one standalone Data Gateway.

        Read-only. On a standalone (VM) gateway this returns per-container
        CPU, memory, block I/O, network and heap figures for each collector
        with its ``status`` and CPU/memory thresholds. **Embedded gateways do
        not report vitals** (verified live: dg-manager answers ``500 "vitals
        for Data Gateway ID with '<id>' not found"`` for both the duuid and the
        vdgUuid of the embedded gateway); that answer is returned as an
        informational message, not an error — use cnc_get_data_gateway
        (``operState`` and the per-component ``operStateDetails``) and
        cnc_get_data_gateway_load_metrics for embedded gateways instead.

        Sends ``{"queryParams": [{"field": "DGID", "value": {"valueStr":
        duuid}}]}`` to ``POST /crosswork/dg-manager/v1/vitals/query``.

        Returns:
            str: JSON body as dg-manager returns it — the 7.2 document shows
            {"components": [{"name", "status", "cpuUsage", "memPercent",
             "memory": {"baseUnit", "used", "free"}, "blockIOStats",
             "networkStats", "gcHeapInfo", "netIoRate", "thresholdCpu",
             "thresholdMemory", "tag", "containerImage", "error"}]}
            (UNVERIFIED live: no standalone gateway was available). "No health
            vitals are available for gateway ..." for an embedded gateway (or
            an unknown id, which dg-manager reports the same way) — recognised
            only by the verified ``500 "vitals for Data Gateway ID with '...'
            not found"`` body. "Error: ..." on any other API failure, including
            other 500s (e.g. 'NATS request failed ...' means a malformed
            request or a service problem, never "no vitals").
        """
        try:
            target = duuid.strip()
            body = {"queryParams": [query_param("DGID", target)]}
            response = await client.request(
                "POST", VITALS_URL, json_body=body, raise_on_error=False
            )
            if response.status_code == 500 and _is_vitals_not_found(response.text):
                return finalize(
                    f"No health vitals are available for gateway {target}: embedded Data "
                    "Gateways do not report vitals (dg-manager answered 'not found'; an "
                    "unknown duuid reads the same). Use cnc_get_data_gateway (operState and "
                    "operStateDetails) and cnc_get_data_gateway_load_metrics instead.",
                    settings,
                )
            if not response.is_success:
                raise http_error(response)
            if not response.content:
                return finalize(to_json({}), settings)
            try:
                data = response.json()
            except ValueError as e:
                raise PlatformError(
                    "dg-manager returned a non-JSON response where JSON was expected."
                ) from e
            return finalize(to_json(data), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_data_gateway_global_parameters",
        title="Get Data Gateway Global Parameters",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_data_gateway_global_parameters(
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the Data Gateway global parameters (collector ports and limits).

        Read-only. These are deployment-wide collector settings applied to
        every gateway: the SNMP trap port (``SNMP_TRAP_PORT``), syslog
        UDP/TCP/TLS ports, CLI session limits, SSH session timeout, and flags
        such as ``RESYNC_ENGINE_DETAILS``. Use it to learn which port devices
        must send traps/syslog to. Values arrive as typed wrappers
        (``{"uint32Value": 31062}``, ``{"boolValue": false}``) and are
        flattened to plain values here.

        Sends an empty ``{}`` body to ``POST
        /crosswork/dg-manager/v1/command/global-parameter/query`` (verified;
        the document's ``{"data": {}}`` form is rejected).

        Args:
            response_format: markdown ('KEY = value' lines sorted by key) or
                json.

        Returns:
            str: Markdown, or JSON {"parameters": {"SNMP_TRAP_PORT": 31062,
            "RESYNC_ENGINE_DETAILS": false, ...}}. On failure: "Error: ..."
            (400 'unable to unmarshal payload to proto' -> the body carried a
            field the endpoint does not know).
        """
        try:
            data = await client.request_json("POST", GLOBAL_PARAMS_URL, json_body={})
            params = _global_parameters(data)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json({"parameters": params}), settings)
            lines = [f"# Data Gateway global parameters ({len(params)})", ""]
            if not params:
                lines.append("No global parameters reported.")
            for key in sorted(params):
                value = params[key]
                lines.append(f"- {key} = {to_json(value) if isinstance(value, dict) else value}")
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_data_destinations",
        title="List Data Destinations",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_data_destinations(
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the data destinations Data Gateways can stream collected data to.

        Read-only. A destination is a Kafka or gRPC endpoint that collection
        jobs dispatch telemetry/inventory data to. Every deployment has the
        pre-defined internal ``CW_KAFKA_DESTINATION`` (Crosswork's own Kafka,
        ``IS_SYSTEM_DEFINED`` true) that the built-in applications consume
        from; external destinations are added for third-party consumers.
        Use it to find a destination ``uuid`` for collection-job tools and to
        check the encoding (``ENCODING``, e.g. gpbkv/json) and security
        properties an external consumer must match.

        Sends the verified ``{"limit": 100, "filter": {}}`` body to ``POST
        /crosswork/dg-manager/v1/destinations/query``; no offset exists, so
        the listing is capped at 100 destinations. The verified answer is
        ``{"data": [...]}`` with no total count, so ``has_more`` is true when
        the listing came back at the cap (100 items) — or, if the platform
        does report ``total_count``, when that exceeds what was returned.

        Args:
            response_format: markdown (one line per destination: name, uuid,
                transport host:port, family, encoding; a closing note when
                the 100 cap was hit) or json.

        Returns:
            str: Markdown listing, or JSON:
            {"total": int|null, "count": int, "items": [{"uuid", "name",
             "family": "ROBOT_PROVIDER_DESTINATION",
             "connectivity_info": [{"type": "ROBOT_MSVC_TRANS_KAFKA"|"..._GRPC",
                                    "ipaddrs": [{"inet_af", "inet_addr", "mask"}],
                                    "port"}],
             "properties": {"DESTINATION_TYPE", "ENCODING", "IS_SECURITY_ENABLED",
                            "IS_SYSTEM_DEFINED", "DISPATCH_SOURCE", ...}}],
             "has_more": bool, "collection_total": int|null, ...}
            ``total``/``collection_total`` are null on the verified response
            (no count is reported). On failure: "Error: ..." (400 'unable to
            unmarshal payload to proto' -> body rejected; 500 'NATS request
            failed' -> malformed request).
        """
        try:
            body = {"limit": DESTINATIONS_LIMIT, "filter": {}}
            data = await client.request_json("POST", DESTINATIONS_URL, json_body=body)
            items, _, _ = unwrap(data, "data")
            destinations = [d for d in items if isinstance(d, dict)]
            # Verified answer: {"data": [...]} with no total_count. Passing None as the
            # result count makes the envelope fall back to the full-page rule, so a
            # response at the 100-item cap still reports has_more instead of hiding it.
            total = _total_count(data)
            envelope = page_envelope(
                destinations,
                result_count=total,
                total_count=total,
                page_size=DESTINATIONS_LIMIT,
                page=0,
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(envelope), settings)
            return finalize(_destinations_markdown(destinations, envelope), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_data_gateway_files",
        title="List Data Gateway Software Files",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_data_gateway_files(
        kind: Annotated[
            str,
            Field(
                description=(
                    f"Which file store to list, one of: {_FILE_KIND_CHOICES} (e.g. 'system'). "
                    "'system' = the pre-packaged device/MIB packages shipped with Crosswork; "
                    "'custom' = packages an operator uploaded."
                ),
                min_length=1,
                max_length=16,
            ),
        ] = "system",
        page_size: Annotated[
            int, Field(description="Files per page (e.g. 20).", ge=1, le=100)
        ] = 20,
        page: Annotated[int, Field(description="0-based page number (e.g. 0).", ge=0)] = 0,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the Data Gateway software packages (system or custom).

        Read-only. Data Gateways collect with *device packages* (CLI command
        definitions per platform) and *MIB packages* (SNMP). Crosswork ships
        system packages (``bundleType`` ``SYSTEM``) and operators can upload
        custom ones (``kind`` 'custom'). Use it to see which packages are
        loaded, their collector type (``CLI``/``SNMP``) and when they changed;
        uploading and downloading packages is out of scope for this server.

        Pages with the verified ``{"startRow": page*page_size, "endRow":
        page*page_size + page_size}`` body to ``POST
        /crosswork/dg-manager/v1/system-files/query`` or ``POST
        /crosswork/dg-manager/v2/custom-files/query``.

        Args:
            kind: 'system' or 'custom'.
            page_size, page: paging (0-based); ``has_more``/``next_page`` say
                whether another page exists (from ``total_count`` when the
                platform reports it, else from a full page).
            response_format: markdown (one line per file: name, file type,
                collector type, bundle type, app, modified time, notes) or json.

        Returns:
            str: Markdown listing, or JSON:
            {"total": int|null, "count": int, "page": int, "page_size": int,
             "items": [{"fileName", "modifiedTime" (epoch s), "bundleType",
                        "fileType": "DEVICE_PACKAGE"|"MIB_PACKAGE"|...,
                        "collectorType": "CLI"|"SNMP"|..., "notes", "appName",
                        "downloadUrl"}],
             "has_more": bool, "next_page": int|null, ...}
            On failure: "Error: ..." (unknown kind -> the accepted values; 400
            'unable to unmarshal payload to proto' -> body rejected).
        """
        try:
            key = kind.strip().lower()
            if key not in FILE_KINDS:
                raise PlatformError(
                    f"Unknown file kind '{kind}'. Use one of: {_FILE_KIND_CHOICES}."
                )
            start = page * page_size
            body = {"startRow": start, "endRow": start + page_size}
            data = await client.request_json("POST", FILE_KINDS[key], json_body=body)
            items, _, _ = unwrap(data, "data")
            files = [f for f in items if isinstance(f, dict)]
            total = _total_count(data)
            envelope = page_envelope(
                files,
                result_count=total,
                total_count=total,
                page_size=page_size,
                page=page,
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(envelope), settings)
            return finalize(_files_markdown(key, files, envelope), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_map_devices_to_data_gateway",
        title="Map Devices To Data Gateway",
        read_only=False,
        destructive=False,
        idempotent=True,
    )
    async def cnc_map_devices_to_data_gateway(
        device_uuids: Annotated[
            str,
            Field(
                description=(
                    "Comma-separated device UUIDs from cnc_list_devices, 1 to "
                    f"{MAX_MAPPING_DEVICES} (e.g. '0a1b2c3d-...,4e5f6a7b-...')."
                ),
                min_length=1,
                max_length=4000,
            ),
        ],
        operation: Annotated[
            str,
            Field(
                description=(
                    f"Mapping operation, one of: {_MAPPING_CHOICES} (e.g. 'add'). 'add' "
                    "attaches unmapped devices, 'remove' detaches them, 'update' moves "
                    "already-mapped devices to the given gateway. Wire values "
                    "(ADD_OPER/REMOVE_OPER/UPDATE_OPER) are accepted too."
                ),
                min_length=1,
                max_length=16,
            ),
        ] = "add",
        vdg_uuid: Annotated[
            str | None,
            Field(
                description=(
                    "Virtual gateway UUID (configData.vdgUuid from cnc_list_data_gateways, "
                    "e.g. 'ce5c70f5-...'). Omit on a single-gateway deployment: the one "
                    "gateway's vdgUuid is used; required when several gateways exist."
                ),
                max_length=100,
            ),
        ] = None,
    ) -> str:
        """Attach devices to, detach them from, or move them to a Data Gateway.

        WRITE operation — only registered when CNC_MCP_ENABLE_WRITES=true.
        Collection (reachability, inventory, telemetry) only happens once a
        device is mapped to a gateway; a device's current mapping is
        ``dg_uuid``/``dg_name`` in cnc_get_device (``dg_uuid`` equals the
        gateway's ``vdgUuid``, ``dg_name`` is the pool name + '-1').

        Sends ``PUT /crosswork/inventory/v1/dg/devicemapping`` with
        ``{"dgDeviceMappings": [{"cdg_duuid": <vdg_uuid>, "mapping_oper":
        ADD_OPER|REMOVE_OPER|UPDATE_OPER, "device_uuid": [...]}], "user":
        <configured username>}`` — note ``cdg_duuid`` takes the *virtual*
        gateway id, and the enum has no DELETE (that answers 500 NATS). The
        optional ``user`` field is job attribution (``created_by`` in the
        job envelope); it is sent only when CNC_MCP_USERNAME is configured —
        under CNC_MCP_API_TOKEN auth set CNC_MCP_USERNAME too if you want the
        job attributed, otherwise the field is omitted rather than sent empty.
        The answer is an inventory job envelope; a failed mapping is HTTP 200
        with ``state: JOB_FAILED`` and the reason in ``error``, which this
        tool turns into "Error: ...". PUT is idempotent here, so a transport
        failure is retried automatically.

        Verified embedded-gateway behaviour (single-VM deployments): REMOVE
        completes and really unmaps the device (``dg_uuid`` becomes null), but
        the embedded pool re-maps it automatically within ~2 seconds, so a
        removal never sticks; ADD succeeds only while the device is unmapped
        and otherwise fails with the misleading "cannot be performed ...
        because invalid dg ID is requested", which here means "already mapped
        to that gateway"; UPDATE on an already-mapped device fails with
        "source and target ...". Multi-gateway deployments (standalone CDG
        VMs / HA pools), where mappings persist, were not exercised live.
        Always confirm the result with cnc_get_device (``dg_uuid`` /
        ``dg_name``) a few seconds later, not from the job state alone.

        Args:
            device_uuids: comma-separated device UUIDs (1..50).
            operation: add | remove | update (or the wire enum).
            vdg_uuid: the target gateway's vdgUuid; defaults to the single
                gateway's when exactly one exists (dg/query is called to find
                it), and is required otherwise.

        Returns:
            str: JSON job envelope ({"job_id", "state": "JOB_COMPLETED",
            "type", "created_by", "impacted": [...],
            "impacted_objects": [...], ...}). "Error: ..." when the UUID list
            or operation is invalid, when no vdg_uuid was given and the
            deployment has zero or several gateways (the candidates are
            listed), when Crosswork reports the job as failed — the platform
            reason is included: "invalid dg ID" (in practice: the device is
            already mapped to that gateway), "Device with ID ... does not
            exist or is Invalid" (unknown device uuid), "source and target
            ..." (UPDATE with nothing to change) — or on an API failure.
        """
        try:
            uuids = parse_uuid_list(device_uuids)
            oper = wire_enum(MAPPING_OPERATIONS, operation, "mapping operation")
            if vdg_uuid is not None and vdg_uuid.strip():
                target = vdg_uuid.strip()
            else:
                gateways, _ = await fetch_gateways(client)
                target = _default_vdg_uuid(gateways)
            body: dict[str, Any] = {
                "dgDeviceMappings": [
                    {"cdg_duuid": target, "mapping_oper": oper, "device_uuid": uuids}
                ],
            }
            # ``user`` is optional job attribution. Under API_TOKEN auth no username is
            # configured; send the field only when there is a real value rather than "".
            if settings.username:
                body["user"] = settings.username
            result = await client.request_json("PUT", DEVICE_MAPPING_URL, json_body=body)
            envelope = check_job(
                result, f"{oper} of {len(uuids)} device(s) on Data Gateway {target}"
            )
            return finalize(to_json(envelope), settings)
        except Exception as e:
            return format_error(e)
