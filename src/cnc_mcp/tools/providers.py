"""Provider tools — SR-PCE, NSO, WAE and the other external systems CNC talks to.

Providers live in the Crosswork inventory service. Everything below follows the
behaviour verified live (see ``crosswork.py`` and the platform notes):

- read with ``POST /crosswork/inventory/v1/providers/query`` and a
  ``filter``/``filterData`` body (paging is ``PageSize``/``PageNum``; a
  top-level ``offset`` is silently ignored by Crosswork);
- the query envelope is ``{"data": [...], "total_count", "result_count"}``,
  with a bare ``{}`` when nothing matched;
- only ``name`` and ``family`` are verified filter fields on this endpoint
  (unknown fields are silently ignored and the whole collection comes back),
  so a lookup by ``uuid`` sends no filter and matches client-side;
- every write (``POST``/``PATCH``/``DELETE`` on the collection URL, body keyed
  ``providers``) answers with a job envelope, and a failed write is HTTP 200
  with ``state != JOB_COMPLETED`` — every write goes through ``check_job``.
- XTC is Crosswork's wire name for the SR-PCE provider family: a provider
  written as ``ROBOT_PROVIDER_SR_PCE`` reads back ``family:
  ROBOT_PROVIDER_XTC``, and a ``family: ROBOT_PROVIDER_SR_PCE`` filter on
  ``providers/query`` matches that provider (both verified live 2026-09-14).
  Markdown renders the family as ``sr_pce``; JSON keeps the wire value.
"""

from __future__ import annotations

import ipaddress
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.crosswork import (
    INVENTORY,
    PROVIDER_FAMILIES,
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
from cnc_mcp.safety import AppContext, register_tool

PROVIDERS_URL = f"{INVENTORY}/providers"
PROVIDERS_QUERY_URL = f"{PROVIDERS_URL}/query"

# Page size used when resolving a single provider: the collection is small
# (a handful of providers per deployment) so one page normally holds it all.
_LOOKUP_PAGE_SIZE = 100
_LOOKUP_MAX_PAGES = 20

# Filter fields verified live on providers/query. ``uuid`` is NOT one of them
# (Crosswork silently ignores unknown fields), so a uuid lookup sends no
# filter at all and relies on the client-side match.
_QUERY_FILTER_FIELDS = frozenset({"name", "family"})

# XTC is Crosswork's wire name for the SR-PCE family (verified live 2026-09-14): the
# provider is WRITTEN as ROBOT_PROVIDER_SR_PCE and READS BACK as ROBOT_PROVIDER_XTC.
# Rendering maps the read value to the friendly 'sr_pce'; JSON keeps the wire value.
SR_PCE_WIRE = PROVIDER_FAMILIES["sr_pce"]
XTC_WIRE = "ROBOT_PROVIDER_XTC"
_XTC_ALIASES = frozenset({"xtc", XTC_WIRE.lower()})

_FAMILY_LABELS = {wire: friendly for friendly, wire in PROVIDER_FAMILIES.items()}
_FAMILY_LABELS[XTC_WIRE] = "sr_pce"
_REACH_LABELS = {wire: friendly for friendly, wire in REACHABILITY_STATES.items()}
_TRANSPORT_LABELS = {wire: friendly for friendly, wire in TRANSPORTS.items()}

_FAMILY_CHOICES = ", ".join(sorted(PROVIDER_FAMILIES))
_TRANSPORT_CHOICES = ", ".join(sorted(TRANSPORTS))


def family_filter(value: str | None) -> str | None:
    """Friendly / wire family -> the ``providers/query`` filter value.

    Like :func:`wire_enum`, plus the read-side alias of the SR-PCE family:
    ``xtc`` / ``ROBOT_PROVIDER_XTC`` (what the provider record shows) is sent
    as ``ROBOT_PROVIDER_SR_PCE`` — the filter value verified live to match the
    provider whose record reads ``ROBOT_PROVIDER_XTC``.
    """
    if value is not None and value.strip().lower() in _XTC_ALIASES:
        return SR_PCE_WIRE
    return wire_enum(PROVIDER_FAMILIES, value, "provider family")


def _label(table: dict[str, str], wire: Any) -> str:
    """Friendly label for a wire enum value; unknown values pass through as-is."""
    if not isinstance(wire, str) or not wire:
        return "?"
    return table.get(wire, wire)


def _endpoint(entry: dict[str, Any]) -> str:
    """Render one connectivity_info entry as ``<protocol> <host>:<port>``."""
    proto = _label(_TRANSPORT_LABELS, entry.get("type"))
    hosts: list[str] = []
    for addr in entry.get("ipaddrs") or []:
        if isinstance(addr, dict) and addr.get("inet_addr"):
            hosts.append(str(addr["inet_addr"]))
    fqdn = entry.get("fqdn")
    if isinstance(fqdn, dict):
        host = ".".join(p for p in (fqdn.get("host_name"), fqdn.get("domain_name")) if p)
        if host:
            hosts.append(host)
    host_text = ",".join(hosts) or "?"
    port = entry.get("port")
    return f"{proto} {host_text}:{port}" if port not in (None, "") else f"{proto} {host_text}"


def _endpoints(provider: dict[str, Any]) -> str:
    entries = [e for e in provider.get("connectivity_info") or [] if isinstance(e, dict)]
    return "; ".join(_endpoint(e) for e in entries) or "no endpoints"


def _providers_markdown(providers: list[dict[str, Any]], envelope: dict[str, Any]) -> str:
    total = envelope["total"] if envelope["total"] is not None else "unknown"
    lines = [
        f"# Providers ({envelope['count']} shown, matching {total}, "
        f"collection {envelope['collection_total']}; page {envelope['page']})",
        "",
    ]
    if not providers:
        lines.append("No providers matched.")
    for p in providers:
        lines.append(
            f"- **{p.get('name', '?')}** ({p.get('uuid', '?')}) "
            f"family={_label(_FAMILY_LABELS, p.get('family'))} "
            f"reachability={_label(_REACH_LABELS, p.get('reachability_state'))} "
            f"endpoints=[{_endpoints(p)}] "
            f"profile={p.get('profile') or '-'}"
        )
    if envelope["has_more"]:
        lines.append("")
        lines.append(f"More available: repeat with page={envelope['next_page']}.")
    return "\n".join(lines)


def parse_properties(text: str | None) -> dict[str, str]:
    """Parse ``key=value,key2=value2`` into a string->string map.

    Values are always sent as strings (Crosswork's provider ``properties`` is a
    string map). Whitespace around keys/values is trimmed; empty pairs are
    skipped. A value may contain ``=`` (split happens on the first one) but not
    ``,``.
    """
    props: dict[str, str] = {}
    if text is None or not text.strip():
        return props
    for raw in text.split(","):
        pair = raw.strip()
        if not pair:
            continue
        if "=" not in pair:
            raise PlatformError(
                f"Invalid properties entry '{pair}': expected key=value pairs separated by "
                "commas, e.g. 'auto-onboard=false,device-profile=cml-xrd'."
            )
        key, value = pair.split("=", 1)
        key = key.strip()
        if not key:
            raise PlatformError(f"Invalid properties entry '{pair}': the key is empty.")
        props[key] = value.strip()
    return props


def _validate_ip(address: str) -> str:
    try:
        return str(ipaddress.ip_address(address.strip()))
    except ValueError as e:
        raise PlatformError(
            f"'{address}' is not a valid IP address. Providers are created by IP "
            "(SR-PCE requires one); FQDN-based providers are not supported by this tool."
        ) from e


def _match(provider: dict[str, Any], field: str, value: str) -> bool:
    got = provider.get(field)
    return isinstance(got, str) and got.lower() == value.lower()


async def _find_provider(client: Any, field: str, value: str) -> dict[str, Any] | None:
    """Resolve one provider by exact ``uuid`` or ``name``.

    A ``name`` lookup sends the filter to Crosswork; a ``uuid`` lookup sends
    no filter because ``uuid`` is not a verified filter field on this endpoint
    (unknown fields are silently ignored and the whole collection comes back
    anyway). Either way the match is re-checked client-side — a wildcard in
    ``value`` would match several. Pages through the (small) collection until
    the provider is found, deciding whether another page exists the same way
    ``page_envelope`` does: from ``result_count`` when Crosswork returns it,
    else from whether the page came back full.
    """
    filters = {field: value} if field in _QUERY_FILTER_FIELDS else {}
    for page in range(_LOOKUP_MAX_PAGES):
        body = query_body(filters, page_size=_LOOKUP_PAGE_SIZE, page=page)
        data = await client.request_json("POST", PROVIDERS_QUERY_URL, json_body=body)
        items, result_count, total_count = unwrap(data, "data")
        for item in items:
            if isinstance(item, dict) and _match(item, field, value):
                return item
        if not items:
            return None
        envelope = page_envelope(
            items,
            result_count=result_count,
            total_count=total_count,
            page_size=_LOOKUP_PAGE_SIZE,
            page=page,
        )
        if not envelope["has_more"]:
            return None
    return None


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_providers",
        title="List Providers",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_providers(
        name: Annotated[
            str | None,
            Field(
                description=(
                    "Provider name filter: exact match, case-insensitive, '*' is a wildcard "
                    "(e.g. 'cml-pce' or '*pce*'). No substring match without '*'."
                ),
                max_length=200,
            ),
        ] = None,
        family: Annotated[
            str | None,
            Field(
                description=(
                    f"Provider family filter, one of: {_FAMILY_CHOICES} (e.g. 'sr_pce'); "
                    "wire values such as 'ROBOT_PROVIDER_SR_PCE' are accepted too, and so is "
                    "'ROBOT_PROVIDER_XTC' (XTC is Crosswork's wire name for the SR-PCE "
                    "family, which is what an SR-PCE provider's record shows)."
                ),
                max_length=64,
            ),
        ] = None,
        page_size: Annotated[
            int, Field(description="Providers per page (e.g. 20).", ge=1, le=500)
        ] = 20,
        page: Annotated[int, Field(description="0-based page number (e.g. 0).", ge=0)] = 0,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the providers configured in Crosswork (SR-PCE, NSO, WAE, ...).

        Read-only. Providers are the external systems CNC integrates with; the
        SR-PCE provider is what feeds the L3/SR-TE topology (via BGP-LS), and
        the NSO provider is used for service provisioning. Use this to discover
        provider UUIDs and check their reachability before touching devices,
        topology, or services; use cnc_get_provider for the full record.

        Filters AND together. Only ``name`` and ``family`` are supported
        filters on this endpoint. Page with ``page``/``page_size`` (0-based).

        XTC is Crosswork's wire name for the SR-PCE provider family: the
        SR-PCE provider's record reads ``family: ROBOT_PROVIDER_XTC`` although
        it is created as ``ROBOT_PROVIDER_SR_PCE``. Markdown shows that family
        as ``sr_pce``; JSON keeps the wire value ``ROBOT_PROVIDER_XTC``. A
        ``family`` filter of 'sr_pce' / 'ROBOT_PROVIDER_SR_PCE' / 'xtc' /
        'ROBOT_PROVIDER_XTC' all select it (the filter is sent as
        ``ROBOT_PROVIDER_SR_PCE``, verified live 2026-09-14 to match the
        provider that reads back XTC).

        Args:
            name: exact/wildcard name filter (case-insensitive).
            family: friendly family name (sr_pce, nso, wae, syslog_storage,
                alert, proxy, onc, accedian_proxy) or wire value (the XTC
                alias of sr_pce included).
            page_size, page: paging; ``has_more``/``next_page`` say whether to
                fetch another page.
            response_format: markdown (one line per provider: name, uuid,
                family, reachability, endpoints, credential profile) or json.

        Returns:
            str: Markdown listing (family rendered friendly: nso, sr_pce, ...),
            or JSON:
            {"total": int|null, "count": int, "page": int, "page_size": int,
             "items": [{"uuid", "name", "family" (wire value, e.g.
                        "ROBOT_PROVIDER_NSO" / "ROBOT_PROVIDER_XTC" for SR-PCE),
                        "profile", "reachability_state",
                        "connectivity_info": [...], "properties": {...}, ...}],
             "has_more": bool, "next_page": int|null,
             "collection_total": int|null, "offset": int, "next_offset": int|null}
            ``total`` is the number of providers matching the filter (absent /
            null when Crosswork omits it, which it does for zero matches);
            ``collection_total`` is the size of the whole provider collection.
            On failure: "Error: <actionable message>" (unknown family value ->
            the list of accepted values; 500 "NATS request failed" -> malformed
            request rather than an outage).
        """
        try:
            filters = {"name": name, "family": family_filter(family)}
            body = query_body(filters, page_size=page_size, page=page)
            data = await client.request_json("POST", PROVIDERS_QUERY_URL, json_body=body)
            items, result_count, total_count = unwrap(data, "data")
            envelope = page_envelope(
                items,
                result_count=result_count,
                total_count=total_count,
                page_size=page_size,
                page=page,
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(envelope), settings)
            return finalize(_providers_markdown(items, envelope), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_provider",
        title="Get Provider Details",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_provider(
        uuid: Annotated[
            str | None,
            Field(
                description=(
                    "Provider UUID, exactly as returned by cnc_list_providers "
                    "(e.g. '4f1c2d3e-...'). Give either uuid or name, not both."
                ),
                max_length=100,
            ),
        ] = None,
        name: Annotated[
            str | None,
            Field(
                description=(
                    "Exact provider name, case-insensitive (e.g. 'cml-pce'). No wildcards; "
                    "use cnc_list_providers to search. Give either uuid or name, not both."
                ),
                max_length=200,
            ),
        ] = None,
    ) -> str:
        """Get the full record of one provider, by UUID or by exact name.

        Read-only. Exactly one of ``uuid`` / ``name`` must be given. Use it to
        inspect a provider's endpoints (``connectivity_info``), credential
        profile (``profile``), family, reachability and ``properties`` (for
        SR-PCE: auto-onboard, outgoing-interface, device-profile,
        preferred-stack) — for example before cnc_update_provider or
        cnc_delete_provider. A uuid lookup scans the (small) provider
        collection and matches client-side, since ``uuid`` is not a verified
        filter field on providers/query.

        Returns:
            str: JSON object with every provider field as Crosswork returns it
            (note ``connectivity_info[].ipaddrs[].inet_af`` reads as
            'ROBOT_INET_ADDR_TYPE_v4'; write bodies use 0 — don't round-trip a
            read object into a write). ``family`` is the wire value: the
            SR-PCE provider reads ``"ROBOT_PROVIDER_XTC"`` — XTC is
            Crosswork's wire name for the SR-PCE family (it is created as
            ``ROBOT_PROVIDER_SR_PCE``; cnc_list_providers' markdown shows it
            as ``sr_pce``). "Error: ..." when neither or both selectors are
            given, when no provider matches (verify with cnc_list_providers),
            or on an API failure.
        """
        try:
            if bool(uuid) == bool(name):
                raise PlatformError("Give exactly one of 'uuid' or 'name'.")
            field, value = ("uuid", uuid) if uuid else ("name", name)
            provider = await _find_provider(client, field, str(value).strip())
            if provider is None:
                raise PlatformError(
                    f"No provider with {field} '{value}'. Names must match exactly "
                    "(case-insensitive, no wildcards); find providers with cnc_list_providers."
                )
            return finalize(to_json(provider), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_create_provider",
        title="Create Provider",
        read_only=False,
        destructive=False,
        idempotent=False,
    )
    async def cnc_create_provider(
        name: Annotated[
            str,
            Field(
                description="Name for the new provider (e.g. 'cml-pce').",
                min_length=1,
                max_length=200,
            ),
        ],
        family: Annotated[
            str,
            Field(
                description=(
                    f"Provider family, one of: {_FAMILY_CHOICES} (e.g. 'sr_pce'). "
                    "Wire values (e.g. 'ROBOT_PROVIDER_SR_PCE') are accepted too."
                ),
                min_length=1,
                max_length=64,
            ),
        ],
        credential_profile: Annotated[
            str,
            Field(
                description=(
                    "Name of an existing credential profile whose credentials CNC will use "
                    "to log in to the provider (e.g. 'cml-xrd')."
                ),
                min_length=1,
                max_length=200,
            ),
        ],
        ip_address: Annotated[
            str,
            Field(
                description="IPv4/IPv6 address of the provider (e.g. '198.18.140.15').",
                min_length=1,
                max_length=64,
            ),
        ],
        protocol: Annotated[
            str,
            Field(
                description=(
                    f"Connectivity protocol, one of: {_TRANSPORT_CHOICES} (e.g. 'http'). "
                    "SR-PCE uses http on its northbound API port."
                ),
                min_length=1,
                max_length=32,
            ),
        ] = "http",
        port: Annotated[
            int,
            Field(description="TCP port of the provider endpoint (e.g. 8080).", ge=1, le=65535),
        ] = 8080,
        timeout_seconds: Annotated[
            int | None,
            Field(
                description="Connection timeout in seconds (e.g. 120). Omit for the "
                "platform default.",
                ge=1,
                le=3600,
            ),
        ] = None,
        properties: Annotated[
            str | None,
            Field(
                description=(
                    "Provider properties as comma-separated key=value pairs, sent as strings "
                    "(e.g. 'auto-onboard=false,outgoing-interface=GigabitEthernet0/0/0/0'). "
                    "SR-PCE keys: auto-onboard, outgoing-interface, device-profile, "
                    "preferred-stack."
                ),
                max_length=2000,
            ),
        ] = None,
    ) -> str:
        """Create a provider (SR-PCE, NSO, WAE, ...) in the Crosswork inventory.

        WRITE operation — only registered when CNC_MCP_ENABLE_WRITES=true. The
        POST is not auto-retried, so a lost response cannot create duplicates;
        check with cnc_list_providers before re-running.

        The credential profile must already exist (see the credentials tools):
        CNC uses that profile's user/password of the matching type (HTTP user
        for an http provider) to log in. The provider is created with
        reachability 'unknown' and only flips to 'reachable' after its first
        check; an unreachable target tends to stay 'unknown' rather than become
        'unreachable' quickly.

        SR-PCE specifics: the provider must point at the router's northbound
        API — TCP 8080, HTTP basic auth against the ``pce / api / user``
        configured on the router — so pass protocol 'http', port 8080 and a
        credential profile with an HTTP user/password. Without an SR-PCE
        provider the inventory fills but the topology map stays empty (CNC's
        L3 topology arrives from SR-PCE via BGP-LS). Do NOT set
        ``auto-onboard`` unless the devices' TE router-IDs (loopbacks) are
        routable from CNC: auto-onboard creates inventory devices keyed on the
        TE router-ID, which then sit Unreachable. Only the sr_pce wire value
        was verified live; the other families use the same
        ``ROBOT_PROVIDER_<FAMILY>`` pattern as the UI shows them. An SR-PCE
        provider is written as ``ROBOT_PROVIDER_SR_PCE`` and reads back as
        ``ROBOT_PROVIDER_XTC`` (XTC is Crosswork's wire name for the SR-PCE
        family) — that is the same provider, not a family change.

        Args:
            name, family, credential_profile, ip_address: required.
            protocol / port / timeout_seconds: the single connectivity entry.
            properties: 'k=v,k2=v2' string map (values sent as strings).

        Returns:
            str: JSON job envelope from Crosswork, e.g.
            {"job_id": str, "state": "JOB_COMPLETED",
             "type": "1 provider(s) added successfully",
             "impacted": ["<uuid> <name>"],
             "impacted_objects": [{"uuid": str, "name": str}], ...}
            — the new provider's UUID is ``impacted_objects[0].uuid``.
            "Error: ..." when validation fails (unknown family/protocol, bad
            IP, malformed properties), when Crosswork reports the job as
            failed (HTTP 200 with state != JOB_COMPLETED; the reason is
            included — e.g. a duplicate name or a missing credential profile),
            or on an API failure.
        """
        try:
            family_wire = wire_enum(PROVIDER_FAMILIES, family, "provider family")
            transport = wire_enum(TRANSPORTS, protocol, "protocol")
            conn: dict[str, Any] = {
                "ipaddrs": [ipaddr(_validate_ip(ip_address))],
                "type": transport,
                "port": port,
            }
            if timeout_seconds is not None:
                # Integer on the wire: the verified nodes body sends "timeout": 0.
                conn["timeout"] = timeout_seconds
            provider = {
                "name": name.strip(),
                "profile": credential_profile.strip(),
                "family": family_wire,
                "connectivity_info": [conn],
                "properties": parse_properties(properties),
            }
            result = await client.request_json(
                "POST", PROVIDERS_URL, json_body={"providers": [provider]}
            )
            envelope = check_job(result, f"Create provider '{provider['name']}'")
            return finalize(to_json(envelope), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_update_provider",
        title="Update Provider",
        read_only=False,
        destructive=False,
        idempotent=True,
    )
    async def cnc_update_provider(
        uuid: Annotated[
            str,
            Field(
                description="UUID of the provider to update (from cnc_list_providers).",
                min_length=1,
                max_length=100,
            ),
        ],
        name: Annotated[
            str | None,
            Field(description="New provider name (e.g. 'cml-pce-2').", max_length=200),
        ] = None,
        credential_profile: Annotated[
            str | None,
            Field(
                description="Name of the existing credential profile to switch to "
                "(e.g. 'cml-xrd').",
                max_length=200,
            ),
        ] = None,
        properties: Annotated[
            str | None,
            Field(
                description=(
                    "Provider properties as comma-separated key=value pairs, sent as strings "
                    "(e.g. 'auto-onboard=false,device-profile=cml-xrd'). Pass the complete "
                    "set you want on the provider."
                ),
                max_length=2000,
            ),
        ] = None,
    ) -> str:
        """Partially update a provider: rename it, change its credential profile,
        and/or set its properties.

        WRITE operation — only registered when CNC_MCP_ENABLE_WRITES=true.
        Sends a PATCH with only the fields given (at least one is required);
        other fields are left untouched. Endpoints (connectivity_info) cannot
        be changed with this tool — delete and re-create the provider instead.
        Whether Crosswork merges or replaces the ``properties`` map on PATCH
        was not verified: pass the complete set you want and confirm with
        cnc_get_provider afterwards.

        Returns:
            str: JSON job envelope ({"job_id", "state": "JOB_COMPLETED",
            "type", "impacted": ["<uuid> <name>"], "impacted_objects": [...]}).
            "Error: ..." when no change was requested, properties are
            malformed, Crosswork reports the job as failed (HTTP 200 with
            state != JOB_COMPLETED, e.g. unknown UUID or missing credential
            profile — the reason is included), or on an API failure.
        """
        try:
            patch: dict[str, Any] = {"uuid": uuid.strip()}
            if name is not None and name.strip():
                patch["name"] = name.strip()
            if credential_profile is not None and credential_profile.strip():
                patch["profile"] = credential_profile.strip()
            if properties is not None:
                patch["properties"] = parse_properties(properties)
            if len(patch) == 1:
                raise PlatformError(
                    "Nothing to update: give at least one of name, credential_profile, properties."
                )
            result = await client.request_json(
                "PATCH", PROVIDERS_URL, json_body={"providers": [patch]}
            )
            envelope = check_job(result, f"Update provider {patch['uuid']}")
            return finalize(to_json(envelope), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_provider",
        title="Delete Provider",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_provider(
        uuid: Annotated[
            str,
            Field(
                description="UUID of the provider to delete (from cnc_list_providers).",
                min_length=1,
                max_length=100,
            ),
        ],
    ) -> str:
        """Permanently delete a provider from the Crosswork inventory.

        DESTRUCTIVE write — only registered when CNC_MCP_ENABLE_WRITES=true.
        Verify the target with cnc_get_provider first. Deleting the SR-PCE
        provider removes the BGP-LS-sourced L3/SR-TE topology from CNC; the
        NSO provider is what service provisioning depends on, so do not delete
        it while devices/services are attached to it.

        Returns:
            str: JSON job envelope ({"job_id", "state": "JOB_COMPLETED",
            "type": "1 provider(s) deleted successfully",
            "impacted": ["<uuid> <name>"], "impacted_objects": [...]}).
            "Error: ..." when Crosswork reports the job as failed (HTTP 200
            with state != JOB_COMPLETED — e.g. the UUID does not exist or the
            provider is still in use; the reason is included) or on an API
            failure.
        """
        try:
            target = uuid.strip()
            result = await client.request_json(
                "DELETE", PROVIDERS_URL, json_body={"providers": [{"uuid": target}]}
            )
            envelope = check_job(result, f"Delete provider {target}")
            return finalize(to_json(envelope), settings)
        except Exception as e:
            return format_error(e)
