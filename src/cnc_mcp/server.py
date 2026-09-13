"""Server assembly and entry point.

This is a stdio MCP server: stdout belongs to the protocol, so ALL logging goes
to stderr. Never print() from tool code.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp.server.mcpserver import MCPServer
from pydantic import ValidationError

from cnc_mcp.auth import AuthStrategy, CrossworkCasAuth, StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.config import Settings
from cnc_mcp.errors import PlatformError
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import register_all_tools

SERVER_NAME = "cnc_mcp"

logger = logging.getLogger(__name__)


def create_auth(settings: Settings) -> AuthStrategy:
    """Choose the auth strategy for Crosswork Network Controller.

    - username/password -> CrossworkCasAuth: two-leg CAS SSO (ticket-granting
      ticket -> service ticket), which Crosswork issues as an ~8 h JWT sent as
      ``Authorization: Bearer``. This is the normal configuration.
    - api_token         -> StaticTokenAuth: a JWT obtained elsewhere (e.g. copied
      from a browser session for a one-off). It cannot be refreshed, so expect
      auth failures after it expires.
    """
    if settings.api_token:
        return StaticTokenAuth(settings.api_token)
    prefix = Settings.model_config.get("env_prefix", "")
    if not (settings.username and settings.password):
        raise PlatformError(
            f"Crosswork credentials are required: set {prefix}USERNAME and "
            f"{prefix}PASSWORD (or {prefix}API_TOKEN with a pre-issued JWT)."
        )
    return CrossworkCasAuth(settings.username, settings.password)


def quiet_http_logging() -> None:
    """Keep httpx's per-request INFO lines out of the log.

    httpx logs every request URL at INFO, and the second CAS leg's URL contains
    the ticket-granting ticket (``.../tickets/TGT-...``) — a credential. Cap the
    HTTP client loggers at WARNING regardless of the configured level.
    """
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)


def build_instructions(settings: Settings) -> str:
    """Server-level instructions shown to connecting agents."""
    prefix = Settings.model_config.get("env_prefix", "")
    lines = [
        "Tools for Cisco Crosswork Network Controller (CNC): device inventory, credential "
        "profiles, providers (SR-PCE, NSO, ...), the topology graph, tags, alarms, users, "
        "installed applications, and inventory jobs.",
        "",
        "Conventions:",
        "- Objects are identified by 'uuid' (devices, providers) or by name (credential "
        "profiles by 'profile', tags by 'name'). List tools return the identifiers; get "
        "tools take exactly one selector.",
        "- List tools page with page_size/page (page is 0-based) and return an envelope "
        "{total, count, page, page_size, has_more, next_page, items}. 'total' counts matches "
        "for the filter; 'collection_total' is the size of the whole collection.",
        "- Filters are exact-match, case-insensitive, and accept '*' as a wildcard "
        "(host_name='PE*'). There is no substring match without '*'.",
        "- response_format='markdown' (default) is a curated summary; 'json' is complete data.",
        "- Enum inputs accept friendly values (admin_state='up', family='sr_pce', "
        "protocol='ssh') or the platform's wire values (ROBOT_ADMIN_STATE_UP).",
        "- Writes return the platform's job envelope (job_id, state, impacted_objects). "
        "A write that the platform rejected is reported as 'Error: ...' with the reason; "
        "use cnc_get_inventory_job / cnc_wait_for_inventory_job for long-running jobs.",
        "- Object model: a device (node) references a credential profile and is attached to "
        "a Data Gateway (dg_name) for collection; providers (e.g. an SR-PCE) also reference "
        "a credential profile. Create the credential profile first, then providers, then "
        "devices. The L3 topology (IS-IS links, SR data, SR policies) is learned from an "
        "SR-PCE provider over gRPC — the provider needs both an HTTP and a GRPC endpoint; "
        "L2 links come from device collection (LLDP). A device's te_router_id must match "
        "its router-id in the SR-PCE topology for the two to be correlated.",
        "- Topology and TE state (cnc_*_topology_*, cnc_list_sr_policies, ...) come from the "
        "RESTCONF topology NBI: nodes are keyed by node-id (= host_name), links by the "
        "verbatim link-id '<src> : <srcIf> : <dst> : <dstIf> : <ISIS_IPV4_L2|ETHERNET>' "
        "(listed once per direction), SR policies by (headend, endpoint, color) where "
        "headend/endpoint are TE router-ids (loopbacks), not hostnames. Pass ids exactly as "
        "the list tools print them; the tools handle URL encoding. Performance metrics "
        "exist for IGP links and policies only (keyed reads, no listing). An all-ETHERNET "
        "topology means the SR-PCE gRPC feed is not up.",
        "- SR-TE operations (cnc_create_sr_policy, cnc_dryrun_sr_policy, ...) go through the "
        "Optimization Engine and the SR-PCE: policies created here are PCE-initiated "
        "(pcep-flag-c 1) and appear on the headend within seconds; PCC-initiated policies "
        "(pcep-flag-c 0) are router configuration and cannot be removed through the PCE. "
        "Head-ends/end-points may be given as hostnames or TE router-ids; explicit hops as "
        "node names. Dry-run before creating; a bare 500 from the engine means an input it "
        "could not resolve.",
        "- Data Gateways (collection engines): a device's dg_uuid is the gateway's "
        "configData.vdgUuid (virtual DG id), not its duuid or the pool's puuid; dg_name is "
        "the pool name plus '-1'. Single-VM deployments have one embedded gateway "
        "(EMBEDDED_DEF_CDG in pool EMBEDDED_DEF_POOL) that maps devices automatically, "
        "reports no health vitals, and serves no OAM ping/traceroute.",
        "- NSO: devices are associated with the NSO provider per the DLM->NSO policy; a "
        "device's nso_state (SYNCED, CONNECT_FAILED, *_STARTED, ...) is Crosswork's view, "
        "while cnc_list_nso_devices shows NSO's own view (NED, oper-state). NSO device "
        "actions are asynchronous: they answer JOB_ACCEPTED and nso_state settles a few "
        "seconds later — use cnc_wait_for_device_nso_state with the after_timestamp the "
        "action returned. cnc_nso_sync_to_device overwrites device configuration; run "
        "compare-config first.",
        "- Newly added devices show reachability 'CONN_STATE_UNKNOWN' / operational "
        "'ROBOT_OPER_STATE_CHECKING' for a minute or two; cnc_wait_for_device_reachable "
        "waits for the check to finish.",
    ]
    if settings.enable_writes:
        lines.append(
            "Write tools are ENABLED and modify the live platform. Confirm intent "
            "before creating, changing, or deleting anything."
        )
    else:
        lines.append(
            "This server is READ-ONLY: write tools are not registered. To enable "
            f"them, set the {prefix}ENABLE_WRITES=true environment variable and restart."
        )
    return "\n".join(lines)


def build_server(settings: Settings | None = None) -> MCPServer:
    """Wire settings, auth, client, and tools into an MCPServer."""
    settings = settings or Settings()  # type: ignore[call-arg]  # env supplies base_url
    # Every embedding (server, smoke runner, tests) must keep the TGT out of logs.
    quiet_http_logging()
    auth = create_auth(settings)
    client = ApiClient(settings, auth)
    ctx = AppContext(settings=settings, client=client)

    @asynccontextmanager
    async def lifespan(_server: MCPServer) -> AsyncIterator[AppContext]:
        try:
            yield ctx
        finally:
            await client.aclose()

    mcp = MCPServer(SERVER_NAME, instructions=build_instructions(settings), lifespan=lifespan)
    register_all_tools(mcp, ctx)
    return mcp


def main() -> None:
    """Console entry point (stdio transport)."""
    try:
        settings = Settings()  # type: ignore[call-arg]  # env supplies base_url
    except ValidationError as e:
        missing = ", ".join(str(err["loc"][0]).upper() for err in e.errors())
        prefix = Settings.model_config.get("env_prefix", "")
        print(
            f"Configuration error — check environment variables ({prefix}{missing}).\n{e}",
            file=sys.stderr,
        )
        raise SystemExit(1) from e

    logging.basicConfig(
        stream=sys.stderr,
        level=settings.log_level.upper(),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    quiet_http_logging()
    logger.info("Starting %s (writes %s)", SERVER_NAME, "ON" if settings.enable_writes else "off")
    try:
        server = build_server(settings)
    except PlatformError as e:
        # Auth strategies raise PlatformError for incomplete credentials — fail fast
        # with a clean message, not a traceback.
        print(f"Configuration error: {e}", file=sys.stderr)
        raise SystemExit(1) from e
    server.run()


if __name__ == "__main__":
    main()
