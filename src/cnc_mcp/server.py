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
from cnc_mcp.prompts import register_prompts
from cnc_mcp.safety import AppContext, safety_mode_lines
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
    lines = [
        "Tools for Cisco Crosswork Network Controller (CNC): device inventory, credential "
        "profiles, providers (SR-PCE, NSO, ...), the topology graph, tags, alarms, users, "
        "installed applications, and inventory jobs.",
        "",
        "Conventions:",
        "- Objects are identified by 'uuid' (devices, providers) or by name (credential "
        "profiles by 'profile', tags by 'name'). List tools return the identifiers; get "
        "tools take exactly one selector.",
        "- Most list tools page with page_size/page (page is 0-based) and return an envelope "
        "{total, count, page, page_size, has_more, next_page, items}. 'total' counts matches "
        "for the filter; 'collection_total' is the size of the whole collection. Tools over "
        "the alarm/event, EMF, CAT service, notification and application-manager APIs "
        "(cnc_list_alarms, cnc_list_events, cnc_list_device_alarms, cnc_list_ems_nodes, "
        "cnc_list_services, cnc_list_notification_subscriptions, cnc_list_app_manager_jobs, "
        "...) take 'limit' instead of page_size — with 'page' where the platform pages "
        "(alarms, events), 'offset' where it is offset-based (EMF, CAT, notifications), or "
        "on its own — the collection-service tools (cnc_list_sensor_templates, "
        "cnc_get_collection_job_summary) page with page_size/page_token and "
        "cnc_list_config_templates with page/size; read each list tool's input schema for "
        "its own paging argument names.",
        "- Filters are exact-match, case-insensitive, and accept '*' as a wildcard "
        "(host_name='PE*'). There is no substring match without '*'.",
        "- response_format='markdown' (default) is a curated summary; 'json' is complete data.",
        "- Arguments are flat and named exactly as each tool's input schema lists them; an "
        "unknown argument name is rejected by name with a closest-match hint (host_names -> "
        "'did you mean host_name?'), never silently ignored.",
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
        "(listed once per direction), SR policies by (headend, endpoint, color) — on the "
        "wire those are TE router-ids (loopbacks); the SR policy read tools accept a host "
        "name or a router-id for headend/endpoint, the RSVP-TE tunnel tools router-ids only. "
        "Pass ids exactly as the list tools print them; the tools handle URL encoding. "
        "Performance metrics exist for IGP links and policies only (keyed reads, no "
        "listing), and the policy PM delay is the PCE's modelled figure unless SR-PM "
        "telemetry is configured. An all-ETHERNET topology means the SR-PCE gRPC feed is "
        "not up. pce-controlled = delegated to the PCE; pcep-flag-c 1 = PCE-initiated, 0 = "
        "configured on the router (PCC-initiated).",
        "- SR-TE operations (cnc_create_sr_policy, cnc_dryrun_sr_policy, ...) go through the "
        "Optimization Engine and the SR-PCE: policies created here are PCE-initiated "
        "(pcep-flag-c 1) and appear on the headend within seconds; PCC-initiated policies "
        "(pcep-flag-c 0) are router configuration and cannot be removed through the PCE. "
        "Head-ends/end-points may be given as hostnames or TE router-ids; explicit hops as "
        "node names. Dry-run before creating; a bare 500 from the engine means an input it "
        "could not resolve.",
        "- Platform administration (cnc_get_cluster_health, cnc_list_microservices, "
        "cnc_list_active_sessions, ...): cluster nodes are keyed by node_id = the node's "
        "management IP; applications by their capp-* id (capp-coe, capp-infra, ...); an "
        "unknown user answers 500 'Invalid Username' (rendered as not found). Crosswork caps "
        "concurrent sessions per user (cnc_get_session_config); this server logs its session "
        "out on exit. A 403 'Unauthorized request' from any tool means the account's role "
        "does not grant the API and method that tool sends: run cnc_check_permissions, which "
        "names the account, its role, the rows to grant and this server's safety mode.",
        "- Alarms: system alarms (Crosswork's own) come from alarms/v1 (cnc_list_alarms, "
        "cnc_search_alarms, cnc_get_alarm, ack/note/clear); the platform ignores server-side "
        "filters and does not page newest-first, so searches and sorting are client-side "
        "(cnc_search_alarms sees every alarm; cnc_list_alarms sorts one page). Crosswork "
        "does not auto-clear old pod-health alarms — an old open alarm with 0 events is "
        "possibly stale: confirm with cnc_get_cluster_health / cnc_list_microservices before "
        "reporting an outage. Acknowledge/annotate notes are permanent; device/network "
        "alarms from the EMF fault manager are a separate list (cnc_list_device_alarms). "
        "Tags are assigned by PATCHing the device (cnc_assign_tags), which briefly flips it "
        "to ROBOT_OPER_STATE_CHECKING; a device lock "
        "(cnc_lock_device) needs the device in ROBOT_OPER_STATE_OK.",
        "- Alarm settings (cnc_set_event_type_severity, cnc_set_event_type_autoclear, "
        "cnc_revert_event_type_autoclear, cnc_update_alarm_manager_settings, "
        "cnc_update_gnmi_alarm_settings, cnc_set_event_type_recommendation, "
        "cnc_update_alarm_suppression_policy) change how EVERY future alarm of an event "
        "type is raised, platform-wide. Severities are lowercase on the wire (critical | "
        "major | minor | warning | information); an auto-clear interval is 5..599940 minutes "
        "in multiples of 5 below 60 and of 60 above; revert DELETES the interval (no default "
        "is restored — read the current value first if it must be put back); the manager / "
        "gNMI switches take one key at a time and echo the stored value; a suppression-policy "
        "update merges over the current policy (the platform needs the full body).",
        "- Device groups (cnc_create_device_group, cnc_set_device_group_members, "
        "cnc_move_group_members, ...): user groups live under the classifier "
        "LocationDevices (tree Location > All Locations > Unassigned Devices; the groups "
        "alarm suppression and PM policies scope on) or DeviceAccess (RBAC); the parent is "
        "resolved by default. Every device sits in exactly one LocationDevices leaf, so "
        "membership is built by MOVING devices out of the leaf that holds them (Unassigned "
        "Devices for a device never placed) — the platform's own 'members' call removes; "
        "cnc_set_device_group_members computes the moves for a wanted list. A dynamic "
        "device-group rule is stored but never evaluated on 7.2.0 (port-group rules are), "
        "and a rule takes one condition. Platform-managed groups are refused with nothing "
        "sent; refusals come back as 'Error: ...' with the platform's code.",
        "- Device configuration (cnc_*_device_backup*, cnc_*_config_template*, "
        "cnc_deploy_config_template): backups and template deployments are asynchronous "
        "jobs — schedule, then use the matching cnc_wait_for_* tool; a deployment changes "
        "the device configuration within seconds and there is no undo (deploy a reverting "
        "template). The EMF inventory (cnc_list_ems_nodes) is a separate view keyed by "
        "FDN ('MD=CISCO_EMS!ND=<name>'); a node must be MANAGED_AND_SYNCHRONIZED there for "
        "config management and device alarms to work.",
        "- Notifications: a webhook subscription (cnc_create_webhook_subscription) needs a "
        "client URL with an explicit port that answers 2xx to Crosswork's probe. An external "
        "Kafka/gRPC subscription (cnc_create_external_subscription) needs a Data Destination "
        "created with dispatch source 'application' (in the UI or the dg-manager API — no "
        "tool here creates one; the system 'datagateway' destinations are refused), named "
        "exactly (case-sensitive); the topic name is the platform-wide key "
        "(cnc_delete_external_subscription takes it). "
        "cnc_clear_notification_subscriptions_by_topic sweeps EVERY user's webhook "
        "subscriptions and WebSocket sessions of one topic — prefer the single delete. LCM "
        "(local congestion mitigation) and Circuit-Style SR are read through cnc_*_lcm_* / "
        "cnc_*_cs_* (the lab has LCM disabled and no CS policies). Collection-service tools "
        "default to the DLM's own CLI collector job.",
        "- Services (Crosswork Active Topology / T-SDN function packs): cnc_list_services and "
        "cnc_get_service_counts read the CAT service inventory (types: policy, odn-template, "
        "cs-sr-te-policy, ietf-l3vpn, ietf-l2vpn, slice-service, tunnel); each service has a "
        "yang-path (its NSO intent, read with cnc_get_service) and a plan (cnc_get_service_plan "
        "/ cnc_wait_for_service_plan: init -> config-apply -> ready). Provisioning goes through "
        "the NSO proxy: cnc_create_odn_template, cnc_create_sr_policy_service (an NSO-configured "
        "head-end policy — distinct from the PCE-initiated cnc_create_sr_policy), "
        "cnc_create_sid_list, cnc_create_l3vpn_service and the generic cnc_provision_service; "
        "every write takes dry_run=true, which returns the exact device CLI NSO would push "
        "without committing — dry-run first. A head-end NSO considers out of sync answers 502 "
        "(run cnc_nso_device_action sync-from, then retry); delete a policy before its SID list; "
        "L3VPN head-ends need a BGP process.",
        "- Performance monitoring (cnc_list_performance_policies, cnc_get_performance_statistics, "
        "cnc_get_performance_top_n, cnc_get_performance_summary): PM policies poll schemas "
        "(CEPMINTERFACE, SRPOLICY, CPU, ...) whose metric names come from "
        "cnc_list_performance_policy_templates; dashboard metrics are named "
        "<SCHEMA>_<metric> (e.g. CEPMINTERFACE_ifInUtilization); pages are 1-based; time "
        "windows are ISO 8601 with milliseconds. NPM analytics (cnc_get_lsp_utilization, "
        "cnc_get_lsp_delay, cnc_get_interface_delay) key LSPs by TE router-ids + color and "
        "interfaces by inventory uuid + name, and answer an empty list for an unknown key "
        "as well as for no data. PM policy writes (cnc_create_performance_policy, "
        "cnc_activate_performance_policy, ...): a created policy is INACTIVE until "
        "activated (activate=true on create, or cnc_activate_performance_policy); "
        "ACTIVATION IS NETWORK-IMPACTING — it starts SNMP/telemetry collection on every "
        "selected device within seconds — so confirm the device selection and cadence "
        "first; deactivate before deleting is not required. Policy ids are integers "
        "(comma-separated for activate / deactivate / delete); cnc_update_performance_policy "
        "never changes the activation state (deactivate -> update -> activate to be sure a "
        "cadence or selection change takes effect). Retention "
        "(cnc_update_performance_retention) is per schema; cnc_reset_performance_retention "
        "resets EVERY table to the defaults.",
        "- OAM trace routes (cnc_start_oam_trace_route, then cnc_wait_for_oam_trace_route) "
        "take the service yang-path plus head-end/tail-end inventory uuids (the tool resolves "
        "names and router-ids itself) and need gNMI onboarded on the devices "
        "(cnc_enable_device_gnmi, after cnc_update_credential_profile adds a gNMI login) plus "
        "'mpls oam' on IOS-XR; a completed trace lists every ECMP path hop by hop, and a "
        "failed one is a verdict, not an API error. "
        "Service Health (probes), Health Insights, Change Automation and Path Analytics "
        "are not installed on single-VM deployments; their prefixes answer the home "
        "application's 404 and the error text names the missing application. SWIM and "
        "ZTP reads (cnc_list_software_images, cnc_list_ztp_*) answer empty on a fresh "
        "deployment. ZTP writes go in the order upload config file "
        "(cnc_upload_ztp_config_file; a Day0-config .txt needs '!! IOS XR' in its first "
        "three lines, pre/post scripts a '#!' first line and a secure profile) -> profile "
        "(cnc_create_ztp_profile) -> serial numbers (cnc_add_ztp_serial_numbers) -> device "
        "(cnc_create_ztp_device: one pre-registered serial, status Unprovisioned), and are "
        "torn down in reverse: an in-use serial cannot be deleted, deleting a referenced "
        "config file flips the profile's / device's isConfigInvalid (the delete tool "
        "guards it). Static routes settle asynchronously (the tools wait). The platform "
        "answers ZTP writes with HTTP 200 and the verdict in the body — the tools read it, "
        "so 'Error: ...' is the platform's refusal. The EMS inventory scheduler jobs "
        "(cnc_list_inventory_scheduler_jobs; "
        "run / suspend / resume by exact, case-sensitive name such as 'Failed Feature "
        "Sync') are the platform's own periodic inventory refreshes — a suspended job "
        "stays suspended until resumed.",
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
        "- Prompts (MCP prompts/list): troubleshoot_device, network_health_check, "
        "explain_sr_policy, provision_l3vpn, alarm_triage and explain_service are playbooks "
        "that say which tools to call (the one-call composite when this build has it, the "
        "individual tools otherwise), how to drill in and how to answer.",
    ]
    lines.extend(safety_mode_lines(settings))  # the prompts' writes_note() shares these
    return "\n".join(lines)


def build_server(settings: Settings | None = None, client: ApiClient | None = None) -> MCPServer:
    """Wire settings, auth, client, and tools into an MCPServer.

    Pass ``client`` to embed the server around a client you own (the live
    smoke runner does, so it can close it — and with it the platform SSO
    session — without running the stdio lifespan). A client built here is
    closed by the lifespan.
    """
    settings = settings or Settings()  # type: ignore[call-arg]  # env supplies base_url
    # Every embedding (server, smoke runner, tests) must keep the TGT out of logs.
    quiet_http_logging()
    owns_client = client is None
    if client is None:
        client = ApiClient(settings, create_auth(settings))
    ctx = AppContext(settings=settings, client=client)

    @asynccontextmanager
    async def lifespan(_server: MCPServer) -> AsyncIterator[AppContext]:
        try:
            yield ctx
        finally:
            if owns_client:
                await client.aclose()

    mcp = MCPServer(SERVER_NAME, instructions=build_instructions(settings), lifespan=lifespan)
    register_all_tools(mcp, ctx)
    register_prompts(mcp, ctx)
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
    logger.info(
        "Starting %s (writes %s, dry-run %s)",
        SERVER_NAME,
        "ON" if settings.enable_writes else "off",
        "ON" if settings.dry_run else "off",
    )
    try:
        server = build_server(settings)
    except PlatformError as e:
        # Auth strategies raise PlatformError for incomplete credentials, and the tool
        # registry for an unknown WRITE_AREAS / DISABLED_TOOLS name — fail fast with a
        # clean message, not a traceback.
        print(f"Configuration error: {e}", file=sys.stderr)
        raise SystemExit(1) from e
    server.run()


if __name__ == "__main__":
    main()
