# cnc-mcp

[![CI](https://github.com/dr-stutters/cnc-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/dr-stutters/cnc-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An [MCP](https://modelcontextprotocol.io) server that lets an AI agent operate
**Cisco Crosswork Network Controller (CNC)** — the SDN controller for Cisco
service-provider networks — through its REST APIs.

With this server connected, an agent can answer questions like *"which
devices are unreachable?"*, *"what does the topology look like?"*, *"which SR
policies are down and what path do they take?"*, *"is the
Data Gateway collecting?"*, *"is PE1 in sync with NSO?"*, *"is the network ready for
SRv6?"*, and, when writes are enabled, onboard devices, manage credential profiles and providers, map
devices to gateways, drive NSO sync and connect actions, provision SR-TE
policies through the SR-PCE, provision ODN templates, SR-TE policies and
L3VPNs — over SR-MPLS or SRv6 — through NSO's T-SDN function packs (dry-run
first), subscribe webhooks
and external Kafka/gRPC feeds to alarm/inventory events, inspect collection
jobs, manage device groups and their membership, the LCM / Circuit-Style
managers, create and activate performance-monitoring policies and read the
dashboards and NPM analytics, tune alarm settings (event-type severity,
auto-clear, alarm-manager switches), run OAM trace routes, read SWIM state
and manage the ZTP catalogue (config files, profiles, serial numbers, static
routes, devices) — all through typed, documented tools with the platform's
own error reasons surfaced verbatim.

**285 tools** (187 read, 98 write) over 24 API areas plus seven MCP prompts. Every tool was built from
behaviour verified against a live CNC 7.2 instance, not from the documentation
alone — see [How it was verified](#how-it-was-verified).

## Contents

- [Quickstart](#quickstart)
- [Tools](#tools) · [SRv6](#srv6)
- [How it works](#how-it-works)
- [Safety controls](#safety-controls)
- [Configuration](#configuration)
- [How it was verified](#how-it-was-verified)
- [Platform facts that shaped the design](#platform-facts-that-shaped-the-design)
- [Roadmap](#roadmap)
- [Project layout](#project-layout)
- [Development](#development)
- Project: [CHANGELOG](CHANGELOG.md) · [CONTRIBUTING](CONTRIBUTING.md) · [SECURITY](SECURITY.md)
- Docs: [platform facts](docs/platform-facts.md) (the full verified list) ·
  [API coverage](docs/COVERAGE.md) (every published CNC 7.2 operation against the tools) ·
  [RBAC](docs/RBAC.md) (the API rows a least-privilege account needs)

## Quickstart

Requires [uv](https://docs.astral.sh/uv/) (it fetches a Python 3.11+ on its
own if none is installed) and a Crosswork user (the `admin` role covers
everything; [docs/RBAC.md](docs/RBAC.md) lists the exact API rows a
least-privilege account needs, and `cnc_check_permissions` verifies one).

### Run it without cloning

```bash
uvx --from git+https://github.com/dr-stutters/cnc-mcp cnc-mcp
```

`uvx` fetches the repository, builds the package into its cache and starts
the server on stdio. Append a ref to the URL to pin what you run — `@v0.1.0` (a release tag, once
that release exists) or `@main`.
Settings are read from `CNC_MCP_*` environment variables or a `.env` file in
the server's working directory — [Configuration](#configuration) lists every
variable and `.env.example` is a commented template. Run unconfigured, the
server exits at once with `Configuration error — check environment variables
(CNC_MCP_BASE_URL)`, which is the quickest check that the install works.

A PyPI package (plain `uvx cnc-mcp`) is planned once the project is
registered there; until then the git URL above is the install path.

### Register it with an MCP client

**Claude Code**

```bash
claude mcp add cnc -e CNC_MCP_BASE_URL=https://cnc.example.com:30603 \
  -- uvx --from git+https://github.com/dr-stutters/cnc-mcp cnc-mcp
```

The credentials (`CNC_MCP_USERNAME` / `CNC_MCP_PASSWORD`, or
`CNC_MCP_API_TOKEN`) reach the server either as variables exported in the
shell that starts the client, or from a `.env` file in the server's working
directory. To make that directory explicit — independent of where the client
happens to start the server — pass uv's `--directory` flag:

```bash
claude mcp add cnc -- uvx --directory /home/me/cnc-config \
  --from git+https://github.com/dr-stutters/cnc-mcp cnc-mcp
```

with `/home/me/cnc-config/.env` holding the `CNC_MCP_*` settings (copy
`.env.example`). Claude Code's default `local` scope and the `user` scope
keep the registration in your own `~/.claude.json`; the `project` scope
writes a `.mcp.json` into the repository for everyone who checks it out.
**`CNC_MCP_USERNAME` / `CNC_MCP_PASSWORD` must never go into a shared client
config** — a `.mcp.json` in a repository, a team-distributed
`claude_desktop_config.json`, a `.cursor/mcp.json` that gets committed.
Use `-e` only for non-secret settings such as `CNC_MCP_BASE_URL`, and keep
the secrets in a `.env` (git-ignored here) or in your own shell environment.

**Claude Desktop** — `claude_desktop_config.json` (Settings → Developer →
Edit Config):

```json
{
  "mcpServers": {
    "cnc": {
      "command": "uvx",
      "args": [
        "--directory", "/home/me/cnc-config",
        "--from", "git+https://github.com/dr-stutters/cnc-mcp", "cnc-mcp"
      ],
      "env": { "CNC_MCP_BASE_URL": "https://cnc.example.com:30603" }
    }
  }
}
```

Desktop clients do not start servers in a predictable working directory, so
the `--directory` form is the reliable way to have the `.env` found. If the
client reports that it cannot find `uvx`, use its absolute path (`which uvx`)
as `command`.

**Cursor** — the same `mcpServers` block in `~/.cursor/mcp.json` (per user)
or `.cursor/mcp.json` (per project, shared if committed).

**VS Code** — `.vscode/mcp.json` (per project) or the user-level `mcp.json`
(*MCP: Open User Configuration*); same entry, but the top-level key is
`servers` and the entry carries `"type": "stdio"`.

Write tools are not registered at all until `CNC_MCP_ENABLE_WRITES=true`,
so a read-only registration cannot be talked into changing anything;
[Safety controls](#safety-controls) covers the area allowlist, the tool
denylist and the dry-run mode that sit on top of that switch.

### Clone and run (development)

```bash
git clone https://github.com/dr-stutters/cnc-mcp && cd cnc-mcp
make install                      # uv sync
cp .env.example .env              # set CNC_MCP_BASE_URL, USERNAME, PASSWORD
make test && make lint            # 2,800+ tests, all HTTP mocked — no CNC needed
make run                          # start the server on stdio
make inspect                      # MCP Inspector against it
make cli ARGS="list"              # scripts/mcp_cli.py: list | schema | call | prompts | prompt
make rbac-check                   # the packaged RBAC map still matches the tool source
make build                        # wheel + sdist into dist/
```

`scripts/mcp_cli.py` drives the server over the real MCP stdio protocol —
`instructions`, `list [--writes]`, `schema <tool>`, `call <tool> '<json>'`,
`prompts`, `prompt <name> '<json>'`, each with `--env NAME=VALUE` to start
the server under other settings — so what it prints is exactly what an
agent sees. To register a checkout with
a client, replace the `uvx` command above with
`"command": "uv", "args": ["--directory", "/path/to/cnc-mcp", "run", "cnc-mcp"]`;
the checkout's own `.env` is then the configuration.

### Docker

```bash
docker run -i --rm --env-file .env ghcr.io/dr-stutters/cnc-mcp:latest
```

The image is published to GHCR by the release workflow on each tag. It
contains no credentials (`.dockerignore` keeps `.env` out of the build
context); they are passed at run time with `--env-file` or `-e`. To build
locally instead: `make docker-build`, then `docker run -i --rm --env-file
.env cnc-mcp`. In a client config the entry is `"command": "docker"` with
`"args": ["run", "-i", "--rm", "--env-file", "/path/to/.env",
"ghcr.io/dr-stutters/cnc-mcp:latest"]`.

Every setting, its default and what it does is in [Configuration](#configuration)
below; `.env.example` is the same list as a commented template.

## Tools

Read tools — registered in every mode:

| Area | Tools |
|---|---|
| **Devices** | `cnc_list_devices` · `cnc_get_device` · `cnc_get_device_collection_summary` · `cnc_wait_for_device_reachable` |
| **Credential profiles** | `cnc_list_credential_profiles` · `cnc_get_credential_profile` |
| **Providers** (SR-PCE, NSO, …) | `cnc_list_providers` · `cnc_get_provider` |
| **Topology** (RESTCONF NBI) | `cnc_get_topology_summary` · `cnc_list_topology_nodes` · `cnc_get_topology_node` · `cnc_list_node_interfaces` · `cnc_get_node_interface` · `cnc_list_topology_links` · `cnc_get_topology_link` · `cnc_list_srv6_locators` |
| **TE state** (SR-PCE feed) | `cnc_get_te_summary` · `cnc_list_sr_policies` · `cnc_get_sr_policy` · `cnc_list_p2mp_policies` · `cnc_get_p2mp_policy` · `cnc_list_rsvp_te_tunnels` · `cnc_get_rsvp_te_tunnel` · `cnc_get_link_performance_metrics` · `cnc_get_sr_policy_performance_metrics` · `cnc_get_rsvp_tunnel_performance_metrics` |
| **SR-TE operations** (Optimization Engine) | `cnc_list_sr_policies_on_nodes` · `cnc_list_sr_policies_on_interface` · `cnc_get_sr_policy_routes` · `cnc_get_sr_policy_metrics` · `cnc_preview_sr_policy_route` · `cnc_dryrun_sr_policy` · `cnc_get_sr_policy_path_notification_state` · `cnc_wait_for_sr_policy_oper_state` |
| **Platform** | `cnc_list_tags` · `cnc_list_users` · `cnc_list_applications` · `cnc_list_alarms` · `cnc_list_inventory_jobs` · `cnc_get_inventory_job` · `cnc_wait_for_inventory_job` |
| **Data Gateway** | `cnc_list_data_gateways` · `cnc_get_data_gateway` · `cnc_list_data_gateway_pools` · `cnc_get_data_gateway_load_metrics` · `cnc_list_data_gateway_outages` · `cnc_get_data_gateway_health` · `cnc_get_data_gateway_global_parameters` · `cnc_list_data_destinations` · `cnc_list_data_gateway_files` |
| **NSO** | `cnc_is_nso_configured` · `cnc_get_nso_policy` · `cnc_list_nso_devices` · `cnc_get_nso_device` · `cnc_check_device_nso_state` · `cnc_check_nso_device_sync` · `cnc_get_nso_device_config` · `cnc_wait_for_device_nso_state` |
| **Inventory extras** | `cnc_get_device_summary` · `cnc_get_inventory_config` · `cnc_get_collection_cadence` · `cnc_get_device_tags` |
| **Fault** | `cnc_get_alarm` · `cnc_search_alarms` · `cnc_list_events` · `cnc_list_device_alarms` · `cnc_get_alarm_settings` · `cnc_get_alarm_manager_settings` · `cnc_list_event_types` · `cnc_get_event_type_recommendation` · `cnc_list_alarm_suppression_policies` |
| **Device configuration** | `cnc_get_device_config_preferences` · `cnc_list_device_backups` · `cnc_get_device_backup` · `cnc_list_config_backup_jobs` · `cnc_get_config_backup_job` · `cnc_list_config_templates` · `cnc_get_config_template` · `cnc_list_template_deployments` · `cnc_get_template_deployment` · `cnc_wait_for_config_backup_job` · `cnc_wait_for_template_deployment` |
| **EMF inventory** | `cnc_list_ems_nodes` · `cnc_get_ems_node` · `cnc_list_ems_interfaces` · `cnc_get_ems_interface` · `cnc_get_ems_inventory_summary` |
| **Platform admin & RBAC** | `cnc_get_platform_version` · `cnc_get_cluster_health` · `cnc_list_cluster_nodes` · `cnc_get_cluster_node` · `cnc_list_microservices` · `cnc_list_application_status` · `cnc_list_app_manager_jobs` · `cnc_list_app_manager_events` · `cnc_get_maintenance_status` · `cnc_list_certificates` · `cnc_check_certificate_expiry` · `cnc_get_login_banner` · `cnc_get_session_config` · `cnc_list_active_sessions` · `cnc_get_user` · `cnc_list_roles` · `cnc_get_role_tasks` · `cnc_get_role_permissions` · `cnc_get_password_policy` · `cnc_list_secured_apis` · `cnc_check_permissions` |
| **Notifications** | `cnc_list_notification_streams` · `cnc_list_notification_subscriptions` · `cnc_get_notification_subscription` · `cnc_list_kafka_subscriptions` |
| **Collection service** | `cnc_get_collection_job_count` · `cnc_get_collection_job_summary` · `cnc_get_collection_job_state` · `cnc_list_export_collection_jobs` · `cnc_list_sensor_templates` · `cnc_get_collection_health` |
| **Device groups** | `cnc_list_group_rule_conditions` · `cnc_list_root_groups` · `cnc_get_group_hierarchy` · `cnc_get_group_details` · `cnc_list_group_devices` · `cnc_list_group_rules` · `cnc_list_group_ports` |
| **LCM & Circuit-Style** (Optimization Engine) | `cnc_list_lcm_domains` · `cnc_get_lcm_config` · `cnc_list_lcm_managed_interfaces` · `cnc_get_lcm_recommendation` · `cnc_get_lcm_recommendation_preview` · `cnc_list_csm_bandwidth_pools` · `cnc_list_cs_policy_paths` · `cnc_list_cs_policies_on_nodes` · `cnc_list_cs_policies_on_interface` |
| **Services** (CAT inventory, T-SDN) | `cnc_list_service_types` · `cnc_get_service_counts` · `cnc_list_services` · `cnc_get_service` · `cnc_get_service_plan` · `cnc_wait_for_service_plan` · `cnc_list_vpn_services` · `cnc_get_vpn_service` · `cnc_get_vpn_service_health` · `cnc_get_vpn_underlay_transport` · `cnc_list_sub_services` · `cnc_find_services_on_transport` · `cnc_list_function_packs` |
| **Performance monitoring** (PM policies, dashboards, NPM) | `cnc_list_performance_policies` · `cnc_get_performance_policy` · `cnc_get_performance_policy_history` · `cnc_list_performance_policy_devices` · `cnc_list_performance_policy_templates` · `cnc_get_performance_retention` · `cnc_get_performance_health_settings` · `cnc_get_performance_statistics` · `cnc_get_performance_top_n` · `cnc_list_performance_top_n_columns` · `cnc_get_performance_summary` · `cnc_get_lsp_utilization` · `cnc_get_lsp_delay` · `cnc_get_interface_delay` · `cnc_get_srv6_locator_statistics` |
| **OAM & probes** | `cnc_get_oam_settings` · `cnc_list_oam_trace_routes` · `cnc_get_oam_trace_route` · `cnc_wait_for_oam_trace_route` · `cnc_get_probe_status` |
| **SWIM & ZTP** | `cnc_get_swim_preferences` · `cnc_list_software_images` · `cnc_get_device_running_images` · `cnc_get_swim_job` · `cnc_list_ztp_profiles` · `cnc_list_ztp_devices` · `cnc_list_ztp_serial_numbers` · `cnc_list_ztp_static_routes` · `cnc_get_ztp_device_policy` · `cnc_list_ztp_config_files` · `cnc_list_ztp_images` |
| **EMS inventory scheduler** | `cnc_list_inventory_scheduler_jobs` · `cnc_get_inventory_scheduler_job` · `cnc_wait_for_inventory_scheduler_job` |
| **Playbooks** (one call, composed from the tools above) | `cnc_investigate_device` · `cnc_network_health_report` · `cnc_explain_sr_policy` · `cnc_alarm_triage` · `cnc_explain_service` · `cnc_srv6_readiness` |

Write tools — registered only with `CNC_MCP_ENABLE_WRITES=true` (and, with
`CNC_MCP_WRITE_AREAS`, only for the listed areas); deletes carry the MCP
`destructive` annotation:

| Area | Tools |
|---|---|
| **Devices** | `cnc_create_device` · `cnc_update_device` · `cnc_delete_device` · `cnc_enable_device_gnmi` |
| **Credential profiles** | `cnc_create_credential_profile` · `cnc_update_credential_profile` · `cnc_delete_credential_profile` |
| **Providers** | `cnc_create_provider` · `cnc_update_provider` · `cnc_delete_provider` |
| **Data Gateway** | `cnc_map_devices_to_data_gateway` |
| **NSO** | `cnc_nso_device_action` (check-sync / sync-from / connect / compare-config …) · `cnc_nso_sync_to_device` · `cnc_sync_inventory_with_nso` |
| **SR-TE operations** | `cnc_create_sr_policy` · `cnc_update_sr_policy` · `cnc_delete_sr_policy` · `cnc_set_sr_policy_path_notifications` |
| **Platform admin** | `cnc_set_login_banner` · `cnc_set_maintenance_mode` · `cnc_restart_microservice` |
| **Inventory extras** | `cnc_create_tag` · `cnc_delete_tag` · `cnc_assign_tags` · `cnc_unassign_tags` · `cnc_set_device_location` · `cnc_clear_device_location` · `cnc_lock_device` · `cnc_unlock_device` |
| **Fault** | `cnc_acknowledge_alarm` · `cnc_annotate_alarm` · `cnc_clear_alarm` · `cnc_create_alarm_suppression_policy` · `cnc_update_alarm_suppression_policy` · `cnc_delete_alarm_suppression_policy` · `cnc_set_event_type_severity` · `cnc_set_event_type_autoclear` · `cnc_revert_event_type_autoclear` · `cnc_set_event_type_recommendation` · `cnc_update_alarm_manager_settings` · `cnc_update_gnmi_alarm_settings` |
| **Device configuration** | `cnc_backup_device_config` · `cnc_delete_config_backup_job` · `cnc_delete_device_backup` · `cnc_create_config_template` · `cnc_delete_config_template` · `cnc_deploy_config_template` · `cnc_delete_template_deployment` |
| **Notifications** | `cnc_create_webhook_subscription` · `cnc_delete_notification_subscription` · `cnc_create_external_subscription` (Kafka / gRPC) · `cnc_delete_external_subscription` · `cnc_clear_notification_subscriptions_by_topic` |
| **Device groups** | `cnc_create_device_group` · `cnc_update_device_group` · `cnc_delete_device_group` · `cnc_set_device_group_members` · `cnc_move_group_members` |
| **LCM** | `cnc_pause_lcm_recommendations` |
| **Service provisioning** (NSO proxy, T-SDN CFPs) | `cnc_create_odn_template` · `cnc_delete_odn_template` · `cnc_create_sr_policy_service` · `cnc_update_sr_policy_service` · `cnc_delete_sr_policy_service` · `cnc_create_sid_list` · `cnc_delete_sid_list` · `cnc_create_l3vpn_service` · `cnc_delete_vpn_service` · `cnc_provision_service` · `cnc_delete_service` · `cnc_resync_service_inventory` — the three creates take `srv6_locator` for SRv6 transport (see [SRv6](#srv6)) |
| **Performance monitoring** (PM policies, retention) | `cnc_create_performance_policy` · `cnc_update_performance_policy` · `cnc_activate_performance_policy` · `cnc_deactivate_performance_policy` · `cnc_delete_performance_policy` · `cnc_update_performance_retention` · `cnc_reset_performance_retention` |
| **OAM & probes** | `cnc_start_oam_trace_route` · `cnc_reactivate_probe` |
| **SWIM & ZTP** (the ZTP catalogue) | `cnc_upload_ztp_config_file` · `cnc_update_ztp_config_file` · `cnc_delete_ztp_config_file` · `cnc_create_ztp_profile` · `cnc_update_ztp_profile` · `cnc_delete_ztp_profile` · `cnc_add_ztp_serial_numbers` · `cnc_delete_ztp_serial_numbers` · `cnc_create_ztp_static_route` · `cnc_delete_ztp_static_route` · `cnc_create_ztp_device` · `cnc_update_ztp_device` · `cnc_delete_ztp_device` |
| **EMS inventory scheduler** | `cnc_run_inventory_scheduler_job` · `cnc_suspend_inventory_scheduler_job` · `cnc_resume_inventory_scheduler_job` |
| **Playbooks** | `cnc_provision_l3vpn_e2e` (dry-run → commit → plan → CAT status → OAM trace; `srv6_locator` for an SRv6 VPN, which skips the MPLS-only trace) · `cnc_create_sr_policy_e2e` (dry-run → create → wait UP → routes) — both take `dry_run=true` to stop after the preview |

The playbook tools compose the others server-side: each answers with a
**verdict** (healthy / degraded / red / deployed …, with the reasons), one
section per underlying tool, and an audit list of the calls it made, so an
agent can drill into any section with the individual tool. A section whose
call fails is reported as unavailable rather than failing the whole answer.
Blind-agent measurements: a "device looks degraded" investigation dropped
from 44 tool calls to a handful, a network health overview from 25.

Seven **MCP prompts** package the operator workflows for clients that expose
them as slash commands: `troubleshoot_device`, `network_health_check`,
`explain_sr_policy`, `provision_l3vpn` (with an optional `srv6_locator`),
`alarm_triage`, `explain_service`, `srv6_readiness`.
Each tells the assistant which playbook to start from, where to drill in, and
what to do when the write tools are absent.

Every tool has flat, typed parameters with examples and constraints (unknown
argument names are rejected with a "did you mean" hint), a docstring that
states when to use it, what it returns, and what each error means, and a
`response_format` of `markdown` (curated summary, the default) or `json`
(complete data). The `wait_for_*` tools poll server-side so an agent
never has to loop on a status check.

Conventions the server also tells agents about at connect time:

- **Paging** is `page_size` / `page` (0-based); list tools return
  `{total, count, page, page_size, has_more, next_page, items}` where `total`
  counts matches for the filter and `collection_total` the whole collection.
- **Filters** are exact-match, case-insensitive, with `*` as a wildcard.
- **Enums** accept friendly values (`admin_state="up"`, `family="sr_pce"`,
  `protocol="ssh"`) or the platform's wire values.
- **Writes** return Crosswork's job envelope (`job_id`, `state`, `impacted`).
  A job the platform rejected comes back as `Error: …` with the platform's
  reason, never as a silent success.
- **Ordering**: credential profile → provider → device. A device's
  `te_router_id` must match its router-id in the SR-PCE topology for the two
  to correlate. ZTP: config file → profile → serial numbers → device, torn
  down in reverse (an in-use serial cannot be deleted).
- **Network-impacting writes are named as such**: activating a PM policy
  starts SNMP/telemetry collection on its devices within seconds; a device
  group is populated by moving devices out of the leaf that holds them
  (`Unassigned Devices` for a device never placed), because the platform's
  "set members" call removes; reverting an event type's auto-clear deletes
  the interval rather than restoring a default.

### SRv6

CNC 7.2 exposes SRv6 through the same NBIs as SR-MPLS, with no locator
object anywhere in the topology model: a node advertises SRv6 node SIDs
per IGP instance and a link End.X adjacency SIDs, so `cnc_list_srv6_locators`
*derives* each locator from a node SID and its block / node lengths
(`fc00:0:1::/48` from lb 32 + ln 16, labelled `uSID F3216` when the function
length is 16 too). `cnc_get_topology_node` / `cnc_get_topology_link` render
the SIDs, their structure and the node's Flex-Algos, `cnc_get_topology_summary`
counts them, and `cnc_list_topology_nodes` / `cnc_list_sr_policies` take a
`dataplane` filter (`sr-mpls` | `srv6`). SR-policy state carries no dataplane
leaf either: a policy is reported as `srv6` when it carries an
`srv6-binding-sid`, IPv6 hops or IPv6 router-id keys (`cnc_get_sr_policy`
accepts them; `cnc_get_te_summary` counts by dataplane; `cnc_explain_sr_policy`
says which dataplane it found). `cnc_get_srv6_locator_statistics` reads the
Performance dashboard's per-locator `outBitRate` series (it needs an
`SRV6LOCATOR` monitoring policy on the device), and `cnc_srv6_readiness` folds
all of it into a READY / PARTIAL / NONE verdict that names the nodes without a
locator and the adjacencies without an End.X SID.

Provisioning goes through the T-SDN function packs only: `srv6_locator` on
`cnc_create_sr_policy_service`, `cnc_create_odn_template`,
`cnc_create_l3vpn_service` (service-wide or per endpoint) and
`cnc_provision_l3vpn_e2e`. The function pack's rules are checked before
anything is sent: an SRv6 policy needs an IPv6 tail-end and a dynamic path —
explicit SID lists, bandwidth and a binding-SID are refused — and NSO
validates neither the locator name nor the tail-end against the routers, so
dry-run first and confirm the locator on the router with
`cnc_get_nso_device_config(subtree='segment-routing/srv6')`. Not in 7.2, and
the tools say so rather than pretend: PCE-initiated SRv6 policies (the
Optimization Engine RPCs `cnc_create_sr_policy` / `cnc_dryrun_sr_policy` are
SR-MPLS only), SRv6 OAM trace routes (`cnc_start_oam_trace_route` is MPLS
LSP-ping only, so the L3VPN playbook skips the trace for an SRv6 VPN),
explicit SRv6 SID lists, and L2VPN with SRv6-TE.

Verification status: the lab has no SRv6 underlay yet, so the
populated SRv6 renderings are built from the 7.2 YANG / OpenAPI shapes and
exercised on fixtures only; what is verified live is that every reader
answers "no SRv6" on the SR-MPLS lab with its SR-MPLS content unchanged,
that `cnc_srv6_readiness` answers NONE with the underlay hint, that the
`srv6locator` PM endpoints answer empty, and — through NSO dry-run, nothing
committed — that the three creates render the expected CLI (`srv6 / locator
LOC1 binding-sid dynamic behavior ub6-insert-reduced` with an IPv6 end-point
for the policy and the ODN template; `segment-routing srv6 / locator LOC1 /
alloc mode per-vrf` under the VRF's address-family for the L3VPN).

## How it works

```
MCP client ──stdio──▶ cnc-mcp ──HTTPS──▶ Tyk gateway (:30603) ──▶ Crosswork services
                        │
                        ├─ auth.py       CAS SSO: ticket-granting ticket → service ticket (an 8 h JWT)
                        ├─ client.py     retries, concurrency cap, one transparent re-auth
                        ├─ errors.py     platform status/body → actionable "Error: …" hints
                        ├─ crosswork.py  JSON-over-POST dialect: query grammar, envelopes, job checks
                        ├─ restconf.py   RESTCONF NBI dialect (topology, optimization engine, NSO proxy)
                        ├─ emf.py        EMF RESTCONF dialect (fault / inventory / performance)
                        ├─ probe.py      "is this API even present on this deployment?"
                        └─ tools/        one module per API area, registered through safety.py
```

**Authentication.** Crosswork's two-leg CAS flow is implemented in
`CrossworkCasAuth`: `POST /crosswork/sso/v1/tickets` yields a ticket-granting
ticket, exchanged for a service ticket that is an 8-hour JWT sent as
`Authorization: Bearer`. Crosswork never answers 401 — an expired token is a
`403 "Unauthorized request"`, a malformed one a `500 "Middleware error"` — so
the auth strategy decides what "re-authenticate" looks like and the client
retries once. httpx's request logging is capped at WARNING because the
second leg's URL contains the ticket.

**One gateway, several API dialects.** Behind the single NodePort, CNC's
services speak differently: JSON-over-POST `…/query` bodies with per-service
grammars (inventory, dg-manager, collection, alarms), RESTCONF NBIs under
`/crosswork/nbi/*` and the NSO proxy, and an EMF RESTCONF that only returns
JSON for exactly `Accept: application/json`. Each dialect's verified quirks
live in one helper module, so tool modules stay thin.

**Safety.** `safety.register_tool()` is the only way a tool is registered: it
forces a read-only/destructive/idempotent decision, refuses to register
write tools unless writes are enabled (and their area allowed), never
registers a disabled tool, and in dry-run mode swaps each write for its
preview — see [Safety controls](#safety-controls). POSTs are not auto-retried on 5xx
(a lost response might mean the write happened) unless a tool explicitly
marks the call safe to re-send. Tools never raise: every failure is returned
as an `Error: …` string with the platform's reason, and secrets never appear
in logs, errors, or output beyond what the platform itself masks.

## Safety controls

Four layers, each an environment variable, each applied when the tools are
registered: a tool a layer excludes is absent from the tool list the agent
sees, not merely refused. (Dry-run mode is the exception by design — the
write tools stay visible, but harmless.)

1. **Writes are off by default.** `CNC_MCP_ENABLE_WRITES=true` registers the
   98 write tools; without it the server is read-only, and the connect-time
   instructions say so.
2. **`CNC_MCP_WRITE_AREAS`** — a comma-separated allowlist of the areas whose
   write tools are registered when writes are on (empty, the default, means
   every area). An area is a module in `src/cnc_mcp/tools/`; the ones with
   write tools are `devices`, `credentials`, `providers`, `sr_te_operations`,
   `data_gateway`, `nso`, `admin`, `inventory_extras`, `fault`,
   `device_config`, `notifications`, `grouping`, `lcm_csm`,
   `service_provisioning`, `performance`, `oam`, `swim_ztp`, `ems_jobs` and
   `composite`. Read tools are never affected. The
   write playbooks in `composite` need the sibling that commits for them:
   `cnc_provision_l3vpn_e2e` needs `service_provisioning` (and `oam` for
   its optional trace step), `cnc_create_sr_policy_e2e` needs
   `sr_te_operations` — `CNC_MCP_WRITE_AREAS=composite` on its own registers
   neither, and the startup log says which sibling each one lacks.
3. **`CNC_MCP_DISABLED_TOOLS`** — a comma-separated denylist of tool names,
   read or write, that are never registered whatever the other settings say
   (`cnc_delete_device,cnc_restart_microservice`).
4. **`CNC_MCP_DRY_RUN=true`** — the write tools stay registered but nothing
   changes on the platform. A write tool that takes `dry_run` runs with it
   forced to `true` and answers the preview (the device CLI NSO would push,
   the path the PCE would compute); every other write tool is not executed
   and answers `NOT EXECUTED` with the arguments it would have sent
   (secret-looking values redacted); the two write playbooks stop after
   their preview stage with a `dry-run` verdict. Each write tool's
   description ends with which of the two applies to it.

An unknown area or tool name is a configuration error at startup, with a
"did you mean" hint, never a silent no-op; an allowlisted area whose tools
are all read-only is logged as a warning. The startup log summarises the
result (`Registered 199 of 285 tools (187 read, 12 write); writes on for
areas fault; disabled tools: none; dry-run off`), the connect-time
instructions tell the agent which mode it is in, and `cnc_check_permissions`
repeats it next to the account's role.

`scripts/mcp_cli.py --env NAME=VALUE` (repeatable) starts the server with
extra variables, to try a mode without editing `.env`:

```bash
uv run python scripts/mcp_cli.py --writes --env CNC_MCP_WRITE_AREAS=fault list
uv run python scripts/mcp_cli.py --writes --env CNC_MCP_DRY_RUN=true \
    call cnc_create_tag '{"name": "site-a"}'
```

**Least-privilege account.** The Crosswork gateway checks every request
against the account's role, per API and HTTP method, so the server can run
under a role that grants only what its registered tools send.
[docs/RBAC.md](docs/RBAC.md) — generated from the tool source by
`scripts/rbac_map.py`, checked in CI against the packaged map — lists the
exact API rows a read-only account needs and what each write area adds,
with ready-made role bodies in `docs/rbac/`. `cnc_check_permissions` reads
the running account's role and reports which registered tools it would
refuse and the rows to grant; a 403 from any tool points at it. The role
bodies are the shape the Crosswork role editor submits (verified against a
role built in the UI and read back; minus the empty `_id`/`id` the editor
also sends, and with the read-back's `limit`/`allowance_scope` row fields),
except that they grant single API ids where a UI tick grants a whole
display-name group — so manage such a role through the API, not the editor
(`docs/RBAC.md` says what is verified and what is not).

## Configuration

Environment variables (or a `.env` file), prefix `CNC_MCP_`:

| Variable | Default | Purpose |
|---|---|---|
| `CNC_MCP_BASE_URL` | (required) | CNC UI/API URL **with scheme**, e.g. `https://host:30603` |
| `CNC_MCP_USERNAME` / `CNC_MCP_PASSWORD` | — | Crosswork user; CAS SSO → JWT, refreshed automatically |
| `CNC_MCP_API_TOKEN` | — | Alternative: a pre-issued JWT (cannot be refreshed; expires in ~8 h) |
| `CNC_MCP_VERIFY_TLS` | `true` | `false` for self-signed lab certificates |
| `CNC_MCP_ENABLE_WRITES` | `false` | **Write tools are not registered until `true`** |
| `CNC_MCP_WRITE_AREAS` | (all) | Comma-separated areas whose write tools are registered when writes are on, e.g. `fault,service_provisioning` |
| `CNC_MCP_DISABLED_TOOLS` | — | Comma-separated tool names never registered, read or write |
| `CNC_MCP_DRY_RUN` | `false` | Write tools registered but not executed: forced preview where the tool has `dry_run`, recorded otherwise |
| `CNC_MCP_TIMEOUT_SECONDS` | `30` | Per-request read timeout, seconds (>= 1) |
| `CNC_MCP_CONNECT_TIMEOUT_SECONDS` | `10` | TCP connect timeout, seconds (>= 1) |
| `CNC_MCP_MAX_RETRIES` | `3` | Retries for 429 / 5xx / transport errors (idempotent calls; 0-10) |
| `CNC_MCP_RETRY_BACKOFF_SECONDS` | `1.0` | Base delay for the exponential backoff between retries, seconds (>= 0) |
| `CNC_MCP_MAX_CONCURRENT_REQUESTS` | `5` | Cap on in-flight requests to the platform |
| `CNC_MCP_MAX_RESPONSE_CHARS` | `40000` | Tool responses longer than this are truncated with a note |
| `CNC_MCP_LOG_LEVEL` | `INFO` | Python logging level (stderr only — stdout is the MCP transport) |

## How it was verified

Unit tests prove the code; only a live run proves the integration. Four
layers were used:

1. **Mocked unit tests** (`make test`): every tool has a happy-path test
   through the MCP server (which validates the input schema) asserting the
   exact request body sent, and an error-path test. All HTTP is mocked with
   `respx`; CI runs them on Python 3.11 and 3.12.
2. **Live smoke** (`scripts/live_smoke.py`): a plan of real tool calls against
   a running instance. The read phase is side-effect free; the write phase
   creates `smoke-*` objects and removes them again, chaining created UUIDs
   into later steps, and must leave the platform exactly as it found it.
   `scripts/smoke_plan.example.json` is a sanitised copy of the plan used.
3. **Agent scenarios** (`scripts/mcp_cli.py`): the server driven over the real
   MCP stdio protocol by assistants that see only the tool list, schemas and
   instructions — ten operator tasks (health overview, traffic ranking,
   policy explanation, service audit, a "degraded device" investigation, and
   five provisioning/operations tasks with full cleanup) run against the
   lab; every point of friction they reported became a fix (alarm triage
   rendering and sorting, unknown arguments rejected by name, host names
   accepted wherever a router-id is a key, modelled-vs-measured PM caveats,
   parseable truncation, ...). `mcp_cli.py` doubles as a manual test client.
4. **Live plumbing check** (`scripts/live_plumbing_check.py`): exercises every
   dialect helper against the instance — the real 409, the real
   error-inside-200, the real XML fallback, the real routing signatures — so a
   platform change that breaks a verified assumption shows up before it
   breaks a tool.

The instance was a single-VM CNC 7.2.0 deployment with embedded NSO and
Data Gateway, fed by a Cisco Modeling Labs fabric of five IOS-XRd routers
running IS-IS + SR-MPLS (no SRv6 underlay yet — see [SRv6](#srv6) for what
that leaves unverified), one of them acting as SR-PCE (BGP-LS + PCEP, feeding
CNC over gRPC) with two PCE-delegated SR policies between the PEs, gNMI
onboarded on every router, `mpls oam` and a vpnv4 iBGP pair on the PEs (so an
L3VPN can be committed through the T-SDN function pack and traced end to end). Each
module was also adversarially reviewed against the recorded facts before it
was merged; that review caught bugs the tests had enshrined (a "not found"
check that would have hidden an absent API, an NSO failure that would have
read as success).

## Platform facts that shaped the design

The published OpenAPI documents describe a platform that is not quite the one
on the wire, so the client is built around the differences, each verified live:
there are no 401s (an expired token is `403`, garbage is `500`); failed writes
are HTTP 200 with `state: JOB_FAILED` in a job envelope; a missing RESTCONF
entry is `409 data-missing` while a 404 means "no such route"; the Optimization
Engine answers bad input with a bare, empty 500; NSO device actions are
fire-and-forget. The full list of 21 verified facts is in
[docs/platform-facts.md](docs/platform-facts.md).

## Roadmap

The published CNC 7.2 API has 948 operations across 103 OpenAPI documents;
this server covers the inventory (incl. tags, locks, locations), the EMF
inventory, topology, TE state, SR-TE operations, fault management, device
configuration (backups, templates, deployments), platform administration and
RBAC, Data Gateway, NSO, notifications (webhook and external Kafka / gRPC
subscriptions), the collection service, device grouping (user groups,
membership and rules), the LCM / Circuit-Style managers, the CAT service
inventory and T-SDN service provisioning through the NSO proxy, performance
monitoring (policy lifecycle, retention, dashboards) and NPM analytics, OAM
trace routes and Service Health probes, SWIM reads, the ZTP catalogue (config
files, profiles, serial numbers, static routes, devices) and the EMS
inventory scheduler.
[docs/COVERAGE.md](docs/COVERAGE.md) is the full picture: every documented
operation, whether a tool sends it, and if not why (it is generated by
`scripts/api_coverage.py` from the OpenAPI set, so its numbers are computed,
not claimed). Planned modules, in the order they become exercisable on a lab:

| Module | Scope |
|---|---|
| SRv6 on a live underlay | the SRv6 readers and renderings ([SRv6](#srv6)) verified against a fabric that runs locators, IS-IS IPv6 and SRv6 policies — which members the SR-PCE feed populates, the endpoint-behaviour strings, a populated `srv6locator` series — then the dry-run-only provisioning steps committed and reverted |
| writes not yet exposed | collection job create, SWIM collect/distribute/activate, ZTP image upload / ownership vouchers / device status patch, config restore, LCM/CSM configuration and RSVP-TE / P2MP policy operations — unverified bodies with real network impact |
| not on this build | change automation, health insights, path analytics, service health (unrouted on a single-VM 7.2 deployment — a 404 from the home application; the error text names the missing application) |

## Project layout

```
src/cnc_mcp/
  server.py       assembly, auth selection, connect-time instructions
  auth.py         auth strategies incl. CrossworkCasAuth
  client.py       ApiClient: retries, re-auth, concurrency, raw bodies
  errors.py       PlatformError and the status/body → hint mapping
  config.py       Settings (env / .env)
  safety.py       register_tool(): annotations, write gating (areas, denylist), dry-run wrapper
  formatting.py   markdown/json response formats, pagination envelope, size cap
  polling.py      wait_until() for the wait_for_* tools
  crosswork.py    inventory query grammar, envelopes, job checks, enums, dg/collection/alarm helpers
  restconf.py     RESTCONF NBI helpers
  emf.py          EMF RESTCONF helpers
  probe.py        routing classification and availability probing
  tools/          devices, credentials, providers, inventory_extras, physical_inventory,
                  topology, te_state, sr_te_operations, platform, fault, device_config,
                  data_gateway, nso, admin, notifications, collection, grouping, lcm_csm,
                  services, service_provisioning, performance, oam, swim_ztp, ems_jobs,
                  composite (the playbooks)
  data/rbac_map.json        which gateway API each tool needs (generated; read by cnc_check_permissions)
scripts/
  live_smoke.py             live tool-call plan runner (read / write phases, $var chaining)
  live_plumbing_check.py    live verification of the dialect helpers
  mcp_cli.py                call the server over the real MCP stdio protocol (list/schema/call/prompts)
  api_coverage.py           maps the published OpenAPI operations onto the tools -> docs/COVERAGE.md
  rbac_map.py               tool -> gateway API map -> data/rbac_map.json, docs/RBAC.md, docs/rbac/
  smoke_plan.example.json   sanitised smoke plan
docs/
  platform-facts.md         the verified platform behaviours the client is built around
  COVERAGE.md               every published CNC 7.2 operation against the tools (generated)
  RBAC.md, rbac/            the API rows a least-privilege role needs, ready-made role bodies (generated)
tests/                      one test module per source module; respx-mocked
```

## Development

```bash
make test          # pytest (respx-mocked HTTP)
make lint          # ruff check
make fmt           # ruff format + autofix
make rbac          # regenerate the RBAC map and docs/RBAC.md from the tool source (offline)
make rbac-check    # exit 1 when they are stale (CI runs this)
make docker-build  # stdio server image; run with: docker run -i --rm --env-file .env cnc-mcp
```

To add a tool module: read `CLAUDE.md` (the conventions are non-negotiable),
copy the pattern of an existing module in `src/cnc_mcp/tools/`, register it
in `tools/__init__.py`, give every tool a happy-path and an error-path test,
add its calls to the smoke plan, run `make rbac` (a new tool without a
regenerated map fails CI), and run the live smoke before merging.

## License

[MIT](LICENSE) © 2026 Mitchell McInnes
