# cnc-mcp

[![CI](https://github.com/dr-stutters/cnc-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/dr-stutters/cnc-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An [MCP](https://modelcontextprotocol.io) server that lets an AI agent operate
**Cisco Crosswork Network Controller (CNC)** — the SDN controller for Cisco
service-provider networks — through its REST APIs.

With this server connected, an agent can answer questions like *"which
devices are unreachable?"*, *"what does the topology look like?"*, *"which SR
policies are down and what path do they take?"*, *"is the
Data Gateway collecting?"*, *"is PE1 in sync with NSO?"*, and, when writes are
enabled, onboard devices, manage credential profiles and providers, map
devices to gateways, drive NSO sync and connect actions, provision SR-TE
policies through the SR-PCE, provision ODN templates, SR-TE policies and
L3VPNs through NSO's T-SDN function packs (dry-run first), subscribe webhooks
to alarm/inventory events, inspect collection jobs, device groups, the
LCM / Circuit-Style managers, performance-monitoring dashboards and NPM
analytics, run OAM trace routes and read SWIM / ZTP state — all
through typed, documented tools with the platform's own error reasons surfaced
verbatim.

**237 tools** (176 read, 61 write) over 24 API areas. Every tool was built from
behaviour verified against a live CNC 7.2 instance, not from the documentation
alone — see [How it was verified](#how-it-was-verified).

## Contents

- [Quickstart](#quickstart)
- [Tools](#tools)
- [How it works](#how-it-works)
- [Configuration](#configuration)
- [How it was verified](#how-it-was-verified)
- [Platform facts that shaped the design](#platform-facts-that-shaped-the-design)
- [Roadmap](#roadmap)
- [Project layout](#project-layout)
- [Development](#development)

## Quickstart

Requires [uv](https://docs.astral.sh/uv/), Python 3.11+, and a Crosswork user
(the `admin` role covers everything; reads need the inventory, topology, alarm
and AAA read tasks, writes need inventory write).

```bash
git clone https://github.com/dr-stutters/cnc-mcp && cd cnc-mcp
make install                      # uv sync
cp .env.example .env              # set CNC_MCP_BASE_URL, USERNAME, PASSWORD
make test && make lint            # 500+ tests, all HTTP mocked — no CNC needed
make run                          # start the server on stdio
make inspect                      # open MCP Inspector against it
```

Register it with an MCP client (Claude Desktop, Claude Code, Cursor, …):

```json
{
  "mcpServers": {
    "cnc": {
      "command": "uv",
      "args": ["--directory", "/path/to/cnc-mcp", "run", "cnc-mcp"],
      "env": { "CNC_MCP_BASE_URL": "https://cnc.example.com:30603" }
    }
  }
}
```

Keep the credentials in `.env` (never in the client config). Write tools are
not even registered until `CNC_MCP_ENABLE_WRITES=true`, so a read-only
deployment cannot be talked into changing anything.

## Tools

Read tools — always registered:

| Area | Tools |
|---|---|
| **Devices** | `cnc_list_devices` · `cnc_get_device` · `cnc_get_device_collection_summary` · `cnc_wait_for_device_reachable` |
| **Credential profiles** | `cnc_list_credential_profiles` · `cnc_get_credential_profile` |
| **Providers** (SR-PCE, NSO, …) | `cnc_list_providers` · `cnc_get_provider` |
| **Topology** (RESTCONF NBI) | `cnc_get_topology_summary` · `cnc_list_topology_nodes` · `cnc_get_topology_node` · `cnc_list_node_interfaces` · `cnc_get_node_interface` · `cnc_list_topology_links` · `cnc_get_topology_link` |
| **TE state** (SR-PCE feed) | `cnc_get_te_summary` · `cnc_list_sr_policies` · `cnc_get_sr_policy` · `cnc_list_p2mp_policies` · `cnc_get_p2mp_policy` · `cnc_list_rsvp_te_tunnels` · `cnc_get_rsvp_te_tunnel` · `cnc_get_link_performance_metrics` · `cnc_get_sr_policy_performance_metrics` · `cnc_get_rsvp_tunnel_performance_metrics` |
| **SR-TE operations** (Optimization Engine) | `cnc_list_sr_policies_on_nodes` · `cnc_list_sr_policies_on_interface` · `cnc_get_sr_policy_routes` · `cnc_get_sr_policy_metrics` · `cnc_preview_sr_policy_route` · `cnc_dryrun_sr_policy` · `cnc_get_sr_policy_path_notification_state` · `cnc_wait_for_sr_policy_oper_state` |
| **Platform** | `cnc_list_tags` · `cnc_list_users` · `cnc_list_applications` · `cnc_list_alarms` · `cnc_list_inventory_jobs` · `cnc_get_inventory_job` · `cnc_wait_for_inventory_job` |
| **Data Gateway** | `cnc_list_data_gateways` · `cnc_get_data_gateway` · `cnc_list_data_gateway_pools` · `cnc_get_data_gateway_load_metrics` · `cnc_list_data_gateway_outages` · `cnc_get_data_gateway_health` · `cnc_get_data_gateway_global_parameters` · `cnc_list_data_destinations` · `cnc_list_data_gateway_files` |
| **NSO** | `cnc_is_nso_configured` · `cnc_get_nso_policy` · `cnc_list_nso_devices` · `cnc_get_nso_device` · `cnc_check_device_nso_state` · `cnc_check_nso_device_sync` · `cnc_get_nso_device_config` · `cnc_wait_for_device_nso_state` |
| **Inventory extras** | `cnc_get_device_summary` · `cnc_get_inventory_config` · `cnc_get_collection_cadence` · `cnc_get_device_tags` |
| **Fault** | `cnc_get_alarm` · `cnc_search_alarms` · `cnc_list_events` · `cnc_list_device_alarms` · `cnc_get_alarm_settings` · `cnc_get_alarm_manager_settings` · `cnc_list_event_types` · `cnc_get_event_type_recommendation` · `cnc_list_alarm_suppression_policies` |
| **Device configuration** | `cnc_get_device_config_preferences` · `cnc_list_device_backups` · `cnc_get_device_backup` · `cnc_list_config_backup_jobs` · `cnc_get_config_backup_job` · `cnc_list_config_templates` · `cnc_get_config_template` · `cnc_list_template_deployments` · `cnc_get_template_deployment` · `cnc_wait_for_config_backup_job` · `cnc_wait_for_template_deployment` |
| **EMF inventory** | `cnc_list_ems_nodes` · `cnc_get_ems_node` · `cnc_list_ems_interfaces` · `cnc_get_ems_interface` · `cnc_get_ems_inventory_summary` |
| **Platform admin & RBAC** | `cnc_get_platform_version` · `cnc_get_cluster_health` · `cnc_list_cluster_nodes` · `cnc_get_cluster_node` · `cnc_list_microservices` · `cnc_list_application_status` · `cnc_list_app_manager_jobs` · `cnc_list_app_manager_events` · `cnc_get_maintenance_status` · `cnc_list_certificates` · `cnc_check_certificate_expiry` · `cnc_get_login_banner` · `cnc_get_session_config` · `cnc_list_active_sessions` · `cnc_get_user` · `cnc_list_roles` · `cnc_get_role_tasks` · `cnc_get_role_permissions` · `cnc_get_password_policy` · `cnc_list_secured_apis` |
| **Notifications** | `cnc_list_notification_streams` · `cnc_list_notification_subscriptions` · `cnc_get_notification_subscription` · `cnc_list_kafka_subscriptions` |
| **Collection service** | `cnc_get_collection_job_count` · `cnc_get_collection_job_summary` · `cnc_get_collection_job_state` · `cnc_list_export_collection_jobs` · `cnc_list_sensor_templates` · `cnc_get_collection_health` |
| **Device groups** | `cnc_list_group_rule_conditions` · `cnc_list_root_groups` · `cnc_get_group_hierarchy` · `cnc_get_group_details` · `cnc_list_group_devices` |
| **LCM & Circuit-Style** (Optimization Engine) | `cnc_list_lcm_domains` · `cnc_get_lcm_config` · `cnc_list_lcm_managed_interfaces` · `cnc_get_lcm_recommendation` · `cnc_get_lcm_recommendation_preview` · `cnc_list_csm_bandwidth_pools` · `cnc_list_cs_policy_paths` · `cnc_list_cs_policies_on_nodes` · `cnc_list_cs_policies_on_interface` |
| **Services** (CAT inventory, T-SDN) | `cnc_list_service_types` · `cnc_get_service_counts` · `cnc_list_services` · `cnc_get_service` · `cnc_get_service_plan` · `cnc_wait_for_service_plan` · `cnc_list_vpn_services` · `cnc_get_vpn_service` · `cnc_get_vpn_service_health` · `cnc_get_vpn_underlay_transport` · `cnc_list_sub_services` · `cnc_find_services_on_transport` · `cnc_list_function_packs` |
| **Performance monitoring** (PM policies, dashboards, NPM) | `cnc_list_performance_policies` · `cnc_get_performance_policy` · `cnc_get_performance_policy_history` · `cnc_list_performance_policy_devices` · `cnc_list_performance_policy_templates` · `cnc_get_performance_retention` · `cnc_get_performance_health_settings` · `cnc_get_performance_statistics` · `cnc_get_performance_top_n` · `cnc_list_performance_top_n_columns` · `cnc_get_performance_summary` · `cnc_get_lsp_utilization` · `cnc_get_lsp_delay` · `cnc_get_interface_delay` |
| **OAM & probes** | `cnc_get_oam_settings` · `cnc_list_oam_trace_routes` · `cnc_get_oam_trace_route` · `cnc_wait_for_oam_trace_route` · `cnc_get_probe_status` |
| **SWIM & ZTP** | `cnc_get_swim_preferences` · `cnc_list_software_images` · `cnc_get_device_running_images` · `cnc_get_swim_job` · `cnc_list_ztp_profiles` · `cnc_list_ztp_devices` · `cnc_list_ztp_serial_numbers` · `cnc_list_ztp_static_routes` · `cnc_get_ztp_device_policy` · `cnc_list_ztp_config_files` · `cnc_list_ztp_images` |
| **EMS inventory scheduler** | `cnc_list_inventory_scheduler_jobs` · `cnc_get_inventory_scheduler_job` · `cnc_wait_for_inventory_scheduler_job` |

Write tools — registered only with `CNC_MCP_ENABLE_WRITES=true`; deletes carry
the MCP `destructive` annotation:

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
| **Fault** | `cnc_acknowledge_alarm` · `cnc_annotate_alarm` · `cnc_clear_alarm` · `cnc_create_alarm_suppression_policy` · `cnc_delete_alarm_suppression_policy` |
| **Device configuration** | `cnc_backup_device_config` · `cnc_delete_config_backup_job` · `cnc_delete_device_backup` · `cnc_create_config_template` · `cnc_delete_config_template` · `cnc_deploy_config_template` · `cnc_delete_template_deployment` |
| **Notifications** | `cnc_create_webhook_subscription` · `cnc_delete_notification_subscription` |
| **LCM** | `cnc_pause_lcm_recommendations` |
| **Service provisioning** (NSO proxy, T-SDN CFPs) | `cnc_create_odn_template` · `cnc_delete_odn_template` · `cnc_create_sr_policy_service` · `cnc_update_sr_policy_service` · `cnc_delete_sr_policy_service` · `cnc_create_sid_list` · `cnc_delete_sid_list` · `cnc_create_l3vpn_service` · `cnc_delete_vpn_service` · `cnc_provision_service` · `cnc_delete_service` · `cnc_resync_service_inventory` |
| **OAM & probes** | `cnc_start_oam_trace_route` · `cnc_reactivate_probe` |
| **EMS inventory scheduler** | `cnc_run_inventory_scheduler_job` · `cnc_suspend_inventory_scheduler_job` · `cnc_resume_inventory_scheduler_job` |

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
  to correlate.

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
forces a read-only/destructive/idempotent decision, and refuses to register
write tools unless writes are enabled. POSTs are not auto-retried on 5xx
(a lost response might mean the write happened) unless a tool explicitly
marks the call safe to re-send. Tools never raise: every failure is returned
as an `Error: …` string with the platform's reason, and secrets never appear
in logs, errors, or output beyond what the platform itself masks.

## Configuration

Environment variables (or a `.env` file), prefix `CNC_MCP_`:

| Variable | Default | Purpose |
|---|---|---|
| `CNC_MCP_BASE_URL` | (required) | CNC UI/API URL **with scheme**, e.g. `https://host:30603` |
| `CNC_MCP_USERNAME` / `CNC_MCP_PASSWORD` | — | Crosswork user; CAS SSO → JWT, refreshed automatically |
| `CNC_MCP_API_TOKEN` | — | Alternative: a pre-issued JWT (cannot be refreshed; expires in ~8 h) |
| `CNC_MCP_VERIFY_TLS` | `true` | `false` for self-signed lab certificates |
| `CNC_MCP_ENABLE_WRITES` | `false` | **Write tools are not registered until `true`** |
| `CNC_MCP_TIMEOUT_SECONDS` | `30` | Per-request read timeout |
| `CNC_MCP_MAX_RETRIES` | `3` | Retries for 429 / 5xx / transport errors (idempotent calls) |
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
running IS-IS + SR-MPLS, one of them acting as SR-PCE (BGP-LS + PCEP, feeding
CNC over gRPC) with two PCE-delegated SR policies between the PEs, gNMI
onboarded on every router, `mpls oam` and a vpnv4 iBGP pair on the PEs (so an
L3VPN can be committed through the T-SDN function pack and traced end to end). Each
module was also adversarially reviewed against the recorded facts before it
was merged; that review caught bugs the tests had enshrined (a "not found"
check that would have hidden an absent API, an NSO failure that would have
read as success).

## Platform facts that shaped the design

These are the behaviours that differ from what the published OpenAPI
documents suggest and that a client must get right. The full record lives in
a platform-notes file kept outside this repository.

- **No 401s.** Rejected or expired tokens are `403 "Unauthorized request"`;
  JWT-shaped garbage is `500 "Middleware error"`. The same 403 body is also
  what a valid token gets on an unknown path.
- **`offset` is ignored.** Inventory `…/query` honours `limit` but silently
  ignores `offset`; real paging is `filterData.PageSize` / `PageNum`.
- **Unknown filter fields are ignored** (the whole collection comes back) on
  inventory, while dg-manager rejects them with `400 unable to unmarshal
  payload to proto`. Two grammars exist inside dg-manager itself.
- **Failed writes are HTTP 200** with `state: JOB_FAILED` in a job envelope;
  `JOB_COMPLETED_WITH_WARNING` is a success with an advisory. Update is
  `PATCH`, delete takes a JSON body; path-parameter forms do not exist.
- **Response envelopes differ per endpoint** (`data`, `tags`, `jobs`,
  `providers`, a dict keyed by username, `application_summary_list`, bare
  `{}` when empty).
- **RESTCONF NBI**: a keyed GET on a top-level list may ignore the key and
  return everything; a missing nested entry is `409 data-missing`, never 404;
  errors use a bare `errors` key (NSO's proxy uses the standard
  `ietf-restconf:errors`); RPC failures ride inside HTTP 200 as
  `output.status: "error"` (COE) or `result: false` (NSO).
- **NSO device actions are fire-and-forget.** `POST /inventory/v1/nso/<action>`
  answers `JOB_ACCEPTED` at once and never validates its node filter, so a
  typo matches nothing and still "succeeds"; the outcome only appears in the
  device's `nso_state` a few seconds later. The tools resolve the selector to
  at least one device first and hand back the timestamp to wait from.
  `nso/sync` is global: the body is ignored and every device is re-checked.
- **A 404 means "no such route"**, never "no such object": the home
  application's fallback page identifies an API that is not installed on the
  deployment (Service Health, Change Automation and Health Insights are
  absent on single-VM builds).
- **CNC 7.x learns the topology from an SR-PCE over gRPC**, not the HTTP
  `/topo/subscribe/json` feed of earlier releases: the router needs
  `lslib-server` and `grpc … service-layer`, and the provider needs **both** an
  HTTP and a GRPC endpoint (plus a gRPC credential). With HTTP only the
  provider reports "Reachable" forever while the topology stays L2-only —
  the HTTP leg is just the reachability probe (and RSVP/Tree-SID/PCEP data).
  The HTTP leg itself must use `authentication digest` on the router.
- **The Optimization Engine rejects bad input with a bare, empty 500** — the same
  answer as an absent backend — so the SR-TE tools validate node names, router-ids
  and explicit hops against the topology before every RPC, and explicit hops are
  sent with both the address *and* the prefix-SID (the documented one-of does not
  work). Failures otherwise ride inside HTTP 200 (`results[].state: failure` with
  the platform's message, e.g. "SR Policy name is empty.").
- **Crosswork caps concurrent SSO sessions per user** (API sessions idle out after
  8 h by default); the client deletes its ticket-granting ticket on close so a
  restart loop or a run of scripts cannot lock the service account out.
- **Topology NBI keys must be fully percent-encoded** (interface names carry
  `/`, link ids carry spaces and `:`); an unencoded `/` breaks the route and
  the gateway answers a plain 404, while a properly encoded key that matches
  nothing answers `409 data-missing`. The keyed `network=<id>` GET returns a
  *shallow* topology (no IS-IS/SR attributes) — only the collection GET is
  complete, so the tools fetch the collection and select the network
  client-side. Performance-metric containers cannot be listed, only read by
  key, and exist for IGP links and policies only.
- **Webhook subscriptions need an explicit port** in the client URL
  (`http://host:80/path`); without one the notification service answers a
  bare 500. The receiver must answer 2xx or the subscription is created and
  then dropped. A duplicate (same topic, URL and format) is refused with the
  existing subscription's id.
- **The collection service reports rejections inside HTTP 200**
  (`result.request_result: REJECTED` with `result.error.error`), and a sensor
  template lookup that matches nothing — the documented wildcard included —
  is one such rejection ("Template for the given TemplateId does not exist"),
  which the tools report as an empty result. Application-context queries need
  both `application_id` and `context_id`; the built-in DLM job is
  `cw.dlminvmgr0` / `dlm/cli-collector/group/te-tunnel-id/subscription`.
- **Device grouping answers an empty list for an unknown classifier** rather
  than an error, and the group-detail RPC takes the group's UUID (the root
  groups are read by classifier name, e.g. `PortType`).
- **NSO's RESTCONF dry-run works through the proxy** (`?dry-run=native`
  answers the exact device CLI NSO would push, and the function pack's
  validation runs too), so every provisioning tool takes `dry_run`. The CAT
  inventory reports the SR policy service type under its own namespace
  (`cisco-ts-sr-policies`), not the YANG module's; a head-end NSO considers
  out of sync answers `502 "device X: out of sync"` (sync-from first); a SID
  list still referenced by a policy cannot be deleted; and an L3VPN without
  `local_as` on its endpoints is rejected with `TSDN-L3VPN-415` unless the PE
  already runs BGP — with `local_as` the function pack renders `router bgp`
  itself.
- **Performance dashboards name metrics `<SCHEMA>_<metric>`** with the exact
  metric names of the policy templates (`CEPMINTERFACE_ifInBitsRate`, not
  `INTERFACE_…`), page from 1, want ISO timestamps with milliseconds, and
  answer a Spring envelope whose `message` is a code (`INVALID_SCHEMA`,
  `MISSING_TIME_DETAILS`, …). The NPM analytics service never validates its
  keys: an unknown LSP or interface answers the same empty list as "no data",
  so the tools refuse host names and a zero colour before sending anything.
- **OAM trace routes need the full request form** (yang-path, both inventory
  uuids, service type and name, node names and TE router-ids — with only the
  uuids the engine answers "No path found" without tracing), gNMI
  connectivity to the routers and `mpls oam` on them; they report their
  verdict in a status code rather than an HTTP error. A successful trace
  returns every ECMP path with per-hop labels and LSP-ping return codes.
- **Onboarding gNMI on a device takes three PATCHes**: the capability cannot
  change while the device is admin-up and attached to a Data Gateway, so the
  tool bounces it admin-down, adds the `ROBOT_MSVC_TRANS_GNMI` transport
  (whose `encoding_type` is mandatory) plus the `GNMI` capability, and brings
  it back up. The credential profile must already carry a gNMI login — and a
  credential PUT is a full replace: an entry left out is removed.
- **CAT's VPN operational reads need `content=nonconfig`** (the batch list
  answers 409 without it even when services exist; `/status/oper-status` is
  never readable as a sub-path — only the service node itself).
- **The EMS job scheduler takes raw text bodies** (`Failed Feature
  Sync:Inventory`, no JSON quoting) and answers a bare `true`/`false` with
  HTTP 200 either way; its job list refuses to answer without a `Range`
  header.

## Roadmap

The published CNC 7.2 API has ~950 operations across 103 OpenAPI documents;
this server covers the inventory (incl. tags, locks, locations), the EMF
inventory, topology, TE state, SR-TE operations, fault management, device
configuration (backups, templates, deployments), platform administration and
RBAC, Data Gateway, NSO, notifications (webhook / Kafka subscriptions), the
collection service, device grouping, the LCM / Circuit-Style managers, the
CAT service inventory and T-SDN service provisioning through the NSO proxy,
performance monitoring and NPM analytics, OAM trace routes and Service
Health probes, SWIM / ZTP reads and the EMS inventory scheduler.
Planned modules, in the order they become exercisable on a lab:

| Module | Scope |
|---|---|
| writes not yet exposed | performance policy create/activate, collection job create, SWIM collect/distribute/activate, ZTP writes, LCM/CSM configuration — unverified bodies with real network impact |
| not on this build | change automation, health insights, path analytics, service health (unrouted on a single-VM 7.2 deployment — a 404 from the home application; the error text names the missing application) |

## Project layout

```
src/cnc_mcp/
  server.py       assembly, auth selection, connect-time instructions
  auth.py         auth strategies incl. CrossworkCasAuth
  client.py       ApiClient: retries, re-auth, concurrency, raw bodies
  errors.py       PlatformError and the status/body → hint mapping
  config.py       Settings (env / .env)
  safety.py       register_tool(): annotations + write gating
  formatting.py   markdown/json response formats, pagination envelope, size cap
  polling.py      wait_until() for the wait_for_* tools
  crosswork.py    inventory query grammar, envelopes, job checks, enums, dg/collection/alarm helpers
  restconf.py     RESTCONF NBI helpers
  emf.py          EMF RESTCONF helpers
  probe.py        routing classification and availability probing
  tools/          devices, credentials, providers, inventory_extras, physical_inventory,
                  topology, te_state, sr_te_operations, platform, fault, device_config,
                  data_gateway, nso, admin, notifications, collection, grouping, lcm_csm,
                  services, service_provisioning, performance, oam, swim_ztp, ems_jobs
scripts/
  live_smoke.py             live tool-call plan runner (read / write phases, $var chaining)
  live_plumbing_check.py    live verification of the dialect helpers
  mcp_cli.py                call the server over the real MCP stdio protocol (list/schema/call)
  smoke_plan.example.json   sanitised smoke plan
tests/                      one test module per source module; respx-mocked
```

## Development

```bash
make test          # pytest (respx-mocked HTTP)
make lint          # ruff check
make fmt           # ruff format + autofix
make docker-build  # stdio server image; run with: docker run -i --rm --env-file .env cnc-mcp
```

To add a tool module: read `CLAUDE.md` (the conventions are non-negotiable),
copy the pattern of an existing module in `src/cnc_mcp/tools/`, register it
in `tools/__init__.py`, give every tool a happy-path and an error-path test,
add its calls to the smoke plan, and run the live smoke before merging.

## License

[MIT](LICENSE) © 2026 Mitchell McInnes
