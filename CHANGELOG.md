# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The release workflow uses the section for the tagged version as the GitHub
Release body, so every release needs its own `## [x.y.z] - date` heading.

## [Unreleased]

### Added

- **Playbook tools** (`tools/composite.py`): `cnc_investigate_device`,
  `cnc_network_health_report`, `cnc_explain_sr_policy`, `cnc_alarm_triage`,
  `cnc_explain_service` (reads) and `cnc_provision_l3vpn_e2e`,
  `cnc_create_sr_policy_e2e` (writes) — one call each, composed server-side
  from the existing tools: a verdict with reasons, one section per underlying
  tool, partial failures reported as unavailable sections, and an audit list
  of the calls made. Verified live (the L3VPN and SR-policy playbooks ran end
  to end on the lab and were reverted); blind-agent measurements cut a
  "device looks degraded" investigation from 44 tool calls and a network
  health overview from 25.
- **MCP prompts** (`prompts.py`): `troubleshoot_device`,
  `network_health_check`, `explain_sr_policy`, `provision_l3vpn`,
  `alarm_triage`, `explain_service` — operator playbooks that name the tools
  to use, adapt to whether the playbook tools are registered, and reject
  unknown arguments by name. `scripts/mcp_cli.py` gains `prompts` and
  `prompt <name>`.
- **Write allowlist, tool denylist and dry-run mode** (`config.py`,
  `safety.py`, `tools/__init__.py`), layered on `CNC_MCP_ENABLE_WRITES`:
  - `CNC_MCP_WRITE_AREAS` — comma-separated areas (the `tools/` module
    names: `fault`, `service_provisioning`, ...) whose write tools are
    registered when writes are on; empty means every area, read tools are
    never affected. A write playbook is registered only when the sibling
    that commits for it is (`register_tool(requires=...)`), the skip reason
    logged.
  - `CNC_MCP_DISABLED_TOOLS` — comma-separated tool names never registered,
    read or write.
  - `CNC_MCP_DRY_RUN=true` — the write tools stay registered but nothing
    changes on the platform: a tool with a `dry_run` argument runs with it
    forced to `true` and answers the preview; every other write is not
    executed and answers `NOT EXECUTED` with the (redacted) arguments it
    would have sent; each write tool's description says which applies. If
    the wrapper cannot be installed the write is removed rather than left
    live.
  - An unknown area or tool name fails startup as a configuration error
    with a "did you mean" hint; an allowlisted area whose tools are all
    read-only is a warning. The startup log summarises what was registered
    (`Registered N of M tools (R read, W write); writes ...; disabled tools:
    ...; dry-run ...`), and the connect-time instructions and the prompts
    describe the mode in force and why an absent write tool is absent.
- **`cnc_check_permissions`** (`tools/admin.py`, read-only): reads the
  account's identity from the session JWT, its role through the
  `aaaread/v1` mirror (falling back to `aaa/v1`), and evaluates every
  registered tool against the role's gateway grants using the packaged
  RBAC map (`src/cnc_mcp/data/rbac_map.json`) — the verdict, the API rows
  and methods to grant, the refused tools by area, and the server's own
  safety mode (writes / areas / dry-run / disabled tools / tools
  registered) next to the role. The 403 hint now points at it.
- **`docs/RBAC.md`, `docs/rbac/*.role.json` and `scripts/rbac_map.py`**: the
  least-privilege recipe for a read-only account and what each write area
  adds, a per-tool table, the task-checkbox bundles, and ready-made role
  bodies — all generated from the tool source, the gateway's secured-API
  catalogue and the platform's stored-role behaviour (`make rbac`, offline;
  `make rbac-fetch`, live; `make rbac-check` fails CI when a tool changed
  without regenerating).
- **Playbook `dry_run`**: `cnc_provision_l3vpn_e2e` and
  `cnc_create_sr_policy_e2e` take `dry_run=true` to stop after their
  preview stage with a `dry-run` verdict and nothing committed; global
  dry-run mode forces it.
- **`scripts/mcp_cli.py --env NAME=VALUE`** (repeatable, before or after the
  command): start the server with extra environment variables — the way to
  try an allowlist, a denylist or dry-run mode without editing `.env`.

### Changed

- Verified with a user on the generated read-only role (2026-09-15): the
  read smoke answered 262 read calls, every predicted refusal answered 403
  and nothing unpredicted did; `cnc_check_permissions` predicted the same
  14 tools. `errors.py` now explains Tyk's two refusal bodies ("Access to
  this API has been disallowed" = the API is not in the role; "Access to
  this resource has been disallowed" = the path/method is not covered) and
  neither triggers a re-login. A user on the generated operator role then
  ran the full read + write smoke (432 steps, every created object removed
  again) with no refusal. The smoke runs were on the previous generation of
  the bodies, which differed only in the two AAA rows — `aaa_cwaaa` a GET
  pattern limited to the paths the tools send then, `/.*` now;
  `aaa_cw_role_read` in the body then, left to the baseline row now —
  `versions` and the `rate` field, and their refusal predictions are
  identical; the bodies as committed were then stored and read back (below)
  and give the same verdict for every tool.
- The RBAC map, `docs/RBAC.md` and the `docs/rbac/*.role.json` bodies now
  follow how Crosswork's role editor submits a role and how the AAA service
  stores it, both verified live (2026-09-14: test roles stored through an
  admin session and read back; 2026-09-15: a role built in the UI's role
  editor read back through the API, the editor's own role model read from
  the UI bundle, and the two generated bodies as committed PUT through an
  admin session and read back). Per ticked
  row the editor sends ONE `{url: "/.*", methods: <union>}` entry — Read
  adds `GET`, Write adds `POST, PUT, PATCH`, Delete adds `DELETE` — with
  `versions []` and its default role fields (`rate 1000`), and a row in the
  editor is a **display-name group** (one tick grants every api_id sharing
  the name; the UI cannot grant a single api_id of a group, the API can).
  The service stores those entries verbatim, appends the platform's per-API
  **read templates** (extra POST entries for that API's read-by-POST paths,
  `/.+/query$` and the like) to a GET-only row, and adds three **baseline
  rows** to every role — `aaa_cw_role_read` (the account's own role through
  the read-only mirror, with its query template), `aaa_cwpassword`,
  `aaa_selected_pref` — so the bodies never carry them. One more rule, seen
  when the operator body was read back: on the APIs on which the service
  reserves a last segment `delete` for the Delete tick (presumably the ones
  that delete through `POST .../delete`; no tool POSTs such a path), a row
  whose single entry carries POST without DELETE (Write without Delete —
  the entry the editor submits) is **split**: POST moves to a second entry
  under a pattern that permits every path except one whose last segment is
  the word `delete`, and the entry keeps its other methods in alphabetical
  order (`[GET, POST, PUT, PATCH]` → `[GET, PATCH, PUT] /.*` + `[POST]
  <pattern>`). Verified on `cwcollection`, `optima_restconf` and
  `platform_cwplatform`; inferred for the seven other APIs on which a
  2026-09-14 POST-only experiment stored the same split — the custom-url
  entry kept with its methods stripped to `[]`, the pattern entry appended
  (`collection_dg-manager`, `cw-fault-alarms-api`, `cw-fault-events-api`,
  `cw-probe-mgr`, `cw-ztp-service`, `dg-manager-global-parameters-api`,
  `optima_analytics_api`); the generator stops when the map's list carries
  an API in neither group. Read and Write submitted as two entries (and, in
  the same 2026-09-14 submission, a custom GET beside a custom POST — the
  split keys on the row having a single entry), and rows carrying DELETE,
  were stored verbatim. Consequence: Write without
  Delete on those APIs still permits every POST except a path ending in
  `/delete` — for the Optimization Engine the delete RPC is
  `...:sr-policy-delete`, one segment, so an operator role without Delete
  can still create and delete SR policies there; the guide quotes the
  pattern and says so. The bodies are the
  shape the editor submits: one `/.*` entry per api_id with the union of
  the row's ticks in the editor's order, the editor's role fields (`rate
  1000`/`per 60` is the gateway's per-key rate limit, the editor's default),
  no custom URL anywhere (a role whose first entry on some api_id has a url
  other than `/.*` crashes the Roles page for everyone — `docs/RBAC.md`
  section 1 carries the warning).
  The editor displays a display-name group as its first api_id in
  `aaa/v2/api` order and rebuilds the group on Save (read from the UI
  bundle), so an API-loaded role is managed through the API — the guide
  names the six rows the bodies leave visibly unticked. The map now records
  each api_id's `position` in `aaa/v2/api` (regenerate once with
  `--catalogue-dir` or live after upgrading), and `--read-templates`
  refuses a capture in the previous format (baseline rows listed among the
  read templates) instead of loading it silently. The read-only body is
  the Read tick on 42 rows, the operator body adds Write/Delete where a
  tool needs them (46 rows); the `aaa_cwaaa` row ("Users and Roles
  Management") is what the RBAC read tools need and the guide says which 10
  tools dropping it refuses.
  The map carries the captured templates, baseline rows, POST-delete APIs
  and the not-delete pattern in a `platform` block (`scripts/rbac_map.py
  --read-templates <capture>`; offline runs reuse it), classifies every
  requirement as the R/W/D tick that permits it (a POST is Read only where
  the API's template names it), and `tests/fixtures/rbac/` pins the
  stored-role model, entry for entry and in stored order, against the five
  real read-backs (the two generated bodies as committed,
  `stored_generated_readonly.json` / `stored_generated_operator.json`, the
  UI-built role and the two API-stored experiments; the read-back of the
  earlier custom-URL body was deleted with that shape). Evaluated on what
  the service stored, `cnc-mcp-readonly` permits 168 of the 182 read tools
  and `cnc-mcp-operator` all 245 — the same verdict as the model's, tool
  for tool; the generator says so in the guide and warns when a read-back
  no longer matches the committed body's stored form, row for row and in
  stored order, or its verdict (a fixture of a previous body can keep the
  verdict while its rows differ, as the previous generation's did; the
  warning names the rows). The 14 read tools that read through
  a POST outside their API's template (NSO check-sync, config-backup jobs,
  sensor templates, the OAM / SR-policy-metrics / SR-policy
  path-notification state / LCM-preview RPCs; docs/RBAC.md section 2 lists
  them) are listed with the two options (tick Write there, or
  `CNC_MCP_DISABLED_TOOLS`), and `cnc_reactivate_probe` is noted as a write
  the Read tick permits. The guide's "Not verified" list now says exactly
  what is read from the bundle or extrapolated rather than observed;
  `cnc_check_permissions` says the same.
- `cnc_get_lsp_utilization` / `cnc_get_lsp_delay` default `hours` is now 6
  (was 24): the largest window NPM answers with raw 5-minute samples, and
  the window `cnc_explain_sr_policy` reads, so a drill-in lands on the same
  series. Pass `hours=24` for the hourly roll-ups.
- `cnc_list_sr_policies` with no headend/endpoint filter now reads the
  topology once so the rows carry host names next to the TE router-ids
  (one extra GET; a failed read degrades to router-ids with a footer).
- `cnc_list_inventory_jobs` renders `created=` / `completed=` as ISO-8601
  UTC with an `age=`, like the alarm lines (the JSON view keeps the raw
  epoch seconds).
- Performance collection-status caveats now describe the method that
  proves sample delivery (a 1-hour statistics window) instead of pointing
  at a "newest sample time" the statistics tool does not return; the
  topology PCEP-session text separates what is verified (no state leaf)
  from what is assumed (down sessions omitted).

## [0.1.0] - 2026-09-14

Initial public release: an MCP server (official MCP Python SDK 2.x, stdio
transport) for Cisco Crosswork Network Controller 7.2 with **237 tools**
(176 read, 61 write) over 24 API areas. Every tool was built from behaviour
verified against a live CNC 7.2.0 instance rather than from the published
OpenAPI documents alone.

### Added

- **Authentication**: Crosswork's two-leg CAS SSO (ticket-granting ticket →
  service-ticket JWT, ~8 h) as a Bearer token, with one transparent
  re-authentication when the platform rejects the token. Crosswork answers
  `403 "Unauthorized request"` (or `500 "Middleware error"`), never 401, so
  the auth strategy decides what counts as an auth failure. The
  ticket-granting ticket is deleted on shutdown so a restart loop cannot
  exhaust the per-user session cap. A pre-issued JWT (`CNC_MCP_API_TOKEN`)
  is accepted as an alternative.
- **API dialect helpers** for the services behind the single gateway:
  JSON-over-POST `…/query` grammars (`crosswork.py`: `filterData`
  paging, per-endpoint envelopes, job-envelope checks, the dg-manager and
  collection-service variants), RESTCONF NBI (`restconf.py`: percent-encoded
  keys, both error-document shapes, `409 data-missing` as not-found, RPC
  failures carried inside HTTP 200), EMF RESTCONF (`emf.py`: exact-`Accept`
  requirement, `startIndex`/`maxCount` paging, the `com.*` envelope) and a
  routing probe (`probe.py`) that tells an unrouted application apart from a
  real 404.
- **Tool modules** (one per API area), all registered through
  `safety.register_tool()` so annotations and write gating are enforced:
  - devices (incl. gNMI onboarding and a reachability wait), credential
    profiles (create/update/delete; PUT is a full replace), providers
  - inventory extras: device summary, inventory config, collection cadence,
    tags, geo-locations, device locks
  - EMF physical inventory: nodes, termination points, summary
  - topology on the RESTCONF NBI: networks, nodes, interfaces, links
  - TE state from the SR-PCE feed: SR / P2MP (Tree-SID) / RSVP-TE policies
    and tunnels, link and policy performance metrics, a one-call summary
  - SR-TE operations through the Optimization Engine: policies on nodes /
    interfaces, routes and metrics, route preview, dry run, create / update /
    delete (PCE-initiated), path notifications, an oper-state wait
  - platform: tags, users, applications, alarms, inventory jobs and a job wait
  - fault management: alarm get / search / events / device alarms, settings,
    event-type catalogue, suppression policies; acknowledge / annotate / clear
  - device configuration: preferences, backups and backup jobs, configuration
    templates and deployments (with waits and the CLI transcript)
  - Data Gateway (dg-manager): gateways, pools, load metrics, outages, health,
    global parameters, data destinations, files, device mapping
  - NSO through the Crosswork proxy: configured / policy checks, NSO's device
    view, per-device `nso_state`, the asynchronous DLM device actions
    (check-sync, sync-from, connect, compare-config, …), sync-to, the global
    inventory re-sync, a timestamp-keyed wait, the CDB copy of a device's
    configuration
  - platform administration and RBAC: version, cluster / node / microservice
    health, application status, app-manager jobs and events, maintenance
    mode, certificates and expiry check, login banner, session config, active
    sessions (ticket ids shortened), users, roles, task permissions, password
    policy, secured APIs; microservice restart
  - notifications: RESTCONF notification streams, webhook / Kafka
    subscriptions, webhook create and delete
  - collection service: job count / summary / state, a one-call health check,
    export jobs, sensor templates
  - device grouping: rule conditions, root groups, hierarchy, group details
    and devices
  - LCM and Circuit-Style Manager: domains, config, managed interfaces,
    recommendations and previews, pause; CSM bandwidth pools and circuit-style
    policy paths
  - services (CAT inventory, T-SDN): service types, counts, listing, service
    intent, plan data and a plan wait, VPN operational data and health,
    underlay transport, sub-services, transport-to-service association,
    function packs
  - service provisioning through the NSO proxy (T-SDN function packs): ODN
    templates, SR policy services, SID lists, L3VPN, generic
    provision / delete for any T-SDN model, CAT resync — every write takes
    `dry_run` (`?dry-run=native` returns the device CLI without committing)
  - performance monitoring: PM policies, history, devices, templates,
    retention, health settings, dashboard statistics / top-N / summary, NPM
    LSP utilization / delay and interface delay
  - OAM and probes: OAM settings, trace routes (list / get / start / wait,
    full request form with every ECMP path rendered hop by hop), Service
    Health probe status and reactivation
  - SWIM and ZTP: SWIM preferences, image repository, running images, jobs;
    ZTP profiles, devices, serial numbers, static routes, device policy,
    config files, images
  - EMS inventory scheduler: job list / get / run / suspend / resume / wait
- **Agent ergonomics**: flat, typed parameters with examples and constraints;
  unknown argument names rejected by name with a "did you mean" hint;
  `response_format` of `markdown` (curated) or `json` (complete) on every
  tool; a `{total, count, page, page_size, has_more, next_page, items}`
  pagination envelope; friendly enum values alongside the wire values; host
  names accepted wherever a TE router-id is the wire key; `wait_for_*` tools
  that poll server-side; a size cap that keeps truncated JSON parseable;
  connect-time instructions describing the platform's id conventions and
  ordering rules (credential profile → provider → device).
- **Safety**: write tools are not registered unless
  `CNC_MCP_ENABLE_WRITES=true`; deletes and overwrites carry the MCP
  `destructive` annotation; POSTs are not auto-retried on 5xx unless a tool
  marks the call safe to re-send; tools never raise — every failure is an
  `Error: …` string carrying the platform's own reason; secrets submitted to
  the credential-profile tools are scrubbed from error text before it is
  truncated; httpx request logging is capped at WARNING because the second
  CAS leg's URL carries the ticket-granting ticket.
- **Verification tooling**: `scripts/live_smoke.py` (read / write phases,
  `$var` chaining of captured ids; the private plan is gitignored and a
  sanitised `smoke_plan.example.json` is included), `scripts/live_plumbing_check.py`
  (every dialect helper exercised against the instance) and
  `scripts/mcp_cli.py` (drives the server over the real MCP stdio protocol:
  `instructions` / `list` / `schema` / `call`).
- **Coverage report**: `docs/COVERAGE.md`, generated by
  `scripts/api_coverage.py` from the published CNC 7.2 OpenAPI documents
  (kept outside the repository) — every documented operation, whether a
  registered tool sends it, and if not why — with `docs/platform-facts.md`
  listing the verified platform behaviours the client is built around.
- **Packaging and release**: PEP 639 metadata in `pyproject.toml` (`license`
  expression and `license-files`, classifiers, keywords); `make build`
  (wheel + sdist) and `make cli` (drive the server over MCP stdio) alongside
  `install`, `test`, `lint`, `fmt`, `run`, `inspect` and `docker-build`; a
  CI workflow running ruff and pytest on Python 3.11 and 3.12 plus a build
  job that starts the console script from the built wheel; a tag-triggered
  release workflow that checks the tag against `pyproject.toml`, creates
  the GitHub Release (this section as its body, wheel and sdist attached),
  pushes `ghcr.io/dr-stutters/cnc-mcp:<version>` and publishes to PyPI with
  trusted publishing once the `PUBLISH_TO_PYPI` repository variable is set.
- Dockerfile for a stdio server image, `.env.example` documenting every
  setting, `CONTRIBUTING.md` (conventions, verification layers, adding a
  module, releasing) and `SECURITY.md` (vulnerability reporting, credential
  handling, write gating, secrets in output, TLS, supply chain).

### Verified

- Instance: a single-VM CNC 7.2.0 deployment with embedded NSO and Data
  Gateway, fed by a Cisco Modeling Labs fabric of five IOS-XRd routers
  (IS-IS + SR-MPLS, one router as SR-PCE with BGP-LS + PCEP feeding CNC over
  gRPC, two PCE-delegated SR policies, gNMI on every router, `mpls oam` and a
  vpnv4 iBGP pair on the PEs).
- 2251 mocked unit tests (`respx`, no network): a happy-path test through the
  MCP server and an error-path test per tool.
- A 416-step live smoke plan, read and write phases, leaving the platform as
  found (create → verify → delete), and a 32-check live plumbing run.
- Two blind rounds of agent scenarios over the real MCP stdio protocol — ten
  operator tasks (health overview, traffic ranking, policy explanation,
  service audit, a "degraded device" investigation, and five
  provisioning / operations tasks with full cleanup); every reported point
  of friction became a fix (alarm triage rendering and sorting, unknown
  arguments rejected by name, host names accepted for router-id keys,
  modelled-vs-measured PM caveats, parseable truncation, NPM host names,
  cleared-alarm rendering, an NSO device-config read).
- Each module was adversarially reviewed against the recorded platform facts
  before it was merged.

### Known limits

- The Health Insights, Change Automation, Service Health and Path Analytics
  API prefixes are not routed on a single-VM CNC 7.2 deployment (the home
  application answers a 404 fallback page), so no tools cover them; a call
  that lands on such a prefix is reported with the missing application's
  name. The one exception is the Service Health probe manager, which is
  routed on that build: its status tool always answers "no active probe
  session" there, and the populated status shape and the reactivate answer
  follow the 7.2 document only (not verified live).
- SWIM holds no software-image inventory for containerised IOS-XRd
  (`DEVICE_SUPPORT_LEVEL_UNCERTIFIED`): its "Invalid Index" answer is
  reported by the running-images tool as "no software-image inventory". The
  lab's image repository and ZTP catalogues were empty, so the populated
  shapes of those reads follow the 7.2 document rather than a live answer.
- Writes that are documented but not exposed because their bodies could not
  be verified without real network impact: performance policy
  create / activate, collection job create, SWIM collect / distribute /
  activate, ZTP writes, LCM / CSM configuration (see the README roadmap).
- Data Gateway OAM ping / traceroute have no responders on the embedded
  gateway and are not exposed; the device-configuration run-a-command
  endpoint is shadowed by the template-name route on this build.
- Only a single-VM deployment was tested; multi-node clusters were not. The
  Docker image was not part of the live verification.

[Unreleased]: https://github.com/dr-stutters/cnc-mcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/dr-stutters/cnc-mcp/releases/tag/v0.1.0
