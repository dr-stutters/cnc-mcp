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

### Changed

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
