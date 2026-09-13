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
devices to gateways, and drive NSO sync and connect actions — all
through typed, documented tools with the platform's own error reasons surfaced
verbatim.

**59 tools** (47 read, 12 write) over 8 API areas. Every tool was built from
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
| **Platform** | `cnc_list_tags` · `cnc_list_users` · `cnc_list_applications` · `cnc_list_alarms` · `cnc_list_inventory_jobs` · `cnc_get_inventory_job` · `cnc_wait_for_inventory_job` |
| **Data Gateway** | `cnc_list_data_gateways` · `cnc_get_data_gateway` · `cnc_list_data_gateway_pools` · `cnc_get_data_gateway_load_metrics` · `cnc_list_data_gateway_outages` · `cnc_get_data_gateway_health` · `cnc_get_data_gateway_global_parameters` · `cnc_list_data_destinations` · `cnc_list_data_gateway_files` |
| **NSO** | `cnc_is_nso_configured` · `cnc_get_nso_policy` · `cnc_list_nso_devices` · `cnc_get_nso_device` · `cnc_check_device_nso_state` · `cnc_wait_for_device_nso_state` |

Write tools — registered only with `CNC_MCP_ENABLE_WRITES=true`; deletes carry
the MCP `destructive` annotation:

| Area | Tools |
|---|---|
| **Devices** | `cnc_create_device` · `cnc_update_device` · `cnc_delete_device` |
| **Credential profiles** | `cnc_create_credential_profile` · `cnc_delete_credential_profile` |
| **Providers** | `cnc_create_provider` · `cnc_update_provider` · `cnc_delete_provider` |
| **Data Gateway** | `cnc_map_devices_to_data_gateway` |
| **NSO** | `cnc_nso_device_action` (check-sync / sync-from / connect / compare-config …) · `cnc_nso_sync_to_device` · `cnc_sync_inventory_with_nso` |

Every tool has flat, typed parameters with examples and constraints, a
docstring that states when to use it, what it returns, and what each error
means, and a `response_format` of `markdown` (curated summary, the default)
or `json` (complete data). The `wait_for_*` tools poll server-side so an agent
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

Unit tests prove the code; only a live run proves the integration. Three
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
3. **Live plumbing check** (`scripts/live_plumbing_check.py`): exercises every
   dialect helper against the instance — the real 409, the real
   error-inside-200, the real XML fallback, the real routing signatures — so a
   platform change that breaks a verified assumption shows up before it
   breaks a tool.

The instance was a single-VM CNC 7.2.0 deployment with embedded NSO and
Data Gateway, fed by a Cisco Modeling Labs fabric of five IOS-XRd routers
running IS-IS + SR-MPLS, one of them acting as SR-PCE (BGP-LS + PCEP, feeding
CNC over gRPC) with two PCE-delegated SR policies between the PEs. Each
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
- **Topology NBI keys must be fully percent-encoded** (interface names carry
  `/`, link ids carry spaces and `:`); an unencoded `/` breaks the route and
  the gateway answers a plain 404, while a properly encoded key that matches
  nothing answers `409 data-missing`. The keyed `network=<id>` GET returns a
  *shallow* topology (no IS-IS/SR attributes) — only the collection GET is
  complete, so the tools fetch the collection and select the network
  client-side. Performance-metric containers cannot be listed, only read by
  key, and exist for IGP links and policies only.

## Roadmap

The published CNC 7.2 API has ~950 operations across 103 OpenAPI documents;
this server covers the inventory, topology, TE state, platform, Data Gateway
and NSO areas.
Planned modules, in the order they become exercisable on a lab:

| Module | Scope |
|---|---|
| `inventory_extras` | device counts and summaries, tags, device lock, sysoid catalogue |
| `services` | service inventory and VPN / SR-TE service reads (Crosswork Active Topology) |
| `fault` | migrate alarms to the RESTCONF fault API; acknowledge / clear; suppression policies |
| `device_config` | configuration backup / restore, templates, deployments |
| later | change automation, health insights, collection jobs, notifications, RBAC, optimization-engine operations |

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
  tools/          devices, credentials, providers, topology, te_state, platform, data_gateway, nso
scripts/
  live_smoke.py             live tool-call plan runner (read / write phases, $var chaining)
  live_plumbing_check.py    live verification of the dialect helpers
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
