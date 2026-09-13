# cnc-mcp

MCP server for **Cisco Crosswork Network Controller (CNC)** — device inventory,
credential profiles, providers (SR-PCE, NSO, …), the topology graph, tags,
alarms, users, installed applications, inventory jobs, and Crosswork Data
Gateways (gateways, pools, load metrics, destinations, device mapping). Official MCP Python
SDK 2.x, stdio transport. Built and verified live against a CNC 7.x lab fed by
a CML/XRd SR-MPLS fabric with an SR-PCE.

## Quickstart

Requires [uv](https://docs.astral.sh/uv/) and a Crosswork user (see
[Account privileges](#account-privileges)).

```bash
make install                      # uv sync
cp .env.example .env              # then set CNC_MCP_BASE_URL / USERNAME / PASSWORD
make test && make lint            # all HTTP mocked; no live platform needed
make run                          # start on stdio
make inspect                      # MCP Inspector against the server
```

Claude Desktop / `.mcp.json`:

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

Put the credentials in `.env` (never in the JSON). Write tools stay hidden until
`CNC_MCP_ENABLE_WRITES=true`.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `CNC_MCP_BASE_URL` | (required) | CNC UI/API URL **with scheme**, e.g. `https://host:30603` |
| `CNC_MCP_USERNAME` / `CNC_MCP_PASSWORD` | — | Crosswork user; two-leg CAS SSO → 8 h JWT, refreshed automatically |
| `CNC_MCP_API_TOKEN` | — | Alternative: a pre-issued JWT (cannot be refreshed) |
| `CNC_MCP_VERIFY_TLS` | `true` | `false` for self-signed lab certificates |
| `CNC_MCP_ENABLE_WRITES` | `false` | **Write tools are not registered until `true`** |
| `CNC_MCP_TIMEOUT_SECONDS` … | see `.env.example` | Timeouts, retries, concurrency, response cap |

## Tools

Read tools (always registered):

| Area | Tools |
|---|---|
| Devices | `cnc_list_devices`, `cnc_get_device`, `cnc_get_device_collection_summary`, `cnc_wait_for_device_reachable` |
| Credential profiles | `cnc_list_credential_profiles`, `cnc_get_credential_profile` |
| Providers | `cnc_list_providers`, `cnc_get_provider` |
| Topology | `cnc_get_topology_summary`, `cnc_get_topology`, `cnc_list_topology_nodes`, `cnc_list_topology_links` |
| Platform | `cnc_list_tags`, `cnc_list_users`, `cnc_list_applications`, `cnc_list_alarms`, `cnc_list_inventory_jobs`, `cnc_get_inventory_job`, `cnc_wait_for_inventory_job` |
| Data Gateway | `cnc_list_data_gateways`, `cnc_get_data_gateway`, `cnc_list_data_gateway_pools`, `cnc_get_data_gateway_load_metrics`, `cnc_list_data_gateway_outages`, `cnc_get_data_gateway_health`, `cnc_get_data_gateway_global_parameters`, `cnc_list_data_destinations`, `cnc_list_data_gateway_files` |

Write tools (`CNC_MCP_ENABLE_WRITES=true`):

| Area | Tools |
|---|---|
| Devices | `cnc_create_device`, `cnc_update_device`, `cnc_delete_device` |
| Credential profiles | `cnc_create_credential_profile`, `cnc_delete_credential_profile` |
| Providers | `cnc_create_provider`, `cnc_update_provider`, `cnc_delete_provider` |
| Data Gateway | `cnc_map_devices_to_data_gateway` |

Conventions the tools follow (and that the server tells agents about):

- List tools page with `page_size` / `page` (0-based) and return
  `{total, count, page, page_size, has_more, next_page, items}`; `total` counts
  matches for the filter, `collection_total` the whole collection.
- Filters are exact-match, case-insensitive, with `*` as a wildcard.
- Enum inputs accept friendly values (`admin_state="up"`, `family="sr_pce"`,
  `protocol="ssh"`) or the platform's wire values.
- Writes return Crosswork's job envelope; a job the platform rejected is
  reported as `Error: …` with the platform's reason.
- Ordering: credential profile → provider → device. A device's `te_router_id`
  must match its router-id in the SR-PCE topology for the two to correlate.

## Account privileges

A user with the `admin` role was used for verification. Read tools need the
inventory, topology, alarm, and AAA read tasks; write tools need inventory
write. Crosswork returns the same "Invalid credentials" for a wrong password
and for a non-existent user — confirm the account under Administration ›
Users and Roles first.

## Live smoke test

`scripts/smoke_plan.json` targets the lab described in the platform notes. The
read phase is side-effect free; the write phase creates `smoke-*` objects and
removes them again.

```bash
uv run python scripts/live_smoke.py            # read phase
uv run python scripts/live_smoke.py --write    # read + write phases
```

## Platform notes

Everything verified live about the CNC API (auth flow, the per-endpoint
response envelopes, the query grammar and its traps, SR-PCE integration) is
kept in the platform notes file outside this repo. Highlights that shaped the
code:

- Crosswork never answers 401: a bad token is `403 "Unauthorized request"`, a
  malformed one `500 "Middleware error"` — the auth strategy classifies those
  so the client re-authenticates.
- `POST …/query` bodies page with `filterData.PageSize/PageNum`; a top-level
  `offset` is silently ignored.
- Unknown filter field names are ignored and return the whole collection.
- Update is `PATCH`, delete takes a JSON body; path-parameter forms do not
  exist. Failed writes are HTTP 200 with `state: JOB_FAILED`.
- CNC authenticates to an SR-PCE's northbound API with HTTP **Digest**.
- The platform speaks several API dialects behind one gateway (JSON-over-POST,
  RESTCONF NBI, EMF RESTCONF); `restconf.py`, `emf.py` and `probe.py` encode
  their verified quirks, and `scripts/live_plumbing_check.py` re-verifies them.

## Development

```bash
make test        # pytest (respx-mocked HTTP)
make lint        # ruff
make fmt         # ruff format + autofix
make docker-build
```
