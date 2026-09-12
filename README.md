# cnc-mcp

Copy-template for building platform MCP servers (official MCP Python SDK 2.x, stdio).

**Workflow**: copy this directory, then hand the copy to Claude — `CLAUDE.md`
contains the full specialization playbook. Keep platform-specific API notes in
a separate file outside the template and hand that to Claude alongside it.

## Creating a new platform server

```bash
cp -r cnc-mcp acme-mcp && cd acme-mcp
python3 scripts/specialize.py acme      # renames package, env prefix, tool prefix
# then ask Claude: "Build out this MCP server for <platform> per CLAUDE.md"
# (hand Claude your platform notes file too, if you keep one)
```

## Development

Requires [uv](https://docs.astral.sh/uv/).

```bash
make install     # uv sync (deps + dev tools)
make test        # pytest (all HTTP mocked; no live platform needed)
make lint        # ruff
make run         # start the server on stdio
make inspect     # open MCP Inspector against the server
```

## Configuration

Everything comes from env vars (prefix `CNC_MCP_`, renamed by specialize)
or a `.env` file — see [.env.example](.env.example). Key settings:

| Variable | Default | Purpose |
|---|---|---|
| `..._BASE_URL` | (required) | Platform API base URL |
| `..._USERNAME` / `..._PASSWORD` | — | Credentials (or `..._API_TOKEN`) |
| `..._VERIFY_TLS` | `true` | Set `false` for self-signed lab certs |
| `..._ENABLE_WRITES` | `false` | **Write tools are hidden until this is `true`** |
| `..._MAX_RETRIES` | `3` | Backoff retries on 429/5xx |
| `..._MAX_RESPONSE_CHARS` | `40000` | Truncation cap for tool responses |

## Hooking into Claude

Project-scoped `.mcp.json` (or `claude mcp add`):

```json
{
  "mcpServers": {
    "cnc": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/cnc-mcp", "cnc-mcp"],
      "env": {
        "CNC_MCP_BASE_URL": "https://platform.example.com",
        "CNC_MCP_USERNAME": "apiuser",
        "CNC_MCP_PASSWORD": "…",
        "CNC_MCP_VERIFY_TLS": "false"
      }
    }
  }
}
```

Docker alternative: `make docker-build`, then use
`docker run -i --rm --env-file .env cnc-mcp` as the command.

## Layout

| Path | Purpose |
|---|---|
| `src/cnc_mcp/server.py` | Assembly: settings → auth → client → tools; entry point |
| `src/cnc_mcp/config.py` | Env-driven settings (pydantic-settings) |
| `src/cnc_mcp/auth.py` | Auth strategies: Basic, StaticToken, LoginToken (+hooks) |
| `src/cnc_mcp/client.py` | httpx wrapper: retries, backoff, 401 re-auth, concurrency cap |
| `src/cnc_mcp/safety.py` | `register_tool()` — annotations + write gating |
| `src/cnc_mcp/formatting.py` | markdown/json formats, pagination envelope, truncation |
| `src/cnc_mcp/errors.py` | Agent-facing error messages |
| `src/cnc_mcp/tools/` | One module per API area (`example_widgets` = the pattern) |
| `tests/` | respx-mocked tests, one happy + one error path per tool |
| `CLAUDE.md` | Specialization playbook |
| `scripts/live_smoke.py` | Live smoke harness driven by `scripts/smoke_plan.json` |
| `src/cnc_mcp/polling.py` | `wait_until()` helper for convergence-wait tools |

## Safety model

Servers are **read-only by default**: write tools aren't registered (agents
never see them) until `..._ENABLE_WRITES=true` is set for that deployment.
Destructive tools additionally carry `destructiveHint` so clients can prompt.
