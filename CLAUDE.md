# cnc-mcp — Conventions and Playbook

This server was specialized from a platform-agnostic MCP template (official MCP
Python SDK 2.x / `MCPServer`, stdio transport) for Cisco Crosswork Network
Controller; Steps 0–3 below are done. Steps 4–8 are the **conventions every new
tool module must follow** — they are non-negotiable, and every existing module
follows them. If you are Claude and this file is in your context, apply them to
whatever module you are adding, and verify against a live instance before
calling it done. Platform-specific facts (auth flow, per-endpoint envelopes,
query grammar, verified quirks) live in the maintainer's platform-notes file
outside this repository; the README summarises the ones that shaped the code.

## Step 0 — Inputs you need

Ask the user (or confirm from their request):
1. Which platform/service? Its API base URL and version if known.
2. Any platform notes file the user keeps outside this template (API quirks,
   auth details, verified facts from earlier builds) — read it before Step 2.
3. Which API areas matter most. Default: comprehensive read coverage of the
   core object model, plus the obviously useful writes.

## Step 1 — Specialize the naming

From a fresh copy of this template, run:

```bash
python3 scripts/specialize.py <service>    # e.g. acme, acme_cloud
```

This renames the package (`cnc_mcp` → `<service>_mcp`), the console script,
the env prefix (`CNC_MCP_` → `<SERVICE>_MCP_`), and the tool-name prefix,
across all files. Verify with `make test` — the suite must still pass after the
rename, before you change any logic.

## Step 2 — Research the platform API

Work from the platform's own API documentation — if the platform serves an
OpenAPI/Swagger spec, fetch it and treat it as ground truth over prior
knowledge. Identify:
- auth flow (endpoint, token lifetime, refresh behavior)
- base path conventions and required headers
- pagination scheme and its limits (or the absence of one — some platforms
  return full collections and need client-side pagination)
- the core object model (what agents will actually ask about)
- rate limits, and any **operation-ordering rules** (state X required before
  operation Y — these bite agents at runtime if undocumented)

## Step 3 — Implement auth

Edit `create_auth()` in `server.py`. The strategies in `auth.py` cover most
schemes via configuration (basic per-request, static token, login-endpoint
token with header/JSON/raw-body extraction); subclass `LoginTokenAuth` only
when the platform needs extra session state. Delete the placeholder default
once the real strategy is in.

## Step 4 — Implement tools

Replace `tools/example_widgets.py` with one module per API area. Add each to
`ALL_MODULES` in `tools/__init__.py`. Non-negotiable conventions (the example
module demonstrates all of them):

- **Naming**: `{service}_{action}_{resource}` snake_case — `acme_list_devices`,
  `acme_get_policy`. Action verbs: list/get/search/create/update/delete/start/stop.
- **Coverage**: prioritize comprehensive read coverage of the core object model;
  add workflow tools only where a single API call can't answer a natural request.
- **Inputs**: FLAT function parameters — every argument is
  `Annotated[type, Field(...)]` with a description (include an example value)
  and constraints (`ge`, `le`, `max_length`). Never wrap arguments in a single
  Pydantic model: it buries the schema behind a `$ref`, forces agents to nest
  arguments under one key, and turns their most common mistake (sending flat
  arguments) into a raw validation error that bypasses `format_error()`.
- **Outputs**: return `str`. List tools support `response_format`
  (markdown default / json) and the `pagination_envelope()`. Every return passes
  through `finalize()`.
- **Errors**: never raise out of a tool. Wrap the body in
  `try/except Exception` and return `format_error(e)`. Add platform-specific
  hints to `errors.py` when a status code has a platform-specific meaning.
- **State preconditions**: when the platform enforces an operation order
  (stop before delete, must-be-running, wipe-before-remove, ...), state the
  full required sequence in the tool docstring AND in its error explanations,
  and consider a `force` option that performs the sequence for the agent.
  These rules often surface only in live testing — bake each one into the
  docs the moment you discover it.
- **Convergence waits**: for async platform operations (boots, deployments,
  background tasks), add `*_wait_for_*` tools built on
  `polling.wait_until()` instead of leaving agents to poll in a loop. On
  timeout return a non-error "not finished yet, current state: ..." message —
  reserve `Error:` for actual API failures.
- **Registration**: always through `register_tool()` (never `@mcp.tool`
  directly) so annotations and write-gating stay enforced. Writes get
  `read_only=False`; deletes/overwrites also get `destructive=True`.
- **Write safety on the wire**: ApiClient auto-retries 5xx/transport errors only
  for idempotent methods (429 is always retried). If a specific POST is safe to
  re-send on this platform, pass `retryable=True` explicitly; otherwise keep the
  default so a lost response can't duplicate a create or deployment.
- **Docstrings**: full pattern from the example module — what it does, when to
  use it (and when not to), args, return schema, error meanings.
- **stdio discipline**: never `print()` in server code; log via `logging`
  (goes to stderr).

Also update `build_instructions()` in `server.py`: describe the platform, ID
conventions, and any object-model quirks the agent needs.

## Step 5 — Tests

Mirror the existing test layout; all HTTP mocked with respx, zero live network.
Required per tool: one happy-path test through `call_tool_text()` (this
validates the input schema too) and one error-path test. Keep the auth flow
tests updated for the real strategy. `make test` and `make lint` must pass.

## Step 6 — Live smoke test

Unit tests prove the code; only a live run proves the integration. Copy
`scripts/smoke_plan.example.json` to `scripts/smoke_plan.json`, fill it with
real tool calls for this platform (read phase always; write phase only for
instances where creating/deleting test objects is acceptable), then:

```bash
uv run python scripts/live_smoke.py            # read phase
uv run python scripts/live_smoke.py --write    # read + write phases
```

Write-phase plans must leave the platform exactly as found (create → verify →
delete). Anything you learn live (ordering rules, quirky responses) goes back
into docstrings and the user's platform notes file.

## Step 7 — Docs and config

- `.env.example`: real variable names for this platform, with comments.
- `README.md`: platform-specific quickstart, tool list, required account
  privileges.
- `pyproject.toml`: update `description`.

## Step 8 — Definition of done

- [ ] `make test` and `make lint` pass; server starts: `uv run <service>-mcp`
      with a configured `.env` (or fails fast with a clear config error)
- [ ] `npx @modelcontextprotocol/inspector uv run <service>-mcp` lists the tools
- [ ] every tool: register_tool + annotations + docstring + tests
- [ ] write tools invisible unless `<SERVICE>_MCP_ENABLE_WRITES=true`
- [ ] `scripts/smoke_plan.json` populated; live smoke read phase passes against
      a real instance (write phase where safe)
- [ ] state-precondition rules discovered live are documented in docstrings
- [ ] no secrets in code, logs, or error messages; no `print()` anywhere
- [ ] example_widgets module deleted
