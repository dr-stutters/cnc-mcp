# Contributing

cnc-mcp is built from behaviour verified against a live Crosswork Network
Controller, not from the documentation alone. Contributions are held to the
same standard: a change that touches what the server sends to or reads from
the platform needs a live run, and the pull request says what was verified
and on which release.

## Set up

Requires [uv](https://docs.astral.sh/uv/) and Python 3.11+.

```bash
git clone https://github.com/dr-stutters/cnc-mcp && cd cnc-mcp
make install        # uv sync (runtime + dev dependencies)
make test           # pytest, all HTTP mocked with respx — no CNC needed
make lint           # ruff check
make fmt            # ruff format + autofix
```

For anything live, copy `.env.example` to `.env` and fill in the instance
(`CNC_MCP_BASE_URL`, `CNC_MCP_USERNAME`, `CNC_MCP_PASSWORD`; see
[SECURITY.md](SECURITY.md) for the rules on credentials). `.env` is
gitignored and dockerignored; keep it that way.

## Conventions

[CLAUDE.md](CLAUDE.md) is the rulebook — Step 4 defines how a tool module is
written (naming, flat `Annotated` parameters, `str` returns through
`finalize()`, `format_error()` instead of raising, `register_tool()` with the
right annotations, docstring pattern, state preconditions, `wait_for_*`
tools, stdio discipline) and Step 5 what a test module must contain. It is
not restated here; a pull request that departs from it will be asked to
conform. Every existing module in `src/cnc_mcp/tools/` follows it and is a
reasonable template.

Platform behaviour that differs from the published OpenAPI documents belongs
in the tool docstring (and, when it shapes a design decision, in the README's
"Platform facts" section) the moment it is discovered.

## Verification layers

Unit tests prove the code; only a live run proves the integration. There are
three layers, and a change is done when the layers that apply to it pass.

1. **Mocked unit tests** — `make test` and `make lint`. Every tool has a
   happy-path test that goes through the MCP server via
   `call_tool_text()` (`tests/conftest.py`), which validates the input schema
   and asserts the exact request sent, plus an error-path test. All HTTP is
   mocked with `respx`; nothing touches the network. CI runs this on Python
   3.11 and 3.12, then builds the wheel and checks the console script starts
   from it.

2. **Live smoke** — `scripts/live_smoke.py` runs a plan of real tool calls
   against the instance in `.env`. The plan, `scripts/smoke_plan.json`, is
   private (gitignored: it carries instance addresses and object names);
   start from the sanitised `scripts/smoke_plan.example.json`. Read-phase
   steps must be side-effect free. Write-phase steps (`"phase": "write"`,
   run only with `--write`) must leave the platform exactly as found:
   create → verify → delete, chaining created ids with `capture` / `$var`.

   ```bash
   uv run python scripts/live_smoke.py            # read phase
   uv run python scripts/live_smoke.py --write    # read + write phases
   ```

   When a change touches the dialect helpers (`crosswork.py`, `restconf.py`,
   `emf.py`, `probe.py`), also run `uv run python scripts/live_plumbing_check.py`,
   which exercises each verified assumption against the instance.

3. **Agent-style checks** — `scripts/mcp_cli.py` starts the server exactly as
   an MCP client would (over stdio, credentials from `.env`) and shows what an
   agent sees: the connect-time instructions, the tool list, a tool's input
   schema, and a tool's text answer.

   ```bash
   uv run python scripts/mcp_cli.py instructions
   uv run python scripts/mcp_cli.py list [--json] [--writes]
   uv run python scripts/mcp_cli.py schema cnc_get_device
   uv run python scripts/mcp_cli.py call cnc_get_device '{"host_name": "PE1"}'
   ```

   Use it to check a new tool the way an agent would: is the schema
   self-explanatory, does a wrong argument name get a useful rejection, does
   the markdown answer say enough, is an error message actionable. The
   release was validated by driving operator tasks this way with assistants
   that saw only the tool list, schemas and instructions; friction they
   reported became fixes.

## Adding a module

1. **Spec first.** Read the CNC OpenAPI document for the service and the
   maintainer's platform notes (kept outside the repository — ask). Probe the
   endpoints live before writing tools: the published bodies, envelopes and
   status codes differ from the platform's behaviour often enough that the
   README has a section about it. Record the verified request and response
   shapes; they are what the module and its tests encode.
2. **Write the module** per CLAUDE.md Step 4, add it to `ALL_MODULES` in
   `src/cnc_mcp/tools/__init__.py`, and add its tests
   (`tests/test_tools_<module>.py`, one happy-path and one error-path test
   per tool). `tests/test_server_safety.py` checks that every registered tool
   carries annotations and a docstring and that write tools are hidden when
   writes are disabled; `tests/test_tools_admin.py` checks that tool names
   stay disjoint across all modules.
3. **Verify live.** Add the module's calls to your private smoke plan and run
   the read phase; run the write phase where creating and deleting test
   objects is acceptable. Drive the new tools through `mcp_cli.py`. Anything
   the live run teaches (ordering rules, a 200 that is really a failure, an
   error that means something else) goes into the docstrings and the error
   hints straight away.
4. **Notes.** Update the README (tool table, counts, platform facts if the
   module added any), `.env.example` if a setting was added, and the
   `[Unreleased]` section of `CHANGELOG.md`. State in the pull request which
   CNC release the module was verified on and which tools, if any, could not
   be exercised live and why.

Write tools that could not be verified against a live instance are not
merged; they are listed in the README roadmap instead.

## Releasing

Releases are cut by the maintainer from `main`:

1. Bump `version` in `pyproject.toml` (`uv version X.Y.Z` does it in place).
   For a pre-release, `uv version 1.0.0-rc1` writes the PEP 440 spelling
   `1.0.0rc1` to `pyproject.toml` (and the wheel is named that way); tag it
   `v1.0.0-rc1` all the same — the workflow compares tag and project version
   on their PEP 440-normalised form, so either spelling of the tag matches.
2. In `CHANGELOG.md`, rename `[Unreleased]` to `[X.Y.Z] - YYYY-MM-DD`, add a
   fresh empty `[Unreleased]` above it, and update the link references at
   the bottom of the file. The release workflow uses this section verbatim as
   the GitHub Release body and fails if it is missing (for a pre-release the
   heading may use either spelling, `[1.0.0-rc1]` or `[1.0.0rc1]`).
3. Commit (`Release vX.Y.Z`), tag and push:

   ```bash
   git tag -a vX.Y.Z -m "cnc-mcp X.Y.Z"
   git push origin main vX.Y.Z
   ```

The tag triggers `.github/workflows/release.yml`:

- **build** checks the tag against `pyproject.toml` (as PEP 440 versions),
  runs `uv build`, starts the console script from the wheel to make sure it
  fails fast with a configuration error when unconfigured, uploads `dist/` as
  a workflow artifact, and creates the GitHub Release with the wheel and sdist
  attached. A version that PEP 440 calls a pre-release or dev release
  (`v1.0.0-rc1`, `v1.0.0b2`, `v1.0.0.dev1`, ...) is marked as a pre-release.
- **image** builds the Dockerfile and pushes
  `ghcr.io/dr-stutters/cnc-mcp:X.Y.Z` — the tag without its `v`, so
  `:1.0.0-rc1` for that tag — and `:latest` for a final release only, using
  the workflow's `GITHUB_TOKEN`. After the first push, check the
  package's visibility under the repository's Packages and make it public if
  it is not.
- **pypi** publishes `dist/` to PyPI with trusted publishing. It only runs
  when the repository variable `PUBLISH_TO_PYPI` is `true`; set the variable
  after registering the trusted publisher on PyPI (below).

### PyPI trusted publishing (one-time setup)

Trusted publishing lets the workflow upload with a short-lived OIDC token, so
no API token is stored in the repository.

1. On PyPI, signed in as the maintainer: *Your account → Publishing → Add a
   new pending publisher* with PyPI project name `cnc-mcp`, owner
   `dr-stutters`, repository `cnc-mcp`, workflow name `release.yml`,
   environment name `pypi`. (A pending publisher is for a project that does
   not exist yet; the first upload creates it. For an existing project, add
   the publisher under the project's *Publishing* settings instead.)
2. In the GitHub repository: *Settings → Environments → New environment*
   named `pypi`. Optionally restrict it to tag deployments (`v*`) and add a
   required reviewer, which makes the PyPI upload a manual approval.
3. *Settings → Secrets and variables → Actions → Variables → New repository
   variable*: `PUBLISH_TO_PYPI` = `true`.
4. Push the next release tag. The `pypi` job appears in the run; the first
   successful upload creates the project on PyPI.

Until the variable is set, the `pypi` job is skipped and releases consist of
the GitHub Release (wheel + sdist) and the container image.
