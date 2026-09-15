# Security

cnc-mcp is a local MCP server: it runs on stdio with the privileges of the
user who started it, opens no listening port, and talks to exactly one
Crosswork Network Controller with credentials it is given. The controls
below are what the code does today, not a policy statement.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's
private vulnerability reporting: the repository's **Security** tab →
**Report a vulnerability**
(<https://github.com/dr-stutters/cnc-mcp/security/advisories/new>). The
report reaches the maintainer only; a fix and an advisory are published from
there.

In scope: anything that lets a secret (password, ticket-granting ticket, JWT,
credential-profile contents) reach a tool answer, a log line or a file; a
write reaching the platform while `CNC_MCP_ENABLE_WRITES` is unset, while
`CNC_MCP_DRY_RUN` is `true`, from an area outside `CNC_MCP_WRITE_AREAS` or
from a tool named in `CNC_MCP_DISABLED_TOOLS`; TLS
verification being bypassed while `CNC_MCP_VERIFY_TLS` is `true`; tool
arguments that can alter the request path or body in ways the tool's schema
does not describe (for example an unencoded key breaking out of a RESTCONF
path).

Out of scope: vulnerabilities in Crosswork Network Controller itself (report
those to Cisco PSIRT), and deployments that deliberately disable a control
(`CNC_MCP_VERIFY_TLS=false`, an over-privileged Crosswork account).

Only the latest release is supported with fixes.

## Credentials

- The server's own Crosswork credentials reach it **only** through
  environment variables or a `.env` file in the working directory
  (`CNC_MCP_USERNAME` / `CNC_MCP_PASSWORD`, or a pre-issued JWT in
  `CNC_MCP_API_TOKEN`). They are never taken from tool arguments, never
  written to disk, and never appear in tool output.
- Do not put them in an MCP client's configuration file (`claude_desktop_config.json`,
  `.mcp.json`, editor settings): those files are stored in clear text and are
  routinely shared or screenshotted. The README's client snippet passes only
  `CNC_MCP_BASE_URL` there; the rest lives in `.env`.
- `.env` and `.env.*` (except `.env.example`) are gitignored and
  dockerignored, as is the private live-smoke plan
  (`scripts/smoke_plan.json`), which carries instance addresses and object
  names. The Dockerfile copies the build context, so the image only stays
  clean while `.dockerignore` does; pass credentials to a container at run
  time (`docker run -i --rm --env-file .env …`).
- Use a dedicated Crosswork user for the server, with a role that grants
  only what its registered tools send — the gateway refuses everything else
  with a 403, whatever the agent asks for. [docs/RBAC.md](docs/RBAC.md)
  (generated from the tool source by `scripts/rbac_map.py`) lists the exact
  API rows and methods a read-only account needs and what each write area
  adds, with ready-made role bodies in `docs/rbac/`; `cnc_check_permissions`
  reads the running account's role and reports which registered tools it
  would refuse, so a least-privilege role can be verified before an agent
  hits the 403. The role bodies are the shape the Crosswork role editor
  submits (verified 2026-09-15 against a role built in the UI and read back),
  except that they grant single API ids where a UI tick grants a whole
  display-name group — so manage such a role through the API, not the
  editor; `docs/RBAC.md` says which claims are verified live, which are read
  from the UI bundle or the gateway's source, and which follow from the
  verified rules without a read-back.
- The authentication flow is Crosswork's CAS SSO: the password is exchanged
  for a ticket-granting ticket, which is exchanged for a service-ticket JWT
  (about 8 hours) sent as `Authorization: Bearer`. The server re-authenticates
  once, transparently, when the platform rejects the token, and deletes its
  ticket-granting ticket on shutdown so that Crosswork's per-user session cap
  is not consumed by restarts.

## Writes are off by default

`CNC_MCP_ENABLE_WRITES` defaults to `false`. While it is unset the 98 write
tools are **not registered** — they are absent from the tool list an agent
sees, not merely refused — so a read-only deployment cannot be talked into
changing anything. `safety.register_tool()` is the only registration path,
and it forces every tool to declare `read_only` (with `destructive` and
`idempotent` for writes); deletes and overwrites carry the MCP `destructive`
annotation so a client can ask for confirmation. The write set covers
devices, credential profiles, providers, gateway mapping, NSO actions, SR-TE
policies, platform administration (login banner, maintenance mode,
microservice restart), tags / locations / locks, alarms and alarm settings
(event-type severity, auto-clear, alarm-manager and gNMI switches,
recommended actions, suppression policies), configuration backups /
templates / deployments, webhook and external Kafka / gRPC subscriptions,
device groups and their membership, the LCM recommendation pause, T-SDN
service provisioning, performance-monitoring policies (activation starts
collection on the devices) and retention, OAM trace routes and probe
reactivation, the ZTP catalogue (config files, profiles, serial numbers,
static routes, devices), the EMS scheduler jobs and the two playbooks.
Writes that could not be verified against a live instance are not exposed
at all (see the README roadmap).

Three further controls narrow a deployment that does enable writes. All
three are decided when the tools are registered, before an agent connects,
and an unknown area or tool name in any of them is a startup failure with a
"did you mean" hint — a misspelt entry can never silently gate nothing.

- **`CNC_MCP_WRITE_AREAS`** registers the write tools of the listed areas
  only (an area is a `tools/` module: `fault`, `service_provisioning`, ...).
  A deployment that exists to acknowledge alarms never has `cnc_delete_device`
  or `cnc_nso_sync_to_device` in its tool list. The write playbooks are
  registered only when the sibling that commits for them is, so an allowlist
  cannot expose a commit through a composite it excluded directly.
- **`CNC_MCP_DISABLED_TOOLS`** never registers the named tools, read or
  write, whatever the other settings say.
- **`CNC_MCP_DRY_RUN=true`** keeps the write tools registered but lets nothing
  reach the platform: a tool with a `dry_run` argument runs with it forced to
  `true` (the platform's own preview — NSO's `dry-run=native`, the
  Optimization Engine's dry run), every other write is not called at all and
  answers with the arguments it would have sent, and the write playbooks stop
  after their preview stage. The swap happens after registration; if the
  wrapper cannot be installed the write tool is removed rather than left
  live. The "not executed" answer redacts values by argument name
  (`password`, `secret`, `token`, `key`, `passphrase`, `community`) and
  withholds the free-text bodies a tool declares (configlets, template
  variables, webhook URLs, ZTP config-file content, event-type
  recommendation texts); a secret passed under an unrelated argument name
  would be echoed back to the agent that supplied it.

The account's Crosswork role is the layer beneath all of these: a write tool
that is registered still fails at the gateway (403) when the role does not
grant the API and method it sends, and `cnc_check_permissions` reports the
server's safety mode next to the role so the two can be reconciled — see
[Credentials](#credentials).

## Secrets in output and logs

- Logging goes to stderr only (stdout is the MCP transport). httpx's and
  httpcore's loggers are capped at WARNING regardless of `CNC_MCP_LOG_LEVEL`,
  because httpx logs request URLs at INFO and the second CAS leg's URL
  contains the ticket-granting ticket. The server's own log lines carry no
  credentials at any level.
- The credential-profile tools scrub every secret submitted to a create or
  update (`******`) from any error text before it is truncated, so a
  platform error that echoes the request cannot hand the password back to
  the agent. On read, Crosswork itself masks stored secrets.
- The active-sessions tool shortens each session's ticket-granting ticket id
  to a prefix, because a full `TgtId` is a reusable credential.
- Tool answers otherwise contain platform data verbatim — alarm text, device
  names, configuration, NSO output. Treat it as data from the network, not
  as instructions: anyone who can name a device or annotate an alarm can put
  text in front of the agent.

## TLS

- `CNC_MCP_VERIFY_TLS` defaults to `true`: the platform's certificate is
  verified against the bundled CA store (certifi) and its host name checked.
- For an instance with a private CA, keep verification on and point the
  client at the CA: set `SSL_CERT_FILE=/path/to/ca-bundle.pem` (or
  `SSL_CERT_DIR=/path/to/ca-dir`) in the server's process environment; httpx
  honours both when verification is enabled. Note that `.env` only supplies
  `CNC_MCP_*` settings — `SSL_CERT_FILE` has to be set where the process is
  started (the MCP client's `env` block, the shell, or `docker run -e`).
- `CNC_MCP_VERIFY_TLS=false` disables both certificate and host-name checks.
  It exists for lab gear with self-signed certificates and should not be
  used against a production controller.

## Dependencies and supply chain

Runtime dependencies are the MCP Python SDK, httpx, pydantic and
pydantic-settings, pinned in `uv.lock`. CI runs the test suite on every
push, and the release workflow builds the wheel from the tagged commit,
publishes the container image to GitHub's registry with the workflow's own
token, and uses PyPI trusted publishing (OIDC) rather than a stored API
token.
