# Platform facts that shaped the design

The behaviours of Cisco Crosswork Network Controller 7.2 that differ from what the published OpenAPI documents suggest and that a client must get right, each verified against a live instance while building the tools (the full record lives in a platform-notes file kept outside this repository; see [COVERAGE.md](COVERAGE.md) for which published operations the tools use).

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
