# RBAC: what a Crosswork account needs to run cnc-mcp

> **Generated** by `scripts/rbac_map.py` from the tool source, the gateway's secured-API catalogue (CNC 7.2.0, 217 APIs in 27 features, catalogue verified live 2026-09-14) and the platform's read templates and baseline rows (captured 2026-09-14 and 2026-09-15) — do not edit by hand. Regenerate with `make rbac` (offline, from the catalogue and templates embedded in `src/cnc_mcp/data/rbac_map.json`) or `make rbac-fetch` (re-read the catalogue from a live instance; `--read-templates <capture>` loads a fresh template capture); `make rbac-check` fails when the committed files are stale.

The server registers 282 tools (184 read-only, 98 write). Each sends a known set of HTTP requests; each request is routed by the gateway to one secured API, and a role must grant that API (with the method) or the gateway refuses the call (403). This page lists exactly which API rows a role needs and which of the role editor's **Read / Write / Delete** ticks on each — first for a read-only account, then per write area, then per tool.

## 1. How Crosswork RBAC works

**Verified live** (CNC 7.2.0 single-VM lab, 2026-09-14 and 2026-09-15):

- The API gateway is **Tyk** (v5.1.1, from its `/hello` health endpoint). Every `/crosswork/*` request is routed to one of 217 secured API definitions (`GET /crosswork/aaa/v1/api`), each with an `api_id`, a display `name` and a gorilla-mux **listen path** (`/crosswork/inventory/`, `/crosswork/alarms/v1/query`, `/crosswork/performance/v{.}/dashboards/`, ...).
- A **role** (`GET /crosswork/aaa/v1/role` → a dict keyed by role name) is a Tyk policy: `access_rights{<api_id>: {api_name, api_id, versions, allowed_urls [{url: <regex>, methods: [GET, POST, PUT, PATCH, DELETE]}], allowance_scope}}` plus the policy fields (`rate`, `per`, `quota_max`, `key_expires_in`, `active`, ...). The lab's built-in role, `admin`, grants every API with `url "/.*"` and all five methods (`rate 5000`, `versions ["Default"]`).
- `GET /crosswork/aaa/v2/api` → `{<feature>: [{api_id, name}]}` (27 features) is what the UI's role editor (Administration > Users and Roles > Roles) builds its rows from; the `feature` column below is it. A **row in the editor is a display-name group**: one tick grants every api_id sharing the row's `name` (below).
- `GET /crosswork/aaa/v1/taskAPIPermission/<role>` → `{<task id>: {apiIds: {<api_id>: ["R", "W", "D"]}}}`: the UI's **task** checkboxes are bundles of per-API R/W/D grants (section 5). `GET aaa/v1/task/<role>` lists the task groups (audit_logs, coe, crosswork_network_controller, nso_management, platform); `GET aaa/v1/roleAccess/<role>` → `{PolicyId, GuiAccess, ApiAccess, PolicyData}` — `ApiAccess false` means no API call at all.
- A **user** (`GET aaa/v1/user/<name>`) carries `PolicyId` (= its role), `Status` and `DeviceAccessGroups [{Uuid, DomainName}]` (`ALL-ACCESS` on the lab). A device access group other than ALL-ACCESS restricts which **devices** the account sees, not which APIs it may call.
- The CAS-issued session token is an HS512 JWT sent as `Authorization: Bearer`; its claims are readable without the key: `sub`/`username` (the login name), `policy_id` (the role), `deviceAccessGroups`, `exp`/`iat` (8 h), `iss`. cnc_check_permissions reads the identity from them.
- The read-only mirror `/crosswork/aaaread/...` (api_id `aaa_cw_role_read`, "Know my role - Read only", same backend) answers the same GETs as `aaa/v1` (`role/<r>`, `roleAccess/<r>`, `user/<u>`, `userpermission`, `task/<r>`, `v1/api`, `v2/api`). It is a **baseline row of every role** — the AAA service adds it to every role it stores (below) — so every account can read its own role, and the mirror's catalogue listing, by platform design. cnc_check_permissions reads the account's role through it.
- The three SSO ticket calls the server logs in with (`POST /crosswork/sso/v1/tickets`, `POST .../tickets/{TGT}`, `DELETE .../tickets/{TGT}`) are **not** gateway APIs: no role grant is involved in logging in, only in what the token may then call.

**Verified live: the role editor, and how Crosswork stores a role** (2026-09-14 through an admin session: test roles stored in several shapes and read back; 2026-09-15: a role built in the editor with three ticks and read back through the API, the editor's own role model read from the UI bundle, and the two generated bodies as committed stored through the API and read back — section 6 says what the fixtures pin):

- `POST /crosswork/aaa/v1/role` needs `Content-Type: application/json; charset=UTF-8` (plain `application/json` → 405); body `{"<name>": {<rbacRole>}}` → **201**. `PUT /crosswork/aaa/v1/role/<name>` with the inner object → **204**. `GET /crosswork/aaa/v1/role/<name>` → the stored object (**404** when absent).
- **What a tick submits.** Per ticked row the editor sends ONE `allowed_urls` entry `{url: "/.*", methods: <union>}` — **Read** adds `GET`, **Write** adds `POST, PUT, PATCH`, **Delete** adds `DELETE` (in that order) — with `versions []` and the editor's role fields (`rate 1000 / per 60 / quota_max -1 / quota_renewal_rate 60 / key_expires_in -1 / active true / hmac_enabled false`; `rate`/`per` is the gateway's per-key rate limit — 1000 requests per 60 s, the editor's default, where the built-in `admin` role carries 5000 — raise it through the API if an agent-driven server hits 429s, which ApiClient retries, slower). A role built in the editor with exactly three ticks — Read on *Alarm Settings*, Write on *Alarm Suppression Policies*, Delete on *Alarms and Events RESTCONF* — was read back as exactly that (`tests/fixtures/rbac/stored_ui_built_role.json`): the seven *Alarm Settings* api_ids `[GET] /.*`, `event-processing-service-suppressionpolicy-api` `[POST, PUT, PATCH] /.*`, the six *Alarms and Events RESTCONF* api_ids `[DELETE] /.*`, plus the three baseline rows. This page calls the ticks R / W / D; the generated bodies use exactly this shape.
- **A row is a display-name group.** The editor shows one row per `name` and hides `aaa_cw_role_read`, `aaa_cwpassword`, `aaa_selected_pref`, `cwcrossclusterstate`; 15 of the editor's 102 rows cover more than one api_id (7 for *Alarm Settings*, 6 for *Alarms and Events RESTCONF*, 31 for *Alarms & Events*, ...), and one tick grants all of them. So **the UI cannot grant a single api_id of a group; the API can** — the generated bodies grant only the api_ids the tools use, and sections 2 and 3 list the sibling api_ids a UI tick grants as well. When the editor displays a stored role it reads only the FIRST `allowed_urls` entry of each api_id, and only when that entry's url is `"/.*"`; a group row shows the ticks of its first api_id in `aaa/v2/api` order (the editor's row order, not the alphabetical order of the tables here). On 6 rows neither generated body grants that first api_id while granting a sibling — *Users and Roles Management* (`get-WebSocket-Subscription`), *External Notification Subscription* (`external-kafka-subscription`), *RESTCONF Notification Subscription* (`nb-api-alarm-nt-5`), *Alarms & Events* (`alarm-rest-service-summary-rest-api`), *Alarms and Events RESTCONF* (`nb-api-alarm-1`), *Device Inventory* (`cw-inventory-job-dashboard-deprecated`) — so the editor shows those rows unticked while the grant is live (from the catalogue's v2 positions and the bundle's row model; not exercised live).
- Every stored role gains 3 **baseline rows** the service adds on its own — `aaa_cw_role_read` (GET `/.*`; POST `/.+/query$`), `aaa_cwpassword` (GET, PUT `/.*`; POST `/(.*passwordHistoryCheck.*)$`), `aaa_selected_pref` (GET, PUT `/.*`) — the account's own role through the mirror, its password change and its UI preferences (verified 2026-09-15: the UI-built role, submitted with none of them, came back with all three; the two 2026-09-14 API-stored experiments, submitted with `aaa_cw_role_read` only, came back with the other two — `tests/fixtures/rbac/`). They are not in the bodies; they appear when a role is read back.
- A row with a GET entry (and no POST entry) additionally receives the platform's per-API **read templates**: extra POST entries naming the read-by-POST paths of that API — so a Read tick permits those POSTs as well. The 16 APIs with a template among the 42 rows the read-only body carries (every other one of these rows received GET only when stored; the 172 catalogued APIs outside these rows and the baseline rows were not in the template capture (2026-09-14), so their templates are unknown and any POST there is classed W — except that the UI-built role stored `cw-fault-alarm-autoclear`, `cw-fault-alarm-autoclear-revert` as GET-only rows, template-free, `tests/fixtures/rbac/stored_ui_built_role.json`); the `aaa_cw_role_read` baseline row carries its own template (`/.+/query$`):
  - `collection_dg-manager`: POST `/.+/query$`
  - `cw-fault-alarms-api`: POST `/crosswork/alarms/v1/query`
  - `cw-fault-events-api`: POST `/crosswork/alarms/v1/event/query`
  - `cw-probe-mgr`: POST `/.+/(probeStatusReport|reactivateProbe)$`
  - `cw-ztp-service`: POST `/.+/(query|csvtemplate|export|count)$`
  - `cwcollection`: POST `/.+/query$`; POST `/.+/v1/jobs/events$`
  - `device-config`: POST `/.+/query$`
  - `dg-manager-global-parameters-api`: POST `/.+/query$`
  - `ems-inventory`: POST `/.+/query$`
  - `inventory_cwinventory`: POST `/.+/query$`
  - `optima_analytics_api`: POST `/.+/api/v1/(dashboard/lsp/.*|lsp/.*|link/.*|interface/.*)$`
  - `optima_restconf`: POST `/.+(sr-policy-dryrun|get-plan|sr-policies-on-interface|sr-policies-on-node|sr-policy-routes|sr-policy-route-preview|rsvp-te-tunnel-dryrun|get-lcm-domains|get-lcm-recommendation-preview|get-lcm-recommendation-policies|get-lcm-recommendation|get-lcm-config|get-lcm-managed-interfaces|cs-policy-paths-on-interface|cs-policy-paths-on-nodes|all-cs-policy-paths|get-csm-interfaces-bandwidth-pool)$`
  - `performance-rest-apis`: POST `.*/links/.*`
  - `platform_cwplatform`: POST `/.+/(query|get|verify|list)$`
  - `proxy_cw-proxy`: POST `/.+/jsonrpc/(nsoLogin|new_trans|get_trans|query|show_config|get_trans_changes|logout|get_service_points|get_module_prefix_map)$`
  - `tsdn_cat-restconf-nbi`: POST `/.+/operations/cat-inventory-rpc:.*`
- A row ticked Read **and** Write is stored as its single `/.*` entry only (no template — the entry already covers every POST), **except on the APIs on which the service reserves a last segment `delete` for the Delete tick** (presumably the ones that delete through `POST .../delete` — no tool POSTs such a path, so the map does not show one): there a row whose single entry carries POST without DELETE — Write without Delete, the one entry the editor submits and the generated bodies carry — is **split**: POST moves to a second entry `{url: ".+(?:/[^/]{1,5}|/[^/]{7,}|/[^d][^/]{5}|/[^/][^e][^/]{4}|/[^/]{2}[^l][^/]{3}|/[^/]{3}[^e][^/]{2}|/[^/]{4}[^t][^/]|/[^/]{5}[^e])[/]?$", methods: [POST]}`, an unanchored search that matches every path whose LAST segment is not the six-character word `delete` (a last segment of 1-5 characters, of 7 or more, or of six characters differing from d-e-l-e-t-e in some position; a trailing slash allowed — `deletes` and `Delete` pass), and the remaining methods come back in **alphabetical** order: the operator body's `[GET, POST, PUT, PATCH] /.*` row read back as `[GET, PATCH, PUT] /.*` + `[POST] <the pattern>`. Verified 2026-09-15 on `cwcollection`, `optima_restconf`, `platform_cwplatform` (the operator body's Write rows there, `tests/fixtures/rbac/stored_generated_operator.json`); **inferred** for `collection_dg-manager`, `cw-fault-alarms-api`, `cw-fault-events-api`, `cw-probe-mgr`, `cw-ztp-service`, `dg-manager-global-parameters-api`, `optima_analytics_api` from the 2026-09-14 experiment in which a row whose only entry was a custom-url POST came back with its methods stripped to `[]` and this same pattern entry appended, on those seven (and on `cwcollection`, `optima_restconf`) — the same split, POST being the entry's only method; no union entry has been stored on them, so the split there is the model's extrapolation, not a read-back. Read and Write submitted as two entries beside each other (the 2026-09-14 experiment) were stored verbatim, and so were the operator body's 10 rows carrying DELETE and its 7 Write-only rows (`[POST, PUT, PATCH]`) — including `cw-ztp-service` on this list: a single entry carrying DELETE is stored verbatim, the split applies only to Write without Delete (read back 2026-09-15). In the same 2026-09-14 submission a custom GET entry beside a custom POST entry was stored verbatim on `platform_cwplatform` (and on three APIs off this list, `device-config`, `inventory_cwinventory`, `tsdn_cat-restconf-nbi`) — the split keys on the row having a single entry. **Consequence: Write without Delete on these APIs still permits every POST except a path ending in `/delete`.** For the Optimization Engine (`optima_restconf`) an operator role without Delete can still create policies, and the delete RPC the map records — `POST /crosswork/nbi/optimization/v3/restconf/operations/cisco-crosswork-optimization-engine-sr-policy-operations:sr-policy-delete` (`cnc_delete_sr_policy`) — ends in the segment `cisco-crosswork-optimization-engine-sr-policy-operations:sr-policy-delete`, not `delete`, so it stays permitted too; no POST any tool sends on these 10 APIs ends in `/delete`.

> **Warning — never load a role body with a url other than `"/.*"`.** A role whose FIRST `allowed_urls` entry on some api_id has any other url **crashes the Roles page for everyone** (verified 2026-09-15: `TypeError: Cannot read properties of undefined (reading 'read')` in the editor's `setAccess` — it looks the url up among its `"/.*"` rows and finds nothing) and the whole page renders blank until the role is fixed through the API or deleted. The service's own appended templates are custom urls too, but they sit at index 1 or later, which the editor never reads. Independently of the crash the service does not store every custom-URL shape verbatim either (2026-09-14: a row whose only entry was a custom-URL POST came back with its methods stripped to `[]` and the not-delete pattern above appended — a wider grant than the url submitted — on the nine APIs it was tried on). The generated bodies carry `"/.*"` only.

**From the Tyk v5.1.1 gateway source** (`gateway/api_loader.go`, `mw_access_rights.go`, `mw_granular_access.go`), confirmed live 2026-09-15 by users carrying the generated roles (read-only: 262 read calls answered, the 7 predicted refusals the smoke exercises answered 403, nothing unpredicted was refused, two writes refused as predicted; operator: all 432 read and write steps of the smoke answered, every created object removed again, no 403 at all; the smoke runs were on the previous generation of the bodies — those of the 245 tools registered on 2026-09-15 (182 read) — which differed from the generated bodies of those tools only in the two AAA rows — `aaa_cwaaa` a GET pattern limited to the paths the tools send then, `/.*` now; `aaa_cw_role_read` in the body then, left to the baseline row now — `versions` and the `rate` field; the bodies as committed now also carry what the 37 tools added since (2 read, 35 write) need — rows and ticks that smoke did not exercise — and the refusal predictions for the tools of that day are identical (the same 14 read tools refused under `cnc-mcp-readonly`, `cnc_reactivate_probe` permitted, every tool permitted under `cnc-mcp-operator`); the bodies as committed were stored through the API and read back (2026-09-15: `tests/fixtures/rbac/stored_generated_readonly.json`, `tests/fixtures/rbac/stored_generated_operator.json`); evaluated on the stored form they give the same verdict for every tool as the model — `cnc-mcp-readonly`: 170 of the 184 read tools permitted, 14 refused, 1 write tool permitted (`cnc_reactivate_probe`); `cnc-mcp-operator`: 282 of 282 permitted):

- Tyk registers the API definitions **longest listen path first** and each as a gorilla-mux path prefix, so a request goes to the API with the longest listen path that claims it; `{...}` in a listen path matches one segment. The map's router additionally requires the match to end at a segment boundary and accepts a missing trailing slash; no template in the map routes differently under either reading (`tests/test_rbac_map.py`). The query string is not part of the match.
- Within the routed API, each `allowed_urls[].url` is run as an **unanchored regex search against the full request path** (`regexp.MatchString` on `r.URL.Path`; the listen path is not stripped first): `/nodes` permits `/crosswork/inventory/v1/nodes/query`, `^/v1/nodes/query$` permits nothing, and `/.+/query$` (an inventory read template) permits every `.../query` under the API. The method must be listed on a matching entry; an API with an empty `allowed_urls` has no path restriction.
- A request the role does not permit is refused with a **403** whose body names which check failed (observed 2026-09-15): `{"error": "Access to this API has been disallowed"}` when the role has no entry for the API at all (`PUT /crosswork/alarms/v1/ack` under the read-only role), `{"error": "Access to this resource has been disallowed"}` when the API is granted but no `allowed_urls` entry covers the path and method (`POST /crosswork/inventory/v1/tags`). Neither is an authentication failure: the server does not re-login on them. Two fail-open cases: an `allowed_urls` regex that does not compile is let through, and so is a role whose `access_rights` map is empty — cnc_check_permissions reports both as refusals (the role as it should be configured).

**Not verified:**

- The editor's wire shape, the display-name groups, the stored form of single-tick, per-tick and union entries (the generated bodies read back), the baseline rows, the split of a Write-without-Delete row on `cwcollection`, `optima_restconf`, `platform_cwplatform` and the gateway's refusals are all observed. Read from the UI bundle but not exercised live: how the editor displays and re-saves an API-loaded role (the group rows above, section 6). Extrapolated, not read back: the same split on the 7 other POST-delete APIs (from a POST-only experiment), and what the service stores for a Write-only row on any of them, or a row carrying DELETE on one other than `cw-ztp-service` (the bodies have none). What is still static is the map itself (section 6: a source-derived heuristic, no tool endpoint is called), a device access group is reported, not evaluated, and whether task bundles exist for roles other than admin (section 5) is unknown.

## 2. Least-privilege recipe: a read-only account

The 184 read-only tools touch 43 API rows; 42 of them go in the role, the other one — `aaa_cw_role_read` — is the baseline row every role has (cnc_check_permissions reads the role through it). **`docs/rbac/cnc-mcp-readonly.role.json` (section 6) grants the Read tick on every one of those 42 rows and nothing else** — R only, never W — in the shape the editor submits (section 1). Building the same account in the editor (Administration > Users and Roles > Roles: create a role, tick **Read** on the 30 editor rows of the first table under their feature, leave `ApiAccess` on) also grants the 74 sibling api_ids in its last column, because a row is a display-name group; the body grants only the api_ids the tools use (second table). Assign the role to a dedicated service account with device access group `ALL-ACCESS` (or the device scope you intend).

**By editor row** (tick Read on each):

| feature | editor row | api_ids the read tools use | sibling api_ids the tick also grants |
|---|---|---|---|
| AAA | Users and Roles Management | `aaa_cwaaa` | `get-WebSocket-Subscription`, `get-WebSocket-Subscription-700` |
| Administrative Operations | External Notification Subscription | `external-notification-subscription` | `alarm-topics-filter`, `external-kafka-destination`, `external-kafka-destination-v2`, `external-kafka-subscription`, `kafka-destinations-to-cw-ui` |
| Administrative Operations | Performance Monitoring Data Retention | `performance-dataretention-apis` | — |
| Administrative Operations | RESTCONF Notification Subscription | `nb-api-alarm-nt-2-700`, `nb-api-alarm-nt-9-700`, `nb-api-subscription-api-700` | `nb-api-alarm-nt-2`, `nb-api-alarm-nt-3`, `nb-api-alarm-nt-3-700`, `nb-api-alarm-nt-4`, `nb-api-alarm-nt-4-700`, `nb-api-alarm-nt-5`, `nb-api-alarm-nt-5-700`, `nb-api-alarm-nt-6`, `nb-api-alarm-nt-6-700`, `nb-api-alarm-nt-9`, `nb-api-subscription-api` |
| Alarms and Events | Alarm Settings | `cw-fault-alarm-manager-settings`, `cw-fault-alarm-recommended-action`, `cw-fault-alarm-settings`, `cw-fault-alarm-severity-settings`, `cw-fault-gnmi-settings` | `cw-fault-alarm-autoclear`, `cw-fault-alarm-autoclear-revert` |
| Alarms and Events | Alarm Suppression Policies | `event-processing-service-suppressionpolicy-api` | — |
| Alarms and Events | Alarms & Events | `cw-fault-alarms-api`, `cw-fault-events-api` | `alarm-processing-service`, `alarm-rest-service`, `alarm-rest-service-networkinventory-rest-api`, `alarm-rest-service-summary-rest-api`, `cw-fault-ack-alarm`, `cw-fault-ack-api`, `cw-fault-ack-api-v2`, `cw-fault-alarm-categories`, `cw-fault-alarm-custom-eventtype`, `cw-fault-alarm-custom-subeventtype`, `cw-fault-alarm-custom-syslog`, `cw-fault-alarm-custom-trap`, `cw-fault-alarm-eventtype`, `cw-fault-alarms-api-v2`, `cw-fault-clear-alarm`, `cw-fault-clear-api`, `cw-fault-clear-api-v2`, `cw-fault-create_events_api`, `cw-fault-create_events_api_v2`, `cw-fault-events-api-v2`, `cw-fault-get-alarms`, `cw-fault-get-events`, `cw-fault-manifest_api`, `cw-fault-manifest_api_v2`, `cw-fault-notes-alarm`, `cw-fault-notes-api`, `cw-fault-notes-api-v2`, `data-retention-service`, `event-processing-service` |
| Alarms and Events | Alarms and Events RESTCONF | `nb-api-alarm-1-700` | `nb-api-alarm-1`, `nb-api-alarm-2`, `nb-api-alarm-3`, `nb-api-alarm-5`, `nb-api-alarm-5-700` |
| CNC | CAT FP Deployment Manager APIs | `cat-fp-deployment-manager` | — |
| CNC | CAT Inventory RESTCONF APIs | `tsdn_cat-restconf-nbi` | — |
| Collection Infra | Collection APIs | `cwcollection` | — |
| Collection Infra | Data Gateway Manager APIs | `collection_dg-manager` | — |
| Crosswork Optimization Engine | OPTIMA Analytics | `optima_analytics_api` | — |
| Crosswork Optimization Engine | Optimization Engine RESTCONF | `optima_restconf` | — |
| Data Gateway Global Settings | Data Gateway Global Parameters API | `dg-manager-global-parameters-api` | — |
| Device Configuration | Device Configuration | `device-config` | — |
| Device Monitoring | Device Inventory | `cw-inventory-job-dashboard`, `ems-inventory` | `cw-inventory`, `cw-inventory-job-dashboard-deprecated`, `ems-inventory-deprecated`, `ems-inventory-diagnostics` |
| Device Monitoring | Device Inventory RESTCONF | `nb-api-inv-chassis-700`, `nb-api-inv-equipment-700`, `nb-api-inv-module-700`, `nb-api-inv-node-700`, `nb-api-inv-tp-700` | `nb-api-inv-chassis`, `nb-api-inv-equipment`, `nb-api-inv-module`, `nb-api-inv-node`, `nb-api-inv-physicalconnector`, `nb-api-inv-physicalconnector-700`, `nb-api-inv-tp` |
| Device Monitoring | Performance Monitoring Dashboards | `performance-rest-apis` | — |
| Device Monitoring | Performance Monitoring Policies | `performance-policies-rest-apis` | — |
| Inventory | Inventory APIs | `inventory_cwinventory` | — |
| Platform | Grouping | `cw-grouping-service` | — |
| Platform | Platform APIs | `platform_cwplatform` | — |
| Probe Manager | Probe Manager APIs | `cw-probe-mgr` | — |
| Proxy | Crosswork Proxy APIs | `proxy_cw-proxy` | — |
| Software Image Management | SWIM | `swim-nbi` | `swim-collection`, `swim-jobrest`, `swim-nbi-new`, `swim-recommendation`, `swim-repository`, `swim-rest`, `swim-treetable` |
| Topology RESTCONF | Topology RESTCONF | `topo_restconf` | — |
| Zero Touch Provisioning | Config Service | `cw-config-service-deprecated` | `cw-config-service` |
| Zero Touch Provisioning | Image Service | `cw-image-service-deprecated` | `cw-image-service` |
| Zero Touch Provisioning | ZTP Service | `cw-ztp-service` | — |

**By api_id** (what an API-loaded body grants; the last column is the tick(s) the read tools' requests need on the row — R = every GET plus the POSTs the row's read template names, W = the other POSTs and every PUT/PATCH, D = DELETE):

| feature | api_id | API name (editor row) | ticks the read tools need |
|---|---|---|---|
| AAA | `aaa_cw_role_read` | Know my role - Read only | R (baseline row: every role has it) |
| AAA | `aaa_cwaaa` | Users and Roles Management | R |
| Administrative Operations | `external-notification-subscription` | External Notification Subscription | R |
| Administrative Operations | `nb-api-alarm-nt-2-700` | RESTCONF Notification Subscription | R |
| Administrative Operations | `nb-api-alarm-nt-9-700` | RESTCONF Notification Subscription | R |
| Administrative Operations | `nb-api-subscription-api-700` | RESTCONF Notification Subscription | R |
| Administrative Operations | `performance-dataretention-apis` | Performance Monitoring Data Retention | R |
| Alarms and Events | `cw-fault-alarm-manager-settings` | Alarm Settings | R |
| Alarms and Events | `cw-fault-alarm-recommended-action` | Alarm Settings | R |
| Alarms and Events | `cw-fault-alarm-settings` | Alarm Settings | R |
| Alarms and Events | `cw-fault-alarm-severity-settings` | Alarm Settings | R |
| Alarms and Events | `cw-fault-alarms-api` | Alarms & Events | R |
| Alarms and Events | `cw-fault-events-api` | Alarms & Events | R |
| Alarms and Events | `cw-fault-gnmi-settings` | Alarm Settings | R |
| Alarms and Events | `event-processing-service-suppressionpolicy-api` | Alarm Suppression Policies | R |
| Alarms and Events | `nb-api-alarm-1-700` | Alarms and Events RESTCONF | R |
| CNC | `cat-fp-deployment-manager` | CAT FP Deployment Manager APIs | R |
| CNC | `tsdn_cat-restconf-nbi` | CAT Inventory RESTCONF APIs | R |
| Collection Infra | `collection_dg-manager` | Data Gateway Manager APIs | R |
| Collection Infra | `cwcollection` | Collection APIs | RW |
| Crosswork Optimization Engine | `optima_analytics_api` | OPTIMA Analytics | R |
| Crosswork Optimization Engine | `optima_restconf` | Optimization Engine RESTCONF | RW |
| Data Gateway Global Settings | `dg-manager-global-parameters-api` | Data Gateway Global Parameters API | R |
| Device Configuration | `device-config` | Device Configuration | RW |
| Device Monitoring | `cw-inventory-job-dashboard` | Device Inventory | R |
| Device Monitoring | `ems-inventory` | Device Inventory | R |
| Device Monitoring | `nb-api-inv-chassis-700` | Device Inventory RESTCONF | R |
| Device Monitoring | `nb-api-inv-equipment-700` | Device Inventory RESTCONF | R |
| Device Monitoring | `nb-api-inv-module-700` | Device Inventory RESTCONF | R |
| Device Monitoring | `nb-api-inv-node-700` | Device Inventory RESTCONF | R |
| Device Monitoring | `nb-api-inv-tp-700` | Device Inventory RESTCONF | R |
| Device Monitoring | `performance-policies-rest-apis` | Performance Monitoring Policies | R |
| Device Monitoring | `performance-rest-apis` | Performance Monitoring Dashboards | R |
| Inventory | `inventory_cwinventory` | Inventory APIs | RW |
| Platform | `cw-grouping-service` | Grouping | R |
| Platform | `platform_cwplatform` | Platform APIs | R |
| Probe Manager | `cw-probe-mgr` | Probe Manager APIs | R |
| Proxy | `proxy_cw-proxy` | Crosswork Proxy APIs | R |
| Software Image Management | `swim-nbi` | SWIM | R |
| Topology RESTCONF | `topo_restconf` | Topology RESTCONF | R |
| Zero Touch Provisioning | `cw-config-service-deprecated` | Config Service | R |
| Zero Touch Provisioning | `cw-image-service-deprecated` | Image Service | R |
| Zero Touch Provisioning | `cw-ztp-service` | ZTP Service | R |

`aaa_cwaaa` (`/crosswork/aaa/`, editor row *Users and Roles Management*) is what the RBAC read tools read users, roles and sessions through. Drop that row and the account can no longer read them: the gateway refuses these 10 tools — `cnc_get_password_policy`, `cnc_get_role_permissions`, `cnc_get_role_tasks`, `cnc_get_session_config`, `cnc_get_user`, `cnc_is_nso_configured`, `cnc_list_active_sessions`, `cnc_list_roles`, `cnc_list_secured_apis`, `cnc_list_users`. cnc_check_permissions keeps working without it: it reads the role through the `aaa_cw_role_read` baseline row and falls back to `aaa/v1` only when the mirror answers 403/404 (either row suffices for it).

Read on these rows also permits what the write tools read before they write: 5 GET request templates no read tool sends — `GET /crosswork/configsvc/v1/configs/files/{}` and `GET /crosswork/configsvc/v1/configs/{}` on `cw-config-service-deprecated`; `GET /crosswork/performance/v1/policies/inventory-devices` on `performance-policies-rest-apis`; `GET /crosswork/proxy/nso/restconf/data/{}-plan={}` and `GET /crosswork/proxy/nso/restconf/data/{}/{}-plan={}` on `proxy_cw-proxy` — sent by 16 write tools, and the 1 POST a read template names — `POST /crosswork/probemgr/v1/reactivateProbe` on `cw-probe-mgr` (`cnc_reactivate_probe`). `cnc_reactivate_probe` is the one write tool whose every request the role permits (section 6); every other write tool also sends a request it refuses.

### The 14 read tools a Read-only role cannot call

Under the stored `cnc-mcp-readonly` role (its 42 R rows plus the read templates and baseline rows the service adds — 45 rows as read back) cnc_check_permissions permits 170 of the 184 read tools. The other 14 read through a POST Crosswork classes as a **write** — the path is outside the API's read template (or the API has none) — so the gateway would refuse it (403) under Read:

- `cwcollection` — Read permits POST on `cwcollection` only where the path matches `/.+/query$`, `/.+/v1/jobs/events$`:
  - `cnc_list_sensor_templates`: `POST /crosswork/collection/v1/template`
- `device-config` — Read permits POST on `device-config` only where the path matches `/.+/query$`:
  - `cnc_get_config_backup_job`: `POST /crosswork/config/v1/config-backup-job/{}`
  - `cnc_list_config_backup_jobs`: `POST /crosswork/config/v1/config-backup-jobs`
  - `cnc_wait_for_config_backup_job`: `POST /crosswork/config/v1/config-backup-job/{}`
- `inventory_cwinventory` — Read permits POST on `inventory_cwinventory` only where the path matches `/.+/query$`:
  - `cnc_check_nso_device_sync`: `POST /crosswork/inventory/v1/nso/check-sync`
  - `cnc_investigate_device`: `POST /crosswork/inventory/v1/nso/check-sync`
- `optima_restconf` — Read permits POST on `optima_restconf` only where the path matches `/.+(sr-policy-dryrun|get-plan|sr-policies-on-interface|sr-policies-on-node|sr-policy-routes|sr-policy-route-preview|rsvp-te-tunnel-dryrun|get-lcm-domains|get-lcm-recommendation-preview|get-lcm-recommendation-policies|get-lcm-recommendation|get-lcm-config|get-lcm-managed-interfaces|cs-policy-paths-on-interface|cs-policy-paths-on-nodes|all-cs-policy-paths|get-csm-interfaces-bandwidth-pool)$`:
  - `cnc_explain_sr_policy`: `POST /crosswork/nbi/optimization/v3/restconf/operations/cisco-crosswork-optimization-engine-operations:sr-policy-metrics`
  - `cnc_get_lcm_recommendation_preview`: `POST /crosswork/nbi/optimization/v3/restconf/operations/cisco-crosswork-optimization-engine-lcm-recommendation-operations:get-lcm-msl-recommendation-preview` — its `POST /crosswork/nbi/optimization/v3/restconf/operations/cisco-crosswork-optimization-engine-lcm-recommendation-operations:get-lcm-recommendation-preview` (the legacy RPC, `msl=false`) is within the template, so that form of the call runs under Read
  - `cnc_get_oam_settings`: `POST /crosswork/nbi/optimization/v3/restconf/operations/cisco-crosswork-optimization-engine-oam-operations:get-oam-delete-interval`
  - `cnc_get_oam_trace_route`: `POST /crosswork/nbi/optimization/v3/restconf/operations/cisco-crosswork-optimization-engine-oam-operations:get-oam-trace-route-by-query-id`
  - `cnc_get_sr_policy_metrics`: `POST /crosswork/nbi/optimization/v3/restconf/operations/cisco-crosswork-optimization-engine-operations:sr-policy-metrics`
  - `cnc_get_sr_policy_path_notification_state`: `POST /crosswork/nbi/optimization/v3/restconf/operations/cisco-crosswork-optimization-engine-operations:get-interface-sr-policy-paths-notification-state`
  - `cnc_list_oam_trace_routes`: `POST /crosswork/nbi/optimization/v3/restconf/operations/cisco-crosswork-optimization-engine-oam-operations:get-oam-trace-route-by-query`
  - `cnc_wait_for_oam_trace_route`: `POST /crosswork/nbi/optimization/v3/restconf/operations/cisco-crosswork-optimization-engine-oam-operations:get-oam-trace-route-by-query-id`

Two ways to handle them:

1. **Tick Write as well as Read** on the rows above — the account is then no longer read-only at the gateway, because Write is `/.*` on the whole API for PUT/PATCH and — except on the POST-delete APIs of section 1 — for POST, and a narrower custom-URL entry is not an option (section 1's warning):
  - `cwcollection`: Write also permits every POST/PUT/PATCH the API serves (no cnc-mcp write tool uses it) — POST under the not-delete pattern, every path except one ending in `/delete` (section 1).
  - `device-config`: Write also permits what its 3 write tools (`cnc_backup_device_config`, `cnc_create_config_template`, `cnc_deploy_config_template`) do there, and any other POST/PUT/PATCH the API serves.
  - `inventory_cwinventory`: Write also permits what its 18 write tools (`cnc_assign_tags`, `cnc_clear_device_location`, `cnc_create_credential_profile`, `cnc_create_device`, `cnc_create_provider`, `cnc_create_tag`, `cnc_enable_device_gnmi`, `cnc_lock_device`, `cnc_map_devices_to_data_gateway`, `cnc_nso_device_action`, `cnc_nso_sync_to_device`, `cnc_set_device_location`, `cnc_sync_inventory_with_nso`, `cnc_unassign_tags`, `cnc_unlock_device`, `cnc_update_credential_profile`, `cnc_update_device`, `cnc_update_provider`) do there, and any other POST/PUT/PATCH the API serves.
  - `optima_restconf`: Write also permits what its 8 write tools (`cnc_create_sr_policy`, `cnc_create_sr_policy_e2e`, `cnc_delete_sr_policy`, `cnc_pause_lcm_recommendations`, `cnc_provision_l3vpn_e2e`, `cnc_set_sr_policy_path_notifications`, `cnc_start_oam_trace_route`, `cnc_update_sr_policy`) do there, and any other POST/PUT/PATCH the API serves — POST under the not-delete pattern, every path except one ending in `/delete` (section 1).
2. **Leave them refused** (they answer the gateway's 403 with a hint pointing at cnc_check_permissions) or, better, keep the agent from seeing them: `CNC_MCP_DISABLED_TOOLS=cnc_check_nso_device_sync,cnc_explain_sr_policy,cnc_get_config_backup_job,cnc_get_lcm_recommendation_preview,cnc_get_oam_settings,cnc_get_oam_trace_route,cnc_get_sr_policy_metrics,cnc_get_sr_policy_path_notification_state,cnc_investigate_device,cnc_list_config_backup_jobs,cnc_list_oam_trace_routes,cnc_list_sensor_templates,cnc_wait_for_config_backup_job,cnc_wait_for_oam_trace_route`. (`cnc_get_lcm_recommendation_preview` is in the list although one form of the call runs under Read, above — leave it out to keep that form.)

## 3. Write areas: what each adds

Write tools are registered only with `CNC_MCP_ENABLE_WRITES=true`. Per area (the `tools/` module), the editor rows and ticks a role needs **in addition to** the read-only recipe of section 2 — a row already ticked Read is listed only when the writes add Write or Delete on it; the api_id column says which member(s) of the row the writes use, the last column which sibling api_ids the tick grants as well (the body grants the members only). `docs/rbac/cnc-mcp-operator.role.json` is section 2 plus every area below, plus the Write ticks the 14 read tools of section 2 need (`cwcollection`, `device-config`, `inventory_cwinventory`, `optima_restconf`).

### admin (3 write tools: `cnc_restart_microservice`, `cnc_set_login_banner`, `cnc_set_maintenance_mode`)

| feature | editor row | api_ids the writes use | sibling api_ids the tick also grants | ticks to add |
|---|---|---|---|---|
| Platform | Platform APIs | `platform_cwplatform` W | — | W |

### composite (2 write tools: `cnc_create_sr_policy_e2e`, `cnc_provision_l3vpn_e2e`)

| feature | editor row | api_ids the writes use | sibling api_ids the tick also grants | ticks to add |
|---|---|---|---|---|
| Crosswork Optimization Engine | Optimization Engine RESTCONF | `optima_restconf` W | — | W |
| Proxy | Crosswork Proxy APIs | `proxy_cw-proxy` W | — | W |

### credentials (3 write tools: `cnc_create_credential_profile`, `cnc_delete_credential_profile`, `cnc_update_credential_profile`)

| feature | editor row | api_ids the writes use | sibling api_ids the tick also grants | ticks to add |
|---|---|---|---|---|
| Inventory | Inventory APIs | `inventory_cwinventory` WD | — | WD |

### data_gateway (1 write tool: `cnc_map_devices_to_data_gateway`)

| feature | editor row | api_ids the writes use | sibling api_ids the tick also grants | ticks to add |
|---|---|---|---|---|
| Inventory | Inventory APIs | `inventory_cwinventory` W | — | W |

### device_config (7 write tools: `cnc_backup_device_config`, `cnc_create_config_template`, `cnc_delete_config_backup_job`, `cnc_delete_config_template`, `cnc_delete_device_backup`, `cnc_delete_template_deployment`, `cnc_deploy_config_template`)

| feature | editor row | api_ids the writes use | sibling api_ids the tick also grants | ticks to add |
|---|---|---|---|---|
| Device Configuration | Device Configuration | `device-config` WD | — | WD |

### devices (4 write tools: `cnc_create_device`, `cnc_delete_device`, `cnc_enable_device_gnmi`, `cnc_update_device`)

| feature | editor row | api_ids the writes use | sibling api_ids the tick also grants | ticks to add |
|---|---|---|---|---|
| Inventory | Inventory APIs | `inventory_cwinventory` WD | — | WD |

### ems_jobs (3 write tools: `cnc_resume_inventory_scheduler_job`, `cnc_run_inventory_scheduler_job`, `cnc_suspend_inventory_scheduler_job`)

| feature | editor row | api_ids the writes use | sibling api_ids the tick also grants | ticks to add |
|---|---|---|---|---|
| Device Monitoring | Device Inventory | `cw-inventory-job-dashboard` W | `cw-inventory`, `cw-inventory-job-dashboard-deprecated`, `ems-inventory`, `ems-inventory-deprecated`, `ems-inventory-diagnostics` | W |

### fault (12 write tools: `cnc_acknowledge_alarm`, `cnc_annotate_alarm`, `cnc_clear_alarm`, `cnc_create_alarm_suppression_policy`, `cnc_delete_alarm_suppression_policy`, `cnc_revert_event_type_autoclear`, `cnc_set_event_type_autoclear`, `cnc_set_event_type_recommendation`, `cnc_set_event_type_severity`, `cnc_update_alarm_manager_settings`, `cnc_update_alarm_suppression_policy`, `cnc_update_gnmi_alarm_settings`)

| feature | editor row | api_ids the writes use | sibling api_ids the tick also grants | ticks to add |
|---|---|---|---|---|
| Alarms and Events | Alarm Settings | `cw-fault-alarm-autoclear` W, `cw-fault-alarm-autoclear-revert` W, `cw-fault-alarm-manager-settings` W, `cw-fault-alarm-recommended-action` W, `cw-fault-alarm-severity-settings` W, `cw-fault-gnmi-settings` W | `cw-fault-alarm-settings` | W |
| Alarms and Events | Alarm Suppression Policies | `event-processing-service-suppressionpolicy-api` WD | — | WD |
| Alarms and Events | Alarms & Events | `cw-fault-ack-api` W, `cw-fault-clear-api` W, `cw-fault-notes-api` W | `alarm-processing-service`, `alarm-rest-service`, `alarm-rest-service-networkinventory-rest-api`, `alarm-rest-service-summary-rest-api`, `cw-fault-ack-alarm`, `cw-fault-ack-api-v2`, `cw-fault-alarm-categories`, `cw-fault-alarm-custom-eventtype`, `cw-fault-alarm-custom-subeventtype`, `cw-fault-alarm-custom-syslog`, `cw-fault-alarm-custom-trap`, `cw-fault-alarm-eventtype`, `cw-fault-alarms-api`, `cw-fault-alarms-api-v2`, `cw-fault-clear-alarm`, `cw-fault-clear-api-v2`, `cw-fault-create_events_api`, `cw-fault-create_events_api_v2`, `cw-fault-events-api`, `cw-fault-events-api-v2`, `cw-fault-get-alarms`, `cw-fault-get-events`, `cw-fault-manifest_api`, `cw-fault-manifest_api_v2`, `cw-fault-notes-alarm`, `cw-fault-notes-api-v2`, `data-retention-service`, `event-processing-service` | W |

### grouping (5 write tools: `cnc_create_device_group`, `cnc_delete_device_group`, `cnc_move_group_members`, `cnc_set_device_group_members`, `cnc_update_device_group`)

| feature | editor row | api_ids the writes use | sibling api_ids the tick also grants | ticks to add |
|---|---|---|---|---|
| Platform | Grouping | `cw-grouping-service` WD | — | WD |

### inventory_extras (8 write tools: `cnc_assign_tags`, `cnc_clear_device_location`, `cnc_create_tag`, `cnc_delete_tag`, `cnc_lock_device`, `cnc_set_device_location`, `cnc_unassign_tags`, `cnc_unlock_device`)

| feature | editor row | api_ids the writes use | sibling api_ids the tick also grants | ticks to add |
|---|---|---|---|---|
| Inventory | Inventory APIs | `inventory_cwinventory` WD | — | WD |

### lcm_csm (1 write tool: `cnc_pause_lcm_recommendations`)

| feature | editor row | api_ids the writes use | sibling api_ids the tick also grants | ticks to add |
|---|---|---|---|---|
| Crosswork Optimization Engine | Optimization Engine RESTCONF | `optima_restconf` W | — | W |

### notifications (5 write tools: `cnc_clear_notification_subscriptions_by_topic`, `cnc_create_external_subscription`, `cnc_create_webhook_subscription`, `cnc_delete_external_subscription`, `cnc_delete_notification_subscription`)

| feature | editor row | api_ids the writes use | sibling api_ids the tick also grants | ticks to add |
|---|---|---|---|---|
| Administrative Operations | External Notification Subscription | `external-notification-subscription` WD | `alarm-topics-filter`, `external-kafka-destination`, `external-kafka-destination-v2`, `external-kafka-subscription`, `kafka-destinations-to-cw-ui` | WD |
| Administrative Operations | RESTCONF Notification Subscription | `nb-api-alarm-nt-3-700` W, `nb-api-subscription-api-700` WD | `nb-api-alarm-nt-2`, `nb-api-alarm-nt-2-700`, `nb-api-alarm-nt-3`, `nb-api-alarm-nt-4`, `nb-api-alarm-nt-4-700`, `nb-api-alarm-nt-5`, `nb-api-alarm-nt-5-700`, `nb-api-alarm-nt-6`, `nb-api-alarm-nt-6-700`, `nb-api-alarm-nt-9`, `nb-api-alarm-nt-9-700`, `nb-api-subscription-api` | WD |

### nso (3 write tools: `cnc_nso_device_action`, `cnc_nso_sync_to_device`, `cnc_sync_inventory_with_nso`)

| feature | editor row | api_ids the writes use | sibling api_ids the tick also grants | ticks to add |
|---|---|---|---|---|
| Inventory | Inventory APIs | `inventory_cwinventory` W | — | W |

### oam (2 write tools: `cnc_reactivate_probe`, `cnc_start_oam_trace_route`)

| feature | editor row | api_ids the writes use | sibling api_ids the tick also grants | ticks to add |
|---|---|---|---|---|
| Crosswork Optimization Engine | Optimization Engine RESTCONF | `optima_restconf` W | — | W |

### performance (7 write tools: `cnc_activate_performance_policy`, `cnc_create_performance_policy`, `cnc_deactivate_performance_policy`, `cnc_delete_performance_policy`, `cnc_reset_performance_retention`, `cnc_update_performance_policy`, `cnc_update_performance_retention`)

| feature | editor row | api_ids the writes use | sibling api_ids the tick also grants | ticks to add |
|---|---|---|---|---|
| Administrative Operations | Performance Monitoring Data Retention | `performance-dataretention-apis` W | — | W |
| Device Monitoring | Performance Monitoring Policies | `performance-policies-rest-apis` WD | — | WD |

### providers (3 write tools: `cnc_create_provider`, `cnc_delete_provider`, `cnc_update_provider`)

| feature | editor row | api_ids the writes use | sibling api_ids the tick also grants | ticks to add |
|---|---|---|---|---|
| Inventory | Inventory APIs | `inventory_cwinventory` WD | — | WD |

### service_provisioning (12 write tools: `cnc_create_l3vpn_service`, `cnc_create_odn_template`, `cnc_create_sid_list`, `cnc_create_sr_policy_service`, `cnc_delete_odn_template`, `cnc_delete_service`, `cnc_delete_sid_list`, `cnc_delete_sr_policy_service`, `cnc_delete_vpn_service`, `cnc_provision_service`, `cnc_resync_service_inventory`, `cnc_update_sr_policy_service`)

| feature | editor row | api_ids the writes use | sibling api_ids the tick also grants | ticks to add |
|---|---|---|---|---|
| CNC | NSO Connector APIs | `nso-connector` W | — | W |
| Proxy | Crosswork Proxy APIs | `proxy_cw-proxy` WD | — | WD |

### sr_te_operations (4 write tools: `cnc_create_sr_policy`, `cnc_delete_sr_policy`, `cnc_set_sr_policy_path_notifications`, `cnc_update_sr_policy`)

| feature | editor row | api_ids the writes use | sibling api_ids the tick also grants | ticks to add |
|---|---|---|---|---|
| Crosswork Optimization Engine | Optimization Engine RESTCONF | `optima_restconf` W | — | W |

### swim_ztp (13 write tools: `cnc_add_ztp_serial_numbers`, `cnc_create_ztp_device`, `cnc_create_ztp_profile`, `cnc_create_ztp_static_route`, `cnc_delete_ztp_config_file`, `cnc_delete_ztp_device`, `cnc_delete_ztp_profile`, `cnc_delete_ztp_serial_numbers`, `cnc_delete_ztp_static_route`, `cnc_update_ztp_config_file`, `cnc_update_ztp_device`, `cnc_update_ztp_profile`, `cnc_upload_ztp_config_file`)

| feature | editor row | api_ids the writes use | sibling api_ids the tick also grants | ticks to add |
|---|---|---|---|---|
| Zero Touch Provisioning | Config Service | `cw-config-service-deprecated` WD | `cw-config-service` | WD |
| Zero Touch Provisioning | ZTP Service | `cw-ztp-service` WD | — | WD |

`cnc-mcp-operator.role.json` carries 49 rows: 26 with Write, 10 with Delete, 7 Write-only (no read tool uses the API).

## 4. Per-tool requirements

Every registered tool with the api_id(s) it needs and the ticks per api_id (R = GET, or a POST the row's read template names; W = any other POST, PUT, PATCH; D = DELETE; a tool that passes the method through needs all three). Playbooks (area `composite`) send nothing themselves: their rows are the union of the siblings they call. A tool that tries one API and falls back to another lists its alternatives with *or*: one of them suffices. The HTTP methods and path templates behind each cell are in `src/cnc_mcp/data/rbac_map.json`.

| tool | area | kind | api_id: ticks |
|---|---|---|---|
| `cnc_acknowledge_alarm` | fault | write | `cw-fault-ack-api`: W, `cw-fault-alarms-api`: R |
| `cnc_activate_performance_policy` | performance | write | `performance-policies-rest-apis`: RW |
| `cnc_add_ztp_serial_numbers` | swim_ztp | write | `cw-ztp-service`: W |
| `cnc_alarm_triage` | composite | read playbook (4 siblings) | `cw-fault-alarms-api`: R, `nb-api-alarm-1-700`: R, `platform_cwplatform`: R |
| `cnc_annotate_alarm` | fault | write | `cw-fault-alarms-api`: R, `cw-fault-notes-api`: W |
| `cnc_assign_tags` | inventory_extras | write | `inventory_cwinventory`: RW |
| `cnc_backup_device_config` | device_config | write | `device-config`: W, `inventory_cwinventory`: R |
| `cnc_check_certificate_expiry` | admin | read | `platform_cwplatform`: R |
| `cnc_check_device_nso_state` | nso | read | `inventory_cwinventory`: R |
| `cnc_check_nso_device_sync` | nso | read (needs W, section 2) | `inventory_cwinventory`: RW |
| `cnc_check_permissions` | admin | read | `aaa_cw_role_read`: R *or* `aaa_cwaaa`: R |
| `cnc_clear_alarm` | fault | write | `cw-fault-alarms-api`: R, `cw-fault-clear-api`: W |
| `cnc_clear_device_location` | inventory_extras | write | `inventory_cwinventory`: RW |
| `cnc_clear_notification_subscriptions_by_topic` | notifications | write | `nb-api-alarm-nt-2-700`: R, `nb-api-alarm-nt-3-700`: W |
| `cnc_create_alarm_suppression_policy` | fault | write | `event-processing-service-suppressionpolicy-api`: W |
| `cnc_create_config_template` | device_config | write | `device-config`: W |
| `cnc_create_credential_profile` | credentials | write | `inventory_cwinventory`: RW |
| `cnc_create_device` | devices | write | `inventory_cwinventory`: W |
| `cnc_create_device_group` | grouping | write | `cw-grouping-service`: RWD |
| `cnc_create_external_subscription` | notifications | write | `collection_dg-manager`: R, `external-notification-subscription`: W |
| `cnc_create_l3vpn_service` | service_provisioning | write | `proxy_cw-proxy`: RW |
| `cnc_create_odn_template` | service_provisioning | write | `proxy_cw-proxy`: RW |
| `cnc_create_performance_policy` | performance | write | `performance-policies-rest-apis`: RW |
| `cnc_create_provider` | providers | write | `inventory_cwinventory`: W |
| `cnc_create_sid_list` | service_provisioning | write | `proxy_cw-proxy`: RW |
| `cnc_create_sr_policy` | sr_te_operations | write | `optima_restconf`: W, `topo_restconf`: R |
| `cnc_create_sr_policy_e2e` | composite | write playbook (4 siblings) | `optima_restconf`: RW, `topo_restconf`: R |
| `cnc_create_sr_policy_service` | service_provisioning | write | `proxy_cw-proxy`: RW |
| `cnc_create_tag` | inventory_extras | write | `inventory_cwinventory`: W |
| `cnc_create_webhook_subscription` | notifications | write | `nb-api-subscription-api-700`: W |
| `cnc_create_ztp_device` | swim_ztp | write | `cw-ztp-service`: RW |
| `cnc_create_ztp_profile` | swim_ztp | write | `cw-ztp-service`: RW |
| `cnc_create_ztp_static_route` | swim_ztp | write | `cw-ztp-service`: RW |
| `cnc_deactivate_performance_policy` | performance | write | `performance-policies-rest-apis`: W |
| `cnc_delete_alarm_suppression_policy` | fault | write | `event-processing-service-suppressionpolicy-api`: D |
| `cnc_delete_config_backup_job` | device_config | write | `device-config`: D |
| `cnc_delete_config_template` | device_config | write | `device-config`: D |
| `cnc_delete_credential_profile` | credentials | write | `inventory_cwinventory`: D |
| `cnc_delete_device` | devices | write | `inventory_cwinventory`: D |
| `cnc_delete_device_backup` | device_config | write | `device-config`: D, `inventory_cwinventory`: R |
| `cnc_delete_device_group` | grouping | write | `cw-grouping-service`: RD |
| `cnc_delete_external_subscription` | notifications | write | `external-notification-subscription`: D |
| `cnc_delete_notification_subscription` | notifications | write | `nb-api-subscription-api-700`: D |
| `cnc_delete_odn_template` | service_provisioning | write | `proxy_cw-proxy`: RD |
| `cnc_delete_performance_policy` | performance | write | `performance-policies-rest-apis`: D |
| `cnc_delete_provider` | providers | write | `inventory_cwinventory`: D |
| `cnc_delete_service` | service_provisioning | write | `proxy_cw-proxy`: RD |
| `cnc_delete_sid_list` | service_provisioning | write | `proxy_cw-proxy`: RD |
| `cnc_delete_sr_policy` | sr_te_operations | write | `optima_restconf`: W, `topo_restconf`: R |
| `cnc_delete_sr_policy_service` | service_provisioning | write | `proxy_cw-proxy`: RD |
| `cnc_delete_tag` | inventory_extras | write | `inventory_cwinventory`: D |
| `cnc_delete_template_deployment` | device_config | write | `device-config`: D |
| `cnc_delete_vpn_service` | service_provisioning | write | `proxy_cw-proxy`: RD |
| `cnc_delete_ztp_config_file` | swim_ztp | write | `cw-config-service-deprecated`: RD, `cw-ztp-service`: R |
| `cnc_delete_ztp_device` | swim_ztp | write | `cw-ztp-service`: RD |
| `cnc_delete_ztp_profile` | swim_ztp | write | `cw-ztp-service`: RD |
| `cnc_delete_ztp_serial_numbers` | swim_ztp | write | `cw-ztp-service`: RD |
| `cnc_delete_ztp_static_route` | swim_ztp | write | `cw-ztp-service`: RD |
| `cnc_deploy_config_template` | device_config | write | `device-config`: RW, `inventory_cwinventory`: R |
| `cnc_dryrun_sr_policy` | sr_te_operations | read | `optima_restconf`: R, `topo_restconf`: R |
| `cnc_enable_device_gnmi` | devices | write | `inventory_cwinventory`: RW |
| `cnc_explain_service` | composite | read playbook (7 siblings) | `cw-probe-mgr`: R, `proxy_cw-proxy`: R, `tsdn_cat-restconf-nbi`: R |
| `cnc_explain_sr_policy` | composite | read playbook (11 siblings) (needs W, section 2) | `inventory_cwinventory`: R, `optima_analytics_api`: R, `optima_restconf`: RW, `proxy_cw-proxy`: R, `topo_restconf`: R, `tsdn_cat-restconf-nbi`: R |
| `cnc_find_services_on_transport` | services | read | `inventory_cwinventory`: R, `tsdn_cat-restconf-nbi`: R |
| `cnc_get_alarm` | fault | read | `cw-fault-alarms-api`: R |
| `cnc_get_alarm_manager_settings` | fault | read | `cw-fault-alarm-manager-settings`: R |
| `cnc_get_alarm_settings` | fault | read | `cw-fault-alarm-settings`: R, `cw-fault-gnmi-settings`: R |
| `cnc_get_cluster_health` | admin | read | `platform_cwplatform`: R |
| `cnc_get_cluster_node` | admin | read | `platform_cwplatform`: R |
| `cnc_get_collection_cadence` | inventory_extras | read | `inventory_cwinventory`: R |
| `cnc_get_collection_health` | collection | read | `cwcollection`: R |
| `cnc_get_collection_job_count` | collection | read | `cwcollection`: R |
| `cnc_get_collection_job_state` | collection | read | `cwcollection`: R |
| `cnc_get_collection_job_summary` | collection | read | `cwcollection`: R |
| `cnc_get_config_backup_job` | device_config | read (needs W, section 2) | `device-config`: W |
| `cnc_get_config_template` | device_config | read | `device-config`: R |
| `cnc_get_credential_profile` | credentials | read | `inventory_cwinventory`: R |
| `cnc_get_data_gateway` | data_gateway | read | `collection_dg-manager`: R |
| `cnc_get_data_gateway_global_parameters` | data_gateway | read | `dg-manager-global-parameters-api`: R |
| `cnc_get_data_gateway_health` | data_gateway | read | `collection_dg-manager`: R |
| `cnc_get_data_gateway_load_metrics` | data_gateway | read | `collection_dg-manager`: R |
| `cnc_get_device` | devices | read | `inventory_cwinventory`: R |
| `cnc_get_device_backup` | device_config | read | `device-config`: R, `inventory_cwinventory`: R |
| `cnc_get_device_collection_summary` | devices | read | `ems-inventory`: R |
| `cnc_get_device_config_preferences` | device_config | read | `device-config`: R |
| `cnc_get_device_running_images` | swim_ztp | read | `swim-nbi`: R |
| `cnc_get_device_summary` | inventory_extras | read | `inventory_cwinventory`: R |
| `cnc_get_device_tags` | inventory_extras | read | `inventory_cwinventory`: R |
| `cnc_get_ems_interface` | physical_inventory | read | `nb-api-inv-tp-700`: R |
| `cnc_get_ems_inventory_summary` | physical_inventory | read | `nb-api-inv-chassis-700`: R, `nb-api-inv-equipment-700`: R, `nb-api-inv-module-700`: R, `nb-api-inv-node-700`: R |
| `cnc_get_ems_node` | physical_inventory | read | `nb-api-inv-node-700`: R |
| `cnc_get_event_type_recommendation` | fault | read | `cw-fault-alarm-recommended-action`: R |
| `cnc_get_group_details` | grouping | read | `cw-grouping-service`: R |
| `cnc_get_group_hierarchy` | grouping | read | `cw-grouping-service`: R |
| `cnc_get_interface_delay` | performance | read | `optima_analytics_api`: R |
| `cnc_get_inventory_config` | inventory_extras | read | `inventory_cwinventory`: R |
| `cnc_get_inventory_job` | platform | read | `inventory_cwinventory`: R |
| `cnc_get_inventory_scheduler_job` | ems_jobs | read | `cw-inventory-job-dashboard`: R |
| `cnc_get_lcm_config` | lcm_csm | read | `optima_restconf`: R |
| `cnc_get_lcm_recommendation` | lcm_csm | read | `optima_restconf`: R |
| `cnc_get_lcm_recommendation_preview` | lcm_csm | read (needs W, section 2) | `optima_restconf`: RW |
| `cnc_get_link_performance_metrics` | te_state | read | `topo_restconf`: R |
| `cnc_get_login_banner` | admin | read | `platform_cwplatform`: R |
| `cnc_get_lsp_delay` | performance | read | `optima_analytics_api`: R, `topo_restconf`: R |
| `cnc_get_lsp_utilization` | performance | read | `optima_analytics_api`: R, `topo_restconf`: R |
| `cnc_get_maintenance_status` | admin | read | `platform_cwplatform`: R |
| `cnc_get_node_interface` | topology | read | `topo_restconf`: R |
| `cnc_get_notification_subscription` | notifications | read | `nb-api-subscription-api-700`: R |
| `cnc_get_nso_device` | nso | read | `proxy_cw-proxy`: R |
| `cnc_get_nso_device_config` | nso | read | `proxy_cw-proxy`: R |
| `cnc_get_nso_policy` | nso | read | `inventory_cwinventory`: R |
| `cnc_get_oam_settings` | oam | read (needs W, section 2) | `optima_restconf`: W |
| `cnc_get_oam_trace_route` | oam | read (needs W, section 2) | `inventory_cwinventory`: R, `optima_restconf`: W |
| `cnc_get_p2mp_policy` | te_state | read | `topo_restconf`: R |
| `cnc_get_password_policy` | admin | read | `aaa_cwaaa`: R |
| `cnc_get_performance_health_settings` | performance | read | `performance-rest-apis`: R |
| `cnc_get_performance_policy` | performance | read | `performance-policies-rest-apis`: R |
| `cnc_get_performance_policy_history` | performance | read | `performance-policies-rest-apis`: R |
| `cnc_get_performance_retention` | performance | read | `performance-dataretention-apis`: R |
| `cnc_get_performance_statistics` | performance | read | `performance-policies-rest-apis`: R, `performance-rest-apis`: R, `topo_restconf`: R |
| `cnc_get_performance_summary` | performance | read | `performance-rest-apis`: R |
| `cnc_get_performance_top_n` | performance | read | `performance-rest-apis`: R |
| `cnc_get_platform_version` | admin | read | `platform_cwplatform`: R |
| `cnc_get_probe_status` | oam | read | `cw-probe-mgr`: R |
| `cnc_get_provider` | providers | read | `inventory_cwinventory`: R |
| `cnc_get_role_permissions` | admin | read | `aaa_cwaaa`: R |
| `cnc_get_role_tasks` | admin | read | `aaa_cwaaa`: R |
| `cnc_get_rsvp_te_tunnel` | te_state | read | `topo_restconf`: R |
| `cnc_get_rsvp_tunnel_performance_metrics` | te_state | read | `topo_restconf`: R |
| `cnc_get_service` | services | read | `proxy_cw-proxy`: R, `tsdn_cat-restconf-nbi`: R |
| `cnc_get_service_counts` | services | read | `tsdn_cat-restconf-nbi`: R |
| `cnc_get_service_plan` | services | read | `proxy_cw-proxy`: R, `tsdn_cat-restconf-nbi`: R |
| `cnc_get_session_config` | admin | read | `aaa_cwaaa`: R |
| `cnc_get_sr_policy` | te_state | read | `topo_restconf`: R |
| `cnc_get_sr_policy_metrics` | sr_te_operations | read (needs W, section 2) | `optima_restconf`: W, `topo_restconf`: R |
| `cnc_get_sr_policy_path_notification_state` | sr_te_operations | read (needs W, section 2) | `optima_restconf`: W |
| `cnc_get_sr_policy_performance_metrics` | te_state | read | `topo_restconf`: R |
| `cnc_get_sr_policy_routes` | sr_te_operations | read | `optima_restconf`: R, `topo_restconf`: R |
| `cnc_get_swim_job` | swim_ztp | read | `swim-nbi`: R |
| `cnc_get_swim_preferences` | swim_ztp | read | `swim-nbi`: R |
| `cnc_get_te_summary` | te_state | read | `topo_restconf`: R |
| `cnc_get_template_deployment` | device_config | read | `device-config`: R |
| `cnc_get_topology_link` | topology | read | `topo_restconf`: R |
| `cnc_get_topology_node` | topology | read | `topo_restconf`: R |
| `cnc_get_topology_summary` | topology | read | `topo_restconf`: R |
| `cnc_get_user` | admin | read | `aaa_cwaaa`: R |
| `cnc_get_vpn_service` | services | read | `tsdn_cat-restconf-nbi`: R |
| `cnc_get_vpn_service_health` | services | read | `tsdn_cat-restconf-nbi`: R |
| `cnc_get_vpn_underlay_transport` | services | read | `tsdn_cat-restconf-nbi`: R |
| `cnc_get_ztp_device_policy` | swim_ztp | read | `cw-ztp-service`: R |
| `cnc_investigate_device` | composite | read playbook (10 siblings) (needs W, section 2) | `cw-fault-alarms-api`: R, `cw-fault-events-api`: R, `device-config`: R, `ems-inventory`: R, `inventory_cwinventory`: RW, `nb-api-alarm-1-700`: R, `nb-api-inv-node-700`: R, `performance-policies-rest-apis`: R, `performance-rest-apis`: R, `topo_restconf`: R |
| `cnc_is_nso_configured` | nso | read | `aaa_cwaaa`: R |
| `cnc_list_active_sessions` | admin | read | `aaa_cwaaa`: R |
| `cnc_list_alarm_suppression_policies` | fault | read | `event-processing-service-suppressionpolicy-api`: R |
| `cnc_list_alarms` | platform | read | `cw-fault-alarms-api`: R |
| `cnc_list_app_manager_events` | admin | read | `platform_cwplatform`: R |
| `cnc_list_app_manager_jobs` | admin | read | `platform_cwplatform`: R |
| `cnc_list_application_status` | admin | read | `platform_cwplatform`: R |
| `cnc_list_applications` | platform | read | `platform_cwplatform`: R |
| `cnc_list_certificates` | admin | read | `platform_cwplatform`: R |
| `cnc_list_cluster_nodes` | admin | read | `platform_cwplatform`: R |
| `cnc_list_config_backup_jobs` | device_config | read (needs W, section 2) | `device-config`: W |
| `cnc_list_config_templates` | device_config | read | `device-config`: R |
| `cnc_list_credential_profiles` | credentials | read | `inventory_cwinventory`: R |
| `cnc_list_cs_policies_on_interface` | lcm_csm | read | `optima_restconf`: R, `topo_restconf`: R |
| `cnc_list_cs_policies_on_nodes` | lcm_csm | read | `optima_restconf`: R, `topo_restconf`: R |
| `cnc_list_cs_policy_paths` | lcm_csm | read | `optima_restconf`: R |
| `cnc_list_csm_bandwidth_pools` | lcm_csm | read | `optima_restconf`: R |
| `cnc_list_data_destinations` | data_gateway | read | `collection_dg-manager`: R |
| `cnc_list_data_gateway_files` | data_gateway | read | `collection_dg-manager`: R |
| `cnc_list_data_gateway_outages` | data_gateway | read | `collection_dg-manager`: R |
| `cnc_list_data_gateway_pools` | data_gateway | read | `collection_dg-manager`: R |
| `cnc_list_data_gateways` | data_gateway | read | `collection_dg-manager`: R |
| `cnc_list_device_alarms` | fault | read | `nb-api-alarm-1-700`: R |
| `cnc_list_device_backups` | device_config | read | `device-config`: R, `inventory_cwinventory`: R |
| `cnc_list_devices` | devices | read | `inventory_cwinventory`: R |
| `cnc_list_ems_interfaces` | physical_inventory | read | `nb-api-inv-tp-700`: R |
| `cnc_list_ems_nodes` | physical_inventory | read | `nb-api-inv-node-700`: R |
| `cnc_list_event_types` | fault | read | `cw-fault-alarm-severity-settings`: R |
| `cnc_list_events` | fault | read | `cw-fault-events-api`: R |
| `cnc_list_export_collection_jobs` | collection | read | `cwcollection`: R |
| `cnc_list_function_packs` | services | read | `cat-fp-deployment-manager`: R |
| `cnc_list_group_devices` | grouping | read | `cw-grouping-service`: R |
| `cnc_list_group_ports` | grouping | read | `cw-grouping-service`: R |
| `cnc_list_group_rule_conditions` | grouping | read | `cw-grouping-service`: R |
| `cnc_list_group_rules` | grouping | read | `cw-grouping-service`: R |
| `cnc_list_inventory_jobs` | platform | read | `inventory_cwinventory`: R |
| `cnc_list_inventory_scheduler_jobs` | ems_jobs | read | `cw-inventory-job-dashboard`: R |
| `cnc_list_kafka_subscriptions` | notifications | read | `external-notification-subscription`: R |
| `cnc_list_lcm_domains` | lcm_csm | read | `optima_restconf`: R |
| `cnc_list_lcm_managed_interfaces` | lcm_csm | read | `optima_restconf`: R |
| `cnc_list_microservices` | admin | read | `platform_cwplatform`: R |
| `cnc_list_node_interfaces` | topology | read | `topo_restconf`: R |
| `cnc_list_notification_streams` | notifications | read | `nb-api-alarm-nt-9-700`: R |
| `cnc_list_notification_subscriptions` | notifications | read | `nb-api-alarm-nt-2-700`: R, `nb-api-subscription-api-700`: R |
| `cnc_list_nso_devices` | nso | read | `proxy_cw-proxy`: R |
| `cnc_list_oam_trace_routes` | oam | read (needs W, section 2) | `optima_restconf`: W |
| `cnc_list_p2mp_policies` | te_state | read | `topo_restconf`: R |
| `cnc_list_performance_policies` | performance | read | `performance-policies-rest-apis`: R |
| `cnc_list_performance_policy_devices` | performance | read | `performance-policies-rest-apis`: R |
| `cnc_list_performance_policy_templates` | performance | read | `performance-policies-rest-apis`: R |
| `cnc_list_performance_top_n_columns` | performance | read | `performance-rest-apis`: R |
| `cnc_list_providers` | providers | read | `inventory_cwinventory`: R |
| `cnc_list_roles` | admin | read | `aaa_cwaaa`: R |
| `cnc_list_root_groups` | grouping | read | `cw-grouping-service`: R |
| `cnc_list_rsvp_te_tunnels` | te_state | read | `topo_restconf`: R |
| `cnc_list_secured_apis` | admin | read | `aaa_cwaaa`: R |
| `cnc_list_sensor_templates` | collection | read (needs W, section 2) | `cwcollection`: W |
| `cnc_list_service_types` | services | read | `tsdn_cat-restconf-nbi`: R |
| `cnc_list_services` | services | read | `tsdn_cat-restconf-nbi`: R |
| `cnc_list_software_images` | swim_ztp | read | `swim-nbi`: R |
| `cnc_list_sr_policies` | te_state | read | `topo_restconf`: R |
| `cnc_list_sr_policies_on_interface` | sr_te_operations | read | `optima_restconf`: R, `topo_restconf`: R |
| `cnc_list_sr_policies_on_nodes` | sr_te_operations | read | `optima_restconf`: R, `topo_restconf`: R |
| `cnc_list_sub_services` | services | read | `tsdn_cat-restconf-nbi`: R |
| `cnc_list_tags` | platform | read | `inventory_cwinventory`: R |
| `cnc_list_template_deployments` | device_config | read | `device-config`: R |
| `cnc_list_topology_links` | topology | read | `topo_restconf`: R |
| `cnc_list_topology_nodes` | topology | read | `topo_restconf`: R |
| `cnc_list_users` | platform | read | `aaa_cwaaa`: R |
| `cnc_list_vpn_services` | services | read | `tsdn_cat-restconf-nbi`: R |
| `cnc_list_ztp_config_files` | swim_ztp | read | `cw-config-service-deprecated`: R |
| `cnc_list_ztp_devices` | swim_ztp | read | `cw-ztp-service`: R |
| `cnc_list_ztp_images` | swim_ztp | read | `cw-image-service-deprecated`: R |
| `cnc_list_ztp_profiles` | swim_ztp | read | `cw-ztp-service`: R |
| `cnc_list_ztp_serial_numbers` | swim_ztp | read | `cw-ztp-service`: R |
| `cnc_list_ztp_static_routes` | swim_ztp | read | `cw-ztp-service`: R |
| `cnc_lock_device` | inventory_extras | write | `inventory_cwinventory`: RW |
| `cnc_map_devices_to_data_gateway` | data_gateway | write | `collection_dg-manager`: R, `inventory_cwinventory`: W |
| `cnc_move_group_members` | grouping | write | `cw-grouping-service`: RW |
| `cnc_network_health_report` | composite | read playbook (12 siblings) | `collection_dg-manager`: R, `cw-fault-alarms-api`: R, `cwcollection`: R, `ems-inventory`: R, `inventory_cwinventory`: R, `nb-api-alarm-1-700`: R, `platform_cwplatform`: R, `topo_restconf`: R |
| `cnc_nso_device_action` | nso | write | `inventory_cwinventory`: RW |
| `cnc_nso_sync_to_device` | nso | write | `inventory_cwinventory`: RW |
| `cnc_pause_lcm_recommendations` | lcm_csm | write | `optima_restconf`: W |
| `cnc_preview_sr_policy_route` | sr_te_operations | read | `optima_restconf`: R, `topo_restconf`: R |
| `cnc_provision_l3vpn_e2e` | composite | write playbook (6 siblings) | `inventory_cwinventory`: R, `optima_restconf`: W, `proxy_cw-proxy`: RW, `tsdn_cat-restconf-nbi`: R |
| `cnc_provision_service` | service_provisioning | write | `proxy_cw-proxy`: RW |
| `cnc_reactivate_probe` | oam | write | `cw-probe-mgr`: R |
| `cnc_reset_performance_retention` | performance | write | `performance-dataretention-apis`: RW |
| `cnc_restart_microservice` | admin | write | `platform_cwplatform`: W |
| `cnc_resume_inventory_scheduler_job` | ems_jobs | write | `cw-inventory-job-dashboard`: RW |
| `cnc_resync_service_inventory` | service_provisioning | write | `nso-connector`: W |
| `cnc_revert_event_type_autoclear` | fault | write | `cw-fault-alarm-autoclear-revert`: W, `cw-fault-alarm-severity-settings`: R |
| `cnc_run_inventory_scheduler_job` | ems_jobs | write | `cw-inventory-job-dashboard`: RW |
| `cnc_search_alarms` | fault | read | `cw-fault-alarms-api`: R |
| `cnc_set_device_group_members` | grouping | write | `cw-grouping-service`: RW |
| `cnc_set_device_location` | inventory_extras | write | `inventory_cwinventory`: RW |
| `cnc_set_event_type_autoclear` | fault | write | `cw-fault-alarm-autoclear`: W, `cw-fault-alarm-severity-settings`: R |
| `cnc_set_event_type_recommendation` | fault | write | `cw-fault-alarm-recommended-action`: RW |
| `cnc_set_event_type_severity` | fault | write | `cw-fault-alarm-severity-settings`: RW |
| `cnc_set_login_banner` | admin | write | `platform_cwplatform`: RW |
| `cnc_set_maintenance_mode` | admin | write | `platform_cwplatform`: RW |
| `cnc_set_sr_policy_path_notifications` | sr_te_operations | write | `optima_restconf`: W |
| `cnc_start_oam_trace_route` | oam | write | `inventory_cwinventory`: R, `optima_restconf`: W |
| `cnc_suspend_inventory_scheduler_job` | ems_jobs | write | `cw-inventory-job-dashboard`: RW |
| `cnc_sync_inventory_with_nso` | nso | write | `inventory_cwinventory`: W |
| `cnc_unassign_tags` | inventory_extras | write | `inventory_cwinventory`: RW |
| `cnc_unlock_device` | inventory_extras | write | `inventory_cwinventory`: RW |
| `cnc_update_alarm_manager_settings` | fault | write | `cw-fault-alarm-manager-settings`: RW |
| `cnc_update_alarm_suppression_policy` | fault | write | `event-processing-service-suppressionpolicy-api`: RW |
| `cnc_update_credential_profile` | credentials | write | `inventory_cwinventory`: RW |
| `cnc_update_device` | devices | write | `inventory_cwinventory`: W |
| `cnc_update_device_group` | grouping | write | `cw-grouping-service`: RWD |
| `cnc_update_gnmi_alarm_settings` | fault | write | `cw-fault-gnmi-settings`: RW |
| `cnc_update_performance_policy` | performance | write | `performance-policies-rest-apis`: RW |
| `cnc_update_performance_retention` | performance | write | `performance-dataretention-apis`: RW |
| `cnc_update_provider` | providers | write | `inventory_cwinventory`: W |
| `cnc_update_sr_policy` | sr_te_operations | write | `optima_restconf`: W, `topo_restconf`: R |
| `cnc_update_sr_policy_service` | service_provisioning | write | `proxy_cw-proxy`: RW |
| `cnc_update_ztp_config_file` | swim_ztp | write | `cw-config-service-deprecated`: RW |
| `cnc_update_ztp_device` | swim_ztp | write | `cw-ztp-service`: RW |
| `cnc_update_ztp_profile` | swim_ztp | write | `cw-ztp-service`: RW |
| `cnc_upload_ztp_config_file` | swim_ztp | write | `cw-config-service-deprecated`: W |
| `cnc_wait_for_config_backup_job` | device_config | read (needs W, section 2) | `device-config`: W |
| `cnc_wait_for_device_nso_state` | nso | read | `inventory_cwinventory`: R |
| `cnc_wait_for_device_reachable` | devices | read | `inventory_cwinventory`: R |
| `cnc_wait_for_inventory_job` | platform | read | `inventory_cwinventory`: R |
| `cnc_wait_for_inventory_scheduler_job` | ems_jobs | read | `cw-inventory-job-dashboard`: R |
| `cnc_wait_for_oam_trace_route` | oam | read (needs W, section 2) | `inventory_cwinventory`: R, `optima_restconf`: W |
| `cnc_wait_for_service_plan` | services | read | `tsdn_cat-restconf-nbi`: R |
| `cnc_wait_for_sr_policy_oper_state` | sr_te_operations | read | `topo_restconf`: R |
| `cnc_wait_for_template_deployment` | device_config | read | `device-config`: R |

Every request template the tools send resolved to a secured API.

## 5. Task checkboxes that bundle the same grants

`GET /crosswork/aaa/v1/taskAPIPermission/admin` answered five task bundles (verified 2026-09-14). Ticking a task in the UI grants the listed api_id(s) with the listed R/W/D ticks — the same letters as the tables above (section 1 says what each letter adds to the row's `/.*` entry and how it is stored), so treat a bundle as "which rows and ticks the UI sets for you".

| task (UI name) | group | grants | rows it covers here |
|---|---|---|---|
| Device Access Group Management (`id_dag_management`) | Platform | `cw-grouping-service` RWD | `cw-grouping-service` (reads need R; writes add WD) |
| Export Audit Logs (`id_export_audit_logs_access`) | Audit Logs | `cw-fault-events-api` RW | `cw-fault-events-api` (reads need R) |
| Function Pack Deployment (`id_nso_fp_deployment_management`) | NSO Management | `nso-fp-dep-mngr` RWD | no cnc-mcp tool uses these rows |
| Provisioning (`id_provisioning`) | Crosswork Network Controller | `inventory_cwinventory` RW | `inventory_cwinventory` (reads need RW; writes add D) |
| View Audit Logs (`id_view_audit_logs_access`) | Audit Logs | `cw-fault-events-api` R | `cw-fault-events-api` (reads need R) |

The remaining tasks the admin role carries — Bandwidth on Demand Configuration (`id_bwod_config`, Crosswork Optimization Engine), Circuit Style SR-TE Configuration (`id_csm_config`, Crosswork Optimization Engine), Local Congestion Mitigation Domain 0 (`id_lcm_0`, Crosswork Optimization Engine), Local Congestion Mitigation All Domains (`id_lcm_all_access`, Crosswork Optimization Engine) — returned no API bundle: they are feature permissions (`GET aaa/v1/userpermission`), not gateway grants, and are not needed for the API calls above. Whether other task bundles exist for other roles is not known.

## 6. Verifying an account

Log the server in as the account (username/password in `.env`) and call `cnc_check_permissions` (`make cli ARGS="call cnc_check_permissions '{}'"`). It reports the identity from the JWT (username, role, device access groups, token expiry), where it read the role from (`aaaread` or the `aaa/v1` fallback), GuiAccess / ApiAccess, and then one of:

- `All N registered tools are permitted by role '<role>'`, or
- `K of N registered tools would be refused by the gateway (403) under role '<role>'`, followed by the **API rows to grant** (feature | api_id | API name | methods to add | tools affected) and, per refused tool, the missing METHOD path rows — the same rows as this page, filtered to what the role lacks. A missing GET is the Read tick; a missing POST is Read when the row's template names the path (section 1) and Write otherwise; PUT/PATCH is Write; DELETE is Delete.
- Tools the packaged map does not know are listed under "not in the RBAC map" — regenerate with `make rbac`.
- `Error: role '<role>' may not read its own role ...` when neither the mirror nor `aaa/v1` lets the account read its role — the service adds the `aaa_cw_role_read` row to every role it stores, so on this platform version check the role's `roleAccess` (`ApiAccess`) and the stored role through an admin session.

Evaluated against the stored `cnc-mcp-readonly` role, it reports 14 of the 184 read tools refused (the list in section 2) and 1 write tool **permitted** — `cnc_reactivate_probe` (`POST /crosswork/probemgr/v1/reactivateProbe` on `cw-probe-mgr`: the platform's read template for the API names that path, so **Read permits this write**). Against the stored `cnc-mcp-operator` role every tool is permitted.

What this verification is and is not:

- **Verified (2026-09-14, admin session, test roles):** the shape the AAA service stores a submitted role in — `/.*` entries verbatim, the read templates added to a GET-only row, the baseline rows, the POST/PUT/GET status codes and the `charset=UTF-8` content type (section 1). The counts above are computed from that stored shape with Tyk's matching rule; `tests/fixtures/rbac/` pins the model against the read-backs.
- **Verified (2026-09-15, users carrying the generated roles; a UI-built role; the bodies as committed read back):** the gateway's refusals — every predicted 403 observed, nothing unpredicted refused (section 1; the smoke runs were on the previous generation of the bodies — those of the 245 tools registered on 2026-09-15 (182 read) — which differed from the generated bodies of those tools only in the two AAA rows — `aaa_cwaaa` a GET pattern limited to the paths the tools send then, `/.*` now; `aaa_cw_role_read` in the body then, left to the baseline row now — `versions` and the `rate` field; the bodies as committed now also carry what the 37 tools added since (2 read, 35 write) need — rows and ticks that smoke did not exercise — and the refusal predictions for the tools of that day are identical (the same 14 read tools refused under `cnc-mcp-readonly`, `cnc_reactivate_probe` permitted, every tool permitted under `cnc-mcp-operator`); the bodies as committed were stored through the API and read back (2026-09-15: `tests/fixtures/rbac/stored_generated_readonly.json`, `tests/fixtures/rbac/stored_generated_operator.json`); evaluated on the stored form they give the same verdict for every tool as the model — `cnc-mcp-readonly`: 170 of the 184 read tools permitted, 14 refused, 1 write tool permitted (`cnc_reactivate_probe`); `cnc-mcp-operator`: 282 of 282 permitted) — and the editor's tick → entry mapping the bodies use.
- The check is **static**: the map is derived from the tool source by api_coverage.py's extraction heuristic; no tool endpoint is called. A request built from platform data folds to `{}`; a probe counts as a use.
- A device access group other than ALL-ACCESS restricts devices, not APIs; it is reported, not evaluated. The two gateway fail-open cases (a regex that does not compile, an empty `access_rights` map) are reported as refusals.

### Ready-made role bodies

`docs/rbac/cnc-mcp-readonly.role.json` (section 2) and `docs/rbac/cnc-mcp-operator.role.json` (sections 2 + 3) are generated with this page, in the shape `POST /crosswork/aaa/v1/role` takes — `{"<role name>": {<rbacRole>}}`, the shape `GET /crosswork/aaa/v1/role` answers. **The generated bodies are the shape the editor submits** (verified 2026-09-15 against the UI-built role's read-back, `tests/fixtures/rbac/stored_ui_built_role.json`) — the editor's role fields, `versions []`, one `access_rights` entry per api_id with a single `{url: "/.*", methods: [...]}` whose methods are the union of the row's ticks (`[GET]` for Read, `[POST, PUT, PATCH]` for Write, `[DELETE]` for Delete, in that order) — minus the empty `_id`/`id` the editor also sends; `limit`/`allowance_scope` are the read-back's fields (the service adds them itself), and `api_name` is the v1 catalogue's HTML-escaped form (`Alarms &amp; Events`, as the built-in `admin` role stores it) where the editor sends `aaa/v2/api`'s unescaped one. What the fixtures pin: both bodies as committed, stored and read back (2026-09-15: `tests/fixtures/rbac/stored_generated_readonly.json`, `tests/fixtures/rbac/stored_generated_operator.json` — the model reproduces every stored row entry for entry: the read-only body's 42 Read rows with their templates; the operator body's union entries, `[GET, POST, PUT, PATCH]` on 9 rows and all five methods on 10, verbatim except the 3 split rows section 1 describes — `cwcollection`, `optima_restconf`, `platform_cwplatform` — where POST came back under the not-delete pattern; plus the three baseline rows on each), the UI-built role's single-tick entries (`[GET]`, `[POST, PUT, PATCH]`, `[DELETE]`) and the 2026-09-14 experiments' per-tick entries on these rows. The Roles page has not been opened on these bodies (their first entries are all `/.*`, the one shape the editor reads). Two differences from a UI-built role: a body grants single api_ids where a UI tick grants the whole display-name group (section 1), and so **an API-loaded role is managed through the API only** — the editor shows a group row from its first api_id in `aaa/v2/api` order (unticked on the 6 rows section 1 names, although the grant is live) and a Save rebuilds every group from the editor's model, the hidden members taking the ticks of the group's most-ticked member (read from the bundle, not exercised live). No baseline row is in a body (the service adds them). `cnc-mcp-readonly` is R only; `cnc-mcp-operator` adds Write and Delete where a tool needs them.

Load one with an admin's SSO JWT (one curl per file; the content type must carry the charset), read it back to see the templates, baseline rows and split rows the service added, then verify with cnc_check_permissions as a user carrying the role:

```bash
CNC=https://<host>:30603
TGT=$(curl -sk -X POST "$CNC/crosswork/sso/v1/tickets" \
      -d "username=$CNC_USER" -d "password=$CNC_PASS")  # an admin
JWT=$(curl -sk -X POST "$CNC/crosswork/sso/v1/tickets/$TGT" \
      -d "service=$CNC/app-dashboard")
# create (201); to update an existing role instead: PUT .../role/<name> with the
# inner object (204)
curl -sk -X POST "$CNC/crosswork/aaa/v1/role" -H "Authorization: Bearer $JWT" \
     -H "Content-Type: application/json; charset=UTF-8" \
     --data @docs/rbac/cnc-mcp-readonly.role.json
curl -sk "$CNC/crosswork/aaa/v1/role/cnc-mcp-readonly" -H "Authorization: Bearer $JWT"
# release the SSO session (Crosswork caps concurrent sessions per user)
curl -sk -X DELETE "$CNC/crosswork/sso/v1/tickets/$TGT" -H "Authorization: Bearer $JWT"
```

No UI import for a role body is documented; the equivalent is ticking the editor rows of sections 2 and 3 by hand, which also grants the sibling api_ids those tables list.
