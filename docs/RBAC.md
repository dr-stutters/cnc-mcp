# RBAC: what a Crosswork account needs to run cnc-mcp

> **Generated** by `scripts/rbac_map.py` from the tool source, the gateway's secured-API catalogue (CNC 7.2.0, 217 APIs in 27 features, catalogue verified live 2026-09-14) and the platform's read templates (captured 2026-09-14) — do not edit by hand. Regenerate with `make rbac` (offline, from the catalogue and templates embedded in `src/cnc_mcp/data/rbac_map.json`) or `make rbac-fetch` (re-read the catalogue from a live instance; `--read-templates <capture>` loads a fresh template capture); `make rbac-check` fails when the committed files are stale.

The server registers 245 tools (182 read-only, 63 write). Each sends a known set of HTTP requests; each request is routed by the gateway to one secured API, and a role must grant that API (with the method) or the gateway refuses the call (403). This page lists exactly which API rows a role needs and which of the role editor's **Read / Write / Delete** ticks on each — first for a read-only account, then per write area, then per tool.

## 1. How Crosswork RBAC works

**Verified live** (CNC 7.2.0 single-VM lab, 2026-09-14):

- The API gateway is **Tyk** (v5.1.1, from its `/hello` health endpoint). Every `/crosswork/*` request is routed to one of 217 secured API definitions (`GET /crosswork/aaa/v1/api`), each with an `api_id`, a display `name` and a gorilla-mux **listen path** (`/crosswork/inventory/`, `/crosswork/alarms/v1/query`, `/crosswork/performance/v{.}/dashboards/`, ...).
- A **role** (`GET /crosswork/aaa/v1/role` → a dict keyed by role name) is a Tyk policy: `access_rights{<api_id>: {api_name, api_id, versions ["Default"], allowed_urls [{url: <regex>, methods: [GET, POST, PUT, PATCH, DELETE]}], allowance_scope}}` plus `rate 5000 / per 60 / quota_max -1 / active true`. The lab's built-in role, `admin`, grants every API with `url "/.*"` and all five methods.
- `GET /crosswork/aaa/v2/api` → `{<feature>: [{api_id, name}]}` (27 features) is the grouping the UI's role editor (Administration > Users and Roles > Roles) shows; the `feature` column below is it.
- `GET /crosswork/aaa/v1/taskAPIPermission/<role>` → `{<task id>: {apiIds: {<api_id>: ["R", "W", "D"]}}}`: the UI's **task** checkboxes are bundles of per-API R/W/D grants (section 5). `GET aaa/v1/task/<role>` lists the task groups (audit_logs, coe, crosswork_network_controller, nso_management, platform); `GET aaa/v1/roleAccess/<role>` → `{PolicyId, GuiAccess, ApiAccess, PolicyData}` — `ApiAccess false` means no API call at all.
- A **user** (`GET aaa/v1/user/<name>`) carries `PolicyId` (= its role), `Status` and `DeviceAccessGroups [{Uuid, DomainName}]` (`ALL-ACCESS` on the lab). A device access group other than ALL-ACCESS restricts which **devices** the account sees, not which APIs it may call.
- The CAS-issued session token is an HS512 JWT sent as `Authorization: Bearer`; its claims are readable without the key: `sub`/`username` (the login name), `policy_id` (the role), `deviceAccessGroups`, `exp`/`iat` (8 h), `iss`. cnc_check_permissions reads the identity from them.
- The read-only mirror `/crosswork/aaaread/...` (api_id `aaa_cw_role_read`, "Know my role - Read only", same backend) answers the same GETs as `aaa/v1` (`role/<r>`, `roleAccess/<r>`, `user/<u>`, `userpermission`, `task/<r>`, `v1/api`, `v2/api` — all 200 as admin). It is the endpoint a non-admin account is expected to read its own role through.
- The three SSO ticket calls the server logs in with (`POST /crosswork/sso/v1/tickets`, `POST .../tickets/{TGT}`, `DELETE .../tickets/{TGT}`) are **not** gateway APIs: no role grant is involved in logging in, only in what the token may then call.

**Verified live: how Crosswork stores a role** (2026-09-14, through an admin session: a test role `cnc-mcp-readonly` was created, rewritten in several shapes and read back each time). The AAA service does **not** store a submitted role verbatim — it normalises `access_rights` per API:

- `POST /crosswork/aaa/v1/role` needs `Content-Type: application/json; charset=UTF-8` (plain `application/json` → 405); body `{"<name>": {<rbacRole>}}` → **201**. `PUT /crosswork/aaa/v1/role/<name>` with the inner object → **204**. `GET /crosswork/aaa/v1/role/<name>` → the stored object (**404** when absent).
- A row submitted as `{url: "/.*", methods: ["GET"]}`, `{url: "/.*", methods: ["POST", "PUT", "PATCH"]}` or `{url: "/.*", methods: ["DELETE"]}` is stored verbatim. This is the shape the generated bodies use — the one the role editor's **Read / Write / Delete** ticks most plausibly emit (an inference, see *Not verified* below; this page calls it the UI shape and the letters R / W / D).
- Every stored role gains 2 **baseline rows** the service adds on its own — `aaa_cwpassword` (POST `/(.*passwordHistoryCheck.*)$`; GET, PUT `/.*`), `aaa_selected_pref` (GET, PUT `/.*`) — the account's own password change and UI preferences. No cnc-mcp tool uses them; they are not in the bodies and appear when the role is read back.
- A row with a GET entry (and no POST entry) additionally receives the platform's per-API **read templates**: extra POST entries naming the read-by-POST paths of that API — so a GET-only row permits those POSTs as well (what a Read tick grants, if it emits that entry). The 17 APIs with a template among the 43 rows the read tools use (every other one of these rows received GET only when stored; the 174 catalogued APIs outside these rows were never stored as GET-only rows, so their templates are unknown and any POST there is classed W):
  - `aaa_cw_role_read`: POST `/.+/query$`
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
- A GET entry with a **custom URL** is kept verbatim (and the read template is still added) — so anchoring the two AAA rows' GET pattern (section 2) works.
- A **custom-URL POST entry is reinterpreted** where it was submitted as the row's only entry — on the 9 APIs that was tried on (`collection_dg-manager`, `cw-fault-alarms-api`, `cw-fault-events-api`, `cw-probe-mgr`, `cw-ztp-service`, `cwcollection`, `dg-manager-global-parameters-api`, `optima_analytics_api`, `optima_restconf`): its methods are stripped to `[]` and a service pattern permitting POST on every path whose last segment is not `delete` is added — a **wider** grant than submitted. In the same submission a custom POST entry next to a custom GET entry was kept verbatim (and no template added) on `device-config`, `inventory_cwinventory`, `platform_cwplatform`, `tsdn_cat-restconf-nbi`. Whether the API or the row shape decides was not isolated. Never submit exact-path POST entries; the bodies carry none (an earlier generation of this page did, and was wrong for this platform).
- A row ticked Read **and** Write was stored as the two `/.*` entries only (no template — the Write entry already covers every POST).

**From the Tyk v5.1.1 gateway source** (`gateway/api_loader.go`, `mw_access_rights.go`, `mw_granular_access.go`), confirmed live 2026-09-15 by a user carrying the generated read-only role (the read smoke: 262 read calls answered, the 7 predicted refusals it exercised answered 403, nothing unpredicted was refused; two writes and the `/v1/api` listings refused as predicted):

- Tyk registers the API definitions **longest listen path first** and each as a gorilla-mux path prefix, so a request goes to the API with the longest listen path that claims it; `{...}` in a listen path matches one segment. The map's router additionally requires the match to end at a segment boundary and accepts a missing trailing slash; no template in the map routes differently under either reading (`tests/test_rbac_map.py`). The query string is not part of the match.
- Within the routed API, each `allowed_urls[].url` is run as an **unanchored regex search against the full request path** (`regexp.MatchString` on `r.URL.Path`; the listen path is not stripped first): `/nodes` permits `/crosswork/inventory/v1/nodes/query`, `^/v1/nodes/query$` permits nothing, and `/.+/query$` (an inventory read template) permits every `.../query` under the API. The method must be listed on a matching entry; an API with an empty `allowed_urls` has no path restriction.
- A request the role does not permit is refused with a **403** whose body names which check failed (observed 2026-09-15): `{"error": "Access to this API has been disallowed"}` when the role has no entry for the API at all (`PUT /crosswork/alarms/v1/ack` under the read-only role), `{"error": "Access to this resource has been disallowed"}` when the API is granted but no `allowed_urls` entry covers the path and method (`POST /crosswork/inventory/v1/tags`, and the `/v1/api` listings excluded by the anchored AAA rows). Neither is an authentication failure: the server does not re-login on them. Two fail-open cases: an `allowed_urls` regex that does not compile is let through, and so is a role whose `access_rights` map is empty — cnc_check_permissions reports both as refusals (the role as it should be configured).

**Not verified (assumed — say so when it bites):**

- The role editor's own wire shape. No UI-built role exists on the lab, so what ticking **Read / Write / Delete** submits was never read back; the generated bodies use the shape whose stored form was verified (`/.*` with `[GET]`, `[POST, PUT, PATCH]`, `[DELETE]`), which is the one a tick most plausibly emits. Should the editor emit something else (a Write template rather than `/.*`, say), the tick columns on this page describe the bodies, not the editor.
- Whether `/crosswork/aaaread/` is readable by **every** role: verified for the admin role and for the generated read-only role (its user read its own role and roleAccess through the mirror, 2026-09-15); a role built without the `aaa_cw_role_read` row is untested. cnc_check_permissions falls back to `/crosswork/aaa/v1` and says which one answered — either grant suffices for it.
- A row ticked Write **without** Read (the operator body has 4: `cw-fault-ack-api`, `cw-fault-clear-api`, `cw-fault-notes-api`, `nso-connector`) was not among the shapes read back; the experiments always carried a GET entry next to the Write entry.

## 2. Least-privilege recipe: a read-only account

The 182 read-only tools touch the 43 API rows below; the last column is the tick(s) their requests need on each row (R = every GET plus the POSTs the row's read template names, W = the other POSTs and every PUT/PATCH, D = DELETE). **`docs/rbac/cnc-mcp-readonly.role.json` (section 6) grants the Read tick on every row and nothing else** — 43 rows, R only, never W — the shape ticking Read on these rows in the role editor (Administration > Users and Roles > Roles: create a role, tick the rows under their feature, leave `ApiAccess` on) is taken to produce (inferred, section 1), except for the URL pattern of the two AAA rows (below). Assign it to a dedicated service account with device access group `ALL-ACCESS` (or the device scope you intend).

| feature | api_id | API name | ticks the read tools need |
|---|---|---|---|
| AAA | `aaa_cw_role_read` | Know my role - Read only | R |
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

`aaa_cw_role_read` (`/crosswork/aaaread/`) is what cnc_check_permissions reads the account's own role through; `aaa_cwaaa` (`/crosswork/aaa/`) is needed by the RBAC read tools (cnc_list_roles, cnc_get_user, ...) and is cnc_check_permissions' fallback (either of the two rows satisfies that tool).

### The 14 read tools a Read-only role cannot call

Under the stored `cnc-mcp-readonly` role (its 43 R rows plus the read templates and baseline rows the service adds — 45 rows as read back) cnc_check_permissions permits 168 of the 182 read tools. The other 14 read through a POST Crosswork classes as a **write** — the path is outside the API's read template (or the API has none) — so the gateway would refuse it (403) under Read:

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

1. **Tick Write as well as Read** on the rows above — the account is then no longer read-only at the gateway, because Write is `/.*` for POST/PUT/PATCH on the whole API. A narrowed POST entry beside the GET entry was stored verbatim on `device-config` and `inventory_cwinventory` in the one shape tried (it then needs the read-template paths listed by hand, since a row with a POST entry receives none) and was reinterpreted into a wider grant where it was the row's only entry (section 1) — untested as a user, so not offered here:
  - `cwcollection`: Write also permits every POST/PUT/PATCH the API serves (no cnc-mcp write tool uses it).
  - `device-config`: Write also permits what its 3 write tools (`cnc_backup_device_config`, `cnc_create_config_template`, `cnc_deploy_config_template`) do there, and any other POST/PUT/PATCH the API serves.
  - `inventory_cwinventory`: Write also permits what its 18 write tools (`cnc_assign_tags`, `cnc_clear_device_location`, `cnc_create_credential_profile`, `cnc_create_device`, `cnc_create_provider`, `cnc_create_tag`, `cnc_enable_device_gnmi`, `cnc_lock_device`, `cnc_map_devices_to_data_gateway`, `cnc_nso_device_action`, `cnc_nso_sync_to_device`, `cnc_set_device_location`, `cnc_sync_inventory_with_nso`, `cnc_unassign_tags`, `cnc_unlock_device`, `cnc_update_credential_profile`, `cnc_update_device`, `cnc_update_provider`) do there, and any other POST/PUT/PATCH the API serves.
  - `optima_restconf`: Write also permits what its 8 write tools (`cnc_create_sr_policy`, `cnc_create_sr_policy_e2e`, `cnc_delete_sr_policy`, `cnc_pause_lcm_recommendations`, `cnc_provision_l3vpn_e2e`, `cnc_set_sr_policy_path_notifications`, `cnc_start_oam_trace_route`, `cnc_update_sr_policy`) do there, and any other POST/PUT/PATCH the API serves.
2. **Leave them refused** (they answer the gateway's 403 with a hint pointing at cnc_check_permissions) or, better, keep the agent from seeing them: `CNC_MCP_DISABLED_TOOLS=cnc_check_nso_device_sync,cnc_explain_sr_policy,cnc_get_config_backup_job,cnc_get_lcm_recommendation_preview,cnc_get_oam_settings,cnc_get_oam_trace_route,cnc_get_sr_policy_metrics,cnc_get_sr_policy_path_notification_state,cnc_investigate_device,cnc_list_config_backup_jobs,cnc_list_oam_trace_routes,cnc_list_sensor_templates,cnc_wait_for_config_backup_job,cnc_wait_for_oam_trace_route`. (`cnc_get_lcm_recommendation_preview` is in the list although one form of the call runs under Read, above — leave it out to keep that form.)

**The two AAA rows.** Both APIs also serve the broader `GET .../v1/api` listing, which returns the gateway's full API definitions — administrative data; do not grant it to a non-administrator. A Read tick grants URL pattern `/.*`, and because the gateway evaluates a row's pattern as an unanchored search on the full path (section 1), `/.*` includes that listing. The generated bodies therefore give these two rows a GET entry anchored to exactly the paths the tools send (the service keeps a custom GET URL verbatim, section 1); where the editor lets you set a row's URL pattern, use the same:

- `aaa_cw_role_read` (GET): `^/crosswork/aaaread/(v1/role/[^/]+|v1/roleAccess/[^/]+)$`
- `aaa_cwaaa` (GET): `^/crosswork/aaa/(v1/activeSessions|v1/getSessionMgmtPermissions|v1/isNSOConfigured|v1/passwordPolicyConfig|v1/role|v1/role/[^/]+|v1/roleAccess/[^/]+|v1/sessionconfig|v1/user|v1/user/[^/]+|v1/userpermission|v1/userpermission/[^/]+|v1/usertask/[^/]+|v2/api)$`

(The `aaa_cw_role_read` row still receives its read template, POST `/.+/query$`, when stored; no read tool sends a POST there.)

## 3. Write areas: what each adds

Write tools are registered only with `CNC_MCP_ENABLE_WRITES=true`. Per area (the `tools/` module), the API rows and ticks a role needs **in addition to** the read-only body of section 2 — a row already ticked Read is listed only when the writes add Write or Delete on it. `docs/rbac/cnc-mcp-operator.role.json` is section 2 plus every area below, plus the Write ticks the 14 read tools of section 2 need (`cwcollection`, `device-config`, `inventory_cwinventory`, `optima_restconf`).

### admin (3 write tools: `cnc_restart_microservice`, `cnc_set_login_banner`, `cnc_set_maintenance_mode`)

| feature | api_id | API name | ticks to add |
|---|---|---|---|
| Platform | `platform_cwplatform` | Platform APIs | W |

### composite (2 write tools: `cnc_create_sr_policy_e2e`, `cnc_provision_l3vpn_e2e`)

| feature | api_id | API name | ticks to add |
|---|---|---|---|
| Crosswork Optimization Engine | `optima_restconf` | Optimization Engine RESTCONF | W |
| Proxy | `proxy_cw-proxy` | Crosswork Proxy APIs | W |

### credentials (3 write tools: `cnc_create_credential_profile`, `cnc_delete_credential_profile`, `cnc_update_credential_profile`)

| feature | api_id | API name | ticks to add |
|---|---|---|---|
| Inventory | `inventory_cwinventory` | Inventory APIs | WD |

### data_gateway (1 write tool: `cnc_map_devices_to_data_gateway`)

| feature | api_id | API name | ticks to add |
|---|---|---|---|
| Inventory | `inventory_cwinventory` | Inventory APIs | W |

### device_config (7 write tools: `cnc_backup_device_config`, `cnc_create_config_template`, `cnc_delete_config_backup_job`, `cnc_delete_config_template`, `cnc_delete_device_backup`, `cnc_delete_template_deployment`, `cnc_deploy_config_template`)

| feature | api_id | API name | ticks to add |
|---|---|---|---|
| Device Configuration | `device-config` | Device Configuration | WD |

### devices (4 write tools: `cnc_create_device`, `cnc_delete_device`, `cnc_enable_device_gnmi`, `cnc_update_device`)

| feature | api_id | API name | ticks to add |
|---|---|---|---|
| Inventory | `inventory_cwinventory` | Inventory APIs | WD |

### ems_jobs (3 write tools: `cnc_resume_inventory_scheduler_job`, `cnc_run_inventory_scheduler_job`, `cnc_suspend_inventory_scheduler_job`)

| feature | api_id | API name | ticks to add |
|---|---|---|---|
| Device Monitoring | `cw-inventory-job-dashboard` | Device Inventory | W |

### fault (5 write tools: `cnc_acknowledge_alarm`, `cnc_annotate_alarm`, `cnc_clear_alarm`, `cnc_create_alarm_suppression_policy`, `cnc_delete_alarm_suppression_policy`)

| feature | api_id | API name | ticks to add |
|---|---|---|---|
| Alarms and Events | `cw-fault-ack-api` | Alarms & Events | W |
| Alarms and Events | `cw-fault-clear-api` | Alarms & Events | W |
| Alarms and Events | `cw-fault-notes-api` | Alarms & Events | W |
| Alarms and Events | `event-processing-service-suppressionpolicy-api` | Alarm Suppression Policies | WD |

### inventory_extras (8 write tools: `cnc_assign_tags`, `cnc_clear_device_location`, `cnc_create_tag`, `cnc_delete_tag`, `cnc_lock_device`, `cnc_set_device_location`, `cnc_unassign_tags`, `cnc_unlock_device`)

| feature | api_id | API name | ticks to add |
|---|---|---|---|
| Inventory | `inventory_cwinventory` | Inventory APIs | WD |

### lcm_csm (1 write tool: `cnc_pause_lcm_recommendations`)

| feature | api_id | API name | ticks to add |
|---|---|---|---|
| Crosswork Optimization Engine | `optima_restconf` | Optimization Engine RESTCONF | W |

### notifications (2 write tools: `cnc_create_webhook_subscription`, `cnc_delete_notification_subscription`)

| feature | api_id | API name | ticks to add |
|---|---|---|---|
| Administrative Operations | `nb-api-subscription-api-700` | RESTCONF Notification Subscription | WD |

### nso (3 write tools: `cnc_nso_device_action`, `cnc_nso_sync_to_device`, `cnc_sync_inventory_with_nso`)

| feature | api_id | API name | ticks to add |
|---|---|---|---|
| Inventory | `inventory_cwinventory` | Inventory APIs | W |

### oam (2 write tools: `cnc_reactivate_probe`, `cnc_start_oam_trace_route`)

| feature | api_id | API name | ticks to add |
|---|---|---|---|
| Crosswork Optimization Engine | `optima_restconf` | Optimization Engine RESTCONF | W |

### providers (3 write tools: `cnc_create_provider`, `cnc_delete_provider`, `cnc_update_provider`)

| feature | api_id | API name | ticks to add |
|---|---|---|---|
| Inventory | `inventory_cwinventory` | Inventory APIs | WD |

### service_provisioning (12 write tools: `cnc_create_l3vpn_service`, `cnc_create_odn_template`, `cnc_create_sid_list`, `cnc_create_sr_policy_service`, `cnc_delete_odn_template`, `cnc_delete_service`, `cnc_delete_sid_list`, `cnc_delete_sr_policy_service`, `cnc_delete_vpn_service`, `cnc_provision_service`, `cnc_resync_service_inventory`, `cnc_update_sr_policy_service`)

| feature | api_id | API name | ticks to add |
|---|---|---|---|
| CNC | `nso-connector` | NSO Connector APIs | W |
| Proxy | `proxy_cw-proxy` | Crosswork Proxy APIs | WD |

### sr_te_operations (4 write tools: `cnc_create_sr_policy`, `cnc_delete_sr_policy`, `cnc_set_sr_policy_path_notifications`, `cnc_update_sr_policy`)

| feature | api_id | API name | ticks to add |
|---|---|---|---|
| Crosswork Optimization Engine | `optima_restconf` | Optimization Engine RESTCONF | W |

`cnc-mcp-operator.role.json` carries 47 rows: 13 with Write, 5 with Delete, 4 Write-only (no read tool uses the API). The AAA rows of section 2 are unchanged (no write tool sends anything on them).

## 4. Per-tool requirements

Every registered tool with the api_id(s) it needs and the ticks per api_id (R = GET, or a POST the row's read template names; W = any other POST, PUT, PATCH; D = DELETE; a tool that passes the method through needs all three). Playbooks (area `composite`) send nothing themselves: their rows are the union of the siblings they call. A tool that tries one API and falls back to another lists its alternatives with *or*: one of them suffices. The HTTP methods and path templates behind each cell are in `src/cnc_mcp/data/rbac_map.json`.

| tool | area | kind | api_id: ticks |
|---|---|---|---|
| `cnc_acknowledge_alarm` | fault | write | `cw-fault-ack-api`: W, `cw-fault-alarms-api`: R |
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
| `cnc_create_alarm_suppression_policy` | fault | write | `event-processing-service-suppressionpolicy-api`: W |
| `cnc_create_config_template` | device_config | write | `device-config`: W |
| `cnc_create_credential_profile` | credentials | write | `inventory_cwinventory`: RW |
| `cnc_create_device` | devices | write | `inventory_cwinventory`: W |
| `cnc_create_l3vpn_service` | service_provisioning | write | `proxy_cw-proxy`: RW |
| `cnc_create_odn_template` | service_provisioning | write | `proxy_cw-proxy`: RW |
| `cnc_create_provider` | providers | write | `inventory_cwinventory`: W |
| `cnc_create_sid_list` | service_provisioning | write | `proxy_cw-proxy`: RW |
| `cnc_create_sr_policy` | sr_te_operations | write | `optima_restconf`: W, `topo_restconf`: R |
| `cnc_create_sr_policy_e2e` | composite | write playbook (4 siblings) | `optima_restconf`: RW, `topo_restconf`: R |
| `cnc_create_sr_policy_service` | service_provisioning | write | `proxy_cw-proxy`: RW |
| `cnc_create_tag` | inventory_extras | write | `inventory_cwinventory`: W |
| `cnc_create_webhook_subscription` | notifications | write | `nb-api-subscription-api-700`: W |
| `cnc_delete_alarm_suppression_policy` | fault | write | `event-processing-service-suppressionpolicy-api`: D |
| `cnc_delete_config_backup_job` | device_config | write | `device-config`: D |
| `cnc_delete_config_template` | device_config | write | `device-config`: D |
| `cnc_delete_credential_profile` | credentials | write | `inventory_cwinventory`: D |
| `cnc_delete_device` | devices | write | `inventory_cwinventory`: D |
| `cnc_delete_device_backup` | device_config | write | `device-config`: D, `inventory_cwinventory`: R |
| `cnc_delete_notification_subscription` | notifications | write | `nb-api-subscription-api-700`: D |
| `cnc_delete_odn_template` | service_provisioning | write | `proxy_cw-proxy`: RD |
| `cnc_delete_provider` | providers | write | `inventory_cwinventory`: D |
| `cnc_delete_service` | service_provisioning | write | `proxy_cw-proxy`: RD |
| `cnc_delete_sid_list` | service_provisioning | write | `proxy_cw-proxy`: RD |
| `cnc_delete_sr_policy` | sr_te_operations | write | `optima_restconf`: W, `topo_restconf`: R |
| `cnc_delete_sr_policy_service` | service_provisioning | write | `proxy_cw-proxy`: RD |
| `cnc_delete_tag` | inventory_extras | write | `inventory_cwinventory`: D |
| `cnc_delete_template_deployment` | device_config | write | `device-config`: D |
| `cnc_delete_vpn_service` | service_provisioning | write | `proxy_cw-proxy`: RD |
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
| `cnc_list_group_rule_conditions` | grouping | read | `cw-grouping-service`: R |
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
| `cnc_network_health_report` | composite | read playbook (12 siblings) | `collection_dg-manager`: R, `cw-fault-alarms-api`: R, `cwcollection`: R, `ems-inventory`: R, `inventory_cwinventory`: R, `nb-api-alarm-1-700`: R, `platform_cwplatform`: R, `topo_restconf`: R |
| `cnc_nso_device_action` | nso | write | `inventory_cwinventory`: RW |
| `cnc_nso_sync_to_device` | nso | write | `inventory_cwinventory`: RW |
| `cnc_pause_lcm_recommendations` | lcm_csm | write | `optima_restconf`: W |
| `cnc_preview_sr_policy_route` | sr_te_operations | read | `optima_restconf`: R, `topo_restconf`: R |
| `cnc_provision_l3vpn_e2e` | composite | write playbook (6 siblings) | `inventory_cwinventory`: R, `optima_restconf`: W, `proxy_cw-proxy`: RW, `tsdn_cat-restconf-nbi`: R |
| `cnc_provision_service` | service_provisioning | write | `proxy_cw-proxy`: RW |
| `cnc_reactivate_probe` | oam | write | `cw-probe-mgr`: R |
| `cnc_restart_microservice` | admin | write | `platform_cwplatform`: W |
| `cnc_resume_inventory_scheduler_job` | ems_jobs | write | `cw-inventory-job-dashboard`: RW |
| `cnc_resync_service_inventory` | service_provisioning | write | `nso-connector`: W |
| `cnc_run_inventory_scheduler_job` | ems_jobs | write | `cw-inventory-job-dashboard`: RW |
| `cnc_search_alarms` | fault | read | `cw-fault-alarms-api`: R |
| `cnc_set_device_location` | inventory_extras | write | `inventory_cwinventory`: RW |
| `cnc_set_login_banner` | admin | write | `platform_cwplatform`: RW |
| `cnc_set_maintenance_mode` | admin | write | `platform_cwplatform`: RW |
| `cnc_set_sr_policy_path_notifications` | sr_te_operations | write | `optima_restconf`: W |
| `cnc_start_oam_trace_route` | oam | write | `inventory_cwinventory`: R, `optima_restconf`: W |
| `cnc_suspend_inventory_scheduler_job` | ems_jobs | write | `cw-inventory-job-dashboard`: RW |
| `cnc_sync_inventory_with_nso` | nso | write | `inventory_cwinventory`: W |
| `cnc_unassign_tags` | inventory_extras | write | `inventory_cwinventory`: RW |
| `cnc_unlock_device` | inventory_extras | write | `inventory_cwinventory`: RW |
| `cnc_update_credential_profile` | credentials | write | `inventory_cwinventory`: RW |
| `cnc_update_device` | devices | write | `inventory_cwinventory`: W |
| `cnc_update_provider` | providers | write | `inventory_cwinventory`: W |
| `cnc_update_sr_policy` | sr_te_operations | write | `optima_restconf`: W, `topo_restconf`: R |
| `cnc_update_sr_policy_service` | service_provisioning | write | `proxy_cw-proxy`: RW |
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

`GET /crosswork/aaa/v1/taskAPIPermission/admin` answered five task bundles (verified 2026-09-14). Ticking a task in the UI grants the listed api_id(s) with the listed R/W/D ticks — the same letters as the tables above (section 1 says what each letter's `/.*` entry is stored as; that a tick emits that entry is inferred, not observed), so treat a bundle as "which rows and ticks the UI sets for you".

| task (UI name) | group | grants | rows it covers here |
|---|---|---|---|
| Device Access Group Management (`id_dag_management`) | Platform | `cw-grouping-service` RWD | `cw-grouping-service` (reads need R) |
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
- `Error: role '<role>' may not read its own role ...` when neither the mirror nor `aaa/v1` lets the account read its role: grant Read on `aaa_cw_role_read` first.

Evaluated against the stored `cnc-mcp-readonly` role, it reports 14 of the 182 read tools refused (the list in section 2) and 1 write tool **permitted** — `cnc_reactivate_probe` (`POST /crosswork/probemgr/v1/reactivateProbe` on `cw-probe-mgr`: the platform's read template for the API names that path, so **Read permits this write**). Against the stored `cnc-mcp-operator` role every tool is permitted.

What this verification is and is not:

- **Verified (2026-09-14, admin session, test role):** the shape the AAA service stores a submitted role in — `/.*` rows verbatim, the read templates added to a GET-only row, a lone custom POST entry reinterpreted, the two baseline rows, the POST/PUT/GET status codes and the `charset=UTF-8` content type (section 1). The counts above are computed from that stored shape with Tyk's matching rule; `tests/fixtures/rbac/` pins the model against the read-backs.
- **Still assumed:** the gateway's refusal itself. No user carrying a restricted role has logged in yet, so no 403 by a role grant has been observed; the matching rule (unanchored search on the full path, method listed) is the Tyk v5.1.1 source. And that the role editor's Read / Write / Delete ticks emit the `/.*` entries the bodies carry (section 1).
- The check is **static**: the map is derived from the tool source by api_coverage.py's extraction heuristic; no tool endpoint is called. A request built from platform data folds to `{}`; a probe counts as a use.
- A device access group other than ALL-ACCESS restricts devices, not APIs; it is reported, not evaluated. `/crosswork/aaaread/` is verified readable by the admin and the generated read-only roles. The two gateway fail-open cases (a regex that does not compile, an empty `access_rights` map) are reported as refusals.

### Ready-made role bodies

`docs/rbac/cnc-mcp-readonly.role.json` (section 2) and `docs/rbac/cnc-mcp-operator.role.json` (sections 2 + 3) are generated with this page, in the shape `POST /crosswork/aaa/v1/role` takes — `{"<role name>": {<rbacRole>}}`, the shape `GET /crosswork/aaa/v1/role` answers — with `rate`/`per`/`quota_max`/`active`/`partitions`/`key_expires_in` copied from the lab's admin role, one `access_rights` entry per api_id, `versions ["Default"]` and `allowance_scope ""` like admin. Each row carries the entries a tick is taken to emit — `/.*` with `[GET]` for Read, `[POST, PUT, PATCH]` for Write, `[DELETE]` for Delete — which the service stores verbatim (section 1); the only custom URL is the anchored GET pattern on the two AAA rows. `cnc-mcp-readonly` is R only; `cnc-mcp-operator` adds Write and Delete where a tool needs them.

Load one with an admin's SSO JWT (one curl per file; the content type must carry the charset), read it back to see the templates and baseline rows the service added, then verify with cnc_check_permissions as a user carrying the role:

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

No UI import for a role body is documented; the equivalent is ticking the rows of sections 2 and 3 in the role editor by hand (the bodies are the shape the editor is taken to emit, section 1), with the two AAA rows' URL patterns set as in section 2 where the editor allows it.
