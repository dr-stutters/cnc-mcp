# RBAC: what a Crosswork account needs to run cnc-mcp

> **Generated** by `scripts/rbac_map.py` from the tool source and the gateway's secured-API catalogue (CNC 7.2.0, 217 APIs in 27 features, catalogue verified live 2026-09-14) — do not edit by hand. Regenerate with `make rbac` (offline, from the catalogue embedded in `src/cnc_mcp/data/rbac_map.json`) or `make rbac-fetch` (re-read the catalogue from a live instance); `make rbac-check` fails when the committed files are stale.

The server registers 245 tools (182 read-only, 63 write). Each sends a known set of HTTP requests; each request is routed by the gateway to one secured API, and a role must grant that API (with the method) or the gateway refuses the call (403). This page lists exactly which API rows a role needs, first for a read-only account, then per write area, then per tool.

## 1. How Crosswork RBAC works

**Verified live** (CNC 7.2.0 single-VM lab, 2026-09-14):

- The API gateway is **Tyk** (v5.1.1, from its `/hello` health endpoint). Every `/crosswork/*` request is routed to one of 217 secured API definitions (`GET /crosswork/aaa/v1/api`), each with an `api_id`, a display `name` and a gorilla-mux **listen path** (`/crosswork/inventory/`, `/crosswork/alarms/v1/query`, `/crosswork/performance/v{.}/dashboards/`, ...).
- A **role** (`GET /crosswork/aaa/v1/role` → a dict keyed by role name) is a Tyk policy: `access_rights{<api_id>: {api_name, api_id, versions ["Default"], allowed_urls [{url: <regex>, methods: [GET, POST, PUT, PATCH, DELETE]}], allowance_scope}}` plus `rate 5000 / per 60 / quota_max -1 / active true`. The lab's only role, `admin`, grants every API with `url "/.*"` and all five methods.
- `GET /crosswork/aaa/v2/api` → `{<feature>: [{api_id, name}]}` (27 features) is the grouping the UI's role editor (Administration > Users and Roles > Roles) shows; the `feature` column below is it.
- `GET /crosswork/aaa/v1/taskAPIPermission/<role>` → `{<task id>: {apiIds: {<api_id>: ["R", "W", "D"]}}}`: the UI's **task** checkboxes are bundles of per-API R/W/D grants (section 5). `GET aaa/v1/task/<role>` lists the task groups (audit_logs, coe, crosswork_network_controller, nso_management, platform); `GET aaa/v1/roleAccess/<role>` → `{PolicyId, GuiAccess, ApiAccess, PolicyData}` — `ApiAccess false` means no API call at all.
- A **user** (`GET aaa/v1/user/<name>`) carries `PolicyId` (= its role), `Status` and `DeviceAccessGroups [{Uuid, DomainName}]` (`ALL-ACCESS` on the lab). A device access group other than ALL-ACCESS restricts which **devices** the account sees, not which APIs it may call.
- The CAS-issued session token is an HS512 JWT sent as `Authorization: Bearer`; its claims are readable without the key: `sub`/`username` (the login name), `policy_id` (the role), `deviceAccessGroups`, `exp`/`iat` (8 h), `iss`. cnc_check_permissions reads the identity from them.
- The read-only mirror `/crosswork/aaaread/...` (api_id `aaa_cw_role_read`, "Know my role - Read only", same backend) answers the same GETs as `aaa/v1` (`role/<r>`, `roleAccess/<r>`, `user/<u>`, `userpermission`, `task/<r>`, `v1/api`, `v2/api` — all 200 as admin). It is the endpoint a non-admin account is expected to read its own role through.
- The three SSO ticket calls the server logs in with (`POST /crosswork/sso/v1/tickets`, `POST .../tickets/{TGT}`, `DELETE .../tickets/{TGT}`) are **not** gateway APIs: no role grant is involved in logging in, only in what the token may then call.

**From the Tyk v5.1.1 gateway source** (`gateway/api_loader.go`, `mw_access_rights.go`, `mw_granular_access.go` — read, not observed live: the lab had no restricted role, so no refusal by a role grant was ever captured):

- Tyk registers the API definitions **longest listen path first** and each as a gorilla-mux path prefix, so a request goes to the API with the longest listen path that claims it; `{...}` in a listen path matches one segment. The map's router additionally requires the match to end at a segment boundary and accepts a missing trailing slash; no template in the map routes differently under either reading (`tests/test_rbac_map.py`). The query string is not part of the match.
- Within the routed API, each `allowed_urls[].url` is run as an **unanchored regex search against the full request path** (`regexp.MatchString` on `r.URL.Path`; the listen path is not stripped first): `/nodes` permits `/crosswork/inventory/v1/nodes/query`, `^/v1/nodes/query$` permits nothing. The method must be listed on a matching entry; an API with an empty `allowed_urls` has no path restriction.
- A request the role does not permit (no entry for the API, or no matching `allowed_urls` entry) is refused with a **403**; the body Crosswork puts on that 403 was not observed. Two fail-open cases: an `allowed_urls` regex that does not compile is let through, and so is a role whose `access_rights` map is empty — cnc_check_permissions reports both as refusals (the role as it should be configured).

**Not verified (assumed — say so when it bites):**

- Which HTTP methods the UI's **R / W / D** checkboxes translate to on the wire. Plausibly R = GET, W = POST/PUT/PATCH, D = DELETE — but many Crosswork READS are `POST .../query` calls (`POST /crosswork/inventory/v1/nodes/query` lists devices), so a UI-built "Read" role may refuse them. The tables below give the exact methods.
- Whether `/crosswork/aaaread/` is readable by every role (verified as admin only; no restricted role existed on the lab). cnc_check_permissions falls back to `/crosswork/aaa/v1` and says which one answered — either grant suffices for it.
- The generated role bodies (section 6) have not been loaded into a real Crosswork yet.

## 2. Least-privilege recipe: a read-only account

The 182 read-only tools need the 43 API rows below with the listed methods. **The recommended way is to load `docs/rbac/cnc-mcp-readonly.role.json` (section 6)**: it grants each row exactly the request paths the read tools send with each method (anchored URL patterns, one per method), so every path that only the write tools send is refused at the gateway (403) even where it shares a row and a method with a read — `POST /crosswork/inventory/v1/nodes/query` (list devices) is permitted while `POST /crosswork/inventory/v1/nodes`, `POST /crosswork/inventory/v1/tags`, `PUT /crosswork/alarms/v1/ack`, `POST /crosswork/nbi/optimization/v3/restconf/operations/cisco-crosswork-optimization-engine-sr-policy-operations:sr-policy-create` and every DELETE are not. Assign the role to a dedicated service account with device access group `ALL-ACCESS` (or the device scope you intend).

Building the role in the UI instead (Administration > Users and Roles > Roles: create a role, tick these rows under their feature, leave `ApiAccess` on) cannot reach the same result: the editor's per-row **Read / Write / Delete** checkboxes cannot separate a POST query from a POST create on the same row, so a UI-built role is read-only only if the UI's *Read* maps to what the tools send — which is not verified (section 1). If the editor offers only Read / Write / Delete, tick **Write as well as Read** for every row whose methods include POST, PUT or PATCH (the query-over-POST reads), and accept that the row then permits its writes too (`POST /crosswork/inventory/v1/nodes` next to `POST .../nodes/query`).

| feature | api_id | API name | HTTP methods the read tools use |
|---|---|---|---|
| AAA | `aaa_cw_role_read` | Know my role - Read only | GET |
| AAA | `aaa_cwaaa` | Users and Roles Management | GET |
| Administrative Operations | `external-notification-subscription` | External Notification Subscription | GET |
| Administrative Operations | `nb-api-alarm-nt-2-700` | RESTCONF Notification Subscription | GET |
| Administrative Operations | `nb-api-alarm-nt-9-700` | RESTCONF Notification Subscription | GET |
| Administrative Operations | `nb-api-subscription-api-700` | RESTCONF Notification Subscription | GET |
| Administrative Operations | `performance-dataretention-apis` | Performance Monitoring Data Retention | GET |
| Alarms and Events | `cw-fault-alarm-manager-settings` | Alarm Settings | GET |
| Alarms and Events | `cw-fault-alarm-recommended-action` | Alarm Settings | GET |
| Alarms and Events | `cw-fault-alarm-settings` | Alarm Settings | GET |
| Alarms and Events | `cw-fault-alarm-severity-settings` | Alarm Settings | GET |
| Alarms and Events | `cw-fault-alarms-api` | Alarms & Events | POST |
| Alarms and Events | `cw-fault-events-api` | Alarms & Events | POST |
| Alarms and Events | `cw-fault-gnmi-settings` | Alarm Settings | GET |
| Alarms and Events | `event-processing-service-suppressionpolicy-api` | Alarm Suppression Policies | GET |
| Alarms and Events | `nb-api-alarm-1-700` | Alarms and Events RESTCONF | GET |
| CNC | `cat-fp-deployment-manager` | CAT FP Deployment Manager APIs | GET |
| CNC | `tsdn_cat-restconf-nbi` | CAT Inventory RESTCONF APIs | GET, POST |
| Collection Infra | `collection_dg-manager` | Data Gateway Manager APIs | POST |
| Collection Infra | `cwcollection` | Collection APIs | POST |
| Crosswork Optimization Engine | `optima_analytics_api` | OPTIMA Analytics | POST |
| Crosswork Optimization Engine | `optima_restconf` | Optimization Engine RESTCONF | POST |
| Data Gateway Global Settings | `dg-manager-global-parameters-api` | Data Gateway Global Parameters API | POST |
| Device Configuration | `device-config` | Device Configuration | GET, POST |
| Device Monitoring | `cw-inventory-job-dashboard` | Device Inventory | GET |
| Device Monitoring | `ems-inventory` | Device Inventory | GET |
| Device Monitoring | `nb-api-inv-chassis-700` | Device Inventory RESTCONF | GET |
| Device Monitoring | `nb-api-inv-equipment-700` | Device Inventory RESTCONF | GET |
| Device Monitoring | `nb-api-inv-module-700` | Device Inventory RESTCONF | GET |
| Device Monitoring | `nb-api-inv-node-700` | Device Inventory RESTCONF | GET |
| Device Monitoring | `nb-api-inv-tp-700` | Device Inventory RESTCONF | GET |
| Device Monitoring | `performance-policies-rest-apis` | Performance Monitoring Policies | GET |
| Device Monitoring | `performance-rest-apis` | Performance Monitoring Dashboards | GET |
| Inventory | `inventory_cwinventory` | Inventory APIs | GET, POST |
| Platform | `cw-grouping-service` | Grouping | GET |
| Platform | `platform_cwplatform` | Platform APIs | GET, POST |
| Probe Manager | `cw-probe-mgr` | Probe Manager APIs | POST |
| Proxy | `proxy_cw-proxy` | Crosswork Proxy APIs | GET |
| Software Image Management | `swim-nbi` | SWIM | GET |
| Topology RESTCONF | `topo_restconf` | Topology RESTCONF | GET |
| Zero Touch Provisioning | `cw-config-service-deprecated` | Config Service | GET |
| Zero Touch Provisioning | `cw-image-service-deprecated` | Image Service | GET |
| Zero Touch Provisioning | `cw-ztp-service` | ZTP Service | POST |

`aaa_cw_role_read` (`/crosswork/aaaread/`) is what cnc_check_permissions reads the account's own role through; `aaa_cwaaa` (`/crosswork/aaa/`) is needed by the RBAC read tools (cnc_list_roles, cnc_get_user, ...) and is cnc_check_permissions' fallback (either of the two rows satisfies that tool).

**The two AAA rows in a UI-built role.** Both APIs also serve the broader `GET .../v1/api` listing, which returns the gateway's full API definitions — administrative data; do not grant it to a non-administrator. A row ticked in the UI grants URL pattern `/.*`, and because the gateway evaluates a row's pattern as an unanchored search on the full path (section 1), `/.*` (or any unanchored pattern) includes that listing. Where the editor lets you set a row's URL pattern, use the anchored patterns below — exactly the paths the read tools send, derived from the map; the generated bodies carry them (and a pattern of the same kind on every other row):

- `aaa_cw_role_read` (GET): `^/crosswork/aaaread/(v1/role/.+|v1/roleAccess/.+)$`
- `aaa_cwaaa` (GET): `^/crosswork/aaa/(v1/activeSessions|v1/getSessionMgmtPermissions|v1/isNSOConfigured|v1/passwordPolicyConfig|v1/role|v1/role/.+|v1/roleAccess/.+|v1/sessionconfig|v1/user|v1/user/.+|v1/userpermission|v1/userpermission/.+|v1/usertask/.+|v2/api)$`

## 3. Write areas: what each adds

Write tools are registered only with `CNC_MCP_ENABLE_WRITES=true`. Per area (the `tools/` module), the API rows and methods a role needs **in addition to** section 2 — a row already granted for reads is listed only when the writes need more methods on it. `docs/rbac/cnc-mcp-operator.role.json` is section 2 plus every area below.

### admin (3 write tools: `cnc_restart_microservice`, `cnc_set_login_banner`, `cnc_set_maintenance_mode`)

Nothing beyond section 2 (the writes use rows and methods the reads already need).

### composite (2 write tools: `cnc_create_sr_policy_e2e`, `cnc_provision_l3vpn_e2e`)

| feature | api_id | API name | additional methods |
|---|---|---|---|
| Proxy | `proxy_cw-proxy` | Crosswork Proxy APIs | PUT |

### credentials (3 write tools: `cnc_create_credential_profile`, `cnc_delete_credential_profile`, `cnc_update_credential_profile`)

| feature | api_id | API name | additional methods |
|---|---|---|---|
| Inventory | `inventory_cwinventory` | Inventory APIs | PUT, DELETE |

### data_gateway (1 write tool: `cnc_map_devices_to_data_gateway`)

| feature | api_id | API name | additional methods |
|---|---|---|---|
| Inventory | `inventory_cwinventory` | Inventory APIs | PUT |

### device_config (7 write tools: `cnc_backup_device_config`, `cnc_create_config_template`, `cnc_delete_config_backup_job`, `cnc_delete_config_template`, `cnc_delete_device_backup`, `cnc_delete_template_deployment`, `cnc_deploy_config_template`)

| feature | api_id | API name | additional methods |
|---|---|---|---|
| Device Configuration | `device-config` | Device Configuration | DELETE |

### devices (4 write tools: `cnc_create_device`, `cnc_delete_device`, `cnc_enable_device_gnmi`, `cnc_update_device`)

| feature | api_id | API name | additional methods |
|---|---|---|---|
| Inventory | `inventory_cwinventory` | Inventory APIs | PATCH, DELETE |

### ems_jobs (3 write tools: `cnc_resume_inventory_scheduler_job`, `cnc_run_inventory_scheduler_job`, `cnc_suspend_inventory_scheduler_job`)

| feature | api_id | API name | additional methods |
|---|---|---|---|
| Device Monitoring | `cw-inventory-job-dashboard` | Device Inventory | POST |

### fault (5 write tools: `cnc_acknowledge_alarm`, `cnc_annotate_alarm`, `cnc_clear_alarm`, `cnc_create_alarm_suppression_policy`, `cnc_delete_alarm_suppression_policy`)

| feature | api_id | API name | additional methods |
|---|---|---|---|
| Alarms and Events | `cw-fault-ack-api` | Alarms & Events | PUT |
| Alarms and Events | `cw-fault-clear-api` | Alarms & Events | PUT |
| Alarms and Events | `cw-fault-notes-api` | Alarms & Events | PUT |
| Alarms and Events | `event-processing-service-suppressionpolicy-api` | Alarm Suppression Policies | POST, DELETE |

### inventory_extras (8 write tools: `cnc_assign_tags`, `cnc_clear_device_location`, `cnc_create_tag`, `cnc_delete_tag`, `cnc_lock_device`, `cnc_set_device_location`, `cnc_unassign_tags`, `cnc_unlock_device`)

| feature | api_id | API name | additional methods |
|---|---|---|---|
| Inventory | `inventory_cwinventory` | Inventory APIs | PUT, PATCH, DELETE |

### lcm_csm (1 write tool: `cnc_pause_lcm_recommendations`)

Nothing beyond section 2 (the writes use rows and methods the reads already need).

### notifications (2 write tools: `cnc_create_webhook_subscription`, `cnc_delete_notification_subscription`)

| feature | api_id | API name | additional methods |
|---|---|---|---|
| Administrative Operations | `nb-api-subscription-api-700` | RESTCONF Notification Subscription | POST, DELETE |

### nso (3 write tools: `cnc_nso_device_action`, `cnc_nso_sync_to_device`, `cnc_sync_inventory_with_nso`)

Nothing beyond section 2 (the writes use rows and methods the reads already need).

### oam (2 write tools: `cnc_reactivate_probe`, `cnc_start_oam_trace_route`)

Nothing beyond section 2 (the writes use rows and methods the reads already need).

### providers (3 write tools: `cnc_create_provider`, `cnc_delete_provider`, `cnc_update_provider`)

| feature | api_id | API name | additional methods |
|---|---|---|---|
| Inventory | `inventory_cwinventory` | Inventory APIs | PATCH, DELETE |

### service_provisioning (12 write tools: `cnc_create_l3vpn_service`, `cnc_create_odn_template`, `cnc_create_sid_list`, `cnc_create_sr_policy_service`, `cnc_delete_odn_template`, `cnc_delete_service`, `cnc_delete_sid_list`, `cnc_delete_sr_policy_service`, `cnc_delete_vpn_service`, `cnc_provision_service`, `cnc_resync_service_inventory`, `cnc_update_sr_policy_service`)

| feature | api_id | API name | additional methods |
|---|---|---|---|
| CNC | `nso-connector` | NSO Connector APIs | POST |
| Proxy | `proxy_cw-proxy` | Crosswork Proxy APIs | PUT, PATCH, DELETE |

### sr_te_operations (4 write tools: `cnc_create_sr_policy`, `cnc_delete_sr_policy`, `cnc_set_sr_policy_path_notifications`, `cnc_update_sr_policy`)

Nothing beyond section 2 (the writes use rows and methods the reads already need).

`cnc-mcp-operator.role.json` widens the URL patterns accordingly: per row, the methods the writes add get their own anchored entries covering exactly the write paths, and a method the reads already use gains the write paths it sends (section 6). The AAA rows of section 2 are unchanged (the write tools add no path on them).

## 4. Per-tool requirements

Every registered tool with the api_id(s) it needs and the methods per api_id (`*` in the map = the tool passes the method through, all five needed; `{}` in a path = a runtime value). Playbooks (area `composite`) send nothing themselves: their rows are the union of the siblings they call. A tool that tries one API and falls back to another lists its alternatives with *or*: one of them suffices.

| tool | area | kind | api_id: methods |
|---|---|---|---|
| `cnc_acknowledge_alarm` | fault | write | `cw-fault-ack-api`: PUT, `cw-fault-alarms-api`: POST |
| `cnc_alarm_triage` | composite | read playbook (4 siblings) | `cw-fault-alarms-api`: POST, `nb-api-alarm-1-700`: GET, `platform_cwplatform`: GET/POST |
| `cnc_annotate_alarm` | fault | write | `cw-fault-alarms-api`: POST, `cw-fault-notes-api`: PUT |
| `cnc_assign_tags` | inventory_extras | write | `inventory_cwinventory`: POST/PATCH |
| `cnc_backup_device_config` | device_config | write | `device-config`: POST, `inventory_cwinventory`: POST |
| `cnc_check_certificate_expiry` | admin | read | `platform_cwplatform`: GET |
| `cnc_check_device_nso_state` | nso | read | `inventory_cwinventory`: POST |
| `cnc_check_nso_device_sync` | nso | read | `inventory_cwinventory`: POST |
| `cnc_check_permissions` | admin | read | `aaa_cw_role_read`: GET *or* `aaa_cwaaa`: GET |
| `cnc_clear_alarm` | fault | write | `cw-fault-alarms-api`: POST, `cw-fault-clear-api`: PUT |
| `cnc_clear_device_location` | inventory_extras | write | `inventory_cwinventory`: POST/PATCH |
| `cnc_create_alarm_suppression_policy` | fault | write | `event-processing-service-suppressionpolicy-api`: POST |
| `cnc_create_config_template` | device_config | write | `device-config`: POST |
| `cnc_create_credential_profile` | credentials | write | `inventory_cwinventory`: POST |
| `cnc_create_device` | devices | write | `inventory_cwinventory`: POST |
| `cnc_create_l3vpn_service` | service_provisioning | write | `proxy_cw-proxy`: GET/PUT |
| `cnc_create_odn_template` | service_provisioning | write | `proxy_cw-proxy`: GET/PUT |
| `cnc_create_provider` | providers | write | `inventory_cwinventory`: POST |
| `cnc_create_sid_list` | service_provisioning | write | `proxy_cw-proxy`: GET/PUT |
| `cnc_create_sr_policy` | sr_te_operations | write | `optima_restconf`: POST, `topo_restconf`: GET |
| `cnc_create_sr_policy_e2e` | composite | write playbook (4 siblings) | `optima_restconf`: POST, `topo_restconf`: GET |
| `cnc_create_sr_policy_service` | service_provisioning | write | `proxy_cw-proxy`: GET/PUT |
| `cnc_create_tag` | inventory_extras | write | `inventory_cwinventory`: POST |
| `cnc_create_webhook_subscription` | notifications | write | `nb-api-subscription-api-700`: POST |
| `cnc_delete_alarm_suppression_policy` | fault | write | `event-processing-service-suppressionpolicy-api`: DELETE |
| `cnc_delete_config_backup_job` | device_config | write | `device-config`: DELETE |
| `cnc_delete_config_template` | device_config | write | `device-config`: DELETE |
| `cnc_delete_credential_profile` | credentials | write | `inventory_cwinventory`: DELETE |
| `cnc_delete_device` | devices | write | `inventory_cwinventory`: DELETE |
| `cnc_delete_device_backup` | device_config | write | `device-config`: DELETE, `inventory_cwinventory`: POST |
| `cnc_delete_notification_subscription` | notifications | write | `nb-api-subscription-api-700`: DELETE |
| `cnc_delete_odn_template` | service_provisioning | write | `proxy_cw-proxy`: GET/DELETE |
| `cnc_delete_provider` | providers | write | `inventory_cwinventory`: DELETE |
| `cnc_delete_service` | service_provisioning | write | `proxy_cw-proxy`: GET/DELETE |
| `cnc_delete_sid_list` | service_provisioning | write | `proxy_cw-proxy`: GET/DELETE |
| `cnc_delete_sr_policy` | sr_te_operations | write | `optima_restconf`: POST, `topo_restconf`: GET |
| `cnc_delete_sr_policy_service` | service_provisioning | write | `proxy_cw-proxy`: GET/DELETE |
| `cnc_delete_tag` | inventory_extras | write | `inventory_cwinventory`: DELETE |
| `cnc_delete_template_deployment` | device_config | write | `device-config`: DELETE |
| `cnc_delete_vpn_service` | service_provisioning | write | `proxy_cw-proxy`: GET/DELETE |
| `cnc_deploy_config_template` | device_config | write | `device-config`: GET/POST, `inventory_cwinventory`: POST |
| `cnc_dryrun_sr_policy` | sr_te_operations | read | `optima_restconf`: POST, `topo_restconf`: GET |
| `cnc_enable_device_gnmi` | devices | write | `inventory_cwinventory`: POST/PATCH |
| `cnc_explain_service` | composite | read playbook (7 siblings) | `cw-probe-mgr`: POST, `proxy_cw-proxy`: GET, `tsdn_cat-restconf-nbi`: GET/POST |
| `cnc_explain_sr_policy` | composite | read playbook (11 siblings) | `inventory_cwinventory`: POST, `optima_analytics_api`: POST, `optima_restconf`: POST, `proxy_cw-proxy`: GET, `topo_restconf`: GET, `tsdn_cat-restconf-nbi`: POST |
| `cnc_find_services_on_transport` | services | read | `inventory_cwinventory`: POST, `tsdn_cat-restconf-nbi`: POST |
| `cnc_get_alarm` | fault | read | `cw-fault-alarms-api`: POST |
| `cnc_get_alarm_manager_settings` | fault | read | `cw-fault-alarm-manager-settings`: GET |
| `cnc_get_alarm_settings` | fault | read | `cw-fault-alarm-settings`: GET, `cw-fault-gnmi-settings`: GET |
| `cnc_get_cluster_health` | admin | read | `platform_cwplatform`: GET |
| `cnc_get_cluster_node` | admin | read | `platform_cwplatform`: POST |
| `cnc_get_collection_cadence` | inventory_extras | read | `inventory_cwinventory`: POST |
| `cnc_get_collection_health` | collection | read | `cwcollection`: POST |
| `cnc_get_collection_job_count` | collection | read | `cwcollection`: POST |
| `cnc_get_collection_job_state` | collection | read | `cwcollection`: POST |
| `cnc_get_collection_job_summary` | collection | read | `cwcollection`: POST |
| `cnc_get_config_backup_job` | device_config | read | `device-config`: POST |
| `cnc_get_config_template` | device_config | read | `device-config`: GET |
| `cnc_get_credential_profile` | credentials | read | `inventory_cwinventory`: POST |
| `cnc_get_data_gateway` | data_gateway | read | `collection_dg-manager`: POST |
| `cnc_get_data_gateway_global_parameters` | data_gateway | read | `dg-manager-global-parameters-api`: POST |
| `cnc_get_data_gateway_health` | data_gateway | read | `collection_dg-manager`: POST |
| `cnc_get_data_gateway_load_metrics` | data_gateway | read | `collection_dg-manager`: POST |
| `cnc_get_device` | devices | read | `inventory_cwinventory`: POST |
| `cnc_get_device_backup` | device_config | read | `device-config`: GET, `inventory_cwinventory`: POST |
| `cnc_get_device_collection_summary` | devices | read | `ems-inventory`: GET |
| `cnc_get_device_config_preferences` | device_config | read | `device-config`: GET |
| `cnc_get_device_running_images` | swim_ztp | read | `swim-nbi`: GET |
| `cnc_get_device_summary` | inventory_extras | read | `inventory_cwinventory`: GET |
| `cnc_get_device_tags` | inventory_extras | read | `inventory_cwinventory`: POST |
| `cnc_get_ems_interface` | physical_inventory | read | `nb-api-inv-tp-700`: GET |
| `cnc_get_ems_inventory_summary` | physical_inventory | read | `nb-api-inv-chassis-700`: GET, `nb-api-inv-equipment-700`: GET, `nb-api-inv-module-700`: GET, `nb-api-inv-node-700`: GET |
| `cnc_get_ems_node` | physical_inventory | read | `nb-api-inv-node-700`: GET |
| `cnc_get_event_type_recommendation` | fault | read | `cw-fault-alarm-recommended-action`: GET |
| `cnc_get_group_details` | grouping | read | `cw-grouping-service`: GET |
| `cnc_get_group_hierarchy` | grouping | read | `cw-grouping-service`: GET |
| `cnc_get_interface_delay` | performance | read | `optima_analytics_api`: POST |
| `cnc_get_inventory_config` | inventory_extras | read | `inventory_cwinventory`: POST |
| `cnc_get_inventory_job` | platform | read | `inventory_cwinventory`: POST |
| `cnc_get_inventory_scheduler_job` | ems_jobs | read | `cw-inventory-job-dashboard`: GET |
| `cnc_get_lcm_config` | lcm_csm | read | `optima_restconf`: POST |
| `cnc_get_lcm_recommendation` | lcm_csm | read | `optima_restconf`: POST |
| `cnc_get_lcm_recommendation_preview` | lcm_csm | read | `optima_restconf`: POST |
| `cnc_get_link_performance_metrics` | te_state | read | `topo_restconf`: GET |
| `cnc_get_login_banner` | admin | read | `platform_cwplatform`: POST |
| `cnc_get_lsp_delay` | performance | read | `optima_analytics_api`: POST, `topo_restconf`: GET |
| `cnc_get_lsp_utilization` | performance | read | `optima_analytics_api`: POST, `topo_restconf`: GET |
| `cnc_get_maintenance_status` | admin | read | `platform_cwplatform`: GET |
| `cnc_get_node_interface` | topology | read | `topo_restconf`: GET |
| `cnc_get_notification_subscription` | notifications | read | `nb-api-subscription-api-700`: GET |
| `cnc_get_nso_device` | nso | read | `proxy_cw-proxy`: GET |
| `cnc_get_nso_device_config` | nso | read | `proxy_cw-proxy`: GET |
| `cnc_get_nso_policy` | nso | read | `inventory_cwinventory`: POST |
| `cnc_get_oam_settings` | oam | read | `optima_restconf`: POST |
| `cnc_get_oam_trace_route` | oam | read | `inventory_cwinventory`: POST, `optima_restconf`: POST |
| `cnc_get_p2mp_policy` | te_state | read | `topo_restconf`: GET |
| `cnc_get_password_policy` | admin | read | `aaa_cwaaa`: GET |
| `cnc_get_performance_health_settings` | performance | read | `performance-rest-apis`: GET |
| `cnc_get_performance_policy` | performance | read | `performance-policies-rest-apis`: GET |
| `cnc_get_performance_policy_history` | performance | read | `performance-policies-rest-apis`: GET |
| `cnc_get_performance_retention` | performance | read | `performance-dataretention-apis`: GET |
| `cnc_get_performance_statistics` | performance | read | `performance-policies-rest-apis`: GET, `performance-rest-apis`: GET, `topo_restconf`: GET |
| `cnc_get_performance_summary` | performance | read | `performance-rest-apis`: GET |
| `cnc_get_performance_top_n` | performance | read | `performance-rest-apis`: GET |
| `cnc_get_platform_version` | admin | read | `platform_cwplatform`: GET |
| `cnc_get_probe_status` | oam | read | `cw-probe-mgr`: POST |
| `cnc_get_provider` | providers | read | `inventory_cwinventory`: POST |
| `cnc_get_role_permissions` | admin | read | `aaa_cwaaa`: GET |
| `cnc_get_role_tasks` | admin | read | `aaa_cwaaa`: GET |
| `cnc_get_rsvp_te_tunnel` | te_state | read | `topo_restconf`: GET |
| `cnc_get_rsvp_tunnel_performance_metrics` | te_state | read | `topo_restconf`: GET |
| `cnc_get_service` | services | read | `proxy_cw-proxy`: GET, `tsdn_cat-restconf-nbi`: POST |
| `cnc_get_service_counts` | services | read | `tsdn_cat-restconf-nbi`: POST |
| `cnc_get_service_plan` | services | read | `proxy_cw-proxy`: GET, `tsdn_cat-restconf-nbi`: POST |
| `cnc_get_session_config` | admin | read | `aaa_cwaaa`: GET |
| `cnc_get_sr_policy` | te_state | read | `topo_restconf`: GET |
| `cnc_get_sr_policy_metrics` | sr_te_operations | read | `optima_restconf`: POST, `topo_restconf`: GET |
| `cnc_get_sr_policy_path_notification_state` | sr_te_operations | read | `optima_restconf`: POST |
| `cnc_get_sr_policy_performance_metrics` | te_state | read | `topo_restconf`: GET |
| `cnc_get_sr_policy_routes` | sr_te_operations | read | `optima_restconf`: POST, `topo_restconf`: GET |
| `cnc_get_swim_job` | swim_ztp | read | `swim-nbi`: GET |
| `cnc_get_swim_preferences` | swim_ztp | read | `swim-nbi`: GET |
| `cnc_get_te_summary` | te_state | read | `topo_restconf`: GET |
| `cnc_get_template_deployment` | device_config | read | `device-config`: POST |
| `cnc_get_topology_link` | topology | read | `topo_restconf`: GET |
| `cnc_get_topology_node` | topology | read | `topo_restconf`: GET |
| `cnc_get_topology_summary` | topology | read | `topo_restconf`: GET |
| `cnc_get_user` | admin | read | `aaa_cwaaa`: GET |
| `cnc_get_vpn_service` | services | read | `tsdn_cat-restconf-nbi`: GET |
| `cnc_get_vpn_service_health` | services | read | `tsdn_cat-restconf-nbi`: GET |
| `cnc_get_vpn_underlay_transport` | services | read | `tsdn_cat-restconf-nbi`: GET |
| `cnc_get_ztp_device_policy` | swim_ztp | read | `cw-ztp-service`: POST |
| `cnc_investigate_device` | composite | read playbook (10 siblings) | `cw-fault-alarms-api`: POST, `cw-fault-events-api`: POST, `device-config`: GET, `ems-inventory`: GET, `inventory_cwinventory`: POST, `nb-api-alarm-1-700`: GET, `nb-api-inv-node-700`: GET, `performance-policies-rest-apis`: GET, `performance-rest-apis`: GET, `topo_restconf`: GET |
| `cnc_is_nso_configured` | nso | read | `aaa_cwaaa`: GET |
| `cnc_list_active_sessions` | admin | read | `aaa_cwaaa`: GET |
| `cnc_list_alarm_suppression_policies` | fault | read | `event-processing-service-suppressionpolicy-api`: GET |
| `cnc_list_alarms` | platform | read | `cw-fault-alarms-api`: POST |
| `cnc_list_app_manager_events` | admin | read | `platform_cwplatform`: POST |
| `cnc_list_app_manager_jobs` | admin | read | `platform_cwplatform`: POST |
| `cnc_list_application_status` | admin | read | `platform_cwplatform`: POST |
| `cnc_list_applications` | platform | read | `platform_cwplatform`: POST |
| `cnc_list_certificates` | admin | read | `platform_cwplatform`: GET |
| `cnc_list_cluster_nodes` | admin | read | `platform_cwplatform`: GET |
| `cnc_list_config_backup_jobs` | device_config | read | `device-config`: POST |
| `cnc_list_config_templates` | device_config | read | `device-config`: POST |
| `cnc_list_credential_profiles` | credentials | read | `inventory_cwinventory`: POST |
| `cnc_list_cs_policies_on_interface` | lcm_csm | read | `optima_restconf`: POST, `topo_restconf`: GET |
| `cnc_list_cs_policies_on_nodes` | lcm_csm | read | `optima_restconf`: POST, `topo_restconf`: GET |
| `cnc_list_cs_policy_paths` | lcm_csm | read | `optima_restconf`: POST |
| `cnc_list_csm_bandwidth_pools` | lcm_csm | read | `optima_restconf`: POST |
| `cnc_list_data_destinations` | data_gateway | read | `collection_dg-manager`: POST |
| `cnc_list_data_gateway_files` | data_gateway | read | `collection_dg-manager`: POST |
| `cnc_list_data_gateway_outages` | data_gateway | read | `collection_dg-manager`: POST |
| `cnc_list_data_gateway_pools` | data_gateway | read | `collection_dg-manager`: POST |
| `cnc_list_data_gateways` | data_gateway | read | `collection_dg-manager`: POST |
| `cnc_list_device_alarms` | fault | read | `nb-api-alarm-1-700`: GET |
| `cnc_list_device_backups` | device_config | read | `device-config`: GET, `inventory_cwinventory`: POST |
| `cnc_list_devices` | devices | read | `inventory_cwinventory`: POST |
| `cnc_list_ems_interfaces` | physical_inventory | read | `nb-api-inv-tp-700`: GET |
| `cnc_list_ems_nodes` | physical_inventory | read | `nb-api-inv-node-700`: GET |
| `cnc_list_event_types` | fault | read | `cw-fault-alarm-severity-settings`: GET |
| `cnc_list_events` | fault | read | `cw-fault-events-api`: POST |
| `cnc_list_export_collection_jobs` | collection | read | `cwcollection`: POST |
| `cnc_list_function_packs` | services | read | `cat-fp-deployment-manager`: GET |
| `cnc_list_group_devices` | grouping | read | `cw-grouping-service`: GET |
| `cnc_list_group_rule_conditions` | grouping | read | `cw-grouping-service`: GET |
| `cnc_list_inventory_jobs` | platform | read | `inventory_cwinventory`: POST |
| `cnc_list_inventory_scheduler_jobs` | ems_jobs | read | `cw-inventory-job-dashboard`: GET |
| `cnc_list_kafka_subscriptions` | notifications | read | `external-notification-subscription`: GET |
| `cnc_list_lcm_domains` | lcm_csm | read | `optima_restconf`: POST |
| `cnc_list_lcm_managed_interfaces` | lcm_csm | read | `optima_restconf`: POST |
| `cnc_list_microservices` | admin | read | `platform_cwplatform`: POST |
| `cnc_list_node_interfaces` | topology | read | `topo_restconf`: GET |
| `cnc_list_notification_streams` | notifications | read | `nb-api-alarm-nt-9-700`: GET |
| `cnc_list_notification_subscriptions` | notifications | read | `nb-api-alarm-nt-2-700`: GET, `nb-api-subscription-api-700`: GET |
| `cnc_list_nso_devices` | nso | read | `proxy_cw-proxy`: GET |
| `cnc_list_oam_trace_routes` | oam | read | `optima_restconf`: POST |
| `cnc_list_p2mp_policies` | te_state | read | `topo_restconf`: GET |
| `cnc_list_performance_policies` | performance | read | `performance-policies-rest-apis`: GET |
| `cnc_list_performance_policy_devices` | performance | read | `performance-policies-rest-apis`: GET |
| `cnc_list_performance_policy_templates` | performance | read | `performance-policies-rest-apis`: GET |
| `cnc_list_performance_top_n_columns` | performance | read | `performance-rest-apis`: GET |
| `cnc_list_providers` | providers | read | `inventory_cwinventory`: POST |
| `cnc_list_roles` | admin | read | `aaa_cwaaa`: GET |
| `cnc_list_root_groups` | grouping | read | `cw-grouping-service`: GET |
| `cnc_list_rsvp_te_tunnels` | te_state | read | `topo_restconf`: GET |
| `cnc_list_secured_apis` | admin | read | `aaa_cwaaa`: GET |
| `cnc_list_sensor_templates` | collection | read | `cwcollection`: POST |
| `cnc_list_service_types` | services | read | `tsdn_cat-restconf-nbi`: POST |
| `cnc_list_services` | services | read | `tsdn_cat-restconf-nbi`: POST |
| `cnc_list_software_images` | swim_ztp | read | `swim-nbi`: GET |
| `cnc_list_sr_policies` | te_state | read | `topo_restconf`: GET |
| `cnc_list_sr_policies_on_interface` | sr_te_operations | read | `optima_restconf`: POST, `topo_restconf`: GET |
| `cnc_list_sr_policies_on_nodes` | sr_te_operations | read | `optima_restconf`: POST, `topo_restconf`: GET |
| `cnc_list_sub_services` | services | read | `tsdn_cat-restconf-nbi`: POST |
| `cnc_list_tags` | platform | read | `inventory_cwinventory`: POST |
| `cnc_list_template_deployments` | device_config | read | `device-config`: POST |
| `cnc_list_topology_links` | topology | read | `topo_restconf`: GET |
| `cnc_list_topology_nodes` | topology | read | `topo_restconf`: GET |
| `cnc_list_users` | platform | read | `aaa_cwaaa`: GET |
| `cnc_list_vpn_services` | services | read | `tsdn_cat-restconf-nbi`: GET |
| `cnc_list_ztp_config_files` | swim_ztp | read | `cw-config-service-deprecated`: GET |
| `cnc_list_ztp_devices` | swim_ztp | read | `cw-ztp-service`: POST |
| `cnc_list_ztp_images` | swim_ztp | read | `cw-image-service-deprecated`: GET |
| `cnc_list_ztp_profiles` | swim_ztp | read | `cw-ztp-service`: POST |
| `cnc_list_ztp_serial_numbers` | swim_ztp | read | `cw-ztp-service`: POST |
| `cnc_list_ztp_static_routes` | swim_ztp | read | `cw-ztp-service`: POST |
| `cnc_lock_device` | inventory_extras | write | `inventory_cwinventory`: POST |
| `cnc_map_devices_to_data_gateway` | data_gateway | write | `collection_dg-manager`: POST, `inventory_cwinventory`: PUT |
| `cnc_network_health_report` | composite | read playbook (12 siblings) | `collection_dg-manager`: POST, `cw-fault-alarms-api`: POST, `cwcollection`: POST, `ems-inventory`: GET, `inventory_cwinventory`: GET/POST, `nb-api-alarm-1-700`: GET, `platform_cwplatform`: GET, `topo_restconf`: GET |
| `cnc_nso_device_action` | nso | write | `inventory_cwinventory`: POST |
| `cnc_nso_sync_to_device` | nso | write | `inventory_cwinventory`: POST |
| `cnc_pause_lcm_recommendations` | lcm_csm | write | `optima_restconf`: POST |
| `cnc_preview_sr_policy_route` | sr_te_operations | read | `optima_restconf`: POST, `topo_restconf`: GET |
| `cnc_provision_l3vpn_e2e` | composite | write playbook (6 siblings) | `inventory_cwinventory`: POST, `optima_restconf`: POST, `proxy_cw-proxy`: GET/PUT, `tsdn_cat-restconf-nbi`: GET/POST |
| `cnc_provision_service` | service_provisioning | write | `proxy_cw-proxy`: GET/PUT/PATCH |
| `cnc_reactivate_probe` | oam | write | `cw-probe-mgr`: POST |
| `cnc_restart_microservice` | admin | write | `platform_cwplatform`: POST |
| `cnc_resume_inventory_scheduler_job` | ems_jobs | write | `cw-inventory-job-dashboard`: GET/POST |
| `cnc_resync_service_inventory` | service_provisioning | write | `nso-connector`: POST |
| `cnc_run_inventory_scheduler_job` | ems_jobs | write | `cw-inventory-job-dashboard`: GET/POST |
| `cnc_search_alarms` | fault | read | `cw-fault-alarms-api`: POST |
| `cnc_set_device_location` | inventory_extras | write | `inventory_cwinventory`: POST/PATCH |
| `cnc_set_login_banner` | admin | write | `platform_cwplatform`: POST |
| `cnc_set_maintenance_mode` | admin | write | `platform_cwplatform`: GET/POST |
| `cnc_set_sr_policy_path_notifications` | sr_te_operations | write | `optima_restconf`: POST |
| `cnc_start_oam_trace_route` | oam | write | `inventory_cwinventory`: POST, `optima_restconf`: POST |
| `cnc_suspend_inventory_scheduler_job` | ems_jobs | write | `cw-inventory-job-dashboard`: GET/POST |
| `cnc_sync_inventory_with_nso` | nso | write | `inventory_cwinventory`: POST |
| `cnc_unassign_tags` | inventory_extras | write | `inventory_cwinventory`: POST/PUT |
| `cnc_unlock_device` | inventory_extras | write | `inventory_cwinventory`: POST |
| `cnc_update_credential_profile` | credentials | write | `inventory_cwinventory`: POST/PUT |
| `cnc_update_device` | devices | write | `inventory_cwinventory`: PATCH |
| `cnc_update_provider` | providers | write | `inventory_cwinventory`: PATCH |
| `cnc_update_sr_policy` | sr_te_operations | write | `optima_restconf`: POST, `topo_restconf`: GET |
| `cnc_update_sr_policy_service` | service_provisioning | write | `proxy_cw-proxy`: GET/PATCH |
| `cnc_wait_for_config_backup_job` | device_config | read | `device-config`: POST |
| `cnc_wait_for_device_nso_state` | nso | read | `inventory_cwinventory`: POST |
| `cnc_wait_for_device_reachable` | devices | read | `inventory_cwinventory`: POST |
| `cnc_wait_for_inventory_job` | platform | read | `inventory_cwinventory`: POST |
| `cnc_wait_for_inventory_scheduler_job` | ems_jobs | read | `cw-inventory-job-dashboard`: GET |
| `cnc_wait_for_oam_trace_route` | oam | read | `inventory_cwinventory`: POST, `optima_restconf`: POST |
| `cnc_wait_for_service_plan` | services | read | `tsdn_cat-restconf-nbi`: POST |
| `cnc_wait_for_sr_policy_oper_state` | sr_te_operations | read | `topo_restconf`: GET |
| `cnc_wait_for_template_deployment` | device_config | read | `device-config`: POST |

Every request template the tools send resolved to a secured API.

## 5. Task checkboxes that bundle the same grants

`GET /crosswork/aaa/v1/taskAPIPermission/admin` answered five task bundles (verified 2026-09-14). Ticking a task in the UI grants the listed api_id(s) with the listed R/W/D letters — how those letters map to HTTP methods is not verified (section 1), so treat a bundle as "which rows the UI ticks for you", not as a substitute for the methods above.

| task (UI name) | group | grants | rows it covers here |
|---|---|---|---|
| Device Access Group Management (`id_dag_management`) | Platform | `cw-grouping-service` RWD | `cw-grouping-service` (reads need GET) |
| Export Audit Logs (`id_export_audit_logs_access`) | Audit Logs | `cw-fault-events-api` RW | `cw-fault-events-api` (reads need POST) |
| Function Pack Deployment (`id_nso_fp_deployment_management`) | NSO Management | `nso-fp-dep-mngr` RWD | no cnc-mcp tool uses these rows |
| Provisioning (`id_provisioning`) | Crosswork Network Controller | `inventory_cwinventory` RW | `inventory_cwinventory` (reads need GET/POST; writes add PUT/PATCH/DELETE) |
| View Audit Logs (`id_view_audit_logs_access`) | Audit Logs | `cw-fault-events-api` R | `cw-fault-events-api` (reads need POST) |

The remaining tasks the admin role carries — Bandwidth on Demand Configuration (`id_bwod_config`, Crosswork Optimization Engine), Circuit Style SR-TE Configuration (`id_csm_config`, Crosswork Optimization Engine), Local Congestion Mitigation Domain 0 (`id_lcm_0`, Crosswork Optimization Engine), Local Congestion Mitigation All Domains (`id_lcm_all_access`, Crosswork Optimization Engine) — returned no API bundle: they are feature permissions (`GET aaa/v1/userpermission`), not gateway grants, and are not needed for the API calls above. Whether other task bundles exist for other roles is not known.

## 6. Verifying an account

Log the server in as the account (username/password in `.env`) and call `cnc_check_permissions` (`make cli ARGS="call cnc_check_permissions '{}'"`). It reports the identity from the JWT (username, role, device access groups, token expiry), where it read the role from (`aaaread` or the `aaa/v1` fallback), GuiAccess / ApiAccess, and then one of:

- `All N registered tools are permitted by role '<role>'`, or
- `K of N registered tools would be refused by the gateway (403) under role '<role>'`, followed by the **API rows to grant** (feature | api_id | API name | methods to add | tools affected) and, per refused tool, the missing METHOD path rows — the same rows as this page, filtered to what the role lacks.
- Tools the packaged map does not know are listed under "not in the RBAC map" — regenerate with `make rbac`.
- `Error: role '<role>' may not read its own role ...` when neither the mirror nor `aaa/v1` lets the account read its role: grant GET on `aaa_cw_role_read` first.

Caveats the tool repeats in its own output:

- The check is **static**: the map is derived from the tool source by api_coverage.py's extraction heuristic and matched against the role's `access_rights` with the Tyk semantics of section 1 (unanchored search on the full path); no tool endpoint is called. A request built from platform data folds to `{}`; a probe counts as a use.
- The R/W/D → HTTP-method mapping of the UI is unverified; the map names methods.
- A device access group other than ALL-ACCESS restricts devices, not APIs; it is reported, not evaluated.
- `/crosswork/aaaread/` is assumed readable by every role (verified as admin only).
- The two gateway fail-open cases (a regex that does not compile, an empty `access_rights` map) are reported as refusals.

### Ready-made role bodies

`docs/rbac/cnc-mcp-readonly.role.json` (section 2) and `docs/rbac/cnc-mcp-operator.role.json` (sections 2 + 3) are generated with this page, in the shape the AAA API document gives for `POST /crosswork/aaa/v1/role` — `{"<role name>": {<rbacRole>}}`, the shape `GET /crosswork/aaa/v1/role` answers — with `rate`/`per`/`quota_max`/`active`/`partitions`/`key_expires_in` copied from the lab's admin role, one `access_rights` entry per api_id, `versions ["Default"]` and `allowance_scope ""` like admin. Where admin grants `allowed_urls [{"url": "/.*", "methods": [all five]}]`, a generated row carries **one entry per HTTP method**, `{"url": "^<listen path>/(<path>|<path>|...)$", "methods": ["POST"]}`, whose URL pattern is an anchored regex naming exactly the path templates the granted tools send with that method (methods that send the same paths share an entry; a runtime value is one segment, `[^/]+`, except in the last segment, `.+`, where a RESTCONF key such as `.../device={}` or `.../restconf/data/{}` carries `/`). The gateway runs each pattern as an unanchored search on the full request path (section 1), which is why every alternative starts with `^` and the listen path and ends with `$` — nothing else on the row is permitted. Two limits of that claim: a last-segment `.+` also admits deeper sub-paths under its template, and a mid-path `[^/]+` assumes the runtime key never contains `/` (the gateway matches the decoded path, so a percent-encoded `/` is refused too) — no key the tools send does today.

So `cnc-mcp-readonly` (43 rows, 47 URL entries) **refuses every write path at the gateway**: of the 53 (method, path) pairs only the write tools send, none with a mutating method matches any of its entries — `POST /crosswork/inventory/v1/nodes`, `POST /crosswork/inventory/v1/tags`, `PUT /crosswork/alarms/v1/ack`, `POST /crosswork/nbi/optimization/v3/restconf/operations/cisco-crosswork-optimization-engine-sr-policy-operations:sr-policy-create` and every DELETE, PUT and PATCH are refused — while every path the read tools send matches one. The 2 write-tool pairs it does match are GETs: reads a write tool sends that fall under a read tool's own runtime-valued path, so a read tool can send them just as well (`GET /crosswork/proxy/nso/restconf/data/{}-plan={}`, `GET /crosswork/proxy/nso/restconf/data/{}/{}-plan={}` under `GET /crosswork/proxy/nso/restconf/data/{}`). No mutating method leaks — the generator refuses to write a body where one would. `tests/test_rbac_map.py` proves all of this under Tyk's matching rule. `cnc-mcp-operator` (47 rows, 60 URL entries) permits every path every tool sends, and nothing beyond their templates. Neither body permits `GET /crosswork/aaa/v1/api` or `GET /crosswork/aaaread/v1/api`.

**They are generated and have not been tested against a real role** (the maintainer will); load one with the SSO JWT (one curl per file) and then verify with cnc_check_permissions as a user carrying the role:

```bash
CNC=https://<host>:30603
TGT=$(curl -sk -X POST "$CNC/crosswork/sso/v1/tickets" \
      -d "username=$CNC_USER" -d "password=$CNC_PASS")  # an admin
JWT=$(curl -sk -X POST "$CNC/crosswork/sso/v1/tickets/$TGT" \
      -d "service=$CNC/app-dashboard")
curl -sk -X POST "$CNC/crosswork/aaa/v1/role" -H "Authorization: Bearer $JWT" \
     -H "Content-Type: application/json" --data @docs/rbac/cnc-mcp-readonly.role.json
# release the SSO session (Crosswork caps concurrent sessions per user)
curl -sk -X DELETE "$CNC/crosswork/sso/v1/tickets/$TGT" -H "Authorization: Bearer $JWT"
```

No UI import for a role body is documented; the alternative is ticking the rows of sections 2 and 3 in the role editor by hand — with the caveat of section 2 that the editor's Read / Write / Delete checkboxes cannot express the per-path grants above.
