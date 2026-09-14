"""Platform administration / RBAC tools end-to-end through MCPServer (schema
validation included).

The module is registered directly (not through build_server) so the test does
not depend on tools/__init__.py's module list. All HTTP is mocked with respx.
Fixtures are the envelopes captured live on the 7.2 single-VM build
(2026-09-13, see the platform notes) — trimmed, but with the real keys, casing
and wrappers.
"""

from __future__ import annotations

import itertools
import json

import httpx
import pytest
import respx
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from cnc_mcp.auth import StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.config import Settings
from cnc_mcp.formatting import TRUNCATION_HINT, epoch_iso
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import ALL_MODULES, admin
from tests.conftest import BASE_URL, call_tool_text

PLATFORM = f"{BASE_URL}/crosswork/platform/v2"
AAA = f"{BASE_URL}/crosswork/aaa/v1"
AAA_V2 = f"{BASE_URL}/crosswork/aaa/v2"

VERSION_URL = f"{PLATFORM}/cluster/version/show"
CLUSTER_SUMMARY_URL = f"{PLATFORM}/cluster/summary/list"
INFRA_SUMMARY_URL = f"{PLATFORM}/cluster/infra/summary"
APP_HEALTH_URL = f"{PLATFORM}/cluster/app/health/list"
NODE_SUMMARY_URL = f"{PLATFORM}/cluster/dc/node/summary/list"
NODE_DETAILS_URL = f"{PLATFORM}/cluster/dc/node/details/query"
MICROSERVICES_URL = f"{PLATFORM}/cluster/microservice/list/query"
RESTART_URL = f"{PLATFORM}/cluster/microservice/restart"
BANNER_GET_URL = f"{PLATFORM}/cluster/banner/get"
BANNER_SET_URL = f"{PLATFORM}/cluster/banner/set"
INSTALLED_IDS_URL = f"{PLATFORM}/capp/installedapplicationid/query"
APP_STATUS_URL = f"{PLATFORM}/capp/applicationstatus/query"
APP_JOBS_URL = f"{PLATFORM}/capp/jobs/query"
APP_EVENTS_URL = f"{PLATFORM}/capp/events/query"
MAINT_STATUS_URL = f"{PLATFORM}/platform/maintenance/status"
MAINT_SET_URL = f"{PLATFORM}/platform/maintenance/set"
UPGRADE_URL = f"{PLATFORM}/upgrademanager"
BALANCER_URL = f"{PLATFORM}/platform/balancer/status"
CERTS_URL = f"{PLATFORM}/cert/summary/list"
CERT_EXPIRY_URL = f"{PLATFORM}/cert/renew/check-expiry"
SESSION_CONFIG_URL = f"{AAA}/sessionconfig"
SESSION_PERMS_URL = f"{AAA}/getSessionMgmtPermissions"
SESSIONS_URL = f"{AAA}/activeSessions"
USER_URL = f"{AAA}/user"
ROLES_URL = f"{AAA}/role"
USERTASK_URL = f"{AAA}/usertask"
ROLE_ACCESS_URL = f"{AAA}/roleAccess"
USER_PERMISSION_URL = f"{AAA}/userpermission"
PASSWORD_POLICY_URL = f"{AAA}/passwordPolicyConfig"
SECURED_APIS_URL = f"{AAA_V2}/api"

NODE_ID = "192.0.2.21"

# --- fixtures (verified envelopes) -------------------------------------------

VERSION = {
    "result": "R_SUCCESS",
    "description": "",
    "result_map": {
        "BUILD": "7.2.0-1234",
        "CLUSTER_TYPE": "SINGLE",
        "OVA_BUILD": "7.2.0-ova-56",
        "PRODUCT": "CNC",
        "STATUS": "ACTIVE",
        "VERSION": "7.2.0",
    },
    "id": "capp-infra",
}


def health(obj_name: str, total: int, healthy: int, degraded: int = 0, down: int = 0) -> dict:
    state = "Healthy" if degraded == 0 and down == 0 else "Degraded"
    return {
        "state": state,
        "total": total,
        "healthy": healthy,
        "degraded": degraded,
        "down": down,
        "obj_name": obj_name,
        "availability": "Not protected",
    }


CLUSTER_SUMMARY = {
    "cluster_summary": {
        "health_summary": health("", 1, 1),
        "cluster_id": "day0-cluster",
        "crosswork_ip_model": "IPV4",
    }
}
INFRA_SUMMARY = {"name": "capp-infra", "health_summary": health("capp-infra", 37, 37)}
APP_HEALTH = {
    "app_health_summary": [
        {
            "health_summary": health("capp-infra", 37, 37),
            "recommendation": "None",
            "description": "",
        },
        {"health_summary": health("capp-coe", 12, 12), "recommendation": "None", "description": ""},
        {
            "health_summary": health("capp-cdg", 5, 4, degraded=1),
            "recommendation": "Restart the degraded pod",
            "description": "",
        },
    ]
}

RESOURCE = {
    "cpu_summary": {
        "current_usage": "30 %",
        "used": "2.40 cores",
        "total": "8.00 cores",
        "thresholds": {"medium_range_start": 60, "high_range_start": 90},
    },
    "memory_summary": {
        "current_usage": "45 %",
        "used": "42.13 GB",
        "total": "94.29 GB",
        "thresholds": {"medium_range_start": 60, "high_range_start": 90},
    },
    "disk_summary": {
        "current_usage": "12 %",
        "used": "110.20 GB",
        "total": "900.00 GB",
        "thresholds": {"medium_range_start": 60, "high_range_start": 90},
    },
    "node_cpu_summary": {
        "current_usage": "35 %",
        "used": "2.80 cores",
        "total": "8.00 cores",
        "thresholds": {"medium_range_start": 98, "high_range_start": 99},
    },
    "node_mem_summary": {
        "current_usage": "50 %",
        "used": "47.00 GB",
        "total": "94.29 GB",
        "thresholds": {"medium_range_start": 98, "high_range_start": 99},
    },
    "last_updated_time": "Sat Sep 13 12:00:00 UTC 2026",
}
NODE = {
    "node_name": "192-0-2-21-hybrid.cw.cisco",
    "node_id": NODE_ID,
    "node_health": "Healthy",
    "node_type": "HYBRID",
    "vm_name": "cnc-single",
    "node_resource": RESOURCE,
    "actions": {
        "cancelJob": False,
        "deployVM": False,
        "eraseVM": False,
        "retry": False,
        "viewDetails": True,
    },
    "vm_state": "Running",
    "vm_id": "vm-1",
    "availability": "Not protected",
    "vm_os_version": "Ubuntu 22.04",
}
NODE_SUMMARY = {"node_summary": [NODE]}

ACTIONS = {
    "actions": [
        {"action_name": "Restart", "action_id": "RESTART"},
        {"action_name": "Request All", "action_id": "REQUEST ALL"},
        {"action_name": "Request Logs", "action_id": "REQUEST LOGS"},
        {"action_name": "Request Metrics", "action_id": "REQUEST METRICS"},
    ]
}
MS_HEALTHY = {
    "Name": "robot-topo-svc",
    "health_state": "Healthy",
    "up_time": "207d 11h 30m 10s",
    "recommendation": "None",
    "description": "",
    "is_dynamic": False,
    "micro_service_action": ACTIONS,
    "Version": "7.2.0",
    "version_history": [],
}
MS_DEGRADED = {
    **MS_HEALTHY,
    "Name": "cw-data-retention-service",
    "health_state": "Degraded",
    "up_time": "0d 0h 2m 5s",
    "recommendation": "Restart the microservice",
    "Version": "7.2.0-prerelease.20",
}
NODE_DETAILS = {
    "node_name": NODE["node_name"],
    "node_id": NODE_ID,
    "node_parameters": {
        "status": "Healthy",
        "availability": "Not protected",
        "type": "HYBRID",
        "size_profile": {"cpu": "Large", "memory": "Large", "disk": "Large"},
        "host": "esx-1",
        "data_store": "datastore1",
        "management_ip": f"{NODE_ID}/18",
        "data_ip": "198.18.1.221",
        "management_ip_v4": NODE_ID,
        "data_ip_v4": "198.18.1.221",
        "management_ip_v6": "",
        "data_ip_v6": "",
    },
    "node_resource": RESOURCE,
    "node_recommendation": {"recommendation": "None"},
    "micro_service_list": {"micro_service": [MS_HEALTHY, MS_DEGRADED]},
    "vm_name": "cnc-single",
    "vm_id": "vm-1",
    "vm_state": "Running",
}
NODE_ID_EMPTY_500 = httpx.Response(500, json={"error": "nodeId is empty", "code": 2})


def capp_result(page_token: str = "") -> dict:
    """The capp/* envelope: ``result`` verified live, ``query_options.pagination``
    in the documented shape (an empty page_token = last page)."""
    return {
        "query_options": {"pagination": {"page_token": page_token, "page_size": 100}},
        "result": {"request_result": "ACCEPTED"},
    }


def page_body(page_token: str = "") -> dict:
    """The documented capp/* paging request the tools must send."""
    return {"query_options": {"pagination": {"page_token": page_token, "page_size": 100}}}


CAPP_RESULT = capp_result()
INSTALLED_IDS = {
    "installed_application_ids": {"application_ids": ["capp-infra", "capp-coe"]},
    **CAPP_RESULT,
}
APP_STATUS = {
    "application_states": [
        {
            "application_id": "capp-coe",
            "version": "7.2.0",
            "install_id": "inst-coe",
            "status": "ACTIVE",
            "progress": 100,
            "possible_actions": ["DEACTIVATE", "VIEW_APPLICATION_DETAILS"],
            "available_updates": [],
            "pending_action": {"action": "UNKNOWN_ACTION", "job_id": ""},
            "last_operation_error": {"message": ""},
        },
        {
            "application_id": "capp-cdg",
            "version": "7.2.0",
            "install_id": "inst-cdg",
            "status": "ACTIVATING",
            "progress": 40,
            "possible_actions": [],
            "available_updates": [],
            "pending_action": {"action": "ACTIVATE", "job_id": "AJ42"},
            "last_operation_error": {"message": "previous activation timed out"},
        },
    ],
    **CAPP_RESULT,
}


def app_job(job_id: str, start: str, status: str, error: str = "") -> dict:
    return {
        "job": {
            "job_id": job_id,
            "job_user": "admin",
            "start_time": start,
            "completion_time": str(int(start) + 60_000),
            "progress": 100,
            "job_status": status,
            "job_type": {"job_type": "ACTIVATE"},
            "error": {"message": error},
            "owner_type": "OWNER_USER",
            "description": f"Activate capp-coe ({job_id})",
        }
    }


# Oldest first on purpose: the tool must order newest first by start_time.
APP_JOBS = {
    "jobs": [
        app_job("AJ39", "1757500000000", "JOB_COMPLETED"),
        app_job("AJ41", "1757700000000", "JOB_FAILED", error="activation timed out"),
        app_job("AJ40", "1757600000000", "JOB_COMPLETED"),
    ],
    **CAPP_RESULT,
}
APP_EVENTS = {
    "events": [
        {
            "event_tags": [{"tag_type": "JOB_ID_EVENT", "tag_value": "AJ40"}],
            "message": "Application activated successfully.",
            "event_time": "1757600050000",
        },
        {
            "event_tags": [
                {"tag_type": "JOB_ID_EVENT", "tag_value": "AJ41"},
                {"tag_type": "APPLICATION_ID_EVENT", "tag_value": "capp-coe"},
            ],
            "message": "Activation timed out.",
            "event_time": "1757700050000",
        },
    ],
    **CAPP_RESULT,
}

MAINT_STATUS_OFF = {
    "message": "",
    "status": "Maintenance_Mode_Off",
    "lastUpdated": "2026-09-13T10:00:00Z",
}
MAINT_STATUS_ON = {
    "message": "Maintenance mode is on",
    "status": "Maintenance_Mode_On",
    "lastUpdated": "2026-09-13T12:00:00Z",
}
UPGRADE = {"message": "Upgrade manager has stopped the upgrade process.", "action": "None"}
BALANCER = {"Status": "Off", "NumberOfTasks": 0, "Tasks": [], "Timeout": ""}
MAINT_SET_OK = {
    "message": "Processing maintenance mode request",
    "requestStatus": "Maintenance_Mode_Request_Status_Success",
    "modeStatus": "Maintenance_Mode_On",
}
MAINT_SET_FAILED = {
    "message": "Backup in progress",
    "requestStatus": "Maintenance_Mode_Request_Status_Failed",
    "modeStatus": "Maintenance_Mode_Off",
}


def cert(name: str, role: str, expires: str, display: str = "READONLY") -> dict:
    return {
        "cert_name": name,
        "expiration_date": expires,
        "last_updated_by": "Crosswork",
        "last_update_time": "Fri, 21 Feb 2026 23:47:42 UTC",
        "assoc_summary": {"role_name": role, "magnetic_role_name": role.lower()},
        "cert_display": display,
        "role_name": role,
        "magnetic_role_name": role.lower(),
        "auth_type": "MUTUAL_AUTH",
    }


# Later expiry first on purpose: the tool must sort soonest expiry first.
CERTS = {
    "cert_summary": [
        cert(
            "Crosswork-Device-Syslog",
            "Device Syslog Communication",
            "Sun, 16 Feb 2031 23:47:42 UTC",
        ),
        cert(
            "Crosswork-Web-Cert",
            "Crosswork Web Server",
            "Tue, 09 Oct 2029 09:04:02 UTC",
            "READWRITE",
        ),
        cert("Crosswork-Odd-Date", "Odd", "not a date"),
    ]
}
EXPIRY_OK = {
    "cert_renewal_required": False,
    "message": "",
    "certificate_name": "",
    "remaining_days": "0",
}
EXPIRY_REQUIRED = {
    "cert_renewal_required": True,
    "message": "Internal certificate expires soon",
    "certificate_name": "Crosswork-Internal-Communication",
    "remaining_days": "10",
}

BANNER = {
    "ShowMessage": True,
    "UserAck": False,
    "Message": "Welcome to Cisco Crosswork.",
    "Icon": "BANNER_ICON_INFO",
    "Title": "Crosswork Legal Disclaimer",
}
BANNER_AFTER = {**BANNER, "Message": "Authorised use only.", "UserAck": True}
ACTION_OK = {"resp_value": "R_SUCCESS", "resp_error": "", "description": ""}
ACTION_NOOP = {"resp_value": "R_NOOP", "resp_error": "", "description": "already set"}
ACTION_FAILED = {"resp_value": "R_FAILURE", "resp_error": "microservice not found"}

SESSION_CONFIG = {
    "IdleSessionTimeout": 480,
    "NumParallelSessions": 200,
    "FallbackType": "FB_ON_NORESP_AUTH_FAILURE",
    "NumParallelSessionsPerUser": 50,
    "enableDAG": True,
}
SESSION_PERMS = {"ListAllowedForUser": True, "TerminateAllowedForUser": False}


def session(user: str, tgt: str, ip: str) -> dict:
    return {
        "UserName": user,
        "LoginTime": "2026-09-13T10:00:00Z",
        "LoginMethod": "Local",
        "TgtId": tgt,
        "ClientIp": ip,
    }


SESSIONS = [
    session("admin", "TGT-1-abcdefghijklmnopqrstuvwxyz-cas", "198.18.133.10"),
    session("mcp-admin", "TGT-2-abcdefghijklmnopqrstuvwxyz-cas", NODE_ID),
    session("Admin", "TGT-3-abcdefghijklmnopqrstuvwxyz-cas", "198.18.133.11"),
]

USER = {
    "Username": "admin",
    "Password": "",
    "PolicyId": "admin",
    "FirstName": "Site",
    "LastName": "Admin",
    "Status": "Active",
    "DeviceAccessGroups": [{"Uuid": "u-1", "DomainName": "ALL-ACCESS"}],
}
INVALID_USERNAME_500 = httpx.Response(500, json={"error": "Invalid Username", "code": 500})


def grant(api_id: str, name: str) -> dict:
    return {
        "api_name": name,
        "api_id": api_id,
        "versions": ["v1"],
        "allowed_urls": [{"url": f"/crosswork/{api_id}", "methods": ["GET", "POST"]}],
    }


ROLES = {
    "admin": {
        "name": "admin",
        "org_id": "1",
        "rate": 1000,
        "per": 1,
        "quota_max": -1,
        "active": True,
        "is_inactive": False,
        "tags": [],
        "access_rights": {
            "api-1": grant("api-1", "Topology"),
            "api-2": grant("api-2", "Inventory"),
        },
    },
    "read-only": {
        "name": "read-only",
        "org_id": "1",
        "rate": 100,
        "per": 1,
        "quota_max": -1,
        "active": False,
        "is_inactive": True,
        "tags": [],
        "access_rights": {"api-1": grant("api-1", "Topology")},
    },
}
USERTASK = [
    {
        "id": "audit_logs",
        "name": "Audit Logs",
        "items": [
            {
                "id": "view_audit_logs",
                "name": "View Audit Logs",
                "enabled": True,
                "permission": "view_audit_logs",
            },
            {
                "id": "export_audit_logs",
                "name": "Export Audit Logs",
                "description": "Export the audit log",
                "enabled": False,
                "permission": "export_audit_logs",
            },
        ],
    },
    {
        "id": "coe",
        "name": "Optimization Engine",
        "items": [{"id": "coe_config", "name": "Configure", "enabled": True}],
    },
]
ROLE_ACCESS = {"PolicyId": "admin", "GuiAccess": True, "ApiAccess": False, "PolicyData": ""}
PERMISSIONS = ["dag_management", "bwod_config", "csm_config"]
PASSWORD_POLICY = {
    "MinPasswordLength": 8,
    "NoUsername": True,
    "NoCiscoVariant": True,
    "NoCharRepetition": False,
    "NumChangedCharsEnable": False,
    "NumChangedChars": 1,
    "NumReuseLimitEnable": True,
    "NumReuseLimit": 5,
    "PasswordReuseDaysEnable": False,
    "PasswordReuseDays": 15,
    "FailedLoginsBefLoEnable": True,
    "FailedLoginsBeforeLockout": 5,
    "LockOutUserTimeEnable": False,
    "LockOutUserTime": 6,
    "PasswordExpiryDaysEnable": False,
    "PasswordExpiryDays": 60,
    "DaysForWarningEnable": False,
    "DaysForWarning": 15,
    "ChangePasswdOnFirstLogin": True,
}
SECURED_APIS = {
    "Topology": [{"api_id": "api-1", "name": "Topology NBI"}],
    "Device Management": [
        {"api_id": "api-2", "name": "Inventory"},
        {"api_id": "api-3", "name": "Credentials"},
    ],
}

NATS_500 = httpx.Response(500, json={"error": "NATS request failed"})
FORBIDDEN_403 = httpx.Response(403, json={"error": "forbidden"})


def build(settings: Settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    admin.register(mcp, ctx)
    return mcp


def sent(route: respx.Route, index: int = 0) -> dict:
    return json.loads(route.calls[index].request.content)


def sent_bodies(route: respx.Route) -> list[dict]:
    return [json.loads(c.request.content) for c in route.calls]


def no_body(route: respx.Route, index: int = 0) -> bool:
    return route.calls[index].request.content == b""


READ_TOOLS = {
    "cnc_get_platform_version",
    "cnc_get_cluster_health",
    "cnc_list_cluster_nodes",
    "cnc_get_cluster_node",
    "cnc_list_microservices",
    "cnc_list_application_status",
    "cnc_list_app_manager_jobs",
    "cnc_list_app_manager_events",
    "cnc_get_maintenance_status",
    "cnc_list_certificates",
    "cnc_check_certificate_expiry",
    "cnc_get_login_banner",
    "cnc_get_session_config",
    "cnc_list_active_sessions",
    "cnc_get_user",
    "cnc_list_roles",
    "cnc_get_role_tasks",
    "cnc_get_role_permissions",
    "cnc_get_password_policy",
    "cnc_list_secured_apis",
}
WRITE_TOOLS = {"cnc_set_login_banner", "cnc_set_maintenance_mode", "cnc_restart_microservice"}


# --- registration / gating ---------------------------------------------------


async def test_write_tools_hidden_unless_enabled(make_settings):
    names = {t.name for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert names == READ_TOOLS
    names = {t.name for t in await build(make_settings(enable_writes=True)).list_tools()}
    assert names == READ_TOOLS | WRITE_TOOLS


async def test_admin_tool_names_do_not_collide_with_other_modules(make_settings):
    """Every registry module plus admin on separate servers: the name sets must be
    pairwise disjoint (MCPServer only warns on a duplicate, so a collision with
    platform.py's user/application tools would otherwise go unnoticed)."""
    settings = make_settings(enable_writes=True)
    modules = list(ALL_MODULES) + ([] if admin in ALL_MODULES else [admin])
    seen: dict[str, str] = {}
    for module in modules:
        mcp = MCPServer("test")
        ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
        module.register(mcp, ctx)
        for tool in await mcp.list_tools():
            assert tool.name not in seen, f"{tool.name} in both {seen[tool.name]} and {module}"
            seen[tool.name] = module.__name__
    assert READ_TOOLS | WRITE_TOOLS <= set(seen)


async def test_annotations(make_settings):
    tools = {t.name: t for t in await build(make_settings(enable_writes=True)).list_tools()}
    for name in READ_TOOLS:
        assert tools[name].annotations.read_only_hint is True, name
        assert tools[name].annotations.destructive_hint is False, name
        assert tools[name].annotations.idempotent_hint is True, name
    banner = tools["cnc_set_login_banner"].annotations
    assert banner.read_only_hint is False and banner.destructive_hint is False
    assert banner.idempotent_hint is True
    maintenance = tools["cnc_set_maintenance_mode"].annotations
    assert maintenance.read_only_hint is False and maintenance.destructive_hint is True
    restart = tools["cnc_restart_microservice"].annotations
    assert restart.read_only_hint is False and restart.destructive_hint is True
    assert restart.idempotent_hint is False


# --- cnc_get_platform_version ------------------------------------------------


@respx.mock
async def test_get_platform_version(settings):
    route = respx.get(VERSION_URL).mock(return_value=httpx.Response(200, json=VERSION))
    text = await call_tool_text(build(settings), "cnc_get_platform_version", {})
    assert no_body(route)
    assert text.startswith(
        "Crosswork CNC 7.2.0 (build 7.2.0-1234, OVA 7.2.0-ova-56), "
        "cluster type SINGLE, status ACTIVE"
    )
    assert json.loads(text.split("\n\n", 1)[1]) == VERSION["result_map"]


@respx.mock
async def test_get_platform_version_failure_result_is_error(settings):
    respx.get(VERSION_URL).mock(
        return_value=httpx.Response(
            200, json={"result": "R_FAILURE", "description": "infra not ready", "result_map": {}}
        )
    )
    text = await call_tool_text(build(settings), "cnc_get_platform_version", {})
    assert text.startswith("Error:") and "R_FAILURE" in text and "infra not ready" in text


@respx.mock
async def test_get_platform_version_api_error_is_string(make_settings):
    respx.get(VERSION_URL).mock(return_value=NATS_500)
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_get_platform_version", {})
    assert text.startswith("Error:") and "500" in text


# --- cnc_get_cluster_health --------------------------------------------------


@respx.mock
async def test_get_cluster_health_flags_degraded_apps_first(settings):
    summary = respx.get(CLUSTER_SUMMARY_URL).mock(
        return_value=httpx.Response(200, json=CLUSTER_SUMMARY)
    )
    infra = respx.get(INFRA_SUMMARY_URL).mock(return_value=httpx.Response(200, json=INFRA_SUMMARY))
    apps = respx.get(APP_HEALTH_URL).mock(return_value=httpx.Response(200, json=APP_HEALTH))
    text = await call_tool_text(build(settings), "cnc_get_cluster_health", {})
    assert summary.call_count == 1 and infra.call_count == 1 and apps.call_count == 1
    assert no_body(summary) and no_body(infra) and no_body(apps)
    markdown, payload = text.split("\n\n{", 1)
    data = json.loads("{" + payload)
    assert "# Cluster health: Healthy (cluster day0-cluster, IP model IPV4" in markdown
    assert "Infrastructure (capp-infra): Healthy — 37/37 healthy, 0 degraded, 0 down" in markdown
    assert "Needs attention (1): capp-cdg" in markdown
    assert "| capp-cdg | Degraded | 4/5 | 1 | 0 | Restart the degraded pod |" in markdown
    assert markdown.index("| capp-cdg |") < markdown.index("| capp-coe |")
    assert data["cluster_id"] == "day0-cluster" and data["state"] == "Healthy"
    assert data["ip_model"] == "IPV4" and data["infra"] == INFRA_SUMMARY["health_summary"]
    assert [a["app"] for a in data["applications"]] == ["capp-cdg", "capp-coe", "capp-infra"]
    assert data["applications"][0] == {
        "app": "capp-cdg",
        "state": "Degraded",
        "healthy": 4,
        "total": 5,
        "degraded": 1,
        "down": 0,
        "recommendation": "Restart the degraded pod",
    }


@respx.mock
async def test_get_cluster_health_all_healthy(settings):
    respx.get(CLUSTER_SUMMARY_URL).mock(return_value=httpx.Response(200, json=CLUSTER_SUMMARY))
    respx.get(INFRA_SUMMARY_URL).mock(return_value=httpx.Response(200, json=INFRA_SUMMARY))
    respx.get(APP_HEALTH_URL).mock(
        return_value=httpx.Response(
            200, json={"app_health_summary": APP_HEALTH["app_health_summary"][:2]}
        )
    )
    text = await call_tool_text(build(settings), "cnc_get_cluster_health", {})
    assert "All 2 applications are healthy." in text and "Needs attention" not in text


@respx.mock
async def test_get_cluster_health_flags_app_by_state_alone(settings):
    """An app whose counts are all zero-degraded/zero-down but whose state is not
    Healthy (Unknown/NA while starting) is still flagged and sorted first."""
    unknown = {
        "health_summary": {**health("capp-cat", 3, 3), "state": "Unknown"},
        "recommendation": "None",
        "description": "",
    }
    respx.get(CLUSTER_SUMMARY_URL).mock(return_value=httpx.Response(200, json=CLUSTER_SUMMARY))
    respx.get(INFRA_SUMMARY_URL).mock(return_value=httpx.Response(200, json=INFRA_SUMMARY))
    respx.get(APP_HEALTH_URL).mock(
        return_value=httpx.Response(
            200, json={"app_health_summary": [*APP_HEALTH["app_health_summary"][:2], unknown]}
        )
    )
    text = await call_tool_text(build(settings), "cnc_get_cluster_health", {})
    assert "Needs attention (1): capp-cat" in text
    assert "| capp-cat | Unknown | 3/3 | 0 | 0 | None |" in text
    assert text.index("| capp-cat |") < text.index("| capp-coe |")


@respx.mock
async def test_get_cluster_health_empty_summary_is_not_error(settings):
    """cluster/summary/list answering {} (no cluster_summary) renders '?' fields."""
    respx.get(CLUSTER_SUMMARY_URL).mock(return_value=httpx.Response(200, json={}))
    respx.get(INFRA_SUMMARY_URL).mock(return_value=httpx.Response(200, json=INFRA_SUMMARY))
    respx.get(APP_HEALTH_URL).mock(return_value=httpx.Response(200, json=APP_HEALTH))
    text = await call_tool_text(build(settings), "cnc_get_cluster_health", {})
    assert not text.startswith("Error:")
    assert "# Cluster health: ? (cluster ?, IP model ?, availability ?)" in text
    data = json.loads("{" + text.split("\n\n{", 1)[1])
    assert data["cluster_id"] is None and data["state"] is None
    assert data["infra"] == INFRA_SUMMARY["health_summary"]
    assert len(data["applications"]) == 3


@respx.mock
async def test_get_cluster_health_api_error_is_string(make_settings):
    respx.get(CLUSTER_SUMMARY_URL).mock(return_value=httpx.Response(200, json=CLUSTER_SUMMARY))
    respx.get(INFRA_SUMMARY_URL).mock(return_value=httpx.Response(200, json=INFRA_SUMMARY))
    respx.get(APP_HEALTH_URL).mock(return_value=NATS_500)
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_get_cluster_health", {})
    assert text.startswith("Error:") and "500" in text


# --- cnc_list_cluster_nodes --------------------------------------------------


@respx.mock
async def test_list_cluster_nodes_markdown(settings):
    route = respx.get(NODE_SUMMARY_URL).mock(return_value=httpx.Response(200, json=NODE_SUMMARY))
    text = await call_tool_text(build(settings), "cnc_list_cluster_nodes", {})
    assert no_body(route)
    assert "# Cluster nodes (1)" in text
    assert f"**192-0-2-21-hybrid.cw.cisco** (node_id {NODE_ID})" in text
    assert "health=Healthy type=HYBRID vm=Running" in text
    assert "cpu=30 % (2.40 cores of 8.00 cores)" in text
    assert "memory=45 % (42.13 GB of 94.29 GB) disk=12 % (110.20 GB of 900.00 GB)" in text
    assert "os=Ubuntu 22.04" in text


@respx.mock
async def test_list_cluster_nodes_json_and_empty(settings):
    respx.get(NODE_SUMMARY_URL).mock(return_value=httpx.Response(200, json=NODE_SUMMARY))
    text = await call_tool_text(
        build(settings), "cnc_list_cluster_nodes", {"response_format": "json"}
    )
    assert json.loads(text) == {"count": 1, "items": [NODE]}
    respx.get(NODE_SUMMARY_URL).mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(build(settings), "cnc_list_cluster_nodes", {})
    assert "No nodes returned" in text and not text.startswith("Error:")


@respx.mock
async def test_list_cluster_nodes_api_error_is_string(make_settings):
    respx.get(NODE_SUMMARY_URL).mock(return_value=FORBIDDEN_403)
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_list_cluster_nodes", {})
    assert text.startswith("Error:") and "403" in text


# --- cnc_get_cluster_node ----------------------------------------------------


@respx.mock
async def test_get_cluster_node_markdown_and_body(settings):
    route = respx.post(NODE_DETAILS_URL).mock(return_value=httpx.Response(200, json=NODE_DETAILS))
    text = await call_tool_text(build(settings), "cnc_get_cluster_node", {"node_id": NODE_ID})
    assert sent(route) == {"node_id": NODE_ID}
    assert f"# Node 192-0-2-21-hybrid.cw.cisco ({NODE_ID})" in text
    assert f"management_ip {NODE_ID}/18, data_ip 198.18.1.221" in text
    assert (
        "size profile cpu=Large memory=Large disk=Large; host esx-1, datastore datastore1" in text
    )
    assert "cpu 30 % (2.40 cores of 8.00 cores)" in text
    assert "recommendation: None" in text
    assert "microservices: 2 (1 not Healthy)" in text
    assert "**cw-data-retention-service** app=- health=Degraded up=0d 0h 2m 5s" in text
    assert "recommendation: Restart the microservice" in text
    assert "robot-topo-svc" not in text  # healthy pods are counted, not listed


@respx.mock
async def test_get_cluster_node_json_is_raw(settings):
    respx.post(NODE_DETAILS_URL).mock(return_value=httpx.Response(200, json=NODE_DETAILS))
    text = await call_tool_text(
        build(settings), "cnc_get_cluster_node", {"node_id": NODE_ID, "response_format": "json"}
    )
    assert json.loads(text) == NODE_DETAILS


@respx.mock
async def test_get_cluster_node_blank_id_is_error_without_request(settings):
    route = respx.post(NODE_DETAILS_URL).mock(return_value=httpx.Response(200, json=NODE_DETAILS))
    text = await call_tool_text(build(settings), "cnc_get_cluster_node", {"node_id": "   "})
    assert text.startswith("Error:") and "node_id is empty" in text
    assert route.call_count == 0


@respx.mock
async def test_get_cluster_node_unexpected_platform_500_is_rendered_with_message(make_settings):
    """A 500 the tool does not special-case (here the platform's own 'nodeId is
    empty' spelling, which a non-blank node_id cannot really trigger) passes
    through with its message so the agent sees what the platform said."""
    respx.post(NODE_DETAILS_URL).mock(return_value=NODE_ID_EMPTY_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_cluster_node", {"node_id": "10.0.0.9"}
    )
    assert text.startswith("Error:") and "500" in text and "Platform said: nodeId is empty" in text


# --- cnc_list_microservices --------------------------------------------------


@respx.mock
async def test_list_microservices_by_app_sends_req_id(settings):
    route = respx.post(MICROSERVICES_URL).mock(
        return_value=httpx.Response(200, json={"micro_service": [MS_HEALTHY, MS_DEGRADED]})
    )
    text = await call_tool_text(build(settings), "cnc_list_microservices", {"app_id": "capp-coe"})
    assert sent(route) == {"req_id": "capp-coe"}
    assert "# Microservices (2; application capp-coe)" in text
    assert (
        "**robot-topo-svc** app=capp-coe health=Healthy up=207d 11h 30m 10s version=7.2.0" in text
    )
    assert "— recommendation" not in text.split("\n")[2]  # "None" is not rendered
    assert (
        "**cw-data-retention-service** app=capp-coe health=Degraded up=0d 0h 2m 5s "
        "version=7.2.0-prerelease.20 — recommendation: Restart the microservice"
    ) in text


@respx.mock
async def test_list_microservices_empty_answer_is_not_error(settings):
    respx.post(MICROSERVICES_URL).mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(build(settings), "cnc_list_microservices", {"app_id": "capp-x"})
    assert "No microservices for application capp-x" in text and not text.startswith("Error:")


@respx.mock
async def test_list_microservices_health_filter_is_case_insensitive(settings):
    respx.post(MICROSERVICES_URL).mock(
        return_value=httpx.Response(200, json={"micro_service": [MS_HEALTHY, MS_DEGRADED]})
    )
    text = await call_tool_text(
        build(settings),
        "cnc_list_microservices",
        {"app_id": "capp-coe", "health": "DEGRADED", "response_format": "json"},
    )
    data = json.loads(text)
    assert data["count"] == 1
    assert data["items"] == [{"app": "capp-coe", **MS_DEGRADED}]


@respx.mock
async def test_list_microservices_unknown_health_is_error_without_request(settings):
    route = respx.post(MICROSERVICES_URL).mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(
        build(settings), "cnc_list_microservices", {"app_id": "capp-coe", "health": "sick"}
    )
    assert text.startswith("Error:") and "Unknown health 'sick'" in text
    assert route.call_count == 0


@respx.mock
async def test_list_microservices_by_node_uses_node_details(settings):
    route = respx.post(NODE_DETAILS_URL).mock(return_value=httpx.Response(200, json=NODE_DETAILS))
    text = await call_tool_text(build(settings), "cnc_list_microservices", {"node_id": NODE_ID})
    assert sent(route) == {"node_id": NODE_ID}
    assert f"# Microservices (2; node {NODE_ID})" in text
    assert "**robot-topo-svc** app=- health=Healthy" in text


@respx.mock
async def test_list_microservices_all_apps_fans_out(settings):
    ids = respx.post(INSTALLED_IDS_URL).mock(return_value=httpx.Response(200, json=INSTALLED_IDS))
    ms = respx.post(MICROSERVICES_URL).mock(
        side_effect=[
            httpx.Response(200, json={"micro_service": [MS_HEALTHY]}),
            httpx.Response(200, json={"micro_service": [MS_DEGRADED]}),
        ]
    )
    text = await call_tool_text(
        build(settings), "cnc_list_microservices", {"response_format": "json"}
    )
    assert sent(ids) == {}
    assert sorted(b["req_id"] for b in sent_bodies(ms)) == ["capp-coe", "capp-infra"]
    data = json.loads(text)
    assert data["count"] == 2
    assert {(r["app"], r["Name"]) for r in data["items"]} == {
        ("capp-infra", "robot-topo-svc"),
        ("capp-coe", "cw-data-retention-service"),
    }


def _pods(n: int) -> list[dict]:
    return [{**MS_HEALTHY, "Name": f"pod-{i:03d}"} for i in range(n)]


@respx.mock
async def test_list_microservices_pages_client_side(settings):
    """page_size/page cut a window out of the fetched list; the envelope and the
    markdown hint say how to continue, and a page past the end is not an error."""
    respx.post(MICROSERVICES_URL).mock(
        return_value=httpx.Response(200, json={"micro_service": _pods(5)})
    )
    text = await call_tool_text(
        build(settings),
        "cnc_list_microservices",
        {"app_id": "capp-coe", "page_size": 2, "page": 1, "response_format": "json"},
    )
    data = json.loads(text)
    assert data["total"] == 5 and data["count"] == 2 and data["collection_total"] == 5
    assert data["page"] == 1 and data["page_size"] == 2
    assert data["has_more"] is True and data["next_page"] == 2
    assert [r["Name"] for r in data["items"]] == ["pod-002", "pod-003"]

    text = await call_tool_text(
        build(settings), "cnc_list_microservices", {"app_id": "capp-coe", "page_size": 2}
    )
    assert "# Microservices (2 shown of 5, page 0; application capp-coe)" in text
    assert "pod-000" in text and "pod-001" in text and "pod-002" not in text
    assert text.rstrip().endswith("More available: repeat with page=1.")

    text = await call_tool_text(
        build(settings),
        "cnc_list_microservices",
        {"app_id": "capp-coe", "page_size": 2, "page": 2},
    )
    assert "# Microservices (1 shown of 5, page 2; application capp-coe)" in text
    assert "pod-004" in text and "More available" not in text

    text = await call_tool_text(
        build(settings),
        "cnc_list_microservices",
        {"app_id": "capp-coe", "page_size": 2, "page": 7},
    )
    assert not text.startswith("Error:")
    assert "Page 7 is past the end: 5 microservices for application capp-coe fill pages 0-2" in text


@respx.mock
async def test_list_microservices_health_filter_precedes_paging(settings):
    """total counts the filtered rows, collection_total what was fetched."""
    pods = _pods(3) + [{**MS_DEGRADED, "Name": f"bad-{i}"} for i in range(3)]
    respx.post(MICROSERVICES_URL).mock(
        return_value=httpx.Response(200, json={"micro_service": pods})
    )
    text = await call_tool_text(
        build(settings),
        "cnc_list_microservices",
        {"app_id": "capp-coe", "health": "degraded", "page_size": 2, "response_format": "json"},
    )
    data = json.loads(text)
    assert data["total"] == 3 and data["collection_total"] == 6 and data["count"] == 2
    assert [r["Name"] for r in data["items"]] == ["bad-0", "bad-1"]


@respx.mock
async def test_list_microservices_oversized_json_stays_parseable(make_settings):
    """A JSON page over the cap is cut to whole items with the tool's own hint —
    never the unparseable character cut, never a promise of limit/offset."""
    settings = make_settings(max_response_chars=4_000)
    respx.post(MICROSERVICES_URL).mock(
        return_value=httpx.Response(200, json={"micro_service": _pods(40)})
    )
    text = await call_tool_text(
        build(settings), "cnc_list_microservices", {"app_id": "capp-coe", "response_format": "json"}
    )
    assert len(text) <= 4_000
    data = json.loads(text)
    assert data["truncated"] is True and 1 <= data["shown"] < 40
    assert len(data["items"]) == data["shown"] and data["total"] == 40
    assert "Lower page_size" in data["truncation_note"] and "app_id" in data["truncation_note"]
    assert "limit/offset" not in text


@respx.mock
async def test_list_microservices_page_size_bounds(settings):
    """Schema-level: page_size 0 / 501 and a negative page are rejected before any request."""
    route = respx.post(MICROSERVICES_URL).mock(return_value=httpx.Response(200, json={}))
    for args, match in (
        ({"app_id": "capp-coe", "page_size": 0}, "page_size"),
        ({"app_id": "capp-coe", "page_size": 501}, "page_size"),
        ({"app_id": "capp-coe", "page": -1}, "page"),
    ):
        with pytest.raises(ToolError, match=match):
            await call_tool_text(build(settings), "cnc_list_microservices", args)
    assert route.call_count == 0


@respx.mock
async def test_list_microservices_rejects_both_selectors(settings):
    route = respx.post(MICROSERVICES_URL).mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(
        build(settings), "cnc_list_microservices", {"app_id": "capp-coe", "node_id": NODE_ID}
    )
    assert text.startswith("Error:") and "at most one" in text
    assert route.call_count == 0


@respx.mock
async def test_list_microservices_api_error_is_string(make_settings):
    respx.post(MICROSERVICES_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_list_microservices", {"app_id": "capp-coe"}
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_list_application_status --------------------------------------------


@respx.mock
async def test_list_application_status_markdown(settings):
    route = respx.post(APP_STATUS_URL).mock(return_value=httpx.Response(200, json=APP_STATUS))
    text = await call_tool_text(build(settings), "cnc_list_application_status", {})
    assert sent(route) == {}
    assert "# Application status (2)" in text
    assert (
        "**capp-coe** 7.2.0 ACTIVE (progress 100) — actions: DEACTIVATE, VIEW_APPLICATION_DETAILS"
        in text
    )
    assert "pending" not in text.split("**capp-coe**")[1].split("\n")[0]
    assert "**capp-cdg** 7.2.0 ACTIVATING (progress 40); pending: ACTIVATE (job AJ42)" in text
    assert "last error: previous activation timed out" in text


@respx.mock
async def test_list_application_status_json_and_rejected(settings):
    respx.post(APP_STATUS_URL).mock(return_value=httpx.Response(200, json=APP_STATUS))
    text = await call_tool_text(
        build(settings), "cnc_list_application_status", {"response_format": "json"}
    )
    data = json.loads(text)
    assert data["count"] == 2
    assert [a["application_id"] for a in data["items"]] == ["capp-cdg", "capp-coe"]
    respx.post(APP_STATUS_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "application_states": [],
                "result": {"request_result": "REJECTED", "error": {"message": "bad query"}},
            },
        )
    )
    text = await call_tool_text(build(settings), "cnc_list_application_status", {})
    assert text.startswith("Error:") and "REJECTED" in text and "bad query" in text


@respx.mock
async def test_list_application_status_api_error_is_string(make_settings):
    respx.post(APP_STATUS_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_list_application_status", {}
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_list_app_manager_jobs ----------------------------------------------


@respx.mock
async def test_list_app_manager_jobs_newest_first_with_limit(settings):
    route = respx.post(APP_JOBS_URL).mock(return_value=httpx.Response(200, json=APP_JOBS))
    text = await call_tool_text(
        build(settings), "cnc_list_app_manager_jobs", {"limit": 2, "response_format": "json"}
    )
    assert route.call_count == 1 and sent(route) == page_body()  # documented paging body
    data = json.loads(text)
    assert [j["job_id"] for j in data["items"]] == ["AJ41", "AJ40"]
    assert data["total"] == 3 and data["count"] == 2 and data["limit"] == 2
    assert data["has_more"] is True and data["more_on_server"] is False
    assert data["items"][0] == APP_JOBS["jobs"][1]["job"]


@respx.mock
async def test_list_app_manager_jobs_follows_page_token(settings):
    """A non-empty page_token is echoed back for the next page; the pages are
    merged before sorting, so a newer job on page two still comes first."""
    page1 = {"jobs": APP_JOBS["jobs"][:2], **capp_result(page_token="p2")}
    page2 = {
        "jobs": [APP_JOBS["jobs"][2], app_job("AJ42", "1757800000000", "JOB_IN_PROGRESS")],
        **capp_result(page_token=""),
    }
    route = respx.post(APP_JOBS_URL).mock(
        side_effect=[httpx.Response(200, json=page1), httpx.Response(200, json=page2)]
    )
    text = await call_tool_text(
        build(settings), "cnc_list_app_manager_jobs", {"response_format": "json"}
    )
    assert sent_bodies(route) == [page_body(""), page_body("p2")]
    data = json.loads(text)
    assert data["total"] == 4 and data["more_on_server"] is False
    assert [j["job_id"] for j in data["items"]] == ["AJ42", "AJ41", "AJ40", "AJ39"]
    assert "Warning" not in text


@respx.mock
async def test_list_app_manager_jobs_unchanged_token_stops(settings):
    """A server that echoes the token it was sent (collection/v1 does) must not
    loop: an unchanged token means no progress."""
    route = respx.post(APP_JOBS_URL).mock(
        return_value=httpx.Response(200, json={"jobs": APP_JOBS["jobs"], **capp_result("")})
    )
    await call_tool_text(build(settings), "cnc_list_app_manager_jobs", {})
    assert route.call_count == 1
    respx.post(APP_JOBS_URL).mock(
        side_effect=[
            httpx.Response(200, json={"jobs": APP_JOBS["jobs"], **capp_result("x")}),
            httpx.Response(200, json={"jobs": APP_JOBS["jobs"], **capp_result("x")}),
        ]
    )
    text = await call_tool_text(
        build(settings), "cnc_list_app_manager_jobs", {"response_format": "json"}
    )
    assert route.call_count == 3  # the echoed "x" was sent once, then the loop stopped
    assert json.loads(text)["total"] == 6 and json.loads(text)["more_on_server"] is False


@respx.mock
async def test_list_app_manager_jobs_page_cap_is_reported(settings):
    """When every page carries a fresh token the tool stops at CAPP_MAX_PAGES and
    says so instead of pretending the totals are complete."""
    calls: list[int] = []

    def endless(request: httpx.Request) -> httpx.Response:
        calls.append(len(calls))
        job = app_job(f"AJ{len(calls)}", str(1757000000000 + len(calls)), "JOB_COMPLETED")
        return httpx.Response(200, json={"jobs": [job], **capp_result(f"t{len(calls)}")})

    route = respx.post(APP_JOBS_URL).mock(side_effect=endless)
    text = await call_tool_text(build(settings), "cnc_list_app_manager_jobs", {"limit": 5})
    assert route.call_count == admin.CAPP_MAX_PAGES
    assert sent(route, 1) == page_body("t1")
    assert f"# Application manager jobs (5 of {admin.CAPP_MAX_PAGES}, newest first)" in text
    assert f"Warning: the platform still had more jobs after {admin.CAPP_MAX_PAGES} pages" in text
    text = await call_tool_text(
        build(settings), "cnc_list_app_manager_jobs", {"response_format": "json"}
    )
    assert json.loads(text)["more_on_server"] is True


@respx.mock
async def test_list_app_manager_jobs_markdown(settings):
    respx.post(APP_JOBS_URL).mock(return_value=httpx.Response(200, json=APP_JOBS))
    text = await call_tool_text(build(settings), "cnc_list_app_manager_jobs", {"limit": 2})
    assert "# Application manager jobs (2 of 3, newest first)" in text
    assert text.index("**AJ41**") < text.index("**AJ40**") and "**AJ39**" not in text
    assert (
        f"**AJ41** JOB_FAILED — ACTIVATE (progress 100, started {epoch_iso('1757700000000')}, "
        f"completed {epoch_iso('1757700060000')}, by admin): Activate capp-coe (AJ41)"
    ) in text
    assert "error: activation timed out" in text
    assert "1 older job(s) not shown; raise limit." in text


@respx.mock
async def test_list_app_manager_jobs_empty_and_error(make_settings):
    settings = make_settings(max_retries=0)
    respx.post(APP_JOBS_URL).mock(return_value=httpx.Response(200, json=CAPP_RESULT))
    text = await call_tool_text(build(settings), "cnc_list_app_manager_jobs", {})
    assert "No application manager jobs returned" in text and not text.startswith("Error:")
    respx.post(APP_JOBS_URL).mock(return_value=NATS_500)
    text = await call_tool_text(build(settings), "cnc_list_app_manager_jobs", {})
    assert text.startswith("Error:") and "500" in text


@respx.mock
async def test_list_app_manager_jobs_oversized_hint_says_lower_limit(make_settings):
    """Over the cap, both formats carry the tool's own advice ("Lower limit.")
    — never the generic hint, never a promise of limit/offset. JSON stays
    parseable (whole trailing items dropped); markdown gets the bracketed note."""
    settings = make_settings(max_response_chars=2_000)
    jobs = [app_job(f"AJ{i}", str(1757000000000 + i * 1000), "JOB_COMPLETED") for i in range(30)]
    respx.post(APP_JOBS_URL).mock(
        return_value=httpx.Response(200, json={"jobs": jobs, **CAPP_RESULT})
    )
    text = await call_tool_text(
        build(settings), "cnc_list_app_manager_jobs", {"response_format": "json"}
    )
    assert len(text) <= 2_000
    data = json.loads(text)
    assert data["truncated"] is True and 1 <= data["shown"] < 20
    assert len(data["items"]) == data["shown"] and data["total"] == 30 and data["count"] == 20
    assert data["truncation_note"].endswith("'items' entries were dropped. Lower limit.")
    assert TRUNCATION_HINT not in text and "limit/offset" not in text
    text = await call_tool_text(build(settings), "cnc_list_app_manager_jobs", {})
    assert text.endswith("[Truncated: response exceeded 2000 characters. Lower limit.]")
    assert TRUNCATION_HINT not in text and "limit/offset" not in text


# --- cnc_list_app_manager_events --------------------------------------------


@respx.mock
async def test_list_app_manager_events_newest_first(settings):
    route = respx.post(APP_EVENTS_URL).mock(return_value=httpx.Response(200, json=APP_EVENTS))
    text = await call_tool_text(build(settings), "cnc_list_app_manager_events", {"limit": 1})
    assert route.call_count == 1 and sent(route) == page_body()  # documented paging body
    assert "# Application manager events (1 of 2, newest first)" in text
    assert (
        f"- {epoch_iso('1757700050000')} Activation timed out. "
        "[JOB_ID_EVENT=AJ41, APPLICATION_ID_EVENT=capp-coe]"
    ) in text
    assert "AJ40" not in text
    assert "1 older event(s) not shown" in text


@respx.mock
async def test_list_app_manager_events_json_and_error(make_settings):
    settings = make_settings(max_retries=0)
    respx.post(APP_EVENTS_URL).mock(return_value=httpx.Response(200, json=APP_EVENTS))
    text = await call_tool_text(
        build(settings), "cnc_list_app_manager_events", {"response_format": "json"}
    )
    data = json.loads(text)
    assert data["total"] == 2 and data["has_more"] is False and data["more_on_server"] is False
    assert data["items"] == [APP_EVENTS["events"][1], APP_EVENTS["events"][0]]
    respx.post(APP_EVENTS_URL).mock(return_value=NATS_500)
    text = await call_tool_text(build(settings), "cnc_list_app_manager_events", {})
    assert text.startswith("Error:") and "500" in text


@respx.mock
async def test_list_app_manager_events_follows_page_token_and_caps(settings):
    newer = {
        "event_tags": [{"tag_type": "JOB_ID_EVENT", "tag_value": "AJ42"}],
        "message": "Activation started.",
        "event_time": "1757800050000",
    }
    route = respx.post(APP_EVENTS_URL).mock(
        side_effect=[
            httpx.Response(200, json={"events": APP_EVENTS["events"], **capp_result("next")}),
            httpx.Response(200, json={"events": [newer], **capp_result("")}),
        ]
    )
    text = await call_tool_text(
        build(settings), "cnc_list_app_manager_events", {"response_format": "json"}
    )
    assert sent_bodies(route) == [page_body(""), page_body("next")]
    data = json.loads(text)
    assert data["total"] == 3 and data["more_on_server"] is False
    assert data["items"][0] == newer  # newest across both pages first
    # Every page carrying a fresh token: stop at the cap and say so.
    fresh = itertools.count(1)
    respx.post(APP_EVENTS_URL).mock(
        side_effect=lambda request: httpx.Response(
            200, json={"events": [newer], **capp_result(f"t{next(fresh)}")}
        )
    )
    text = await call_tool_text(build(settings), "cnc_list_app_manager_events", {"limit": 1})
    assert route.call_count == 2 + admin.CAPP_MAX_PAGES
    assert f"# Application manager events (1 of {admin.CAPP_MAX_PAGES}, newest first)" in text
    assert f"Warning: the platform still had more events after {admin.CAPP_MAX_PAGES} pages" in text


@respx.mock
async def test_list_app_manager_events_oversized_hint_says_lower_limit(make_settings):
    """Same contract as the jobs tool: the tool's own "Lower limit." advice in
    the JSON truncation_note and in the markdown bracketed note."""
    settings = make_settings(max_response_chars=2_000)
    events = [
        {
            "event_tags": [{"tag_type": "JOB_ID_EVENT", "tag_value": f"AJ{i}"}],
            "message": f"Step {i} done.",
            "event_time": str(1757000000000 + i * 1000),
        }
        for i in range(60)
    ]
    respx.post(APP_EVENTS_URL).mock(
        return_value=httpx.Response(200, json={"events": events, **CAPP_RESULT})
    )
    text = await call_tool_text(
        build(settings), "cnc_list_app_manager_events", {"response_format": "json"}
    )
    assert len(text) <= 2_000
    data = json.loads(text)
    assert data["truncated"] is True and 1 <= data["shown"] < 50
    assert len(data["items"]) == data["shown"] and data["total"] == 60 and data["count"] == 50
    assert data["truncation_note"].endswith("'items' entries were dropped. Lower limit.")
    assert TRUNCATION_HINT not in text and "limit/offset" not in text
    text = await call_tool_text(build(settings), "cnc_list_app_manager_events", {})
    assert text.endswith("[Truncated: response exceeded 2000 characters. Lower limit.]")
    assert TRUNCATION_HINT not in text and "limit/offset" not in text


# --- cnc_get_maintenance_status ---------------------------------------------


@respx.mock
async def test_get_maintenance_status(settings):
    status = respx.get(MAINT_STATUS_URL).mock(
        return_value=httpx.Response(200, json=MAINT_STATUS_OFF)
    )
    upgrade = respx.get(UPGRADE_URL).mock(return_value=httpx.Response(200, json=UPGRADE))
    balancer = respx.get(BALANCER_URL).mock(return_value=httpx.Response(200, json=BALANCER))
    text = await call_tool_text(build(settings), "cnc_get_maintenance_status", {})
    assert no_body(status) and no_body(upgrade) and no_body(balancer)
    line, payload = text.split("\n\n", 1)
    assert line == (
        "Maintenance mode: Maintenance_Mode_Off (last updated 2026-09-13T10:00:00Z); "
        "upgrade action: None; balancer: Off (0 task(s))"
    )
    assert json.loads(payload) == {
        "maintenance_mode": "Maintenance_Mode_Off",
        "last_updated": "2026-09-13T10:00:00Z",
        "message": "",
        "upgrade_action": "None",
        "upgrade_message": UPGRADE["message"],
        "balancer": BALANCER,
    }


@respx.mock
async def test_get_maintenance_status_api_error_is_string(make_settings):
    respx.get(MAINT_STATUS_URL).mock(return_value=httpx.Response(200, json=MAINT_STATUS_OFF))
    respx.get(UPGRADE_URL).mock(return_value=NATS_500)
    respx.get(BALANCER_URL).mock(return_value=httpx.Response(200, json=BALANCER))
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_maintenance_status", {}
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_list_certificates ---------------------------------------------------


@respx.mock
async def test_list_certificates_sorted_by_expiry(settings):
    route = respx.get(CERTS_URL).mock(return_value=httpx.Response(200, json=CERTS))
    text = await call_tool_text(build(settings), "cnc_list_certificates", {})
    assert no_body(route)
    assert "# Certificates (3, soonest expiry first)" in text
    web = text.index("**Crosswork-Web-Cert**")
    syslog = text.index("**Crosswork-Device-Syslog**")
    odd = text.index("**Crosswork-Odd-Date**")
    assert web < syslog < odd
    assert (
        "**Crosswork-Web-Cert** role=Crosswork Web Server auth=MUTUAL_AUTH display=READWRITE "
        "expires Tue, 09 Oct 2029 09:04:02 UTC (updated Fri, 21 Feb 2026 23:47:42 UTC by Crosswork)"
    ) in text


@respx.mock
async def test_list_certificates_json_and_error(make_settings):
    settings = make_settings(max_retries=0)
    respx.get(CERTS_URL).mock(return_value=httpx.Response(200, json=CERTS))
    text = await call_tool_text(
        build(settings), "cnc_list_certificates", {"response_format": "json"}
    )
    data = json.loads(text)
    assert data["count"] == 3
    assert [c["cert_name"] for c in data["items"]] == [
        "Crosswork-Web-Cert",
        "Crosswork-Device-Syslog",
        "Crosswork-Odd-Date",
    ]
    assert data["items"][0] == CERTS["cert_summary"][1]
    respx.get(CERTS_URL).mock(return_value=FORBIDDEN_403)
    text = await call_tool_text(build(settings), "cnc_list_certificates", {})
    assert text.startswith("Error:") and "403" in text


# --- cnc_check_certificate_expiry -------------------------------------------


@respx.mock
async def test_check_certificate_expiry(make_settings):
    settings = make_settings(max_retries=0)
    route = respx.get(CERT_EXPIRY_URL).mock(return_value=httpx.Response(200, json=EXPIRY_OK))
    text = await call_tool_text(build(settings), "cnc_check_certificate_expiry", {})
    assert no_body(route)
    assert text.startswith("Certificate renewal is not required.")
    assert json.loads(text.split("\n\n", 1)[1]) == EXPIRY_OK
    respx.get(CERT_EXPIRY_URL).mock(return_value=httpx.Response(200, json=EXPIRY_REQUIRED))
    text = await call_tool_text(build(settings), "cnc_check_certificate_expiry", {})
    assert text.startswith(
        "Renewal REQUIRED: Internal certificate expires soon "
        "(Crosswork-Internal-Communication, 10 days)"
    )
    respx.get(CERT_EXPIRY_URL).mock(return_value=NATS_500)
    text = await call_tool_text(build(settings), "cnc_check_certificate_expiry", {})
    assert text.startswith("Error:") and "500" in text


# --- cnc_get_login_banner ----------------------------------------------------


@respx.mock
async def test_get_login_banner(make_settings):
    settings = make_settings(max_retries=0)
    route = respx.post(BANNER_GET_URL).mock(return_value=httpx.Response(200, json=BANNER))
    text = await call_tool_text(build(settings), "cnc_get_login_banner", {})
    assert sent(route) == {}
    assert "Title: Crosswork Legal Disclaimer" in text
    assert "Message: Welcome to Cisco Crosswork." in text
    assert "Shown at login: yes; acknowledgement required: no; icon: BANNER_ICON_INFO" in text
    assert json.loads(text.split("\n\n", 1)[1]) == BANNER
    respx.post(BANNER_GET_URL).mock(return_value=NATS_500)
    text = await call_tool_text(build(settings), "cnc_get_login_banner", {})
    assert text.startswith("Error:") and "500" in text


# --- cnc_get_session_config --------------------------------------------------


@respx.mock
async def test_get_session_config(settings):
    config = respx.get(SESSION_CONFIG_URL).mock(
        return_value=httpx.Response(200, json=SESSION_CONFIG)
    )
    perms = respx.get(SESSION_PERMS_URL).mock(return_value=httpx.Response(200, json=SESSION_PERMS))
    text = await call_tool_text(build(settings), "cnc_get_session_config", {})
    assert no_body(config) and no_body(perms)
    line, payload = text.split("\n\n", 1)
    assert line == (
        "Sessions: idle timeout 480 min, 50 parallel sessions per user (200 total), "
        "fallback FB_ON_NORESP_AUTH_FAILURE; this user may list sessions: yes, "
        "terminate sessions: no"
    )
    assert json.loads(payload) == {**SESSION_CONFIG, **SESSION_PERMS}


@respx.mock
async def test_get_session_config_renders_api_idle_timeout_when_present(settings):
    """Builds that report a separate API idle timeout (IdleSessionTimeoutAPI, 480
    min against a 30-min UI timeout in the notes) get it in the headline."""
    config = {**SESSION_CONFIG, "IdleSessionTimeout": 30, "IdleSessionTimeoutAPI": 480}
    respx.get(SESSION_CONFIG_URL).mock(return_value=httpx.Response(200, json=config))
    respx.get(SESSION_PERMS_URL).mock(return_value=httpx.Response(200, json=SESSION_PERMS))
    text = await call_tool_text(build(settings), "cnc_get_session_config", {})
    line, payload = text.split("\n\n", 1)
    assert line.startswith("Sessions: idle timeout 30 min (API sessions 480 min), 50 parallel")
    assert json.loads(payload)["IdleSessionTimeoutAPI"] == 480


@respx.mock
async def test_get_session_config_api_error_is_string(make_settings):
    respx.get(SESSION_CONFIG_URL).mock(return_value=httpx.Response(200, json=SESSION_CONFIG))
    respx.get(SESSION_PERMS_URL).mock(return_value=FORBIDDEN_403)
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_get_session_config", {})
    assert text.startswith("Error:") and "403" in text


# --- cnc_list_active_sessions ------------------------------------------------


@respx.mock
async def test_list_active_sessions_markdown_counts_and_short_tgt(settings):
    route = respx.get(SESSIONS_URL).mock(return_value=httpx.Response(200, json=SESSIONS))
    text = await call_tool_text(build(settings), "cnc_list_active_sessions", {})
    assert no_body(route)
    assert "# Active sessions (3: Admin 1, admin 1, mcp-admin 1)" in text
    assert (
        "- **admin** since 2026-09-13T10:00:00Z via Local from 198.18.133.10 (tgt TGT-1-abcdef…)"
    ) in text
    assert "TGT-1-abcdefghijklmnopqrstuvwxyz-cas" not in text
    assert "cannot be terminated through the API" in text


@respx.mock
async def test_list_active_sessions_username_filter_is_case_insensitive(settings):
    respx.get(SESSIONS_URL).mock(return_value=httpx.Response(200, json=SESSIONS))
    text = await call_tool_text(
        build(settings),
        "cnc_list_active_sessions",
        {"username": "ADMIN", "response_format": "json"},
    )
    data = json.loads(text)
    assert data["count"] == 2 and data["per_user"] == {"admin": 1, "Admin": 1}
    # The TGT is a credential: JSON carries the same shortened form as markdown.
    assert data["items"] == [
        {**SESSIONS[0], "TgtId": "TGT-1-abcdef…"},
        {**SESSIONS[2], "TgtId": "TGT-3-abcdef…"},
    ]
    assert "abcdefghijklmnopqrstuvwxyz" not in text
    text = await call_tool_text(build(settings), "cnc_list_active_sessions", {"username": "ghost"})
    assert "No active sessions for user 'ghost'" in text and not text.startswith("Error:")


@respx.mock
async def test_list_active_sessions_json_never_carries_a_whole_tgt(settings):
    """Unfiltered JSON — the path that used to copy the raw list through — masks
    every row, and a row without a TgtId is passed through untouched."""
    rows = [*SESSIONS, {"UserName": "svc", "LoginTime": "2026-09-13T11:00:00Z"}]
    respx.get(SESSIONS_URL).mock(return_value=httpx.Response(200, json=rows))
    text = await call_tool_text(
        build(settings), "cnc_list_active_sessions", {"response_format": "json"}
    )
    data = json.loads(text)
    assert data["count"] == 4
    assert [s.get("TgtId") for s in data["items"]] == [
        "TGT-1-abcdef…",
        "TGT-2-abcdef…",
        "TGT-3-abcdef…",
        None,
    ]
    assert "abcdefghijklmnopqrstuvwxyz" not in text


@respx.mock
async def test_list_active_sessions_api_error_is_string(make_settings):
    respx.get(SESSIONS_URL).mock(return_value=FORBIDDEN_403)
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_list_active_sessions", {})
    assert text.startswith("Error:") and "403" in text


# --- cnc_get_user ------------------------------------------------------------


@respx.mock
async def test_get_user_markdown_never_shows_password(settings):
    route = respx.get(f"{USER_URL}/admin").mock(return_value=httpx.Response(200, json=USER))
    text = await call_tool_text(build(settings), "cnc_get_user", {"username": "admin"})
    assert no_body(route)
    assert text == (
        "**admin** — role admin, status Active, name: Site Admin, device access groups: ALL-ACCESS"
    )
    text = await call_tool_text(
        build(settings), "cnc_get_user", {"username": "admin", "response_format": "json"}
    )
    data = json.loads(text)
    assert data == {
        "username": "admin",
        "role": "admin",
        "first_name": "Site",
        "last_name": "Admin",
        "status": "Active",
        "device_access_groups": ["ALL-ACCESS"],
    }
    assert "Password" not in text and "password" not in text


@respx.mock
async def test_get_user_url_encodes_the_name(settings):
    route = respx.get(url__regex=rf"{USER_URL}/.*").mock(
        return_value=httpx.Response(200, json=USER)
    )
    await call_tool_text(build(settings), "cnc_get_user", {"username": "svc user@corp"})
    assert route.calls[0].request.url.raw_path == b"/crosswork/aaa/v1/user/svc%20user%40corp"


@respx.mock
async def test_get_user_unknown_is_no_user_error(make_settings):
    respx.get(f"{USER_URL}/ghost").mock(return_value=INVALID_USERNAME_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_user", {"username": "ghost"}
    )
    assert text == "Error: no user 'ghost' (list with cnc_list_users)"


@respx.mock
async def test_get_user_other_500_is_generic_error(make_settings):
    respx.get(f"{USER_URL}/admin").mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_user", {"username": "admin"}
    )
    assert text.startswith("Error:") and "500" in text and "no user" not in text


# --- cnc_list_roles ----------------------------------------------------------


@respx.mock
async def test_list_roles_markdown_summarises_grants(settings):
    route = respx.get(ROLES_URL).mock(return_value=httpx.Response(200, json=ROLES))
    text = await call_tool_text(build(settings), "cnc_list_roles", {})
    assert no_body(route)
    assert "# Roles (2)" in text
    assert "- **admin** — 2 API grants, rate 1000/1s" in text
    assert "- **read-only** — 1 API grants, rate 100/1s (inactive)" in text
    assert "allowed_urls" not in text


@respx.mock
async def test_list_roles_json_is_raw_and_error(make_settings):
    settings = make_settings(max_retries=0)
    respx.get(ROLES_URL).mock(return_value=httpx.Response(200, json=ROLES))
    text = await call_tool_text(build(settings), "cnc_list_roles", {"response_format": "json"})
    assert json.loads(text) == ROLES
    respx.get(ROLES_URL).mock(return_value=FORBIDDEN_403)
    text = await call_tool_text(build(settings), "cnc_list_roles", {})
    assert text.startswith("Error:") and "403" in text


@respx.mock
async def test_list_roles_oversized_json_hint_points_to_markdown_and_per_role_tools(
    make_settings,
):
    """aaa/v1/role is a dict keyed by role name with no top-level list, so an
    oversized JSON answer takes the character cut — the bracketed note must
    carry the tool's own advice (markdown summary / per-role tools), not the
    generic hint and not a limit/offset promise."""
    settings = make_settings(max_response_chars=2_000)
    roles = {
        f"role-{i}": {
            **ROLES["admin"],
            "name": f"role-{i}",
            "access_rights": {f"api-{j}": grant(f"api-{j}", f"API {j}") for j in range(6)},
        }
        for i in range(4)
    }
    respx.get(ROLES_URL).mock(return_value=httpx.Response(200, json=roles))
    text = await call_tool_text(build(settings), "cnc_list_roles", {"response_format": "json"})
    assert text.endswith(
        "[Truncated: response exceeded 2000 characters. Use markdown for the per-role "
        "summary, or cnc_get_role_permissions / cnc_get_role_tasks for one role.]"
    )
    assert TRUNCATION_HINT not in text and "limit/offset" not in text
    # the markdown summary of the same answer fits, as the hint promises
    text = await call_tool_text(build(settings), "cnc_list_roles", {})
    assert "# Roles (4)" in text and "[Truncated" not in text
    assert "- **role-3** — 6 API grants, rate 1000/1s" in text


# --- cnc_get_role_tasks ------------------------------------------------------


@respx.mock
async def test_get_role_tasks_grouped_markdown(settings):
    tasks = respx.get(f"{USERTASK_URL}/admin").mock(return_value=httpx.Response(200, json=USERTASK))
    access = respx.get(f"{ROLE_ACCESS_URL}/admin").mock(
        return_value=httpx.Response(200, json=ROLE_ACCESS)
    )
    text = await call_tool_text(build(settings), "cnc_get_role_tasks", {"role": "admin"})
    assert no_body(tasks) and no_body(access)
    assert text.startswith("# Role admin\n\nGUI access: yes, API access: no\n")
    assert "## Audit Logs (audit_logs)" in text
    assert "- [x] View Audit Logs (view_audit_logs)" in text
    assert "- [ ] Export Audit Logs (export_audit_logs)" in text
    assert "## Optimization Engine (coe)\n- [x] Configure\n" in text + "\n"


@respx.mock
async def test_get_role_tasks_renders_dict_wrapped_task_items(settings):
    """The document wraps a group's items as rbacTaskItems {"items": [...]}; the
    lab answered a bare list. Both spellings (and an empty group) render."""
    wrapped = [
        {
            "id": "audit_logs",
            "name": "Audit Logs",
            "items": {"items": USERTASK[0]["items"]},
        },
        {"id": "coe", "name": "Optimization Engine", "items": {"Items": USERTASK[1]["items"]}},
        {"id": "empty", "name": "Empty Group", "items": {}},
    ]
    respx.get(f"{USERTASK_URL}/operator").mock(return_value=httpx.Response(200, json=wrapped))
    respx.get(f"{ROLE_ACCESS_URL}/operator").mock(
        return_value=httpx.Response(200, json={**ROLE_ACCESS, "PolicyId": "operator"})
    )
    text = await call_tool_text(build(settings), "cnc_get_role_tasks", {"role": "operator"})
    assert "## Audit Logs (audit_logs)\n- [x] View Audit Logs (view_audit_logs)" in text
    assert "- [ ] Export Audit Logs (export_audit_logs)" in text
    assert "## Optimization Engine (coe)\n- [x] Configure\n" in text
    assert text.rstrip().endswith("## Empty Group (empty)")


@respx.mock
async def test_get_role_tasks_json_and_unknown_role_passthrough(make_settings):
    settings = make_settings(max_retries=0)
    respx.get(f"{USERTASK_URL}/admin").mock(return_value=httpx.Response(200, json=USERTASK))
    respx.get(f"{ROLE_ACCESS_URL}/admin").mock(return_value=httpx.Response(200, json=ROLE_ACCESS))
    text = await call_tool_text(
        build(settings), "cnc_get_role_tasks", {"role": "admin", "response_format": "json"}
    )
    assert json.loads(text) == {"role": "admin", "access": ROLE_ACCESS, "tasks": USERTASK}
    respx.get(f"{USERTASK_URL}/ghost").mock(
        return_value=httpx.Response(500, json={"error": "role not found"})
    )
    respx.get(f"{ROLE_ACCESS_URL}/ghost").mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(build(settings), "cnc_get_role_tasks", {"role": "ghost"})
    assert text.startswith("Error:") and "500" in text and "role not found" in text


# --- cnc_get_role_permissions -----------------------------------------------


@respx.mock
async def test_get_role_permissions_own_and_named(make_settings):
    settings = make_settings(max_retries=0)
    own = respx.get(USER_PERMISSION_URL).mock(return_value=httpx.Response(200, json=PERMISSIONS))
    named = respx.get(f"{USER_PERMISSION_URL}/read-only").mock(
        return_value=httpx.Response(200, json=["view_audit_logs"])
    )
    text = await call_tool_text(build(settings), "cnc_get_role_permissions", {})
    assert own.call_count == 1 and no_body(own)
    line, payload = text.split("\n\n", 1)
    assert (
        line
        == "the calling account's role has 3 permissions: bwod_config, csm_config, dag_management"
    )
    assert json.loads(payload) == sorted(PERMISSIONS)
    text = await call_tool_text(build(settings), "cnc_get_role_permissions", {"role": "read-only"})
    assert named.call_count == 1
    assert text.startswith("role read-only has 1 permissions: view_audit_logs")
    respx.get(f"{USER_PERMISSION_URL}/ghost").mock(return_value=FORBIDDEN_403)
    text = await call_tool_text(build(settings), "cnc_get_role_permissions", {"role": "ghost"})
    assert text.startswith("Error:") and "403" in text


# --- cnc_get_password_policy -------------------------------------------------


@respx.mock
async def test_get_password_policy_lists_enabled_rules(make_settings):
    settings = make_settings(max_retries=0)
    route = respx.get(PASSWORD_POLICY_URL).mock(
        return_value=httpx.Response(200, json=PASSWORD_POLICY)
    )
    text = await call_tool_text(build(settings), "cnc_get_password_policy", {})
    assert no_body(route)
    markdown, payload = text.rsplit("\n\n", 1)
    assert json.loads(payload) == PASSWORD_POLICY
    assert "- minimum length 8" in markdown
    assert "- no username (or its reverse) in the password: yes" in markdown
    assert "- no character repeated more than three times in a row: no" in markdown
    assert "- change password on first login: yes" in markdown
    assert "- cannot reuse the last 5 passwords" in markdown
    assert "- lock out after 5 failed logins" in markdown
    assert "- lock out for 6 minutes (disabled)" in markdown
    assert "NumChangedChars" not in markdown and "must change at least" not in markdown
    assert "expires after" not in markdown and "warn" not in markdown
    respx.get(PASSWORD_POLICY_URL).mock(return_value=FORBIDDEN_403)
    text = await call_tool_text(build(settings), "cnc_get_password_policy", {})
    assert text.startswith("Error:") and "403" in text


# --- cnc_list_secured_apis ---------------------------------------------------


@respx.mock
async def test_list_secured_apis_grouped_and_filtered(make_settings):
    settings = make_settings(max_retries=0)
    route = respx.get(SECURED_APIS_URL).mock(return_value=httpx.Response(200, json=SECURED_APIS))
    text = await call_tool_text(build(settings), "cnc_list_secured_apis", {})
    assert no_body(route)
    assert "# Secured APIs (3 in 2 feature(s))" in text
    assert "## Device Management (2)\n- Inventory (api-2)\n- Credentials (api-3)" in text
    assert "## Topology (1)\n- Topology NBI (api-1)" in text
    text = await call_tool_text(
        build(settings), "cnc_list_secured_apis", {"feature": "TOPO", "response_format": "json"}
    )
    assert json.loads(text) == {"Topology": SECURED_APIS["Topology"]}
    text = await call_tool_text(build(settings), "cnc_list_secured_apis", {"feature": "nothing"})
    assert "No features matched" in text and not text.startswith("Error:")
    respx.get(SECURED_APIS_URL).mock(return_value=FORBIDDEN_403)
    text = await call_tool_text(build(settings), "cnc_list_secured_apis", {})
    assert text.startswith("Error:") and "403" in text


@respx.mock
async def test_list_secured_apis_oversized_hint_says_narrow_with_feature(make_settings):
    """Over the cap, both formats carry the tool's own advice ("Narrow with
    feature, or use markdown."). The JSON is {"<feature>": [...]}, so the
    JSON-aware cut drops trailing entries of the largest feature list and
    stays parseable; markdown gets the bracketed note."""
    settings = make_settings(max_response_chars=2_000)
    apis = {
        "Topology": [{"api_id": f"api-{i}", "name": f"Topology API {i}"} for i in range(100)],
        "Device Management": SECURED_APIS["Device Management"],
    }
    respx.get(SECURED_APIS_URL).mock(return_value=httpx.Response(200, json=apis))
    text = await call_tool_text(
        build(settings), "cnc_list_secured_apis", {"response_format": "json"}
    )
    assert len(text) <= 2_000
    data = json.loads(text)
    assert data["truncated"] is True and 1 <= data["shown"] < 100
    assert data["Topology"] == apis["Topology"][: data["shown"]]
    assert data["Device Management"] == SECURED_APIS["Device Management"]  # untouched
    assert data["truncation_note"].endswith(
        "'Topology' entries were dropped. Narrow with feature, or use markdown."
    )
    assert TRUNCATION_HINT not in text and "limit/offset" not in text
    text = await call_tool_text(build(settings), "cnc_list_secured_apis", {})
    assert text.startswith("# Secured APIs (102 in 2 feature(s))")
    assert text.endswith(
        "[Truncated: response exceeded 2000 characters. Narrow with feature, or use markdown.]"
    )
    assert TRUNCATION_HINT not in text and "limit/offset" not in text
    # the feature filter narrows the same answer under the cap, as the hint promises
    text = await call_tool_text(
        build(settings), "cnc_list_secured_apis", {"feature": "device", "response_format": "json"}
    )
    assert json.loads(text) == {"Device Management": SECURED_APIS["Device Management"]}


# --- cnc_set_login_banner ----------------------------------------------------


def banner_calls() -> list[str]:
    """The banner endpoints hit, in wire order (last path segment)."""
    return [
        c.request.url.path.rsplit("/", 1)[1]
        for c in respx.calls
        if c.request.url.path.endswith(("/banner/get", "/banner/set"))
    ]


@respx.mock
async def test_set_login_banner_merges_over_current_and_sends_full_object(make_settings):
    """banner/set is protobuf-backed (omitted == false/""), so the tool reads the
    current banner first, merges the given fields over it and sends every field."""
    settings = make_settings(enable_writes=True)
    set_route = respx.post(BANNER_SET_URL).mock(return_value=httpx.Response(200, json=ACTION_OK))
    get_route = respx.post(BANNER_GET_URL).mock(
        side_effect=[httpx.Response(200, json=BANNER), httpx.Response(200, json=BANNER_AFTER)]
    )
    text = await call_tool_text(
        build(settings),
        "cnc_set_login_banner",
        {"message": "Authorised use only.", "user_ack": True},
    )
    assert banner_calls() == ["get", "set", "get"]  # read, merge+write, re-read
    assert sent_bodies(get_route) == [{}, {}]
    assert sent(set_route) == {
        "ShowMessage": True,  # kept from the current banner
        "UserAck": True,
        "Message": "Authorised use only.",
        "Icon": "BANNER_ICON_INFO",  # kept
        "Title": "Crosswork Legal Disclaimer",  # kept
    }
    assert text.startswith("Login banner updated.\n\nTitle: Crosswork Legal Disclaimer")
    assert "Message: Authorised use only." in text
    assert "acknowledgement required: yes" in text
    assert json.loads(text.split("\n\n")[-1]) == BANNER_AFTER


@respx.mock
async def test_set_login_banner_icon_is_validated_case_insensitively(make_settings):
    settings = make_settings(enable_writes=True)
    set_route = respx.post(BANNER_SET_URL).mock(return_value=httpx.Response(200, json=ACTION_OK))
    get_route = respx.post(BANNER_GET_URL).mock(return_value=httpx.Response(200, json=BANNER))
    await call_tool_text(
        build(settings),
        "cnc_set_login_banner",
        {"icon": " banner_icon_important ", "show": False},
    )
    assert sent(set_route) == {
        "ShowMessage": False,
        "UserAck": False,
        "Message": "Welcome to Cisco Crosswork.",
        "Icon": "BANNER_ICON_IMPORTANT",
        "Title": "Crosswork Legal Disclaimer",
    }
    text = await call_tool_text(build(settings), "cnc_set_login_banner", {"icon": "warning"})
    assert text.startswith("Error:") and "Unknown icon 'warning'" in text
    assert "BANNER_ICON_INFO | BANNER_ICON_IMPORTANT | BANNER_ICON_CRITICAL" in text
    assert set_route.call_count == 1 and get_route.call_count == 2  # bad icon: no request at all


@respx.mock
async def test_set_login_banner_fills_defaults_when_current_banner_is_sparse(make_settings):
    """A banner/get with missing fields (protobuf omits zero values) still yields
    the full object: false, "" and the documented default icon."""
    settings = make_settings(enable_writes=True)
    set_route = respx.post(BANNER_SET_URL).mock(return_value=httpx.Response(200, json=ACTION_OK))
    respx.post(BANNER_GET_URL).mock(return_value=httpx.Response(200, json={}))
    await call_tool_text(build(settings), "cnc_set_login_banner", {"title": "Notice"})
    assert sent(set_route) == {
        "ShowMessage": False,
        "UserAck": False,
        "Message": "",
        "Icon": "BANNER_ICON_INFO",
        "Title": "Notice",
    }


@respx.mock
async def test_set_login_banner_reset_sends_reset_alone_without_prior_read(make_settings):
    settings = make_settings(enable_writes=True)
    set_route = respx.post(BANNER_SET_URL).mock(return_value=httpx.Response(200, json=ACTION_OK))
    get_route = respx.post(BANNER_GET_URL).mock(return_value=httpx.Response(200, json=BANNER))
    await call_tool_text(
        build(settings),
        "cnc_set_login_banner",
        {"reset": True, "message": "ignored", "show": False, "icon": "bogus"},
    )
    assert sent(set_route) == {"ResetSettings": True}
    assert banner_calls() == ["set", "get"]  # no read before a reset, one re-read after
    assert get_route.call_count == 1


@respx.mock
async def test_set_login_banner_noop_verdict_is_success(make_settings):
    """R_NOOP (nothing changed) passes the cluster verdict check like R_SUCCESS."""
    settings = make_settings(enable_writes=True)
    respx.post(BANNER_SET_URL).mock(return_value=httpx.Response(200, json=ACTION_NOOP))
    respx.post(BANNER_GET_URL).mock(return_value=httpx.Response(200, json=BANNER))
    text = await call_tool_text(
        build(settings), "cnc_set_login_banner", {"message": BANNER["Message"]}
    )
    assert text.startswith("Login banner updated.") and "Error" not in text


@respx.mock
async def test_set_login_banner_nothing_given_is_error_without_request(make_settings):
    settings = make_settings(enable_writes=True)
    set_route = respx.post(BANNER_SET_URL).mock(return_value=httpx.Response(200, json=ACTION_OK))
    get_route = respx.post(BANNER_GET_URL).mock(return_value=httpx.Response(200, json=BANNER))
    text = await call_tool_text(build(settings), "cnc_set_login_banner", {})
    assert text.startswith("Error:") and "nothing to set" in text and "icon" in text
    assert set_route.call_count == 0 and get_route.call_count == 0


@respx.mock
async def test_set_login_banner_platform_failure_is_error(make_settings):
    settings = make_settings(enable_writes=True, max_retries=0)
    respx.post(BANNER_SET_URL).mock(return_value=httpx.Response(200, json=ACTION_FAILED))
    get_route = respx.post(BANNER_GET_URL).mock(return_value=httpx.Response(200, json=BANNER))
    text = await call_tool_text(build(settings), "cnc_set_login_banner", {"title": "x"})
    assert text.startswith("Error:") and "R_FAILURE" in text
    assert get_route.call_count == 1  # the pre-read only: no re-read after a failed write
    respx.post(BANNER_SET_URL).mock(return_value=NATS_500)
    text = await call_tool_text(build(settings), "cnc_set_login_banner", {"title": "x"})
    assert text.startswith("Error:") and "500" in text
    assert get_route.call_count == 2
    # A failed pre-read stops the tool before it writes anything.
    respx.post(BANNER_GET_URL).mock(return_value=NATS_500)
    set_route = respx.post(BANNER_SET_URL).mock(return_value=httpx.Response(200, json=ACTION_OK))
    text = await call_tool_text(build(settings), "cnc_set_login_banner", {"title": "x"})
    assert text.startswith("Error:") and "500" in text
    assert set_route.call_count == 2  # unchanged: the two earlier writes, none now


# --- cnc_set_maintenance_mode ------------------------------------------------


@respx.mock
async def test_set_maintenance_mode_sends_flag_and_rereads_status(make_settings):
    settings = make_settings(enable_writes=True)
    set_route = respx.post(MAINT_SET_URL).mock(return_value=httpx.Response(200, json=MAINT_SET_OK))
    status = respx.get(MAINT_STATUS_URL).mock(
        return_value=httpx.Response(200, json=MAINT_STATUS_ON)
    )
    text = await call_tool_text(build(settings), "cnc_set_maintenance_mode", {"enabled": True})
    assert sent(set_route) == {"isSetMaintenance": True}
    assert status.call_count == 1
    line, payload = text.split("\n\n", 1)
    assert line == (
        "Maintenance mode on requested: Processing maintenance mode request. "
        "Current status: Maintenance_Mode_On."
    )
    assert json.loads(payload) == {"request": MAINT_SET_OK, "status": MAINT_STATUS_ON}


@respx.mock
async def test_set_maintenance_mode_failed_request_is_error(make_settings):
    settings = make_settings(enable_writes=True, max_retries=0)
    respx.post(MAINT_SET_URL).mock(return_value=httpx.Response(200, json=MAINT_SET_FAILED))
    status = respx.get(MAINT_STATUS_URL).mock(
        return_value=httpx.Response(200, json=MAINT_STATUS_OFF)
    )
    text = await call_tool_text(build(settings), "cnc_set_maintenance_mode", {"enabled": False})
    assert text.startswith("Error:") and "Backup in progress" in text
    assert status.call_count == 0
    respx.post(MAINT_SET_URL).mock(return_value=NATS_500)
    text = await call_tool_text(build(settings), "cnc_set_maintenance_mode", {"enabled": False})
    assert text.startswith("Error:") and "500" in text


# --- cnc_restart_microservice ------------------------------------------------


@respx.mock
async def test_restart_microservice_sends_req_id(make_settings):
    settings = make_settings(enable_writes=True)
    route = respx.post(RESTART_URL).mock(return_value=httpx.Response(200, json=ACTION_OK))
    text = await call_tool_text(
        build(settings), "cnc_restart_microservice", {"name": " robot-topo-svc "}
    )
    assert sent(route) == {"req_id": "robot-topo-svc"}
    assert text.startswith("Restart requested for microservice robot-topo-svc.")
    assert json.loads(text.split("\n\n", 1)[1]) == ACTION_OK


@respx.mock
async def test_restart_microservice_failure_and_blank_name(make_settings):
    settings = make_settings(enable_writes=True, max_retries=0)
    route = respx.post(RESTART_URL).mock(return_value=httpx.Response(200, json=ACTION_FAILED))
    text = await call_tool_text(build(settings), "cnc_restart_microservice", {"name": "ghost"})
    assert text.startswith("Error:") and "R_FAILURE" in text and "microservice not found" in text
    text = await call_tool_text(build(settings), "cnc_restart_microservice", {"name": "  "})
    assert text.startswith("Error:") and "name is empty" in text
    assert route.call_count == 1  # the blank name never reached the wire
    respx.post(RESTART_URL).mock(return_value=NATS_500)
    text = await call_tool_text(build(settings), "cnc_restart_microservice", {"name": "x"})
    assert text.startswith("Error:") and "500" in text
