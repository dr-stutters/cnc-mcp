"""Device-configuration tools end-to-end through MCPServer (schema validation included).

The module is registered directly (not through build_server) so the test does
not depend on tools/__init__.py's module list. All HTTP is mocked with respx.
Fixtures mirror the shapes verified live on Crosswork 7.2 (2026-09-13, see the
platform notes): the backup list (empty ``file``) and detail (with the masked
configuration text), the jobs list with its ``backup_job_status_summary``, the
job detail with runs, a SYSTEM template with a mandatory variable, the
deployment detail with the CLI transcript (``device_uuid`` = HOSTNAME), and
the 202 / 500 / 400 answers verbatim. ``nodes/query`` answers carry
``result_count`` on a host_name filter but NOT on a uuid filter (verified).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest
import respx
from mcp.server.mcpserver import MCPServer

from cnc_mcp import polling
from cnc_mcp.auth import StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.config import Settings
from cnc_mcp.errors import PlatformError
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import device_config
from cnc_mcp.tools.device_config import (
    RESULT_TAIL_CHARS,
    as_int,
    backup_job_body,
    configlet_references,
    default_backup_job_name,
    deploy_body,
    job_of,
    parse_deploy_variables,
    parse_statuses,
    parse_template_variables,
    parse_version,
    resolve_deploy_variables,
    result_tail,
    runs_of,
    sort_backups,
    start_at_time,
    template_body,
)
from tests.conftest import BASE_URL, call_tool_text

CONFIG = f"{BASE_URL}/crosswork/config/v1"
NODES_QUERY_URL = f"{BASE_URL}/crosswork/inventory/v1/nodes/query"
PREFERENCES_URL = f"{CONFIG}/device-config-preferences/config-settings"
CONFIG_BACKUP_URL = f"{CONFIG}/config-backup"
LATEST_BACKUP_URL = f"{CONFIG}/latest-config-backup"
SCHEDULE_URL = f"{CONFIG}/schedule-config-backup-job"
JOBS_URL = f"{CONFIG}/config-backup-jobs"
JOB_URL = f"{CONFIG}/config-backup-job"
RESTORE_JOB_URL = f"{CONFIG}/config-backup-restore-job"
TEMPLATES_URL = f"{CONFIG}/templates"
TEMPLATES_QUERY_URL = f"{TEMPLATES_URL}/query"
DEPLOYMENTS_QUERY_URL = f"{TEMPLATES_URL}/jobs/deployments/query"
DEPLOY_URL = f"{TEMPLATES_URL}/deploy-template"

PE1_UUID = "2a9b7c1e-0f3d-4b8a-9c6e-1d2f3a4b5c6d"
P1_UUID = "7f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f"
RUN_ID = "e79bb231-3b4d-425e-940e-e229a526f06b"
JOB_NAME = "mcp-backup-20260913-120000"
BACKUP_NAME = f"{JOB_NAME}_{RUN_ID}"
DEPLOYMENT_ID = "mcp-loopback99_DeployJob_20260913_120500"
NOW = datetime(2026, 9, 13, 12, 0, 0, tzinfo=UTC)


def node(uuid: str, host: str) -> dict:
    return {
        "uuid": uuid,
        "host_name": host,
        "node_ip": {"inet_af": "ROBOT_INET_ADDR_TYPE_v4", "inet_addr": "198.18.140.11"},
        "admin_state": "ROBOT_ADMIN_STATE_UP",
        "reachability_state": "CONN_STATE_REACHABLE",
        "operational_state": "ROBOT_OPER_STATE_OK",
        "profile": "cml-xrd",
        "tag_names": ["cli", "snmp"],
        "errors": [],
    }


PE1 = node(PE1_UUID, "PE1")
P1 = node(P1_UUID, "P1")
ONE_NODE = {"data": [PE1], "total_count": 5, "result_count": 1}
TWO_NODES = {"data": [PE1, P1], "total_count": 5, "result_count": 2}
UUID_NODE = {"data": [PE1], "total_count": 5}  # a uuid filter omits result_count (verified)
NO_NODES: dict = {}  # verified: an empty match is a bare {} with no data key


def query_of(selector: dict, page: int = 0) -> dict:
    return {"filter": selector, "filterData": {"PageSize": 100, "PageNum": page, "Criteria": ""}}


# Verified GET device-config-preferences/config-settings keys.
PREFERENCES = {
    "timeout": 120,
    "hold_off_timer": 60,
    "max_backups_to_retain": 10,
    "max_days_to_retain_backups": 30,
    "alarm_threshold": 3,
    "max_days_to_retain_jobs": 30,
    "backup_config_on_device_add": True,
    "backup_config_on_config_change": False,
    "initiate_backup_config_from_ems": False,
    "enable_syslog_traps_on_device": False,
    "is_nso_configured": True,
}

MASKED_CONFIG = (
    "!! IOS XR Configuration 26.1.1\nhostname PE1\nusername cisco\n group root-lr\n "
    "secret 10 ********\n!\ninterface Loopback0\n ipv4 address 10.0.0.1 255.255.255.255\n!\nend"
)


def backup(name: str, backedup_at: str, trigger: str, files: list | None = None) -> dict:
    """A backup_config entry (verified keys); the LIST form carries an empty ``file``."""
    return {
        "name": name,
        "device_uuid": PE1_UUID,
        "file": files or [],
        "backedup_at": backedup_at,
        "status": "SUCCESS",
        "tag": [],
        "pinned": False,
        "trigger": trigger,
        "result": f"Backup by {trigger}",
        "notes": "",
        "created_by": "admin" if trigger == "SCHEDULED_JOB" else "",
        "complianceStatus": "COMPLIANT",
    }


INITIAL_BACKUP = backup("Initial_Version", "2026-09-12T20:11:05Z", "DEVICE_ADD")
JOB_BACKUP = backup(BACKUP_NAME, "2026-09-13T12:00:06Z", "SCHEDULED_JOB")
BACKUP_LIST = {"backup_config": [INITIAL_BACKUP, JOB_BACKUP]}  # oldest first on the wire
EMPTY_BACKUP_LIST = {"backup_config": []}
BACKUP_DETAIL = backup(
    BACKUP_NAME,
    "2026-09-13T12:00:06Z",
    "SCHEDULED_JOB",
    files=[{"file_name": "", "config": MASKED_CONFIG, "type": "RUNNINGCONFIG"}],
)

# Verified job shapes.
JOB = {
    "name": JOB_NAME,
    "task": "com.cisco.ems.config.service.ConfigBackupJob",
    "schedule": {},
    "params": {},
    "status": "COMPLETED",
    "last_run_at": "2026-09-13T12:00:05.001Z",
    "next_run_at": "1970-01-01T00:00:00Z",
    "last_run_status": "SUCCESS",
    "job_type": "BACKUP",
    "duration": 6007,
    "percentage_completed": 100,
    "created_by": "admin",
    "run_count": 1,
}
JOB_RUNNING = {**JOB, "status": "RUNNING", "last_run_status": "IN_PROGRESS", "duration": 0}
JOB_SCHEDULED = {**JOB, "status": "SCHEDULED", "last_run_status": "NOT_STARTED", "run_count": 0}
STATUS_SUMMARY = {
    "scheduled_count": 0,
    "completed_count": 1,
    "failed_count": 0,
    "running_count": 0,
    "paused_count": 0,
    "blocked_count": 0,
}
JOBS_LIST = {
    "config_backup_restore_jobs": [{"job": JOB, "device_count": 1}],
    "page_summary": {"page_size": 1000, "page_number": 0, "total_pages": 1, "total_elements": 1},
    "backup_job_status_summary": STATUS_SUMMARY,
}
RUN = {
    "run_id": RUN_ID,
    "job_name": JOB_NAME,
    "run_status": "SUCCESS",
    "start_at": "2026-09-13T12:00:05.001Z",
    "duration": 6007,
}
JOB_DETAIL = {
    "config_backup_restore_job": {"job": JOB, "device_count": 1},
    "job_runs": {"backup_job_run": [RUN]},
}
JOB_DETAIL_RUNNING = {
    "config_backup_restore_job": {"job": JOB_RUNNING, "device_count": 1},
    "job_runs": {"backup_job_run": [{**RUN, "run_status": "IN_PROGRESS", "duration": 0}]},
}
JOB_DETAIL_FAILED = {
    "config_backup_restore_job": {
        "job": {**JOB, "status": "FAILED", "last_run_status": "RUN_FAILED"},
        "device_count": 1,
    },
    "job_runs": {"backup_job_run": [{**RUN, "run_status": "RUN_FAILED"}]},
}
UNKNOWN_JOB: dict = {}  # verified: an unknown job name answers a bare {}

# Verified 202 / 500 answers of schedule-config-backup-job.
BACKUP_ACCEPTED = {
    "status_code": 202,
    "job_id": JOB_NAME,
    "message": "Backup Config request is successful",
}
BACKUP_DUPLICATE = {
    "status_code": 500,
    "job_id": "",
    "message": f"Job already exists with name {JOB_NAME}",
}
DELETE_BACKUP_OK = f"Deleted backup {BACKUP_NAME}for device: {PE1_UUID}"
DELETE_BACKUP_NOT_FOUND = f"Backup with name ghost not found for device: {PE1_UUID}"


def variable(name: str, mandatory: bool, default: str = "", display: str | None = None) -> dict:
    return {
        "name": name,
        "display_name": display or name,
        "type": "string",
        "default_value": default,
        "is_mandatory": mandatory,
        "description": "",
        "options": [],
        "version": 1.0,
    }


SYSTEM_TEMPLATE = {
    "name": "Cisco_IOS-XR_Interface_config",
    "version": 1.0,
    "description": "Configure an interface on IOS XR",
    "configlet": (
        "interface ${interfaceName}\n description ${description}\n#if($shutdown == 'true')\n"
        " shutdown\n#end"
    ),
    "created_at": "2026-09-01T00:00:00Z",
    "transport": "CLI",
    "category": "INTERFACE",
    "type": "SYSTEM",
    "variables": [
        variable("interfaceName", True, display="Interface Name"),
        variable("description", False, default="managed by CNC"),
        variable("shutdown", False),
    ],
    "device_type": ["Cisco IOS XR"],
    "port_type": [],
    "is_read": True,
    "author": "system",
    "tagList": [],
    "accessList": [],
    "path": "",
    "failurePolicy": "CONTINUE_ON_FAILURE",
    "last_deployed_status": "NOT_DEPLOYED",
    "notes": "",
}
USER_TEMPLATE = {
    **SYSTEM_TEMPLATE,
    "name": "mcp-loopback99",
    "description": "Adds Loopback99",
    "configlet": "interface Loopback99\n description ${desc}",
    "category": "DEVICE",
    "type": "USER_DEFINED_SIMPLE",
    "variables": [variable("desc", False, default="mcp")],
    "device_type": [],
    "is_read": False,
    "author": "admin",
    "last_deployed_status": "SUCCESS",
}
# Verified: total_elements is a STRING on the wire.
TEMPLATES_PAGE = {
    "template": [SYSTEM_TEMPLATE, USER_TEMPLATE],
    "page_size": 20,
    "page_number": 0,
    "total_pages": 1,
    "total_elements": "2",
}
NO_TEMPLATE = {"templates": []}  # verified: an unknown template name

TRANSCRIPT = (
    "RP/0/RP0/CPU0:PE1#configure terminal\nRP/0/RP0/CPU0:PE1(config)#interface Loopback99\n"
    "RP/0/RP0/CPU0:PE1(config-if)# description mcp\nRP/0/RP0/CPU0:PE1(config-if)#commit\n"
    "RP/0/RP0/CPU0:PE1(config-if)#end"
)


def detail(host: str, status: str, result: str = TRANSCRIPT) -> dict:
    """A deploy-template/<id>/query detail (verified: device_uuid is the HOSTNAME)."""
    return {
        "deployment_id": DEPLOYMENT_ID,
        "template_name": "",
        "version": 1.0,
        "device_uuid": host,
        "deployed_configlet": "interface Loopback99\n description mcp",
        "deployed_at": "2026-09-13T12:05:03Z",
        "status": status,
        "result": result,
        "variables": [],
        "params": {},
        "duration": 4120,
    }


def deployment_page(*details: dict) -> dict:
    return {
        "details": list(details),
        "page_size": 20,
        "page_number": 0,
        "total_pages": 1,
        "total_elements": len(details),
    }


DEPLOYMENT_DETAIL = deployment_page(detail("PE1", "SUCCESS"))
DEPLOYMENT_IN_PROGRESS = deployment_page(detail("PE1", "IN_PROGRESS", result=""))
DEPLOYMENT_FAILED = deployment_page(
    detail("PE1", "SUCCESS"), detail("P1", "FAILED", result="% Invalid input detected")
)
NO_DEPLOYMENT = deployment_page()  # verified: unknown id -> empty details
# SYSTEM_FAILURE / NOT_DEPLOYED are in the documented DeploymentStatus enum (not seen live).
DEPLOYMENT_SYSTEM_FAILURE = deployment_page(
    detail("PE1", "SYSTEM_FAILURE", result="Internal error: collector unavailable")
)
DEPLOYMENT_NOT_DEPLOYED = deployment_page(
    detail("PE1", "SUCCESS"), detail("P1", "NOT_DEPLOYED", result="")
)
# A 2-device deployment the platform pages one device at a time.
PAGE_0_OF_2 = {**deployment_page(detail("PE1", "SUCCESS")), "total_pages": 2, "total_elements": 2}
PAGE_1_OF_2 = {
    **deployment_page(detail("P1", "SUCCESS")),
    "page_number": 1,
    "total_pages": 2,
    "total_elements": 2,
}


def paged_deployment_route(url: str, *pages: dict) -> respx.Route:
    """A deploy-template/<id>/query route answering by the ``page`` query parameter; a page
    beyond the last one repeats the last (a platform that ignores ``page`` looks like
    ``pages[0]`` alone)."""

    def answer(request: httpx.Request) -> httpx.Response:
        index = int(request.url.params.get("page", "0"))
        return httpx.Response(200, json=pages[min(index, len(pages) - 1)])

    return respx.post(url).mock(side_effect=answer)


def pages_requested(route: respx.Route) -> list[tuple[str, str]]:
    return [(c.request.url.params["page"], c.request.url.params["size"]) for c in route.calls]


DEPLOYMENT_JOB = {
    "name": DEPLOYMENT_ID,
    "task": "com.cisco.ems.config.service.TemplateDeployJob",
    "params": {},
    "status": "COMPLETED",
    "last_run_at": "2026-09-13T12:05:00.001Z",
    "last_run_status": "SUCCESS",
    "job_type": "DEPLOYMENT",
    "duration": 4120,
    "percentage_completed": 100,
    "created_by": "admin",
    "run_count": 1,
}
DEPLOYMENT_JOBS = {
    "jobs": [DEPLOYMENT_JOB],
    "page_summary": {"page_size": 1000, "page_number": 0, "total_pages": 1, "total_elements": 1},
}
DEPLOY_ACCEPTED = {"status_code": 202, "job_id": DEPLOYMENT_ID, "message": "Deployment scheduled"}
# Verified 400 / 500 answers of the templates endpoints.
TEMPLATE_DUPLICATE = {"code": 400, "errorMessage": "Template mcp-loopback99 already present."}
TEMPLATE_DELETE_FAILED = {
    "code": 500,
    "errorMessage": "Failed to delete templates : [mcp-loopback99]",
}
NATS_500 = httpx.Response(500, json={"error": "NATS request failed"})


def build(settings: Settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    device_config.register(mcp, ctx)
    return mcp


def sent(route: respx.Route, index: int = 0) -> dict:
    return json.loads(route.calls[index].request.content)


def mock_nodes(body: dict) -> respx.Route:
    return respx.post(NODES_QUERY_URL).mock(return_value=httpx.Response(200, json=body))


def mock_sequence(method: str, url: str, *bodies: dict) -> respx.Route:
    """A route answering the given bodies in order; the last one repeats forever."""
    replies = [httpx.Response(200, json=b) for b in bodies]

    def answer(_request: httpx.Request) -> httpx.Response:
        return replies.pop(0) if len(replies) > 1 else replies[0]

    return respx.route(method=method, url=url).mock(side_effect=answer)


class _FakeClock:
    """Stands in for both ``time`` and ``asyncio`` inside cnc_mcp.polling."""

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def fake_clock(monkeypatch) -> _FakeClock:
    clock = _FakeClock()
    monkeypatch.setattr(polling, "time", clock)
    monkeypatch.setattr(polling, "asyncio", clock)
    return clock


@pytest.fixture
def fixed_now(monkeypatch) -> datetime:
    monkeypatch.setattr(device_config, "utcnow", lambda: NOW)
    return NOW


@pytest.fixture
def writes(make_settings) -> Settings:
    return make_settings(enable_writes=True, max_retries=0)


@pytest.fixture
def writes_retrying(make_settings) -> Settings:
    """Write settings WITH retries enabled (backoff is 0 in conftest, nothing sleeps): the
    "not auto-retried" tests must be built with this, otherwise call_count == 1 would hold
    even if a POST were wrongly marked retryable."""
    return make_settings(enable_writes=True, max_retries=2)


READ_TOOLS = {
    "cnc_get_device_config_preferences",
    "cnc_list_device_backups",
    "cnc_get_device_backup",
    "cnc_list_config_backup_jobs",
    "cnc_get_config_backup_job",
    "cnc_list_config_templates",
    "cnc_get_config_template",
    "cnc_list_template_deployments",
    "cnc_get_template_deployment",
    "cnc_wait_for_config_backup_job",
    "cnc_wait_for_template_deployment",
}
WRITE_TOOLS = {
    "cnc_backup_device_config",
    "cnc_delete_config_backup_job",
    "cnc_delete_device_backup",
    "cnc_create_config_template",
    "cnc_delete_config_template",
    "cnc_deploy_config_template",
    "cnc_delete_template_deployment",
}


# --- registration / gating ---------------------------------------------------


async def test_write_tools_hidden_unless_enabled(make_settings):
    names = {t.name for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert names == READ_TOOLS
    names = {t.name for t in await build(make_settings(enable_writes=True)).list_tools()}
    assert names == READ_TOOLS | WRITE_TOOLS


async def test_annotations(make_settings):
    tools = {t.name: t for t in await build(make_settings(enable_writes=True)).list_tools()}
    for name in READ_TOOLS:
        assert tools[name].annotations.read_only_hint is True, name
        assert tools[name].annotations.idempotent_hint is True, name
    for name in WRITE_TOOLS:
        assert tools[name].annotations.read_only_hint is False, name
    destructive = {
        "cnc_delete_config_backup_job",
        "cnc_delete_device_backup",
        "cnc_delete_config_template",
        "cnc_deploy_config_template",
        "cnc_delete_template_deployment",
    }
    for name in WRITE_TOOLS:
        assert tools[name].annotations.destructive_hint is (name in destructive), name
    not_idempotent = {
        "cnc_backup_device_config",
        "cnc_create_config_template",
        "cnc_deploy_config_template",
    }
    for name in WRITE_TOOLS:
        assert tools[name].annotations.idempotent_hint is (name not in not_idempotent), name
    # Flat schemas: every argument is a top-level property (no $ref wrapper).
    props = tools["cnc_deploy_config_template"].input_schema["properties"]
    assert set(props) == {
        "name", "uuid", "host_name", "version", "variables",
        "backup_before_deploy", "rollback_on_failure",
    }  # fmt: skip
    props = tools["cnc_backup_device_config"].input_schema["properties"]
    assert props["delay_seconds"]["minimum"] == 0 and props["delay_seconds"]["maximum"] == 3600
    props = tools["cnc_wait_for_config_backup_job"].input_schema["properties"]
    assert props["timeout_seconds"]["minimum"] == 10 and props["timeout_seconds"]["maximum"] == 900
    assert props["interval_seconds"]["minimum"] == 2 and props["interval_seconds"]["maximum"] == 60
    props = tools["cnc_list_config_templates"].input_schema["properties"]
    assert props["size"]["minimum"] == 1 and props["size"]["maximum"] == 200
    assert tools["cnc_get_device_config_preferences"].input_schema.get("properties", {}) == {}


# --- pure helpers ------------------------------------------------------------


def test_start_at_time_and_default_job_name():
    assert start_at_time(5, NOW) == "2026-09-13T12:00:05.000Z"
    assert start_at_time(0, NOW) == "2026-09-13T12:00:00.000Z"
    assert default_backup_job_name(NOW) == "mcp-backup-20260913-120000"


def test_wire_bodies():
    assert backup_job_body("bkup", "2026-09-13T12:00:05.000Z", [PE1_UUID, P1_UUID]) == {
        "name": "bkup",
        "trigger": "SCHEDULED_JOB",
        "schedule": {"start_at_time": "2026-09-13T12:00:05.000Z"},
        "device_uuids": {"device_uuids": [PE1_UUID, P1_UUID]},
    }
    body = deploy_body(
        "mcp-loopback99", 1, [PE1_UUID], {"desc": "mcp"},
        backup_before_deploy=True, rollback_on_failure=False,
    )  # fmt: skip
    assert body == {
        "template_name": "mcp-loopback99",
        "version": "1",  # a string at the top level ...
        "device_uuids": {"device_uuids": [PE1_UUID]},
        "details": [
            {"version": 1, "device_uuid": "GLOBAL", "variables": [{"name": "desc", "value": "mcp"}]}
        ],  # ... an int inside the GLOBAL detail (verified)
        "additional_params": {"backup_before_deploy": True, "rollback_on_failure": False},
    }
    variables = parse_template_variables("desc=mcp")
    assert template_body(
        "mcp-loopback99",
        "interface Loopback99",
        description="d",
        notes="n",
        category="DEVICE",
        transport="CLI",
        variables=variables,
        device_types=["Cisco IOS XR"],
    ) == {  # fmt: skip
        "name": "mcp-loopback99",
        "version": 1.0,
        "notes": "n",
        "description": "d",
        "is_read": False,
        "device_type": ["Cisco IOS XR"],
        "category": "DEVICE",
        "transport": "CLI",
        "tagList": [],
        "accessList": [],
        "configlet": "interface Loopback99",
        "variables": variables,
        "type": "USER_DEFINED_SIMPLE",
    }


def test_as_int_coerces_the_string_total_elements():
    assert as_int("2") == 2 and as_int(" 7 ") == 7 and as_int("1.0") == 1
    assert as_int(3) == 3 and as_int(1.0) == 1
    assert as_int(True) is None and as_int(None) is None and as_int("x") is None


def test_parse_statuses():
    assert parse_statuses("completed, FAILED,completed", ("COMPLETED", "FAILED"), "s") == [
        "COMPLETED",
        "FAILED",
    ]
    assert parse_statuses(None, ("A",), "s") == [] and parse_statuses(" , ", ("A",), "s") == []
    with pytest.raises(PlatformError, match="Unknown backup job status 'bogus'. Use one of: A"):
        parse_statuses("bogus", ("A",), "backup job status")


def test_parse_version():
    assert parse_version("1") == 1 and parse_version("1.0") == 1 and parse_version(" 2 ") == 2
    for bad in ("0", "1.5", "one", ""):
        with pytest.raises(PlatformError, match="version must be a whole number"):
            parse_version(bad)


def test_parse_deploy_variables_both_forms():
    assert parse_deploy_variables(None) == {} and parse_deploy_variables("  ") == {}
    assert parse_deploy_variables("interfaceName=Loopback99, description=a=b") == {
        "interfaceName": "Loopback99",
        "description": "a=b",
    }
    assert parse_deploy_variables('{"mtu": 1500, "shutdown": true, "desc": "x, y", "n": null}') == {
        "mtu": "1500",
        "shutdown": "true",
        "desc": "x, y",
        "n": "",
    }
    with pytest.raises(PlatformError, match="is not 'name=value'"):
        parse_deploy_variables("novalue")
    with pytest.raises(PlatformError, match="not a valid identifier"):
        parse_deploy_variables("bad name=1")
    with pytest.raises(PlatformError, match="not valid JSON"):
        parse_deploy_variables("{")
    with pytest.raises(PlatformError, match="must be a scalar"):
        parse_deploy_variables('{"x": [1]}')


def test_parse_template_variables_both_forms():
    assert parse_template_variables(None) == []
    comma = parse_template_variables("desc=mcp, mtu")
    assert comma == [
        {"name": "desc", "display_name": "desc", "type": "string", "default_value": "mcp",
         "description": "", "is_mandatory": False, "options": []},
        {"name": "mtu", "display_name": "mtu", "type": "string", "default_value": "",
         "description": "", "is_mandatory": False, "options": []},
    ]  # fmt: skip
    as_json = parse_template_variables(
        '[{"name": "ifname", "is_mandatory": true, "description": "Interface"}, '
        '{"name": "mtu", "default_value": 1500, "type": "integer"}]'
    )
    assert as_json[0] == {
        "name": "ifname", "display_name": "ifname", "type": "string", "default_value": "",
        "description": "Interface", "is_mandatory": True, "options": [],
    }  # fmt: skip
    assert as_json[1]["default_value"] == "1500" and as_json[1]["type"] == "integer"
    assert parse_template_variables('[{"name": "x", "is_mandatory": "true"}]')[0]["is_mandatory"]
    with pytest.raises(PlatformError, match="unknown key\\(s\\) defaultValue"):
        parse_template_variables('[{"name": "x", "defaultValue": "1"}]')
    with pytest.raises(PlatformError, match="defined twice"):
        parse_template_variables("a=1,a=2")
    with pytest.raises(PlatformError, match="not a valid identifier"):
        parse_template_variables("1bad=1")
    with pytest.raises(PlatformError, match="at least a 'name' key"):
        parse_template_variables('[{"default_value": "1"}]')
    with pytest.raises(PlatformError, match="not valid JSON"):
        parse_template_variables("[oops")


def test_configlet_references():
    assert configlet_references("interface ${a}\n#if($b == 'x')\n mtu ${a}\n#end $c.d") == [
        "a",
        "b",
        "c",
    ]
    assert configlet_references("") == []


def test_resolve_deploy_variables_defaults_mandatory_and_unknown():
    values, unset = resolve_deploy_variables(SYSTEM_TEMPLATE, {"interfaceName": "Loopback99"})
    assert values == {"interfaceName": "Loopback99", "description": "managed by CNC"}
    assert unset == ["shutdown"]
    values, _ = resolve_deploy_variables(
        SYSTEM_TEMPLATE, {"interfaceName": "Lo1", "shutdown": "true"}
    )
    assert values["shutdown"] == "true"
    with pytest.raises(
        PlatformError, match="requires a value for mandatory variable\\(s\\) interfaceName"
    ):
        resolve_deploy_variables(SYSTEM_TEMPLATE, {})
    with pytest.raises(
        PlatformError, match="has no variable\\(s\\) ghost; it defines: interfaceName"
    ):
        resolve_deploy_variables(SYSTEM_TEMPLATE, {"interfaceName": "x", "ghost": "1"})
    assert resolve_deploy_variables({"name": "t", "variables": []}, {}) == ({}, [])


def test_sort_backups_newest_first_and_job_helpers():
    assert [b["name"] for b in sort_backups(BACKUP_LIST["backup_config"])] == [
        BACKUP_NAME,
        "Initial_Version",
    ]
    assert job_of(JOB_DETAIL) == JOB and job_of(UNKNOWN_JOB) is None and job_of(None) is None
    assert runs_of(JOB_DETAIL) == [RUN] and runs_of(UNKNOWN_JOB) == []
    assert result_tail("short") == "short"
    long = "x" * (RESULT_TAIL_CHARS + 10)
    assert result_tail(long) == "..." + "x" * RESULT_TAIL_CHARS
    assert result_tail(None) == ""


# --- cnc_get_device_config_preferences ---------------------------------------


@respx.mock
async def test_get_preferences(settings):
    route = respx.get(PREFERENCES_URL).mock(return_value=httpx.Response(200, json=PREFERENCES))
    text = await call_tool_text(build(settings), "cnc_get_device_config_preferences", {})
    assert route.call_count == 1
    assert text.startswith("# Device configuration preferences\n\n- timeout: 120\n")
    assert "- max_backups_to_retain: 10" in text and "- is_nso_configured: True" in text
    assert json.loads(text[text.index("{") :]) == PREFERENCES


@respx.mock
async def test_get_preferences_api_error_is_string(make_settings):
    respx.get(PREFERENCES_URL).mock(
        return_value=httpx.Response(403, json={"error": "Unauthorized request"})
    )
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_device_config_preferences", {}
    )
    assert text.startswith("Error:") and "403" in text


# --- cnc_list_device_backups -------------------------------------------------


@respx.mock
async def test_list_device_backups_by_host_name_newest_first(settings):
    nodes = mock_nodes(ONE_NODE)
    route = respx.get(f"{CONFIG_BACKUP_URL}/{PE1_UUID}").mock(
        return_value=httpx.Response(200, json=BACKUP_LIST)
    )
    text = await call_tool_text(build(settings), "cnc_list_device_backups", {"host_name": "PE1"})
    assert sent(nodes) == query_of({"host_name": "PE1"}) and route.call_count == 1
    lines = text.split("\n")
    assert lines[0] == f"2 backup(s) for **PE1** ({PE1_UUID}), newest first:"
    assert lines[1] == (
        f"- **{BACKUP_NAME}**: 2026-09-13T12:00:06Z, SCHEDULED_JOB, SUCCESS, COMPLIANT"
    )
    assert lines[2] == "- **Initial_Version**: 2026-09-12T20:11:05Z, DEVICE_ADD, SUCCESS, COMPLIANT"
    assert "cnc_get_device_backup(name=...)" in text


@respx.mock
async def test_list_device_backups_json_by_uuid(settings):
    nodes = mock_nodes(UUID_NODE)
    respx.get(f"{CONFIG_BACKUP_URL}/{PE1_UUID}").mock(
        return_value=httpx.Response(200, json=BACKUP_LIST)
    )
    text = await call_tool_text(
        build(settings), "cnc_list_device_backups", {"uuid": PE1_UUID, "response_format": "json"}
    )
    assert sent(nodes) == query_of({"uuid": PE1_UUID})
    data = json.loads(text)
    assert data["device"] == {"host_name": "PE1", "uuid": PE1_UUID} and data["count"] == 2
    assert [b["name"] for b in data["backups"]] == [BACKUP_NAME, "Initial_Version"]
    assert data["backups"][0] == {
        "name": BACKUP_NAME, "backedup_at": "2026-09-13T12:00:06Z", "trigger": "SCHEDULED_JOB",
        "status": "SUCCESS", "complianceStatus": "COMPLIANT", "pinned": False, "tag": [],
        "notes": "", "result": "Backup by SCHEDULED_JOB", "created_by": "admin",
    }  # fmt: skip


@respx.mock
async def test_list_device_backups_empty_is_not_an_error(settings):
    mock_nodes(ONE_NODE)
    respx.get(f"{CONFIG_BACKUP_URL}/{PE1_UUID}").mock(
        return_value=httpx.Response(200, json=EMPTY_BACKUP_LIST)
    )
    text = await call_tool_text(build(settings), "cnc_list_device_backups", {"host_name": "PE1"})
    assert text.startswith(f"No backups for PE1 ({PE1_UUID}).")
    assert "cnc_backup_device_config" in text


@respx.mock
async def test_list_device_backups_zero_match_is_error(settings):
    mock_nodes(NO_NODES)
    route = respx.get(f"{CONFIG_BACKUP_URL}/{PE1_UUID}")
    text = await call_tool_text(build(settings), "cnc_list_device_backups", {"host_name": "ghost"})
    assert text.startswith("Error: no device matches host_name 'ghost'")
    assert route.call_count == 0


@respx.mock
async def test_list_device_backups_ambiguous_wildcard_is_error(settings):
    mock_nodes(TWO_NODES)
    text = await call_tool_text(build(settings), "cnc_list_device_backups", {"host_name": "P*"})
    assert text.startswith("Error: host_name 'P*' matched 2 devices (PE1, P1, ...)")


@pytest.mark.parametrize("args", [{}, {"uuid": PE1_UUID, "host_name": "PE1"}])
@respx.mock
async def test_list_device_backups_requires_exactly_one_selector(settings, args):
    nodes = mock_nodes(ONE_NODE)
    text = await call_tool_text(build(settings), "cnc_list_device_backups", args)
    assert text.startswith("Error:") and "exactly one" in text and nodes.call_count == 0


# --- cnc_get_device_backup ---------------------------------------------------


@respx.mock
async def test_get_device_backup_by_name_renders_masked_config(settings):
    mock_nodes(ONE_NODE)
    route = respx.get(f"{CONFIG_BACKUP_URL}/{PE1_UUID}/{BACKUP_NAME}").mock(
        return_value=httpx.Response(200, json=BACKUP_DETAIL)
    )
    text = await call_tool_text(
        build(settings), "cnc_get_device_backup", {"host_name": "PE1", "name": BACKUP_NAME}
    )
    assert route.call_count == 1
    assert text.startswith(f"# Backup {BACKUP_NAME} of PE1 ({PE1_UUID})\n")
    assert "- taken: 2026-09-13T12:00:06Z (SCHEDULED_JOB, SUCCESS, COMPLIANT)" in text
    assert f"- 1 file(s), {len(MASKED_CONFIG)} characters of configuration" in text
    assert "## file 1 (RUNNINGCONFIG)\n```\n" + MASKED_CONFIG + "\n```" in text
    assert "secret 10 ********" in text


@respx.mock
async def test_get_device_backup_latest_when_no_name_json(settings):
    mock_nodes(UUID_NODE)
    named = respx.get(f"{CONFIG_BACKUP_URL}/{PE1_UUID}/{BACKUP_NAME}")
    latest = respx.get(f"{LATEST_BACKUP_URL}/{PE1_UUID}").mock(
        return_value=httpx.Response(200, json=BACKUP_DETAIL)
    )
    text = await call_tool_text(
        build(settings), "cnc_get_device_backup", {"uuid": PE1_UUID, "response_format": "json"}
    )
    assert latest.call_count == 1 and named.call_count == 0
    assert json.loads(text) == BACKUP_DETAIL


@respx.mock
async def test_get_device_backup_name_is_url_encoded(settings):
    mock_nodes(ONE_NODE)
    route = respx.get(f"{CONFIG_BACKUP_URL}/{PE1_UUID}/pre%20change%2F1").mock(
        return_value=httpx.Response(200, json={**BACKUP_DETAIL, "name": "pre change/1"})
    )
    text = await call_tool_text(
        build(settings), "cnc_get_device_backup", {"host_name": "PE1", "name": "pre change/1"}
    )
    assert route.call_count == 1 and text.startswith("# Backup pre change/1 of PE1")


@respx.mock
async def test_get_device_backup_empty_200_is_not_found(settings):
    mock_nodes(ONE_NODE)
    # verified: an unknown backup name answers HTTP 200 with an EMPTY body
    respx.get(f"{CONFIG_BACKUP_URL}/{PE1_UUID}/ghost").mock(return_value=httpx.Response(200))
    text = await call_tool_text(
        build(settings), "cnc_get_device_backup", {"host_name": "PE1", "name": "ghost"}
    )
    assert text == (
        f"Error: no backup 'ghost' for PE1 ({PE1_UUID}) (list with cnc_list_device_backups)."
    )


@respx.mock
async def test_get_device_backup_latest_empty_is_error_saying_no_backup(settings):
    mock_nodes(ONE_NODE)
    respx.get(f"{LATEST_BACKUP_URL}/{PE1_UUID}").mock(return_value=httpx.Response(200))
    text = await call_tool_text(build(settings), "cnc_get_device_backup", {"host_name": "PE1"})
    assert text.startswith(f"Error: no backup for PE1 ({PE1_UUID}): the device has no stored")


@respx.mock
async def test_get_device_backup_zero_match_is_error(settings):
    mock_nodes(NO_NODES)
    text = await call_tool_text(build(settings), "cnc_get_device_backup", {"uuid": "nope"})
    assert text.startswith("Error: no device matches uuid 'nope'")


# --- cnc_list_config_backup_jobs ---------------------------------------------


@respx.mock
async def test_list_backup_jobs_sends_empty_body_and_renders_summary(settings):
    route = respx.post(JOBS_URL).mock(return_value=httpx.Response(200, json=JOBS_LIST))
    text = await call_tool_text(build(settings), "cnc_list_config_backup_jobs", {})
    assert sent(route) == {}
    lines = text.split("\n")
    assert lines[0] == (
        "1 backup/restore job(s) (scheduled 0, completed 1, failed 0, running 0, paused 0, "
        "blocked 0):"
    )
    assert lines[1] == (
        f"- **{JOB_NAME}** BACKUP: status COMPLETED, last run SUCCESS at "
        "2026-09-13T12:00:05.001Z (6007 ms), next run -, 1 device(s), by admin"
    )


@respx.mock
async def test_list_backup_jobs_status_filter_json(settings):
    route = respx.post(JOBS_URL).mock(return_value=httpx.Response(200, json=JOBS_LIST))
    text = await call_tool_text(
        build(settings),
        "cnc_list_config_backup_jobs",
        {"status": "running, scheduled", "response_format": "json"},
    )
    assert sent(route) == {"status": ["RUNNING", "SCHEDULED"]}
    data = json.loads(text)
    assert data["count"] == 1 and data["status_summary"] == STATUS_SUMMARY
    assert data["jobs"][0] == {
        "name": JOB_NAME, "job_type": "BACKUP", "status": "COMPLETED",
        "last_run_status": "SUCCESS", "last_run_at": "2026-09-13T12:00:05.001Z",
        "next_run_at": "1970-01-01T00:00:00Z", "duration_ms": 6007, "run_count": 1,
        "created_by": "admin", "device_count": 1,
    }  # fmt: skip
    assert data["page_summary"] == JOBS_LIST["page_summary"]


@respx.mock
async def test_list_backup_jobs_bad_status_is_error_before_any_call(settings):
    route = respx.post(JOBS_URL)
    text = await call_tool_text(build(settings), "cnc_list_config_backup_jobs", {"status": "DONE"})
    assert text.startswith("Error: Unknown backup job status 'DONE'. Use one of: SCHEDULED")
    assert route.call_count == 0


@respx.mock
async def test_list_backup_jobs_empty_and_api_error(make_settings):
    respx.post(JOBS_URL).mock(
        return_value=httpx.Response(200, json={"config_backup_restore_jobs": []})
    )
    text = await call_tool_text(build(make_settings()), "cnc_list_config_backup_jobs", {})
    assert text == "0 backup/restore job(s):\n- (none)"
    respx.post(JOBS_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_list_config_backup_jobs", {}
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_get_config_backup_job -----------------------------------------------


@respx.mock
async def test_get_backup_job_with_runs(settings):
    route = respx.post(f"{JOB_URL}/{JOB_NAME}").mock(
        return_value=httpx.Response(200, json=JOB_DETAIL)
    )
    text = await call_tool_text(build(settings), "cnc_get_config_backup_job", {"name": JOB_NAME})
    assert sent(route) == {}
    lines = text.split("\n")
    assert lines[0].startswith(f"- **{JOB_NAME}** BACKUP: status COMPLETED, last run SUCCESS")
    assert lines[1] == "1 run(s):"
    assert lines[2] == f"- run {RUN_ID}: SUCCESS, started 2026-09-13T12:00:05.001Z, 6007 ms"


@respx.mock
async def test_get_backup_job_json_and_url_encoding(settings):
    route = respx.post(f"{JOB_URL}/pre%20change").mock(
        return_value=httpx.Response(200, json=JOB_DETAIL)
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_config_backup_job",
        {"name": "pre change", "response_format": "json"},
    )
    assert route.call_count == 1
    data = json.loads(text)
    assert data["job"]["name"] == JOB_NAME and data["job"]["device_count"] == 1
    assert data["runs"] == [
        {"run_id": RUN_ID, "run_status": "SUCCESS", "start_at": "2026-09-13T12:00:05.001Z",
         "duration_ms": 6007}
    ]  # fmt: skip


@respx.mock
async def test_get_backup_job_unknown_is_not_found(settings):
    respx.post(f"{JOB_URL}/ghost").mock(return_value=httpx.Response(200, json=UNKNOWN_JOB))
    text = await call_tool_text(build(settings), "cnc_get_config_backup_job", {"name": "ghost"})
    assert text == "Error: no backup/restore job 'ghost' (cnc_list_config_backup_jobs lists them)."


# --- cnc_list_config_templates -----------------------------------------------


@respx.mock
async def test_list_templates_paging_and_filters(settings):
    route = respx.post(TEMPLATES_QUERY_URL).mock(
        return_value=httpx.Response(200, json=TEMPLATES_PAGE)
    )
    text = await call_tool_text(
        build(settings),
        "cnc_list_config_templates",
        {"name": "Interface", "template_type": "system", "page": 1, "size": 50},
    )
    request = route.calls[0].request
    assert dict(request.url.params) == {"page": "1", "size": "50"}
    assert json.loads(request.content) == {"filter": {"name": "Interface", "type": ["SYSTEM"]}}
    lines = text.split("\n")
    assert lines[0] == "2 of 2 template(s) (page 1):"
    assert lines[1] == (
        "- **Cisco_IOS-XR_Interface_config** v1.0 SYSTEM/INTERFACE/CLI — Configure an interface "
        "on IOS XR; 3 variable(s); last deployed: NOT_DEPLOYED; by system"
    )
    assert lines[2].startswith("- **mcp-loopback99** v1.0 USER_DEFINED_SIMPLE/DEVICE/CLI")


@respx.mock
async def test_list_templates_json_coerces_string_total(settings):
    route = respx.post(TEMPLATES_QUERY_URL).mock(
        return_value=httpx.Response(200, json={**TEMPLATES_PAGE, "total_elements": "41"})
    )
    text = await call_tool_text(
        build(settings), "cnc_list_config_templates", {"response_format": "json"}
    )
    assert sent(route) == {"filter": {}}
    assert dict(route.calls[0].request.url.params) == {"page": "0", "size": "20"}
    data = json.loads(text)
    assert data["total"] == 41 and data["count"] == 2 and data["page"] == 0
    assert data["page_size"] == 20 and data["has_more"] is True and data["next_page"] == 1
    assert data["total_pages"] == 1 and "collection_total" not in data
    assert data["items"][0]["variables"] == 3 and data["items"][1]["name"] == "mcp-loopback99"


@respx.mock
async def test_list_templates_more_pages_note_and_bad_type(settings):
    route = respx.post(TEMPLATES_QUERY_URL).mock(
        return_value=httpx.Response(200, json={**TEMPLATES_PAGE, "total_elements": "3"})
    )
    text = await call_tool_text(build(settings), "cnc_list_config_templates", {"size": 2})
    assert text.endswith("More templates: call again with page=1.")
    text = await call_tool_text(
        build(settings), "cnc_list_config_templates", {"template_type": "COMPOSITE"}
    )
    assert text.startswith("Error: Unknown template type 'COMPOSITE'. Use one of: SYSTEM")
    assert route.call_count == 1


@respx.mock
async def test_list_templates_api_error_is_string(make_settings):
    respx.post(TEMPLATES_QUERY_URL).mock(
        return_value=httpx.Response(403, json={"error": "Unauthorized request"})
    )
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_list_config_templates", {}
    )
    assert text.startswith("Error:") and "403" in text


# --- cnc_get_config_template -------------------------------------------------


@respx.mock
async def test_get_template_renders_variables_table_and_configlet(settings):
    route = respx.get(f"{TEMPLATES_URL}/Cisco_IOS-XR_Interface_config").mock(
        return_value=httpx.Response(200, json={"templates": [SYSTEM_TEMPLATE]})
    )
    text = await call_tool_text(
        build(settings), "cnc_get_config_template", {"name": "Cisco_IOS-XR_Interface_config"}
    )
    assert dict(route.calls[0].request.url.params) == {"all": "false"}
    assert text.startswith("# Template Cisco_IOS-XR_Interface_config v1.0\n")
    assert "- type SYSTEM, category INTERFACE, transport CLI, by system, created" in text
    assert "- device types: Cisco IOS XR" in text
    assert "| interfaceName | string | - | yes |" in text
    assert "| description | string | managed by CNC | no |" in text
    assert text.endswith("```\n" + SYSTEM_TEMPLATE["configlet"] + "\n```")


@respx.mock
async def test_get_template_all_versions_json_and_url_encoding(settings):
    route = respx.get(f"{TEMPLATES_URL}/my%20template").mock(
        return_value=httpx.Response(
            200, json={"templates": [USER_TEMPLATE, {**USER_TEMPLATE, "version": 2.0}]}
        )
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_config_template",
        {"name": "my template", "all_versions": True, "response_format": "json"},
    )
    assert dict(route.calls[0].request.url.params) == {"all": "true"}
    data = json.loads(text)
    assert data["count"] == 2 and data["templates"][1]["version"] == 2.0


@respx.mock
async def test_get_template_unknown_is_not_found(settings):
    respx.get(f"{TEMPLATES_URL}/ghost").mock(return_value=httpx.Response(200, json=NO_TEMPLATE))
    text = await call_tool_text(build(settings), "cnc_get_config_template", {"name": "ghost"})
    assert text == "Error: no template 'ghost' (cnc_list_config_templates lists them)."


# --- cnc_list_template_deployments -------------------------------------------


@respx.mock
async def test_list_deployments_empty_body_and_lines(settings):
    route = respx.post(DEPLOYMENTS_QUERY_URL).mock(
        return_value=httpx.Response(200, json=DEPLOYMENT_JOBS)
    )
    text = await call_tool_text(build(settings), "cnc_list_template_deployments", {})
    assert sent(route) == {}
    assert text == (
        "1 template deployment(s):\n"
        f"- **{DEPLOYMENT_ID}**: last run SUCCESS at 2026-09-13T12:05:00.001Z (4120 ms), "
        "status COMPLETED, by admin, runs 1"
    )


@respx.mock
async def test_list_deployments_status_filter_json(settings):
    route = respx.post(DEPLOYMENTS_QUERY_URL).mock(
        return_value=httpx.Response(200, json=DEPLOYMENT_JOBS)
    )
    text = await call_tool_text(
        build(settings),
        "cnc_list_template_deployments",
        {"status": "run_failed,PARTIAL", "response_format": "json"},
    )
    assert sent(route) == {"last_run_status": ["RUN_FAILED", "PARTIAL"]}
    data = json.loads(text)
    assert data["count"] == 1 and data["deployments"][0]["name"] == DEPLOYMENT_ID
    assert data["deployments"][0]["last_run_status"] == "SUCCESS"


@respx.mock
async def test_list_deployments_accepts_every_documented_run_status(settings):
    """JobRunStatus is NOT_STARTED | SUCCESS | IN_PROGRESS | RUN_FAILED | PARTIAL (documented);
    a just-scheduled deployment (NOT_STARTED) must be filterable too."""
    route = respx.post(DEPLOYMENTS_QUERY_URL).mock(
        return_value=httpx.Response(200, json={"jobs": [], "page_summary": {}})
    )
    text = await call_tool_text(
        build(settings), "cnc_list_template_deployments", {"status": "not_started"}
    )
    assert sent(route) == {"last_run_status": ["NOT_STARTED"]}
    assert text.startswith("0 template deployment(s) with last run NOT_STARTED:")


@respx.mock
async def test_list_deployments_bad_status_is_error(settings):
    route = respx.post(DEPLOYMENTS_QUERY_URL)
    text = await call_tool_text(
        build(settings), "cnc_list_template_deployments", {"status": "FAILED"}
    )
    assert text.startswith(
        "Error: Unknown deployment status 'FAILED'. Use one of: NOT_STARTED, SUCCESS"
    )
    assert route.call_count == 0


# --- cnc_get_template_deployment ---------------------------------------------


@respx.mock
async def test_get_deployment_renders_transcript(settings):
    route = respx.post(f"{DEPLOY_URL}/{DEPLOYMENT_ID}/query").mock(
        return_value=httpx.Response(200, json=DEPLOYMENT_DETAIL)
    )
    text = await call_tool_text(
        build(settings), "cnc_get_template_deployment", {"deployment_id": DEPLOYMENT_ID}
    )
    # Body {} (verified) with the documented page/size query (one page holds the 100-device
    # cap of cnc_deploy_config_template); total_elements == len(details) -> one request.
    assert sent(route) == {} and pages_requested(route) == [("0", "100")]
    assert text.startswith(f"# Deployment {DEPLOYMENT_ID}\n\n1 device(s): 1 SUCCESS\n")
    assert "## PE1 — SUCCESS (deployed 2026-09-13T12:05:03Z, 4120 ms)" in text
    assert "deployed configlet:\n```\ninterface Loopback99\n description mcp\n```" in text
    assert "result (CLI transcript):\n```\n" + TRANSCRIPT + "\n```" in text


@respx.mock
async def test_get_deployment_json_maps_hostname(settings):
    respx.post(f"{DEPLOY_URL}/{DEPLOYMENT_ID}/query").mock(
        return_value=httpx.Response(200, json=DEPLOYMENT_FAILED)
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_template_deployment",
        {"deployment_id": DEPLOYMENT_ID, "response_format": "json"},
    )
    data = json.loads(text)
    assert data["count"] == 2 and data["total"] == 2
    assert [(d["device"], d["status"]) for d in data["details"]] == [
        ("PE1", "SUCCESS"),
        ("P1", "FAILED"),
    ]
    assert data["details"][1]["result"] == "% Invalid input detected"


@respx.mock
async def test_get_deployment_follows_total_elements_across_pages(settings):
    """total_elements > len(details) on the first page -> the next pages are read too, so a
    deployment larger than one page is never silently truncated."""
    route = paged_deployment_route(f"{DEPLOY_URL}/{DEPLOYMENT_ID}/query", PAGE_0_OF_2, PAGE_1_OF_2)
    text = await call_tool_text(
        build(settings),
        "cnc_get_template_deployment",
        {"deployment_id": DEPLOYMENT_ID, "response_format": "json"},
    )
    assert pages_requested(route) == [("0", "100"), ("1", "100")]
    data = json.loads(text)
    assert data["count"] == 2 and data["total"] == 2
    assert [d["device"] for d in data["details"]] == ["PE1", "P1"]


@respx.mock
async def test_get_deployment_reports_partial_read_when_paging_is_ignored(settings):
    """A platform that ignores ``page`` answers the same devices again: the walk stops
    (nothing new) and the answer says how many devices Crosswork counts but did not show."""
    route = paged_deployment_route(f"{DEPLOY_URL}/{DEPLOYMENT_ID}/query", PAGE_0_OF_2)
    text = await call_tool_text(
        build(settings), "cnc_get_template_deployment", {"deployment_id": DEPLOYMENT_ID}
    )
    assert pages_requested(route) == [("0", "100"), ("1", "100")]
    assert text.startswith(f"# Deployment {DEPLOYMENT_ID}\n\n1 of 2 device(s): 1 SUCCESS\n")
    assert "(Crosswork reports 2 devices in this deployment but answered only 1;" in text
    data = json.loads(
        await call_tool_text(
            build(settings),
            "cnc_get_template_deployment",
            {"deployment_id": DEPLOYMENT_ID, "response_format": "json"},
        )
    )
    assert data["count"] == 1 and data["total"] == 2


@respx.mock
async def test_get_deployment_unknown_is_not_found(settings):
    respx.post(f"{DEPLOY_URL}/ghost/query").mock(
        return_value=httpx.Response(200, json=NO_DEPLOYMENT)
    )
    text = await call_tool_text(
        build(settings), "cnc_get_template_deployment", {"deployment_id": "ghost"}
    )
    assert text == "Error: no deployment 'ghost' (cnc_list_template_deployments lists them)."


# --- cnc_backup_device_config ------------------------------------------------


@respx.mock
async def test_backup_device_config_body_and_next(writes, fixed_now):
    nodes = mock_nodes(ONE_NODE)
    route = respx.post(SCHEDULE_URL).mock(return_value=httpx.Response(202, json=BACKUP_ACCEPTED))
    text = await call_tool_text(build(writes), "cnc_backup_device_config", {"host_name": "PE1"})
    assert sent(nodes) == query_of({"host_name": "PE1"})
    assert sent(route) == {
        "name": "mcp-backup-20260913-120000",
        "trigger": "SCHEDULED_JOB",
        "schedule": {"start_at_time": "2026-09-13T12:00:05.000Z"},
        "device_uuids": {"device_uuids": [PE1_UUID]},
    }
    data = json.loads(text)
    assert data["job_id"] == JOB_NAME and data["job_name"] == JOB_NAME
    assert data["status_code"] == 202 and data["message"] == BACKUP_ACCEPTED["message"]
    assert data["start_at_time"] == "2026-09-13T12:00:05.000Z"
    assert data["devices"] == [{"host_name": "PE1", "uuid": PE1_UUID}]
    assert data["next"].startswith(f"cnc_wait_for_config_backup_job(name='{JOB_NAME}')")


@respx.mock
async def test_backup_device_config_wildcard_custom_name_and_delay(writes, fixed_now):
    mock_nodes(TWO_NODES)
    route = respx.post(SCHEDULE_URL).mock(
        return_value=httpx.Response(202, json={**BACKUP_ACCEPTED, "job_id": "pre-change"})
    )
    text = await call_tool_text(
        build(writes),
        "cnc_backup_device_config",
        {"host_name": "*", "job_name": " pre-change ", "delay_seconds": 90},
    )
    body = sent(route)
    assert body["name"] == "pre-change"
    assert body["schedule"] == {"start_at_time": "2026-09-13T12:01:30.000Z"}
    assert body["device_uuids"] == {"device_uuids": [PE1_UUID, P1_UUID]}
    data = json.loads(text)
    assert [d["host_name"] for d in data["devices"]] == ["PE1", "P1"]


@respx.mock
async def test_backup_device_config_zero_match_sends_nothing(writes):
    mock_nodes(NO_NODES)
    route = respx.post(SCHEDULE_URL)
    text = await call_tool_text(build(writes), "cnc_backup_device_config", {"host_name": "ghost"})
    assert text.startswith("Error: no device matches host_name 'ghost'; nothing was sent.")
    assert route.call_count == 0


@respx.mock
async def test_backup_device_config_duplicate_job_is_error_with_hint(writes):
    mock_nodes(ONE_NODE)
    respx.post(SCHEDULE_URL).mock(return_value=httpx.Response(500, json=BACKUP_DUPLICATE))
    text = await call_tool_text(
        build(writes), "cnc_backup_device_config", {"host_name": "PE1", "job_name": JOB_NAME}
    )
    assert text.startswith(
        f"Error: backup job '{JOB_NAME}' was not created: Job already exists with name {JOB_NAME}."
    )
    assert "Pick another job_name" in text and "cnc_delete_config_backup_job" in text


@respx.mock
async def test_backup_device_config_other_error_and_no_retry(writes_retrying):
    """The scheduling POST is a non-idempotent write: with max_retries=2 a 503 is still sent
    exactly once (a lost answer must not schedule the job twice)."""
    mock_nodes(ONE_NODE)
    route = respx.post(SCHEDULE_URL).mock(return_value=httpx.Response(503, text="busy"))
    text = await call_tool_text(
        build(writes_retrying), "cnc_backup_device_config", {"host_name": "PE1"}
    )
    assert text.startswith("Error: API request failed with status 503")
    assert route.call_count == 1


@respx.mock
async def test_backup_device_config_too_many_matches_is_refused(writes):
    many = {"data": [node(f"u{i}", f"D{i}") for i in range(100)], "total_count": 250,
            "result_count": 250}  # fmt: skip
    mock_nodes(many)
    route = respx.post(SCHEDULE_URL)
    text = await call_tool_text(build(writes), "cnc_backup_device_config", {"host_name": "*"})
    assert text.startswith("Error: host_name '*' matches 250 devices, more than the 100")
    assert route.call_count == 0


# --- cnc_wait_for_config_backup_job ------------------------------------------


@respx.mock
async def test_wait_for_backup_job_polls_until_success(settings, fake_clock):
    route = mock_sequence(
        "POST", f"{JOB_URL}/{JOB_NAME}", UNKNOWN_JOB, JOB_DETAIL_RUNNING, JOB_DETAIL
    )
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_config_backup_job",
        {"name": JOB_NAME, "timeout_seconds": 60, "interval_seconds": 5},
    )
    assert route.call_count == 3 and sent(route) == {}
    assert text.startswith(f"Backup job {JOB_NAME} finished SUCCESS after 10s (1 run(s)).")
    data = json.loads(text[text.index("{") :])
    assert data["job"]["last_run_status"] == "SUCCESS" and data["elapsed_seconds"] == 10
    assert data["runs"][0]["run_id"] == RUN_ID


@respx.mock
async def test_wait_for_backup_job_run_failed_is_error_with_runs(settings, fake_clock):
    route = mock_sequence("POST", f"{JOB_URL}/{JOB_NAME}", JOB_DETAIL_RUNNING, JOB_DETAIL_FAILED)
    text = await call_tool_text(
        build(settings), "cnc_wait_for_config_backup_job", {"name": JOB_NAME}
    )
    assert route.call_count == 2
    assert text.startswith(
        f"Error: backup job {JOB_NAME} failed after 5s (last_run_status RUN_FAILED): run "
        f"{RUN_ID}: RUN_FAILED, started 2026-09-13T12:00:05.001Z, 6007 ms."
    )
    assert "cnc_list_device_backups" in text and '"last_run_status": "RUN_FAILED"' in text


@respx.mock
async def test_wait_for_backup_job_partial_is_error(settings, fake_clock):
    partial = {
        "config_backup_restore_job": {
            "job": {**JOB, "last_run_status": "PARTIAL"},
            "device_count": 2,
        },
        "job_runs": {"backup_job_run": [{**RUN, "run_status": "PARTIAL"}]},
    }
    mock_sequence("POST", f"{JOB_URL}/{JOB_NAME}", partial)
    text = await call_tool_text(
        build(settings), "cnc_wait_for_config_backup_job", {"name": JOB_NAME}
    )
    assert text.startswith(f"Error: backup job {JOB_NAME} finished PARTIAL after 0s")


@respx.mock
async def test_wait_for_backup_job_timeout_is_not_an_error(settings, fake_clock):
    route = mock_sequence("POST", f"{JOB_URL}/{JOB_NAME}", JOB_DETAIL_RUNNING)
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_config_backup_job",
        {"name": JOB_NAME, "timeout_seconds": 10, "interval_seconds": 10},
    )
    assert route.call_count == 2 and not text.startswith("Error:")
    assert text.startswith(
        f"Backup job {JOB_NAME} not finished after 10s; status RUNNING, last run IN_PROGRESS."
    )
    assert '"last_run_status": "IN_PROGRESS"' in text


@respx.mock
async def test_wait_for_backup_job_still_unknown_at_timeout_says_not_found_yet(
    settings, fake_clock
):
    route = mock_sequence("POST", f"{JOB_URL}/ghost", UNKNOWN_JOB)
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_config_backup_job",
        {"name": "ghost", "timeout_seconds": 10, "interval_seconds": 5},
    )
    assert route.call_count == 3 and not text.startswith("Error:")
    assert text.startswith("Backup job ghost not found (yet) after 10s")
    assert "cnc_list_config_backup_jobs" in text
    head, _, body = text.partition("\n")
    assert head.endswith("check the name with cnc_list_config_backup_jobs.")
    assert json.loads(body) == {"job": None, "runs": [], "elapsed_seconds": 10}


@respx.mock
async def test_wait_for_backup_job_api_error_is_string(make_settings, fake_clock):
    respx.post(f"{JOB_URL}/{JOB_NAME}").mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_wait_for_config_backup_job", {"name": JOB_NAME}
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_delete_config_backup_job --------------------------------------------


@respx.mock
async def test_delete_backup_job_204_and_url_encoding(writes):
    route = respx.delete(f"{RESTORE_JOB_URL}/pre%20change").mock(return_value=httpx.Response(204))
    text = await call_tool_text(
        build(writes), "cnc_delete_config_backup_job", {"name": "pre change"}
    )
    assert route.call_count == 1 and not route.calls[0].request.content
    assert text.startswith("Backup/restore job 'pre change' deleted (HTTP 204).")
    assert "answers 204 for an unknown name too" in text
    assert json.loads(text[text.index("{") :]) == {"job_name": "pre change", "status_code": 204}


@respx.mock
async def test_delete_backup_job_api_error_is_string(writes):
    respx.delete(f"{RESTORE_JOB_URL}/{JOB_NAME}").mock(
        return_value=httpx.Response(403, json={"error": "Unauthorized request"})
    )
    text = await call_tool_text(build(writes), "cnc_delete_config_backup_job", {"name": JOB_NAME})
    assert text.startswith("Error:") and "403" in text


# --- cnc_delete_device_backup ------------------------------------------------


@respx.mock
async def test_delete_device_backup_ok_text(writes):
    nodes = mock_nodes(ONE_NODE)
    route = respx.delete(f"{CONFIG_BACKUP_URL}/{PE1_UUID}/{BACKUP_NAME}").mock(
        return_value=httpx.Response(200, text=DELETE_BACKUP_OK)
    )
    text = await call_tool_text(
        build(writes), "cnc_delete_device_backup", {"host_name": "PE1", "name": BACKUP_NAME}
    )
    assert sent(nodes) == query_of({"host_name": "PE1"}) and route.call_count == 1
    assert text.startswith(f"Deleted backup '{BACKUP_NAME}' of PE1 ({PE1_UUID}).")
    data = json.loads(text[text.index("{") :])
    assert data == {
        "device": {"host_name": "PE1", "uuid": PE1_UUID},
        "backup": BACKUP_NAME,
        "message": DELETE_BACKUP_OK,
    }


@respx.mock
async def test_delete_device_backup_not_found_500_text(writes):
    mock_nodes(UUID_NODE)
    respx.delete(f"{CONFIG_BACKUP_URL}/{PE1_UUID}/ghost").mock(
        return_value=httpx.Response(500, text=DELETE_BACKUP_NOT_FOUND)
    )
    text = await call_tool_text(
        build(writes), "cnc_delete_device_backup", {"uuid": PE1_UUID, "name": "ghost"}
    )
    assert text.startswith(f"Error: no backup 'ghost' for PE1 ({PE1_UUID}) (list with")
    assert f"Platform said: {DELETE_BACKUP_NOT_FOUND}" in text


@respx.mock
async def test_delete_device_backup_zero_match_sends_nothing(writes):
    mock_nodes(NO_NODES)
    route = respx.delete(f"{CONFIG_BACKUP_URL}/{PE1_UUID}/{BACKUP_NAME}")
    text = await call_tool_text(
        build(writes), "cnc_delete_device_backup", {"host_name": "ghost", "name": BACKUP_NAME}
    )
    assert text.startswith("Error: no device matches host_name 'ghost'")
    assert route.call_count == 0


@respx.mock
async def test_delete_device_backup_other_500_is_generic_error(writes):
    mock_nodes(ONE_NODE)
    respx.delete(f"{CONFIG_BACKUP_URL}/{PE1_UUID}/{BACKUP_NAME}").mock(return_value=NATS_500)
    text = await call_tool_text(
        build(writes), "cnc_delete_device_backup", {"host_name": "PE1", "name": BACKUP_NAME}
    )
    assert text.startswith("Error: API request failed with status 500")


# --- cnc_create_config_template ----------------------------------------------


@respx.mock
async def test_create_template_body_204(writes):
    route = respx.post(TEMPLATES_URL).mock(return_value=httpx.Response(204))
    text = await call_tool_text(
        build(writes),
        "cnc_create_config_template",
        {
            "name": "mcp-loopback99",
            "configlet": "interface Loopback99\n description ${desc}",
            "description": "Adds Loopback99",
            "variables": "desc=mcp",
            "device_types": "Cisco IOS XR",
        },
    )
    assert sent(route) == {
        "name": "mcp-loopback99",
        "version": 1.0,
        "notes": "Initial version",
        "description": "Adds Loopback99",
        "is_read": False,
        "device_type": ["Cisco IOS XR"],
        "category": "DEVICE",
        "transport": "CLI",
        "tagList": [],
        "accessList": [],
        "configlet": "interface Loopback99\n description ${desc}",
        "variables": [
            {
                "name": "desc",
                "display_name": "desc",
                "type": "string",
                "default_value": "mcp",
                "description": "",
                "is_mandatory": False,
                "options": [],
            }
        ],  # fmt: skip
        "type": "USER_DEFINED_SIMPLE",
    }
    data = json.loads(text)
    assert data["created"] is True and data["warnings"] == []
    assert data["template"]["name"] == "mcp-loopback99" and data["template"]["version"] == 1.0
    assert data["template"]["variables"][0]["name"] == "desc"
    assert data["next"].startswith("cnc_deploy_config_template(name='mcp-loopback99'")


@respx.mock
async def test_create_template_json_variables_interface_and_warning(writes):
    route = respx.post(TEMPLATES_URL).mock(return_value=httpx.Response(204))
    text = await call_tool_text(
        build(writes),
        "cnc_create_config_template",
        {
            "name": "mcp-if",
            "configlet": "interface ${ifname}\n mtu ${mtu}\n description ${undeclared}",
            "category": "interface",
            "variables": (
                '[{"name": "ifname", "is_mandatory": true}, {"name": "mtu", "default_value": 1500}]'
            ),
        },
    )
    body = sent(route)
    assert body["category"] == "INTERFACE" and body["device_type"] == []
    assert [(v["name"], v["is_mandatory"], v["default_value"]) for v in body["variables"]] == [
        ("ifname", True, ""),
        ("mtu", False, "1500"),
    ]
    data = json.loads(text)
    assert data["warnings"] == [
        "the configlet references ${undeclared} but no variable named 'undeclared' is defined"
    ]


@respx.mock
async def test_create_template_duplicate_is_error_with_hint(writes):
    respx.post(TEMPLATES_URL).mock(return_value=httpx.Response(400, json=TEMPLATE_DUPLICATE))
    text = await call_tool_text(
        build(writes),
        "cnc_create_config_template",
        {"name": "mcp-loopback99", "configlet": "interface Loopback99"},
    )
    assert text.startswith(
        "Error: template 'mcp-loopback99' was not created: Template mcp-loopback99 already "
        "present. List the existing templates with cnc_list_config_templates"
    )
    assert "cnc_delete_config_template" in text


@pytest.mark.parametrize(
    ("args", "marker"),
    [
        ({"category": "CHASSIS"}, "Unknown template category 'CHASSIS'"),
        ({"transport": "SSH"}, "Unknown transport 'SSH'"),
        ({"variables": "a=1,a=2"}, "variable 'a' is defined twice"),
        ({"variables": "[oops"}, "variables is not valid JSON"),
    ],
)
@respx.mock
async def test_create_template_bad_input_sends_nothing(writes, args, marker):
    route = respx.post(TEMPLATES_URL)
    text = await call_tool_text(
        build(writes),
        "cnc_create_config_template",
        {"name": "t", "configlet": "x", **args},
    )
    assert text.startswith("Error:") and marker in text
    assert route.call_count == 0


@pytest.mark.parametrize(
    ("args", "key", "value"),
    [
        ({"category": "module"}, "category", "MODULE"),
        ({"transport": "netconf"}, "transport", "NETCONF"),
        ({"transport": "gnmi"}, "transport", "GNMI"),
    ],
)
@respx.mock
async def test_create_template_accepts_every_documented_enum_value(writes, args, key, value):
    """Documented-but-unverified enum values (TemplateCategory MODULE, Transport GNMI /
    NETCONF) are accepted and sent upper-cased — the same rule for every enum here."""
    route = respx.post(TEMPLATES_URL).mock(return_value=httpx.Response(204))
    text = await call_tool_text(
        build(writes), "cnc_create_config_template", {"name": "t", "configlet": "x", **args}
    )
    assert sent(route)[key] == value
    assert json.loads(text)["template"][key] == value


@respx.mock
async def test_create_template_other_error_not_retried(writes_retrying):
    """POST templates is not auto-retried even with max_retries=2."""
    route = respx.post(TEMPLATES_URL).mock(return_value=httpx.Response(503, text="busy"))
    text = await call_tool_text(
        build(writes_retrying), "cnc_create_config_template", {"name": "t", "configlet": "x"}
    )
    assert text.startswith("Error: API request failed with status 503") and route.call_count == 1


# --- cnc_delete_config_template ----------------------------------------------


@respx.mock
async def test_delete_template_body_204(writes):
    route = respx.delete(TEMPLATES_URL).mock(return_value=httpx.Response(204))
    text = await call_tool_text(
        build(writes), "cnc_delete_config_template", {"name": " mcp-loopback99 "}
    )
    assert sent(route) == {"templateName": ["mcp-loopback99"]}
    assert text.startswith("Template 'mcp-loopback99' deleted (HTTP 204).")
    assert json.loads(text[text.index("{") :]) == {"template": "mcp-loopback99", "status_code": 204}


@respx.mock
async def test_delete_template_failed_500_is_error_with_sequence(writes):
    respx.delete(TEMPLATES_URL).mock(return_value=httpx.Response(500, json=TEMPLATE_DELETE_FAILED))
    text = await call_tool_text(
        build(writes), "cnc_delete_config_template", {"name": "mcp-loopback99"}
    )
    assert text.startswith(
        "Error: template 'mcp-loopback99' could not be deleted (unknown, a SYSTEM template, or "
        "still referenced by a deployment — delete the deployment first"
    )
    assert "cnc_delete_template_deployment" in text
    assert "Platform said: Failed to delete templates : [mcp-loopback99]" in text


@respx.mock
async def test_delete_template_other_error_is_string(writes):
    respx.delete(TEMPLATES_URL).mock(
        return_value=httpx.Response(403, json={"error": "Unauthorized request"})
    )
    text = await call_tool_text(build(writes), "cnc_delete_config_template", {"name": "t"})
    assert text.startswith("Error: API request failed with status 403")


# --- cnc_deploy_config_template ----------------------------------------------


def mock_template(*templates: dict, name: str = "mcp-loopback99") -> respx.Route:
    return respx.get(f"{TEMPLATES_URL}/{name}").mock(
        return_value=httpx.Response(200, json={"templates": list(templates)})
    )


@respx.mock
async def test_deploy_template_body_and_next(writes):
    template = mock_template(USER_TEMPLATE)
    nodes = mock_nodes(ONE_NODE)
    route = respx.post(DEPLOY_URL).mock(return_value=httpx.Response(202, json=DEPLOY_ACCEPTED))
    text = await call_tool_text(
        build(writes),
        "cnc_deploy_config_template",
        {"name": "mcp-loopback99", "host_name": "PE1", "variables": "desc=lab"},
    )
    assert dict(template.calls[0].request.url.params) == {"all": "true"}
    assert sent(nodes) == query_of({"host_name": "PE1"})
    assert sent(route) == {
        "template_name": "mcp-loopback99",
        "version": "1",
        "device_uuids": {"device_uuids": [PE1_UUID]},
        "details": [
            {"version": 1, "device_uuid": "GLOBAL", "variables": [{"name": "desc", "value": "lab"}]}
        ],
        "additional_params": {"backup_before_deploy": True, "rollback_on_failure": False},
    }
    data = json.loads(text)
    assert data["deployment_id"] == DEPLOYMENT_ID and data["template"] == "mcp-loopback99"
    assert data["version"] == 1 and data["variables"] == {"desc": "lab"}
    assert data["unset_variables"] == [] and data["message"] == "Deployment scheduled"
    assert data["devices"] == [{"host_name": "PE1", "uuid": PE1_UUID}]
    assert data["next"].startswith(
        f"cnc_wait_for_template_deployment(deployment_id='{DEPLOYMENT_ID}')"
    )
    assert "no undo" in data["next"]


@respx.mock
async def test_deploy_template_wildcard_defaults_and_flags(writes):
    mock_template(USER_TEMPLATE)
    mock_nodes(TWO_NODES)
    route = respx.post(DEPLOY_URL).mock(return_value=httpx.Response(202, json=DEPLOY_ACCEPTED))
    text = await call_tool_text(
        build(writes),
        "cnc_deploy_config_template",
        {
            "name": "mcp-loopback99",
            "host_name": "*",
            "backup_before_deploy": False,
            "rollback_on_failure": True,
        },
    )
    body = sent(route)
    assert body["device_uuids"] == {"device_uuids": [PE1_UUID, P1_UUID]}
    # the template's default_value fills a variable the caller did not pass
    assert body["details"][0]["variables"] == [{"name": "desc", "value": "mcp"}]
    assert body["additional_params"] == {"backup_before_deploy": False, "rollback_on_failure": True}
    data = json.loads(text)
    assert [d["host_name"] for d in data["devices"]] == ["PE1", "P1"]


@respx.mock
async def test_deploy_template_system_template_mandatory_and_unset(writes):
    mock_template(SYSTEM_TEMPLATE, name="Cisco_IOS-XR_Interface_config")
    mock_nodes(UUID_NODE)
    route = respx.post(DEPLOY_URL).mock(return_value=httpx.Response(202, json=DEPLOY_ACCEPTED))
    text = await call_tool_text(
        build(writes),
        "cnc_deploy_config_template",
        {
            "name": "Cisco_IOS-XR_Interface_config",
            "uuid": PE1_UUID,
            "variables": '{"interfaceName": "Loopback99"}',
        },
    )
    assert sent(route)["details"][0]["variables"] == [
        {"name": "interfaceName", "value": "Loopback99"},
        {"name": "description", "value": "managed by CNC"},
    ]
    assert json.loads(text)["unset_variables"] == ["shutdown"]


@respx.mock
async def test_deploy_template_missing_mandatory_variable_is_refused_before_post(writes):
    mock_template(SYSTEM_TEMPLATE, name="Cisco_IOS-XR_Interface_config")
    nodes = mock_nodes(ONE_NODE)
    route = respx.post(DEPLOY_URL)
    text = await call_tool_text(
        build(writes),
        "cnc_deploy_config_template",
        {"name": "Cisco_IOS-XR_Interface_config", "host_name": "PE1"},
    )
    assert text.startswith(
        "Error: template 'Cisco_IOS-XR_Interface_config' requires a value for mandatory "
        "variable(s) interfaceName (no default); pass variables='interfaceName=<value>'. "
        "Nothing was deployed."
    )
    assert route.call_count == 0 and nodes.call_count == 0


@respx.mock
async def test_deploy_template_unknown_variable_is_refused(writes):
    mock_template(USER_TEMPLATE)
    route = respx.post(DEPLOY_URL)
    text = await call_tool_text(
        build(writes),
        "cnc_deploy_config_template",
        {"name": "mcp-loopback99", "host_name": "PE1", "variables": "desc=x,ghost=1"},
    )
    assert text.startswith(
        "Error: template 'mcp-loopback99' has no variable(s) ghost; it defines: desc."
    )
    assert route.call_count == 0


@respx.mock
async def test_deploy_template_unknown_template_is_error(writes):
    mock_template(name="ghost")
    nodes = mock_nodes(ONE_NODE)
    route = respx.post(DEPLOY_URL)
    text = await call_tool_text(
        build(writes), "cnc_deploy_config_template", {"name": "ghost", "host_name": "PE1"}
    )
    assert text.startswith("Error: no template 'ghost' (cnc_list_config_templates lists them)")
    assert route.call_count == 0 and nodes.call_count == 0


@respx.mock
async def test_deploy_template_unknown_version_is_error(writes):
    mock_template(USER_TEMPLATE, {**USER_TEMPLATE, "version": 2.0})
    route = respx.post(DEPLOY_URL)
    text = await call_tool_text(
        build(writes),
        "cnc_deploy_config_template",
        {"name": "mcp-loopback99", "host_name": "PE1", "version": "3"},
    )
    assert text.startswith(
        "Error: template 'mcp-loopback99' has no version 3 (stored: 1, 2); nothing was deployed."
    )
    assert route.call_count == 0


@respx.mock
async def test_deploy_template_picks_the_requested_version(writes):
    mock_template(USER_TEMPLATE, {**USER_TEMPLATE, "version": 2.0, "variables": []})
    mock_nodes(ONE_NODE)
    route = respx.post(DEPLOY_URL).mock(return_value=httpx.Response(202, json=DEPLOY_ACCEPTED))
    await call_tool_text(
        build(writes),
        "cnc_deploy_config_template",
        {"name": "mcp-loopback99", "host_name": "PE1", "version": "2"},
    )
    body = sent(route)
    assert body["version"] == "2" and body["details"][0] == {
        "version": 2, "device_uuid": "GLOBAL", "variables": [],
    }  # fmt: skip


@respx.mock
async def test_deploy_template_zero_match_sends_nothing(writes):
    mock_template(USER_TEMPLATE)
    mock_nodes(NO_NODES)
    route = respx.post(DEPLOY_URL)
    text = await call_tool_text(
        build(writes),
        "cnc_deploy_config_template",
        {"name": "mcp-loopback99", "host_name": "ghost"},
    )
    assert text.startswith("Error: no device matches host_name 'ghost'; nothing was sent.")
    assert route.call_count == 0


@respx.mock
async def test_deploy_template_bad_version_text_is_error_before_any_call(writes):
    template = mock_template(USER_TEMPLATE)
    text = await call_tool_text(
        build(writes),
        "cnc_deploy_config_template",
        {"name": "mcp-loopback99", "host_name": "PE1", "version": "one"},
    )
    assert text.startswith("Error: version must be a whole number") and template.call_count == 0


@respx.mock
async def test_deploy_template_post_error_is_string_and_not_retried(writes_retrying):
    """The deployment POST is not auto-retried even with max_retries=2 (a lost answer must
    not push the configuration twice)."""
    mock_template(USER_TEMPLATE)
    mock_nodes(ONE_NODE)
    route = respx.post(DEPLOY_URL).mock(return_value=httpx.Response(503, text="busy"))
    text = await call_tool_text(
        build(writes_retrying),
        "cnc_deploy_config_template",
        {"name": "mcp-loopback99", "host_name": "PE1"},
    )
    assert text.startswith("Error: API request failed with status 503") and route.call_count == 1


# --- cnc_wait_for_template_deployment ----------------------------------------


@respx.mock
async def test_wait_for_deployment_polls_until_success(settings, fake_clock):
    route = mock_sequence(
        "POST",
        f"{DEPLOY_URL}/{DEPLOYMENT_ID}/query",
        NO_DEPLOYMENT,
        DEPLOYMENT_IN_PROGRESS,
        DEPLOYMENT_DETAIL,
    )
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_template_deployment",
        {"deployment_id": DEPLOYMENT_ID, "timeout_seconds": 60, "interval_seconds": 5},
    )
    assert route.call_count == 3 and sent(route) == {}
    assert text.startswith(f"Deployment {DEPLOYMENT_ID} finished SUCCESS on 1 device(s) after 10s.")
    data = json.loads(text[text.index("{") :])
    assert data["devices"] == [
        {"device": "PE1", "status": "SUCCESS", "deployed_at": "2026-09-13T12:05:03Z",
         "duration_ms": 4120, "result_tail": TRANSCRIPT}
    ]  # fmt: skip
    assert data["elapsed_seconds"] == 10


@respx.mock
async def test_wait_for_deployment_failed_device_is_error_with_tail(settings, fake_clock):
    route = mock_sequence(
        "POST", f"{DEPLOY_URL}/{DEPLOYMENT_ID}/query", DEPLOYMENT_IN_PROGRESS, DEPLOYMENT_FAILED
    )
    text = await call_tool_text(
        build(settings), "cnc_wait_for_template_deployment", {"deployment_id": DEPLOYMENT_ID}
    )
    assert route.call_count == 2
    assert text.startswith(
        f"Error: deployment {DEPLOYMENT_ID} failed on P1 (FAILED) after 5s: P1: % Invalid "
        "input detected."
    )
    assert "cnc_get_template_deployment" in text and '"status": "FAILED"' in text


@respx.mock
async def test_wait_for_deployment_system_failure_is_terminal_error(settings, fake_clock):
    """SYSTEM_FAILURE (documented DeploymentStatus, a platform-side failure) ends the wait
    on the FIRST poll as the deployment's outcome — never 'keep waiting' to the timeout."""
    route = mock_sequence("POST", f"{DEPLOY_URL}/{DEPLOYMENT_ID}/query", DEPLOYMENT_SYSTEM_FAILURE)
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_template_deployment",
        {"deployment_id": DEPLOYMENT_ID, "timeout_seconds": 60, "interval_seconds": 5},
    )
    assert route.call_count == 1 and fake_clock.now == 0.0
    assert text.startswith(
        f"Error: deployment {DEPLOYMENT_ID} failed on PE1 (SYSTEM_FAILURE) after 0s: PE1: "
        "Internal error: collector unavailable."
    )
    assert '"status": "SYSTEM_FAILURE"' in text


@respx.mock
async def test_wait_for_deployment_not_deployed_is_terminal_error(settings, fake_clock):
    """NOT_DEPLOYED (documented: the device was skipped) is terminal and not a success."""
    route = mock_sequence("POST", f"{DEPLOY_URL}/{DEPLOYMENT_ID}/query", DEPLOYMENT_NOT_DEPLOYED)
    text = await call_tool_text(
        build(settings), "cnc_wait_for_template_deployment", {"deployment_id": DEPLOYMENT_ID}
    )
    assert route.call_count == 1
    assert text.startswith(
        f"Error: deployment {DEPLOYMENT_ID} failed on P1 (NOT_DEPLOYED) after 0s: P1: "
        "(no transcript)."
    )


@respx.mock
async def test_wait_for_deployment_reads_every_page_before_declaring_success(settings, fake_clock):
    """Two devices on two pages, both SUCCESS: success is declared for 2 devices (not 1)."""
    route = paged_deployment_route(f"{DEPLOY_URL}/{DEPLOYMENT_ID}/query", PAGE_0_OF_2, PAGE_1_OF_2)
    text = await call_tool_text(
        build(settings), "cnc_wait_for_template_deployment", {"deployment_id": DEPLOYMENT_ID}
    )
    assert pages_requested(route) == [("0", "100"), ("1", "100")]
    assert text.startswith(f"Deployment {DEPLOYMENT_ID} finished SUCCESS on 2 device(s) after 0s.")
    data = json.loads(text[text.index("{") :])
    assert [d["device"] for d in data["devices"]] == ["PE1", "P1"] and data["total"] == 2


@respx.mock
async def test_wait_for_deployment_unseen_devices_keep_it_waiting(settings, fake_clock):
    """First page: 1 SUCCESS detail, total_elements 2, and the platform ignores ``page``:
    the wait must NOT answer 'finished SUCCESS on 1 device(s)' — it keeps polling and the
    timeout message names the unseen devices."""
    route = paged_deployment_route(f"{DEPLOY_URL}/{DEPLOYMENT_ID}/query", PAGE_0_OF_2)
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_template_deployment",
        {"deployment_id": DEPLOYMENT_ID, "timeout_seconds": 10, "interval_seconds": 5},
    )
    # 3 polls x (page 0 + the page 1 that brought nothing new).
    assert route.call_count == 6
    assert not text.startswith("Error:") and "finished SUCCESS" not in text
    assert text.startswith(
        f"Deployment {DEPLOYMENT_ID} not finished after 10s; only 1 of 2 device(s) visible "
        "(PE1 SUCCESS) — Crosswork counts 2 devices in this deployment but answered fewer"
    )
    data = json.loads(text[text.index("{") :])
    assert data["total"] == 2 and [d["device"] for d in data["devices"]] == ["PE1"]


@respx.mock
async def test_wait_for_deployment_timeout_is_not_an_error(settings, fake_clock):
    mock_sequence("POST", f"{DEPLOY_URL}/{DEPLOYMENT_ID}/query", DEPLOYMENT_IN_PROGRESS)
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_template_deployment",
        {"deployment_id": DEPLOYMENT_ID, "timeout_seconds": 10, "interval_seconds": 10},
    )
    assert not text.startswith("Error:")
    assert text.startswith(
        f"Deployment {DEPLOYMENT_ID} not finished after 10s; PE1 IN_PROGRESS. Call again"
    )


@respx.mock
async def test_wait_for_deployment_still_empty_at_timeout_says_not_found_yet(settings, fake_clock):
    route = mock_sequence("POST", f"{DEPLOY_URL}/ghost/query", NO_DEPLOYMENT)
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_template_deployment",
        {"deployment_id": "ghost", "timeout_seconds": 10, "interval_seconds": 5},
    )
    assert route.call_count == 3 and not text.startswith("Error:")
    assert text.startswith("Deployment ghost not found (yet) after 10s")
    assert "cnc_list_template_deployments" in text


@respx.mock
async def test_wait_for_deployment_api_error_is_string(make_settings, fake_clock):
    respx.post(f"{DEPLOY_URL}/{DEPLOYMENT_ID}/query").mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)),
        "cnc_wait_for_template_deployment",
        {"deployment_id": DEPLOYMENT_ID},
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_delete_template_deployment ------------------------------------------


@respx.mock
async def test_delete_deployment_204_and_url_encoding(writes):
    route = respx.delete(f"{DEPLOY_URL}/a%20b").mock(return_value=httpx.Response(204))
    text = await call_tool_text(
        build(writes), "cnc_delete_template_deployment", {"deployment_id": "a b"}
    )
    assert route.call_count == 1
    assert text.startswith(
        "Deployment 'a b' deleted (HTTP 204). The device configuration it pushed"
    )
    assert json.loads(text[text.index("{") :]) == {"deployment_id": "a b", "status_code": 204}


@respx.mock
async def test_delete_deployment_api_error_is_string(writes):
    respx.delete(f"{DEPLOY_URL}/{DEPLOYMENT_ID}").mock(return_value=NATS_500)
    text = await call_tool_text(
        build(writes), "cnc_delete_template_deployment", {"deployment_id": DEPLOYMENT_ID}
    )
    assert text.startswith("Error: API request failed with status 500")


@respx.mock
async def test_delete_deployment_503_is_retried_unlike_the_posts(writes_retrying):
    """Pins the contrast with the three "not retried" POST tests above: on the SAME
    settings an idempotent DELETE is re-sent (max_retries=2 -> three attempts)."""
    route = respx.delete(f"{DEPLOY_URL}/{DEPLOYMENT_ID}").mock(
        return_value=httpx.Response(503, text="busy")
    )
    text = await call_tool_text(
        build(writes_retrying), "cnc_delete_template_deployment", {"deployment_id": DEPLOYMENT_ID}
    )
    assert text.startswith("Error: API request failed with status 503")
    assert route.call_count == 3
