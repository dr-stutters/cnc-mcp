"""Device configuration tools — configuration backups, backup jobs, configuration
templates and template deployments on ``/crosswork/config/v1`` (the Device
Management > Configuration pages of the Crosswork UI).

Everything here was verified live against Crosswork Network Controller 7.2 on
2026-09-13 (one backup job and two template deployments, every object removed
afterwards); the exact paths, bodies and answers are in the platform notes and
repeated in the tool docstrings. The service is plain JSON over a Bearer token
(no RESTCONF dialect, no ``filterData`` grammar): reads are ``GET`` or ``POST
.../query {}`` and every write answers either ``204`` or a small
``{"status_code", "job_id", "message"}`` document.

Device selection: every ``device_uuid`` on this service is the inventory
uuid (``cnc_list_devices``), so every tool that touches a device takes
``uuid`` / ``host_name`` and resolves exactly one device with ``POST
/crosswork/inventory/v1/nodes/query`` first (exact match, case-insensitive,
``*`` wildcard); zero matches is an Error and nothing is sent. The two bulk
writes (cnc_backup_device_config, cnc_deploy_config_template) accept a
wildcard host_name such as ``'*'`` or ``'PE*'`` and act on every match in ONE
request (one ``device_uuids`` list); more than 100 matches is refused.

Object model:

- **Backups** (``GET config-backup/<uuid>`` -> ``{"backup_config": [...]}``):
  one entry per stored configuration of a device, named ``Initial_Version``
  (taken on device add, ``trigger DEVICE_ADD``) or ``<job>_<run_id>`` (taken by
  a backup job, ``trigger SCHEDULED_JOB``). The list entries carry an EMPTY
  ``file`` list; ``GET config-backup/<uuid>/<name>`` and ``GET
  latest-config-backup/<uuid>`` return the same object WITH ``file[{file_name,
  config, type}]`` — the full running configuration text with secrets masked
  as ``********`` by the platform. An unknown backup name answers HTTP 200
  with an EMPTY body (reported as not found); an unknown device uuid answers
  ``{"backup_config": []}``.
- **Backup jobs** (``POST schedule-config-backup-job`` -> 202, ``POST
  config-backup-jobs {}`` / ``config-backup-job/<name> {}`` to read, ``DELETE
  config-backup-restore-job/<name>`` -> 204): a job is a named schedule over a
  device list; a start time a few seconds ahead runs at once (``SUCCESS`` in
  about 6 s on the lab) and leaves a backup named ``<job>_<run_id>`` on each
  device. Job ``status`` SCHEDULED|RUNNING|COMPLETED|FAILED|PAUSED|BLOCKED;
  ``last_run_status`` NOT_STARTED|IN_PROGRESS|SUCCESS|RUN_FAILED|PARTIAL. A
  duplicate job name is HTTP 500 ``"Job already exists with name <n>"``.
- **Templates** (``POST templates/query``, ``GET templates/<name>``, ``POST
  templates`` -> 204, ``DELETE templates {"templateName": [...]}`` -> 204):
  Velocity configlets (``${var}``, ``#if``) with a ``variables`` list
  (``name, display_name, type, default_value, is_mandatory, description,
  options``), ``type`` SYSTEM (Cisco-shipped, e.g.
  ``Cisco_IOS-XR_Interface_config``) or USER_DEFINED_SIMPLE, ``category``
  DEVICE|INTERFACE (MODULE documented, not seen), ``transport`` CLI (GNMI|
  NETCONF documented, not exercised). ``templates/query`` reports
  ``total_elements`` as a STRING (coerced here).
- **Deployments** (``POST templates/deploy-template`` -> 202 ``job_id
  "<template>_DeployJob_<date>_<time>"``): the configlet, rendered with the
  given variables, is pushed to every selected device — the configuration is
  on the device within ~5 s. ``POST templates/deploy-template/<id>/query {}``
  is PAGED (``?page=&size=`` documented; the answer carries ``page_size,
  page_number, total_pages, total_elements``) and answers ``details[]`` with
  one entry per device (``device_uuid`` holds the HOSTNAME on the wire,
  ``status`` NOT_STARTED|IN_PROGRESS|SUCCESS|FAILED|PARTIAL seen live plus
  the documented NOT_DEPLOYED|SYSTEM_FAILURE, ``result`` is the CLI
  transcript, ``deployed_configlet`` the rendered text); an unknown id
  answers empty ``details``. ``DELETE
  templates/deploy-template/<id>`` -> 204 removes the deployment record (not
  the configuration). Crosswork keeps no undo: deploy a reverting template
  (``no interface Loopback99`` reverted the lab deployment cleanly), or
  restore the pre-deployment backup in the UI.

NOT exposed (verified unusable or too risky through this interface):
``restore-config`` and ``upload-config-file`` (bodies undocumented beyond
field names; a restore rewrites a device's running configuration),
``config-backup-archive/<uuid>/<name>/<sanitized>`` (answers 500 "No
acceptable representation" — it is a zip download), and ``GET
templates/current-device-config?device_id&command`` (the router matches it
as the template name "current-device-config" and answers ``{"templates":
[]}`` for every input). Pause/resume/edit of jobs and template PUT/import/
export are out of scope.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from urllib.parse import quote

import httpx
from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.crosswork import INVENTORY, page_envelope, query_body, unwrap
from cnc_mcp.errors import PlatformError, format_error, http_error
from cnc_mcp.formatting import ResponseFormat, finalize, to_json
from cnc_mcp.polling import wait_until
from cnc_mcp.safety import AppContext, register_tool

CONFIG = "/crosswork/config/v1"
PREFERENCES_URL = f"{CONFIG}/device-config-preferences/config-settings"
CONFIG_BACKUP_URL = f"{CONFIG}/config-backup"
LATEST_BACKUP_URL = f"{CONFIG}/latest-config-backup"
SCHEDULE_BACKUP_JOB_URL = f"{CONFIG}/schedule-config-backup-job"
BACKUP_JOBS_URL = f"{CONFIG}/config-backup-jobs"
BACKUP_JOB_URL = f"{CONFIG}/config-backup-job"
BACKUP_RESTORE_JOB_URL = f"{CONFIG}/config-backup-restore-job"
TEMPLATES_URL = f"{CONFIG}/templates"
TEMPLATES_QUERY_URL = f"{TEMPLATES_URL}/query"
DEPLOYMENTS_QUERY_URL = f"{TEMPLATES_URL}/jobs/deployments/query"
DEPLOY_TEMPLATE_URL = f"{TEMPLATES_URL}/deploy-template"
NODES_QUERY_URL = f"{INVENTORY}/nodes/query"

# Rule for the enums below: every value the 7.2 OpenAPI document lists is accepted as an
# input, and the comment says which of them were actually seen live — an agent should
# not be refused a documented value because the lab happened not to produce it.
#
# Job.status (documented enum; UNKNOWN/UNRECOGNIZED are not filter values).
BACKUP_JOB_STATUSES = ("SCHEDULED", "RUNNING", "COMPLETED", "FAILED", "PAUSED", "BLOCKED")
# JobRunStatus (Job.last_run_status / BackupJobRun.run_status): NOT_STARTED | SUCCESS |
# IN_PROGRESS | RUN_FAILED | PARTIAL — the deployments query filters on the same enum
# (documented in JobFilterRequest; the filter form itself is UNVERIFIED live, only {} was sent).
DEPLOYMENT_RUN_STATUSES = ("NOT_STARTED", "SUCCESS", "IN_PROGRESS", "RUN_FAILED", "PARTIAL")
RUN_SUCCESS = "SUCCESS"
RUN_FAILED = "RUN_FAILED"
RUN_PARTIAL = "PARTIAL"
RUN_TERMINAL_STATES = {RUN_SUCCESS, RUN_FAILED, RUN_PARTIAL}
# DeploymentStatus (DeploymentDetails.status): NOT_STARTED | IN_PROGRESS | SUCCESS | FAILED |
# PARTIAL (all five seen live) plus NOT_DEPLOYED and SYSTEM_FAILURE (documented in the 7.2
# DeploymentStatus enum, not produced by the lab). Everything but NOT_STARTED / IN_PROGRESS
# is terminal: a wait must stop on a platform-side failure instead of polling to the timeout.
DETAIL_SUCCESS = "SUCCESS"
DETAIL_TERMINAL_STATES = {DETAIL_SUCCESS, "FAILED", "PARTIAL", "NOT_DEPLOYED", "SYSTEM_FAILURE"}
# TemplateType enum from the document; SYSTEM and USER_DEFINED_SIMPLE were seen live,
# USER_DEFINED_COMPOSITE / MANAGEABILITY / EVENT_DRIVEN are documented only (a filter on
# a type this build does not have simply answers no templates).
TEMPLATE_TYPES = (
    "SYSTEM",
    "USER_DEFINED_SIMPLE",
    "USER_DEFINED_COMPOSITE",
    "MANAGEABILITY",
    "EVENT_DRIVEN",
)
# TemplateCategory enum from the document (DEVICE | INTERFACE | MODULE); DEVICE and
# INTERFACE were seen live, MODULE is documented only.
TEMPLATE_CATEGORIES = ("DEVICE", "INTERFACE", "MODULE")
# Transport enum from the document (CLI | GNMI | NETCONF); only CLI was exercised live.
TEMPLATE_TRANSPORTS = ("CLI", "GNMI", "NETCONF")
USER_TEMPLATE_TYPE = "USER_DEFINED_SIMPLE"
BACKUP_TRIGGER = "SCHEDULED_JOB"
DEPLOY_GLOBAL = "GLOBAL"
DEFAULT_JOB_NAME_PREFIX = "mcp-backup-"
START_AT_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"
# next_run_at of a one-shot job that will not run again (verified: the epoch).
_NO_NEXT_RUN_PREFIX = "1970-01-01T"

# How many devices one bulk write (backup job / deployment) may name: one nodes/query
# page. A match beyond the page would be silently left out, so the tools refuse instead.
SELECTOR_PAGE_SIZE = 100
# ``size`` sent to the paged deploy-template/<id>/query: one page holds every device a
# deployment made here can name (SELECTOR_PAGE_SIZE); larger (UI-made) deployments are
# followed across pages by ``total_elements``, up to this many pages.
DEPLOYMENT_PAGE_SIZE = SELECTOR_PAGE_SIZE
DEPLOYMENT_MAX_PAGES = 50
# Tail of a CLI transcript kept in wait/summary answers (the full text is in the get tool).
RESULT_TAIL_CHARS = 600
# Template variable names must be Velocity identifiers.
_VARIABLE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# ${name} / $name references inside a configlet (the .x suffix of $obj.prop is dropped).
_REFERENCE_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")
_TEMPLATE_VARIABLE_KEYS = {"name", "default_value", "type", "is_mandatory", "description"}

_SELECTOR_HELP = (
    "Filters are exact-match, case-insensitive, '*' wildcard; list devices with cnc_list_devices."
)
_BATCH_HELP = "Narrow the host_name pattern (e.g. 'PE*') and run it in batches."


# --- pure helpers ------------------------------------------------------------


def utcnow() -> datetime:
    """Current UTC time (a function so tests can pin it)."""
    return datetime.now(tz=UTC)


def start_at_time(delay_seconds: int, now: datetime | None = None) -> str:
    """``schedule.start_at_time`` for a backup job: now + delay as ``%Y-%m-%dT%H:%M:%S.000Z``."""
    base = now or utcnow()
    return (base + timedelta(seconds=delay_seconds)).strftime(START_AT_FORMAT)


def default_backup_job_name(now: datetime | None = None) -> str:
    """``mcp-backup-<YYYYmmdd-HHMMSS>`` (UTC) — unique per second, which is what the
    platform's unique-job-name rule needs."""
    base = now or utcnow()
    return f"{DEFAULT_JOB_NAME_PREFIX}{base:%Y%m%d-%H%M%S}"


def backup_job_body(name: str, start_at: str, device_uuids: list[str]) -> dict[str, Any]:
    """The verified ``POST schedule-config-backup-job`` body (note the nested device_uuids)."""
    return {
        "name": name,
        "trigger": BACKUP_TRIGGER,
        "schedule": {"start_at_time": start_at},
        "device_uuids": {"device_uuids": list(device_uuids)},
    }


def deploy_body(
    template_name: str,
    version: int,
    device_uuids: list[str],
    variables: dict[str, str],
    *,
    backup_before_deploy: bool,
    rollback_on_failure: bool,
) -> dict[str, Any]:
    """The verified ``POST templates/deploy-template`` body: ``version`` is a STRING at the
    top level and an INT inside ``details``; the single GLOBAL detail carries the variables
    every device gets."""
    return {
        "template_name": template_name,
        "version": str(version),
        "device_uuids": {"device_uuids": list(device_uuids)},
        "details": [
            {
                "version": version,
                "device_uuid": DEPLOY_GLOBAL,
                "variables": [{"name": k, "value": v} for k, v in variables.items()],
            }
        ],
        "additional_params": {
            "backup_before_deploy": backup_before_deploy,
            "rollback_on_failure": rollback_on_failure,
        },
    }


def template_body(
    name: str,
    configlet: str,
    *,
    description: str,
    notes: str,
    category: str,
    transport: str,
    variables: list[dict[str, Any]],
    device_types: list[str],
) -> dict[str, Any]:
    """The verified ``POST templates`` body (camelCase ``tagList``/``accessList`` as sent
    by the UI; ``version`` 1.0 for a new template)."""
    return {
        "name": name,
        "version": 1.0,
        "notes": notes,
        "description": description,
        "is_read": False,
        "device_type": list(device_types),
        "category": category,
        "transport": transport,
        "tagList": [],
        "accessList": [],
        "configlet": configlet,
        "variables": variables,
        "type": USER_TEMPLATE_TYPE,
    }


def _selector(uuid: str | None, host_name: str | None) -> dict[str, str]:
    """Exactly one of uuid / host_name (non-blank) -> the nodes/query filter for it."""
    uuid_value = (uuid or "").strip()
    host_value = (host_name or "").strip()
    if bool(uuid_value) == bool(host_value):
        raise PlatformError("Pass exactly one of 'uuid' or 'host_name' to select the device(s).")
    return {"uuid": uuid_value} if uuid_value else {"host_name": host_value}


def describe_selector(selector: dict[str, str]) -> str:
    key, value = next(iter(selector.items()))
    return f"{key} '{value}'"


def device_ref(node: dict[str, Any]) -> dict[str, Any]:
    return {"host_name": node.get("host_name"), "uuid": node.get("uuid")}


def device_label(node: dict[str, Any]) -> str:
    return f"{node.get('host_name') or '?'} ({node.get('uuid') or '?'})"


def as_int(value: Any) -> int | None:
    """An int from an int, float or numeric string (``total_elements`` is a string on the
    wire); None otherwise. Booleans are not numbers here."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text)
        except ValueError:
            try:
                return int(float(text))
            except ValueError:
                return None
    return None


def parse_statuses(text: str | None, allowed: tuple[str, ...], what: str) -> list[str]:
    """'completed, FAILED' -> ['COMPLETED', 'FAILED'] (upper-cased, deduplicated);
    an unknown value is a PlatformError naming the allowed ones. Blank -> []."""
    out: list[str] = []
    for token in (text or "").split(","):
        value = token.strip().upper()
        if not value:
            continue
        if value not in allowed:
            raise PlatformError(
                f"Unknown {what} '{token.strip()}'. Use one of: {', '.join(allowed)}."
            )
        if value not in out:
            out.append(value)
    return out


def parse_version(text: str) -> int:
    """'1' / '1.0' / '2' -> 1 / 1 / 2; anything else is a PlatformError. Template versions are
    integers on the wire (a float ``1.0`` on read, ``"1"`` / ``1`` in the deploy body)."""
    value = (text or "").strip()
    try:
        number = float(value)
    except ValueError:
        raise PlatformError(
            f"version must be a whole number such as '1' or '2', got '{text}'."
        ) from None
    if number < 1 or number != int(number):
        raise PlatformError(
            f"version must be a whole number >= 1 such as '1' or '2', got '{text}'."
        )
    return int(number)


def version_of(template: dict[str, Any]) -> int | None:
    return as_int(template.get("version"))


def split_csv(text: str | None) -> list[str]:
    """'a, b,,a' -> ['a', 'b'] (order kept, duplicates dropped)."""
    out: list[str] = []
    for token in (text or "").split(","):
        value = token.strip()
        if value and value not in out:
            out.append(value)
    return out


def _bool_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def parse_deploy_variables(text: str | None) -> dict[str, str]:
    """Deployment variable values from ``'k=v,k2=v2'`` or a JSON object text -> {name: value}.

    Values are sent as strings (a JSON ``true`` becomes ``"true"``). Use the JSON
    form for a value that contains a comma. Blank -> {}.
    """
    raw = (text or "").strip()
    if not raw:
        return {}
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
        except ValueError as e:
            raise PlatformError(f"variables is not valid JSON: {e}") from None
        if not isinstance(data, dict):
            raise PlatformError('variables JSON must be an object such as {"name": "value"}.')
        out: dict[str, str] = {}
        for key, value in data.items():
            name = str(key).strip()
            if not _VARIABLE_NAME_RE.match(name):
                raise PlatformError(f"variable name '{key}' is not a valid identifier.")
            if isinstance(value, dict | list):
                raise PlatformError(
                    f"variable '{name}' must be a scalar value, not {type(value).__name__}."
                )
            out[name] = "" if value is None else _bool_text(value)
        return out
    out = {}
    for token in raw.split(","):
        pair = token.strip()
        if not pair:
            continue
        if "=" not in pair:
            raise PlatformError(
                f"variables entry '{pair}' is not 'name=value'; pass 'k=v,k2=v2' or a JSON object."
            )
        name, _, value = pair.partition("=")
        name = name.strip()
        if not _VARIABLE_NAME_RE.match(name):
            raise PlatformError(f"variable name '{name}' is not a valid identifier.")
        out[name] = value.strip()
    return out


def _variable_entry(
    name: str,
    default_value: Any = "",
    var_type: Any = "string",
    is_mandatory: Any = False,
    description: Any = "",
) -> dict[str, Any]:
    if not isinstance(name, str) or not _VARIABLE_NAME_RE.match(name.strip()):
        raise PlatformError(
            f"template variable name '{name}' is not a valid identifier (letters, digits, '_')."
        )
    if isinstance(is_mandatory, str):
        lowered = is_mandatory.strip().lower()
        if lowered not in ("true", "false"):
            raise PlatformError(f"variable '{name}': is_mandatory must be true or false.")
        is_mandatory = lowered == "true"
    if not isinstance(is_mandatory, bool):
        raise PlatformError(f"variable '{name}': is_mandatory must be true or false.")
    if isinstance(default_value, dict | list):
        raise PlatformError(f"variable '{name}': default_value must be a scalar.")
    type_text = str(var_type or "string").strip() or "string"
    clean = name.strip()
    return {
        "name": clean,
        "display_name": clean,
        "type": type_text,
        "default_value": "" if default_value is None else _bool_text(default_value),
        "description": "" if description is None else str(description),
        "is_mandatory": is_mandatory,
        "options": [],
    }


def parse_template_variables(text: str | None) -> list[dict[str, Any]]:
    """Template variable definitions from a JSON array text or a ``'name=default,name2'`` list.

    JSON entries are ``{"name", "default_value"?, "type"?: "string", "is_mandatory"?:
    false, "description"?}`` (unknown keys are refused — they are usually
    typos); the comma form gives every variable type string, not mandatory, with
    the text after ``=`` (or nothing) as default. Every variable is completed
    with ``display_name`` = name and ``options`` = [] as the UI sends them.
    Duplicate names are refused. Blank -> [].
    """
    raw = (text or "").strip()
    if not raw:
        return []
    entries: list[dict[str, Any]] = []
    if raw.startswith("["):
        try:
            data = json.loads(raw)
        except ValueError as e:
            raise PlatformError(f"variables is not valid JSON: {e}") from None
        if not isinstance(data, list):
            raise PlatformError('variables JSON must be an array of {"name": ...} objects.')
        for item in data:
            if not isinstance(item, dict) or "name" not in item:
                raise PlatformError(
                    "every variables entry must be an object with at least a 'name' key."
                )
            unknown = sorted(set(item) - _TEMPLATE_VARIABLE_KEYS)
            if unknown:
                raise PlatformError(
                    f"variable '{item.get('name')}': unknown key(s) {', '.join(unknown)}; allowed: "
                    f"{', '.join(sorted(_TEMPLATE_VARIABLE_KEYS))}."
                )
            entries.append(
                _variable_entry(
                    item["name"],
                    item.get("default_value", ""),
                    item.get("type", "string"),
                    item.get("is_mandatory", False),
                    item.get("description", ""),
                )
            )
    else:
        for token in raw.split(","):
            pair = token.strip()
            if not pair:
                continue
            name, _, default = pair.partition("=")
            entries.append(_variable_entry(name.strip(), default.strip()))
    seen: set[str] = set()
    for entry in entries:
        if entry["name"] in seen:
            raise PlatformError(f"variable '{entry['name']}' is defined twice.")
        seen.add(entry["name"])
    return entries


def configlet_references(configlet: str) -> list[str]:
    """Variable names a Velocity configlet references (``${x}`` or ``$x``), in order."""
    out: list[str] = []
    for match in _REFERENCE_RE.finditer(configlet or ""):
        name = match.group(1)
        if name not in out:
            out.append(name)
    return out


def template_variables(template: dict[str, Any]) -> list[dict[str, Any]]:
    variables = template.get("variables")
    return [v for v in variables if isinstance(v, dict)] if isinstance(variables, list) else []


def resolve_deploy_variables(
    template: dict[str, Any], given: dict[str, str]
) -> tuple[dict[str, str], list[str]]:
    """Merge the caller's values with the template's defaults -> (values to send, unset names).

    Refuses (PlatformError, nothing sent) a name the template does not define
    and a mandatory variable that has neither a given value nor a non-empty
    default. Non-mandatory variables with neither are omitted from the body
    and returned as ``unset`` so the caller can mention them.
    """
    defined = template_variables(template)
    names = [str(v.get("name")) for v in defined]
    unknown = [k for k in given if k not in names]
    if unknown:
        raise PlatformError(
            f"template '{template.get('name')}' has no variable(s) {', '.join(unknown)}; it "
            f"defines: {', '.join(names) or '(none)'}. Nothing was deployed."
        )
    values: dict[str, str] = {}
    unset: list[str] = []
    missing: list[str] = []
    for var in defined:
        name = str(var.get("name"))
        default = var.get("default_value")
        default_text = "" if default is None else str(default)
        if name in given and given[name] != "":
            values[name] = given[name]
        elif default_text != "":
            values[name] = default_text
        elif var.get("is_mandatory") is True:
            missing.append(name)
        else:
            unset.append(name)
    if missing:
        raise PlatformError(
            f"template '{template.get('name')}' requires a value for mandatory variable(s) "
            f"{', '.join(missing)} (no default); pass variables='{missing[0]}=<value>'. "
            "Nothing was deployed."
        )
    return values, unset


def job_of(data: Any) -> dict[str, Any] | None:
    """The ``job`` object of a ``config-backup-job/<name>`` answer (None for the ``{}`` of an
    unknown job)."""
    if not isinstance(data, dict):
        return None
    wrapper = data.get("config_backup_restore_job")
    job = wrapper.get("job") if isinstance(wrapper, dict) else None
    return job if isinstance(job, dict) else None


def device_count_of(data: Any) -> int | None:
    wrapper = data.get("config_backup_restore_job") if isinstance(data, dict) else None
    return as_int(wrapper.get("device_count")) if isinstance(wrapper, dict) else None


def runs_of(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    runs = data.get("job_runs")
    items = runs.get("backup_job_run") if isinstance(runs, dict) else None
    return [r for r in items if isinstance(r, dict)] if isinstance(items, list) else []


def run_view(run: dict[str, Any]) -> dict[str, Any]:
    return {
        "run_id": run.get("run_id"),
        "run_status": run.get("run_status"),
        "start_at": run.get("start_at"),
        "duration_ms": as_int(run.get("duration")),
    }


def job_view(job: dict[str, Any], device_count: int | None = None) -> dict[str, Any]:
    view = {
        "name": job.get("name"),
        "job_type": job.get("job_type"),
        "status": job.get("status"),
        "last_run_status": job.get("last_run_status"),
        "last_run_at": job.get("last_run_at"),
        "next_run_at": job.get("next_run_at"),
        "duration_ms": as_int(job.get("duration")),
        "run_count": as_int(job.get("run_count")),
        "created_by": job.get("created_by"),
    }
    if device_count is not None:
        view["device_count"] = device_count
    return view


def _when(value: Any) -> str:
    """An ISO timestamp for display; the epoch (a job that will not run again) -> '-'."""
    text = str(value or "").strip()
    if not text or text.startswith(_NO_NEXT_RUN_PREFIX):
        return "-"
    return text


def _ms(value: Any) -> str:
    number = as_int(value)
    return f"{number} ms" if number is not None else "-"


def job_line(view: dict[str, Any]) -> str:
    """'- **name** BACKUP: status COMPLETED, last run SUCCESS at <t> (6007 ms), next run -,
    1 device(s), by admin'."""
    devices = f", {view['device_count']} device(s)" if view.get("device_count") is not None else ""
    return (
        f"- **{view.get('name') or '?'}** {view.get('job_type') or '?'}: status "
        f"{view.get('status') or '?'}, last run {view.get('last_run_status') or '?'} at "
        f"{_when(view.get('last_run_at'))} ({_ms(view.get('duration_ms'))}), next run "
        f"{_when(view.get('next_run_at'))}{devices}, by {view.get('created_by') or '?'}"
    )


def run_line(view: dict[str, Any]) -> str:
    return (
        f"- run {view.get('run_id') or '?'}: {view.get('run_status') or '?'}, started "
        f"{_when(view.get('start_at'))}, {_ms(view.get('duration_ms'))}"
    )


def backup_view(backup: dict[str, Any]) -> dict[str, Any]:
    tags = backup.get("tag")
    return {
        "name": backup.get("name"),
        "backedup_at": backup.get("backedup_at"),
        "trigger": backup.get("trigger"),
        "status": backup.get("status"),
        "complianceStatus": backup.get("complianceStatus"),
        "pinned": backup.get("pinned"),
        "tag": [str(t) for t in tags] if isinstance(tags, list) else [],
        "notes": backup.get("notes"),
        "result": backup.get("result"),
        "created_by": backup.get("created_by"),
    }


def sort_backups(backups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Newest first by ``backedup_at`` (ISO text sorts chronologically)."""
    return sorted(backups, key=lambda b: str(b.get("backedup_at") or ""), reverse=True)


def backup_line(view: dict[str, Any]) -> str:
    extras = []
    if view.get("pinned"):
        extras.append("pinned")
    if view.get("tag"):
        extras.append("tags " + ", ".join(view["tag"]))
    tail = f" ({'; '.join(extras)})" if extras else ""
    return (
        f"- **{view.get('name') or '?'}**: {_when(view.get('backedup_at'))}, "
        f"{view.get('trigger') or '?'}, {view.get('status') or '?'}, "
        f"{view.get('complianceStatus') or '?'}{tail}"
    )


def backup_files(backup: dict[str, Any]) -> list[dict[str, Any]]:
    files = backup.get("file")
    return [f for f in files if isinstance(f, dict)] if isinstance(files, list) else []


def backup_markdown(node: dict[str, Any], backup: dict[str, Any]) -> str:
    view = backup_view(backup)
    files = backup_files(backup)
    total_chars = sum(len(str(f.get("config") or "")) for f in files)
    lines = [
        f"# Backup {view.get('name') or '?'} of {device_label(node)}",
        "",
        f"- taken: {_when(view.get('backedup_at'))} ({view.get('trigger') or '?'}, "
        f"{view.get('status') or '?'}, {view.get('complianceStatus') or '?'})",
        f"- result: {view.get('result') or '-'}; notes: {view.get('notes') or '-'}; "
        f"created by: {view.get('created_by') or '-'}; pinned: {bool(view.get('pinned'))}; "
        f"tags: {', '.join(view['tag']) or '-'}",
        f"- {len(files)} file(s), {total_chars} characters of configuration (secrets masked "
        "as ******** by Crosswork; a long configuration is cut by the response cap)",
    ]
    for index, entry in enumerate(files, 1):
        title = str(entry.get("file_name") or "").strip() or f"file {index}"
        kind = entry.get("type")
        heading = f"## {title}" + (f" ({kind})" if kind else "")
        lines.extend(["", heading, "```", str(entry.get("config") or ""), "```"])
    if not files:
        lines.append("- (no configuration files in this backup)")
    return "\n".join(lines)


def template_view(template: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": template.get("name"),
        "version": template.get("version"),
        "type": template.get("type"),
        "category": template.get("category"),
        "transport": template.get("transport"),
        "description": template.get("description"),
        "variables": len(template_variables(template)),
        "last_deployed_status": template.get("last_deployed_status"),
        "author": template.get("author"),
        "device_type": template.get("device_type"),
        "created_at": template.get("created_at"),
        "updated_at": template.get("updated_at"),
    }


def template_line(view: dict[str, Any]) -> str:
    description = str(view.get("description") or "").strip()
    desc = f" — {description}" if description else ""
    return (
        f"- **{view.get('name') or '?'}** v{view.get('version') or '?'} "
        f"{view.get('type') or '?'}/{view.get('category') or '?'}/{view.get('transport') or '?'}"
        f"{desc}; {view.get('variables')} variable(s); last deployed: "
        f"{view.get('last_deployed_status') or '?'}; by {view.get('author') or '?'}"
    )


def template_markdown(template: dict[str, Any]) -> str:
    view = template_view(template)
    lines = [
        f"# Template {view.get('name') or '?'} v{view.get('version') or '?'}",
        "",
        f"- type {view.get('type') or '?'}, category {view.get('category') or '?'}, transport "
        f"{view.get('transport') or '?'}, by {view.get('author') or '?'}, created "
        f"{_when(view.get('created_at'))}, last deployed: "
        f"{view.get('last_deployed_status') or '?'}",
        f"- description: {view.get('description') or '-'}",
        f"- device types: {', '.join(str(t) for t in view.get('device_type') or []) or '-'}",
        "",
    ]
    variables = template_variables(template)
    if variables:
        lines.extend(["| variable | type | default | mandatory |", "|---|---|---|---|"])
        for var in variables:
            lines.append(
                f"| {var.get('name') or '?'} | {var.get('type') or '?'} | "
                f"{var.get('default_value') if var.get('default_value') not in (None, '') else '-'}"
                f" | {'yes' if var.get('is_mandatory') else 'no'} |"
            )
    else:
        lines.append("(no variables)")
    lines.extend(["", "```", str(template.get("configlet") or ""), "```"])
    return "\n".join(lines)


def detail_view(detail: dict[str, Any]) -> dict[str, Any]:
    return {
        "device": detail.get("device_uuid"),  # the HOSTNAME on the wire (verified)
        "status": detail.get("status"),
        "deployed_at": detail.get("deployed_at"),
        "duration_ms": as_int(detail.get("duration")),
        "deployment_id": detail.get("deployment_id"),
        "version": detail.get("version"),
        "variables": detail.get("variables"),
        "deployed_configlet": detail.get("deployed_configlet"),
        "result": detail.get("result"),
    }


def result_tail(text: Any, limit: int = RESULT_TAIL_CHARS) -> str:
    value = str(text or "")
    return value if len(value) <= limit else "..." + value[-limit:]


def deployment_markdown(
    deployment_id: str, details: list[dict[str, Any]], total: int | None = None
) -> str:
    counts: dict[str, int] = {}
    for d in details:
        key = str(d.get("status") or "?")
        counts[key] = counts.get(key, 0) + 1
    summary = ", ".join(f"{n} {s}" for s, n in counts.items())
    lines = [f"# Deployment {deployment_id}", "", f"{device_count_text(details, total)}: {summary}"]
    if total is not None and total > len(details):
        lines.append(
            f"(Crosswork reports {total} devices in this deployment but answered only "
            f"{len(details)}; the rest could not be read — their outcome is unknown.)"
        )
    for d in details:
        view = detail_view(d)
        lines.extend(
            [
                "",
                f"## {view['device'] or '?'} — {view['status'] or '?'} (deployed "
                f"{_when(view['deployed_at'])}, {_ms(view['duration_ms'])})",
                "deployed configlet:",
                "```",
                str(view["deployed_configlet"] or ""),
                "```",
                "result (CLI transcript):",
                "```",
                str(view["result"] or ""),
                "```",
            ]
        )
    return "\n".join(lines)


def details_of(data: Any) -> list[dict[str, Any]]:
    items = data.get("details") if isinstance(data, dict) else None
    return [d for d in items if isinstance(d, dict)] if isinstance(items, list) else []


def total_devices_of(data: Any) -> int | None:
    """``total_elements`` of a deploy-template/<id>/query answer (the number of devices in
    the deployment across every page); None when the key is absent or not numeric."""
    return as_int(data.get("total_elements")) if isinstance(data, dict) else None


def all_details_present(data: Any) -> bool:
    """True when the ``details`` list holds every device ``total_elements`` promises (or the
    platform did not say how many there are)."""
    total = total_devices_of(data)
    return total is None or len(details_of(data)) >= total


def device_count_text(details: list[dict[str, Any]], total: int | None) -> str:
    """'3 device(s)' or, when Crosswork reports more than were read, '3 of 30 device(s)'."""
    if total is not None and total > len(details):
        return f"{len(details)} of {total} device(s)"
    return f"{len(details)} device(s)"


def _parse_json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return None


def _message_of(response: httpx.Response) -> str:
    """The platform's message text of an answer: ``message`` / ``errorMessage`` of a JSON
    body, else the raw text."""
    data = _parse_json(response)
    if isinstance(data, dict):
        for key in ("message", "errorMessage", "error"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return response.text.strip()


# --- tools -------------------------------------------------------------------


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    async def query_page(
        selector: dict[str, str], page: int
    ) -> tuple[list[dict[str, Any]], int | None, int | None]:
        data = await client.request_json(
            "POST",
            NODES_QUERY_URL,
            json_body=query_body(selector, page_size=SELECTOR_PAGE_SIZE, page=page),
            retryable=True,  # a read: safe to re-send on 5xx / transport errors
        )
        items, result_count, total_count = unwrap(data, "data")
        return [n for n in items if isinstance(n, dict)], result_count, total_count

    async def resolve_devices(selector: dict[str, str]) -> list[dict[str, Any]]:
        """Every device the selector matches, from ONE page; PlatformError when none match
        or the match may exceed the page (a bulk write would silently drop the rest)."""
        nodes, result_count, total_count = await query_page(selector, 0)
        if not nodes:
            raise PlatformError(
                f"no device matches {describe_selector(selector)}; nothing was sent. "
                f"{_SELECTOR_HELP}"
            )
        if result_count is not None and result_count > len(nodes):
            raise PlatformError(
                f"{describe_selector(selector)} matches {result_count} devices, more than the "
                f"{SELECTOR_PAGE_SIZE} this tool handles in one call; nothing was sent. "
                f"{_BATCH_HELP}"
            )
        if result_count is None and len(nodes) >= SELECTOR_PAGE_SIZE:
            known = (
                f" (the inventory holds {total_count} devices)" if total_count is not None else ""
            )
            raise PlatformError(
                f"{describe_selector(selector)} fills a whole page of {SELECTOR_PAGE_SIZE} "
                f"devices and Crosswork did not report the match count{known}, so the match "
                f"may be larger than the {SELECTOR_PAGE_SIZE} this tool handles in one call; "
                f"nothing was sent. {_BATCH_HELP}"
            )
        return nodes

    async def find_one_device(selector: dict[str, str]) -> dict[str, Any]:
        """Exactly one device; PlatformError when none or several match."""
        nodes = await resolve_devices(selector)
        if len(nodes) > 1:
            names = ", ".join(str(n.get("host_name")) for n in nodes[:5])
            raise PlatformError(
                f"{describe_selector(selector)} matched {len(nodes)} devices ({names}, ...); "
                "this tool takes exactly one. Narrow the host_name or use the uuid."
            )
        return nodes[0]

    async def get_template_versions(name: str, all_versions: bool) -> list[dict[str, Any]]:
        """``GET templates/<name>?all=`` -> the ``templates`` list ([] for an unknown name)."""
        data = await client.request_json(
            "GET",
            f"{TEMPLATES_URL}/{quote(name, safe='')}",
            params={"all": "true" if all_versions else "false"},
        )
        items = data.get("templates") if isinstance(data, dict) else None
        return [t for t in items if isinstance(t, dict)] if isinstance(items, list) else []

    async def fetch_backup_job(name: str) -> Any:
        return await client.request_json(
            "POST", f"{BACKUP_JOB_URL}/{quote(name, safe='')}", json_body={}, retryable=True
        )

    async def fetch_deployment(deployment_id: str) -> dict[str, Any]:
        """``POST deploy-template/<id>/query {}`` -> the first page's document with
        ``details`` holding EVERY device of the deployment that could be read.

        The endpoint is paged (``?page=&size=`` are documented for it and verified on
        the sibling ``templates/query``; the answer carries ``page_size, page_number,
        total_pages, total_elements``). ``size`` = DEPLOYMENT_PAGE_SIZE fits every
        deployment this server makes (cnc_deploy_config_template caps at
        SELECTOR_PAGE_SIZE devices) in one page; a larger (UI-made) deployment is
        followed across pages while ``total_elements`` says more exist. A page that
        brings no device not already seen (a ``page`` parameter the platform ignores)
        ends the walk, so callers compare ``len(details)`` with ``total_elements``
        (all_details_present) before treating the list as complete.
        """
        url = f"{DEPLOY_TEMPLATE_URL}/{quote(deployment_id, safe='')}/query"
        first: dict[str, Any] = {}
        details: list[dict[str, Any]] = []
        seen: set[str] = set()
        for page in range(DEPLOYMENT_MAX_PAGES):
            data = await client.request_json(
                "POST",
                url,
                params={"page": page, "size": DEPLOYMENT_PAGE_SIZE},
                json_body={},
                retryable=True,
            )
            if page == 0:
                first = dict(data) if isinstance(data, dict) else {}
            fresh = []
            for d in details_of(data):
                key = str(d.get("device_uuid") or json.dumps(d, sort_keys=True, default=str))
                if key not in seen:
                    seen.add(key)
                    fresh.append(d)
            details.extend(fresh)
            total = total_devices_of(data)
            if not fresh or total is None or len(details) >= total:
                break
        first["details"] = details
        return first

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_device_config_preferences",
        title="Get Device Configuration Preferences",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_device_config_preferences() -> str:
        """Get the device-configuration preferences: backup retention, automatic
        backup triggers, timeouts and whether NSO is configured.

        Read-only; ``GET /crosswork/config/v1/device-config-preferences/
        config-settings`` (verified). Keys: ``timeout`` and ``hold_off_timer``
        (seconds for a device configuration operation and the settle time after
        a change before a backup), ``max_backups_to_retain`` and
        ``max_days_to_retain_backups`` (per-device backup retention),
        ``max_days_to_retain_jobs``, ``alarm_threshold``,
        ``backup_config_on_device_add`` (the ``Initial_Version`` backup every
        device gets on add), ``backup_config_on_config_change`` (a backup after
        each detected change), ``initiate_backup_config_from_ems``,
        ``enable_syslog_traps_on_device`` and ``is_nso_configured``. Use it to
        explain why a device has (or lacks) automatic backups, or how many
        backups cnc_list_device_backups can hold. Changing the preferences
        (``PATCH config-settings``) is not exposed.

        Returns:
            str: Markdown (one "- key: value" line per setting) followed by the
            JSON document as Crosswork returns it. On failure: "Error: ..."
            (403 -> the account lacks the configuration-management task).
        """
        try:
            data = await client.request_json("GET", PREFERENCES_URL)
            data = data if isinstance(data, dict) else {}
            lines = ["# Device configuration preferences", ""]
            lines.extend(f"- {key}: {value}" for key, value in data.items())
            if not data:
                lines.append("- (no settings returned)")
            lines.extend(["", to_json(data)])
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_device_backups",
        title="List Device Configuration Backups",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_device_backups(
        uuid: Annotated[
            str | None,
            Field(
                description="Device uuid (e.g. '2a9b7c1e-0f3d-4b8a-9c6e-1d2f3a4b5c6d').",
                max_length=100,
            ),
        ] = None,
        host_name: Annotated[
            str | None,
            Field(
                description=(
                    "Device host name, exact match, case-insensitive (e.g. 'PE1'); a '*' "
                    "wildcard is accepted but must resolve to exactly one device."
                ),
                max_length=253,
            ),
        ] = None,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the stored configuration backups of one device, newest first.

        Read-only. Resolves exactly one device with ``POST nodes/query`` (pass
        uuid or host_name), then ``GET /crosswork/config/v1/config-backup/
        <uuid>`` (verified) -> ``backup_config[]``. Each backup carries
        ``name`` (``Initial_Version`` for the backup taken on device add,
        ``<job>_<run_id>`` for one taken by a backup job), ``backedup_at``
        (ISO), ``trigger`` (DEVICE_ADD | SCHEDULED_JOB | CONFIG_CHANGE),
        ``status`` (SUCCESS | FAILED), ``complianceStatus`` (COMPLIANT |
        NON_COMPLIANT — against the device's compliance policy, if any),
        ``pinned`` (kept beyond the retention limit), ``tag``, ``notes``,
        ``result`` and ``created_by``. The configuration text itself is NOT
        in the list (``file`` is empty here): read one backup with
        cnc_get_device_backup(name=...) — or the newest with no name. A
        device with no backups is a non-error "No backups for ..." (also what
        an unknown uuid answers; the selector step already rules that out).
        Take a new one with cnc_backup_device_config; remove one with
        cnc_delete_device_backup. Retention is governed by
        cnc_get_device_config_preferences (max_backups_to_retain).

        Args:
            uuid / host_name: exactly one selector, one device.
            response_format: markdown (one line per backup) or json.

        Returns:
            str: Markdown "N backup(s) for **PE1** (uuid), newest first:" and
            one "- **name**: backedup_at, trigger, status, compliance
            (pinned; tags ...)" line per backup, or JSON:
            {"device": {"host_name", "uuid"}, "count": int,
             "backups": [{"name", "backedup_at", "trigger", "status",
                          "complianceStatus", "pinned", "tag": [str], "notes",
                          "result", "created_by"}]}
            "No backups for PE1 (uuid)." when the list is empty. "Error: no
            device matches ..." / "... matched N devices", or "Error: ..." on
            an API failure.
        """
        try:
            node = await find_one_device(_selector(uuid, host_name))
            node_uuid = str(node.get("uuid"))
            data = await client.request_json("GET", f"{CONFIG_BACKUP_URL}/{node_uuid}")
            items = data.get("backup_config") if isinstance(data, dict) else None
            backups = sort_backups([b for b in items if isinstance(b, dict)]) if items else []
            views = [backup_view(b) for b in backups]
            if response_format is ResponseFormat.JSON:
                payload = {"device": device_ref(node), "count": len(views), "backups": views}
                return finalize(to_json(payload), settings)
            if not views:
                return finalize(
                    f"No backups for {device_label(node)}. Take one with cnc_backup_device_config.",
                    settings,
                )
            lines = [
                f"{len(views)} backup(s) for **{node.get('host_name')}** ({node_uuid}), "
                "newest first:"
            ]
            lines.extend(backup_line(v) for v in views)
            lines.append(
                "\nRead the configuration text with cnc_get_device_backup(name=...) — no name "
                "reads the newest."
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_device_backup",
        title="Get Device Configuration Backup",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_device_backup(
        uuid: Annotated[
            str | None,
            Field(
                description="Device uuid (e.g. '2a9b7c1e-0f3d-4b8a-9c6e-1d2f3a4b5c6d').",
                max_length=100,
            ),
        ] = None,
        host_name: Annotated[
            str | None,
            Field(
                description=(
                    "Device host name, exact match, case-insensitive (e.g. 'PE1'); must resolve "
                    "to exactly one device."
                ),
                max_length=253,
            ),
        ] = None,
        name: Annotated[
            str | None,
            Field(
                description=(
                    "Backup name as listed by cnc_list_device_backups (e.g. 'Initial_Version' or "
                    "'mcp-backup-20260913-120000_e79bb231-3b4d-425e-940e-e229a526f06b'); omit "
                    "for the newest backup."
                ),
                max_length=300,
            ),
        ] = None,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Read one configuration backup of a device — the stored running
        configuration text (secrets masked) with its metadata.

        Read-only. Resolves exactly one device with ``POST nodes/query``
        first. With ``name``: ``GET /crosswork/config/v1/config-backup/<uuid>/
        <name>`` (URL-encoded); an unknown name answers HTTP 200 with an
        EMPTY body (verified) and is reported as "Error: no backup ...".
        Without ``name``: ``GET /crosswork/config/v1/latest-config-backup/
        <uuid>`` — the newest backup. Both answer the backup object WITH
        ``file[{file_name, config, type}]``: the full configuration text as
        Crosswork stored it, passwords and keys already replaced by
        ``********`` by the platform (type RUNNINGCONFIG on IOS XR; STARTUPCONFIG
        and others where the platform collects them). Use it to inspect a
        device's configuration at a point in time, to diff two backups (call
        it twice), or before cnc_delete_device_backup. The whole response
        passes through the response-size cap (max_response_chars, 40 000 by
        default): a long configuration is cut with a "[Truncated ...]" note —
        the markdown header says how many characters the files hold, and the
        JSON form is not smaller. Restoring a backup is NOT exposed here (use
        the Crosswork UI) — this server can only deploy configuration through
        templates (cnc_deploy_config_template).

        Args:
            uuid / host_name: exactly one selector, one device.
            name: the backup name; omit for the newest backup.
            response_format: markdown (header + fenced configuration text per
                file) or json (the raw backup object).

        Returns:
            str: Markdown "# Backup <name> of PE1 (uuid)", the metadata lines
            (taken, trigger, status, compliance, result, notes, pinned, tags,
            file/character count) and one "## <file> (<type>)" fenced block
            per configuration file; or the raw JSON backup object
            {"name", "device_uuid", "file": [{"file_name", "config", "type"}],
             "backedup_at", "status", "tag", "pinned", "trigger", "result",
             "notes", "created_by", "complianceStatus"}.
            "Error: no backup '<name>' for PE1 (uuid) (list with
            cnc_list_device_backups)" for an unknown name; "Error: no backup
            for ..." when the device has none; "Error: no device matches ...",
            or "Error: ..." on an API failure.
        """
        try:
            node = await find_one_device(_selector(uuid, host_name))
            node_uuid = str(node.get("uuid"))
            wanted = (name or "").strip()
            if wanted:
                url = f"{CONFIG_BACKUP_URL}/{node_uuid}/{quote(wanted, safe='')}"
            else:
                url = f"{LATEST_BACKUP_URL}/{node_uuid}"
            data = await client.request_json("GET", url)
            if not isinstance(data, dict) or not data.get("name"):
                if wanted:
                    raise PlatformError(
                        f"no backup '{wanted}' for {device_label(node)} (list with "
                        "cnc_list_device_backups)."
                    )
                raise PlatformError(
                    f"no backup for {device_label(node)}: the device has no stored "
                    "configuration yet (cnc_list_device_backups lists them; "
                    "cnc_backup_device_config takes one)."
                )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(data), settings)
            return finalize(backup_markdown(node, data), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_config_backup_jobs",
        title="List Configuration Backup Jobs",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_config_backup_jobs(
        status: Annotated[
            str | None,
            Field(
                description=(
                    "Comma-separated job statuses to keep (SCHEDULED, RUNNING, COMPLETED, "
                    "FAILED, PAUSED, BLOCKED; e.g. 'RUNNING,SCHEDULED'); omit for every job."
                ),
                max_length=100,
            ),
        ] = None,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the configuration backup (and restore) jobs with their last-run
        outcome, plus the platform's per-status counts.

        Read-only; ``POST /crosswork/config/v1/config-backup-jobs`` with
        ``{"status": [...]}`` when a filter is given and ``{}`` otherwise
        (both verified). Each entry is ``{"job": {name, task, schedule,
        params, status, last_run_at, next_run_at, last_run_status, job_type
        BACKUP|RESTORE, duration (ms), percentage_completed, created_by,
        run_count}, "device_count"}``; the answer also carries
        ``backup_job_status_summary`` (scheduled/completed/failed/running/
        paused/blocked counts) and a ``page_summary`` (the platform pages at
        1000 — not exposed). ``status`` is the schedule state (SCHEDULED
        waiting for its start time, RUNNING, COMPLETED, FAILED, PAUSED,
        BLOCKED); ``last_run_status`` is the outcome of the last run
        (NOT_STARTED, IN_PROGRESS, SUCCESS, RUN_FAILED, PARTIAL). A one-shot
        job that ran reads COMPLETED / SUCCESS with ``next_run_at`` at the
        epoch (rendered '-'). Drill into a job's runs with
        cnc_get_config_backup_job; create one with cnc_backup_device_config;
        remove one with cnc_delete_config_backup_job.

        Args:
            status: comma-separated statuses to keep; omit for all.
            response_format: markdown or json.

        Returns:
            str: Markdown "N job(s) (scheduled a, running b, completed c,
            failed d, paused e, blocked f):" and one "- **name** BACKUP: status
            ..., last run ... at ... (ms), next run ..., N device(s), by user"
            line per job; or JSON:
            {"count": int, "jobs": [{"name", "job_type", "status",
              "last_run_status", "last_run_at", "next_run_at", "duration_ms",
              "run_count", "created_by", "device_count"}],
             "status_summary": {"scheduled_count", "completed_count", "failed_count",
                                "running_count", "paused_count", "blocked_count"},
             "page_summary": {...}}
            "Error: Unknown backup job status ..." for a bad filter value;
            "Error: ..." on an API failure.
        """
        try:
            wanted = parse_statuses(status, BACKUP_JOB_STATUSES, "backup job status")
            body: dict[str, Any] = {"status": wanted} if wanted else {}
            data = await client.request_json(
                "POST", BACKUP_JOBS_URL, json_body=body, retryable=True
            )
            data = data if isinstance(data, dict) else {}
            entries = data.get("config_backup_restore_jobs")
            entries = (
                [e for e in entries if isinstance(e, dict)] if isinstance(entries, list) else []
            )
            views = []
            for entry in entries:
                job = entry.get("job")
                if isinstance(job, dict):
                    views.append(job_view(job, as_int(entry.get("device_count"))))
            summary = data.get("backup_job_status_summary")
            summary = summary if isinstance(summary, dict) else {}
            page_summary = data.get("page_summary")
            payload = {
                "count": len(views),
                "jobs": views,
                "status_summary": summary,
                "page_summary": page_summary if isinstance(page_summary, dict) else None,
            }
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(payload), settings)
            counts = ", ".join(
                f"{key.removesuffix('_count')} {value}" for key, value in summary.items()
            )
            filter_text = f" with status {', '.join(wanted)}" if wanted else ""
            head = f"{len(views)} backup/restore job(s){filter_text}"
            head += f" ({counts}):" if counts else ":"
            lines = [head]
            lines.extend(job_line(v) for v in views)
            if not views:
                lines.append("- (none)")
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_config_backup_job",
        title="Get Configuration Backup Job",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_config_backup_job(
        name: Annotated[
            str,
            Field(
                description="Job name as listed by cnc_list_config_backup_jobs (e.g. "
                "'mcp-backup-20260913-120000').",
                min_length=1,
                max_length=200,
            ),
        ],
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one backup/restore job with every run it has made.

        Read-only; ``POST /crosswork/config/v1/config-backup-job/<name> {}``
        (URL-encoded, verified) -> ``{"config_backup_restore_job": {"job":
        {...}, "device_count"}, "job_runs": {"backup_job_run": [{run_id,
        job_name, run_status, start_at, duration}]}}``; an unknown name
        answers a bare ``{}`` and is reported as "Error: no backup/restore job
        ...". A run's ``run_status`` is NOT_STARTED | IN_PROGRESS | SUCCESS |
        RUN_FAILED | PARTIAL and its ``run_id`` is the suffix of the backups
        it produced (``<job>_<run_id>`` in cnc_list_device_backups). To wait
        for a run to finish use cnc_wait_for_config_backup_job instead of
        polling this tool.

        Args:
            name: the job name (exact).
            response_format: markdown or json.

        Returns:
            str: Markdown: the job line ("- **name** BACKUP: status ..., last
            run ... at ... (ms), next run ..., N device(s), by user") and one
            "- run <run_id>: <status>, started <t>, <ms>" line per run; or
            JSON {"job": {"name", "job_type", "status", "last_run_status",
            "last_run_at", "next_run_at", "duration_ms", "run_count",
            "created_by", "device_count"}, "runs": [{"run_id", "run_status",
            "start_at", "duration_ms"}]}. "Error: no backup/restore job
            '<name>'" when unknown; "Error: ..." on an API failure.
        """
        try:
            wanted = name.strip()
            data = await fetch_backup_job(wanted)
            job = job_of(data)
            if job is None:
                raise PlatformError(
                    f"no backup/restore job '{wanted}' (cnc_list_config_backup_jobs lists them)."
                )
            view = job_view(job, device_count_of(data))
            runs = [run_view(r) for r in runs_of(data)]
            if response_format is ResponseFormat.JSON:
                return finalize(to_json({"job": view, "runs": runs}), settings)
            lines = [job_line(view), f"{len(runs)} run(s):"]
            lines.extend(run_line(r) for r in runs)
            if not runs:
                lines.append("- (no runs yet)")
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_config_templates",
        title="List Configuration Templates",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_config_templates(
        name: Annotated[
            str | None,
            Field(
                description="Substring of the template name to match (e.g. 'Interface').",
                max_length=200,
            ),
        ] = None,
        template_type: Annotated[
            str | None,
            Field(
                description="Template type to keep: 'SYSTEM' (Cisco-shipped) or "
                "'USER_DEFINED_SIMPLE' (created here / in the UI) — both verified; "
                "'USER_DEFINED_COMPOSITE', 'MANAGEABILITY' and 'EVENT_DRIVEN' are documented "
                "in the TemplateType enum but were not seen on the lab build.",
                max_length=40,
            ),
        ] = None,
        page: Annotated[int, Field(description="0-based page number (e.g. 0).", ge=0)] = 0,
        size: Annotated[
            int, Field(description="Templates per page, 1..200 (e.g. 20).", ge=1, le=200)
        ] = 20,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the configuration templates (Cisco-shipped SYSTEM ones and
        user-defined ones), paged.

        Read-only; ``POST /crosswork/config/v1/templates/query?page=&size=``
        with ``{"filter": {"name": <substring>, "type": [<type>]}}`` (only the
        given keys; ``{"filter": {}}`` without any — verified with filters).
        The answer ``{"template": [...], "page_size", "page_number",
        "total_pages", "total_elements"}`` reports ``total_elements`` as a
        STRING, coerced here. Each template: ``name``, ``version`` (1.0),
        ``type`` SYSTEM | USER_DEFINED_SIMPLE, ``category`` DEVICE |
        INTERFACE (| MODULE documented), ``transport`` CLI (| GNMI | NETCONF
        documented), ``description``, ``variables`` (count
        here), ``last_deployed_status`` (NOT_DEPLOYED | SUCCESS | ...),
        ``author``, ``device_type``. The system templates
        (``Cisco_IOS-XR_Interface_config`` etc.) are deployable as they are.
        Read a template's configlet and variables with
        cnc_get_config_template; create one with cnc_create_config_template;
        push one with cnc_deploy_config_template.

        Args:
            name: name substring filter.
            template_type: 'SYSTEM' or 'USER_DEFINED_SIMPLE' (verified); the other
                documented TemplateType values are accepted, unverified.
            page, size: paging (0-based page, 1..200 per page).
            response_format: markdown or json.

        Returns:
            str: Markdown "N of M template(s) (page p):" and one "- **name**
            vX TYPE/CATEGORY/TRANSPORT — description; N variable(s); last
            deployed: ...; by author" line per template, with a "next page"
            note when more exist; or JSON pagination envelope
            {"total": int, "count": int, "page": int, "page_size": int,
             "total_pages": int|null, "has_more": bool, "next_page": int|null,
             "items": [{"name", "version", "type", "category", "transport",
                        "description", "variables": int, "last_deployed_status",
                        "author", "device_type", "created_at", "updated_at"}]}
            "Error: Unknown template type ..." for a bad filter; "Error: ..."
            on an API failure.
        """
        try:
            filters: dict[str, Any] = {}
            name_value = (name or "").strip()
            if name_value:
                filters["name"] = name_value
            type_value = (template_type or "").strip().upper()
            if type_value:
                if type_value not in TEMPLATE_TYPES:
                    raise PlatformError(
                        f"Unknown template type '{template_type}'. Use one of: "
                        f"{', '.join(TEMPLATE_TYPES)}."
                    )
                filters["type"] = [type_value]
            data = await client.request_json(
                "POST",
                TEMPLATES_QUERY_URL,
                params={"page": page, "size": size},
                json_body={"filter": filters},
                retryable=True,
            )
            data = data if isinstance(data, dict) else {}
            items = data.get("template")
            templates = [t for t in items if isinstance(t, dict)] if isinstance(items, list) else []
            views = [template_view(t) for t in templates]
            total = as_int(data.get("total_elements"))
            env = page_envelope(
                views, result_count=total, total_count=None, page_size=size, page=page
            )
            env.pop("collection_total", None)
            env["total_pages"] = as_int(data.get("total_pages"))
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(env), settings)
            total_text = str(total) if total is not None else "?"
            lines = [f"{len(views)} of {total_text} template(s) (page {page}):"]
            lines.extend(template_line(v) for v in views)
            if not views:
                lines.append("- (none)")
            if env["has_more"]:
                lines.append(f"\nMore templates: call again with page={env['next_page']}.")
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_config_template",
        title="Get Configuration Template",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_config_template(
        name: Annotated[
            str,
            Field(
                description="Template name, exact (e.g. 'Cisco_IOS-XR_Interface_config').",
                min_length=1,
                max_length=200,
            ),
        ],
        all_versions: Annotated[
            bool,
            Field(description="True to return every stored version instead of the latest."),
        ] = False,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one configuration template: its variables and the Velocity configlet.

        Read-only; ``GET /crosswork/config/v1/templates/<name>?all=true|false``
        (URL-encoded, verified) -> ``{"templates": [...]}`` — one entry
        (the latest version) or every version with ``all_versions``; an
        unknown name answers an empty list and is reported as "Error: no
        template ...". The configlet is Apache Velocity: ``${name}`` is
        replaced by the variable's value at deployment and ``#if($x ==
        'true') ... #end`` blocks are conditional. Each variable carries
        ``name``, ``display_name``, ``type``, ``default_value``,
        ``is_mandatory`` (a value is required at deployment — no default),
        ``description`` and ``options``. Use it before
        cnc_deploy_config_template to see which variables to pass, and to
        review a template created with cnc_create_config_template.

        Args:
            name: the template name (exact).
            all_versions: return every version (default: latest only).
            response_format: markdown or json.

        Returns:
            str: Markdown per version: "# Template <name> vN", a metadata line
            (type, category, transport, author, created, last deployed), the
            description and device types, a variables table (variable, type,
            default, mandatory) and the configlet in a fenced block; or JSON
            {"count": int, "templates": [<raw template objects>]} with
            "configlet", "variables": [{"name", "display_name", "type",
            "default_value", "is_mandatory", "description", "options"}], ...
            "Error: no template '<name>'" when unknown; "Error: ..." on an
            API failure.
        """
        try:
            wanted = name.strip()
            templates = await get_template_versions(wanted, all_versions)
            if not templates:
                raise PlatformError(
                    f"no template '{wanted}' (cnc_list_config_templates lists them)."
                )
            if response_format is ResponseFormat.JSON:
                return finalize(
                    to_json({"count": len(templates), "templates": templates}), settings
                )
            return finalize("\n\n".join(template_markdown(t) for t in templates), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_template_deployments",
        title="List Template Deployments",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_template_deployments(
        status: Annotated[
            str | None,
            Field(
                description=(
                    "Comma-separated last-run statuses to keep (NOT_STARTED, SUCCESS, "
                    "IN_PROGRESS, RUN_FAILED, PARTIAL — the documented JobRunStatus enum; e.g. "
                    "'RUN_FAILED,PARTIAL'); omit for every deployment. The filter form is "
                    "documented but was not exercised live."
                ),
                max_length=100,
            ),
        ] = None,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the template deployment jobs (every cnc_deploy_config_template /
        UI deployment) with their outcome.

        Read-only; ``POST /crosswork/config/v1/templates/jobs/deployments/
        query`` with ``{}`` (verified) when no filter is given, or
        ``{"last_run_status": [...]}`` (documented in JobFilterRequest,
        UNVERIFIED live — if the platform ignores it, unfiltered jobs come
        back) -> ``{"jobs": [{name, task, params, status, last_run_at,
        last_run_status, job_type DEPLOYMENT, duration (ms),
        percentage_completed, created_by, run_count}], "page_summary"}``.
        ``name`` is the deployment id (``<template>_DeployJob_<date>_<time>``)
        that cnc_get_template_deployment, cnc_wait_for_template_deployment
        and cnc_delete_template_deployment take. ``last_run_status`` is the
        JobRunStatus enum NOT_STARTED (just scheduled) | IN_PROGRESS |
        SUCCESS | RUN_FAILED | PARTIAL (PARTIAL = some devices failed).

        Args:
            status: comma-separated last-run statuses (documented enum, filter
                form unverified live); omit for all.
            response_format: markdown or json.

        Returns:
            str: Markdown "N deployment(s):" and one "- **<deployment id>**:
            last run <status> at <t> (<ms>), status <job status>, by <user>,
            runs N" line per deployment; or JSON
            {"count": int, "deployments": [{"name", "job_type", "status",
              "last_run_status", "last_run_at", "next_run_at", "duration_ms",
              "run_count", "created_by"}], "page_summary": {...}}
            "Error: Unknown deployment status ..." for a bad filter; "Error:
            ..." on an API failure.
        """
        try:
            wanted = parse_statuses(status, DEPLOYMENT_RUN_STATUSES, "deployment status")
            body: dict[str, Any] = {"last_run_status": wanted} if wanted else {}
            data = await client.request_json(
                "POST", DEPLOYMENTS_QUERY_URL, json_body=body, retryable=True
            )
            data = data if isinstance(data, dict) else {}
            items = data.get("jobs")
            jobs = [j for j in items if isinstance(j, dict)] if isinstance(items, list) else []
            views = [job_view(j) for j in jobs]
            page_summary = data.get("page_summary")
            payload = {
                "count": len(views),
                "deployments": views,
                "page_summary": page_summary if isinstance(page_summary, dict) else None,
            }
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(payload), settings)
            filter_text = f" with last run {', '.join(wanted)}" if wanted else ""
            lines = [f"{len(views)} template deployment(s){filter_text}:"]
            for v in views:
                lines.append(
                    f"- **{v.get('name') or '?'}**: last run {v.get('last_run_status') or '?'} "
                    f"at {_when(v.get('last_run_at'))} ({_ms(v.get('duration_ms'))}), status "
                    f"{v.get('status') or '?'}, by {v.get('created_by') or '?'}, runs "
                    f"{v.get('run_count') if v.get('run_count') is not None else '?'}"
                )
            if not views:
                lines.append("- (none)")
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_template_deployment",
        title="Get Template Deployment",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_template_deployment(
        deployment_id: Annotated[
            str,
            Field(
                description="Deployment id (job_id of cnc_deploy_config_template / name in "
                "cnc_list_template_deployments, e.g. 'mcp-loopback_DeployJob_20260913_120500').",
                min_length=1,
                max_length=300,
            ),
        ],
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one template deployment's per-device results: status, the rendered
        configlet and the CLI transcript.

        Read-only; ``POST /crosswork/config/v1/templates/deploy-template/
        <id>/query {}`` (URL-encoded, verified) -> ``{"details": [{deployment_id,
        template_name, version, device_uuid, deployed_configlet, deployed_at,
        status, result, variables, params, duration}], page_size, page_number,
        total_pages, total_elements}``. The answer is PAGED: ``?page=&size=``
        (documented) are sent with size 100 and further pages are read while
        ``total_elements`` says more devices exist, so ``count`` normally
        equals ``total``; when it does not (the platform ignored the paging),
        the Markdown says "N of M device(s)" and the unseen devices' outcome
        is unknown. ``device_uuid`` holds the device HOSTNAME on the wire
        (verified) — rendered as ``device``. ``status`` NOT_STARTED |
        IN_PROGRESS | SUCCESS | FAILED | PARTIAL (seen live) or NOT_DEPLOYED |
        SYSTEM_FAILURE (documented DeploymentStatus values, not produced by
        the lab); ``result`` is the CLI session transcript (the commands as
        sent, the router's answers, the commit); an unknown id answers empty
        ``details`` and is reported as "Error: no deployment ...". Right after
        cnc_deploy_config_template use cnc_wait_for_template_deployment
        instead of polling this tool.

        Args:
            deployment_id: the deployment id.
            response_format: markdown or json.

        Returns:
            str: Markdown "# Deployment <id>", "N device(s): a SUCCESS, b
            FAILED" (or "N of M device(s)" when not every device could be
            read) and per device "## <host> — <status> (deployed <t>, <ms>)"
            with the deployed configlet and the CLI transcript in fenced
            blocks; or JSON {"deployment_id", "count": int, "total": int|null
            (Crosswork's total_elements), "details":
            [{"device", "status", "deployed_at", "duration_ms", "deployment_id",
              "version", "variables", "deployed_configlet", "result"}]}.
            "Error: no deployment '<id>'" when unknown; "Error: ..." on an
            API failure.
        """
        try:
            wanted = deployment_id.strip()
            data = await fetch_deployment(wanted)
            details = details_of(data)
            if not details:
                raise PlatformError(
                    f"no deployment '{wanted}' (cnc_list_template_deployments lists them)."
                )
            total = total_devices_of(data)
            if response_format is ResponseFormat.JSON:
                payload = {
                    "deployment_id": wanted,
                    "count": len(details),
                    "total": total,
                    "details": [detail_view(d) for d in details],
                }
                return finalize(to_json(payload), settings)
            return finalize(deployment_markdown(wanted, details, total), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_backup_device_config",
        title="Back Up Device Configuration",
        read_only=False,
        destructive=False,
        idempotent=False,
    )
    async def cnc_backup_device_config(
        uuid: Annotated[
            str | None,
            Field(
                description="Device uuid to back up (e.g. '2a9b7c1e-0f3d-4b8a-9c6e-1d2f3a4b5c6d').",
                max_length=100,
            ),
        ] = None,
        host_name: Annotated[
            str | None,
            Field(
                description=(
                    "Device host name(s) to back up: exact match, case-insensitive, '*' "
                    "wildcard (e.g. 'PE1', 'PE*', or '*' for every device — one job)."
                ),
                max_length=253,
            ),
        ] = None,
        job_name: Annotated[
            str | None,
            Field(
                description="Name of the backup job, unique on the platform (e.g. "
                "'pre-change-PE1'); default 'mcp-backup-<YYYYmmdd-HHMMSS>'.",
                max_length=200,
            ),
        ] = None,
        delay_seconds: Annotated[
            int,
            Field(
                description="Seconds from now until the job starts, 0..3600 (e.g. 5).",
                ge=0,
                le=3600,
            ),
        ] = 5,
    ) -> str:
        """Take a configuration backup of the selected device(s) now, through a
        one-shot backup job.

        WRITE operation — only registered when CNC_MCP_ENABLE_WRITES=true.
        The selector (exactly one of uuid / host_name; host_name may carry
        '*') is resolved with ``POST nodes/query`` FIRST: zero matches is an
        Error and nothing is sent; more than 100 matches (or a full page
        whose count Crosswork did not report) is refused — narrow the pattern.
        Then ONE ``POST /crosswork/config/v1/schedule-config-backup-job
        {"name", "trigger": "SCHEDULED_JOB", "schedule": {"start_at_time":
        "<now + delay, %Y-%m-%dT%H:%M:%S.000Z>"}, "device_uuids":
        {"device_uuids": [...]}}`` (verified) answers 202 ``{"status_code":
        202, "job_id": "<name>", "message": "Backup Config request is
        successful"}``. A start time a few seconds ahead runs at once: on the
        lab the run was SUCCESS after ~6 s and a backup named
        ``<job>_<run_id>`` appeared on the device (cnc_list_device_backups).
        Follow with cnc_wait_for_config_backup_job(name=<job>) — the
        ``next`` field spells it out. Job names are unique: a duplicate is
        HTTP 500 "Job already exists with name <n>" (reported as an Error
        that says to pick another job_name or delete the old job with
        cnc_delete_config_backup_job); the default name carries the UTC
        second, so it is unique in practice. The job record stays until
        deleted (max_days_to_retain_jobs in the preferences) — remove it
        with cnc_delete_config_backup_job once the backup exists; the backup
        itself is independent of the job. The POST is not auto-retried (a
        lost answer cannot schedule the job twice: a re-run with the same
        name answers the duplicate error). Not idempotent: every call makes a
        new job and, when it runs, a new backup.

        Args:
            uuid / host_name: exactly one selector; host_name may use '*'.
            job_name: unique job name (default 'mcp-backup-<timestamp>').
            delay_seconds: start delay (default 5; 0 is accepted).

        Returns:
            str: JSON {"job_id": str, "job_name": str, "status_code": 202,
            "message": str, "start_at_time": str, "devices": [{"host_name",
            "uuid"}], "next": "cnc_wait_for_config_backup_job(name='<job>')
            ..."}. "Error: no device matches ..." (nothing sent), "Error:
            backup job '<n>' was not created: Job already exists with name
            <n>. Pick another job_name ...", or "Error: ..." on an API
            failure.
        """
        try:
            selector = _selector(uuid, host_name)
            now = utcnow()
            name = (job_name or "").strip() or default_backup_job_name(now)
            nodes = await resolve_devices(selector)
            start_at = start_at_time(delay_seconds, now)
            body = backup_job_body(name, start_at, [str(n.get("uuid")) for n in nodes])
            response = await client.request(
                "POST", SCHEDULE_BACKUP_JOB_URL, json_body=body, raise_on_error=False
            )
            if not response.is_success:
                message = _message_of(response)
                if "already exists" in message.lower():
                    raise PlatformError(
                        f"backup job '{name}' was not created: {message}. Pick another "
                        "job_name (the default 'mcp-backup-<timestamp>' is unique per second), "
                        "or delete the old job with cnc_delete_config_backup_job "
                        f"(cnc_get_config_backup_job(name='{name}') shows it)."
                    )
                raise http_error(response)
            data = _parse_json(response)
            data = data if isinstance(data, dict) else {}
            job_id = str(data.get("job_id") or name)
            payload = {
                "job_id": job_id,
                "job_name": name,
                "status_code": data.get("status_code", response.status_code),
                "message": data.get("message"),
                "start_at_time": start_at,
                "devices": [device_ref(n) for n in nodes],
                "next": (
                    f"cnc_wait_for_config_backup_job(name='{job_id}') waits for the run; the "
                    "backups then appear in cnc_list_device_backups as '<job>_<run_id>'."
                ),
            }
            return finalize(to_json(payload), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_wait_for_config_backup_job",
        title="Wait for Configuration Backup Job",
        read_only=True,
        idempotent=True,
    )
    async def cnc_wait_for_config_backup_job(
        name: Annotated[
            str,
            Field(
                description="Backup job name (the job_id cnc_backup_device_config returned, "
                "e.g. 'mcp-backup-20260913-120000').",
                min_length=1,
                max_length=200,
            ),
        ],
        timeout_seconds: Annotated[
            int, Field(description="How long to wait in total, 10..900 (e.g. 120).", ge=10, le=900)
        ] = 120,
        interval_seconds: Annotated[
            int, Field(description="Seconds between polls, 2..60 (e.g. 5).", ge=2, le=60)
        ] = 5,
    ) -> str:
        """Poll a backup job until its run finishes (SUCCESS, RUN_FAILED or
        PARTIAL) or the timeout elapses.

        Read-only convergence wait. Call it right after
        cnc_backup_device_config instead of polling cnc_get_config_backup_job
        in a loop. Polls ``POST config-backup-job/<name> {}`` every
        ``interval_seconds``:

        - ``job.last_run_status`` SUCCESS -> success, with the runs;
        - RUN_FAILED -> "Error: backup job <name> failed" with the run
          details (this is the job's outcome, not a timeout — check the
          device's reachability with cnc_get_device and the job in the UI);
        - PARTIAL (a multi-device job where some devices failed) -> "Error:
          ... finished PARTIAL" with the runs; cnc_list_device_backups shows
          which devices got a backup;
        - NOT_STARTED / IN_PROGRESS keep polling; a bare ``{}`` (the job is
          not visible yet — a freshly scheduled job can take a moment to
          appear, or the name is wrong) keeps polling too, and is reported
          as "not found (yet)" if it is still ``{}`` at the timeout.

        On timeout the answer is NOT an error: "Backup job <name> not
        finished after Ns; ..." — call again to keep waiting. Job names are
        unique, so a name that ran before answers its old outcome at once
        (a job cannot be re-run through this server).

        Args:
            name: the job name.
            timeout_seconds, interval_seconds: the polling budget.

        Returns:
            str: On success: "Backup job <name> finished SUCCESS after Ns (N
            run(s))." followed by JSON {"job": {...}, "runs": [{"run_id",
            "run_status", "start_at", "duration_ms"}], "elapsed_seconds"}.
            On timeout (not an error): "Backup job <name> not finished after
            Ns; status ..., last run ..." (or "... not found (yet) ...") plus
            the same JSON. "Error: backup job <name> failed ..." / "...
            finished PARTIAL ..." with the runs; "Error: ..." on an API
            failure.
        """
        try:
            wanted = name.strip()
            finished, data, elapsed = await wait_until(
                lambda: fetch_backup_job(wanted),
                lambda d: (job_of(d) or {}).get("last_run_status") in RUN_TERMINAL_STATES,
                timeout_seconds=timeout_seconds,
                interval_seconds=interval_seconds,
            )
            job = job_of(data)
            runs = [run_view(r) for r in runs_of(data)]
            view = job_view(job, device_count_of(data)) if job else None
            payload = {"job": view, "runs": runs, "elapsed_seconds": round(elapsed)}
            state = (job or {}).get("last_run_status")
            if finished and state == RUN_SUCCESS:
                head = (
                    f"Backup job {wanted} finished SUCCESS after {elapsed:.0f}s "
                    f"({len(runs)} run(s)). The backups are listed by cnc_list_device_backups "
                    f"as '{wanted}_<run_id>'."
                )
            elif finished:
                verdict = "failed" if state == RUN_FAILED else f"finished {state}"
                run_text = "; ".join(run_line(r).removeprefix("- ") for r in runs) or "no runs"
                raise PlatformError(
                    f"backup job {wanted} {verdict} after {elapsed:.0f}s (last_run_status "
                    f"{state}): {run_text}. Check the device(s) with cnc_get_device "
                    "(reachability, credentials) and the job in the Crosswork UI; "
                    "cnc_list_device_backups shows which devices got a backup.\n"
                    f"{to_json(payload)}"
                )
            elif job is None:
                head = (
                    f"Backup job {wanted} not found (yet) after {elapsed:.0f}s: the platform "
                    "still answers {} for that name. A just-scheduled job can take a moment "
                    "to appear — call again; if it never does, check the name with "
                    "cnc_list_config_backup_jobs."
                )
            else:
                head = (
                    f"Backup job {wanted} not finished after {elapsed:.0f}s; status "
                    f"{job.get('status')}, last run {state or '?'}. Call again to keep waiting."
                )
            return finalize(f"{head}\n{to_json(payload)}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_config_backup_job",
        title="Delete Configuration Backup Job",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_config_backup_job(
        name: Annotated[
            str,
            Field(
                description="Backup/restore job name to delete (e.g. "
                "'mcp-backup-20260913-120000').",
                min_length=1,
                max_length=200,
            ),
        ],
    ) -> str:
        """Delete a backup/restore job record (its schedule and run history).

        DESTRUCTIVE write — only registered when CNC_MCP_ENABLE_WRITES=true.
        Sends ``DELETE /crosswork/config/v1/config-backup-restore-job/<name>``
        (URL-encoded, verified) -> 204. The backups a job produced are NOT
        deleted (they belong to the device: cnc_delete_device_backup). The
        platform answers 204 for an unknown name too (verified), so a 204
        does not prove the job existed — check with
        cnc_get_config_backup_job first when that matters. Deleting a
        SCHEDULED job that has not run yet cancels it; deleting a RUNNING one
        was not exercised. Idempotent and auto-retried on 5xx/transport
        errors.

        Args:
            name: the job name (exact).

        Returns:
            str: "Backup/restore job '<name>' deleted (HTTP 204). The platform
            answers 204 for an unknown name too ..." followed by JSON
            {"job_name": str, "status_code": int}. "Error: ..." on an API
            failure (403 -> the account lacks the configuration-management
            write task).
        """
        try:
            wanted = name.strip()
            response = await client.request(
                "DELETE", f"{BACKUP_RESTORE_JOB_URL}/{quote(wanted, safe='')}"
            )
            head = (
                f"Backup/restore job '{wanted}' deleted (HTTP {response.status_code}). The "
                "platform answers 204 for an unknown name too, so this does not prove the job "
                "existed; cnc_list_config_backup_jobs shows what remains. Its backups (if any) "
                "stay on the devices."
            )
            payload = {"job_name": wanted, "status_code": response.status_code}
            return finalize(f"{head}\n{to_json(payload)}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_device_backup",
        title="Delete Device Configuration Backup",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_device_backup(
        name: Annotated[
            str,
            Field(
                description="Backup name as listed by cnc_list_device_backups (e.g. "
                "'mcp-backup-20260913-120000_e79bb231-3b4d-425e-940e-e229a526f06b').",
                min_length=1,
                max_length=300,
            ),
        ],
        uuid: Annotated[
            str | None,
            Field(
                description="Device uuid (e.g. '2a9b7c1e-0f3d-4b8a-9c6e-1d2f3a4b5c6d').",
                max_length=100,
            ),
        ] = None,
        host_name: Annotated[
            str | None,
            Field(
                description=(
                    "Device host name, exact match, case-insensitive (e.g. 'PE1'); must resolve "
                    "to exactly one device."
                ),
                max_length=253,
            ),
        ] = None,
    ) -> str:
        """Delete one stored configuration backup of a device.

        DESTRUCTIVE write — only registered when CNC_MCP_ENABLE_WRITES=true;
        the stored configuration is gone (read it first with
        cnc_get_device_backup if it may be needed). Resolves exactly one
        device with ``POST nodes/query`` first, then ``DELETE
        /crosswork/config/v1/config-backup/<uuid>/<name>`` (URL-encoded,
        verified) -> HTTP 200 with the text "Deleted backup <name>for device:
        <uuid>". An unknown backup name is HTTP 500 with the text "Backup
        with name <n> not found for device: <uuid>" and is reported as "Error:
        no backup ...". Whether the platform lets ``Initial_Version`` or a
        pinned backup go was not exercised — it decides. Idempotent in effect
        (a second call is the not-found error); auto-retried on 5xx/transport
        errors other than that 500.

        Args:
            name: the backup name (exact).
            uuid / host_name: exactly one selector, one device.

        Returns:
            str: "Deleted backup '<name>' of PE1 (uuid)." followed by JSON
            {"device": {"host_name", "uuid"}, "backup": str, "message": str}.
            "Error: no backup '<name>' for PE1 (uuid) ...", "Error: no device
            matches ..." (nothing sent), or "Error: ..." on an API failure.
        """
        try:
            node = await find_one_device(_selector(uuid, host_name))
            node_uuid = str(node.get("uuid"))
            wanted = name.strip()
            response = await client.request(
                "DELETE",
                f"{CONFIG_BACKUP_URL}/{node_uuid}/{quote(wanted, safe='')}",
                raise_on_error=False,
            )
            message = _message_of(response)
            if response.status_code == 500 and "not found" in message.lower():
                raise PlatformError(
                    f"no backup '{wanted}' for {device_label(node)} (list with "
                    f"cnc_list_device_backups). Platform said: {message}"
                )
            if not response.is_success:
                raise http_error(response)
            payload = {"device": device_ref(node), "backup": wanted, "message": message}
            return finalize(
                f"Deleted backup '{wanted}' of {device_label(node)}.\n{to_json(payload)}",
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_create_config_template",
        title="Create Configuration Template",
        read_only=False,
        destructive=False,
        idempotent=False,
    )
    async def cnc_create_config_template(
        name: Annotated[
            str,
            Field(
                description="Template name, unique on the platform (e.g. 'mcp-loopback99').",
                min_length=1,
                max_length=64,
            ),
        ],
        configlet: Annotated[
            str,
            Field(
                description=(
                    "The configuration text (Apache Velocity: ${var} placeholders, #if/#end "
                    "blocks), e.g. 'interface Loopback99\\n description ${desc}'."
                ),
                min_length=1,
                max_length=20000,
            ),
        ],
        description: Annotated[
            str,
            Field(description="Free-text description (e.g. 'Adds Loopback99').", max_length=500),
        ] = "",
        notes: Annotated[
            str, Field(description="Version notes (e.g. 'Initial version').", max_length=500)
        ] = "Initial version",
        category: Annotated[
            str,
            Field(
                description="'DEVICE' (device-level configlet) or 'INTERFACE' (both verified); "
                "'MODULE' is documented in the TemplateCategory enum but was not exercised live.",
                max_length=20,
            ),
        ] = "DEVICE",
        transport: Annotated[
            str,
            Field(
                description="Delivery transport: 'CLI' (verified); the document also lists "
                "'GNMI' and 'NETCONF'.",
                max_length=20,
            ),
        ] = "CLI",
        variables: Annotated[
            str,
            Field(
                description=(
                    'Variable definitions as TEXT: a JSON array of {"name", "default_value"?, '
                    '"type"?: "string", "is_mandatory"?: false, "description"?} objects, '
                    "or a comma-separated 'name=default,name2' list (e.g. 'desc=mcp,mtu=1500'); "
                    "empty for a template without variables."
                ),
                max_length=20000,
            ),
        ] = "",
        device_types: Annotated[
            str | None,
            Field(
                description="Comma-separated device types the template applies to (e.g. "
                "'Cisco IOS XR'); omit for any.",
                max_length=500,
            ),
        ] = None,
    ) -> str:
        """Create a user-defined (USER_DEFINED_SIMPLE) configuration template.

        WRITE operation — only registered when CNC_MCP_ENABLE_WRITES=true.
        Sends ``POST /crosswork/config/v1/templates {"name", "version": 1.0,
        "notes", "description", "is_read": false, "device_type": [...],
        "category", "transport", "tagList": [], "accessList": [],
        "configlet", "variables": [...], "type": "USER_DEFINED_SIMPLE"}``
        (verified) -> 204. Every variable is completed with ``display_name``
        (= name) and ``options`` ([]) as the UI sends them; the JSON form
        allows ``type``, ``is_mandatory`` (the deployment must then supply a
        value — no default) and ``description``. Variable names must be
        identifiers (letters, digits, '_') and are referenced in the
        configlet as ``${name}``; a ``${x}`` the configlet references but no
        variable defines is returned as a warning (the platform accepts it —
        what it renders was not exercised). Template names are unique: a
        duplicate is HTTP 400 "Template <n> already present." (reported as
        an Error pointing at cnc_list_config_templates). Creating a template
        changes nothing on any device — deploy it with
        cnc_deploy_config_template; remove it with
        cnc_delete_config_template. The POST is not auto-retried (a lost
        answer cannot create the template twice: a re-run answers the
        duplicate error).

        Args:
            name: unique template name (1-64 characters).
            configlet: the Velocity configuration text.
            description, notes: free text.
            category: 'DEVICE' or 'INTERFACE' (verified); 'MODULE' documented, unverified.
            transport: 'CLI' (default; GNMI/NETCONF documented, unverified).
            variables: JSON array text or 'name=default,...' list.
            device_types: comma-separated device types (optional).

        Returns:
            str: JSON {"created": true, "template": {"name", "version": 1.0,
            "type", "category", "transport", "device_type": [str],
            "variables": [{"name", "display_name", "type", "default_value",
            "is_mandatory", "description", "options"}]}, "warnings": [str],
            "next": "cnc_deploy_config_template(name=...) ..."}. "Error:
            template '<n>' was not created: Template <n> already present.
            ..." for a duplicate; "Error: variable ..." / "Error: Unknown
            template category ..." (nothing sent); "Error: ..." on an API
            failure.
        """
        try:
            template_name = name.strip()
            category_value = category.strip().upper()
            if category_value not in TEMPLATE_CATEGORIES:
                raise PlatformError(
                    f"Unknown template category '{category}'. Use one of: "
                    f"{', '.join(TEMPLATE_CATEGORIES)}."
                )
            transport_value = transport.strip().upper()
            if transport_value not in TEMPLATE_TRANSPORTS:
                raise PlatformError(
                    f"Unknown transport '{transport}'. Use one of: "
                    f"{', '.join(TEMPLATE_TRANSPORTS)}."
                )
            defined = parse_template_variables(variables)
            body = template_body(
                template_name,
                configlet,
                description=description.strip(),
                notes=notes.strip(),
                category=category_value,
                transport=transport_value,
                variables=defined,
                device_types=split_csv(device_types),
            )
            names = {v["name"] for v in defined}
            warnings = [
                f"the configlet references ${{{ref}}} but no variable named '{ref}' is defined"
                for ref in configlet_references(configlet)
                if ref not in names
            ]
            response = await client.request(
                "POST", TEMPLATES_URL, json_body=body, raise_on_error=False
            )
            if not response.is_success:
                message = _message_of(response)
                if response.status_code == 400 and "already present" in message.lower():
                    raise PlatformError(
                        f"template '{template_name}' was not created: {message} List the "
                        "existing templates with cnc_list_config_templates and pick another "
                        "name, or delete the old one with cnc_delete_config_template."
                    )
                raise http_error(response)
            payload = {
                "created": True,
                "template": {
                    "name": template_name,
                    "version": 1.0,
                    "type": USER_TEMPLATE_TYPE,
                    "category": category_value,
                    "transport": transport_value,
                    "device_type": body["device_type"],
                    "variables": defined,
                },
                "warnings": warnings,
                "next": (
                    f"cnc_deploy_config_template(name='{template_name}', host_name=...) pushes "
                    "it; cnc_get_config_template shows it as stored."
                ),
            }
            return finalize(to_json(payload), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_config_template",
        title="Delete Configuration Template",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_config_template(
        name: Annotated[
            str,
            Field(
                description="Template name to delete (e.g. 'mcp-loopback99').",
                min_length=1,
                max_length=200,
            ),
        ],
    ) -> str:
        """Delete a configuration template (every version).

        DESTRUCTIVE write — only registered when CNC_MCP_ENABLE_WRITES=true.
        Sends ``DELETE /crosswork/config/v1/templates {"templateName":
        [<name>]}`` (verified; the collection URL with a body is the form) ->
        204. Deleting a template does not touch any device's configuration.
        A refusal is HTTP 500 "Failed to delete templates : [<name>]" —
        the platform gives that same answer for an unknown name and for a
        template that cannot go (a system template, or one a deployment
        record still references): the Error says so and suggests deleting
        the deployment first (cnc_list_template_deployments /
        cnc_delete_template_deployment). Auto-retried on 5xx/transport
        errors other than that 500 (DELETE is idempotent).

        Args:
            name: the template name (exact).

        Returns:
            str: "Template '<name>' deleted (HTTP 204)." followed by JSON
            {"template": str, "status_code": int}. "Error: template '<name>'
            could not be deleted (unknown, a system template, or still
            referenced by a deployment — delete the deployment first) ..."
            on the platform's refusal; "Error: ..." on an API failure.
        """
        try:
            wanted = name.strip()
            response = await client.request(
                "DELETE", TEMPLATES_URL, json_body={"templateName": [wanted]}, raise_on_error=False
            )
            if not response.is_success:
                message = _message_of(response)
                if response.status_code == 500 and "failed to delete" in message.lower():
                    raise PlatformError(
                        f"template '{wanted}' could not be deleted (unknown, a SYSTEM template, "
                        "or still referenced by a deployment — delete the deployment first with "
                        "cnc_delete_template_deployment, see cnc_list_template_deployments; "
                        f"cnc_list_config_templates shows what exists). Platform said: {message}"
                    )
                raise http_error(response)
            payload = {"template": wanted, "status_code": response.status_code}
            return finalize(
                f"Template '{wanted}' deleted (HTTP {response.status_code}).\n{to_json(payload)}",
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_deploy_config_template",
        title="Deploy Configuration Template",
        read_only=False,
        destructive=True,
        idempotent=False,
    )
    async def cnc_deploy_config_template(
        name: Annotated[
            str,
            Field(
                description="Template name to deploy (e.g. 'mcp-loopback99' or "
                "'Cisco_IOS-XR_Interface_config').",
                min_length=1,
                max_length=200,
            ),
        ],
        uuid: Annotated[
            str | None,
            Field(
                description="Device uuid to deploy to (e.g. "
                "'2a9b7c1e-0f3d-4b8a-9c6e-1d2f3a4b5c6d').",
                max_length=100,
            ),
        ] = None,
        host_name: Annotated[
            str | None,
            Field(
                description=(
                    "Device host name(s) to deploy to: exact match, case-insensitive, '*' "
                    "wildcard (e.g. 'PE1', 'PE*', or '*' for every device — one deployment)."
                ),
                max_length=253,
            ),
        ] = None,
        version: Annotated[
            str,
            Field(
                description="Template version to deploy (e.g. '1').", min_length=1, max_length=10
            ),
        ] = "1",
        variables: Annotated[
            str,
            Field(
                description=(
                    "Variable values as TEXT: 'k=v,k2=v2' or a JSON object (e.g. "
                    "'interfaceName=Loopback99,description=mcp' or '{\"mtu\": 1500}'); use the "
                    "JSON form for a value containing a comma; empty when the template's "
                    "defaults suffice."
                ),
                max_length=20000,
            ),
        ] = "",
        backup_before_deploy: Annotated[
            bool,
            Field(description="Take a configuration backup of each device first (default true)."),
        ] = True,
        rollback_on_failure: Annotated[
            bool,
            Field(
                description="Ask Crosswork to roll back a device whose push fails (default false)."
            ),
        ] = False,
    ) -> str:
        """Push a configuration template to the selected device(s) — this CHANGES
        DEVICE CONFIGURATION.

        DESTRUCTIVE write — only registered when CNC_MCP_ENABLE_WRITES=true.
        The rendered configlet lands on every selected device within seconds
        (verified: ~5 s on the lab) and Crosswork keeps NO undo: to revert,
        deploy a reverting template (``no interface Loopback99`` reverted the
        lab deployment cleanly) or restore the pre-deployment backup in the
        Crosswork UI (``backup_before_deploy`` — on by default — takes it).
        Deleting the deployment record afterwards does not touch the device.

        Preconditions, all checked BEFORE anything is sent:
        1. the template exists — ``GET templates/<name>?all=true``; an
           unknown name or a ``version`` the template does not have is an
           Error listing the stored versions;
        2. every variable name passed is one the template defines, and every
           ``is_mandatory`` variable has a value — from ``variables`` or the
           template's non-empty ``default_value`` (cnc_get_config_template
           shows them); non-mandatory variables without either are left out
           and named in ``unset_variables``;
        3. the selector (exactly one of uuid / host_name; host_name may carry
           '*') resolves with ``POST nodes/query`` to 1..100 devices — zero
           matches is an Error, more than a page is refused (narrow the
           pattern).
        Then ONE ``POST /crosswork/config/v1/templates/deploy-template
        {"template_name", "version": "<n>", "device_uuids": {"device_uuids":
        [...]}, "details": [{"version": <n>, "device_uuid": "GLOBAL",
        "variables": [{"name", "value"}, ...]}], "additional_params":
        {"backup_before_deploy", "rollback_on_failure"}}`` (verified: the
        version is a string at the top level and an int in the GLOBAL
        detail, which carries the values every device gets) answers 202
        ``{"status_code": 202, "job_id": "<template>_DeployJob_<date>_<time>",
        "message": "Deployment scheduled"}``. Follow with
        cnc_wait_for_template_deployment(deployment_id=<job_id>) — the
        ``next`` field spells it out — and read the per-device CLI transcript
        with cnc_get_template_deployment. The POST is not auto-retried (a
        lost answer could otherwise push the configuration twice). Not
        idempotent: every call is a new deployment and a new push.

        Args:
            name: the template name.
            uuid / host_name: exactly one selector; host_name may use '*'.
            version: template version (default '1').
            variables: variable values ('k=v,...' or JSON object).
            backup_before_deploy: back up each device first (default true).
            rollback_on_failure: platform-side rollback on a failed push.

        Returns:
            str: JSON {"deployment_id": str, "template": str, "version": int,
            "devices": [{"host_name", "uuid"}], "variables": {name: value},
            "unset_variables": [str], "additional_params": {...}, "message":
            str, "next": "cnc_wait_for_template_deployment(deployment_id=
            '...') ..."}. "Error: no template '<n>'" / "... has no version
            <v>", "Error: template ... has no variable(s) ..." / "... requires
            a value for mandatory variable(s) ...", "Error: no device matches
            ..." (all before anything is sent), or "Error: ..." on an API
            failure.
        """
        try:
            template_name = name.strip()
            wanted_version = parse_version(version)
            given = parse_deploy_variables(variables)
            selector = _selector(uuid, host_name)
            templates = await get_template_versions(template_name, True)
            if not templates:
                raise PlatformError(
                    f"no template '{template_name}' (cnc_list_config_templates lists them); "
                    "nothing was deployed."
                )
            matching = [t for t in templates if version_of(t) == wanted_version]
            if not matching:
                versions = ", ".join(
                    str(v) for v in sorted({version_of(t) for t in templates if version_of(t)})
                )
                raise PlatformError(
                    f"template '{template_name}' has no version {wanted_version} (stored: "
                    f"{versions or '?'}); nothing was deployed."
                )
            template = matching[0]
            values, unset = resolve_deploy_variables(template, given)
            nodes = await resolve_devices(selector)
            body = deploy_body(
                template_name,
                wanted_version,
                [str(n.get("uuid")) for n in nodes],
                values,
                backup_before_deploy=backup_before_deploy,
                rollback_on_failure=rollback_on_failure,
            )
            data = await client.request_json("POST", DEPLOY_TEMPLATE_URL, json_body=body)
            data = data if isinstance(data, dict) else {}
            deployment_id = str(data.get("job_id") or "")
            if not deployment_id:
                raise PlatformError(
                    f"deploying template '{template_name}' was accepted but Crosswork returned "
                    f"no job_id; check cnc_list_template_deployments. Response: {str(data)[:300]}"
                )
            payload = {
                "deployment_id": deployment_id,
                "template": template_name,
                "version": wanted_version,
                "devices": [device_ref(n) for n in nodes],
                "variables": values,
                "unset_variables": unset,
                "additional_params": body["additional_params"],
                "message": data.get("message"),
                "next": (
                    f"cnc_wait_for_template_deployment(deployment_id='{deployment_id}') waits "
                    "for every device; cnc_get_template_deployment shows the CLI transcript. "
                    "There is no undo: deploy a reverting template to roll back."
                ),
            }
            return finalize(to_json(payload), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_wait_for_template_deployment",
        title="Wait for Template Deployment",
        read_only=True,
        idempotent=True,
    )
    async def cnc_wait_for_template_deployment(
        deployment_id: Annotated[
            str,
            Field(
                description="Deployment id returned by cnc_deploy_config_template (e.g. "
                "'mcp-loopback99_DeployJob_20260913_120500').",
                min_length=1,
                max_length=300,
            ),
        ],
        timeout_seconds: Annotated[
            int, Field(description="How long to wait in total, 10..900 (e.g. 120).", ge=10, le=900)
        ] = 120,
        interval_seconds: Annotated[
            int, Field(description="Seconds between polls, 2..60 (e.g. 5).", ge=2, le=60)
        ] = 5,
    ) -> str:
        """Poll a template deployment until every device has finished (SUCCESS,
        FAILED, PARTIAL, NOT_DEPLOYED or SYSTEM_FAILURE) or the timeout
        elapses.

        Read-only convergence wait. Call it right after
        cnc_deploy_config_template instead of polling
        cnc_get_template_deployment in a loop. Polls ``POST
        templates/deploy-template/<id>/query {}`` (paged, ``?page=&size=100``,
        every page read while ``total_elements`` says more devices exist)
        every ``interval_seconds`` and stops when every device the platform
        counts in ``total_elements`` is present in ``details[]`` AND every
        entry's ``status`` is terminal:

        - all SUCCESS -> success, with each device's status and the tail of
          its CLI transcript;
        - any FAILED / PARTIAL / SYSTEM_FAILURE (a platform-side failure) /
          NOT_DEPLOYED (the device was skipped) -> "Error: deployment <id>
          failed on <devices>: <transcript tail>" — the deployment's outcome,
          not a timeout. The configuration may be partly applied on those
          devices: read the full transcript with cnc_get_template_deployment,
          then fix and deploy again, or deploy a reverting template. FAILED /
          PARTIAL were seen live; NOT_DEPLOYED / SYSTEM_FAILURE are the
          documented DeploymentStatus values the lab did not produce;
        - NOT_STARTED / IN_PROGRESS keep polling; empty ``details`` (the
          deployment is not visible yet, or the id is wrong) keeps polling
          too and is reported as "not found (yet)" at the timeout; fewer
          ``details`` than ``total_elements`` (the platform ignored the
          paging) keeps polling and is reported as "only N of M device(s)
          visible" at the timeout.

        On timeout the answer is NOT an error ("Deployment <id> not finished
        after Ns; ...") — call again to keep waiting.

        Args:
            deployment_id: the deployment id.
            timeout_seconds, interval_seconds: the polling budget.

        Returns:
            str: On success: "Deployment <id> finished SUCCESS on N device(s)
            after Ns." followed by JSON {"deployment_id", "devices":
            [{"device", "status", "deployed_at", "duration_ms",
            "result_tail"}], "total": int|null, "elapsed_seconds"}. On
            timeout (not an error): "Deployment <id> not finished after Ns;
            ..." (or "... not found (yet) ..." / "... only N of M device(s)
            visible ...") plus the same JSON. "Error: deployment <id> failed
            on PE1 (FAILED): <tail>" with the JSON; "Error: ..." on an API
            failure.
        """
        try:
            wanted = deployment_id.strip()

            def is_done(data: Any) -> bool:
                details = details_of(data)
                return (
                    bool(details)
                    and all_details_present(data)
                    and all(d.get("status") in DETAIL_TERMINAL_STATES for d in details)
                )

            finished, data, elapsed = await wait_until(
                lambda: fetch_deployment(wanted),
                is_done,
                timeout_seconds=timeout_seconds,
                interval_seconds=interval_seconds,
            )
            details = details_of(data)
            devices = [
                {
                    "device": d.get("device_uuid"),
                    "status": d.get("status"),
                    "deployed_at": d.get("deployed_at"),
                    "duration_ms": as_int(d.get("duration")),
                    "result_tail": result_tail(d.get("result")),
                }
                for d in details
            ]
            total = total_devices_of(data)
            payload = {
                "deployment_id": wanted,
                "devices": devices,
                "total": total,
                "elapsed_seconds": round(elapsed),
            }
            failed = [d for d in devices if d["status"] != DETAIL_SUCCESS]
            if finished and not failed:
                head = (
                    f"Deployment {wanted} finished SUCCESS on {len(devices)} device(s) after "
                    f"{elapsed:.0f}s."
                )
            elif finished:
                names = ", ".join(f"{d['device']} ({d['status']})" for d in failed)
                tails = " | ".join(
                    f"{d['device']}: {d['result_tail'] or '(no transcript)'}" for d in failed
                )
                raise PlatformError(
                    f"deployment {wanted} failed on {names} after {elapsed:.0f}s: {tails}. The "
                    "configuration may be partly applied — read the full transcript with "
                    "cnc_get_template_deployment, then deploy a corrected or reverting "
                    f"template.\n{to_json(payload)}"
                )
            elif not details:
                head = (
                    f"Deployment {wanted} not found (yet) after {elapsed:.0f}s: the platform "
                    "still answers no details for that id. A just-scheduled deployment can take "
                    "a moment to appear — call again; if it never does, check the id with "
                    "cnc_list_template_deployments."
                )
            elif not all_details_present(data):
                seen = ", ".join(f"{d['device']} {d['status']}" for d in devices)
                head = (
                    f"Deployment {wanted} not finished after {elapsed:.0f}s; only "
                    f"{len(devices)} of {total} device(s) visible ({seen}) — Crosswork counts "
                    f"{total} devices in this deployment but answered fewer, so the others' "
                    "outcome is unknown. Call again to keep waiting, or read the deployment "
                    "in the UI (Device Management > Configuration > Templates > Deployments)."
                )
            else:
                pending = ", ".join(f"{d['device']} {d['status']}" for d in devices)
                head = (
                    f"Deployment {wanted} not finished after {elapsed:.0f}s; {pending}. Call "
                    "again to keep waiting."
                )
            return finalize(f"{head}\n{to_json(payload)}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_template_deployment",
        title="Delete Template Deployment",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_template_deployment(
        deployment_id: Annotated[
            str,
            Field(
                description="Deployment id to delete (e.g. "
                "'mcp-loopback99_DeployJob_20260913_120500').",
                min_length=1,
                max_length=300,
            ),
        ],
    ) -> str:
        """Delete a template deployment record (its per-device results and
        transcripts).

        DESTRUCTIVE write — only registered when CNC_MCP_ENABLE_WRITES=true.
        Sends ``DELETE /crosswork/config/v1/templates/deploy-template/<id>``
        (URL-encoded, verified) -> 204. This removes the RECORD only: the
        configuration the deployment pushed stays on the devices (deploy a
        reverting template to undo it). A template that a deployment record
        references may refuse deletion (cnc_delete_config_template) — delete
        the deployment first, then the template. What the platform answers
        for an unknown id was not captured (expect 204 or a 500 reported as
        an Error). Auto-retried on 5xx/transport errors (DELETE is
        idempotent).

        Args:
            deployment_id: the deployment id (exact).

        Returns:
            str: "Deployment '<id>' deleted (HTTP 204). The device
            configuration it pushed is unchanged." followed by JSON
            {"deployment_id": str, "status_code": int}. "Error: ..." on an
            API failure.
        """
        try:
            wanted = deployment_id.strip()
            response = await client.request(
                "DELETE", f"{DEPLOY_TEMPLATE_URL}/{quote(wanted, safe='')}"
            )
            payload = {"deployment_id": wanted, "status_code": response.status_code}
            head = (
                f"Deployment '{wanted}' deleted (HTTP {response.status_code}). The device "
                "configuration it pushed is unchanged — deploy a reverting template to undo it."
            )
            return finalize(f"{head}\n{to_json(payload)}", settings)
        except Exception as e:
            return format_error(e)
