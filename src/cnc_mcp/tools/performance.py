"""Performance monitoring tools — PM policies, schemas and dashboards on
``/crosswork/performance/v1`` (the Performance pages of the Crosswork UI) and
the NPM / Optima analytics time series on ``/crosswork/optima-analytics/api/v1``
(LSP and interface utilisation, delay and loss).

Everything here was verified live against Crosswork Network Controller 7.2 on
2026-09-13 (reads only — see the platform notes, "Performance monitoring" and
"NPM / Optima analytics"); the exact paths, parameters and answers are
repeated in the tool docstrings. Two services, two dialects:

- **Performance (``/crosswork/performance/v1``)** is Spring JSON over a
  Bearer token. ``page`` is **1-based** everywhere. Errors carry a Spring
  envelope ``{"timestamp", "code", "status", "message": "<CODE>", "details",
  "parameters": [...]}`` whose ``message`` is a code, not a sentence
  (``MISSING_POLICY_ID``, ``MISSING_POLICY_HISTORY``, ``INVALID_SCHEMA``,
  ``INVALID_SCHEMA_METRIC_COMBO``, ``MISSING_TIME_DETAILS``); the tools
  render them as ``Error: <what it means> (<CODE>)``. The RESTCONF flavour of
  this API (``/crosswork/performance/restconf``, the "RESTCONF Performance
  APIs" document) is NOT routed on a 7.2 single-VM deployment (home-app 404),
  and neither is ``performance/v1/pre-streaming``.
- **NPM (``/crosswork/optima-analytics/api/v1``)** is plain JSON: every
  endpoint is a ``POST`` whose body is a free-form map, and the service
  **never validates it** — an unknown key, a missing time range or a
  misspelt field all answer the same empty list ``[]`` as a known object with
  no data. Every empty answer from these tools says so; check the key before
  concluding there is no traffic.

Object model (performance):

- **Policies** (``GET policies`` -> a bare LIST of ``{"monitoringPolicy",
  "monitoringPolicyTemplate", "policyCollectionStatus"}``): a *monitoring
  policy* is an instance of a *policy template* applied to a device / device
  group / port group selection, with one polling interval per **schema**
  (``schemasInterval``, seconds; ``0`` = that schema is not polled). A fresh
  7.2 install ships two built-in active policies: id 1 "Default interface
  health" (template INTERFACE: schema CEPMINTERFACE every 300 s, CEPMCRC
  off) and id 2 "Default LSP traffic" (template SRPOLICY: schema SRPOLICY
  every 300 s). ``GET policies/<id>`` takes ONE id (the documented comma list
  answers 500); ``policies/<id>/deployment-history`` lists every activation
  with the selection it carried; ``policies/devices/<id>`` pages the devices
  the policy polls with their ``collectionStatus`` (ACTIVE | DEGRADED |
  NOTPOLLING, plus ``comments`` explaining a NOTPOLLING).
- **Templates, schemas, metrics** — three levels of names: a *template*
  (SRPOLICY, INTERFACE, deviceHealth, QOS, PTP, GNSS, SRV6LOCATOR, OPTICALZRP,
  OpticalSFP) groups one or more *schemas* (INTERFACE -> CEPMINTERFACE and
  CEPMCRC; deviceHealth -> CPU, MEMORY, DVAVAILABILITY, ENVTEMP; PTP ->
  CEPMPTP, CEPMSYNCE; OPTICALZRP -> OPTICSLANE, OTUCONTROLLERSINFO; ...), and
  a schema holds *metrics* (CEPMINTERFACE: ifInBitsRate, ifOutBitsRate,
  ifInUtilization, ifOutUtilization, ifInErrorsRate, ...). ``GET
  policies/policy-templates`` is the authoritative source of every name.
  Dashboards address a metric with the token ``<SCHEMA>_<metric>`` —
  ``CEPMINTERFACE_ifInUtilization``, ``CPU_cpuUtilization`` — schema in
  upper case, metric name exactly as the template spells it. Top-N knows
  only the 13 schemas of ``GET dashboards/topn/columns``
  (:data:`TOP_N_SCHEMAS`); a ``SRPOLICY_...`` or ``<template>_...`` token
  answers 400 INVALID_SCHEMA_METRIC_COMBO and is refused here before the
  request.
- **Time windows**: ``dashboards/statistics`` takes either ``timeInterval``
  (hours back from now) or ``from`` + ``to``; ``topn`` and ``summary`` need
  ``from`` + ``to``. Times are ISO-8601 UTC ``YYYY-MM-DDTHH:mm:ss.SSSZ`` on
  the wire; the tools accept ``2026-09-13T12:00:00Z`` (milliseconds optional)
  and normalise. Retention (``GET dataretention/all|default``): raw 24 h,
  hourly 168 h, daily 744 h, weekly 9072 h by default — a window older than
  the raw retention only has aggregated data.

Object model (NPM): an **LSP** is keyed by TE router-ids — ``peerAddress``
the head-end router-id (the loopback the PCE knows the node by, e.g.
``10.0.0.1``, NOT the host name), ``destAddress`` the tail-end router-id,
plus ``color`` (a STRING on the wire) for ``lspType SR`` or ``tunnelId`` for
``lspType RSVP``; cnc_list_sr_policies / cnc_list_rsvp_te_tunnels show them.
Because NPM never validates, the tools refuse before sending whatever would
only ever produce a silent ``[]``: a host name where a router-id is needed
(:func:`router_id`), color 0 for an SR key (no SR policy has color 0;
:func:`lsp_key`) and anything but a uuid as an interface's ``device_uuid``
(:func:`device_uuid_key`). An **interface** is keyed by the inventory
``device_uuid`` (cnc_list_devices) and ``int_name``
(``GigabitEthernet0/0/0/0``). Samples are 5-minute
``{"tst": "<ISO>", ...}`` rows; the ``max`` endpoints answer ``{"max...",
"success", "message"}`` where ``success false`` means "no data" (still HTTP
200). Delay / loss series need the corresponding SR-PM / Y.1731 probes on the
devices; a lab without them answers ``[]`` everywhere.

NOT exposed (writes, unverified live): policy create / update / activate /
deactivate / delete (``POST policies``, ``PUT policies/<id>``, ``PUT
policies/activate|deactivate/<ids>``, ``DELETE policies/<ids>``), ``PUT
dataretention`` and ``PUT dashboards/healthsettings`` (+ the ``reset``
endpoints), the per-schema graph endpoints (``dashboards/<area>/graph/...``)
and ``dashboards/summary/topN``; all are read-only observation here.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import uuid as uuid_lib
from datetime import UTC, datetime
from typing import Annotated, Any

import httpx
from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.crosswork import REACHABILITY_STATES
from cnc_mcp.errors import PlatformError, format_error, http_error
from cnc_mcp.formatting import ResponseFormat, epoch_iso, finalize, pagination_envelope, to_json
from cnc_mcp.safety import AppContext, register_tool

PERFORMANCE = "/crosswork/performance/v1"
NPM = "/crosswork/optima-analytics/api/v1"

POLICIES_URL = f"{PERFORMANCE}/policies"
POLICY_DEVICES_URL = f"{POLICIES_URL}/devices"
POLICY_TEMPLATES_URL = f"{POLICIES_URL}/policy-templates"
RETENTION_ALL_URL = f"{PERFORMANCE}/dataretention/all"
RETENTION_DEFAULT_URL = f"{PERFORMANCE}/dataretention/default"
HEALTH_SETTINGS_URL = f"{PERFORMANCE}/dashboards/healthsettings"
STATISTICS_URL = f"{PERFORMANCE}/dashboards/statistics"
TOPN_URL = f"{PERFORMANCE}/dashboards/topn"
TOPN_COLUMNS_URL = f"{TOPN_URL}/columns"
SUMMARY_URL = f"{PERFORMANCE}/dashboards/summary"

NPM_LSP_UTILIZATIONS_URL = f"{NPM}/lsp/utilizations"
NPM_LSP_MAX_UTILIZATION_URL = f"{NPM}/lsp/max/utilization"
NPM_LSP_DELAY_URL = f"{NPM}/lsp/delay"
NPM_LSP_MAX_DELAY_URL = f"{NPM}/lsp/max/delay"
NPM_LSP_DELAY_VARIANCE_URL = f"{NPM}/lsp/delayVariance"
NPM_LSP_LOSS_URL = f"{NPM}/lsp/loss"
NPM_INTERFACE_DELAYS_URL = f"{NPM}/interface/delays"
NPM_INTERFACE_MAX_DELAY_URL = f"{NPM}/interface/max/delay"
NPM_INTERFACE_LOSS_URL = f"{NPM}/interface/loss"

# The 13 schemas ``GET dashboards/topn/columns`` lists on 7.2 (verified live) — the only
# schemas the top-N dashboard accepts in its ``<SCHEMA>_<metric>`` token.
TOP_N_SCHEMAS = (
    "CEPMINTERFACE",
    "CEPMCRC",
    "CPU",
    "MEMORY",
    "DVAVAILABILITY",
    "ENVTEMP",
    "CEPMQOS",
    "CEPMPTP",
    "CEPMSYNCE",
    "CEPMGNSS",
    "OPTICALSFP",
    "OPTICSLANE",
    "OTUCONTROLLERSINFO",
)
# Every schema the 7.2 policy templates define (``GET policies/policy-templates``): the
# top-N ones plus SRPOLICY (template SRPOLICY) and SRV6LOCATOR (template SRV6LOCATOR),
# which the statistics dashboard serves but top-N does not.
KNOWN_SCHEMAS = TOP_N_SCHEMAS + ("SRPOLICY", "SRV6LOCATOR")
# MonitoringPolicyDeviceDTO.collectionStatus (documented enum; all three seen live).
COLLECTION_STATUSES = ("ACTIVE", "DEGRADED", "NOTPOLLING")
# Documented reachabilityState filter values beyond the friendly names of
# crosswork.REACHABILITY_STATES (accepted verbatim, never seen live).
_DOCUMENTED_REACHABILITY = {
    "CONN_STATE_INVALID",
    "CONN_STATE_UNKNOWN",
    "CONN_STATE_REACHABLE",
    "CONN_STATE_UNREACHABLE",
    "CONN_STATE_MAX",
    "CONN_STATE_DEGRADED",
}
# Spring error-envelope codes this module explains (verified live, see the module doc).
CODE_MISSING_POLICY_ID = "MISSING_POLICY_ID"
CODE_MISSING_POLICY_HISTORY = "MISSING_POLICY_HISTORY"
CODE_INVALID_SCHEMA = "INVALID_SCHEMA"
CODE_INVALID_SCHEMA_METRIC_COMBO = "INVALID_SCHEMA_METRIC_COMBO"
CODE_MISSING_TIME_DETAILS = "MISSING_TIME_DETAILS"
# The longest window the statistics dashboard is asked for in hours: the default weekly
# retention (9072 h); anything older is gone whatever the request says.
MAX_HOURS = 9072

_ISO_TIME_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?Z$")
_ERROR_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")

NPM_EMPTY_CAVEAT = (
    "NPM never validates its input: an unknown key answers the same empty list as a known "
    "object with no data in the window, so check the key and the time window before "
    "concluding there is no data."
)
# The NPM LSP key parameters use the same names and wording as the sibling TE tools
# (te_state cnc_list_sr_policies / cnc_get_sr_policy_performance_metrics, sr_te_operations)
# so an agent can chain them without remapping.
_HEADEND_DESC = (
    "Head-end TE router-id — the loopback address the PCE knows the node by (e.g. "
    "'10.0.0.1'), NOT the host name; cnc_list_sr_policies shows it."
)
_ENDPOINT_DESC = "Tail-end TE router-id, the policy's endpoint loopback (e.g. '10.0.0.3')."
_COLOR_DESC = (
    "SR policy color (e.g. 100; cnc_list_sr_policies shows it) — required for an SR policy "
    "(0, the default, is refused: no SR policy has color 0); ignored when tunnel_id is given."
)
_SCHEMA_HELP = "cnc_list_performance_policy_templates lists every schema with its metrics."
_TOP_N_HELP = (
    "the token is <SCHEMA>_<exact metric name> and top-N covers only the schemas of "
    f"cnc_list_performance_top_n_columns ({', '.join(TOP_N_SCHEMAS)})"
)


# --- pure helpers ------------------------------------------------------------


def parse_iso_time(text: str | None, what: str) -> datetime:
    """An ISO-8601 UTC timestamp (``2026-09-13T12:00:00Z``, milliseconds optional) ->
    an aware datetime; anything else is a PlatformError naming the parameter."""
    value = (text or "").strip()
    match = _ISO_TIME_RE.match(value)
    if not match:
        raise PlatformError(
            f"{what} must be an ISO-8601 UTC timestamp such as 2026-09-13T12:00:00Z "
            f"(milliseconds optional: 2026-09-13T12:00:00.000Z), got '{text}'."
        )
    micros = int((match.group(3) or "0").ljust(6, "0"))
    try:
        base = datetime.strptime(f"{match.group(1)}T{match.group(2)}", "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        raise PlatformError(f"{what} '{value}' is not a real date/time.") from None
    return base.replace(microsecond=micros, tzinfo=UTC)


def time_window(from_time: str | None, to_time: str | None) -> tuple[datetime, datetime]:
    """Both bounds parsed (parse_iso_time) and ordered; ``to_time`` must be after ``from_time``."""
    start = parse_iso_time(from_time, "from_time")
    end = parse_iso_time(to_time, "to_time")
    if end <= start:
        raise PlatformError(
            f"to_time must be after from_time (got from_time {from_time!s} and to_time "
            f"{to_time!s})."
        )
    return start, end


def performance_time(value: datetime) -> str:
    """The ``YYYY-MM-DDTHH:mm:ss.SSSZ`` form the performance dashboards take (verified live)."""
    return f"{value:%Y-%m-%dT%H:%M:%S}.{value.microsecond // 1000:03d}Z"


def npm_time(value: datetime) -> str:
    """The ``YYYY-MM-DDTHH:mm:ssZ`` form the NPM bodies were verified with."""
    return f"{value:%Y-%m-%dT%H:%M:%SZ}"


def parse_metric_token(token: str | None, *, top_n: bool) -> str:
    """Normalise a ``<SCHEMA>_<metric>`` dashboard token (schema upper-cased, metric kept
    exactly). Refuses a token without both halves; with ``top_n`` also refuses a schema
    outside :data:`TOP_N_SCHEMAS` before anything is sent (the platform would answer 400
    INVALID_SCHEMA_METRIC_COMBO)."""
    value = (token or "").strip()
    schema, sep, metric = value.partition("_")
    if not sep or not schema.strip() or not metric.strip():
        raise PlatformError(
            f"metric must be a <SCHEMA>_<metric> token such as CEPMINTERFACE_ifInUtilization, "
            f"got '{token}'. {_SCHEMA_HELP}"
        )
    schema = schema.strip().upper()
    metric = metric.strip()
    if top_n and schema not in TOP_N_SCHEMAS:
        raise PlatformError(
            f"'{value}' is not a top-N schema/metric — {_TOP_N_HELP}. Nothing was sent. "
            f"{_SCHEMA_HELP}"
        )
    return f"{schema}_{metric}"


def parse_schema(text: str | None) -> str:
    """A schema name for the statistics dashboard: stripped, upper-cased, non-blank."""
    value = (text or "").strip().upper()
    if not value:
        raise PlatformError(
            f"schema is required (e.g. CEPMINTERFACE). Schemas on 7.2: {', '.join(KNOWN_SCHEMAS)}."
        )
    return value


def parse_reachability(text: str | None) -> str | None:
    """A friendly reachability name (reachable/unreachable/degraded/unknown) or a documented
    ``CONN_STATE_*`` value -> the wire value; blank -> None; anything else is refused."""
    value = (text or "").strip()
    if not value:
        return None
    wire = REACHABILITY_STATES.get(value.lower())
    if wire:
        return wire
    if value.upper() in _DOCUMENTED_REACHABILITY:
        return value.upper()
    raise PlatformError(
        f"Unknown reachability_state '{text}'. Use one of: "
        f"{', '.join(sorted(REACHABILITY_STATES))} (or a CONN_STATE_* wire value)."
    )


def parse_collection_status(text: str | None) -> str | None:
    value = (text or "").strip().upper()
    if not value:
        return None
    if value not in COLLECTION_STATUSES:
        raise PlatformError(
            f"Unknown collection_status '{text}'. Use one of: {', '.join(COLLECTION_STATUSES)}."
        )
    return value


def router_id(text: str | None, what: str) -> str:
    """A TE router-id (an IP address) for an NPM LSP key; a host name is refused because NPM
    would silently answer an empty list for it."""
    value = (text or "").strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise PlatformError(
            f"{what} must be a TE router-id (an IP address such as 10.0.0.1), not a host name "
            f"— got '{text}'. cnc_list_sr_policies / cnc_list_topology_nodes show the router-ids."
        ) from None


def split_csv(text: str | None) -> list[str]:
    """'a, b,,a' -> ['a', 'b'] (order kept, duplicates dropped)."""
    out: list[str] = []
    for token in (text or "").split(","):
        value = token.strip()
        if value and value not in out:
            out.append(value)
    return out


def num_text(value: Any) -> str:
    """A compact number for markdown: floats that are whole print as ints, others to 4 dp."""
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(int(value)) if value.is_integer() else f"{round(value, 4)}"
    return "-" if value in (None, "") else str(value)


def _parse_json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return None


def error_envelope(response: httpx.Response) -> dict[str, Any] | None:
    """The Spring error envelope of a performance/v1 answer as ``{"code", "details",
    "parameters"}`` when its ``message`` is a CODE (``MISSING_POLICY_ID``), else None (a
    500 whose ``message`` is a sentence — "Method parameter 'units': Failed to convert" —
    goes through the generic http_error instead)."""
    data = _parse_json(response)
    if not isinstance(data, dict):
        return None
    code = data.get("message")
    if not isinstance(code, str) or not _ERROR_CODE_RE.match(code.strip()):
        return None
    details = data.get("details")
    parameters = data.get("parameters")
    return {
        "code": code.strip(),
        "details": details.strip() if isinstance(details, str) else "",
        "parameters": list(parameters) if isinstance(parameters, list) else [],
    }


def performance_error(
    response: httpx.Response, hints: dict[str, str | tuple[str, str]] | None = None
) -> PlatformError:
    """A PlatformError for a failed performance/v1 answer: ``<meaning> (<CODE>). <guidance>``
    for a code in ``hints`` (value: the meaning, or (meaning, guidance)), ``<details>
    (<CODE>)`` for any other enveloped code, and the generic http_error otherwise."""
    envelope = error_envelope(response)
    if envelope is None:
        return http_error(response)
    code = envelope["code"]
    hint = (hints or {}).get(code)
    guidance = ""
    if isinstance(hint, tuple):
        meaning, guidance = hint
    elif isinstance(hint, str):
        meaning = hint
    else:
        meaning = envelope["details"] or (
            f"the performance service rejected the request with status {response.status_code}"
        )
    text = f"{meaning} ({code})."
    if guidance:
        text += f" {guidance}"
    return PlatformError(text)


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def intervals_text(schemas_interval: dict[str, Any]) -> str:
    """'CEPMINTERFACE every 300 s, CEPMCRC off' (0 = the schema is not polled)."""
    parts = []
    for schema, seconds in schemas_interval.items():
        if isinstance(seconds, int | float) and not isinstance(seconds, bool) and seconds > 0:
            parts.append(f"{schema} every {num_text(seconds)} s")
        else:
            parts.append(f"{schema} off")
    return ", ".join(parts) or "(no schemas)"


def scope_text(view: dict[str, Any]) -> str:
    parts = []
    if view.get("devices"):
        parts.append("devices " + ", ".join(view["devices"]))
    if view.get("device_groups"):
        parts.append("device groups " + ", ".join(view["device_groups"]))
    if view.get("port_groups"):
        parts.append("port groups " + ", ".join(view["port_groups"]))
    return "; ".join(parts) or "no devices or groups selected"


def policy_view(dto: dict[str, Any]) -> dict[str, Any]:
    policy = _dict(dto.get("monitoringPolicy"))
    intervals = _dict(policy.get("schemasInterval"))
    return {
        "id": policy.get("id"),
        "name": policy.get("name"),
        "description": policy.get("description"),
        "template": policy.get("policyTemplate"),
        "active": policy.get("active"),
        "collection_status": dto.get("policyCollectionStatus"),
        "schemas_interval": {str(k): v for k, v in intervals.items()},
        "devices": split_csv(policy.get("devices")),
        "device_groups": split_csv(policy.get("deviceGroups")),
        "port_groups": split_csv(policy.get("portGroups")),
        "tag": policy.get("tag"),
        "thresholds": policy.get("thresholds"),
        "created_at": epoch_iso(policy.get("creationTimestamp")),
        "last_changed_at": epoch_iso(policy.get("lastChangedTimestamp")),
    }


def policy_line(view: dict[str, Any]) -> str:
    """'- **Default interface health** (id 1, template INTERFACE): active, collection OK;
    CEPMINTERFACE every 300 s, CEPMCRC off; device groups <uuid>; changed <t>'."""
    state = "active" if view.get("active") else "inactive"
    return (
        f"- **{view.get('name') or '?'}** (id {view.get('id')}, template "
        f"{view.get('template') or '?'}): {state}, collection "
        f"{view.get('collection_status') or '?'}; {intervals_text(view['schemas_interval'])}; "
        f"{scope_text(view)}; changed {view['last_changed_at']}"
    )


def template_schema_lines(template: dict[str, Any]) -> list[str]:
    """One '- SCHEMA (display) — default 300 s, allowed 0/300/900 s: metric (UNIT), ...' line
    per schema of a policy template object (``schemasInterval`` + ``schemasFieldMetadata``)."""
    intervals = _dict(template.get("schemasInterval"))
    metadata = _dict(template.get("schemasFieldMetadata"))
    display = _dict(template.get("schemaDisplayMap"))
    schemas: list[str] = []
    for key in list(intervals) + list(metadata):
        if key not in schemas:
            schemas.append(str(key))
    lines = []
    for schema in schemas:
        interval = _dict(intervals.get(schema))
        default = interval.get("defaultInterval")
        allowed = interval.get("pollingIntervals")
        allowed_text = (
            "/".join(num_text(a) for a in allowed) if isinstance(allowed, list) and allowed else "-"
        )
        fields = _dict(metadata.get(schema))
        metrics = ", ".join(
            f"{metric} ({_dict(meta).get('unitType') or '-'})" for metric, meta in fields.items()
        )
        label = display.get(schema)
        head = f"- {schema}" + (f" ({label})" if label else "")
        lines.append(
            f"{head} — default {num_text(default)} s, allowed {allowed_text} s: "
            f"{metrics or '(no metrics listed)'}"
        )
    return lines


def template_view(template: dict[str, Any]) -> dict[str, Any]:
    metadata = _dict(template.get("schemasFieldMetadata"))
    return {
        "template": template.get("policyTemplate"),
        "port_group_supported": template.get("portGroupSupported"),
        "schema_display_map": _dict(template.get("schemaDisplayMap")),
        "schemas_interval": _dict(template.get("schemasInterval")),
        "schemas": {
            str(schema): {
                str(metric): {
                    "unit": _dict(meta).get("unitType"),
                    "min": _dict(meta).get("min"),
                    "max": _dict(meta).get("max"),
                    "tca_enabled": _dict(meta).get("TCAEnabled"),
                }
                for metric, meta in _dict(fields).items()
            }
            for schema, fields in metadata.items()
        },
    }


def policy_markdown(dto: dict[str, Any]) -> str:
    view = policy_view(dto)
    template = _dict(dto.get("monitoringPolicyTemplate"))
    state = "active" if view.get("active") else "inactive"
    thresholds = view.get("thresholds")
    lines = [
        f"# Performance policy {view.get('id')}: {view.get('name') or '?'}",
        "",
        f"- template {view.get('template') or '?'}; {state}; collection status "
        f"{view.get('collection_status') or '?'}",
        f"- description: {view.get('description') or '-'}",
        f"- polling: {intervals_text(view['schemas_interval'])}",
        f"- scope: {scope_text(view)}",
        f"- created {view['created_at']}; last changed {view['last_changed_at']}",
        f"- thresholds: {to_json(thresholds) if thresholds else 'none'}",
        "",
        f"## Template {template.get('policyTemplate') or view.get('template') or '?'} "
        "schemas and metrics",
    ]
    schema_lines = template_schema_lines(template)
    lines.extend(schema_lines or ["(the answer carried no template metadata)"])
    return "\n".join(lines)


def history_view(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": entry.get("id"),
        "last_activated_at": epoch_iso(entry.get("lastActivatedTimestamp")),
        "devices": split_csv(entry.get("devices")),
        "device_groups": split_csv(entry.get("deviceGroups")),
        "port_groups": split_csv(entry.get("portGroups")),
    }


def history_line(view: dict[str, Any]) -> str:
    return f"- activated {view['last_activated_at']}: {scope_text(view)}"


def policy_device_view(row: dict[str, Any]) -> dict[str, Any]:
    comments = [
        {"type": c.get("type"), "argument": c.get("argument")}
        for c in _list_of_dicts(row.get("comments"))
    ]
    return {
        "host_name": row.get("hostName"),
        "ip_address": row.get("ipAddress"),
        "uuid": row.get("uuid"),
        "reachability_state": row.get("reachabilityState"),
        "admin_state": row.get("adminState"),
        "collection_status": row.get("collectionStatus"),
        "product_type": row.get("productType"),
        "gateway_name": row.get("gatewayName"),
        "last_update_at": epoch_iso(row.get("lastUpdateTime")),
        "selected": row.get("selected"),
        "comments": comments,
    }


def policy_device_line(view: dict[str, Any]) -> str:
    notes = "; ".join(
        f"{c.get('type') or '?'} {c.get('argument') or ''}".strip() for c in view["comments"]
    )
    tail = f" [{notes}]" if notes else ""
    return (
        f"- **{view.get('host_name') or '?'}** {view.get('ip_address') or '-'} "
        f"({view.get('uuid') or '?'}): {view.get('reachability_state') or '?'} / "
        f"{view.get('admin_state') or '?'}, collection {view.get('collection_status') or '?'}, "
        f"{view.get('product_type') or '-'}, gateway {view.get('gateway_name') or '-'}, "
        f"updated {view['last_update_at']}{tail}"
    )


def page_view(items: list[Any], *, total: int | None, page: int, page_size: int) -> dict[str, Any]:
    """A 1-based page envelope: has_more from ``total`` when the platform reported one, else
    from a full page (``count >= page_size``)."""
    env = pagination_envelope(items, total=total, offset=(page - 1) * page_size, limit=page_size)
    env["page"] = page
    env["page_size"] = page_size
    env["next_page"] = page + 1 if env["has_more"] else None
    return env


def retention_view(name: str, entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "display_name": name,
        "schema": entry.get("schemaName"),
        "policy_type": entry.get("policyType"),
        "raw_hours": entry.get("rawDataRetentionPeriod"),
        "hourly_hours": entry.get("hourlyDataRetentionPeriod"),
        "daily_hours": entry.get("dailyDataRetentionPeriod"),
        "weekly_hours": entry.get("weeklyDataRetentionPeriod"),
        "has_aggregation_option": entry.get("hasAggrOption"),
    }


def retention_markdown(defaults: dict[str, Any], views: list[dict[str, Any]]) -> str:
    lines = [
        "# Performance data retention (hours)",
        "",
        f"Default: raw {num_text(defaults.get('rawDataRetentionPeriod'))}, hourly "
        f"{num_text(defaults.get('hourlyDataRetentionPeriod'))}, daily "
        f"{num_text(defaults.get('dailyDataRetentionPeriod'))}, weekly "
        f"{num_text(defaults.get('weeklyDataRetentionPeriod'))}",
        "",
    ]
    if not views:
        lines.append("(no per-schema retention entries)")
        return "\n".join(lines)
    lines.extend(
        [
            "| display name | schema | policy type | raw | hourly | daily | weekly | aggregation |",
            "|---|---|---|---|---|---|---|---|",
        ]
    )
    for v in views:
        lines.append(
            f"| {v['display_name']} | {v.get('schema') or '-'} | {v.get('policy_type') or '-'} | "
            f"{num_text(v.get('raw_hours'))} | {num_text(v.get('hourly_hours'))} | "
            f"{num_text(v.get('daily_hours'))} | {num_text(v.get('weekly_hours'))} | "
            f"{'yes' if v.get('has_aggregation_option') else 'no'} |"
        )
    return "\n".join(lines)


def health_setting_line(token: str, setting: dict[str, Any]) -> str:
    """'- CEPMINTERFACE_ifInUtilization (PERCENTAGE): HEALTHY 0-50 | MINOR 50-75 | ...'."""
    categories = " | ".join(
        f"{c.get('level') or '?'} {num_text(c.get('min'))}-{num_text(c.get('max'))}"
        for c in _list_of_dicts(setting.get("categories"))
    )
    return f"- {token} ({setting.get('unit') or '-'}): {categories or '(no categories)'}"


def health_settings_markdown(data: dict[str, Any]) -> str:
    lines = [f"# Performance health settings ({len(data)} template(s))"]
    for template, settings_of in data.items():
        lines.extend(["", f"## {template}"])
        entries = _dict(settings_of)
        if not entries:
            lines.append("(no metrics)")
        for token, setting in entries.items():
            lines.append(health_setting_line(str(token), _dict(setting)))
    return "\n".join(lines)


def keys_label(keys: dict[str, Any]) -> str:
    """'PE1 GigabitEthernet0/0/0/0' / 'PE1 srte_c_100_ep_10.0.0.3 color=0' — hostname, then
    the interface/object name, then any other non-empty key as key=value; the device uuid is
    left to the JSON form."""
    parts: list[str] = []
    host = keys.get("hostname")
    if host not in (None, ""):
        parts.append(str(host))
    for key in ("interfaceName", "name"):
        value = keys.get(key)
        if value not in (None, ""):
            parts.append(str(value))
    for key, value in keys.items():
        if key in ("hostname", "interfaceName", "name", "device") or value in (None, ""):
            continue
        parts.append(f"{key}={value}")
    return " ".join(parts) or "?"


def metric_text(value: Any) -> str:
    """A statistics metric value: a plain number, or ``{unit, value}`` with units=true."""
    if isinstance(value, dict):
        unit = value.get("unit")
        text = num_text(value.get("value"))
        return f"{text} {unit}" if unit else text
    return num_text(value)


def statistics_line(entry: dict[str, Any]) -> str:
    metrics = _dict(entry.get("metrics"))
    values = ", ".join(f"{m}={metric_text(v)}" for m, v in metrics.items()) or "(no metrics)"
    return f"- {keys_label(_dict(entry.get('keys')))}: {values}"


def topn_line(entry: dict[str, Any]) -> str:
    unit = entry.get("unit")
    severity = entry.get("severity")
    return (
        f"- {keys_label(_dict(entry.get('keys')))}: avg {num_text(entry.get('average'))}, "
        f"min {num_text(entry.get('minimum'))}, max {num_text(entry.get('maximum'))}"
        + (f" {unit}" if unit else "")
        + (f", {severity}" if severity else "")
    )


def topn_columns_line(entry: dict[str, Any]) -> str:
    columns = ", ".join(
        f"{c.get('key') or '?'} ({c.get('displayName') or '-'})"
        for c in _list_of_dicts(entry.get("keyToDisplayNameList"))
    )
    return f"- {entry.get('schemaName') or '?'}: {columns or '(no key columns)'}"


def summary_rows(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Merge a summary's average/minimum/maximum series by timestamp (sorted) into
    ``[{timestamp, average, minimum, maximum}]``."""
    series = {
        "average": _list_of_dicts(entry.get("averageSeries")),
        "minimum": _list_of_dicts(entry.get("minimumSeries")),
        "maximum": _list_of_dicts(entry.get("maximumSeries")),
    }
    rows: dict[str, dict[str, Any]] = {}
    for field, points in series.items():
        for point in points:
            stamp = str(point.get("timestamp") or "")
            rows.setdefault(stamp, {"timestamp": stamp})[field] = point.get("value")
    return [rows[k] for k in sorted(rows)]


def summary_line(row: dict[str, Any]) -> str:
    return (
        f"- {row.get('timestamp') or '?'}: avg {num_text(row.get('average'))}, "
        f"min {num_text(row.get('minimum'))}, max {num_text(row.get('maximum'))}"
    )


def lsp_key(
    headend: str,
    endpoint: str,
    color: int,
    tunnel_id: str | None,
    start: datetime,
    end: datetime,
) -> dict[str, str]:
    """The verified NPM LSP key: SR ``{lspType, peerAddress, destAddress, color (STRING), from,
    to}``, or RSVP ``{lspType "RSVP", peerAddress, destAddress, tunnelId, from, to}`` when a
    tunnel_id is given. An SR key needs a real color: no SR policy has color 0 (IOS-XR
    colors are 1-4294967295) and NPM would silently answer ``[]`` for it, so color 0 without
    a tunnel_id is refused before anything is sent."""
    head = router_id(headend, "headend")
    tail = router_id(endpoint, "endpoint")
    tunnel = (tunnel_id or "").strip()
    key: dict[str, str] = {"lspType": "RSVP" if tunnel else "SR", "peerAddress": head}
    key["destAddress"] = tail
    if tunnel:
        key["tunnelId"] = tunnel
    else:
        if color < 1:
            raise PlatformError(
                "color is required for an SR policy (no SR policy has color 0, and NPM would "
                "silently answer an empty list for it): pass the policy's color — "
                "cnc_list_sr_policies shows it — or tunnel_id for an RSVP-TE tunnel. Nothing "
                "was sent."
            )
        key["color"] = str(color)
    key["from"] = npm_time(start)
    key["to"] = npm_time(end)
    return key


def lsp_label(key: dict[str, str]) -> str:
    """'SR LSP 10.0.0.1 -> 10.0.0.3 color 100' / 'RSVP LSP 10.0.0.1 -> 10.0.0.3 tunnel 11'."""
    kind = key.get("lspType")
    tail = f"tunnel {key['tunnelId']}" if kind == "RSVP" else f"color {key.get('color')}"
    return f"{kind} LSP {key.get('peerAddress')} -> {key.get('destAddress')} {tail}"


def device_uuid_key(text: str | None) -> str:
    """An inventory uuid for an NPM interface key, sent canonical (lower-case, hyphenated,
    as cnc_list_devices shows it); a host name, IP address or anything else that is not a
    uuid is refused before sending because NPM never validates its key and would answer
    the same empty list as a known interface with no data (verified live)."""
    value = (text or "").strip()
    try:
        return str(uuid_lib.UUID(value.lower()))
    except ValueError:
        raise PlatformError(
            f"device_uuid must be the device's inventory uuid (e.g. "
            f"'2a9b7c1e-0f3d-4b8a-9c6e-1d2f3a4b5c6d'), not a host name or IP address — got "
            f"'{text}'. NPM never validates its key and would silently answer an empty list; "
            f"cnc_get_device(host_name='{value}') or cnc_list_devices shows the uuid. Nothing "
            "was sent."
        ) from None


def interface_key(
    device_uuid: str, interface: str, start: datetime, end: datetime
) -> dict[str, str]:
    """The verified NPM interface key ``{device_uuid, int_name, from, to}``; the uuid is
    validated (device_uuid_key) so a host name never reaches the wire."""
    uuid = (device_uuid or "").strip()
    name = (interface or "").strip()
    if not uuid or not name:
        raise PlatformError(
            "device_uuid (the inventory uuid, cnc_list_devices) and interface (e.g. "
            "'GigabitEthernet0/0/0/0') are both required."
        )
    return {
        "device_uuid": device_uuid_key(uuid),
        "int_name": name,
        "from": npm_time(start),
        "to": npm_time(end),
    }


def samples_of(data: Any) -> list[dict[str, Any]]:
    """The sample rows of an NPM series answer (a list of ``{"tst", ...}``); anything else -> []."""
    return _list_of_dicts(data)


def sample_line(sample: dict[str, Any]) -> str:
    """'- 2026-09-13T12:01:36Z: util 0' — the timestamp, then every other field."""
    values = ", ".join(f"{k} {num_text(v)}" for k, v in sample.items() if k != "tst")
    return f"- {sample.get('tst') or '?'}: {values or '(no values)'}"


def series_stats(samples: list[dict[str, Any]], field: str) -> dict[str, Any]:
    """count / first_at / last_at / average / minimum / maximum / last of a numeric field."""
    values = [
        s[field]
        for s in samples
        if isinstance(s.get(field), int | float) and not isinstance(s.get(field), bool)
    ]
    stamps = [str(s.get("tst")) for s in samples if s.get("tst") not in (None, "")]
    stats: dict[str, Any] = {
        "count": len(samples),
        "first_at": stamps[0] if stamps else None,
        "last_at": stamps[-1] if stamps else None,
    }
    if values:
        stats.update(
            {
                "average": round(sum(values) / len(values), 4),
                "minimum": min(values),
                "maximum": max(values),
                "last": values[-1],
            }
        )
    return stats


def stats_text(stats: dict[str, Any], field: str) -> str:
    """'72 samples (2026-... to 2026-...): util avg 0, min 0, max 0, last 0'."""
    text = f"{stats['count']} sample(s)"
    if stats.get("first_at"):
        text += f" ({stats['first_at']} to {stats['last_at']})"
    if "average" in stats:
        text += (
            f": {field} avg {num_text(stats['average'])}, min {num_text(stats['minimum'])}, "
            f"max {num_text(stats['maximum'])}, last {num_text(stats['last'])}"
        )
    return text


def max_text(data: Any, field: str, what: str) -> str:
    """'max delay (platform): 5 — Successfully found ...' / 'max delay (platform): no data
    (Maximum Average Delay ... not present)' from a ``{"<field>", "success", "message"}``."""
    payload = _dict(data)
    message = str(payload.get("message") or "").strip()
    if payload.get("success") is False:
        return f"{what} (platform): no data" + (f" ({message})" if message else "")
    value = payload.get(field)
    if value is None and not payload:
        return f"{what} (platform): not reported"
    return f"{what} (platform): {num_text(value)}" + (f" — {message}" if message else "")


def series_section(title: str, samples: list[dict[str, Any]]) -> list[str]:
    lines = ["", f"## {title} ({len(samples)} sample(s))"]
    lines.extend(sample_line(s) for s in samples)
    if not samples:
        lines.append("(no samples)")
    return lines


# --- tools -------------------------------------------------------------------


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    async def perf_get(
        path: str,
        params: dict[str, Any] | None = None,
        hints: dict[str, str | tuple[str, str]] | None = None,
    ) -> Any:
        """``GET`` on performance/v1: a Spring error envelope becomes the precise PlatformError
        of performance_error(); the JSON body otherwise (None for an empty body)."""
        response = await client.request("GET", path, params=params, raise_on_error=False)
        if not response.is_success:
            raise performance_error(response, hints)
        if not response.content:
            return None
        data = _parse_json(response)
        if data is None:
            raise PlatformError(
                "The performance service returned a non-JSON response where JSON was expected."
            )
        return data

    async def npm_post(path: str, body: dict[str, str]) -> Any:
        """``POST`` an NPM query (a read: safe to re-send on 5xx / transport errors)."""
        return await client.request_json("POST", path, json_body=body, retryable=True)

    def policy_hints(policy_id: int) -> dict[str, str | tuple[str, str]]:
        return {
            CODE_MISSING_POLICY_ID: (
                f"no performance policy {policy_id}",
                "List policies with cnc_list_performance_policies.",
            ),
            CODE_MISSING_POLICY_HISTORY: (
                f"no deployment history for policy {policy_id} (unknown policy?)",
                "List policies with cnc_list_performance_policies.",
            ),
        }

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_performance_policies",
        title="List Performance Monitoring Policies",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_performance_policies(
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the performance monitoring policies — which schemas are polled, how
        often, on which devices / groups, and whether collection is healthy.

        Read-only; ``GET /crosswork/performance/v1/policies`` (verified) answers
        a bare LIST of ``{"monitoringPolicy": {id, policyTemplate, name,
        description, schemasInterval {<SCHEMA>: seconds}, devices, deviceGroups,
        portGroups (comma-separated uuids / names), tag, thresholds, active,
        creationTimestamp, lastChangedTimestamp (epoch ms)},
        "monitoringPolicyTemplate": {...}, "policyCollectionStatus": "OK" |
        "PARTIAL"}``. A fresh 7.2 install has two built-in active policies: id
        1 "Default interface health" (INTERFACE: CEPMINTERFACE every 300 s,
        CEPMCRC off) and id 2 "Default LSP traffic" (SRPOLICY every 300 s). An
        interval of 0 means the schema is not polled. Use this first to learn
        the policy ids for cnc_get_performance_policy /
        cnc_list_performance_policy_devices and to see which schemas produce
        data at all (a schema no active policy polls answers empty
        statistics). Creating or changing policies is not exposed.

        Returns:
            str: Markdown "# N performance monitoring policies" and one
            "- **name** (id, template): active|inactive, collection OK;
            <schema> every N s, ...; device groups ...; changed <ISO>" line per
            policy, or JSON {"count": int, "policies": [{"id", "name",
            "description", "template", "active", "collection_status",
            "schemas_interval": {schema: seconds}, "devices": [str],
            "device_groups": [str], "port_groups": [str], "tag", "thresholds",
            "created_at", "last_changed_at"}]}. "No performance monitoring
            policies." when the list is empty; "Error: ..." on an API failure.
        """
        try:
            data = await perf_get(POLICIES_URL)
            views = [policy_view(d) for d in _list_of_dicts(data)]
            if response_format is ResponseFormat.JSON:
                return finalize(to_json({"count": len(views), "policies": views}), settings)
            if not views:
                return finalize("No performance monitoring policies.", settings)
            lines = [f"# {len(views)} performance monitoring policies", ""]
            lines.extend(policy_line(v) for v in views)
            lines.append(
                "\nDetails and the template's metrics: cnc_get_performance_policy(policy_id)."
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_performance_policy",
        title="Get Performance Monitoring Policy",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_performance_policy(
        policy_id: Annotated[
            int,
            Field(
                description="Policy id as listed by cnc_list_performance_policies (e.g. 1).", ge=1
            ),
        ],
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one performance monitoring policy with its template's schemas and
        metric names.

        Read-only; ``GET /crosswork/performance/v1/policies/<id>`` (verified)
        — ONE id per call: the documented comma-separated list
        (``policies/1,2``) answers 500 on 7.2. Answers the same
        ``{"monitoringPolicy", "monitoringPolicyTemplate",
        "policyCollectionStatus"}`` object as the list, and the template part
        is what makes this tool useful: ``schemasInterval`` (default and
        allowed polling intervals per schema) and ``schemasFieldMetadata``
        (every metric of every schema with its ``unitType``) — the exact names
        to use as ``<SCHEMA>_<metric>`` tokens in cnc_get_performance_top_n /
        cnc_get_performance_summary and as ``schema`` / ``metrics`` in
        cnc_get_performance_statistics. An unknown id answers 400
        MISSING_POLICY_ID.

        Args:
            policy_id: the policy id (an integer).
            response_format: markdown or json (the raw object).

        Returns:
            str: Markdown "# Performance policy <id>: <name>", the template /
            state / collection status, description, polling intervals, scope,
            timestamps, thresholds, then "## Template <name> schemas and
            metrics" with one "- SCHEMA (display) — default N s, allowed ...:
            metric (UNIT), ..." line per schema; or the raw JSON object. "Error:
            no performance policy <id> (MISSING_POLICY_ID). ..." for an unknown
            id; "Error: ..." on an API failure.
        """
        try:
            data = await perf_get(f"{POLICIES_URL}/{policy_id}", hints=policy_hints(policy_id))
            if isinstance(data, list):
                data = data[0] if data and isinstance(data[0], dict) else None
            if not isinstance(data, dict) or not _dict(data.get("monitoringPolicy")):
                raise PlatformError(
                    f"no performance policy {policy_id}: the platform answered no policy object. "
                    "List policies with cnc_list_performance_policies."
                )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(data), settings)
            return finalize(policy_markdown(data), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_performance_policy_history",
        title="Get Performance Policy Deployment History",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_performance_policy_history(
        policy_id: Annotated[
            int,
            Field(
                description="Policy id as listed by cnc_list_performance_policies (e.g. 1).", ge=1
            ),
        ],
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the deployment (activation) history of a performance policy —
        when it was activated and with which device / group selection.

        Read-only; ``GET /crosswork/performance/v1/policies/<id>/
        deployment-history`` (verified) -> ``[{id, lastActivatedTimestamp
        (epoch ms), devices, deviceGroups (e.g. "All Locations"), portGroups}]``,
        one entry per activation. Use it to see when a policy started polling
        (why data begins at some time) or what scope an earlier activation
        had. An unknown policy answers 400 MISSING_POLICY_HISTORY.

        Args:
            policy_id: the policy id (an integer).
            response_format: markdown or json.

        Returns:
            str: Markdown "# Deployment history of performance policy <id>"
            with one "- activated <ISO>: device groups ...; devices ..." line
            per entry, or JSON {"policy_id": int, "count": int, "history":
            [{"id", "last_activated_at", "devices": [str], "device_groups":
            [str], "port_groups": [str]}]}. "No deployment history for policy
            <id>." when the list is empty; "Error: no deployment history for
            policy <id> (unknown policy?) (MISSING_POLICY_HISTORY). ..." for an
            unknown id; "Error: ..." on an API failure.
        """
        try:
            data = await perf_get(
                f"{POLICIES_URL}/{policy_id}/deployment-history", hints=policy_hints(policy_id)
            )
            views = [history_view(e) for e in _list_of_dicts(data)]
            if response_format is ResponseFormat.JSON:
                payload = {"policy_id": policy_id, "count": len(views), "history": views}
                return finalize(to_json(payload), settings)
            if not views:
                return finalize(f"No deployment history for policy {policy_id}.", settings)
            lines = [f"# Deployment history of performance policy {policy_id}", ""]
            lines.extend(history_line(v) for v in views)
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_performance_policy_devices",
        title="List Performance Policy Devices",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_performance_policy_devices(
        policy_id: Annotated[
            int,
            Field(
                description="Policy id as listed by cnc_list_performance_policies (e.g. 1).", ge=1
            ),
        ],
        host_name: Annotated[
            str,
            Field(
                description="Filter by device host name (e.g. 'PE1'); blank for all.",
                max_length=253,
            ),
        ] = "",
        ip_address: Annotated[
            str,
            Field(
                description="Filter by device IP address (e.g. '10.0.0.1'); blank for all.",
                max_length=64,
            ),
        ] = "",
        reachability_state: Annotated[
            str,
            Field(
                description=(
                    "Filter by reachability: reachable, unreachable, degraded, unknown (or a "
                    "CONN_STATE_* wire value); blank for all."
                ),
                max_length=40,
            ),
        ] = "",
        collection_status: Annotated[
            str,
            Field(
                description=(
                    "Filter by collection status: ACTIVE, DEGRADED or NOTPOLLING; blank for all."
                ),
                max_length=20,
            ),
        ] = "",
        page_size: Annotated[
            int, Field(description="Devices per page (e.g. 50).", ge=1, le=1000)
        ] = 50,
        page: Annotated[int, Field(description="Page number, 1-based (e.g. 1).", ge=1)] = 1,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the devices a performance policy polls, with each device's
        collection status (is PM data actually being collected from it?).

        Read-only; ``GET /crosswork/performance/v1/policies/devices/<id>?
        pageSize=&page=`` (verified; ``page`` is 1-based) plus the optional
        ``hostName`` / ``ipAddress`` / ``reachabilityState`` /
        ``collectionStatus`` filters -> ``{"data": [{hostName, ipAddress, uuid
        (inventory uuid), reachabilityState, adminState, collectionStatus
        ACTIVE | DEGRADED | NOTPOLLING, comments [{type, argument}] when
        NOTPOLLING, productType, gatewayName, lastUpdateTime (epoch s),
        selected}], "total_count": N}``. ``total_count`` is present when a
        filter is given and ABSENT on the plain page (verified): the total is
        then unknown and ``has_more`` is inferred from a full page. Use it to
        answer "is PE1 being polled by the interface policy?" or to find the
        NOTPOLLING devices (the ``comments`` say why: POLLED_BY_ANOTHER_POLICY,
        MISSING_DEVICE_DETAILS, UN_MANAGED_DEVICE, SCHEDULING_FAILURE, ...).

        Args:
            policy_id: the policy id (an integer).
            host_name / ip_address / reachability_state / collection_status:
                optional filters (blank = no filter).
            page_size / page: 1-based paging.
            response_format: markdown or json.

        Returns:
            str: Markdown "# Devices of performance policy <id> (page P, N
            shown, total T|unknown)" and one "- **host** ip (uuid):
            reachability / admin state, collection STATUS, product, gateway,
            updated <ISO> [notes]" line per device, plus a "(more ...)" note
            when another page may exist; or JSON {"policy_id", "total" (null
            when unknown), "count", "page", "page_size", "has_more",
            "next_page", "offset", "next_offset", "items": [{"host_name",
            "ip_address", "uuid", "reachability_state", "admin_state",
            "collection_status", "product_type", "gateway_name",
            "last_update_at", "selected", "comments": [{"type", "argument"}]}]}.
            "No devices for policy <id> ..." when the page is empty; "Error:
            no performance policy <id> (MISSING_POLICY_ID). ..." for an unknown
            id; "Error: Unknown reachability_state ..." / "... collection_status
            ..." (nothing sent) for a bad filter; "Error: ..." on an API failure.
        """
        try:
            params: dict[str, Any] = {"pageSize": page_size, "page": page}
            if host_name.strip():
                params["hostName"] = host_name.strip()
            if ip_address.strip():
                params["ipAddress"] = ip_address.strip()
            reachability = parse_reachability(reachability_state)
            if reachability:
                params["reachabilityState"] = reachability
            status = parse_collection_status(collection_status)
            if status:
                params["collectionStatus"] = status
            data = await perf_get(
                f"{POLICY_DEVICES_URL}/{policy_id}", params=params, hints=policy_hints(policy_id)
            )
            rows = _list_of_dicts(_dict(data).get("data"))
            total = _dict(data).get("total_count")
            total = total if isinstance(total, int) and not isinstance(total, bool) else None
            views = [policy_device_view(r) for r in rows]
            env = page_view(views, total=total, page=page, page_size=page_size)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json({"policy_id": policy_id, **env}), settings)
            filters = ", ".join(
                f"{k}={v}" for k, v in params.items() if k not in ("pageSize", "page")
            )
            if not views:
                where = f" matching {filters}" if filters else ""
                return finalize(
                    f"No devices for policy {policy_id}{where} on page {page}. Check the policy "
                    "with cnc_get_performance_policy; the built-in policies select device groups.",
                    settings,
                )
            total_text = f"total {total}" if total is not None else "total unknown"
            lines = [
                f"# Devices of performance policy {policy_id} (page {page}, {len(views)} shown, "
                f"{total_text}" + (f"; filters {filters}" if filters else "") + ")",
                "",
            ]
            lines.extend(policy_device_line(v) for v in views)
            if env["has_more"]:
                lines.append(f"\n(more may exist: call again with page={env['next_page']})")
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_performance_policy_templates",
        title="List Performance Policy Templates",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_performance_policy_templates(
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the performance policy templates with their schemas, every metric
        name and unit, and the default / allowed polling intervals — the
        authoritative name catalogue for every other performance tool.

        Read-only; ``GET /crosswork/performance/v1/policies/policy-templates``
        (verified) -> a dict keyed by template (SRPOLICY, OPTICALZRP, QOS,
        INTERFACE, GNSS, SRV6LOCATOR, deviceHealth, PTP, OpticalSFP on 7.2)
        -> ``{policyTemplate, schemasInterval {<SCHEMA>: {defaultInterval,
        pollingIntervals[]}}, schemasFieldMetadata {<SCHEMA>: {<metric>:
        {min, max, unitType, TCAEnabled}}}, schemaDisplayMap, portGroupSupported}``.
        Three name levels: template -> schema(s) -> metrics (INTERFACE ->
        CEPMINTERFACE: ifInBitsRate, ifOutBitsRate, ifInUtilization, ...;
        CEPMCRC: crc, crcPercentage; deviceHealth -> CPU cpuUtilization,
        MEMORY memoryUtilization, DVAVAILABILITY deviceAvailability, ENVTEMP
        envTemperatureX100 / envTemperatureInletX100; SRPOLICY -> outBitRate,
        outPktsRate). Dashboards take ``<SCHEMA>_<metric>`` tokens
        (``CEPMINTERFACE_ifInUtilization``) — never the template name. Use it
        before cnc_get_performance_statistics / _top_n / _summary when unsure
        of a schema or metric spelling.

        Returns:
            str: Markdown "# N performance policy templates" and, per
            template, "## <template> (port groups supported|not supported)"
            with one "- SCHEMA (display) — default N s, allowed a/b/c s: metric
            (UNIT), ..." line per schema; or JSON {"count": int, "templates":
            [{"template", "port_group_supported", "schema_display_map",
            "schemas_interval": {schema: {defaultInterval, pollingIntervals}},
            "schemas": {schema: {metric: {"unit", "min", "max",
            "tca_enabled"}}}}]}. "Error: ..." on an API failure.
        """
        try:
            data = _dict(await perf_get(POLICY_TEMPLATES_URL))
            templates = []
            for key, template in data.items():
                view = template_view(_dict(template))
                view["template"] = view["template"] or str(key)
                templates.append((str(key), _dict(template), view))
            if response_format is ResponseFormat.JSON:
                payload = {"count": len(templates), "templates": [t[2] for t in templates]}
                return finalize(to_json(payload), settings)
            if not templates:
                return finalize("No performance policy templates.", settings)
            lines = [f"# {len(templates)} performance policy templates"]
            for key, template, view in templates:
                support = "supported" if view.get("port_group_supported") else "not supported"
                lines.extend(["", f"## {key} (port groups {support})"])
                lines.extend(template_schema_lines(template) or ["(no schemas)"])
            lines.append(
                "\nDashboard tokens are <SCHEMA>_<metric> (e.g. CEPMINTERFACE_ifInUtilization); "
                f"top-N covers only: {', '.join(TOP_N_SCHEMAS)}."
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_performance_retention",
        title="Get Performance Data Retention",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_performance_retention(
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get how long performance data is kept — per schema and the platform
        default — at raw, hourly, daily and weekly granularity.

        Read-only; ``GET /crosswork/performance/v1/dataretention/all``
        (verified) -> a dict keyed by display name (``DeviceEnvTemp``,
        ``DeviceAvailability``, ``Interface``, ...) -> ``{schemaName,
        policyType, rawDataRetentionPeriod, hourlyDataRetentionPeriod,
        dailyDataRetentionPeriod, weeklyDataRetentionPeriod (all hours),
        hasAggrOption}``, plus ``GET dataretention/default`` -> the four default
        periods (24 / 168 / 744 / 9072 h on 7.2). Use it to know how far back
        cnc_get_performance_statistics / _top_n / _summary can look and at
        which resolution (raw 5-minute samples for 24 h, then hourly roll-ups,
        ...). Changing retention (``PUT dataretention``) is not exposed.

        Returns:
            str: Markdown "# Performance data retention (hours)", the default
            line and a table (display name | schema | policy type | raw |
            hourly | daily | weekly | aggregation); or JSON {"default":
            {"rawDataRetentionPeriod", "hourlyDataRetentionPeriod",
            "dailyDataRetentionPeriod", "weeklyDataRetentionPeriod"}, "count":
            int, "schemas": [{"display_name", "schema", "policy_type",
            "raw_hours", "hourly_hours", "daily_hours", "weekly_hours",
            "has_aggregation_option"}]}. "Error: ..." on an API failure.
        """
        try:
            all_data, defaults = await asyncio.gather(
                perf_get(RETENTION_ALL_URL), perf_get(RETENTION_DEFAULT_URL)
            )
            views = [retention_view(str(k), _dict(v)) for k, v in _dict(all_data).items()]
            defaults = _dict(defaults)
            if response_format is ResponseFormat.JSON:
                payload = {"default": defaults, "count": len(views), "schemas": views}
                return finalize(to_json(payload), settings)
            return finalize(retention_markdown(defaults, views), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_performance_health_settings",
        title="Get Performance Health Settings",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_performance_health_settings(
        template: Annotated[
            str,
            Field(
                description=(
                    "Only this policy template's settings (e.g. 'INTERFACE', 'deviceHealth'; "
                    "case-insensitive); blank for every template."
                ),
                max_length=60,
            ),
        ] = "",
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the health (severity) thresholds the performance dashboards apply
        to each metric — the value ranges behind HEALTHY / MINOR / MAJOR /
        CRITICAL in top-N answers.

        Read-only; ``GET /crosswork/performance/v1/dashboards/healthsettings``
        (verified) -> a dict keyed by template (INTERFACE, deviceHealth, ...)
        -> ``{"<SCHEMA>_<metric>": {metric, schemaName, policy, categories
        [{level, min, max}], unit, possibleUnits, min, categoryType,
        editable}}``. The ``<SCHEMA>_<metric>`` keys are exactly the tokens
        cnc_get_performance_top_n and cnc_get_performance_summary take. Use it
        to interpret a ``severity`` (which range a value fell in) or to check
        what "MAJOR" means for a metric before alarming on it. Changing the
        thresholds (``PUT dashboards/healthsettings``) is not exposed.

        Args:
            template: optional template filter (case-insensitive key match).
            response_format: markdown or json.

        Returns:
            str: Markdown "# Performance health settings (N template(s))" and,
            per template, "## <template>" with one "- SCHEMA_metric (UNIT):
            LEVEL min-max | LEVEL min-max ..." line per metric; or JSON (the
            platform's dict, filtered to the template when one is given).
            "Error: no health settings for template '<x>'; templates: ..."
            when the filter matches nothing; "Error: ..." on an API failure.
        """
        try:
            data = _dict(await perf_get(HEALTH_SETTINGS_URL))
            wanted = template.strip()
            if wanted:
                matches = {k: v for k, v in data.items() if str(k).lower() == wanted.lower()}
                if not matches:
                    raise PlatformError(
                        f"no health settings for template '{wanted}'; templates: "
                        f"{', '.join(str(k) for k in data) or '(none)'}."
                    )
                data = matches
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(data), settings)
            if not data:
                return finalize("No performance health settings.", settings)
            return finalize(health_settings_markdown(data), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_performance_statistics",
        title="Get Performance Statistics",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_performance_statistics(
        schema: Annotated[
            str,
            Field(
                description=(
                    "Performance schema (e.g. 'CEPMINTERFACE', 'SRPOLICY', 'CPU'); "
                    "cnc_list_performance_policy_templates lists them."
                ),
                max_length=60,
            ),
        ],
        metrics: Annotated[
            str,
            Field(
                description=(
                    "Comma-separated metric names of the schema to return (e.g. "
                    "'ifInUtilization,ifOutUtilization'); blank for every metric."
                ),
                max_length=1000,
            ),
        ] = "",
        device_uuid: Annotated[
            str,
            Field(
                description="Only this device (inventory uuid, cnc_list_devices); blank for all.",
                max_length=100,
            ),
        ] = "",
        hours: Annotated[
            int,
            Field(
                description=(
                    "Window: the last N hours (e.g. 24); ignored when from_time and to_time "
                    "are given."
                ),
                ge=1,
                le=MAX_HOURS,
            ),
        ] = 24,
        from_time: Annotated[
            str,
            Field(
                description=(
                    "Explicit window start, ISO-8601 UTC (e.g. '2026-09-13T00:00:00Z'); pass "
                    "with to_time, or neither."
                ),
                max_length=40,
            ),
        ] = "",
        to_time: Annotated[
            str,
            Field(
                description="Explicit window end, ISO-8601 UTC (e.g. '2026-09-13T12:00:00Z').",
                max_length=40,
            ),
        ] = "",
        with_units: Annotated[
            bool,
            Field(
                description="true to return each value as {unit, value} instead of a bare number."
            ),
        ] = False,
        page_size: Annotated[
            int, Field(description="Rows per page (e.g. 50).", ge=1, le=1000)
        ] = 50,
        page: Annotated[int, Field(description="Page number, 1-based (e.g. 1).", ge=1)] = 1,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the per-object averages of a performance schema over a time window
        — one row per interface / policy / CPU / ... with its metric values
        (the Performance dashboard's table).

        Read-only; ``GET /crosswork/performance/v1/dashboards/statistics?
        schema=<SCHEMA>&timeInterval=<hours>`` or ``&from=&to=`` (ISO
        ``YYYY-MM-DDTHH:mm:ss.SSSZ``; neither answers 400 MISSING_TIME_DETAILS)
        ``[&metrics=a,b][&device=<uuid>]&units=true|false&pageSize=&page=``
        (verified; ``page`` 1-based) -> ``{"schema", "page", "records" (rows on
        this page), "entries": [{"keys": {hostname, interfaceName | name +
        color + endpoint (SRPOLICY: name "srte_c_100_ep_10.0.0.3") | cpuName |
        ..., device (uuid)}, "metrics": {<metric>: <average> | {unit, value}}}]}``.
        Past the last page: ``records 0, entries []``. Values are the window's
        averages per object. A schema no active policy polls answers empty
        (CPU / MEMORY / DVAVAILABILITY on a fresh install: no deviceHealth
        policy); an unknown schema answers 400 INVALID_SCHEMA. Schemas and
        metric names: cnc_list_performance_policy_templates (INTERFACE ->
        CEPMINTERFACE / CEPMCRC, SRPOLICY, deviceHealth -> CPU / MEMORY /
        DVAVAILABILITY / ENVTEMP, ...). For a ranked list use
        cnc_get_performance_top_n; for a time series of one metric across
        the network use cnc_get_performance_summary.

        Args:
            schema: the schema name (upper-cased before sending).
            metrics: optional comma list of metric names.
            device_uuid: optional inventory uuid filter.
            hours: window length when from_time / to_time are not given.
            from_time / to_time: explicit window (both or neither).
            with_units: wrap every value as {unit, value}.
            page_size / page: 1-based paging.
            response_format: markdown or json.

        Returns:
            str: Markdown "# <SCHEMA> statistics — last N h | <from> to <to>,
            page P (R rows)" and one "- <hostname> <interface|name ...>:
            metric=value[ UNIT], ..." line per row plus a "(more ...)" note
            when the page is full; or JSON {"schema", "window": {"hours" |
            "from", "to"}, "page", "page_size", "records", "has_more",
            "next_page", "entries": [...] (as the platform returns them)}.
            "No <SCHEMA> statistics ..." (non-error) when records is 0;
            "Error: unknown performance schema '<x>' (INVALID_SCHEMA). ..."
            listing the known schemas; "Error: from_time must be ..." (nothing
            sent) for a bad time; "Error: ..." on an API failure.
        """
        try:
            schema_name = parse_schema(schema)
            params: dict[str, Any] = {"schema": schema_name}
            window: dict[str, Any]
            has_from, has_to = bool(from_time.strip()), bool(to_time.strip())
            if has_from != has_to:
                raise PlatformError(
                    "pass both from_time and to_time for an explicit window, or neither "
                    "(then the last `hours` hours are used). Nothing was sent."
                )
            if has_from:
                start, end = time_window(from_time, to_time)
                params["from"] = performance_time(start)
                params["to"] = performance_time(end)
                window = {"from": params["from"], "to": params["to"]}
            else:
                params["timeInterval"] = hours
                window = {"hours": hours}
            metric_names = split_csv(metrics)
            if metric_names:
                params["metrics"] = ",".join(metric_names)
            if device_uuid.strip():
                params["device"] = device_uuid.strip()
            params["units"] = "true" if with_units else "false"
            params["pageSize"] = page_size
            params["page"] = page
            hints: dict[str, str | tuple[str, str]] = {
                CODE_INVALID_SCHEMA: (
                    f"unknown performance schema '{schema_name}'",
                    f"Schemas on 7.2: {', '.join(KNOWN_SCHEMAS)}. {_SCHEMA_HELP}",
                ),
                CODE_MISSING_TIME_DETAILS: (
                    "the platform needs a time window",
                    "Pass hours, or both from_time and to_time.",
                ),
            }
            data = _dict(await perf_get(STATISTICS_URL, params=params, hints=hints))
            entries = _list_of_dicts(data.get("entries"))
            records = data.get("records")
            records = (
                records
                if isinstance(records, int) and not isinstance(records, bool)
                else len(entries)
            )
            has_more = records >= page_size and records > 0
            window_text = (
                f"last {hours} h" if "hours" in window else f"{window['from']} to {window['to']}"
            )
            if response_format is ResponseFormat.JSON:
                payload = {
                    "schema": data.get("schema") or schema_name,
                    "window": window,
                    "metrics": metric_names,
                    "device": device_uuid.strip() or None,
                    "page": data.get("page") if data.get("page") is not None else page,
                    "page_size": page_size,
                    "records": records,
                    "has_more": has_more,
                    "next_page": page + 1 if has_more else None,
                    "entries": entries,
                }
                return finalize(to_json(payload), settings)
            if not entries:
                return finalize(
                    f"No {schema_name} statistics for {window_text} (page {page}). Either no "
                    "active policy polls this schema (cnc_list_performance_policies), the "
                    "window has no data, or the page is past the end.",
                    settings,
                )
            filters = []
            if metric_names:
                filters.append(f"metrics {', '.join(metric_names)}")
            if device_uuid.strip():
                filters.append(f"device {device_uuid.strip()}")
            lines = [
                f"# {schema_name} statistics — {window_text}, page {page} ({records} rows"
                + (f"; {'; '.join(filters)}" if filters else "")
                + ")",
                "",
            ]
            lines.extend(statistics_line(e) for e in entries)
            if has_more:
                lines.append(f"\n(page full: more may exist, call again with page={page + 1})")
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_performance_top_n",
        title="Get Performance Top-N",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_performance_top_n(
        metric: Annotated[
            str,
            Field(
                description=(
                    "Metric token <SCHEMA>_<metric> (e.g. 'CEPMINTERFACE_ifInUtilization', "
                    "'CPU_cpuUtilization'); cnc_list_performance_top_n_columns lists the "
                    "13 top-N schemas."
                ),
                max_length=120,
            ),
        ],
        from_time: Annotated[
            str,
            Field(
                description="Window start, ISO-8601 UTC (e.g. '2026-09-13T00:00:00Z').",
                max_length=40,
            ),
        ],
        to_time: Annotated[
            str,
            Field(
                description="Window end, ISO-8601 UTC (e.g. '2026-09-13T12:00:00Z').",
                max_length=40,
            ),
        ],
        page_size: Annotated[
            int, Field(description="Entries per page — the N (e.g. 10).", ge=1, le=500)
        ] = 10,
        page: Annotated[int, Field(description="Page number, 1-based (e.g. 1).", ge=1)] = 1,
        sort: Annotated[
            str,
            Field(
                description=(
                    "Sort attribute, '-' prefix for descending (e.g. '-value', 'average', "
                    "'-maximum', 'minimum'); blank for the platform's default order."
                ),
                max_length=40,
            ),
        ] = "",
        severity: Annotated[
            str,
            Field(
                description=(
                    "Only entries of this health severity (e.g. 'MAJOR'; levels per "
                    "cnc_get_performance_health_settings); blank for all."
                ),
                max_length=20,
            ),
        ] = "",
        device_groups: Annotated[
            str,
            Field(
                description=(
                    "Only these device groups (comma-separated names / uuids); blank for all."
                ),
                max_length=500,
            ),
        ] = "",
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Rank the objects of a metric over a window — the busiest interfaces,
        hottest CPUs, worst CRC counters — with average / minimum / maximum
        and the health severity of each.

        Read-only; ``GET /crosswork/performance/v1/dashboards/topn?metric=
        <SCHEMA>_<metric>&from=&to=&pageSize=&page=[&sort=][&severity=]
        [&deviceGroups=]`` (verified; ISO ``YYYY-MM-DDTHH:mm:ss.SSSZ``; ``page``
        1-based) -> ``[{"metricName", "entries": [{"keys": {hostname,
        interfaceName | cpuName | ..., device}, "average", "maximum",
        "minimum", "unit" (KBITS_PER_SECOND, PERCENTAGE, ...),
        "trendURLParameters", "severity"? (HEALTHY | MINOR | MAJOR | CRITICAL)}]}]``.
        The token is ``<SCHEMA>_<exact metric name>``
        (``CEPMINTERFACE_ifInBitsRate``), and top-N knows ONLY the 13 schemas
        of cnc_list_performance_top_n_columns (CEPMINTERFACE, CEPMCRC, CPU,
        MEMORY, DVAVAILABILITY, ENVTEMP, CEPMQOS, CEPMPTP, CEPMSYNCE, CEPMGNSS,
        OPTICALSFP, OPTICSLANE, OTUCONTROLLERSINFO) — ``SRPOLICY_...`` or a
        template name (``INTERFACE_...``) answers 400
        INVALID_SCHEMA_METRIC_COMBO, so an unknown schema is refused here
        before the request; a misspelt metric of a known schema is left to the
        platform (same 400, explained). A valid metric with no data in the
        window answers ``[]`` (non-error). Thresholds behind ``severity``:
        cnc_get_performance_health_settings. For SR policy traffic use
        cnc_get_performance_statistics(schema='SRPOLICY').

        Args:
            metric: the <SCHEMA>_<metric> token (schema upper-cased before sending).
            from_time / to_time: the window (both required).
            page_size / page: the N and the 1-based page.
            sort / severity / device_groups: optional, passed as given
                (``sort`` upper/lower-case as documented: average | minimum |
                maximum | value, '-' for descending; verified live: '-value').
            response_format: markdown or json.

        Returns:
            str: Markdown "# Top N <token> (<from> to <to>[, sort ..][,
            severity ..])" and one "- <hostname> <object>: avg A, min B, max C
            UNIT, SEVERITY" line per entry; or JSON {"metric", "from", "to",
            "page", "page_size", "sort", "severity", "device_groups", "count",
            "results": [...] (the platform's list)}. "No top-N entries for
            <token> ..." (non-error) for an empty answer; "Error: '<token>' is
            not a top-N schema/metric — ..." (nothing sent, or from the
            platform's 400 INVALID_SCHEMA_METRIC_COMBO); "Error: from_time must
            be ..." for a bad time; "Error: ..." on an API failure.
        """
        try:
            token = parse_metric_token(metric, top_n=True)
            start, end = time_window(from_time, to_time)
            params: dict[str, Any] = {
                "metric": token,
                "from": performance_time(start),
                "to": performance_time(end),
                "pageSize": page_size,
                "page": page,
            }
            if sort.strip():
                params["sort"] = sort.strip()
            if severity.strip():
                params["severity"] = severity.strip().upper()
            groups = split_csv(device_groups)
            if groups:
                params["deviceGroups"] = ",".join(groups)
            hints: dict[str, str | tuple[str, str]] = {
                CODE_INVALID_SCHEMA_METRIC_COMBO: (
                    f"'{token}' is not a top-N schema/metric — {_TOP_N_HELP}",
                    f"{_SCHEMA_HELP} The platform's own wording: 'Policy {{0}} or metric "
                    "{1} do not exist'.",
                ),
                CODE_MISSING_TIME_DETAILS: (
                    "the platform needs a time window",
                    "Pass both from_time and to_time.",
                ),
            }
            data = await perf_get(TOPN_URL, params=params, hints=hints)
            results = _list_of_dicts(data)
            entries = [e for r in results for e in _list_of_dicts(r.get("entries"))]
            if response_format is ResponseFormat.JSON:
                payload = {
                    "metric": token,
                    "from": params["from"],
                    "to": params["to"],
                    "page": page,
                    "page_size": page_size,
                    "sort": params.get("sort"),
                    "severity": params.get("severity"),
                    "device_groups": groups,
                    "count": len(entries),
                    "results": results,
                }
                return finalize(to_json(payload), settings)
            if not entries:
                return finalize(
                    f"No top-N entries for {token} between {params['from']} and {params['to']}"
                    f"{' on page ' + str(page) if page > 1 else ''}: no data was collected for "
                    "that metric in the window (is a policy polling its schema? "
                    "cnc_list_performance_policies), or the severity / device-group filter "
                    "excludes everything.",
                    settings,
                )
            extras = []
            if params.get("sort"):
                extras.append(f"sort {params['sort']}")
            if params.get("severity"):
                extras.append(f"severity {params['severity']}")
            if groups:
                extras.append(f"device groups {', '.join(groups)}")
            lines = [
                f"# Top {page_size} {token} ({params['from']} to {params['to']}"
                + (f", {', '.join(extras)}" if extras else "")
                + (f", page {page}" if page > 1 else "")
                + ")",
                "",
            ]
            lines.extend(topn_line(e) for e in entries)
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_performance_top_n_columns",
        title="List Performance Top-N Columns",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_performance_top_n_columns(
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the schemas the top-N dashboard supports and the key columns
        (hostname, interfaceName, cpuName, ...) that identify each entry.

        Read-only; ``GET /crosswork/performance/v1/dashboards/topn/columns``
        (verified) -> ``[{"schemaName", "keyToDisplayNameList": [{"key",
        "displayName"}]}]`` — 13 schemas on 7.2 (OTUCONTROLLERSINFO,
        DVAVAILABILITY, CEPMGNSS, CEPMQOS, CEPMSYNCE, ENVTEMP, CPU, CEPMCRC,
        CEPMINTERFACE, OPTICALSFP, MEMORY, OPTICSLANE, CEPMPTP). These are the
        only schemas cnc_get_performance_top_n accepts in its
        ``<SCHEMA>_<metric>`` token (SRPOLICY and SRV6LOCATOR are not top-N
        schemas); the metric names come from
        cnc_list_performance_policy_templates.

        Returns:
            str: Markdown "# N top-N schemas" and one "- SCHEMA: key (Display
            name), ..." line per schema, or the raw JSON list. "Error: ..." on
            an API failure.
        """
        try:
            data = _list_of_dicts(await perf_get(TOPN_COLUMNS_URL))
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(data), settings)
            if not data:
                return finalize("No top-N schemas reported.", settings)
            lines = [f"# {len(data)} top-N schemas", ""]
            lines.extend(topn_columns_line(e) for e in data)
            lines.append(
                "\nUse them as <SCHEMA>_<metric> in cnc_get_performance_top_n; metric names per "
                "schema: cnc_list_performance_policy_templates."
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_performance_summary",
        title="Get Performance Metric Summary",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_performance_summary(
        metric: Annotated[
            str,
            Field(
                description=(
                    "Metric token <SCHEMA>_<metric> (e.g. 'CEPMINTERFACE_ifInUtilization'); "
                    "cnc_list_performance_policy_templates lists the names."
                ),
                max_length=120,
            ),
        ],
        from_time: Annotated[
            str,
            Field(
                description="Window start, ISO-8601 UTC (e.g. '2026-09-13T00:00:00Z').",
                max_length=40,
            ),
        ],
        to_time: Annotated[
            str,
            Field(
                description="Window end, ISO-8601 UTC (e.g. '2026-09-13T12:00:00Z').",
                max_length=40,
            ),
        ],
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the network-wide time series of one metric over a window — the
        average, minimum and maximum across every polled object per bucket
        (the Performance dashboard's summary graph).

        Read-only; ``GET /crosswork/performance/v1/dashboards/summary?metric=
        <SCHEMA>_<metric>&from=&to=`` (verified; ISO ``YYYY-MM-DDTHH:mm:ss.SSSZ``)
        -> ``[{"metricName", "metricUnit", "averageSeries": [{value,
        timestamp}], "minimumSeries": [...], "maximumSeries": [...]}]`` in
        2-hour buckets on 7.2. Empty series (a metric nobody polls, or a window
        with no data) are a non-error answer. Same token rules as
        cnc_get_performance_top_n; the platform answers 400
        INVALID_SCHEMA_METRIC_COMBO for a schema / metric it does not know.
        For per-object values use cnc_get_performance_statistics.

        Args:
            metric: the <SCHEMA>_<metric> token (schema upper-cased before sending).
            from_time / to_time: the window (both required).
            response_format: markdown or json.

        Returns:
            str: Markdown "# <token> summary (UNIT), <from> to <to>, N
            bucket(s)" and one "- <timestamp>: avg A, min B, max C" line per
            bucket; or JSON {"metric", "from", "to", "results": [{"metricName",
            "metricUnit", "rows": [{"timestamp", "average", "minimum",
            "maximum"}]}]}. "No summary data for <token> ..." (non-error) for
            empty series; "Error: '<token>' is not a ... (INVALID_SCHEMA_METRIC_COMBO)"
            from the platform; "Error: from_time must be ..." for a bad time;
            "Error: ..." on an API failure.
        """
        try:
            token = parse_metric_token(metric, top_n=False)
            start, end = time_window(from_time, to_time)
            params = {"metric": token, "from": performance_time(start), "to": performance_time(end)}
            hints: dict[str, str | tuple[str, str]] = {
                CODE_INVALID_SCHEMA_METRIC_COMBO: (
                    f"'{token}' is not a schema/metric the summary dashboard knows — the token "
                    "is <SCHEMA>_<exact metric name>",
                    _SCHEMA_HELP,
                ),
                CODE_MISSING_TIME_DETAILS: (
                    "the platform needs a time window",
                    "Pass both from_time and to_time.",
                ),
            }
            results = _list_of_dicts(await perf_get(SUMMARY_URL, params=params, hints=hints))
            series = [
                {
                    "metricName": r.get("metricName"),
                    "metricUnit": r.get("metricUnit"),
                    "rows": summary_rows(r),
                }
                for r in results
            ]
            if response_format is ResponseFormat.JSON:
                payload = {
                    "metric": token,
                    "from": params["from"],
                    "to": params["to"],
                    "results": series,
                }
                return finalize(to_json(payload), settings)
            if not any(s["rows"] for s in series):
                return finalize(
                    f"No summary data for {token} between {params['from']} and {params['to']}: "
                    "no active policy polls this metric's schema "
                    "(cnc_list_performance_policies), or the window has no data.",
                    settings,
                )
            lines: list[str] = []
            for s in series:
                if lines:
                    lines.append("")
                lines.append(
                    f"# {s['metricName'] or token} summary ({s['metricUnit'] or '-'}), "
                    f"{params['from']} to {params['to']}, {len(s['rows'])} bucket(s)"
                )
                lines.append("")
                lines.extend(summary_line(row) for row in s["rows"])
                if not s["rows"]:
                    lines.append("(no data in this series)")
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_lsp_utilization",
        title="Get LSP Utilization (NPM)",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_lsp_utilization(
        headend: Annotated[str, Field(description=_HEADEND_DESC, max_length=64)],
        endpoint: Annotated[str, Field(description=_ENDPOINT_DESC, max_length=64)],
        from_time: Annotated[
            str,
            Field(
                description="Window start, ISO-8601 UTC (e.g. '2026-09-13T12:00:00Z').",
                max_length=40,
            ),
        ],
        to_time: Annotated[
            str,
            Field(
                description="Window end, ISO-8601 UTC (e.g. '2026-09-13T18:00:00Z').",
                max_length=40,
            ),
        ],
        color: Annotated[int, Field(description=_COLOR_DESC, ge=0, le=4294967295)] = 0,
        tunnel_id: Annotated[
            str,
            Field(
                description=(
                    "RSVP-TE tunnel id (e.g. '11') — selects an RSVP LSP instead of an SR "
                    "policy; blank for SR."
                ),
                max_length=40,
            ),
        ] = "",
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the utilisation time series of one SR policy or RSVP-TE tunnel
        from NPM (Optima analytics), with its maximum over the window.

        Read-only; two ``POST``s on ``/crosswork/optima-analytics/api/v1``
        (verified): ``lsp/utilizations`` and ``lsp/max/utilization``, both with
        the LSP key ``{"lspType": "SR", "peerAddress": <head-end router-id>,
        "destAddress": <tail-end router-id>, "color": "<color as a STRING>",
        "from", "to"}`` (or ``{"lspType": "RSVP", ..., "tunnelId"}`` when
        tunnel_id is given; times as ``2026-09-13T12:00:00Z``). Answers:
        ``[{"tst": "<ISO>", "util": <number>}, ...]`` (5-minute samples) and
        ``{"maxUtilization", "success", "message"}``. Keys are TE router-ids
        (IP addresses — a host name is refused here because NPM would
        silently answer an empty list), and an SR key needs the policy's
        real color: color 0 (the default) without a tunnel_id is refused for
        the same reason (no SR policy has color 0). NPM never validates: an
        unknown key, a wrong color or a window with no data all answer ``[]``,
        so an empty answer is reported as such with that caveat. The lab's PCE-delegated
        policy answered zeros. Related: cnc_get_lsp_delay for delay / loss;
        cnc_get_performance_statistics(schema='SRPOLICY') for the PM
        policy's outBitRate.

        Args:
            headend / endpoint: TE router-ids (the same names and values as
                cnc_list_sr_policies / cnc_get_sr_policy_performance_metrics).
            from_time / to_time: the window (both required).
            color: the SR policy color (required for SR; 0 is refused).
            tunnel_id: an RSVP-TE tunnel id (switches to lspType RSVP).
            response_format: markdown or json.

        Returns:
            str: Markdown "# Utilization of SR LSP <head> -> <tail> color C,
            <from> to <to>", "- max utilization (platform): M — <message>",
            "- N sample(s) (<first> to <last>): util avg A, min B, max C, last
            D" and one "- <tst>: util V" line per sample; or JSON {"lsp": <the
            key>, "max": {"maxUtilization", "success", "message"}, "stats":
            {"count", "first_at", "last_at", "average", "minimum", "maximum",
            "last"}, "samples": [{"tst", "util"}]}. "No LSP utilization samples
            for ..." (non-error, with the unknown-key caveat) for an empty
            list; "Error: headend must be a TE router-id ..." or "Error: color
            is required for an SR policy ..." (nothing sent); "Error: ..." on
            an API failure.
        """
        try:
            start, end = time_window(from_time, to_time)
            key = lsp_key(headend, endpoint, color, tunnel_id, start, end)
            label = lsp_label(key)
            samples_data, max_data = await asyncio.gather(
                npm_post(NPM_LSP_UTILIZATIONS_URL, key),
                npm_post(NPM_LSP_MAX_UTILIZATION_URL, key),
            )
            samples = samples_of(samples_data)
            stats = series_stats(samples, "util")
            if response_format is ResponseFormat.JSON:
                payload = {"lsp": key, "max": _dict(max_data), "stats": stats, "samples": samples}
                return finalize(to_json(payload), settings)
            if not samples:
                return finalize(
                    f"No LSP utilization samples for {label} between {key['from']} and "
                    f"{key['to']} (an unknown key answers the same empty list). {NPM_EMPTY_CAVEAT}"
                    " Check the policy with cnc_list_sr_policies (head-end / endpoint "
                    "router-ids and color) or cnc_list_rsvp_te_tunnels.",
                    settings,
                )
            lines = [
                f"# Utilization of {label}, {key['from']} to {key['to']}",
                "",
                f"- {max_text(max_data, 'maxUtilization', 'max utilization')}",
                f"- {stats_text(stats, 'util')}",
            ]
            lines.extend(series_section("Samples", samples))
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_lsp_delay",
        title="Get LSP Delay and Loss (NPM)",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_lsp_delay(
        headend: Annotated[str, Field(description=_HEADEND_DESC, max_length=64)],
        endpoint: Annotated[str, Field(description=_ENDPOINT_DESC, max_length=64)],
        from_time: Annotated[
            str,
            Field(
                description="Window start, ISO-8601 UTC (e.g. '2026-09-13T12:00:00Z').",
                max_length=40,
            ),
        ],
        to_time: Annotated[
            str,
            Field(
                description="Window end, ISO-8601 UTC (e.g. '2026-09-13T18:00:00Z').",
                max_length=40,
            ),
        ],
        color: Annotated[int, Field(description=_COLOR_DESC, ge=0, le=4294967295)] = 0,
        tunnel_id: Annotated[
            str,
            Field(
                description=(
                    "RSVP-TE tunnel id (e.g. '11') — selects an RSVP LSP instead of an SR "
                    "policy; blank for SR."
                ),
                max_length=40,
            ),
        ] = "",
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the delay, delay variance and loss time series of one SR policy or
        RSVP-TE tunnel from NPM, with the maximum average delay over the window.

        Read-only; four ``POST``s on ``/crosswork/optima-analytics/api/v1``
        (verified): ``lsp/delay`` -> ``[{preferenceId, minimumDelay,
        maximumDelay, averageDelay, delayVariance, tst}]``, ``lsp/max/delay``
        -> ``{"maxDelay", "success", "message"}`` (``success false`` = no
        data), ``lsp/delayVariance`` -> ``[{delayVariance, tst}]`` and
        ``lsp/loss`` -> ``[{..., tst}]``, all with the same LSP key as
        cnc_get_lsp_utilization (``lspType`` SR + ``color`` as a string, or
        RSVP + ``tunnelId``; TE router-ids, not host names). Delay data needs
        SR-PM / performance-measurement probes on the head-end: a lab without
        them answers ``[]`` on every series, and NPM answers the same ``[]``
        for an unknown key — every empty section says so.

        Args:
            headend / endpoint: TE router-ids (the same names and values as
                cnc_list_sr_policies / cnc_get_sr_policy_performance_metrics).
            from_time / to_time: the window (both required).
            color / tunnel_id: SR color (required for SR; 0 is refused), or an
                RSVP-TE tunnel id.
            response_format: markdown or json.

        Returns:
            str: Markdown "# Delay and loss of SR LSP ... , <from> to <to>",
            "- max average delay (platform): ...", then "## Delay (N
            sample(s))", "## Delay variance (...)" and "## Loss (...)" with
            one "- <tst>: field value, ..." line per sample; or JSON {"lsp":
            <the key>, "max_delay": {...}, "delay": [...], "delay_variance":
            [...], "loss": [...]}. "No LSP delay, delay-variance or loss
            samples for ..." (non-error, with the caveat) when every series is
            empty; "Error: headend must be ..." or "Error: color is required
            for an SR policy ..." (nothing sent);
            "Error: ..." on an API failure.
        """
        try:
            start, end = time_window(from_time, to_time)
            key = lsp_key(headend, endpoint, color, tunnel_id, start, end)
            label = lsp_label(key)
            delay_data, max_data, variance_data, loss_data = await asyncio.gather(
                npm_post(NPM_LSP_DELAY_URL, key),
                npm_post(NPM_LSP_MAX_DELAY_URL, key),
                npm_post(NPM_LSP_DELAY_VARIANCE_URL, key),
                npm_post(NPM_LSP_LOSS_URL, key),
            )
            delay = samples_of(delay_data)
            variance = samples_of(variance_data)
            loss = samples_of(loss_data)
            if response_format is ResponseFormat.JSON:
                payload = {
                    "lsp": key,
                    "max_delay": _dict(max_data),
                    "delay": delay,
                    "delay_variance": variance,
                    "loss": loss,
                }
                return finalize(to_json(payload), settings)
            if not (delay or variance or loss):
                return finalize(
                    f"No LSP delay, delay-variance or loss samples for {label} between "
                    f"{key['from']} and {key['to']} (an unknown key answers the same empty "
                    f"lists). {NPM_EMPTY_CAVEAT} Delay series also need SR-PM probes on the "
                    f"head-end. {max_text(max_data, 'maxDelay', 'Max average delay')}.",
                    settings,
                )
            lines = [
                f"# Delay and loss of {label}, {key['from']} to {key['to']}",
                "",
                f"- {max_text(max_data, 'maxDelay', 'max average delay')}",
                f"- delay: {stats_text(series_stats(delay, 'averageDelay'), 'averageDelay')}",
            ]
            lines.extend(series_section("Delay", delay))
            lines.extend(series_section("Delay variance", variance))
            lines.extend(series_section("Loss", loss))
            if not (delay and variance and loss):
                lines.extend(["", f"(An empty series: {NPM_EMPTY_CAVEAT})"])
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_interface_delay",
        title="Get Interface Delay and Loss (NPM)",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_interface_delay(
        device_uuid: Annotated[
            str,
            Field(
                description=(
                    "Device inventory uuid (cnc_list_devices), e.g. "
                    "'2a9b7c1e-0f3d-4b8a-9c6e-1d2f3a4b5c6d'."
                ),
                max_length=100,
            ),
        ],
        interface: Annotated[
            str,
            Field(
                description="Interface name as on the device (e.g. 'GigabitEthernet0/0/0/0').",
                max_length=200,
            ),
        ],
        from_time: Annotated[
            str,
            Field(
                description="Window start, ISO-8601 UTC (e.g. '2026-09-13T12:00:00Z').",
                max_length=40,
            ),
        ],
        to_time: Annotated[
            str,
            Field(
                description="Window end, ISO-8601 UTC (e.g. '2026-09-13T18:00:00Z').",
                max_length=40,
            ),
        ],
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the link delay and loss time series of one interface from NPM,
        with the maximum average delay over the window.

        Read-only; three ``POST``s on ``/crosswork/optima-analytics/api/v1``
        (verified): ``interface/delays`` -> ``[{minimumDelay, maximumDelay,
        averageDelay, delayVariance, tst}]``, ``interface/max/delay`` ->
        ``{"maxDelay", "success", "message"}`` (``success false`` + "Maximum
        Average Delay for given Interface not present..returning default
        delay!" = no data, still HTTP 200) and ``interface/loss`` -> ``[{...,
        tst}]``, all with the key ``{"device_uuid": <inventory uuid>,
        "int_name": "<interface>", "from", "to"}``. Link delay comes from
        performance-measurement probes on the link (the same source as the
        topology link's delay metrics, cnc_get_link_performance_metrics);
        without them every series is ``[]`` — and NPM answers the same ``[]``
        for an unknown uuid or interface name, so an empty answer carries that
        caveat, and a device_uuid that is not a uuid (a host name, an IP) is
        refused before sending — cnc_get_device(host_name=...) shows the
        uuid. Interface names: cnc_list_node_interfaces.

        Args:
            device_uuid: the inventory uuid (any spelling; sent canonical).
            interface: the interface name.
            from_time / to_time: the window (both required).
            response_format: markdown or json.

        Returns:
            str: Markdown "# Delay and loss of <interface> on <uuid>, <from> to
            <to>", "- max average delay (platform): ...", then "## Delay (N
            sample(s))" and "## Loss (...)" with one "- <tst>: field value,
            ..." line per sample; or JSON {"interface": <the key>,
            "max_delay": {...}, "delay": [...], "loss": [...]}. "No delay or
            loss samples for ..." (non-error, with the caveat) when both series
            are empty; "Error: device_uuid ... and interface ... are both
            required" or "Error: device_uuid must be the device's inventory
            uuid ..." (nothing sent); "Error: ..." on an API failure.
        """
        try:
            start, end = time_window(from_time, to_time)
            key = interface_key(device_uuid, interface, start, end)
            label = f"{key['int_name']} on {key['device_uuid']}"
            delay_data, max_data, loss_data = await asyncio.gather(
                npm_post(NPM_INTERFACE_DELAYS_URL, key),
                npm_post(NPM_INTERFACE_MAX_DELAY_URL, key),
                npm_post(NPM_INTERFACE_LOSS_URL, key),
            )
            delay = samples_of(delay_data)
            loss = samples_of(loss_data)
            if response_format is ResponseFormat.JSON:
                payload = {
                    "interface": key,
                    "max_delay": _dict(max_data),
                    "delay": delay,
                    "loss": loss,
                }
                return finalize(to_json(payload), settings)
            if not (delay or loss):
                return finalize(
                    f"No delay or loss samples for {label} between {key['from']} and "
                    f"{key['to']} (an unknown uuid or interface name answers the same empty "
                    f"lists). {NPM_EMPTY_CAVEAT} Link delay also needs performance-measurement "
                    f"probes on the link. {max_text(max_data, 'maxDelay', 'Max average delay')}.",
                    settings,
                )
            lines = [
                f"# Delay and loss of {label}, {key['from']} to {key['to']}",
                "",
                f"- {max_text(max_data, 'maxDelay', 'max average delay')}",
                f"- delay: {stats_text(series_stats(delay, 'averageDelay'), 'averageDelay')}",
            ]
            lines.extend(series_section("Delay", delay))
            lines.extend(series_section("Loss", loss))
            if not (delay and loss):
                lines.extend(["", f"(An empty series: {NPM_EMPTY_CAVEAT})"])
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)
