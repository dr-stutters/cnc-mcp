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
  the performance wire and ``YYYY-MM-DDTHH:mm:ssZ`` on the NPM wire; every
  tool here takes its ``from_time`` / ``to_time`` through ONE parser
  (:func:`parse_iso_time`) that accepts ISO-8601 with or without
  milliseconds, with ``Z`` or a UTC offset, and epoch milliseconds (13
  digits) or seconds (10 digits) — any other bare integer, a year or a
  dashless date, is refused rather than read as 1970 — and normalises to
  the form each service was verified with — so
  ``2026-09-13T12:00:00Z``, ``2026-09-13T12:00:00.000Z``,
  ``2026-09-13T14:00:00+02:00`` and ``1789300800000`` are all the same
  instant to every tool. The top-N and NPM tools also take ``hours`` like
  the statistics dashboard (default 24 — except the two NPM LSP series,
  which default to :data:`LSP_DEFAULT_HOURS` = 6, the largest window NPM
  answers with 5-minute samples and the window cnc_explain_sr_policy uses)
  — the tool computes ``from`` / ``to`` itself where the wire has no
  ``timeInterval`` — so a "last N hours" question needs no explicit window;
  only ``summary`` still needs both bounds. Retention (``GET
  dataretention/all|default``): raw 24 h, hourly
  168 h, daily 744 h, weekly 9072 h by default — a window older than the
  raw retention only has aggregated data. How long NPM keeps its samples is
  not documented and was not verified.
- **SRPOLICY rows** (``dashboards/statistics?schema=SRPOLICY``, verified live
  2026-09-14): the platform leaves ``color`` at 0 and ``endpoint`` at ``""``
  in every row's keys; the ``name`` (``srte_c_100_ep_10.0.0.3`` — the
  IOS-XR policy name the CFP renders as ``srte_c_<color>_ep_<tail-end>``)
  is what carries them, so the tool fills both from the name
  (:func:`sr_policy_name_parts`) and, best effort, names the endpoint's
  host from one topology GET (``endpoint=10.0.0.3 (PE2)``; te_state's
  ``router_id_names``). With ``units=true`` the same rows report
  ``unit "NUMBER"`` for outBitRate and outPktsRate, whereas the template
  catalogue says BITS_PER_SECOND / PACKETS_PER_SECOND (and CEPMINTERFACE
  rows do carry their real units). NUMBER is also a genuine template unit
  (OTUCONTROLLERSINFO uc is a count; 27 metrics have no unitType at all),
  so the tool annotates a NUMBER unit with the catalogue's unit only where
  the catalogue says otherwise (:func:`unit_unresolved`).
- **CEPMINTERFACE rows** (verified live 2026-09-14) include the head-end's
  SR-policy virtual interfaces — ``interfaceName srte_c_<color>_ep_<tail>``,
  one per policy the node hosts (32 rows on the lab, of which 2) — as
  ordinary interfaces; the tool counts them separately in the header
  (:func:`is_sr_policy_interface`) so an interface tally is not inflated.
  CEPMCRC presumably shares the interface key set, but the lab's default
  interface policy polls it at interval 0, so its rows were never
  observed (unverified).

Object model (NPM): an **LSP** is keyed by TE router-ids — ``peerAddress``
the head-end router-id (the loopback the PCE knows the node by, e.g.
``10.0.0.1``), ``destAddress`` the tail-end router-id, plus ``color`` (a
STRING on the wire) for ``lspType SR`` or ``tunnelId`` for ``lspType
RSVP``; cnc_list_sr_policies / cnc_list_rsvp_te_tunnels show them. The LSP
tools take a host name OR a router-id for ``headend`` / ``endpoint`` and
resolve a host name to its router-id through the topology NBI with the
SR-policy tools' own resolver (te_state's ``resolve_policy_ends``: one
``networks`` GET, issued only when a name is not an IP literal; an unknown
name is refused before anything is sent; the header then prints the
topology's node id next to each router-id, ``end_label``). Because NPM never
validates, the tools refuse before sending whatever would only ever produce
a silent ``[]``: an unresolvable name (:func:`router_id` is the final
guard), color 0 for an SR key (no SR policy has color 0; :func:`lsp_key`)
and anything but a uuid as an interface's ``device_uuid``
(:func:`device_uuid_key`). An **interface** is keyed by the inventory
``device_uuid`` (cnc_list_devices) and ``int_name``
(``GigabitEthernet0/0/0/0``). Samples are ``{"tst": "<ISO>", ...}`` rows
whose spacing depends on the window (verified live 2026-09-14 on
``lsp/utilizations``): a window of at most 6 h answers the raw ~5-minute
samples (73 for 6 h), a longer one — even 6 h 1 min — answers hourly
roll-ups stamped on the hour (18 for 24 h); the tools print the observed
spacing (:func:`sample_spacing`). The ``max`` endpoints answer ``{"max...",
"success", "message"}`` where ``success false`` means "no data" (still HTTP
200). Delay / loss series need the corresponding SR-PM / Y.1731 probes on the
devices; a lab without them answers ``[]`` everywhere.

Policy and retention writes (verified live 2026-09-15 with a temporary
``phase-d-pm`` INTERFACE policy on PE1 — create -> read back -> update ->
activate -> deactivate -> delete, the lab left as found):

- ``POST policies`` (MonitoringPolicyInputDTO: ``policyTemplate``, ``name``,
  ``description``, ``schemasInterval {SCHEMA: seconds}``, ``devices`` /
  ``deviceGroups`` / ``portGroups`` as comma-separated uuid STRINGS, ``tag``,
  ``thresholds {}``, ``active``) answers 200 with the same
  ``{"monitoringPolicy", "monitoringPolicyTemplate", "policyCollectionStatus"}``
  object as a GET; ids are sequential integers that are never reused (3, 4
  deleted -> the next create got 5). ``active`` omitted -> the policy is
  created INACTIVE (the spec's "default true" is wrong): activation is a
  separate call. Errors are Spring envelopes: a duplicate name -> 400
  ``POLICY_EXITS`` (sic) "There is already an existing policy with the same
  name" (parameters ``["<name> (<TEMPLATE>)"]``); an unknown template -> 400
  ``INVALID_POLICY_TYPE``; no name -> 400 ``MISSING_NAME``; no devices, groups
  or port groups -> 400 ``MISSING_DEVICES`` "The policy must be created with
  either device IPs, device groups OR port groups selected"; an unknown
  schema in ``schemasInterval`` -> 400 ``INVALID_SCHEMA`` "Invalid schema
  provided" (parameters ``["BOGUSfor policy INTERFACE"]``). NOT validated by
  the platform: the cadence (``CEPMINTERFACE: 123`` was accepted although the
  template allows 0/300/600/900/1800/3600), a device that is not an inventory
  uuid (``"PE1"`` was accepted and the activated policy simply polled NOTHING
  — ``policies/devices/<id>`` empty) and an unknown group uuid (accepted) —
  the tools here validate all three before sending.
- ``PUT policies/<id>`` needs the FULL MonitoringPolicy body including
  ``id`` (a partial body, or a body whose ``id`` differs from the path, is
  answered 400 ``MISSING_POLICY_ID`` "Given policy ID doesn't exist" naming
  the PATH id — misleading) and the body's ``active`` IS the activation
  state: ``active: true`` on an inactive policy activates it (a
  deployment-history entry appears, the device polls within ~3 s),
  ``active: false`` OR THE KEY ABSENT deactivates an active one. So an update
  must read-merge-write and carry the current flag — cnc_update_performance_policy
  does. The PUT answer echoes the policy with ``creationTimestamp`` /
  ``lastChangedTimestamp`` 0; a GET has the real ones. Renaming to an
  EXISTING name is accepted (uniqueness is checked on create only) — the tool
  refuses it before sending.
- ``PUT policies/activate/<ids>``, ``PUT policies/deactivate/<ids>`` and
  ``DELETE policies/<ids>`` take ONE comma-separated path segment of integer
  ids (``activate/3,999999`` verified; a non-integer answers 500 "Method
  parameter 'policyIdOrIds': Failed to convert ... to required type
  'java.util.List'") and answer 200 with a LIST of OperationResult
  ``{"policyId", "status": OK | ALREADY_ACTIVATED | ALREADY_DEACTIVATED |
  NOT_FOUND (| DB_ERROR, documented), "policyName" ("" for NOT_FOUND)}`` —
  an unknown id is a 200 NOT_FOUND, never an HTTP error, so the tools turn
  it into one. Activation timing: at t+0 the policy reads ``active true,
  policyCollectionStatus PARTIAL`` and the device ``NOTPOLLING`` with a
  comment ``{"type": "IN_PROGRESS"}``; at t+5 s the device is ``ACTIVE`` and
  the policy ``OK``. Deactivation is immediate (``active false``, device
  list empty). A second INTERFACE policy on PE1 did NOT displace the
  built-in "Default interface health" policy's PE1 row (both stayed ACTIVE,
  no POLLED_BY_ANOTHER_POLICY). Delete needs no deactivation first (an
  ACTIVE policy deleted fine); a deleted / unknown id answers NOT_FOUND.
- ``PUT dataretention`` body ``{"<raw table>": {rawDataRetentionPeriod,
  hourlyDataRetentionPeriod, dailyDataRetentionPeriod,
  weeklyDataRetentionPeriod}}`` where the raw table is EXACTLY a key of
  ``GET dataretention/all`` (``CEPM_INTERFACE``, ``CEPM_SRPOLICY``,
  ``DeviceCpuUtilInfo``, ``OPTPM_OPTICSLANE``, ... — case-sensitive) ->
  ``200 true`` and the change reads back at once; an unknown / miscased key
  -> ``200 false`` and NOTHING changes (so ``false`` means "no such table");
  ``{}`` -> ``200 true``; a non-object or non-integer value -> 400 "JSON parse
  error ..." (a sentence, not a code). Partial bodies (fewer than four
  periods) were NOT sent live — the tool always sends all four. ``POST
  dataretention/reset`` (spec: 200 boolean) was NOT called live: it would
  overwrite every table with the defaults. ``GET dataretention`` -> 500
  "Request method 'GET' is not supported".
- ``PUT dashboards/healthsettings`` takes the NESTED shape of the GET
  (``{"<template>": {"<SCHEMA>_<metric>": {metric, schemaName, policy,
  categories [{level, min, max}], unit, ...}}}``; an unchanged body ->
  200 with an empty body); the flat ``{"<SCHEMA>_<metric>": {...}}`` form and
  a non-object setting -> 400 ``METRIC_HEALTH_INVALID_REQ`` "Invalid
  Request"; ``{}`` -> 200. A CHANGED threshold was not sent live and the
  categories are a range list, so the health-settings write and its
  ``reset`` stay unexposed (``GET dashboards/healthsettings/<token>`` is the
  per-metric read; an unknown token answers ``{}``).

Still NOT exposed: ``PUT dashboards/healthsettings`` (+ ``reset``), TCA
thresholds on a policy (``thresholds`` is sent as ``{}`` on create and kept
as-is on update), the per-schema graph endpoints
(``dashboards/<area>/graph/...``) and ``dashboards/summary/topN``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import time
import uuid as uuid_lib
from datetime import UTC, datetime, timedelta, timezone
from typing import Annotated, Any

import httpx
from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.crosswork import REACHABILITY_STATES
from cnc_mcp.errors import PlatformError, format_error, http_error
from cnc_mcp.formatting import ResponseFormat, epoch_iso, finalize, pagination_envelope, to_json
from cnc_mcp.polling import wait_until
from cnc_mcp.safety import AppContext, register_tool
from cnc_mcp.tools.te_state import (
    end_label,
    fetch_topology_nodes,
    resolve_policy_ends,
    router_id_names,
)
from cnc_mcp.tools.topology import DEFAULT_NETWORK

logger = logging.getLogger(__name__)

PERFORMANCE = "/crosswork/performance/v1"
NPM = "/crosswork/optima-analytics/api/v1"

POLICIES_URL = f"{PERFORMANCE}/policies"
POLICY_DEVICES_URL = f"{POLICIES_URL}/devices"
POLICY_TEMPLATES_URL = f"{POLICIES_URL}/policy-templates"
POLICY_INVENTORY_DEVICES_URL = f"{POLICIES_URL}/inventory-devices"
POLICY_ACTIVATE_URL = f"{POLICIES_URL}/activate"
POLICY_DEACTIVATE_URL = f"{POLICIES_URL}/deactivate"
RETENTION_URL = f"{PERFORMANCE}/dataretention"
RETENTION_ALL_URL = f"{RETENTION_URL}/all"
RETENTION_DEFAULT_URL = f"{RETENTION_URL}/default"
RETENTION_RESET_URL = f"{RETENTION_URL}/reset"
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
# Verified live 2026-09-14: a device whose interface samples had stopped ~6 h earlier (stuck
# ROBOT_OPER_STATE_CHECKING after a re-attach) still listed 'collection ACTIVE, updated
# <re-attach time>' — the flag is scheduler membership, not sample delivery. The proof that
# works is a SHORT statistics window: cnc_get_performance_statistics returns per-object
# window averages with no sample time, so that same device still answered rows for the
# default 24 h (samples existed earlier in the window) and only hours=1 answered "No
# CEPMINTERFACE statistics for last 1 h"; cnc_get_collection_health reported the collector
# job healthy throughout (it is job state, not sample delivery).
COLLECTION_STATUS_CAVEAT = (
    "collection ACTIVE / DEGRADED / NOTPOLLING is the policy's membership flag (its scheduling "
    "state; 'updated' is when that record last changed), not proof that samples are arriving "
    "— verify with cnc_get_performance_statistics(schema=<SCHEMA>, device_uuid=<uuid>, "
    "hours=1): rows in a 1 h window prove samples are arriving; 'No <SCHEMA> statistics' in "
    "that short window while hours=24 still answers rows means collection stalled — narrow "
    "from_time/to_time to date the last sample (the rows are window averages with no sample "
    "time; cnc_get_collection_health reports the collector job's state, not sample delivery)."
)
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
# Policy-write codes (verified live 2026-09-15; POLICY_EXITS is the platform's spelling).
CODE_POLICY_EXISTS = "POLICY_EXITS"
CODE_INVALID_POLICY_TYPE = "INVALID_POLICY_TYPE"
CODE_MISSING_NAME = "MISSING_NAME"
CODE_MISSING_DEVICES = "MISSING_DEVICES"
# OperationResult.status of activate / deactivate / delete (all but DB_ERROR seen live).
OPERATION_OK = "OK"
OPERATION_ALREADY = ("ALREADY_ACTIVATED", "ALREADY_DEACTIVATED")
OPERATION_NOT_FOUND = "NOT_FOUND"
# The comment type a freshly activated policy's device carries while the scheduler is
# still deploying the collection job (verified live: NOTPOLLING + IN_PROGRESS at t+0,
# ACTIVE at t+5 s).
IN_PROGRESS_COMMENT = "IN_PROGRESS"
# Page size of the internal lookups (policies/inventory-devices for a host name,
# policies/devices/<id> for the activation wait): the endpoints' documented default, and
# verified live 2026-09-15 to be accepted (an out-of-range page answers ``{"data": [],
# "total_count": N}``). LOOKUP_MAX_PAGES bounds the walk (10 000 rows).
LOOKUP_PAGE_SIZE = 1000
LOOKUP_MAX_PAGES = 10
# The four retention periods (hours) of one raw table, in the platform's spelling.
RETENTION_FIELDS = (
    "rawDataRetentionPeriod",
    "hourlyDataRetentionPeriod",
    "dailyDataRetentionPeriod",
    "weeklyDataRetentionPeriod",
)
# The MonitoringPolicy fields a PUT policies/<id> body carries (the template part of the
# DTO is read-only and must not be echoed back).
POLICY_BODY_FIELDS = (
    "id",
    "policyTemplate",
    "name",
    "description",
    "schemasInterval",
    "devices",
    "deviceGroups",
    "portGroups",
    "tag",
    "thresholds",
    "active",
)
_POLICY_ID_RE = re.compile(r"^\d+$")
# The longest window the statistics dashboard is asked for in hours: the default weekly
# retention (9072 h); anything older is gone whatever the request says.
MAX_HOURS = 9072

_ISO_TIME_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|z|[+-]\d{2}:?\d{2})$"
)
# A bare epoch is exactly 10 digits (seconds) or 13 (milliseconds): a bare year ('2026'),
# a dashless date ('20260913') or datetime ('202609131200') must NOT be read as an epoch
# near 1970 / 1976 — they fall through to the ISO error instead.
_EPOCH_RE = re.compile(r"^(?:\d{10}|\d{13})$")
# The IOS-XR name of a CFP-rendered SR policy: srte_c_<color>_ep_<tail-end router-id>.
_SR_POLICY_NAME_RE = re.compile(r"^srte_c_(\d+)_ep_(.+)$")
_ERROR_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
# The unit the statistics dashboard reports when it did not resolve one (SRPOLICY rows on
# 7.2, verified live 2026-09-14: the template says BITS_PER_SECOND / PACKETS_PER_SECOND).
# NUMBER is ALSO a genuine template unit (OTUCONTROLLERSINFO uc is a count), so a NUMBER
# row counts as unresolved only where the template catalogue says otherwise.
UNRESOLVED_UNIT = "NUMBER"

NPM_EMPTY_CAVEAT = (
    "NPM never validates its input: an unknown key answers the same empty list as a known "
    "object with no data in the window, so check the key and the time window before "
    "concluding there is no data."
)
# The NPM LSP key parameters use the same names, wording and host-name resolution as the
# sibling TE tools (te_state cnc_get_sr_policy / cnc_get_sr_policy_performance_metrics,
# sr_te_operations) so an agent can chain them without remapping.
_NODE_HELP = (
    "a host name (the topology node id, case-insensitive, e.g. 'PE1') or its TE router-id "
    "(the loopback, e.g. '10.0.0.1')"
)
_HEADEND_DESC = (
    f"Head-end of the LSP: {_NODE_HELP}. A host name is resolved to the router-id through "
    "the topology (one GET, as cnc_get_sr_policy does); a router-id is sent as given — the "
    "NPM key is always the router-id, and cnc_list_sr_policies shows it."
)
_ENDPOINT_DESC = f"Endpoint (tail-end) of the LSP: {_NODE_HELP}; e.g. 'PE2' or '10.0.0.3'."
_NETWORK_DESC = (
    f"Topology network id host names are resolved against (e.g. '{DEFAULT_NETWORK}', the "
    "only network on a standard deployment). Not read when both names are router-ids."
)
_COLOR_DESC = (
    "SR policy color (e.g. 100; cnc_list_sr_policies shows it) — required for an SR policy "
    "(0, the default, is refused: no SR policy has color 0); ignored when tunnel_id is given."
)
_SCHEMA_HELP = "cnc_list_performance_policy_templates lists every schema with its metrics."
# One wording for every from_time / to_time in the module: either form is accepted.
_TIME_FORMS = (
    "ISO-8601 with or without milliseconds, 'Z' or a UTC offset (e.g. "
    "'2026-09-13T00:00:00Z', '2026-09-13T00:00:00.000Z', '2026-09-13T02:00:00+02:00'), or "
    "epoch milliseconds (e.g. '1789257600000') — either form is accepted and normalised"
)
_FROM_DESC = f"Window start — {_TIME_FORMS}."
_TO_DESC = f"Window end — {_TIME_FORMS}."
_HOURS_DESC = (
    "Window: the last N hours back from now (e.g. 24); ignored when from_time and to_time "
    "are given."
)
# The NPM LSP series (cnc_get_lsp_utilization / cnc_get_lsp_delay) default to 6 h — the
# largest window NPM answers with raw ~5-minute samples (verified live 2026-09-14: 6 h ->
# 73 samples, anything longer -> hourly roll-ups) and the window cnc_explain_sr_policy
# uses, so a drill-in from the composite lands on the same series. Deliberate exception
# to the PM family's 24 h default (dashboards/statistics has no such resolution cliff).
LSP_DEFAULT_HOURS = 6
_LSP_HOURS_DESC = (
    f"Window: the last N hours back from now (default {LSP_DEFAULT_HOURS} — the largest window "
    "NPM answers with raw 5-minute samples; longer windows, e.g. 24, answer hourly roll-ups); "
    "ignored when from_time and to_time are given."
)
_FROM_OPTIONAL_DESC = (
    f"Explicit window start — {_TIME_FORMS}; pass with to_time, or neither (then the last "
    "`hours` hours are used)."
)
_TO_OPTIONAL_DESC = f"Explicit window end — {_TIME_FORMS}."
_TOP_N_HELP = (
    "the token is <SCHEMA>_<exact metric name> and top-N covers only the schemas of "
    f"cnc_list_performance_top_n_columns ({', '.join(TOP_N_SCHEMAS)})"
)


# --- pure helpers ------------------------------------------------------------


def utcnow() -> datetime:
    """Current UTC time (a function so tests can pin it)."""
    return datetime.now(tz=UTC)


def parse_iso_time(text: str | None, what: str) -> datetime:
    """The ONE time parser of the PM family -> an aware UTC datetime. Accepts ISO-8601 with
    or without fractional seconds (``2026-09-13T12:00:00Z``, ``2026-09-13T12:00:00.000Z``),
    with ``Z`` or a UTC offset (``2026-09-13T14:00:00+02:00`` -> 12:00 UTC), and an epoch
    in milliseconds (``1789300800000``, 13 digits) or seconds (``1789300800``, 10 digits).
    Any other bare integer — a year (``2026``), a dashless date (``20260913``) or datetime
    (``202609131200``), ``0`` — is refused rather than silently read as an epoch in 1970
    (the window would be sent and answer empty, and the agent would conclude "no data"). A
    timestamp without any zone is refused (it would be ambiguous), as is anything else — a
    PlatformError naming the parameter."""
    value = (text or "").strip()
    if _EPOCH_RE.match(value):
        n = int(value)
        seconds = n / 1000 if len(value) == 13 else float(n)
        try:
            return datetime.fromtimestamp(seconds, tz=UTC)
        except (OverflowError, OSError, ValueError):
            raise PlatformError(f"{what} '{value}' is not a valid epoch time.") from None
    match = _ISO_TIME_RE.match(value)
    if not match:
        raise PlatformError(
            f"{what} must be an ISO-8601 timestamp with a zone — 2026-09-13T12:00:00Z, "
            f"2026-09-13T12:00:00.000Z or 2026-09-13T14:00:00+02:00 — or epoch milliseconds "
            f"(1789300800000); got '{text}'."
        )
    micros = int((match.group(3) or "0")[:6].ljust(6, "0"))
    try:
        base = datetime.strptime(f"{match.group(1)}T{match.group(2)}", "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        raise PlatformError(f"{what} '{value}' is not a real date/time.") from None
    zone = match.group(4)
    if zone in ("Z", "z"):
        return base.replace(microsecond=micros, tzinfo=UTC)
    sign = 1 if zone[0] == "+" else -1
    digits = zone[1:].replace(":", "")
    offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
    if offset >= timedelta(hours=24):
        raise PlatformError(f"{what} '{value}' has an impossible UTC offset.")
    aware = base.replace(microsecond=micros, tzinfo=timezone(sign * offset))
    return aware.astimezone(UTC)


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


def hours_or_window(
    hours: int, from_time: str | None, to_time: str | None
) -> tuple[datetime, datetime, bool]:
    """The window of a tool that takes ``hours`` OR ``from_time`` + ``to_time`` (the
    statistics-dashboard convention): both bounds -> that window (explicit=True); neither
    -> the last ``hours`` hours ending now, whole seconds (explicit=False); one without the
    other is refused before anything is sent."""
    has_from, has_to = bool((from_time or "").strip()), bool((to_time or "").strip())
    if has_from != has_to:
        raise PlatformError(
            "pass both from_time and to_time for an explicit window, or neither (then the "
            "last `hours` hours are used). Nothing was sent."
        )
    if has_from:
        start, end = time_window(from_time, to_time)
        return start, end, True
    end = utcnow().replace(microsecond=0)
    return end - timedelta(hours=hours), end, False


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
    """A TE router-id (an IP address) for an NPM LSP key — the final guard after host-name
    resolution (te_state's resolve_policy_ends turns a host name into its router-id and
    refuses an unknown one, so only a value that is neither reaches here); anything that
    is not an IP
    is refused because NPM would silently answer an empty list for it."""
    value = (text or "").strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise PlatformError(
            f"{what} must be a TE router-id (an IP address such as 10.0.0.1) or a host name "
            f"the topology knows — got '{text}'. cnc_list_sr_policies / cnc_list_topology_nodes "
            "show the router-ids."
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


def is_uuid(text: Any) -> bool:
    try:
        uuid_lib.UUID(str(text).strip())
    except (ValueError, AttributeError, TypeError):
        return False
    return True


def group_list_text(label: str, values: list[str]) -> str:
    """'device groups All Locations' when the platform sent names (deployment history),
    'device group uuids 7913c888-... (names: cnc_get_group_details)' when it sent uuids (the
    policies themselves carry the target group as a raw uuid on 7.2)."""
    if values and all(is_uuid(v) for v in values):
        return f"{label} uuids {', '.join(values)} (names: cnc_get_group_details)"
    return f"{label}s {', '.join(values)}"


def scope_text(view: dict[str, Any]) -> str:
    parts = []
    if view.get("devices"):
        parts.append("devices " + ", ".join(view["devices"]))
    if view.get("device_groups"):
        parts.append(group_list_text("device group", view["device_groups"]))
    if view.get("port_groups"):
        parts.append(group_list_text("port group", view["port_groups"]))
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


def sr_policy_name_parts(name: Any) -> tuple[int, str] | None:
    """``srte_c_100_ep_10.0.0.3`` -> ``(100, "10.0.0.3")`` — the color and tail-end
    router-id an IOS-XR / CFP policy name encodes; None for any other name."""
    match = _SR_POLICY_NAME_RE.match(str(name or "").strip())
    if not match:
        return None
    return int(match.group(1)), match.group(2)


def fill_sr_policy_keys(keys: dict[str, Any]) -> dict[str, Any]:
    """A copy of a statistics row's keys with ``color`` / ``endpoint`` filled from the
    ``srte_c_<color>_ep_<ip>`` name when the platform left them at 0 / "" (every SRPOLICY
    row on 7.2, verified live 2026-09-14); populated values are never overwritten."""
    parts = sr_policy_name_parts(keys.get("name"))
    if parts is None:
        return dict(keys)
    color, endpoint = parts
    out = dict(keys)
    if out.get("color") in (None, "", 0, "0"):
        out["color"] = color
    if out.get("endpoint") in (None, ""):
        out["endpoint"] = endpoint
    return out


def is_sr_policy_interface(keys: dict[str, Any]) -> bool:
    """True for a CEPMINTERFACE row whose ``interfaceName`` is an SR policy's virtual
    interface (``srte_c_<color>_ep_<tail-end>``) — the head-end's policies appear among its
    interfaces (verified live 2026-09-14: 32 CEPMINTERFACE rows, of which 2), so an
    interface tally over-counts ports by their number. CEPMCRC presumably shares the
    interface key set but was not polled on the lab (interval 0), so it is unverified."""
    return sr_policy_name_parts(keys.get("interfaceName")) is not None


def keys_label(keys: dict[str, Any], host_names: dict[str, str] | None = None) -> str:
    """'PE1 GigabitEthernet0/0/0/0' / 'PE1 srte_c_100_ep_10.0.0.3 color=100
    endpoint=10.0.0.3 (PE2)' — hostname, then the interface/object name, then any other
    populated key as key=value (an SRPOLICY row's color / endpoint come from its name when
    the platform sends 0 / ""; a color of 0 is never printed, no SR policy has it; the
    endpoint is followed by its host name when ``host_names`` knows the router-id); the
    device uuid is left to the JSON form."""
    keys = fill_sr_policy_keys(keys)
    parts: list[str] = []
    host = keys.get("hostname")
    if host not in (None, ""):
        parts.append(str(host))
    for key in ("interfaceName", "name"):
        value = keys.get(key)
        if value not in (None, ""):
            parts.append(str(value))
    # color then endpoint in a fixed order (the platform's key order varies), then the rest.
    ordered = ["color", "endpoint"] + [k for k in keys if k not in ("color", "endpoint")]
    for key in ordered:
        value = keys.get(key)
        if key in ("hostname", "interfaceName", "name", "device", "endpoint_host_name"):
            continue
        if value in (None, ""):
            continue
        if key == "color" and value in (0, "0"):
            continue
        text = f"{key}={value}"
        if key == "endpoint":
            name = (host_names or {}).get(str(value)) or keys.get("endpoint_host_name")
            if name:
                text += f" ({name})"
        parts.append(text)
    return " ".join(parts) or "?"


def unit_unresolved(value: Any, template_unit: str | None) -> bool:
    """True when a ``{unit, value}`` statistics metric reports NUMBER while the template
    catalogue says otherwise — the platform did not resolve the unit (SRPOLICY rows,
    verified live 2026-09-14). NUMBER with a NUMBER template (OTUCONTROLLERSINFO uc, a
    count) or with no template unit at all is NOT unresolved."""
    return (
        isinstance(value, dict)
        and value.get("unit") == UNRESOLVED_UNIT
        and bool(template_unit)
        and template_unit != UNRESOLVED_UNIT
    )


def metric_text(value: Any, template_unit: str | None = None) -> str:
    """A statistics metric value: a plain number, or ``{unit, value}`` with units=true —
    '12.5 KBITS_PER_SECOND'; an unresolved unit (NUMBER where the template says otherwise,
    see unit_unresolved) is annotated with the template catalogue's unit: '0 NUMBER
    (template unit BITS_PER_SECOND)'. A genuine NUMBER (template NUMBER) prints as
    '5 NUMBER'."""
    if isinstance(value, dict):
        unit = value.get("unit")
        text = num_text(value.get("value"))
        if not unit:
            return text
        if unit_unresolved(value, template_unit):
            return f"{text} {unit} (template unit {template_unit})"
        return f"{text} {unit}"
    return num_text(value)


def metric_number(value: Any) -> float | None:
    """The numeric value of a statistics metric (bare, or ``{unit, value}``); None when it
    is not a number."""
    raw = value.get("value") if isinstance(value, dict) else value
    if isinstance(raw, bool) or not isinstance(raw, int | float):
        return None
    return float(raw)


def entry_is_all_zero(entry: dict[str, Any]) -> bool:
    """True when every metric of a statistics row is 0 (or the row has no numeric metric) —
    the rows ``only_nonzero`` drops."""
    numbers = [metric_number(v) for v in _dict(entry.get("metrics")).values()]
    return all(n is None or n == 0 for n in numbers)


def statistics_entry(
    entry: dict[str, Any], host_names: dict[str, str] | None = None
) -> dict[str, Any]:
    """A statistics row as returned, with its keys passed through fill_sr_policy_keys and,
    when ``host_names`` knows the (filled) endpoint router-id, an ``endpoint_host_name``
    key added ("PE2")."""
    keys = fill_sr_policy_keys(_dict(entry.get("keys")))
    name = (host_names or {}).get(str(keys.get("endpoint") or ""))
    if name:
        keys["endpoint_host_name"] = name
    return {**entry, "keys": keys}


def statistics_line(entry: dict[str, Any], template_units: dict[str, str] | None = None) -> str:
    metrics = _dict(entry.get("metrics"))
    units = template_units or {}
    values = (
        ", ".join(f"{m}={metric_text(v, units.get(str(m)))}" for m, v in metrics.items())
        or "(no metrics)"
    )
    return f"- {keys_label(_dict(entry.get('keys')))}: {values}"


def entry_has_unresolved_unit(entry: dict[str, Any], template_units: dict[str, str]) -> bool:
    """True when statistics_line annotated at least one metric of this row with
    "(template unit ...)" — drives the footer explaining the annotation."""
    return any(
        unit_unresolved(v, template_units.get(str(m)))
        for m, v in _dict(entry.get("metrics")).items()
    )


def template_units_of(templates: Any, schema: str) -> dict[str, str]:
    """``{metric: unitType}`` of one schema from the ``policies/policy-templates`` answer
    (searched across every template); {} when the schema is not there."""
    for template in _dict(templates).values():
        fields = _dict(_dict(_dict(template).get("schemasFieldMetadata")).get(schema))
        if fields:
            return {
                str(metric): str(_dict(meta).get("unitType"))
                for metric, meta in fields.items()
                if _dict(meta).get("unitType")
            }
    return {}


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
    check_sr_color(color, tunnel_id)
    head = router_id(headend, "headend")
    tail = router_id(endpoint, "endpoint")
    tunnel = (tunnel_id or "").strip()
    key: dict[str, str] = {"lspType": "RSVP" if tunnel else "SR", "peerAddress": head}
    key["destAddress"] = tail
    if tunnel:
        key["tunnelId"] = tunnel
    else:
        key["color"] = str(color)
    key["from"] = npm_time(start)
    key["to"] = npm_time(end)
    return key


def check_sr_color(color: int, tunnel_id: str | None) -> None:
    """Refuse color 0 for an SR key (no tunnel_id) — checked before any host name is
    resolved, so the refusal costs no request at all."""
    if (tunnel_id or "").strip():
        return
    if color < 1:
        raise PlatformError(
            "color is required for an SR policy (no SR policy has color 0, and NPM would "
            "silently answer an empty list for it): pass the policy's color — "
            "cnc_list_sr_policies shows it — or tunnel_id for an RSVP-TE tunnel. Nothing "
            "was sent."
        )


def lsp_label(
    key: dict[str, str],
    headend: str = "",
    endpoint: str = "",
    names: dict[str, str] | None = None,
) -> str:
    """'SR LSP 10.0.0.1 -> 10.0.0.3 color 100' / 'RSVP LSP 10.0.0.1 -> 10.0.0.3 tunnel 11';
    each end through te_state's ``end_label`` exactly as cnc_get_sr_policy prints it: the
    topology's node id when the ``names`` map (router-id -> node-id, from
    ``resolve_policy_ends``) knows the router-id ('SR LSP PE1 (10.0.0.1) -> PE2 (10.0.0.3)
    color 100', whatever spelling the caller gave), else the name the caller gave next to
    its router-id, and a name that IS the router-id (or no name) printed once."""
    kind = key.get("lspType")
    tail = f"tunnel {key['tunnelId']}" if kind == "RSVP" else f"color {key.get('color')}"
    head_id, end_id = str(key.get("peerAddress")), str(key.get("destAddress"))
    head = end_label(headend.strip() or head_id, head_id, names)
    end = end_label(endpoint.strip() or end_id, end_id, names)
    return f"{kind} LSP {head} -> {end} {tail}"


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


def _sample_epoch(sample: dict[str, Any]) -> float | None:
    """The ``tst`` of an NPM sample as epoch seconds; None when absent or unparseable."""
    try:
        return parse_iso_time(str(sample.get("tst") or ""), "tst").timestamp()
    except PlatformError:
        return None


def sample_spacing(samples: list[dict[str, Any]]) -> dict[str, Any]:
    """The observed spacing of an NPM series: ``{"spacing_seconds": <the most common gap
    between consecutive samples>, "gap_min_seconds", "gap_max_seconds"}`` (all None with
    fewer than two timestamped samples). NPM rolls up with the window (verified live
    2026-09-14): a window of at most 6 h answers ~5-minute samples (300 s, with the odd
    shorter gap around a collection restart), a longer one hourly samples (3600 s) — so a
    24 h answer has hourly, not 5-minute, resolution."""
    stamps = [t for t in (_sample_epoch(s) for s in samples) if t is not None]
    gaps = [int(round(b - a)) for a, b in zip(stamps, stamps[1:], strict=False) if b > a]
    if not gaps:
        return {"spacing_seconds": None, "gap_min_seconds": None, "gap_max_seconds": None}
    counts: dict[int, int] = {}
    for gap in gaps:
        counts[gap] = counts.get(gap, 0) + 1
    modal = max(counts, key=lambda g: (counts[g], g))
    return {"spacing_seconds": modal, "gap_min_seconds": min(gaps), "gap_max_seconds": max(gaps)}


def spacing_text(spacing: dict[str, Any]) -> str:
    """'60-minute spacing' / '~5-minute spacing, gaps 93 s to 300 s' / '90-second spacing';
    '' when the spacing is unknown."""
    seconds = spacing.get("spacing_seconds")
    if not isinstance(seconds, int) or seconds <= 0:
        return ""
    unit = f"{seconds // 60}-minute" if seconds % 60 == 0 else f"{seconds}-second"
    low, high = spacing.get("gap_min_seconds"), spacing.get("gap_max_seconds")
    if low == high:
        return f"{unit} spacing"
    return f"~{unit} spacing, gaps {low} s to {high} s"


def series_stats(samples: list[dict[str, Any]], field: str) -> dict[str, Any]:
    """count / first_at / last_at / spacing_seconds / gap_min_seconds / gap_max_seconds /
    average / minimum / maximum / last of a numeric field."""
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
        **sample_spacing(samples),
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
    """'18 sample(s) (2026-... to 2026-...; 60-minute spacing): util avg 0, min 0, max 0,
    last 0' — the observed spacing says which resolution the window got (5-minute up to
    6 h, hourly beyond)."""
    text = f"{stats['count']} sample(s)"
    spacing = spacing_text(stats)
    if stats.get("first_at"):
        text += f" ({stats['first_at']} to {stats['last_at']}" + (
            f"; {spacing})" if spacing else ")"
        )
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
    """'## Delay (73 sample(s); ~5-minute spacing, gaps 93 s to 300 s)' and one sample_line
    per sample."""
    spacing = spacing_text(sample_spacing(samples))
    head = f"{len(samples)} sample(s)" + (f"; {spacing}" if spacing else "")
    lines = ["", f"## {title} ({head})"]
    lines.extend(sample_line(s) for s in samples)
    if not samples:
        lines.append("(no samples)")
    return lines


# --- policy and retention writes (pure helpers) ------------------------------


def parse_policy_ids(text: str | None) -> list[int]:
    """'3' / '3, 5' -> [3, 5] (order kept, duplicates dropped) — the comma list the
    activate / deactivate / delete path segment takes (verified live: ``activate/3,999999``).
    Anything that is not a positive integer is refused before sending (the platform would
    answer 500 "Failed to convert ... to required type 'java.util.List'")."""
    ids: list[int] = []
    for token in (text or "").split(","):
        value = token.strip()
        if not value:
            continue
        if not _POLICY_ID_RE.match(value) or int(value) < 1:
            raise PlatformError(
                f"policy_ids must be one or more positive integer policy ids separated by "
                f"commas (e.g. '3' or '3,5'), got '{text}'. cnc_list_performance_policies "
                "shows the ids. Nothing was sent."
            )
        if int(value) not in ids:
            ids.append(int(value))
    if not ids:
        raise PlatformError(
            "policy_ids is required (e.g. '3' or '3,5'); cnc_list_performance_policies shows "
            "the ids. Nothing was sent."
        )
    return ids


def find_template(templates: Any, name: str | None) -> tuple[str, dict[str, Any]]:
    """The ``(canonical key, template object)`` of ``GET policies/policy-templates`` whose
    key matches ``name`` case-insensitively ('interface' -> 'INTERFACE', 'devicehealth' ->
    'deviceHealth'); an unknown name is refused naming every template."""
    wanted = (name or "").strip()
    catalogue = _dict(templates)
    for key, template in catalogue.items():
        if str(key).lower() == wanted.lower() and wanted:
            return str(key), _dict(template)
    raise PlatformError(
        f"unknown policy template '{name}'. Templates on this platform: "
        f"{', '.join(str(k) for k in catalogue) or '(none)'} — "
        "cnc_list_performance_policy_templates shows their schemas and cadences. Nothing "
        "was sent."
    )


def parse_schemas_interval(
    text: str | None, template_key: str, template: dict[str, Any]
) -> dict[str, int]:
    """``schemas_interval`` -> the ``{SCHEMA: seconds}`` map a policy body carries, validated
    against the template (the platform does not validate the cadence — 123 s was accepted
    live — nor fills missing schemas): 'CEPMINTERFACE=3600,CEPMCRC=0' (also ':' as the
    separator) names schemas explicitly, a bare integer ('300') applies to EVERY schema of
    the template, and every template schema not named is set to 0 (not polled). A schema
    the template does not have, or a cadence outside the schema's ``pollingIntervals``,
    is refused naming the allowed values."""
    intervals = _dict(template.get("schemasInterval"))
    if not intervals:
        raise PlatformError(
            f"template {template_key} lists no schemas; cnc_list_performance_policy_templates "
            "shows the catalogue. Nothing was sent."
        )
    value = (text or "").strip()
    if not value:
        raise PlatformError(
            "schemas_interval is required: 'SCHEMA=seconds,...' (e.g. 'CEPMINTERFACE=3600') "
            f"or one cadence for every schema (e.g. '300'). Schemas of {template_key}: "
            f"{', '.join(intervals)}. Nothing was sent."
        )
    by_lower = {str(k).lower(): str(k) for k in intervals}
    result: dict[str, int] = {}
    if _POLICY_ID_RE.match(value):
        pairs = [(schema, value) for schema in intervals]
    else:
        pairs = []
        for token in value.split(","):
            token = token.strip()
            if not token:
                continue
            schema, sep, seconds = token.replace(":", "=").partition("=")
            if not sep or not schema.strip() or not seconds.strip():
                raise PlatformError(
                    f"schemas_interval token '{token}' is not SCHEMA=seconds (e.g. "
                    "'CEPMINTERFACE=3600'). Nothing was sent."
                )
            pairs.append((schema.strip(), seconds.strip()))
    for schema, seconds in pairs:
        canonical = by_lower.get(schema.lower())
        if canonical is None:
            raise PlatformError(
                f"schema '{schema}' is not part of template {template_key} (its schemas: "
                f"{', '.join(intervals)}). Nothing was sent."
            )
        allowed = _dict(intervals.get(canonical)).get("pollingIntervals")
        allowed_list = [int(a) for a in allowed] if isinstance(allowed, list) else []
        if not _POLICY_ID_RE.match(seconds):
            raise PlatformError(
                f"cadence '{seconds}' for {canonical} is not a whole number of seconds; "
                f"allowed: {'/'.join(str(a) for a in allowed_list) or 'per template'}. "
                "Nothing was sent."
            )
        cadence = int(seconds)
        if allowed_list and cadence not in allowed_list:
            raise PlatformError(
                f"cadence {cadence} s is not allowed for {canonical}: the template permits "
                f"{'/'.join(str(a) for a in allowed_list)} s (0 = not polled). The platform "
                "would accept it silently and poll at an unsupported interval. Nothing was sent."
            )
        result[canonical] = cadence
    for schema in intervals:
        result.setdefault(str(schema), 0)
    return result


def parse_uuid_list(text: str | None, what: str, hint: str) -> list[str]:
    """A comma list of uuids (canonical lower-case; duplicates dropped); anything else is
    refused — the platform accepts any string as a group uuid and then polls nothing."""
    out: list[str] = []
    for token in (text or "").split(","):
        value = token.strip()
        if not value:
            continue
        try:
            canonical = str(uuid_lib.UUID(value.lower()))
        except ValueError:
            raise PlatformError(
                f"{what} must be comma-separated uuids, got '{value}' — {hint}. The platform "
                "would accept it silently and the policy would poll nothing. Nothing was sent."
            ) from None
        if canonical not in out:
            out.append(canonical)
    return out


def operation_results(data: Any) -> list[dict[str, Any]]:
    """The OperationResult list of activate / deactivate / delete as ``[{"policy_id",
    "status", "policy_name", "error_message"}]`` (a single object is wrapped)."""
    rows = data if isinstance(data, list) else [data]
    return [
        {
            "policy_id": r.get("policyId"),
            "status": r.get("status"),
            "policy_name": r.get("policyName") or None,
            "error_message": r.get("errorMessage") or None,
        }
        for r in rows
        if isinstance(r, dict)
    ]


def check_operation_results(
    results: list[dict[str, Any]], ids: list[int], verb: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split the results into ``(done, already)`` — status OK, and ALREADY_ACTIVATED /
    ALREADY_DEACTIVATED (a no-op the tools report as success) — and raise for a NOT_FOUND
    (the platform answers it as a 200), a DB_ERROR / unknown status, or an id the answer
    does not mention at all."""
    by_id = {r.get("policy_id"): r for r in results}
    done: list[dict[str, Any]] = []
    already: list[dict[str, Any]] = []
    problems: list[str] = []
    for policy_id in ids:
        result = by_id.get(policy_id)
        if result is None:
            problems.append(f"policy {policy_id}: no result in the platform's answer")
            continue
        status = str(result.get("status") or "")
        if status == OPERATION_OK:
            done.append(result)
        elif status in OPERATION_ALREADY:
            already.append(result)
        elif status == OPERATION_NOT_FOUND:
            problems.append(f"no performance policy {policy_id} (NOT_FOUND)")
        else:
            message = result.get("error_message")
            problems.append(
                f"policy {policy_id}: {status or 'no status'}"
                + (f" — {message}" if message else "")
            )
    if problems:
        state = f"{len(done)} {verb}, {len(already)} already so" if (done or already) else "none"
        raise PlatformError(
            f"{'; '.join(problems)}. Applied to the others: {state}. "
            "cnc_list_performance_policies shows the ids."
        )
    return done, already


def policy_body(policy: dict[str, Any]) -> dict[str, Any]:
    """The MonitoringPolicy fields of a GET answer as the full body ``PUT policies/<id>``
    needs (the platform rejects a partial body with MISSING_POLICY_ID and reads a missing
    ``active`` as false — verified live); ``thresholds`` defaults to {} and ``active`` to
    False when absent."""
    body = {field: policy.get(field) for field in POLICY_BODY_FIELDS}
    for field in ("description", "devices", "deviceGroups", "portGroups", "tag"):
        if body[field] is None:
            body[field] = ""
    if not isinstance(body["thresholds"], dict):
        body["thresholds"] = {}
    if not isinstance(body["schemasInterval"], dict):
        body["schemasInterval"] = {}
    body["active"] = bool(body["active"])
    return body


def policy_write_hints(name: str = "", template: str = "") -> dict[str, str | tuple[str, str]]:
    """The Spring codes a policy create / update can answer (verified live)."""
    return {
        CODE_POLICY_EXISTS: (
            f"a performance policy named '{name}' already exists",
            "cnc_list_performance_policies shows it — pick another name, or change that "
            "policy with cnc_update_performance_policy.",
        ),
        CODE_INVALID_POLICY_TYPE: (
            f"unknown policy template '{template}'",
            "cnc_list_performance_policy_templates lists the templates.",
        ),
        CODE_MISSING_NAME: ("the policy name is mandatory", "Pass a non-blank name."),
        CODE_MISSING_DEVICES: (
            "the policy needs a selection",
            "Pass devices (inventory uuids or host names), device_groups or port_groups.",
        ),
        CODE_INVALID_SCHEMA: (
            "a schema in schemas_interval is not part of the template",
            "cnc_list_performance_policy_templates shows each template's schemas.",
        ),
        CODE_MISSING_POLICY_ID: (
            "no such performance policy (or the body's id did not match)",
            "cnc_list_performance_policies shows the ids.",
        ),
    }


def paged_total(data: dict[str, Any]) -> int | None:
    """``total_count`` of a ``{"data": [...], "total_count": N}`` page as an int, None when
    absent (the plain policies/devices page has been seen without it)."""
    total = data.get("total_count")
    return total if isinstance(total, int) and not isinstance(total, bool) else None


def same_selection(a: str | None, b: str | None) -> bool:
    """True when two comma-joined selection strings name the same set (order and case
    of the uuids / names ignored, blanks dropped)."""

    def tokens(text: str | None) -> set[str]:
        return {t.strip().lower() for t in (text or "").split(",") if t.strip()}

    return tokens(a) == tokens(b)


def policy_devices_settled(rows: list[dict[str, Any]]) -> bool:
    """True once no device of a freshly activated policy is still IN_PROGRESS (the
    scheduler has decided ACTIVE / DEGRADED / NOTPOLLING-with-a-reason for every row)."""
    for row in rows:
        for comment in _list_of_dicts(row.get("comments")):
            if str(comment.get("type") or "").upper() == IN_PROGRESS_COMMENT:
                return False
    return True


def devices_status_text(rows: list[dict[str, Any]]) -> str:
    """'PE1 ACTIVE, PE2 NOTPOLLING [POLLED_BY_ANOTHER_POLICY Default interface health]' — or
    '(no devices listed)'."""
    parts = []
    for row in rows:
        notes = "; ".join(
            f"{c.get('type') or '?'} {c.get('argument') or ''}".strip()
            for c in _list_of_dicts(row.get("comments"))
        )
        parts.append(
            f"{row.get('hostName') or row.get('uuid') or '?'} {row.get('collectionStatus') or '?'}"
            + (f" [{notes}]" if notes else "")
        )
    return ", ".join(parts) or "(no devices listed)"


def find_retention_table(all_data: Any, table: str | None) -> tuple[str, dict[str, Any]]:
    """The ``(raw table key, entry)`` of ``GET dataretention/all`` that ``table`` names —
    by key (``CEPM_INTERFACE``, ``DeviceCpuUtilInfo``; case-insensitive, the canonical
    spelling is what the PUT needs: a miscased key answers ``false`` and changes nothing)
    or by ``schemaName`` (``CEPMINTERFACE``, ``CPU``); unknown -> refused naming every table."""
    wanted = (table or "").strip().lower()
    entries = _dict(all_data)
    if wanted:
        for key, entry in entries.items():
            if str(key).lower() == wanted:
                return str(key), _dict(entry)
        for key, entry in entries.items():
            if str(_dict(entry).get("schemaName") or "").lower() == wanted:
                return str(key), _dict(entry)
    raise PlatformError(
        f"unknown retention table '{table}'. Tables (raw table key = schema): "
        + ", ".join(f"{k} = {_dict(v).get('schemaName') or '?'}" for k, v in entries.items())
        + ". Nothing was sent."
    )


def retention_body(entry: dict[str, Any], changes: dict[str, int | None]) -> dict[str, int]:
    """The four periods of one table: the current values with the given ``changes``
    (``{"rawDataRetentionPeriod": 48, ...}``, None = keep) applied — always all four, the
    platform's behaviour on a partial body being unverified."""
    body: dict[str, int] = {}
    for field in RETENTION_FIELDS:
        new = changes.get(field)
        current = entry.get(field)
        value = new if new is not None else current
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise PlatformError(
                f"the platform reports no {field} for this table and none was given; pass "
                "all four periods."
            )
        body[field] = int(value)
    return body


def retention_periods_text(values: dict[str, Any]) -> str:
    return (
        f"raw {num_text(values.get('rawDataRetentionPeriod'))} h, hourly "
        f"{num_text(values.get('hourlyDataRetentionPeriod'))} h, daily "
        f"{num_text(values.get('dailyDataRetentionPeriod'))} h, weekly "
        f"{num_text(values.get('weeklyDataRetentionPeriod'))} h"
    )


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
        interval of 0 means the schema is not polled. The target
        ``deviceGroups`` / ``portGroups`` are RAW GROUP UUIDS on 7.2 (verified
        live: the built-in policies target one device-group uuid, which is
        the "All Locations" location group) — the tool labels them "device
        group uuids ... (names: cnc_get_group_details)"; resolve a uuid with
        cnc_get_group_details(group_uuid=...), or read the group NAME the
        policy was activated with from cnc_get_performance_policy_history
        (its deployment-history entries carry "All Locations"). Use this
        first to learn the policy ids for cnc_get_performance_policy /
        cnc_list_performance_policy_devices and to see which schemas produce
        data at all (a schema no active policy polls answers empty
        statistics). Create / change / activate / deactivate / delete a
        policy with cnc_create_performance_policy,
        cnc_update_performance_policy, cnc_activate_performance_policy,
        cnc_deactivate_performance_policy, cnc_delete_performance_policy
        (write tools; ids are integers, never reused).

        Returns:
            str: Markdown "# N performance monitoring policies" and one
            "- **name** (id, template): active|inactive, collection OK;
            <schema> every N s, ...; device group uuids <uuid> (names:
            cnc_get_group_details); changed <ISO>" line per policy, or JSON
            {"count": int, "policies": [{"id", "name", "description",
            "template", "active", "collection_status", "schemas_interval":
            {schema: seconds}, "devices": [str], "device_groups": [uuid str],
            "port_groups": [uuid str], "tag", "thresholds", "created_at",
            "last_changed_at"}]}. "No performance monitoring policies." when
            the list is empty; "Error: ..." on an API failure.
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
                "\nDetails and the template's metrics: cnc_get_performance_policy(policy_id). "
                "Group uuids: cnc_get_group_details(group_uuid) names one; "
                "cnc_get_performance_policy_history(policy_id) shows the group name the "
                "policy was activated with."
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

        ``collectionStatus`` is the policy's MEMBERSHIP flag — whether the
        scheduler has the device in this policy's active / degraded /
        not-polling set — and ``lastUpdateTime`` is when that membership
        record last changed (a re-attach, a policy edit), NOT the newest
        sample. It is not refreshed when a collector stops delivering: a
        device whose interface samples stopped hours ago (seen live
        2026-09-14 on a device stuck ROBOT_OPER_STATE_CHECKING after a
        re-attach) still reads ``collection ACTIVE``. Treat ACTIVE as "meant
        to be polled" and prove data with a SHORT statistics window:
        cnc_get_performance_statistics(schema=<SCHEMA>, device_uuid=<uuid>,
        hours=1) — rows in a 1 h window prove samples are arriving; "No
        <SCHEMA> statistics" in that short window while ``hours=24`` still
        answers rows means collection stalled, so narrow from_time/to_time
        to date the last sample. The statistics rows are window averages
        with no sample time, which is why a long window hides a stall (that
        same device still answered rows for 24 h), and
        cnc_get_collection_health reports the collector job's state, not
        sample delivery (it read healthy while those samples were 6 h
        stale). The markdown ends with that caveat.

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
            updated <ISO> [notes]" line per device, the membership-flag caveat
            line, plus a "(more ...)" note
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
            lines.extend(["", COLLECTION_STATUS_CAVEAT])
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
        ...). The display name column IS the raw table key
        cnc_update_performance_retention takes (``CEPM_INTERFACE``,
        ``DeviceCpuUtilInfo``, ...; the schema name works too);
        cnc_reset_performance_retention puts every table back to the default.

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
        thresholds (``PUT dashboards/healthsettings``, which takes this same
        nested shape — verified with an unchanged body) is not exposed.

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
        hours: Annotated[int, Field(description=_HOURS_DESC, ge=1, le=MAX_HOURS)] = 24,
        from_time: Annotated[str, Field(description=_FROM_OPTIONAL_DESC, max_length=40)] = "",
        to_time: Annotated[str, Field(description=_TO_OPTIONAL_DESC, max_length=40)] = "",
        with_units: Annotated[
            bool,
            Field(
                description="true to return each value as {unit, value} instead of a bare number."
            ),
        ] = False,
        only_nonzero: Annotated[
            bool,
            Field(
                description=(
                    "true to drop the rows whose every returned metric is 0 on the fetched page "
                    "— e.g. with metrics='ifInErrorsRate,ifOutErrorsRate,ifInDiscardsRate,"
                    "ifOutDiscardsRate' and a large page_size: 'which interfaces had any "
                    "errors or discards?' in one call."
                )
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
        schema=<SCHEMA>&timeInterval=<hours>`` or ``&from=&to=`` (sent as ISO
        ``YYYY-MM-DDTHH:mm:ss.SSSZ``; neither answers 400 MISSING_TIME_DETAILS)
        ``[&metrics=a,b][&device=<uuid>]&units=true|false&pageSize=&page=``
        (verified; ``page`` 1-based) -> ``{"schema", "page", "records" (rows on
        this page), "entries": [{"keys": {hostname, interfaceName | name +
        color + endpoint (SRPOLICY) | cpuName | ..., device (uuid)},
        "metrics": {<metric>: <average> | {unit, value}}}]}``. Past the last
        page: ``records 0, entries []``. Values are the window's averages per
        object (a brief spike shows as a small non-zero average). A schema no
        active policy polls answers empty (CPU / MEMORY / DVAVAILABILITY on a
        fresh install: no deviceHealth policy); an unknown schema answers 400
        INVALID_SCHEMA. Schemas and metric names:
        cnc_list_performance_policy_templates (INTERFACE -> CEPMINTERFACE /
        CEPMCRC, SRPOLICY, deviceHealth -> CPU / MEMORY / DVAVAILABILITY /
        ENVTEMP, ...). For a ranked list use cnc_get_performance_top_n; for a
        time series of one metric across the network use
        cnc_get_performance_summary.

        SRPOLICY rows (verified live 2026-09-14): the platform sends ``color
        0`` and ``endpoint ""`` in every row and only the ``name``
        (``srte_c_100_ep_10.0.0.3`` = color 100, endpoint 10.0.0.3) carries
        them, so the tool fills color / endpoint from the name in both output
        forms and never prints "color=0". The endpoint router-id is then
        named, best effort, from one topology ``networks`` GET (the same
        node list cnc_get_sr_policy resolves host names in, Default-network):
        "endpoint=10.0.0.3 (PE2)" in markdown and ``keys.endpoint_host_name``
        in JSON — omitted, never an error, when the topology cannot be read
        or does not know the router-id. With with_units=true the same rows
        report ``unit "NUMBER"`` (the platform did not resolve the unit; the
        template catalogue says outBitRate BITS_PER_SECOND, outPktsRate
        PACKETS_PER_SECOND, and CEPMINTERFACE rows do carry BITS_PER_SECOND /
        PERCENTAGE / PACKETS_PER_SECOND). NUMBER is also a genuine template
        unit (OTUCONTROLLERSINFO uc is a count; 27 other metrics have no
        unitType at all), so a NUMBER row is unresolved only where the
        template says otherwise: those metrics are annotated "(template unit
        ...)" from one extra ``GET policies/policy-templates`` (issued
        whenever a row reports NUMBER) and the JSON carries the schema's
        template units as ``template_units``; a NUMBER row whose template
        unit is NUMBER (or unknown) prints plainly, with no footer.

        CEPMINTERFACE rows (verified live 2026-09-14) include the head-end's
        SR-policy virtual interfaces as ordinary interfaces — ``interfaceName``
        ``srte_c_<color>_ep_<tail-end>``, one per policy the node hosts
        (32 CEPMINTERFACE rows on the lab, of which 2 are ``srte_c_*``; their
        counters were 0 while SRPOLICY reported the same policies). CEPMCRC
        presumably shares the interface key set but was not polled on the lab
        (the default interface policy sets its interval to 0), so its rows are
        unverified. An interface tally therefore over-counts physical /
        logical ports by the number of SR policies: the header says "(R
        rows, of which N are srte_c_* SR-policy interfaces)" and the JSON
        carries ``sr_policy_interface_rows`` — subtract them, or read the
        policies' traffic from schema SRPOLICY instead.

        Time window: ``hours`` (default 24, sent as ``timeInterval``) or both
        ``from_time`` and ``to_time`` — ISO-8601 with or without milliseconds,
        'Z' or a UTC offset, or epoch milliseconds; either form is accepted
        and normalised. Retention: cnc_get_performance_retention (raw 24 h,
        then hourly / daily / weekly roll-ups by default).

        Args:
            schema: the schema name (upper-cased before sending).
            metrics: optional comma list of metric names.
            device_uuid: optional inventory uuid filter.
            hours: window length when from_time / to_time are not given.
            from_time / to_time: explicit window (both or neither; either
                time form accepted).
            with_units: wrap every value as {unit, value}.
            only_nonzero: drop the all-zero rows of the fetched page
                (client-side; ``records`` still counts the platform's rows,
                so paging is unaffected).
            page_size / page: 1-based paging.
            response_format: markdown or json.

        Returns:
            str: Markdown "# <SCHEMA> statistics — last N h | <from> to <to>,
            page P (R rows[, of which N are srte_c_* SR-policy interfaces][, N
            shown after dropping all-zero rows])" and one "- <hostname>
            <interface|name color=C endpoint=E[ (host)]>: metric=value[ UNIT[
            (template unit U)]], ..." line per row, a "(unit NUMBER where the
            template says otherwise = ...)" footer only when a row was
            annotated, plus a "(more ...)" note when the page is full; or
            JSON {"schema", "window": {"hours" | "from", "to"}, "metrics",
            "device", "only_nonzero", "page", "page_size", "records"
            (platform rows on the page), "count" (rows returned),
            "sr_policy_interface_rows" (srte_c_* rows on the page), "has_more",
            "next_page", "template_units": {metric: unit} (the schema's
            template units, looked up only when a row reports NUMBER) | null,
            "entries": [...] (as the platform returns them, except that
            SRPOLICY color / endpoint are filled from the name when the
            platform left them 0 / "" and ``keys.endpoint_host_name`` is added
            when the topology names the endpoint)}. "No <SCHEMA> statistics
            ..." (non-error) when records is 0, and "All R rows of ... are
            zero ..." (non-error) when only_nonzero drops every row — it ends
            with whether this page was the whole collection ("R rows <
            page_size P: this page is the whole collection") or the paging
            hint, so no confirmation call is needed; "Error: unknown
            performance schema '<x>' (INVALID_SCHEMA). ..." listing the known
            schemas; "Error: from_time must be ..." (nothing sent) for a bad
            time; "Error: ..." on an API failure.
        """
        try:
            schema_name = parse_schema(schema)
            params: dict[str, Any] = {"schema": schema_name}
            window: dict[str, Any]
            start, end, explicit = hours_or_window(hours, from_time, to_time)
            if explicit:
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
            raw_entries = _list_of_dicts(data.get("entries"))
            host_names: dict[str, str] | None = None
            if schema_name == "SRPOLICY" and raw_entries:
                # Best effort: naming the endpoint must never sink the statistics themselves.
                try:
                    host_names = router_id_names(
                        await fetch_topology_nodes(client, DEFAULT_NETWORK)
                    )
                except Exception as lookup_error:
                    logger.warning(
                        "topology lookup for SRPOLICY endpoint names failed: %s", lookup_error
                    )
            entries = [statistics_entry(e, host_names) for e in raw_entries]
            records = data.get("records")
            records = (
                records
                if isinstance(records, int) and not isinstance(records, bool)
                else len(entries)
            )
            has_more = records >= page_size and records > 0
            policy_rows = sum(1 for e in entries if is_sr_policy_interface(_dict(e.get("keys"))))
            shown = [e for e in entries if not entry_is_all_zero(e)] if only_nonzero else entries
            template_units: dict[str, str] | None = None
            if with_units and any(
                _dict(v).get("unit") == UNRESOLVED_UNIT
                for e in shown
                for v in _dict(e.get("metrics")).values()
            ):
                # Best effort: the annotation must never sink the statistics themselves.
                try:
                    template_units = template_units_of(
                        await perf_get(POLICY_TEMPLATES_URL), schema_name
                    )
                except Exception as lookup_error:
                    logger.warning(
                        "policy-templates lookup for %s units failed: %s", schema_name, lookup_error
                    )
                    template_units = None
            window_text = (
                f"last {hours} h" if "hours" in window else f"{window['from']} to {window['to']}"
            )
            if response_format is ResponseFormat.JSON:
                payload = {
                    "schema": data.get("schema") or schema_name,
                    "window": window,
                    "metrics": metric_names,
                    "device": device_uuid.strip() or None,
                    "only_nonzero": only_nonzero,
                    "page": data.get("page") if data.get("page") is not None else page,
                    "page_size": page_size,
                    "records": records,
                    "count": len(shown),
                    "sr_policy_interface_rows": policy_rows,
                    "has_more": has_more,
                    "next_page": page + 1 if has_more else None,
                    "template_units": template_units,
                    "entries": shown,
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
            more = f"\n(page full: more may exist, call again with page={page + 1})"
            if not shown:
                # Say whether the page was the whole collection, so no confirmation call is
                # needed: a short page is the last one (has_more is inferred from a full page).
                if has_more:
                    whole = more
                elif page == 1:
                    whole = (
                        f" {records} rows < page_size {page_size}: this page is the whole "
                        "collection, so no object had a non-zero value in the window."
                    )
                else:
                    whole = (
                        f" {records} rows < page_size {page_size}: this is the last page (earlier "
                        "pages were not re-checked)."
                    )
                return finalize(
                    f"All {records} rows of {schema_name} statistics for {window_text} (page "
                    f"{page}{'; ' + '; '.join(filters) if filters else ''}) are zero: no "
                    "non-zero value on this page." + whole,
                    settings,
                )
            dropped = (
                f", {len(shown)} shown after dropping {len(entries) - len(shown)} all-zero"
                if only_nonzero
                else ""
            )
            policy_text = (
                f", of which {policy_rows} are srte_c_* SR-policy interfaces" if policy_rows else ""
            )
            lines = [
                f"# {schema_name} statistics — {window_text}, page {page} ({records} rows"
                f"{policy_text}{dropped}" + (f"; {'; '.join(filters)}" if filters else "") + ")",
                "",
            ]
            lines.extend(statistics_line(e, template_units) for e in shown)
            # The footer explains the "(template unit ...)" annotation, so it appears only
            # when a row actually carries one — a genuine NUMBER unit (template NUMBER, e.g.
            # OTUCONTROLLERSINFO uc) is not "unresolved" and gets no footer.
            if template_units and any(entry_has_unresolved_unit(e, template_units) for e in shown):
                lines.append(
                    "\n(unit NUMBER where the template says otherwise = the platform did not "
                    "resolve the unit; the template unit in brackets is from "
                    "cnc_list_performance_policy_templates)"
                )
            if has_more:
                lines.append(more)
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
        hours: Annotated[int, Field(description=_HOURS_DESC, ge=1, le=MAX_HOURS)] = 24,
        from_time: Annotated[str, Field(description=_FROM_OPTIONAL_DESC, max_length=40)] = "",
        to_time: Annotated[str, Field(description=_TO_OPTIONAL_DESC, max_length=40)] = "",
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

        Time window: ``hours`` (default 24, the last N hours ending now —
        the dashboard has no ``timeInterval`` here, so the tool computes
        ``from`` / ``to`` itself) or both ``from_time`` and ``to_time`` —
        ISO-8601 with or without milliseconds, 'Z' or a UTC offset, or epoch
        milliseconds; either form is accepted and normalised to the
        ``.SSSZ`` form the dashboard takes (the same convention as
        cnc_get_performance_statistics: an explicit window wins over
        ``hours``, one bound without the other is refused).

        Args:
            metric: the <SCHEMA>_<metric> token (schema upper-cased before sending).
            hours: window length when from_time / to_time are not given.
            from_time / to_time: explicit window (both or neither; either
                time form accepted).
            page_size / page: the N and the 1-based page.
            sort / severity / device_groups: optional, passed as given
                (``sort`` upper/lower-case as documented: average | minimum |
                maximum | value, '-' for descending; verified live: '-value').
            response_format: markdown or json.

        Returns:
            str: Markdown "# Top N <token> (last H h: <from> to <to> | <from>
            to <to>[, sort ..][, severity ..])" and one "- <hostname>
            <object>: avg A, min B, max C UNIT, SEVERITY" line per entry; or
            JSON {"metric", "hours" (null for an explicit window), "from",
            "to", "page", "page_size", "sort", "severity", "device_groups",
            "count", "results": [...] (the platform's list)}. "No top-N
            entries for <token> ..." (non-error) for an empty answer; "Error:
            '<token>' is not a top-N schema/metric — ..." (nothing sent, or
            from the platform's 400 INVALID_SCHEMA_METRIC_COMBO); "Error:
            from_time must be ..." or "Error: pass both from_time and
            to_time ..." (nothing sent) for a bad window; "Error: ..." on an
            API failure.
        """
        try:
            token = parse_metric_token(metric, top_n=True)
            start, end, explicit = hours_or_window(hours, from_time, to_time)
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
                    "Pass hours, or both from_time and to_time.",
                ),
            }
            data = await perf_get(TOPN_URL, params=params, hints=hints)
            results = _list_of_dicts(data)
            entries = [e for r in results for e in _list_of_dicts(r.get("entries"))]
            window_text = (
                f"{params['from']} to {params['to']}"
                if explicit
                else f"last {hours} h: {params['from']} to {params['to']}"
            )
            if response_format is ResponseFormat.JSON:
                payload = {
                    "metric": token,
                    "hours": None if explicit else hours,
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
                    f"{'' if explicit else f' (the last {hours} h)'}"
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
                f"# Top {page_size} {token} ({window_text}"
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
        from_time: Annotated[str, Field(description=_FROM_DESC, max_length=40)],
        to_time: Annotated[str, Field(description=_TO_DESC, max_length=40)],
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
            from_time / to_time: the window (both required) — ISO-8601 with
                or without milliseconds, 'Z' or a UTC offset, or epoch
                milliseconds; either form is accepted and normalised to the
                ``.SSSZ`` form the dashboard takes.
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
        headend: Annotated[str, Field(description=_HEADEND_DESC, max_length=253)],
        endpoint: Annotated[str, Field(description=_ENDPOINT_DESC, max_length=253)],
        hours: Annotated[int, Field(description=_LSP_HOURS_DESC, ge=1, le=MAX_HOURS)] = (
            LSP_DEFAULT_HOURS
        ),
        from_time: Annotated[str, Field(description=_FROM_OPTIONAL_DESC, max_length=40)] = "",
        to_time: Annotated[str, Field(description=_TO_OPTIONAL_DESC, max_length=40)] = "",
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
        network: Annotated[str, Field(description=_NETWORK_DESC, max_length=200)] = DEFAULT_NETWORK,
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
        tunnel_id is given; times sent as ``2026-09-13T12:00:00Z``). Answers:
        ``[{"tst": "<ISO>", "util": <number>}, ...]`` and
        ``{"maxUtilization", "success", "message"}``.

        headend / endpoint take a host name OR a TE router-id, as
        cnc_get_sr_policy does: a host name is resolved to its router-id
        through the topology NBI (one ``networks`` GET, only when a name is
        not an IP literal; verified live 2026-09-14 — PE2 -> 10.0.0.3) and
        the header prints the topology's node id next to each router-id,
        "PE2 (10.0.0.3) -> PE1 (10.0.0.1)" (whatever spelling was given); an
        unknown name is refused before anything is sent ("Error: no node
        ..."), because NPM would silently answer ``[]`` for it. The key on
        the wire is always the router-id. An SR key needs the policy's real
        color: color 0 (the default) without a tunnel_id is refused for the
        same reason (no SR policy has color 0). NPM never validates: an
        unknown key, a wrong color or a window with no data all answer ``[]``,
        so an empty answer is reported as such with that caveat. The lab's
        PCE-delegated policy answered zeros. Related: cnc_get_lsp_delay for
        delay / loss; cnc_get_performance_statistics(schema='SRPOLICY') for
        the PM policy's outBitRate.

        Sample spacing depends on the window (verified live 2026-09-14): a
        window of at most 6 h answers the raw ~5-minute samples (73 for 6 h;
        the odd shorter gap around a collection restart), a longer window —
        even 6 h 1 min — answers hourly roll-ups stamped on the hour (18 for
        24 h, hourly history starting when collection began). The summary
        line prints the observed spacing ("18 sample(s) (... to ...;
        60-minute spacing)"), so report the resolution you actually got; for 5-minute
        detail over a long period, page through it in 6 h windows.

        Time window: ``hours`` (default 6 — the largest window that answers
        raw 5-minute samples, and the window cnc_explain_sr_policy uses, so
        a drill-in lands on the same series; pass 24 for the hourly roll-up
        view) or both ``from_time`` and ``to_time`` — ISO-8601 with or
        without milliseconds, 'Z' or a UTC offset, or epoch milliseconds;
        either form is accepted and normalised (the same convention as
        cnc_get_performance_statistics, whose ``hours`` defaults to 24). How
        long NPM keeps samples is not documented and was not verified; the
        performance service's retention (cnc_get_performance_retention) does
        not govern NPM.

        Args:
            headend / endpoint: host name or TE router-id (the same names
                and values as cnc_list_sr_policies / cnc_get_sr_policy /
                cnc_get_sr_policy_performance_metrics).
            hours: window length when from_time / to_time are not given.
            from_time / to_time: explicit window (both or neither; either
                time form accepted).
            color: the SR policy color (required for SR; 0 is refused).
            tunnel_id: an RSVP-TE tunnel id (switches to lspType RSVP).
            network: topology network id host names are resolved in.
            response_format: markdown or json.

        Returns:
            str: Markdown "# Utilization of SR LSP <head> -> <tail> color C,
            <from> to <to>" (each end as "PE2 (10.0.0.3)" when a host name was
            given), "- max utilization (platform): M — <message>", "- N
            sample(s) (<first> to <last>; <spacing>): util avg A, min B, max
            C, last D" and one "- <tst>: util V" line per sample; or JSON
            {"lsp": <the key>, "label": "SR LSP PE2 (10.0.0.3) -> ...",
            "max": {"maxUtilization", "success", "message"}, "stats":
            {"count", "first_at", "last_at", "spacing_seconds" (the most
            common gap, e.g. 300 or 3600), "gap_min_seconds",
            "gap_max_seconds", "average", "minimum", "maximum", "last"},
            "samples": [{"tst", "util"}]}. "No LSP utilization samples for
            ..." (non-error, with the unknown-key caveat) for an empty list;
            "Error: no node '<name>' in the topology ...", "Error: color is
            required for an SR policy ..." or "Error: pass both from_time and
            to_time ..." (nothing sent); "Error: ..." on an API failure.
        """
        try:
            start, end, _ = hours_or_window(hours, from_time, to_time)
            check_sr_color(color, tunnel_id)
            head_id, end_id, names = await resolve_policy_ends(client, network, headend, endpoint)
            key = lsp_key(head_id, end_id, color, tunnel_id, start, end)
            label = lsp_label(key, headend, endpoint, names)
            samples_data, max_data = await asyncio.gather(
                npm_post(NPM_LSP_UTILIZATIONS_URL, key),
                npm_post(NPM_LSP_MAX_UTILIZATION_URL, key),
            )
            samples = samples_of(samples_data)
            stats = series_stats(samples, "util")
            if response_format is ResponseFormat.JSON:
                payload = {
                    "lsp": key,
                    "label": label,
                    "max": _dict(max_data),
                    "stats": stats,
                    "samples": samples,
                }
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
        headend: Annotated[str, Field(description=_HEADEND_DESC, max_length=253)],
        endpoint: Annotated[str, Field(description=_ENDPOINT_DESC, max_length=253)],
        hours: Annotated[int, Field(description=_LSP_HOURS_DESC, ge=1, le=MAX_HOURS)] = (
            LSP_DEFAULT_HOURS
        ),
        from_time: Annotated[str, Field(description=_FROM_OPTIONAL_DESC, max_length=40)] = "",
        to_time: Annotated[str, Field(description=_TO_OPTIONAL_DESC, max_length=40)] = "",
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
        network: Annotated[str, Field(description=_NETWORK_DESC, max_length=200)] = DEFAULT_NETWORK,
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
        RSVP + ``tunnelId``). headend / endpoint take a host name OR a TE
        router-id exactly as there (and as cnc_get_sr_policy): a host name
        is resolved through the topology NBI with one ``networks`` GET (only
        when a name is not an IP literal; verified live 2026-09-14), the
        header prints "PE2 (10.0.0.3) -> PE1 (10.0.0.1)", and an unknown
        name is refused before anything is sent because NPM would silently
        answer ``[]`` for it. Delay data needs SR-PM / performance-measurement
        probes on the head-end: a lab without them answers ``[]`` on every
        series, and NPM answers the same ``[]`` for an unknown key — every
        empty section says so. (The ``delay-us`` of
        cnc_get_sr_policy_performance_metrics is a PCE-side figure that is
        present even when this tool has no samples — seen live: delay-us 20
        with no NPM delay series and no SR-PM probes — so treat THIS tool as
        the measured series and that one as computed.)

        Sample spacing depends on the window, as for cnc_get_lsp_utilization
        (verified live 2026-09-14 on the utilisation series; the delay
        series were empty on the lab): a window of at most 6 h answers the
        raw ~5-minute samples, a longer one hourly roll-ups stamped on the
        hour. Every section header and the delay summary line print the
        observed spacing ("73 sample(s) (... to ...; ~5-minute spacing, gaps
        93 s to 300 s)"), so report the resolution you actually got.

        Time window: ``hours`` (default 6 — the largest window that answers
        raw 5-minute samples, and the window cnc_explain_sr_policy uses, so
        a drill-in lands on the same series; pass 24 for the hourly roll-up
        view) or both ``from_time`` and ``to_time`` — ISO-8601 with or
        without milliseconds, 'Z' or a UTC offset, or epoch milliseconds;
        either form is accepted and normalised (the same convention as
        cnc_get_performance_statistics, whose ``hours`` defaults to 24). How
        long NPM keeps samples is not documented and was not verified.

        Args:
            headend / endpoint: host name or TE router-id (the same names
                and values as cnc_list_sr_policies / cnc_get_sr_policy /
                cnc_get_sr_policy_performance_metrics).
            hours: window length when from_time / to_time are not given.
            from_time / to_time: explicit window (both or neither; either
                time form accepted).
            color / tunnel_id: SR color (required for SR; 0 is refused), or an
                RSVP-TE tunnel id.
            network: topology network id host names are resolved in.
            response_format: markdown or json.

        Returns:
            str: Markdown "# Delay and loss of SR LSP ... , <from> to <to>"
            (each end as "PE2 (10.0.0.3)" when a host name was given), "- max
            average delay (platform): ...", "- delay: N sample(s) (...;
            <spacing>): averageDelay avg ...", then "## Delay (N sample(s)[;
            <spacing>])", "## Delay variance (...)" and "## Loss
            (...)" with one "- <tst>: field value, ..." line per sample; or
            JSON {"lsp": <the key>, "label": "SR LSP PE2 (10.0.0.3) -> ...",
            "max_delay": {...}, "delay": [...], "delay_variance": [...],
            "loss": [...]}. "No LSP delay, delay-variance or loss samples for
            ..." (non-error, with the caveat) when every series is empty;
            "Error: no node '<name>' in the topology ...", "Error: color is
            required for an SR policy ..." or "Error: pass both from_time and
            to_time ..." (nothing sent); "Error: ..." on an API failure.
        """
        try:
            start, end, _ = hours_or_window(hours, from_time, to_time)
            check_sr_color(color, tunnel_id)
            head_id, end_id, names = await resolve_policy_ends(client, network, headend, endpoint)
            key = lsp_key(head_id, end_id, color, tunnel_id, start, end)
            label = lsp_label(key, headend, endpoint, names)
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
                    "label": label,
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
        hours: Annotated[int, Field(description=_HOURS_DESC, ge=1, le=MAX_HOURS)] = 24,
        from_time: Annotated[str, Field(description=_FROM_OPTIONAL_DESC, max_length=40)] = "",
        to_time: Annotated[str, Field(description=_TO_OPTIONAL_DESC, max_length=40)] = "",
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

        Time window: ``hours`` (default 24, the last N hours ending now) or
        both ``from_time`` and ``to_time`` — ISO-8601 with or without
        milliseconds, 'Z' or a UTC offset, or epoch milliseconds; either form
        is accepted and normalised (the same convention as
        cnc_get_performance_statistics). How long NPM keeps samples is not
        documented and was not verified.

        Args:
            device_uuid: the inventory uuid (any spelling; sent canonical).
            interface: the interface name.
            hours: window length when from_time / to_time are not given.
            from_time / to_time: explicit window (both or neither; either
                time form accepted).
            response_format: markdown or json.

        Returns:
            str: Markdown "# Delay and loss of <interface> on <uuid>, <from> to
            <to>", "- max average delay (platform): ...", "- delay: N
            sample(s) (...[; <observed spacing>])", then "## Delay (N
            sample(s)[; <spacing>])" and "## Loss (...)" with one "- <tst>:
            field value, ..." line per sample; or JSON {"interface": <the key>,
            "max_delay": {...}, "delay": [...], "loss": [...]}. "No delay or
            loss samples for ..." (non-error, with the caveat) when both series
            are empty; "Error: device_uuid ... and interface ... are both
            required", "Error: device_uuid must be the device's inventory
            uuid ..." or "Error: pass both from_time and to_time ..." (nothing
            sent); "Error: ..." on an API failure.
        """
        try:
            start, end, _ = hours_or_window(hours, from_time, to_time)
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

    # --- policy and retention writes -------------------------------------------

    async def perf_send(
        method: str,
        path: str,
        json_body: Any = None,
        hints: dict[str, str | tuple[str, str]] | None = None,
    ) -> Any:
        """A write on performance/v1 (POST is never re-sent on a 5xx / transport error — a
        lost create answer must not duplicate the policy; PUT / DELETE keep the client's
        idempotent retry): a Spring error envelope becomes the precise PlatformError of
        performance_error(); the JSON body otherwise (None for an empty body)."""
        response = await client.request(method, path, json_body=json_body, raise_on_error=False)
        if not response.is_success:
            raise performance_error(response, hints)
        if not response.content:
            return None
        return _parse_json(response)

    async def perf_rows(
        path: str,
        params: dict[str, Any],
        hints: dict[str, str | tuple[str, str]] | None = None,
    ) -> list[dict[str, Any]]:
        """Every row of a paged performance/v1 listing (``{"data": [...], "total_count":
        N}``): page 1 at LOOKUP_PAGE_SIZE, then the next pages while ``total_count`` says
        more remain (or, when it is absent, while the page came back full), at most
        LOOKUP_MAX_PAGES pages."""
        rows: list[dict[str, Any]] = []
        for page in range(1, LOOKUP_MAX_PAGES + 1):
            data = _dict(
                await perf_get(
                    path, params={**params, "pageSize": LOOKUP_PAGE_SIZE, "page": page}, hints=hints
                )
            )
            page_rows = _list_of_dicts(data.get("data"))
            rows.extend(page_rows)
            total = paged_total(data)
            more = len(rows) < total if total is not None else len(page_rows) >= LOOKUP_PAGE_SIZE
            if not page_rows or not more:
                break
        return rows

    async def resolve_devices(text: str) -> list[str]:
        """``devices`` -> canonical inventory uuids: a uuid is kept, a host name is looked
        up with ``GET policies/inventory-devices?hostName=<name>`` (verified live: answers
        ``{"data": [{hostName, uuid, ...}], "total_count": N}``) and must match exactly one
        device by exact (case-insensitive) host name. The platform's ``hostName`` filter is
        a case-insensitive SUBSTRING match (verified live 2026-09-15: ``hostName=P``
        answered P1, P2, PCE, PE1, PE2), so the exact-name match is client-side and every
        page of the substring hits is walked (pageSize 1000) before deciding. The platform
        accepts ANY string as a device (``"PE1"`` was stored and the activated policy polled
        nothing), so nothing but a resolved uuid is ever sent."""
        out: list[str] = []
        for token in split_csv(text):
            if is_uuid(token):
                canonical = str(uuid_lib.UUID(token.lower()))
            else:
                rows = [
                    r
                    for r in await perf_rows(POLICY_INVENTORY_DEVICES_URL, {"hostName": token})
                    if str(r.get("hostName") or "").lower() == token.lower()
                ]
                if len(rows) != 1 or not is_uuid(rows[0].get("uuid")):
                    raise PlatformError(
                        f"device '{token}' is not an inventory uuid and {len(rows)} device(s) "
                        "match it by host name — pass the uuid or the exact host name "
                        "(cnc_list_devices shows both). The platform would accept the text "
                        "silently and the policy would poll nothing. Nothing was sent."
                    )
                canonical = str(uuid_lib.UUID(str(rows[0]["uuid"]).lower()))
            if canonical not in out:
                out.append(canonical)
        return out

    async def selection_of(devices: str, device_groups: str, port_groups: str) -> dict[str, str]:
        """The three comma-joined selection strings of a policy body, validated / resolved."""
        return {
            "devices": ",".join(await resolve_devices(devices)),
            "deviceGroups": ",".join(
                parse_uuid_list(
                    device_groups,
                    "device_groups",
                    "cnc_get_group_hierarchy / cnc_get_group_details show group uuids",
                )
            ),
            "portGroups": ",".join(
                parse_uuid_list(port_groups, "port_groups", "port-group uuids from the CNC UI")
            ),
        }

    async def policy_dto(policy_id: int) -> dict[str, Any]:
        """``GET policies/<id>`` as the DTO dict (a list answer is unwrapped)."""
        data = await perf_get(f"{POLICIES_URL}/{policy_id}", hints=policy_hints(policy_id))
        if isinstance(data, list):
            data = data[0] if data and isinstance(data[0], dict) else None
        if not isinstance(data, dict) or not _dict(data.get("monitoringPolicy")):
            raise PlatformError(
                f"no performance policy {policy_id}: the platform answered no policy object. "
                "List policies with cnc_list_performance_policies."
            )
        return data

    async def activation_wait(policy_id: int, wait_seconds: int) -> dict[str, Any]:
        """Poll ``policies/devices/<id>`` (every page, pageSize 1000) until no device is
        still IN_PROGRESS (verified live: NOTPOLLING + IN_PROGRESS at t+0, ACTIVE at t+5 s)
        or ``wait_seconds`` elapse; always reads at least once. A failed poll (a 5xx, a
        transport error) is NOT raised — the activation itself already succeeded — but
        reported in the result as ``error`` with an empty device list, so the caller can
        say "activated; device status unavailable"."""

        async def fetch() -> list[dict[str, Any]]:
            return await perf_rows(
                f"{POLICY_DEVICES_URL}/{policy_id}", {}, hints=policy_hints(policy_id)
            )

        started = time.monotonic()
        try:
            settled, rows, elapsed = await wait_until(
                fetch, policy_devices_settled, timeout_seconds=wait_seconds, interval_seconds=3
            )
        except Exception as e:
            error = format_error(e)
            logger.warning("policy %s activated; device status poll failed: %s", policy_id, error)
            return {
                "policy_id": policy_id,
                "settled": False,
                "elapsed_seconds": round(time.monotonic() - started),
                "summary": f"device status unavailable ({error})",
                "devices": [],
                "error": error,
            }
        return {
            "policy_id": policy_id,
            "settled": settled,
            "elapsed_seconds": round(elapsed),
            "summary": devices_status_text(rows),
            "devices": [policy_device_view(r) for r in rows],
            "error": None,
        }

    async def activate_policies(ids: list[int], wait_seconds: int) -> dict[str, Any]:
        """``PUT policies/activate/<ids>`` (one comma-joined segment), the results checked,
        then the deployment wait for every policy that was (or already is) active — the
        waits run CONCURRENTLY, so the whole step takes about ``wait_seconds`` at most,
        not ``wait_seconds`` per policy."""
        raw = await perf_send("PUT", f"{POLICY_ACTIVATE_URL}/{','.join(str(i) for i in ids)}")
        results = operation_results(raw)
        done, already = check_operation_results(results, ids, "activated")
        waits = list(
            await asyncio.gather(
                *(activation_wait(int(r["policy_id"]), wait_seconds) for r in done + already)
            )
        )
        return {"results": results, "activated": done, "already_active": already, "waits": waits}

    def activation_lines(outcome: dict[str, Any]) -> list[str]:
        lines = []
        for result in outcome["activated"]:
            lines.append(
                f"- policy {result['policy_id']} '{result['policy_name'] or '?'}': activated"
            )
        for result in outcome["already_active"]:
            lines.append(
                f"- policy {result['policy_id']} '{result['policy_name'] or '?'}': already active"
            )
        for wait in outcome["waits"]:
            if wait.get("error"):
                lines.append(
                    f"- policy {wait['policy_id']} devices: status unavailable after "
                    f"{wait['elapsed_seconds']} s ({wait['error']}) — the activation itself "
                    f"succeeded; cnc_list_performance_policy_devices(policy_id="
                    f"{wait['policy_id']}) shows the devices"
                )
                continue
            state = "settled" if wait["settled"] else "still deploying"
            lines.append(
                f"- policy {wait['policy_id']} devices after {wait['elapsed_seconds']} s "
                f"({state}): {wait['summary']}"
            )
        return lines

    @register_tool(
        mcp,
        ctx,
        name="cnc_create_performance_policy",
        title="Create Performance Monitoring Policy",
        read_only=False,
        idempotent=False,
        dry_run_hint=(
            "cnc_list_performance_policy_templates (read-only) shows the template's schemas "
            "and allowed cadences and cnc_list_performance_policies the policies that exist"
        ),
    )
    async def cnc_create_performance_policy(
        name: Annotated[
            str,
            Field(
                description="Unique policy name (e.g. 'PE1 interface health, hourly').",
                min_length=1,
                max_length=200,
            ),
        ],
        template: Annotated[
            str,
            Field(
                description=(
                    "Policy template to instantiate, as cnc_list_performance_policy_templates "
                    "names it (e.g. 'INTERFACE', 'deviceHealth', 'SRPOLICY'; case-insensitive)."
                ),
                min_length=1,
                max_length=60,
            ),
        ],
        schemas_interval: Annotated[
            str,
            Field(
                description=(
                    "Polling cadence per schema of the template: 'SCHEMA=seconds' pairs "
                    "separated by commas (e.g. 'CEPMINTERFACE=3600,CEPMCRC=0'), or one number "
                    "for every schema (e.g. '300'). Schemas not named are set to 0 (not polled). "
                    "Each cadence must be one of the schema's allowed pollingIntervals "
                    "(0/300/600/900/1800/3600 on 7.2; cnc_list_performance_policy_templates)."
                ),
                min_length=1,
                max_length=1000,
            ),
        ],
        devices: Annotated[
            str,
            Field(
                description=(
                    "Comma-separated devices to poll: inventory uuids or exact host names (e.g. "
                    "'PE1,PE2' or 'af1986fa-e1cb-4f8c-aa83-4f05a00472e7'); blank for none. At "
                    "least one of devices / device_groups / port_groups is required."
                ),
                max_length=8000,
            ),
        ] = "",
        device_groups: Annotated[
            str,
            Field(
                description=(
                    "Comma-separated device-group uuids (e.g. "
                    "'7913c888-f691-4c08-ac71-55a35b236e49' — cnc_get_group_hierarchy); blank "
                    "for none."
                ),
                max_length=4000,
            ),
        ] = "",
        port_groups: Annotated[
            str,
            Field(
                description=(
                    "Comma-separated port-group uuids (interface templates only); blank for none."
                ),
                max_length=4000,
            ),
        ] = "",
        description: Annotated[
            str,
            Field(
                description="Free-text description (e.g. 'Hourly PE1 counters').", max_length=1000
            ),
        ] = "",
        tag: Annotated[
            str,
            Field(
                description=(
                    "Contact / tag text the policy carries (e.g. '{contact:noc@example.com}')."
                ),
                max_length=500,
            ),
        ] = "",
        activate: Annotated[
            bool,
            Field(
                description=(
                    "true to activate the policy right after creating it (starts collection on "
                    "the selected devices — network-impacting); false (default) creates it "
                    "inactive for cnc_activate_performance_policy later."
                )
            ),
        ] = False,
        wait_seconds: Annotated[
            int,
            Field(
                description=(
                    "With activate=true: how long in total to wait for the devices to leave "
                    "IN_PROGRESS (e.g. 20; 0 = read the device statuses once and return)."
                ),
                ge=0,
                le=120,
            ),
        ] = 20,
    ) -> str:
        """Create a performance monitoring policy from a template — which schemas
        to poll, how often, on which devices / groups — inactive unless
        ``activate`` is set.

        Write; ``POST /crosswork/performance/v1/policies`` with
        ``{policyTemplate, name, description, schemasInterval {SCHEMA:
        seconds}, devices, deviceGroups, portGroups (comma-joined uuid
        strings), tag, thresholds {}, active false}`` (verified live
        2026-09-15) -> 200 with the policy object (``monitoringPolicy.id`` is
        a sequential integer, never reused). The policy is created INACTIVE
        whatever the spec says about ``active`` defaulting to true (verified:
        omitted -> false), so nothing is polled until
        cnc_activate_performance_policy — or ``activate=true`` here, which
        then calls ``PUT policies/activate/<id>`` and waits like that tool
        (activation starts SNMP / telemetry collection jobs on every selected
        device at the given cadence: network-impacting; preview the template
        with cnc_list_performance_policy_templates first). Use it for a
        device- or group-specific cadence or a schema the built-in policies
        do not poll (CEPMCRC, deviceHealth CPU / MEMORY, QOS, PTP, ...); a
        second policy on a device the built-in "Default interface health"
        already polls is allowed (verified: both stayed ACTIVE). Do not use it
        to change an existing policy (cnc_update_performance_policy) or for
        TCA thresholds (not exposed; ``thresholds`` is sent empty).

        Validated BEFORE sending, because the platform does not (verified):
        the template name (case-insensitive, canonical spelling sent); every
        schema of ``schemas_interval`` must belong to the template and every
        cadence must be in the schema's ``pollingIntervals`` (123 s was
        accepted live and would poll at an unsupported interval); ``devices``
        must resolve to inventory uuids (a host name is looked up with ``GET
        policies/inventory-devices?hostName=``; "PE1" sent raw was stored and
        the policy polled NOTHING); group uuids must be uuids (an unknown
        uuid is accepted silently). Platform errors: a duplicate name -> 400
        ``POLICY_EXITS`` (the platform's spelling); no selection -> 400
        ``MISSING_DEVICES``; unknown template -> 400 ``INVALID_POLICY_TYPE``.
        Not idempotent: a repeat with the same name fails.

        With ``activate=true`` the create and the activation are two calls,
        and the answer says which succeeded: once the POST has answered a
        policy id, a failed activation (a 5xx on the activate PUT, a
        NOT_FOUND / DB_ERROR result) is reported as "CREATED, but its
        activation failed" naming the id — the policy EXISTS, so do not
        re-create it (that answers POLICY_EXITS): retry with
        cnc_activate_performance_policy or remove it with
        cnc_delete_performance_policy. A failed device-status poll after a
        successful activation is not an error at all: "created and activated"
        with a "status unavailable" devices line. ``wait_seconds`` is the
        total wait (one policy here).

        Args:
            name: unique policy name.
            template: template key (INTERFACE, deviceHealth, SRPOLICY, ...).
            schemas_interval: 'SCHEMA=seconds,...' or one cadence for all.
            devices / device_groups / port_groups: the selection (at least one).
            description / tag: free text.
            activate: also activate (network-impacting) and wait.
            wait_seconds: the activation wait (0 = one status read).

        Returns:
            str: "Performance policy <id> '<name>' created (inactive — activate
            with cnc_activate_performance_policy(policy_ids='<id>'))." or
            "... created and activated." plus the "- policy <id> devices after
            N s (settled|still deploying): PE1 ACTIVE" line (or "- policy <id>
            devices: status unavailable after N s (Error: ...) — the activation
            itself succeeded; ..."), then JSON {"policy": {"id", "name",
            "template", "active", "collection_status", "schemas_interval",
            "devices", "device_groups", "port_groups", ...} (read back after
            an activation, so ``active`` is true then), "policy_ids":
            "<id>" (the string cnc_activate_performance_policy /
            cnc_deactivate_performance_policy take), "activation": {"results",
            "activated", "already_active", "waits": [{"policy_id", "settled",
            "elapsed_seconds", "summary", "devices": [...], "error": str |
            null}]} | null, "activation_error": str | null}. "Performance
            policy <id> '<name>' CREATED, but its activation failed: Error: ...
            The policy exists — do not re-create it ..." (non-"Error:" head:
            the create succeeded) when the activate step fails after the POST;
            "Error: a performance policy named '<name>' already exists
            (POLICY_EXITS). ..." on a duplicate; "Error: cadence 123 s is not
            allowed for CEPMINTERFACE ... Nothing was sent." / "Error: device
            'x' is not an inventory uuid ..." for a refused input; "Error: ..."
            on an API failure before or during the POST.
        """
        try:
            templates = await perf_get(POLICY_TEMPLATES_URL)
            template_key, template_obj = find_template(templates, template)
            intervals = parse_schemas_interval(schemas_interval, template_key, template_obj)
            selection = await selection_of(devices, device_groups, port_groups)
            if not any(selection.values()):
                raise PlatformError(
                    "the policy needs a selection: pass devices (uuids or host names), "
                    "device_groups or port_groups. Nothing was sent."
                )
            body = {
                "policyTemplate": template_key,
                "name": name.strip(),
                "description": description.strip(),
                "schemasInterval": intervals,
                **selection,
                "tag": tag.strip(),
                "thresholds": {},
                "active": False,
            }
            dto = await perf_send(
                "POST", POLICIES_URL, body, hints=policy_write_hints(body["name"], template_key)
            )
            if isinstance(dto, list):
                dto = dto[0] if dto and isinstance(dto[0], dict) else None
            view = policy_view(_dict(dto))
            policy_id = view.get("id")
            if not isinstance(policy_id, int) or isinstance(policy_id, bool):
                raise PlatformError(
                    "the platform answered no policy id; check cnc_list_performance_policies "
                    f"for '{body['name']}' before retrying (a repeat would answer POLICY_EXITS)."
                )
            activation: dict[str, Any] | None = None
            lines = []
            if activate:
                # The policy exists from here on: a failed activation must never read as
                # a failed create (an agent that "tries again" would re-create it).
                try:
                    activation = await activate_policies([policy_id], wait_seconds)
                except Exception as e:
                    error = format_error(e)
                    logger.warning("policy %s created; activation failed: %s", policy_id, error)
                    payload = {
                        "policy": view,
                        "policy_ids": str(policy_id),
                        "activation": None,
                        "activation_error": error,
                    }
                    return finalize(
                        f"Performance policy {policy_id} '{view.get('name')}' CREATED, but its "
                        f"activation failed: {error} The policy exists — do not re-create it (a "
                        f"repeat answers POLICY_EXITS): cnc_get_performance_policy(policy_id="
                        f"{policy_id}) shows its state, cnc_activate_performance_policy("
                        f"policy_ids='{policy_id}') retries the activation, "
                        f"cnc_delete_performance_policy(policy_id={policy_id}) removes it.\n\n"
                        f"{to_json(payload)}",
                        settings,
                    )
                head = f"Performance policy {policy_id} '{view.get('name')}' created and activated."
                lines.extend(activation_lines(activation))
                try:  # the POST echo still says active false; show the activated state
                    view = policy_view(await policy_dto(policy_id))
                except Exception as e:
                    logger.warning("policy %s read-back after activation failed: %s", policy_id, e)
            else:
                head = (
                    f"Performance policy {policy_id} '{view.get('name')}' created (inactive — "
                    f"activate with cnc_activate_performance_policy(policy_ids='{policy_id}'))."
                )
            payload = {
                "policy": view,
                "policy_ids": str(policy_id),
                "activation": activation,
                "activation_error": None,
            }
            return finalize(
                "\n".join([head, *lines, "", to_json(payload)])
                if lines
                else f"{head}\n\n{to_json(payload)}",
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_update_performance_policy",
        title="Update Performance Monitoring Policy",
        read_only=False,
        idempotent=True,
        dry_run_hint=(
            "cnc_get_performance_policy (read-only) shows the policy as it is and "
            "cnc_list_performance_policy_templates the cadences the change may use"
        ),
    )
    async def cnc_update_performance_policy(
        policy_id: Annotated[
            int,
            Field(
                description="Policy id as listed by cnc_list_performance_policies (e.g. 3).", ge=1
            ),
        ],
        name: Annotated[
            str,
            Field(
                description="New unique name (e.g. 'PE1 interface health'); blank to keep.",
                max_length=200,
            ),
        ] = "",
        description: Annotated[
            str, Field(description="New description; blank to keep.", max_length=1000)
        ] = "",
        schemas_interval: Annotated[
            str,
            Field(
                description=(
                    "New cadences: 'SCHEMA=seconds,...' (e.g. 'CEPMINTERFACE=900,CEPMCRC=0') or "
                    "one number for every schema; schemas not named are set to 0. Blank to keep."
                ),
                max_length=1000,
            ),
        ] = "",
        devices: Annotated[
            str,
            Field(
                description=(
                    "New device selection (uuids or exact host names, comma-separated). Giving "
                    "ANY of devices / device_groups / port_groups replaces the whole selection; "
                    "all three blank keeps it."
                ),
                max_length=8000,
            ),
        ] = "",
        device_groups: Annotated[
            str,
            Field(
                description="New device-group uuids (comma-separated); see devices.",
                max_length=4000,
            ),
        ] = "",
        port_groups: Annotated[
            str,
            Field(
                description="New port-group uuids (comma-separated); see devices.", max_length=4000
            ),
        ] = "",
        tag: Annotated[
            str, Field(description="New contact / tag text; blank to keep.", max_length=500)
        ] = "",
    ) -> str:
        """Change a performance policy's name, description, cadences, selection
        or tag — the rest, including whether it is active, is kept.

        Write; read-merge-write: ``GET policies/<id>``, the given fields
        applied, then ``PUT /crosswork/performance/v1/policies/<id>`` with the
        FULL MonitoringPolicy body ``{id, policyTemplate, name, description,
        schemasInterval, devices, deviceGroups, portGroups, tag, thresholds,
        active}`` (verified live 2026-09-15: a partial body, or a body whose
        ``id`` differs from the path, is answered 400 ``MISSING_POLICY_ID``
        naming the path id; and the body's ``active`` IS the activation state
        — ``false`` or absent DEACTIVATES an active policy, ``true`` activates
        an inactive one — so the current flag is carried through and this
        tool never changes it; use cnc_activate_performance_policy /
        cnc_deactivate_performance_policy for that). A PUT on an ACTIVE
        policy (verified live 2026-09-15, cadence 3600 -> 1800 s on a PE1
        policy): accepted, the policy stays ``active true`` / collection OK
        and reads back with the new cadence at once, but ``deployment-history``
        gets NO new entry and the device rows never cycle through
        IN_PROGRESS — so whether the running collection jobs pick up the new
        cadence / selection without a re-activation is NOT observable through
        the API. To be sure a change takes effect: cnc_deactivate -> update ->
        cnc_activate_performance_policy (network-impacting when it adds
        devices or shortens a cadence), or watch the sample spacing with
        cnc_get_performance_statistics after a cadence has elapsed. The
        template cannot change (create a new policy instead). Validated
        before sending as in cnc_create_performance_policy (schema names and
        cadences against the template, devices resolved to uuids, group
        uuids) — plus the new name must not belong to another policy: the
        platform checks uniqueness on create only and accepted a rename to
        "Default interface health" live, so the tool lists the policies and
        refuses that. Only a value that differs from the policy's current one
        counts as a change; when every given value already matches, nothing is
        sent (verified: a no-op PUT still bumps ``lastChangedTimestamp``). The
        PUT answer echoes the policy with both timestamps 0; the tool reads it
        back for the real ones.

        Args:
            policy_id: the policy to change.
            name / description / tag: blank keeps the current value.
            schemas_interval: blank keeps the current cadences.
            devices / device_groups / port_groups: any of them given replaces
                the whole selection.

        Returns:
            str: "Performance policy <id> '<name>' updated (<changed fields>;
            still active|inactive)." then JSON {"changed": [field, ...],
            "policy": {"id", "name", "template", "active", ...}}. "Nothing to
            change for policy <id>: pass name, ..." (non-error, nothing read
            or sent) when every argument is blank; "Nothing to change for
            policy <id>: every given value already matches the policy. Nothing
            was sent." (non-error) when the given values equal the current
            ones; "Error: no performance policy <id> (MISSING_POLICY_ID). ..."
            for an unknown id; "Error: a performance policy named '<name>'
            already exists (id N). Nothing was sent." on a clashing rename;
            "Error: cadence ... Nothing was sent." for a refused cadence;
            "Error: ..." on an API failure.
        """
        try:
            wants_selection = any(v.strip() for v in (devices, device_groups, port_groups))
            if (
                not any(v.strip() for v in (name, description, schemas_interval, tag))
                and not wants_selection
            ):
                return finalize(
                    f"Nothing to change for policy {policy_id}: pass name, description, "
                    "schemas_interval, tag, or a new selection. Nothing was sent.",
                    settings,
                )
            current = _dict((await policy_dto(policy_id)).get("monitoringPolicy"))
            body = policy_body(current)
            body["id"] = policy_id
            changed: list[str] = []
            if name.strip() and name.strip() != body["name"]:
                policies = _list_of_dicts(await perf_get(POLICIES_URL))
                for other in policies:
                    mp = _dict(other.get("monitoringPolicy"))
                    if mp.get("name") == name.strip() and mp.get("id") != policy_id:
                        raise PlatformError(
                            f"a performance policy named '{name.strip()}' already exists (id "
                            f"{mp.get('id')}); the platform would accept the duplicate on update. "
                            "Nothing was sent."
                        )
                body["name"] = name.strip()
                changed.append("name")
            if description.strip() and description.strip() != body["description"]:
                body["description"] = description.strip()
                changed.append("description")
            if tag.strip() and tag.strip() != body["tag"]:
                body["tag"] = tag.strip()
                changed.append("tag")
            if schemas_interval.strip():
                templates = await perf_get(POLICY_TEMPLATES_URL)
                template_key, template_obj = find_template(templates, str(body["policyTemplate"]))
                intervals = parse_schemas_interval(schemas_interval, template_key, template_obj)
                if intervals != body["schemasInterval"]:
                    body["schemasInterval"] = intervals
                    changed.append("schemas_interval")
            if wants_selection:
                selection = await selection_of(devices, device_groups, port_groups)
                if not any(selection.values()):
                    raise PlatformError(
                        "the new selection resolved to nothing; pass devices, device_groups or "
                        "port_groups. Nothing was sent."
                    )
                if any(not same_selection(selection[k], body[k]) for k in selection):
                    body.update(selection)
                    changed.append("selection")
            if not changed:
                return finalize(
                    f"Nothing to change for policy {policy_id}: every given value already "
                    "matches the policy. Nothing was sent.",
                    settings,
                )
            await perf_send(
                "PUT",
                f"{POLICIES_URL}/{policy_id}",
                body,
                hints=policy_write_hints(str(body["name"]), str(body["policyTemplate"])),
            )
            view = policy_view(await policy_dto(policy_id))
            state = "active" if view.get("active") else "inactive"
            head = (
                f"Performance policy {policy_id} '{view.get('name')}' updated "
                f"({', '.join(changed)}; still {state})."
            )
            return finalize(f"{head}\n\n{to_json({'changed': changed, 'policy': view})}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_activate_performance_policy",
        title="Activate Performance Monitoring Policy",
        read_only=False,
        idempotent=True,
        dry_run_hint=(
            "cnc_get_performance_policy (read-only) shows the scope and cadence the "
            "activation would start polling with, cnc_list_performance_policy_devices the "
            "devices it would cover"
        ),
    )
    async def cnc_activate_performance_policy(
        policy_ids: Annotated[
            str,
            Field(
                description=(
                    "Policy id, or several separated by commas (e.g. '3' or '3,5'), as listed "
                    "by cnc_list_performance_policies."
                ),
                min_length=1,
                max_length=200,
            ),
        ],
        wait_seconds: Annotated[
            int,
            Field(
                description=(
                    "How long in total to wait for every device of every policy to leave "
                    "IN_PROGRESS (e.g. 20; 0 = read the device statuses once and return). The "
                    "policies are waited on concurrently, so this is the call's ceiling."
                ),
                ge=0,
                le=120,
            ),
        ] = 20,
    ) -> str:
        """Activate one or more performance policies — start collecting their
        schemas from their devices at the configured cadence.

        Write, NETWORK-IMPACTING: activation deploys SNMP / telemetry
        collection jobs to every device the policy selects (through the Data
        Gateway) and they poll from then on. Preview what would start with
        cnc_get_performance_policy (cadence, schemas, selection) first.
        ``PUT /crosswork/performance/v1/policies/activate/<id[,id...]>``
        (verified live 2026-09-15; ONE comma-joined path segment) answers 200
        with ``[{"policyId", "status": OK | ALREADY_ACTIVATED | NOT_FOUND,
        "policyName"}]`` — an unknown id is a 200 NOT_FOUND, reported here as
        an error naming it (the others are still applied and listed);
        ALREADY_ACTIVATED is a no-op success (idempotent). Then the tool polls
        ``policies/devices/<id>`` (every page) every 3 s up to
        ``wait_seconds`` — for all the policies CONCURRENTLY, so
        ``wait_seconds`` is the total ceiling of the call, not per policy:
        verified sequence — t+0 the policy reads ``active true`` / collection
        PARTIAL and each device NOTPOLLING with comment IN_PROGRESS; t+5 s
        the device is ACTIVE and the policy OK. A device left NOTPOLLING with
        another comment (MISSING_DEVICE_DETAILS, UN_MANAGED_DEVICE, ...) will
        not be polled — cnc_list_performance_policy_devices explains. A
        failed status poll (a 5xx on the devices read) does not fail the
        call — the activation already succeeded — it is reported per policy
        as "devices: status unavailable". Data appears in
        cnc_get_performance_statistics after the first cadence elapses.

        Args:
            policy_ids: '3' or '3,5'.
            wait_seconds: total deployment wait (0 = one read).

        Returns:
            str: "Activated N performance policy(ies)." with one "- policy <id>
            '<name>': activated|already active" line per id and one "- policy
            <id> devices after S s (settled|still deploying): PE1 ACTIVE, ..."
            line per policy (or "- policy <id> devices: status unavailable
            after S s (Error: ...) — the activation itself succeeded; ..."),
            then JSON {"results": [{"policy_id", "status", "policy_name",
            "error_message"}], "activated": [...], "already_active": [...],
            "waits": [{"policy_id", "settled", "elapsed_seconds", "summary",
            "devices": [{"host_name", "uuid", "collection_status", "comments",
            ...}], "error": str | null}]}. "Error: no performance policy 999
            (NOT_FOUND). Applied to the others: ..." for an unknown id;
            "Error: policy_ids must be ..." (nothing sent) for a bad list;
            "Error: ..." when the activate PUT itself fails.
        """
        try:
            ids = parse_policy_ids(policy_ids)
            outcome = await activate_policies(ids, wait_seconds)
            head = f"Activated {len(outcome['activated'])} performance policy(ies)"
            if outcome["already_active"]:
                head += f" ({len(outcome['already_active'])} already active)"
            lines = [head + ".", *activation_lines(outcome), "", to_json(outcome)]
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_deactivate_performance_policy",
        title="Deactivate Performance Monitoring Policy",
        read_only=False,
        idempotent=True,
    )
    async def cnc_deactivate_performance_policy(
        policy_ids: Annotated[
            str,
            Field(
                description=(
                    "Policy id, or several separated by commas (e.g. '3' or '3,5'), as listed "
                    "by cnc_list_performance_policies."
                ),
                min_length=1,
                max_length=200,
            ),
        ],
    ) -> str:
        """Deactivate one or more performance policies — stop collecting their
        schemas (the policies and their history stay).

        Write; ``PUT /crosswork/performance/v1/policies/deactivate/<id[,id...]>``
        (verified live 2026-09-15; one comma-joined path segment) answers 200
        with ``[{"policyId", "status": OK | ALREADY_DEACTIVATED | NOT_FOUND,
        "policyName"}]`` — an unknown id is a 200 NOT_FOUND, reported here as
        an error naming it (the others are still applied); ALREADY_DEACTIVATED
        is a no-op success. Deactivation is immediate (verified: the policy
        reads ``active false`` and ``policies/devices/<id>`` is empty at once).
        Deactivating a built-in policy (1 "Default interface health", 2
        "Default LSP traffic") stops the interface / LSP dashboards from
        filling — say so before doing it. Deletion does not need it
        (cnc_delete_performance_policy removes an active policy too).

        Args:
            policy_ids: '3' or '3,5'.

        Returns:
            str: "Deactivated N performance policy(ies)." with one "- policy
            <id> '<name>': deactivated|already inactive" line per id, then JSON
            {"results": [{"policy_id", "status", "policy_name",
            "error_message"}], "deactivated": [...], "already_inactive": [...]}.
            "Error: no performance policy 999 (NOT_FOUND). ..." for an unknown
            id; "Error: policy_ids must be ..." (nothing sent) for a bad list;
            "Error: ..." on an API failure.
        """
        try:
            ids = parse_policy_ids(policy_ids)
            raw = await perf_send("PUT", f"{POLICY_DEACTIVATE_URL}/{','.join(str(i) for i in ids)}")
            results = operation_results(raw)
            done, already = check_operation_results(results, ids, "deactivated")
            head = f"Deactivated {len(done)} performance policy(ies)"
            if already:
                head += f" ({len(already)} already inactive)"
            lines = [head + "."]
            lines.extend(
                f"- policy {r['policy_id']} '{r['policy_name'] or '?'}': deactivated" for r in done
            )
            lines.extend(
                f"- policy {r['policy_id']} '{r['policy_name'] or '?'}': already inactive"
                for r in already
            )
            payload = {"results": results, "deactivated": done, "already_inactive": already}
            return finalize("\n".join([*lines, "", to_json(payload)]), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_performance_policy",
        title="Delete Performance Monitoring Policy",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_performance_policy(
        policy_id: Annotated[
            int,
            Field(
                description="Policy id as listed by cnc_list_performance_policies (e.g. 3).", ge=1
            ),
        ],
    ) -> str:
        """Delete a performance monitoring policy — collection for it stops and
        its deployment history goes.

        DESTRUCTIVE write; ``DELETE /crosswork/performance/v1/policies/<id>``
        (verified live 2026-09-15) answers 200 with ``[{"policyId", "status":
        OK | NOT_FOUND, "policyName"}]`` — an unknown or already deleted id is
        a 200 NOT_FOUND, reported here as an error. No deactivation is needed
        first (an ACTIVE policy was deleted live and the built-in policy's
        devices stayed ACTIVE); the platform's comma-list form
        (``policies/3,5``) is deliberately not offered — one policy per call.
        Verify the target with cnc_get_performance_policy first; deleting a
        built-in policy (1 "Default interface health", 2 "Default LSP
        traffic") empties the interface / LSP dashboards from then on. Ids are
        never reused, so a stale id cannot hit a newer policy.

        Args:
            policy_id: the policy to delete.

        Returns:
            str: "Performance policy <id> '<name>' deleted." then JSON
            {"policy_id", "status": "OK", "policy_name"}. "Error: no
            performance policy <id> (NOT_FOUND). ..." for an unknown id;
            "Error: ..." on an API failure.
        """
        try:
            raw = await perf_send("DELETE", f"{POLICIES_URL}/{policy_id}")
            results = operation_results(raw)
            done, _already = check_operation_results(results, [policy_id], "deleted")
            result = done[0]
            return finalize(
                f"Performance policy {policy_id} '{result.get('policy_name') or '?'}' deleted.\n\n"
                f"{to_json(result)}",
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_update_performance_retention",
        title="Update Performance Data Retention",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_update_performance_retention(
        table: Annotated[
            str,
            Field(
                description=(
                    "Retention table to change — its raw table key as "
                    "cnc_get_performance_retention lists it (e.g. 'CEPM_INTERFACE', "
                    "'CEPM_SRPOLICY', 'DeviceCpuUtilInfo') or its "
                    "schema name (e.g. 'CEPMINTERFACE', 'CPU'); case-insensitive."
                ),
                min_length=1,
                max_length=80,
            ),
        ],
        raw_hours: Annotated[
            int | None,
            Field(
                description="New raw-sample retention in hours (e.g. 48); omit to keep.",
                ge=0,
                le=100000,
            ),
        ] = None,
        hourly_hours: Annotated[
            int | None,
            Field(
                description="New hourly roll-up retention in hours (e.g. 336); omit to keep.",
                ge=0,
                le=100000,
            ),
        ] = None,
        daily_hours: Annotated[
            int | None,
            Field(
                description="New daily roll-up retention in hours (e.g. 1488); omit to keep.",
                ge=0,
                le=100000,
            ),
        ] = None,
        weekly_hours: Annotated[
            int | None,
            Field(
                description="New weekly roll-up retention in hours (e.g. 18144); omit to keep.",
                ge=0,
                le=100000,
            ),
        ] = None,
    ) -> str:
        """Change how long one performance schema's data is kept (raw, hourly,
        daily, weekly) — the other periods and tables stay as they are.

        DESTRUCTIVE write (it overwrites the table's retention setting, and a
        shortened period lets the platform purge the older samples for good);
        read-merge-write: ``GET dataretention/all``, the table found by
        its raw table key or schema name, the given periods applied, then
        ``PUT /crosswork/performance/v1/dataretention`` with ``{"<raw table
        key>": {rawDataRetentionPeriod, hourlyDataRetentionPeriod,
        dailyDataRetentionPeriod, weeklyDataRetentionPeriod}}`` — always all
        four (a partial body is unverified) and the key in the platform's
        exact spelling (verified live 2026-09-15: ``CEPM_INTERFACE`` weekly
        9072 -> 9073 answered ``200 true`` and read back at once; the
        lower-cased key answered ``200 false`` and changed NOTHING — ``false``
        means "no such table" and is reported as an error). The change is
        read back and both states are returned. Lowering a period lets the
        platform purge older data (irreversible) — the answer carries the
        exact call that restores the previous values, so the recipe is: note
        the "before" line (or cnc_get_performance_retention first), change,
        and restore with the printed call when done. Tables whose
        ``has_aggregation_option`` is false (CEPM_PTP, CEPM_SYNCE, CEPM_GNSS)
        sit at hourly / daily / weekly 0 by default; what the platform does
        with roll-up periods on them is unverified. Whether raw <= hourly <=
        daily <= weekly is enforced is unverified too (no such error was
        seen). Defaults: 24 / 168 / 744 / 9072 h (cnc_get_performance_retention;
        cnc_reset_performance_retention puts EVERY table back to them).

        Args:
            table: raw table key or schema name.
            raw_hours / hourly_hours / daily_hours / weekly_hours: at least one.

        Returns:
            str: "Retention of <key> (schema <SCHEMA>) updated: raw R h, hourly
            H h, daily D h, weekly W h (before: ...)." (or "... unchanged: ..."
            when the values already matched — the PUT is still sent), the
            "Restore with: cnc_update_performance_retention(table='<key>',
            raw_hours=..., ...)" line, then JSON {"table", "schema", "before":
            {four periods}, "after": {four periods}, "changed": bool,
            "restore_call": str}. "Error: unknown retention table '<x>'.
            Tables: ... Nothing was sent." for a bad name; "Error: pass at
            least one of ..." (nothing sent) when all four are omitted;
            "Error: the platform applied nothing (answered false) ..." when the
            PUT is refused; "Error: ..." on an API failure.
        """
        try:
            changes: dict[str, int | None] = {
                "rawDataRetentionPeriod": raw_hours,
                "hourlyDataRetentionPeriod": hourly_hours,
                "dailyDataRetentionPeriod": daily_hours,
                "weeklyDataRetentionPeriod": weekly_hours,
            }
            if all(v is None for v in changes.values()):
                raise PlatformError(
                    "pass at least one of raw_hours, hourly_hours, daily_hours, weekly_hours. "
                    "Nothing was sent."
                )
            all_data = await perf_get(RETENTION_ALL_URL)
            key, entry = find_retention_table(all_data, table)
            before = {field: entry.get(field) for field in RETENTION_FIELDS}
            body = retention_body(entry, changes)
            answer = await perf_send("PUT", RETENTION_URL, {key: body})
            if answer is not True:
                raise PlatformError(
                    f"the platform applied nothing for retention table '{key}' (it answered "
                    f"{to_json(answer)} instead of true) — the table name is not one it knows in "
                    "this spelling; cnc_get_performance_retention lists the tables."
                )
            after_all = await perf_get(RETENTION_ALL_URL)
            after_entry = _dict(_dict(after_all).get(key))
            after = {field: after_entry.get(field) for field in RETENTION_FIELDS}
            if after != body:
                raise PlatformError(
                    f"the platform answered true but retention table '{key}' reads back as "
                    f"{retention_periods_text(after)}, not {retention_periods_text(body)}; "
                    "check cnc_get_performance_retention."
                )
            restore_call = (
                f"cnc_update_performance_retention(table='{key}', "
                f"raw_hours={num_text(before['rawDataRetentionPeriod'])}, "
                f"hourly_hours={num_text(before['hourlyDataRetentionPeriod'])}, "
                f"daily_hours={num_text(before['dailyDataRetentionPeriod'])}, "
                f"weekly_hours={num_text(before['weeklyDataRetentionPeriod'])})"
            )
            changed = after != before
            schema = entry.get("schemaName") or "?"
            head = (
                f"Retention of {key} (schema {schema}) {'updated' if changed else 'unchanged'}: "
                f"{retention_periods_text(after)}"
                + (f" (before: {retention_periods_text(before)})." if changed else ".")
            )
            payload = {
                "table": key,
                "schema": entry.get("schemaName"),
                "before": before,
                "after": after,
                "changed": changed,
                "restore_call": restore_call,
            }
            return finalize(
                "\n".join([head, f"Restore with: {restore_call}", "", to_json(payload)]), settings
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_reset_performance_retention",
        title="Reset Performance Data Retention",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_reset_performance_retention() -> str:
        """Reset EVERY performance retention table to the platform defaults
        (raw 24 h, hourly 168 h, daily 744 h, weekly 9072 h).

        DESTRUCTIVE write: it overwrites every table's periods at once (a
        table whose retention was raised loses that, and shortened periods let
        the platform purge data). ``POST
        /crosswork/performance/v1/dataretention/reset`` — per the spec a 200
        with a boolean; NOT exercised live (it would have changed the lab's
        settings), so the answer envelope is unverified and the tool relies on
        ``GET dataretention/all`` before and after instead: every table whose
        periods changed is listed with its previous values and the
        cnc_update_performance_retention call that restores them. Read
        cnc_get_performance_retention first; to change one table use
        cnc_update_performance_retention instead. Whether the reset also sets
        hourly / daily / weekly on the no-aggregation tables (CEPM_PTP,
        CEPM_SYNCE, CEPM_GNSS, at 0 by default) to the defaults is unknown.

        Returns:
            str: "Performance retention reset to the defaults: N table(s)
            changed." with one "- <key> (schema): before ... -> after ...;
            restore with cnc_update_performance_retention(...)" line per
            changed table (or "no table changed"), then JSON {"default": {four
            periods}, "answer": <the platform's body>, "changed": [{"table",
            "schema", "before", "after", "restore_call"}]}. "Error: ..." on an
            API failure (a non-true answer is reported with the read-back).
        """
        try:
            before_all = _dict(await perf_get(RETENTION_ALL_URL))
            answer = await perf_send("POST", RETENTION_RESET_URL)
            after_all, defaults = await asyncio.gather(
                perf_get(RETENTION_ALL_URL), perf_get(RETENTION_DEFAULT_URL)
            )
            changed = []
            for key, entry in before_all.items():
                old = {f: _dict(entry).get(f) for f in RETENTION_FIELDS}
                new = {f: _dict(_dict(after_all).get(key)).get(f) for f in RETENTION_FIELDS}
                if old != new:
                    changed.append(
                        {
                            "table": str(key),
                            "schema": _dict(entry).get("schemaName"),
                            "before": old,
                            "after": new,
                            "restore_call": (
                                f"cnc_update_performance_retention(table='{key}', "
                                f"raw_hours={num_text(old['rawDataRetentionPeriod'])}, "
                                f"hourly_hours={num_text(old['hourlyDataRetentionPeriod'])}, "
                                f"daily_hours={num_text(old['dailyDataRetentionPeriod'])}, "
                                f"weekly_hours={num_text(old['weeklyDataRetentionPeriod'])})"
                            ),
                        }
                    )
            if answer is not True and answer is not None:
                raise PlatformError(
                    f"the platform answered {to_json(answer)} instead of true; "
                    f"{len(changed)} table(s) read back changed — check "
                    "cnc_get_performance_retention."
                )
            head = f"Performance retention reset to the defaults: {len(changed)} table(s) changed."
            lines = [head]
            for c in changed:
                lines.append(
                    f"- {c['table']} ({c['schema'] or '?'}): "
                    f"{retention_periods_text(c['before'])} -> "
                    f"{retention_periods_text(c['after'])}; restore with {c['restore_call']}"
                )
            if not changed:
                lines.append("- no table changed (all were already at the defaults)")
            payload = {"default": _dict(defaults), "answer": answer, "changed": changed}
            return finalize("\n".join([*lines, "", to_json(payload)]), settings)
        except Exception as e:
            return format_error(e)
