"""Fault management: alarm detail/search, events, the alarm lifecycle
(acknowledge / note / clear), fault settings, the event-type catalogue and
alarm suppression policies.

Crosswork's fault surface is spread over THREE API bases (all verified live
2026-09-13 on the 7.2 lab; ack/unack/note/clear were exercised on a real
alarm). ``cnc_list_alarms`` (in :mod:`cnc_mcp.tools.platform`) stays the paged
alarm listing; this module adds everything else.

1. **``/crosswork/alarms/v1`` (plural)** — alarm and event queries plus the
   lifecycle writes. The official guides spell the fault context ``alarm/v1``,
   but ``query`` / ``event/query`` / ``ack`` / ``note`` / ``clear`` only answer
   on the PLURAL base; on the singular base they are HTTP 200
   ``{"error": "Fail", "code": 0, "message": "Input Request is invalid"}``.
   Reads are ``POST query {"openAlarmsOnly": bool, "criteria": "select * from
   alarm limit N page M"}`` -> ``{"state": "Success", "alarms": [...]}`` and
   ``POST event/query {"criteria": "select * from event limit N page M"}`` ->
   ``{"state": "Success", "events": [...]}``. **Criteria-grammar limits**: a
   ``where`` clause never matches (0 rows for any field, ``{}`` for events) and
   ``order by`` is ignored, so every filter and sort in this module is applied
   client-side. ``select * from alarm`` with NO ``limit`` returns the whole
   collection (open and cleared — 99 rows on the lab), which is what the
   get-by-id and search tools use; events without a limit answer 100 rows.
   Lifecycle writes are ``PUT ack {"alarmId", "ack": bool, "note"?}``,
   ``PUT note {"alarmId", "note"}`` and ``PUT clear {"alarmId", "note"?}``; all
   answer HTTP 200 with ``{"state": "Success"|"Fail", "Message": ...}``, so the
   status code proves nothing and every answer goes through
   :func:`check_lifecycle`. The acknowledge flag is **asynchronous**: it flips
   1-3 s after the ``Success`` answer, and an immediate re-read may still show
   the old value. **Wire safety**: ``ack`` and ``note`` are sent with
   ``retryable=False`` — the platform records every accepted call (AckHist
   entry / permanent note), so a blind re-send after a lost answer could record
   it twice; ``clear`` keeps the client's PUT auto-retry because a clear that
   already landed is refused by the platform (``Fail "Alarm is already
   cleared."``) rather than applied twice. Every write targets the platform's
   own spelling of the ``AlarmId`` (the pre-flight match is case-insensitive).
2. **``/crosswork/alarm/v1`` (singular)** — fault settings (``settings``,
   ``gnmi/settings``, ``manager/settings``), the event-type catalogue
   (``severity-config`` and ``autoclear`` answer the SAME ``items[]``),
   ``recommended-action?eventType=<name>`` and the ``suppressionpolicy``
   collection.
3. **``/crosswork/alarm/restconf/data/v2/rtm:alarm``** — the EMF RESTCONF
   fault manager's alarms (``Accept: application/json``,
   ``.startIndex``/``.maxCount`` paging, ``nd-ref=<FDN>`` and
   ``perceived-severity=`` filters). The spec's ``alarmtype=system|network|
   device`` selects the class and **defaults to device when omitted**; only
   the default was exercised live (empty on the lab: ``com.lastIndex -1``, no
   ``com.data``) — ``network`` and ``system`` are exposed as documented but
   unverified.

Alarm shape (``alarms/v1``): ``{AlarmId, AlarmCategory "System", State
Critical|Major|Minor|Warning|Info|Clear, Acknowledge bool, Description,
object_id, object_description ("Device P2 (<uuid>)"), origin_app_id
("capp-infra:DLM"), origin_service_id, event_type (int), events_count,
Created/Updated (epoch ms strings), Events[{EventId, EventSeverity,
Description, Timestamp, EventCategory, alarm_id, Flagging}], AckHist[{CreatedBy,
Description "Ack"|"UnAck", Timestamp}], Notes[{CreatedBy, Description,
Timestamp}]}``. Event shape: ``{EventId, alarm_id, EventSeverity (incl.
"Clear"), EventCategory, Description, Timestamp, object_description,
origin_app_id, event_type}``.

NOT exposed (verified or deliberately left out): the RESTCONF ``PUT
alarm:handle-alarm`` RPC (answers 400 ``"Invalid Input, payload must contain
'type' attribute"`` for every JSON shape tried, so ack/clear on the RTM alarms
is not offered); the ``alarm-manager`` / ``severity-config`` / ``autoclear``
writes; custom syslog/trap event-type definitions; the notification
destinations (``trap-dest`` / ``syslog-dest`` / ``rest-dest``).
"""

from __future__ import annotations

import logging
from typing import Annotated, Any
from urllib.parse import quote

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.crosswork import ALARM_V1, ALARMS, check_alarm_v1, page_envelope, unwrap
from cnc_mcp.emf import (
    EMF_ALARM,
    EMF_HEADERS,
    MAX_COUNT,
    decode_json,
    page_envelope_from,
    page_params,
    strip_prefixes,
)
from cnc_mcp.emf import unwrap as emf_unwrap
from cnc_mcp.errors import PlatformError, format_error, http_error
from cnc_mcp.formatting import ResponseFormat, epoch_iso, finalize, to_json
from cnc_mcp.safety import AppContext, register_tool

logger = logging.getLogger(__name__)

# alarms/v1 (plural): queries and lifecycle.
ALARMS_QUERY = f"{ALARMS}/query"
EVENTS_QUERY = f"{ALARMS}/event/query"
ACK_PATH = f"{ALARMS}/ack"
NOTE_PATH = f"{ALARMS}/note"
CLEAR_PATH = f"{ALARMS}/clear"
# alarm/v1 (singular): settings, catalogue, policies.
SETTINGS_PATH = f"{ALARM_V1}/settings"
GNMI_SETTINGS_PATH = f"{ALARM_V1}/gnmi/settings"
MANAGER_SETTINGS_PATH = f"{ALARM_V1}/manager/settings"
SEVERITY_CONFIG_PATH = f"{ALARM_V1}/severity-config"
RECOMMENDED_ACTION_PATH = f"{ALARM_V1}/recommended-action"
SUPPRESSION_POLICY_PATH = f"{ALARM_V1}/suppressionpolicy"
# EMF RESTCONF fault manager.
RTM_ALARM_PATH = f"{EMF_ALARM}/rtm:alarm"

# The no-limit form: returns EVERY alarm (verified live). ``where`` never matches,
# so get-by-id and search must fetch everything and filter client-side.
ALL_ALARMS_CRITERIA = "select * from alarm"
# Per the notes, the endpoint returns 100 rows without a limit; keep the tool's
# ceiling at that so a page never silently truncates.
EVENTS_MAX_LIMIT = 100

ALARM_STATES = ("Critical", "Major", "Minor", "Warning", "Info", "Clear")
# rtm:alarm ``perceived-severity`` values (restconf_fault_ap_is_7_2_0.json).
RTM_SEVERITIES = ("critical", "major", "minor", "warning", "cleared", "indeterminate")
# rtm:alarm ``alarmtype`` values (same document). The platform defaults to
# ``device`` when the parameter is omitted; only that default is verified live,
# so the tool sends ``alarmtype`` only for the other two.
RTM_ALARM_TYPES = ("device", "network", "system")
RTM_DEFAULT_ALARM_TYPE = "device"
SUPPRESSION_ACTIONS = ("suppressAlarm", "suppressEvent")
MANAGER_KEY_PREFIX = "alarmManager/"
# Markers inside the alarm/v1 400 bodies that mean "no such object" (verified live).
_EVENT_TYPE_MISSING = "eventtype does not exist"
_POLICY_CREATE_FAILED = "failed to create policy rule"
_POLICY_DELETE_FAILED = "failed to delete alarm policy"

# Events listed under an alarm in the get-alarm markdown (the JSON form has them all).
_EVENTS_SHOWN = 10


# --- pure helpers (no I/O) -----------------------------------------------------


def canonical(value: str | None, allowed: tuple[str, ...], what: str) -> str | None:
    """Case-insensitive lookup of ``value`` in ``allowed``; None/empty -> None."""
    if value is None or not value.strip():
        return None
    wanted = value.strip().lower()
    for candidate in allowed:
        if candidate.lower() == wanted:
            return candidate
    raise PlatformError(f"Unknown {what} '{value}'. Use one of: {', '.join(allowed)}.")


def check_query(data: Any, what: str) -> dict[str, Any]:
    """Validate an ``alarms/v1`` query answer (``state`` must be ``Success``)."""
    check_alarm_v1(data, what)
    if isinstance(data, dict) and "state" in data and data["state"] != "Success":
        reason = data.get("Message") or data.get("error") or data.get("message") or data
        raise PlatformError(
            f"{what} failed: state {data['state']}. Platform said: {str(reason)[:300]}"
        )
    return data if isinstance(data, dict) else {}


def check_lifecycle(data: Any, what: str) -> dict[str, Any]:
    """Validate a ``PUT alarms/v1/{ack,note,clear}`` answer; raise on ``state Fail``.

    Verified live: every lifecycle call answers HTTP 200 with ``{"state":
    "Success"|"Fail", "Message": ...}`` — e.g. ``Fail "Alarm was not
    acknowledged, cannot unacknowledge it. "``, ``Fail "No matching alarms were
    found for query:null"``, ``Fail "Alarm is already cleared. "``. The
    singular-base error document (``{"error": "Fail", ...}``) is caught too.
    """
    check_alarm_v1(data, what)
    if not isinstance(data, dict) or "state" not in data:
        raise PlatformError(
            f"{what}: Crosswork did not return a state envelope. Response: {str(data)[:300]}"
        )
    if data["state"] != "Success":
        message = str(data.get("Message") or data.get("message") or "no reason given").strip()
        raise PlatformError(f"{what} failed: {message}")
    return data


def find_alarm(alarms: list[Any], alarm_id: str) -> dict[str, Any] | None:
    """The alarm whose ``AlarmId`` equals ``alarm_id`` (case-insensitive), else None."""
    wanted = alarm_id.strip().lower()
    for alarm in alarms:
        if isinstance(alarm, dict) and str(alarm.get("AlarmId", "")).strip().lower() == wanted:
            return alarm
    return None


def _epoch_int(value: Any) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def _contains(needle: str, *haystacks: Any) -> bool:
    return any(needle in str(h).lower() for h in haystacks if h is not None)


def filter_alarms(
    alarms: list[Any],
    *,
    text: str | None = None,
    state: str | None = None,
    category: str | None = None,
    acknowledged: bool | None = None,
) -> list[dict[str, Any]]:
    """Client-side alarm filters (the platform's ``where`` never matches); newest first."""
    out = [a for a in alarms if isinstance(a, dict)]
    if text and text.strip():
        needle = text.strip().lower()
        out = [
            a for a in out if _contains(needle, a.get("Description"), a.get("object_description"))
        ]
    if state:
        out = [a for a in out if str(a.get("State", "")).lower() == state.lower()]
    if category and category.strip():
        wanted = category.strip().lower()
        out = [a for a in out if str(a.get("AlarmCategory", "")).lower() == wanted]
    if acknowledged is not None:
        out = [a for a in out if bool(a.get("Acknowledge")) is acknowledged]
    out.sort(key=lambda a: _epoch_int(a.get("Updated")), reverse=True)
    return out


def filter_events(
    events: list[Any],
    *,
    severity: str | None = None,
    category: str | None = None,
    text: str | None = None,
) -> list[dict[str, Any]]:
    """Client-side event filters, applied to the page that was fetched."""
    out = [e for e in events if isinstance(e, dict)]
    if severity and severity.strip():
        wanted = severity.strip().lower()
        out = [e for e in out if str(e.get("EventSeverity", "")).lower() == wanted]
    if category and category.strip():
        wanted = category.strip().lower()
        out = [e for e in out if str(e.get("EventCategory", "")).lower() == wanted]
    if text and text.strip():
        needle = text.strip().lower()
        out = [
            e for e in out if _contains(needle, e.get("Description"), e.get("object_description"))
        ]
    return out


def filter_event_types(
    items: list[Any],
    *,
    category: str | None = None,
    name: str | None = None,
    severity: str | None = None,
) -> list[dict[str, Any]]:
    """Client-side filters over the ``severity-config`` catalogue."""
    out = [i for i in items if isinstance(i, dict)]
    if category and category.strip():
        wanted = category.strip().lower()
        out = [i for i in out if str(i.get("defaultCategory", "")).lower() == wanted]
    if name and name.strip():
        needle = name.strip().lower()
        out = [i for i in out if _contains(needle, i.get("name"), i.get("eventTypeName"))]
    if severity and severity.strip():
        wanted = severity.strip().lower()
        out = [i for i in out if str(i.get("severity", "")).lower() == wanted]
    return out


def alarm_line(a: dict[str, Any]) -> str:
    """One search-result line: ``[State] object — Description (id, ack=…, updated=…)``."""
    return (
        f"- [{a.get('State', '?')}] {a.get('object_description') or a.get('object_id') or '?'} "
        f"— {a.get('Description', '?')} ({a.get('AlarmId', '?')}, "
        f"ack={a.get('Acknowledge', '?')}, updated={epoch_iso(a.get('Updated'))})"
    )


def event_line(e: dict[str, Any]) -> str:
    """``[EventSeverity] object — Description (EventId, alarm <id>, <Timestamp iso>)``."""
    return (
        f"- [{e.get('EventSeverity', '?')}] {e.get('object_description') or '?'} "
        f"— {e.get('Description', '?')} ({e.get('EventId', '?')}, "
        f"alarm {e.get('alarm_id') or '-'}, {epoch_iso(e.get('Timestamp'))})"
    )


def _history_line(entry: dict[str, Any]) -> str:
    """An AckHist / Notes entry: ``- <Timestamp iso> <CreatedBy>: <Description>``."""
    return (
        f"- {epoch_iso(entry.get('Timestamp'))} {entry.get('CreatedBy', '?')}: "
        f"{entry.get('Description', '?')}"
    )


def alarm_markdown(a: dict[str, Any]) -> str:
    """Full detail of one alarm including its ack history and notes."""
    lines = [
        f"# Alarm {a.get('AlarmId', '?')}",
        "",
        f"- State: {a.get('State', '?')} (category {a.get('AlarmCategory', '?')})",
        f"- Acknowledged: {a.get('Acknowledge', '?')}",
        f"- Description: {a.get('Description', '?')}",
        f"- Object: {a.get('object_description') or '?'} (object_id {a.get('object_id') or '?'})",
        f"- Origin: {a.get('origin_app_id') or '?'}"
        + (f" / {a['origin_service_id']}" if a.get("origin_service_id") else ""),
        f"- Event type: {a.get('event_type', '?')}",
        f"- Created: {epoch_iso(a.get('Created'))} — Updated: {epoch_iso(a.get('Updated'))}",
    ]
    events = [e for e in (a.get("Events") or []) if isinstance(e, dict)]
    count = a.get("events_count", len(events))
    lines.append(f"- Events: {count}")
    for e in events[:_EVENTS_SHOWN]:
        lines.append(
            f"  - [{e.get('EventSeverity', '?')}] {e.get('Description', '?')} "
            f"({e.get('EventId', '?')}, {epoch_iso(e.get('Timestamp'))})"
        )
    if len(events) > _EVENTS_SHOWN:
        lines.append(f"  - ... {len(events) - _EVENTS_SHOWN} more (response_format='json')")
    hist = [h for h in (a.get("AckHist") or []) if isinstance(h, dict)]
    lines.extend(["", f"## Acknowledgement history ({len(hist)})"])
    if not hist:
        lines.append("- none")
    lines.extend(_history_line(h) for h in hist)
    notes = [n for n in (a.get("Notes") or []) if isinstance(n, dict)]
    lines.extend(["", f"## Notes ({len(notes)})"])
    if not notes:
        lines.append("- none")
    lines.extend(_history_line(n) for n in notes)
    return "\n".join(lines)


def rtm_alarm_line(item: dict[str, Any]) -> str:
    """One EMF (rtm:alarm) alarm, prefixes stripped: ``[severity] node — description (uuid, …)``."""
    a = strip_prefixes(item)
    ident = a.get("alarm-identifier") if isinstance(a.get("alarm-identifier"), dict) else {}
    source = a.get("source-object-name") or a.get("source-object-ref") or ""
    node = a.get("node-ref") or "?"
    where = f"{node} {source}".strip()
    extras = [
        f"category {a['category']}" if a.get("category") else "",
        f"type {a['type']}" if a.get("type") else "",
        f"ack {a['ack-state']}" if a.get("ack-state") else "",
        f"cause {a.get('probable-cause') or ident.get('probable-cause')}"
        if (a.get("probable-cause") or ident.get("probable-cause"))
        else "",
        f"updated {a['system-update-time-iso8601']}" if a.get("system-update-time-iso8601") else "",
    ]
    extras = [x for x in extras if x]
    return (
        f"- [{a.get('perceived-severity', '?')}] {where} — {a.get('description', '?')} "
        f"({a.get('uuid') or ident.get('event-identifier') or '?'}"
        + (f"; {'; '.join(extras)}" if extras else "")
        + ")"
    )


def settings_markdown(retention: dict[str, Any], gnmi: dict[str, Any] | None) -> str:
    """Age-outs/retention, the collection-job switches and the gNMI vendor flags."""
    lines = ["# Alarm settings", "", "## Retention / age-out (values as the platform reports them)"]
    ageout_keys = [
        "deleteOldAlertDays",
        "networkAlertAgeout",
        "systemAlertAgeout",
        "auditAlertAgeout",
        "securityAlertAgeout",
        "nonSecurityAlertAgeout",
        "deleteAllEvents",
    ]
    shown: set[str] = set()
    for key in ageout_keys:
        if key in retention:
            lines.append(f"- {key}: {retention[key]}")
            shown.add(key)
    lines.extend(["", "## Collection jobs"])
    lines.append(
        f"- syslog collection job enabled: {retention.get('syslogCollectionJobEnable', '?')}"
    )
    lines.append(f"- trap collection job enabled: {retention.get('trapCollectionJobEnable', '?')}")
    shown.update({"syslogCollectionJobEnable", "trapCollectionJobEnable"})
    other = {k: v for k, v in retention.items() if k not in shown}
    if other:
        lines.extend(["", "## Other settings"])
        lines.extend(f"- {k}: {v}" for k, v in other.items())
    lines.extend(["", "## gNMI alarm collection (per vendor)"])
    if isinstance(gnmi, dict) and gnmi and "error" not in gnmi:
        lines.extend(f"- {vendor}: {flag}" for vendor, flag in gnmi.items())
    elif isinstance(gnmi, dict) and gnmi.get("error"):
        lines.append(f"- not available: {gnmi['error']}")
    else:
        lines.append("- none reported")
    return "\n".join(lines)


def manager_entries(data: Any) -> list[tuple[str, bool]]:
    """``{"alarmManager/<device type>": bool}`` -> sorted ``[(device type, enabled)]``."""
    if not isinstance(data, dict):
        return []
    entries = []
    for key, value in data.items():
        name = str(key)
        if name.startswith(MANAGER_KEY_PREFIX):
            name = name[len(MANAGER_KEY_PREFIX) :]
        entries.append((name, bool(value)))
    entries.sort(key=lambda e: e[0].lower())
    return entries


def manager_markdown(entries: list[tuple[str, bool]], enabled_only: bool) -> str:
    on = [n for n, flag in entries if flag]
    off = [n for n, flag in entries if not flag]
    lines = [f"# Alarm manager per device type ({len(on)} on, {len(off)} off)", ""]
    if not entries:
        lines.append("No alarm-manager settings returned.")
        return "\n".join(lines)
    lines.append("## Alarm manager ON")
    lines.extend(f"- {n}" for n in on)
    if not on:
        lines.append("- none")
    if enabled_only:
        lines.append("")
        lines.append(f"{len(off)} device type(s) have it off (enabled_only=False lists them).")
    else:
        lines.extend(["", "## Alarm manager OFF"])
        lines.extend(f"- {n}" for n in off)
        if not off:
            lines.append("- none")
    return "\n".join(lines)


def event_type_line(item: dict[str, Any]) -> str:
    """``<name> [<defaultCategory>] severity=<severity> autoclear=<revert> min|never``."""
    revert = item.get("revert")
    autoclear = f"{revert} min" if revert not in (None, "", 0, "0") else "never"
    name = item.get("name") or item.get("eventTypeName") or "?"
    line = f"- {name} [{item.get('defaultCategory', '?')}] severity={item.get('severity', '?')} "
    line += f"autoclear={autoclear}"
    if item.get("eventTypeName") and item.get("eventTypeName") != name:
        line += f" (eventTypeName {item['eventTypeName']})"
    return line


def recommendation_markdown(event_type: str, data: dict[str, Any]) -> str:
    """Explanation + recommended action; a non-empty custom text overrides the default."""
    explanation = data.get("explaination") or data.get("defaultexplaination") or "(none)"
    action = data.get("recommendedaction") or data.get("defaultrecommendedaction") or "(none)"
    custom = bool(data.get("explaination") or data.get("recommendedaction"))
    lines = [
        f"# Event type {event_type}",
        "",
        f"- Explanation: {explanation}",
        f"- Recommended action: {action}",
    ]
    if custom:
        lines.append("- Source: custom text set on this instance (overrides the default)")
        if data.get("defaultexplaination") and data["defaultexplaination"] != explanation:
            lines.append(f"- Default explanation: {data['defaultexplaination']}")
        if data.get("defaultrecommendedaction") and data["defaultrecommendedaction"] != action:
            lines.append(f"- Default recommended action: {data['defaultrecommendedaction']}")
    else:
        lines.append("- Source: platform defaults")
    if data.get("nextstepupdate"):
        lines.append(f"- Next step: {data['nextstepupdate']}")
    return "\n".join(lines)


def policies_markdown(policies: list[dict[str, Any]]) -> str:
    lines = [f"# Alarm suppression policies ({len(policies)})", ""]
    for p in policies:
        groups = p.get("deviceGroups") if isinstance(p.get("deviceGroups"), list) else []
        line = (
            f"- **{p.get('policyname', '?')}** — action {p.get('action', '?')}, "
            f"criteria `{p.get('criteria', '?')}`, device groups: {len(groups)}"
        )
        if p.get("description"):
            line += f" — {p['description']}"
        lines.append(line)
    return "\n".join(lines)


def _more_hint(envelope: dict[str, Any]) -> list[str]:
    if envelope.get("has_more"):
        return ["", f"More available: repeat with page={envelope['next_page']}."]
    return []


def _response_result(data: Any) -> str:
    """The text of an alarm/v1 error body (``responseResult`` / ``Message``), lower-cased."""
    if isinstance(data, dict):
        for key in ("responseResult", "Message", "message"):
            if isinstance(data.get(key), str):
                return data[key].lower()
    return str(data or "").lower()


def _parse_json(response: Any) -> Any:
    try:
        return response.json()
    except ValueError:
        return None


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    async def fetch_all_alarms() -> list[dict[str, Any]]:
        """Every alarm, open and cleared, via the no-limit criteria (verified live)."""
        body = {"openAlarmsOnly": False, "criteria": ALL_ALARMS_CRITERIA}
        data = await client.request_json("POST", ALARMS_QUERY, json_body=body)
        check_query(data, "Alarm query")
        alarms, _, _ = unwrap(data, "alarms")
        return [a for a in alarms if isinstance(a, dict)]

    async def resolve_alarm(alarm_id: str) -> dict[str, Any]:
        """The alarm for ``alarm_id`` or a PlatformError — nothing is written for an unknown id."""
        alarm = find_alarm(await fetch_all_alarms(), alarm_id)
        if alarm is None:
            raise PlatformError(f"no alarm '{alarm_id}' (list with cnc_list_alarms)")
        return alarm

    def platform_id(alarm: dict[str, Any]) -> str:
        """The AlarmId exactly as the platform spells it.

        ``find_alarm`` matches case-insensitively, so every lifecycle PUT is built
        from the resolved record's id — never the caller's spelling — to
        guarantee the write targets the object the pre-flight read found.
        """
        return str(alarm.get("AlarmId", ""))

    def alarm_before(alarm: dict[str, Any]) -> dict[str, Any]:
        return {
            "state": alarm.get("State"),
            "acknowledged": alarm.get("Acknowledge"),
            "description": alarm.get("Description"),
            "object_description": alarm.get("object_description"),
        }

    # --- reads ---------------------------------------------------------------

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_alarm",
        title="Get Alarm",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_alarm(
        alarm_id: Annotated[
            str,
            Field(
                description="AlarmId as shown by cnc_list_alarms / cnc_search_alarms "
                "(e.g. '5b7d0a2e-3c1f-4e8a-9b6d-2f1e0c9a8b7d').",
                min_length=1,
                max_length=200,
            ),
        ],
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get one Crosswork platform alarm by AlarmId, with its events, acknowledgement
        history (AckHist) and notes.

        Read-only. Use it to inspect an alarm before acknowledging, annotating or
        clearing it, or to confirm the acknowledge flag settled after a write.
        COST: the alarms API has no working per-id lookup ('where' clauses never
        match, verified live), so this tool sends the no-limit criteria
        'select * from alarm' with openAlarmsOnly=false — one call that returns
        EVERY alarm, open and cleared (99 rows on the lab; can be large and slow on
        a busy instance) — and finds the id client-side. Cleared alarms are found
        too. For device/network (RTM) alarms use cnc_list_device_alarms instead.

        Args:
            alarm_id: the AlarmId (exact, case-insensitive).

        Returns:
            str: Markdown with state, category, acknowledged flag, description,
            object, origin, created/updated (ISO-8601 from the platform's epoch
            ms), the events (first 10), the AckHist entries and the Notes; or the
            raw alarm JSON:
            {"AlarmId", "AlarmCategory", "State", "Acknowledge", "Description",
             "object_id", "object_description", "origin_app_id", "origin_service_id",
             "event_type", "events_count", "Created", "Updated", "Events": [...],
             "AckHist": [{"CreatedBy", "Description": "Ack"|"UnAck", "Timestamp"}],
             "Notes": [{"CreatedBy", "Description", "Timestamp"}]}
            "Error: no alarm '<id>' (list with cnc_list_alarms)" when nothing
            matches; other failures: "Error: <actionable message>".
        """
        try:
            alarm = await resolve_alarm(alarm_id)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(alarm), settings)
            return finalize(alarm_markdown(alarm), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_search_alarms",
        title="Search Alarms",
        read_only=True,
        idempotent=True,
    )
    async def cnc_search_alarms(
        text: Annotated[
            str | None,
            Field(
                description="Case-insensitive substring matched against Description and "
                "object_description (e.g. 'unreachable', 'P2').",
                max_length=500,
            ),
        ] = None,
        state: Annotated[
            str | None,
            Field(
                description="Alarm state to keep: Critical, Major, Minor, Warning, Info or Clear "
                "(case-insensitive, e.g. 'Critical').",
                max_length=20,
            ),
        ] = None,
        category: Annotated[
            str | None,
            Field(
                description="Exact AlarmCategory to keep, case-insensitive (e.g. 'System').",
                max_length=100,
            ),
        ] = None,
        acknowledged: Annotated[
            bool | None,
            Field(description="True for acknowledged alarms only, False for unacknowledged only."),
        ] = None,
        open_only: Annotated[
            bool,
            Field(description="True (default) for open alarms only; False to include cleared."),
        ] = True,
        limit: Annotated[
            int, Field(description="Maximum alarms to return (e.g. 50).", ge=1, le=500)
        ] = 50,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Search Crosswork platform alarms by text, state, category and
        acknowledged flag; newest Updated first.

        Read-only. Use it for "which alarms mention P2", "all unacknowledged
        Critical alarms", "cleared alarms about collection" — questions
        cnc_list_alarms (plain paging) cannot answer. WHY CLIENT-SIDE: the alarms
        API's SQL-like criteria accepts 'where' and 'order by' clauses but a
        'where' never matches (0 rows for any field) and 'order by' is ignored
        (verified live), so the tool sends the no-limit criteria
        'select * from alarm' — one call returning every alarm in scope (open, or
        open+cleared) — and filters, sorts and caps the result itself. Expect that
        call to be slower on an instance with thousands of alarms. For
        device/network (RTM) alarms use cnc_list_device_alarms.

        Args:
            text: substring over Description / object_description.
            state: Critical|Major|Minor|Warning|Info|Clear (Clear only with open_only=False).
            category: exact AlarmCategory (e.g. 'System').
            acknowledged: True / False to keep only that flag; None for both.
            open_only: False to include cleared alarms.
            limit: cap on the returned rows (the count of all matches is reported).

        Returns:
            str: Markdown, one line per alarm
            "[State] object_description — Description (AlarmId, ack=…, updated=…)",
            or JSON: {"total": <matches>, "count": int, "items": [<alarm>, ...],
            "truncated": bool, "fetched": <alarms fetched before filtering>}.
            No match is not an error ("No alarms matched ..."). On failure:
            "Error: <actionable message>".
        """
        try:
            wanted_state = canonical(state, ALARM_STATES, "alarm state")
            body = {"openAlarmsOnly": open_only, "criteria": ALL_ALARMS_CRITERIA}
            data = await client.request_json("POST", ALARMS_QUERY, json_body=body)
            check_query(data, "Alarm query")
            alarms, _, _ = unwrap(data, "alarms")
            matches = filter_alarms(
                alarms,
                text=text,
                state=wanted_state,
                category=category,
                acknowledged=acknowledged,
            )
            items = matches[:limit]
            if response_format is ResponseFormat.JSON:
                return finalize(
                    to_json(
                        {
                            "total": len(matches),
                            "count": len(items),
                            "items": items,
                            "truncated": len(matches) > limit,
                            "fetched": len(alarms),
                        }
                    ),
                    settings,
                )
            scope = "open only" if open_only else "open and cleared"
            lines = [
                f"# Alarms matching ({len(items)} shown of {len(matches)} matches, "
                f"{len(alarms)} fetched, {scope})",
                "",
            ]
            if not items:
                lines.append("No alarms matched the filters.")
            lines.extend(alarm_line(a) for a in items)
            if len(matches) > limit:
                lines.extend(["", f"{len(matches) - limit} more matched; raise limit or narrow."])
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_events",
        title="List Events",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_events(
        limit: Annotated[
            int, Field(description="Events per page (e.g. 50).", ge=1, le=EVENTS_MAX_LIMIT)
        ] = 50,
        page: Annotated[int, Field(description="0-based page number (e.g. 0).", ge=0)] = 0,
        severity: Annotated[
            str | None,
            Field(
                description="EventSeverity to keep, case-insensitive (e.g. 'Major', 'Clear'). "
                "Applied client-side within the fetched page.",
                max_length=20,
            ),
        ] = None,
        category: Annotated[
            str | None,
            Field(
                description="EventCategory to keep, case-insensitive (e.g. 'System'). "
                "Applied client-side within the fetched page.",
                max_length=100,
            ),
        ] = None,
        text: Annotated[
            str | None,
            Field(
                description="Case-insensitive substring over Description / object_description "
                "(e.g. 'unreachable'). Applied client-side within the fetched page.",
                max_length=500,
            ),
        ] = None,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List Crosswork platform events (the raw occurrences that alarms are
        built from, including 'Clear' events), paged as the platform orders them.

        Read-only. Use it to see what happened around an alarm, or to trace the
        events of an alarm by its alarm_id. Paging is the platform's
        ('select * from event limit N page M'); the severity/category/text filters
        are applied CLIENT-SIDE WITHIN THE FETCHED PAGE (the criteria grammar's
        'where' answers an empty document, verified live), so a filtered page can
        come back short or empty while later pages still hold matches — 'has_more'
        refers to the unfiltered page, keep paging.

        Args:
            limit / page: platform page size (max 100) and 0-based page.
            severity / category / text: filters within the page.

        Returns:
            str: Markdown "[EventSeverity] object_description — Description
            (EventId, alarm <alarm_id>, <Timestamp ISO>)" lines, or JSON:
            {"total": null, "count": <after filtering>, "page": int, "page_size": int,
             "fetched": <rows in the page>, "items": [{"EventId", "alarm_id",
             "EventSeverity", "EventCategory", "Description", "Timestamp",
             "object_description", "origin_app_id", "event_type"}, ...],
             "has_more": bool, "next_page": int|null}
            On failure: "Error: <actionable message>".
        """
        try:
            body = {"criteria": f"select * from event limit {limit} page {page}"}
            data = await client.request_json("POST", EVENTS_QUERY, json_body=body)
            check_query(data, "Event query")
            events, _, _ = unwrap(data, "events")
            fetched = [e for e in events if isinstance(e, dict)]
            items = filter_events(fetched, severity=severity, category=category, text=text)
            envelope = page_envelope(
                fetched, result_count=None, total_count=None, page_size=limit, page=page
            )
            envelope["items"] = items
            envelope["count"] = len(items)
            envelope["fetched"] = len(fetched)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(envelope), settings)
            lines = [
                f"# Events ({len(items)} shown of {len(fetched)} in page {page})",
                "",
            ]
            if not fetched:
                lines.append("No events returned.")
            elif not items:
                lines.append("No events in this page matched the filters (later pages may).")
            lines.extend(event_line(e) for e in items)
            lines.extend(_more_hint(envelope))
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_device_alarms",
        title="List Device Alarms",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_device_alarms(
        node_fdn: Annotated[
            str | None,
            Field(
                description="Node FDN to filter on (nd-ref), as the EMF inventory reports it "
                "(e.g. 'MD=CISCO_EMS!ND=PE1').",
                max_length=500,
            ),
        ] = None,
        severity: Annotated[
            str | None,
            Field(
                description="perceived-severity to filter on: critical, major, minor, warning, "
                "cleared or indeterminate (e.g. 'major').",
                max_length=20,
            ),
        ] = None,
        alarm_type: Annotated[
            str,
            Field(
                description="Alarm class to list: 'device' (default, the platform's own default "
                "and the only value verified live), 'network' or 'system' (documented "
                "alarmtype values, not verified on a live instance). E.g. 'device'.",
                max_length=20,
            ),
        ] = RTM_DEFAULT_ALARM_TYPE,
        limit: Annotated[
            int, Field(description="Alarms per page, max 100 (e.g. 50).", ge=1, le=MAX_COUNT)
        ] = 50,
        offset: Annotated[
            int, Field(description="0-based object offset (.startIndex), e.g. 0.", ge=0)
        ] = 0,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List DEVICE alarms (by default) from the EMF fault manager (RESTCONF
        rtm:alarm): syslog/trap/gNMI-derived alarms such as OSPF adjacency down,
        interface down, or environmental faults on managed devices.

        Read-only. This is the RESTCONF fault API
        (/crosswork/alarm/restconf/data/v2/rtm:alarm); Crosswork's own SYSTEM
        alarms (reachability, collection, application health) live in
        cnc_list_alarms / cnc_search_alarms, not here. Sends exactly
        'Accept: application/json' with .startIndex/.maxCount paging (the EMF
        dialect; anything else makes the service answer XML) plus nd-ref /
        perceived-severity filters when given. SCOPE: the API's alarmtype
        parameter (system | network | device) defaults to device when omitted,
        so without alarm_type this tool lists device alarms ONLY. alarm_type
        'network' / 'system' sends alarmtype=<value> as documented in the 7.2
        spec but has NOT been verified on a live instance (the lab had no EMF
        alarms of any class: com.lastIndex -1), so the item rendering follows
        the documented alm.* shape. Acknowledging or clearing these alarms is
        NOT offered: the RESTCONF alarm:handle-alarm RPC could not be driven
        (400 "payload must contain 'type' attribute" for every shape tried).

        Args:
            node_fdn: nd-ref FDN filter (from the EMF inventory's nd.fdn).
            severity: perceived-severity filter (lower-case wire values).
            alarm_type: device (default, verified) | network | system (unverified).
            limit / offset: EMF page size (1..100) and 0-based start index.

        Returns:
            str: Markdown "[severity] node source — description (uuid; category;
            type; ack; cause; updated)" lines, or JSON:
            {"total": null, "count": int, "offset": int, "items": [<alm.* object>, ...],
             "has_more": bool, "next_offset": int|null, "first_index", "last_index",
             "iterator_id", "start_index", "max_count", "next_start_index"}
            An empty page is not an error: "No <alarm_type> alarms are reported
            by the EMF fault manager." "Error: Unknown alarm type '<x>'. Use one
            of: device, network, system." for a bad alarm_type (nothing sent);
            other failures: "Error: <actionable message>".
        """
        try:
            wanted = canonical(severity, RTM_SEVERITIES, "perceived severity")
            wanted_type = (
                canonical(alarm_type, RTM_ALARM_TYPES, "alarm type") or RTM_DEFAULT_ALARM_TYPE
            )
            params: dict[str, Any] = dict(page_params(offset, limit))
            if node_fdn and node_fdn.strip():
                params["nd-ref"] = node_fdn.strip()
            if wanted:
                params["perceived-severity"] = wanted
            # Omitted for the default so the verified request stays byte-identical;
            # the platform itself defaults to device alarms.
            if wanted_type != RTM_DEFAULT_ALARM_TYPE:
                params["alarmtype"] = wanted_type
            response = await client.request(
                "GET", RTM_ALARM_PATH, headers=EMF_HEADERS, params=params
            )
            data = decode_json(response.text)
            items, header = emf_unwrap(data)
            envelope = page_envelope_from(items, header, offset, limit)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(envelope), settings)
            if not items:
                filters = []
                if node_fdn:
                    filters.append(f"node {node_fdn}")
                if wanted:
                    filters.append(f"severity {wanted}")
                suffix = f" (filters: {', '.join(filters)})" if filters else ""
                if offset:
                    suffix += f" at offset {offset}"
                return finalize(
                    f"No {wanted_type} alarms are reported by the EMF fault manager{suffix}.",
                    settings,
                )
            lines = [
                f"# {wanted_type.capitalize()} alarms ({len(items)} shown from offset {offset})",
                "",
            ]
            lines.extend(rtm_alarm_line(i) for i in items if isinstance(i, dict))
            if envelope.get("has_more"):
                lines.extend(["", f"More available: repeat with offset={envelope['next_offset']}."])
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_alarm_settings",
        title="Get Alarm Settings",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_alarm_settings(
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the fault-management settings: alarm/event retention and age-out
        values, whether the syslog and trap collection jobs are enabled, and the
        per-vendor gNMI alarm-collection flags.

        Read-only. Use it to explain why old alarms disappeared (age-outs) or why
        no device alarms arrive (collection jobs / gNMI collection off). Reads
        GET /crosswork/alarm/v1/settings and GET .../gnmi/settings; a failure of
        the gNMI read is reported inside the result rather than failing the call.
        Age-out values are shown as the platform reports them (their unit is not
        documented on the wire).

        Returns:
            str: Markdown sections (retention/age-out, collection jobs, gNMI), or JSON:
            {"retention": {"deleteOldAlertDays", "networkAlertAgeout", "systemAlertAgeout",
                           "auditAlertAgeout", "securityAlertAgeout", "nonSecurityAlertAgeout",
                           "syslogCollectionJobEnable": bool, "trapCollectionJobEnable": bool,
                           "deleteAllEvents": bool},
             "gnmi": {"<vendor>": bool, ...} | {"error": str}}
            On failure: "Error: <actionable message>".
        """
        try:
            retention = await client.request_json("GET", SETTINGS_PATH)
            check_alarm_v1(retention, "Alarm settings read")
            if not isinstance(retention, dict):
                raise PlatformError(
                    f"Alarm settings read: unexpected response shape: {str(retention)[:300]}"
                )
            try:
                gnmi = await client.request_json("GET", GNMI_SETTINGS_PATH)
                check_alarm_v1(gnmi, "gNMI alarm settings read")
                if not isinstance(gnmi, dict):
                    gnmi = {"error": f"unexpected response shape: {str(gnmi)[:200]}"}
            except PlatformError as e:
                logger.warning("gnmi/settings read failed: %s", e)
                gnmi = {"error": str(e)}
            if response_format is ResponseFormat.JSON:
                return finalize(to_json({"retention": retention, "gnmi": gnmi}), settings)
            return finalize(settings_markdown(retention, gnmi), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_alarm_manager_settings",
        title="Get Alarm Manager Settings",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_alarm_manager_settings(
        enabled_only: Annotated[
            bool,
            Field(
                description="True to list only device types with the alarm manager on "
                "(the off count is still reported)."
            ),
        ] = False,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get the per-device-type alarm manager switches — which device types
        Crosswork raises device alarms for.

        Read-only. Use it when device alarms are missing for a platform family:
        the alarm manager may simply be off for that type. Reads
        GET /crosswork/alarm/v1/manager/settings, which answers
        {"alarmManager/<device type>": bool, ...} (dozens of keys).

        Args:
            enabled_only: True lists only the enabled device types.

        Returns:
            str: Markdown listing device types with the alarm manager on (and,
            unless enabled_only, the ones with it off; the off count is always
            given), or the raw JSON {"alarmManager/<device type>": bool, ...}
            (filtered to true values when enabled_only).
            On failure: "Error: <actionable message>".
        """
        try:
            data = await client.request_json("GET", MANAGER_SETTINGS_PATH)
            check_alarm_v1(data, "Alarm manager settings read")
            if not isinstance(data, dict):
                raise PlatformError(
                    f"Alarm manager settings read: unexpected response shape: {str(data)[:300]}"
                )
            entries = manager_entries(data)
            if response_format is ResponseFormat.JSON:
                raw = {k: v for k, v in data.items() if not enabled_only or bool(v)}
                return finalize(to_json(raw), settings)
            return finalize(manager_markdown(entries, enabled_only), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_event_types",
        title="List Event Types",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_event_types(
        category: Annotated[
            str | None,
            Field(
                description="Exact defaultCategory to keep, case-insensitive (e.g. 'BGP', "
                "'Interface'). Applied client-side.",
                max_length=100,
            ),
        ] = None,
        name: Annotated[
            str | None,
            Field(
                description="Case-insensitive substring of the event type name "
                "(e.g. 'ADJCHANGE'). Applied client-side.",
                max_length=200,
            ),
        ] = None,
        severity: Annotated[
            str | None,
            Field(
                description="Exact severity to keep, case-insensitive (e.g. 'Major'). "
                "Applied client-side.",
                max_length=20,
            ),
        ] = None,
        limit: Annotated[
            int, Field(description="Event types per page (e.g. 100).", ge=1, le=500)
        ] = 100,
        page: Annotated[int, Field(description="0-based page number (e.g. 0).", ge=0)] = 0,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the event-type catalogue: every syslog/trap/gNMI event type
        Crosswork knows, with its default category, severity and auto-clear
        (revert) interval.

        Read-only. Use it to find the exact event type names for a suppression
        policy criteria ('eventType in [BGP-5-ADJCHANGE_DOWN]') or for
        cnc_get_event_type_recommendation, and to answer "does X auto-clear?"
        — GET severity-config and GET autoclear return the SAME catalogue
        (verified live), so this one tool answers both the severity and the
        auto-clear questions. The whole catalogue (hundreds of entries) is
        fetched in one call and filtered/paged client-side.

        Args:
            category / name / severity: client-side filters.
            limit / page: client-side paging over the filtered catalogue.

        Returns:
            str: Markdown "<name> [<defaultCategory>] severity=<severity>
            autoclear=<revert> min|never" lines, or JSON:
            {"total": int, "count": int, "page": int, "page_size": int,
             "items": [{"name", "eventTypeName", "defaultCategory", "severity",
                        "revert": "<minutes>"?}, ...],
             "has_more": bool, "next_page": int|null, "collection_total": int}
            On failure: "Error: <actionable message>".
        """
        try:
            data = await client.request_json("GET", SEVERITY_CONFIG_PATH)
            check_alarm_v1(data, "Event type catalogue read")
            items, _, _ = unwrap(data, "items")
            catalogue = [i for i in items if isinstance(i, dict)]
            matches = filter_event_types(catalogue, category=category, name=name, severity=severity)
            start = page * limit
            shown = matches[start : start + limit]
            envelope = page_envelope(
                shown,
                result_count=len(matches),
                total_count=len(catalogue),
                page_size=limit,
                page=page,
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(envelope), settings)
            lines = [
                f"# Event types ({len(shown)} shown of {len(matches)} matching, "
                f"{len(catalogue)} in the catalogue)",
                "",
            ]
            if not shown:
                lines.append("No event types matched.")
            lines.extend(event_type_line(i) for i in shown)
            lines.extend(_more_hint(envelope))
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_event_type_recommendation",
        title="Get Event Type Recommendation",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_event_type_recommendation(
        event_type: Annotated[
            str,
            Field(
                description="Event type name exactly as listed by cnc_list_event_types "
                "(e.g. 'BGP-5-ADJCHANGE_DOWN').",
                min_length=1,
                max_length=200,
            ),
        ],
    ) -> str:
        """Get the explanation and recommended action for an event type (what the
        event means and what an operator should do about it).

        Read-only. Use it when an alarm or event names an event type and the agent
        needs to explain or triage it. Reads
        GET /crosswork/alarm/v1/recommended-action?eventType=<name>; a custom
        explanation / recommended action set on this instance overrides the
        platform default when non-empty (both are shown when they differ).

        Args:
            event_type: exact catalogue name (find it with cnc_list_event_types).

        Returns:
            str: Markdown with the explanation, the recommended action, whether the
            text is custom or default, and any next-step note.
            "Error: no event type '<x>' (find names with cnc_list_event_types)"
            when the platform answers 400 "EventType does not exist"; other
            failures: "Error: <actionable message>".
        """
        try:
            name = event_type.strip()
            response = await client.request(
                "GET", RECOMMENDED_ACTION_PATH, params={"eventType": name}, raise_on_error=False
            )
            body = _parse_json(response)
            if response.status_code == 400 and _EVENT_TYPE_MISSING in _response_result(body):
                raise PlatformError(
                    f"no event type '{name}' (find names with cnc_list_event_types)"
                )
            if not response.is_success:
                raise http_error(response)
            check_alarm_v1(body, "Recommended action read")
            if not isinstance(body, dict):
                raise PlatformError(
                    f"Recommended action read: unexpected response shape: {str(body)[:300]}"
                )
            return finalize(recommendation_markdown(name, body), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_alarm_suppression_policies",
        title="List Alarm Suppression Policies",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_alarm_suppression_policies(
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the alarm suppression policies — rules that drop alarms or events
        matching an event-type criteria, optionally scoped to device groups.

        Read-only. Use it to explain why an expected alarm never appeared, and
        before creating a policy (names must be unique). Reads
        GET /crosswork/alarm/v1/suppressionpolicy.

        Returns:
            str: Markdown, one line per policy (name, action, criteria, device
            group count, description), or JSON:
            {"count": int,
             "items": [{"policyname": str, "description": str,
                        "action": "suppressAlarm"|"suppressEvent",
                        "deviceGroups": [str, ...], "criteria": str,
                        "inputType": str}, ...]}
            "No alarm suppression policies are configured." when there are none.
            On failure: "Error: <actionable message>".
        """
        try:
            data = await client.request_json("GET", SUPPRESSION_POLICY_PATH)
            check_alarm_v1(data, "Suppression policy read")
            policies, _, _ = unwrap(data, "data")
            policies = [p for p in policies if isinstance(p, dict)]
            if response_format is ResponseFormat.JSON:
                return finalize(to_json({"count": len(policies), "items": policies}), settings)
            if not policies:
                return finalize("No alarm suppression policies are configured.", settings)
            return finalize(policies_markdown(policies), settings)
        except Exception as e:
            return format_error(e)

    # --- writes --------------------------------------------------------------

    @register_tool(
        mcp,
        ctx,
        name="cnc_acknowledge_alarm",
        title="Acknowledge Alarm",
        read_only=False,
        # Not idempotent: the platform records every accepted call (AckHist), and
        # whether a repeated ack is a no-op or a second entry is unverified.
        idempotent=False,
    )
    async def cnc_acknowledge_alarm(
        alarm_id: Annotated[
            str,
            Field(
                description="AlarmId to acknowledge (e.g. '5b7d0a2e-3c1f-4e8a-9b6d-2f1e0c9a8b7d').",
                min_length=1,
                max_length=200,
            ),
        ],
        acknowledge: Annotated[
            bool,
            Field(description="True (default) to acknowledge, False to un-acknowledge."),
        ] = True,
        note: Annotated[
            str | None,
            Field(
                description="Optional note recorded with the acknowledgement "
                "(e.g. 'Ticket INC-1234 opened').",
                max_length=1000,
            ),
        ] = None,
    ) -> str:
        """Acknowledge (or un-acknowledge) a Crosswork platform alarm.

        Write. The alarm is resolved first (the same whole-collection read as
        cnc_get_alarm), so an unknown id fails WITHOUT sending the write, and the
        PUT carries the platform's own spelling of the AlarmId (the match is
        case-insensitive). Then PUT /crosswork/alarms/v1/ack {"alarmId", "ack",
        "note"?} is sent. VERIFIED LIVE: a Success answer carries the user name
        as Message; un-acknowledging an alarm that is not acknowledged answers
        HTTP 200 with state "Fail" and "Alarm was not acknowledged, cannot
        unacknowledge it." — so when the pre-flight read shows the alarm
        unacknowledged, this tool refuses an un-ack WITHOUT sending it; an
        unknown id on the platform side answers Fail "No matching alarms were
        found". The flag is ASYNCHRONOUS: it settles 1-3 s after the Success
        answer, so an immediate cnc_get_alarm may still show the old value —
        re-read after a moment (and if an un-ack right after an ack is refused
        for that reason, wait a few seconds and retry). NOT VERIFIED LIVE:
        whether acknowledging an already-acknowledged alarm succeeds, fails, or
        adds a second AckHist entry — check "before.acknowledged" in the result
        (or cnc_get_alarm first) instead of re-sending blindly; the tool is
        therefore not marked idempotent. A lost answer (transport error, 5xx) is
        NOT auto-retried because each accepted call is recorded in the alarm's
        AckHist: on "may already have been applied", re-read with cnc_get_alarm
        before repeating.

        Args:
            alarm_id: the AlarmId (exact, case-insensitive).
            acknowledge: True to ack, False to un-ack.
            note: optional note.

        Returns:
            str: "Alarm <id> acknowledged|un-acknowledged. The flag settles within
            a few seconds; re-read with cnc_get_alarm." followed by JSON
            {"alarm_id" (the platform's spelling), "acknowledge", "note",
             "before": {"state", "acknowledged", "description", "object_description"},
             "response": {"state": "Success", "Message": "<user>"}}.
            "Error: no alarm '<id>' (list with cnc_list_alarms)" (nothing written);
            "Error: alarm <id> is not acknowledged ... cannot be un-acknowledged"
            (nothing written; re-read and retry if it was acknowledged moments
            ago); "Error: Acknowledge alarm <id> failed: <platform Message>" for a
            state-Fail answer; "Error: Could not reach the platform ... may already
            have been applied" for a lost answer; other failures:
            "Error: <actionable message>".
        """
        try:
            alarm = await resolve_alarm(alarm_id)
            alarm_id = platform_id(alarm)
            if not acknowledge and not bool(alarm.get("Acknowledge")):
                raise PlatformError(
                    f"alarm {alarm_id} is not acknowledged (per the pre-flight read), so it "
                    "cannot be un-acknowledged — the platform refuses this with 'Alarm was "
                    "not acknowledged, cannot unacknowledge it.' If it was acknowledged "
                    "moments ago the flag settles within a few seconds: re-read with "
                    "cnc_get_alarm and retry."
                )
            body: dict[str, Any] = {"alarmId": alarm_id, "ack": acknowledge}
            if note and note.strip():
                body["note"] = note.strip()
            # retryable=False: every accepted ack/un-ack is recorded in AckHist, so a
            # re-send after a lost answer could record it twice (CLAUDE.md wire safety).
            data = await client.request_json("PUT", ACK_PATH, json_body=body, retryable=False)
            what = f"{'Acknowledge' if acknowledge else 'Un-acknowledge'} alarm {alarm_id}"
            check_lifecycle(data, what)
            verb = "acknowledged" if acknowledge else "un-acknowledged"
            result = {
                "alarm_id": alarm_id,
                "acknowledge": acknowledge,
                "note": body.get("note"),
                "before": alarm_before(alarm),
                "response": data,
            }
            return finalize(
                f"Alarm {alarm_id} {verb}. The flag settles within a few seconds; re-read with "
                f"cnc_get_alarm.\n\n{to_json(result)}",
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_annotate_alarm",
        title="Annotate Alarm",
        read_only=False,
        idempotent=False,
    )
    async def cnc_annotate_alarm(
        alarm_id: Annotated[
            str,
            Field(
                description="AlarmId to annotate (e.g. '5b7d0a2e-3c1f-4e8a-9b6d-2f1e0c9a8b7d').",
                min_length=1,
                max_length=200,
            ),
        ],
        note: Annotated[
            str,
            Field(
                description="Note text to attach (e.g. 'Root cause: fibre cut, ETA 2h').",
                min_length=1,
                max_length=1000,
            ),
        ],
    ) -> str:
        """Add a note to a Crosswork platform alarm.

        Write. The alarm is resolved first (whole-collection read), so an unknown
        id fails WITHOUT sending the write, and the PUT carries the platform's own
        spelling of the AlarmId (the match is case-insensitive); then
        PUT /crosswork/alarms/v1/note {"alarmId", "note"} is sent. NOTES ARE
        PERMANENT: there is no API to edit or delete one (verified live), and
        every call appends a new entry, so this tool is not idempotent. For that
        reason the PUT is NOT auto-retried by the client: a transport error or
        5xx after the platform may have stored the note is reported as
        "Could not reach the platform ... may already have been applied" — check
        cnc_get_alarm's Notes before re-running rather than re-sending blindly.

        Args:
            alarm_id: the AlarmId (exact, case-insensitive).
            note: the text (1..1000 characters).

        Returns:
            str: "Note added to alarm <id> (notes are permanent)." followed by JSON
            {"alarm_id" (the platform's spelling), "note", "before": {...},
             "response": {"state": "Success", "Message": ...}}.
            "Error: The note must not be blank." (nothing read or written);
            "Error: no alarm '<id>' (list with cnc_list_alarms)" (nothing written);
            "Error: Annotate alarm <id> failed: <platform Message>" for a state-Fail
            answer; "Error: Could not reach the platform ... may already have been
            applied" for a lost answer; other failures: "Error: <actionable message>".
        """
        try:
            text = note.strip()
            if not text:
                raise PlatformError("The note must not be blank.")
            alarm = await resolve_alarm(alarm_id)
            alarm_id = platform_id(alarm)
            body = {"alarmId": alarm_id, "note": text}
            # retryable=False: notes are permanent and a re-send after a lost
            # answer would append a second copy (CLAUDE.md wire safety).
            data = await client.request_json("PUT", NOTE_PATH, json_body=body, retryable=False)
            check_lifecycle(data, f"Annotate alarm {alarm_id}")
            result = {
                "alarm_id": alarm_id,
                "note": body["note"],
                "before": alarm_before(alarm),
                "response": data,
            }
            return finalize(
                f"Note added to alarm {alarm_id} (notes are permanent).\n\n{to_json(result)}",
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_clear_alarm",
        title="Clear Alarm",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_clear_alarm(
        alarm_id: Annotated[
            str,
            Field(
                description="AlarmId to clear (e.g. '5b7d0a2e-3c1f-4e8a-9b6d-2f1e0c9a8b7d').",
                min_length=1,
                max_length=200,
            ),
        ],
        note: Annotated[
            str | None,
            Field(
                description="Optional note recorded with the clear (e.g. 'Cleared after fix').",
                max_length=1000,
            ),
        ] = None,
    ) -> str:
        """Manually clear a Crosswork platform alarm (state -> Clear; it leaves the
        open-alarm list).

        Write, destructive: clearing hides a condition the platform may still be
        observing — prefer acknowledging unless the cause is fixed. The alarm is
        resolved first (whole-collection read), so an unknown id fails WITHOUT
        sending the write, and the PUT carries the platform's own spelling of the
        AlarmId (the match is case-insensitive); then
        PUT /crosswork/alarms/v1/clear {"alarmId", "note"?} is sent. Clearing an
        already-cleared alarm answers state "Fail" with "Alarm is already
        cleared." and is reported as an error (the alarm is nevertheless cleared,
        so a repeat is harmless). Because the platform refuses a second clear
        rather than applying it twice, the client's PUT auto-retry is kept: if
        the first attempt was lost after it landed, the retry reports that
        "already cleared" error — confirm with cnc_get_alarm.

        Args:
            alarm_id: the AlarmId (exact, case-insensitive).
            note: optional note.

        Returns:
            str: "Alarm <id> cleared." followed by JSON {"alarm_id" (the
            platform's spelling), "note", "before": {...},
            "response": {"state": "Success", "Message": ...}}.
            "Error: no alarm '<id>' (list with cnc_list_alarms)" (nothing written);
            "Error: Clear alarm <id> failed: Alarm is already cleared." when it
            was already cleared; other failures: "Error: <actionable message>".
        """
        try:
            alarm = await resolve_alarm(alarm_id)
            alarm_id = platform_id(alarm)
            body: dict[str, Any] = {"alarmId": alarm_id}
            if note and note.strip():
                body["note"] = note.strip()
            # Default PUT auto-retry kept on purpose: a clear that already landed is
            # refused by the platform ("Alarm is already cleared."), never applied twice.
            data = await client.request_json("PUT", CLEAR_PATH, json_body=body)
            check_lifecycle(data, f"Clear alarm {alarm_id}")
            result = {
                "alarm_id": alarm_id,
                "note": body.get("note"),
                "before": alarm_before(alarm),
                "response": data,
            }
            return finalize(f"Alarm {alarm_id} cleared.\n\n{to_json(result)}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_create_alarm_suppression_policy",
        title="Create Alarm Suppression Policy",
        read_only=False,
        idempotent=False,
    )
    async def cnc_create_alarm_suppression_policy(
        name: Annotated[
            str,
            Field(
                description="Unique policy name (e.g. 'suppress-bgp-flaps').",
                min_length=1,
                max_length=200,
            ),
        ],
        criteria: Annotated[
            str,
            Field(
                description="Event-type criteria, e.g. 'eventType in [BGP-5-ADJCHANGE_DOWN]' "
                "or 'eventType in [A,B]' (names from cnc_list_event_types).",
                min_length=1,
                max_length=2000,
            ),
        ],
        action: Annotated[
            str,
            Field(
                description="'suppressAlarm' (default: drop the alarm) or 'suppressEvent' "
                "(drop the event too)."
            ),
        ] = "suppressAlarm",
        description: Annotated[
            str,
            Field(
                description="Free-text description (e.g. 'Planned maintenance').", max_length=1000
            ),
        ] = "",
        device_groups: Annotated[
            str,
            Field(
                description="Comma-separated device-group UUIDs to scope the policy to; empty "
                "(default) for all devices (e.g. 'uuid-1,uuid-2').",
                max_length=4000,
            ),
        ] = "",
    ) -> str:
        """Create an alarm suppression policy that drops alarms (or events)
        matching an event-type criteria, optionally only for some device groups.

        Write. Sends POST /crosswork/alarm/v1/suppressionpolicy {"policyname",
        "description", "action", "deviceGroups": [...], "criteria"}. Names must
        be unique: a duplicate is answered HTTP 400 {"Message": "Failed to create
        policy rule <name>", "status": "Failed"} — the same answer the platform
        gives for any rejected rule, so the error carries the hint that the name
        may already exist (check cnc_list_alarm_suppression_policies). Not
        idempotent: a repeat with the same name fails rather than duplicating.

        Args:
            name: unique policy name.
            criteria: e.g. 'eventType in [BGP-5-ADJCHANGE_DOWN]'.
            action: 'suppressAlarm' | 'suppressEvent'.
            description: free text.
            device_groups: comma-separated group UUIDs (empty = all devices).

        Returns:
            str: "Suppression policy '<name>' created." followed by JSON
            {"policy": {<body sent>}, "response": {"Message": "Success", "status": "Success"}}.
            "Error: API request failed with status 400 ... Failed to create policy
            rule <name> Hint: a policy with that name may already exist ..." on a
            rejected rule; other failures: "Error: <actionable message>".
        """
        try:
            wire_action = canonical(action, SUPPRESSION_ACTIONS, "suppression action")
            groups = [g.strip() for g in device_groups.split(",") if g.strip()]
            body = {
                "policyname": name.strip(),
                "description": description.strip(),
                "action": wire_action,
                "deviceGroups": groups,
                "criteria": criteria.strip(),
            }
            response = await client.request(
                "POST", SUPPRESSION_POLICY_PATH, json_body=body, raise_on_error=False
            )
            data = _parse_json(response)
            if not response.is_success:
                err = http_error(response)
                if response.status_code == 400 and _POLICY_CREATE_FAILED in _response_result(data):
                    raise PlatformError(
                        f"{err} Hint: a policy with that name may already exist — check "
                        "cnc_list_alarm_suppression_policies (the platform gives this same "
                        "answer for any rejected rule, so also verify the criteria syntax)."
                    )
                raise err
            check_alarm_v1(data, f"Create suppression policy '{name}'")
            if isinstance(data, dict) and str(data.get("status", "Success")).lower() != "success":
                raise PlatformError(
                    f"Create suppression policy '{name}' failed: "
                    f"{data.get('Message') or data.get('message') or data}"
                )
            return finalize(
                f"Suppression policy '{body['policyname']}' created.\n\n"
                f"{to_json({'policy': body, 'response': data})}",
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_alarm_suppression_policy",
        title="Delete Alarm Suppression Policy",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_alarm_suppression_policy(
        name: Annotated[
            str,
            Field(
                description="Policy name as listed by cnc_list_alarm_suppression_policies "
                "(e.g. 'suppress-bgp-flaps').",
                min_length=1,
                max_length=200,
            ),
        ],
    ) -> str:
        """Delete an alarm suppression policy by name.

        Write, destructive: alarms the policy was dropping start appearing again.
        Sends DELETE /crosswork/alarm/v1/suppressionpolicy/<name> (URL-encoded).
        An unknown name is answered HTTP 400 {"Message": "Failed to delete Alarm
        Policy", "status": "Failed"} and reported as not found.

        Args:
            name: the policy name (exact).

        Returns:
            str: "Suppression policy '<name>' deleted." followed by the platform
            JSON ({"Message": "Alarm Policy deleted successfully", "status": "Success"}).
            "Error: no suppression policy '<name>' (or it could not be deleted)"
            when the platform refuses; other failures: "Error: <actionable message>".
        """
        try:
            wanted = name.strip()
            path = f"{SUPPRESSION_POLICY_PATH}/{quote(wanted, safe='')}"
            response = await client.request("DELETE", path, raise_on_error=False)
            data = _parse_json(response)
            if response.status_code == 400 and _POLICY_DELETE_FAILED in _response_result(data):
                raise PlatformError(
                    f"no suppression policy '{wanted}' (or it could not be deleted)"
                )
            if not response.is_success:
                raise http_error(response)
            check_alarm_v1(data, f"Delete suppression policy '{wanted}'")
            if isinstance(data, dict) and str(data.get("status", "Success")).lower() != "success":
                raise PlatformError(
                    f"Delete suppression policy '{wanted}' failed: "
                    f"{data.get('Message') or data.get('message') or data}"
                )
            return finalize(f"Suppression policy '{wanted}' deleted.\n\n{to_json(data)}", settings)
        except Exception as e:
            return format_error(e)
