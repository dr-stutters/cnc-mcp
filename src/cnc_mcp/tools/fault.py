"""Fault management: alarm detail/search, events, the alarm lifecycle
(acknowledge / note / clear), fault settings, the event-type catalogue and
alarm suppression policies.

Crosswork's fault surface is spread over THREE API bases (all verified live
2026-09-13 on the 7.2 lab; ack/unack/note/clear were exercised on a real
alarm). ``cnc_list_alarms`` (in :mod:`cnc_mcp.tools.platform`) stays the paged
alarm listing; this module adds everything else. :func:`alarm_line` and
:func:`stale_alarm_footer` are the shared alarm renderers — every alarm tool
should print the same ``[State] object — Description (id, ack=, events=,
created=, updated=, age=)`` line so a listing is triage-able on its own.

Facts added from the 2026-09-14 agent round (read live, read-only):

- **Alarm order is NOT newest-first.** ``alarms/v1/query`` with ``limit N page
  M`` returned a page of 5 open alarms with Created 1789213359508,
  1789212185976, 1789212400578, 1789244942444, 1789212255608 — so "the most
  recent alarm" must be sorted client-side (``cnc_search_alarms`` ``sort=``).
- **Events ARE newest-first.** ``event/query`` pages 0-3 (limit 30, 120 rows)
  came back with Timestamp strictly descending within each page and across the
  page boundaries (2026-09-13T23:46:54Z ... 12:12:55Z) — page 0 holds the
  newest events. This is an observation, not an API contract.
- **AckHist is a date-only, UNORDERED tally** (``Timestamp`` ``"2026-09-14
  00:00:00.0"``, not epoch ms). The entries come back in no stable order: the
  same alarm answered its 2026-09-14 rows as Ack, UnAck, Ack, UnAck on one read
  and UnAck, UnAck, Ack, Ack, Ack after one more ack (true sequence Ack, UnAck,
  Ack, UnAck, Ack), and its 2026-09-13 pair flipped from Ack, UnAck to UnAck,
  Ack between two reads (agent round 2026-09-14; re-read live 2026-09-14:
  UnAck, UnAck, Ack, Ack, UnAck, Ack — two consecutive UnAcks are impossible,
  so the list order carries no information). Never infer a sequence from
  AckHist; the renderers show it as per-day counts. ``Notes`` carry epoch-ms
  timestamps and give the exact times of the acks/un-acks that recorded a
  note: an ack WITHOUT a note makes the platform append the note ``"Alarm
  acknowledged"`` and a note-less un-ack the note ``"Alarm unacknowledged"``
  (``CreatedBy`` = the acting user); an ack WITH a note stores only that note.
  Observed on the 2026-09-13 scout alarm (read back 2026-09-14): Notes
  'cnc-mcp scout ack' -> 'Alarm unacknowledged' -> 'Alarm acknowledged' ->
  'Alarm unacknowledged' -> 'cnc-mcp scout clear' against AckHist
  Ack/UnAck/Ack/UnAck, and no script or test ever sent the text 'Alarm
  acknowledged'. **The Notes are NOT a complete ack timeline**: an accepted
  ack (``state Success``) was observed live leaving NO note at all — alarm
  e564077d, 2026-09-14 03:31:53Z, sent WITH the note 'cnc-mcp smoke ack'
  (the same text as its 2026-09-13 ack note), followed by an annotate and a
  note-less un-ack whose 'Alarm unacknowledged' note IS present — so the alarm
  shows 3 Ack in its 2026-09-14 AckHist tally against 2 ack-time notes. The
  mechanism (a repeated note text dropped? an ack-path drop?) is UNVERIFIED
  pending a write-phase smoke; until then a day's AckHist count may exceed
  its ack notes. Whether an un-ack WITH a note also stores the platform note
  is unverified (every live un-ack was note-less). Neither AckHist entries
  nor notes can be deleted (no API).
- **An alarm's ``Description`` is always its NEWEST event's text** (verified
  live 2026-09-14 on all 105 lab alarms: ``Events`` is Timestamp-descending
  inside every alarm and ``Description == Events[0].Description`` for every
  alarm that has events). For a **Cleared** alarm that is the CLEARING event's
  text ("NSO device is in sync.", "Was able to connect to NSO nso service
  pack.", "Device was detached.", "<pod> is healthy.") — the fault that was
  cleared is only in the newest FAULT-SEVERITY event (Critical / Major /
  Minor / Warning; 35 of 67 cleared alarms with events carried a different
  fault text; 18 had several Clear events from re-clears). **Info events are
  not faults**: two NSO-onboarding alarms (PE2 6ddc88ed, PCE 72395fe4) carry
  Major "Failed to onboard the node on NSO ..." -> Info "Node was onboarded
  on NSO." -> Clear "NSO device is in sync.", and only the Major text says
  what went wrong, so :func:`fault_event` skips Info events and falls back
  to the newest non-Clear (Info) event only when an alarm has no
  fault-severity event at all (live: the "pipeline health updating: HEALTHY"
  and "Updating Credentials ... to Deep Inventory Service" alarms, Info ->
  Clear only). Seven cleared pod-health alarms had ``events_count`` 0 and no
  ``Events`` at all, so their fault text is unrecoverable. :func:`alarm_line`
  therefore renders a Cleared alarm as ``[<sev>] <fault> | cleared: <text>``
  (see :func:`alarm_text`) and :func:`alarm_markdown` adds a ``Fault:`` line.
- **Stale alarms.** Pod-health alarms ("<pod> is down.", Created/Updated
  2026-08-07, ``events_count`` 0, no ``Events`` key at all) stay open long
  after the pods recovered — Crosswork does not auto-clear them. The renderers
  flag "0 events and no update for >= 7 days" as a stale-alarm check.
- **The no-limit criteria caps at 100 rows.** ``select * from alarm`` (no
  ``limit``) looked like "the whole collection" on 2026-09-13 only because the
  lab had 99 alarms; with 104 alarms it returned exactly 100 and three OPEN
  Major alarms were missing, so ``cnc_get_alarm`` answered "no alarm" for a
  real id. An explicit limit is honoured above 100 (``limit 200 page 0`` ->
  all 104, ``page 1`` -> 0; ``limit 100`` pages 0/1 -> 100 + 4 unique rows,
  page 2 empty), so :func:`fetch_alarms` pages with ``limit 200`` until a short
  page and de-duplicates by ``AlarmId``.

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
   client-side. ``select * from alarm`` with NO ``limit`` answers at most 100
   rows (see above), so the get-by-id, search and lifecycle tools page the
   collection with an explicit limit; events without a limit answer 100 rows.
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
   collection. **Settings writes (verified live 2026-09-15 on the 7.2 lab,
   every change read back and reverted):**

   - ``POST severity-config {"sourceType": "scc", "sourceValue": <severity>,
     "eventTypes": [<name>, ...]}`` -> 200 ``{"status": "OK", "headers": {},
     "body": "Severity configuration update success"}``; the catalogue shows
     the new severity on the very next read. ``sourceValue`` must be one of
     the LOWERCASE spellings critical / major / minor / warning / information
     (``WARNING``, ``info`` and ``cleared`` are 400 ``Invalid sourceValue``);
     the catalogue reads it back capitalised (``Information``). An unknown
     name is 400 ``Invalid eventType`` and the whole call is rejected — a list
     mixing a known and an unknown name changes NOTHING. The 400 bodies are
     PLAIN TEXT under ``Content-Type: application/json`` (``Invalid eventType``
     / ``Invalid sourceValue`` / ``Invalid eventTypes`` (empty list) /
     ``Invalid sourceType``).
   - ``POST autoclear {"sourceType": "aac", "sourceValue": "<minutes>",
     "eventTypes": [...]}`` -> 200 ``{"status": "OK", ..., "body": "Alarm
     autoclear update:success"}``; the ``revert`` key appears in BOTH
     catalogue documents immediately. The platform's own rule (400 ``Invalid
     sourceValue : Please enter valid integer value in the range of 5 to
     599940. If value is less than or equal to 55, then it should be in
     multiples of 5. If the value is greater than or equal to 60, then it
     should be in multiples of 60.``) is enforced client-side too; the value
     is a string of digits only (``" 30 "`` and ``10.5`` are rejected).
   - ``POST autoclear/revert {"eventTypes": [...]}`` -> 200 ``{"status":
     "OK", ..., "body": "Alarm autoclear deletion operation completed
     successfully"}``. **It DELETES the interval, it does not restore a
     default**: reverting ``ciscoPtpSlaveLost`` (shipped with ``revert
     "1440"``) left it with NO revert at all (re-set to 1440 afterwards).
     Reverting a type that has no interval is a 200 no-op; an empty or
     missing list is 400 ``Invalid eventTypes``.
   - ``POST manager/settings {"alarmManager/<device type>": bool}`` and
     ``POST gnmi/settings {"<vendor>": bool}`` take a PARTIAL document: only
     the keys sent change, the answer echoes those keys with their stored
     values (``{"alarmManager/Cisco NCS 5001": true}``), ``{}`` is a 200
     no-op, and a non-boolean value (``"yes"``) is silently stored as
     ``false`` — so the tools send real booleans and verify the echo. Whether
     an unknown key is created (and can be removed) was deliberately NOT
     tried; the tools resolve the key against the current document first.
   - ``POST recommended-action {"erroreventype", "explaination",
     "recommendedaction"}`` -> 200 ``{"responseResult": "Data Saved
     Successfully"}``; the GET shows the text immediately and empty strings
     restore the platform default text. ``nextstepupdate`` flips 0 -> 1 on
     the first save and stays 1 (it is a "custom text was ever saved" flag,
     not a next step). Unknown or missing name: 400 ``{"responseResult":
     "Invalid input : EventType does not exist : <x|null>"}``.
   - ``PUT suppressionpolicy {policyname, description, action, deviceGroups,
     criteria}`` (the collection path, NOT ``/<name>`` — that is 405) -> 200
     ``{"Message": "Success", "status": "Success"}``; the list shows the new
     values immediately. The FULL body is required: a body without ``action``
     is 400 ``{"Message ": "Action type is null", "status": "Failed"}`` (the
     key really carries a trailing space), a bad action 400 ``{"Message ":
     "Invalid Action type"}``, and an unknown name 400 ``{"Message": "Failed
     to update policy rule <name>"}``. The tool therefore reads the policy
     first and merges the requested changes over it.
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
is not offered); the custom syslog/trap event-type definitions
(``custom/syslog`` / ``custom/trap`` / ``custom/subeventtype``; scouted live
2026-09-15: ``POST custom/syslog {mnemonic, mnemonicregex, regexDetails[],
eventDetails[]}`` -> 200 ``{"status": "Success"}``, duplicate 400
``{"message": "Invalid input : EventType already defined : <x>", "status":
"Fail"}``, ``GET|PUT|DELETE custom/syslog/<eventType>`` (keyed by the EVENT
TYPE, not the mnemonic; unknown -> 400 ``"Invalid request : Event Type does
not exist : <x>"``), ``POST custom/eventtype {}`` -> ``{"eventTypes": [...],
"totalCount"}`` or ``{"message": "No Data"}`` — but the GET echoes the event
type name as ``description``, the PUT dropped the type from the
``severity-config`` catalogue, and the nested regex/event/match-condition
payload does not fit flat tool arguments, so they wait for their own design);
the notification destinations (``trap-dest`` / ``syslog-dest`` /
``rest-dest``).
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
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
AUTOCLEAR_PATH = f"{ALARM_V1}/autoclear"
AUTOCLEAR_REVERT_PATH = f"{ALARM_V1}/autoclear/revert"
RECOMMENDED_ACTION_PATH = f"{ALARM_V1}/recommended-action"
SUPPRESSION_POLICY_PATH = f"{ALARM_V1}/suppressionpolicy"
# EMF RESTCONF fault manager.
RTM_ALARM_PATH = f"{EMF_ALARM}/rtm:alarm"

# ``where`` never matches, so get-by-id and search must fetch everything and filter
# client-side — by PAGING: the no-limit form ``select * from alarm`` silently caps
# at 100 rows (verified live 2026-09-14: 104 alarms, 100 returned, 3 open Major
# alarms missing). An explicit limit above 100 is honoured (``limit 200 page 0``
# returned all 104, ``page 1`` none), so fetch_alarms pages with this size until a
# page comes back short. The page ceiling is a runaway guard, not a platform limit.
ALARM_FETCH_PAGE = 200
ALARM_FETCH_MAX_PAGES = 50
# Per the notes, the endpoint returns 100 rows without a limit; keep the tool's
# ceiling at that so a page never silently truncates.
EVENTS_MAX_LIMIT = 100


def alarm_criteria(limit: int, page: int) -> str:
    """The alarms/v1 SQL-like paging criteria (the only working clause)."""
    return f"select * from alarm limit {limit} page {page}"


ALARM_STATES = ("Critical", "Major", "Minor", "Warning", "Info", "Clear")
# Event severities that describe a FAULT. Info events are progress/notification
# rows ("Node was onboarded on NSO.", "pipeline health updating: HEALTHY") and
# Clear events close the alarm — neither is the fault that was cleared (live
# 2026-09-14: the NSO-onboarding alarms carry Major -> Info -> Clear, and only the
# Major text says what went wrong). fault_event() prefers these severities.
FAULT_SEVERITIES = frozenset({"critical", "major", "minor", "warning"})
# Client-side sort orders for the alarm search (the platform's ``order by`` is
# ignored and its natural order is not newest-first — verified live 2026-09-14).
ALARM_SORTS = ("updated_desc", "created_desc", "platform")
DEFAULT_ALARM_SORT = "updated_desc"
# Stale-alarm heuristic (a rendering aid, not a platform fact): an open alarm with
# no events that has not changed for this many days is flagged for a live check.
STALE_ALARM_DAYS = 7
# The hint is deliberately generic: is_stale() fires on ANY open alarm with 0 events
# unchanged for STALE_ALARM_DAYS (a one-off migration warning qualifies too), so the
# pod-health check is offered only for the "<pod> is down." family.
STALE_ALARM_HINT = (
    "Possibly stale — Crosswork does not auto-clear such alarms (verified live 2026-09-14 on "
    'pod-health alarms). For "<pod> is down." alarms confirm with cnc_get_cluster_health / '
    "cnc_list_microservices(app_id=...); for any other alarm verify the underlying condition "
    "before reporting it as current."
)
# AckHist ``Timestamp`` as the platform sends it: a date-only string (verified live).
_DATE_ONLY_STAMP = re.compile(r"^(\d{4}-\d{2}-\d{2})[ T]00:00:00(\.0+)?$")
# rtm:alarm ``perceived-severity`` values (restconf_fault_ap_is_7_2_0.json).
RTM_SEVERITIES = ("critical", "major", "minor", "warning", "cleared", "indeterminate")
# rtm:alarm ``alarmtype`` values (same document). The platform defaults to
# ``device`` when the parameter is omitted; only that default is verified live,
# so the tool sends ``alarmtype`` only for the other two.
RTM_ALARM_TYPES = ("device", "network", "system")
RTM_DEFAULT_ALARM_TYPE = "device"
SUPPRESSION_ACTIONS = ("suppressAlarm", "suppressEvent")
MANAGER_KEY_PREFIX = "alarmManager/"
# severity-config ``sourceValue`` spellings: LOWERCASE only (verified live 2026-09-15:
# ``WARNING``, ``info`` and ``cleared`` are 400 ``Invalid sourceValue``); the catalogue
# reads them back capitalised (``Information``).
EVENT_SEVERITIES = ("critical", "major", "minor", "warning", "information")
SEVERITY_SOURCE_TYPE = "scc"
AUTOCLEAR_SOURCE_TYPE = "aac"
# The platform's auto-clear interval rule (its own 400 text, verified live 2026-09-15):
# 5..599940 minutes; <= 55 in multiples of 5; >= 60 in multiples of 60.
AUTOCLEAR_MIN_MINUTES = 5
AUTOCLEAR_MAX_MINUTES = 599940
AUTOCLEAR_SMALL_STEP = 5
AUTOCLEAR_SMALL_MAX = 55
AUTOCLEAR_LARGE_STEP = 60
# Markers inside the alarm/v1 400 bodies that mean "no such object" (verified live).
_EVENT_TYPE_MISSING = "eventtype does not exist"
_INVALID_EVENT_TYPE = "invalid eventtype"
_POLICY_CREATE_FAILED = "failed to create policy rule"
_POLICY_UPDATE_FAILED = "failed to update policy rule"
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


def _epoch_seconds(value: Any) -> float | None:
    """An epoch value (ms on the alarm API; s/us/ns tolerated by magnitude, like
    :func:`cnc_mcp.formatting.epoch_iso`) as seconds, or None when unusable."""
    n = _epoch_int(value)
    if n <= 0:
        return None
    for threshold, divisor in ((10**17, 10**9), (10**14, 10**6), (10**11, 10**3)):
        if n >= threshold:
            return n / divisor
    return float(n)


def age_text(value: Any, now: datetime) -> str:
    """Elapsed time since an epoch value: ``38d`` / ``5h`` / ``12m`` / ``<1m``; ``-`` if unknown."""
    seconds = _epoch_seconds(value)
    if seconds is None:
        return "-"
    delta = max(0, int(now.timestamp() - seconds))
    if delta >= 86400:
        return f"{delta // 86400}d"
    if delta >= 3600:
        return f"{delta // 3600}h"
    if delta >= 60:
        return f"{delta // 60}m"
    return "<1m"


def event_count(a: dict[str, Any]) -> int:
    """``events_count`` (the platform omits ``Events`` entirely when there are none)."""
    count = a.get("events_count")
    if count is None:
        events = a.get("Events")
        return len(events) if isinstance(events, list) else 0
    return _epoch_int(count)


def is_stale(a: dict[str, Any], now: datetime) -> bool:
    """Open, no events, and unchanged for >= STALE_ALARM_DAYS — worth a live check."""
    if is_cleared(a) or event_count(a) != 0:
        return False
    seconds = _epoch_seconds(a.get("Updated") or a.get("Created"))
    return seconds is not None and now.timestamp() - seconds >= STALE_ALARM_DAYS * 86400


def is_cleared(a: dict[str, Any]) -> bool:
    """True when the alarm's ``State`` is Clear (case-insensitive)."""
    return str(a.get("State", "")).strip().lower() == "clear"


def event_severity(e: dict[str, Any]) -> str:
    """An event's ``EventSeverity``, lower-cased and stripped ('' when missing)."""
    return str(e.get("EventSeverity", "")).strip().lower()


def is_fault_severity(e: dict[str, Any]) -> bool:
    """True when the event's severity is Critical / Major / Minor / Warning."""
    return event_severity(e) in FAULT_SEVERITIES


def fault_event(a: dict[str, Any]) -> dict[str, Any] | None:
    """The newest FAULT-SEVERITY event (Critical/Major/Minor/Warning) of an alarm.

    The platform overwrites an alarm's top-level ``Description`` with its NEWEST
    event's text (verified live 2026-09-14 on all 105 lab alarms), so for a
    Cleared alarm ``Description`` is the CLEARING event's text and the fault
    that was cleared lives only here. Info events are NOT faults — live, the
    NSO-onboarding alarms carry Major "Failed to onboard the node on NSO ..."
    -> Info "Node was onboarded on NSO." -> Clear "NSO device is in sync.", and
    taking the newest non-Clear event would hide the Major fault behind the
    Info progress row. Only when the alarm has no fault-severity event at all
    (live: Info -> Clear alarms such as "pipeline health updating: HEALTHY")
    does this fall back to the newest non-Clear event; None when every event
    is a Clear or there are no events. Picked by ``Timestamp`` (not list
    position) — ``Events`` was Timestamp-descending on every live alarm, but
    the order is an observation, not a contract.
    """
    events = [e for e in (a.get("Events") or []) if isinstance(e, dict)]
    candidates = [e for e in events if is_fault_severity(e)]
    if not candidates:
        candidates = [e for e in events if event_severity(e) != "clear"]
    if not candidates:
        return None
    return max(candidates, key=lambda e: _epoch_int(e.get("Timestamp")))


def fault_event_label(fault: dict[str, Any]) -> str:
    """How :func:`alarm_markdown` qualifies the ``Fault:`` line's source event."""
    if is_fault_severity(fault):
        return "newest fault-severity event"
    return "newest non-Clear event — no Critical/Major/Minor/Warning event recorded"


def alarm_text(a: dict[str, Any]) -> str:
    """The description segment of :func:`alarm_line`.

    Open alarm: ``Description`` as the platform sends it (its newest event's
    text). Cleared alarm with events: ``[<fault severity>] <fault text> |
    cleared: <Description>`` where the fault is the newest fault-severity
    event per :func:`fault_event` (``cleared: (same text)`` when the clearing
    event repeats the fault text, e.g. the gluster volume alarms), so a listing
    shows what went wrong without a cnc_get_alarm per alarm. Cleared alarm
    without events (live: pod-health alarms with events_count 0 and no
    ``Events``): ``<Description> | original fault not recorded (0 events)``.
    """
    description = a.get("Description", "?")
    if not is_cleared(a):
        return str(description)
    fault = fault_event(a)
    if fault is None:
        count = event_count(a)
        why = "0 events" if count == 0 else f"no non-Clear event among {count}"
        return f"{description} | original fault not recorded ({why})"
    fault_text = fault.get("Description", "?")
    cleared = "(same text)" if fault_text == description else description
    return f"[{fault.get('EventSeverity', '?')}] {fault_text} | cleared: {cleared}"


def sort_alarms(
    alarms: list[dict[str, Any]], sort: str = DEFAULT_ALARM_SORT
) -> list[dict[str, Any]]:
    """Order alarms client-side: ``updated_desc`` (default), ``created_desc`` or
    ``platform`` (as returned — NOT newest-first, verified live 2026-09-14)."""
    if sort == "platform":
        return list(alarms)
    field = "Created" if sort == "created_desc" else "Updated"
    return sorted(alarms, key=lambda a: _epoch_int(a.get(field)), reverse=True)


def _contains(needle: str, *haystacks: Any) -> bool:
    return any(needle in str(h).lower() for h in haystacks if h is not None)


def _searchable_texts(a: dict[str, Any]) -> tuple[Any, ...]:
    """The strings the alarm ``text`` filter matches: Description,
    object_description and, for a Cleared alarm, the fault event's text."""
    texts: tuple[Any, ...] = (a.get("Description"), a.get("object_description"))
    if is_cleared(a):
        fault = fault_event(a)
        if fault is not None:
            texts += (fault.get("Description"),)
    return texts


def filter_alarms(
    alarms: list[Any],
    *,
    text: str | None = None,
    state: str | None = None,
    category: str | None = None,
    acknowledged: bool | None = None,
    sort: str = DEFAULT_ALARM_SORT,
) -> list[dict[str, Any]]:
    """Client-side alarm filters (the platform's ``where`` never matches), then
    :func:`sort_alarms` (newest Updated first by default). ``text`` is matched
    against ``Description``, ``object_description`` and — because a Cleared
    alarm's ``Description`` is only the clearing event's text — the fault text
    :func:`fault_event` renders for a Cleared alarm."""
    out = [a for a in alarms if isinstance(a, dict)]
    if text and text.strip():
        needle = text.strip().lower()
        out = [a for a in out if _contains(needle, *_searchable_texts(a))]
    if state:
        out = [a for a in out if str(a.get("State", "")).lower() == state.lower()]
    if category and category.strip():
        wanted = category.strip().lower()
        out = [a for a in out if str(a.get("AlarmCategory", "")).lower() == wanted]
    if acknowledged is not None:
        out = [a for a in out if bool(a.get("Acknowledge")) is acknowledged]
    return sort_alarms(out, sort)


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


def alarm_line(a: dict[str, Any], now: datetime | None = None) -> str:
    """The shared one-line alarm rendering (use it in EVERY alarm listing):
    ``[State] object — Description (id, ack=…, events=N, created=<ISO>,
    updated=<ISO>, age=<since Created>)``, where the Description segment of a
    Cleared alarm is ``[<sev>] <fault> | cleared: <text>`` (:func:`alarm_text`).

    ``now`` fixes the reference time for ``age`` (tests); default: current UTC.
    """
    now = now or datetime.now(UTC)
    return (
        f"- [{a.get('State', '?')}] {a.get('object_description') or a.get('object_id') or '?'} "
        f"— {alarm_text(a)} ({a.get('AlarmId', '?')}, "
        f"ack={a.get('Acknowledge', '?')}, events={event_count(a)}, "
        f"created={epoch_iso(a.get('Created'))}, updated={epoch_iso(a.get('Updated'))}, "
        f"age={age_text(a.get('Created'), now)})"
    )


def stale_alarm_footer(alarms: list[dict[str, Any]], now: datetime | None = None) -> list[str]:
    """Markdown lines flagging alarms that :func:`is_stale` — empty when none are."""
    now = now or datetime.now(UTC)
    stale = [a for a in alarms if is_stale(a, now)]
    if not stale:
        return []
    verb = "has" if len(stale) == 1 else "have"
    return [
        "",
        f"Stale-alarm check: {len(stale)} of the alarms shown {verb} 0 events and no update "
        f"for {STALE_ALARM_DAYS}+ days. {STALE_ALARM_HINT}",
    ]


def event_line(e: dict[str, Any]) -> str:
    """``[EventSeverity] object — Description (EventId, alarm <id>, <Timestamp iso>)``."""
    return (
        f"- [{e.get('EventSeverity', '?')}] {e.get('object_description') or '?'} "
        f"— {e.get('Description', '?')} ({e.get('EventId', '?')}, "
        f"alarm {e.get('alarm_id') or '-'}, {epoch_iso(e.get('Timestamp'))})"
    )


def history_stamp(value: Any) -> str:
    """An AckHist / Notes ``Timestamp``: epoch -> ISO; the platform's date-only
    AckHist form ``"2026-09-14 00:00:00.0"`` -> ``"2026-09-14 (date only)"``;
    anything else verbatim."""
    text = "" if value is None else str(value).strip()
    match = _DATE_ONLY_STAMP.match(text)
    if match:
        return f"{match.group(1)} (date only)"
    return epoch_iso(value)


def _history_line(entry: dict[str, Any]) -> str:
    """A Notes entry: ``- <stamp> <CreatedBy>: <Description>``."""
    return (
        f"- {history_stamp(entry.get('Timestamp'))} {entry.get('CreatedBy', '?')}: "
        f"{entry.get('Description', '?')}"
    )


ACK_HIST_NOTE = (
    "(AckHist is a per-day tally only: its timestamps are date-only and the platform "
    "returns the entries in no stable order — the same alarm answered its rows in a "
    "different order on consecutive reads, verified live 2026-09-14 — so no ack/un-ack "
    "sequence can be read from it. The Notes below give the exact epoch-ms times of the "
    "acks/un-acks that recorded a note: a note-less ack/un-ack writes the platform note "
    "'Alarm acknowledged' / 'Alarm unacknowledged', an ack with a note stores that note "
    "instead. They are NOT guaranteed complete: an accepted ack was observed live leaving "
    "no note at all (alarm e564077d, 2026-09-14 03:31Z, sent with a note), so a day's "
    "AckHist count may exceed its ack notes — the mechanism is unverified.)"
)


def ack_hist_lines(hist: list[dict[str, Any]]) -> list[str]:
    """AckHist rendered as per-day counts, newest day first — never as ordered
    rows, because the platform's order is meaningless (see :data:`ACK_HIST_NOTE`):
    ``- <day> (date only): 3 Ack, 2 UnAck — by admin``."""
    days: dict[str, dict[str, int]] = {}
    users: dict[str, set[str]] = {}
    for entry in hist:
        day = history_stamp(entry.get("Timestamp"))
        counts = days.setdefault(day, {})
        what = str(entry.get("Description") or "?")
        counts[what] = counts.get(what, 0) + 1
        users.setdefault(day, set()).add(str(entry.get("CreatedBy") or "?"))
    lines = []
    for day in sorted(days, reverse=True):
        # Sorted (Ack before UnAck) so the text is stable across reads — the platform's
        # own order of the rows is not.
        tally = ", ".join(f"{n} {what}" for what, n in sorted(days[day].items()))
        lines.append(f"- {day}: {tally} — by {', '.join(sorted(users[day]))}")
    return lines


def alarm_markdown(a: dict[str, Any], now: datetime | None = None) -> str:
    """Full detail of one alarm including its ack history and notes."""
    now = now or datetime.now(UTC)
    lines = [
        f"# Alarm {a.get('AlarmId', '?')}",
        "",
        f"- State: {a.get('State', '?')} (category {a.get('AlarmCategory', '?')})",
        f"- Acknowledged: {a.get('Acknowledge', '?')}",
    ]
    if is_cleared(a):
        # Description is the CLEARING event's text (the platform keeps the newest
        # event's text there); the fault that was cleared is the newest fault-severity
        # event (Info rows such as "Node was onboarded on NSO." are skipped).
        fault = fault_event(a)
        lines.append(
            f"- Description: {a.get('Description', '?')} (the clearing event's text — the "
            "platform's Description is always the newest event's)"
        )
        if fault is None:
            count = event_count(a)
            why = "0 events" if count == 0 else f"no non-Clear event among {count}"
            lines.append(f"- Fault: not recorded ({why})")
        else:
            lines.append(
                f"- Fault: [{fault.get('EventSeverity', '?')}] {fault.get('Description', '?')} "
                f"({fault_event_label(fault)}, {epoch_iso(fault.get('Timestamp'))})"
            )
    else:
        lines.append(f"- Description: {a.get('Description', '?')}")
    lines += [
        f"- Object: {a.get('object_description') or '?'} (object_id {a.get('object_id') or '?'})",
        f"- Origin: {a.get('origin_app_id') or '?'}"
        + (f" / {a['origin_service_id']}" if a.get("origin_service_id") else ""),
        f"- Event type: {a.get('event_type', '?')}",
        f"- Created: {epoch_iso(a.get('Created'))} (age {age_text(a.get('Created'), now)}) "
        f"— Updated: {epoch_iso(a.get('Updated'))} ({age_text(a.get('Updated'), now)} ago)",
    ]
    events = [e for e in (a.get("Events") or []) if isinstance(e, dict)]
    lines.append(f"- Events: {event_count(a)}")
    for e in events[:_EVENTS_SHOWN]:
        lines.append(
            f"  - [{e.get('EventSeverity', '?')}] {e.get('Description', '?')} "
            f"({e.get('EventId', '?')}, {epoch_iso(e.get('Timestamp'))})"
        )
    if len(events) > _EVENTS_SHOWN:
        lines.append(f"  - ... {len(events) - _EVENTS_SHOWN} more (response_format='json')")
    if is_stale(a, now):
        lines.append(
            f"- Stale-alarm check: 0 events and no update for "
            f"{age_text(a.get('Updated') or a.get('Created'), now)}. {STALE_ALARM_HINT}"
        )
    hist = [h for h in (a.get("AckHist") or []) if isinstance(h, dict)]
    lines.extend(["", f"## Acknowledgement history ({len(hist)})"])
    if not hist:
        lines.append("- none")
    else:
        lines.append(ACK_HIST_NOTE)
        lines.extend(ack_hist_lines(hist))
    notes = [n for n in (a.get("Notes") or []) if isinstance(n, dict)]
    notes.sort(key=lambda n: _epoch_int(n.get("Timestamp")), reverse=True)
    lines.extend(["", f"## Notes ({len(notes)}, newest first, permanent)"])
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
            # Verified live 2026-09-15: nextstepupdate is a 0/1 "custom text was ever
            # saved" flag that stays 1 after the text is cleared, not a next step.
            lines.append(
                "- Note: custom text was saved on this instance before and later cleared "
                "(nextstepupdate=1); cnc_set_event_type_recommendation sets new text."
            )
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


def autoclear_minutes_error(minutes: int) -> str | None:
    """Why ``minutes`` is not a valid auto-clear interval, or None when it is.

    Mirrors the platform's rule (its 400 text, verified live 2026-09-15) so the
    tool refuses a bad value without a call and with a clearer message.
    """
    if minutes < AUTOCLEAR_MIN_MINUTES or minutes > AUTOCLEAR_MAX_MINUTES:
        return (
            f"auto-clear minutes must be between {AUTOCLEAR_MIN_MINUTES} and "
            f"{AUTOCLEAR_MAX_MINUTES} (got {minutes})"
        )
    if minutes <= AUTOCLEAR_SMALL_MAX and minutes % AUTOCLEAR_SMALL_STEP:
        return (
            f"auto-clear minutes up to {AUTOCLEAR_SMALL_MAX} must be a multiple of "
            f"{AUTOCLEAR_SMALL_STEP} (got {minutes})"
        )
    if minutes >= AUTOCLEAR_LARGE_STEP and minutes % AUTOCLEAR_LARGE_STEP:
        return (
            f"auto-clear minutes from {AUTOCLEAR_LARGE_STEP} up must be a multiple of "
            f"{AUTOCLEAR_LARGE_STEP} (got {minutes})"
        )
    return None


def autoclear_minutes(item: dict[str, Any]) -> int | None:
    """The catalogue entry's ``revert`` (a string of minutes) as an int, or None."""
    revert = item.get("revert")
    if revert in (None, "", 0, "0"):
        return None
    try:
        return int(str(revert))
    except ValueError:
        return None


def event_type_state(item: dict[str, Any]) -> dict[str, Any]:
    """The catalogue fields a settings write can change, for before/after reporting."""
    return {
        "name": item.get("name") or item.get("eventTypeName"),
        "category": item.get("defaultCategory"),
        "severity": item.get("severity"),
        "autoclear_minutes": autoclear_minutes(item),
    }


def find_event_type(catalogue: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    """The catalogue entry named ``name``: exact match first, then case-insensitive.

    The write is always built from the entry's own ``name`` so it targets the
    platform's spelling (``severity-config`` rejects a misspelt name with 400
    ``Invalid eventType``).
    """
    wanted = name.strip()
    for item in catalogue:
        if item.get("name") == wanted or item.get("eventTypeName") == wanted:
            return item
    folded = wanted.lower()
    for item in catalogue:
        if str(item.get("name", "")).lower() == folded:
            return item
        if str(item.get("eventTypeName", "")).lower() == folded:
            return item
    return None


def find_policy(policies: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    """The suppression policy named ``name``: exact match first, then case-insensitive."""
    wanted = name.strip()
    for p in policies:
        if p.get("policyname") == wanted:
            return p
    folded = wanted.lower()
    for p in policies:
        if str(p.get("policyname", "")).lower() == folded:
            return p
    return None


def resolve_setting_key(document: dict[str, Any], wanted: str, prefix: str = "") -> str | None:
    """The key of a ``{"<key>": bool}`` settings document that ``wanted`` names.

    ``wanted`` may be given with or without ``prefix`` (``"Cisco NCS 5001"`` or
    ``"alarmManager/Cisco NCS 5001"``); exact match first, then
    case-insensitive. None when the document has no such key — the tools never
    write a key the platform did not list, because whether an unknown key is
    created (and can then be removed) is unverified.
    """
    candidates = [wanted.strip()]
    if prefix and not wanted.strip().startswith(prefix):
        candidates.append(prefix + wanted.strip())
    for candidate in candidates:
        if candidate in document:
            return candidate
    folded = [c.lower() for c in candidates]
    for key in document:
        if str(key).lower() in folded:
            return str(key)
    return None


def flag_line(key: str, value: Any, prefix: str = "") -> str:
    name = key[len(prefix) :] if prefix and key.startswith(prefix) else key
    return f"{name}: {'on' if value else 'off'}"


def _more_hint(envelope: dict[str, Any]) -> list[str]:
    if envelope.get("has_more"):
        return ["", f"More available: repeat with page={envelope['next_page']}."]
    return []


def _response_result(data: Any) -> str:
    """The text of an alarm/v1 error body (``responseResult`` / ``Message``), lower-cased.

    Keys are matched with surrounding whitespace stripped: the ``PUT
    suppressionpolicy`` 400 bodies spell theirs ``"Message "`` (verified live
    2026-09-15).
    """
    if isinstance(data, dict):
        stripped = {str(k).strip(): v for k, v in data.items()}
        for key in ("responseResult", "Message", "message"):
            if isinstance(stripped.get(key), str):
                return stripped[key].lower()
    return str(data or "").lower()


def platform_message(response: Any, data: Any) -> str:
    """The platform's own words for a failed alarm/v1 write, original case.

    JSON bodies give their ``responseResult`` / ``Message`` / ``message`` /
    ``body`` text; the severity-config and autoclear 400s are PLAIN TEXT under
    ``Content-Type: application/json`` (``Invalid eventType``), so the raw text
    is the fallback.
    """
    if isinstance(data, dict):
        stripped = {str(k).strip(): v for k, v in data.items()}
        for key in ("responseResult", "Message", "message", "body"):
            if isinstance(stripped.get(key), str) and stripped[key].strip():
                return stripped[key].strip()
        return str(data)[:300]
    text = str(getattr(response, "text", "") or "").strip()
    return text[:300] or f"HTTP {getattr(response, 'status_code', '?')} with an empty body"


def _parse_json(response: Any) -> Any:
    try:
        return response.json()
    except ValueError:
        return None


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    async def fetch_alarms(open_only: bool) -> list[dict[str, Any]]:
        """Every alarm in scope (open, or open+cleared), paged with an explicit
        limit and de-duplicated by AlarmId — the no-limit criteria caps at 100
        rows (verified live 2026-09-14), so it is never used."""
        seen: set[str] = set()
        out: list[dict[str, Any]] = []
        for page in range(ALARM_FETCH_MAX_PAGES):
            body = {
                "openAlarmsOnly": open_only,
                "criteria": alarm_criteria(ALARM_FETCH_PAGE, page),
            }
            data = await client.request_json("POST", ALARMS_QUERY, json_body=body)
            check_query(data, "Alarm query")
            rows, _, _ = unwrap(data, "alarms")
            rows = [a for a in rows if isinstance(a, dict)]
            for a in rows:
                key = str(a.get("AlarmId", "")).strip().lower()
                if key and key in seen:
                    continue
                if key:
                    seen.add(key)
                out.append(a)
            if len(rows) < ALARM_FETCH_PAGE:
                return out
        logger.warning(
            "alarm fetch stopped after %d pages of %d (%d alarms) — raise ALARM_FETCH_MAX_PAGES",
            ALARM_FETCH_MAX_PAGES,
            ALARM_FETCH_PAGE,
            len(out),
        )
        return out

    async def resolve_alarm(alarm_id: str) -> dict[str, Any]:
        """The alarm for ``alarm_id`` or a PlatformError — nothing is written for an
        unknown id. Open alarms are searched first (the common case, one small
        scope), then open+cleared so cleared alarms are found too."""
        alarm = find_alarm(await fetch_alarms(open_only=True), alarm_id)
        if alarm is None:
            alarm = find_alarm(await fetch_alarms(open_only=False), alarm_id)
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
        match, verified live), so this tool pages the collection ('select * from
        alarm limit 200 page N', open alarms first, then open+cleared when the id
        is not open) and finds the id client-side — a few calls, slower on an
        instance with thousands of alarms. Cleared alarms are found too. It does
        NOT use the no-limit criteria: that form silently caps at 100 rows
        (verified live 2026-09-14 — it hid three open Major alarms). For
        device/network (RTM) alarms use cnc_list_device_alarms instead.

        CLEARED ALARMS (verified live 2026-09-14 on all 105 lab alarms): the
        platform's top-level Description is always the NEWEST event's text, so
        for a Cleared alarm it is the CLEARING event's text ("NSO device is in
        sync.", "Device was detached.", "<pod> is healthy.") and the fault that
        was cleared is only in the Events. The markdown therefore adds a
        "Fault: [<severity>] <text>" line taken from the newest fault-severity
        event (Critical/Major/Minor/Warning — NOT an Info event: the
        NSO-onboarding alarms carry Major "Failed to onboard the node on NSO
        ..." -> Info "Node was onboarded on NSO." -> Clear, and only the Major
        text is the fault; the newest Info event is used only when the alarm
        has no fault-severity event at all, and the line says so). "Fault: not
        recorded (0 events)" for cleared pod-health alarms, which carry
        events_count 0 and no Events at all; Events are listed newest first as
        the platform sends them. In JSON read Events[] yourself — Description
        is the clear text there too.
        READING THE HISTORY (verified live 2026-09-14): AckHist is a DATE-ONLY,
        UNORDERED tally. Its timestamps are "2026-09-14 00:00:00.0" (rendered
        "2026-09-14 (date only)") and the platform returns the entries in no
        stable order — the same alarm answered its same-day rows as Ack, UnAck,
        Ack, UnAck on one read and UnAck, UnAck, Ack, Ack, Ack after one more
        ack, and a two-entry day flipped between reads — so the markdown
        renders AckHist as per-day counts ("2026-09-14 (date only): 3 Ack, 2
        UnAck — by admin") and NO ack/un-ack sequence must ever be inferred
        from it (raw JSON included). The Notes give the exact times of the
        acks/un-acks that recorded a note: they carry full epoch-ms timestamps
        (rendered ISO, newest first); an ack's note is stored there at the ack
        time and a note-less ack / un-ack makes the platform append its own
        note "Alarm acknowledged" / "Alarm unacknowledged" (observed on the
        2026-09-13 scout alarm). They are NOT a complete ack timeline: an
        accepted ack was observed live leaving no note at all (alarm
        e564077d, 2026-09-14 03:31Z, sent with a note whose text repeated an
        earlier note; the un-ack seconds later DID leave its note), so a day's
        AckHist count may exceed its ack notes — the mechanism (repeated note
        text dropped? an ack-path drop?) is UNVERIFIED pending a write-phase
        smoke. Both lists are permanent (no delete API).
        STALE ALARMS: when an open alarm shows 0 events and no update for 7+
        days the markdown adds a "Stale-alarm check" line — Crosswork does not
        auto-clear such alarms (verified live 2026-09-14 on pod-health alarms
        "<pod> is down.", which stayed open with events_count 0 for weeks after
        the pods recovered). For "<pod> is down." alarms confirm the current
        state with cnc_get_cluster_health / cnc_list_microservices(app_id=...);
        for any other alarm verify the underlying condition before reporting
        it as current.

        Args:
            alarm_id: the AlarmId (exact, case-insensitive).

        Returns:
            str: Markdown with state, category, acknowledged flag, description
            (plus the "Fault:" line for a Cleared alarm), object, origin,
            created/updated (ISO-8601 from the platform's epoch ms, with the
            age), the event count and events (first 10, newest first), a
            stale-alarm check line when applicable, the AckHist per-day counts
            and the Notes (newest first); or the raw alarm JSON:
            {"AlarmId", "AlarmCategory", "State", "Acknowledge",
             "Description" (the newest event's text), "object_id",
             "object_description", "origin_app_id", "origin_service_id",
             "event_type", "events_count", "Created", "Updated" (epoch ms strings),
             "Events": [...] (newest first; absent when there are none),
             "AckHist": [{"CreatedBy", "Description": "Ack"|"UnAck",
                          "Timestamp": "<YYYY-MM-DD 00:00:00.0>"}] (unordered),
             "Notes": [{"CreatedBy", "Description", "Timestamp": "<epoch ms>"}]}
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
        sort: Annotated[
            str,
            Field(
                description="Client-side order: 'updated_desc' (default, most recently changed "
                "first), 'created_desc' (most recently raised first — use this for 'the newest "
                "alarm') or 'platform' (as the API returned them, NOT newest-first).",
                max_length=20,
            ),
        ] = DEFAULT_ALARM_SORT,
        limit: Annotated[
            int,
            Field(
                description="Maximum alarms to return after filtering and sorting (e.g. 50). "
                "This is a cap, not a page size: there is no page argument — every alarm in "
                "scope is fetched and the count of all matches is reported.",
                ge=1,
                le=500,
            ),
        ] = 50,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Search Crosswork platform alarms by text, state, category and
        acknowledged flag, sorted client-side (newest Updated first by default,
        or newest Created first with sort='created_desc').

        CLEARED ALARMS (verified live 2026-09-14 on all 105 lab alarms): the
        platform overwrites an alarm's top-level Description with its NEWEST
        event's text, so for a Cleared alarm Description is the CLEARING
        event's text ("NSO device is in sync.", "Was able to connect to NSO nso
        service pack.", "Device was detached.", "<pod> is healthy.") and says
        nothing about what went wrong. Each markdown line of a Cleared alarm
        therefore renders the newest fault-severity event
        (Critical/Major/Minor/Warning — Info rows such as "Node was onboarded
        on NSO." are skipped, so the NSO-onboarding alarms show their Major
        "Failed to onboard ..." text; an Info event is used only when the
        alarm has no fault-severity event at all) as the fault, then the
        clear text: "[Clear] NSO Provider nso — [Major] Unable to connect to
        NSO nso service pack. | cleared: Was able to connect to NSO nso service
        pack. (...)" ("cleared: (same text)" when the clearing event repeats the
        fault text; "<text> | original fault not recorded (0 events)" for the
        cleared pod-health alarms, which have no Events at all). The `text`
        filter matches that fault text too, so text='unable to connect' with
        open_only=False finds the cleared alarm whose Description now reads
        "Was able to connect ...". In JSON the items are raw — read Events[]
        (newest first) for the fault text.

        Read-only. Use it for "which alarms mention P2", "all unacknowledged
        Critical alarms", "cleared alarms about collection", "the most recent
        alarm" — questions cnc_list_alarms (plain paging) cannot answer.
        ORDERING: the platform's own order is NOT newest-first (verified live
        2026-09-14: a paged listing of 5 open alarms came back with Created
        1789213359508, 1789212185976, 1789212400578, 1789244942444,
        1789212255608), so never take the first row of cnc_list_alarms as the
        newest alarm — use this tool with sort='created_desc' (raised most
        recently) or the default 'updated_desc' (changed most recently: a new
        event, ack, note or clear bumps Updated). WHY CLIENT-SIDE: the alarms
        API's SQL-like criteria accepts 'where' and 'order by' clauses but a
        'where' never matches (0 rows for any field) and 'order by' is ignored
        (verified live), so the tool pages every alarm in scope (open, or
        open+cleared; 'select * from alarm limit 200 page N' until a short page)
        and filters, sorts and caps the result itself — 'fetched' is the number
        of alarms read. Expect more calls on an instance with thousands of
        alarms. The no-limit criteria is NOT used: it silently caps at 100 rows
        (verified live 2026-09-14). For device/network (RTM) alarms use
        cnc_list_device_alarms.
        STALE ALARMS: every line shows events= and age=; when a shown alarm has
        0 events and no update for 7+ days the output ends with a "Stale-alarm
        check" line — Crosswork does not auto-clear such alarms (verified live
        2026-09-14 on pod-health alarms "<pod> is down.", which stayed open
        with 0 events for weeks after the pods recovered). For "<pod> is down."
        alarms confirm the current state with cnc_get_cluster_health /
        cnc_list_microservices(app_id=...); for any other alarm (a one-off
        migration warning also matches the heuristic) verify the underlying
        condition before reporting it as current.

        Args:
            text: substring over Description / object_description (and the
                fault event text of a Cleared alarm).
            state: Critical|Major|Minor|Warning|Info|Clear (Clear only with open_only=False).
            category: exact AlarmCategory (e.g. 'System').
            acknowledged: True / False to keep only that flag; None for both.
            open_only: False to include cleared alarms.
            sort: updated_desc (default) | created_desc | platform.
            limit: cap on the returned rows — NOT a page size (no page argument;
                the count of all matches is reported and 'truncated' says
                whether the cap cut the list). cnc_list_alarms / cnc_list_events
                page with limit (their page size) + page instead.

        Returns:
            str: Markdown, one line per alarm
            "[State] object_description — Description (AlarmId, ack=…, events=N,
            created=<ISO>, updated=<ISO>, age=<since Created, e.g. 38d>)" — for a
            Cleared alarm the Description segment is "[<fault severity>] <fault
            text> | cleared: <Description>" — plus the stale-alarm check line
            when applicable; or JSON:
            {"total": <matches>, "count": int, "sort": str, "items": [<alarm>, ...],
             "truncated": bool, "fetched": <alarms fetched before filtering>}
            (Created/Updated are epoch-ms strings; "Events" is absent when
            events_count is 0). No match is not an error ("No alarms matched
            ..."). "Error: Unknown sort order '<x>'. Use one of: updated_desc,
            created_desc, platform." for a bad sort (nothing sent); on other
            failures: "Error: <actionable message>".
        """
        try:
            wanted_state = canonical(state, ALARM_STATES, "alarm state")
            wanted_sort = canonical(sort, ALARM_SORTS, "sort order") or DEFAULT_ALARM_SORT
            alarms = await fetch_alarms(open_only)
            matches = filter_alarms(
                alarms,
                text=text,
                state=wanted_state,
                category=category,
                acknowledged=acknowledged,
                sort=wanted_sort,
            )
            items = matches[:limit]
            if response_format is ResponseFormat.JSON:
                return finalize(
                    to_json(
                        {
                            "total": len(matches),
                            "count": len(items),
                            "sort": wanted_sort,
                            "items": items,
                            "truncated": len(matches) > limit,
                            "fetched": len(alarms),
                        }
                    ),
                    settings,
                )
            now = datetime.now(UTC)
            scope = "open only" if open_only else "open and cleared"
            lines = [
                f"# Alarms matching ({len(items)} shown of {len(matches)} matches, "
                f"{len(alarms)} fetched, {scope}, sort {wanted_sort})",
                "",
            ]
            if not items:
                lines.append("No alarms matched the filters.")
            lines.extend(alarm_line(a, now) for a in items)
            if len(matches) > limit:
                lines.extend(["", f"{len(matches) - limit} more matched; raise limit or narrow."])
            lines.extend(stale_alarm_footer(items, now))
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
            int,
            Field(
                description="Events per page — this tool's page size, max 100 (e.g. 50); "
                "'page' selects the page.",
                ge=1,
                le=EVENTS_MAX_LIMIT,
            ),
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
        built from, including 'Clear' events), newest first: page 0 holds the
        most recent events.

        Read-only. Use it to see what happened around an alarm, or to trace the
        events of an alarm by its alarm_id. ORDER (verified live 2026-09-14):
        the platform returns events with Timestamp descending — strictly
        newest-first within each page AND across pages 0-3 (limit 30, 120 rows,
        2026-09-13T23:46:54Z down to 12:12:55Z), unlike cnc_list_alarms whose
        order is not newest-first. This is an observation, not a documented
        contract, so the tool does not re-sort; if a page ever looks unordered,
        sort the JSON items by Timestamp yourself. Note that acknowledging,
        un-acknowledging or annotating an alarm does NOT create an event (verified
        live: those actions appear only in the alarm's AckHist/Notes and bump
        its Updated; whether a manual clear adds a 'Clear' event is unverified —
        the platform's own auto-clears do). Paging is
        the platform's ('select * from event limit N page M'); the
        severity/category/text filters are applied CLIENT-SIDE WITHIN THE
        FETCHED PAGE (the criteria grammar's 'where' answers an empty document,
        verified live), so a filtered page can come back short or empty while
        later pages still hold matches — 'has_more' refers to the unfiltered
        page, keep paging.

        Args:
            limit (this tool's page size, max 100) / page (0-based): the
                platform's own paging.
            severity / category / text: filters within the page.

        Returns:
            str: Markdown "[EventSeverity] object_description — Description
            (EventId, alarm <alarm_id>, <Timestamp ISO>)" lines, newest first,
            or JSON:
            {"total": null, "count": <after filtering>, "page": int, "page_size": int,
             "fetched": <rows in the page>, "items": [{"EventId", "alarm_id",
             "EventSeverity", "EventCategory", "Description", "Timestamp" (epoch ms),
             "object_id", "object_description", "origin_app_id", "origin_service_id",
             "event_type", "event_case", "Flagging"}, ...],
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
            int,
            Field(
                description="Alarms per page — this tool's page size, max 100 (e.g. 50); "
                "'offset' selects the page start.",
                ge=1,
                le=MAX_COUNT,
            ),
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
            limit (this tool's page size, 1..100) / offset (0-based start
                index): EMF .maxCount / .startIndex paging.

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
            int,
            Field(
                description="Event types per page — this tool's page size (e.g. 100); 'page' "
                "selects the page.",
                ge=1,
                le=500,
            ),
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
            limit (this tool's page size) / page (0-based): client-side paging
                over the filtered catalogue.

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
                "(e.g. 'Ticket INC-1234 opened'). PERMANENT: it becomes a Notes entry "
                "that no API can edit or delete. Omitting it does NOT avoid a note: the "
                "platform then stores its own 'Alarm acknowledged' / 'Alarm unacknowledged' "
                "note instead.",
                max_length=1000,
            ),
        ] = None,
    ) -> str:
        """Acknowledge (or un-acknowledge) a Crosswork platform alarm.

        Write. The alarm is resolved first (the same paged collection read as
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
        for that reason, wait a few seconds and retry).

        PERMANENT RESIDUE (verified live 2026-09-14) — an ack/un-ack is NOT fully
        reversible, so do not promise "full cleanup" when a task asks for it:
        - every accepted call appends an AckHist entry ("Ack" / "UnAck"); there
          is no API to remove one. AckHist is a DATE-ONLY, UNORDERED tally
          (timestamps "2026-09-14 00:00:00.0"; the platform returns the entries
          in no stable order — the same alarm's same-day rows came back as Ack,
          UnAck, Ack, UnAck before an ack and UnAck, UnAck, Ack, Ack, Ack after
          it, verified live 2026-09-14), so cnc_get_alarm renders it as per-day
          counts and no sequence must be inferred from it; the Notes (see
          below) give the exact times of the calls that recorded a note;
        - the optional `note` becomes a permanent Notes entry (no edit/delete
          API, exactly like cnc_annotate_alarm);
        - an ack WITHOUT a note makes the platform append the permanent note
          "Alarm acknowledged" (observed on the 2026-09-13 scout alarm, read
          back 2026-09-14); with a note only that note is stored;
        - un-acknowledging WITHOUT a note makes the platform append the
          permanent note "Alarm unacknowledged" (CreatedBy = the un-acking
          user). Whether an un-ack WITH a note also stores the platform note is
          UNVERIFIED (every live un-ack was note-less; by the ack pattern the
          user's note probably replaces it).
        Expect a note per accepted call, but do NOT rely on it: one accepted
        ack (state Success) was observed live leaving NO note at all — alarm
        e564077d, 2026-09-14 03:31Z, sent with the note 'cnc-mcp smoke ack'
        (the same text as that alarm's 2026-09-13 ack note), while the
        annotate and the note-less un-ack seconds later recorded theirs — so
        the AckHist per-day count may exceed the ack notes; the mechanism
        (repeated note text dropped? an ack-path drop?) is UNVERIFIED pending a
        write-phase smoke. Re-read with cnc_get_alarm when the note matters.
        NOT VERIFIED LIVE: whether acknowledging an
        already-acknowledged alarm succeeds, fails, or adds a second AckHist
        entry — check "before.acknowledged" in the result (or cnc_get_alarm
        first) instead of re-sending blindly; the tool is therefore not marked
        idempotent. A lost answer (transport error, 5xx) is NOT auto-retried
        because each accepted call is recorded in the alarm's AckHist: on "may
        already have been applied", re-read with cnc_get_alarm before repeating.

        Args:
            alarm_id: the AlarmId (exact, case-insensitive).
            acknowledge: True to ack, False to un-ack.
            note: optional note (permanent).

        Returns:
            str: "Alarm <id> acknowledged|un-acknowledged. The flag settles within
            a few seconds; re-read with cnc_get_alarm. Residue: <what was
            permanently recorded — the AckHist entry plus either the note sent
            or, without one, the platform's own 'Alarm acknowledged' / 'Alarm
            unacknowledged' note>." followed by JSON
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
            residue = [f"an AckHist '{'Ack' if acknowledge else 'UnAck'}' entry"]
            if body.get("note"):
                # With a note the platform stores only that note (observed live for an
                # ack; for an un-ack it is unverified — every live un-ack was note-less).
                # Not guaranteed: one accepted ack with a note left no note at all
                # (e564077d, 2026-09-14 03:31Z) — see the docstring.
                residue.append(f"the note '{body['note']}' as a Notes entry")
                if not acknowledge:
                    residue[-1] += (
                        " (whether the platform also adds 'Alarm unacknowledged' next to a "
                        "user note is unverified)"
                    )
            else:
                # A note-less ack / un-ack makes the platform append its own note
                # (observed live on the 2026-09-13 scout alarm).
                platform_note = "Alarm acknowledged" if acknowledge else "Alarm unacknowledged"
                residue.append(f"the platform note '{platform_note}'")
            return finalize(
                f"Alarm {alarm_id} {verb}. The flag settles within a few seconds; re-read with "
                f"cnc_get_alarm. Residue: {', '.join(residue)} — permanent, no delete API."
                f"\n\n{to_json(result)}",
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

        Write. The alarm is resolved first (paged collection read, as in
        cnc_get_alarm), so an unknown id fails WITHOUT sending the write, and
        the PUT carries the platform's own
        spelling of the AlarmId (the match is case-insensitive); then
        PUT /crosswork/alarms/v1/note {"alarmId", "note"} is sent. NOTES ARE
        PERMANENT: there is no API to edit or delete one (verified live), and
        every call appends a new entry, so this tool is not idempotent — do not
        promise "full cleanup" after annotating. For that reason the PUT is NOT
        auto-retried by the client: a transport error or 5xx after the platform
        may have stored the note is reported as "Could not reach the platform
        ... may already have been applied" — check cnc_get_alarm's Notes before
        re-running rather than re-sending blindly. The Notes list (cnc_get_alarm)
        carries full epoch-ms timestamps and is shown newest first; it also
        holds the notes written by cnc_acknowledge_alarm and the platform's own
        "Alarm acknowledged" / "Alarm unacknowledged" entries from note-less
        acks and un-acks (verified live 2026-09-14). Annotating
        does not create an event and does not touch the acknowledge flag.

        Args:
            alarm_id: the AlarmId (exact, case-insensitive).
            note: the text (1..1000 characters), permanent.

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
        resolved first (paged collection read, as in cnc_get_alarm), so an
        unknown id fails WITHOUT
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

    # --- settings writes (alarm/v1, verified live 2026-09-15) ----------------

    async def fetch_catalogue() -> list[dict[str, Any]]:
        """The whole event-type catalogue (``GET severity-config``; ``autoclear`` is the same)."""
        data = await client.request_json("GET", SEVERITY_CONFIG_PATH)
        check_alarm_v1(data, "Event type catalogue read")
        items, _, _ = unwrap(data, "items")
        return [i for i in items if isinstance(i, dict)]

    async def resolve_event_type(name: str) -> dict[str, Any]:
        """The catalogue entry for ``name`` or a PlatformError — nothing is written
        for an unknown name (the platform would answer 400 ``Invalid eventType``
        anyway, but the pre-flight read also gives the before-state)."""
        item = find_event_type(await fetch_catalogue(), name)
        if item is None:
            raise PlatformError(
                f"no event type '{name.strip()}' (find names with cnc_list_event_types)"
            )
        return item

    async def catalogue_write(path: str, body: dict[str, Any], what: str) -> Any:
        """POST a severity-config / autoclear body and turn the platform's answer
        into a PlatformError when it is not a success.

        Success is 200 ``{"status": "OK", "headers": {}, "body": "<text>"}``; the
        400 bodies are PLAIN TEXT (``Invalid eventType`` / ``Invalid sourceValue
        ...``) under a JSON content type. Safe to re-send (a repeat applies the
        same setting), so the POST opts into the client's retry.
        """
        response = await client.request(
            "POST", path, json_body=body, raise_on_error=False, retryable=True
        )
        data = _parse_json(response)
        if not response.is_success:
            message = platform_message(response, data)
            if response.status_code == 400 and _INVALID_EVENT_TYPE in message.lower():
                raise PlatformError(
                    f"{what}: the platform rejected the event type name(s) "
                    f"{body.get('eventTypes')} ({message}); nothing was changed. Use the exact "
                    "names from cnc_list_event_types."
                )
            if response.status_code == 400:
                raise PlatformError(f"{what} rejected: {message}. Nothing was changed.")
            raise http_error(response)
        check_alarm_v1(data, what)
        if isinstance(data, dict) and str(data.get("status", "OK")).upper() not in (
            "OK",
            "SUCCESS",
        ):
            raise PlatformError(f"{what} failed: {platform_message(response, data)}")
        return data

    def require_applied(what: str, applied: bool, response: Any, shows: str) -> None:
        """Raise when the platform accepted a catalogue write but the read-back does
        not show the requested value.

        The catalogue reflects a write on the very next read (verified live
        2026-09-15), so a mismatch means the write was ignored, or a stale
        answer; either way the agent must not be told its request was a no-op.
        """
        if not applied:
            raise PlatformError(
                f"{what}: the platform accepted the write ({str(response)[:300]}) but the "
                f"catalogue still shows {shows}; re-read with cnc_list_event_types"
            )

    async def fetch_flags(path: str, what: str) -> dict[str, Any]:
        data = await client.request_json("GET", path)
        check_alarm_v1(data, what)
        if not isinstance(data, dict):
            raise PlatformError(f"{what}: unexpected response shape: {str(data)[:300]}")
        return data

    async def write_flag(
        path: str, key: str, enabled: bool, what: str, reader: str
    ) -> dict[str, Any]:
        """POST a one-key partial document and verify the echoed stored value.

        The platform stores a non-boolean as ``false`` without complaint
        (verified live), so the value is always a real bool and the answer —
        ``{"<key>": <stored value>}`` — must echo what was asked. An answer
        without the key (``{}`` is what an EMPTY body gets, verified live) is
        an error, not a success: nothing proves the flag was stored.
        """
        response = await client.request(
            "POST", path, json_body={key: bool(enabled)}, raise_on_error=False, retryable=True
        )
        data = _parse_json(response)
        if not response.is_success:
            raise http_error(response)
        check_alarm_v1(data, what)
        if not isinstance(data, dict):
            raise PlatformError(f"{what}: unexpected response shape: {str(data)[:300]}")
        if key not in data:
            raise PlatformError(
                f"{what}: the platform did not echo {key!r} (answer {str(data)[:200]}); "
                f"re-read with {reader}"
            )
        if bool(data[key]) is not bool(enabled):
            raise PlatformError(
                f"{what}: the platform stored {key!r} as {data[key]!r}, not {bool(enabled)!r}"
            )
        return data

    def settings_flag_report(
        heading: str, key: str, before: Any, after: Any, response: dict[str, Any], prefix: str
    ) -> str:
        name = key[len(prefix) :] if prefix and key.startswith(prefix) else key
        changed = bool(before) is not bool(after)
        lines = [
            f"{heading} — {name}: {'on' if after else 'off'}"
            + ("" if changed else " (already; nothing changed)"),
            "",
            to_json(
                {
                    "key": key,
                    "before": bool(before),
                    "after": bool(after),
                    "changed": changed,
                    "response": response,
                }
            ),
        ]
        return "\n".join(lines)

    @register_tool(
        mcp,
        ctx,
        name="cnc_set_event_type_severity",
        title="Set Event Type Severity",
        read_only=False,
        destructive=False,
        idempotent=True,
    )
    async def cnc_set_event_type_severity(
        event_type: Annotated[
            str,
            Field(
                description="Event type name exactly as listed by cnc_list_event_types "
                "(e.g. 'BGP-5-ADJCHANGE_DOWN').",
                min_length=1,
                max_length=200,
            ),
        ],
        severity: Annotated[
            str,
            Field(
                description="New severity: 'critical', 'major', 'minor', 'warning' or "
                "'information' (case-insensitive here; e.g. 'minor').",
                min_length=1,
                max_length=20,
            ),
        ],
    ) -> str:
        """Change the severity Crosswork assigns to every alarm raised from an
        event type (the catalogue's ``severity``).

        Write. Applies to alarms raised from now on for that event type on every
        device; use it to promote a noisy-but-important syslog to Major or demote
        a chatty one to Information. Not for silencing an event type (use a
        suppression policy) and not a per-alarm change (cnc_clear_alarm /
        cnc_acknowledge_alarm act on one alarm). Sends
        POST /crosswork/alarm/v1/severity-config {"sourceType": "scc",
        "sourceValue": "<severity, lowercase>", "eventTypes": ["<name>"]}.

        Read-first / put-it-back recipe: the event type is resolved in the
        catalogue BEFORE the write (unknown name -> error, nothing sent) and the
        answer reports ``before.severity``; to undo, call this tool again with
        ``severity = before.severity``. The change is visible on the very next
        catalogue read (verified live 2026-09-15: Major -> Minor -> Major on
        ROUTING-RIP-6-INFO_OOM, each read back within 0.2 s). Idempotent: the
        same severity twice is a no-op. The platform only accepts the LOWERCASE
        spellings and rejects 'cleared'/'info' (400 ``Invalid sourceValue``); the
        tool normalises case and refuses other values without a call.

        Args:
            event_type: exact catalogue name (case-insensitive match; the write
                uses the platform's spelling).
            severity: critical | major | minor | warning | information.

        Returns:
            str: "Event type <name> severity: <before> -> <after>." followed by
            JSON {"event_type": str, "before": {"name", "category", "severity",
            "autoclear_minutes"}, "after": {...same...}, "changed": bool,
            "response": {"status": "OK", "headers": {}, "body": "Severity
            configuration update success"}}.
            "Error: no event type '<x>' (find names with cnc_list_event_types)"
            for an unknown name (nothing written); "Error: Unknown event severity
            '<x>' ..." for a bad severity (nothing written); "Error: Set severity
            of <name> rejected: <platform text>. Nothing was changed." on a 400;
            "Error: Set severity of <name>: the platform accepted the write
            (...) but the catalogue still shows severity <x>; re-read with
            cnc_list_event_types" when the read-back does not show the requested
            value ("already; nothing changed" is only said when the request
            matched the before-state); other failures: "Error: <actionable
            message>".
        """
        try:
            wire = canonical(severity, EVENT_SEVERITIES, "event severity")
            item = await resolve_event_type(event_type)
            name = str(item.get("name") or item.get("eventTypeName"))
            before = event_type_state(item)
            body = {"sourceType": SEVERITY_SOURCE_TYPE, "sourceValue": wire, "eventTypes": [name]}
            response = await catalogue_write(SEVERITY_CONFIG_PATH, body, f"Set severity of {name}")
            after_item = find_event_type(await fetch_catalogue(), name) or item
            after = event_type_state(after_item)
            changed = before["severity"] != after["severity"]
            # "already" means the REQUEST matched the before-state — never that the
            # read-back merely equals it (which would hide an ignored write).
            require_applied(
                f"Set severity of {name}",
                str(after["severity"]).lower() == wire,
                response,
                f"severity {after['severity']}",
            )
            headline = (
                f"Event type {name} severity: {before['severity']} -> {after['severity']}."
                if changed
                else (
                    f"Event type {name} severity is {after['severity']} (already; nothing changed)."
                )
            )
            return finalize(
                f"{headline}\n\n"
                + to_json(
                    {
                        "event_type": name,
                        "before": before,
                        "after": after,
                        "changed": changed,
                        "response": response,
                    }
                ),
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_set_event_type_autoclear",
        title="Set Event Type Auto-Clear",
        read_only=False,
        destructive=False,
        idempotent=True,
    )
    async def cnc_set_event_type_autoclear(
        event_type: Annotated[
            str,
            Field(
                description="Event type name exactly as listed by cnc_list_event_types "
                "(e.g. 'SECURITY-LOGIN-4-AUTHEN_FAILED').",
                min_length=1,
                max_length=200,
            ),
        ],
        minutes: Annotated[
            int,
            Field(
                description="Auto-clear interval in minutes (e.g. 30 or 1440). The platform "
                "accepts 5-599940; up to 55 it must be a multiple of 5, from 60 up a "
                "multiple of 60.",
                ge=AUTOCLEAR_MIN_MINUTES,
                le=AUTOCLEAR_MAX_MINUTES,
            ),
        ],
    ) -> str:
        """Make alarms of an event type clear themselves after N minutes (the
        catalogue's ``revert`` interval).

        Write. Use it for event types that never send a matching "up"/clear
        event (login failures, threshold crossings) so their alarms do not stay
        open forever. To remove the interval again use
        cnc_revert_event_type_autoclear. Sends POST /crosswork/alarm/v1/autoclear
        {"sourceType": "aac", "sourceValue": "<minutes>", "eventTypes": ["<name>"]}.

        Read-first: the event type is resolved in the catalogue BEFORE the write
        (unknown name -> error, nothing sent) and the answer reports
        ``before.autoclear_minutes`` (null = never), which is what to pass back
        to restore it; when it was null, cnc_revert_event_type_autoclear puts it
        back to never (it deletes the interval — there is no default to
        restore). The new interval shows in the catalogue on the very next read
        (verified live 2026-09-15). Idempotent: the same interval twice is a
        no-op. The platform's rule (5-599940; <= 55 in multiples of 5; >= 60 in
        multiples of 60) is checked here first so a bad value is refused without
        a call.

        Args:
            event_type: exact catalogue name (case-insensitive match).
            minutes: 5..599940 per the rule above.

        Returns:
            str: "Event type <name> auto-clear: <before|never> -> <N> min."
            followed by JSON {"event_type": str, "before": {"name", "category",
            "severity", "autoclear_minutes": int|null}, "after": {...},
            "changed": bool, "response": {"status": "OK", "headers": {},
            "body": "Alarm autoclear update:success"}}.
            "Error: no event type '<x>' ..." for an unknown name (nothing
            written); "Error: auto-clear minutes ... (got N)" for a value the
            platform would refuse (nothing written); "Error: Set auto-clear of
            <name> rejected: <platform text>. Nothing was changed." on a 400;
            "Error: Set auto-clear of <name>: the platform accepted the write
            (...) but the catalogue still shows auto-clear <x>; re-read with
            cnc_list_event_types" when the read-back does not show the requested
            interval ("already; nothing changed" is only said when the request
            matched the before-state); other failures: "Error: <actionable
            message>".
        """
        try:
            problem = autoclear_minutes_error(minutes)
            if problem:
                raise PlatformError(problem)
            item = await resolve_event_type(event_type)
            name = str(item.get("name") or item.get("eventTypeName"))
            before = event_type_state(item)
            body = {
                "sourceType": AUTOCLEAR_SOURCE_TYPE,
                "sourceValue": str(minutes),
                "eventTypes": [name],
            }
            response = await catalogue_write(AUTOCLEAR_PATH, body, f"Set auto-clear of {name}")
            after_item = find_event_type(await fetch_catalogue(), name) or item
            after = event_type_state(after_item)
            changed = before["autoclear_minutes"] != after["autoclear_minutes"]
            was = (
                f"{before['autoclear_minutes']} min"
                if before["autoclear_minutes"] is not None
                else "never"
            )
            now = (
                f"{after['autoclear_minutes']} min"
                if after["autoclear_minutes"] is not None
                else "never"
            )
            require_applied(
                f"Set auto-clear of {name}",
                after["autoclear_minutes"] == minutes,
                response,
                f"auto-clear {now}",
            )
            headline = (
                f"Event type {name} auto-clear: {was} -> {now}."
                if changed
                else f"Event type {name} auto-clear is {now} (already; nothing changed)."
            )
            return finalize(
                f"{headline}\n\n"
                + to_json(
                    {
                        "event_type": name,
                        "before": before,
                        "after": after,
                        "changed": changed,
                        "response": response,
                    }
                ),
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_revert_event_type_autoclear",
        title="Revert Event Type Auto-Clear",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_revert_event_type_autoclear(
        event_type: Annotated[
            str,
            Field(
                description="Event type name exactly as listed by cnc_list_event_types "
                "(e.g. 'SECURITY-LOGIN-4-AUTHEN_FAILED').",
                min_length=1,
                max_length=200,
            ),
        ],
    ) -> str:
        """Remove an event type's auto-clear interval so its alarms stay open
        until cleared by a matching event or an operator.

        Write, destructive: despite the endpoint's name this DELETES the
        interval — it does NOT restore a factory default. Verified live
        2026-09-15: reverting ciscoPtpSlaveLost, which ships with a 1440-minute
        interval, left it with no interval at all (re-set afterwards). So read
        the answer's ``before.autoclear_minutes`` and, to restore, call
        cnc_set_event_type_autoclear with that value. Sends
        POST /crosswork/alarm/v1/autoclear/revert {"eventTypes": ["<name>"]}.

        Read-first: the event type is resolved in the catalogue BEFORE the write
        (unknown name -> error, nothing sent). Idempotent: reverting a type that
        has no interval is a 200 no-op (reported as such). The change is visible
        on the very next catalogue read.

        Args:
            event_type: exact catalogue name (case-insensitive match).

        Returns:
            str: "Event type <name> auto-clear: <N> min -> never." (or "... is
            never (already; nothing changed).") followed by JSON {"event_type",
            "before": {"name", "category", "severity", "autoclear_minutes"},
            "after": {...}, "changed": bool, "response": {"status": "OK",
            "headers": {}, "body": "Alarm autoclear deletion operation completed
            successfully"}}.
            "Error: no event type '<x>' ..." for an unknown name (nothing
            written); "Error: Revert auto-clear of <name>: the platform accepted
            the write (...) but the catalogue still shows auto-clear <N> min;
            re-read with cnc_list_event_types" when the interval is still there
            after the write ("already; nothing changed" is only said when there
            was no interval to begin with); other failures: "Error: <actionable
            message>".
        """
        try:
            item = await resolve_event_type(event_type)
            name = str(item.get("name") or item.get("eventTypeName"))
            before = event_type_state(item)
            response = await catalogue_write(
                AUTOCLEAR_REVERT_PATH, {"eventTypes": [name]}, f"Revert auto-clear of {name}"
            )
            after_item = find_event_type(await fetch_catalogue(), name) or item
            after = event_type_state(after_item)
            changed = before["autoclear_minutes"] != after["autoclear_minutes"]
            require_applied(
                f"Revert auto-clear of {name}",
                after["autoclear_minutes"] is None,
                response,
                f"auto-clear {after['autoclear_minutes']} min",
            )
            headline = (
                f"Event type {name} auto-clear: {before['autoclear_minutes']} min -> never. "
                f"Restore with cnc_set_event_type_autoclear(minutes="
                f"{before['autoclear_minutes']})."
                if changed
                else f"Event type {name} auto-clear is never (already; nothing changed)."
            )
            return finalize(
                f"{headline}\n\n"
                + to_json(
                    {
                        "event_type": name,
                        "before": before,
                        "after": after,
                        "changed": changed,
                        "response": response,
                    }
                ),
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_update_alarm_manager_settings",
        title="Update Alarm Manager Settings",
        read_only=False,
        destructive=False,
        idempotent=True,
    )
    async def cnc_update_alarm_manager_settings(
        device_type: Annotated[
            str,
            Field(
                description="Device type exactly as listed by cnc_get_alarm_manager_settings, "
                "with or without the 'alarmManager/' prefix (e.g. 'Cisco NCS 5001').",
                min_length=1,
                max_length=200,
            ),
        ],
        enabled: Annotated[
            bool,
            Field(
                description="True to turn the alarm manager on for that device type, "
                "False to turn it off."
            ),
        ],
    ) -> str:
        """Turn Crosswork's alarm manager on or off for one device type — whether
        it raises device alarms for that platform family.

        Write. Use it when a family's device alarms are unwanted (off) or missing
        (on). Only device types the platform already lists can be changed: the
        current document is read first and the name resolved against it
        (unknown -> error, nothing sent), because whether an unknown key would be
        created — and could then be removed — is unverified. Sends
        POST /crosswork/alarm/v1/manager/settings {"alarmManager/<type>": bool}, a
        PARTIAL document: only that key changes (verified live 2026-09-15 on
        'Cisco NCS 5001': flipped on and back off, the other 98 keys untouched,
        each read back immediately). The platform echoes {"<key>": <stored>} and
        stores a non-boolean as false without complaint, so the tool sends a real
        boolean and checks the echo. Idempotent.

        Args:
            device_type: the key with or without 'alarmManager/' (case-insensitive).
            enabled: desired state.

        Returns:
            str: "Alarm manager — <type>: on|off" (with "(already; nothing
            changed)" when it was) followed by JSON {"key": "alarmManager/<type>",
            "before": bool, "after": bool, "changed": bool,
            "response": {"alarmManager/<type>": bool}}.
            "Error: no alarm-manager device type '<x>' (list them with
            cnc_get_alarm_manager_settings)" for an unknown type (nothing
            written); "Error: Alarm manager update for <key>: the platform did
            not echo '<key>' ..." / "... stored '<key>' as False, not True"
            when the answer does not prove the flag was stored (re-read with
            cnc_get_alarm_manager_settings); other failures: "Error:
            <actionable message>".
        """
        try:
            current = await fetch_flags(MANAGER_SETTINGS_PATH, "Alarm manager settings read")
            key = resolve_setting_key(current, device_type, MANAGER_KEY_PREFIX)
            if key is None:
                raise PlatformError(
                    f"no alarm-manager device type '{device_type.strip()}' (list them with "
                    "cnc_get_alarm_manager_settings)"
                )
            before = current.get(key)
            response = await write_flag(
                MANAGER_SETTINGS_PATH,
                key,
                enabled,
                f"Alarm manager update for {key}",
                "cnc_get_alarm_manager_settings",
            )
            after = response[key]
            return finalize(
                settings_flag_report(
                    "Alarm manager", key, before, after, response, MANAGER_KEY_PREFIX
                ),
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_update_gnmi_alarm_settings",
        title="Update gNMI Alarm Settings",
        read_only=False,
        destructive=False,
        idempotent=True,
    )
    async def cnc_update_gnmi_alarm_settings(
        enabled: Annotated[
            bool,
            Field(description="True to collect alarms over gNMI for the vendor, False to stop."),
        ],
        vendor: Annotated[
            str,
            Field(
                description="Vendor key as listed by cnc_get_alarm_settings (gNMI section); "
                "the only one on Crosswork 7.2 is 'Cisco Systems' (default).",
                min_length=1,
                max_length=100,
            ),
        ] = "Cisco Systems",
    ) -> str:
        """Turn gNMI-based alarm collection on or off for a vendor.

        Write. Use it when devices are onboarded with gNMI (cnc_enable_device_gnmi)
        and alarms should come over gNMI telemetry instead of syslog/SNMP traps
        — or to stop that. Only vendors the platform already lists can be
        changed: the current document is read first (unknown vendor -> error,
        nothing sent). Sends POST /crosswork/alarm/v1/gnmi/settings {"<vendor>":
        bool}, a PARTIAL document that answers {"<vendor>": <stored>} (verified
        live 2026-09-15: 'Cisco Systems' false -> true -> false, each read back
        immediately; a non-boolean is stored as false, so the tool sends a real
        boolean and checks the echo). Idempotent. Whether existing gNMI-capable
        devices need re-collection after the flip is unverified.

        Args:
            enabled: desired state.
            vendor: 'Cisco Systems' unless the platform lists others.

        Returns:
            str: "gNMI alarm collection — <vendor>: on|off" (with "(already;
            nothing changed)" when it was) followed by JSON {"key": "<vendor>",
            "before": bool, "after": bool, "changed": bool,
            "response": {"<vendor>": bool}}.
            "Error: no gNMI alarm vendor '<x>' (cnc_get_alarm_settings lists
            them)" for an unknown vendor (nothing written); "Error: gNMI alarm
            settings update for <vendor>: the platform did not echo '<vendor>'
            ..." / "... stored '<vendor>' as False, not True" when the answer
            does not prove the flag was stored (re-read with
            cnc_get_alarm_settings); other failures: "Error: <actionable
            message>".
        """
        try:
            current = await fetch_flags(GNMI_SETTINGS_PATH, "gNMI alarm settings read")
            key = resolve_setting_key(current, vendor)
            if key is None:
                raise PlatformError(
                    f"no gNMI alarm vendor '{vendor.strip()}' (cnc_get_alarm_settings lists them)"
                )
            before = current.get(key)
            response = await write_flag(
                GNMI_SETTINGS_PATH,
                key,
                enabled,
                f"gNMI alarm settings update for {key}",
                "cnc_get_alarm_settings",
            )
            after = response[key]
            return finalize(
                settings_flag_report("gNMI alarm collection", key, before, after, response, ""),
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_set_event_type_recommendation",
        title="Set Event Type Recommendation",
        read_only=False,
        destructive=True,
        idempotent=True,
        redact=("explanation", "recommended_action"),
    )
    async def cnc_set_event_type_recommendation(
        event_type: Annotated[
            str,
            Field(
                description="Event type name exactly as listed by cnc_list_event_types "
                "(e.g. 'BGP-5-ADJCHANGE_DOWN').",
                min_length=1,
                max_length=200,
            ),
        ],
        explanation: Annotated[
            str,
            Field(
                description="Custom explanation shown for the event type (e.g. 'A BGP "
                "session to a customer CE dropped'); empty (default) restores the "
                "platform's default explanation.",
                max_length=4000,
            ),
        ] = "",
        recommended_action: Annotated[
            str,
            Field(
                description="Custom recommended action (e.g. 'Open a P2 ticket with the "
                "NOC and check the CE'); empty (default) restores the platform's "
                "default action.",
                max_length=4000,
            ),
        ] = "",
    ) -> str:
        """Set (or clear) the custom explanation and recommended action shown for
        an event type — the text cnc_get_event_type_recommendation returns and
        operators see in the alarm UI.

        Write, destructive: it OVERWRITES both custom texts at once (the platform
        has no per-field update), so pass both — an omitted/empty field clears
        that text back to the platform default. Read-first: the current texts are
        read and reported as ``before`` (restore by passing them back). Sends
        POST /crosswork/alarm/v1/recommended-action {"erroreventype": "<name>",
        "explaination": ..., "recommendedaction": ...} (the platform's own
        spelling) -> 200 {"responseResult": "Data Saved Successfully"}; the GET
        shows the new text immediately (verified live 2026-09-15: set, read
        back, cleared with empty strings, read back as defaults). The endpoint
        answers 200 for error documents too ({"responseResult": "Invalid input
        ..."}), so the tool trusts only the read-back: after the write the texts
        are read again and must equal what was sent (whitespace-trimmed), else
        the tool is an error. ``nextstepupdate`` becomes 1 after the first save
        and stays 1 — a "custom text was ever saved" flag, not a next step.
        Idempotent. The texts are withheld from the dry-run echo (they are
        free-form runbook text).

        Args:
            event_type: exact catalogue name (find it with cnc_list_event_types).
            explanation / recommended_action: the custom texts; empty clears.

        Returns:
            str: "Recommendation for <name> saved." (or "... cleared to the platform
            defaults.") followed by JSON {"event_type": str,
            "before": {"explanation": str, "recommended_action": str},
            "after": {"explanation": str, "recommended_action": str},
            "defaults": {"explanation": str, "recommended_action": str},
            "response": {"responseResult": "Data Saved Successfully"}}. The
            headline follows the REQUEST (both texts empty -> "cleared"), the
            JSON the read-back.
            "Error: no event type '<x>' (find names with cnc_list_event_types)"
            when the platform answers 400 "EventType does not exist" (nothing
            saved); "Error: Set recommendation for <name>: the platform answered
            <its text> but the read-back shows {...}; re-read with
            cnc_get_event_type_recommendation" when a 200 answer did not store
            the texts (an error document such as "Invalid input ...", or an
            ignored write); other failures: "Error: <actionable message>".
        """
        try:
            name = event_type.strip()

            async def read_texts() -> dict[str, Any]:
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
                return body if isinstance(body, dict) else {}

            current = await read_texts()
            before = {
                "explanation": current.get("explaination") or "",
                "recommended_action": current.get("recommendedaction") or "",
            }
            body = {
                "erroreventype": name,
                "explaination": explanation.strip(),
                "recommendedaction": recommended_action.strip(),
            }
            response = await client.request(
                "POST",
                RECOMMENDED_ACTION_PATH,
                json_body=body,
                raise_on_error=False,
                retryable=True,
            )
            data = _parse_json(response)
            if response.status_code == 400 and _EVENT_TYPE_MISSING in _response_result(data):
                raise PlatformError(
                    f"no event type '{name}' (find names with cnc_list_event_types)"
                )
            if not response.is_success:
                raise http_error(response)
            check_alarm_v1(data, f"Set recommendation for {name}")
            if isinstance(data, dict) and str(data.get("status", "Success")).lower() not in (
                "success",
                "ok",
            ):
                raise PlatformError(
                    f"Set recommendation for {name} failed: {platform_message(response, data)}"
                )
            latest = await read_texts()
            after = {
                "explanation": latest.get("explaination") or "",
                "recommended_action": latest.get("recommendedaction") or "",
            }
            # The only proof of success is the read-back: the endpoint answers 200
            # for error documents too ({"responseResult": "Invalid input ..."}), and
            # a silently ignored write would otherwise be reported as done.
            wanted = {
                "explanation": body["explaination"],
                "recommended_action": body["recommendedaction"],
            }
            if after != wanted:
                raise PlatformError(
                    f"Set recommendation for {name}: the platform answered "
                    f"{platform_message(response, data)} but the read-back shows "
                    f"{str(after)[:300]}; re-read with cnc_get_event_type_recommendation"
                )
            cleared = not (wanted["explanation"] or wanted["recommended_action"])
            headline = (
                f"Recommendation for {name} cleared to the platform defaults."
                if cleared
                else f"Recommendation for {name} saved."
            )
            return finalize(
                f"{headline}\n\n"
                + to_json(
                    {
                        "event_type": name,
                        "before": before,
                        "after": after,
                        "defaults": {
                            "explanation": latest.get("defaultexplaination") or "",
                            "recommended_action": latest.get("defaultrecommendedaction") or "",
                        },
                        "response": data,
                    }
                ),
                settings,
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_update_alarm_suppression_policy",
        title="Update Alarm Suppression Policy",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_update_alarm_suppression_policy(
        name: Annotated[
            str,
            Field(
                description="Policy name as listed by cnc_list_alarm_suppression_policies "
                "(e.g. 'suppress-bgp-flaps'). Names cannot be changed.",
                min_length=1,
                max_length=200,
            ),
        ],
        description: Annotated[
            str | None,
            Field(
                description="New free-text description (e.g. 'Maintenance window extended'); "
                "omit to keep the current one.",
                max_length=1000,
            ),
        ] = None,
        criteria: Annotated[
            str | None,
            Field(
                description="New event-type criteria, e.g. 'eventType in [BGP-5-ADJCHANGE_DOWN,"
                "BGP-5-ADJCHANGE_UP]' (names from cnc_list_event_types); omit to keep.",
                max_length=2000,
            ),
        ] = None,
        action: Annotated[
            str | None,
            Field(
                description="New action: 'suppressAlarm' (drop the alarm) or 'suppressEvent' "
                "(drop the event too); omit to keep."
            ),
        ] = None,
        device_groups: Annotated[
            str | None,
            Field(
                description="New comma-separated device-group UUIDs (e.g. 'uuid-1,uuid-2'); "
                "'' (empty string) scopes the policy to ALL devices; omit to keep.",
                max_length=4000,
            ),
        ] = None,
    ) -> str:
        """Change an existing alarm suppression policy's description, criteria,
        action or device-group scope (its name is fixed; delete and recreate to
        rename).

        Write, destructive: the platform's PUT replaces the whole rule, so the
        tool reads the policy first and merges only the fields given over the
        current values (an omitted field is kept; nothing is sent when no field
        is given or the policy does not exist). Sends
        PUT /crosswork/alarm/v1/suppressionpolicy {"policyname", "description",
        "action", "deviceGroups": [...], "criteria"} — the collection path (a
        PUT on /<name> is 405) with the FULL body (a partial body is 400
        {"Message ": "Action type is null"}) -> 200 {"Message": "Success",
        "status": "Success"}; the list shows the new values immediately
        (verified live 2026-09-15: description, action and criteria changed on a
        phase-d policy and read back). An unknown name is 400 {"Message":
        "Failed to update policy rule <name>"}. Idempotent.

        Args:
            name: existing policy name (case-insensitive match).
            description / criteria / action / device_groups: the new values;
                omit any to keep it. device_groups='' means all devices.

        Returns:
            str: "Suppression policy '<name>' updated (<fields>)." followed by JSON
            {"before": {<policy as listed>}, "policy": {<body sent>},
             "changed": [field, ...], "response": {"Message": "Success",
             "status": "Success"}}.
            "Error: no suppression policy '<x>' (list with
            cnc_list_alarm_suppression_policies)" when it does not exist (nothing
            sent); "Error: nothing to update ..." when no field is given; "Error:
            Update suppression policy '<x>' rejected: <platform text>" on a 400;
            other failures: "Error: <actionable message>".
        """
        try:
            wire_action = canonical(action, SUPPRESSION_ACTIONS, "suppression action")
            if (
                description is None
                and criteria is None
                and action is None
                and device_groups is None
            ):
                raise PlatformError(
                    "nothing to update: give at least one of description, criteria, action, "
                    "device_groups"
                )
            data = await client.request_json("GET", SUPPRESSION_POLICY_PATH)
            check_alarm_v1(data, "Suppression policy read")
            policies, _, _ = unwrap(data, "data")
            current = find_policy([p for p in policies if isinstance(p, dict)], name)
            if current is None:
                raise PlatformError(
                    f"no suppression policy '{name.strip()}' (list with "
                    "cnc_list_alarm_suppression_policies)"
                )
            groups_before = (
                [str(g) for g in current.get("deviceGroups")]
                if isinstance(current.get("deviceGroups"), list)
                else []
            )
            body = {
                "policyname": str(current.get("policyname")),
                "description": (
                    description.strip()
                    if description is not None
                    else str(current.get("description") or "")
                ),
                "action": wire_action or str(current.get("action") or SUPPRESSION_ACTIONS[0]),
                "deviceGroups": (
                    [g.strip() for g in device_groups.split(",") if g.strip()]
                    if device_groups is not None
                    else groups_before
                ),
                "criteria": criteria.strip()
                if criteria is not None
                else str(current.get("criteria") or ""),
            }
            changed = [
                field
                for field, key, old in (
                    ("description", "description", str(current.get("description") or "")),
                    ("action", "action", str(current.get("action") or "")),
                    ("device_groups", "deviceGroups", groups_before),
                    ("criteria", "criteria", str(current.get("criteria") or "")),
                )
                if body[key] != old
            ]
            response = await client.request(
                "PUT", SUPPRESSION_POLICY_PATH, json_body=body, raise_on_error=False
            )
            result = _parse_json(response)
            if not response.is_success:
                message = platform_message(response, result)
                if response.status_code == 400 and _POLICY_UPDATE_FAILED in message.lower():
                    raise PlatformError(
                        f"no suppression policy '{body['policyname']}' — the platform refused "
                        f"the update ({message}); list with cnc_list_alarm_suppression_policies "
                        "and verify the criteria syntax."
                    )
                if response.status_code == 400:
                    raise PlatformError(
                        f"Update suppression policy '{body['policyname']}' rejected: {message}"
                    )
                raise http_error(response)
            check_alarm_v1(result, f"Update suppression policy '{body['policyname']}'")
            if (
                isinstance(result, dict)
                and str(result.get("status", "Success")).lower() != "success"
            ):
                raise PlatformError(
                    f"Update suppression policy '{body['policyname']}' failed: "
                    f"{platform_message(response, result)}"
                )
            what = ", ".join(changed) if changed else "no field differed; re-sent as is"
            return finalize(
                f"Suppression policy '{body['policyname']}' updated ({what}).\n\n"
                + to_json(
                    {"before": current, "policy": body, "changed": changed, "response": result}
                ),
                settings,
            )
        except Exception as e:
            return format_error(e)
