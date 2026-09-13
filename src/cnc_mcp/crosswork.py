"""Crosswork-specific request/response helpers shared by every tool module.

Everything here encodes behaviour verified live against Crosswork Network
Controller (see the platform notes). The two rules that matter most:

- Inventory collections are read with ``POST .../query`` and a body of
  ``{"filter": {...}, "filterData": {"PageSize": n, "PageNum": p}}``. A
  top-level ``limit`` is honoured but ``offset`` is silently ignored, so paging
  MUST go through ``filterData``.
- Inventory writes answer with a *job envelope* (``job_id``, ``state``, ...),
  and a failed write is an HTTP 200 whose ``state`` is ``JOB_FAILED``. Every
  write must go through :func:`check_job`.

The inventory idiom does not generalise. The other JSON-over-POST services
behind the same gateway each have their own grammar (verified live
2026-09-12) and get their own helpers here:

- **dg-manager** (``/crosswork/dg-manager/v1|v2``): bodies are
  ``{"filterData": {"Criteria": "select * from <Table>"}}`` (or ``{}``) and
  unknown fields are *rejected* with 400 — :func:`dg_query_body`.
- **collection/v1**: ``query_options`` token paging and a
  ``result.request_result`` verdict — :func:`collection_query_body`,
  :func:`collection_next_token`, :func:`check_collection_result`.
- **alarm/v1**: failures ride inside HTTP 200 as
  ``{"error": "Fail", "code": n, "message": ...}`` — :func:`check_alarm_v1`.
- **alarms/v1** (the UI's endpoint; marked deprecated in the 7.2 document but
  answering live): a SQL-like ``criteria`` string with ``limit N page M``
  paging — :func:`alarms_criteria`.
"""

from __future__ import annotations

from typing import Any

from cnc_mcp.errors import PlatformError
from cnc_mcp.formatting import pagination_envelope

INVENTORY = "/crosswork/inventory/v1"
AAA = "/crosswork/aaa/v1"
ALARMS = "/crosswork/alarms/v1"
# The documented alarm lifecycle API (POST .../query); distinct from the UI's ALARMS above.
ALARM_V1 = "/crosswork/alarm/v1"
PLATFORM = "/crosswork/platform/v2"
DG_MANAGER = "/crosswork/dg-manager/v1"
COLLECTION = "/crosswork/collection/v1"

# dg-manager query tables (verified: ``select * from RobotDataGateway`` lists gateways;
# ``hapool/query`` answers on v1 and v2 with different address shapes).
# dg-manager tables and the body grammar each query endpoint accepts (verified live):
# dg/query wants {"filterData": {"Criteria": ...}}; hapool/query rejects filterData
# ("unknown field \"filterData\" in robotapi.HAPoolGetReq") and wants {"criteria": ...}.
DG_TABLES = {"gateways": "RobotDataGateway", "pools": "HAPool"}
_DG_GRAMMAR = {"RobotDataGateway": "filterData", "HAPool": "criteria"}

# alarms/v1 criteria paging bound exposed by the tools (the platform's own maximum is
# not verified; 20 was the UI's page size).
ALARMS_MAX_LIMIT = 200

COLLECTION_ACCEPTED = "ACCEPTED"

JOB_COMPLETED = "JOB_COMPLETED"
# RobotNodeJob.state (documented enum): JOB_INVALID, JOB_REJECTED, JOB_ACCEPTED,
# JOB_DB_UPDATED, JOB_NOTIFICATION_PUBLISHED, JOB_COMPLETED, JOB_FAILED, JOB_RUNNING,
# JOB_PARTIAL, JOB_COMPLETED_WITH_WARNING.
# Verified: a no-op or partially applied write answers JOB_COMPLETED_WITH_WARNING with the
# note in "error" — a success with an advisory. Asynchronous actions (the NSO device
# actions) answer JOB_ACCEPTED immediately and finish later — accepted, not failed.
JOB_SUCCESS_STATES = {JOB_COMPLETED, "JOB_COMPLETED_WITH_WARNING", "JOB_PARTIAL"}
JOB_PENDING_STATES = {"JOB_ACCEPTED", "JOB_RUNNING", "JOB_DB_UPDATED", "JOB_NOTIFICATION_PUBLISHED"}
JOB_FAILURE_STATES = {"JOB_FAILED", "JOB_REJECTED", "JOB_INVALID", "JOB_CANCELLED", "JOB_ABORTED"}
JOB_TERMINAL_STATES = JOB_SUCCESS_STATES | JOB_FAILURE_STATES

# Wire enums (verified). UI labels in comments.
ADMIN_STATES = {
    "up": "ROBOT_ADMIN_STATE_UP",  # Up
    "down": "ROBOT_ADMIN_STATE_DOWN",  # Down
    "unmanaged": "ROBOT_ADMIN_STATE_UNMANAGED",  # Unmanaged
}
REACHABILITY_STATES = {
    "reachable": "CONN_STATE_REACHABLE",
    "unreachable": "CONN_STATE_UNREACHABLE",
    "degraded": "CONN_STATE_DEGRADED",
    "unknown": "CONN_STATE_UNKNOWN",
}
PROVIDER_FAMILIES = {
    "sr_pce": "ROBOT_PROVIDER_SR_PCE",
    "nso": "ROBOT_PROVIDER_NSO",
    "wae": "ROBOT_PROVIDER_WAE",
    "syslog_storage": "ROBOT_PROVIDER_SYSLOG_STORAGE",
    "alert": "ROBOT_PROVIDER_ALERT",
    "proxy": "ROBOT_PROVIDER_PROXY",
    "onc": "ROBOT_PROVIDER_ONC",
    "accedian_proxy": "ROBOT_PROVIDER_ACCEDIAN_PROXY",
}
TRANSPORTS = {
    "ssh": "ROBOT_MSVC_TRANS_SSH",
    "snmp": "ROBOT_MSVC_TRANS_SNMP",
    "http": "ROBOT_MSVC_TRANS_HTTP",
    "https": "ROBOT_MSVC_TRANS_HTTPS",
    "netconf": "ROBOT_MSVC_TRANS_NETCONF",
    "telnet": "ROBOT_MSVC_TRANS_TELNET",
    "tcp": "ROBOT_MSVC_TRANS_TCP",
    "gnmi": "ROBOT_MSVC_TRANS_GNMI",
    "grpc": "ROBOT_MSVC_TRANS_GRPC",
}
DEFAULT_PORTS = {
    "ssh": 22,
    "snmp": 161,
    "http": 80,
    "https": 443,
    "netconf": 830,
    "telnet": 23,
    "tcp": 0,
    "gnmi": 57400,
    "grpc": 57400,
}
CAPABILITIES = {"snmp": "SNMP", "yang_cli": "YANG_CLI", "yang_mdt": "YANG_MDT", "gnmi": "GNMI"}


def wire_enum(table: dict[str, str], value: str | None, what: str) -> str | None:
    """Translate a friendly enum value (case-insensitive) to its wire form.

    Accepts the wire form itself too, so agents that learned the wire value from
    a previous response can pass it straight back.
    """
    if value is None or value == "":
        return None
    key = value.strip().lower()
    if key in table:
        return table[key]
    if value in table.values():
        return value
    raise PlatformError(f"Unknown {what} '{value}'. Use one of: {', '.join(sorted(table))}.")


def query_body(
    filters: dict[str, str | None] | None,
    *,
    page_size: int,
    page: int,
) -> dict[str, Any]:
    """Build an inventory ``*/query`` body.

    Filter values are exact-match, case-insensitive, and may contain ``*`` as a
    wildcard. Empty/None values are dropped. Callers must only pass field names
    known to the endpoint: unknown names are silently ignored by Crosswork and
    the whole collection comes back.
    """
    clean = {k: v for k, v in (filters or {}).items() if v not in (None, "")}
    return {
        "filter": clean,
        "filterData": {"PageSize": page_size, "PageNum": page, "Criteria": ""},
    }


def unwrap(data: Any, key: str) -> tuple[list[Any], int | None, int | None]:
    """Unwrap a query response into (items, result_count, total_count).

    Envelope keys differ per endpoint (``data``, ``tags``, ``jobs``,
    ``providers``...). An empty result is a bare ``{}`` with no list key at all,
    and ``result_count`` is omitted when zero matched — both are normal.
    """
    if not isinstance(data, dict):
        return [], None, None
    items = data.get(key)
    if not isinstance(items, list):
        items = []
    result_count = data.get("result_count")
    total_count = data.get("total_count")
    return (
        items,
        result_count if isinstance(result_count, int) else None,
        total_count if isinstance(total_count, int) else None,
    )


def page_envelope(
    items: list[Any],
    *,
    result_count: int | None,
    total_count: int | None,
    page_size: int,
    page: int,
) -> dict[str, Any]:
    """Pagination envelope in page terms, on top of the template's offset one.

    ``total`` is the number of matches for the filter (``result_count``);
    Crosswork's ``total_count`` is the size of the whole collection regardless
    of filter, and is exposed separately as ``collection_total``.
    """
    env = pagination_envelope(items, total=result_count, offset=page * page_size, limit=page_size)
    env["page"] = page
    env["page_size"] = page_size
    env["next_page"] = page + 1 if env["has_more"] else None
    env["collection_total"] = total_count
    return env


def check_job(result: Any, what: str) -> dict[str, Any]:
    """Validate an inventory write's job envelope; raise PlatformError on failure.

    Crosswork returns HTTP 200 for failed writes with ``state`` in
    :data:`JOB_FAILURE_STATES` and the reason in ``error``. Success states
    return the envelope with ``impacted`` parsed into ``impacted_objects`` and
    any advisory (``JOB_COMPLETED_WITH_WARNING`` / ``JOB_PARTIAL``) copied to
    ``warning``. Pending states (:data:`JOB_PENDING_STATES` — what an
    asynchronous action such as an NSO device action answers) are returned with
    ``pending: True`` so the caller can point the agent at a wait tool; they
    are not failures.
    """
    if not isinstance(result, dict) or "state" not in result:
        raise PlatformError(
            f"{what}: Crosswork did not return a job envelope. Response: {str(result)[:300]}"
        )
    state = result.get("state")
    if state in JOB_PENDING_STATES:
        result["pending"] = True
        result["impacted_objects"] = parse_impacted(result.get("impacted"))
        return result
    if state not in JOB_SUCCESS_STATES:
        reason = result.get("error") or result.get("type") or "no reason given"
        raise PlatformError(f"{what} failed (job {result.get('job_id')}, state {state}): {reason}")
    if state != JOB_COMPLETED and result.get("error"):
        result["warning"] = result["error"]
    result["impacted_objects"] = parse_impacted(result.get("impacted"))
    return result


def is_job_pending(result: Any) -> bool:
    """True when a job envelope's state is one of :data:`JOB_PENDING_STATES`."""
    return isinstance(result, dict) and result.get("state") in JOB_PENDING_STATES


def parse_impacted(impacted: Any) -> list[dict[str, str]]:
    """``impacted`` entries are ``"<uuid> <name> [<ip>]"`` strings; split them."""
    out: list[dict[str, str]] = []
    for entry in impacted or []:
        if not isinstance(entry, str):
            continue
        parts = entry.split()
        if not parts:
            continue
        obj = {"uuid": parts[0]}
        if len(parts) > 1:
            obj["name"] = parts[1]
        if len(parts) > 2:
            obj["ip"] = parts[2]
        out.append(obj)
    return out


def ipaddr(address: str, prefix_length: int | None = None) -> dict[str, Any]:
    """Address object for write bodies (``inet_af`` is 0 on write, a string on read)."""
    obj: dict[str, Any] = {"inet_af": 0, "inet_addr": address}
    if prefix_length is not None:
        obj["mask"] = str(prefix_length)
    return obj


def dg_query_body(table: str, criteria: str | None = None) -> dict[str, Any]:
    """Build a dg-manager ``*/query`` body in the grammar that table's endpoint accepts.

    Verified live — the grammars differ per endpoint inside one service:
    ``POST /crosswork/dg-manager/v2/dg/query`` takes
    ``{"filterData": {"Criteria": "select * from RobotDataGateway"}}`` (or a bare
    ``{}``), while ``POST …/hapool/query`` (v1 and v2) takes
    ``{"criteria": "select * from HAPool"}`` and answers ``400 unable to
    unmarshal payload to proto … unknown field "filterData"`` for the other
    form. dg-manager rejects unknown fields everywhere, so the body contains
    nothing else. ``table`` is a :data:`DG_TABLES` key (``gateways``,
    ``pools``) or a wire table name; ``criteria`` replaces the default
    ``select * from <Table>`` when given.
    """
    key = table.strip().lower()
    if key in DG_TABLES:
        wire = DG_TABLES[key]
    elif table in DG_TABLES.values():
        wire = table
    else:
        raise PlatformError(
            f"Unknown Data Gateway table '{table}'. Use one of: {', '.join(sorted(DG_TABLES))}."
        )
    if criteria is None:
        criteria = f"select * from {wire}"
    if _DG_GRAMMAR[wire] == "criteria":
        return {"criteria": criteria}
    return {"filterData": {"Criteria": criteria}}


def collection_query_body(
    page_size: int = 100,
    page_token: str = "0",
    filters: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a collection/v1 ``*/query`` body with ``query_options`` token paging.

    UNVERIFIED-as-request: the live call that was verified sent ``{}`` and the
    platform echoed ``"query_options": {"page_token": "0", "page_size": 100,
    "filter_list": []}`` in the response, from which this request shape is
    inferred. The published Collection Service document agrees
    (``QueryOptions{page_token, page_size, filter_list}``; its examples use
    ``page_token: ""``). Pass the ``page_token`` the previous response echoed to
    fetch the next page; ``filters`` are ``{"operator": "OPERATOR_AND",
    "field_list": [{"field": ..., "value": ...}]}`` entries.

    End of data is UNVERIFIED: the document says an empty ``page_token`` means
    no more pages ("If collection_job_device_sets is empty or the page token
    are empty, there are no more results"), but the lab's empty ``jobs/query``
    echoed ``"0"`` — stop on an empty item list OR an empty/unchanged token
    until verified live. :func:`collection_next_token` applies that rule.
    """
    return {
        "query_options": {
            "page_size": page_size,
            "page_token": page_token,
            "filter_list": list(filters or []),
        }
    }


def collection_next_token(data: Any, sent_token: str | None = None) -> str | None:
    """The ``page_token`` to send for the next collection/v1 page, or None at the end.

    Returns None when the response carries no ``query_options.page_token``, when
    the token is empty (the documented end-of-data signal), or when it equals
    ``sent_token`` (the lab's empty ``jobs/query`` echoed the ``"0"`` it was sent,
    so an unchanged token cannot mean "more"). Callers must ALSO stop on an empty
    item list — the stop condition is UNVERIFIED live, see
    :func:`collection_query_body`.
    """
    if not isinstance(data, dict):
        return None
    options = data.get("query_options")
    token = options.get("page_token") if isinstance(options, dict) else None
    if not isinstance(token, str) or token == "":
        return None
    if sent_token is not None and token == sent_token:
        return None
    return token


def check_collection_result(data: Any, what: str) -> dict[str, Any]:
    """Validate a collection/v1 response's ``result`` verdict; raise PlatformError on rejection.

    Verified live: every collection/v1 answer carries ``{"result":
    {"request_result": "ACCEPTED"|"REJECTED", "error": {"error": "<reason>"}}}``
    alongside the payload, and a rejected request is still HTTP 200. Returns
    ``data`` when the verdict is ``ACCEPTED``.
    """
    result = data.get("result") if isinstance(data, dict) else None
    if not isinstance(result, dict) or "request_result" not in result:
        raise PlatformError(
            f"{what}: Crosswork did not return a collection result envelope. "
            f"Response: {str(data)[:300]}"
        )
    verdict = result.get("request_result")
    if verdict != COLLECTION_ACCEPTED:
        error = result.get("error")
        reason = error.get("error") if isinstance(error, dict) else error
        raise PlatformError(
            f"{what} was {verdict or 'not accepted'}: {reason or 'no reason given'}"
        )
    return data


def check_alarm_v1(data: Any, what: str) -> Any:
    """Raise PlatformError when an alarm/v1 HTTP 200 body is an error document; else return data.

    Verified live: ``POST /crosswork/alarm/v1/query`` reports failures as HTTP
    200 with ``{"error": "Fail", "code": 0, "message": "Input Request is
    invalid"}``, so the HTTP status proves nothing and every alarm/v1 response
    must pass through here.
    """
    if isinstance(data, dict) and str(data.get("error", "")).strip().lower() == "fail":
        message = data.get("message") or "no reason given"
        code = data.get("code")
        suffix = f" (code {code})" if code is not None else ""
        raise PlatformError(f"{what} failed{suffix}: {message}")
    return data


def alarms_criteria(
    limit: int,
    page: int,
    *,
    where: str | None = None,
    order: str | None = None,
) -> str:
    """The ``criteria`` string for ``POST /crosswork/alarms/v1/query``.

    Verified live: only ``select * from alarm limit {limit} page {page}`` with a
    0-based page (the UI sends ``limit 20 page 0``). The 7.2 alarms document
    (``crosswork_alarms_and_events_ap_is_7_2_0.json``) shows the same grammar
    taking ``where`` and ``order`` clauses — e.g. ``select * from event limit
    100 page 0 where eventCategory=3 order userName asc`` — and marks
    ``POST /crosswork/alarms/v1/query`` ``deprecated: true`` (it still answers
    on the lab). ``where``/``order`` are appended verbatim as ``where {where}``
    / ``order {order}`` and are UNVERIFIED live for alarms; leave them unset for
    the verified form. ``limit`` must be 1..:data:`ALARMS_MAX_LIMIT` and
    ``page`` >= 0 — enforced here so a bad value is a clear PlatformError
    rather than a 500 from the platform.
    """
    if not 1 <= limit <= ALARMS_MAX_LIMIT:
        raise PlatformError(
            f"Alarm page size must be between 1 and {ALARMS_MAX_LIMIT}, got {limit}."
        )
    if page < 0:
        raise PlatformError(f"Alarm page number must be 0 or greater, got {page}.")
    criteria = f"select * from alarm limit {limit} page {page}"
    if where and where.strip():
        criteria += f" where {where.strip()}"
    if order and order.strip():
        criteria += f" order {order.strip()}"
    return criteria
