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
"""

from __future__ import annotations

from typing import Any

from cnc_mcp.errors import PlatformError
from cnc_mcp.formatting import pagination_envelope

INVENTORY = "/crosswork/inventory/v1"
TOPOLOGY = "/crosswork/topology/v1/topology-service/topology"
AAA = "/crosswork/aaa/v1"
ALARMS = "/crosswork/alarms/v1"
PLATFORM = "/crosswork/platform/v2"

JOB_COMPLETED = "JOB_COMPLETED"
# Verified: a no-op or partially applied write answers JOB_COMPLETED_WITH_WARNING with the
# note in "error". It is a success with an advisory, not a failure.
JOB_SUCCESS_STATES = {JOB_COMPLETED, "JOB_COMPLETED_WITH_WARNING"}
JOB_TERMINAL_STATES = JOB_SUCCESS_STATES | {"JOB_FAILED", "JOB_CANCELLED", "JOB_ABORTED"}

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

    Crosswork returns HTTP 200 for failed writes with ``state`` outside
    :data:`JOB_SUCCESS_STATES` and the reason in ``error``. Returns the envelope
    (with ``impacted`` parsed into ``impacted_objects`` and any advisory from a
    ``JOB_COMPLETED_WITH_WARNING`` state copied to ``warning``) when the job
    completed.
    """
    if not isinstance(result, dict) or "state" not in result:
        raise PlatformError(
            f"{what}: Crosswork did not return a job envelope. Response: {str(result)[:300]}"
        )
    state = result.get("state")
    if state not in JOB_SUCCESS_STATES:
        reason = result.get("error") or result.get("type") or "no reason given"
        raise PlatformError(f"{what} failed (job {result.get('job_id')}, state {state}): {reason}")
    if state != JOB_COMPLETED and result.get("error"):
        result["warning"] = result["error"]
    result["impacted_objects"] = parse_impacted(result.get("impacted"))
    return result


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
