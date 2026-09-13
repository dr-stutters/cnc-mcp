"""Inventory extras — DLM summaries and configuration, tags on devices,
geo-coordinates and device locks, all on ``/crosswork/inventory/v1``.

Everything here was verified live against Crosswork Network Controller 7.2
on 2026-09-13 (every write reverted afterwards); the exact paths, bodies and
answers are in the platform notes and repeated in the tool docstrings.

Reads (``GET`` summaries and ``POST .../query {}`` reads):

- ``GET nodes/count`` -> ``{"number_of_nodes": n}``; ``GET
  nodes/operstatesummary`` -> ``{"ok": 4, "checking": 1}`` with the keys
  ``ok|checking|down|error|unmanaged|locked|deleting`` ABSENT when 0; ``GET
  nodes/reachabilitysummary`` -> ``{"reachable": 5}`` (``reachable|
  unreachable|degraded|unknown``, absent when 0); ``GET
  sysoids/licensetype/count/query`` -> ``{"LicenseTypeCount": {"Type A": 5,
  ...}}``. The summary tool renders every absent key as 0.
- ``POST inventoryconfig/query {}`` -> ``{"name", "device": {"host_identifier"}}``;
  ``POST policies/query {}`` -> ``{"data": [{name, invType, fields[], Type}],
  "total_count"}``; ``POST devicepackage/cadence/query {}`` ->
  ``{"JobToCadence": {"reach-check": 600, ...}}`` (seconds).
- ``sysoids/query`` and ``sysoids/vendors/query`` need an undocumented ORM
  ``Criteria`` string (every table name tried answered ``"Could not find
  Struct <x> in Orm Registry"`` / ``"invalid query"``) — unusable, NOT exposed.

Device selection (``POST nodes/query``, :func:`cnc_mcp.crosswork.query_body`):
filters are exact-match, case-insensitive, with ``*`` as a wildcard anywhere in
the value (``PE*``); there is no substring match without ``*``. Every write
here resolves its selector FIRST, refuses when nothing matches (nothing is
sent), and reports the devices it acted on. Device records expose the tags as
``tag_names`` (a list of strings); the ``tags`` object list is never populated
on reads.

Job envelopes (every inventory write except the lock): the answer is
``{"job_id", "state", "type", "error"?, "impacted"?, ...}`` and a failed write
is HTTP 200 with ``state: JOB_FAILED`` — every write goes through
:func:`cnc_mcp.crosswork.check_job`. ``JOB_COMPLETED_WITH_WARNING`` is a
success with an advisory (returned as ``warning``); a tag assignment answers it
with "Note, if device ... is used in NSO, any updates to it needs be done
through NSO interface". A ``PATCH nodes`` (tag assignment, cnc_update_device)
flips the device to ``ROBOT_OPER_STATE_CHECKING`` for a while — a lock taken
right after a PATCH fails until the device is back to ``ROBOT_OPER_STATE_OK``.

Tags: ``POST tags {"tags": [{"name", "category"}]}`` creates; a duplicate is
``JOB_FAILED "The tag <n> already exists. Provide a unique name for the new
tag."``. ``DELETE tags {"tags": [{"name"}]}`` deletes; while any device
carries the tag it is ``JOB_FAILED "Tag Name:<n> is in use and cannot be
deleted."``. Assign = ``PATCH nodes {"data": [{"uuid", "tags": [{"name"}]}]}``
(the tag is ADDED to the device's ``tag_names``; system tags stay). Unassign =
``PUT nodes/unassigntag {"data": [{"uuid", "tag_names": [...]}]}`` — with the
``"tags": [{"name"}]`` object form the job also says JOB_COMPLETED but NOTHING
is removed (verified silent no-op), so this module only ever sends
``tag_names``.

Geo-coordinates: ``PATCH nodesgeocoord {"Operation": "UpdateGeoCoordinates",
"node_uuid_to_geocoords": {"<uuid>": {"latitude": {"value": 51.5},
"longitude": {"value": -0.12}}}}`` — the ``{"value": n}`` (``robotapiDouble``)
wrapper is REQUIRED; bare numbers answer ``500 "NATS request failed"``.
``"Operation": "RemoveGeoCoordinates"`` with ``{"<uuid>": {}}`` clears them
(the device then reads ``geo_info.coordinates {}``).

Device locks (what Change Automation and Pulse take while they work on a
device): ``POST locknodes {"state": "LOCKED", "uuids": [...], "owner_cookie",
"timeout": "<seconds as a string>"}``. The answer is NOT a job envelope:
success is ``{"rc": "NODE_REQ_SUCCESS", "rc_msg": "Operation success",
"owner_cookie", "lock_id", "start_time", "end_time"}``; failure is HTTP 200
with ONLY ``rc_msg`` (e.g. ``"Node:<uuid> is allowed to lock only in
Operational state:ROBOT_OPER_STATE_OK"``) — a missing or non-SUCCESS ``rc`` is
a failure. Unlock = ``{"state": "UNLOCKED", "uuids": [...], "owner_cookie",
"lock_id"}``; unlocking a device that is not locked answers ``{"rc_msg":
"Error Locking Node!"}``. A locked device shows ``lock_status {lock_id, state
LOCKED, owner, start_time, end_time}`` and the lock expires at ``end_time``.
Whether the platform checks ``owner_cookie`` on unlock is NOT verified, so
cnc_unlock_device itself refuses (before sending) a lock whose ``owner``
differs from the given owner unless ``lock_id`` is passed explicitly.

Selector paging: ``result_count`` (matches before paging) is OMITTED on a
``uuid`` filter (verified), so a full page without it means the match count
is unknown — the single-page writes refuse it rather than write a partial
set; the wildcard unassign scans every page instead.
"""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.crosswork import INVENTORY, check_job, query_body, unwrap
from cnc_mcp.errors import PlatformError, format_error
from cnc_mcp.formatting import epoch_iso, finalize, to_json
from cnc_mcp.safety import AppContext, register_tool

NODES_URL = f"{INVENTORY}/nodes"
NODES_QUERY_URL = f"{NODES_URL}/query"
NODES_COUNT_URL = f"{NODES_URL}/count"
OPER_STATE_SUMMARY_URL = f"{NODES_URL}/operstatesummary"
REACHABILITY_SUMMARY_URL = f"{NODES_URL}/reachabilitysummary"
LICENSE_TYPE_COUNT_URL = f"{INVENTORY}/sysoids/licensetype/count/query"
INVENTORY_CONFIG_QUERY_URL = f"{INVENTORY}/inventoryconfig/query"
POLICIES_QUERY_URL = f"{INVENTORY}/policies/query"
CADENCE_QUERY_URL = f"{INVENTORY}/devicepackage/cadence/query"
TAGS_URL = f"{INVENTORY}/tags"
UNASSIGN_TAG_URL = f"{NODES_URL}/unassigntag"
GEOCOORD_URL = f"{INVENTORY}/nodesgeocoord"
LOCK_NODES_URL = f"{INVENTORY}/locknodes"

# robotapiOperStateSummary / robotapiReachabilitySummary keys (documented; verified live
# that a zero count is ABSENT from the answer).
OPER_STATE_KEYS = ("ok", "checking", "down", "error", "unmanaged", "locked", "deleting")
REACHABILITY_KEYS = ("reachable", "unreachable", "degraded", "unknown")

# robotapiRobotNodeOperationalState (OpenAPI, "derived state for a device"): UNKNOWN |
# UNMANAGED | ADMIN_DOWN | CHECKING | OK | ERROR | LOCKED | DELETING. Only OK can be locked.
OPER_STATE_OK = "ROBOT_OPER_STATE_OK"
OPER_STATE_CHECKING = "ROBOT_OPER_STATE_CHECKING"
OPER_STATE_LOCKED = "ROBOT_OPER_STATE_LOCKED"
OPER_STATES_ADMIN = ("ROBOT_OPER_STATE_UNMANAGED", "ROBOT_OPER_STATE_ADMIN_DOWN")
# robotapiRobotEntityLockState: INVALID_STATE | UNLOCKED | LOCKED | ERRORED (ERRORED = the
# owner neither renewed nor released the lock within its timeout).
LOCK_STATE_LOCKED = "LOCKED"
# robotapiRobotNodeReqRc: NODE_REQ_INVALID | NODE_REQ_SUCCESS | NODE_REQ_FAILURE |
# NODE_REQ_DEV_NOT_FOUND | NODE_REQ_REJECTED. Verified: a refused lock carries no rc at all.
LOCK_RC_SUCCESS = "NODE_REQ_SUCCESS"
GEO_UPDATE = "UpdateGeoCoordinates"
GEO_REMOVE = "RemoveGeoCoordinates"
DEFAULT_LOCK_OWNER = "cnc-mcp"
DEFAULT_TAG_CATEGORY = "default"

# How many devices one bulk tag write may name (one nodes/query page). The PATCH/PUT lists
# every uuid explicitly, so a match beyond the page a selector resolved would be silently
# left out — the tools refuse instead and ask for a narrower selector. A wildcard
# unassign SCANS every page (a read) and bounds only the carriers it will name.
SELECTOR_PAGE_SIZE = 100
# Upper bound on the pages a full scan walks (a guard against a platform that keeps
# answering full pages); 100 pages x 100 = 10 000 devices.
SCAN_MAX_PAGES = 100
# How many skipped devices a wildcard unassign lists in full (the count is always exact).
SKIPPED_LIST_LIMIT = 25

# What the DLM persistent jobs in the cadence map do. Most job names match a system tag a
# device carries (reach-check, snmp, te-tunnel-id); the show-clock job corresponds to the
# clock-drift-check tag — there is no 'show-clock' tag (the 12 built-ins are cli, snmp,
# gnmi, mdt, ios-xr, reach-check, clock-drift-check, te-tunnel-id, fault-*, PM_*).
CADENCE_JOBS = {
    "reach-check": "reachability probe (tag reach-check)",
    "show-clock": "clock-drift check (tag clock-drift-check)",
    "snmp": "SNMP inventory collection (tag snmp)",
    "te-tunnel-id": "TE tunnel-id collection (tag te-tunnel-id)",
}

_SELECTOR_HELP = (
    "Filters are exact-match, case-insensitive, '*' wildcard; list devices with cnc_list_devices."
)
_BATCH_HELP = "Narrow the host_name pattern (e.g. 'PE*') and run it in batches."


def lock_hint(oper: Any, uuid: str) -> str:
    """What to do about a lock refusal, by the device's ``operational_state``.

    Only ROBOT_OPER_STATE_OK can be locked (verified). The advice differs per
    state: CHECKING passes on its own, LOCKED means a lock is already held,
    UNMANAGED / ADMIN_DOWN need an admin-state change, the rest are named.
    """
    if oper == OPER_STATE_OK:
        return ""
    if oper == OPER_STATE_CHECKING:
        return (
            " The device is ROBOT_OPER_STATE_CHECKING: a PATCH (tag assignment, "
            "cnc_update_device, a geo-coordinate change) or a fresh add flips it there for a "
            "while — wait for cnc_get_device to read ROBOT_OPER_STATE_OK again and retry."
        )
    if oper == OPER_STATE_LOCKED:
        return (
            " The device is ROBOT_OPER_STATE_LOCKED: it already carries a device lock — read "
            "lock_status (owner, lock_id, end_time) with cnc_get_device_tags and release it "
            "with cnc_unlock_device if it is yours, or wait for it to expire at end_time."
        )
    if oper in OPER_STATES_ADMIN:
        return (
            f" The device is {oper}: its admin state keeps it out of service and only "
            f"ROBOT_OPER_STATE_OK can be locked — bring it up with cnc_update_device("
            f"uuid='{uuid}', admin_state='up'), wait for cnc_get_device to read OK and retry."
        )
    return (
        f" The device is {oper or 'in an unknown operational state'}; only "
        "ROBOT_OPER_STATE_OK can be locked (cnc_get_device shows the state and its errors)."
    )


def create_tag_hint(reason: str, tag_name: str) -> str:
    """Runtime pointer for a failed tag creation (appended to the platform's reason)."""
    if "already exists" in reason.lower():
        return (
            f" Tag names are unique across categories: list the existing tags with "
            f"cnc_list_tags, then either use '{tag_name}' as it is (cnc_assign_tags) or pick "
            "another name."
        )
    return " List the existing tags with cnc_list_tags."


def delete_tag_hint(reason: str, tag_name: str) -> str:
    """Runtime pointer for a failed tag deletion: the free-before-delete sequence."""
    if "in use" in reason.lower():
        return (
            f" A tag that any device carries cannot be deleted: free it first with "
            f"cnc_unassign_tags(tags='{tag_name}', host_name='*') (it scans every device and "
            f"removes the tag from the carriers, up to {SELECTOR_PAGE_SIZE} per call — narrow "
            "host_name into batches beyond that), then delete it again."
        )
    return " Check the tag (name, tag_type, devices_tagged) with cnc_list_tags."


# --- pure helpers ------------------------------------------------------------


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


def is_wildcard(selector: dict[str, str]) -> bool:
    """True when the selector value carries the '*' wildcard (may match several devices)."""
    return "*" in next(iter(selector.values()))


def split_tags(tags: str) -> list[str]:
    """'site-a, site-b' -> ['site-a', 'site-b'] (order kept, duplicates dropped); error if empty."""
    out: list[str] = []
    for token in (tags or "").split(","):
        name = token.strip()
        if name and name not in out:
            out.append(name)
    if not out:
        raise PlatformError(
            "tags is empty: give one or more tag names separated by commas (e.g. 'site-a' or "
            "'site-a,ring-1'); list the defined tags with cnc_list_tags."
        )
    return out


def summary_counts(data: Any, keys: tuple[str, ...]) -> dict[str, int]:
    """A summary answer with every documented key present (absent = 0; extra keys kept)."""
    counts = {key: 0 for key in keys}
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, int) and not isinstance(value, bool):
                counts[str(key)] = value
    return counts


def _nonzero(counts: dict[str, int], keys: tuple[str, ...]) -> str:
    ordered = list(keys) + [k for k in counts if k not in keys]
    return " / ".join(f"{counts[k]} {k}" for k in ordered if counts.get(k))


def summary_line(
    total: int | None,
    oper: dict[str, int],
    reach: dict[str, int],
    licenses: dict[str, Any],
) -> str:
    """'5 devices: 4 ok / 1 checking; 5 reachable; licenses Type A 5'."""
    head = f"{total} devices" if total is not None else "unknown number of devices"
    oper_text = _nonzero(oper, OPER_STATE_KEYS) or "no operational-state counts"
    reach_text = _nonzero(reach, REACHABILITY_KEYS) or "no reachability counts"
    lic_text = ", ".join(f"{k} {v}" for k, v in licenses.items() if v) or "none"
    return f"{head}: {oper_text}; {reach_text}; licenses {lic_text}"


def cadence_line(job_to_cadence: dict[str, Any]) -> str:
    """'reach-check every 600 s, show-clock every 1800 s, ...'."""
    parts = [f"{job} every {seconds} s" for job, seconds in job_to_cadence.items()]
    return ", ".join(parts) if parts else "no cadences reported"


def device_ref(node: dict[str, Any]) -> dict[str, Any]:
    return {"host_name": node.get("host_name"), "uuid": node.get("uuid")}


def tag_names_of(node: dict[str, Any]) -> list[str]:
    """The device's ``tag_names`` (strings; the ``tags`` object list is never populated)."""
    names = node.get("tag_names")
    return [str(n) for n in names] if isinstance(names, list) else []


def lock_status_of(node: dict[str, Any]) -> dict[str, Any] | None:
    status = node.get("lock_status")
    return status if isinstance(status, dict) and status else None


def is_locked(node: dict[str, Any]) -> bool:
    status = lock_status_of(node)
    return bool(status and status.get("state") == LOCK_STATE_LOCKED and status.get("lock_id"))


def geo_coordinates_of(node: dict[str, Any]) -> dict[str, float] | None:
    """``geo_info.coordinates`` with the ``{"value": n}`` wrappers flattened; None when unset.

    A cleared device reads ``geo_info.coordinates {}`` (verified) — that is None here.
    """
    geo = node.get("geo_info")
    coords = geo.get("coordinates") if isinstance(geo, dict) else None
    if not isinstance(coords, dict):
        return None
    out: dict[str, float] = {}
    for key in ("latitude", "longitude", "altitude"):
        entry = coords.get(key)
        if isinstance(entry, dict):
            entry = entry.get("value")
        if isinstance(entry, int | float) and not isinstance(entry, bool):
            out[key] = entry
    return out or None


def device_tags_view(node: dict[str, Any]) -> dict[str, Any]:
    return {
        **device_ref(node),
        "tag_names": tag_names_of(node),
        "lock_status": lock_status_of(node),
        "geo_coordinates": geo_coordinates_of(node),
    }


def device_tags_line(view: dict[str, Any]) -> str:
    tags = ", ".join(view["tag_names"]) or "(none)"
    lock = view["lock_status"]
    if lock and lock.get("state") == LOCK_STATE_LOCKED:
        lock_text = (
            f"LOCKED by {lock.get('owner') or '?'} until {epoch_iso(lock.get('end_time'))} "
            f"(lock_id {lock.get('lock_id') or '?'})"
        )
    elif lock:
        lock_text = str(lock.get("state") or "?").lower()
    else:
        lock_text = "unlocked"
    geo = view["geo_coordinates"]
    if geo:
        geo_text = f"{geo.get('latitude', '?')}, {geo.get('longitude', '?')}"
        if "altitude" in geo:
            geo_text += f", altitude {geo['altitude']}"
    else:
        geo_text = "none"
    return (
        f"**{view['host_name'] or '?'}** ({view['uuid'] or '?'}) tags: {tags}; "
        f"lock: {lock_text}; location: {geo_text}"
    )


def geo_body(
    uuid: str, latitude: float, longitude: float, altitude: float | None = None
) -> dict[str, Any]:
    """The verified ``PATCH nodesgeocoord`` body: every number inside a ``{"value": n}`` wrapper."""
    coords: dict[str, Any] = {
        "latitude": {"value": latitude},
        "longitude": {"value": longitude},
    }
    if altitude is not None:
        coords["altitude"] = {"value": altitude}
    return {"Operation": GEO_UPDATE, "node_uuid_to_geocoords": {uuid: coords}}


def geo_clear_body(uuid: str) -> dict[str, Any]:
    return {"Operation": GEO_REMOVE, "node_uuid_to_geocoords": {uuid: {}}}


def lock_body(uuid: str, owner: str, timeout_seconds: int) -> dict[str, Any]:
    """The verified ``POST locknodes`` lock body (``timeout`` is a string of seconds)."""
    return {
        "state": LOCK_STATE_LOCKED,
        "uuids": [uuid],
        "owner_cookie": owner,
        "timeout": str(timeout_seconds),
    }


def unlock_body(uuid: str, owner: str, lock_id: str) -> dict[str, Any]:
    return {"state": "UNLOCKED", "uuids": [uuid], "owner_cookie": owner, "lock_id": lock_id}


def check_lock_response(result: Any, what: str, hint: str = "") -> dict[str, Any]:
    """Validate a ``locknodes`` answer; raise PlatformError unless ``rc`` is NODE_REQ_SUCCESS.

    Verified live: a refused lock/unlock is HTTP 200 with ONLY ``rc_msg`` (no
    ``rc``), so a missing ``rc`` counts as failure and ``rc_msg`` is the reason.
    """
    if not isinstance(result, dict):
        raise PlatformError(
            f"{what}: Crosswork did not return a lock response. Response: {str(result)[:300]}"
        )
    rc = result.get("rc")
    if rc != LOCK_RC_SUCCESS:
        reason = result.get("rc_msg") or "no reason given"
        code = f" (rc {rc})" if rc else ""
        raise PlatformError(f"{what} failed{code}: {reason}{hint}")
    return result


def _times(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "start_time": result.get("start_time"),
        "start_time_iso": epoch_iso(result.get("start_time")),
        "end_time": result.get("end_time"),
        "end_time_iso": epoch_iso(result.get("end_time")),
    }


def _policy_line(policy: dict[str, Any]) -> str:
    fields = policy.get("fields")
    field_text = ", ".join(str(f) for f in fields) if isinstance(fields, list) and fields else "-"
    return (
        f"- **{policy.get('name', '?')}**: {policy.get('invType', '?')}, "
        f"{policy.get('Type', '?')}, fields: {field_text}"
    )


# --- tools -------------------------------------------------------------------


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    async def query_page(
        selector: dict[str, str], page: int
    ) -> tuple[list[dict[str, Any]], int | None, int | None]:
        """One ``nodes/query`` page for the selector -> (nodes, result_count, total_count).

        ``result_count`` (matches before paging) is omitted by Crosswork when
        nothing matched AND on a ``uuid`` filter (verified) — None here.
        """
        data = await client.request_json(
            "POST",
            NODES_QUERY_URL,
            json_body=query_body(selector, page_size=SELECTOR_PAGE_SIZE, page=page),
            retryable=True,  # a read: safe to re-send on 5xx / transport errors
        )
        items, result_count, total_count = unwrap(data, "data")
        return [n for n in items if isinstance(n, dict)], result_count, total_count

    def no_match(selector: dict[str, str]) -> PlatformError:
        return PlatformError(
            f"no device matches {describe_selector(selector)}; nothing was changed. "
            f"{_SELECTOR_HELP}"
        )

    async def resolve_devices(selector: dict[str, str]) -> list[dict[str, Any]]:
        """Every device the selector matches, from ONE page; PlatformError when none
        match or the match may exceed the page (the write would silently drop the rest).

        A match count above the page is refused when Crosswork reports it
        (``result_count``); when it does not (a ``uuid`` filter never carries
        ``result_count``, verified) a FULL page means the count is unknown and
        the selection may be incomplete — refused as well, nothing is sent.
        """
        nodes, result_count, total_count = await query_page(selector, 0)
        if not nodes:
            raise no_match(selector)
        if result_count is not None and result_count > len(nodes):
            raise PlatformError(
                f"{describe_selector(selector)} matches {result_count} devices, more than the "
                f"{SELECTOR_PAGE_SIZE} this tool handles in one call; nothing was changed. "
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
                f"nothing was changed. {_BATCH_HELP}"
            )
        return nodes

    async def scan_devices(selector: dict[str, str]) -> list[dict[str, Any]]:
        """Every device the selector matches across ALL pages (a read-only scan, deduplicated
        by uuid); PlatformError when none match. The caller bounds what it writes."""
        nodes: list[dict[str, Any]] = []
        seen: set[str] = set()
        for page in range(SCAN_MAX_PAGES):
            page_nodes, result_count, _ = await query_page(selector, page)
            for n in page_nodes:
                key = str(n.get("uuid"))
                if key not in seen:
                    seen.add(key)
                    nodes.append(n)
            if len(page_nodes) < SELECTOR_PAGE_SIZE:
                break  # a short (or empty: past the end) page ends the scan
            if result_count is not None and len(nodes) >= result_count:
                break
        else:
            raise PlatformError(
                f"{describe_selector(selector)} matches more than "
                f"{SCAN_MAX_PAGES * SELECTOR_PAGE_SIZE} devices; nothing was changed. "
                f"{_BATCH_HELP}"
            )
        if not nodes:
            raise no_match(selector)
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

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_device_summary",
        title="Get Device Inventory Summary",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_device_summary() -> str:
        """Count the inventory's devices by operational state, reachability and
        license type — the headline numbers of the Network Devices page.

        Read-only; four GETs on /crosswork/inventory/v1: ``nodes/count``,
        ``nodes/operstatesummary``, ``nodes/reachabilitysummary`` and
        ``sysoids/licensetype/count/query``. Use it as the first health check
        before drilling in with cnc_list_devices (e.g. reachability='unreachable')
        or cnc_get_device_collection_summary (collection status). Crosswork omits
        a state whose count is 0 (verified); every documented key is rendered
        here with 0 so the shape is stable. Operational states: ok, checking
        (first contact or right after a PATCH), down, error, unmanaged
        (admin_state unmanaged), locked (a device lock — see cnc_lock_device),
        deleting. License types come from the sysoid catalogue (Type A/B/C,
        Unlicensed).

        Returns:
            str: One markdown line ("5 devices: 4 ok / 1 checking; 5 reachable;
            licenses Type A 5") followed by JSON:
            {"total": int|null,
             "operational_state": {"ok", "checking", "down", "error", "unmanaged",
                                   "locked", "deleting": int},
             "reachability": {"reachable", "unreachable", "degraded", "unknown": int},
             "license_types": {"<type>": int}}
            On failure: "Error: ..." (403 -> the account lacks the inventory
            read task; 500 'NATS request failed' -> the platform could not
            process the request).
        """
        try:
            count = await client.request_json("GET", NODES_COUNT_URL)
            oper = await client.request_json("GET", OPER_STATE_SUMMARY_URL)
            reach = await client.request_json("GET", REACHABILITY_SUMMARY_URL)
            lic = await client.request_json("GET", LICENSE_TYPE_COUNT_URL)
            total = count.get("number_of_nodes") if isinstance(count, dict) else None
            oper_counts = summary_counts(oper, OPER_STATE_KEYS)
            reach_counts = summary_counts(reach, REACHABILITY_KEYS)
            licenses = lic.get("LicenseTypeCount") if isinstance(lic, dict) else None
            licenses = licenses if isinstance(licenses, dict) else {}
            payload = {
                "total": total if isinstance(total, int) else None,
                "operational_state": oper_counts,
                "reachability": reach_counts,
                "license_types": licenses,
            }
            head = summary_line(payload["total"], oper_counts, reach_counts, licenses)
            return finalize(f"{head}\n{to_json(payload)}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_inventory_config",
        title="Get Inventory Configuration",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_inventory_config() -> str:
        """Get the DLM inventory configuration (how devices are identified) and the
        unique-key policies the inventory enforces.

        Read-only; ``POST inventoryconfig/query {}`` and ``POST policies/query
        {}`` (verified empty bodies). ``device.host_identifier`` says what the
        DLM treats as a device's identity: HOSTNAME_ONLY (the bare host name)
        or HOSTNAME_AND_DOMAIN (host name plus domain — the lab's value). The
        unique-key policies (``Default Policy`` on the lab, with an empty
        ``fields`` list) name the node fields whose values must be unique
        across the inventory; ``Type`` INDEPENDENT means each listed field on
        its own, COMBINED the combination; ``invType`` is INV_TYPE_NODE (in
        this release policies exist only for nodes). Use it when a device add
        fails with a uniqueness error, or to learn whether host names are
        compared with their domain. Writing either object is out of scope.

        Returns:
            str: Markdown (configuration name, host identifier, one line per
            policy) followed by JSON:
            {"inventory_config": {"name": str, "device": {"host_identifier": str}},
             "unique_policies": [{"name", "invType", "fields": [str], "Type"}],
             "total_policies": int}
            On failure: "Error: ..." (500 'NATS request failed' -> the body
            could not be parsed).
        """
        try:
            config = await client.request_json(
                "POST", INVENTORY_CONFIG_QUERY_URL, json_body={}, retryable=True
            )
            policies_data = await client.request_json(
                "POST", POLICIES_QUERY_URL, json_body={}, retryable=True
            )
            config = config if isinstance(config, dict) else {}
            items, _, total_count = unwrap(policies_data, "data")
            policies = [p for p in items if isinstance(p, dict)]
            payload = {
                "inventory_config": config,
                "unique_policies": policies,
                "total_policies": total_count if total_count is not None else len(policies),
            }
            device = config.get("device") if isinstance(config.get("device"), dict) else {}
            lines = [
                f"# Inventory configuration '{config.get('name', '?')}'",
                "",
                f"- host identifier: {device.get('host_identifier', '?')} (HOSTNAME_ONLY = "
                "devices are identified by bare host name; HOSTNAME_AND_DOMAIN = host name "
                "plus domain)",
                f"- unique-key policies ({payload['total_policies']}):",
            ]
            lines.extend(_policy_line(p) for p in policies)
            if not policies:
                lines.append("- (none)")
            lines.extend(["", to_json(payload)])
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_collection_cadence",
        title="Get Collection Cadence",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_collection_cadence() -> str:
        """Get how often the DLM's persistent collection jobs run (seconds per job).

        Read-only; ``POST devicepackage/cadence/query {}`` (verified) answers
        ``{"JobToCadence": {"reach-check": 600, "show-clock": 1800, "snmp":
        1200, "te-tunnel-id": 1200}}`` — the interval in seconds of the
        reachability probe, the clock-drift check, the SNMP inventory
        collection and the TE tunnel-id collection. Most job names match a
        system tag the device carries when the job runs on it (reach-check,
        snmp, te-tunnel-id in tag_names, see cnc_get_device_tags /
        cnc_list_tags); the show-clock job corresponds to the
        clock-drift-check tag — there is no 'show-clock' tag. Use it to explain
        how stale a device's reachability or inventory data can be, or before
        judging a wait as "too long". Changing the cadence (``PUT
        devicepackage/cadence``, same shape) is not exposed.

        Returns:
            str: One markdown line ("reach-check every 600 s, show-clock every
            1800 s, ...") and one naming each known job and its tag, followed
            by the JSON as Crosswork returns it:
            {"JobToCadence": {"<job>": <seconds>}}
            On failure: "Error: ...".
        """
        try:
            data = await client.request_json(
                "POST", CADENCE_QUERY_URL, json_body={}, retryable=True
            )
            data = data if isinstance(data, dict) else {}
            cadence = data.get("JobToCadence")
            cadence = cadence if isinstance(cadence, dict) else {}
            head = cadence_line(cadence)
            described = [f"{job}: {CADENCE_JOBS[job]}" for job in cadence if job in CADENCE_JOBS]
            if described:
                head += f"\n({'; '.join(described)})"
            return finalize(f"{head}\n{to_json({'JobToCadence': cadence})}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_device_tags",
        title="Get Device Tags, Lock and Location",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_device_tags(
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
    ) -> str:
        """Read one device's tags, lock status and geo-coordinates.

        Read-only. Pass exactly one selector (uuid or host_name — exact match,
        case-insensitive, '*' wildcard; it must resolve to one device). The
        answer is the device's ``tag_names`` — system tags Crosswork derives
        from its capabilities (``cli``, ``snmp``, ``mdt``, ``reach-check``,
        ...) plus every user tag assigned with cnc_assign_tags — its
        ``lock_status`` when it has ever been locked (``state`` LOCKED /
        UNLOCKED / ERRORED, ``owner``, ``lock_id``, ``start_time``/``end_time``
        epoch seconds) and its geo-coordinates (``geo_info.coordinates`` with
        the ``{"value": n}`` wrappers flattened; null when never set or
        cleared). Use it before cnc_unassign_tags (which refuses tags the
        device does not carry), before cnc_delete_tag (a tag in use cannot be
        deleted) and before cnc_unlock_device (it needs the lock_id and owner).

        Returns:
            str: One markdown line ("**PE1** (uuid) tags: cli, snmp, site-a;
            lock: unlocked | LOCKED by <owner> until <iso> (lock_id ...);
            location: 51.5, -0.12 | none") followed by JSON:
            {"host_name": str, "uuid": str, "tag_names": [str],
             "lock_status": {"lock_id", "state", "owner", "start_time", "end_time"}|null,
             "geo_coordinates": {"latitude": float, "longitude": float,
                                 "altitude"?: float}|null}
            "Error: no device matches ..." when nothing matches; "Error: ...
            matched N devices" for an ambiguous wildcard; "Error: ..." on an
            API failure.
        """
        try:
            node = await find_one_device(_selector(uuid, host_name))
            view = device_tags_view(node)
            return finalize(f"{device_tags_line(view)}\n{to_json(view)}", settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_create_tag",
        title="Create Tag",
        read_only=False,
        destructive=False,
        idempotent=False,
    )
    async def cnc_create_tag(
        name: Annotated[
            str,
            Field(
                description="Name of the new tag, unique on the platform (e.g. 'site-a').",
                min_length=1,
                max_length=64,
            ),
        ],
        category: Annotated[
            str,
            Field(
                description="Tag category the UI groups tags by (e.g. 'default').",
                min_length=1,
                max_length=64,
            ),
        ] = DEFAULT_TAG_CATEGORY,
    ) -> str:
        """Create a user-defined tag that can then be assigned to devices.

        WRITE operation — only registered when CNC_MCP_ENABLE_WRITES=true.
        Sends ``POST /crosswork/inventory/v1/tags {"tags": [{"name", "category"}]}``
        (verified) and answers with the job envelope ("1 tag(s) added
        successfully"). Tag names are unique across categories: a duplicate is
        an HTTP 200 job with state JOB_FAILED and the reason "The tag <name>
        already exists. Provide a unique name for the new tag." — reported as
        an Error that points at cnc_list_tags. Check cnc_list_tags first when
        unsure. Creating a tag does not tag any device: follow with
        cnc_assign_tags. The POST is not auto-retried (a lost answer cannot
        create the tag twice: a re-run answers the duplicate error).

        Args:
            name: the tag name (1-64 characters).
            category: the category (default 'default').

        Returns:
            str: JSON job envelope {"job_id", "state": "JOB_COMPLETED", "type":
            "1 tag(s) added successfully", "impacted_objects": [...], ...} plus
            "tag": {"name", "category"}. On failure: "Error: Creating tag '<n>'
            failed (job ..., state JOB_FAILED): The tag <n> already exists...
            list the existing tags with cnc_list_tags ...", or "Error: ..." on
            an API failure.
        """
        try:
            tag = {"name": name.strip(), "category": category.strip()}
            result = await client.request_json("POST", TAGS_URL, json_body={"tags": [tag]})
            try:
                job = check_job(result, f"Creating tag '{tag['name']}'")
            except PlatformError as e:
                raise PlatformError(f"{e}{create_tag_hint(str(e), tag['name'])}") from e
            return finalize(to_json({**job, "tag": tag}), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_tag",
        title="Delete Tag",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_tag(
        name: Annotated[
            str,
            Field(
                description="Name of the tag to delete (e.g. 'site-a').",
                min_length=1,
                max_length=64,
            ),
        ],
    ) -> str:
        """Delete a user-defined tag from the platform.

        DESTRUCTIVE write — only registered when CNC_MCP_ENABLE_WRITES=true.
        Sends ``DELETE /crosswork/inventory/v1/tags {"tags": [{"name"}]}``
        (verified; the collection URL with a body is the only form).

        Ordering rule (verified live): a tag that any device still carries
        cannot be deleted — the job is HTTP 200 with state JOB_FAILED and
        "Tag Name:<n> is in use and cannot be deleted." (the Error repeats the
        sequence below). Unassign it from every device first:
        cnc_unassign_tags(tags='<n>', host_name='*') scans the whole inventory
        (every nodes/query page — tag_names cannot be filtered server-side)
        and removes the tag from every carrier, up to 100 carriers per call;
        when more devices carry it, run it in host_name batches ('PE*', 'P*',
        ...) — cnc_list_tags shows ``devices_tagged`` per tag. Then delete.
        System tags (tag_type TAG_TYPE_SYSTEM / TAG_TYPE_INTERNAL in
        cnc_list_tags: cli, snmp, mdt, reach-check, ...) are Crosswork's own;
        whether the platform refuses to delete them was not exercised — leave
        them alone.

        Returns:
            str: JSON job envelope {"job_id", "state": "JOB_COMPLETED", ...}
            plus "tag": {"name"}. On failure: "Error: Deleting tag '<n>' failed
            (job ..., state JOB_FAILED): Tag Name:<n> is in use and cannot be
            deleted. A tag that any device carries cannot be deleted: free it
            first with cnc_unassign_tags(...) ...", or "Error: ..." on an API
            failure.
        """
        try:
            tag_name = name.strip()
            result = await client.request_json(
                "DELETE", TAGS_URL, json_body={"tags": [{"name": tag_name}]}
            )
            try:
                job = check_job(result, f"Deleting tag '{tag_name}'")
            except PlatformError as e:
                raise PlatformError(f"{e}{delete_tag_hint(str(e), tag_name)}") from e
            return finalize(to_json({**job, "tag": {"name": tag_name}}), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_assign_tags",
        title="Assign Tags to Devices",
        read_only=False,
        destructive=False,
        idempotent=True,
    )
    async def cnc_assign_tags(
        tags: Annotated[
            str,
            Field(
                description=(
                    "Comma-separated tag names to add to the device(s) (e.g. 'site-a' or "
                    "'site-a,ring-1'). The tags must already exist (cnc_list_tags / "
                    "cnc_create_tag)."
                ),
                min_length=1,
                max_length=500,
            ),
        ],
        uuid: Annotated[
            str | None,
            Field(
                description="Device uuid to tag (e.g. '2a9b7c1e-0f3d-4b8a-9c6e-1d2f3a4b5c6d').",
                max_length=100,
            ),
        ] = None,
        host_name: Annotated[
            str | None,
            Field(
                description=(
                    "Device host name to tag: exact match, case-insensitive, '*' wildcard "
                    "(e.g. 'PE1' or 'PE*' — every match is tagged)."
                ),
                max_length=253,
            ),
        ] = None,
    ) -> str:
        """Assign one or more existing tags to the selected device(s).

        WRITE operation — only registered when CNC_MCP_ENABLE_WRITES=true.
        The selector (exactly one of uuid / host_name; host_name may carry
        '*') is resolved with ``POST nodes/query`` FIRST: zero matches is an
        Error and nothing is sent; more than 100 matches is refused (narrow
        the pattern), and so is a full page of 100 whose match count Crosswork
        did not report (a uuid filter never reports it) — a partial write is
        never sent. Then ONE ``PATCH /crosswork/inventory/v1/nodes {"data":
        [{"uuid": <device>, "tags": [{"name": <tag>}, ...]}, ...]}`` (verified)
        with one entry per matched device adds the tags to each device's
        ``tag_names`` (existing tags, system tags included, stay). Assigning
        a tag the device already carries is harmless.

        The job normally answers JOB_COMPLETED_WITH_WARNING with the advisory
        "Note, if device <host> is used in NSO, any updates to it needs be done
        through NSO interface" — that is a success, returned as ``warning``.
        Side effect (verified): the PATCH flips each device to
        ROBOT_OPER_STATE_CHECKING for a while, so a cnc_lock_device right
        afterwards fails until it reads ROBOT_OPER_STATE_OK again. Tags cannot
        be set at device creation (cnc_create_device) — this is the way. What
        the platform answers for a tag name that does not exist was not
        captured live; create tags first. The PATCH is not auto-retried.

        Args:
            tags: comma-separated tag names.
            uuid / host_name: exactly one selector; host_name may use '*'.

        Returns:
            str: JSON job envelope {"job_id", "state": "JOB_COMPLETED" |
            "JOB_COMPLETED_WITH_WARNING", "warning"?: str, "impacted_objects":
            [...], ...} plus "tags": [str] and "devices": [{"host_name",
            "uuid"}] (the devices the PATCH named). "Error: no device matches
            ..." (nothing sent), "Error: tags is empty ...", "Error: Assigning
            tags ... failed (job ..., state JOB_FAILED): <reason>", or
            "Error: ..." on an API failure.
        """
        try:
            names = split_tags(tags)
            selector = _selector(uuid, host_name)
            nodes = await resolve_devices(selector)
            tag_objects = [{"name": n} for n in names]
            body = {"data": [{"uuid": node.get("uuid"), "tags": tag_objects} for node in nodes]}
            result = await client.request_json("PATCH", NODES_URL, json_body=body)
            job = check_job(result, f"Assigning tags {', '.join(names)} to {len(nodes)} device(s)")
            payload = {**job, "tags": names, "devices": [device_ref(n) for n in nodes]}
            return finalize(to_json(payload), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_unassign_tags",
        title="Unassign Tags from Devices",
        read_only=False,
        destructive=False,
        idempotent=True,
    )
    async def cnc_unassign_tags(
        tags: Annotated[
            str,
            Field(
                description=(
                    "Comma-separated tag names to remove from the device(s) (e.g. 'site-a' or "
                    "'site-a,ring-1'); see the device's tag_names in cnc_get_device_tags."
                ),
                min_length=1,
                max_length=500,
            ),
        ],
        uuid: Annotated[
            str | None,
            Field(
                description="Device uuid to untag (e.g. '2a9b7c1e-0f3d-4b8a-9c6e-1d2f3a4b5c6d').",
                max_length=100,
            ),
        ] = None,
        host_name: Annotated[
            str | None,
            Field(
                description=(
                    "Device host name to untag: exact match, case-insensitive, '*' wildcard "
                    "(e.g. 'PE1', or '*' to strip the tags from every device carrying them)."
                ),
                max_length=253,
            ),
        ] = None,
    ) -> str:
        """Remove one or more tags from the selected device(s).

        WRITE operation — only registered when CNC_MCP_ENABLE_WRITES=true.
        The selector is resolved with ``POST nodes/query`` FIRST (zero matches
        -> Error, nothing sent). An exact selector reads one page; a wildcard
        selector SCANS every page of the inventory (a read — ``tag_names``
        cannot be filtered server-side, verified 500), so host_name='*' finds
        every carrier however large the inventory. Then ONE ``PUT
        /crosswork/inventory/v1/nodes/unassigntag {"data": [{"uuid": <device>,
        "tag_names": [<tag>, ...]}, ...]}`` (verified) naming only the devices
        that carry a requested tag; more than 100 carriers is refused before
        anything is sent — narrow host_name ('PE*', 'P*', ...) and run it in
        batches. The ``tag_names`` string form is the only one that works:
        with ``"tags": [{"name"}]`` objects the job also says JOB_COMPLETED but
        nothing is removed (verified silent no-op), so this tool never sends
        it.

        Precondition, checked here against the device's ``tag_names``:
        - an exact selector (uuid, or a host_name without '*') must name a
          device that carries EVERY requested tag; otherwise the tool refuses,
          says which tags it does carry, and sends nothing;
        - a wildcard selector removes from each matched device the requested
          tags it actually carries, skips devices carrying none of them
          (counted in ``skipped_count``, the first 25 listed as ``skipped``),
          and refuses only when no matched device carries any — so
          cnc_unassign_tags(tags='site-a', host_name='*') is the way to free
          a tag before cnc_delete_tag.
        Tag names are compared exactly (case-sensitive). System tags (cli,
        snmp, mdt, reach-check, ...) drive collection; whether the platform
        lets them go was not exercised — it decides. The PUT is idempotent
        and auto-retried on 5xx/transport errors.

        Args:
            tags: comma-separated tag names.
            uuid / host_name: exactly one selector; host_name may use '*'.

        Returns:
            str: JSON job envelope {"job_id", "state": "JOB_COMPLETED", "type":
            "Unassign tags", ...} plus "tags": [str], "devices": [{"host_name",
            "uuid", "tag_names_removed": [str]}], "scanned": int (devices the
            selector matched), "skipped_count": int and "skipped":
            [{"host_name", "uuid", "tag_names": [str]}] (wildcard only; at
            most 25 entries). "Error: device <host> does not carry tag(s) ...;
            it carries: ..." (nothing sent), "Error: no device matches ...",
            "Error: N of the M device(s) ... carry ...; more than the 100 ..."
            (nothing sent), "Error: Unassigning tags ... failed (job ..., state
            JOB_FAILED): <reason>", or "Error: ..." on an API failure.
        """
        try:
            names = split_tags(tags)
            selector = _selector(uuid, host_name)
            wildcard = is_wildcard(selector)
            nodes = await scan_devices(selector) if wildcard else await resolve_devices(selector)
            plan: list[tuple[dict[str, Any], list[str]]] = []
            skipped: list[dict[str, Any]] = []
            for node in nodes:
                carried = tag_names_of(node)
                present = [n for n in names if n in carried]
                missing = [n for n in names if n not in carried]
                if missing and not wildcard:
                    raise PlatformError(
                        f"device {node.get('host_name')} ({node.get('uuid')}) does not carry "
                        f"tag(s) {', '.join(missing)}; it carries: "
                        f"{', '.join(carried) or '(no tags)'}. Nothing was changed."
                    )
                if not present:
                    skipped.append({**device_ref(node), "tag_names": carried})
                    continue
                plan.append((node, present))
            if not plan:
                raise PlatformError(
                    f"none of the {len(nodes)} device(s) matching {describe_selector(selector)} "
                    f"carries any of the tag(s) {', '.join(names)}; nothing was changed."
                )
            if len(plan) > SELECTOR_PAGE_SIZE:
                raise PlatformError(
                    f"{len(plan)} of the {len(nodes)} device(s) matching "
                    f"{describe_selector(selector)} carry the tag(s) {', '.join(names)}, more "
                    f"than the {SELECTOR_PAGE_SIZE} this tool unassigns in one call; nothing "
                    f"was changed. {_BATCH_HELP}"
                )
            body = {
                "data": [{"uuid": node.get("uuid"), "tag_names": present} for node, present in plan]
            }
            result = await client.request_json("PUT", UNASSIGN_TAG_URL, json_body=body)
            job = check_job(
                result, f"Unassigning tags {', '.join(names)} from {len(plan)} device(s)"
            )
            payload = {
                **job,
                "tags": names,
                "devices": [
                    {**device_ref(node), "tag_names_removed": present} for node, present in plan
                ],
                "scanned": len(nodes),
                "skipped_count": len(skipped),
                "skipped": skipped[:SKIPPED_LIST_LIMIT],
            }
            return finalize(to_json(payload), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_set_device_location",
        title="Set Device Geo-Coordinates",
        read_only=False,
        destructive=False,
        idempotent=True,
    )
    async def cnc_set_device_location(
        latitude: Annotated[
            float,
            Field(
                description="Latitude in decimal degrees, -90..90 (e.g. 51.5074).", ge=-90, le=90
            ),
        ],
        longitude: Annotated[
            float,
            Field(
                description="Longitude in decimal degrees, -180..180 (e.g. -0.1278).",
                ge=-180,
                le=180,
            ),
        ],
        altitude: Annotated[
            float | None,
            Field(description="Altitude in metres, optional (e.g. 35.0).", ge=-20000, le=100000),
        ] = None,
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
        """Set (or replace) one device's geo-coordinates, which place it on the
        geographical topology map.

        WRITE operation — only registered when CNC_MCP_ENABLE_WRITES=true.
        Resolves exactly one device with ``POST nodes/query`` first (zero or
        several matches -> Error, nothing sent), then ``PATCH
        /crosswork/inventory/v1/nodesgeocoord {"Operation":
        "UpdateGeoCoordinates", "node_uuid_to_geocoords": {"<uuid>":
        {"latitude": {"value": lat}, "longitude": {"value": lon}[, "altitude":
        {"value": alt}]}}}`` (verified). Every number MUST sit inside the
        ``{"value": n}`` wrapper — bare numbers answer 500 "NATS request
        failed" — and this tool always sends it. The job answers JOB_COMPLETED
        "UpdateGeoCoordinates geo coordinates for 1 nodes"; the device then
        reads ``geo_info.coordinates`` (cnc_get_device_tags flattens it).
        Re-sending the same coordinates is harmless. Caveat from the API
        document: "default values of the fields are ignored" — a coordinate of
        exactly 0 may be dropped by the platform (not exercised). A PATCH may
        flip the device to ROBOT_OPER_STATE_CHECKING for a while. Not
        auto-retried.

        Args:
            latitude, longitude: decimal degrees; altitude: metres, optional.
            uuid / host_name: exactly one selector, one device.

        Returns:
            str: JSON job envelope {"job_id", "state": "JOB_COMPLETED", "type":
            "UpdateGeoCoordinates geo coordinates for 1 nodes", ...} plus
            "device": {"host_name", "uuid"} and "coordinates": {"latitude",
            "longitude", "altitude"?}. "Error: no device matches ..." /
            "... matched N devices" (nothing sent), "Error: Setting the
            location of ... failed (job ..., state JOB_FAILED): <reason>", or
            "Error: ..." on an API failure (500 NATS -> body rejected).
        """
        try:
            node = await find_one_device(_selector(uuid, host_name))
            node_uuid = str(node.get("uuid"))
            body = geo_body(node_uuid, latitude, longitude, altitude)
            result = await client.request_json("PATCH", GEOCOORD_URL, json_body=body)
            job = check_job(
                result, f"Setting the location of device {node.get('host_name')} ({node_uuid})"
            )
            coordinates: dict[str, float] = {"latitude": latitude, "longitude": longitude}
            if altitude is not None:
                coordinates["altitude"] = altitude
            payload = {**job, "device": device_ref(node), "coordinates": coordinates}
            return finalize(to_json(payload), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_clear_device_location",
        title="Clear Device Geo-Coordinates",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_clear_device_location(
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
        """Remove one device's geo-coordinates (it drops off the geographical map).

        DESTRUCTIVE write — only registered when CNC_MCP_ENABLE_WRITES=true;
        the coordinates are gone (read them first with cnc_get_device_tags if
        you may want them back). Resolves exactly one device first, then
        ``PATCH /crosswork/inventory/v1/nodesgeocoord {"Operation":
        "RemoveGeoCoordinates", "node_uuid_to_geocoords": {"<uuid>": {}}}``
        (verified); the device then reads ``geo_info.coordinates {}``.
        Clearing a device that has no coordinates was not exercised — expect a
        completed job with nothing to do. Not auto-retried.

        Returns:
            str: JSON job envelope plus "device": {"host_name", "uuid"} and
            "previous_coordinates": {...}|null (what the device carried before
            the call). "Error: no device matches ..." / "... matched N devices"
            (nothing sent), a JOB_FAILED reason, or "Error: ..." on an API
            failure.
        """
        try:
            node = await find_one_device(_selector(uuid, host_name))
            node_uuid = str(node.get("uuid"))
            result = await client.request_json(
                "PATCH", GEOCOORD_URL, json_body=geo_clear_body(node_uuid)
            )
            job = check_job(
                result, f"Clearing the location of device {node.get('host_name')} ({node_uuid})"
            )
            payload = {
                **job,
                "device": device_ref(node),
                "previous_coordinates": geo_coordinates_of(node),
            }
            return finalize(to_json(payload), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_lock_device",
        title="Lock Device",
        read_only=False,
        destructive=False,
        idempotent=False,
    )
    async def cnc_lock_device(
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
        owner: Annotated[
            str,
            Field(
                description=(
                    "Owner cookie recorded on the lock (e.g. 'cnc-mcp'); the same value is "
                    "needed to unlock."
                ),
                min_length=1,
                max_length=100,
            ),
        ] = DEFAULT_LOCK_OWNER,
        timeout_seconds: Annotated[
            int,
            Field(
                description="Seconds until the lock expires on its own, 10..86400 (e.g. 300).",
                ge=10,
                le=86400,
            ),
        ] = 300,
    ) -> str:
        """Take the DLM device lock on one device — what Change Automation and
        Pulse take while they work on a device, so that other applications
        leave it alone.

        WRITE operation — only registered when CNC_MCP_ENABLE_WRITES=true.
        Resolves exactly one device with ``POST nodes/query`` first, then
        ``POST /crosswork/inventory/v1/locknodes {"state": "LOCKED", "uuids":
        [<uuid>], "owner_cookie": <owner>, "timeout": "<seconds>"}`` (verified;
        ``timeout`` is a string). The answer is not a job envelope: success is
        ``{"rc": "NODE_REQ_SUCCESS", "rc_msg": "Operation success",
        "owner_cookie", "lock_id", "start_time", "end_time"}``; a refusal is
        HTTP 200 with only ``rc_msg`` and is reported as an Error with that
        message.

        Preconditions (verified live): the device must be ROBOT_OPER_STATE_OK
        — otherwise "Node:<uuid> is allowed to lock only in Operational
        state:ROBOT_OPER_STATE_OK". The Error names the device's state and
        what to do about it: ROBOT_OPER_STATE_CHECKING passes by itself (a
        PATCH — tag assignment, cnc_update_device, a geo-coordinate change —
        or a fresh add flips the device there for a while: wait for
        cnc_get_device to read OK again); ROBOT_OPER_STATE_LOCKED means a lock
        is already held (cnc_get_device_tags shows lock_status — release it
        with cnc_unlock_device if it is yours, or wait for end_time);
        ROBOT_OPER_STATE_UNMANAGED / ADMIN_DOWN need cnc_update_device(
        admin_state='up') first; ERROR / UNKNOWN / DELETING are just named.
        The lock expires by itself at ``end_time`` (owner-less expiry leaves
        the device's lock state ERRORED per the API document); release it
        earlier with cnc_unlock_device using the SAME owner and the returned
        lock_id. What the platform answers for a device that is already
        locked was not captured — expect an rc_msg-only refusal. Not
        idempotent: each successful call mints a new lock_id. Not
        auto-retried.

        Args:
            uuid / host_name: exactly one selector, one device.
            owner: owner cookie (default 'cnc-mcp').
            timeout_seconds: lock lifetime (default 300).

        Returns:
            str: JSON {"device": {"host_name", "uuid"}, "rc": "NODE_REQ_SUCCESS",
            "rc_msg", "owner_cookie", "lock_id", "start_time", "start_time_iso",
            "end_time", "end_time_iso", "note": "Release with cnc_unlock_device
            (owner=..., lock_id=...) ..."}. "Error: Locking device ... failed:
            Node:<uuid> is allowed to lock only in Operational state:... The
            device is ROBOT_OPER_STATE_<x>: <what to do>" (the device is not
            OK), "Error: no device matches ..." (nothing sent), or "Error: ..."
            on an API failure.
        """
        try:
            node = await find_one_device(_selector(uuid, host_name))
            node_uuid = str(node.get("uuid"))
            oper = node.get("operational_state")
            result = await client.request_json(
                "POST", LOCK_NODES_URL, json_body=lock_body(node_uuid, owner, timeout_seconds)
            )
            lock = check_lock_response(
                result,
                f"Locking device {node.get('host_name')} ({node_uuid}, operational_state={oper})",
                lock_hint(oper, node_uuid),
            )
            payload = {
                "device": device_ref(node),
                "rc": lock.get("rc"),
                "rc_msg": lock.get("rc_msg"),
                "owner_cookie": lock.get("owner_cookie", owner),
                "lock_id": lock.get("lock_id"),
                **_times(lock),
                "note": (
                    f"Release with cnc_unlock_device(host_name='{node.get('host_name')}', "
                    f"owner='{lock.get('owner_cookie', owner)}', lock_id='{lock.get('lock_id')}') "
                    "— the same owner and lock_id are required; otherwise the lock expires on "
                    "its own at end_time."
                ),
            }
            return finalize(to_json(payload), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_unlock_device",
        title="Unlock Device",
        read_only=False,
        destructive=False,
        idempotent=True,
    )
    async def cnc_unlock_device(
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
        owner: Annotated[
            str,
            Field(
                description="Owner cookie the lock was taken with (e.g. 'cnc-mcp').",
                min_length=1,
                max_length=100,
            ),
        ] = DEFAULT_LOCK_OWNER,
        lock_id: Annotated[
            str | None,
            Field(
                description=(
                    "lock_id returned by cnc_lock_device (e.g. "
                    "'29a12334-fa9e-43c4-b82b-922a01a73940'); when omitted the device's current "
                    "lock_status.lock_id is used."
                ),
                max_length=100,
            ),
        ] = None,
    ) -> str:
        """Release the DLM device lock on one device.

        WRITE operation — only registered when CNC_MCP_ENABLE_WRITES=true.
        Resolves exactly one device with ``POST nodes/query`` first. When
        ``lock_id`` is not given, the device's ``lock_status.lock_id`` is used
        — and a device that is not locked (no lock_status, or its state is not
        LOCKED) is an Error before anything is sent (the platform's own answer
        for that case is the unhelpful ``{"rc_msg": "Error Locking Node!"}``,
        also reported as an Error when it happens). Only your own locks are
        released by default: when the device's ``lock_status.owner`` differs
        from ``owner`` the tool refuses before anything is sent, naming the
        owner — a lock taken by Change Automation or Pulse belongs to that
        application; releasing it under it is what the owner cookie is meant
        to prevent (whether the platform itself checks the cookie is not
        verified, so this guard does not rely on it). Passing ``lock_id``
        explicitly is the deliberate override: the request goes out as given
        and the platform decides. Then ``POST /crosswork/inventory/v1/locknodes
        {"state": "UNLOCKED", "uuids": [<uuid>], "owner_cookie": <owner>,
        "lock_id": <lock_id>}`` (verified) answers ``rc: NODE_REQ_SUCCESS`` on
        success. Use the same owner the lock was taken with
        (cnc_get_device_tags shows lock_status.owner). Not auto-retried.

        Args:
            uuid / host_name: exactly one selector, one device.
            owner: owner cookie (default 'cnc-mcp').
            lock_id: the lock to release (default: the device's current lock,
                which must be owned by ``owner``).

        Returns:
            str: JSON {"device": {"host_name", "uuid"}, "rc": "NODE_REQ_SUCCESS",
            "rc_msg", "owner_cookie", "lock_id", "lock_status_before": {...}|null}.
            "Error: device ... is not locked ..." (nothing sent), "Error:
            device ... is locked by '<owner>', not by '<owner arg>' ..."
            (nothing sent), "Error: Unlocking device ... failed: <rc_msg>"
            (wrong owner/lock_id, or the platform's 'Error Locking Node!'),
            "Error: no device matches ...", or "Error: ..." on an API failure.
        """
        try:
            node = await find_one_device(_selector(uuid, host_name))
            node_uuid = str(node.get("uuid"))
            status = lock_status_of(node)
            target = (lock_id or "").strip()
            if not target:
                if status is None or not is_locked(node):
                    state = status.get("state") if status else None
                    raise PlatformError(
                        f"device {node.get('host_name')} ({node_uuid}) is not locked "
                        f"(lock_status: {state or 'none'}); nothing was sent. Pass lock_id to "
                        "release a specific lock anyway."
                    )
                lock_owner = status.get("owner")
                if lock_owner and str(lock_owner) != owner:
                    raise PlatformError(
                        f"device {node.get('host_name')} ({node_uuid}) is locked by "
                        f"'{lock_owner}', not by '{owner}' (lock_id {status.get('lock_id')}, "
                        f"until {epoch_iso(status.get('end_time'))}); nothing was sent. That "
                        "lock belongs to the application that took it (Change Automation, "
                        "Pulse, ...): leave it to expire at end_time. Passing lock_id "
                        "explicitly overrides this guard — only for a lock you know is stale."
                    )
                target = str(status["lock_id"])
            context = ""
            if status:
                context = (
                    f" (device lock_status: state={status.get('state')}, "
                    f"owner={status.get('owner')}, lock_id={status.get('lock_id')})"
                )
            result = await client.request_json(
                "POST", LOCK_NODES_URL, json_body=unlock_body(node_uuid, owner, target)
            )
            unlock = check_lock_response(
                result, f"Unlocking device {node.get('host_name')} ({node_uuid})", context
            )
            payload = {
                "device": device_ref(node),
                "rc": unlock.get("rc"),
                "rc_msg": unlock.get("rc_msg"),
                "owner_cookie": unlock.get("owner_cookie", owner),
                "lock_id": unlock.get("lock_id", target),
                "lock_status_before": status,
            }
            return finalize(to_json(payload), settings)
        except Exception as e:
            return format_error(e)
