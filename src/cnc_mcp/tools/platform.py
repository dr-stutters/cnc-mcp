"""Cross-cutting platform reads: tags, users, installed applications, alarms,
and the inventory job queue.

Everything here is read-only. The endpoints are the odd ones out on
Crosswork:

- ``POST inventory/v1/tags/query`` answers ``{"tags": [...]}`` (verified
  live). Which request body it honours and whether it pages server-side is
  NOT verified: this module sends ``{}``, filters and pages client-side, and
  uses any ``result_count``/``total_count`` in the response to notice a
  server-paged (truncated) collection.
- ``GET aaa/v1/user`` answers a dict *keyed by username* with PascalCase
  fields (verified live); it is flattened to a snake_case list (never
  exposing ``Password``).
- ``POST platform/v2/capp/applicationsummary/query`` answers
  ``{"application_summary_list": [...]}`` (verified live).
- ``POST alarms/v1/query`` takes a SQL-like ``criteria`` string
  (``select * from alarm limit N page M``), not a JSON filter body
  (verified live).
- ``POST inventory/v1/jobs/query`` is *assumed* to follow the inventory
  query grammar and answer ``{"jobs": [...]}``; it is NOT yet verified live
  (only the job envelope every inventory write returns is). A ``job_id``
  filter field is not verified either, and Crosswork silently ignores unknown
  filter names, so single-job lookups also walk the newest pages.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.crosswork import (
    AAA,
    ALARMS,
    INVENTORY,
    JOB_TERMINAL_STATES,
    PLATFORM,
    check_job,
    page_envelope,
    parse_impacted,
    query_body,
    unwrap,
)
from cnc_mcp.errors import PlatformError, format_error
from cnc_mcp.formatting import ResponseFormat, finalize, to_json
from cnc_mcp.polling import wait_until
from cnc_mcp.safety import AppContext, register_tool
from cnc_mcp.tools.fault import (
    ALARM_SORTS,
    DEFAULT_ALARM_SORT,
    alarm_line,
    sort_alarms,
    stale_alarm_footer,
)

logger = logging.getLogger(__name__)

TAGS_QUERY = f"{INVENTORY}/tags/query"
JOBS_QUERY = f"{INVENTORY}/jobs/query"
USERS_PATH = f"{AAA}/user"
APPLICATIONS_QUERY = f"{PLATFORM}/capp/applicationsummary/query"
ALARMS_QUERY = f"{ALARMS}/query"

# Single-job lookup: ``jobs/query`` honours ``filter: {"job_id": ...}`` (verified
# live — an exact id returns that one job, an unknown id returns a bare ``{}``).
_JOB_LOOKUP_PAGE_SIZE = 5


def _more_hint(envelope: dict[str, Any]) -> list[str]:
    if envelope.get("has_more"):
        return ["", f"More available: repeat with page={envelope['next_page']}."]
    return []


def _tags_markdown(tags: list[dict], envelope: dict[str, Any], fetched: int) -> str:
    lines = [f"# Tags ({envelope['count']} shown, total {envelope['total']})", ""]
    if envelope["collection_total"] > fetched:
        lines.append(
            f"Note: Crosswork returned {fetched} of {envelope['collection_total']} tags; "
            "the rest were not fetched, so the filters/paging saw only this subset."
        )
        lines.append("")
    if not tags:
        lines.append("No tags matched.")
    for t in tags:
        lines.append(
            f"- **{t.get('name', '?')}** (category: {t.get('category', '?')}, "
            f"type: {t.get('tag_type', '?')}, created by {t.get('created_by', '?')})"
        )
    lines.extend(_more_hint(envelope))
    return "\n".join(lines)


def _users_from_response(data: Any) -> list[dict[str, Any]]:
    """Flatten ``GET aaa/v1/user`` (dict keyed by username, PascalCase fields).

    Only whitelisted fields are copied, so the (empty-string) ``Password`` field
    the API returns never reaches the agent.
    """
    if isinstance(data, dict):
        raw = [(k, v) for k, v in data.items() if isinstance(v, dict)]
    elif isinstance(data, list):
        raw = [(u.get("Username", ""), u) for u in data if isinstance(u, dict)]
    else:
        raw = []
    users: list[dict[str, Any]] = []
    for key, u in raw:
        groups = u.get("DeviceAccessGroups") or []
        users.append(
            {
                "username": u.get("Username") or key,
                "role": u.get("PolicyId"),
                "first_name": u.get("FirstName"),
                "last_name": u.get("LastName"),
                "status": u.get("Status"),
                "device_access_groups": [
                    g.get("DomainName") for g in groups if isinstance(g, dict)
                ],
            }
        )
    users.sort(key=lambda u: str(u["username"]).lower())
    return users


def _users_markdown(users: list[dict[str, Any]]) -> str:
    lines = [f"# Users ({len(users)})", ""]
    if not users:
        lines.append("No users returned.")
    for u in users:
        full_name = " ".join(p for p in (u["first_name"], u["last_name"]) if p)
        groups = ", ".join(g for g in u["device_access_groups"] if g) or "none"
        line = f"- **{u['username']}** — role {u['role'] or '?'}, status {u['status'] or '?'}"
        if full_name:
            line += f", name: {full_name}"
        line += f", device access groups: {groups}"
        lines.append(line)
    return "\n".join(lines)


def _applications_markdown(apps: list[dict]) -> str:
    lines = [f"# Installed applications ({len(apps)})", ""]
    if not apps:
        lines.append("No applications returned.")
    for app in apps:
        data = app.get("application_data") or {}
        summary = data.get("summary") or {}
        build = data.get("build_information") or {}
        line = (
            f"- **{summary.get('name', '?')}** ({app.get('application_id', '?')}) "
            f"{data.get('version', '?')}"
        )
        if summary.get("description"):
            line += f" — {summary['description']}"
        extras = [
            f"category: {data['category']}" if data.get("category") else "",
            f"publisher: {build['publisher']}" if build.get("publisher") else "",
            f"built: {build['date_time']}" if build.get("date_time") else "",
        ]
        extras = [e for e in extras if e]
        if extras:
            line += f" ({'; '.join(extras)})"
        lines.append(line)
    return "\n".join(lines)


def _alarms_markdown(
    alarms: list[dict], envelope: dict[str, Any], open_only: bool, sort: str
) -> str:
    """One :func:`fault.alarm_line` per alarm (State, object, ISO times, age) so a page
    can be triaged as-is, plus the stale-alarm footer — the same rendering as
    cnc_search_alarms / cnc_get_alarm."""
    scope = "open only" if open_only else "open and cleared"
    order = "platform order (NOT newest-first)" if sort == "platform" else f"sorted {sort}"
    lines = [
        f"# Alarms ({envelope['count']} shown, page {envelope['page']}, {scope}, {order})",
        "",
    ]
    if not alarms:
        lines.append("No alarms returned.")
    lines.extend(alarm_line(a) for a in alarms)
    lines.extend(stale_alarm_footer(alarms))
    lines.extend(_more_hint(envelope))
    if sort != "platform":
        lines.extend(
            [
                "",
                "Sorting is per page (client-side): the platform pages in its own order, so "
                "the newest alarm overall may sit on another page — cnc_search_alarms fetches "
                "every alarm and sorts the whole set.",
            ]
        )
    return "\n".join(lines)


def _job_line(j: dict) -> str:
    line = f"- **{j.get('job_id', '?')}** {j.get('state', '?')} — {j.get('type', '?')}"
    details = [
        f"created {j['creation_time']}" if j.get("creation_time") else "",
        f"completed {j['completion_time']}" if j.get("completion_time") else "",
        f"by {j['created_by']}" if j.get("created_by") else "",
        f"impacted: {len(j['impacted'])}" if isinstance(j.get("impacted"), list) else "",
    ]
    details = [d for d in details if d]
    if details:
        line += f" ({', '.join(details)})"
    if j.get("error"):
        line += f"\n  - error: {j['error']}"
    return line


def _jobs_markdown(jobs: list[dict], envelope: dict[str, Any]) -> str:
    total = envelope["total"] if envelope["total"] is not None else "unknown"
    lines = [
        f"# Inventory jobs ({envelope['count']} shown, page {envelope['page']}, total {total})",
        "",
    ]
    if not jobs:
        lines.append("No inventory jobs returned.")
    lines.extend(_job_line(j) for j in jobs)
    lines.extend(_more_hint(envelope))
    return "\n".join(lines)


def _with_impacted_objects(job: dict[str, Any]) -> dict[str, Any]:
    job["impacted_objects"] = parse_impacted(job.get("impacted"))
    return job


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    async def fetch_job(job_id: str) -> dict[str, Any] | None:
        """Look one job up by id; None when Crosswork returns no matching job.

        ``jobs/query`` honours ``filter: {"job_id": ...}`` (verified live), so a
        single request answers. The id is still compared client-side so a
        platform that ever ignored the filter could not hand back the wrong job.
        """
        wanted = job_id.strip().lower()
        body = query_body({"job_id": job_id}, page_size=_JOB_LOOKUP_PAGE_SIZE, page=0)
        data = await client.request_json("POST", JOBS_QUERY, json_body=body)
        jobs, _, _ = unwrap(data, "jobs")
        for job in jobs:
            if isinstance(job, dict) and str(job.get("job_id", "")).lower() == wanted:
                return job
        return None

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_tags",
        title="List Tags",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_tags(
        name: Annotated[
            str | None,
            Field(
                description="Case-insensitive substring to match against tag names "
                "(e.g. 'mdt'). Applied client-side.",
                max_length=200,
            ),
        ] = None,
        category: Annotated[
            str | None,
            Field(
                description="Exact tag category to keep, case-insensitive (e.g. 'default'). "
                "Applied client-side.",
                max_length=200,
            ),
        ] = None,
        page_size: Annotated[int, Field(description="Tags per page (e.g. 50).", ge=1, le=500)] = 50,
        page: Annotated[int, Field(description="0-based page number (e.g. 0).", ge=0)] = 0,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the tags defined on Crosswork (system tags such as 'mdt' plus any
        user-defined ones), with optional name/category filtering and paging.

        Read-only. Use it to learn the exact tag names before filtering devices by
        tag or attaching tags to devices. The tool sends an empty body and
        applies the name/category filters and the paging itself after the
        fetch. Whether tags/query honours a filter body or pages server-side
        is not verified; if the response carries result_count/total_count
        larger than the rows returned, the collection was truncated by the
        server and the output says so. 'total' is the number of fetched tags
        that matched the filters; 'collection_total' is the number of tags on
        the platform (from the server's counts when present, else the number
        fetched).

        Args:
            name: case-insensitive substring of the tag name.
            category: exact category (case-insensitive), e.g. 'default'.
            page_size / page: client-side paging over the filtered tags.

        Returns:
            str: Markdown listing, or JSON:
            {"total": int, "count": int, "page": int, "page_size": int,
             "items": [{"name": str, "category": str, "created_by": str,
                        "creation_time": str, "tag_type": str}, ...],
             "has_more": bool, "next_page": int|null, "collection_total": int}
            On failure: "Error: <actionable message>".
        """
        try:
            data = await client.request_json("POST", TAGS_QUERY, json_body={})
            tags, result_count, total_count = unwrap(data, "tags")
            tags = [t for t in tags if isinstance(t, dict)]
            if total_count is not None:
                collection_total = total_count
            elif result_count is not None:
                collection_total = result_count
            else:
                collection_total = len(tags)
            if collection_total > len(tags):
                logger.warning(
                    "tags/query returned %d of %d tags; the server paged the collection",
                    len(tags),
                    collection_total,
                )
            filtered = tags
            if name:
                needle = name.strip().lower()
                filtered = [t for t in filtered if needle in str(t.get("name", "")).lower()]
            if category:
                wanted = category.strip().lower()
                filtered = [t for t in filtered if str(t.get("category", "")).lower() == wanted]
            start = page * page_size
            items = filtered[start : start + page_size]
            envelope = page_envelope(
                items,
                result_count=len(filtered),
                total_count=collection_total,
                page_size=page_size,
                page=page,
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(envelope), settings)
            return finalize(_tags_markdown(items, envelope, len(tags)), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_users",
        title="List Users",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_users(
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the Crosswork user accounts with their role, status and device
        access groups.

        Read-only. Use it to confirm an account exists (Crosswork answers the same
        'Invalid credentials' for an unknown username and a wrong password) and to
        see which role (PolicyId, e.g. 'admin') and device access groups
        (e.g. 'ALL-ACCESS') an account carries. The platform returns a dict keyed
        by username with PascalCase fields; this tool flattens it to a list and
        never returns the Password field.

        Returns:
            str: Markdown listing, or JSON:
            {"count": int,
             "items": [{"username": str, "role": str, "first_name": str,
                        "last_name": str, "status": str,
                        "device_access_groups": [str, ...]}, ...]}
            On failure: "Error: <actionable message>" (403 -> the configured
            account lacks the user-administration privilege).
        """
        try:
            data = await client.request_json("GET", USERS_PATH)
            users = _users_from_response(data)
            if response_format is ResponseFormat.JSON:
                return finalize(to_json({"count": len(users), "items": users}), settings)
            return finalize(_users_markdown(users), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_applications",
        title="List Installed Applications",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_applications(
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the applications installed on the Crosswork platform with their
        versions (e.g. Crosswork Optimization Engine, Service Health, ...).

        Read-only. Use it to check what is installed and at which version before
        assuming a feature (topology, SR-TE, VPN services) is available on this
        instance.

        Returns:
            str: Markdown "name (application_id) version — description" lines, or
            JSON:
            {"count": int,
             "items": [{"application_id": str,
                        "application_data": {"version": str,
                                             "summary": {"name": str, "description": str},
                                             "category": str,
                                             "build_information": {"date_time": str,
                                                                   "publisher": str}}},
                       ...]}
            On failure: "Error: <actionable message>".
        """
        try:
            data = await client.request_json("POST", APPLICATIONS_QUERY, json_body={})
            apps, _, _ = unwrap(data, "application_summary_list")
            apps = [a for a in apps if isinstance(a, dict)]
            if response_format is ResponseFormat.JSON:
                return finalize(to_json({"count": len(apps), "items": apps}), settings)
            return finalize(_applications_markdown(apps), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_alarms",
        title="List Alarms",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_alarms(
        open_only: Annotated[
            bool,
            Field(description="True (default) for open alarms only; False to include cleared."),
        ] = True,
        limit: Annotated[int, Field(description="Alarms per page (e.g. 20).", ge=1, le=200)] = 20,
        page: Annotated[int, Field(description="0-based page number (e.g. 0).", ge=0)] = 0,
        sort: Annotated[
            str,
            Field(
                description=(
                    "Order of the alarms ON THIS PAGE: 'updated_desc' (default, newest "
                    "change first), 'created_desc' (newest alarm first) or 'platform' (as "
                    "Crosswork returns them — NOT newest-first, verified live). "
                    "E.g. 'created_desc'."
                ),
                max_length=20,
            ),
        ] = DEFAULT_ALARM_SORT,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List Crosswork platform alarms (device reachability, collection,
        application health, ...) one page at a time.

        Read-only. Use it to find out why something is unhealthy before digging
        into devices or providers. Alarms are paged with a SQL-like criteria
        string ('select * from alarm limit N page M'); no other filtering is
        exposed. The platform reports no total, so 'has_more' means the page came
        back full — request the next page to check. ORDER (verified live
        2026-09-14): the platform does NOT page newest-first, so the rows are
        re-sorted client-side per page (``sort``); to find the newest alarm
        overall, or to filter by state/text, use cnc_search_alarms (it fetches
        every alarm). Each markdown line is the shared alarm rendering ([State]
        object — description, id, ack, events, created/updated as ISO times,
        age); open alarms with 0 events that have not changed for 7+ days are
        flagged as possibly stale (Crosswork does not auto-clear pod-health
        alarms — confirm with cnc_get_cluster_health / cnc_list_microservices
        before reporting an outage).

        Args:
            open_only: True for open alarms only (default), False for all.
            limit / page: page size and 0-based page number.
            sort: per-page order: updated_desc (default) | created_desc | platform.

        Returns:
            str: Markdown with one line per alarm ([State] object — description,
            id, ack, events, created, updated, age), a stale-alarm note when
            any qualifies, or JSON (items in the requested order):
            {"total": null, "count": int, "page": int, "page_size": int,
             "items": [{"AlarmId": str, "AlarmCategory": str, "Description": str,
                        "Created": str, "Updated": str, "Acknowledge": bool,
                        "object_id": str, "origin_app_id": str, "events_count": int,
                        "Events": [...]}, ...],
             "has_more": bool, "next_page": int|null}
            On failure: "Error: <actionable message>".
        """
        try:
            order = sort.strip().lower()
            if order not in ALARM_SORTS:
                raise PlatformError(
                    f"Unknown sort '{sort}'. Use one of: {', '.join(ALARM_SORTS)}. "
                    "Nothing was sent."
                )
            body = {
                "openAlarmsOnly": open_only,
                "criteria": f"select * from alarm limit {limit} page {page}",
            }
            data = await client.request_json("POST", ALARMS_QUERY, json_body=body)
            if isinstance(data, dict) and "state" in data and data["state"] != "Success":
                raise PlatformError(
                    f"Alarm query failed: state {data['state']}. "
                    f"Platform said: {str(data.get('error') or data.get('message') or data)[:300]}"
                )
            alarms, _, _ = unwrap(data, "alarms")
            alarms = sort_alarms([a for a in alarms if isinstance(a, dict)], order)
            envelope = page_envelope(
                alarms, result_count=None, total_count=None, page_size=limit, page=page
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json({**envelope, "sort": order}), settings)
            return finalize(_alarms_markdown(alarms, envelope, open_only, order), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_inventory_jobs",
        title="List Inventory Jobs",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_inventory_jobs(
        page_size: Annotated[int, Field(description="Jobs per page (e.g. 20).", ge=1, le=200)] = 20,
        page: Annotated[int, Field(description="0-based page number (e.g. 0).", ge=0)] = 0,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List inventory jobs — the audit trail of every device, credential,
        provider and tag write on Crosswork (each write returns one job).

        Read-only. Use it to review recent changes or to find the job_id of a
        write whose result was lost, then inspect one with cnc_get_inventory_job
        or wait for it with cnc_wait_for_inventory_job. Paged with the inventory
        filterData.PageSize/PageNum grammar (assumed for this endpoint; 'total'
        is null when the platform reports no result_count, and 'has_more' then
        means the page came back full).

        Args:
            page_size / page: page size and 0-based page number.

        Returns:
            str: Markdown listing, or JSON:
            {"total": int|null, "count": int, "page": int, "page_size": int,
             "items": [{"job_id": str, "state": str, "type": str,
                        "creation_time": str, "completion_time": str,
                        "created_by": str, "impacted": [str, ...], "error": str},
                       ...],
             "has_more": bool, "next_page": int|null, "collection_total": int|null}
            States: JOB_COMPLETED and JOB_COMPLETED_WITH_WARNING (a success with
            an advisory in "error", e.g. a no-op or partially applied write),
            JOB_FAILED / JOB_CANCELLED / JOB_ABORTED (unsuccessful), JOB_RUNNING
            and other in-progress states. On failure: "Error: <actionable
            message>".
        """
        try:
            body = query_body({}, page_size=page_size, page=page)
            data = await client.request_json("POST", JOBS_QUERY, json_body=body)
            jobs, result_count, total_count = unwrap(data, "jobs")
            jobs = [j for j in jobs if isinstance(j, dict)]
            envelope = page_envelope(
                jobs,
                result_count=result_count,
                total_count=total_count,
                page_size=page_size,
                page=page,
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(envelope), settings)
            return finalize(_jobs_markdown(jobs, envelope), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_inventory_job",
        title="Get Inventory Job",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_inventory_job(
        job_id: Annotated[
            str,
            Field(
                description="Inventory job id as returned by a write tool or "
                "cnc_list_inventory_jobs (e.g. '0f6c1a2e-...').",
                min_length=1,
                max_length=200,
            ),
        ],
    ) -> str:
        """Get one inventory job by id: its state, type, timestamps, the objects
        it touched and the error text when it failed.

        Read-only. Use it to check the outcome of a device/credential/provider
        write. For a job that may still be running prefer
        cnc_wait_for_inventory_job, which polls until it finishes. The lookup
        scans the newest few hundred jobs (newest first), so a very old job may
        not be found even though cnc_list_inventory_jobs can still page to it.

        Returns:
            str: JSON of the job: {"job_id", "state", "type", "creation_time",
            "completion_time", "created_by", "impacted": ["<uuid> <name> [<ip>]"],
            "impacted_objects": [{"uuid", "name", "ip"}], "error"}. A state of
            JOB_COMPLETED_WITH_WARNING is a success whose advisory is in "error".
            "Error: No inventory job with id ..." when the id matches nothing;
            other failures: "Error: <actionable message>".
        """
        try:
            job = await fetch_job(job_id)
            if job is None:
                raise PlatformError(
                    f"No inventory job with id '{job_id}' was found. Check the id with "
                    "cnc_list_inventory_jobs."
                )
            return finalize(to_json(_with_impacted_objects(job)), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_wait_for_inventory_job",
        title="Wait For Inventory Job",
        read_only=True,
        idempotent=True,
    )
    async def cnc_wait_for_inventory_job(
        job_id: Annotated[
            str,
            Field(
                description="Inventory job id to wait for (e.g. '0f6c1a2e-...').",
                min_length=1,
                max_length=200,
            ),
        ],
        timeout_seconds: Annotated[
            int,
            Field(description="Give up after this many seconds (e.g. 120).", ge=1, le=900),
        ] = 120,
        interval_seconds: Annotated[
            int, Field(description="Seconds between polls (e.g. 5).", ge=1, le=60)
        ] = 5,
    ) -> str:
        """Poll an inventory job until it reaches a terminal state or the
        timeout elapses.

        Read-only. Use it right after a write that came back JOB_RUNNING instead
        of calling cnc_get_inventory_job in a loop. Terminal states are the
        verified ones: JOB_COMPLETED and JOB_COMPLETED_WITH_WARNING (both
        successes; the latter carries an advisory, e.g. a no-op or partially
        applied write), and JOB_FAILED / JOB_CANCELLED / JOB_ABORTED (failures).
        Any other state (JOB_RUNNING or an in-progress state not seen before)
        keeps the tool polling until the timeout.

        Returns:
            str: "Inventory job <id> completed after <n>s." followed by the job
            JSON (with "impacted_objects" parsed from "impacted") on success; for
            JOB_COMPLETED_WITH_WARNING the line also carries "Warning: <advisory>"
            and the JSON gains a "warning" key.
            A timeout is NOT an error: "Inventory job <id> not finished after <n>s;
            current state: JOB_RUNNING. ..." followed by the job JSON — call again
            to keep waiting.
            "Error: Inventory job <id> failed (job <id>, state JOB_FAILED): <reason>"
            when the job ended unsuccessfully; "Error: No inventory job with id
            ..." when the id matches nothing; other API failures: "Error: ...".
        """
        try:
            finished, job, elapsed = await wait_until(
                lambda: fetch_job(job_id),
                lambda j: j is None or j.get("state") in JOB_TERMINAL_STATES,
                timeout_seconds=timeout_seconds,
                interval_seconds=interval_seconds,
            )
            if job is None:
                raise PlatformError(
                    f"No inventory job with id '{job_id}' was found. Check the id with "
                    "cnc_list_inventory_jobs."
                )
            if not finished:
                job = _with_impacted_objects(job)
                return finalize(
                    f"Inventory job {job_id} not finished after {elapsed:.0f}s; current state: "
                    f"{job.get('state')}. Call cnc_wait_for_inventory_job again to keep "
                    f"waiting.\n\n{to_json(job)}",
                    settings,
                )
            # Raises PlatformError for JOB_FAILED / JOB_CANCELLED / JOB_ABORTED, copies a
            # JOB_COMPLETED_WITH_WARNING advisory to "warning", parses impacted_objects.
            job = check_job(job, f"Inventory job {job_id}")
            summary = f"Inventory job {job_id} completed after {elapsed:.0f}s."
            if job.get("warning"):
                summary += f" Warning: {job['warning']}"
            return finalize(f"{summary}\n\n{to_json(job)}", settings)
        except Exception as e:
            return format_error(e)
