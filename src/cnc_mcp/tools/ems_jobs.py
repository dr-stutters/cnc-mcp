"""EMS inventory job scheduler — the recurring system jobs that keep the device
inventory current (list, run now, suspend, resume, wait).

What it is. The element-management layer runs a handful of built-in
scheduler jobs of type ``Inventory``: ``internalSchedule``, ``Switch
Inventory``, ``Failed Feature Sync``, ``thirdPartyDeviceSync`` and
``reBuildAssociation`` (cadences seen live: every 4 h, daily and hourly).
Going by their names they refresh the EMF inventory
(:mod:`cnc_mcp.tools.physical_inventory`) and re-sync devices whose feature
collection failed. The service is
``/crosswork/rs/json/jobSchedulerServiceInv/v1`` (Spring JSON, Bearer).

Wire facts (verified live on Crosswork 7.2, 2026-09-13, base :data:`JOBS`):

- ``GET getSystemLazyJobsSpecification`` REQUIRES a ``Range: items=<start>-
  <end>`` header — without it the service answers ``400 {"timestamp":
  <epoch ms>, "status": 400, "error": "Bad Request", "path": "/jobScheduler
  Service/getSystemLazyJobsSpecification"}``. With it: ``200`` (whole set
  fits) or ``206`` (partial) plus ``Content-Range: items=0-99/5`` and
  ``{"identifier": "id", "totalCount": 5, "pageNo": 0, "items": [{"id":
  "435435", "jobType": "Inventory", "jobName": "internalSchedule",
  "description": null, "nextRunTime": "September 13, 2026 at 7:28:32 PM
  UTC", "workState": "Scheduled" | "Suspended" | "In-Progress", "duration":
  "00:00:05", "startTime": "<prose>", "owner": "SYSTEM", "creationTime":
  null, "recurrence": null, "priority": null, "authEntityId": "-11111",
  "lastRunResultState": "Success" | "Running", "lastRunJobId": "449540",
  "jobInterval": "04 hour(s)" | "1 day(s)" | "1 hour(s)"}]}``. Times are
  prose strings (``nextRunTime`` is ``null`` while a job is suspended); the
  tools pass them through as text. Only ``{"items": []}`` is a genuine
  empty answer — an empty body or any other shape is reported as an error
  rather than as "no jobs".
- The three writes take a RAW text body ``"<jobName>:<jobType>"`` (for
  example ``Failed Feature Sync:Inventory``; ``application/json`` and
  ``text/plain`` Content-Types both work) and answer a bare ``true`` /
  ``false`` with HTTP 200 either way. ``false`` was verified ONLY for a
  nonexistent key (``nope:Inventory``); whether the scheduler also answers
  ``false`` when it refuses a write for the job's current state is unknown,
  so on ``false`` the tools read the list back: a missing row is reported
  as "no such job", a present row as "the scheduler refused the <verb>".
  ``POST suspendJob`` -> ``workState`` Suspended, ``nextRunTime`` null;
  ``POST resumeJob`` -> Scheduled again with the next run time; ``POST
  runJob`` -> In-Progress / ``lastRunResultState`` Running within seconds
  and back to Scheduled / Success when the run ends (Failed Feature Sync
  takes ~5 s on the lab). Suspending an already suspended job, resuming a
  job that is not suspended, and running a job that is already In-Progress
  were NOT exercised live. ``reScheduleJob`` (a jobSchedule body) is not
  exposed — unverified, and it changes the platform's own maintenance
  cadence.
- The job key is ``<jobName>:<jobType>``; every verified job has
  ``jobType`` ``Inventory``, so the tools take the name and default the
  type. Names are case-sensitive and may contain spaces. Because the key is
  sent as raw text with ``:`` as the delimiter, names and types are limited
  client-side to letters, digits, spaces, ``_``, ``.`` and ``-``.
- After a write the tools read the list back once and report the row. The
  write is reported as applied even when that read-back fails (the verdict
  is what proves the write); right after ``runJob`` the read-back may still
  show Scheduled because the scheduler picks the run up a moment later —
  the wait tool's ``previous_run_job_id`` (that read-back's
  ``lastRunJobId``) keeps it from ending before the run has started.
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.errors import PlatformError, format_error
from cnc_mcp.formatting import ResponseFormat, finalize, to_json
from cnc_mcp.polling import wait_until
from cnc_mcp.safety import AppContext, register_tool

JOBS = "/crosswork/rs/json/jobSchedulerServiceInv/v1"
LIST_URL = f"{JOBS}/getSystemLazyJobsSpecification"
RUN_URL = f"{JOBS}/runJob"
SUSPEND_URL = f"{JOBS}/suspendJob"
RESUME_URL = f"{JOBS}/resumeJob"
# The verified job type of every built-in scheduler job.
DEFAULT_JOB_TYPE = "Inventory"
# Verified live: the five built-in inventory scheduler jobs of a 7.2 instance.
BUILT_IN_JOBS = (
    "internalSchedule",
    "Switch Inventory",
    "Failed Feature Sync",
    "thirdPartyDeviceSync",
    "reBuildAssociation",
)
STATE_SCHEDULED = "Scheduled"
STATE_SUSPENDED = "Suspended"
STATE_IN_PROGRESS = "In-Progress"
# The whole set is five rows; a wide window lists everything in one call.
RANGE_END = 199
RAW_HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}
_JSON_ACCEPT = {"Accept": "application/json"}

_RESPONSE_FORMAT_DESC = "'markdown' for human-readable output, 'json' for the raw platform data."
_JOB_NAME_DESC = (
    "Scheduler job name, case-sensitive, spaces allowed — one of the built-in inventory jobs "
    "'internalSchedule', 'Switch Inventory', 'Failed Feature Sync', 'thirdPartyDeviceSync', "
    "'reBuildAssociation' (cnc_list_inventory_scheduler_jobs shows them). "
    "E.g. 'Failed Feature Sync'."
)
_JOB_TYPE_DESC = (
    "Scheduler job type; every verified job is 'Inventory' (the default; blank means the "
    "default). E.g. 'Inventory'."
)
_KEY_CHARS = re.compile(r"[A-Za-z0-9 _.\-]+")


# --- pure helpers ----------------------------------------------------------------


def job_key(job_name: str, job_type: str) -> str:
    """The raw ``<jobName>:<jobType>`` body the scheduler writes take; refuses odd names."""
    name = job_name.strip()
    kind = job_type.strip() or DEFAULT_JOB_TYPE
    if not name:
        raise PlatformError(
            "job_name is empty; list the jobs with cnc_list_inventory_scheduler_jobs. "
            "Nothing was sent."
        )
    for label, value in (("job_name", name), ("job_type", kind)):
        if not _KEY_CHARS.fullmatch(value):
            raise PlatformError(
                f"{label} '{value}' carries characters outside letters, digits, spaces, '_', "
                "'.' and '-' (the job key is sent as raw text '<name>:<type>'). Nothing was sent."
            )
    return f"{name}:{kind}"


def jobs_of(data: Any) -> list[dict[str, Any]]:
    """The ``items`` rows of the verified list document.

    Only ``{"items": [...]}`` is accepted (non-dict entries are dropped). An
    empty body is named as such and any other shape is a shape error, so a
    surprise answer is never read as "no scheduler jobs".
    """
    if data is None:
        raise PlatformError(
            "The job scheduler answered an empty body where the job list "
            '{"items": [...]} was expected.'
        )
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        raise PlatformError(
            'The job scheduler answered an unexpected document (expected {"items": [...]}): '
            f"{str(data)[:300]}"
        )
    return [row for row in data["items"] if isinstance(row, dict)]


def total_of(data: Any) -> int | None:
    """``totalCount`` when it is a genuine int (the verified spelling), else None."""
    if isinstance(data, dict):
        total = data.get("totalCount")
        if isinstance(total, int) and not isinstance(total, bool):
            return total
    return None


def find_job(rows: list[dict[str, Any]], job_name: str, job_type: str) -> dict[str, Any] | None:
    """The row whose ``jobName`` / ``jobType`` match exactly (a missing type counts
    as the default)."""
    name = job_name.strip()
    kind = job_type.strip() or DEFAULT_JOB_TYPE
    for row in rows:
        if row.get("jobName") == name and str(row.get("jobType") or DEFAULT_JOB_TYPE) == kind:
            return row
    return None


def _text(value: Any, missing: str = "-") -> str:
    return missing if value in (None, "") else str(value)


def job_line(row: dict[str, Any]) -> str:
    state = _text(row.get("workState"), "?")
    next_run = row.get("nextRunTime") or (
        "none while suspended" if state == STATE_SUSPENDED else "-"
    )
    return (
        f"- **{_text(row.get('jobName'), '?')}** ({_text(row.get('jobType'), '?')}, "
        f"id {_text(row.get('id'), '?')}): {state}; every {_text(row.get('jobInterval'))}; "
        f"next run {next_run}; last run {_text(row.get('lastRunResultState'))} "
        f"(job {_text(row.get('lastRunJobId'))}, {_text(row.get('duration'))})"
    )


def job_markdown(row: dict[str, Any]) -> str:
    lines = [
        f"# Scheduler job {_text(row.get('jobName'), '?')} ({_text(row.get('jobType'), '?')})",
        "",
    ]
    for label, key in (
        ("id", "id"),
        ("state", "workState"),
        ("interval", "jobInterval"),
        ("next run", "nextRunTime"),
        ("last start", "startTime"),
        ("last duration", "duration"),
        ("last result", "lastRunResultState"),
        ("last run job id", "lastRunJobId"),
        ("owner", "owner"),
        ("description", "description"),
    ):
        lines.append(f"- {label}: {_text(row.get(key))}")
    return "\n".join(lines)


def verdict_of(response_text: str) -> bool:
    """The bare ``true`` / ``false`` the writes answer (anything else is unexpected)."""
    text = response_text.strip().lower()
    if text == "true":
        return True
    if text == "false":
        return False
    raise PlatformError(
        "The job scheduler answered neither 'true' nor 'false' to the write: "
        f"{response_text[:200]!r}"
    )


# --- registration -----------------------------------------------------------------


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    async def read_jobs() -> tuple[list[dict[str, Any]], int | None]:
        data = await client.request_json(
            "GET",
            LIST_URL,
            headers={**_JSON_ACCEPT, "Range": f"items=0-{RANGE_END}"},
            ok_statuses={206},
        )
        return jobs_of(data), total_of(data)

    async def read_job(job_name: str, job_type: str) -> dict[str, Any] | None:
        rows, _ = await read_jobs()
        return find_job(rows, job_name, job_type)

    async def write(url: str, key: str, verb: str, job_name: str, job_type: str) -> None:
        """POST the raw key; a ``false`` verdict is turned into the right error.

        ``false`` was verified live only for a nonexistent key, so the list is
        read back to tell a missing job (the verified meaning) from a refusal
        of a job that exists (a state the writes never exercised live).
        """
        response = await client.request(
            "POST", url, content=key, headers=RAW_HEADERS, retryable=False
        )
        if verdict_of(response.text):
            return
        try:
            row = await read_job(job_name, job_type)
        except Exception as e:
            raise PlatformError(
                f"The job scheduler answered false to {verb} '{key}' (no such job, or the "
                f"{verb} was refused) and the job list could not be read back to tell which: "
                f"{format_error(e)}"
            ) from e
        if row is None:
            raise PlatformError(
                f"The job scheduler answered false to {verb} '{key}': no such job (the key is "
                "'<jobName>:<jobType>', case-sensitive — list the jobs with "
                "cnc_list_inventory_scheduler_jobs)."
            )
        raise PlatformError(
            f"The job scheduler answered false to {verb} '{key}' but the job exists (workState "
            f"{_text(row.get('workState'), '?')}) — the scheduler refused the {verb}; a {verb} "
            "of a job in that state was not exercised live. cnc_get_inventory_scheduler_job "
            "shows the job."
        )

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_inventory_scheduler_jobs",
        title="List Inventory Scheduler Jobs",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_inventory_scheduler_jobs(
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the EMS inventory scheduler jobs — the built-in recurring jobs
        that refresh the device inventory — with their state, cadence and last
        result.

        Read-only. ``GET /crosswork/rs/json/jobSchedulerServiceInv/v1/
        getSystemLazyJobsSpecification`` with ``Range: items=0-199`` (the
        header is REQUIRED — verified live: without it the service answers 400
        Bad Request). Answers 200 or 206 with ``{"totalCount", "items": [{
        jobName, jobType, workState Scheduled|Suspended|In-Progress,
        jobInterval, nextRunTime, startTime, duration, lastRunResultState
        Success|Running, lastRunJobId, ...}]}``; the verified instance has
        five jobs (internalSchedule, Switch Inventory, Failed Feature Sync,
        thirdPartyDeviceSync, reBuildAssociation), all of type Inventory.

        Use it before cnc_run_inventory_scheduler_job / suspend / resume to
        get the exact job name, and after them to see the new state.

        Args:
            response_format: markdown (one line per job) or json.

        Returns:
            str: Markdown, or JSON {"total": int|null, "count": int, "items":
            [rows]}. "No scheduler jobs are listed." when ``items`` is empty;
            "Error: ..." on an HTTP failure, an empty body or an unexpected
            document.
        """
        try:
            rows, total = await read_jobs()
            if response_format is ResponseFormat.JSON:
                return finalize(
                    to_json({"total": total, "count": len(rows), "items": rows}), settings
                )
            if not rows:
                return finalize(
                    "No scheduler jobs are listed (the job scheduler answered an empty set).",
                    settings,
                )
            partial = total is not None and total > len(rows)
            shown = f"{len(rows)} of {total}" if partial else f"{len(rows)}"
            lines = [f"# Inventory scheduler jobs ({shown})", ""]
            lines.extend(job_line(row) for row in rows)
            if partial:
                lines.extend(
                    [
                        "",
                        f"Partial answer: the scheduler reports {total} jobs but the "
                        f"Range window items=0-{RANGE_END} returned {len(rows)}.",
                    ]
                )
            lines.extend(
                [
                    "",
                    "Run one now with cnc_run_inventory_scheduler_job(job_name=...); pause / "
                    "unpause with cnc_suspend_inventory_scheduler_job / "
                    "cnc_resume_inventory_scheduler_job.",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_inventory_scheduler_job",
        title="Get Inventory Scheduler Job",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_inventory_scheduler_job(
        job_name: Annotated[str, Field(description=_JOB_NAME_DESC, min_length=1, max_length=100)],
        job_type: Annotated[
            str, Field(description=_JOB_TYPE_DESC, max_length=50)
        ] = DEFAULT_JOB_TYPE,
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Show one inventory scheduler job (state, cadence, next run, last run).

        Read-only. No per-job read of this service is verified, so this lists
        the jobs (``GET getSystemLazyJobsSpecification`` with the Range
        header) and selects the row whose ``jobName`` / ``jobType`` match
        exactly (case-sensitive).

        Args:
            job_name: exact job name.
            job_type: job type, default 'Inventory'.
            response_format: markdown or json.

        Returns:
            str: Markdown of the job's fields, or the row as JSON. "Error: no
            scheduler job '<name>:<type>' ..." when no row matches; "Error:
            job_name ... Nothing was sent." for a name the raw key cannot
            carry; "Error: ..." on an HTTP failure.
        """
        try:
            key = job_key(job_name, job_type)
            row = await read_job(job_name, job_type)
            if row is None:
                raise PlatformError(
                    f"no scheduler job '{key}' (names are case-sensitive; the built-in jobs are "
                    f"{', '.join(BUILT_IN_JOBS)} — cnc_list_inventory_scheduler_jobs lists them)."
                )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(row), settings)
            return finalize(job_markdown(row), settings)
        except Exception as e:
            return format_error(e)

    async def act(
        url: str,
        verb: str,
        job_name: str,
        job_type: str,
        done_text: str,
        expected_state: str,
        lag_note: str = "",
    ) -> str:
        """Send one scheduler write, then read the job back once.

        The bare ``true`` verdict is what proves the write; a read-back that
        fails or does not find the row is reported inside a non-error answer
        (an "Error:" here would invite a re-send of a write that was applied).
        """
        key = job_key(job_name, job_type)
        await write(url, key, verb, job_name, job_type)
        row: dict[str, Any] | None = None
        read_error: str | None = None
        try:
            row = await read_job(job_name, job_type)
        except Exception as e:  # the write was applied; the read-back is best effort
            read_error = format_error(e)
        if read_error is not None:
            state = f"state not readable afterwards ({read_error})"
        elif row is None:
            state = "state not readable afterwards (the job is missing from the list)"
        else:
            actual = _text(row.get("workState"), "?")
            state = f"now {actual}"
            if actual != expected_state:
                state += f" (expected {expected_state}{lag_note})"
        summary = f"{done_text} scheduler job '{key}': the scheduler answered true; {state}."
        payload = {"job": key, "verdict": True, "state": row, "state_error": read_error}
        return finalize(f"{summary}\n\n{to_json(payload)}", settings)

    @register_tool(
        mcp,
        ctx,
        name="cnc_run_inventory_scheduler_job",
        title="Run Inventory Scheduler Job Now",
        read_only=False,
        destructive=False,
        idempotent=False,
    )
    async def cnc_run_inventory_scheduler_job(
        job_name: Annotated[str, Field(description=_JOB_NAME_DESC, min_length=1, max_length=100)],
        job_type: Annotated[
            str, Field(description=_JOB_TYPE_DESC, max_length=50)
        ] = DEFAULT_JOB_TYPE,
    ) -> str:
        """Run an inventory scheduler job now, ahead of its schedule (for
        example 'Failed Feature Sync' after fixing a device's credentials, or
        'Switch Inventory' to refresh the EMS inventory without waiting for
        the daily run).

        WRITE. ``POST /crosswork/rs/json/jobSchedulerServiceInv/v1/runJob``
        with the raw text body ``<jobName>:<jobType>`` (verified live) —
        answers ``true`` and the job goes In-Progress within seconds (Failed
        Feature Sync takes ~5 s on the lab); ``false`` was verified only for
        a nonexistent key. The job's regular schedule is unchanged. The
        read-back right after the write may still show Scheduled (the
        scheduler has not picked the run up yet); follow with
        cnc_wait_for_inventory_scheduler_job, passing that read-back's
        ``lastRunJobId`` (the previous run's id while the row still shows
        Scheduled) as ``previous_run_job_id`` so the wait cannot end before
        the run starts. Not re-sent on a transport error (a second send could
        queue a second run); running a job that is already In-Progress was
        not exercised live.

        Args:
            job_name: exact job name.
            job_type: job type, default 'Inventory'.

        Returns:
            str: "Started scheduler job '<key>': the scheduler answered true;
            now In-Progress." (or "now Scheduled (expected In-Progress ...)"
            when the read-back is too early, or "state not readable
            afterwards (...)" when the read-back fails — the run was still
            accepted) plus a JSON {"job", "verdict", "state": row|null,
            "state_error": null|"Error: ..."}; ``state.lastRunJobId`` is the
            value to hand cnc_wait_for_inventory_scheduler_job as
            ``previous_run_job_id`` when ``state.workState`` is still
            Scheduled. "Error: The job scheduler answered false to run
            '<key>': no such job ..." for an unknown name, "... but the job
            exists (workState <state>) — the scheduler refused the run ..."
            when the row is listed; "Error: job_name ... Nothing was sent."
            for a name the raw key cannot carry; "Error: ..." on an HTTP
            failure of the write itself.
        """
        try:
            return await act(
                RUN_URL,
                "run",
                job_name,
                job_type,
                "Started",
                STATE_IN_PROGRESS,
                lag_note=(
                    " — the scheduler picks the run up within seconds; "
                    "cnc_wait_for_inventory_scheduler_job follows it"
                ),
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_suspend_inventory_scheduler_job",
        title="Suspend Inventory Scheduler Job",
        read_only=False,
        destructive=False,
        idempotent=True,
    )
    async def cnc_suspend_inventory_scheduler_job(
        job_name: Annotated[str, Field(description=_JOB_NAME_DESC, min_length=1, max_length=100)],
        job_type: Annotated[
            str, Field(description=_JOB_TYPE_DESC, max_length=50)
        ] = DEFAULT_JOB_TYPE,
    ) -> str:
        """Suspend an inventory scheduler job so it stops running on its schedule
        (e.g. during a maintenance window); cnc_resume_inventory_scheduler_job
        puts it back.

        WRITE. ``POST .../suspendJob`` with the raw body ``<jobName>:<jobType>``
        (verified live: answers ``true``; the job's ``workState`` becomes
        Suspended and its ``nextRunTime`` null). Suspending an already
        suspended job was not exercised live (expected to be a no-op). A
        suspended inventory job means the EMS inventory stops refreshing —
        remember to resume it.

        Args:
            job_name: exact job name.
            job_type: job type, default 'Inventory'.

        Returns:
            str: "Suspended scheduler job '<key>': ... now Suspended." plus a
            JSON {"job", "verdict", "state": row|null, "state_error":
            null|"Error: ..."} (the read-back failing is reported inside this
            answer, not as an error); "Error: ... answered false ... no such
            job" for an unknown job, "... but the job exists (workState
            <state>) — the scheduler refused the suspend ..." when the row is
            listed; "Error: job_name ... Nothing was sent." for a name the
            raw key cannot carry; "Error: ..." on an HTTP failure of the
            write itself.
        """
        try:
            return await act(
                SUSPEND_URL, "suspend", job_name, job_type, "Suspended", STATE_SUSPENDED
            )
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_resume_inventory_scheduler_job",
        title="Resume Inventory Scheduler Job",
        read_only=False,
        destructive=False,
        idempotent=True,
    )
    async def cnc_resume_inventory_scheduler_job(
        job_name: Annotated[str, Field(description=_JOB_NAME_DESC, min_length=1, max_length=100)],
        job_type: Annotated[
            str, Field(description=_JOB_TYPE_DESC, max_length=50)
        ] = DEFAULT_JOB_TYPE,
    ) -> str:
        """Resume a suspended inventory scheduler job (it returns to Scheduled
        with a new next-run time).

        WRITE. ``POST .../resumeJob`` with the raw body ``<jobName>:<jobType>``
        (verified live: answers ``true``, ``workState`` back to Scheduled).
        Resuming a job that is not suspended was not exercised live (expected
        to be a no-op).

        Args:
            job_name: exact job name.
            job_type: job type, default 'Inventory'.

        Returns:
            str: "Resumed scheduler job '<key>': ... now Scheduled." plus a
            JSON {"job", "verdict", "state": row|null, "state_error":
            null|"Error: ..."} (the read-back failing is reported inside this
            answer, not as an error); "Error: ... answered false ... no such
            job" for an unknown job, "... but the job exists (workState
            <state>) — the scheduler refused the resume ..." when the row is
            listed; "Error: job_name ... Nothing was sent." for a name the
            raw key cannot carry; "Error: ..." on an HTTP failure of the
            write itself.
        """
        try:
            return await act(RESUME_URL, "resume", job_name, job_type, "Resumed", STATE_SCHEDULED)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_wait_for_inventory_scheduler_job",
        title="Wait For Inventory Scheduler Job",
        read_only=True,
        idempotent=True,
    )
    async def cnc_wait_for_inventory_scheduler_job(
        job_name: Annotated[str, Field(description=_JOB_NAME_DESC, min_length=1, max_length=100)],
        job_type: Annotated[
            str, Field(description=_JOB_TYPE_DESC, max_length=50)
        ] = DEFAULT_JOB_TYPE,
        timeout_seconds: Annotated[
            int, Field(description="Give up after this many seconds (e.g. 120).", ge=5, le=1800)
        ] = 120,
        interval_seconds: Annotated[
            int, Field(description="Seconds between polls (e.g. 5).", ge=1, le=60)
        ] = 5,
        previous_run_job_id: Annotated[
            str | None,
            Field(
                description=(
                    "The job's lastRunJobId from BEFORE the run (cnc_get_inventory_scheduler_job "
                    "before calling run, or the run tool's read-back while it still shows "
                    "Scheduled). With it the wait cannot end before the scheduler has started "
                    "the run: it finishes only once the job is not In-Progress AND lastRunJobId "
                    "differs from this value (or In-Progress was observed). E.g. '449540'."
                ),
                max_length=50,
            ),
        ] = None,
    ) -> str:
        """Wait until an inventory scheduler job is no longer In-Progress —
        typically right after cnc_run_inventory_scheduler_job.

        Read-only polling of the job list (Range header) every
        ``interval_seconds`` until ``workState`` is not In-Progress, then
        reports the last run result. THE START RACE: the scheduler moves a
        job to In-Progress a moment after ``runJob`` answers, so a wait that
        starts too early would find the job still Scheduled and end at once
        without having seen the run. Pass ``previous_run_job_id`` (the row's
        ``lastRunJobId`` before the run) to close it: the wait then finishes
        only once the job is not In-Progress and ``lastRunJobId`` has moved
        on from that value — or In-Progress was observed, so a run that is
        caught mid-flight finishes even if the id did not change (each run
        getting a fresh ``lastRunJobId`` is inferred from the field's name,
        not verified live). Without the parameter the answer says whether
        In-Progress was observed; when it was not, compare the row's
        ``lastRunJobId`` / ``startTime`` with the run's read-back, or call
        again a few seconds later.

        Args:
            job_name: exact job name.
            job_type: job type, default 'Inventory'.
            timeout_seconds: how long to wait.
            interval_seconds: poll interval.
            previous_run_job_id: lastRunJobId from before the run (optional).

        Returns:
            str: "Scheduler job '<key>' finished after <t>s: <state>, last run
            <result>." when the run was seen (In-Progress observed, or
            lastRunJobId moved on from ``previous_run_job_id``) and the job
            is no longer In-Progress; "Scheduler job '<key>' was not
            In-Progress when polled (<t>s): <state>, last run <result>. ..."
            when no ``previous_run_job_id`` was given and it never was; on
            timeout a non-error "Scheduler job '<key>' not finished yet after
            <t>s, current state: In-Progress ..." or, with
            ``previous_run_job_id`` and no run seen, "... not finished yet
            after <t>s: the scheduler has not started the run yet
            (lastRunJobId still <id>, state <state>) ..." — call again to
            keep waiting; "Error: no scheduler job ..." when the row is
            missing; "Error: job_name ... Nothing was sent." for a name the
            raw key cannot carry; "Error: ..." on an HTTP failure.
        """
        try:
            key = job_key(job_name, job_type)
            seen_in_progress = False

            async def fetch() -> dict[str, Any] | None:
                nonlocal seen_in_progress
                row = await read_job(job_name, job_type)
                if row is not None and row.get("workState") == STATE_IN_PROGRESS:
                    seen_in_progress = True
                return row

            def run_seen(row: dict[str, Any]) -> bool:
                """The run was witnessed: In-Progress observed, or the id moved on."""
                if seen_in_progress:
                    return True
                if previous_run_job_id is None:
                    return False
                return _text(row.get("lastRunJobId"), "") != previous_run_job_id

            def done(row: dict[str, Any] | None) -> bool:
                if row is None:
                    return True
                if row.get("workState") == STATE_IN_PROGRESS:
                    return False
                return previous_run_job_id is None or run_seen(row)

            finished, row, elapsed = await wait_until(
                fetch, done, timeout_seconds=timeout_seconds, interval_seconds=interval_seconds
            )
            if row is None:
                raise PlatformError(
                    f"no scheduler job '{key}' (cnc_list_inventory_scheduler_jobs lists them)."
                )
            state = _text(row.get("workState"), "?")
            result = _text(row.get("lastRunResultState"))
            if not finished:
                if previous_run_job_id is not None and not run_seen(row):
                    head = (
                        f"Scheduler job '{key}' not finished yet after {elapsed:.0f}s: the "
                        f"scheduler has not started the run yet (lastRunJobId still "
                        f"{previous_run_job_id}, state {state}, last result {result}). Call "
                        "again to keep waiting."
                    )
                else:
                    head = (
                        f"Scheduler job '{key}' not finished yet after {elapsed:.0f}s, current "
                        f"state: {state} (last result {result}). Call again to keep waiting."
                    )
                return finalize(f"{head}\n\n{to_json(row)}", settings)
            outcome = (
                f"{state}, last run {result} (job {_text(row.get('lastRunJobId'))}, "
                f"{_text(row.get('duration'))})"
            )
            if run_seen(row):
                head = f"Scheduler job '{key}' finished after {elapsed:.0f}s: {outcome}."
            else:
                head = (
                    f"Scheduler job '{key}' was not In-Progress when polled ({elapsed:.0f}s): "
                    f"{outcome}. If you have just called cnc_run_inventory_scheduler_job the "
                    "scheduler may not have picked the run up yet (it goes In-Progress within "
                    "seconds) — compare lastRunJobId / startTime with the run's read-back, or "
                    "call again in a few seconds."
                )
            return finalize(f"{head}\n\n{to_json(row)}", settings)
        except Exception as e:
            return format_error(e)
