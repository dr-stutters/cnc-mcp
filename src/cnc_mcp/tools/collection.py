"""Collection service tools — the collection jobs Crosswork's applications run on
the Data Gateway: job counts, status, lifecycle state, export jobs and sensor
templates.

What the collection service is. Every Crosswork application that needs data
from devices (the DLM inventory manager, the Optimization Engine, Health
Insights, ...) registers a **collection job** with the collection service
(``/crosswork/collection/v1``), which schedules it on the Crosswork Data
Gateway (the embedded DG on a standard deployment —
:mod:`cnc_mcp.tools.data_gateway` lists the gateways and their per-collector
load). A job is keyed by its ``application_context``: ``application_id`` (the
owning application — Crosswork apps always prefix it with ``cw.``) plus
``context_id`` (the application's own subscription id), and every query here
takes that key. The one job verified live (2026-09-13) is the DLM's CLI
collector, ``cw.dlminvmgr0`` / ``dlm/cli-collector/group/te-tunnel-id/
subscription`` — the built-in job that exists on every deployment with managed
devices — so it is the tools' default context and a bare call answers.

Wire facts (verified live on Crosswork 7.2, 2026-09-13; base
:data:`cnc_mcp.crosswork.COLLECTION`, plain JSON):

- Every ``collectionjob/*/query`` read is a POST with ``{"application_context":
  {"application_id", "context_id"}, "query_options": {"page_token": "",
  "page_size": N, "filter_list": [], "filter_query": ""}}``. ``jobs/query``
  takes ``query_options`` only, with ``page_token`` ``"0"`` — the token the
  platform echoed for an empty ``jobs/query`` body — and the 7.2 document
  says of it "currently the query options are not utilized", so that tool
  exposes no paging. ``template`` takes ``template_id`` + ``query_options``;
  the document says the ``template_id`` "is required; if not specified,
  nothing is returned" (a wildcard pattern matches any template_id containing
  it). The ``query_options`` block is the shared
  :func:`cnc_mcp.crosswork.collection_query_body` plus the ``filter_query``
  field every verified body carried.
- Every answer carries ``result.request_result`` — ``ACCEPTED``, or a
  rejection (still HTTP 200) with the reason in ``result.error.error``;
  :func:`cnc_mcp.crosswork.check_collection_result` gates every answer.
- ``collectionjob/count/query`` answers ``{job_count, device_count,
  input_collection_count, output_collection_count,
  input_error_collection_count, output_error_collection_count,
  control_error_count, input_filtered_count, output_filtered_count}`` —
  **all strings** (``"1"``, ``"5"``); the tools coerce them to ints.
- ``collectionjob/summary/query`` answers ``collection_job_status_list[]``
  (``application_context``, ``creation_time`` epoch ms, ``deletion_time``,
  ``progress`` 100, ``status`` READY, ``phase`` ACTIVE, ``collector_type``
  CLI_COLLECTOR, ``job_error.error``). ``collectionjob/state/query`` answers
  ``collection_life_cycle_states[]`` (``life_cycle_state``
  SUCCESS_LIFE_CYCLE_STATE, ``creation_time``, ``state_evaluation_time``) and
  echoes an **opaque hash** as ``query_options.page_token`` even for a single
  entry — the token alone is no end-of-data signal, and the verified
  ``summary`` answer carries no ``query_options`` at all. The paged tools take
  a ``page_token`` (sent verbatim) and answer a three-valued ``has_more`` from
  :func:`page_state`: False when the page came back short; True when it came
  back full AND :func:`cnc_mcp.crosswork.collection_next_token` found a token
  that differs from the one sent (``next_page_token``); None (unknown, with a
  ``paging_note``) when it came back full but no new token was echoed — a
  full page is never reported as "no more" (the template's
  ``pagination_envelope`` rule). The rule is a heuristic — only single-entry
  and empty pages were seen live — so a second page has NOT been fetched on
  a real instance (the echoed ``query_options`` are passed through in JSON).
- ``jobs/query`` answers ``jobs: []`` on the lab (no export jobs) — a normal
  empty result, not an error. ``template`` answered ``sensor_templates: []``
  on the lab for a body WITHOUT ``template_id`` — the documented
  "nothing is returned" answer, so whether the lab defines any template is
  UNVERIFIED until a ``template_id`` query is run live. Item rendering of
  both follows the 7.2 document.
- The document says an omitted ``application_context`` makes ``count`` and
  ``summary`` answer for ALL collection jobs in the system; the tools send no
  context when both ids are given blank (documented, NOT verified live).

Not exposed: creating and deleting collection jobs (``PUT`` / ``DELETE
collectionjob`` need a data destination and a sensor definition — left for a
later module), template collection jobs, export-job create/delete, the
``jobs/query`` ``ids[]`` selector (export application_contexts), and the
per-device status queries (``controlstatus`` / ``datastatus`` /
``datametrics`` / ``taskstatus``), none of which was verified live.
"""

from __future__ import annotations

import asyncio
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.crosswork import (
    COLLECTION,
    COLLECTION_ACCEPTED,
    check_collection_result,
    collection_next_token,
    collection_query_body,
)
from cnc_mcp.errors import PlatformError, format_error
from cnc_mcp.formatting import ResponseFormat, epoch_iso, finalize, to_json
from cnc_mcp.safety import AppContext, register_tool

COLLECTION_JOB_COUNT_URL = f"{COLLECTION}/collectionjob/count/query"
COLLECTION_JOB_SUMMARY_URL = f"{COLLECTION}/collectionjob/summary/query"
COLLECTION_JOB_STATE_URL = f"{COLLECTION}/collectionjob/state/query"
JOBS_QUERY_URL = f"{COLLECTION}/jobs/query"
TEMPLATE_QUERY_URL = f"{COLLECTION}/template"

# The built-in DLM CLI-collector job (verified live) — the tools' default context.
DLM_APPLICATION_ID = "cw.dlminvmgr0"
DLM_CONTEXT_ID = "dlm/cli-collector/group/te-tunnel-id/subscription"

# First-page tokens as sent live: "" on the application-context queries, "0" on
# jobs/query and template (the token the platform echoed for an empty body).
FIRST_PAGE_TOKEN = ""
JOBS_FIRST_PAGE_TOKEN = "0"
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 500
# The platform's own default page size (echoed live for an empty body). Sent with
# the queries that expose no paging: count (a single document) and jobs/query
# (the 7.2 document: "currently the query options are not utilized").
PLATFORM_PAGE_SIZE = 100

# collectionjob/count/query fields, in rendering order (all strings on the wire).
COUNT_FIELDS = (
    "job_count",
    "device_count",
    "input_collection_count",
    "output_collection_count",
    "input_error_collection_count",
    "output_error_collection_count",
    "control_error_count",
    "input_filtered_count",
    "output_filtered_count",
)
ERROR_COUNT_FIELDS = (
    "input_error_collection_count",
    "output_error_collection_count",
    "control_error_count",
)
FILTERED_COUNT_FIELDS = ("input_filtered_count", "output_filtered_count")

# Documented enumerations (collection_serviceStatus / Phase / LifeCycleState).
STATUS_READY = "READY"
PHASE_ACTIVE = "ACTIVE"
LIFE_CYCLE_SUCCESS = "SUCCESS_LIFE_CYCLE_STATE"
_LIFE_CYCLE_SUFFIX = "_LIFE_CYCLE_STATE"

_RESPONSE_FORMAT_DESC = "'markdown' for human-readable output, 'json' for the raw platform data."
_APPLICATION_ID_DESC = (
    "application_id of the collection job's application_context — the owning application, "
    f"'cw.'-prefixed for Crosswork apps (default '{DLM_APPLICATION_ID}', the DLM inventory "
    "manager's built-in CLI collector job). Give both ids blank ('') for every job in the "
    "system (documented, not verified live)."
)
_CONTEXT_ID_DESC = (
    "context_id of the application_context — the application's subscription id (default "
    f"'{DLM_CONTEXT_ID}', the built-in DLM job). Blank together with application_id for "
    "every job."
)
_PAGE_SIZE_DESC = (
    "Entries per page (e.g. 50). The answer's has_more / next_page_token say whether to call "
    "again with page_token (true: a full page plus a new token from the platform; null: a "
    "full page with no new token — more may exist, re-query with a larger page_size)."
)
_PAGE_TOKEN_DESC = (
    "Token of the page to fetch — the next_page_token of the previous answer (e.g. "
    "'a7859eb217ee381541afe2f911dfd21c'); leave blank ('') for the first page."
)
_TEMPLATE_ID_DESC = (
    "sensor_template_id to look up (e.g. 'show-interface'). Required by the platform: the "
    "7.2 document says 'if not specified, nothing is returned', and that a wildcard pattern "
    "matches every template_id containing it (the wildcard syntax is not verified live)."
)
_TEMPLATE_ID_RULE = (
    "cnc_list_sensor_templates needs a template_id: the platform answers nothing for a blank "
    "one (7.2 document: 'The template_id is required; if not specified, nothing is returned')."
)
_CONTEXT_RULE = (
    "application_id and context_id go together: give both (the job's application_context) "
    "or both blank for every job in the system."
)


# --- pure helpers: request bodies ------------------------------------------------


def application_context(application_id: str, context_id: str) -> dict[str, str] | None:
    """``{"application_id", "context_id"}`` (stripped), or ``None`` when both are blank.

    Both blank means "no application_context" — the documented way to ask
    about every collection job (not verified live). One blank and one given
    is a PlatformError: the platform would key the query on half a context.
    """
    app = application_id.strip()
    ctx = context_id.strip()
    if not app and not ctx:
        return None
    if not app or not ctx:
        raise PlatformError(_CONTEXT_RULE)
    return {"application_id": app, "context_id": ctx}


def query_options(page_size: int, page_token: str = FIRST_PAGE_TOKEN) -> dict[str, Any]:
    """The verified ``query_options`` block: token, size, empty filter list and filter query.

    Built on the shared :func:`cnc_mcp.crosswork.collection_query_body` (the
    one collection/v1 body builder) plus ``filter_query``, the field every
    body verified live on this service carried alongside ``filter_list``.
    """
    options = collection_query_body(page_size=page_size, page_token=page_token)["query_options"]
    options["filter_query"] = ""
    return options


def job_query_body(
    application_id: str,
    context_id: str,
    page_size: int = DEFAULT_PAGE_SIZE,
    page_token: str = FIRST_PAGE_TOKEN,
) -> dict[str, Any]:
    """The body of a ``collectionjob/*/query``: application_context (when given) + query_options."""
    body: dict[str, Any] = {}
    context = application_context(application_id, context_id)
    if context is not None:
        body["application_context"] = context
    body["query_options"] = query_options(page_size, page_token)
    return body


def list_query_body(
    page_size: int = PLATFORM_PAGE_SIZE, page_token: str = JOBS_FIRST_PAGE_TOKEN
) -> dict[str, Any]:
    """The body of ``jobs/query``: query_options only, first page ``"0"``.

    Sent with the platform's own page size and first-page token because the
    7.2 document says of GetJobsRequest "currently the query options are not
    utilized" (the lab echoed the ``"0"`` it was sent, consistent with that).
    """
    return {"query_options": query_options(page_size, page_token)}


_TEMPLATE_MISSING = "template for the given templateid does not exist"


def template_lookup_missed(data: dict[str, Any]) -> bool:
    """True when a ``POST template`` answer is the platform's "no such template" rejection.

    Verified live: an unmatched ``template_id`` (the wildcard ``*`` included,
    when the platform holds no template at all) answers HTTP 200 with
    ``result.request_result`` REJECTED and ``result.error.error`` "Template
    for the given TemplateId does not exist" beside an empty
    ``sensor_templates`` list. That is a "no match", not a failure.
    """
    result = data.get("result")
    if not isinstance(result, dict) or result.get("request_result") == COLLECTION_ACCEPTED:
        return False
    error = result.get("error")
    reason = error.get("error") if isinstance(error, dict) else error
    return isinstance(reason, str) and _TEMPLATE_MISSING in reason.lower()


def template_query_body(
    template_id: str, page_size: int = DEFAULT_PAGE_SIZE, page_token: str = JOBS_FIRST_PAGE_TOKEN
) -> dict[str, Any]:
    """The body of ``POST template``: ``template_id`` (required) + query_options.

    A blank ``template_id`` is a PlatformError rather than a request: the
    document says "if not specified, nothing is returned", so sending none
    would only ever produce an empty list that reads as "no templates".
    """
    ident = template_id.strip()
    if not ident:
        raise PlatformError(_TEMPLATE_ID_RULE)
    return {"template_id": ident, **list_query_body(page_size, page_token)}


def page_state(
    items: list[Any], data: dict[str, Any], page_size: int, sent_token: str
) -> dict[str, Any]:
    """Token-paging fields of a list answer: page_size, page_token, has_more,
    next_page_token, paging_note.

    ``has_more`` is three-valued, because the platform's end-of-data signal is
    UNVERIFIED live (only single-entry and empty pages were seen):

    - False: the page came back short (fewer than ``page_size`` entries) —
      nothing more is on the server.
    - True: the page came back full AND the platform echoed a
      ``query_options.page_token`` that differs from the one sent
      (:func:`cnc_mcp.crosswork.collection_next_token`); ``next_page_token``
      is the token to pass back as ``page_token``. A heuristic — the state
      query echoes an opaque hash even for one entry.
    - None (unknown): the page came back full but no new token was echoed
      (the verified summary answer carries no ``query_options`` at all;
      ``jobs/query`` echoed the ``"0"`` it was sent). More entries may sit on
      the server, and ``paging_note`` says to re-query with a larger
      ``page_size``. A full page is never reported as False — the template's
      :func:`cnc_mcp.formatting.pagination_envelope` rule ("no total: a full
      page means more") applied to token paging.

    ``paging_note`` is None unless ``has_more`` is None.
    """
    next_token = collection_next_token(data, sent_token)
    full = len(items) >= page_size
    has_more: bool | None
    if not full:
        has_more = False
    elif next_token is not None:
        has_more = True
    else:
        has_more = None
    note = None
    if has_more is None:
        note = (
            f"page full ({len(items)} entries at page_size {page_size}) and the platform "
            "echoed no new page token — more entries may exist; call again with a larger "
            "page_size"
        )
    return {
        "page_size": page_size,
        "page_token": sent_token,
        "has_more": has_more,
        "next_page_token": next_token if has_more else None,
        "paging_note": note,
    }


def more_note(paging: dict[str, Any], tool: str) -> list[str]:
    """Markdown trailer when :func:`page_state` says more entries may sit on the server."""
    if paging["has_more"] is True:
        return [
            "",
            f"(more on server: call {tool} again with page_token "
            f"'{paging['next_page_token']}' — heuristic: this page came back full and the "
            "platform echoed a new token.)",
        ]
    if paging["has_more"] is None:
        return ["", f"({paging['paging_note']} on {tool}.)"]
    return []


# --- pure helpers: response shapes -------------------------------------------------


def as_int(value: Any) -> int | None:
    """Coerce a count the platform sends as a string (``"5"``) to an int; ``None`` if absent.

    Every count in ``collectionjob/count/query`` is a string on the wire
    (verified live); ints and numeric strings are accepted, anything else
    (missing, blank, text) is ``None`` so a rendering never invents a zero.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def dict_list(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def context_text(context: Any) -> str:
    """``<application_id> / <context_id>`` for an application_context object."""
    if not isinstance(context, dict):
        return "?"
    return f"{context.get('application_id') or '?'} / {context.get('context_id') or '?'}"


def scope_text(context: dict[str, str] | None) -> str:
    return context_text(context) if context is not None else "all collection jobs"


def error_text(block: Any) -> str:
    """The ``error`` string of a ``{"error": "..."}`` wrapper (``""`` when empty/absent)."""
    if isinstance(block, dict):
        text = block.get("error")
        return text.strip() if isinstance(text, str) else ""
    if isinstance(block, str):
        return block.strip()
    return ""


def coerce_counts(data: dict[str, Any]) -> dict[str, int | None]:
    """The :data:`COUNT_FIELDS` of a count answer as ints (``None`` where absent)."""
    return {field: as_int(data.get(field)) for field in COUNT_FIELDS}


def count_or_unknown(value: int | None) -> str:
    """A coerced count as text, ``?`` when the platform omitted it (never an invented 0)."""
    return str(value) if value is not None else "?"


def total_or_unknown(counts: dict[str, int | None], fields: tuple[str, ...]) -> str:
    """The sum of the ``fields`` the platform sent, ``?`` when it sent none of them."""
    present = [counts[f] for f in fields if counts.get(f) is not None]
    return str(sum(present)) if present else "?"


def count_summary_line(counts: dict[str, int | None], scope: str) -> str:
    """One line: jobs, devices, input/output collections, errors, filtered.

    Every figure is ``?`` when the platform omitted the field (the error and
    filtered totals when it omitted ALL of their fields) — :func:`as_int`'s
    "never invent a zero" contract carried through to the rendering.
    """
    jobs = counts.get("job_count")
    if jobs == 0:
        return f"No collection job is registered for {scope}."
    return (
        f"{count_or_unknown(jobs)} collection job(s) for {scope} on "
        f"{count_or_unknown(counts.get('device_count'))} device(s): "
        f"{count_or_unknown(counts.get('input_collection_count'))} input / "
        f"{count_or_unknown(counts.get('output_collection_count'))} output collections, "
        f"{total_or_unknown(counts, ERROR_COUNT_FIELDS)} error(s), "
        f"{total_or_unknown(counts, FILTERED_COUNT_FIELDS)} filtered."
    )


def job_status_line(entry: dict[str, Any]) -> str:
    """One markdown line per ``collection_job_status_list`` entry."""
    progress = entry.get("progress")
    error = error_text(entry.get("job_error"))
    line = (
        f"- **{context_text(entry.get('application_context'))}** "
        f"status={entry.get('status', '?')} phase={entry.get('phase', '?')} "
        f"progress={progress if progress is not None else '?'}% "
        f"collector={entry.get('collector_type', '?')} "
        f"created={epoch_iso(entry.get('creation_time'))} "
        f"deleted={epoch_iso(entry.get('deletion_time'))}"
    )
    if error:
        line += f" error={error}"
    return line


def life_cycle_short(state: Any) -> str:
    """``SUCCESS_LIFE_CYCLE_STATE`` -> ``SUCCESS`` (the raw value is kept in JSON)."""
    text = str(state or "?")
    return text[: -len(_LIFE_CYCLE_SUFFIX)] if text.endswith(_LIFE_CYCLE_SUFFIX) else text


def life_cycle_line(entry: dict[str, Any]) -> str:
    """One markdown line per ``collection_life_cycle_states`` entry."""
    return (
        f"- **{context_text(entry.get('application_context'))}** "
        f"life-cycle={entry.get('life_cycle_state', '?')} "
        f"created={epoch_iso(entry.get('creation_time'))} "
        f"evaluated={epoch_iso(entry.get('state_evaluation_time'))}"
    )


def export_job_line(job: dict[str, Any]) -> str:
    """One markdown line per ``jobs[]`` entry (documented shape; none seen live)."""
    ident = job.get("id") if isinstance(job.get("id"), dict) else {}
    export = ident.get("export_id") if isinstance(ident.get("export_id"), dict) else {}
    progress = job.get("progress")
    line = (
        f"- **{context_text(export.get('application_context'))}** "
        f"type={job.get('type', '?')} status={job.get('status', '?')} "
        f"progress={progress if progress is not None else '?'}% user={job.get('user') or '-'} "
        f"created={epoch_iso(job.get('created'))} completed={epoch_iso(job.get('completed'))}"
    )
    if job.get("description"):
        line += f" — {job['description']}"
    return line


def template_definition_text(definition: Any) -> str:
    """The CLI command / device package / gNMI path of a sensor_template_Definition."""
    if not isinstance(definition, dict):
        return "-"
    parts: list[str] = []
    cli = definition.get("cli_sensor_template")
    if isinstance(cli, dict):
        command = cli.get("template_command")
        if isinstance(command, dict) and command.get("templatecommand"):
            parts.append(f"cli '{command['templatecommand']}'")
            variables = command.get("template_variables")
            if isinstance(variables, list) and variables:
                parts.append(f"variables {', '.join(str(v) for v in variables)}")
        package = cli.get("template_device_package")
        if isinstance(package, dict) and package.get("device_package_name"):
            parts.append(
                f"device-package {package['device_package_name']}."
                f"{package.get('function_name') or '?'}"
            )
    gnmi = definition.get("gnmi_sensor_template")
    if isinstance(gnmi, dict) and gnmi.get("gnmi_path"):
        parts.append(f"gnmi '{gnmi['gnmi_path']}'")
        variables = gnmi.get("template_variables")
        if isinstance(variables, list) and variables:
            parts.append(f"variables {', '.join(str(v) for v in variables)}")
    return " ".join(parts) if parts else "-"


def sensor_template_line(template: dict[str, Any]) -> str:
    """One markdown line per ``sensor_templates[]`` entry (documented shape; none seen live)."""
    cadence = as_int(template.get("cadence_in_millisec"))
    return (
        f"- **{template.get('sensor_template_id') or '?'}** "
        f"type={template.get('collection_type', '?')} "
        f"cadence={f'{cadence} ms' if cadence is not None else '-'} "
        f"definition: {template_definition_text(template.get('sensor_template_Definition'))}"
    )


def health_payload(
    context: dict[str, str],
    counts: dict[str, int | None],
    statuses: list[dict[str, Any]],
    states: list[dict[str, Any]],
) -> dict[str, Any]:
    """The cnc_get_collection_health document: counts + status/phase + lifecycle + verdict.

    ``status`` / ``phase`` / ``life_cycle_state`` are those of the first
    entry the platform lists for the context (one job per context is the
    verified case; every entry is kept under ``jobs`` / ``life_cycles``).
    ``healthy`` is READY + ACTIVE + SUCCESS lifecycle with no job error and
    zero error counts.
    """
    first_status = statuses[0] if statuses else {}
    first_state = states[0] if states else {}
    status = first_status.get("status")
    phase = first_status.get("phase")
    life_cycle = first_state.get("life_cycle_state")
    job_errors = [error_text(s.get("job_error")) for s in statuses]
    job_errors = [e for e in job_errors if e]
    error_counts = {field: counts.get(field) for field in ERROR_COUNT_FIELDS}
    error_total = sum(v or 0 for v in error_counts.values())
    job_count = counts.get("job_count")
    healthy = (
        bool(job_count)
        and status == STATUS_READY
        and phase == PHASE_ACTIVE
        and life_cycle == LIFE_CYCLE_SUCCESS
        and not job_errors
        and error_total == 0
    )
    if not job_count and not statuses:
        verdict = (
            f"No collection job is registered for {context_text(context)} — check the "
            "application_context (cnc_get_collection_job_count with blank ids counts every job)."
        )
    else:
        verdict = (
            f"Collection job {status or '?'}/{phase or '?'} on "
            f"{count_or_unknown(counts.get('device_count'))} devices, "
            f"lifecycle {life_cycle_short(life_cycle)}"
        )
        if len(statuses) > 1:
            verdict += f" ({len(statuses)} jobs under this context; first shown)"
        if job_errors:
            verdict += f"; job error: {'; '.join(job_errors)}"
        if error_total:
            verdict += f"; {error_total} collection error(s)"
        verdict += "." if healthy else " — NOT healthy."
    return {
        "application_id": context["application_id"],
        "context_id": context["context_id"],
        "job_count": job_count,
        "device_count": counts.get("device_count"),
        "input_collection_count": counts.get("input_collection_count"),
        "output_collection_count": counts.get("output_collection_count"),
        "status": status,
        "phase": phase,
        "progress": first_status.get("progress"),
        "collector_type": first_status.get("collector_type"),
        "life_cycle_state": life_cycle,
        "state_evaluation_time": first_state.get("state_evaluation_time"),
        "errors": {"job_errors": job_errors, **error_counts},
        "healthy": healthy,
        "jobs": statuses,
        "life_cycles": states,
        "verdict": verdict,
    }


# --- registration ----------------------------------------------------------------


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    async def query(url: str, body: dict[str, Any], what: str) -> dict[str, Any]:
        """POST one collection/v1 query and return its (ACCEPTED) document.

        Sent with ``retryable=True`` — these POSTs are reads. Any
        ``result.request_result`` other than ACCEPTED is raised through
        :func:`cnc_mcp.crosswork.check_collection_result` with the platform's
        ``result.error.error`` text; a non-dict body is reported as such.
        """
        data = await client.request_json("POST", url, json_body=body, retryable=True)
        if not isinstance(data, dict):
            raise PlatformError(
                f"{what}: the collection service returned an unexpected response shape: "
                f"{str(data)[:300]}"
            )
        return check_collection_result(data, what)

    async def read_counts(application_id: str, context_id: str) -> dict[str, int | None]:
        body = job_query_body(application_id, context_id, PLATFORM_PAGE_SIZE)
        data = await query(COLLECTION_JOB_COUNT_URL, body, "Collection job count query")
        return coerce_counts(data)

    async def read_summary(
        application_id: str, context_id: str, page_size: int, page_token: str = FIRST_PAGE_TOKEN
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        body = job_query_body(application_id, context_id, page_size, page_token)
        data = await query(COLLECTION_JOB_SUMMARY_URL, body, "Collection job summary query")
        return dict_list(data.get("collection_job_status_list")), data

    async def read_states(
        application_id: str, context_id: str, page_size: int
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        body = job_query_body(application_id, context_id, page_size)
        data = await query(COLLECTION_JOB_STATE_URL, body, "Collection job state query")
        return dict_list(data.get("collection_life_cycle_states")), data

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_collection_job_count",
        title="Get Collection Job Count",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_collection_job_count(
        application_id: Annotated[
            str, Field(description=_APPLICATION_ID_DESC, max_length=200)
        ] = DLM_APPLICATION_ID,
        context_id: Annotated[str, Field(description=_CONTEXT_ID_DESC, max_length=500)] = (
            DLM_CONTEXT_ID
        ),
    ) -> str:
        """Count a collection job's devices, input/output collections and errors.

        Read-only. ``POST /crosswork/collection/v1/collectionjob/count/query``
        with ``{"application_context": {"application_id", "context_id"},
        "query_options": {...}}``. A collection job is what a Crosswork
        application (the DLM inventory manager, the Optimization Engine,
        Health Insights, ...) registers with the collection service to have
        the Data Gateway poll devices; it is keyed by the application's
        ``application_context``. The defaults name the built-in DLM CLI
        collector job (``cw.dlminvmgr0`` / ``dlm/cli-collector/group/
        te-tunnel-id/subscription``, verified live: 1 job on 5 devices), so a
        bare call answers "is device collection running?". Every count is a
        string on the wire and is coerced to an int here. ``job_count`` 0 is
        a normal answer (no job under that context), not an error. Blank
        ``application_id`` AND ``context_id`` send no context, which the
        document says counts every job in the system (not verified live).
        Creating/deleting collection jobs is not exposed (a job needs a data
        destination and a sensor definition — left for a later module).

        Args:
            application_id: the owning application's id ('cw.'-prefixed).
            context_id: the application's subscription id.

        Returns:
            str: JSON {"application_id", "context_id" (null for all jobs),
            "job_count", "device_count", "input_collection_count",
            "output_collection_count", "input_error_collection_count",
            "output_error_collection_count", "control_error_count",
            "input_filtered_count", "output_filtered_count" (ints; null when
            the platform omitted one), "summary": "<one line>"}. "Error: ...
            was REJECTED: <reason>" when result.request_result is not
            ACCEPTED; "Error: application_id and context_id go together ..."
            when only one is blank; "Error: ..." on any other API failure.
        """
        try:
            context = application_context(application_id, context_id)
            counts = await read_counts(application_id, context_id)
            payload: dict[str, Any] = {
                "application_id": context["application_id"] if context else None,
                "context_id": context["context_id"] if context else None,
                **counts,
                "summary": count_summary_line(counts, scope_text(context)),
            }
            return finalize(to_json(payload), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_collection_job_summary",
        title="Get Collection Job Summary",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_collection_job_summary(
        application_id: Annotated[
            str, Field(description=_APPLICATION_ID_DESC, max_length=200)
        ] = DLM_APPLICATION_ID,
        context_id: Annotated[str, Field(description=_CONTEXT_ID_DESC, max_length=500)] = (
            DLM_CONTEXT_ID
        ),
        page_size: Annotated[
            int, Field(description=_PAGE_SIZE_DESC, ge=1, le=MAX_PAGE_SIZE)
        ] = DEFAULT_PAGE_SIZE,
        page_token: Annotated[str, Field(description=_PAGE_TOKEN_DESC, max_length=200)] = (
            FIRST_PAGE_TOKEN
        ),
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get a collection job's operational status: READY/NOTREADY/FAILED, its phase,
        progress, collector type and any job error.

        Read-only. ``POST /crosswork/collection/v1/collectionjob/summary/query``
        with the ``application_context`` and ``query_options``. Answers one
        ``collection_job_status_list`` entry per job under the context
        (verified live for the built-in DLM job: status READY, phase ACTIVE,
        progress 100, collector CLI_COLLECTOR, empty job_error). ``status``
        is READY | NOTREADY | FAILED; ``phase`` is ACTIVE | TERMINATING |
        TERMINATION_FAILED | DELETED — once a job is TERMINATING or
        TERMINATION_FAILED its status no longer matters and no create/update
        is possible on that context. ``job_error.error`` carries the reason
        for a FAILED / TERMINATION_FAILED job. Paging is by token: leave
        ``page_token`` blank for the first page and pass back the answer's
        ``next_page_token`` when ``has_more`` is true — a HEURISTIC (this
        page came back full and the platform echoed a token different from
        the one sent; the platform's token is an opaque hash even for one
        entry and no second page has been fetched live). ``has_more`` null
        means the page came back full but no new token was echoed (the
        verified answer carries no ``query_options`` at all) — more jobs MAY
        exist, so re-query with a larger ``page_size``; a full page is never
        reported as "no more". Blank ids send no context — every job in the
        system per the document (not verified live). An empty list is a
        normal "no collection job" result.

        Args:
            application_id / context_id: the job's application_context.
            page_size: entries per page.
            page_token: the previous answer's next_page_token; '' first page.
            response_format: markdown (one line per job: context, status,
                phase, progress, collector, created/deleted times, error,
                plus a "(more on server ...)" / "(page full ...)" note when
                has_more is true / null) or json.

        Returns:
            str: Markdown, or JSON {"application_id", "context_id", "count":
            int, "items": [{"application_context": {"application_id",
            "context_id"}, "creation_time" (epoch ms string), "deletion_time",
            "progress", "status", "phase", "collector_type", "job_error":
            {"error"}}], "page_size", "page_token" (as sent), "has_more":
            bool|null, "next_page_token": str|null, "paging_note": str|null
            (set when has_more is null), "query_options": <the platform's
            echo>}. "No collection job status is reported for ..." when the
            list is empty. "Error: ... was REJECTED: <reason>" when
            result.request_result is not ACCEPTED; "Error: application_id and
            context_id go together ..." when only one is blank (nothing is
            sent); "Error: ..." on any other API failure.
        """
        try:
            context = application_context(application_id, context_id)
            token = page_token.strip()
            statuses, data = await read_summary(application_id, context_id, page_size, token)
            paging = page_state(statuses, data, page_size, token)
            if response_format is ResponseFormat.JSON:
                payload = {
                    "application_id": context["application_id"] if context else None,
                    "context_id": context["context_id"] if context else None,
                    "count": len(statuses),
                    "items": statuses,
                    **paging,
                    "query_options": data.get("query_options"),
                }
                return finalize(to_json(payload), settings)
            scope = scope_text(context)
            if not statuses:
                return finalize(
                    f"No collection job status is reported for {scope} (the collection "
                    "service lists no job under that application_context).",
                    settings,
                )
            lines = [f"# Collection job status for {scope} ({len(statuses)})", ""]
            lines.extend(job_status_line(s) for s in statuses)
            lines.extend(more_note(paging, "cnc_get_collection_job_summary"))
            lines.extend(
                [
                    "",
                    "status READY|NOTREADY|FAILED, phase ACTIVE|TERMINATING|TERMINATION_FAILED|"
                    "DELETED; cnc_get_collection_job_state gives the lifecycle verdict, "
                    "cnc_get_collection_job_count the per-device collection counts.",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_collection_job_state",
        title="Get Collection Job State",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_collection_job_state(
        application_id: Annotated[
            str, Field(description=_APPLICATION_ID_DESC, max_length=200)
        ] = DLM_APPLICATION_ID,
        context_id: Annotated[str, Field(description=_CONTEXT_ID_DESC, max_length=500)] = (
            DLM_CONTEXT_ID
        ),
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Get a collection job's lifecycle state — the platform's overall verdict on the
        job, computed from its counters (SUCCESS, DEGRADED, NO_DATA, ...).

        Read-only. ``POST /crosswork/collection/v1/collectionjob/state/query``
        with the ``application_context`` and ``query_options``. Answers one
        ``collection_life_cycle_states`` entry per job under the context
        (verified live for the built-in DLM job: SUCCESS_LIFE_CYCLE_STATE).
        The documented states are SCHEDULED, CREATING, SUCCESS, DEGRADED,
        DELETING, DELETE_FAILED and NO_DATA (each suffixed
        ``_LIFE_CYCLE_STATE``); ``state_evaluation_time`` is when the platform
        last computed it. This is the counters-based verdict; the operational
        status/phase is cnc_get_collection_job_summary. Only the first page of
        50 is fetched (the platform echoes an opaque hash as page token even
        for a single entry, so no end-of-data signal is trusted); when that
        page comes back full, ``page_full`` is true and a note says more jobs
        may exist. Blank ids send no context (documented "every job", not
        verified live). An empty list is a normal "no collection job" result.

        Args:
            application_id / context_id: the job's application_context.
            response_format: markdown (one line per job: context, lifecycle
                state, created and evaluated times, plus a "(page full ...)"
                note when the 50-entry page is full) or json.

        Returns:
            str: Markdown, or JSON {"application_id", "context_id", "count":
            int, "items": [{"life_cycle_state", "application_context":
            {"application_id", "context_id"}, "creation_time" (epoch ms
            string), "state_evaluation_time"}], "page_size": 50, "page_full":
            bool, "query_options": <the platform's echo>}. "No collection job
            lifecycle state is reported for ..." when the list is empty.
            "Error: ... was REJECTED: <reason>" when result.request_result is
            not ACCEPTED; "Error: application_id and context_id go together
            ..." when only one is blank (nothing is sent); "Error: ..." on any
            other API failure.
        """
        try:
            context = application_context(application_id, context_id)
            states, data = await read_states(application_id, context_id, DEFAULT_PAGE_SIZE)
            page_full = len(states) >= DEFAULT_PAGE_SIZE
            if response_format is ResponseFormat.JSON:
                payload = {
                    "application_id": context["application_id"] if context else None,
                    "context_id": context["context_id"] if context else None,
                    "count": len(states),
                    "items": states,
                    "page_size": DEFAULT_PAGE_SIZE,
                    "page_full": page_full,
                    "query_options": data.get("query_options"),
                }
                return finalize(to_json(payload), settings)
            scope = scope_text(context)
            if not states:
                return finalize(
                    f"No collection job lifecycle state is reported for {scope} (the "
                    "collection service lists no job under that application_context).",
                    settings,
                )
            lines = [f"# Collection job lifecycle state for {scope} ({len(states)})", ""]
            lines.extend(life_cycle_line(s) for s in states)
            if page_full:
                lines.extend(
                    [
                        "",
                        f"(page full at {DEFAULT_PAGE_SIZE} entries — this tool fetches only "
                        "the first page, so more jobs may exist; query a narrower "
                        "application_context.)",
                    ]
                )
            lines.extend(
                [
                    "",
                    "States: SCHEDULED, CREATING, SUCCESS, DEGRADED, DELETING, DELETE_FAILED, "
                    "NO_DATA (suffixed _LIFE_CYCLE_STATE); cnc_get_collection_job_summary "
                    "shows the operational status and phase.",
                ]
            )
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_export_collection_jobs",
        title="List Export Collection Jobs",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_export_collection_jobs(
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List the collection service's export (and other underlying) jobs — the
        one-shot jobs that export collected data, with their status and progress.

        Read-only. ``POST /crosswork/collection/v1/jobs/query`` with
        ``{"query_options": {"page_token": "0", "page_size": 100,
        "filter_list": [], "filter_query": ""}}`` — the generic job list of
        the collection service (job ``type`` EXPORT_COLLECTIONS |
        COLLECTION_JOB | TEMPLATE_COLLECTION_JOB, ``status`` JOB_CREATED |
        JOB_IN_PROGRESS | JOB_COMPLETED | JOB_FAILED, ``progress`` 0-100,
        ``user``, ``created`` / ``completed`` epoch ms). The lab answers
        ``jobs: []`` (verified live) — a normal "No export collection jobs."
        result, not an error — so the item rendering follows the 7.2
        document. The recurring application collection jobs are NOT listed
        here; they are keyed by application_context
        (cnc_get_collection_job_summary). No paging is exposed: the 7.2
        document says of this request "currently the query options are not
        utilized", and the lab echoed the ``"0"`` token it was sent, so the
        answer is whatever the platform lists (the platform's own page size
        100 and first-page token are sent as the verified body). The
        document's only selector, ``ids[]`` (export application_contexts),
        is not exposed — unverified live. Creating or deleting export jobs
        is not exposed.

        Args:
            response_format: markdown (one line per job: context, type,
                status, progress, user, created/completed, description) or
                json.

        Returns:
            str: Markdown, or JSON {"count": int, "items": [{"id":
            {"export_id": {"application_context": {"application_id",
            "context_id"}}}, "user", "created", "completed", "progress",
            "status", "type", "description"}], "query_options": <the
            platform's echo>}. "No export collection jobs." when the list is
            empty. "Error: ... was REJECTED: <reason>" when
            result.request_result is not ACCEPTED; "Error: ..." on any other
            API failure.
        """
        try:
            data = await query(JOBS_QUERY_URL, list_query_body(), "Collection jobs query")
            jobs = dict_list(data.get("jobs"))
            if response_format is ResponseFormat.JSON:
                payload = {
                    "count": len(jobs),
                    "items": jobs,
                    "query_options": data.get("query_options"),
                }
                return finalize(to_json(payload), settings)
            if not jobs:
                return finalize(
                    "No export collection jobs. The collection service lists no export/one-shot "
                    "job; the recurring application jobs are read with "
                    "cnc_get_collection_job_summary.",
                    settings,
                )
            lines = [f"# Collection service jobs ({len(jobs)})", ""]
            lines.extend(export_job_line(j) for j in jobs)
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_sensor_templates",
        title="List Sensor Templates",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_sensor_templates(
        template_id: Annotated[
            str, Field(description=_TEMPLATE_ID_DESC, min_length=1, max_length=200)
        ],
        page_size: Annotated[
            int, Field(description=_PAGE_SIZE_DESC, ge=1, le=MAX_PAGE_SIZE)
        ] = DEFAULT_PAGE_SIZE,
        page_token: Annotated[str, Field(description=_PAGE_TOKEN_DESC, max_length=200)] = (
            FIRST_PAGE_TOKEN
        ),
        response_format: Annotated[
            ResponseFormat, Field(description=_RESPONSE_FORMAT_DESC)
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """Look up sensor templates by id — reusable, parameterised CLI commands,
        device-package functions or gNMI paths that template collection jobs collect at
        a cadence.

        Read-only. ``POST /crosswork/collection/v1/template`` (a query despite
        the path — PUT creates, DELETE removes; neither is exposed) with
        ``{"template_id": "<id or pattern>", "query_options": {"page_token":
        "0", "page_size": N, "filter_list": [], "filter_query": ""}}``. The
        ``template_id`` is REQUIRED by the platform — the 7.2 document:
        "The template_id is required; if not specified, nothing is returned.
        If you use a wildcard pattern, any template_id that contains the
        pattern is a match" (the wildcard syntax is not verified live); a
        blank id is refused here without a call. Each template carries
        ``sensor_template_id``, ``collection_type`` (CLI_COLLECTOR,
        GNMI_COLLECTOR, ...), ``cadence_in_millisec`` (a string) and its
        ``sensor_template_Definition`` — a ``cli_sensor_template``
        (``template_command.templatecommand`` such as ``show interface
        {{interface_name}}`` with ``template_variables``, or a
        ``template_device_package``) or a ``gnmi_sensor_template``
        (``gnmi_path``). Verified live (a lab without templates): a body
        without template_id answers ACCEPTED with an empty list (the
        documented "nothing is returned" case); ANY template_id — the
        wildcard ``*`` included — answers HTTP 200 with request_result
        REJECTED and error "Template for the given TemplateId does not
        exist". That rejection is the platform's "no match", so this tool
        reports it as an empty result rather than an error; the item
        rendering follows the 7.2 document (no populated answer seen live
        yet). An empty list is a normal "no match" result. Paging is
        by token: a blank ``page_token`` sends the first-page token ``"0"``;
        pass back the answer's ``next_page_token`` when ``has_more`` is true
        (a HEURISTIC: full page plus a token different from the one sent);
        ``has_more`` null means a full page with no new token — more may
        exist, re-query with a larger ``page_size``.

        Args:
            template_id: the sensor_template_id (or documented wildcard
                pattern) to look up.
            page_size: entries per page.
            page_token: the previous answer's next_page_token; '' first page.
            response_format: markdown (one line per template: id, collector
                type, cadence, the command / package / gNMI path and its
                variables, plus a "(more on server ...)" / "(page full ...)"
                note when has_more is true / null) or json.

        Returns:
            str: Markdown, or JSON {"template_id" (as sent), "count": int,
            "items": [{"sensor_template_id", "collection_type",
            "sensor_template_Definition": {"cli_sensor_template":
            {"template_command": {"templatecommand", "template_variables"},
            "template_device_package": {"device_package_name",
            "function_name", "template_params"}}, "gnmi_sensor_template":
            {"gnmi_path", "template_variables"}}, "cadence_in_millisec"}],
            "page_size", "page_token" (as sent, "0" for the first page),
            "has_more": bool|null, "next_page_token": str|null,
            "paging_note": str|null, "query_options": <the platform's
            echo>}. "No sensor template matches '<template_id>'." when the
            list is empty. "Error: cnc_list_sensor_templates needs a
            template_id ..." for a blank id (nothing is sent); "Error: ...
            was REJECTED: <reason>" when result.request_result is not
            ACCEPTED; "Error: ..." on any other API failure.
        """
        try:
            token = page_token.strip() or JOBS_FIRST_PAGE_TOKEN
            body = template_query_body(template_id, page_size, token)
            data = await client.request_json(
                "POST", TEMPLATE_QUERY_URL, json_body=body, retryable=True
            )
            if not isinstance(data, dict):
                raise PlatformError(
                    "Sensor template query: the collection service returned an unexpected "
                    f"response shape: {str(data)[:300]}"
                )
            if not template_lookup_missed(data):
                check_collection_result(data, "Sensor template query")
            templates = dict_list(data.get("sensor_templates"))
            paging = page_state(templates, data, page_size, token)
            if response_format is ResponseFormat.JSON:
                payload = {
                    "template_id": body["template_id"],
                    "count": len(templates),
                    "items": templates,
                    **paging,
                    "query_options": data.get("query_options"),
                }
                return finalize(to_json(payload), settings)
            if not templates:
                return finalize(
                    f"No sensor template matches '{body['template_id']}'. Verified live: an "
                    "unmatched template_id (the wildcard '*' included, when no template exists "
                    "at all) answers REJECTED 'Template for the given TemplateId does not "
                    "exist' with an empty list — reported here as no match, not as an error. "
                    "Templates are created by applications (or PUT "
                    "/crosswork/collection/v1/template, not exposed here) for template "
                    "collection jobs; the built-in DLM collection needs none.",
                    settings,
                )
            lines = [f"# Sensor templates matching '{body['template_id']}' ({len(templates)})", ""]
            lines.extend(sensor_template_line(t) for t in templates)
            lines.extend(more_note(paging, "cnc_list_sensor_templates"))
            return finalize("\n".join(lines), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_collection_health",
        title="Get Collection Health",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_collection_health(
        application_id: Annotated[
            str,
            Field(
                description=(
                    "application_id of the collection job's application_context (default "
                    f"'{DLM_APPLICATION_ID}', the built-in DLM CLI collector job)."
                ),
                min_length=1,
                max_length=200,
            ),
        ] = DLM_APPLICATION_ID,
        context_id: Annotated[
            str,
            Field(
                description=(
                    "context_id of the application_context (default "
                    f"'{DLM_CONTEXT_ID}', the built-in DLM job)."
                ),
                min_length=1,
                max_length=500,
            ),
        ] = DLM_CONTEXT_ID,
    ) -> str:
        """One-call health check of a collection job: counts + status/phase + lifecycle
        state, with a one-line verdict.

        Read-only. Sends the three ``collectionjob/{count,summary,state}/query``
        POSTs for one ``application_context`` (in parallel) and combines them:
        ``job_count`` / ``device_count`` and the error counts from the count
        query, ``status`` / ``phase`` / ``progress`` / ``collector_type`` /
        ``job_error`` from the summary, ``life_cycle_state`` from the state
        query. Use it to answer "is device collection healthy?" before the
        individual tools; the defaults name the built-in DLM CLI collector
        job (verified live: READY/ACTIVE on 5 devices, lifecycle SUCCESS). A
        context is required here — blank ids are refused (the per-tool
        "every job" query makes no single verdict). ``healthy`` is true only
        for READY + ACTIVE + SUCCESS_LIFE_CYCLE_STATE with no job error and
        zero input/output/control error counts; anything else ends the
        verdict with "NOT healthy" and names what is off. "No collection job
        is registered" (job_count 0 and no status entry) is a non-error
        verdict. When several jobs sit under one context, the first status /
        state entry drives the verdict and all are kept in ``jobs`` /
        ``life_cycles``.

        Args:
            application_id / context_id: the job's application_context.

        Returns:
            str: JSON {"application_id", "context_id", "job_count",
            "device_count", "input_collection_count",
            "output_collection_count" (ints), "status", "phase", "progress",
            "collector_type", "life_cycle_state", "state_evaluation_time",
            "errors": {"job_errors": [str], "input_error_collection_count",
            "output_error_collection_count", "control_error_count"},
            "healthy": bool, "jobs": [<summary entries>], "life_cycles":
            [<state entries>], "verdict": "Collection job READY/ACTIVE on 5
            devices, lifecycle SUCCESS."}. "Error: ... was REJECTED: <reason>"
            when any of the three answers is not ACCEPTED; "Error: ..." on
            any other API failure.
        """
        try:
            context = application_context(application_id, context_id)
            if context is None:
                raise PlatformError(
                    "cnc_get_collection_health needs a collection job's application_context: "
                    f"give application_id and context_id (defaults: '{DLM_APPLICATION_ID}' / "
                    f"'{DLM_CONTEXT_ID}', the built-in DLM job)."
                )
            counts, (statuses, _), (states, _) = await asyncio.gather(
                read_counts(application_id, context_id),
                read_summary(application_id, context_id, DEFAULT_PAGE_SIZE),
                read_states(application_id, context_id, DEFAULT_PAGE_SIZE),
            )
            return finalize(to_json(health_payload(context, counts, statuses, states)), settings)
        except Exception as e:
            return format_error(e)
