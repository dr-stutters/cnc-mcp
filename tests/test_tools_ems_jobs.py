"""Tests for the EMS inventory job scheduler tools (tools/ems_jobs.py).

Fixtures mirror the answers verified live on Crosswork 7.2 (2026-09-13): the
five built-in inventory jobs, the 400 without a Range header, the bare
``true`` / ``false`` write verdicts and the state transitions they cause.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from mcp.server.mcpserver import MCPServer

from cnc_mcp.auth import StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.config import Settings
from cnc_mcp.errors import PlatformError
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import ems_jobs
from cnc_mcp.tools.ems_jobs import (
    LIST_URL,
    RESUME_URL,
    RUN_URL,
    SUSPEND_URL,
    find_job,
    job_key,
    jobs_of,
    verdict_of,
)
from tests.conftest import BASE_URL, call_tool_text

LIST = f"{BASE_URL}{LIST_URL}"
RUN = f"{BASE_URL}{RUN_URL}"
SUSPEND = f"{BASE_URL}{SUSPEND_URL}"
RESUME = f"{BASE_URL}{RESUME_URL}"

READ_TOOLS = {
    "cnc_list_inventory_scheduler_jobs",
    "cnc_get_inventory_scheduler_job",
    "cnc_wait_for_inventory_scheduler_job",
}
WRITE_TOOLS = {
    "cnc_run_inventory_scheduler_job",
    "cnc_suspend_inventory_scheduler_job",
    "cnc_resume_inventory_scheduler_job",
}


def job(name: str, state: str = "Scheduled", result: str = "Success", **extra) -> dict:
    row = {
        "id": "435437",
        "jobType": "Inventory",
        "jobName": name,
        "description": None,
        "nextRunTime": None if state == "Suspended" else "September 13, 2026 at 8:10:00 PM UTC",
        "workState": state,
        "duration": "00:00:05",
        "startTime": "September 13, 2026 at 7:10:02 PM UTC",
        "owner": "SYSTEM",
        "creationTime": None,
        "recurrence": None,
        "priority": None,
        "authEntityId": "-11111",
        "lastRunResultState": result,
        "lastRunJobId": "449550",
        "jobInterval": "1 hour(s)",
    }
    row.update(extra)
    return row


def listing(*rows: dict) -> dict:
    return {"identifier": "id", "totalCount": len(rows), "pageNo": 0, "items": list(rows)}


FIVE = listing(
    job("internalSchedule", id="435435", jobInterval="04 hour(s)"),
    job("Switch Inventory", id="435436", jobInterval="1 day(s)", duration="00:00:34"),
    job("Failed Feature Sync"),
    job("thirdPartyDeviceSync", id="435438"),
    job("reBuildAssociation", id="435439"),
)
# Verified live: the list without the Range header.
NO_RANGE_400 = {
    "timestamp": 1789327615817,
    "status": 400,
    "error": "Bad Request",
    "path": "/jobSchedulerService/getSystemLazyJobsSpecification",
}


def payload_of(text: str) -> dict:
    """The JSON block a write / wait answer appends after its summary line."""
    return json.loads(text[text.rindex("\n\n{") + 2 :])


def build(settings: Settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    ems_jobs.register(mcp, ctx)
    return mcp


def mock_list(*bodies: dict, status: int = 200):
    responses = [
        httpx.Response(
            status, json=body, headers={"Content-Range": f"items=0-199/{len(body['items'])}"}
        )
        for body in bodies
    ]
    return respx.get(LIST).mock(
        side_effect=responses if len(responses) > 1 else None,
        return_value=responses[0] if len(responses) == 1 else None,
    )


# --- registration -----------------------------------------------------------------


async def test_reads_visible_without_writes_and_writes_gated(make_settings):
    names = {t.name for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert names == READ_TOOLS
    tools = {t.name: t for t in await build(make_settings(enable_writes=True)).list_tools()}
    assert set(tools) == READ_TOOLS | WRITE_TOOLS
    for name in WRITE_TOOLS:
        assert tools[name].annotations.read_only_hint is False, name
        assert tools[name].annotations.destructive_hint is False, name
    assert tools["cnc_run_inventory_scheduler_job"].annotations.idempotent_hint is False
    assert tools["cnc_suspend_inventory_scheduler_job"].annotations.idempotent_hint is True
    assert tools["cnc_resume_inventory_scheduler_job"].annotations.idempotent_hint is True
    for name in READ_TOOLS:
        assert tools[name].annotations.read_only_hint is True, name
        assert tools[name].annotations.idempotent_hint is True, name


# --- pure helpers -----------------------------------------------------------------


def test_job_key_defaults_the_type_and_refuses_odd_characters():
    assert job_key("Failed Feature Sync", "Inventory") == "Failed Feature Sync:Inventory"
    assert job_key(" Switch Inventory ", "") == "Switch Inventory:Inventory"
    with pytest.raises(PlatformError, match="job_name is empty"):
        job_key("   ", "Inventory")
    with pytest.raises(PlatformError, match="characters outside"):
        job_key("a:b", "Inventory")
    with pytest.raises(PlatformError, match="job_type 'x/y'"):
        job_key("ok", "x/y")


def test_jobs_of_total_and_find_job():
    rows = jobs_of(FIVE)
    assert [r["jobName"] for r in rows] == list(ems_jobs.BUILT_IN_JOBS)
    assert ems_jobs.total_of(FIVE) == 5
    assert ems_jobs.total_of({"totalCount": "5"}) is None
    assert ems_jobs.total_of({"totalCount": True}) is None
    assert ems_jobs.total_of([1]) is None
    with pytest.raises(PlatformError, match="empty body"):
        jobs_of(None)
    assert jobs_of({"identifier": "id", "totalCount": 0, "items": []}) == []
    assert jobs_of({"items": [1, None, "x", {"jobName": "x"}]}) == [{"jobName": "x"}]
    with pytest.raises(PlatformError, match="unexpected document"):
        jobs_of({"items": "nope"})
    with pytest.raises(PlatformError, match="unexpected document"):
        jobs_of([1, 2])
    assert find_job(rows, "Failed Feature Sync", "Inventory")["id"] == "435437"
    assert find_job(rows, "failed feature sync", "Inventory") is None  # case-sensitive
    assert find_job(rows, "Failed Feature Sync", "Other") is None
    assert find_job(rows, " Failed Feature Sync ", "") is not None


def test_verdict_of_accepts_only_true_or_false():
    assert verdict_of("true") is True
    assert verdict_of(" False\n") is False
    with pytest.raises(PlatformError, match="neither 'true' nor 'false'"):
        verdict_of('{"status": "ok"}')


# --- cnc_list_inventory_scheduler_jobs --------------------------------------------


@respx.mock
async def test_list_jobs_sends_the_range_header_and_renders(settings):
    route = mock_list(FIVE)
    text = await call_tool_text(build(settings), "cnc_list_inventory_scheduler_jobs", {})
    assert route.call_count == 1
    request = route.calls.last.request
    assert request.headers["Range"] == "items=0-199"
    assert request.headers["Accept"] == "application/json"
    assert text.startswith("# Inventory scheduler jobs (5)")
    assert (
        "- **Switch Inventory** (Inventory, id 435436): Scheduled; every 1 day(s); next run "
        "September 13, 2026 at 8:10:00 PM UTC; last run Success (job 449550, 00:00:34)"
    ) in text
    assert "cnc_run_inventory_scheduler_job" in text
    text = await call_tool_text(
        build(settings), "cnc_list_inventory_scheduler_jobs", {"response_format": "json"}
    )
    payload = json.loads(text)
    assert payload["total"] == 5 and payload["count"] == 5
    assert payload["items"][2]["jobName"] == "Failed Feature Sync"


@respx.mock
async def test_list_jobs_accepts_206_and_shows_a_partial_count(settings):
    partial = {"identifier": "id", "totalCount": 5, "pageNo": 0, "items": [job("internalSchedule")]}
    respx.get(LIST).mock(
        return_value=httpx.Response(206, json=partial, headers={"Content-Range": "items=0-0/5"})
    )
    text = await call_tool_text(build(settings), "cnc_list_inventory_scheduler_jobs", {})
    assert text.startswith("# Inventory scheduler jobs (1 of 5)")


@respx.mock
async def test_list_jobs_empty_and_suspended_rendering(settings):
    mock_list({"identifier": "id", "totalCount": 0, "pageNo": 0, "items": []})
    text = await call_tool_text(build(settings), "cnc_list_inventory_scheduler_jobs", {})
    assert text.startswith("No scheduler jobs are listed")
    text = await call_tool_text(
        build(settings), "cnc_list_inventory_scheduler_jobs", {"response_format": "json"}
    )
    assert json.loads(text) == {"total": 0, "count": 0, "items": []}
    respx.get(LIST).mock(
        return_value=httpx.Response(200, json=listing(job("Failed Feature Sync", "Suspended")))
    )
    text = await call_tool_text(build(settings), "cnc_list_inventory_scheduler_jobs", {})
    assert "Suspended; every 1 hour(s); next run none while suspended" in text


@respx.mock
async def test_list_and_get_render_a_row_with_missing_fields(settings):
    respx.get(LIST).mock(
        return_value=httpx.Response(200, json=listing({}, {"jobName": "bare", "workState": None}))
    )
    text = await call_tool_text(build(settings), "cnc_list_inventory_scheduler_jobs", {})
    assert text.startswith("# Inventory scheduler jobs (2)")
    assert "- **?** (?, id ?): ?; every -; next run -; last run - (job -, -)" in text
    assert "- **bare** (?, id ?): ?; every -; next run -; last run - (job -, -)" in text
    text = await call_tool_text(
        build(settings), "cnc_get_inventory_scheduler_job", {"job_name": "bare"}
    )
    assert text.startswith("# Scheduler job bare (?)")
    assert "- state: -" in text and "- last run job id: -" in text


@respx.mock
async def test_list_jobs_errors(settings):
    respx.get(LIST).mock(return_value=httpx.Response(400, json=NO_RANGE_400))
    text = await call_tool_text(build(settings), "cnc_list_inventory_scheduler_jobs", {})
    assert text.startswith("Error:") and "400" in text
    respx.get(LIST).mock(return_value=httpx.Response(200, json={"items": "nope"}))
    text = await call_tool_text(build(settings), "cnc_list_inventory_scheduler_jobs", {})
    assert text.startswith("Error: The job scheduler answered an unexpected document")
    respx.get(LIST).mock(return_value=httpx.Response(200, content=b""))
    text = await call_tool_text(build(settings), "cnc_list_inventory_scheduler_jobs", {})
    assert text.startswith("Error: The job scheduler answered an empty body")


# --- cnc_get_inventory_scheduler_job ----------------------------------------------


@respx.mock
async def test_get_job_selects_the_row_and_reports_not_found(settings):
    mock_list(FIVE)
    text = await call_tool_text(
        build(settings), "cnc_get_inventory_scheduler_job", {"job_name": "Switch Inventory"}
    )
    assert text.startswith("# Scheduler job Switch Inventory (Inventory)")
    assert "- state: Scheduled" in text and "- interval: 1 day(s)" in text
    assert "- description: -" in text
    text = await call_tool_text(
        build(settings),
        "cnc_get_inventory_scheduler_job",
        {"job_name": "Switch Inventory", "response_format": "json"},
    )
    assert json.loads(text)["id"] == "435436"
    text = await call_tool_text(
        build(settings), "cnc_get_inventory_scheduler_job", {"job_name": "switch inventory"}
    )
    assert text.startswith("Error: no scheduler job 'switch inventory:Inventory'")
    assert "case-sensitive" in text


@respx.mock
async def test_get_job_refuses_a_bad_key_before_any_call(settings):
    route = mock_list(FIVE)
    text = await call_tool_text(
        build(settings), "cnc_get_inventory_scheduler_job", {"job_name": "a:b"}
    )
    assert text.startswith("Error: job_name 'a:b' carries characters outside")
    assert route.call_count == 0
    # '   ' passes Field(min_length=1); job_key refuses it before any request.
    text = await call_tool_text(
        build(settings), "cnc_get_inventory_scheduler_job", {"job_name": "   "}
    )
    assert text.startswith("Error: job_name is empty")
    assert "Nothing was sent." in text
    assert route.call_count == 0


# --- writes ------------------------------------------------------------------------


@pytest.fixture
def writes(make_settings) -> MCPServer:
    return build(make_settings(enable_writes=True))


@respx.mock
async def test_run_job_sends_the_raw_key_and_reads_the_state_back(writes):
    run = respx.post(RUN).mock(return_value=httpx.Response(200, text="true"))
    respx.get(LIST).mock(
        return_value=httpx.Response(
            200, json=listing(job("Failed Feature Sync", "In-Progress", "Running"))
        )
    )
    text = await call_tool_text(
        writes, "cnc_run_inventory_scheduler_job", {"job_name": "Failed Feature Sync"}
    )
    assert run.call_count == 1
    request = run.calls.last.request
    assert request.content == b"Failed Feature Sync:Inventory"
    assert request.headers["Content-Type"] == "application/json"
    assert text.startswith(
        "Started scheduler job 'Failed Feature Sync:Inventory': the scheduler answered true; "
        "now In-Progress."
    )
    payload = json.loads(text[text.index("{") :])
    assert payload == {
        "job": "Failed Feature Sync:Inventory",
        "verdict": True,
        "state": listing(job("Failed Feature Sync", "In-Progress", "Running"))["items"][0],
        "state_error": None,
    }


@respx.mock
async def test_run_job_read_back_still_scheduled_is_reported_as_lag(writes):
    respx.post(RUN).mock(return_value=httpx.Response(200, text="true"))
    respx.get(LIST).mock(return_value=httpx.Response(200, json=listing(job("Switch Inventory"))))
    text = await call_tool_text(
        writes, "cnc_run_inventory_scheduler_job", {"job_name": "Switch Inventory"}
    )
    assert not text.startswith("Error:")
    assert "now Scheduled (expected In-Progress — the scheduler picks the run up" in text
    assert "cnc_wait_for_inventory_scheduler_job" in text
    payload = payload_of(text)
    assert payload["state"]["lastRunJobId"] == "449550" and payload["state_error"] is None


@respx.mock
async def test_suspend_and_resume_report_the_new_state(writes):
    suspend = respx.post(SUSPEND).mock(return_value=httpx.Response(200, text="true"))
    resume = respx.post(RESUME).mock(return_value=httpx.Response(200, text="true"))
    respx.get(LIST).mock(
        side_effect=[
            httpx.Response(200, json=listing(job("Failed Feature Sync", "Suspended"))),
            httpx.Response(200, json=listing(job("Failed Feature Sync", "Scheduled"))),
        ]
    )
    text = await call_tool_text(
        writes, "cnc_suspend_inventory_scheduler_job", {"job_name": "Failed Feature Sync"}
    )
    assert suspend.calls.last.request.content == b"Failed Feature Sync:Inventory"
    assert text.startswith("Suspended scheduler job 'Failed Feature Sync:Inventory'")
    assert "now Suspended." in text
    text = await call_tool_text(
        writes, "cnc_resume_inventory_scheduler_job", {"job_name": "Failed Feature Sync"}
    )
    assert resume.calls.last.request.content == b"Failed Feature Sync:Inventory"
    assert "now Scheduled." in text


@respx.mock
async def test_write_false_is_not_found_and_no_retry_on_5xx(make_settings):
    writes = build(make_settings(enable_writes=True, max_retries=2))
    suspend = respx.post(SUSPEND).mock(return_value=httpx.Response(200, text="false"))
    listing_route = respx.get(LIST).mock(return_value=httpx.Response(200, json=FIVE))
    text = await call_tool_text(writes, "cnc_suspend_inventory_scheduler_job", {"job_name": "nope"})
    assert text.startswith(
        "Error: The job scheduler answered false to suspend 'nope:Inventory': no such job"
    )
    assert "case-sensitive" in text
    assert listing_route.call_count == 1  # the read-back that proved the row is missing
    run = respx.post(RUN).mock(return_value=httpx.Response(503, text="busy"))
    text = await call_tool_text(writes, "cnc_run_inventory_scheduler_job", {"job_name": "nope"})
    assert text.startswith("Error:") and "503" in text
    assert run.call_count == 1  # a run is never re-sent
    assert suspend.call_count == 1
    assert listing_route.call_count == 1  # no read-back after a failed write


@respx.mock
async def test_write_false_for_a_listed_job_is_a_refusal_not_not_found(writes):
    # A `false` for an existing job was never seen live; the tool must not claim
    # the (correct) name is wrong.
    resume = respx.post(RESUME).mock(return_value=httpx.Response(200, text="false"))
    listing_route = respx.get(LIST).mock(return_value=httpx.Response(200, json=FIVE))
    text = await call_tool_text(
        writes, "cnc_resume_inventory_scheduler_job", {"job_name": "Failed Feature Sync"}
    )
    assert text.startswith(
        "Error: The job scheduler answered false to resume 'Failed Feature Sync:Inventory' "
        "but the job exists (workState Scheduled) — the scheduler refused the resume"
    )
    assert "not exercised live" in text and "no such job" not in text
    assert resume.call_count == 1 and listing_route.call_count == 1
    # The read-back itself failing: still an error, and it says which it could not tell.
    respx.get(LIST).mock(return_value=httpx.Response(500, text="boom"))
    text = await call_tool_text(
        writes, "cnc_resume_inventory_scheduler_job", {"job_name": "Failed Feature Sync"}
    )
    assert text.startswith(
        "Error: The job scheduler answered false to resume 'Failed Feature Sync:Inventory' "
        "(no such job, or the resume was refused) and the job list could not be read back"
    )
    assert "500" in text


@respx.mock
async def test_write_with_unexpected_body_and_state_unreadable(writes):
    respx.post(RESUME).mock(return_value=httpx.Response(200, json={"status": "ok"}))
    text = await call_tool_text(
        writes, "cnc_resume_inventory_scheduler_job", {"job_name": "Failed Feature Sync"}
    )
    assert text.startswith("Error: The job scheduler answered neither 'true' nor 'false'")
    respx.post(RESUME).mock(return_value=httpx.Response(200, text="true"))
    respx.get(LIST).mock(return_value=httpx.Response(200, json=listing(job("other"))))
    text = await call_tool_text(
        writes, "cnc_resume_inventory_scheduler_job", {"job_name": "Failed Feature Sync"}
    )
    assert not text.startswith("Error:")
    assert "state not readable afterwards (the job is missing from the list)" in text
    payload = payload_of(text)
    assert payload["state"] is None and payload["state_error"] is None


@respx.mock
async def test_write_applied_but_read_back_fails_is_not_an_error(writes):
    suspend = respx.post(SUSPEND).mock(return_value=httpx.Response(200, text="true"))
    listing_route = respx.get(LIST).mock(return_value=httpx.Response(500, text="boom"))
    text = await call_tool_text(
        writes, "cnc_suspend_inventory_scheduler_job", {"job_name": "Failed Feature Sync"}
    )
    assert suspend.call_count == 1 and listing_route.call_count >= 1
    assert not text.startswith("Error:")
    assert text.startswith(
        "Suspended scheduler job 'Failed Feature Sync:Inventory': the scheduler answered true; "
        "state not readable afterwards (Error:"
    )
    payload = payload_of(text)
    assert payload["job"] == "Failed Feature Sync:Inventory" and payload["verdict"] is True
    assert payload["state"] is None
    assert isinstance(payload["state_error"], str) and payload["state_error"].startswith("Error:")
    assert "500" in payload["state_error"]


@respx.mock
async def test_writes_refuse_a_bad_key_before_any_call(writes):
    run = respx.post(RUN).mock(return_value=httpx.Response(200, text="true"))
    text = await call_tool_text(writes, "cnc_run_inventory_scheduler_job", {"job_name": "a;b"})
    assert text.startswith("Error: job_name 'a;b' carries characters outside")
    assert run.call_count == 0


# --- cnc_wait_for_inventory_scheduler_job -----------------------------------------


@respx.mock
async def test_wait_finishes_when_no_longer_in_progress(settings):
    respx.get(LIST).mock(
        side_effect=[
            httpx.Response(200, json=listing(job("Failed Feature Sync", "In-Progress", "Running"))),
            httpx.Response(200, json=listing(job("Failed Feature Sync", "Scheduled", "Success"))),
        ]
    )
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_inventory_scheduler_job",
        {"job_name": "Failed Feature Sync", "timeout_seconds": 30, "interval_seconds": 1},
    )
    assert text.startswith("Scheduler job 'Failed Feature Sync:Inventory' finished after ")
    assert "Scheduled, last run Success (job 449550, 00:00:05)." in text
    assert json.loads(text[text.index("{") :])["workState"] == "Scheduled"


@respx.mock
async def test_wait_timeout_is_not_an_error_and_missing_job_is(settings):
    respx.get(LIST).mock(
        return_value=httpx.Response(
            200, json=listing(job("Failed Feature Sync", "In-Progress", "Running"))
        )
    )
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_inventory_scheduler_job",
        {"job_name": "Failed Feature Sync", "timeout_seconds": 5, "interval_seconds": 5},
    )
    assert text.startswith("Scheduler job 'Failed Feature Sync:Inventory' not finished yet after")
    assert "current state: In-Progress" in text
    respx.get(LIST).mock(return_value=httpx.Response(200, json=FIVE))
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_inventory_scheduler_job",
        {"job_name": "gone", "timeout_seconds": 5},
    )
    assert text.startswith("Error: no scheduler job 'gone:Inventory'")
    respx.get(LIST).mock(return_value=httpx.Response(500, text="boom"))
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_inventory_scheduler_job",
        {"job_name": "Failed Feature Sync", "timeout_seconds": 5},
    )
    assert text.startswith("Error:") and "500" in text


@respx.mock
async def test_wait_refuses_a_bad_key_before_any_call(settings):
    route = mock_list(FIVE)
    text = await call_tool_text(
        build(settings), "cnc_wait_for_inventory_scheduler_job", {"job_name": "a:b"}
    )
    assert text.startswith("Error: job_name 'a:b' carries characters outside")
    assert route.call_count == 0


@respx.mock
async def test_wait_with_previous_run_job_id_outlasts_the_start_race(settings):
    # Scheduled with the old id (the run not picked up yet) -> In-Progress -> Scheduled, new id.
    route = respx.get(LIST).mock(
        side_effect=[
            httpx.Response(200, json=listing(job("Failed Feature Sync", "Scheduled", "Success"))),
            httpx.Response(200, json=listing(job("Failed Feature Sync", "In-Progress", "Running"))),
            httpx.Response(
                200,
                json=listing(
                    job("Failed Feature Sync", "Scheduled", "Success", lastRunJobId="449560")
                ),
            ),
        ]
    )
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_inventory_scheduler_job",
        {
            "job_name": "Failed Feature Sync",
            "timeout_seconds": 30,
            "interval_seconds": 1,
            "previous_run_job_id": "449550",
        },
    )
    assert route.call_count == 3
    assert text.startswith("Scheduler job 'Failed Feature Sync:Inventory' finished after ")
    assert "Scheduled, last run Success (job 449560, 00:00:05)." in text
    assert "was not In-Progress" not in text
    assert payload_of(text)["lastRunJobId"] == "449560"


@respx.mock
async def test_wait_with_previous_run_job_id_finishes_on_a_new_id_alone(settings):
    # A short run that finished between polls: never seen In-Progress, but the id moved on.
    respx.get(LIST).mock(
        return_value=httpx.Response(
            200, json=listing(job("Failed Feature Sync", lastRunJobId="449561"))
        )
    )
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_inventory_scheduler_job",
        {"job_name": "Failed Feature Sync", "timeout_seconds": 5, "previous_run_job_id": "449550"},
    )
    assert text.startswith("Scheduler job 'Failed Feature Sync:Inventory' finished after ")
    assert "(job 449561, 00:00:05)." in text


@respx.mock
async def test_wait_with_previous_run_job_id_reports_a_run_not_started(settings):
    route = respx.get(LIST).mock(
        return_value=httpx.Response(200, json=listing(job("Failed Feature Sync")))
    )
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_inventory_scheduler_job",
        {
            "job_name": "Failed Feature Sync",
            "timeout_seconds": 5,
            "interval_seconds": 5,
            "previous_run_job_id": "449550",
        },
    )
    assert route.call_count == 1
    assert not text.startswith("Error:")
    assert text.startswith("Scheduler job 'Failed Feature Sync:Inventory' not finished yet after ")
    assert (
        "the scheduler has not started the run yet (lastRunJobId still 449550, state Scheduled"
        in text
    )
    assert "Call again to keep waiting." in text
    assert payload_of(text)["workState"] == "Scheduled"


@respx.mock
async def test_wait_without_previous_run_job_id_reports_the_start_race(settings):
    route = respx.get(LIST).mock(
        return_value=httpx.Response(200, json=listing(job("Failed Feature Sync")))
    )
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_inventory_scheduler_job",
        {"job_name": "Failed Feature Sync", "timeout_seconds": 5},
    )
    assert route.call_count == 1
    assert text.startswith(
        "Scheduler job 'Failed Feature Sync:Inventory' was not In-Progress when polled ("
    )
    assert "compare lastRunJobId / startTime" in text
