"""Platform tools (tags, users, applications, alarms, inventory jobs) end-to-end
through MCPServer (schema validation included). All HTTP mocked with respx."""

from __future__ import annotations

import json

import httpx
import respx
from mcp.server.mcpserver import MCPServer

from cnc_mcp.auth import StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import platform
from tests.conftest import BASE_URL, call_tool_text

TAGS_URL = f"{BASE_URL}/crosswork/inventory/v1/tags/query"
JOBS_URL = f"{BASE_URL}/crosswork/inventory/v1/jobs/query"
USERS_URL = f"{BASE_URL}/crosswork/aaa/v1/user"
APPS_URL = f"{BASE_URL}/crosswork/platform/v2/capp/applicationsummary/query"
ALARMS_URL = f"{BASE_URL}/crosswork/alarms/v1/query"

NATS_500 = httpx.Response(500, json={"error": "NATS request failed"})

TAGS = {
    "tags": [
        {
            "name": "mdt",
            "category": "default",
            "created_by": "system",
            "creation_time": "1789212325",
            "tag_type": "TAG_TYPE_SYSTEM",
        },
        {
            "name": "core",
            "category": "site",
            "created_by": "admin",
            "creation_time": "1789212400",
            "tag_type": "TAG_TYPE_USER",
        },
        {
            "name": "Edge-MDT",
            "category": "default",
            "created_by": "admin",
            "creation_time": "1789212500",
            "tag_type": "TAG_TYPE_USER",
        },
    ]
}

USERS = {
    "admin": {
        "Username": "admin",
        "Password": "",
        "PolicyId": "admin",
        "FirstName": "Site",
        "LastName": "Admin",
        "Status": "Active",
        "DeviceAccessGroups": [{"Uuid": "u-1", "DomainName": "ALL-ACCESS"}],
    },
    "mcp-admin": {
        "Username": "mcp-admin",
        "Password": "",
        "PolicyId": "admin",
        "FirstName": "",
        "LastName": "",
        "Status": "Active",
        "DeviceAccessGroups": [{"Uuid": "u-1", "DomainName": "ALL-ACCESS"}],
    },
}

APPS = {
    "application_summary_list": [
        {
            "application_id": "cw-optima",
            "application_data": {
                "version": "7.1.0",
                "summary": {
                    "name": "Optimization Engine",
                    "description": "SR-TE and RSVP-TE path optimisation",
                },
                "category": "network",
                "build_information": {"date_time": "2026-05-01", "publisher": "Cisco"},
            },
        }
    ]
}

ALARM = {
    "AlarmId": "a-1",
    "AlarmCategory": "Reachability",
    "Description": "Device PE1 unreachable",
    "Created": "1789212325000",
    "Updated": "1789212325000",
    "Acknowledge": False,
    "object_id": "n-1",
    "origin_app_id": "cw-inventory",
    "events_count": 2,
    "Events": [{"EventId": "e-1", "Description": "SNMP timeout"}],
}

JOB_RUNNING = {
    "job_id": "j-1",
    "state": "JOB_RUNNING",
    "type": "1 device(s) being added",
    "creation_time": "1789212325",
    "created_by": "admin",
    "impacted": [],
}
JOB_COMPLETED = {
    "job_id": "j-1",
    "state": "JOB_COMPLETED",
    "type": "1 device(s) added successfully",
    "completion_time": "1789212330",
    "creation_time": "1789212325",
    "created_by": "admin",
    "impacted": ["0f6c1a2e PE1 198.18.140.11"],
}
JOB_FAILED = {
    "job_id": "j-1",
    "state": "JOB_FAILED",
    "type": "1 device(s) details updation failed ",
    "error": "Software Type needs to be configured",
    "completion_time": "1789212330",
    "creation_time": "1789212325",
    "created_by": "admin",
    "impacted": [],
}
# Verified live: a no-op / partially applied write is a success with an advisory.
JOB_COMPLETED_WITH_WARNING = {
    "job_id": "j-1",
    "state": "JOB_COMPLETED_WITH_WARNING",
    "type": "1 device(s) details patched",
    "error": "nothing to change",
    "completion_time": "1789212330",
    "creation_time": "1789212325",
    "created_by": "admin",
    "impacted": ["0f6c1a2e PE1 198.18.140.11"],
}
# An in-progress state the code has never seen: must keep polling, not fail.
JOB_PENDING = {**JOB_RUNNING, "state": "JOB_PENDING"}


def other_jobs(n: int, prefix: str = "other") -> list[dict]:
    """n distinct non-matching jobs, for simulating an ignored job_id filter."""
    return [{**JOB_COMPLETED, "job_id": f"{prefix}-{i}"} for i in range(n)]


def make_server(settings) -> MCPServer:
    """Register only the platform module (tools/__init__ still lists the template)."""
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    platform.register(mcp, ctx)
    return mcp


async def _no_sleep(_seconds: float) -> None:
    return None


# --- tags -------------------------------------------------------------------


@respx.mock
async def test_list_tags_markdown_sends_empty_body(settings):
    route = respx.post(TAGS_URL).mock(return_value=httpx.Response(200, json=TAGS))
    text = await call_tool_text(make_server(settings), "cnc_list_tags", {"page_size": 2})
    assert json.loads(route.calls[0].request.content) == {}
    assert "**mdt**" in text and "**core**" in text and "Edge-MDT" not in text
    assert "total 3" in text
    assert "page=1" in text  # has_more hint: 2 of 3 shown


@respx.mock
async def test_list_tags_client_side_paging_json(settings):
    respx.post(TAGS_URL).mock(return_value=httpx.Response(200, json=TAGS))
    text = await call_tool_text(
        make_server(settings),
        "cnc_list_tags",
        {"page_size": 2, "page": 1, "response_format": "json"},
    )
    data = json.loads(text)
    assert [t["name"] for t in data["items"]] == ["Edge-MDT"]
    assert data["total"] == 3 and data["collection_total"] == 3
    assert data["count"] == 1 and data["page"] == 1 and data["page_size"] == 2
    assert data["has_more"] is False and data["next_page"] is None


@respx.mock
async def test_list_tags_name_and_category_filters_are_client_side(settings):
    route = respx.post(TAGS_URL).mock(return_value=httpx.Response(200, json=TAGS))
    mcp = make_server(settings)
    text = await call_tool_text(mcp, "cnc_list_tags", {"name": "MDT", "response_format": "json"})
    data = json.loads(text)
    assert sorted(t["name"] for t in data["items"]) == ["Edge-MDT", "mdt"]
    assert data["total"] == 2 and data["collection_total"] == 3
    assert json.loads(route.calls[0].request.content) == {}  # never a server filter

    text = await call_tool_text(
        mcp, "cnc_list_tags", {"category": "SITE", "response_format": "json"}
    )
    data = json.loads(text)
    assert [t["name"] for t in data["items"]] == ["core"]
    assert data["total"] == 1


@respx.mock
async def test_list_tags_empty_collection(settings):
    respx.post(TAGS_URL).mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(make_server(settings), "cnc_list_tags", {})
    assert "No tags matched" in text
    assert "total 0" in text
    assert "Note:" not in text


@respx.mock
async def test_list_tags_server_counts_reveal_truncation(settings):
    # Whether tags/query pages server-side is unverified: if it ever does, the
    # server's counts must win over len(tags) and the output must say so.
    respx.post(TAGS_URL).mock(
        return_value=httpx.Response(200, json={**TAGS, "result_count": 5, "total_count": 5})
    )
    mcp = make_server(settings)
    text = await call_tool_text(mcp, "cnc_list_tags", {"response_format": "json"})
    data = json.loads(text)
    assert data["collection_total"] == 5 and data["total"] == 3 and data["count"] == 3

    text = await call_tool_text(mcp, "cnc_list_tags", {})
    assert "Note: Crosswork returned 3 of 5 tags" in text
    assert "total 3" in text


@respx.mock
async def test_list_tags_error_is_string(make_settings):
    respx.post(TAGS_URL).mock(return_value=NATS_500)
    text = await call_tool_text(make_server(make_settings(max_retries=0)), "cnc_list_tags", {})
    assert text.startswith("Error:") and "500" in text


# --- users ------------------------------------------------------------------


@respx.mock
async def test_list_users_converts_keyed_dict(settings):
    respx.get(USERS_URL).mock(return_value=httpx.Response(200, json=USERS))
    text = await call_tool_text(
        make_server(settings), "cnc_list_users", {"response_format": "json"}
    )
    data = json.loads(text)
    assert data["count"] == 2
    assert data["items"][0] == {
        "username": "admin",
        "role": "admin",
        "first_name": "Site",
        "last_name": "Admin",
        "status": "Active",
        "device_access_groups": ["ALL-ACCESS"],
    }
    assert data["items"][1]["username"] == "mcp-admin"
    assert "Password" not in text and "password" not in text
    assert "PolicyId" not in text  # PascalCase fields are flattened away


@respx.mock
async def test_list_users_markdown(settings):
    respx.get(USERS_URL).mock(return_value=httpx.Response(200, json=USERS))
    text = await call_tool_text(make_server(settings), "cnc_list_users", {})
    assert "# Users (2)" in text
    assert "**admin** — role admin, status Active, name: Site Admin" in text
    assert "ALL-ACCESS" in text
    assert "Password" not in text


@respx.mock
async def test_list_users_empty_responses(settings):
    mcp = make_server(settings)
    for empty in ([], {}):
        respx.get(USERS_URL).mock(return_value=httpx.Response(200, json=empty))
        text = await call_tool_text(mcp, "cnc_list_users", {})
        assert "# Users (0)" in text and "No users returned" in text
        data = json.loads(await call_tool_text(mcp, "cnc_list_users", {"response_format": "json"}))
        assert data == {"count": 0, "items": []}


@respx.mock
async def test_list_users_accepts_list_shaped_response(settings):
    # The verified shape is a dict keyed by username; a plain list of the same
    # PascalCase records must flatten identically (and drop Password).
    respx.get(USERS_URL).mock(
        return_value=httpx.Response(200, json=[USERS["mcp-admin"], USERS["admin"], "junk"])
    )
    text = await call_tool_text(
        make_server(settings), "cnc_list_users", {"response_format": "json"}
    )
    data = json.loads(text)
    assert [u["username"] for u in data["items"]] == ["admin", "mcp-admin"]
    assert data["items"][0]["device_access_groups"] == ["ALL-ACCESS"]
    assert "Password" not in text


@respx.mock
async def test_list_users_error_is_string(make_settings):
    respx.get(USERS_URL).mock(return_value=httpx.Response(403, json={"error": "forbidden"}))
    text = await call_tool_text(make_server(make_settings(max_retries=0)), "cnc_list_users", {})
    assert text.startswith("Error:") and "403" in text


# --- applications -----------------------------------------------------------


@respx.mock
async def test_list_applications_markdown_sends_empty_body(settings):
    route = respx.post(APPS_URL).mock(return_value=httpx.Response(200, json=APPS))
    text = await call_tool_text(make_server(settings), "cnc_list_applications", {})
    assert json.loads(route.calls[0].request.content) == {}
    assert "**Optimization Engine** (cw-optima) 7.1.0 — SR-TE and RSVP-TE" in text


@respx.mock
async def test_list_applications_json(settings):
    respx.post(APPS_URL).mock(return_value=httpx.Response(200, json=APPS))
    text = await call_tool_text(
        make_server(settings), "cnc_list_applications", {"response_format": "json"}
    )
    data = json.loads(text)
    assert data["count"] == 1
    assert data["items"][0]["application_id"] == "cw-optima"
    assert data["items"][0]["application_data"]["version"] == "7.1.0"


@respx.mock
async def test_list_applications_error_is_string(make_settings):
    respx.post(APPS_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        make_server(make_settings(max_retries=0)), "cnc_list_applications", {}
    )
    assert text.startswith("Error:") and "500" in text


# --- alarms -----------------------------------------------------------------


@respx.mock
async def test_list_alarms_criteria_string_and_markdown(settings):
    route = respx.post(ALARMS_URL).mock(
        return_value=httpx.Response(200, json={"state": "Success", "alarms": [ALARM]})
    )
    text = await call_tool_text(
        make_server(settings), "cnc_list_alarms", {"limit": 5, "page": 2, "open_only": False}
    )
    assert json.loads(route.calls[0].request.content) == {
        "openAlarmsOnly": False,
        "criteria": "select * from alarm limit 5 page 2",
    }
    assert "[Reachability] Device PE1 unreachable — created 1789212325000, id a-1" in text
    assert "SNMP timeout" not in text  # Events detail dropped from markdown
    assert "open and cleared" in text
    assert "page=" not in text  # 1 of 5: no more pages


@respx.mock
async def test_list_alarms_defaults_and_json_has_more(settings):
    route = respx.post(ALARMS_URL).mock(
        return_value=httpx.Response(200, json={"state": "Success", "alarms": [ALARM, ALARM]})
    )
    text = await call_tool_text(
        make_server(settings), "cnc_list_alarms", {"limit": 2, "response_format": "json"}
    )
    assert json.loads(route.calls[0].request.content) == {
        "openAlarmsOnly": True,
        "criteria": "select * from alarm limit 2 page 0",
    }
    data = json.loads(text)
    assert data["count"] == 2 and data["has_more"] is True and data["next_page"] == 1
    assert data["items"][0]["Events"][0]["Description"] == "SNMP timeout"


@respx.mock
async def test_list_alarms_non_success_state_is_error(settings):
    respx.post(ALARMS_URL).mock(
        return_value=httpx.Response(200, json={"state": "Failure", "error": "bad criteria"})
    )
    text = await call_tool_text(make_server(settings), "cnc_list_alarms", {})
    assert text.startswith("Error:") and "bad criteria" in text


@respx.mock
async def test_list_alarms_error_is_string(make_settings):
    respx.post(ALARMS_URL).mock(return_value=NATS_500)
    text = await call_tool_text(make_server(make_settings(max_retries=0)), "cnc_list_alarms", {})
    assert text.startswith("Error:") and "500" in text


# --- inventory jobs ---------------------------------------------------------


@respx.mock
async def test_list_inventory_jobs_uses_filterdata_paging(settings):
    route = respx.post(JOBS_URL).mock(
        return_value=httpx.Response(
            200, json={"jobs": [JOB_COMPLETED, JOB_FAILED], "result_count": 2, "total_count": 2}
        )
    )
    text = await call_tool_text(
        make_server(settings), "cnc_list_inventory_jobs", {"page_size": 10, "page": 1}
    )
    assert json.loads(route.calls[0].request.content) == {
        "filter": {},
        "filterData": {"PageSize": 10, "PageNum": 1, "Criteria": ""},
    }
    assert "**j-1** JOB_COMPLETED — 1 device(s) added successfully" in text
    assert "error: Software Type needs to be configured" in text


@respx.mock
async def test_list_inventory_jobs_json_envelope(settings):
    respx.post(JOBS_URL).mock(
        return_value=httpx.Response(
            200, json={"jobs": [JOB_COMPLETED], "result_count": 3, "total_count": 3}
        )
    )
    text = await call_tool_text(
        make_server(settings),
        "cnc_list_inventory_jobs",
        {"page_size": 1, "response_format": "json"},
    )
    data = json.loads(text)
    assert data["total"] == 3 and data["count"] == 1
    assert data["has_more"] is True and data["next_page"] == 1
    assert data["items"][0]["job_id"] == "j-1"


@respx.mock
async def test_list_inventory_jobs_bare_empty_response(settings):
    # Crosswork answers an empty inventory collection with a bare {} (no list
    # key, no counts); that is "no jobs", not an error.
    respx.post(JOBS_URL).mock(return_value=httpx.Response(200, json={}))
    mcp = make_server(settings)
    text = await call_tool_text(mcp, "cnc_list_inventory_jobs", {})
    assert not text.startswith("Error:")
    assert "No inventory jobs returned" in text and "total unknown" in text
    data = json.loads(
        await call_tool_text(mcp, "cnc_list_inventory_jobs", {"response_format": "json"})
    )
    assert data["count"] == 0 and data["has_more"] is False and data["next_page"] is None
    assert data["total"] is None and data["collection_total"] is None


@respx.mock
async def test_list_inventory_jobs_full_page_without_result_count(settings):
    # result_count is omitted in some responses; a full page then means has_more.
    respx.post(JOBS_URL).mock(return_value=httpx.Response(200, json={"jobs": other_jobs(3)}))
    text = await call_tool_text(
        make_server(settings),
        "cnc_list_inventory_jobs",
        {"page_size": 3, "response_format": "json"},
    )
    data = json.loads(text)
    assert data["count"] == 3 and data["total"] is None
    assert data["has_more"] is True and data["next_page"] == 1


@respx.mock
async def test_list_inventory_jobs_error_is_string(make_settings):
    respx.post(JOBS_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        make_server(make_settings(max_retries=0)), "cnc_list_inventory_jobs", {}
    )
    assert text.startswith("Error:") and "500" in text


@respx.mock
async def test_get_inventory_job_filters_by_job_id(settings):
    route = respx.post(JOBS_URL).mock(
        return_value=httpx.Response(200, json={"jobs": [JOB_COMPLETED], "result_count": 1})
    )
    text = await call_tool_text(make_server(settings), "cnc_get_inventory_job", {"job_id": "j-1"})
    body = json.loads(route.calls[0].request.content)
    assert body["filter"] == {"job_id": "j-1"}
    assert body["filterData"]["PageNum"] == 0
    data = json.loads(text)
    assert data["state"] == "JOB_COMPLETED"
    assert data["impacted_objects"] == [{"uuid": "0f6c1a2e", "name": "PE1", "ip": "198.18.140.11"}]


@respx.mock
async def test_get_inventory_job_not_found_is_error_not_listing(settings):
    respx.post(JOBS_URL).mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(make_server(settings), "cnc_get_inventory_job", {"job_id": "nope"})
    assert text.startswith("Error:") and "nope" in text and "cnc_list_inventory_jobs" in text


@respx.mock
async def test_get_inventory_job_ignores_non_matching_rows(settings):
    # If Crosswork ever ignored the filter and returned other jobs, the tool must
    # not hand back the wrong job.
    route = respx.post(JOBS_URL).mock(
        return_value=httpx.Response(200, json={"jobs": [JOB_COMPLETED], "result_count": 1})
    )
    text = await call_tool_text(
        make_server(settings), "cnc_get_inventory_job", {"job_id": "j-other"}
    )
    assert text.startswith("Error:") and "j-other" in text
    assert route.call_count == 1  # result_count says there is nothing more to page


@respx.mock
async def test_get_inventory_job_filters_by_job_id_in_one_query(settings):
    """jobs/query honours filter.job_id (verified live): one request, exact match."""
    route = respx.post(JOBS_URL).mock(
        return_value=httpx.Response(200, json={"jobs": [JOB_COMPLETED], "total_count": 9})
    )
    text = await call_tool_text(
        make_server(settings), "cnc_get_inventory_job", {"job_id": JOB_COMPLETED["job_id"]}
    )
    assert json.loads(text)["job_id"] == JOB_COMPLETED["job_id"]
    assert route.call_count == 1
    body = json.loads(route.calls[0].request.content)
    assert body["filter"] == {"job_id": JOB_COMPLETED["job_id"]}
    assert "offset" not in body


@respx.mock
async def test_get_inventory_job_unknown_id_is_not_found(settings):
    """An unknown id answers a bare {} (verified live) -> not-found error string."""
    respx.post(JOBS_URL).mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(make_server(settings), "cnc_get_inventory_job", {"job_id": "nope"})
    assert text.startswith("Error:") and "nope" in text


@respx.mock
async def test_get_inventory_job_ignores_a_wrong_job_returned_by_the_filter(settings):
    other = dict(JOB_COMPLETED, job_id="some-other-job")
    respx.post(JOBS_URL).mock(return_value=httpx.Response(200, json={"jobs": [other]}))
    text = await call_tool_text(
        make_server(settings), "cnc_get_inventory_job", {"job_id": "wanted-id"}
    )
    assert text.startswith("Error:")


@respx.mock
async def test_get_inventory_job_error_is_string(make_settings):
    respx.post(JOBS_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        make_server(make_settings(max_retries=0)), "cnc_get_inventory_job", {"job_id": "j-1"}
    )
    assert text.startswith("Error:") and "500" in text


@respx.mock
async def test_wait_for_inventory_job_polls_until_completed(settings, monkeypatch):
    monkeypatch.setattr("cnc_mcp.polling.asyncio.sleep", _no_sleep)
    route = respx.post(JOBS_URL).mock(
        side_effect=[
            httpx.Response(200, json={"jobs": [JOB_RUNNING]}),
            httpx.Response(200, json={"jobs": [JOB_COMPLETED]}),
        ]
    )
    text = await call_tool_text(
        make_server(settings),
        "cnc_wait_for_inventory_job",
        {"job_id": "j-1", "timeout_seconds": 60, "interval_seconds": 1},
    )
    assert route.call_count == 2
    assert text.startswith("Inventory job j-1 completed")
    assert json.loads(route.calls[0].request.content)["filter"] == {"job_id": "j-1"}
    assert '"impacted_objects"' in text and "PE1" in text


@respx.mock
async def test_wait_for_inventory_job_completed_with_warning_is_success(settings):
    route = respx.post(JOBS_URL).mock(
        return_value=httpx.Response(200, json={"jobs": [JOB_COMPLETED_WITH_WARNING]})
    )
    text = await call_tool_text(
        make_server(settings), "cnc_wait_for_inventory_job", {"job_id": "j-1"}
    )
    assert route.call_count == 1  # terminal on the first poll
    assert not text.startswith("Error:")
    assert text.startswith("Inventory job j-1 completed")
    assert "Warning: nothing to change" in text
    body = json.loads(text.split("\n\n", 1)[1])
    assert body["state"] == "JOB_COMPLETED_WITH_WARNING"
    assert body["warning"] == "nothing to change"
    assert body["impacted_objects"] == [{"uuid": "0f6c1a2e", "name": "PE1", "ip": "198.18.140.11"}]


@respx.mock
async def test_wait_for_inventory_job_keeps_polling_on_unlisted_state(settings, monkeypatch):
    # Only the verified terminal states end the wait; an in-progress state the
    # code has never seen (JOB_PENDING) must keep polling, not report failure.
    monkeypatch.setattr("cnc_mcp.polling.asyncio.sleep", _no_sleep)
    route = respx.post(JOBS_URL).mock(
        side_effect=[
            httpx.Response(200, json={"jobs": [JOB_PENDING]}),
            httpx.Response(200, json={"jobs": [JOB_COMPLETED]}),
        ]
    )
    text = await call_tool_text(
        make_server(settings),
        "cnc_wait_for_inventory_job",
        {"job_id": "j-1", "timeout_seconds": 60, "interval_seconds": 1},
    )
    assert route.call_count == 2
    assert text.startswith("Inventory job j-1 completed")


@respx.mock
async def test_wait_for_inventory_job_unlisted_state_times_out_without_error(settings):
    respx.post(JOBS_URL).mock(return_value=httpx.Response(200, json={"jobs": [JOB_PENDING]}))
    text = await call_tool_text(
        make_server(settings),
        "cnc_wait_for_inventory_job",
        {"job_id": "j-1", "timeout_seconds": 1, "interval_seconds": 5},
    )
    assert not text.startswith("Error:")
    assert "not finished" in text and "JOB_PENDING" in text


@respx.mock
async def test_wait_for_inventory_job_failed_is_error_string(settings):
    respx.post(JOBS_URL).mock(return_value=httpx.Response(200, json={"jobs": [JOB_FAILED]}))
    text = await call_tool_text(
        make_server(settings), "cnc_wait_for_inventory_job", {"job_id": "j-1"}
    )
    assert text.startswith("Error: Inventory job j-1 failed (job j-1, state JOB_FAILED)")
    assert "Software Type needs to be configured" in text


@respx.mock
async def test_wait_for_inventory_job_cancelled_is_error_string(settings):
    cancelled = {**JOB_FAILED, "state": "JOB_CANCELLED", "error": ""}
    respx.post(JOBS_URL).mock(return_value=httpx.Response(200, json={"jobs": [cancelled]}))
    text = await call_tool_text(
        make_server(settings), "cnc_wait_for_inventory_job", {"job_id": "j-1"}
    )
    assert text.startswith("Error: Inventory job j-1 failed (job j-1, state JOB_CANCELLED)")
    assert "1 device(s) details updation failed" in text  # falls back to "type"


@respx.mock
async def test_wait_for_inventory_job_timeout_is_not_error(settings):
    respx.post(JOBS_URL).mock(return_value=httpx.Response(200, json={"jobs": [JOB_RUNNING]}))
    text = await call_tool_text(
        make_server(settings),
        "cnc_wait_for_inventory_job",
        {"job_id": "j-1", "timeout_seconds": 1, "interval_seconds": 5},
    )
    assert not text.startswith("Error:")
    assert "not finished" in text and "JOB_RUNNING" in text


@respx.mock
async def test_wait_for_inventory_job_not_found_is_error(settings):
    respx.post(JOBS_URL).mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(
        make_server(settings), "cnc_wait_for_inventory_job", {"job_id": "nope"}
    )
    assert text.startswith("Error:") and "nope" in text


@respx.mock
async def test_wait_for_inventory_job_api_error_is_string(make_settings):
    respx.post(JOBS_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        make_server(make_settings(max_retries=0)),
        "cnc_wait_for_inventory_job",
        {"job_id": "j-1"},
    )
    assert text.startswith("Error:") and "500" in text


async def test_platform_tools_are_all_read_only(settings):
    mcp = make_server(settings)
    tools = {t.name: t for t in await mcp.list_tools()}
    expected = {
        "cnc_list_tags",
        "cnc_list_users",
        "cnc_list_applications",
        "cnc_list_alarms",
        "cnc_list_inventory_jobs",
        "cnc_get_inventory_job",
        "cnc_wait_for_inventory_job",
    }
    assert expected <= set(tools)
    for name in expected:
        assert tools[name].annotations.read_only_hint is True
        assert tools[name].annotations.destructive_hint is False
