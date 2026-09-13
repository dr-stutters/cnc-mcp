"""Collection service tools end-to-end through MCPServer (schema validation included).

The module is registered directly (not through build_server) so the test does
not depend on tools/__init__.py's module list. All HTTP is mocked with respx.
Fixtures mirror the answers verified live on Crosswork 7.2 (2026-09-13, see
the platform notes "Collection service"): the string-valued count document,
the READY/ACTIVE summary entry and SUCCESS lifecycle entry of the built-in DLM
CLI-collector job, and the EMPTY ``jobs`` / ``sensor_templates`` lists (the
latter answered for a body without ``template_id`` — the documented "nothing
is returned" case, so the template fixtures follow the 7.2 document).
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from cnc_mcp.auth import StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.config import Settings
from cnc_mcp.crosswork import collection_query_body
from cnc_mcp.errors import PlatformError
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import collection
from cnc_mcp.tools.collection import (
    DLM_APPLICATION_ID,
    DLM_CONTEXT_ID,
    application_context,
    as_int,
    coerce_counts,
    count_summary_line,
    export_job_line,
    health_payload,
    job_query_body,
    life_cycle_short,
    list_query_body,
    more_note,
    page_state,
    sensor_template_line,
    template_definition_text,
    template_query_body,
    total_or_unknown,
)
from tests.conftest import BASE_URL, call_tool_text

COLLECTION_BASE = f"{BASE_URL}/crosswork/collection/v1"
COUNT_URL = f"{COLLECTION_BASE}/collectionjob/count/query"
SUMMARY_URL = f"{COLLECTION_BASE}/collectionjob/summary/query"
STATE_URL = f"{COLLECTION_BASE}/collectionjob/state/query"
JOBS_URL = f"{COLLECTION_BASE}/jobs/query"
TEMPLATE_URL = f"{COLLECTION_BASE}/template"

NATS_500 = httpx.Response(500, json={"error": "NATS request failed"})

ACCEPTED = {"request_result": "ACCEPTED", "error": {"error": ""}}
REJECTED = {"request_result": "REJECTED", "error": {"error": "application context not found"}}
DLM_CONTEXT = {"application_id": DLM_APPLICATION_ID, "context_id": DLM_CONTEXT_ID}
DLM_QUERY_OPTIONS = {"page_token": "", "page_size": 50, "filter_list": [], "filter_query": ""}

# Verified live: every count is a STRING.
COUNT = {
    "job_count": "1",
    "input_collection_count": "5",
    "output_collection_count": "5",
    "input_error_collection_count": "0",
    "output_error_collection_count": "0",
    "control_error_count": "0",
    "device_count": "5",
    "input_filtered_count": "0",
    "output_filtered_count": "0",
    "result": ACCEPTED,
}
COUNT_NONE = {**COUNT, "job_count": "0", "device_count": "0"}

# Verified live: the DLM CLI-collector job, READY / ACTIVE / progress 100.
JOB_STATUS = {
    "application_context": DLM_CONTEXT,
    "creation_time": "1757750400000",
    "deletion_time": "0",
    "progress": 100,
    "status": "READY",
    "phase": "ACTIVE",
    "collector_type": "CLI_COLLECTOR",
    "job_error": {"error": ""},
}
SUMMARY = {"collection_job_status_list": [JOB_STATUS], "result": ACCEPTED}
SUMMARY_EMPTY = {"collection_job_status_list": [], "result": ACCEPTED}

# Verified live: SUCCESS lifecycle; the echoed page_token is an opaque hash.
LIFE_CYCLE = {
    "life_cycle_state": "SUCCESS_LIFE_CYCLE_STATE",
    "application_context": DLM_CONTEXT,
    "creation_time": "1757750400000",
    "state_evaluation_time": "1757754000000",
}
STATE = {
    "collection_life_cycle_states": [LIFE_CYCLE],
    "query_options": {
        "page_token": "a7859eb217ee381541afe2f911dfd21c",
        "page_size": 50,
        "filter_list": [],
    },
    "result": ACCEPTED,
}
STATE_EMPTY = {"collection_life_cycle_states": [], "result": ACCEPTED}

# Verified live: no export jobs; the platform echoes the "0" token it was sent.
JOBS_EMPTY = {
    "result": ACCEPTED,
    "query_options": {"page_token": "0", "page_size": 100, "filter_list": []},
    "jobs": [],
}
# Documented job shape (collection_serviceJob) — none seen live.
EXPORT_JOB = {
    "id": {
        "export_id": {
            "application_context": {"application_id": "cw.export", "context_id": "export/1"}
        }
    },
    "user": "admin",
    "created": "1757750400000",
    "completed": "1757754000000",
    "progress": 100,
    "status": "JOB_COMPLETED",
    "type": "EXPORT_COLLECTIONS",
    "description": "nightly export",
}
JOBS = {**JOBS_EMPTY, "jobs": [EXPORT_JOB]}

# Verified live for a body WITHOUT template_id (the documented "nothing is returned"
# answer) — not proof that the lab has no templates.
TEMPLATES_EMPTY = {"sensor_templates": [], "result": ACCEPTED}
TEMPLATE_ARGS = {"template_id": "show-interface"}
NO_PAGING_NOTE = {"has_more": False, "next_page_token": None, "paging_note": None}
# Documented template shape (common_collection_dataSensorTemplate) — none seen live.
CLI_TEMPLATE = {
    "sensor_template_id": "show-interface",
    "collection_type": "CLI_COLLECTOR",
    "sensor_template_Definition": {
        "cli_sensor_template": {
            "template_command": {
                "templatecommand": "show interface {{interface_name}}",
                "template_variables": ["interface_name"],
            }
        }
    },
    "cadence_in_millisec": "60000",
}
GNMI_TEMPLATE = {
    "sensor_template_id": "gnmi-cpu",
    "collection_type": "GNMI_COLLECTOR",
    "sensor_template_Definition": {
        "gnmi_sensor_template": {
            "gnmi_path": "Cisco-IOS-XR-wdsysmon-fd-oper:system-monitoring/cpu-utilization"
        }
    },
    "cadence_in_millisec": "30000",
}
TEMPLATES = {"sensor_templates": [CLI_TEMPLATE, GNMI_TEMPLATE], "result": ACCEPTED}

TOOLS = {
    "cnc_get_collection_job_count",
    "cnc_get_collection_job_summary",
    "cnc_get_collection_job_state",
    "cnc_list_export_collection_jobs",
    "cnc_list_sensor_templates",
    "cnc_get_collection_health",
}


def build(settings: Settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    collection.register(mcp, ctx)
    return mcp


def sent(route: respx.Route, index: int = 0) -> dict:
    return json.loads(route.calls[index].request.content)


def mock(url: str, body: dict) -> respx.Route:
    return respx.post(url).mock(return_value=httpx.Response(200, json=body))


def rejected(body: dict) -> dict:
    return {**body, "result": REJECTED}


# --- registration -------------------------------------------------------------


async def test_all_tools_are_reads_visible_without_writes(make_settings):
    mcp = build(make_settings(enable_writes=False))
    tools = {t.name: t for t in await mcp.list_tools()}
    assert set(tools) == TOOLS
    for name, tool in tools.items():
        assert tool.annotations.read_only_hint is True, name
        assert tool.annotations.idempotent_hint is True, name
        assert tool.annotations.destructive_hint is False, name


async def test_dlm_context_is_the_default_of_every_context_tool(make_settings):
    tools = {t.name: t for t in await build(make_settings()).list_tools()}
    for name in (
        "cnc_get_collection_job_count",
        "cnc_get_collection_job_summary",
        "cnc_get_collection_job_state",
        "cnc_get_collection_health",
    ):
        props = tools[name].input_schema["properties"]
        assert props["application_id"]["default"] == "cw.dlminvmgr0", name
        assert (
            props["context_id"]["default"] == "dlm/cli-collector/group/te-tunnel-id/subscription"
        ), name


# --- pure helpers ---------------------------------------------------------------


def test_application_context_strips_blank_means_all_and_half_is_refused():
    assert application_context(" cw.x ", " ctx/1 ") == {
        "application_id": "cw.x",
        "context_id": "ctx/1",
    }
    assert application_context("", "  ") is None
    with pytest.raises(PlatformError, match="go together"):
        application_context("cw.x", "")
    with pytest.raises(PlatformError, match="go together"):
        application_context("", "ctx/1")


def test_job_query_body_is_the_verified_shape():
    assert job_query_body(DLM_APPLICATION_ID, DLM_CONTEXT_ID) == {
        "application_context": DLM_CONTEXT,
        "query_options": DLM_QUERY_OPTIONS,
    }
    assert job_query_body("", "", 10) == {
        "query_options": {"page_token": "", "page_size": 10, "filter_list": [], "filter_query": ""}
    }
    assert job_query_body(DLM_APPLICATION_ID, DLM_CONTEXT_ID, 10, "abc")["query_options"] == {
        "page_token": "abc",
        "page_size": 10,
        "filter_list": [],
        "filter_query": "",
    }
    # jobs/query: the platform's own page size and first-page token (query options are
    # "currently not utilized" per the 7.2 document, so nothing else is ever sent).
    assert list_query_body() == {
        "query_options": {
            "page_token": "0",
            "page_size": 100,
            "filter_list": [],
            "filter_query": "",
        }
    }
    assert list_query_body(25, "tok")["query_options"]["page_token"] == "tok"


def test_template_query_body_requires_a_template_id():
    """POST template carries template_id next to query_options (7.2 document: required;
    'if not specified, nothing is returned'); a blank one is refused, never sent."""
    assert template_query_body(" show-interface ", 25) == {
        "template_id": "show-interface",
        "query_options": {
            "page_token": "0",
            "page_size": 25,
            "filter_list": [],
            "filter_query": "",
        },
    }
    assert template_query_body("x", 2, "tpl-2")["query_options"]["page_token"] == "tpl-2"
    with pytest.raises(PlatformError, match="needs a template_id"):
        template_query_body("   ")


def test_query_options_are_the_shared_builder_plus_filter_query():
    """One body builder for collection/v1: crosswork.collection_query_body, extended with the
    ``filter_query`` field every verified body carried."""
    shared = collection_query_body(page_size=25, page_token="0")["query_options"]
    assert list_query_body(25)["query_options"] == {**shared, "filter_query": ""}
    shared = collection_query_body(page_size=50, page_token="")["query_options"]
    assert job_query_body("", "")["query_options"] == {**shared, "filter_query": ""}


def test_page_state_is_three_valued():
    echo_hash = {"query_options": {"page_token": "a7859eb217ee381541afe2f911dfd21c"}}
    # Verified live: one entry, page_size 50, opaque hash echoed -> a short page, no more.
    assert page_state([JOB_STATUS], echo_hash, 50, "") == {
        "page_size": 50,
        "page_token": "",
        **NO_PAGING_NOTE,
    }
    assert more_note(page_state([JOB_STATUS], echo_hash, 50, ""), "t") == []
    # A full page AND a token that differs from the one sent -> more (heuristic).
    assert page_state([JOB_STATUS], echo_hash, 1, "") == {
        "page_size": 1,
        "page_token": "",
        "has_more": True,
        "next_page_token": "a7859eb217ee381541afe2f911dfd21c",
        "paging_note": None,
    }
    note = more_note(page_state([JOB_STATUS], echo_hash, 1, ""), "cnc_get_collection_job_summary")
    assert note[0] == ""
    assert note[1].startswith(
        "(more on server: call cnc_get_collection_job_summary again with page_token "
        "'a7859eb217ee381541afe2f911dfd21c'"
    )
    # A full page with NO new token is unknown, never "no more" (pagination_envelope's
    # full-page rule): no echo at all (the verified summary answer) ...
    unknown = page_state([JOB_STATUS], SUMMARY, 1, "")
    assert unknown["has_more"] is None and unknown["next_page_token"] is None
    assert unknown["paging_note"] == (
        "page full (1 entries at page_size 1) and the platform echoed no new page token — "
        "more entries may exist; call again with a larger page_size"
    )
    note = more_note(unknown, "cnc_get_collection_job_summary")
    assert note == ["", f"({unknown['paging_note']} on cnc_get_collection_job_summary.)"]
    # ... or the token it was sent echoed back (verified live: jobs/query echoes the "0").
    assert page_state([EXPORT_JOB], JOBS_EMPTY, 1, "0")["has_more"] is None
    # An empty page is a short page: False, whatever is echoed.
    assert page_state([], echo_hash, 1, "")["has_more"] is False


def test_as_int_coerces_wire_strings_and_never_invents_a_number():
    assert as_int("5") == 5
    assert as_int(" 12 ") == 12
    assert as_int(7) == 7
    assert as_int(None) is None
    assert as_int("") is None
    assert as_int("five") is None
    assert as_int(True) is None


def test_coerce_counts_and_summary_line():
    counts = coerce_counts(COUNT)
    assert counts == {
        "job_count": 1,
        "device_count": 5,
        "input_collection_count": 5,
        "output_collection_count": 5,
        "input_error_collection_count": 0,
        "output_error_collection_count": 0,
        "control_error_count": 0,
        "input_filtered_count": 0,
        "output_filtered_count": 0,
    }
    assert count_summary_line(counts, "cw.dlminvmgr0 / ctx") == (
        "1 collection job(s) for cw.dlminvmgr0 / ctx on 5 device(s): 5 input / 5 output "
        "collections, 0 error(s), 0 filtered."
    )
    assert count_summary_line(coerce_counts(COUNT_NONE), "cw.x / y") == (
        "No collection job is registered for cw.x / y."
    )
    # Omitted fields render as "?" — never Python None, never an invented 0. An error /
    # filtered total is printed only when at least one contributing field is present.
    partial = coerce_counts({"job_count": "2", "control_error_count": "3"})
    assert partial["device_count"] is None
    assert count_summary_line(partial, "all collection jobs") == (
        "2 collection job(s) for all collection jobs on ? device(s): ? input / ? output "
        "collections, 3 error(s), ? filtered."
    )
    bare = coerce_counts({"job_count": "2"})
    assert count_summary_line(bare, "all collection jobs") == (
        "2 collection job(s) for all collection jobs on ? device(s): ? input / ? output "
        "collections, ? error(s), ? filtered."
    )
    assert "None" not in count_summary_line(bare, "x")
    assert count_summary_line(coerce_counts({}), "x").startswith("? collection job(s) for x on ?")
    assert total_or_unknown({"a": 1, "b": None}, ("a", "b")) == "1"
    assert total_or_unknown({"a": None}, ("a", "b")) == "?"
    assert total_or_unknown({"a": 0, "b": 0}, ("a", "b")) == "0"


def test_life_cycle_short_strips_only_the_suffix():
    assert life_cycle_short("SUCCESS_LIFE_CYCLE_STATE") == "SUCCESS"
    assert life_cycle_short("NO_DATA_LIFE_CYCLE_STATE") == "NO_DATA"
    assert life_cycle_short("weird") == "weird"
    assert life_cycle_short(None) == "?"


def test_export_job_and_template_lines_follow_the_document():
    assert export_job_line(EXPORT_JOB) == (
        "- **cw.export / export/1** type=EXPORT_COLLECTIONS status=JOB_COMPLETED progress=100% "
        "user=admin created=2025-09-13T08:00:00Z completed=2025-09-13T09:00:00Z — nightly export"
    )
    assert export_job_line({}) == (
        "- **?** type=? status=? progress=?% user=- created=- completed=-"
    )
    assert sensor_template_line(CLI_TEMPLATE) == (
        "- **show-interface** type=CLI_COLLECTOR cadence=60000 ms definition: "
        "cli 'show interface {{interface_name}}' variables interface_name"
    )
    assert template_definition_text(GNMI_TEMPLATE["sensor_template_Definition"]) == (
        "gnmi 'Cisco-IOS-XR-wdsysmon-fd-oper:system-monitoring/cpu-utilization'"
    )
    package = {
        "cli_sensor_template": {
            "template_device_package": {"device_package_name": "xde-pkg", "function_name": "fn"}
        }
    }
    assert template_definition_text(package) == "device-package xde-pkg.fn"
    assert template_definition_text(None) == "-"
    assert template_definition_text({}) == "-"


def test_health_payload_healthy_verdict():
    payload = health_payload(DLM_CONTEXT, coerce_counts(COUNT), [JOB_STATUS], [LIFE_CYCLE])
    assert payload["healthy"] is True
    assert payload["verdict"] == "Collection job READY/ACTIVE on 5 devices, lifecycle SUCCESS."
    assert payload["status"] == "READY" and payload["phase"] == "ACTIVE"
    assert payload["life_cycle_state"] == "SUCCESS_LIFE_CYCLE_STATE"
    assert payload["errors"] == {
        "job_errors": [],
        "input_error_collection_count": 0,
        "output_error_collection_count": 0,
        "control_error_count": 0,
    }
    assert payload["jobs"] == [JOB_STATUS] and payload["life_cycles"] == [LIFE_CYCLE]


def test_health_payload_unhealthy_names_what_is_off():
    failed = {**JOB_STATUS, "status": "FAILED", "job_error": {"error": "device unreachable"}}
    degraded = {**LIFE_CYCLE, "life_cycle_state": "DEGRADED_LIFE_CYCLE_STATE"}
    counts = coerce_counts({**COUNT, "control_error_count": "2"})
    payload = health_payload(DLM_CONTEXT, counts, [failed], [degraded])
    assert payload["healthy"] is False
    assert payload["verdict"] == (
        "Collection job FAILED/ACTIVE on 5 devices, lifecycle DEGRADED; job error: device "
        "unreachable; 2 collection error(s) — NOT healthy."
    )
    assert payload["errors"]["job_errors"] == ["device unreachable"]
    assert payload["errors"]["control_error_count"] == 2


def test_health_payload_no_job_is_a_non_error_verdict():
    payload = health_payload(DLM_CONTEXT, coerce_counts(COUNT_NONE), [], [])
    assert payload["healthy"] is False
    assert payload["verdict"].startswith("No collection job is registered for cw.dlminvmgr0 /")
    assert payload["status"] is None and payload["life_cycle_state"] is None


# --- cnc_get_collection_job_count -------------------------------------------------


@respx.mock
async def test_get_collection_job_count_sends_dlm_context_and_coerces_strings(settings):
    route = mock(COUNT_URL, COUNT)
    text = await call_tool_text(build(settings), "cnc_get_collection_job_count", {})
    assert sent(route) == {
        "application_context": DLM_CONTEXT,
        "query_options": {
            "page_token": "",
            "page_size": 100,
            "filter_list": [],
            "filter_query": "",
        },
    }
    payload = json.loads(text)
    assert payload["application_id"] == DLM_APPLICATION_ID
    assert payload["context_id"] == DLM_CONTEXT_ID
    assert payload["job_count"] == 1 and payload["device_count"] == 5
    assert payload["input_collection_count"] == 5 and payload["output_collection_count"] == 5
    assert payload["control_error_count"] == 0 and payload["output_filtered_count"] == 0
    assert payload["summary"] == (
        f"1 collection job(s) for {DLM_APPLICATION_ID} / {DLM_CONTEXT_ID} on 5 device(s): "
        "5 input / 5 output collections, 0 error(s), 0 filtered."
    )


@respx.mock
async def test_get_collection_job_count_blank_ids_send_no_context(settings):
    route = mock(COUNT_URL, COUNT)
    text = await call_tool_text(
        build(settings),
        "cnc_get_collection_job_count",
        {"application_id": "", "context_id": ""},
    )
    assert "application_context" not in sent(route)
    payload = json.loads(text)
    assert payload["application_id"] is None and payload["context_id"] is None
    assert "for all collection jobs" in payload["summary"]


@respx.mock
async def test_get_collection_job_count_half_context_is_refused_without_a_call(settings):
    route = mock(COUNT_URL, COUNT)
    text = await call_tool_text(
        build(settings), "cnc_get_collection_job_count", {"application_id": "", "context_id": "x"}
    )
    assert text.startswith("Error: application_id and context_id go together")
    assert not route.called


@respx.mock
async def test_get_collection_job_count_zero_jobs_is_not_an_error(settings):
    mock(COUNT_URL, COUNT_NONE)
    text = await call_tool_text(
        build(settings),
        "cnc_get_collection_job_count",
        {"application_id": "cw.nope", "context_id": "nope/ctx"},
    )
    payload = json.loads(text)
    assert payload["job_count"] == 0
    assert payload["summary"] == "No collection job is registered for cw.nope / nope/ctx."


@respx.mock
async def test_get_collection_job_count_rejected_is_error_with_reason(settings):
    mock(COUNT_URL, rejected(COUNT))
    text = await call_tool_text(build(settings), "cnc_get_collection_job_count", {})
    assert text == ("Error: Collection job count query was REJECTED: application context not found")


@respx.mock
async def test_get_collection_job_count_missing_envelope_and_http_error(make_settings):
    respx.post(COUNT_URL).mock(return_value=httpx.Response(200, json={"job_count": "1"}))
    text = await call_tool_text(build(make_settings()), "cnc_get_collection_job_count", {})
    assert text.startswith("Error:") and "collection result envelope" in text
    respx.post(COUNT_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_collection_job_count", {}
    )
    assert text.startswith("Error:") and "500" in text


# --- the shared query() helper: retry, response shape, empty-bodied 500 -----------


@respx.mock
async def test_query_posts_are_retried_once_on_503(make_settings):
    """Every collection/v1 POST is a read and is sent retryable=True: a 503 then a 200
    is one retry and a normal answer, not an Error (a plain POST would not be retried)."""
    route = respx.post(COUNT_URL).mock(
        side_effect=[httpx.Response(503), httpx.Response(200, json=COUNT)]
    )
    text = await call_tool_text(
        build(make_settings(max_retries=1)), "cnc_get_collection_job_count", {}
    )
    assert route.call_count == 2
    assert not text.startswith("Error:")
    assert json.loads(text)["job_count"] == 1


@respx.mock
async def test_query_list_or_null_body_is_an_unexpected_shape(settings):
    respx.post(JOBS_URL).mock(return_value=httpx.Response(200, json=[]))
    text = await call_tool_text(build(settings), "cnc_list_export_collection_jobs", {})
    assert text.startswith("Error: Collection jobs query: the collection service returned an ")
    assert "unexpected response shape: []" in text
    respx.post(JOBS_URL).mock(
        return_value=httpx.Response(
            200, content=b"null", headers={"content-type": "application/json"}
        )
    )
    text = await call_tool_text(build(settings), "cnc_list_export_collection_jobs", {})
    assert "unexpected response shape: None" in text
    respx.post(JOBS_URL).mock(return_value=httpx.Response(200, content=b""))
    text = await call_tool_text(build(settings), "cnc_list_export_collection_jobs", {})
    assert "unexpected response shape: None" in text


@respx.mock
async def test_query_bare_empty_500_names_the_empty_body(settings):
    """A 500 with an EMPTY body (the platform's 'backend absent / input unresolved' answer)
    surfaces errors.py's dedicated hint; 500 is not auto-retried."""
    route = respx.post(TEMPLATE_URL).mock(return_value=httpx.Response(500, text=""))
    text = await call_tool_text(build(settings), "cnc_list_sensor_templates", TEMPLATE_ARGS)
    assert text.startswith("Error: API request failed with status 500.")
    assert "EMPTY body" in text
    assert route.call_count == 1


# --- cnc_get_collection_job_summary -----------------------------------------------


@respx.mock
async def test_get_collection_job_summary_markdown(settings):
    route = mock(SUMMARY_URL, SUMMARY)
    text = await call_tool_text(build(settings), "cnc_get_collection_job_summary", {})
    assert sent(route) == {"application_context": DLM_CONTEXT, "query_options": DLM_QUERY_OPTIONS}
    assert text.startswith(
        f"# Collection job status for {DLM_APPLICATION_ID} / {DLM_CONTEXT_ID} (1)"
    )
    assert (
        f"- **{DLM_APPLICATION_ID} / {DLM_CONTEXT_ID}** status=READY phase=ACTIVE "
        "progress=100% collector=CLI_COLLECTOR created=2025-09-13T08:00:00Z deleted=-"
    ) in text
    assert " error=" not in text  # an empty job_error is not rendered


@respx.mock
async def test_get_collection_job_summary_json_and_page_size(settings):
    route = mock(SUMMARY_URL, SUMMARY)
    text = await call_tool_text(
        build(settings),
        "cnc_get_collection_job_summary",
        {
            "application_id": "cw.coe",
            "context_id": "coe/ctx",
            "page_size": 5,
            "response_format": "json",
        },
    )
    body = sent(route)
    assert body["application_context"] == {"application_id": "cw.coe", "context_id": "coe/ctx"}
    assert body["query_options"]["page_size"] == 5 and body["query_options"]["page_token"] == ""
    payload = json.loads(text)
    assert payload["count"] == 1 and payload["items"] == [JOB_STATUS]
    assert payload["application_id"] == "cw.coe" and payload["query_options"] is None
    assert payload["page_size"] == 5 and payload["page_token"] == ""
    assert {k: payload[k] for k in NO_PAGING_NOTE} == NO_PAGING_NOTE


@respx.mock
async def test_get_collection_job_summary_pages_by_token(settings):
    """A full page plus a new echoed token -> has_more; the token is sent back verbatim."""
    paged = {**SUMMARY, "query_options": {"page_token": "hash2", "page_size": 1}}
    route = mock(SUMMARY_URL, paged)
    text = await call_tool_text(
        build(settings),
        "cnc_get_collection_job_summary",
        {"page_size": 1, "response_format": "json"},
    )
    payload = json.loads(text)
    assert payload["has_more"] is True and payload["next_page_token"] == "hash2"
    assert payload["paging_note"] is None
    text = await call_tool_text(build(settings), "cnc_get_collection_job_summary", {"page_size": 1})
    more = "(more on server: call cnc_get_collection_job_summary again with page_token 'hash2'"
    assert more in text
    # Second page: the token goes out verbatim; the platform echoing it back on a full page
    # is no proof of the end -> has_more unknown (null) with a note.
    text = await call_tool_text(
        build(settings),
        "cnc_get_collection_job_summary",
        {"page_size": 1, "page_token": "hash2", "response_format": "json"},
    )
    assert sent(route, 2)["query_options"]["page_token"] == "hash2"
    payload = json.loads(text)
    assert payload["page_token"] == "hash2"
    assert payload["has_more"] is None and payload["next_page_token"] is None
    assert payload["paging_note"].startswith("page full (1 entries at page_size 1)")
    # A short page is never "more", whatever token is echoed (verified single-entry echo).
    text = await call_tool_text(
        build(settings), "cnc_get_collection_job_summary", {"response_format": "json"}
    )
    assert json.loads(text)["has_more"] is False
    assert "(more on server" not in await call_tool_text(
        build(settings), "cnc_get_collection_job_summary", {}
    )


@respx.mock
async def test_get_collection_job_summary_full_page_without_token_is_unknown(settings):
    """The verified summary answer carries no query_options: a full page then says
    has_more null plus a note, never a silent has_more false (all-jobs query truncation)."""
    route = mock(SUMMARY_URL, SUMMARY)
    text = await call_tool_text(
        build(settings),
        "cnc_get_collection_job_summary",
        {"application_id": "", "context_id": "", "page_size": 1, "response_format": "json"},
    )
    assert "application_context" not in sent(route)
    payload = json.loads(text)
    assert payload["application_id"] is None and payload["count"] == 1
    assert payload["has_more"] is None and payload["next_page_token"] is None
    assert payload["paging_note"] == (
        "page full (1 entries at page_size 1) and the platform echoed no new page token — "
        "more entries may exist; call again with a larger page_size"
    )
    text = await call_tool_text(
        build(settings),
        "cnc_get_collection_job_summary",
        {"application_id": "", "context_id": "", "page_size": 1},
    )
    assert text.startswith("# Collection job status for all collection jobs (1)")
    assert (
        "(page full (1 entries at page_size 1) and the platform echoed no new page token — "
        "more entries may exist; call again with a larger page_size on "
        "cnc_get_collection_job_summary.)"
    ) in text


@respx.mock
async def test_get_collection_job_summary_half_context_is_refused_without_a_call(settings):
    route = mock(SUMMARY_URL, SUMMARY)
    text = await call_tool_text(
        build(settings),
        "cnc_get_collection_job_summary",
        {"application_id": "cw.x", "context_id": " "},
    )
    assert text.startswith("Error: application_id and context_id go together")
    assert not route.called


@respx.mock
async def test_get_collection_job_summary_http_error_is_string(make_settings):
    respx.post(SUMMARY_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_collection_job_summary", {}
    )
    assert text.startswith("Error:") and "500" in text and "NATS request failed" in text


@respx.mock
async def test_get_collection_job_summary_renders_a_job_error(settings):
    failed = {**JOB_STATUS, "status": "FAILED", "job_error": {"error": "no device package"}}
    mock(SUMMARY_URL, {"collection_job_status_list": [failed], "result": ACCEPTED})
    text = await call_tool_text(build(settings), "cnc_get_collection_job_summary", {})
    assert "status=FAILED" in text and "error=no device package" in text


@respx.mock
async def test_get_collection_job_summary_empty_is_not_an_error(settings):
    mock(SUMMARY_URL, SUMMARY_EMPTY)
    text = await call_tool_text(build(settings), "cnc_get_collection_job_summary", {})
    assert text.startswith("No collection job status is reported for cw.dlminvmgr0 /")
    mock(SUMMARY_URL, {"result": ACCEPTED})  # the list key absent entirely
    text = await call_tool_text(
        build(settings), "cnc_get_collection_job_summary", {"response_format": "json"}
    )
    assert json.loads(text)["count"] == 0


@respx.mock
async def test_get_collection_job_summary_rejected_and_bad_page_size(settings):
    mock(SUMMARY_URL, rejected(SUMMARY_EMPTY))
    text = await call_tool_text(build(settings), "cnc_get_collection_job_summary", {})
    assert text == (
        "Error: Collection job summary query was REJECTED: application context not found"
    )
    with pytest.raises(ToolError):
        await call_tool_text(build(settings), "cnc_get_collection_job_summary", {"page_size": 0})


# --- cnc_get_collection_job_state -------------------------------------------------


@respx.mock
async def test_get_collection_job_state_markdown(settings):
    route = mock(STATE_URL, STATE)
    text = await call_tool_text(build(settings), "cnc_get_collection_job_state", {})
    assert sent(route) == {"application_context": DLM_CONTEXT, "query_options": DLM_QUERY_OPTIONS}
    assert text.startswith(
        f"# Collection job lifecycle state for {DLM_APPLICATION_ID} / {DLM_CONTEXT_ID} (1)"
    )
    assert (
        f"- **{DLM_APPLICATION_ID} / {DLM_CONTEXT_ID}** life-cycle=SUCCESS_LIFE_CYCLE_STATE "
        "created=2025-09-13T08:00:00Z evaluated=2025-09-13T09:00:00Z"
    ) in text


@respx.mock
async def test_get_collection_job_state_json_passes_the_opaque_token_through(settings):
    mock(STATE_URL, STATE)
    text = await call_tool_text(
        build(settings), "cnc_get_collection_job_state", {"response_format": "json"}
    )
    payload = json.loads(text)
    assert payload["count"] == 1 and payload["items"] == [LIFE_CYCLE]
    assert payload["query_options"]["page_token"] == "a7859eb217ee381541afe2f911dfd21c"
    assert payload["page_size"] == 50 and payload["page_full"] is False


@respx.mock
async def test_get_collection_job_state_full_first_page_is_flagged(settings):
    """Only the first page (50) is fetched: a full page says so instead of truncating silently."""
    mock(STATE_URL, {**STATE, "collection_life_cycle_states": [LIFE_CYCLE] * 50})
    text = await call_tool_text(
        build(settings),
        "cnc_get_collection_job_state",
        {"application_id": "", "context_id": "", "response_format": "json"},
    )
    payload = json.loads(text)
    assert payload["count"] == 50 and payload["page_full"] is True
    text = await call_tool_text(
        build(settings), "cnc_get_collection_job_state", {"application_id": "", "context_id": ""}
    )
    assert text.startswith("# Collection job lifecycle state for all collection jobs (50)")
    assert "(page full at 50 entries — this tool fetches only the first page" in text


@respx.mock
async def test_get_collection_job_state_empty_is_not_an_error(settings):
    mock(STATE_URL, STATE_EMPTY)
    text = await call_tool_text(build(settings), "cnc_get_collection_job_state", {})
    assert text.startswith("No collection job lifecycle state is reported for cw.dlminvmgr0 /")


@respx.mock
async def test_get_collection_job_state_half_context_is_refused_without_a_call(settings):
    route = mock(STATE_URL, STATE)
    text = await call_tool_text(
        build(settings), "cnc_get_collection_job_state", {"application_id": "", "context_id": "x"}
    )
    assert text.startswith("Error: application_id and context_id go together")
    assert not route.called


@respx.mock
async def test_get_collection_job_state_rejected_and_http_error(make_settings):
    mock(STATE_URL, rejected(STATE_EMPTY))
    text = await call_tool_text(build(make_settings()), "cnc_get_collection_job_state", {})
    assert text == "Error: Collection job state query was REJECTED: application context not found"
    respx.post(STATE_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_collection_job_state", {}
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_list_export_collection_jobs ----------------------------------------------


@respx.mock
async def test_list_export_collection_jobs_empty_lab_answer(settings):
    """The verified body: the platform's own page size 100 and first-page token "0" — the
    7.2 document says GetJobsRequest's query options are 'currently not utilized'."""
    route = mock(JOBS_URL, JOBS_EMPTY)
    text = await call_tool_text(build(settings), "cnc_list_export_collection_jobs", {})
    assert sent(route) == {
        "query_options": {
            "page_token": "0",
            "page_size": 100,
            "filter_list": [],
            "filter_query": "",
        }
    }
    assert text.startswith("No export collection jobs.")
    mock(JOBS_URL, {"result": ACCEPTED})  # no jobs key at all
    text = await call_tool_text(build(settings), "cnc_list_export_collection_jobs", {})
    assert text.startswith("No export collection jobs.")


async def test_list_export_collection_jobs_exposes_no_paging(make_settings):
    """No page_size / page_token: the document declares the query options unused."""
    tools = {t.name: t for t in await build(make_settings()).list_tools()}
    props = tools["cnc_list_export_collection_jobs"].input_schema["properties"]
    assert set(props) == {"response_format"}


@respx.mock
async def test_list_export_collection_jobs_renders_documented_jobs(settings):
    mock(JOBS_URL, JOBS)
    text = await call_tool_text(build(settings), "cnc_list_export_collection_jobs", {})
    assert text.startswith("# Collection service jobs (1)")
    assert "- **cw.export / export/1** type=EXPORT_COLLECTIONS status=JOB_COMPLETED" in text
    assert "(more on server" not in text and "(page full" not in text
    text = await call_tool_text(
        build(settings), "cnc_list_export_collection_jobs", {"response_format": "json"}
    )
    payload = json.loads(text)
    assert payload == {
        "count": 1,
        "items": [EXPORT_JOB],
        "query_options": {"page_token": "0", "page_size": 100, "filter_list": []},
    }


@respx.mock
async def test_list_export_collection_jobs_rejected_is_error(settings):
    mock(JOBS_URL, rejected(JOBS_EMPTY))
    text = await call_tool_text(build(settings), "cnc_list_export_collection_jobs", {})
    assert text == "Error: Collection jobs query was REJECTED: application context not found"


# --- cnc_list_sensor_templates ----------------------------------------------------


@respx.mock
async def test_list_sensor_templates_sends_template_id_and_empty_is_no_match(settings):
    """The body carries template_id next to query_options (7.2 document: required — 'if not
    specified, nothing is returned'); an empty list is "no match", not "no templates"."""
    route = mock(TEMPLATE_URL, TEMPLATES_EMPTY)
    text = await call_tool_text(
        build(settings), "cnc_list_sensor_templates", {"template_id": " show-interface "}
    )
    assert sent(route) == {
        "template_id": "show-interface",
        "query_options": {
            "page_token": "0",
            "page_size": 50,
            "filter_list": [],
            "filter_query": "",
        },
    }
    assert text.startswith("No sensor template matches 'show-interface'.")
    assert "REJECTED 'Template for the given TemplateId does not exist'" in text
    text = await call_tool_text(
        build(settings),
        "cnc_list_sensor_templates",
        {**TEMPLATE_ARGS, "response_format": "json"},
    )
    assert json.loads(text) == {
        "template_id": "show-interface",
        "count": 0,
        "items": [],
        "page_size": 50,
        "page_token": "0",
        **NO_PAGING_NOTE,
        "query_options": None,
    }


@respx.mock
async def test_list_sensor_templates_blank_template_id_is_refused_without_a_call(settings):
    route = mock(TEMPLATE_URL, TEMPLATES)
    tools = {t.name: t for t in await build(settings).list_tools()}
    assert "template_id" in tools["cnc_list_sensor_templates"].input_schema["required"]
    with pytest.raises(ToolError):  # schema: required, min_length 1
        await call_tool_text(build(settings), "cnc_list_sensor_templates", {})
    with pytest.raises(ToolError):
        await call_tool_text(build(settings), "cnc_list_sensor_templates", {"template_id": ""})
    text = await call_tool_text(build(settings), "cnc_list_sensor_templates", {"template_id": "  "})
    assert text.startswith("Error: cnc_list_sensor_templates needs a template_id")
    assert not route.called


@respx.mock
async def test_list_sensor_templates_pages_by_token(settings):
    route = mock(
        TEMPLATE_URL, {**TEMPLATES, "query_options": {"page_token": "tpl-2", "page_size": 2}}
    )
    text = await call_tool_text(
        build(settings),
        "cnc_list_sensor_templates",
        {**TEMPLATE_ARGS, "page_size": 2, "response_format": "json"},
    )
    payload = json.loads(text)
    assert payload["has_more"] is True and payload["next_page_token"] == "tpl-2"
    assert payload["paging_note"] is None
    text = await call_tool_text(
        build(settings),
        "cnc_list_sensor_templates",
        {**TEMPLATE_ARGS, "page_size": 2, "page_token": "tpl-2"},
    )
    assert sent(route, 1) == {
        "template_id": "show-interface",
        "query_options": {
            "page_token": "tpl-2",
            "page_size": 2,
            "filter_list": [],
            "filter_query": "",
        },
    }
    # The platform echoing the sent token back on a full page -> unknown, with a note.
    assert text.startswith("# Sensor templates matching 'show-interface' (2)")
    assert "(more on server" not in text
    assert "(page full (2 entries at page_size 2)" in text
    assert "on cnc_list_sensor_templates.)" in text
    # page_size larger than the page -> not full -> no more, even with a new token.
    text = await call_tool_text(
        build(settings),
        "cnc_list_sensor_templates",
        {**TEMPLATE_ARGS, "page_size": 10, "response_format": "json"},
    )
    assert json.loads(text)["has_more"] is False


@respx.mock
async def test_list_sensor_templates_renders_documented_templates(settings):
    mock(TEMPLATE_URL, TEMPLATES)
    text = await call_tool_text(
        build(settings), "cnc_list_sensor_templates", {**TEMPLATE_ARGS, "page_size": 10}
    )
    assert text.startswith("# Sensor templates matching 'show-interface' (2)")
    assert (
        "- **show-interface** type=CLI_COLLECTOR cadence=60000 ms definition: "
        "cli 'show interface {{interface_name}}' variables interface_name"
    ) in text
    assert (
        "- **gnmi-cpu** type=GNMI_COLLECTOR cadence=30000 ms definition: "
        "gnmi 'Cisco-IOS-XR-wdsysmon-fd-oper:system-monitoring/cpu-utilization'"
    ) in text


@respx.mock
async def test_list_sensor_templates_missing_template_is_no_match(settings):
    """Verified live (a lab without templates): any template_id, the wildcard '*' included,
    answers HTTP 200 REJECTED 'Template for the given TemplateId does not exist' with an
    empty list — the platform's "no match", reported as an empty result, not an error."""
    missing = {
        "sensor_templates": [],
        "result": {
            "request_result": "REJECTED",
            "error": {"error": "Template for the given TemplateId does not exist"},
        },
        "query_options": None,
    }
    mock(TEMPLATE_URL, missing)
    text = await call_tool_text(build(settings), "cnc_list_sensor_templates", {"template_id": "*"})
    assert text.startswith("No sensor template matches '*'.")
    text = await call_tool_text(
        build(settings),
        "cnc_list_sensor_templates",
        {"template_id": "*", "response_format": "json"},
    )
    payload = json.loads(text)
    assert payload["template_id"] == "*" and payload["count"] == 0 and payload["items"] == []


@respx.mock
async def test_list_sensor_templates_rejected_and_http_error(make_settings):
    mock(TEMPLATE_URL, rejected(TEMPLATES_EMPTY))
    text = await call_tool_text(build(make_settings()), "cnc_list_sensor_templates", TEMPLATE_ARGS)
    assert text == "Error: Sensor template query was REJECTED: application context not found"
    respx.post(TEMPLATE_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_list_sensor_templates", TEMPLATE_ARGS
    )
    assert text.startswith("Error:") and "500" in text and "NATS request failed" in text


# --- cnc_get_collection_health ----------------------------------------------------


@respx.mock
async def test_get_collection_health_combines_the_three_queries(settings):
    count_route = mock(COUNT_URL, COUNT)
    summary_route = mock(SUMMARY_URL, SUMMARY)
    state_route = mock(STATE_URL, STATE)
    text = await call_tool_text(build(settings), "cnc_get_collection_health", {})
    for route in (count_route, summary_route, state_route):
        assert route.call_count == 1
        assert sent(route)["application_context"] == DLM_CONTEXT
        assert sent(route)["query_options"]["page_token"] == ""
    payload = json.loads(text)
    assert payload["application_id"] == DLM_APPLICATION_ID
    assert payload["context_id"] == DLM_CONTEXT_ID
    assert payload["job_count"] == 1 and payload["device_count"] == 5
    assert payload["status"] == "READY" and payload["phase"] == "ACTIVE"
    assert payload["progress"] == 100 and payload["collector_type"] == "CLI_COLLECTOR"
    assert payload["life_cycle_state"] == "SUCCESS_LIFE_CYCLE_STATE"
    assert payload["state_evaluation_time"] == "1757754000000"
    assert payload["errors"] == {
        "job_errors": [],
        "input_error_collection_count": 0,
        "output_error_collection_count": 0,
        "control_error_count": 0,
    }
    assert payload["healthy"] is True
    assert payload["verdict"] == "Collection job READY/ACTIVE on 5 devices, lifecycle SUCCESS."


@respx.mock
async def test_get_collection_health_unhealthy_job(settings):
    mock(COUNT_URL, {**COUNT, "output_error_collection_count": "5"})
    mock(
        SUMMARY_URL,
        {"collection_job_status_list": [{**JOB_STATUS, "status": "NOTREADY"}], "result": ACCEPTED},
    )
    mock(
        STATE_URL,
        {
            **STATE,
            "collection_life_cycle_states": [
                {**LIFE_CYCLE, "life_cycle_state": "NO_DATA_LIFE_CYCLE_STATE"}
            ],
        },
    )
    text = await call_tool_text(build(settings), "cnc_get_collection_health", {})
    payload = json.loads(text)
    assert payload["healthy"] is False
    assert payload["verdict"] == (
        "Collection job NOTREADY/ACTIVE on 5 devices, lifecycle NO_DATA; "
        "5 collection error(s) — NOT healthy."
    )


@respx.mock
async def test_get_collection_health_several_jobs_under_one_context(settings):
    """Two summary entries: the first drives the verdict, both are kept, and the verdict
    says so."""
    second = {
        **JOB_STATUS,
        "status": "NOTREADY",
        "collector_type": "SNMP_COLLECTOR",
        "job_error": {"error": "snmp timeout"},
    }
    mock(COUNT_URL, {**COUNT, "job_count": "2"})
    mock(SUMMARY_URL, {"collection_job_status_list": [JOB_STATUS, second], "result": ACCEPTED})
    mock(STATE_URL, STATE)
    text = await call_tool_text(build(settings), "cnc_get_collection_health", {})
    payload = json.loads(text)
    assert payload["job_count"] == 2
    assert payload["status"] == "READY" and payload["collector_type"] == "CLI_COLLECTOR"
    assert payload["jobs"] == [JOB_STATUS, second]
    assert payload["errors"]["job_errors"] == ["snmp timeout"]
    assert payload["healthy"] is False
    assert payload["verdict"] == (
        "Collection job READY/ACTIVE on 5 devices, lifecycle SUCCESS (2 jobs under this "
        "context; first shown); job error: snmp timeout — NOT healthy."
    )
    healthy_pair = health_payload(DLM_CONTEXT, coerce_counts(COUNT), [JOB_STATUS, JOB_STATUS], [])
    assert "(2 jobs under this context; first shown)" in healthy_pair["verdict"]


@respx.mock
async def test_get_collection_health_no_job_is_a_verdict_not_an_error(settings):
    mock(COUNT_URL, COUNT_NONE)
    mock(SUMMARY_URL, SUMMARY_EMPTY)
    mock(STATE_URL, STATE_EMPTY)
    text = await call_tool_text(
        build(settings),
        "cnc_get_collection_health",
        {"application_id": "cw.nope", "context_id": "nope/ctx"},
    )
    payload = json.loads(text)
    assert payload["job_count"] == 0 and payload["healthy"] is False
    assert payload["verdict"].startswith("No collection job is registered for cw.nope / nope/ctx")


@respx.mock
async def test_get_collection_health_rejected_leg_is_error(settings):
    mock(COUNT_URL, COUNT)
    mock(SUMMARY_URL, rejected(SUMMARY_EMPTY))
    mock(STATE_URL, STATE)
    text = await call_tool_text(build(settings), "cnc_get_collection_health", {})
    assert text == (
        "Error: Collection job summary query was REJECTED: application context not found"
    )


@respx.mock
async def test_get_collection_health_blank_ids_are_refused_by_the_schema(settings):
    count_route = mock(COUNT_URL, COUNT)
    with pytest.raises(ToolError):
        await call_tool_text(
            build(settings), "cnc_get_collection_health", {"application_id": "", "context_id": ""}
        )
    assert not count_route.called
    text = await call_tool_text(
        build(settings), "cnc_get_collection_health", {"application_id": "  ", "context_id": " "}
    )
    assert text.startswith("Error: cnc_get_collection_health needs a collection job's")
    assert not count_route.called


@respx.mock
async def test_get_collection_health_http_error_is_string(make_settings):
    respx.post(COUNT_URL).mock(return_value=NATS_500)
    mock(SUMMARY_URL, SUMMARY)
    mock(STATE_URL, STATE)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_collection_health", {}
    )
    assert text.startswith("Error:") and "500" in text
