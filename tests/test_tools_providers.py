"""Provider tools end-to-end through MCPServer (schema validation included).

The module is registered directly (not through build_server) so the test does
not depend on tools/__init__.py's module list. All HTTP is mocked with respx.
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
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import providers
from cnc_mcp.tools.providers import parse_properties
from tests.conftest import BASE_URL, call_tool_text

PROVIDERS_URL = f"{BASE_URL}/crosswork/inventory/v1/providers"
QUERY_URL = f"{PROVIDERS_URL}/query"

PCE_UUID = "4f1c2d3e-0000-4000-8000-00000000pce1"
NSO_UUID = "4f1c2d3e-0000-4000-8000-00000000nso1"

PCE = {
    "uuid": PCE_UUID,
    "name": "cml-pce",
    "family": "ROBOT_PROVIDER_SR_PCE",
    "profile": "cml-xrd",
    "reachability_state": "CONN_STATE_REACHABLE",
    "connectivity_info": [
        {
            "type": "ROBOT_MSVC_TRANS_HTTP",
            "port": 8080,
            "timeout": 120,
            "ipaddrs": [{"inet_af": "ROBOT_INET_ADDR_TYPE_v4", "inet_addr": "198.18.140.15"}],
        }
    ],
    "properties": {"auto-onboard": "false"},
}
NSO = {
    "uuid": NSO_UUID,
    "name": "nso",
    "family": "ROBOT_PROVIDER_NSO",
    "profile": "nso",
    "reachability_state": "CONN_STATE_REACHABLE",
    "connectivity_info": [
        {
            "type": "ROBOT_MSVC_TRANS_SSH",
            "port": 2024,
            "fqdn": {"host_name": "enso", "domain_name": "default.svc.cluster.local"},
        },
        {
            "type": "ROBOT_MSVC_TRANS_HTTP",
            "port": 8080,
            "fqdn": {"host_name": "enso", "domain_name": "default.svc.cluster.local"},
        },
    ],
    "properties": {},
}
BOTH = {"data": [PCE, NSO], "total_count": 2, "result_count": 2}

NATS_500 = httpx.Response(500, json={"error": "NATS request failed"})


def filler(n: int) -> list[dict]:
    """``n`` distinct providers that match neither PCE's uuid nor its name."""
    return [{**NSO, "uuid": f"filler-{i:04d}", "name": f"filler-{i}"} for i in range(n)]


def query_body(filters: dict, page_size: int = 20, page: int = 0) -> dict:
    return {
        "filter": filters,
        "filterData": {"PageSize": page_size, "PageNum": page, "Criteria": ""},
    }


def job(state: str = "JOB_COMPLETED", **extra) -> dict:
    env = {
        "job_id": "job-1",
        "state": state,
        "type": "1 provider(s) added successfully",
        "created_by": "admin",
        "impacted": [f"{PCE_UUID} cml-pce"],
    }
    env.update(extra)
    return env


def build(settings: Settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    providers.register(mcp, ctx)
    return mcp


def sent(route: respx.Route, index: int = 0) -> dict:
    return json.loads(route.calls[index].request.content)


# --- registration / gating ---------------------------------------------------


async def test_write_tools_hidden_unless_enabled(make_settings):
    names = {t.name for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert names == {"cnc_list_providers", "cnc_get_provider"}
    names = {t.name for t in await build(make_settings(enable_writes=True)).list_tools()}
    assert names == {
        "cnc_list_providers",
        "cnc_get_provider",
        "cnc_create_provider",
        "cnc_update_provider",
        "cnc_delete_provider",
    }


async def test_annotations(make_settings):
    tools = {t.name: t for t in await build(make_settings(enable_writes=True)).list_tools()}
    assert tools["cnc_list_providers"].annotations.read_only_hint is True
    assert tools["cnc_create_provider"].annotations.read_only_hint is False
    assert tools["cnc_create_provider"].annotations.destructive_hint is False
    assert tools["cnc_delete_provider"].annotations.destructive_hint is True


# --- cnc_list_providers ------------------------------------------------------


@respx.mock
async def test_list_providers_markdown_and_body(settings):
    route = respx.post(QUERY_URL).mock(return_value=httpx.Response(200, json=BOTH))
    text = await call_tool_text(
        build(settings), "cnc_list_providers", {"family": "sr_pce", "page_size": 50, "page": 1}
    )
    assert sent(route) == query_body({"family": "ROBOT_PROVIDER_SR_PCE"}, page_size=50, page=1)
    assert "offset" not in route.calls[0].request.content.decode()
    assert f"**cml-pce** ({PCE_UUID})" in text
    assert "family=sr_pce" in text and "reachability=reachable" in text
    assert "http 198.18.140.15:8080" in text and "profile=cml-xrd" in text
    assert "ssh enso.default.svc.cluster.local:2024" in text  # fqdn endpoints rendered too
    assert "More available" not in text


@respx.mock
async def test_list_providers_json_envelope_pages_by_result_count(settings):
    route = respx.post(QUERY_URL).mock(
        return_value=httpx.Response(200, json={"data": [PCE], "total_count": 5, "result_count": 3})
    )
    text = await call_tool_text(
        build(settings),
        "cnc_list_providers",
        {"name": "*pce*", "page_size": 1, "response_format": "json"},
    )
    assert sent(route) == query_body({"name": "*pce*"}, page_size=1, page=0)
    data = json.loads(text)
    assert data["total"] == 3 and data["collection_total"] == 5
    assert data["count"] == 1 and data["has_more"] is True and data["next_page"] == 1
    assert data["items"][0]["uuid"] == PCE_UUID


@respx.mock
async def test_list_providers_empty_bare_envelope(settings):
    route = respx.post(QUERY_URL).mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(build(settings), "cnc_list_providers", {})
    assert sent(route) == query_body({}, page_size=20, page=0)
    assert "No providers matched" in text
    assert not text.startswith("Error:")


@respx.mock
async def test_list_providers_rejects_unknown_family_without_calling_api(settings):
    route = respx.post(QUERY_URL).mock(return_value=httpx.Response(200, json=BOTH))
    text = await call_tool_text(build(settings), "cnc_list_providers", {"family": "pcep"})
    assert text.startswith("Error:") and "Unknown provider family 'pcep'" in text
    assert "sr_pce" in text
    assert route.call_count == 0


@respx.mock
async def test_list_providers_api_error_is_string(make_settings):
    respx.post(QUERY_URL).mock(return_value=NATS_500)
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_list_providers", {})
    assert text.startswith("Error:") and "500" in text
    assert "malformed request body" in text


# --- cnc_get_provider --------------------------------------------------------


@respx.mock
async def test_get_provider_by_uuid_sends_no_filter(settings):
    # ``uuid`` is not a verified filter field on providers/query, so the lookup
    # sends an empty filter and matches client-side.
    route = respx.post(QUERY_URL).mock(
        return_value=httpx.Response(200, json={"data": [PCE], "total_count": 2})
    )
    text = await call_tool_text(build(settings), "cnc_get_provider", {"uuid": PCE_UUID})
    assert sent(route) == query_body({}, page_size=100, page=0)
    assert json.loads(text) == PCE


@respx.mock
async def test_get_provider_by_name_verifies_match_client_side(settings):
    # When more than one provider comes back (wildcard, or a filter Crosswork
    # ignored), the tool must still pick the exact-name match.
    route = respx.post(QUERY_URL).mock(return_value=httpx.Response(200, json=BOTH))
    text = await call_tool_text(build(settings), "cnc_get_provider", {"name": "NSO"})
    assert sent(route) == query_body({"name": "NSO"}, page_size=100, page=0)
    assert json.loads(text)["uuid"] == NSO_UUID


@respx.mock
async def test_get_provider_uuid_mismatch_is_not_found(settings):
    # A lone provider with a different uuid must not be returned as the match.
    route = respx.post(QUERY_URL).mock(
        return_value=httpx.Response(200, json={"data": [NSO], "total_count": 1, "result_count": 1})
    )
    text = await call_tool_text(build(settings), "cnc_get_provider", {"uuid": PCE_UUID})
    assert route.call_count == 1
    assert text.startswith("Error:") and f"No provider with uuid '{PCE_UUID}'" in text


@respx.mock
async def test_get_provider_pages_until_found(settings):
    # Page 0 is full but does not hold the target; result_count says there is
    # more, so page 1 must be fetched (same PageSize, PageNum 0 then 1).
    page0 = {"data": filler(100), "total_count": 101, "result_count": 101}
    page1 = {"data": [PCE], "total_count": 101, "result_count": 101}
    route = respx.post(QUERY_URL).mock(
        side_effect=[httpx.Response(200, json=page0), httpx.Response(200, json=page1)]
    )
    text = await call_tool_text(build(settings), "cnc_get_provider", {"uuid": PCE_UUID})
    assert route.call_count == 2
    assert sent(route, 0) == query_body({}, page_size=100, page=0)
    assert sent(route, 1) == query_body({}, page_size=100, page=1)
    assert json.loads(text) == PCE


@respx.mock
async def test_get_provider_stops_when_result_count_is_exhausted(settings):
    # A full page whose result_count says nothing follows must not trigger a
    # second request (has_more comes from result_count, not page fullness).
    route = respx.post(QUERY_URL).mock(
        return_value=httpx.Response(
            200, json={"data": filler(100), "total_count": 100, "result_count": 100}
        )
    )
    text = await call_tool_text(build(settings), "cnc_get_provider", {"name": "cml-pce"})
    assert route.call_count == 1
    assert text.startswith("Error:") and "No provider with name 'cml-pce'" in text


@respx.mock
async def test_get_provider_full_page_without_result_count_fetches_next_page(settings):
    # Without result_count the fallback is "the page came back full": fetch
    # page 1, and stop once an empty page comes back.
    route = respx.post(QUERY_URL).mock(
        side_effect=[
            httpx.Response(200, json={"data": filler(100), "total_count": 100}),
            httpx.Response(200, json={}),
        ]
    )
    text = await call_tool_text(build(settings), "cnc_get_provider", {"name": "cml-pce"})
    assert route.call_count == 2
    assert sent(route, 0) == query_body({"name": "cml-pce"}, page_size=100, page=0)
    assert sent(route, 1) == query_body({"name": "cml-pce"}, page_size=100, page=1)
    assert text.startswith("Error:") and "No provider with name 'cml-pce'" in text


@respx.mock
async def test_get_provider_not_found(settings):
    respx.post(QUERY_URL).mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(build(settings), "cnc_get_provider", {"name": "ghost"})
    assert text.startswith("Error:") and "No provider with name 'ghost'" in text


@pytest.mark.parametrize("args", [{}, {"uuid": PCE_UUID, "name": "cml-pce"}])
@respx.mock
async def test_get_provider_requires_exactly_one_selector(settings, args):
    route = respx.post(QUERY_URL).mock(return_value=httpx.Response(200, json=BOTH))
    text = await call_tool_text(build(settings), "cnc_get_provider", args)
    assert text.startswith("Error:") and "exactly one" in text
    assert route.call_count == 0


@respx.mock
async def test_get_provider_api_error_is_string(make_settings):
    respx.post(QUERY_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_provider", {"uuid": PCE_UUID}
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_create_provider -----------------------------------------------------


@respx.mock
async def test_create_provider_minimal_body(make_settings):
    route = respx.post(PROVIDERS_URL).mock(return_value=httpx.Response(200, json=job()))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_create_provider",
        {
            "name": "cml-pce",
            "family": "sr_pce",
            "credential_profile": "cml-xrd",
            "ip_address": "198.18.140.15",
        },
    )
    assert sent(route) == {
        "providers": [
            {
                "name": "cml-pce",
                "profile": "cml-xrd",
                "family": "ROBOT_PROVIDER_SR_PCE",
                "connectivity_info": [
                    {
                        "ipaddrs": [{"inet_af": 0, "inet_addr": "198.18.140.15"}],
                        "type": "ROBOT_MSVC_TRANS_HTTP",
                        "port": 8080,
                    }
                ],
                "properties": {},
            }
        ]
    }
    data = json.loads(text)
    assert data["state"] == "JOB_COMPLETED"
    assert data["impacted_objects"] == [{"uuid": PCE_UUID, "name": "cml-pce"}]


@respx.mock
async def test_create_provider_full_body(make_settings):
    route = respx.post(PROVIDERS_URL).mock(return_value=httpx.Response(200, json=job()))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_create_provider",
        {
            "name": "wae-1",
            "family": "ROBOT_PROVIDER_WAE",
            "credential_profile": "wae-creds",
            "ip_address": "10.0.0.9",
            "protocol": "https",
            "port": 8443,
            "timeout_seconds": 120,
            "properties": "auto-onboard=false, outgoing-interface=GigabitEthernet0/0/0/0",
        },
    )
    assert not text.startswith("Error:")
    body = sent(route)["providers"][0]
    assert body["family"] == "ROBOT_PROVIDER_WAE"
    assert body["connectivity_info"] == [
        {
            "ipaddrs": [{"inet_af": 0, "inet_addr": "10.0.0.9"}],
            "type": "ROBOT_MSVC_TRANS_HTTPS",
            "port": 8443,
            "timeout": 120,  # an int on the wire, like the verified nodes body
        }
    ]
    assert body["properties"] == {
        "auto-onboard": "false",
        "outgoing-interface": "GigabitEthernet0/0/0/0",
    }


@pytest.mark.parametrize(
    ("args", "marker"),
    [
        ({"family": "pcep"}, "Unknown provider family"),
        ({"protocol": "carrier-pigeon"}, "Unknown protocol"),
        ({"ip_address": "pce.example.test"}, "not a valid IP address"),
        ({"properties": "auto-onboard"}, "Invalid properties entry"),
    ],
)
@respx.mock
async def test_create_provider_validation_errors_skip_api(make_settings, args, marker):
    route = respx.post(PROVIDERS_URL).mock(return_value=httpx.Response(200, json=job()))
    base = {
        "name": "cml-pce",
        "family": "sr_pce",
        "credential_profile": "cml-xrd",
        "ip_address": "198.18.140.15",
    }
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_create_provider", {**base, **args}
    )
    assert text.startswith("Error:") and marker in text
    assert route.call_count == 0


@respx.mock
async def test_create_provider_failed_job_is_error_not_exception(make_settings):
    respx.post(PROVIDERS_URL).mock(
        return_value=httpx.Response(
            200,
            json=job(
                "JOB_FAILED",
                type="1 provider(s) addition failed",
                error="Provider with name cml-pce already exists",
            ),
        )
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_create_provider",
        {
            "name": "cml-pce",
            "family": "sr_pce",
            "credential_profile": "cml-xrd",
            "ip_address": "198.18.140.15",
        },
    )
    assert text.startswith("Error:")
    assert "JOB_FAILED" in text and "already exists" in text


CREATE_ARGS = {
    "name": "cml-pce",
    "family": "sr_pce",
    "credential_profile": "cml-xrd",
    "ip_address": "198.18.140.15",
}


@respx.mock
async def test_create_provider_500_is_error_string(make_settings):
    respx.post(PROVIDERS_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=0)),
        "cnc_create_provider",
        CREATE_ARGS,
    )
    assert text.startswith("Error:") and "500" in text
    assert "malformed request body" in text


@respx.mock
async def test_create_provider_503_not_retried(make_settings):
    # 503 is in ApiClient.RETRYABLE_STATUS, so this only stays at one call if
    # the tool leaves the POST non-retryable (a 500 would never be retried for
    # any method and proves nothing).
    route = respx.post(PROVIDERS_URL).mock(
        return_value=httpx.Response(503, json={"error": "service unavailable"})
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=3)),
        "cnc_create_provider",
        CREATE_ARGS,
    )
    assert text.startswith("Error:") and "503" in text
    assert route.call_count == 1  # a POST must never be re-sent automatically


# --- cnc_update_provider -----------------------------------------------------


@respx.mock
async def test_update_provider_patch_body(make_settings):
    route = respx.patch(PROVIDERS_URL).mock(
        return_value=httpx.Response(
            200, json=job(type="1 provider(s) details patched successfully")
        )
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_update_provider",
        {"uuid": PCE_UUID, "credential_profile": "cml-xrd-2", "properties": "auto-onboard=true"},
    )
    assert sent(route) == {
        "providers": [
            {"uuid": PCE_UUID, "profile": "cml-xrd-2", "properties": {"auto-onboard": "true"}}
        ]
    }
    assert json.loads(text)["state"] == "JOB_COMPLETED"


@respx.mock
async def test_update_provider_rename_only(make_settings):
    route = respx.patch(PROVIDERS_URL).mock(return_value=httpx.Response(200, json=job()))
    await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_update_provider",
        {"uuid": PCE_UUID, "name": "cml-pce-2"},
    )
    assert sent(route) == {"providers": [{"uuid": PCE_UUID, "name": "cml-pce-2"}]}


@respx.mock
async def test_update_provider_requires_a_change(make_settings):
    route = respx.patch(PROVIDERS_URL).mock(return_value=httpx.Response(200, json=job()))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_update_provider", {"uuid": PCE_UUID}
    )
    assert text.startswith("Error:") and "Nothing to update" in text
    assert route.call_count == 0


@respx.mock
async def test_update_provider_failed_job_is_error(make_settings):
    respx.patch(PROVIDERS_URL).mock(
        return_value=httpx.Response(
            200, json=job("JOB_FAILED", error="Provider not found for uuid")
        )
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_update_provider",
        {"uuid": "nope", "name": "x"},
    )
    assert text.startswith("Error:") and "Provider not found" in text


# --- cnc_delete_provider -----------------------------------------------------


@respx.mock
async def test_delete_provider_sends_json_body(make_settings):
    route = respx.delete(PROVIDERS_URL).mock(
        return_value=httpx.Response(200, json=job(type="1 provider(s) deleted successfully"))
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_delete_provider", {"uuid": PCE_UUID}
    )
    assert sent(route) == {"providers": [{"uuid": PCE_UUID}]}
    data = json.loads(text)
    assert data["state"] == "JOB_COMPLETED"
    assert data["impacted_objects"][0]["uuid"] == PCE_UUID


@respx.mock
async def test_delete_provider_failed_job_is_error(make_settings):
    respx.delete(PROVIDERS_URL).mock(
        return_value=httpx.Response(
            200,
            json=job(
                "JOB_FAILED", type="1 provider(s) deletion failed", error="Provider is in use"
            ),
        )
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_delete_provider", {"uuid": PCE_UUID}
    )
    assert text.startswith("Error:") and "in use" in text


@respx.mock
async def test_delete_provider_non_envelope_response_is_error(make_settings):
    respx.delete(PROVIDERS_URL).mock(return_value=httpx.Response(200, json={"data": []}))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_delete_provider", {"uuid": PCE_UUID}
    )
    assert text.startswith("Error:") and "did not return a job envelope" in text


# --- helpers -----------------------------------------------------------------


def test_parse_properties():
    assert parse_properties(None) == {}
    assert parse_properties("  ") == {}
    assert parse_properties("a=1, b = x=y ,,") == {"a": "1", "b": "x=y"}
