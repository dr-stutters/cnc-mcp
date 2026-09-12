"""Example tools end-to-end through MCPServer (schema validation included)."""

from __future__ import annotations

import json

import httpx
import respx

from cnc_mcp.server import build_server
from tests.conftest import BASE_URL, call_tool_text

WIDGETS = {
    "total": 3,
    "items": [
        {"id": "w-1", "name": "edge-router", "description": "Edge box"},
        {"id": "w-2", "name": "core-switch", "description": ""},
    ],
}


@respx.mock
async def test_list_widgets_markdown(settings):
    respx.get(f"{BASE_URL}/v1/widgets").mock(return_value=httpx.Response(200, json=WIDGETS))
    mcp = build_server(settings)
    text = await call_tool_text(mcp, "cnc_list_widgets", {"limit": 2, "offset": 0})
    assert "edge-router" in text and "(w-1)" in text
    assert "offset=2" in text  # has_more hint: 2 of 3 shown


@respx.mock
async def test_list_widgets_json_envelope(settings):
    respx.get(f"{BASE_URL}/v1/widgets").mock(return_value=httpx.Response(200, json=WIDGETS))
    mcp = build_server(settings)
    text = await call_tool_text(
        mcp, "cnc_list_widgets", {"limit": 2, "offset": 0, "response_format": "json"}
    )
    data = json.loads(text)
    assert data["total"] == 3
    assert data["count"] == 2
    assert data["has_more"] is True
    assert data["next_offset"] == 2


@respx.mock
async def test_list_widgets_passes_filter(settings):
    route = respx.get(f"{BASE_URL}/v1/widgets").mock(
        return_value=httpx.Response(200, json={"total": 0, "items": []})
    )
    mcp = build_server(settings)
    await call_tool_text(mcp, "cnc_list_widgets", {"name_filter": "edge"})
    assert route.calls[0].request.url.params["name"] == "edge"


@respx.mock
async def test_get_widget_error_is_string_not_exception(make_settings):
    settings = make_settings(max_retries=0)
    respx.get(f"{BASE_URL}/v1/widgets/w-404").mock(return_value=httpx.Response(404))
    mcp = build_server(settings)
    text = await call_tool_text(mcp, "cnc_get_widget", {"widget_id": "w-404"})
    assert text.startswith("Error:")
    assert "404" in text


@respx.mock
async def test_create_widget_when_writes_enabled(make_settings):
    settings = make_settings(enable_writes=True)
    route = respx.post(f"{BASE_URL}/v1/widgets").mock(
        return_value=httpx.Response(201, json={"id": "w-9", "name": "new-widget"})
    )
    mcp = build_server(settings)
    text = await call_tool_text(mcp, "cnc_create_widget", {"name": "new-widget"})
    assert json.loads(text)["id"] == "w-9"
    assert json.loads(route.calls[0].request.content) == {"name": "new-widget"}


@respx.mock
async def test_truncation_applied(make_settings):
    settings = make_settings(max_response_chars=1_000)
    big = {
        "total": 1,
        "items": [{"id": "w-1", "name": "x" * 5_000, "description": ""}],
    }
    respx.get(f"{BASE_URL}/v1/widgets").mock(return_value=httpx.Response(200, json=big))
    mcp = build_server(settings)
    text = await call_tool_text(mcp, "cnc_list_widgets", {})
    assert "[Truncated:" in text
    assert len(text) < 1_500
