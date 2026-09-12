"""ApiClient behavior: retries, 401 re-auth, error mapping."""

from __future__ import annotations

import httpx
import pytest
import respx

from cnc_mcp.auth import LoginTokenAuth, StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.errors import PlatformError
from tests.conftest import BASE_URL


def make_client(settings, auth=None) -> ApiClient:
    return ApiClient(settings, auth or StaticTokenAuth("test-token"))


@respx.mock
async def test_retries_5xx_then_succeeds(settings):
    route = respx.get(f"{BASE_URL}/v1/thing").mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    client = make_client(settings)
    try:
        assert await client.request_json("GET", "/v1/thing") == {"ok": True}
        assert route.call_count == 2
    finally:
        await client.aclose()


@respx.mock
async def test_retries_429_honoring_retry_after(settings):
    route = respx.get(f"{BASE_URL}/v1/thing").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "0"}),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    client = make_client(settings)
    try:
        assert await client.request_json("GET", "/v1/thing") == {"ok": True}
        assert route.call_count == 2
    finally:
        await client.aclose()


@respx.mock
async def test_retries_exhausted_returns_last_error(make_settings):
    settings = make_settings(max_retries=1)
    respx.get(f"{BASE_URL}/v1/thing").mock(return_value=httpx.Response(503))
    client = make_client(settings)
    try:
        with pytest.raises(PlatformError, match="status 503"):
            await client.request_json("GET", "/v1/thing")
    finally:
        await client.aclose()


@respx.mock
async def test_transport_error_retried_then_fails_actionably(make_settings):
    settings = make_settings(max_retries=1)
    respx.get(f"{BASE_URL}/v1/thing").mock(side_effect=httpx.ConnectError("boom"))
    client = make_client(settings)
    try:
        with pytest.raises(PlatformError, match="Could not reach the platform"):
            await client.request_json("GET", "/v1/thing")
    finally:
        await client.aclose()


@respx.mock
async def test_404_maps_to_actionable_message(settings):
    respx.get(f"{BASE_URL}/v1/thing").mock(
        return_value=httpx.Response(404, json={"message": "no such thing"})
    )
    client = make_client(settings)
    try:
        with pytest.raises(PlatformError) as excinfo:
            await client.request_json("GET", "/v1/thing")
        message = str(excinfo.value)
        assert "404" in message and "no such thing" in message
    finally:
        await client.aclose()


@respx.mock
async def test_401_triggers_reauth_and_retry(make_settings):
    settings = make_settings(api_token="", username="admin", password="secret")
    respx.post(f"{BASE_URL}/auth/login").mock(
        side_effect=[
            httpx.Response(200, json={"token": "stale"}),
            httpx.Response(200, json={"token": "fresh"}),
        ]
    )
    api_route = respx.get(f"{BASE_URL}/v1/thing").mock(
        side_effect=[
            httpx.Response(401),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    auth = LoginTokenAuth(
        "/auth/login", "admin", "secret", login_style="json", token_location="json"
    )
    client = ApiClient(settings, auth)
    try:
        assert await client.request_json("GET", "/v1/thing") == {"ok": True}
        assert api_route.call_count == 2
        assert api_route.calls[1].request.headers["Authorization"] == "Bearer fresh"
    finally:
        await client.aclose()


@respx.mock
async def test_post_not_retried_on_5xx(make_settings):
    """A POST may already have been applied when a 5xx/timeout arrives — never re-send."""
    route = respx.post(f"{BASE_URL}/v1/thing").mock(
        side_effect=[httpx.Response(503), httpx.Response(201, json={"id": 1})]
    )
    client = make_client(make_settings())
    try:
        with pytest.raises(PlatformError, match="status 503"):
            await client.request_json("POST", "/v1/thing", json_body={})
        assert route.call_count == 1
    finally:
        await client.aclose()


@respx.mock
async def test_post_retried_on_429(settings):
    """429 means the platform rejected the request before processing: safe for POST."""
    route = respx.post(f"{BASE_URL}/v1/thing").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "0"}),
            httpx.Response(201, json={"id": 1}),
        ]
    )
    client = make_client(settings)
    try:
        assert await client.request_json("POST", "/v1/thing", json_body={}) == {"id": 1}
        assert route.call_count == 2
    finally:
        await client.aclose()


@respx.mock
async def test_post_opt_in_retry(settings):
    route = respx.post(f"{BASE_URL}/v1/thing").mock(
        side_effect=[httpx.Response(503), httpx.Response(201, json={"id": 1})]
    )
    client = make_client(settings)
    try:
        result = await client.request_json("POST", "/v1/thing", json_body={}, retryable=True)
        assert result == {"id": 1}
        assert route.call_count == 2
    finally:
        await client.aclose()


async def test_backoff_caps_server_supplied_retry_after(make_settings, monkeypatch):
    """A huge Retry-After must not stall the client: 30s cap applies before jitter."""
    settings = make_settings(retry_backoff_seconds=1.0)
    client = make_client(settings)
    slept: list[float] = []

    async def fake_sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr("cnc_mcp.client.asyncio.sleep", fake_sleep)
    try:
        await client._backoff(0, retry_after="3600")
        await client._backoff(9)  # deep exponential attempt
    finally:
        await client.aclose()
    assert all(delay <= 30.0 * 1.25 for delay in slept), slept


@respx.mock
async def test_non_json_response_raises_toolerror(settings):
    respx.get(f"{BASE_URL}/v1/thing").mock(
        return_value=httpx.Response(200, text="<html>login page</html>")
    )
    client = make_client(settings)
    try:
        with pytest.raises(PlatformError, match="non-JSON"):
            await client.request_json("GET", "/v1/thing")
    finally:
        await client.aclose()


@respx.mock
async def test_crosswork_403_unauthorized_request_triggers_reauth(make_settings):
    """Crosswork never answers 401: an expired JWT surfaces as 403 'Unauthorized request'.
    The client must let the strategy classify it and re-authenticate once."""
    from cnc_mcp.auth import CrossworkCasAuth

    settings = make_settings(api_token="", username="mcp-admin", password="secret")
    tickets = f"{BASE_URL}/crosswork/sso/v1/tickets"
    respx.post(tickets).mock(return_value=httpx.Response(201, text="TGT-1-x"))
    leg2 = respx.post(f"{tickets}/TGT-1-x").mock(
        side_effect=[
            httpx.Response(200, text="a.stale.jwt"),
            httpx.Response(200, text="a.fresh.jwt"),
        ]
    )
    api = respx.post(f"{BASE_URL}/crosswork/inventory/v1/nodes/query").mock(
        side_effect=[
            httpx.Response(403, json={"error": "Unauthorized request"}),
            httpx.Response(200, json={"data": []}),
        ]
    )
    client = ApiClient(settings, CrossworkCasAuth("mcp-admin", "secret"))
    try:
        result = await client.request_json(
            "POST", "/crosswork/inventory/v1/nodes/query", json_body={}
        )
        assert result == {"data": []}
        assert api.call_count == 2
        assert leg2.call_count == 2
        assert api.calls[1].request.headers["Authorization"] == "Bearer a.fresh.jwt"
    finally:
        await client.aclose()


@respx.mock
async def test_crosswork_genuine_403_does_not_reauth(make_settings):
    from cnc_mcp.auth import CrossworkCasAuth

    settings = make_settings(api_token="", username="mcp-admin", password="secret")
    tickets = f"{BASE_URL}/crosswork/sso/v1/tickets"
    respx.post(tickets).mock(return_value=httpx.Response(201, text="TGT-1-x"))
    leg2 = respx.post(f"{tickets}/TGT-1-x").mock(return_value=httpx.Response(200, text="a.b.c"))
    respx.get(f"{BASE_URL}/crosswork/aaa/v1/user").mock(
        return_value=httpx.Response(403, json={"error": "User lacks role for this operation"})
    )
    client = ApiClient(settings, CrossworkCasAuth("mcp-admin", "secret"))
    try:
        with pytest.raises(PlatformError, match="Permission denied"):
            await client.request_json("GET", "/crosswork/aaa/v1/user")
        assert leg2.call_count == 1  # logged in once; no re-auth storm on real RBAC denials
    finally:
        await client.aclose()


@pytest.mark.parametrize(
    ("status", "body", "fragment"),
    [
        (403, {"error": "Unauthorized request"}, "rejected the bearer token"),
        (403, {"error": "Missing Authorization header"}, "no bearer token"),
        (500, {"error": "Middleware error"}, "gateway rejected the bearer token"),
        (500, {"error": "NATS request failed"}, "malformed request body"),
        (500, {"error": "something else"}, "server error"),
        (403, {"error": "no such role"}, "Permission denied"),
    ],
)
def test_crosswork_error_hints(status, body, fragment):
    from cnc_mcp.errors import http_error

    msg = str(http_error(httpx.Response(status, json=body)))
    assert fragment in msg
    assert body["error"] in msg  # the platform's own words are preserved
