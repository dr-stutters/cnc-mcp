"""Auth strategies: header construction, login flows, 401 recovery."""

from __future__ import annotations

import base64

import httpx
import pytest
import respx

from cnc_mcp.auth import BasicAuth, LoginTokenAuth, StaticTokenAuth
from cnc_mcp.errors import PlatformError
from tests.conftest import BASE_URL


def test_basic_auth_header():
    auth = BasicAuth("admin", "secret")
    expected = base64.b64encode(b"admin:secret").decode()
    assert auth.headers() == {"Authorization": f"Basic {expected}"}


def test_basic_auth_requires_credentials():
    with pytest.raises(PlatformError):
        BasicAuth("admin", "")


def test_static_token_header_variants():
    assert StaticTokenAuth("tok").headers() == {"Authorization": "Bearer tok"}
    assert StaticTokenAuth("tok", header_name="X-Auth-Token", scheme=None).headers() == {
        "X-Auth-Token": "tok"
    }


@respx.mock
async def test_login_json_body_json_token():
    """Credentials as a JSON body; token in a JSON response field."""
    route = respx.post(f"{BASE_URL}/auth/login").mock(
        return_value=httpx.Response(200, json={"token": "abc123"})
    )
    auth = LoginTokenAuth(
        "/auth/login", "admin", "secret", login_style="json", token_location="json"
    )
    async with httpx.AsyncClient(base_url=BASE_URL) as http:
        await auth.ensure_authenticated(http)
    assert auth.headers() == {"Authorization": "Bearer abc123"}
    assert route.call_count == 1
    body = route.calls[0].request.content
    assert b'"username"' in body and b'"secret"' in body


@respx.mock
async def test_login_basic_header_token():
    """Basic auth on login; token arrives in a response header."""
    respx.post(f"{BASE_URL}/auth/generatetoken").mock(
        return_value=httpx.Response(204, headers={"X-auth-access-token": "hdr-tok"})
    )
    auth = LoginTokenAuth(
        "/auth/generatetoken",
        "admin",
        "secret",
        login_style="basic",
        token_location="header",
        token_field="X-auth-access-token",
        auth_header="X-auth-access-token",
        auth_scheme=None,
    )
    async with httpx.AsyncClient(base_url=BASE_URL) as http:
        await auth.ensure_authenticated(http)
    assert auth.headers() == {"X-auth-access-token": "hdr-tok"}


@respx.mock
async def test_login_body_token():
    """The whole response body is the token (a JSON-encoded string)."""
    respx.post(f"{BASE_URL}/api/v0/authenticate").mock(
        return_value=httpx.Response(200, json="jwt-token-value")
    )
    auth = LoginTokenAuth(
        "/api/v0/authenticate", "admin", "secret", login_style="json", token_location="body"
    )
    async with httpx.AsyncClient(base_url=BASE_URL) as http:
        await auth.ensure_authenticated(http)
    assert auth.headers() == {"Authorization": "Bearer jwt-token-value"}


@respx.mock
async def test_handle_unauthorized_relogs_in():
    route = respx.post(f"{BASE_URL}/auth/login").mock(
        side_effect=[
            httpx.Response(200, json={"token": "first"}),
            httpx.Response(200, json={"token": "second"}),
        ]
    )
    auth = LoginTokenAuth(
        "/auth/login", "admin", "secret", login_style="json", token_location="json"
    )
    async with httpx.AsyncClient(base_url=BASE_URL) as http:
        await auth.ensure_authenticated(http)
        assert auth.headers()["Authorization"] == "Bearer first"
        assert await auth.handle_unauthorized(http) is True
    assert auth.headers()["Authorization"] == "Bearer second"
    assert route.call_count == 2


@respx.mock
async def test_stale_401_does_not_discard_fresh_token():
    """A late 401 from a request that carried an already-replaced token must not
    trigger another login (re-login storm prevention)."""
    route = respx.post(f"{BASE_URL}/auth/login").mock(
        side_effect=[
            httpx.Response(200, json={"token": "t1"}),
            httpx.Response(200, json={"token": "t2"}),
            httpx.Response(200, json={"token": "t3"}),
        ]
    )
    auth = LoginTokenAuth(
        "/auth/login", "admin", "secret", login_style="json", token_location="json"
    )
    async with httpx.AsyncClient(base_url=BASE_URL) as http:
        await auth.ensure_authenticated(http)
        stale_headers = auth.headers()  # token t1
        assert await auth.handle_unauthorized(http, stale_headers) is True  # real expiry -> t2
        assert await auth.handle_unauthorized(http, stale_headers) is True  # late 401: no login
    assert auth.headers()["Authorization"] == "Bearer t2"
    assert route.call_count == 2


@respx.mock
async def test_login_rejected_raises_actionable_error():
    respx.post(f"{BASE_URL}/auth/login").mock(return_value=httpx.Response(401))
    auth = LoginTokenAuth(
        "/auth/login", "admin", "wrong", login_style="json", token_location="json"
    )
    async with httpx.AsyncClient(base_url=BASE_URL) as http:
        with pytest.raises(PlatformError, match="credentials were rejected"):
            await auth.ensure_authenticated(http)


@respx.mock
async def test_login_missing_token_raises():
    respx.post(f"{BASE_URL}/auth/login").mock(
        return_value=httpx.Response(200, json={"unexpected": "shape"})
    )
    auth = LoginTokenAuth(
        "/auth/login", "admin", "secret", login_style="json", token_location="json"
    )
    async with httpx.AsyncClient(base_url=BASE_URL) as http:
        with pytest.raises(PlatformError, match="no token"):
            await auth.ensure_authenticated(http)
