"""Auth strategies: header construction, login flows, 401 recovery."""

from __future__ import annotations

import base64
import json

import httpx
import pytest
import respx

from cnc_mcp.auth import (
    AuthStrategy,
    BasicAuth,
    CrossworkCasAuth,
    LoginTokenAuth,
    NoAuth,
    StaticTokenAuth,
    jwt_claims,
)
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


# --- CrossworkCasAuth: the real strategy for this server ---------------------------

TICKETS = f"{BASE_URL}/crosswork/sso/v1/tickets"
JWT = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJtY3AtYWRtaW4ifQ.sig"


def _mock_cas(tgt: str = "TGT-1-abc", jwt: str = JWT):
    """Mock both CAS legs; returns (leg1_route, leg2_route)."""
    leg1 = respx.post(TICKETS).mock(
        return_value=httpx.Response(
            201, text=tgt, headers={"Location": f"https://internal:5489/tickets/{tgt}"}
        )
    )
    leg2 = respx.post(f"{TICKETS}/{tgt}").mock(return_value=httpx.Response(200, text=jwt))
    return leg1, leg2


@respx.mock
async def test_crosswork_two_leg_login_yields_bearer_jwt():
    leg1, leg2 = _mock_cas()
    auth = CrossworkCasAuth("mcp-admin", "secret")
    async with httpx.AsyncClient(base_url=BASE_URL) as http:
        await auth.ensure_authenticated(http)
    assert auth.headers() == {"Authorization": f"Bearer {JWT}"}
    # Leg 1: form-urlencoded credentials, not JSON and not HTTP Basic.
    req1 = leg1.calls[0].request
    assert req1.headers["Content-Type"].startswith("application/x-www-form-urlencoded")
    assert b"username=mcp-admin" in req1.content and b"password=secret" in req1.content
    assert "Authorization" not in req1.headers
    # Leg 2: the service URL is derived from base_url and becomes the JWT audience.
    req2 = leg2.calls[0].request
    assert b"service=" in req2.content
    assert BASE_URL.replace(":", "%3A").replace("/", "%2F").encode() in req2.content
    assert b"app-dashboard" in req2.content


@respx.mock
async def test_crosswork_does_not_follow_internal_location():
    """Leg 1's Location header points at an internal port; it must never be requested."""
    _mock_cas()
    internal = respx.post("https://internal:5489/tickets/TGT-1-abc").mock(
        return_value=httpx.Response(200, text="should-not-be-called")
    )
    auth = CrossworkCasAuth("mcp-admin", "secret")
    async with httpx.AsyncClient(base_url=BASE_URL) as http:
        await auth.ensure_authenticated(http)
    assert internal.call_count == 0


@respx.mock
async def test_crosswork_bad_credentials_message_mentions_nonexistent_user():
    respx.post(TICKETS).mock(
        return_value=httpx.Response(
            401, json={"authentication_exceptions": ["Invalid credentials"]}
        )
    )
    auth = CrossworkCasAuth("nobody", "wrong")
    async with httpx.AsyncClient(base_url=BASE_URL) as http:
        with pytest.raises(PlatformError, match="does not exist"):
            await auth.ensure_authenticated(http)


@respx.mock
async def test_crosswork_non_tgt_body_is_actionable():
    respx.post(TICKETS).mock(return_value=httpx.Response(200, text="<html>login page</html>"))
    auth = CrossworkCasAuth("mcp-admin", "secret")
    async with httpx.AsyncClient(base_url=BASE_URL) as http:
        with pytest.raises(PlatformError, match="ticket-granting ticket"):
            await auth.ensure_authenticated(http)


@respx.mock
async def test_crosswork_leg2_failure_is_actionable():
    respx.post(TICKETS).mock(return_value=httpx.Response(201, text="TGT-1-abc"))
    respx.post(f"{TICKETS}/TGT-1-abc").mock(return_value=httpx.Response(404))
    auth = CrossworkCasAuth("mcp-admin", "secret")
    async with httpx.AsyncClient(base_url=BASE_URL) as http:
        with pytest.raises(PlatformError, match="service-ticket exchange failed"):
            await auth.ensure_authenticated(http)


@respx.mock
async def test_crosswork_non_jwt_service_ticket_is_rejected():
    respx.post(TICKETS).mock(return_value=httpx.Response(201, text="TGT-1-abc"))
    respx.post(f"{TICKETS}/TGT-1-abc").mock(return_value=httpx.Response(200, text="ST-9-plain"))
    auth = CrossworkCasAuth("mcp-admin", "secret")
    async with httpx.AsyncClient(base_url=BASE_URL) as http:
        with pytest.raises(PlatformError, match="not a JWT"):
            await auth.ensure_authenticated(http)


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (401, None, True),
        (403, {"error": "Missing Authorization header"}, True),
        (403, {"error": "Unauthorized request"}, True),
        (500, {"error": "Middleware error"}, True),
        # Genuine permission denial and genuine server faults must NOT re-auth.
        (403, {"error": "User lacks role for this operation"}, False),
        (500, {"error": "NATS request failed"}, False),
        (500, None, False),
        (404, {"error": "Unauthorized request"}, False),
        (200, {"error": "Unauthorized request"}, False),
    ],
)
def test_crosswork_is_auth_failure_matrix(status, body, expected):
    auth = CrossworkCasAuth("mcp-admin", "secret")
    response = httpx.Response(status, json=body) if body is not None else httpx.Response(status)
    assert auth.is_auth_failure(response) is expected


def test_default_strategy_only_treats_401_as_auth_failure():
    auth = StaticTokenAuth("tok")
    assert auth.is_auth_failure(httpx.Response(401)) is True
    denied = httpx.Response(403, json={"error": "Unauthorized request"})
    assert auth.is_auth_failure(denied) is False


@respx.mock
async def test_crosswork_logout_deletes_the_tgt_and_forgets_the_token():
    """Crosswork caps concurrent sessions per user: closing must release the SSO session."""
    _mock_cas()
    delete = respx.delete(f"{TICKETS}/TGT-1-abc").mock(return_value=httpx.Response(200))
    auth = CrossworkCasAuth("mcp-admin", "secret")
    async with httpx.AsyncClient(base_url=BASE_URL) as http:
        await auth.ensure_authenticated(http)
        await auth.logout(http)
        await auth.logout(http)  # idempotent: nothing to release the second time
    assert delete.call_count == 1
    # verified live: without the Bearer JWT the delete answers 400 and the session stays
    assert delete.calls[0].request.headers["Authorization"] == f"Bearer {JWT}"
    assert auth.headers() == {}


@respx.mock
async def test_crosswork_relogin_releases_the_rejected_session_first():
    """A 403 'Unauthorized request' also answers an unknown path or a missing role grant
    with a perfectly valid JWT, so the re-login it triggers must DELETE the current TGT
    (with that JWT — the only form Crosswork accepts) before opening a new session;
    otherwise every such re-login leaks one session towards the per-user cap."""
    leg1 = respx.post(TICKETS).mock(
        side_effect=[httpx.Response(201, text="TGT-1-abc"), httpx.Response(201, text="TGT-2-def")]
    )
    respx.post(f"{TICKETS}/TGT-1-abc").mock(return_value=httpx.Response(200, text="a.old.jwt"))
    respx.post(f"{TICKETS}/TGT-2-def").mock(return_value=httpx.Response(200, text="a.new.jwt"))
    delete_old = respx.delete(f"{TICKETS}/TGT-1-abc").mock(return_value=httpx.Response(200))
    delete_new = respx.delete(f"{TICKETS}/TGT-2-def").mock(return_value=httpx.Response(200))
    auth = CrossworkCasAuth("mcp-admin", "secret")
    async with httpx.AsyncClient(base_url=BASE_URL) as http:
        await auth.ensure_authenticated(http)
        assert auth.headers() == {"Authorization": "Bearer a.old.jwt"}
        assert await auth.handle_unauthorized(http, {"Authorization": "Bearer a.old.jwt"})
        assert auth.headers() == {"Authorization": "Bearer a.new.jwt"}
        assert delete_old.call_count == 1 and delete_new.call_count == 0
        assert delete_old.calls[0].request.headers["Authorization"] == "Bearer a.old.jwt"
        assert leg1.call_count == 2
        await auth.logout(http)  # closing releases the NEW session, exactly once
    assert delete_old.call_count == 1 and delete_new.call_count == 1


@respx.mock
async def test_crosswork_relogin_proceeds_when_the_release_fails():
    """A failed DELETE (the session may already be gone) never blocks the re-login."""
    respx.post(TICKETS).mock(
        side_effect=[httpx.Response(201, text="TGT-1-abc"), httpx.Response(201, text="TGT-2-def")]
    )
    respx.post(f"{TICKETS}/TGT-1-abc").mock(return_value=httpx.Response(200, text="a.old.jwt"))
    respx.post(f"{TICKETS}/TGT-2-def").mock(return_value=httpx.Response(200, text="a.new.jwt"))
    delete_old = respx.delete(f"{TICKETS}/TGT-1-abc").mock(
        return_value=httpx.Response(403, json={"error": "Your session has ended."})
    )
    auth = CrossworkCasAuth("mcp-admin", "secret")
    async with httpx.AsyncClient(base_url=BASE_URL) as http:
        await auth.ensure_authenticated(http)
        assert await auth.handle_unauthorized(http, {"Authorization": "Bearer a.old.jwt"})
    assert delete_old.call_count == 1
    assert auth.headers() == {"Authorization": "Bearer a.new.jwt"}
    assert auth._tgt == "TGT-2-def"


@respx.mock
async def test_crosswork_logout_never_raises():
    _mock_cas()
    respx.delete(f"{TICKETS}/TGT-1-abc").mock(side_effect=httpx.ConnectError("gone"))
    auth = CrossworkCasAuth("mcp-admin", "secret")
    async with httpx.AsyncClient(base_url=BASE_URL) as http:
        await auth.ensure_authenticated(http)
        await auth.logout(http)  # must not raise
    assert not auth._tgt


async def test_crosswork_logout_without_login_is_a_noop():
    auth = CrossworkCasAuth("mcp-admin", "secret")
    async with httpx.AsyncClient(base_url=BASE_URL) as http:
        await auth.logout(http)


@respx.mock
async def test_crosswork_session_limit_503_is_explained():
    # Verified live: leg 1 answers 503 with this body once the user's session cap is hit.
    respx.post(TICKETS).mock(
        return_value=httpx.Response(
            503,
            json={
                "error": (
                    "Per user session limit reached. Close unused sessions or try after sometime."
                )
            },
        )
    )
    auth = CrossworkCasAuth("mcp-admin", "secret")
    async with httpx.AsyncClient(base_url=BASE_URL) as http:
        with pytest.raises(PlatformError, match="concurrent-session limit"):
            await auth.ensure_authenticated(http)


@respx.mock
async def test_crosswork_terminated_session_403_is_an_auth_failure():
    # verified live: after the TGT is deleted (or an admin ends the session) every call
    # answers 403 "Your session has ended..." — the client must log in again, not give up
    auth = CrossworkCasAuth("mcp-admin", "secret")
    ended = httpx.Response(
        403, json={"error": "Your session has ended. Log into the system again to continue."}
    )
    assert auth.is_auth_failure(ended)
    denied = httpx.Response(403, json={"error": "Permission denied for role"})
    assert not auth.is_auth_failure(denied)


# --- identity: bearer_token() and jwt_claims() -------------------------------------------


def b64url(data: bytes) -> str:
    """base64url without padding, as JWTs encode their parts."""
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def make_jwt(claims: dict) -> str:
    header = b64url(b'{"alg":"HS512","typ":"JWT"}')
    return f"{header}.{b64url(json.dumps(claims).encode())}.c2ln"


def test_jwt_claims_decodes_the_payload_without_the_key():
    claims = {
        "sub": "mcp-ro",
        "username": "mcp-ro",
        "policy_id": "cnc-mcp-readonly",
        "deviceAccessGroups": "ALL-ACCESS",
        "exp": 1789500000,
        "iat": 1789471200,
        "iss": "https://cnc.example.test/crosswork/sso",
    }
    assert jwt_claims(make_jwt(claims)) == claims


@pytest.mark.parametrize("length", range(1, 8))
def test_jwt_claims_restores_dropped_padding(length):
    # Payloads of every length modulo 4 (JWT encoding drops the '=' padding).
    claims = {"sub": "x" * length}
    assert jwt_claims(make_jwt(claims)) == claims


@pytest.mark.parametrize(
    "token",
    [
        None,
        "",
        "not-a-jwt",
        "only.two",
        "a.b.c.d",
        "header.!!!not-base64!!!.sig",
        f"h.{b64url(b'not json')}.s",
        f"h.{b64url(b'[1, 2, 3]')}.s",  # valid JSON, not an object
        "TGT-123-abc-cas",  # a CAS ticket-granting ticket, not a JWT
    ],
)
def test_jwt_claims_rejects_garbage_and_non_jwts(token):
    assert jwt_claims(token) is None


def test_bearer_token_per_strategy():
    assert AuthStrategy().bearer_token() is None
    assert NoAuth().bearer_token() is None
    assert BasicAuth("u", "p").bearer_token() is None
    assert StaticTokenAuth("tok").bearer_token() == "tok"
    login = LoginTokenAuth("/auth/login", "u", "p")
    assert login.bearer_token() is None  # never logs in on its own
    cas = CrossworkCasAuth("mcp-admin", "secret")
    assert cas.bearer_token() is None


@respx.mock
async def test_bearer_token_after_crosswork_login_is_the_jwt():
    jwt = make_jwt({"sub": "mcp-admin", "policy_id": "admin"})
    respx.post(TICKETS).mock(return_value=httpx.Response(201, text="TGT-1-abc-cas"))
    respx.post(f"{TICKETS}/TGT-1-abc-cas").mock(return_value=httpx.Response(200, text=jwt))
    auth = CrossworkCasAuth("mcp-admin", "secret")
    async with httpx.AsyncClient(base_url=BASE_URL) as http:
        await auth.ensure_authenticated(http)
    assert auth.bearer_token() == jwt
    assert jwt_claims(auth.bearer_token()) == {"sub": "mcp-admin", "policy_id": "admin"}
