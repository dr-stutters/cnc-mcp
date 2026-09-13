"""Pluggable authentication strategies for platform APIs.

Pick (or subclass) one in ``server.create_auth()`` during specialization:

- BasicAuth        -> HTTP Basic on every request (no session state).
- StaticTokenAuth  -> a pre-issued long-lived token from configuration.
- LoginTokenAuth   -> POST to a login endpoint, cache the token, re-login on
                      401. Covers most session-token schemes via configuration:
                      credentials sent as HTTP Basic or a JSON body; token
                      extracted from a JSON field, a response header, or the
                      raw response body; presented in any header with any
                      scheme prefix. Subclass its hooks when the platform
                      returns extra session state on login.
- CrossworkCasAuth -> the real strategy for this server: Cisco Crosswork's
                      two-leg CAS SSO (ticket-granting ticket -> service
                      ticket, which is a JWT), presented as a Bearer token.

Every strategy decides what an auth failure looks like via is_auth_failure();
ApiClient calls handle_unauthorized() once per request when it fires, so
expired tokens are transparently re-acquired.
"""

from __future__ import annotations

import asyncio
import base64
import logging

import httpx

from cnc_mcp.errors import PlatformError

logger = logging.getLogger(__name__)


class AuthStrategy:
    """Base class for authentication strategies. Override only what the platform needs;
    the defaults are correct for stateless schemes."""

    async def ensure_authenticated(self, http: httpx.AsyncClient) -> None:
        """Acquire credentials if needed. Called before every request (must be cheap)."""

    def headers(self) -> dict[str, str]:
        """Headers to attach to every API request."""
        return {}

    def is_auth_failure(self, response: httpx.Response) -> bool:
        """Does this response mean 'credentials were not accepted'?

        ApiClient consults this once per request and, if True, calls
        handle_unauthorized() and retries. The default (401 only) is right for
        well-behaved platforms; override when a gateway hides auth failures
        behind other status codes.
        """
        return response.status_code == 401

    async def handle_unauthorized(
        self, http: httpx.AsyncClient, failed_headers: dict[str, str] | None = None
    ) -> bool:
        """Called once after an auth failure, with the auth headers the failed
        request carried.

        Return True if the request is worth retrying.
        """
        return False

    def invalidate(self) -> None:
        """Drop any cached credentials/tokens."""

    async def logout(self, http: httpx.AsyncClient) -> None:
        """Release the platform-side session, if the scheme has one.

        Called by ApiClient.aclose(). Must never raise: a failed logout is
        logged and forgotten, since the caller is shutting down anyway.
        """


class NoAuth(AuthStrategy):
    """No authentication (rare; useful for local mocks)."""


class BasicAuth(AuthStrategy):
    """HTTP Basic on every request (stateless; nothing cached)."""

    def __init__(self, username: str, password: str) -> None:
        if not username or not password:
            raise PlatformError(
                "Basic auth requires both username and password. "
                "Set the *_USERNAME and *_PASSWORD environment variables."
            )
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        self._header_value = f"Basic {credentials}"

    def headers(self) -> dict[str, str]:
        return {"Authorization": self._header_value}

    async def handle_unauthorized(
        self, http: httpx.AsyncClient, failed_headers: dict[str, str] | None = None
    ) -> bool:
        # Static credentials were rejected; retrying with the same ones is pointless.
        return False


class StaticTokenAuth(AuthStrategy):
    """A pre-issued, long-lived token from configuration."""

    def __init__(
        self,
        token: str,
        header_name: str = "Authorization",
        scheme: str | None = "Bearer",
    ) -> None:
        if not token:
            raise PlatformError("Static token auth requires the *_API_TOKEN environment variable.")
        self._header_name = header_name
        self._value = f"{scheme} {token}" if scheme else token

    def headers(self) -> dict[str, str]:
        return {self._header_name: self._value}


class LoginTokenAuth(AuthStrategy):
    """Session-token auth: POST to a login endpoint, cache the token, re-login on 401.

    Configurable enough to cover most session-token schemes:

    - login_style:    'basic' sends HTTP Basic on the login request;
                      'json' sends {"username": ..., "password": ...} as the body.
    - token_location: 'json' reads token_field from the JSON response body;
                      'header' reads the token_field response header;
                      'body' takes the whole response body as the token.
    - auth_header/auth_scheme: how the cached token is presented on API requests,
                      e.g. ('X-Auth-Token', None) or ('Authorization', 'Bearer').

    Subclass hooks: override _extract_token() or _on_login_response() for
    platforms that return extra session state (scoping IDs, refresh tokens).
    """

    def __init__(
        self,
        login_path: str,
        username: str,
        password: str,
        *,
        login_style: str = "basic",
        token_location: str = "json",
        token_field: str = "token",
        auth_header: str = "Authorization",
        auth_scheme: str | None = "Bearer",
    ) -> None:
        if not username or not password:
            raise PlatformError(
                "Login-token auth requires both username and password. "
                "Set the *_USERNAME and *_PASSWORD environment variables."
            )
        if login_style not in ("basic", "json"):
            raise ValueError("login_style must be 'basic' or 'json'")
        if token_location not in ("json", "header", "body"):
            raise ValueError("token_location must be 'json', 'header', or 'body'")
        self._login_path = login_path
        self._username = username
        self._password = password
        self._login_style = login_style
        self._token_location = token_location
        self._token_field = token_field
        self._auth_header = auth_header
        self._auth_scheme = auth_scheme
        self._token: str | None = None
        self._lock = asyncio.Lock()

    async def ensure_authenticated(self, http: httpx.AsyncClient) -> None:
        if self._token is None:
            async with self._lock:
                if self._token is None:  # re-check: another task may have logged in
                    await self._login(http)

    def headers(self) -> dict[str, str]:
        if self._token is None:
            return {}
        value = f"{self._auth_scheme} {self._token}" if self._auth_scheme else self._token
        return {self._auth_header: value}

    async def handle_unauthorized(
        self, http: httpx.AsyncClient, failed_headers: dict[str, str] | None = None
    ) -> bool:
        failed_value = (failed_headers or {}).get(self._auth_header)
        async with self._lock:
            current_value = self.headers().get(self._auth_header)
            if current_value and failed_value and current_value != failed_value:
                # A concurrent task already re-authenticated after this request was
                # sent; the cached token is fresher than the one that failed. Retry
                # with it instead of discarding it (prevents re-login storms when
                # several in-flight requests all 401 on an expired token).
                return True
            logger.info("Session token rejected (401); re-authenticating")
            self._token = None
            await self._login(http)
        return True

    def invalidate(self) -> None:
        self._token = None

    async def _login(self, http: httpx.AsyncClient) -> None:
        kwargs: dict = {}
        if self._login_style == "basic":
            kwargs["auth"] = (self._username, self._password)
        else:
            kwargs["json"] = {"username": self._username, "password": self._password}
        response = await http.post(self._login_path, **kwargs)
        if response.status_code in (401, 403):
            raise PlatformError(
                "Login to the platform failed: credentials were rejected. "
                "Verify the *_USERNAME and *_PASSWORD environment variables."
            )
        if not response.is_success:
            raise PlatformError(
                f"Login to the platform failed with status {response.status_code}. "
                "Check that base_url points at the API and the login endpoint is correct."
            )
        self._token = self._extract_token(response)
        if not self._token:
            raise PlatformError(
                "Login succeeded but no token was found in the response. "
                "The token_location/token_field configuration may not match this platform."
            )
        self._on_login_response(response)
        logger.info("Authenticated to platform (token acquired)")

    def _extract_token(self, response: httpx.Response) -> str | None:
        if self._token_location == "header":
            return response.headers.get(self._token_field)
        if self._token_location == "body":
            try:
                data = response.json()
            except ValueError:
                return response.text.strip() or None
            return data if isinstance(data, str) else None
        try:
            data = response.json()
        except ValueError:
            return None
        if isinstance(data, dict):
            value = data.get(self._token_field)
            return value if isinstance(value, str) else None
        return None

    def _on_login_response(self, response: httpx.Response) -> None:
        """Hook for subclasses to capture extra session state from the login response."""


def _error_text(response: httpx.Response) -> str:
    """Lower-cased 'error' field of a Crosswork gateway JSON error body ('' if absent)."""
    try:
        data = response.json()
    except ValueError:
        return ""
    if isinstance(data, dict) and isinstance(data.get("error"), str):
        return data["error"].strip().lower()
    return ""


class CrossworkCasAuth(LoginTokenAuth):
    """Cisco Crosswork Network Controller: two-leg CAS SSO, then a Bearer JWT.

    Verified live against CNC (Tyk-fronted, NodePort 30603):

    1. ``POST /crosswork/sso/v1/tickets`` with form-urlencoded ``username`` and
       ``password`` -> 201; the body is a ticket-granting ticket (``TGT-...``).
       The ``Location`` header points at an internal port and is never followed.
    2. ``POST /crosswork/sso/v1/tickets/{TGT}`` with form-urlencoded
       ``service=<base_url>/app-dashboard`` -> 200; the body is the JWT (its
       ``aud`` claim is that service URL, ``sub`` is the username).
    3. Every API call carries ``Authorization: Bearer <JWT>``. The JWT lives
       about 8 hours; re-login simply repeats both legs.
    4. ``DELETE /crosswork/sso/v1/tickets/{TGT}`` **with the Bearer JWT** ends
       the SSO session (without the header it answers ``400 "Authorization
       header is missing"`` and the session stays). This matters: Crosswork
       enforces a **per-user concurrent session limit** (RBAC
       ``NumParallelSessionsPerUser``; API sessions idle out only after
       ``IdleSessionTimeoutAPI``, 480 min by default), and leg 1 answers
       ``503 {"error": "Per user session limit reached. Close unused sessions
       or try after sometime."}`` once it is hit (verified live after a run of
       short-lived scripts that logged in and never out). ApiClient.aclose()
       therefore calls logout(), which deletes the TGT.

    The gateway never answers 401. A missing or garbage token is a 403
    (``"Missing Authorization header"`` / ``"Unauthorized request"``) and a
    JWT-shaped but invalid one is a 500 (``"Middleware error"``), so
    is_auth_failure() recognises those bodies — otherwise an expired token
    would surface as a permission error and never trigger re-authentication.
    """

    TICKETS_PATH = "/crosswork/sso/v1/tickets"
    SERVICE_PATH = "/app-dashboard"
    # Verified live: a bad/expired JWT is 403 "Unauthorized request"; no header is 403
    # "Missing Authorization header"; a session terminated server-side (an admin ending
    # it, or the TGT deleted) is 403 "Your session has ended. Log into the system again
    # to continue." — all three mean "log in again", none is a permission problem.
    _AUTH_FAILURE_BODIES: dict[int, tuple[str, ...]] = {
        403: ("missing authorization header", "unauthorized request", "your session has ended"),
        500: ("middleware error",),
    }

    def __init__(
        self,
        username: str,
        password: str,
        *,
        tickets_path: str = TICKETS_PATH,
        service_path: str = SERVICE_PATH,
    ) -> None:
        super().__init__(
            tickets_path,
            username,
            password,
            login_style="basic",  # unused: _login is overridden
            token_location="body",
            auth_header="Authorization",
            auth_scheme="Bearer",
        )
        self._service_path = service_path
        self._tgt: str | None = None

    def is_auth_failure(self, response: httpx.Response) -> bool:
        if response.status_code == 401:
            return True
        markers = self._AUTH_FAILURE_BODIES.get(response.status_code)
        if not markers:
            return False
        text = _error_text(response)
        return any(m in text for m in markers)

    async def _login(self, http: httpx.AsyncClient) -> None:
        # Leg 1: ticket-granting ticket.
        first = await http.post(
            self._login_path,
            data={"username": self._username, "password": self._password},
        )
        if first.status_code in (401, 403):
            raise PlatformError(
                "Login to Crosswork failed: credentials were rejected. Verify the "
                "*_USERNAME and *_PASSWORD environment variables. Crosswork returns the "
                "same 'Invalid credentials' for a wrong password and for a username that "
                "does not exist, so confirm the account under Administration > Users and Roles."
            )
        if first.status_code == 503 and "session limit" in _error_text(first):
            raise PlatformError(
                "Login to Crosswork failed: this user has reached its concurrent-session "
                "limit ('Per user session limit reached'). Sessions left open by other "
                "clients (or earlier runs that did not log out) must expire or be closed "
                "first; Crosswork's session timeout controls how long that takes. Use a "
                "dedicated service account for this server."
            )
        if not first.is_success:
            raise PlatformError(
                f"Crosswork SSO ticket request failed with status {first.status_code}. "
                "Check that base_url is the Crosswork UI/API URL (https://<host>:30603)."
            )
        tgt = first.text.strip()
        if not tgt.startswith("TGT-"):
            raise PlatformError(
                "Crosswork SSO did not return a ticket-granting ticket. The base_url may "
                "point at something other than a Crosswork SSO endpoint."
            )

        # Leg 2: service ticket, which Crosswork issues as a JWT.
        service = f"{str(http.base_url).rstrip('/')}{self._service_path}"
        second = await http.post(f"{self._login_path}/{tgt}", data={"service": service})
        if not second.is_success:
            raise PlatformError(
                f"Crosswork SSO service-ticket exchange failed with status "
                f"{second.status_code}. The ticket-granting ticket may have expired; retry."
            )
        token = second.text.strip()
        if token.count(".") != 2:
            raise PlatformError(
                "Crosswork SSO returned a service ticket that is not a JWT; this server "
                "expects the JWT flow used by Crosswork Network Controller."
            )
        self._token = token
        self._tgt = tgt
        logger.info("Authenticated to Crosswork (JWT acquired)")

    async def logout(self, http: httpx.AsyncClient) -> None:
        """Delete the ticket-granting ticket so the SSO session is released."""
        tgt, self._tgt = self._tgt, None
        if not tgt:
            return
        try:
            response = await http.delete(f"{self._login_path}/{tgt}", headers=self.headers())
        except httpx.HTTPError as exc:
            logger.warning("Crosswork SSO logout failed: %s", type(exc).__name__)
            return
        if response.is_success:
            logger.info("Crosswork SSO session released")
        else:
            logger.warning("Crosswork SSO logout answered %s", response.status_code)
        self._token = None
