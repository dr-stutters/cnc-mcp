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

All strategies are 401-aware: ApiClient calls handle_unauthorized() once per
request, so expired tokens are transparently re-acquired.
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

    async def handle_unauthorized(
        self, http: httpx.AsyncClient, failed_headers: dict[str, str] | None = None
    ) -> bool:
        """Called once after a 401, with the auth headers the failed request carried.

        Return True if the request is worth retrying.
        """
        return False

    def invalidate(self) -> None:
        """Drop any cached credentials/tokens."""


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
