"""Async HTTP client for the platform API.

Wraps httpx.AsyncClient with the behaviors every platform server needs:
- auth via a pluggable AuthStrategy, including one transparent re-auth when the
  strategy's is_auth_failure() says the response means the token was rejected
- retry with exponential backoff (+ jitter, honoring Retry-After): 429 is retried
  for every method (the platform rejected the request before processing it);
  5xx and transport errors are retried only for idempotent methods, because a
  lost response to a POST may mean the write already happened — re-sending would
  duplicate it. Write tools can opt in per-call with retryable=True.
- a concurrency cap so an agent fanning out tool calls can't hammer the platform
- TLS-verification toggle for lab gear with self-signed certificates
- non-success responses raised as PlatformError with agent-actionable messages
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any

import httpx

from cnc_mcp.auth import AuthStrategy
from cnc_mcp.config import Settings
from cnc_mcp.errors import PlatformError, http_error

logger = logging.getLogger(__name__)

RETRYABLE_STATUS = {429, 502, 503, 504}
IDEMPOTENT_METHODS = {"GET", "HEAD", "OPTIONS", "PUT", "DELETE"}


class ApiClient:
    """Shared client for all tools. Create once in build_server(), close via lifespan."""

    def __init__(self, settings: Settings, auth: AuthStrategy) -> None:
        self._settings = settings
        self._auth = auth
        self._semaphore = asyncio.Semaphore(settings.max_concurrent_requests)
        self._http = httpx.AsyncClient(
            base_url=settings.base_url,
            verify=settings.verify_tls,
            timeout=httpx.Timeout(
                settings.timeout_seconds, connect=settings.connect_timeout_seconds
            ),
            headers={"Accept": "application/json"},
        )

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        headers: dict[str, str] | None = None,
        raise_on_error: bool = True,
        retryable: bool | None = None,
    ) -> httpx.Response:
        """Make a request with auth, retries, and one re-auth on auth failure. Returns the response.

        retryable=None (default) auto-retries 5xx/transport errors only for
        idempotent methods; pass True when a write is known-safe to re-send on
        this platform, or False to disable even idempotent retries.

        Raises PlatformError for non-success responses unless raise_on_error=False,
        and for transport failures that survive all retries.
        """
        if retryable is None:
            retryable = method.upper() in IDEMPOTENT_METHODS
        async with self._semaphore:
            response = await self._request_with_retries(
                method, path, params, json_body, headers, retryable
            )
        if raise_on_error and not response.is_success:
            raise http_error(response)
        return response

    async def request_json(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        headers: dict[str, str] | None = None,
        retryable: bool | None = None,
    ) -> Any:
        """request(), then parse the body as JSON (empty body -> None)."""
        response = await self.request(
            method, path, params=params, json_body=json_body, headers=headers,
            retryable=retryable,
        )
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError as e:
            raise PlatformError(
                "The platform returned a non-JSON response where JSON was expected. "
                "The base_url may point at a UI endpoint instead of the API."
            ) from e

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _request_with_retries(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None,
        json_body: Any,
        extra_headers: dict[str, str] | None,
        retryable: bool,
    ) -> httpx.Response:
        attempt = 0
        reauth_attempted = False
        while True:
            await self._auth.ensure_authenticated(self._http)
            headers = {**self._auth.headers(), **(extra_headers or {})}
            try:
                response = await self._http.request(
                    method, path, params=params, json=json_body, headers=headers
                )
            except httpx.TransportError as e:
                if retryable and attempt < self._settings.max_retries:
                    await self._backoff(attempt)
                    attempt += 1
                    continue
                hint = (
                    "Check base_url, network reachability, and the verify_tls setting."
                    if retryable
                    else "The request was not auto-retried because it is a write that "
                    "may already have been applied; check the platform state before "
                    "re-running it."
                )
                raise PlatformError(
                    f"Could not reach the platform ({type(e).__name__}). {hint}"
                ) from e

            if not reauth_attempted and self._auth.is_auth_failure(response):
                reauth_attempted = True
                if await self._auth.handle_unauthorized(self._http, headers):
                    continue

            if attempt < self._settings.max_retries and (
                response.status_code == 429  # rejected before processing: safe for any method
                or (retryable and response.status_code in RETRYABLE_STATUS)
            ):
                await self._backoff(attempt, retry_after=response.headers.get("Retry-After"))
                attempt += 1
                continue

            return response

    async def _backoff(self, attempt: int, retry_after: str | None = None) -> None:
        delay = self._settings.retry_backoff_seconds * (2**attempt)
        if retry_after:
            try:
                delay = max(delay, float(retry_after))
            except ValueError:
                pass  # Retry-After was an HTTP date; exponential backoff is fine
        # Cap BEFORE jitter so a huge (server-controlled) Retry-After can't stall
        # the tool call — the sleep happens while the concurrency slot is held.
        delay = min(delay, 30.0)
        delay += random.uniform(0, delay / 4)
        logger.debug("Retrying after %.1fs (attempt %d)", delay, attempt + 1)
        await asyncio.sleep(delay)
