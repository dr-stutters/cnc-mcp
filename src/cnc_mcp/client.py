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
- per-call body and status controls for Crosswork's other API dialects: a
  per-call Content-Type that overrides httpx's ``application/json`` default
  (verified live 2026-09-12: RESTCONF RPCs and the NSO proxy need
  ``application/yang-data+json`` — the proxy answers ``application/json`` with
  415), ``ok_statuses`` so a caller can accept a non-2xx answer that is a normal
  outcome for that endpoint (206 for ``Range`` paging, 409 ``data-missing`` on a
  keyed RESTCONF GET) without an exception, and a raw ``content=`` body for the
  Inventory Job Scheduler (``rs`` prefix, ``POST
  /crosswork/rs/json/jobSchedulerServiceInv/v1/{runJob,suspendJob,resumeJob}``,
  documented in ``job_scheduler_ap_is_7_2_0.json`` as an unquoted string such
  as ``Switch Inventory:Inventory`` sent as ``application/json``; verified live
  2026-09-13 — the service answers a bare ``true``/``false``). It is the only
  raw-text consumer — the EMF RESTCONF endpoints take JSON/XML, never raw text.

Accepted statuses (``ok_statuses``) and the re-auth pass: an accepted status is
never retried by the backoff loop, but it is still subject to the one
transparent re-authentication when the auth strategy classifies it as an auth
failure (Crosswork 403 ``Unauthorized request`` / 500 ``Middleware error``) —
that retry is what tells a stale JWT from an unrouted path, and ``probe.py``
relies on it.
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
# httpx sets no Content-Type for a raw ``content=`` body. The one raw-body consumer
# (Inventory Job Scheduler runJob/suspendJob/resumeJob, ``rs`` prefix) takes its
# unquoted-string body under ``application/json`` (verified live 2026-09-13; text/plain
# works too). Callers pass their own Content-Type header to override it.
DEFAULT_RAW_CONTENT_TYPE = "application/json"


def _has_header(headers: dict[str, str] | None, name: str) -> bool:
    """Case-insensitive presence check for a header name in a plain dict."""
    return any(k.lower() == name.lower() for k in (headers or {}))


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
        content: str | bytes | None = None,
        headers: dict[str, str] | None = None,
        raise_on_error: bool = True,
        retryable: bool | None = None,
        ok_statuses: set[int] | None = None,
    ) -> httpx.Response:
        """Make a request with auth, retries, and one re-auth on auth failure. Returns the response.

        Body: pass EITHER ``json_body`` (serialised as JSON, Content-Type
        ``application/json`` unless ``headers`` carries its own — RESTCONF RPC
        bodies and the NSO proxy need ``application/yang-data+json``; the proxy
        answers ``application/json`` with 415) OR ``content`` (sent verbatim;
        Content-Type from ``headers`` or :data:`DEFAULT_RAW_CONTENT_TYPE` when
        none is given). The one raw-body consumer is the Inventory Job
        Scheduler (``POST /crosswork/rs/json/jobSchedulerServiceInv/v1/
        {runJob,suspendJob,resumeJob}``, body an unquoted string such as
        ``Switch Inventory:Inventory`` under ``application/json`` — verified
        live 2026-09-13, see ``tools/ems_jobs.py``). Passing both is a
        programming error and raises ValueError before anything is sent.

        retryable=None (default) auto-retries 5xx/transport errors only for
        idempotent methods; pass True when a write is known-safe to re-send on
        this platform, or False to disable even idempotent retries.

        ok_statuses: extra status codes that count as success for this call —
        they are returned as-is and never raised (e.g. ``{206}`` for ``Range``
        paging, ``{409}`` for a keyed RESTCONF GET that answers
        ``data-missing``). 2xx is always accepted. An accepted status is never
        retried by the backoff loop, but it is still subject to the one
        transparent re-authentication when the auth strategy classifies it as an
        auth failure (Crosswork 403 ``Unauthorized request`` / 500 ``Middleware
        error``): the request is re-sent once with a fresh token and the second
        answer is returned. That retry is what tells a stale JWT from an
        unrouted path (``probe.py`` depends on it).

        Raises PlatformError for non-success responses unless raise_on_error=False,
        and for transport failures that survive all retries.
        """
        if content is not None and json_body is not None:
            raise ValueError("ApiClient.request(): pass either json_body or content, not both")
        if retryable is None:
            retryable = method.upper() in IDEMPOTENT_METHODS
        accepted = ok_statuses or set()
        async with self._semaphore:
            response = await self._request_with_retries(
                method, path, params, json_body, content, headers, retryable, accepted
            )
        if raise_on_error and not response.is_success and response.status_code not in accepted:
            raise http_error(response)
        return response

    async def request_json(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        content: str | bytes | None = None,
        headers: dict[str, str] | None = None,
        retryable: bool | None = None,
        ok_statuses: set[int] | None = None,
    ) -> Any:
        """request(), then parse the body as JSON (empty body -> None).

        Takes the same body/status controls as :meth:`request`; a response whose
        status is in ``ok_statuses`` is parsed and returned like a 200.
        """
        response = await self.request(
            method,
            path,
            params=params,
            json_body=json_body,
            content=content,
            headers=headers,
            retryable=retryable,
            ok_statuses=ok_statuses,
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
        """Release the platform session (if the auth scheme has one), then the pool."""
        try:
            await self._auth.logout(self._http)
        except Exception:  # never let shutdown fail because of a logout
            logger.warning("Auth logout raised during close", exc_info=True)
        await self._http.aclose()

    async def _request_with_retries(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None,
        json_body: Any,
        content: str | bytes | None,
        extra_headers: dict[str, str] | None,
        retryable: bool,
        accepted: set[int],
    ) -> httpx.Response:
        attempt = 0
        reauth_attempted = False
        while True:
            await self._auth.ensure_authenticated(self._http)
            headers = {**self._auth.headers(), **(extra_headers or {})}
            if content is not None and not _has_header(extra_headers, "Content-Type"):
                headers["Content-Type"] = DEFAULT_RAW_CONTENT_TYPE
            try:
                # A per-call Content-Type in ``headers`` overrides the one httpx
                # derives from ``json=`` (verified against httpx 0.28: request
                # headers take precedence over the encoder's defaults).
                response = await self._http.request(
                    method, path, params=params, json=json_body, content=content, headers=headers
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

            if (
                attempt < self._settings.max_retries
                and response.status_code not in accepted
                and (
                    response.status_code == 429  # rejected before processing: safe for any method
                    or (retryable and response.status_code in RETRYABLE_STATUS)
                )
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
