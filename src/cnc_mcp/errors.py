"""Error types and agent-facing error formatting.

Tools never let exceptions escape to the MCP layer: they catch and return an
"Error: ..." string built here. Messages must be actionable — tell the agent
what likely went wrong and what to try next — without leaking internals
(no tracebacks, no credentials, no raw HTML error pages).
"""

from __future__ import annotations

import httpx


class PlatformError(Exception):
    """An error whose message is safe and useful to show to the calling agent.

    (Named PlatformError to avoid clashing with the MCP SDK's own ToolError.)
    """


_STATUS_HINTS: dict[int, str] = {
    400: "The platform rejected the request. Check parameter values and formats.",
    401: "Authentication failed. Verify the configured credentials/token are valid.",
    403: (
        "Permission denied. The configured account lacks the required role/privilege "
        "for this operation on the platform."
    ),
    404: "Resource not found. Check that the ID or name is correct and still exists.",
    409: "Conflict. The resource may already exist or is locked by another change.",
    422: "The platform could not process the payload. Check required fields and value formats.",
    429: "Rate limit exceeded. Retries were exhausted; wait before making more requests.",
}


def _extract_detail(response: httpx.Response, max_chars: int = 300) -> str:
    """Pull a short, human-readable detail string out of an API error response."""
    try:
        data = response.json()
    except ValueError:
        text = response.text.strip()
        # Avoid dumping HTML error pages into the agent's context.
        if text.startswith("<"):
            return ""
        return text[:max_chars]
    if isinstance(data, dict):
        # Common error-message keys across platform APIs.
        for key in ("message", "detail", "error", "description", "response"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()[:max_chars]
            if isinstance(value, dict):
                nested = value.get("message") or value.get("detail")
                if isinstance(nested, str) and nested.strip():
                    return nested.strip()[:max_chars]
    return str(data)[:max_chars]


# Crosswork hides several distinct conditions behind generic status codes
# (verified live). Matched case-insensitively against the extracted detail and
# checked before the generic status hint.
_DETAIL_HINTS: list[tuple[int, str, str]] = [
    (
        403,
        "missing authorization header",
        "Authentication failed: no bearer token reached Crosswork. This indicates a "
        "server bug rather than a permissions problem.",
    ),
    (
        403,
        "unauthorized request",
        "Crosswork answered 'Unauthorized request'. This is either a rejected bearer "
        "token (the server already re-authenticated once and retried) or a path the "
        "gateway does not know / your role may not call — check the endpoint path before "
        "suspecting the credentials.",
    ),
    (
        500,
        "middleware error",
        "The Crosswork gateway rejected the bearer token before it reached the service "
        "(malformed or expired JWT). The server re-authenticates automatically once per "
        "request; if this persists, verify the configured credentials.",
    ),
    (
        500,
        "nats request failed",
        "The Crosswork service could not process the request. On this platform that "
        "usually means a malformed request body rather than an outage — check the "
        "payload (valid JSON, expected field names) before retrying.",
    ),
]


def http_error(response: httpx.Response) -> PlatformError:
    """Build a PlatformError for a non-success HTTP response."""
    status = response.status_code
    detail = _extract_detail(response)
    hint = next(
        (h for st, marker, h in _DETAIL_HINTS if st == status and marker in detail.lower()),
        None,
    ) or _STATUS_HINTS.get(
        status,
        "The platform API request failed."
        if status < 500
        else "The platform returned a server error. It may be busy or mid-deploy; try again.",
    )
    message = f"API request failed with status {status}. {hint}"
    if detail:
        message += f" Platform said: {detail}"
    return PlatformError(message)


def format_error(e: Exception) -> str:
    """Catch-all used by every tool: turn any exception into an 'Error: ...' string."""
    if isinstance(e, PlatformError):
        return f"Error: {e}"
    if isinstance(e, httpx.TimeoutException):
        return "Error: Request to the platform timed out. It may be slow or unreachable; try again."
    if isinstance(e, httpx.TransportError):
        return (
            "Error: Could not connect to the platform. Check base_url, network reachability, "
            "and whether verify_tls should be disabled for a self-signed certificate."
        )
    return f"Error: Unexpected {type(e).__name__} while calling the platform API."
