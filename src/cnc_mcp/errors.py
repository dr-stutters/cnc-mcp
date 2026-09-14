"""Error types and agent-facing error formatting.

Tools never let exceptions escape to the MCP layer: they catch and return an
"Error: ..." string built here. Messages must be actionable — tell the agent
what likely went wrong and what to try next — without leaking internals
(no tracebacks, no credentials, no raw HTML error pages).
"""

from __future__ import annotations

import re
from typing import Any

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
    415: "Unsupported media type: set Content-Type to the type this endpoint documents.",
    422: "The platform could not process the payload. Check required fields and value formats.",
    429: "Rate limit exceeded. Retries were exhausted; wait before making more requests.",
}


# Crosswork's home app answers unrouted paths with a Spring error document whose
# ``path`` is the SSO login redirect it tried to make (verified live); the same
# document is served as YAML ("--- !<java.util.LinkedHashMap>\npath: /crosswork/sso/login/...")
# or as Spring JSON depending on the Accept header.
_HOME_APP_PATH_PREFIX = "/crosswork/sso/login/"
_YAML_PATH_RE = re.compile(r"^\s*path:\s*['\"]?(\S+)", re.MULTILINE)


def _parse_json(response: httpx.Response) -> Any | None:
    """The parsed JSON body, or None when the body is not JSON (never raises)."""
    try:
        return response.json()
    except ValueError:
        return None


def _restconf_errors(data: Any) -> list[dict[str, Any]]:
    """The ``error`` entries of a RESTCONF error document, else an empty list.

    Three spellings, all verified live: Crosswork's RESTCONF NBIs use the bare
    ``errors`` key (``nbi/topology/v3``); the NSO proxy
    (``/crosswork/proxy/nso/restconf``) uses the RFC 8040
    ``ietf-restconf:errors`` key (its 415 answer to an ``application/json``
    body); the EMF RESTCONF services (``/crosswork/inventory/restconf``,
    ``/crosswork/alarm/restconf``) use ``rc.errors`` whose ``error`` is a single
    object, not a list (e.g. ``{"rc.errors":{"error":{"error-tag":"invalid-value",
    "error-app-tag":"FW.0089","error-message":"Cannot find device with Node
    Name: nope"}}}``).
    """
    if not isinstance(data, dict):
        return []
    for key in ("errors", "ietf-restconf:errors", "rc.errors"):
        block = data.get(key)
        if not isinstance(block, dict):
            continue
        entries = block.get("error")
        if key == "rc.errors" and isinstance(entries, dict):
            entries = [entries]  # the EMF spelling carries one object, not a list
        if isinstance(entries, list):
            return [e for e in entries if isinstance(e, dict)]
    return []


def _restconf_detail(errors: list[dict[str, Any]]) -> str:
    """Render RESTCONF error entries as ``RESTCONF <tag>: <message>`` (joined with '; ')."""
    parts = []
    for err in errors:
        tag = str(err.get("error-tag") or "error").strip()
        message = str(err.get("error-message") or "").strip()
        parts.append(f"RESTCONF {tag}: {message}" if message else f"RESTCONF {tag}")
    return "; ".join(parts)


def _home_app_fallback_path(data: Any, text: str) -> str | None:
    """The ``path`` of a home-app fallback document (YAML or Spring JSON), else None.

    Only a path under :data:`_HOME_APP_PATH_PREFIX` counts: that is the signature
    of "nothing is routed here" (verified live), whereas a Spring 404 from a real
    service carries the requested path instead.
    """
    path: Any = None
    if isinstance(data, dict):
        path = data.get("path")
    elif text.startswith("---"):
        match = _YAML_PATH_RE.search(text)
        path = match.group(1) if match else None
    if isinstance(path, str) and path.startswith(_HOME_APP_PATH_PREFIX):
        return path
    return None


# API prefixes that are unrouted on a single-VM CNC 7.2 deployment (verified
# live 2026-09-13) and the application each belongs to — so the hint can say
# which application is missing instead of "some prefix".
_UNROUTED_APPLICATIONS: dict[str, str] = {
    "/crosswork/aa/": "Service Health (Crosswork Active Assurance, capp-aa)",
    "/crosswork/hi/": "Health Insights",
    "/crosswork/nca/": "Change Automation",
    "/crosswork/path_analytics/": "Path Analytics",
    "/crosswork/performance/restconf/": (
        "the RESTCONF performance API (the JSON /crosswork/performance/v1 API is routed)"
    ),
    "/crosswork/crosscluster/": "the cross-cluster (multi-cluster) service",
}


def _application_for_path(fallback_path: str) -> str | None:
    """Name the application an unrouted home-app fallback path belongs to, if known."""
    requested = fallback_path[len(_HOME_APP_PATH_PREFIX) - 1 :]  # keep the leading "/"
    for prefix, application in _UNROUTED_APPLICATIONS.items():
        if requested.startswith(prefix):
            return application
    return None


def _extract_detail(response: httpx.Response, max_chars: int = 300) -> str:
    """Pull a short, human-readable detail string out of an API error response.

    HTML pages and YAML documents (Crosswork's home app answers unrouted paths
    with ``--- !<java.util.LinkedHashMap>`` YAML) are dropped rather than dumped
    into the agent's context. RESTCONF error documents are rendered as
    ``RESTCONF <error-tag>: <error-message>``.
    """
    data = _parse_json(response)
    if data is None:
        text = response.text.strip()
        # Avoid dumping HTML error pages or YAML documents into the agent's context.
        if text.startswith(("<", "---")):
            return ""
        return text[:max_chars]
    restconf = _restconf_errors(data)
    if restconf:
        return _restconf_detail(restconf)[:max_chars]
    if isinstance(data, dict):
        # Common error-message keys across platform APIs (``errorMessage`` is Spring's).
        for key in ("message", "detail", "error", "errorMessage", "description", "response"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()[:max_chars]
            if isinstance(value, dict):
                nested = value.get("message") or value.get("detail")
                if isinstance(nested, str) and nested.strip():
                    return nested.strip()[:max_chars]
    return str(data)[:max_chars]


# Shared by the Spring "No static resource" forms and Go-mux "404 page not found":
# in both cases a real service answered, so the prefix is routed and only the path is wrong.
_ROUTED_NO_RESOURCE_HINT = (
    "The service is present but does not serve this path on this build. Check the path "
    "against the API document for this Crosswork version; the prefix is routed, the "
    "resource is not."
)

# Crosswork hides several distinct conditions behind generic status codes
# (verified live). Matched case-insensitively against the whole response body
# (so a marker in a key ``_extract_detail`` does not surface still counts) and
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
    # dg-manager (and other proto-backed services) reject unknown body fields outright,
    # unlike inventory which silently ignores them.
    (
        400,
        "unable to unmarshal payload to proto",
        "This service rejects unknown fields — the request body has a field the API does "
        "not define. Remove it (check the field name and casing against the API document).",
    ),
    # Spring-served services answer a path they do not serve with
    # {"code":500,"errorMessage":"No static resource ..."} or a 404 that names
    # NoResourceFoundException; Go-mux services (probemgr, authconfig) answer a plain
    # text "404 page not found". The service is routed and alive; the path is wrong
    # for this build (verified live — see "Routing detection, refined" in the notes).
    (500, "no static resource", _ROUTED_NO_RESOURCE_HINT),
    (404, "no static resource", _ROUTED_NO_RESOURCE_HINT),
    (404, "noresourcefoundexception", _ROUTED_NO_RESOURCE_HINT),
    (404, "404 page not found", _ROUTED_NO_RESOURCE_HINT),
]

_RESTCONF_TAG_HINTS: dict[tuple[int, str], str] = {
    (400, "unknown-element"): (
        "RESTCONF path or key problem: an element in the data path does not exist in the "
        "YANG model at this position. Check module prefixes, list names and key names."
    ),
    (400, "missing-attribute"): (
        "RESTCONF path or key problem: a required key is missing — a sub-list cannot be "
        "read without its parent's key (e.g. network=<id> before node=<id>)."
    ),
    # Verified live on the topology NBI: policy=PE1,PE2,100 (host names where
    # inet:ip-address router-ids belong) answers 400 invalid-value "Invalid value 'PE1'
    # for (...)headend" — a key part failed its YANG type, not a missing object.
    (400, "invalid-value"): (
        "RESTCONF key problem: a key part has the wrong type for the YANG model (e.g. a "
        "host name where an IP address / TE router-id is expected, or text where an "
        "integer such as a color or tunnel-id is expected). Fix the key; the object may "
        "well exist."
    ),
    (409, "data-missing"): (
        "RESTCONF: no such object — the keyed resource does not exist (a keyed GET that "
        "finds nothing answers 409 data-missing on this platform, not 404)."
    ),
    # Verified live on /crosswork/proxy/nso/restconf: an application/json request body is
    # answered 415 {"ietf-restconf:errors":{"error":[{"error-tag":"malformed-message",
    # "error-message":"Unsupported media type..."}]}} — the path and body are fine, the
    # Content-Type header is the problem.
    (415, "malformed-message"): (
        "The NSO proxy rejected the request media type: send request bodies with "
        "Content-Type: application/yang-data+json (application/json is answered with 415 "
        "on /crosswork/proxy/nso/restconf)."
    ),
}


def _hint_for(status: int, response: httpx.Response, data: Any) -> str:
    """Pick the most specific agent-facing hint for a failed response (verified cases first)."""
    text = response.text
    restconf = _restconf_errors(data)
    if restconf:
        for err in restconf:
            hint = _RESTCONF_TAG_HINTS.get((status, str(err.get("error-tag", "")).lower()))
            if hint:
                return hint
        return (
            "The RESTCONF service rejected the request (see the error-tag). Check the data "
            "path, keys and body against the YANG model."
        )
    fallback_path = _home_app_fallback_path(data, text) if status == 404 else None
    if fallback_path is not None:
        app = _application_for_path(fallback_path)
        named = f" On CNC 7.2 that prefix belongs to {app}." if app else ""
        return (
            "This path is not routed on this Crosswork instance (application not installed "
            "or not licensed): the request fell through to the home app's login redirect. "
            f"It is not a bad ID — the whole API prefix is absent.{named}"
        )
    if status == 500 and not text.strip():
        return (
            "The gateway answered 500 with an EMPTY body. On this platform that means either the "
            "backend behind the call is absent or down (e.g. the OPM package service — retrying "
            "will not help) or, on the Optimization Engine RPCs, an input the engine could not "
            "resolve (an unknown node or interface name, a router-id where a host name belongs "
            "or vice versa, an explicit hop without its SID). Check the inputs against the "
            "topology first; if they are right, the feature is not available here."
        )
    lowered = text.lower()
    for st, marker, hint in _DETAIL_HINTS:
        if st == status and marker in lowered:
            return hint
    return _STATUS_HINTS.get(
        status,
        "The platform API request failed."
        if status < 500
        else "The platform returned a server error. It may be busy or mid-deploy; try again.",
    )


def http_error(response: httpx.Response) -> PlatformError:
    """Build a PlatformError for a non-success HTTP response.

    The hint is chosen from the body, not just the status, because Crosswork
    overloads its status codes (verified live): RESTCONF error documents, the
    home app's unrouted-path fallback, Spring "No static resource" answers,
    proto unmarshal rejections and empty-bodied 500s each mean something
    specific that the generic status text would hide.
    """
    status = response.status_code
    detail = _extract_detail(response)
    hint = _hint_for(status, response, _parse_json(response))
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
