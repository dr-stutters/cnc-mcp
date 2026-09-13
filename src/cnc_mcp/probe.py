"""Routing detection: is a path/service actually served by THIS Crosswork deployment?

Crosswork is a single Tyk gateway in front of many independently installed
applications, and the eval/single-VM builds ship without several of them
(Service Health ``aa``, Health Insights ``hi``, Change Automation ``nca``,
``cat``, ``crosscluster``, ...). A tool that blindly calls one of those paths
gets a confusing 404, so future tool modules probe first and explain.

The signatures marked *verified* below were observed live on a 7.2 build
(platform notes, "Routing detection, refined"); the ones marked *extrapolated*
are defensive readings of adjacent cases that have NOT been seen live and may
need revisiting when they are:

- **UNROUTED** (verified) — the gateway has no route and the request fell
  through to the home app, which answers ``404`` with a body whose ``path``
  starts with ``/crosswork/sso/login/``. The body is either YAML beginning with
  ``--- !<java.util.LinkedHashMap>`` or the Spring JSON error object. This is
  the ONLY reliable "not installed / not routed" signal. For the per-path
  services (``alarms``, ``sso``, ``notification``) it means only that this
  specific path is unknown to the gateway, not that the service is absent.
- **ROUTED_NO_PATH** (verified) — a real service answered but does not serve
  that path: Go's plain-text ``404 page not found``; Spring JSON 404 mentioning
  ``No static resource`` / ``NoResourceFoundException`` (seen from
  ``notification/v2`` among others); Spring
  ``500 {"code":500,"errorMessage":"No static resource ..."}``.
  *Extrapolated*: a Spring JSON 404 whose ``path`` is elsewhere and that
  carries no ``message`` (Spring's default document for an unmapped path), and
  a YAML ``--- !<java.util.LinkedHashMap>`` 404 whose ``path`` is not under
  ``/crosswork/sso/login/`` (the YAML form has only ever been seen from the
  home app).
- **ROUTED_NO_RBAC** (verified) — ``403 {"error":"Unauthorized request"}``. A
  bad token gets the same body, but the ApiClient has already re-authenticated
  once before the response reaches us, so with a fresh token it means the
  gateway has no RBAC entry for the path.
- **ROUTED_BAD_BODY** (verified) — ``500 {"error":"NATS request failed"}`` or a
  ``400`` containing ``unable to unmarshal payload to proto``: the path is
  served, the request body was not accepted (typically a synthetic probe body).
- **INCONCLUSIVE** — the answer proves nothing about the path. Verified: a
  ``500`` with an empty body (the notes: ``nbi/optimization/v3`` and the
  wrong base ``nbi/optima/v2`` both answer 500-empty, "so it proves nothing").
  *Extrapolated*: auth-layer answers that survived the client's one re-login —
  ``403 Missing Authorization header``, ``500 Middleware error``, any ``401``.
  Treated as served (benefit of the doubt) so :meth:`Availability.require`
  lets the real call through and ``errors.py`` reports the actual problem;
  never cached, so the next caller probes again.
- **AVAILABLE** — any 2xx (verified, including ``alarm/v1`` answering
  ``200 {"error":"Fail"}`` and the EMF empty envelope), plus application
  errors verified from the target service (RESTCONF ``{"errors": ...}`` 400s,
  a RESTCONF ``409 data-missing``, the NSO proxy's ``415
  ietf-restconf:errors``). *Extrapolated*: every other 4xx/5xx, and a Spring
  JSON 404 whose ``path`` is elsewhere but whose ``message`` is the service's
  own text (a served endpoint raising an application-level not-found for an
  ID).

Routing is per top-level prefix (``/crosswork/<svc>``, version-agnostic) for
most services, but ``alarms``, ``sso`` and ``notification`` route only their
known paths (``alarms/v1/query`` works while ``alarms/v1/x`` is unrouted;
``notification/v2/...`` is routed while ``notification/restconf/data/v2`` is
not) — so probe a REAL documented endpoint, never a synthetic one. The cache
key from :func:`prefix_of` is the service prefix for the former and the full
path for the latter.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from enum import StrEnum
from typing import Any, Protocol

import httpx

from cnc_mcp.errors import PlatformError

logger = logging.getLogger(__name__)

SSO_LOGIN_PREFIX = "/crosswork/sso/login/"
#: Services verified (7.2 eval build) to route only their known paths, so a cache
#: verdict for one path says nothing about a sibling: ``alarms/v1/query`` works while
#: ``alarms/v1/x`` is unrouted; ``notification/v2/...`` is routed while
#: ``notification/restconf/data/v2`` is not. :func:`prefix_of` keys these by full path.
PER_PATH_PREFIXES = frozenset({"alarms", "sso", "notification"})
_YAML_FALLBACK_PREFIX = "--- !<java.util.LinkedHashMap>"
# A `path:` line in the home app's YAML error body; the value may be quoted or bare.
_YAML_PATH_RE = re.compile(r"^\s*path:\s*[\"']?(?P<path>[^\"'\s]+)", re.MULTILINE)
_PREFIX_RE = re.compile(r"^/crosswork/(?P<svc>[^/?#]+)")
_QUERY_OR_FRAGMENT_RE = re.compile(r"[?#].*$", re.DOTALL)
# Spring Boot's placeholder when the error document carries no message
# (``server.error.include-message=never``); treated the same as an absent message.
_SPRING_NO_MESSAGE = "no message available"


class Routing(StrEnum):
    """What a response says about whether the probed path is served on this deployment."""

    UNROUTED = "unrouted"
    ROUTED_NO_PATH = "routed_no_path"
    ROUTED_NO_RBAC = "routed_no_rbac"
    ROUTED_BAD_BODY = "routed_bad_body"
    INCONCLUSIVE = "inconclusive"
    AVAILABLE = "available"

    @property
    def served(self) -> bool:
        """True unless the probe positively established that the path is NOT served.

        ``AVAILABLE`` and ``ROUTED_BAD_BODY`` prove the endpoint exists (the latter
        with a rejected body); ``INCONCLUSIVE`` proved nothing and gets the benefit of
        the doubt so the real call can surface its own error. ``UNROUTED``,
        ``ROUTED_NO_PATH`` and ``ROUTED_NO_RBAC`` are the blocking verdicts.
        """
        return self in (Routing.AVAILABLE, Routing.ROUTED_BAD_BODY, Routing.INCONCLUSIVE)

    @property
    def conclusive(self) -> bool:
        """True when the verdict is worth remembering (everything but ``INCONCLUSIVE``)."""
        return self is not Routing.INCONCLUSIVE


class _RequestClient(Protocol):
    """The slice of ApiClient that probing needs (a stub with this shape works in tests)."""

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = ...,
        json_body: Any = ...,
        headers: dict[str, str] | None = ...,
        raise_on_error: bool = ...,
        retryable: bool | None = ...,
    ) -> httpx.Response: ...


def _json_object(text: str) -> dict[str, Any] | None:
    """Parse ``text`` as a JSON object, leniently: anything that is not one -> None."""
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _yaml_fallback_path(text: str) -> str | None:
    """The ``path`` value of a home-app YAML error body, or None if ``text`` is not one.

    Only a body starting with the full ``--- !<java.util.LinkedHashMap>`` marker counts
    (a bare ``---`` is any YAML document); a marker without a ``path:`` line yields ``""``.
    """
    if not text.lstrip().startswith(_YAML_FALLBACK_PREFIX):
        return None
    match = _YAML_PATH_RE.search(text)
    return match.group("path") if match else ""


def home_app_fallback_path(data: Any, text: str) -> str | None:
    """The ``path`` of the home app's unrouted-path fallback document, else None.

    ``data`` is the parsed JSON body (or None / a non-dict when the body is not
    JSON) and ``text`` the raw body. The verified signature of "nothing is routed
    here" is a document — Spring JSON or the YAML
    ``--- !<java.util.LinkedHashMap>`` form, depending on the Accept header —
    whose ``path`` starts with ``/crosswork/sso/login/`` (the login redirect the
    home app tried to make). A Spring 404 from a real service carries the
    requested path instead and is NOT a fallback. This is the single shared
    implementation of that signature; ``errors.py`` should use it too.
    """
    path: Any = data.get("path") if isinstance(data, dict) else _yaml_fallback_path(text)
    if isinstance(path, str) and path.startswith(SSO_LOGIN_PREFIX):
        return path
    return None


def classify(status: int, body_text: str) -> Routing:
    """Classify one HTTP response (status + raw body) into a :class:`Routing`. Pure.

    Applies the signatures listed in the module docstring (verified ones first,
    extrapolated ones where noted), in this order: 2xx is AVAILABLE outright;
    404 distinguishes the home-app fallback (``path`` under
    ``/crosswork/sso/login/`` in YAML or JSON -> UNROUTED) from a real service's
    "no such path" (Go ``404 page not found``, Spring ``No static
    resource``/``NoResourceFoundException`` -> ROUTED_NO_PATH), then the
    extrapolated Spring cases: a JSON ``path`` elsewhere with no ``message`` (or
    Spring's "No message available" placeholder) -> ROUTED_NO_PATH, with the
    service's own ``message`` -> AVAILABLE, and a YAML body with a non-login
    path -> ROUTED_NO_PATH; 500 ``No static resource`` is ROUTED_NO_PATH; 403
    ``Unauthorized request`` is ROUTED_NO_RBAC; 500 ``NATS request failed`` and
    400 ``unable to unmarshal payload to proto`` are ROUTED_BAD_BODY; a 500 with
    an empty body, 403 ``Missing Authorization header``, 500 ``Middleware
    error`` and any 401 are INCONCLUSIVE. Anything else — including
    application-level 4xx/5xx from the target service — is AVAILABLE. JSON is
    parsed leniently; a body that is neither JSON nor the YAML fallback is
    matched as text, case-insensitively.
    """
    if 200 <= status < 300:
        return Routing.AVAILABLE
    text = body_text or ""
    lowered = text.lower()

    if status == 401:
        return Routing.INCONCLUSIVE

    if status == 404:
        obj = _json_object(text)
        if home_app_fallback_path(obj, text) is not None:
            return Routing.UNROUTED
        if _yaml_fallback_path(text) is not None:
            return Routing.ROUTED_NO_PATH  # extrapolated: YAML form, non-login path
        if "no static resource" in lowered or "noresourcefoundexception" in lowered:
            return Routing.ROUTED_NO_PATH
        if "404 page not found" in lowered:
            return Routing.ROUTED_NO_PATH
        if obj is not None and isinstance(obj.get("path"), str):
            # Extrapolated: Spring's default document for an unmapped path has no
            # message; a served endpoint raising an application-level 404 (an ID
            # that does not exist) puts its own text there.
            message = obj.get("message")
            if (
                not isinstance(message, str)
                or not message.strip()
                or message.strip().lower() == _SPRING_NO_MESSAGE
            ):
                return Routing.ROUTED_NO_PATH
        return Routing.AVAILABLE

    if status == 500:
        if not text.strip():
            return Routing.INCONCLUSIVE
        if "no static resource" in lowered:
            return Routing.ROUTED_NO_PATH
        if "nats request failed" in lowered:
            return Routing.ROUTED_BAD_BODY
        if "middleware error" in lowered:
            return Routing.INCONCLUSIVE
        return Routing.AVAILABLE

    if status == 403:
        if "unauthorized request" in lowered:
            return Routing.ROUTED_NO_RBAC
        if "missing authorization header" in lowered:
            return Routing.INCONCLUSIVE
        return Routing.AVAILABLE

    if status == 400 and "unable to unmarshal payload to proto" in lowered:
        return Routing.ROUTED_BAD_BODY

    return Routing.AVAILABLE


def explain(routing: Routing, path: str) -> str:
    """One agent-facing sentence saying what ``routing`` means for ``path`` and what to do."""
    if routing is Routing.UNROUTED:
        return (
            f"{path} is not routed on this Crosswork instance — the application behind it is "
            "probably not installed or not licensed (Service Health, Change Automation and "
            "Health Insights are absent on single-VM eval builds); for the per-path services "
            "(alarms, sso, notification) it means only this exact path is unknown to the gateway."
        )
    if routing is Routing.ROUTED_NO_PATH:
        return (
            f"{path}: the service is present but this path is not served by this build — "
            "check the API version/base path (alarms, sso and notification route only their "
            "documented paths)."
        )
    if routing is Routing.ROUTED_NO_RBAC:
        return (
            f"{path}: the Crosswork gateway answered 'Unauthorized request' with a fresh token, "
            "so it has no RBAC entry for this path — the endpoint probably does not exist "
            "under this prefix, or the account's role may not call it."
        )
    if routing is Routing.ROUTED_BAD_BODY:
        return (
            f"{path} is served, but the service rejected the request body (malformed JSON "
            "or an unknown field) — the path exists; fix the payload."
        )
    if routing is Routing.INCONCLUSIVE:
        return (
            f"{path}: the probe was inconclusive (an empty-bodied 500 or an auth-layer answer "
            "that says nothing about routing) — the call is allowed through so the real "
            "request can report the actual error; the backend may be down."
        )
    return f"{path} is available on this Crosswork instance."


def prefix_of(path: str) -> str:
    """The routing/cache key for ``path``.

    ``/crosswork/<svc>`` for most services (gateway routing is per top-level
    service prefix, version-agnostic); the full path (query string and fragment
    dropped) for the :data:`PER_PATH_PREFIXES` services, whose routing is per
    path. A path outside ``/crosswork/`` is its own key.
    """
    match = _PREFIX_RE.match(path)
    if not match:
        return path
    if match.group("svc") in PER_PATH_PREFIXES:
        return _QUERY_OR_FRAGMENT_RE.sub("", path)
    return match.group(0)


async def probe_path(
    client: _RequestClient,
    path: str,
    *,
    method: str = "GET",
    json_body: Any = None,
) -> Routing:
    """Issue ONE request to ``path`` and classify the answer. Never raises on HTTP errors.

    Uses ``client.request(..., raise_on_error=False)`` so every status code is
    classified rather than turned into an error; the ApiClient still performs
    its one transparent re-authentication, which is what makes a surviving 403
    ``Unauthorized request`` mean "no RBAC entry" rather than "bad token".
    Transport failures (unreachable host, TLS) propagate as
    :class:`~cnc_mcp.errors.PlatformError` — a probe cannot say anything about
    routing when nothing answered.
    """
    response = await client.request(method, path, json_body=json_body, raise_on_error=False)
    routing = classify(response.status_code, response.text)
    logger.debug("probe %s %s -> %s (%s)", method, path, routing, response.status_code)
    return routing


class Availability:
    """In-memory cache of probe results keyed by :func:`prefix_of` (``/crosswork/aa``,
    or the full path for the per-path services) or by an explicit key.

    One instance lives for the server's lifetime: the first tool that needs a
    service probes its real endpoint once via :meth:`ensure`; every later call
    for the same key answers from memory. Only conclusive probes are
    remembered — a transport failure propagates and an ``INCONCLUSIVE`` verdict
    is returned but not stored, so the next call probes again.
    """

    def __init__(self) -> None:
        self._results: dict[str, Routing] = {}
        self._probed: dict[str, str] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def _key(self, prefix_or_path: str) -> str:
        """Normalise a caller's key: an explicit key stored verbatim by :meth:`ensure`
        wins; otherwise a path is reduced with :func:`prefix_of`."""
        if prefix_or_path in self._results:
            return prefix_or_path
        return prefix_of(prefix_or_path)

    def get(self, prefix: str) -> Routing | None:
        """The cached routing for ``prefix`` — an explicit key given to :meth:`ensure`,
        a service prefix, or a path (reduced with :func:`prefix_of`) — if probed."""
        return self._results.get(self._key(prefix))

    def forget(self, prefix: str | None = None) -> None:
        """Drop one cached key (resolved like :meth:`get`), or every one when None."""
        if prefix is None:
            self._results.clear()
            self._probed.clear()
            return
        key = self._key(prefix)
        self._results.pop(key, None)
        self._probed.pop(key, None)

    async def ensure(
        self,
        client: _RequestClient,
        probe_path_for_prefix: str,
        *,
        prefix: str | None = None,
        method: str = "GET",
        json_body: Any = None,
    ) -> Routing:
        """Probe ``probe_path_for_prefix`` once per key and remember the result.

        The key is ``prefix`` when given (stored verbatim — an explicit key,
        including ``""``, is never reduced) and otherwise :func:`prefix_of` the
        probe path, which is the full path for the per-path services
        (``alarms``, ``sso``, ``notification``). Pass a REAL documented endpoint:
        a made-up path under one of those prefixes looks unrouted. Concurrent
        calls for the same key share one probe. An ``INCONCLUSIVE`` verdict is
        returned but not cached.
        """
        key = prefix if prefix is not None else prefix_of(probe_path_for_prefix)
        cached = self._results.get(key)
        if cached is not None:
            return cached
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            cached = self._results.get(key)
            if cached is not None:
                return cached
            routing = await probe_path(
                client, probe_path_for_prefix, method=method, json_body=json_body
            )
            if routing.conclusive:
                self._results[key] = routing
                self._probed[key] = probe_path_for_prefix
            return routing

    async def require(
        self,
        client: _RequestClient,
        probe_path_for_prefix: str,
        *,
        prefix: str | None = None,
        method: str = "GET",
        json_body: Any = None,
    ) -> Routing:
        """:meth:`ensure`, then raise :class:`PlatformError` (with :func:`explain`'s
        sentence) unless the path is served (``AVAILABLE``, ``ROUTED_BAD_BODY`` or the
        benefit-of-the-doubt ``INCONCLUSIVE``)."""
        routing = await self.ensure(
            client, probe_path_for_prefix, prefix=prefix, method=method, json_body=json_body
        )
        if not routing.served:
            raise PlatformError(explain(routing, probe_path_for_prefix))
        return routing

    def describe(self) -> str:
        """Human-readable summary of every cached key, one line each (sorted)."""
        if not self._results:
            return "No Crosswork service prefixes have been probed yet."
        lines = []
        for key in sorted(self._results):
            routing = self._results[key]
            lines.append(
                f"- {key}: {routing.value} (probed {self._probed.get(key, '?')}) — "
                f"{explain(routing, self._probed.get(key, key))}"
            )
        return "\n".join(lines)
