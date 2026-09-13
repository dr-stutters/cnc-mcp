"""RESTCONF NBI dialect helpers (pure functions, no I/O).

Crosswork exposes several YANG/RESTCONF surfaces behind the same gateway and
JWT as the JSON-over-POST services: the topology and optimization NBIs under
``/crosswork/nbi/*/restconf`` and the transparent NSO proxy under
``/crosswork/proxy/nso/restconf``. Everything in this module encodes behaviour
verified live on Crosswork 7.2 (see the platform notes, "API dialects verified
live 2026-09-12"), and it deliberately departs from the published OpenAPI
documents where the two disagree:

- Errors arrive as ``{"errors": {"error": [...]}}`` with a *bare* ``errors``
  key on Crosswork's own NBIs; the NSO proxy answers with the standard
  ``ietf-restconf:errors`` key (verified on its 415). Both are parsed by the
  same code as :func:`cnc_mcp.errors.http_error` so an agent reads one wording
  whichever path a tool took.
- Keyed GETs are inconsistent: a key on a top-level list may be ignored and
  the whole list returned, while a key on a nested list answers
  ``409 data-missing``. Callers must re-filter client-side.
- ``404`` is never "no such entry" on this gateway: it is the home app's
  unrouted-path fallback or a Spring "No static resource" answer, i.e. the
  service or path is absent. Not-found is spelled ``409 data-missing``.
- RPC application failures ride inside HTTP 200 as ``output.status ==
  "error"`` plus ``output.message`` (Crosswork NBIs) or ``output.result ==
  false`` plus ``output.info`` (NSO device actions).
- NSO device actions (``connect``, ``ssh/fetch-host-keys``, ``sync-from``) are
  RESTCONF *actions* under ``/data/tailf-ncs:devices/device=<name>/...``, not
  ``/operations`` RPCs, and their POST body must be sent as
  ``Content-Type: application/yang-data+json`` (``application/json`` → 415).
- A 500 with an empty body from an RPC means the backend behind that RPC is
  not deployed, not that the request was malformed.
- ``?offset=&limit=`` paging is accepted; whether ``offset`` advances the
  window has not been verified live, and no total is ever reported.

Not for the EMF RESTCONF surfaces (``/crosswork/{inventory,alarm}/restconf/
data/v2``): those return XML for anything but exactly ``Accept:
application/json`` — see :mod:`cnc_mcp.emf`.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

# errors.py is the leaf module (this one imports PlatformError from it), so the
# RESTCONF error-document parser and the verified tag hints live there and are
# reused here rather than re-implemented; making them public names in errors.py
# is the follow-up, out of scope for this change.
from cnc_mcp.errors import (
    _RESTCONF_TAG_HINTS,
    PlatformError,
    _restconf_detail,
    _restconf_errors,
)
from cnc_mcp.formatting import pagination_envelope

YANG_JSON = "application/yang-data+json"
# What was sent live: every RESTCONF GET carried only Accept (a bodiless GET with
# a Content-Type is unverified); the RPC POSTs carried both headers. Plain
# application/json also works for Accept, but yang-data+json is the documented
# type, and the NSO proxy REQUIRES it as the Content-Type of a POST body.
YANG_ACCEPT: dict[str, str] = {"Accept": YANG_JSON}
YANG_HEADERS: dict[str, str] = {**YANG_ACCEPT, "Content-Type": YANG_JSON}

# RESTCONF bases. Verified 200 live: TOPOLOGY_NBI (ietf-network-state:networks)
# and NSO_PROXY (tailf-ncs:devices/device). OPTIMIZATION_NBI is the COE RPC base
# (the guide's nbi/optima/v2 answers 500-empty for every RPC and proves nothing).
# CAT_INVENTORY_NBI is routed by prefix but its backend is unprobed.
TOPOLOGY_NBI = "/crosswork/nbi/topology/v3/restconf"
OPTIMIZATION_NBI = "/crosswork/nbi/optimization/v3/restconf"
CAT_INVENTORY_NBI = "/crosswork/nbi/cat-inventory/v1/restconf"
NSO_PROXY = "/crosswork/proxy/nso/restconf"

# NSO's module prefix on the proxy: device list ``tailf-ncs:devices/device`` and
# action replies ``{"tailf-ncs:output": {...}}`` (both verified live).
NSO_MODULE = "tailf-ncs"
# Device actions verified live through :func:`action_path` (body ``{}``).
NSO_ACTION_CONNECT = "connect"
NSO_ACTION_FETCH_HOST_KEYS = "ssh/fetch-host-keys"
NSO_ACTION_SYNC_FROM = "sync-from"

# Error-tag meanings verified live.
TAG_UNKNOWN_ELEMENT = "unknown-element"  # 400: bad module prefix / container / list name
TAG_MISSING_ATTRIBUTE = "missing-attribute"  # 400: sub-list listed without its parent key
TAG_DATA_MISSING = "data-missing"  # 409: keyed entry does not exist (nested lists only)
TAG_MALFORMED_MESSAGE = "malformed-message"  # 415: NSO proxy refused the body's media type

NSO_415_HINT = (
    "RESTCONF: the request body's media type was rejected. The NSO proxy requires "
    "'Content-Type: application/yang-data+json' on POST bodies (it answers 415 "
    "malformed-message to application/json) — resend with the YANG media type."
)

# The verified tag hints shared with errors.http_error(), plus the NSO proxy's
# 415 which only this module knows about so far (errors.py should adopt the same
# entry so http_error() says it too; until then only this path explains a 415).
RESTCONF_TAG_HINTS: dict[tuple[int, str], str] = {
    **_RESTCONF_TAG_HINTS,
    (415, TAG_MALFORMED_MESSAGE): NSO_415_HINT,
}

# Mirrors the fallback errors._hint_for() uses for a RESTCONF document whose tag
# has no dedicated hint, so both entry points read alike.
_GENERIC_RESTCONF_HINT = (
    "The RESTCONF service rejected the request (see the error-tag). Check the data "
    "path, keys and body against the YANG model."
)
_DETAIL_MAX_CHARS = 300  # same cap errors._extract_detail applies

# Same text errors.http_error() emits for an empty-bodied 500 (asserted by test);
# exposed here for tools that inspect a non-raising response themselves.
EMPTY_500_EXPLANATION = (
    "The backend behind this call is not available on this deployment (the gateway "
    "answered 500 with an empty body). Retrying will not help; the feature is absent "
    "or its service is down."
)


def parse_restconf_errors(data: Any) -> list[dict[str, str | None]]:
    """Normalise a RESTCONF error document into ``[{tag, message, path}, ...]``.

    Locating the entries is delegated to :func:`cnc_mcp.errors._restconf_errors`
    (the single definition of which documents count), so the accepted shapes
    are exactly those :func:`cnc_mcp.errors.http_error` accepts: the live
    Crosswork shape ``{"errors": {"error": [...]}}`` (verified: the NBIs answer
    with a bare ``errors`` key) and the RFC 8040 shape
    ``{"ietf-restconf:errors": {"error": [...]}}`` (verified: the NSO proxy's
    415). ``error`` must be a list, as RFC 8040 defines it; non-dict items are
    skipped. Each entry maps ``error-tag`` / ``error-message`` / ``error-path``
    to ``tag`` / ``message`` / ``path`` (``None`` when absent). Returns ``[]``
    when the body is not an error document at all (including ``None``, a
    non-dict, or an ``errors`` key holding something other than a dict).
    """
    return [
        {
            "tag": _opt_str(item.get("error-tag")),
            "message": _opt_str(item.get("error-message")),
            "path": _opt_str(item.get("error-path")),
        }
        for item in _restconf_errors(data)
    ]


def _opt_str(value: Any) -> str | None:
    """Coerce a scalar error field to a stripped string, or None when absent/empty."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def restconf_error_message(status: int, data: Any) -> str | None:
    """One-line, agent-facing explanation of a RESTCONF error body, or None.

    Produces the same ``<hint> Platform said: <detail>`` text that
    :func:`cnc_mcp.errors.http_error` puts after its ``API request failed with
    status N.`` prefix, for tools that inspect a non-raising response
    (``raise_on_error=False`` / ``ok_statuses``) instead of letting the client
    raise. The hint comes from :data:`RESTCONF_TAG_HINTS` (verified live):

    - ``400`` + ``unknown-element`` → unknown YANG module/path;
    - ``400`` + ``missing-attribute`` → a parent list key is required first;
    - ``409`` + ``data-missing`` → no such object (this platform's not-found);
    - ``415`` + ``malformed-message`` → the NSO proxy wants
      ``Content-Type: application/yang-data+json`` on the body;
    - anything else → the generic "check the path, keys and body" hint.

    The platform's own ``error-path`` is appended as ``(path: ...)`` when
    present (``http_error`` does not surface it). Returns ``None`` when
    ``data`` carries no RESTCONF error document, so callers can fall back to
    the generic HTTP hint.
    """
    entries = _restconf_errors(data)
    if not entries:
        return None
    hint = None
    for err in entries:
        hint = RESTCONF_TAG_HINTS.get((status, str(err.get("error-tag") or "").lower()))
        if hint:
            break
    text = f"{hint or _GENERIC_RESTCONF_HINT} Platform said: "
    text += _restconf_detail(entries)[:_DETAIL_MAX_CHARS]
    path = _opt_str(entries[0].get("error-path"))
    if path:
        text += f" (path: {path})"
    return text


def is_not_found(status: int, data: Any) -> bool:
    """True when a RESTCONF response means "no such entry".

    Two verified spellings:

    - Crosswork's own NBI: a keyed GET on a nested list (``node=nope``) answers
      ``409`` with error-tag ``data-missing``; a 409 with any other tag is a
      real conflict.
    - The NSO proxy: a missing device answers ``404`` **with a RESTCONF error
      document** (``ietf-restconf:errors``, tag ``invalid-value``, message
      ``uri keypath not found``).

    A bare 404 (no RESTCONF error document) is never a not-found on this
    gateway: it is the home app's unrouted-path fallback or Spring's ``No
    static resource``, meaning the API prefix or path is absent. Those are
    left to :func:`cnc_mcp.errors.http_error`, which explains them.
    """
    errors = parse_restconf_errors(data)
    if status == 409:
        return any((e["tag"] or "").lower() == TAG_DATA_MISSING for e in errors)
    if status == 404:
        return bool(errors)
    return False


def unwrap_list(data: Any, module: str, name: str) -> list[Any]:
    """Pull the list of ``<name>`` entries out of a RESTCONF GET body.

    Both verified shapes are handled:

    - keyed/list GET → ``{"<module>:<name>": [...]}`` (e.g.
      ``ietf-network-state:network``), and
    - container GET → ``{"<module>:<plural>": {"<name>": [...]}}`` (e.g.
      ``ietf-network-state:networks`` → ``network``).

    A single entry returned as a bare dict is wrapped into a one-item list, an
    unprefixed ``<name>`` key is tolerated, and ``None`` / ``{}`` (a 204 or an
    empty container) yield ``[]``. The plural container key is not required
    up-front: any ``<module>:``-prefixed dict value holding ``<name>`` is used,
    then any other dict value, so callers need not know the container's name.
    """
    if not isinstance(data, dict) or not data:
        return []
    direct = data.get(f"{module}:{name}", data.get(name))
    if direct is not None:
        return _as_list(direct)
    prefix = f"{module}:"
    candidates = sorted(data.items(), key=lambda kv: not str(kv[0]).startswith(prefix))
    for _key, value in candidates:
        if isinstance(value, dict) and name in value:
            return _as_list(value[name])
    return []


def _as_list(value: Any) -> list[Any]:
    """A list as-is, a dict wrapped as a single entry, anything else → []."""
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def select_key(items: list[Any], key_field: str, key: Any) -> list[Any]:
    """Client-side key filter for RESTCONF list entries.

    Needed because a keyed GET on a top-level list may ignore the key and
    return everything (verified: ``network=does-not-exist`` returned the whole
    ``networks`` list). Matching is case-sensitive and exact; a non-string
    stored value (e.g. an integer ``tunnel-id``) also matches its string form,
    since URL keys are always strings. Non-dict items are dropped.
    """
    out: list[Any] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        value = item.get(key_field)
        if value is None:
            continue
        if value == key or (not isinstance(value, str) and str(value) == str(key)):
            out.append(item)
    return out


def rpc_path(base: str, module: str, rpc: str) -> str:
    """``<base>/operations/<module>:<rpc>`` — the verified RPC URL form.

    E.g. ``rpc_path(OPTIMIZATION_NBI, "cisco-crosswork-optimization-engine-operations",
    "get-plan")``. A trailing slash on ``base`` is tolerated. Not for NSO device
    actions, which live under ``/data`` — use :func:`action_path`.
    """
    return f"{base.rstrip('/')}/operations/{module}:{rpc}"


def action_path(base: str, device_name: str, action: str) -> str:
    """``<base>/data/tailf-ncs:devices/device=<name>/<action>`` — an NSO device action URL.

    Verified live on the NSO proxy: device actions (``connect``,
    ``ssh/fetch-host-keys``, ``sync-from`` — see the ``NSO_ACTION_*``
    constants) are RESTCONF actions addressed under ``/data`` on the device
    entry, NOT ``/operations`` RPCs, so :func:`rpc_path` cannot express them.
    POST the body ``{}`` with :data:`YANG_HEADERS`: the proxy answers ``415``
    ``malformed-message`` to a ``Content-Type: application/json`` body. The
    reply is ``{"tailf-ncs:output": {"result": true|false|"unchanged",
    "info": "..."}}`` — pass it through ``rpc_output(data, NSO_MODULE)`` and
    :func:`check_rpc_output`, because ``result: false`` inside HTTP 200 is the
    failure signal.

    ``device_name`` is percent-encoded as a single list key (``/``, spaces and
    ``,`` included); ``action`` is used verbatim since it may contain a path
    segment (``ssh/fetch-host-keys``). A trailing slash on ``base`` is tolerated.
    """
    key = quote(device_name, safe="")
    return f"{base.rstrip('/')}/data/{NSO_MODULE}:devices/device={key}/{action.strip('/')}"


def rpc_body(**input_fields: Any) -> dict[str, dict[str, Any]]:
    """``{"input": {...}}`` — the verified RPC request envelope.

    ``None``-valued fields are dropped so optional RPC inputs can be passed
    straight through from tool arguments; an empty input is sent as
    ``{"input": {}}`` (RESTCONF requires the ``input`` container even when empty).
    """
    return {"input": {k: v for k, v in input_fields.items() if v is not None}}


def rpc_output(data: Any, module: str) -> dict[str, Any]:
    """Extract the RPC/action ``output`` container from a response body.

    Verified: RPC replies are ``{"<module>:output": {...}}`` (RFC 7951: the
    module that defines the RPC or action, e.g. ``tailf-ncs:output`` for NSO
    device actions). A bare ``"output"`` key is accepted too, and as a
    defensive fallback any single key ending in ``:output`` (unverified whether
    Crosswork ever emits a foreign prefix; two such keys are ambiguous and
    yield ``{}``). Returns ``{}`` when the body is not a dict, the key is
    absent, or its value is not a dict (204 No Content → ``{}``).
    """
    if not isinstance(data, dict):
        return {}
    for key in (f"{module}:output", "output"):
        if isinstance(data.get(key), dict):
            return data[key]
    suffixed = [v for k, v in data.items() if str(k).endswith(":output") and isinstance(v, dict)]
    if len(suffixed) == 1:
        return suffixed[0]
    return {}


def check_rpc_output(output: dict[str, Any], what: str) -> dict[str, Any]:
    """Raise :class:`PlatformError` when an RPC/action reported failure inside HTTP 200.

    Two verified failure signals are recognised:

    - Crosswork NBI RPCs: ``output.status == "error"`` (case-insensitive) with
      the reason in ``output.message`` — ``get-plan`` answered 200 with
      "failed to export network: Abort: Invalid version spec 'current'.".
    - NSO device actions (``connect``, ``ssh/fetch-host-keys``, ``sync-from``):
      ``output.result`` is the JSON boolean ``false`` with the reason in
      ``output.info``; ``true`` and ``"unchanged"`` are success.

    A missing ``status`` / ``result`` (most RPCs report neither) is success.
    Returns ``output`` unchanged on success.
    """
    if not isinstance(output, dict):
        return output
    status = output.get("status")
    if isinstance(status, str) and status.strip().lower() == "error":
        raise PlatformError(f"{what} failed: {_reason(output.get('message'))}")
    if output.get("result") is False:
        raise PlatformError(f"{what} failed: {_reason(output.get('info'))}")
    return output


def _reason(value: Any) -> str:
    """A stripped failure reason string, or 'no message given'."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    return "no message given"


def page_params(offset: int, limit: int) -> dict[str, int]:
    """``?offset=&limit=`` query parameters — accepted by the NBIs (verified).

    Accepted means the request succeeds with them; whether ``offset`` actually
    advances the window (and ``limit`` truncates) has NOT been verified live —
    the JSON-over-POST services on this same platform verifiably ignore a
    top-level ``offset``, so treat paging as unproven until
    ``scripts/live_plumbing_check.py`` asserts that two adjacent ``limit=1``
    pages return different entries. Use with ``ApiClient.request(params=...)``;
    there is no total count anywhere in the reply, so pair with
    :func:`page_envelope_from`.
    """
    return {"offset": offset, "limit": limit}


def page_envelope_from(items: list[Any], offset: int, limit: int) -> dict[str, Any]:
    """Pagination envelope for a RESTCONF page.

    RESTCONF reports no totals, so ``total`` is ``None`` and ``has_more`` is
    inferred from a full page (``len(items) >= limit``); the last page is
    detected only when it comes back short (or empty / 204). Caveat from
    :func:`page_params`: if the NBI ignores ``offset``, every full page reports
    ``has_more`` and a caller following ``next_offset`` loops — cap the number
    of pages a tool will fetch until advancement is verified.
    """
    return pagination_envelope(items, total=None, offset=offset, limit=limit)


def explain_empty_500(status: int, body_text: str | None) -> str | None:
    """Explain a 500 with an EMPTY body from an RPC endpoint, or None.

    Verified: ``list-opm-package`` answers ``500`` with no body at all when the
    backend behind the RPC is not deployed on the instance (the same reply
    from the guide's ``nbi/optima/v2`` base is why that base proves nothing).
    A 500 *with* a body is a different condition (e.g. NATS parse failures)
    and is left to the generic hints. The text is the one
    :func:`cnc_mcp.errors.http_error` uses for the same condition.
    """
    if status != 500:
        return None
    if body_text is None or not body_text.strip():
        return EMPTY_500_EXPLANATION
    return None
