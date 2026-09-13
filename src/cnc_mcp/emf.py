"""EMF RESTCONF dialect helpers (inventory, alarm and performance RESTCONF).

Crosswork's Element Management Functions expose a second, RESTCONF-flavoured API
next to the JSON-over-POST services handled by :mod:`cnc_mcp.crosswork`:

- ``/crosswork/inventory/restconf/data/v2`` (``resource-physical:node``, ...)
- ``/crosswork/alarm/restconf/data/v2`` (``rtm:alarm``, ``alarm:handle-alarm``)
- ``/crosswork/performance/restconf/data/v1`` (``resource-network:performance-*``)

Everything in this module encodes behaviour verified live on the 7.2 lab
instance (platform notes, "API dialects verified live 2026-09-12", family 3)
for the inventory and alarm bases, cross-checked against the published RESTCONF
OpenAPI documents. The performance base is documented with the same dialect but
was unrouted on the lab, so nothing below is verified for it:

- JSON is returned ONLY for exactly ``Accept: application/json``. Sending
  ``application/yang-data+json``, ``*/*`` or any q-list yields XML. Tools must
  send :data:`EMF_HEADERS` unchanged and check :func:`looks_like_xml` before
  parsing (``ApiClient.request_json`` would otherwise report the XML as "the
  base_url may point at a UI endpoint", which is the wrong hint here).
- Paging is ``?.startIndex=<n>&.maxCount=<n>`` (0-based, max 100 per page per
  the specs); the position comes back in the body, not in headers. Only page 0
  (``com.firstIndex 0`` / ``com.lastIndex 0``) has been observed live, so
  whether the header positions are absolute offsets or page-relative at
  ``.startIndex > 0`` is unknown — :func:`page_envelope_from` advances by page
  length, which is correct under either reading.
- The envelope is
  ``{"com.response-message": {"com.header": {"com.firstIndex", "com.lastIndex",
  "com.iteratorId"}, "com.data": {"<prefix>.<list>": [...]}}}``. The data key is
  namespace-prefixed and varies by module (``nd.node``, ``tp.termination-point``,
  ``eq.chassis``, ``alm.alarm``, ``perf.perf-metrics``) and the objects inside
  carry prefixed field names too, often several prefixes per object
  (``nd.uuid`` next to ``fdtn.name``). One response may carry SEVERAL sibling
  lists under ``com.data`` — the documented ``resource-physical:equipment``
  answer has ``eq.module``, ``eq.equipment`` and ``eq.chassis`` side by side
  with ``com.lastIndex`` counting across all of them — so :func:`unwrap`
  concatenates every list it finds, in order.
- An empty result has ``com.lastIndex == -1`` and NO ``com.data`` at all.

Every function here is pure (no I/O): call ``client.request(...)`` with
:data:`EMF_HEADERS` and :func:`page_params`, then :func:`decode_json`,
:func:`unwrap`, :func:`page_envelope_from` and (for rendering)
:func:`strip_prefixes`, in that order.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

from cnc_mcp.errors import PlatformError
from cnc_mcp.formatting import pagination_envelope

EMF_INVENTORY = "/crosswork/inventory/restconf/data/v2"
EMF_ALARM = "/crosswork/alarm/restconf/data/v2"
# Documented base (note the v1). The `performance` prefix was NOT routed on the lab
# instance at its documented paths (platform notes, "Routing detection, refined").
EMF_PERFORMANCE = "/crosswork/performance/restconf/data/v1"

# Spec text on every EMF RESTCONF list operation: "The default max batch size for
# retrieval is set to 100 and maximum 100 objects can be retrieved."
MAX_COUNT = 100
DEFAULT_MAX_COUNT = 100

EMF_HEADERS: dict[str, str] = {"Accept": "application/json"}
"""Request headers for every EMF RESTCONF call — must be exactly this.

Verified live on the inventory (``resource-physical:node``) and alarm
(``rtm:alarm``) bases: they return JSON only when the Accept header is exactly
``application/json``. ``application/yang-data+json`` (what the RESTCONF RFC and
the NBI dialect use), ``*/*``, or any comma-separated list / q-list
(``application/json, */*;q=0.8``) all make the service fall back to XML — with an
HTTP 200, so nothing but the body tells you it happened. The performance base
(``/crosswork/performance/restconf/data/v1``) is documented with the same
dialect but was unrouted on the 7.2 lab, so its behaviour is presumed, not
verified. Pass this mapping unchanged as the per-request ``headers`` (do not
merge extra Accept values into it) and run the body through
:func:`looks_like_xml` / :func:`decode_json`.
"""

ENVELOPE_KEY = "com.response-message"
HEADER_KEY = "com.header"
DATA_KEY = "com.data"

# A namespace prefix is a leading identifier followed by a dot and at least one
# more character: "nd.node", "com.header", "fdtn.name". Keys starting with a dot
# (".startIndex"), a digit ("1.2.3.4") or without a dot are left alone.
_PREFIX_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*\.(?=.)")
# ``\ufeff`` is a possible byte-order mark; ``re`` understands the escape even
# inside a raw string, so the pattern stays visible in editors and diffs.
_XML_START_RE = re.compile(r"^\ufeff?\s*<(\?xml|[A-Za-z_][\w.:-]*)")
_XML_ELEMENT_RE = re.compile(r"<([A-Za-z_][\w.:-]*)")


def page_params(start_index: int, max_count: int) -> dict[str, int]:
    """Query parameters for one EMF RESTCONF page: ``{".startIndex": n, ".maxCount": n}``.

    ``start_index`` is a 0-based object offset (not a page number); ``max_count``
    is the page size, 1..100 — the specs cap every EMF list at 100 objects per
    retrieval. Values outside those ranges raise :class:`PlatformError` here so
    the agent gets an actionable message instead of an opaque platform answer.
    """
    if isinstance(start_index, bool) or not isinstance(start_index, int) or start_index < 0:
        raise PlatformError(
            f"start_index must be an integer >= 0 (got {start_index!r}); it is a 0-based "
            "object offset, not a page number."
        )
    if (
        isinstance(max_count, bool)
        or not isinstance(max_count, int)
        or not 1 <= max_count <= MAX_COUNT
    ):
        raise PlatformError(
            f"max_count must be an integer between 1 and {MAX_COUNT} (got {max_count!r}); "
            "EMF RESTCONF retrieves at most 100 objects per request."
        )
    return {".startIndex": start_index, ".maxCount": max_count}


def looks_like_xml(text: str) -> bool:
    """True when a response body is the XML fallback rather than JSON.

    Verified live (inventory and alarm bases): an EMF RESTCONF request whose
    Accept header is not exactly ``application/json`` answers HTTP 200 with an
    XML document. The body starts
    with an XML declaration (``<?xml``) or straight with the root element. HTML
    (``<html``/``<!DOCTYPE``) is not the RESTCONF XML fallback and returns False;
    JSON, empty and non-string bodies return False.
    """
    if not isinstance(text, str):
        return False
    match = _XML_START_RE.match(text)
    if match is None:
        return False
    return match.group(1).lower() != "html"


def explain_xml(text: str) -> str:
    """Agent-facing explanation for an XML body: the request lacked the exact Accept.

    Names the root element when one can be found (``response-message`` means the
    service answered the query and only the media type went wrong) and tells the
    agent to re-send with :data:`EMF_HEADERS` unchanged. Safe to embed in an
    ``Error: ...`` string; never echoes the XML itself.
    """
    root = _root_element(text)
    where = f" (root element <{root}>)" if root else ""
    return (
        f"Crosswork answered this EMF RESTCONF request with XML{where} instead of JSON. "
        "The EMF RESTCONF services return JSON only when the request carries exactly "
        "'Accept: application/json' (verified live on /crosswork/inventory|alarm/restconf/"
        "data/v2; /crosswork/performance/restconf/data/v1 is documented the same way but "
        "was unrouted on the 7.2 lab, so there it is presumed); 'application/yang-data+json', "
        "'*/*' or any list of media types makes them fall back to XML. Re-send the request "
        "with the EMF_HEADERS mapping unchanged and no additional Accept values."
    )


def decode_json(text: str | None) -> Any:
    """Parse an EMF RESTCONF body: JSON -> data, empty -> None, XML -> PlatformError.

    Use instead of ``response.json()`` so the XML fallback (see :data:`EMF_HEADERS`)
    surfaces as the specific :func:`explain_xml` hint rather than a generic
    non-JSON error. Any other unparsable body raises :class:`PlatformError` with a
    short, non-HTML excerpt.
    """
    if text is None or not text.strip():
        return None
    if looks_like_xml(text):
        raise PlatformError(explain_xml(text))
    try:
        return json.loads(text)
    except ValueError as e:
        stripped = text.strip()
        excerpt = "an HTML page (not shown)" if stripped.startswith("<") else repr(stripped[:200])
        raise PlatformError(
            f"EMF RESTCONF returned a body that is neither JSON nor XML: {excerpt}. "
            "Check the endpoint path (an unknown path under a routed prefix answers 403, "
            "an unrouted prefix falls through to the home app)."
        ) from e


def unwrap(data: Any) -> tuple[list[Any], dict[str, int | None]]:
    """Split a ``com.response-message`` envelope into ``(items, header)``.

    ``header`` is ``{"first_index", "last_index", "iterator_id"}`` from
    ``com.header`` (``None`` for anything absent — ``com.iteratorId`` is missing
    from several documented responses). ``items`` is the concatenation, in dict
    order, of EVERY list found under ``com.data`` whatever its prefixed keys
    (``nd.node``, ``alm.alarm``, ...): the documented ``resource-physical:equipment``
    response carries ``eq.module``, ``eq.equipment`` and ``eq.chassis`` side by
    side and its ``com.lastIndex`` counts across all three, so reading only one
    list would silently drop objects. When no key holds a list, the first dict
    under ``com.data`` is returned as a single item. :func:`data_keys` reports
    which keys were read. The verified empty shape
    (``com.lastIndex == -1`` and no ``com.data``) yields ``([], header)`` with
    ``last_index == -1``. A body without ``com.response-message`` (or a non-dict)
    yields ``([], header)`` with every header value ``None`` — callers decide
    whether that is an empty page or a wrong endpoint. Items keep their prefixed
    field names; apply :func:`strip_prefixes` afterwards for rendering.
    """
    header: dict[str, int | None] = {"first_index": None, "last_index": None, "iterator_id": None}
    if not isinstance(data, dict):
        return [], header
    message = data.get(ENVELOPE_KEY)
    if not isinstance(message, dict):
        return [], header
    raw_header = message.get(HEADER_KEY)
    if isinstance(raw_header, dict):
        header = {
            "first_index": _as_int(raw_header.get("com.firstIndex")),
            "last_index": _as_int(raw_header.get("com.lastIndex")),
            "iterator_id": _as_int(raw_header.get("com.iteratorId")),
        }
    items: list[Any] = []
    for _, values in _data_entries(message.get(DATA_KEY)):
        items.extend(values)
    return items, header


def data_keys(data: Any) -> list[str]:
    """The prefixed keys under ``com.data`` that :func:`unwrap` reads, in order.

    Diagnostics only: lets a tool report which list(s) the service answered with
    when the shape is unexpected — ``["nd.node"]`` for a node page,
    ``["eq.module", "eq.equipment", "eq.chassis"]`` for the documented equipment
    response. When ``com.data`` is a dict but holds nothing list- or dict-valued
    (so :func:`unwrap` read nothing) every key present is returned, so the
    diagnostic still names what came back. Empty when there is no ``com.data``
    (the empty result), when it is not a dict, or when it is a bare list.
    """
    if not isinstance(data, dict):
        return []
    message = data.get(ENVELOPE_KEY)
    if not isinstance(message, dict):
        return []
    com_data = message.get(DATA_KEY)
    if not isinstance(com_data, dict) or not com_data:
        return []
    keys = [key for key, _ in _data_entries(com_data) if isinstance(key, str)]
    return keys or [str(key) for key in com_data]


def data_key(data: Any) -> str | None:
    """The first of :func:`data_keys` (e.g. ``nd.node``), or ``None`` when there is none.

    Convenience for the common single-list response; a multi-list response has
    more keys than this reports, so prefer :func:`data_keys` in diagnostics.
    """
    keys = data_keys(data)
    return keys[0] if keys else None


def page_envelope_from(
    items: list[Any],
    header: dict[str, int | None],
    start_index: int,
    max_count: int,
) -> dict[str, Any]:
    """Pagination envelope for an EMF page, on top of the template's offset one.

    Built with ``formatting.pagination_envelope(total=None)`` (EMF reports no
    overall count) and then corrected from the ``com.header`` positions. The
    page length is ``last_index - first_index + 1`` (0 when ``last_index`` is
    -1); ``has_more`` is True when that is >= ``max_count`` (a full page), else
    False — so an exactly-full final page reports ``has_more`` and the next
    request comes back empty (``last_index == -1``), which is normal.
    ``next_start_index`` is ``start_index + page length`` when ``has_more``,
    else ``None``. Only page 0 (``firstIndex 0`` / ``lastIndex 0``) has been
    verified live, so whether the header positions are absolute collection
    offsets or page-relative at ``.startIndex > 0`` is unknown; advancing by
    page length equals ``last_index + 1`` under the absolute reading and stays
    correct under the page-relative one (where ``last_index + 1`` would send an
    agent back to the same page forever). When the header carries no
    ``last_index`` at all, the template's "page came back full" rule applies
    and the advance is the item count. Adds ``first_index``, ``last_index``,
    ``iterator_id``, ``start_index``, ``max_count`` and ``next_start_index``;
    ``next_offset`` mirrors ``next_start_index``.
    """
    env = pagination_envelope(items, total=None, offset=start_index, limit=max_count)
    first = header.get("first_index")
    last = header.get("last_index")
    if last is None:
        has_more = bool(env["has_more"])
        next_start = start_index + len(items) if has_more else None
    else:
        if first is None:
            first = start_index
        page_len = max(0, last - first + 1) if last >= 0 else 0
        has_more = page_len >= max_count
        next_start = start_index + page_len if has_more else None
    env["has_more"] = has_more
    env["next_offset"] = next_start
    env["first_index"] = first if last is not None else header.get("first_index")
    env["last_index"] = last
    env["iterator_id"] = header.get("iterator_id")
    env["start_index"] = start_index
    env["max_count"] = max_count
    env["next_start_index"] = next_start
    return env


def strip_prefixes(obj: Any) -> Any:
    """Return a copy of ``obj`` with the ``xx.`` namespace prefixes dropped from dict keys.

    Applies recursively through dicts and lists: ``{"nd.node": [{"nd.uuid": ..,
    "fdtn.name": ..}]}`` becomes ``{"node": [{"uuid": .., "name": ..}]}``. Keys
    without a leading ``<identifier>.`` (``uuid``, ``.startIndex``, ``1.2.3.4``)
    are kept as they are, and values — string values in particular, which may
    legitimately contain dots (FDNs, IPs, ``<status>`` XML snippets) — are never
    touched. A key takes its stripped name only when no other key in the same
    dict maps to that name (an unprefixed key counts for its own name, so
    ``{"eq.name": .., "name": ..}`` keeps both) and the name is not itself
    another key of that dict; otherwise every key involved keeps its original
    prefixed name — ``{"fdtn.name": .., "eq.name": ..}`` comes back unchanged.
    No value is ever dropped or silently moved to another namespace's name.
    Non-container inputs are returned unchanged.
    """
    if isinstance(obj, dict):
        stripped = {key: _strip_key(key) for key in obj}
        claims = Counter(stripped.values())
        out: dict[Any, Any] = {}
        for key, value in obj.items():
            new_key = stripped[key]
            if claims[new_key] > 1 or (new_key != key and new_key in obj):
                new_key = key
            out[new_key] = strip_prefixes(value)
        return out
    if isinstance(obj, list):
        return [strip_prefixes(item) for item in obj]
    return obj


def _as_int(value: Any) -> int | None:
    """Coerce a header position to int (``None`` for absent or non-numeric values)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _strip_key(key: Any) -> Any:
    """``key`` without its leading ``<identifier>.`` namespace prefix (non-strings as-is)."""
    return _PREFIX_RE.sub("", key, count=1) if isinstance(key, str) else key


def _data_entries(com_data: Any) -> list[tuple[str | None, list[Any]]]:
    """Locate the payload lists under ``com.data`` as ``(key, items)`` pairs, in order.

    Every list-valued key contributes its list (a response may carry several
    sibling lists). When no key holds a list, the first dict-valued key
    contributes that dict as a single item. A bare list directly under
    ``com.data`` is accepted with key ``None``. Empty when nothing is payload-like.
    """
    if isinstance(com_data, list):
        return [(None, list(com_data))]
    if not isinstance(com_data, dict):
        return []
    entries = [(key, list(value)) for key, value in com_data.items() if isinstance(value, list)]
    if entries:
        return entries
    for key, value in com_data.items():
        if isinstance(value, dict):
            return [(key, [value])]
    return []


def _root_element(text: str) -> str | None:
    """Name of the first XML element that is not the ``<?xml`` declaration."""
    if not isinstance(text, str):
        return None
    for match in _XML_ELEMENT_RE.finditer(text[:2000]):
        return match.group(1)
    return None
