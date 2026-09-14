"""Response formatting shared by all tools.

Every listing tool supports two output formats (agents pick via response_format):
- markdown: human-readable, curated fields, IDs in parentheses
- json: complete structured data for programmatic processing

Every tool response passes through finalize() so oversized payloads are
truncated with a note instead of flooding the agent's context. A JSON
payload is shortened by dropping whole trailing list entries (so it stays
parseable and carries a ``"truncated": true`` marker); anything else is cut
at the character cap with a bracketed note. The note's hint is generic
unless the tool passes its own — finalize() must never promise a parameter
the tool does not have.
"""

from __future__ import annotations

import json
from contextvars import ContextVar
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from cnc_mcp.config import Settings


class ResponseFormat(StrEnum):
    """Output format for tool responses."""

    MARKDOWN = "markdown"
    JSON = "json"


def to_json(data: Any) -> str:
    """Serialize API data for the agent (stable keys, non-JSON types stringified)."""
    return json.dumps(data, indent=2, default=str)


def pagination_envelope(
    items: list[Any], *, total: int | None, offset: int, limit: int
) -> dict[str, Any]:
    """Standard pagination wrapper for list responses.

    total may be None when the platform doesn't report an overall count; has_more
    then falls back to 'page came back full'.
    """
    count = len(items)
    if total is not None:
        has_more = offset + count < total
    else:
        has_more = count >= limit
    return {
        "total": total,
        "count": count,
        "offset": offset,
        "items": items,
        "has_more": has_more,
        "next_offset": offset + count if has_more else None,
    }


# What an oversized response tells the agent to do when the tool gave no hint of
# its own. Deliberately names no parameter: not every tool pages, and the ones
# that do spell out their paging arguments in their own description.
TRUNCATION_HINT = (
    "Narrow the query with the tool's filters, or page through the results if the "
    "tool offers paging (its description says so)."
)

# JSON-aware truncation parses the whole payload once; past this size the plain
# character cut is used so a pathological response cannot stall the server.
_JSON_AWARE_MAX_CHARS = 8_000_000


# Set (by tools/composite.py) around a server-side sub-call: the answer feeds
# another tool, never an agent's context, so the size cap must not apply — the
# composite's own finalize() caps what finally leaves the server. A capped
# sub-answer would silently drop data the composite then reasons over
# (verified in an agent scenario: an alarm triage read 15 of 32 alarms).
uncapped_internal_call: ContextVar[bool] = ContextVar(
    "cnc_mcp_uncapped_internal_call", default=False
)


def finalize(text: str, settings: Settings, *, hint: str | None = None) -> str:
    """Apply the response-size cap. Call as the last step of every tool.

    Inside a server-side composite sub-call (:data:`uncapped_internal_call`
    true) the text is returned untouched: the cap belongs to the answer that
    reaches the client, not to an intermediate one.

    ``hint`` is the tool's own advice for an oversized answer (e.g. "Lower
    page_size or narrow with app_id."); without it the generic
    :data:`TRUNCATION_HINT` is used. A JSON payload (a list, or an object with
    a list-valued key — ``items`` preferred, else the largest list) is
    shortened by dropping whole trailing entries of that list, so the result
    stays parseable and reports what happened: ``"truncated": true``,
    ``"shown": <entries kept>`` and ``"truncation_note"``; a bare list is
    wrapped as ``{"items": [...]}`` to carry the marker. When that cannot
    keep at least one entry, or the text is not such a JSON payload, the
    text is cut at the cap and a bracketed note is appended instead.
    """
    if uncapped_internal_call.get():
        return text
    limit = settings.max_response_chars
    if len(text) <= limit:
        return text
    advice = hint or TRUNCATION_HINT
    shortened = _truncate_json(text, limit, advice)
    if shortened is not None:
        return shortened
    return text[:limit] + f"\n\n[Truncated: response exceeded {limit} characters. {advice}]"


def _truncate_json(text: str, limit: int, advice: str) -> str | None:
    """Parseable shortening of an oversized JSON payload, or None when not possible.

    Only a top-level list, or an object with at least one list-valued key,
    qualifies; entries are dropped from the end of that list (``items`` when
    present, otherwise the largest list) until the re-serialised payload fits.
    None when the text is not JSON, has no list to shorten, or not even one
    entry fits — the caller then falls back to the plain cut.
    """
    if len(text) > _JSON_AWARE_MAX_CHARS or text.lstrip()[:1] not in ("{", "["):
        return None
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return None
    if isinstance(data, list):
        container: dict[str, Any] = {"items": data}
        key = "items"
    elif isinstance(data, dict):
        lists = {k: v for k, v in data.items() if isinstance(v, list)}
        if not lists:
            return None
        container = data
        key = "items" if "items" in lists else max(lists, key=lambda k: len(to_json(lists[k])))
    else:
        return None
    entries = container[key]
    total = len(entries)

    def render(shown: int) -> str:
        note = (
            f"Response exceeded {limit} characters: {total - shown} of {total} '{key}' "
            f"entries were dropped. {advice}"
        )
        out: dict[str, Any] = {"truncated": True, "shown": shown, "truncation_note": note}
        out.update((k, v) for k, v in container.items() if k not in out)
        out[key] = entries[:shown]
        return to_json(out)

    # Largest number of entries (at least one) whose rendering fits the cap.
    # Probes shrink geometrically while they overshoot, so the total work is
    # about one serialisation of the original payload.
    best = 0
    lo, hi = 1, total - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if len(render(mid)) <= limit:
            best, lo = mid, mid + 1
        else:
            hi = mid - 1
    if not best:
        return None
    result = render(best)
    while len(result) > limit and best > 1:  # the note's digits shift by a char or two
        best -= 1
        result = render(best)
    return result if len(result) <= limit else None


def epoch_iso(value: Any) -> str:
    """Render an epoch timestamp as ISO-8601 UTC, whatever unit the platform used.

    dg-manager mixes units per field (``createdTime`` in nanoseconds,
    ``lastUpdatedTime`` in seconds, file ``modifiedTime`` in seconds, outage
    timestamps in nanoseconds) and sends them as ints or numeric strings; the
    unit is inferred from the magnitude. ``0``/empty/unparseable -> ``-`` /
    the raw text.
    """
    if value in (None, ""):
        return "-"
    try:
        n = int(str(value).strip())
    except ValueError:
        return str(value)
    if n <= 0:
        return "-"
    seconds: float = n
    for threshold, divisor in ((10**17, 10**9), (10**14, 10**6), (10**11, 10**3)):
        if n >= threshold:
            seconds = n / divisor
            break
    try:
        return datetime.fromtimestamp(seconds, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return str(value)
