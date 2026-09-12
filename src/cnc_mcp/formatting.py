"""Response formatting shared by all tools.

Every listing tool supports two output formats (agents pick via response_format):
- markdown: human-readable, curated fields, IDs in parentheses
- json: complete structured data for programmatic processing

Every tool response passes through finalize() so oversized payloads are
truncated with a note instead of flooding the agent's context.
"""

from __future__ import annotations

import json
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


def finalize(text: str, settings: Settings) -> str:
    """Apply the response-size cap. Call as the last step of every tool."""
    limit = settings.max_response_chars
    if len(text) <= limit:
        return text
    return (
        text[:limit]
        + f"\n\n[Truncated: response exceeded {limit} characters. "
        "Narrow the query with filters, or page through results with limit/offset.]"
    )
