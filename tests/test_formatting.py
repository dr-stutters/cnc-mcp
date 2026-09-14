"""formatting.py — the response-size cap and the helpers every tool shares.

No HTTP here: finalize() takes text, so the truncation behaviour is exercised
directly with a small max_response_chars.
"""

from __future__ import annotations

import json

from cnc_mcp.formatting import (
    TRUNCATION_HINT,
    epoch_iso,
    finalize,
    pagination_envelope,
    to_json,
)


def _items(n: int, size: int = 40) -> list[dict]:
    return [{"id": i, "pad": "x" * size} for i in range(n)]


# --- finalize: plain text ------------------------------------------------------


def test_finalize_returns_short_text_unchanged(make_settings):
    settings = make_settings(max_response_chars=1_000)
    assert finalize("hello", settings) == "hello"
    exact = "y" * 1_000
    assert finalize(exact, settings) == exact


def test_finalize_cuts_text_with_a_generic_hint_that_promises_no_parameter(make_settings):
    """The generic hint must not name limit/offset (or any parameter): most tools
    lack them, and an agent that trusts the hint tries arguments that do not exist."""
    settings = make_settings(max_response_chars=1_000)
    text = finalize("# Report\n" + "z" * 5_000, settings)
    assert text.startswith("# Report\n" + "z" * 991)
    assert "[Truncated: response exceeded 1000 characters. " + TRUNCATION_HINT + "]" in text
    assert "limit/offset" not in text and "limit" not in TRUNCATION_HINT.lower()
    assert "page through" in TRUNCATION_HINT and "filters" in TRUNCATION_HINT


def test_finalize_uses_the_tools_own_hint(make_settings):
    settings = make_settings(max_response_chars=1_000)
    text = finalize("z" * 5_000, settings, hint="Lower page_size or narrow with app_id.")
    assert text.endswith(
        "[Truncated: response exceeded 1000 characters. Lower page_size or narrow with app_id.]"
    )
    assert TRUNCATION_HINT not in text


# --- finalize: JSON-aware truncation ----------------------------------------


def test_finalize_drops_trailing_items_and_keeps_json_parseable(make_settings):
    settings = make_settings(max_response_chars=2_000)
    payload = {"total": 100, "count": 100, "has_more": False, "items": _items(100)}
    text = finalize(to_json(payload), settings)
    assert len(text) <= 2_000
    data = json.loads(text)
    assert data["truncated"] is True
    assert 1 <= data["shown"] < 100 and len(data["items"]) == data["shown"]
    assert data["items"] == _items(data["shown"])  # whole leading entries, in order
    assert data["total"] == 100 and data["count"] == 100  # the tool's figures are untouched
    assert data["has_more"] is False
    note = data["truncation_note"]
    assert note.startswith("Response exceeded 2000 characters: ")
    assert f"{100 - data['shown']} of 100 'items' entries were dropped." in note
    assert note.endswith(TRUNCATION_HINT)
    # marker keys lead so a reader sees them before the payload
    assert list(data)[:3] == ["truncated", "shown", "truncation_note"]
    assert "[Truncated" not in text


def test_finalize_json_truncation_keeps_as_many_items_as_fit(make_settings):
    settings = make_settings(max_response_chars=3_000)
    payload = {"items": _items(200)}
    data = json.loads(finalize(to_json(payload), settings))
    one_more = {**data, "items": _items(data["shown"] + 1)}
    assert len(to_json(one_more)) > 3_000  # one more entry would not have fit


def test_finalize_json_truncation_carries_the_tool_hint(make_settings):
    settings = make_settings(max_response_chars=2_000)
    text = finalize(to_json({"items": _items(100)}), settings, hint="Lower page_size.")
    data = json.loads(text)
    assert data["truncation_note"].endswith("Lower page_size.")
    assert TRUNCATION_HINT not in text


def test_finalize_wraps_a_bare_json_list(make_settings):
    settings = make_settings(max_response_chars=2_000)
    data = json.loads(finalize(to_json(_items(100)), settings))
    assert data["truncated"] is True and data["items"] == _items(data["shown"])
    assert "'items' entries were dropped" in data["truncation_note"]


def test_finalize_json_truncation_picks_items_then_the_largest_list(make_settings):
    settings = make_settings(max_response_chars=2_000)
    # "items" wins even when another list is larger
    payload = {"other": _items(8, 60), "items": _items(50, 10)}
    data = json.loads(finalize(to_json(payload), settings))
    assert data["truncated"] is True and len(data["items"]) < 50 and len(data["other"]) == 8
    # Otherwise the list with the largest serialisation is shortened, and named
    payload = {"small": _items(3), "big": _items(80)}
    data = json.loads(finalize(to_json(payload), settings))
    assert len(data["small"]) == 3 and 1 <= len(data["big"]) < 80
    assert "'big' entries were dropped" in data["truncation_note"]


def test_finalize_overrides_a_tools_truncated_false(make_settings):
    """cnc_search_alarms reports its own limit cut as ``truncated``; a size cut
    must turn that True rather than leave a contradictory False beside the marker."""
    settings = make_settings(max_response_chars=2_000)
    payload = {"truncated": False, "items": _items(100)}
    data = json.loads(finalize(to_json(payload), settings))
    assert data["truncated"] is True and list(data).count("truncated") == 1


def test_finalize_falls_back_to_the_text_cut_when_json_cannot_be_shortened(make_settings):
    settings = make_settings(max_response_chars=1_000)
    # an object with no list to shorten (e.g. aaa/v1/role keyed by role name)
    text = finalize(to_json({f"role-{i}": {"pad": "x" * 100} for i in range(50)}), settings)
    assert text.endswith(f"{TRUNCATION_HINT}]") and len(text) > 1_000
    # not even one entry fits
    text = finalize(to_json({"items": [{"pad": "x" * 3_000}, {"pad": "y" * 3_000}]}), settings)
    assert "[Truncated: response exceeded 1000 characters." in text
    # a single entry cannot be "dropped from the end"
    text = finalize(to_json({"items": [{"pad": "x" * 3_000}]}), settings)
    assert "[Truncated: response exceeded 1000 characters." in text
    # markdown followed by JSON is not a JSON payload
    text = finalize("Line one\n\n" + to_json({"items": _items(100)}), settings)
    assert text.startswith("Line one\n\n{") and "[Truncated" in text
    # malformed JSON that starts like JSON
    text = finalize("{" + "x" * 5_000, settings)
    assert text.startswith("{" + "x" * 999) and "[Truncated" in text
    # a JSON scalar
    text = finalize(json.dumps("s" * 5_000), settings)
    assert "[Truncated" in text


def test_finalize_json_truncation_never_exceeds_the_cap(make_settings):
    """Sweep item sizes around the cap so the fit is checked, not assumed."""
    for size in (10, 55, 120, 333, 900):
        settings = make_settings(max_response_chars=2_000)
        text = finalize(to_json({"items": _items(300, size)}), settings)
        assert len(text) <= 2_000, size
        json.loads(text)


# --- pagination_envelope ---------------------------------------------------------


def test_pagination_envelope_with_and_without_total():
    env = pagination_envelope([1, 2], total=5, offset=2, limit=2)
    assert env == {
        "total": 5,
        "count": 2,
        "offset": 2,
        "items": [1, 2],
        "has_more": True,
        "next_offset": 4,
    }
    assert pagination_envelope([1], total=5, offset=4, limit=2)["has_more"] is False
    # no total: a full page means "maybe more"
    assert pagination_envelope([1, 2], total=None, offset=0, limit=2)["has_more"] is True
    assert pagination_envelope([1], total=None, offset=0, limit=2)["next_offset"] is None


# --- epoch_iso -------------------------------------------------------------------


def test_epoch_iso_units_and_edge_cases():
    assert epoch_iso(1757700000) == "2025-09-12T18:00:00Z"  # seconds
    assert epoch_iso("1757700000000") == "2025-09-12T18:00:00Z"  # milliseconds
    assert epoch_iso(1757700000000000) == "2025-09-12T18:00:00Z"  # microseconds
    assert epoch_iso("1757700000000000000") == "2025-09-12T18:00:00Z"  # nanoseconds
    assert epoch_iso(None) == "-" and epoch_iso("") == "-" and epoch_iso(0) == "-"
    assert epoch_iso("not-a-number") == "not-a-number"
