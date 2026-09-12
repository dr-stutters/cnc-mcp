"""Crosswork-specific helpers: query bodies, envelopes, job checking, enums."""

from __future__ import annotations

import pytest

from cnc_mcp.crosswork import (
    ADMIN_STATES,
    check_job,
    ipaddr,
    page_envelope,
    parse_impacted,
    query_body,
    unwrap,
    wire_enum,
)
from cnc_mcp.errors import PlatformError


def test_query_body_uses_filterdata_paging_and_drops_empty_filters():
    body = query_body({"host_name": "PE*", "profile": "", "uuid": None}, page_size=20, page=2)
    assert body == {
        "filter": {"host_name": "PE*"},
        "filterData": {"PageSize": 20, "PageNum": 2, "Criteria": ""},
    }
    assert "offset" not in body and "limit" not in body  # offset is ignored by Crosswork


@pytest.mark.parametrize(
    ("data", "key", "expected"),
    [
        ({}, "data", ([], None, None)),  # empty inventory returns a bare {}
        ({"total_count": 5}, "data", ([], None, 5)),  # zero matches: result_count omitted
        ({"data": [{"a": 1}], "total_count": 5, "result_count": 1}, "data", ([{"a": 1}], 1, 5)),
        ({"tags": [{"name": "mdt"}]}, "tags", ([{"name": "mdt"}], None, None)),
        ("not a dict", "data", ([], None, None)),
    ],
)
def test_unwrap_tolerates_every_envelope_shape(data, key, expected):
    assert unwrap(data, key) == expected


def test_page_envelope_uses_result_count_for_has_more():
    env = page_envelope([1, 2], result_count=5, total_count=9, page_size=2, page=0)
    assert env["total"] == 5 and env["collection_total"] == 9
    assert env["has_more"] is True and env["next_page"] == 1 and env["offset"] == 0


def test_page_envelope_falls_back_to_full_page_when_no_result_count():
    full = page_envelope([1, 2], result_count=None, total_count=5, page_size=2, page=1)
    assert full["has_more"] is True and full["next_page"] == 2 and full["offset"] == 2
    short = page_envelope([1], result_count=None, total_count=5, page_size=2, page=1)
    assert short["has_more"] is False and short["next_page"] is None


def test_check_job_accepts_completed_and_parses_impacted():
    env = check_job(
        {
            "job_id": "j1",
            "state": "JOB_COMPLETED",
            "impacted": ["u-1 PE1 198.18.140.11", "u-2 nso"],
        },
        "Create device",
    )
    assert env["impacted_objects"] == [
        {"uuid": "u-1", "name": "PE1", "ip": "198.18.140.11"},
        {"uuid": "u-2", "name": "nso"},
    ]


def test_check_job_treats_completed_with_warning_as_success():
    env = check_job(
        {
            "job_id": "j3",
            "state": "JOB_COMPLETED_WITH_WARNING",
            "type": "1 device(s) details patched  (Completed with warnings)",
            "error": "Note, if device af19 has no changes ...",
            "impacted": ["u-1 PE1"],
        },
        "Update device",
    )
    assert env["warning"].startswith("Note, if device")
    assert env["impacted_objects"] == [{"uuid": "u-1", "name": "PE1"}]


def test_check_job_raises_on_failed_state_with_reason():
    with pytest.raises(PlatformError, match="Software Type needs"):
        check_job(
            {
                "job_id": "j2",
                "state": "JOB_FAILED",
                "type": "updation failed",
                "error": "Software Type needs to be configured",
            },
            "Update device",
        )


def test_check_job_raises_when_no_envelope():
    with pytest.raises(PlatformError, match="did not return a job envelope"):
        check_job({"data": []}, "Create device")


def test_parse_impacted_ignores_garbage():
    assert parse_impacted(None) == []
    assert parse_impacted(["", 42, "only-uuid"]) == [{"uuid": "only-uuid"}]


def test_wire_enum_accepts_friendly_and_wire_values():
    assert wire_enum(ADMIN_STATES, "Up", "admin state") == "ROBOT_ADMIN_STATE_UP"
    assert (
        wire_enum(ADMIN_STATES, "ROBOT_ADMIN_STATE_DOWN", "admin state") == "ROBOT_ADMIN_STATE_DOWN"
    )
    assert wire_enum(ADMIN_STATES, None, "admin state") is None
    with pytest.raises(PlatformError, match="Unknown admin state 'sideways'"):
        wire_enum(ADMIN_STATES, "sideways", "admin state")


def test_ipaddr_write_shape():
    assert ipaddr("198.18.140.11", 18) == {"inet_af": 0, "inet_addr": "198.18.140.11", "mask": "18"}
    assert ipaddr("198.18.140.15") == {"inet_af": 0, "inet_addr": "198.18.140.15"}
