"""Crosswork-specific helpers: query bodies, envelopes, job checking, enums."""

from __future__ import annotations

import pytest

from cnc_mcp.crosswork import (
    ADMIN_STATES,
    ALARMS_MAX_LIMIT,
    alarms_criteria,
    check_alarm_v1,
    check_collection_result,
    check_job,
    collection_next_token,
    collection_query_body,
    dg_query_body,
    ipaddr,
    is_job_pending,
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


# --- module 0: the other JSON-over-POST dialects ---------------------------------------


def test_dg_query_body_uses_the_grammar_each_endpoint_accepts():
    """Verified live: dg/query wants filterData.Criteria; hapool/query wants criteria."""
    assert dg_query_body("gateways") == {
        "filterData": {"Criteria": "select * from RobotDataGateway"}
    }
    assert dg_query_body("Pools") == {"criteria": "select * from HAPool"}
    assert dg_query_body("HAPool") == dg_query_body("pools")
    assert dg_query_body("RobotDataGateway") == dg_query_body("gateways")


def test_dg_query_body_carries_nothing_else():
    """dg-manager rejects unknown fields, so the body must be exactly the grammar."""
    assert set(dg_query_body("gateways")) == {"filterData"}
    assert set(dg_query_body("gateways")["filterData"]) == {"Criteria"}
    assert set(dg_query_body("pools")) == {"criteria"}


def test_dg_query_body_explicit_criteria_and_unknown_table():
    custom = "select * from RobotDataGateway where name = 'x'"
    assert dg_query_body("gateways", custom) == {"filterData": {"Criteria": custom}}
    assert dg_query_body("pools", "select * from HAPool where name = 'p'") == {
        "criteria": "select * from HAPool where name = 'p'"
    }
    with pytest.raises(PlatformError, match="Unknown Data Gateway table"):
        dg_query_body("whatever", custom)


def test_collection_query_body_defaults_match_the_verified_echo():
    assert collection_query_body() == {
        "query_options": {"page_size": 100, "page_token": "0", "filter_list": []}
    }


def test_collection_query_body_with_token_and_filters():
    flt = {"operator": "OPERATOR_AND", "field_list": [{"field": "CollectionState", "value": "x"}]}
    body = collection_query_body(page_size=50, page_token="abc", filters=[flt])
    assert body["query_options"] == {"page_size": 50, "page_token": "abc", "filter_list": [flt]}
    body["query_options"]["filter_list"].append({})  # the caller's list is not aliased
    assert collection_query_body(filters=[flt])["query_options"]["filter_list"] == [flt]


def test_collection_next_token_stops_on_empty_or_unchanged_token():
    """End of data is UNVERIFIED live: the document says an empty page_token ends paging, but
    the lab's empty jobs/query echoed the "0" it was sent — so both must read as 'no more'."""
    echoed_zero = {
        "result": {"request_result": "ACCEPTED", "error": {"error": ""}},
        "query_options": {"page_token": "0", "page_size": 100, "filter_list": []},
        "jobs": [],
    }
    assert collection_next_token(echoed_zero, "0") is None  # unchanged token
    assert collection_next_token({"query_options": {"page_token": ""}}, "0") is None  # documented
    assert collection_next_token({"query_options": {"page_token": ""}}) is None
    # a changed, non-empty token is the next page (document example: an opaque hash)
    nxt = {"query_options": {"page_token": "a7859eb217ee381541afe2f911dfd21c", "page_size": 100}}
    assert collection_next_token(nxt, "0") == "a7859eb217ee381541afe2f911dfd21c"
    assert collection_next_token(nxt) == "a7859eb217ee381541afe2f911dfd21c"


def test_collection_next_token_tolerates_missing_or_garbage_options():
    assert collection_next_token({}) is None
    assert collection_next_token({"query_options": {}}) is None
    assert collection_next_token({"query_options": "nope"}) is None
    assert collection_next_token({"query_options": {"page_token": 7}}) is None
    assert collection_next_token(None) is None
    assert collection_next_token([]) is None


def test_check_collection_result_accepts_and_returns_data():
    data = {
        "result": {"request_result": "ACCEPTED", "error": {"error": ""}},
        "query_options": {"page_token": "0", "page_size": 100, "filter_list": []},
        "jobs": [],
    }
    assert check_collection_result(data, "List collection jobs") is data


def test_check_collection_result_raises_on_rejection_with_reason():
    data = {
        "result": {"request_result": "REJECTED", "error": {"error": "empty request"}},
        "jobs": [],
    }
    with pytest.raises(PlatformError, match="List collection jobs was REJECTED: empty request"):
        check_collection_result(data, "List collection jobs")


def test_check_collection_result_tolerates_missing_reason_and_missing_envelope():
    with pytest.raises(PlatformError, match="was REJECTED: no reason given"):
        check_collection_result({"result": {"request_result": "REJECTED"}}, "Query")
    with pytest.raises(PlatformError, match="did not return a collection result envelope"):
        check_collection_result({"jobs": []}, "Query")
    with pytest.raises(PlatformError, match="did not return a collection result envelope"):
        check_collection_result(None, "Query")


def test_check_alarm_v1_raises_on_200_fail_document():
    with pytest.raises(
        PlatformError, match=r"Query alarms failed \(code 0\): Input Request is invalid"
    ):
        check_alarm_v1(
            {"error": "Fail", "code": 0, "message": "Input Request is invalid"}, "Query alarms"
        )
    with pytest.raises(PlatformError, match="Query alarms failed: no reason given"):
        check_alarm_v1({"error": "FAIL"}, "Query alarms")


def test_check_alarm_v1_passes_through_everything_else():
    ok = {"alarms": [{"AlarmId": "1"}], "error": ""}
    assert check_alarm_v1(ok, "Query alarms") is ok
    assert check_alarm_v1([], "Query alarms") == []
    assert check_alarm_v1(None, "Query alarms") is None
    # an "error" key with another value is data, not the Fail document
    assert check_alarm_v1({"error": "Success"}, "Query alarms") == {"error": "Success"}


def test_alarms_criteria_grammar_and_bounds():
    assert alarms_criteria(20, 0) == "select * from alarm limit 20 page 0"
    assert (
        alarms_criteria(ALARMS_MAX_LIMIT, 3)
        == f"select * from alarm limit {ALARMS_MAX_LIMIT} page 3"
    )
    with pytest.raises(PlatformError, match="between 1 and 200, got 0"):
        alarms_criteria(0, 0)
    with pytest.raises(PlatformError, match="between 1 and 200, got 201"):
        alarms_criteria(201, 0)
    with pytest.raises(PlatformError, match="0 or greater, got -1"):
        alarms_criteria(10, -1)


def test_alarms_criteria_where_and_order_clauses_are_appended_verbatim():
    """The documented (UNVERIFIED live) grammar from the 7.2 alarms document:
    'select * from event limit 100 page 0 where eventCategory=3 order userName asc'."""
    assert (
        alarms_criteria(100, 0, where="eventCategory=3", order="userName asc")
        == "select * from alarm limit 100 page 0 where eventCategory=3 order userName asc"
    )
    assert alarms_criteria(20, 1, where=" Acknowledge=false ") == (
        "select * from alarm limit 20 page 1 where Acknowledge=false"
    )
    assert alarms_criteria(20, 1, order="Created desc") == (
        "select * from alarm limit 20 page 1 order Created desc"
    )
    # blank clauses leave the verified form untouched
    assert alarms_criteria(20, 0, where="", order="  ") == "select * from alarm limit 20 page 0"
    assert alarms_criteria(20, 0, where=None, order=None) == "select * from alarm limit 20 page 0"


def test_check_job_pending_states_are_returned_not_raised():
    """Verified: NSO device actions answer JOB_ACCEPTED immediately (they finish later)."""
    env = check_job(
        {"job_id": "j4", "state": "JOB_ACCEPTED", "type": "NSO device check sync"},
        "NSO check-sync",
    )
    assert env["pending"] is True and env["impacted_objects"] == []
    assert is_job_pending(env) and not is_job_pending({"state": "JOB_COMPLETED"})


def test_check_job_rejected_and_partial():
    with pytest.raises(PlatformError, match="state JOB_REJECTED"):
        check_job({"job_id": "j5", "state": "JOB_REJECTED", "error": "nope"}, "x")
    env = check_job({"job_id": "j6", "state": "JOB_PARTIAL", "error": "1 of 2 failed"}, "x")
    assert env["warning"] == "1 of 2 failed"
