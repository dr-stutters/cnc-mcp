"""RESTCONF NBI dialect helpers: error documents, list unwrapping, RPC envelopes, paging.

Every ``LIVE_*`` fixture body below mirrors a response observed live on
Crosswork 7.2 (platform notes, "API dialects verified live 2026-09-12"); the
few synthetic documents are labelled as such where they are defined.
"""

from __future__ import annotations

import httpx
import pytest

from cnc_mcp.errors import PlatformError, http_error
from cnc_mcp.restconf import (
    EMPTY_500_EXPLANATION,
    NSO_ACTION_CONNECT,
    NSO_ACTION_FETCH_HOST_KEYS,
    NSO_ACTION_SYNC_FROM,
    NSO_MODULE,
    NSO_PROXY,
    OPTIMIZATION_NBI,
    TOPOLOGY_NBI,
    YANG_ACCEPT,
    YANG_HEADERS,
    action_path,
    check_rpc_output,
    explain_empty_500,
    is_not_found,
    page_envelope_from,
    page_params,
    parse_restconf_errors,
    restconf_error_message,
    rpc_body,
    rpc_output,
    rpc_path,
    select_key,
    unwrap_list,
)

# Live shapes -----------------------------------------------------------------

# 400 from the topology NBI for a bad module prefix — note the BARE "errors" key.
LIVE_UNKNOWN_ELEMENT = {
    "errors": {
        "error": [
            {
                "error-type": "protocol",
                "error-tag": "unknown-element",
                "error-message": "Unknown element: ietf-network:networks",
            }
        ]
    }
}
# 400 for listing a sub-list without its parent key.
LIVE_MISSING_ATTRIBUTE = {
    "errors": {
        "error": [
            {
                "error-tag": "missing-attribute",
                "error-message": "Missing key for list 'network'",
                "error-path": "/ietf-network-state:networks/network/node",
            }
        ]
    }
}
# 409 for a keyed GET on a nested list whose key does not exist (node=nope).
LIVE_DATA_MISSING = {
    "errors": {
        "error": [
            {
                "error-tag": "data-missing",
                "error-message": (
                    "Request could not be completed because the relevant data model "
                    "content does not exist"
                ),
            }
        ]
    }
}
# 415 from the NSO proxy for a POST body sent as application/json — the one
# verified ietf-restconf:errors (RFC 8040 key) document. The notes record the
# message only up to "Unsupported media type…".
LIVE_NSO_415 = {
    "ietf-restconf:errors": {
        "error": [
            {
                "error-tag": "malformed-message",
                "error-message": "Unsupported media type",
            }
        ]
    }
}
# 404 bodies verified live — both mean "nothing is routed / served here", never
# "no such entry": the home app's fallback (Spring-JSON form; the YAML form
# carries the same path) and a Spring-served service's "No static resource".
LIVE_404_HOME_APP = {
    "timestamp": "2026-09-12T10:00:00.000+00:00",
    "status": 404,
    "error": "Not Found",
    "path": "/crosswork/sso/login/crosswork/nbi/cat-inventory/v1/restconf/data/x",
}
LIVE_404_SPRING = {"code": 404, "errorMessage": "No static resource crosswork/swim/v1/x."}
# Container GET: {"<module>:<plural>": {"<name>": [...]}}
LIVE_NETWORKS = {
    "ietf-network-state:networks": {
        "network": [{"network-id": "Default-network", "node": [{"node-id": "PE1"}]}]
    }
}
# Keyed GET: {"<module>:<name>": [...]}
LIVE_NETWORK_KEYED = {"ietf-network-state:network": [{"network-id": "Default-network"}]}
# get-plan: application failure inside HTTP 200. The RPC is defined by
# cisco-crosswork-optimization-engine-operations (OpenAPI document
# cisco_crosswork_optimization_engine_operations_api_7_2_0), so that is the
# module prefixing the reply.
COE_MODULE = "cisco-crosswork-optimization-engine-operations"
LIVE_GET_PLAN_ERROR = {
    f"{COE_MODULE}:output": {
        "status": "error",
        "message": "failed to export network: Abort: Invalid version spec 'current'.",
    }
}
# NSO proxy device action replies (POST .../device=PE1/connect with body {}).
LIVE_NSO_CONNECT_OK = {
    "tailf-ncs:output": {"result": True, "info": "(admin) Connected to PE1 - 198.18.140.11:22"}
}
LIVE_NSO_SYNC_UNCHANGED = {"tailf-ncs:output": {"result": "unchanged"}}
LIVE_NSO_CONNECT_FAILED = {
    "tailf-ncs:output": {
        "result": False,
        "info": "Failed to connect to device PE1: connection refused",
    }
}
# SYNTHETIC: a 409 that is a real conflict, not data-missing.
SYNTHETIC_CONFLICT = {
    "errors": {"error": [{"error-tag": "in-use", "error-message": "device is locked by admin"}]}
}


def _response(status: int, data: object) -> httpx.Response:
    """A standalone response with a JSON body, for cross-checking against http_error()."""
    return httpx.Response(status, json=data)


# Headers / bases ---------------------------------------------------------------


def test_yang_accept_is_get_only_and_yang_headers_add_content_type_for_bodies():
    assert YANG_ACCEPT == {"Accept": "application/yang-data+json"}
    assert YANG_HEADERS == {
        "Accept": "application/yang-data+json",
        "Content-Type": "application/yang-data+json",
    }
    assert TOPOLOGY_NBI.endswith("/restconf") and OPTIMIZATION_NBI.endswith("/restconf")
    assert NSO_PROXY == "/crosswork/proxy/nso/restconf"
    assert NSO_MODULE == "tailf-ncs"


# parse_restconf_errors ---------------------------------------------------------


def test_parse_restconf_errors_accepts_bare_errors_key():
    assert parse_restconf_errors(LIVE_MISSING_ATTRIBUTE) == [
        {
            "tag": "missing-attribute",
            "message": "Missing key for list 'network'",
            "path": "/ietf-network-state:networks/network/node",
        }
    ]
    # Fields not present in the document come back as None, not KeyError.
    assert parse_restconf_errors(LIVE_UNKNOWN_ELEMENT) == [
        {
            "tag": "unknown-element",
            "message": "Unknown element: ietf-network:networks",
            "path": None,
        }
    ]


def test_parse_restconf_errors_accepts_standard_ietf_key():
    assert parse_restconf_errors(LIVE_NSO_415) == [
        {"tag": "malformed-message", "message": "Unsupported media type", "path": None}
    ]


def test_parse_restconf_errors_strips_fields_and_skips_junk_items():
    doc = {"errors": {"error": [{"error-tag": "operation-failed", "error-message": " x "}]}}
    assert parse_restconf_errors(doc) == [{"tag": "operation-failed", "message": "x", "path": None}]
    mixed = {"ietf-restconf:errors": {"error": ["not a dict", {"error-tag": "t"}]}}
    assert parse_restconf_errors(mixed) == [{"tag": "t", "message": None, "path": None}]


@pytest.mark.parametrize(
    "data",
    [
        None,
        {},
        [],
        "errors",
        {"ietf-network-state:networks": {"network": []}},  # a normal body
        {"errors": ["not", "restconf"]},  # some other service's errors list
        {"errors": {"error": "a string"}},
        # RFC 8040 defines ``error`` as a list; a bare dict is not a RESTCONF document
        # (and errors.http_error agrees — the two parsers must not diverge).
        {"errors": {"error": {"error-tag": "operation-failed"}}},
        {"error": "NATS request failed"},  # inventory-style error
        LIVE_404_HOME_APP,
        LIVE_404_SPRING,
    ],
)
def test_parse_restconf_errors_returns_empty_for_non_error_documents(data):
    assert parse_restconf_errors(data) == []


# restconf_error_message --------------------------------------------------------


def test_restconf_error_message_explains_unknown_element():
    msg = restconf_error_message(400, LIVE_UNKNOWN_ELEMENT)
    assert msg is not None and "\n" not in msg
    assert msg.startswith("RESTCONF path or key problem: an element in the data path")
    assert "Platform said: RESTCONF unknown-element: Unknown element: ietf-network:networks" in msg


def test_restconf_error_message_explains_missing_attribute_with_path():
    msg = restconf_error_message(400, LIVE_MISSING_ATTRIBUTE)
    assert msg is not None
    assert msg.startswith("RESTCONF path or key problem: a required key is missing")
    assert msg.endswith("(path: /ietf-network-state:networks/network/node)")


def test_restconf_error_message_explains_data_missing_as_no_such_object():
    msg = restconf_error_message(409, LIVE_DATA_MISSING)
    assert msg is not None and msg.startswith("RESTCONF: no such object")
    assert "not 404" in msg


def test_restconf_error_message_explains_nso_415_with_the_fix():
    msg = restconf_error_message(415, LIVE_NSO_415)
    assert msg is not None
    assert "Content-Type: application/yang-data+json" in msg
    assert "NSO proxy" in msg
    assert msg.endswith("Platform said: RESTCONF malformed-message: Unsupported media type")


@pytest.mark.parametrize(
    ("status", "data"),
    [
        (409, LIVE_DATA_MISSING),
        (400, LIVE_UNKNOWN_ELEMENT),
        (400, LIVE_DATA_MISSING),  # generic fallback: the tag hint is keyed on the status too
        (409, SYNTHETIC_CONFLICT),
    ],
)
def test_restconf_error_message_matches_http_error_wording(status, data):
    """Both entry points (raise_on_error=True vs. inspecting the response) say the same thing."""
    expected = f"API request failed with status {status}. {restconf_error_message(status, data)}"
    assert str(http_error(_response(status, data))) == expected


def test_restconf_error_message_falls_back_to_generic_hint_and_detail():
    generic = restconf_error_message(409, SYNTHETIC_CONFLICT)
    assert generic is not None
    assert generic.startswith("The RESTCONF service rejected the request (see the error-tag).")
    assert generic.endswith("Platform said: RESTCONF in-use: device is locked by admin")
    # Missing message / tag never crash.
    assert restconf_error_message(500, {"errors": {"error": [{}]}}) == (
        "The RESTCONF service rejected the request (see the error-tag). Check the data "
        "path, keys and body against the YANG model. Platform said: RESTCONF error"
    )


def test_restconf_error_message_lists_every_error():
    doc = {"errors": {"error": [{"error-tag": "a", "error-message": "m1"}, {"error-tag": "b"}]}}
    msg = restconf_error_message(400, doc)
    assert msg is not None and msg.endswith("Platform said: RESTCONF a: m1; RESTCONF b")


@pytest.mark.parametrize(
    "data", [None, {}, {"error": "NATS request failed"}, "<html>", LIVE_404_HOME_APP]
)
def test_restconf_error_message_is_none_without_restconf_errors(data):
    assert restconf_error_message(400, data) is None


# is_not_found ------------------------------------------------------------------


def test_is_not_found_only_for_409_data_missing():
    assert is_not_found(409, LIVE_DATA_MISSING) is True
    assert is_not_found(409, SYNTHETIC_CONFLICT) is False  # a real conflict, not data-missing
    assert is_not_found(409, {}) is False
    assert is_not_found(409, None) is False
    assert is_not_found(400, LIVE_DATA_MISSING) is False  # tag only counts on a 409
    assert is_not_found(200, LIVE_NETWORKS) is False


@pytest.mark.parametrize(
    "data",
    [
        LIVE_404_HOME_APP,  # unrouted prefix (e.g. an undeployed NBI) — not a bad ID
        LIVE_404_SPRING,  # routed service, path not served on this build
        None,
        {"error": "page not found"},
    ],
)
def test_is_not_found_never_treats_404_as_missing_entry(data):
    """A 404 on this gateway means the route is absent, so it must not read as 'no such node'."""
    assert is_not_found(404, data) is False


# unwrap_list -------------------------------------------------------------------


def test_unwrap_list_handles_container_shape():
    items = unwrap_list(LIVE_NETWORKS, "ietf-network-state", "network")
    assert items == [{"network-id": "Default-network", "node": [{"node-id": "PE1"}]}]


def test_unwrap_list_handles_keyed_shape():
    assert unwrap_list(LIVE_NETWORK_KEYED, "ietf-network-state", "network") == [
        {"network-id": "Default-network"}
    ]


def test_unwrap_list_wraps_bare_dict_and_tolerates_unprefixed_key():
    single = {"ietf-network-state:node": {"node-id": "P1"}}
    assert unwrap_list(single, "ietf-network-state", "node") == [{"node-id": "P1"}]
    assert unwrap_list({"node": [{"node-id": "P1"}]}, "ietf-network-state", "node") == [
        {"node-id": "P1"}
    ]
    nested_single = {"ietf-network-state:networks": {"network": {"network-id": "only"}}}
    assert unwrap_list(nested_single, "ietf-network-state", "network") == [{"network-id": "only"}]


def test_unwrap_list_prefers_module_prefixed_container():
    data = {
        "other:things": {"device": [{"name": "wrong"}]},
        "tailf-ncs:devices": {"device": [{"name": "PE1"}]},
    }
    assert unwrap_list(data, NSO_MODULE, "device") == [{"name": "PE1"}]


@pytest.mark.parametrize(
    "data",
    [
        None,
        {},
        [],
        "text",
        {"ietf-network-state:networks": {}},  # empty container
        {"ietf-network-state:networks": {"network": []}},
        {"ietf-network-state:network": "not a list"},
        {"unrelated:key": [{"network-id": "x"}]},
    ],
)
def test_unwrap_list_returns_empty_for_empty_or_foreign_bodies(data):
    assert unwrap_list(data, "ietf-network-state", "network") == []


# select_key --------------------------------------------------------------------


def test_select_key_filters_when_platform_ignored_the_key():
    # network=does-not-exist returned the whole list live; the filter must drop it all.
    whole = [{"network-id": "Default-network"}, {"network-id": "Other"}]
    assert select_key(whole, "network-id", "does-not-exist") == []
    assert select_key(whole, "network-id", "Default-network") == [{"network-id": "Default-network"}]


def test_select_key_is_case_sensitive_exact_and_skips_junk():
    items = [{"node-id": "PE1"}, {"node-id": "pe1"}, {"node-id": "PE10"}, "junk", {"other": "PE1"}]
    assert select_key(items, "node-id", "PE1") == [{"node-id": "PE1"}]
    assert select_key(items, "node-id", "pe1") == [{"node-id": "pe1"}]
    assert select_key([], "node-id", "PE1") == []


def test_select_key_matches_numeric_stored_keys_against_url_strings():
    items = [{"tunnel-id": 7}, {"tunnel-id": 70}, {"tunnel-id": None}]
    assert select_key(items, "tunnel-id", "7") == [{"tunnel-id": 7}]
    assert select_key(items, "tunnel-id", 7) == [{"tunnel-id": 7}]
    assert select_key(items, "tunnel-id", "None") == []


# rpc_path / action_path / rpc_body ----------------------------------------------


def test_rpc_path_builds_operations_url():
    expected = f"{OPTIMIZATION_NBI}/operations/{COE_MODULE}:get-plan"
    assert rpc_path(OPTIMIZATION_NBI, COE_MODULE, "get-plan") == expected
    assert rpc_path(OPTIMIZATION_NBI + "/", COE_MODULE, "get-plan") == expected


def test_action_path_builds_nso_device_action_under_data_not_operations():
    expected = f"{NSO_PROXY}/data/tailf-ncs:devices/device=PE1/connect"
    assert action_path(NSO_PROXY, "PE1", NSO_ACTION_CONNECT) == expected
    assert action_path(NSO_PROXY + "/", "PE1", "/connect/") == expected
    assert "/operations/" not in expected
    # The action itself may carry a path segment and is used verbatim.
    assert action_path(NSO_PROXY, "PE1", NSO_ACTION_FETCH_HOST_KEYS).endswith(
        "/device=PE1/ssh/fetch-host-keys"
    )
    assert action_path(NSO_PROXY, "PE1", NSO_ACTION_SYNC_FROM).endswith("/device=PE1/sync-from")


def test_action_path_percent_encodes_the_device_key():
    path = action_path(NSO_PROXY, "edge rtr/1,a", NSO_ACTION_CONNECT)
    assert path == f"{NSO_PROXY}/data/tailf-ncs:devices/device=edge%20rtr%2F1%2Ca/connect"


def test_rpc_body_wraps_input_and_drops_none():
    assert rpc_body(**{"version": "current", "format": None}) == {"input": {"version": "current"}}
    assert rpc_body() == {"input": {}}
    assert rpc_body(enabled=False, count=0) == {"input": {"enabled": False, "count": 0}}


# rpc_output --------------------------------------------------------------------


def test_rpc_output_extracts_module_prefixed_and_bare_output():
    assert rpc_output(LIVE_GET_PLAN_ERROR, COE_MODULE) == {
        "status": "error",
        "message": "failed to export network: Abort: Invalid version spec 'current'.",
    }
    assert rpc_output(LIVE_NSO_CONNECT_OK, NSO_MODULE) == LIVE_NSO_CONNECT_OK["tailf-ncs:output"]
    assert rpc_output({"output": {"results": []}}, COE_MODULE) == {"results": []}
    # Defensive fallback: a single ":output" key under a prefix we did not ask for is
    # still taken (unverified whether Crosswork ever emits a foreign prefix).
    assert rpc_output({"other-module:output": {"ok": True}}, COE_MODULE) == {"ok": True}


@pytest.mark.parametrize(
    "data",
    [
        None,
        {},
        [],
        {"m:output": "not a dict"},
        {"a:output": {"x": 1}, "b:output": {"x": 2}},  # ambiguous: refuse to guess
        {"errors": {"error": []}},
    ],
)
def test_rpc_output_returns_empty_when_absent(data):
    assert rpc_output(data, "m") == {}


# check_rpc_output --------------------------------------------------------------


def test_check_rpc_output_raises_on_status_error_inside_200():
    output = rpc_output(LIVE_GET_PLAN_ERROR, COE_MODULE)
    with pytest.raises(PlatformError) as exc:
        check_rpc_output(output, "Get plan")
    assert str(exc.value) == (
        "Get plan failed: failed to export network: Abort: Invalid version spec 'current'."
    )


def test_check_rpc_output_is_case_insensitive_and_tolerates_missing_message():
    with pytest.raises(PlatformError, match="^Dry run failed: no message given$"):
        check_rpc_output({"status": " ERROR "}, "Dry run")


def test_check_rpc_output_passes_success_and_missing_status_through():
    ok = {"status": "success", "results": [{"state": "success"}]}
    assert check_rpc_output(ok, "Create") is ok
    no_status = {"results": []}
    assert check_rpc_output(no_status, "Create") is no_status
    assert check_rpc_output({}, "Create") == {}
    # A non-string status is not a failure verdict.
    assert check_rpc_output({"status": 0}, "Create") == {"status": 0}


def test_check_rpc_output_raises_on_nso_result_false_with_info():
    output = rpc_output(LIVE_NSO_CONNECT_FAILED, NSO_MODULE)
    with pytest.raises(PlatformError) as exc:
        check_rpc_output(output, "Connect")
    assert str(exc.value) == "Connect failed: Failed to connect to device PE1: connection refused"
    with pytest.raises(PlatformError, match="^Sync-from failed: no message given$"):
        check_rpc_output({"result": False}, "Sync-from")


def test_check_rpc_output_accepts_nso_result_true_unchanged_and_missing():
    ok = rpc_output(LIVE_NSO_CONNECT_OK, NSO_MODULE)
    assert check_rpc_output(ok, "Connect") is ok
    unchanged = rpc_output(LIVE_NSO_SYNC_UNCHANGED, NSO_MODULE)
    assert check_rpc_output(unchanged, "Sync-from") is unchanged
    assert check_rpc_output({"info": "nothing to do"}, "Sync-from") == {"info": "nothing to do"}
    # Only the JSON boolean false is the verified failure signal, not other falsy values.
    assert check_rpc_output({"result": 0}, "Connect") == {"result": 0}
    assert check_rpc_output({"result": None}, "Connect") == {"result": None}


# page_params / page_envelope_from ----------------------------------------------


def test_page_params_are_offset_and_limit():
    assert page_params(20, 10) == {"offset": 20, "limit": 10}


def test_page_envelope_from_infers_has_more_from_full_page_only():
    full = page_envelope_from([1, 2], offset=2, limit=2)
    assert full["total"] is None and full["count"] == 2 and full["offset"] == 2
    assert full["has_more"] is True and full["next_offset"] == 4
    short = page_envelope_from([1], offset=4, limit=2)
    assert short["has_more"] is False and short["next_offset"] is None
    empty = page_envelope_from([], offset=6, limit=2)
    assert empty["count"] == 0 and empty["has_more"] is False


# explain_empty_500 -------------------------------------------------------------


def test_explain_empty_500_only_for_empty_body_500():
    assert explain_empty_500(500, "") == EMPTY_500_EXPLANATION
    assert explain_empty_500(500, None) == EMPTY_500_EXPLANATION
    assert explain_empty_500(500, "  \n") == EMPTY_500_EXPLANATION
    assert "not available on this deployment" in EMPTY_500_EXPLANATION


def test_explain_empty_500_uses_the_same_text_as_http_error():
    message = str(http_error(httpx.Response(500, text="")))
    assert message == f"API request failed with status 500. {EMPTY_500_EXPLANATION}"


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (500, '{"error":"NATS request failed"}'),  # a 500 WITH a body is a different story
        (200, ""),
        (204, ""),
        (404, ""),
        (503, ""),
    ],
)
def test_explain_empty_500_is_none_otherwise(status, body):
    assert explain_empty_500(status, body) is None
