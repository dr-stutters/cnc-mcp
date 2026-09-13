"""EMF RESTCONF dialect helpers: headers, paging, envelope, XML fallback, prefixes.

Shapes below are the ones verified live on the 7.2 lab instance (platform notes,
"API dialects verified live 2026-09-12", family 3) plus the documented spec
examples (alarm `alm.alarm`, inventory `tp.termination-point` without iteratorId,
`resource-physical:equipment` with three sibling lists under `com.data`).
"""

from __future__ import annotations

import httpx
import pytest
import respx

from cnc_mcp.auth import StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.emf import (
    DEFAULT_MAX_COUNT,
    EMF_ALARM,
    EMF_HEADERS,
    EMF_INVENTORY,
    EMF_PERFORMANCE,
    MAX_COUNT,
    data_key,
    data_keys,
    decode_json,
    explain_xml,
    looks_like_xml,
    page_envelope_from,
    page_params,
    strip_prefixes,
    unwrap,
)
from cnc_mcp.errors import PlatformError
from tests.conftest import BASE_URL

# Verified live: GET /crosswork/inventory/restconf/data/v2/resource-physical:node
FULL_ENVELOPE = {
    "com.response-message": {
        "com.header": {"com.firstIndex": 0, "com.lastIndex": 0, "com.iteratorId": 0},
        "com.data": {
            "nd.node": [
                {
                    "nd.fdn": "MD=CISCO_EMS!ND=PE1",
                    "nd.uuid": "940d04d0-d72b-48cc-8f8e-a5510ec118f7",
                    "fdtn.name": "PE1",
                    "nd.lifecycle-state": "MANAGED_AND_SYNCHRONIZED",
                }
            ]
        },
    }
}

# Verified live: rtm:alarm on a lab with no device alarms — lastIndex -1, no com.data.
EMPTY_ENVELOPE = {
    "com.response-message": {
        "com.header": {"com.firstIndex": 0, "com.lastIndex": -1, "com.iteratorId": 0},
    }
}

# Documented: GetEquipmentJson in restconf_inventory_ap_is_7_2_0.json (fields trimmed).
# Three sibling lists under com.data; com.lastIndex 2 counts across all of them.
EQUIPMENT_ENVELOPE = {
    "com.response-message": {
        "com.header": {"com.firstIndex": 0, "com.lastIndex": 2},
        "com.data": {
            "eq.module": [
                {
                    "fdtn.name": "subslot 0/5 transceiver 0",
                    "eq.equipment-type": "MODULE",
                    "eq.fdn": "MD=CISCO_EMS!ND=ASR903-47!EQ=name=subslot 0/5 transceiver 0",
                }
            ],
            "eq.equipment": [
                {
                    "fdtn.name": "subslot 0/5 transceiver container 0",
                    "eq.equipment-type": "OTHER",
                    "eq.fdn": "MD=CISCO_EMS!ND=ASR903-47!EQ=name=subslot 0/5 xcvr container 0",
                }
            ],
            "eq.chassis": [
                {
                    "fdtn.name": "Chassis",
                    "eq.equipment-type": "CHASSIS",
                    "eq.fdn": "MD=CISCO_EMS!ND=ASR903-47!EQ=name=Chassis;partnumber=68-3992-01",
                }
            ],
        },
    }
}

XML_BODY = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<ns14:response-message xmlns:ns14="urn:cisco:params:xml:ns:yang:nrf-common:v1">'
    "<ns14:header><ns14:firstIndex>0</ns14:firstIndex></ns14:header></ns14:response-message>"
)


# --- constants -----------------------------------------------------------------


def test_headers_are_exactly_application_json():
    assert EMF_HEADERS == {"Accept": "application/json"}
    assert list(EMF_HEADERS) == ["Accept"]  # no Content-Type, no extra media types


def test_base_paths_and_limits():
    assert EMF_INVENTORY == "/crosswork/inventory/restconf/data/v2"
    assert EMF_ALARM == "/crosswork/alarm/restconf/data/v2"
    assert EMF_PERFORMANCE == "/crosswork/performance/restconf/data/v1"
    assert MAX_COUNT == 100 and DEFAULT_MAX_COUNT == 100


@respx.mock
async def test_headers_and_page_params_reach_the_wire_unchanged(settings):
    """The verified facts are wire shapes: exactly one 'Accept: application/json' and
    '?.startIndex=0&.maxCount=100' must survive ApiClient's merge with its own default
    Accept and the auth headers."""
    path = f"{EMF_INVENTORY}/resource-physical:node"
    route = respx.get(f"{BASE_URL}{path}").mock(
        return_value=httpx.Response(200, json=FULL_ENVELOPE)
    )
    client = ApiClient(settings, StaticTokenAuth("test-token"))
    try:
        response = await client.request(
            "GET", path, headers=EMF_HEADERS, params=page_params(0, DEFAULT_MAX_COUNT)
        )
        items, header = unwrap(decode_json(response.text))
        assert len(items) == 1 and header["last_index"] == 0
        sent = route.calls[0].request
        assert sent.headers["Accept"] == "application/json"
        assert sent.headers.get_list("Accept") == ["application/json"]
        assert sent.url.params[".startIndex"] == "0"
        assert sent.url.params[".maxCount"] == "100"
        assert str(sent.url).endswith(f"{path}?.startIndex=0&.maxCount=100")
    finally:
        await client.aclose()


# --- page_params ---------------------------------------------------------------


def test_page_params_builds_dotted_query_params():
    assert page_params(0, 100) == {".startIndex": 0, ".maxCount": 100}
    assert page_params(250, 1) == {".startIndex": 250, ".maxCount": 1}


@pytest.mark.parametrize(
    ("start_index", "max_count", "match"),
    [
        (-1, 10, "start_index must be"),
        ("0", 10, "start_index must be"),
        (True, 10, "start_index must be"),
        (0, 0, "max_count must be"),
        (0, 101, "max_count must be"),
        (0, -5, "max_count must be"),
        (0, "50", "max_count must be"),
        (0, True, "max_count must be"),
    ],
)
def test_page_params_rejects_out_of_range_values(start_index, max_count, match):
    with pytest.raises(PlatformError, match=match):
        page_params(start_index, max_count)


# --- unwrap / data_key(s) ------------------------------------------------------


def test_unwrap_verified_full_envelope():
    items, header = unwrap(FULL_ENVELOPE)
    assert header == {"first_index": 0, "last_index": 0, "iterator_id": 0}
    assert len(items) == 1
    assert items[0]["nd.uuid"] == "940d04d0-d72b-48cc-8f8e-a5510ec118f7"
    assert data_key(FULL_ENVELOPE) == "nd.node"
    assert data_keys(FULL_ENVELOPE) == ["nd.node"]


def test_unwrap_verified_empty_envelope_has_last_index_minus_one_and_no_items():
    items, header = unwrap(EMPTY_ENVELOPE)
    assert items == []
    assert header == {"first_index": 0, "last_index": -1, "iterator_id": 0}
    assert data_key(EMPTY_ENVELOPE) is None
    assert data_keys(EMPTY_ENVELOPE) == []


def test_unwrap_documented_equipment_response_concatenates_sibling_lists():
    """GetEquipmentJson: eq.module + eq.equipment + eq.chassis, lastIndex 2 across all."""
    items, header = unwrap(EQUIPMENT_ENVELOPE)
    assert header == {"first_index": 0, "last_index": 2, "iterator_id": None}
    assert [i["eq.equipment-type"] for i in items] == ["MODULE", "OTHER", "CHASSIS"]
    assert data_keys(EQUIPMENT_ENVELOPE) == ["eq.module", "eq.equipment", "eq.chassis"]
    assert data_key(EQUIPMENT_ENVELOPE) == "eq.module"
    env = page_envelope_from(items, header, 0, DEFAULT_MAX_COUNT)
    assert env["count"] == 3 == header["last_index"] + 1
    assert env["has_more"] is False and env["next_start_index"] is None


def test_unwrap_concatenates_every_list_whatever_the_prefix():
    alarms = {
        "com.response-message": {
            "com.header": {"com.firstIndex": 0, "com.lastIndex": 2},  # iteratorId absent (spec)
            "com.data": {
                "alm.count": 3,
                "alm.alarm": [{"alm.uuid": "a"}, {"alm.uuid": "b"}],
                "alm.other": [{"x": 1}],
            },
        }
    }
    items, header = unwrap(alarms)
    assert items == [{"alm.uuid": "a"}, {"alm.uuid": "b"}, {"x": 1}]  # nothing dropped
    assert header == {"first_index": 0, "last_index": 2, "iterator_id": None}
    assert data_keys(alarms) == ["alm.alarm", "alm.other"]  # scalar alm.count is not payload
    assert data_key(alarms) == "alm.alarm"


def test_unwrap_accepts_single_dict_and_bare_list_under_data():
    single = {
        "com.response-message": {
            "com.header": {"com.firstIndex": 0, "com.lastIndex": 0},
            "com.data": {"nd.node": {"nd.fdn": "MD=CISCO_EMS!ND=P1"}},
        }
    }
    items, _ = unwrap(single)
    assert items == [{"nd.fdn": "MD=CISCO_EMS!ND=P1"}]
    assert data_key(single) == "nd.node"
    assert data_keys(single) == ["nd.node"]

    bare = {"com.response-message": {"com.header": {}, "com.data": [{"a": 1}]}}
    items, header = unwrap(bare)
    assert items == [{"a": 1}]
    assert header == {"first_index": None, "last_index": None, "iterator_id": None}
    assert data_key(bare) is None
    assert data_keys(bare) == []


@pytest.mark.parametrize(
    "data",
    [
        {},  # no envelope at all
        {"data": [{"a": 1}]},  # inventory/v1 shape, not EMF
        {"com.response-message": "nope"},
        [],
        None,
        "<xml/>",
    ],
)
def test_unwrap_tolerates_missing_envelope(data):
    assert unwrap(data) == ([], {"first_index": None, "last_index": None, "iterator_id": None})
    assert data_key(data) is None
    assert data_keys(data) == []


def test_unwrap_coerces_string_positions_and_ignores_garbage():
    env = {
        "com.response-message": {
            "com.header": {"com.firstIndex": "0", "com.lastIndex": "-1", "com.iteratorId": "x"},
        }
    }
    _, header = unwrap(env)
    assert header == {"first_index": 0, "last_index": -1, "iterator_id": None}


def test_data_keys_report_every_key_when_nothing_listlike():
    env = {"com.response-message": {"com.header": {}, "com.data": {"nd.count": 5, "nd.x": "y"}}}
    assert unwrap(env)[0] == []
    assert data_keys(env) == ["nd.count", "nd.x"]
    assert data_key(env) == "nd.count"


# --- XML fallback --------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (XML_BODY, True),
        ("<response-message><header/></response-message>", True),
        ("\ufeff  <?xml version='1.0'?><a/>", True),  # BOM (as an escape, kept visible)
        ('{"com.response-message": {}}', False),
        ("", False),
        ("   ", False),
        ("<html><body>502</body></html>", False),
        ("<!DOCTYPE html><html></html>", False),
        (None, False),
        (b"<a/>", False),
    ],
)
def test_looks_like_xml(text, expected):
    assert looks_like_xml(text) is expected


def test_explain_xml_names_root_element_and_the_exact_accept_header():
    hint = explain_xml(XML_BODY)
    assert "root element <ns14:response-message>" in hint
    assert "exactly 'Accept: application/json'" in hint
    assert "yang-data+json" in hint and "*/*" in hint
    assert "xmlns" not in hint  # never echoes the XML body
    # Verified on inventory and alarm only; performance is documented, not verified.
    assert "verified live on /crosswork/inventory|alarm/restconf/data/v2" in hint
    assert "/crosswork/performance/restconf/data/v1" in hint and "presumed" in hint
    # Still useful without a detectable root element.
    assert "Accept: application/json" in explain_xml("")


def test_decode_json_parses_json_and_turns_xml_into_the_accept_hint():
    assert decode_json('{"com.response-message": {"com.header": {"com.lastIndex": -1}}}') == {
        "com.response-message": {"com.header": {"com.lastIndex": -1}}
    }
    assert decode_json("") is None and decode_json(None) is None
    with pytest.raises(PlatformError, match="exactly 'Accept: application/json'"):
        decode_json(XML_BODY)


def test_decode_json_rejects_other_garbage_without_dumping_html():
    with pytest.raises(PlatformError, match="neither JSON nor XML: 'not json'"):
        decode_json("not json")
    with pytest.raises(PlatformError, match=r"an HTML page \(not shown\)") as exc:
        decode_json("<html><body>secret</body></html>")
    assert "secret" not in str(exc.value)


# --- page_envelope_from --------------------------------------------------------


def test_page_envelope_full_page_at_boundary_has_more():
    header = {"first_index": 0, "last_index": 1, "iterator_id": 7}
    env = page_envelope_from([{"a": 1}, {"a": 2}], header, 0, 2)
    assert env["has_more"] is True
    assert env["next_start_index"] == 2 and env["next_offset"] == 2
    assert env["total"] is None and env["count"] == 2 and env["offset"] == 0
    assert env["first_index"] == 0 and env["last_index"] == 1 and env["iterator_id"] == 7
    assert env["start_index"] == 0 and env["max_count"] == 2
    assert env["items"] == [{"a": 1}, {"a": 2}]


def test_page_envelope_short_page_has_no_more():
    header = {"first_index": 0, "last_index": 0, "iterator_id": 0}
    env = page_envelope_from([{"a": 1}], header, 0, 2)
    assert env["has_more"] is False
    assert env["next_start_index"] is None and env["next_offset"] is None


def test_page_envelope_empty_result_is_last_index_minus_one():
    header = {"first_index": 0, "last_index": -1, "iterator_id": 0}
    env = page_envelope_from([], header, 200, 100)
    assert env["has_more"] is False and env["next_start_index"] is None
    assert env["count"] == 0 and env["offset"] == 200 and env["last_index"] == -1


def test_page_envelope_later_page_uses_header_positions_not_item_count():
    header = {"first_index": 2, "last_index": 3, "iterator_id": 1}
    env = page_envelope_from([{"a": 3}, {"a": 4}], header, 2, 2)
    assert env["has_more"] is True and env["next_start_index"] == 4
    # One short of a full page by the header, even if the list looked full.
    header = {"first_index": 2, "last_index": 2, "iterator_id": 1}
    env = page_envelope_from([{"a": 3}, {"a": 4}], header, 2, 2)
    assert env["has_more"] is False and env["next_start_index"] is None


def test_page_envelope_advances_by_page_length_under_either_header_reading():
    """Only page 0 is verified live; the header may be absolute or page-relative at
    .startIndex > 0. Advancing by page length is right either way — last_index + 1
    would loop an agent at 100 forever under the page-relative reading."""
    relative = {"first_index": 0, "last_index": 99, "iterator_id": 1}
    env = page_envelope_from([{"a": i} for i in range(100)], relative, 100, 100)
    assert env["has_more"] is True
    assert env["next_start_index"] == 200 and env["next_offset"] == 200
    assert env["first_index"] == 0 and env["last_index"] == 99  # header echoed as received
    absolute = {"first_index": 100, "last_index": 199, "iterator_id": 1}
    env = page_envelope_from([{"a": i} for i in range(100)], absolute, 100, 100)
    assert env["has_more"] is True and env["next_start_index"] == 200
    # A short page under the page-relative reading is still the last page.
    env = page_envelope_from(
        [{"a": i} for i in range(50)], {"first_index": 0, "last_index": 49}, 100, 100
    )
    assert env["has_more"] is False and env["next_start_index"] is None
    # A header with last < first (garbage) never reports more.
    env = page_envelope_from([], {"first_index": 5, "last_index": 2}, 0, 1)
    assert env["has_more"] is False and env["next_start_index"] is None


def test_page_envelope_without_header_positions_falls_back_to_full_page_rule():
    nones = {"first_index": None, "last_index": None, "iterator_id": None}
    full = page_envelope_from([1, 2], nones, 10, 2)
    assert full["has_more"] is True and full["next_start_index"] == 12
    assert full["first_index"] is None and full["last_index"] is None
    short = page_envelope_from([1], nones, 10, 2)
    assert short["has_more"] is False and short["next_start_index"] is None
    # last_index present but first_index missing: start_index stands in for first.
    env = page_envelope_from([1, 2], {"first_index": None, "last_index": 11}, 10, 2)
    assert env["has_more"] is True and env["next_start_index"] == 12


# --- strip_prefixes ------------------------------------------------------------


def test_strip_prefixes_recurses_through_dicts_and_lists():
    stripped = strip_prefixes(FULL_ENVELOPE)
    assert stripped == {
        "response-message": {
            "header": {"firstIndex": 0, "lastIndex": 0, "iteratorId": 0},
            "data": {
                "node": [
                    {
                        "fdn": "MD=CISCO_EMS!ND=PE1",
                        "uuid": "940d04d0-d72b-48cc-8f8e-a5510ec118f7",
                        "name": "PE1",
                        "lifecycle-state": "MANAGED_AND_SYNCHRONIZED",
                    }
                ]
            },
        }
    }
    # The input is not mutated.
    assert "com.response-message" in FULL_ENVELOPE


def test_strip_prefixes_handles_nested_lists_and_mixed_prefixes():
    node = {
        "nd.node": [
            {
                "nd.equipment-list": {"eq.equipment": [{"fdtn.name": "Chassis", "eq.slots": 0}]},
                "nd.tp-list": [{"tp.ce-tp": {"tp.mtu": 1500}}, {"tp.ce-tp": {"tp.mtu": 9000}}],
            }
        ]
    }
    assert strip_prefixes(node) == {
        "node": [
            {
                "equipment-list": {"equipment": [{"name": "Chassis", "slots": 0}]},
                "tp-list": [{"ce-tp": {"mtu": 1500}}, {"ce-tp": {"mtu": 9000}}],
            }
        ]
    }


def test_strip_prefixes_leaves_unprefixed_keys_and_string_values_alone():
    obj = {
        "uuid": "u1",
        ".startIndex": 0,
        "1.2.3.4": "ip-keyed",
        "nd.": "dot-only",
        "nd.ip-address-prefix": "1.104.120.47/32",
        "nd.collection-status": '<status><general code="SUCCESS"/></status>',
        "nd.fdn": "MD=CISCO_EMS!ND=PE1!EQ=name=module R0;partnumber=68-5552-02",
        7: "non-string key",
    }
    assert strip_prefixes(obj) == {
        "uuid": "u1",
        ".startIndex": 0,
        "1.2.3.4": "ip-keyed",
        "nd.": "dot-only",
        "ip-address-prefix": "1.104.120.47/32",
        "collection-status": '<status><general code="SUCCESS"/></status>',
        "fdn": "MD=CISCO_EMS!ND=PE1!EQ=name=module R0;partnumber=68-5552-02",
        7: "non-string key",
    }
    assert strip_prefixes("nd.node") == "nd.node"
    assert strip_prefixes(42) == 42 and strip_prefixes(None) is None


def test_strip_prefixes_keeps_colliding_keys_distinct():
    # Two prefixed keys that would collapse onto one name both keep their prefix,
    # so neither value is dropped and neither silently changes namespace.
    obj = {"fdtn.name": "human", "eq.name": "wire"}
    assert strip_prefixes(obj) == {"fdtn.name": "human", "eq.name": "wire"}


def test_strip_prefixes_never_drops_a_value_when_an_unprefixed_key_collides():
    # An unprefixed key claims its own name: the prefixed one must keep its prefix
    # whichever order the two arrive in.
    assert strip_prefixes({"eq.name": "wire", "name": "plain"}) == {
        "eq.name": "wire",
        "name": "plain",
    }
    assert strip_prefixes({"name": "plain", "eq.name": "wire"}) == {
        "name": "plain",
        "eq.name": "wire",
    }
    # A stripped name that is itself another literal key ("a.b.c" -> "b.c") keeps
    # its prefix, even when that other key is being stripped to something else.
    assert strip_prefixes({"a.b.c": 1, "b.c": 2, "c": 3}) == {"a.b.c": 1, "b.c": 2, "c": 3}
    assert strip_prefixes({"a.b.c": 1, "b.c": 2}) == {"a.b.c": 1, "c": 2}
    # Nested dicts are checked independently.
    nested = {"nd.node": [{"eq.name": "wire", "name": "plain"}, {"eq.name": "only"}]}
    assert strip_prefixes(nested) == {
        "node": [{"eq.name": "wire", "name": "plain"}, {"name": "only"}]
    }
