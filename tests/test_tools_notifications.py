"""Notification tools end-to-end through MCPServer (schema validation included).

The module is registered directly (not through build_server) so the test does
not depend on tools/__init__.py's module list. All HTTP is mocked with respx.
Fixtures mirror the shapes verified live on Crosswork 7.2 (2026-09-13, platform
notes "Notifications"): the single-subscription envelope (an OBJECT under
"ietf-restconf:notification.subscription"), the list form, the empty envelope
(com.lastIndex -1, no com.data), the streams document, the rc.errors answers
NOT.0029 / NOT.0006 / NOT.0037 / NOT.0016, the DELETE text "Success", and the
EMPTY Kafka body. Error routing is checked on every tool: any rc.errors answer
(the list and streams GETs included) renders the service's own NOT.xxxx tag,
an empty-bodied 500 on the subscription POST is the module's own explanation,
and a 2xx DELETE without the "Success" text is reported as unconfirmed.

The external (Kafka/gRPC) subscription fixtures mirror what the 7.2 lab answered
on 2026-09-15 (recorded in the module docstring of cnc_mcp.tools.notifications,
"External (Kafka/gRPC) subscription writes"): the non-empty subscriptionList,
HTTP 200 {"result": "Create Successful"} / {"result": "Delete Successful"}, the
HTTP-200 application failures (duplicate topic, refused destination — also for
a destination name in the wrong case), the 400 {"error": "Following param(s)
are invalid : ..."} form, the 400 {"result": "... not found and could not be
deleted :[t]"} delete answer, and the text "Clear successful" of clear-by-topic
(also for a topic with none).
"""

from __future__ import annotations

import json
import re

import httpx
import pytest
import respx
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from cnc_mcp.auth import StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.config import Settings
from cnc_mcp.errors import PlatformError
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import notifications
from cnc_mcp.tools.notifications import (
    CLEAR_BY_TOPIC_PATH,
    DESTINATIONS_QUERY_PATH,
    KAFKA_SUBSCRIPTION_PATH,
    NOTIFICATIONS,
    NS,
    STREAMS_PATH,
    SUBSCRIPTION_ADMIN_PATH,
    SUBSCRIPTION_PATH,
    bare_500_error,
    build_external_subscription,
    clear_confirmed,
    delete_confirmed,
    destination_diagnosis,
    emf_body,
    emf_rejection,
    error_matches,
    external_result,
    invalid_params_error,
    is_rc_error,
    kafka_entries,
    kafka_line,
    match_choice,
    rc_error,
    rejection,
    result_is,
    streams_from,
    subscription_items,
    subscription_line,
    subscription_markdown,
    subscription_with_id,
    subscriptions_of_topic,
    validate_client_url,
)
from tests.conftest import BASE_URL, call_tool_text

STREAMS_URL = f"{BASE_URL}{STREAMS_PATH}"
SUBSCRIPTION_URL = f"{BASE_URL}{SUBSCRIPTION_PATH}"
ADMIN_URL = f"{BASE_URL}{SUBSCRIPTION_ADMIN_PATH}"
KAFKA_URL = f"{BASE_URL}{KAFKA_SUBSCRIPTION_PATH}"
CLEAR_URL = f"{BASE_URL}{CLEAR_BY_TOPIC_PATH}"
DESTINATIONS_URL = f"{BASE_URL}{DESTINATIONS_QUERY_PATH}"

SINK_URL = "http://198.18.140.17:80/hook"

# Verified single subscription (POST answer / keyed GET / one-entry list), verbatim keys.
SUB = {
    f"{NS}subscription-id": 12,
    f"{NS}subscribed-user": "admin",
    f"{NS}client-url": SINK_URL,
    f"{NS}client-ip": "198.18.140.17",
    f"{NS}session-id": "6c1f6c3a-0c1e-4a2d-9f3b-8e7d6c5b4a39",
    f"{NS}topic": "alarm",
    f"{NS}creation-time": "Sat Sep 13 10:15:42 UTC 2026",
    f"{NS}time-of-update": "Sat Sep 13 10:15:42 UTC 2026",
    f"{NS}format": "json",
    f"{NS}connection-type": "connection-less",
}
SUB2 = {
    **SUB,
    f"{NS}subscription-id": 13,
    f"{NS}topic": "inventory",
    f"{NS}format": "xml",
    f"{NS}client-url": "https://sink.example:443/inv",
    f"{NS}subscribed-user": "ops",
}


def envelope(data, last_index: int) -> dict:
    return {
        "com.response-message": {
            "com.header": {"com.firstIndex": 0, "com.lastIndex": last_index},
            "com.data": {f"{NS}subscription": data},
        }
    }


# A SINGLE subscription is an OBJECT under the key (verified live).
SINGLE = envelope(SUB, 0)
# Several are a list.
LISTED = envelope([SUB, SUB2], 1)
# None: lastIndex -1 and no com.data at all.
EMPTY = {"com.response-message": {"com.header": {"com.firstIndex": 0, "com.lastIndex": -1}}}

# Verified streams document (trimmed to three streams).
STREAMS = {
    "rcmon.streams": {
        "rcmon.stream": [
            {
                "rcmon.name": "RestConf (connection-less) alarm and inventory "
                "notification subscription",
                "rcmon.description": "Connection-less client subscription using payload",
                "rcmon.access": [
                    {
                        "rcmon.encoding": "xml",
                        "rcmon.location": "POST https://cnc.example:30603/crosswork/notification/"
                        "restconf/data/v2/cisco-notifications:subscription",
                    },
                    {
                        "rcmon.encoding": "json",
                        "rcmon.location": "POST https://cnc.example:30603/crosswork/notification/"
                        "restconf/data/v2/cisco-notifications:subscription",
                    },
                ],
            },
            {
                "rcmon.name": "WebSocket (connection-oriented) Alarm Notification Streaming",
                "rcmon.description": "Connection-oriented client subscription",
                "rcmon.access": [
                    {
                        "rcmon.encoding": "xml",
                        "rcmon.location": "wss://cnc.example:30603/crosswork/notification/"
                        "restconf/streams/v2/alarm.xml",
                    },
                    {
                        "rcmon.encoding": "json",
                        "rcmon.location": "wss://cnc.example:30603/crosswork/notification/"
                        "restconf/streams/v2/alarm.json",
                    },
                ],
            },
            {
                "rcmon.name": "WebSocket (connection-oriented) Inventory Notification Streaming",
                "rcmon.description": "Connection-oriented client subscription",
                "rcmon.access": [
                    {
                        "rcmon.encoding": "json",
                        "rcmon.location": "wss://cnc.example:30603/crosswork/notification/"
                        "restconf/streams/v1/inventory.json",
                    }
                ],
            },
        ]
    }
}


def rc_errors(app_tag: str, message: str, tag: str = "operation-failed") -> dict:
    """The EMF error document: rc.errors with a single error OBJECT (verified live)."""
    return {
        "rc.errors": {
            "error": {
                "error-type": "application",
                "error-tag": tag,
                "error-app-tag": app_tag,
                "error-message": message,
            }
        }
    }


NOT_0029 = rc_errors("NOT.0029", "The endpoint is not reachable.")
NOT_0006 = rc_errors(
    "NOT.0006", "Subscription already exists for the given topic, endpoint (and format)"
)
NOT_0037 = rc_errors("NOT.0037", "There is no subscription for given subscriptionId")
NOT_0016 = rc_errors("NOT.0016", "Unable to find subscription")

# Verified non-empty Kafka/gRPC answer (the spec's example shape, seen live 2026-09-15).
KAFKA_LISTED = {
    "subscriptionList": [
        {
            "createTime": "Thu Sep 11 06:06:07 UTC 2025",
            "destinationName": "kafkadest",
            "destinationType": "Kafka",
            "filter": None,
            "subscriptionData": None,
            "subscriptionDataType": "System_Audit",
            "topicName": "audit123",
            "userName": "admin",
        }
    ]
}

READ_TOOLS = {
    "cnc_list_notification_streams",
    "cnc_list_notification_subscriptions",
    "cnc_get_notification_subscription",
    "cnc_list_kafka_subscriptions",
}
WRITE_TOOLS = {
    "cnc_create_webhook_subscription",
    "cnc_delete_notification_subscription",
    "cnc_create_external_subscription",
    "cnc_delete_external_subscription",
    "cnc_clear_notification_subscriptions_by_topic",
}

# Verified external-subscription answers (2026-09-15).
EXT_CREATE_OK = {"result": "Create Successful"}
EXT_DELETE_OK = {"result": "Delete Successful"}
EXT_DUPLICATE = {
    "result": "A subscription with this topic name already exists. Please choose a different "
    "topic name."
}
EXT_BAD_DESTINATION = {
    "result": "Destination does not exist or might be a data-gateway destination, which is not "
    "allowed for external subscriptions."
}
EXT_NOT_FOUND = {
    "result": "Following subscription(s) not found and could not be deleted :[phase-d-audit]"
}
EXT_INVALID = {
    "error": "Following param(s) are invalid : Subscription Data Type, Subscription Data"
}
# Verified destinations list (trimmed): the system Kafka one (datagateway) and an
# application-dispatch Kafka and gRPC pair like the throwaway ones used live.
DESTINATIONS = {
    "data": [
        {
            "uuid": "c2a8fba8-8363-3d22-b0c2-a9e449693fae",
            "name": "CW_KAFKA_DESTINATION",
            "properties": {
                "DESTINATION_TYPE": "destination_type_kafka",
                "DISPATCH_SOURCE": "datagateway",
                "IS_SYSTEM_DEFINED": "true",
            },
        },
        {
            "uuid": "b7f73ed3-62e6-47d8-927c-ece3d8e79bff",
            "name": "phase-d-kafka",
            "properties": {
                "DESTINATION_TYPE": "destination_type_kafka",
                "DISPATCH_SOURCE": "application",
                "IS_SYSTEM_DEFINED": "false",
            },
        },
        {
            "uuid": "7de83fa7-adde-4337-92f0-9d6a99317649",
            "name": "phase-d-grpc",
            "properties": {
                "DESTINATION_TYPE": "destination_type_grpc",
                "DISPATCH_SOURCE": "application",
            },
        },
    ]
}


def build(settings: Settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    notifications.register(mcp, ctx)
    return mcp


def writable(make_settings, **overrides) -> MCPServer:
    return build(make_settings(enable_writes=True, **overrides))


def sent(route: respx.Route, index: int = 0) -> dict:
    return json.loads(route.calls[index].request.content)


def accept_of(route: respx.Route, index: int = 0) -> list[str]:
    return route.calls[index].request.headers.get_list("Accept")


# --- registration / gating ---------------------------------------------------


async def test_write_tools_hidden_unless_enabled(make_settings):
    names = {t.name for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert names == READ_TOOLS
    names = {t.name for t in await writable(make_settings).list_tools()}
    assert names == READ_TOOLS | WRITE_TOOLS


async def test_annotations(make_settings):
    tools = {t.name: t for t in await writable(make_settings).list_tools()}
    for name in READ_TOOLS:
        assert tools[name].annotations.read_only_hint is True, name
        assert tools[name].annotations.idempotent_hint is True, name
        assert tools[name].annotations.destructive_hint is False, name
    create = tools["cnc_create_webhook_subscription"].annotations
    assert create.read_only_hint is False
    assert create.idempotent_hint is False
    assert create.destructive_hint is False
    delete = tools["cnc_delete_notification_subscription"].annotations
    assert delete.read_only_hint is False
    assert delete.destructive_hint is True
    assert delete.idempotent_hint is True
    create_ext = tools["cnc_create_external_subscription"].annotations
    assert create_ext.read_only_hint is False
    assert create_ext.destructive_hint is False
    assert create_ext.idempotent_hint is False
    for name in (
        "cnc_delete_external_subscription",
        "cnc_clear_notification_subscriptions_by_topic",
    ):
        ann = tools[name].annotations
        assert ann.read_only_hint is False, name
        assert ann.destructive_hint is True, name
        assert ann.idempotent_hint is True, name


def test_base_path_is_the_verified_one():
    assert NOTIFICATIONS == "/crosswork/notification/restconf/data/v2"
    assert STREAMS_PATH.endswith("/ietf-restconf-monitoring:restconf-state/streams")
    assert SUBSCRIPTION_PATH.endswith("/notifications:subscription")
    assert SUBSCRIPTION_ADMIN_PATH.endswith("/notifications:subscription-admin")
    assert KAFKA_SUBSCRIPTION_PATH == "/crosswork/notification/v2/subscription"
    assert CLEAR_BY_TOPIC_PATH == "/crosswork/notification/restconf/data/v2/clear-by-topic"
    assert DESTINATIONS_QUERY_PATH == "/crosswork/dg-manager/v1/destinations/query"


# --- pure helpers ------------------------------------------------------------


def test_validate_client_url_accepts_explicit_ports_only():
    assert validate_client_url(f"  {SINK_URL} ") == SINK_URL
    assert validate_client_url("https://sink.example:8443/a/b?x=1") == (
        "https://sink.example:8443/a/b?x=1"
    )
    with pytest.raises(PlatformError, match="has no explicit port") as info:
        validate_client_url("http://198.18.140.17/hook")
    assert "bare HTTP 500" in str(info.value)
    assert "'http://198.18.140.17:80/hook'" in str(info.value)  # the corrected example
    with pytest.raises(PlatformError, match="e.g. 'https://sink.example:443/hook\\?a=b'"):
        validate_client_url("https://sink.example/hook?a=b")
    with pytest.raises(PlatformError, match="e.g. 'http://sink.example:80/'"):
        validate_client_url("http://sink.example")
    # An empty port: the corrected example must not carry a double colon.
    with pytest.raises(PlatformError, match="has no explicit port") as info:
        validate_client_url("http://sink.example:/hook")
    assert "e.g. 'http://sink.example:80/hook'" in str(info.value)
    assert "::" not in str(info.value)
    # IPv6 hosts stay bracketed and userinfo is kept in the corrected example.
    with pytest.raises(PlatformError, match=r"e\.g\. 'http://\[::1\]:80/hook'"):
        validate_client_url("http://[::1]/hook")
    with pytest.raises(PlatformError, match="e.g. 'https://u:p@sink.example:443/hook'"):
        validate_client_url("https://u:p@sink.example/hook")
    assert validate_client_url("http://[::1]:8080/hook") == "http://[::1]:8080/hook"


def test_validate_client_url_rejects_scheme_host_and_port_problems():
    with pytest.raises(PlatformError, match="must use the http or https scheme"):
        validate_client_url("ftp://sink.example:21/hook")
    with pytest.raises(PlatformError, match="must use the http or https scheme"):
        validate_client_url("sink.example:80/hook")
    with pytest.raises(PlatformError, match="has no host"):
        validate_client_url("http:///hook")
    with pytest.raises(PlatformError, match="not a valid URL"):
        validate_client_url("http://sink.example:abc/hook")
    with pytest.raises(PlatformError, match="must not be blank"):
        validate_client_url("   ")


def test_rc_error_reads_object_and_list_forms():
    assert rc_error(NOT_0029) == {
        "tag": "operation-failed",
        "app_tag": "NOT.0029",
        "message": "The endpoint is not reachable.",
    }
    as_list = {"rc.errors": {"error": [{"error-app-tag": "not.0037", "error-message": "gone"}]}}
    assert rc_error(as_list) == {"tag": "", "app_tag": "NOT.0037", "message": "gone"}
    empty = {"tag": "", "app_tag": "", "message": ""}
    assert rc_error({"errors": {"error": [{"error-app-tag": "NOT.0029"}]}}) == empty
    assert rc_error({"rc.errors": {"error": "junk"}}) == empty
    assert rc_error("Internal Server Error") == empty
    assert rc_error(None) == empty


def test_error_matches_on_app_tag_or_message():
    assert error_matches(rc_error(NOT_0006), "not.0006", "nothing")
    assert error_matches(rc_error(NOT_0006), "NOT.9999", "already exists")
    assert not error_matches(rc_error(NOT_0006), "NOT.0029", "not reachable")
    assert not error_matches(rc_error({}), "NOT.0029", "not reachable")


def test_is_rc_error_and_emf_rejection_render_the_service_tags():
    assert is_rc_error(rc_error(NOT_0006))
    assert not is_rc_error(rc_error({"message": "Bad Request"}))
    assert not is_rc_error(rc_error({"rc.errors": {"error": {}}}))
    text = str(emf_rejection(400, rc_error(rc_errors("NOT.0001", "Invalid input."))))
    assert text.startswith(
        "EMF RESTCONF rejected the request (HTTP 400): operation-failed [NOT.0001]: Invalid input."
    )
    assert "NOT.0029" in text  # the verified tags are listed for orientation
    assert str(emf_rejection(500, {"tag": "", "app_tag": "", "message": "boom"})).startswith(
        "EMF RESTCONF rejected the request (HTTP 500): error: boom."
    )


def test_rejection_and_emf_body_ladder():
    # rc.errors (any status) -> the module's rendering; anything else -> http_error.
    err = rejection(httpx.Response(500, json=NOT_0029))
    assert str(err).startswith(
        "EMF RESTCONF rejected the request (HTTP 500): operation-failed [NOT.0029]: "
        "The endpoint is not reachable"
    )
    err = rejection(httpx.Response(403, text="Unauthorized request"))
    assert str(err).startswith("API request failed with status 403")
    err = rejection(httpx.Response(400, json={"message": "Bad Request"}))
    assert str(err).startswith("API request failed with status 400")
    # emf_body: 2xx bodies are decoded (empty -> None, XML -> the Accept hint).
    assert emf_body(httpx.Response(200, json=SINGLE)) == SINGLE
    assert emf_body(httpx.Response(200, text="")) is None
    with pytest.raises(PlatformError, match="Accept: application/json"):
        emf_body(httpx.Response(200, text="<?xml version='1.0'?><x/>"))
    with pytest.raises(PlatformError, match=r"\[NOT\.0006\]"):
        emf_body(httpx.Response(500, json=NOT_0006))
    with pytest.raises(PlatformError, match="status 403"):
        emf_body(httpx.Response(403, text="Unauthorized request"))


def test_bare_500_error_names_the_url_and_the_verified_cause():
    text = str(bare_500_error(SINK_URL))
    assert text.startswith(
        f"Crosswork answered a bare HTTP 500 (empty body) to the subscription request for "
        f"{SINK_URL}."
    )
    assert "client-url form" in text and "without a port" in text
    assert "reachability probe" in text
    assert "cnc_list_notification_subscriptions" in text


def test_delete_confirmed_only_for_the_success_text():
    assert delete_confirmed("Success")
    assert delete_confirmed("  success\n")
    assert delete_confirmed('"Success"')
    assert not delete_confirmed("Failed")
    assert not delete_confirmed("")
    assert not delete_confirmed(None)
    assert not delete_confirmed('{"status":"Success"}')
    assert not delete_confirmed("Success: 1 deleted")


def test_subscription_items_accepts_envelope_and_bare_shapes():
    assert subscription_items(SINGLE, SUBSCRIPTION_PATH) == (
        [SUB],
        {"first_index": 0, "last_index": 0, "iterator_id": None},
    )
    assert subscription_items(LISTED, SUBSCRIPTION_PATH)[0] == [SUB, SUB2]
    subs, header = subscription_items(EMPTY, SUBSCRIPTION_PATH)
    assert subs == [] and header["last_index"] == -1
    # Defensive: a bare object, and a bare {"...subscription": <object | list>}.
    no_header = {"first_index": None, "last_index": None, "iterator_id": None}
    assert subscription_items(SUB, SUBSCRIPTION_PATH) == ([SUB], no_header)
    assert subscription_items({f"{NS}subscription": SUB}, SUBSCRIPTION_PATH) == ([SUB], no_header)
    assert subscription_items({f"{NS}subscription": [SUB, "junk", SUB2]}, SUBSCRIPTION_PATH) == (
        [SUB, SUB2],
        no_header,
    )


@pytest.mark.parametrize(
    "data",
    [
        None,  # empty body
        {},
        [],
        {"com.response-message": {}},  # envelope without a header
        {"com.response-message": {"com.header": {}, "com.data": {f"{NS}subscription": SUB}}},
        {"rcmon.streams": {}},  # another endpoint's document
        {f"{NS}subscription": "junk"},
    ],
)
def test_subscription_items_raises_for_documents_it_does_not_understand(data):
    with pytest.raises(PlatformError, match="unexpected answer from .*notifications:subscription"):
        subscription_items(data, SUBSCRIPTION_PATH)


def test_subscription_with_id_compares_as_text_and_ignores_other_entries():
    assert subscription_with_id([SUB, SUB2], 13) == SUB2
    assert subscription_with_id([SUB, SUB2], 12) == SUB
    assert subscription_with_id([{**SUB, f"{NS}subscription-id": "12"}], 12) is not None
    assert subscription_with_id([SUB, SUB2], 14) is None
    assert subscription_with_id([{}, {"subscription-id": None}], 12) is None
    assert subscription_with_id([], 12) is None


def test_streams_from_accepts_list_object_and_rejects_other_documents():
    assert len(streams_from(STREAMS)) == 3
    single = {"rcmon.streams": {"rcmon.stream": STREAMS["rcmon.streams"]["rcmon.stream"][0]}}
    assert len(streams_from(single)) == 1
    assert streams_from({"rcmon.streams": {}}) == []
    assert streams_from({"rcmon.streams": {"rcmon.stream": ["junk", 1]}}) == []
    with pytest.raises(PlatformError, match="did not carry 'rcmon.streams'"):
        streams_from({"com.response-message": {}})
    with pytest.raises(PlatformError, match="did not carry 'rcmon.streams'"):
        streams_from(None)


def test_subscription_line_and_markdown_use_the_verbatim_keys():
    assert subscription_line(SUB) == (
        f"- 12: alarm as json -> {SINK_URL} (user admin, connection-less, "
        "created Sat Sep 13 10:15:42 UTC 2026)"
    )
    assert subscription_line({}) == "- ?: ? as ? -> ? (user ?, ?, created ?)"
    text = subscription_markdown({**SUB, f"{NS}extra": "x"})
    assert text.startswith("# Notification subscription 12\n\n- Topic: alarm\n- Format: json\n")
    assert f"- Client URL: {SINK_URL}" in text
    assert "- Connection type: connection-less" in text
    assert "- Subscribed user: admin" in text
    assert "- Client IP: 198.18.140.17" in text
    assert "- Created: Sat Sep 13 10:15:42 UTC 2026" in text
    assert text.endswith("- extra: x")  # unknown fields are listed, prefix stripped
    assert "- Session ID: -" in subscription_markdown({f"{NS}subscription-id": 1})


def test_kafka_entries_only_for_the_documented_shape():
    assert kafka_entries(KAFKA_LISTED) == KAFKA_LISTED["subscriptionList"]
    assert kafka_entries({"subscriptionList": ["junk"]}) == []
    assert kafka_entries({"items": []}) is None
    assert kafka_entries([]) is None


# --- cnc_list_notification_streams -------------------------------------------


@respx.mock
async def test_list_streams_renders_each_stream_and_access_entry(settings):
    route = respx.get(STREAMS_URL).mock(return_value=httpx.Response(200, json=STREAMS))
    text = await call_tool_text(build(settings), "cnc_list_notification_streams", {})
    assert route.call_count == 1
    assert accept_of(route) == ["application/json"]
    assert text.startswith("# Notification streams (3)")
    assert "## RestConf (connection-less) alarm and inventory notification subscription" in text
    assert "Connection-less client subscription using payload" in text
    assert (
        "- xml: POST https://cnc.example:30603/crosswork/notification/restconf/data/v2/"
        "cisco-notifications:subscription"
    ) in text
    assert "## WebSocket (connection-oriented) Alarm Notification Streaming" in text
    assert (
        "- json: wss://cnc.example:30603/crosswork/notification/restconf/streams/v2/alarm.json"
    ) in text
    assert (
        "- json: wss://cnc.example:30603/crosswork/notification/restconf/streams/v1/inventory.json"
    ) in text


@respx.mock
async def test_list_streams_json_keeps_verbatim_keys(settings):
    respx.get(STREAMS_URL).mock(return_value=httpx.Response(200, json=STREAMS))
    text = await call_tool_text(
        build(settings), "cnc_list_notification_streams", {"response_format": "json"}
    )
    data = json.loads(text)
    assert data["count"] == 3
    assert data["items"] == STREAMS["rcmon.streams"]["rcmon.stream"]


@respx.mock
async def test_list_streams_empty_is_not_an_error(settings):
    respx.get(STREAMS_URL).mock(
        return_value=httpx.Response(200, json={"rcmon.streams": {"rcmon.stream": []}})
    )
    text = await call_tool_text(build(settings), "cnc_list_notification_streams", {})
    assert text == "No notification streams are advertised."


@respx.mock
async def test_list_streams_xml_fallback_and_http_errors_are_strings(make_settings):
    respx.get(STREAMS_URL).mock(
        return_value=httpx.Response(
            200, text='<?xml version="1.0"?><streams/>', headers={"Content-Type": "text/xml"}
        )
    )
    mcp = build(make_settings(max_retries=0))
    text = await call_tool_text(mcp, "cnc_list_notification_streams", {})
    assert text.startswith("Error:") and "Accept: application/json" in text
    respx.get(STREAMS_URL).mock(return_value=httpx.Response(403, text="Unauthorized request"))
    text = await call_tool_text(mcp, "cnc_list_notification_streams", {})
    assert text.startswith("Error:") and "403" in text


# --- cnc_list_notification_subscriptions -------------------------------------


@respx.mock
async def test_list_subscriptions_unwraps_the_single_object_form(settings):
    route = respx.get(SUBSCRIPTION_URL).mock(return_value=httpx.Response(200, json=SINGLE))
    text = await call_tool_text(build(settings), "cnc_list_notification_subscriptions", {})
    assert route.call_count == 1
    assert accept_of(route) == ["application/json"]
    # The default page is the platform's own default batch (.maxCount 100 from 0).
    assert dict(route.calls[0].request.url.params) == {".startIndex": "0", ".maxCount": "100"}
    assert text.startswith("# Notification subscriptions (1, configured user)")
    assert f"- 12: alarm as json -> {SINK_URL} (user admin, connection-less, created" in text
    assert "More available" not in text
    data = json.loads(
        await call_tool_text(
            build(settings),
            "cnc_list_notification_subscriptions",
            {"response_format": "json"},
        )
    )
    # the OBJECT under the key became a one-item list, keys verbatim
    assert data["count"] == 1 and data["scope"] == "own"
    assert data["items"] == [SUB]
    assert data["first_index"] == 0 and data["last_index"] == 0
    assert data["has_more"] is False and data["next_offset"] is None
    assert data["start_index"] == 0 and data["max_count"] == 100
    assert data["total"] is None and data["offset"] == 0


@respx.mock
async def test_list_subscriptions_pages_with_start_index_and_max_count(settings):
    # A full page of 2 at offset 3: has_more and the next offset are reported.
    route = respx.get(ADMIN_URL).mock(
        return_value=httpx.Response(200, json=envelope([SUB, SUB2], 1))
    )
    text = await call_tool_text(
        build(settings),
        "cnc_list_notification_subscriptions",
        {"all_users": True, "limit": 2, "offset": 3},
    )
    assert dict(route.calls[0].request.url.params) == {".startIndex": "3", ".maxCount": "2"}
    assert text.startswith("# Notification subscriptions (2, all users)")
    assert text.endswith("More available: repeat with offset=5.")
    data = json.loads(
        await call_tool_text(
            build(settings),
            "cnc_list_notification_subscriptions",
            {"all_users": True, "limit": 2, "offset": 3, "response_format": "json"},
        )
    )
    assert data["count"] == 2 and data["has_more"] is True
    assert data["next_offset"] == 5 and data["next_start_index"] == 5
    assert data["start_index"] == 3 and data["max_count"] == 2
    # An empty page past the end names the offset.
    respx.get(ADMIN_URL).mock(return_value=httpx.Response(200, json=EMPTY))
    text = await call_tool_text(
        build(settings),
        "cnc_list_notification_subscriptions",
        {"all_users": True, "limit": 2, "offset": 5},
    )
    assert text.startswith("No notification subscriptions at offset 5. Scope: every user.")


async def test_list_subscriptions_schema_bounds_the_page(settings):
    with pytest.raises(ToolError, match="limit"):
        await call_tool_text(build(settings), "cnc_list_notification_subscriptions", {"limit": 101})
    with pytest.raises(ToolError, match="offset"):
        await call_tool_text(build(settings), "cnc_list_notification_subscriptions", {"offset": -1})


@respx.mock
async def test_list_subscriptions_unexpected_200_is_an_error_not_none(make_settings):
    # An empty body, {} or another document is never "no subscriptions".
    mcp = build(make_settings(max_retries=0))
    for body in ({"text": ""}, {"json": {}}, {"json": {"rcmon.streams": {}}}):
        respx.get(SUBSCRIPTION_URL).mock(return_value=httpx.Response(200, **body))
        text = await call_tool_text(mcp, "cnc_list_notification_subscriptions", {})
        assert text.startswith("Error: unexpected answer from"), body
        assert "notifications:subscription" in text
        assert "No notification subscriptions" not in text
    # ... whereas a bare object (not the verified envelope) is still listed.
    respx.get(SUBSCRIPTION_URL).mock(return_value=httpx.Response(200, json=SUB))
    text = await call_tool_text(mcp, "cnc_list_notification_subscriptions", {})
    assert text.startswith("# Notification subscriptions (1, configured user)")


@respx.mock
async def test_list_subscriptions_all_users_hits_the_admin_path_and_lists_all(settings):
    own = respx.get(SUBSCRIPTION_URL).mock(return_value=httpx.Response(200, json=SINGLE))
    admin = respx.get(ADMIN_URL).mock(return_value=httpx.Response(200, json=LISTED))
    text = await call_tool_text(
        build(settings), "cnc_list_notification_subscriptions", {"all_users": True}
    )
    assert own.call_count == 0 and admin.call_count == 1
    assert text.startswith("# Notification subscriptions (2, all users)")
    assert "- 12: alarm as json ->" in text
    assert "- 13: inventory as xml -> https://sink.example:443/inv (user ops," in text
    data = json.loads(
        await call_tool_text(
            build(settings),
            "cnc_list_notification_subscriptions",
            {"all_users": True, "response_format": "json"},
        )
    )
    assert data["count"] == 2 and data["scope"] == "all_users"
    assert data["items"] == [SUB, SUB2]


@respx.mock
async def test_list_subscriptions_empty_envelope_is_not_an_error(settings):
    respx.get(SUBSCRIPTION_URL).mock(return_value=httpx.Response(200, json=EMPTY))
    text = await call_tool_text(build(settings), "cnc_list_notification_subscriptions", {})
    assert text.startswith("No notification subscriptions.")
    assert "all_users=True" in text
    data = json.loads(
        await call_tool_text(
            build(settings),
            "cnc_list_notification_subscriptions",
            {"response_format": "json"},
        )
    )
    assert data["count"] == 0 and data["items"] == [] and data["last_index"] == -1


@respx.mock
async def test_list_subscriptions_http_error_is_string(make_settings):
    respx.get(SUBSCRIPTION_URL).mock(return_value=httpx.Response(403, text="Unauthorized request"))
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_list_notification_subscriptions", {}
    )
    assert text.startswith("Error:") and "403" in text


@respx.mock
async def test_list_subscriptions_rc_errors_renders_the_service_tags(make_settings):
    # An rc.errors answer to the list GET (e.g. to a paging parameter the
    # service will not take) is the module's own rendering with the NOT.xxxx
    # tag — never errors.http_error's topology-NBI "RESTCONF key problem" hint.
    mcp = build(make_settings(max_retries=0))
    respx.get(SUBSCRIPTION_URL).mock(
        return_value=httpx.Response(
            400, json=rc_errors("NOT.0002", "Invalid start index", tag="invalid-value")
        )
    )
    text = await call_tool_text(mcp, "cnc_list_notification_subscriptions", {"offset": 7})
    assert text.startswith(
        "Error: EMF RESTCONF rejected the request (HTTP 400): invalid-value [NOT.0002]: "
        "Invalid start index"
    )
    assert "API request failed" not in text
    assert "RESTCONF key problem" not in text and "YANG" not in text
    # ... the admin path and a 500 rc.errors alike.
    respx.get(ADMIN_URL).mock(
        return_value=httpx.Response(500, json=rc_errors("NOT.0099", "Internal failure"))
    )
    text = await call_tool_text(mcp, "cnc_list_notification_subscriptions", {"all_users": True})
    assert text.startswith(
        "Error: EMF RESTCONF rejected the request (HTTP 500): operation-failed [NOT.0099]: "
        "Internal failure"
    )


@respx.mock
async def test_list_streams_rc_errors_renders_the_service_tags(make_settings):
    respx.get(STREAMS_URL).mock(
        return_value=httpx.Response(400, json=rc_errors("NOT.0002", "Invalid input"))
    )
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_list_notification_streams", {}
    )
    assert text.startswith(
        "Error: EMF RESTCONF rejected the request (HTTP 400): operation-failed [NOT.0002]: "
        "Invalid input"
    )
    assert "API request failed" not in text and "YANG" not in text


# --- cnc_get_notification_subscription ---------------------------------------


@respx.mock
async def test_get_subscription_renders_the_object(settings):
    route = respx.get(f"{SUBSCRIPTION_URL}/12").mock(return_value=httpx.Response(200, json=SINGLE))
    text = await call_tool_text(
        build(settings), "cnc_get_notification_subscription", {"subscription_id": 12}
    )
    assert route.call_count == 1
    assert accept_of(route) == ["application/json"]
    assert text.startswith("# Notification subscription 12")
    assert "- Topic: alarm" in text and "- Format: json" in text
    assert f"- Client URL: {SINK_URL}" in text
    assert "- Session ID: 6c1f6c3a-0c1e-4a2d-9f3b-8e7d6c5b4a39" in text
    text = await call_tool_text(
        build(settings),
        "cnc_get_notification_subscription",
        {"subscription_id": 12, "response_format": "json"},
    )
    assert json.loads(text) == SUB


@respx.mock
async def test_get_subscription_unknown_id_is_not_found(settings):
    respx.get(f"{SUBSCRIPTION_URL}/99").mock(return_value=httpx.Response(400, json=NOT_0016))
    text = await call_tool_text(
        build(settings), "cnc_get_notification_subscription", {"subscription_id": 99}
    )
    assert text == "Error: no subscription 99 (list with cnc_list_notification_subscriptions)"


@respx.mock
async def test_get_subscription_empty_envelope_is_not_found_too(settings):
    respx.get(f"{SUBSCRIPTION_URL}/7").mock(return_value=httpx.Response(200, json=EMPTY))
    text = await call_tool_text(
        build(settings), "cnc_get_notification_subscription", {"subscription_id": 7}
    )
    assert text == "Error: no subscription 7 (list with cnc_list_notification_subscriptions)"


@respx.mock
async def test_get_subscription_other_400_keeps_the_platform_words(settings):
    respx.get(f"{SUBSCRIPTION_URL}/5").mock(
        return_value=httpx.Response(400, json=rc_errors("NOT.0001", "Invalid input"))
    )
    text = await call_tool_text(
        build(settings), "cnc_get_notification_subscription", {"subscription_id": 5}
    )
    # The module's own rendering, not errors.http_error's topology-NBI RESTCONF hints.
    assert text.startswith(
        "Error: EMF RESTCONF rejected the request (HTTP 400): operation-failed [NOT.0001]: "
        "Invalid input"
    )
    assert "NOT.0016" in text  # the verified tags are listed for orientation
    assert "API request failed" not in text and "YANG" not in text


@respx.mock
async def test_get_subscription_non_restconf_error_takes_the_generic_hint(make_settings):
    respx.get(f"{SUBSCRIPTION_URL}/5").mock(
        return_value=httpx.Response(403, text="Unauthorized request")
    )
    text = await call_tool_text(
        build(make_settings(max_retries=0)),
        "cnc_get_notification_subscription",
        {"subscription_id": 5},
    )
    assert text.startswith("Error: API request failed with status 403")
    assert "Unauthorized request" in text


async def test_get_subscription_schema_requires_an_integer(settings):
    with pytest.raises(ToolError, match="subscription_id"):
        await call_tool_text(
            build(settings), "cnc_get_notification_subscription", {"subscription_id": "abc"}
        )


# --- cnc_list_kafka_subscriptions --------------------------------------------


@respx.mock
async def test_list_kafka_subscriptions_empty_body_is_not_an_error(settings):
    route = respx.get(KAFKA_URL).mock(return_value=httpx.Response(200, text=""))
    text = await call_tool_text(build(settings), "cnc_list_kafka_subscriptions", {})
    assert route.call_count == 1
    assert text == "No Kafka/gRPC subscriptions."
    text = await call_tool_text(
        build(settings), "cnc_list_kafka_subscriptions", {"response_format": "json"}
    )
    assert json.loads(text) == {"count": 0, "items": []}


@respx.mock
async def test_list_kafka_subscriptions_documented_shape_and_raw_fallback(settings):
    respx.get(KAFKA_URL).mock(return_value=httpx.Response(200, json=KAFKA_LISTED))
    text = await call_tool_text(build(settings), "cnc_list_kafka_subscriptions", {})
    assert text.startswith("# Kafka/gRPC subscriptions (1)")
    assert "verified" not in text
    assert (
        "- audit123 -> kafkadest (Kafka; data System_Audit; user admin; "
        "created Thu Sep 11 06:06:07 UTC 2025)"
    ) in text
    text = await call_tool_text(
        build(settings), "cnc_list_kafka_subscriptions", {"response_format": "json"}
    )
    # Always the envelope: the documented entries become "items".
    assert json.loads(text) == {"count": 1, "items": KAFKA_LISTED["subscriptionList"]}
    other = {"subscriptions": [{"name": "x"}]}
    respx.get(KAFKA_URL).mock(return_value=httpx.Response(200, json=other))
    text = await call_tool_text(build(settings), "cnc_list_kafka_subscriptions", {})
    assert text.startswith("# Kafka/gRPC subscriptions (shape not the verified one")
    assert "shown unparsed" in text
    assert json.loads(text.split("\n\n", 2)[2]) == other
    # JSON mode for the unknown shape: empty items plus the body under "raw".
    text = await call_tool_text(
        build(settings), "cnc_list_kafka_subscriptions", {"response_format": "json"}
    )
    assert json.loads(text) == {"count": 0, "items": [], "raw": other}
    # A documented but empty list is not the unknown shape.
    respx.get(KAFKA_URL).mock(return_value=httpx.Response(200, json={"subscriptionList": []}))
    text = await call_tool_text(build(settings), "cnc_list_kafka_subscriptions", {})
    assert text == "No Kafka/gRPC subscriptions."
    text = await call_tool_text(
        build(settings), "cnc_list_kafka_subscriptions", {"response_format": "json"}
    )
    assert json.loads(text) == {"count": 0, "items": []}


@respx.mock
async def test_list_kafka_subscriptions_http_error_is_string(make_settings):
    respx.get(KAFKA_URL).mock(
        return_value=httpx.Response(404, json={"errorMessage": "No static resource"})
    )
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_list_kafka_subscriptions", {}
    )
    assert text.startswith("Error:") and "404" in text


# --- cnc_create_webhook_subscription -----------------------------------------


@respx.mock
async def test_create_webhook_subscription_sends_verbatim_keys_and_returns_the_object(
    make_settings,
):
    route = respx.post(SUBSCRIPTION_URL).mock(return_value=httpx.Response(200, json=SINGLE))
    text = await call_tool_text(
        writable(make_settings),
        "cnc_create_webhook_subscription",
        {"client_url": f" {SINK_URL} ", "topic": "Alarm"},
    )
    assert route.call_count == 1
    request = route.calls[0].request
    assert request.method == "POST"
    assert request.headers.get_list("Accept") == ["application/json"]
    assert request.headers["Content-Type"] == "application/json"
    assert sent(route) == {
        "ietf-restconf:notification.client-url": SINK_URL,
        "ietf-restconf:notification.topic": "alarm",
        "ietf-restconf:notification.format": "json",
    }
    assert text.startswith(
        f"Webhook subscription 12 created: topic alarm, format json, url {SINK_URL}."
    )
    assert json.loads(text.split("\n\n", 1)[1]) == SUB


@respx.mock
async def test_create_webhook_subscription_xml_inventory(make_settings):
    route = respx.post(SUBSCRIPTION_URL).mock(
        return_value=httpx.Response(200, json=envelope(SUB2, 0))
    )
    text = await call_tool_text(
        writable(make_settings),
        "cnc_create_webhook_subscription",
        {"client_url": "https://sink.example:443/inv", "topic": "inventory", "format": "XML"},
    )
    assert sent(route) == {
        "ietf-restconf:notification.client-url": "https://sink.example:443/inv",
        "ietf-restconf:notification.topic": "inventory",
        "ietf-restconf:notification.format": "xml",
    }
    assert text.startswith(
        "Webhook subscription 13 created: topic inventory, format xml, "
        "url https://sink.example:443/inv."
    )


@respx.mock
async def test_create_webhook_subscription_refuses_a_url_without_port_before_sending(
    make_settings,
):
    route = respx.post(SUBSCRIPTION_URL).mock(return_value=httpx.Response(200, json=SINGLE))
    text = await call_tool_text(
        writable(make_settings),
        "cnc_create_webhook_subscription",
        {"client_url": "http://198.18.140.17/hook", "topic": "alarm"},
    )
    assert route.call_count == 0
    assert text.startswith("Error: client_url 'http://198.18.140.17/hook' has no explicit port")
    assert "bare HTTP 500" in text and "'http://198.18.140.17:80/hook'" in text
    text = await call_tool_text(
        writable(make_settings),
        "cnc_create_webhook_subscription",
        {"client_url": "ftp://sink.example:21/hook", "topic": "alarm"},
    )
    assert route.call_count == 0
    assert text.startswith("Error: client_url 'ftp://sink.example:21/hook' must use the http")


@respx.mock
async def test_create_webhook_subscription_refuses_bad_topic_and_format_before_sending(
    make_settings,
):
    route = respx.post(SUBSCRIPTION_URL).mock(return_value=httpx.Response(200, json=SINGLE))
    text = await call_tool_text(
        writable(make_settings),
        "cnc_create_webhook_subscription",
        {"client_url": SINK_URL, "topic": "events"},
    )
    assert text == "Error: Unknown topic 'events'. Use one of: alarm, inventory."
    text = await call_tool_text(
        writable(make_settings),
        "cnc_create_webhook_subscription",
        {"client_url": SINK_URL, "topic": "alarm", "format": "yaml"},
    )
    assert text == "Error: Unknown format 'yaml'. Use one of: json, xml."
    text = await call_tool_text(
        writable(make_settings),
        "cnc_create_webhook_subscription",
        {"client_url": SINK_URL, "topic": "  "},
    )
    assert text.startswith("Error: topic must not be blank")
    assert route.call_count == 0


@respx.mock
async def test_create_webhook_subscription_unreachable_endpoint(make_settings):
    respx.post(SUBSCRIPTION_URL).mock(return_value=httpx.Response(500, json=NOT_0029))
    text = await call_tool_text(
        writable(make_settings),
        "cnc_create_webhook_subscription",
        {"client_url": SINK_URL, "topic": "alarm"},
    )
    assert text.startswith(
        f"Error: the platform could not reach {SINK_URL} (it probes the endpoint before "
        "subscribing)"
    )
    assert "reachable from the Crosswork cluster" in text
    assert "Platform said: The endpoint is not reachable." in text


@respx.mock
async def test_create_webhook_subscription_duplicate(make_settings):
    respx.post(SUBSCRIPTION_URL).mock(return_value=httpx.Response(500, json=NOT_0006))
    text = await call_tool_text(
        writable(make_settings),
        "cnc_create_webhook_subscription",
        {"client_url": SINK_URL, "topic": "alarm", "format": "json"},
    )
    assert text.startswith(
        f"Error: a subscription for topic alarm at {SINK_URL} (format json) already exists"
    )
    assert "cnc_list_notification_subscriptions" in text
    assert "Platform said: Subscription already exists for the given topic" in text


@respx.mock
async def test_create_webhook_subscription_post_is_not_auto_retried(make_settings):
    # 503 is in the client's RETRYABLE_STATUS set (500 is not, so a 500 would
    # prove nothing): with max_retries=3 a GET would be sent four times, the
    # POST exactly once — a lost answer could mean the subscription exists.
    route = respx.post(SUBSCRIPTION_URL).mock(return_value=httpx.Response(503, text=""))
    text = await call_tool_text(
        writable(make_settings, max_retries=3),
        "cnc_create_webhook_subscription",
        {"client_url": SINK_URL, "topic": "alarm"},
    )
    assert route.call_count == 1
    assert text.startswith("Error: API request failed with status 503")


@respx.mock
async def test_create_webhook_subscription_empty_500_is_explained_by_the_module(make_settings):
    # The only verified cause of a bare 500 on this endpoint is a client-url
    # form the service cannot use (a failed probe may surface the same way);
    # errors.http_error's empty-500 hint (OPM / Optimization Engine) must not show.
    route = respx.post(SUBSCRIPTION_URL).mock(return_value=httpx.Response(500, text=""))
    text = await call_tool_text(
        writable(make_settings, max_retries=3),
        "cnc_create_webhook_subscription",
        {"client_url": SINK_URL, "topic": "alarm"},
    )
    assert route.call_count == 1
    assert text.startswith(
        "Error: Crosswork answered a bare HTTP 500 (empty body) to the subscription request "
        f"for {SINK_URL}."
    )
    assert "client-url form" in text and "reachability probe" in text
    assert "cnc_list_notification_subscriptions" in text
    assert "OPM" not in text and "Optimization Engine" not in text and "topology" not in text
    # A 500 WITH a body is not the bare case and keeps the generic rendering.
    respx.post(SUBSCRIPTION_URL).mock(
        return_value=httpx.Response(500, json={"errorMessage": "No static resource x"})
    )
    text = await call_tool_text(
        writable(make_settings, max_retries=3),
        "cnc_create_webhook_subscription",
        {"client_url": SINK_URL, "topic": "alarm"},
    )
    assert text.startswith("Error: API request failed with status 500")
    assert "bare HTTP 500" not in text


@respx.mock
async def test_create_webhook_subscription_other_errors_are_strings(make_settings):
    mcp = writable(make_settings, max_retries=0)
    respx.post(SUBSCRIPTION_URL).mock(
        return_value=httpx.Response(400, json={"message": "Bad Request"})
    )
    text = await call_tool_text(
        mcp, "cnc_create_webhook_subscription", {"client_url": SINK_URL, "topic": "alarm"}
    )
    assert text.startswith("Error: API request failed with status 400")
    assert "Bad Request" in text
    # Any other rc.errors answer renders the service's own tag verbatim.
    respx.post(SUBSCRIPTION_URL).mock(
        return_value=httpx.Response(400, json=rc_errors("NOT.0001", "Invalid input"))
    )
    text = await call_tool_text(
        mcp, "cnc_create_webhook_subscription", {"client_url": SINK_URL, "topic": "alarm"}
    )
    assert text.startswith(
        "Error: EMF RESTCONF rejected the request (HTTP 400): operation-failed [NOT.0001]: "
        "Invalid input"
    )


@respx.mock
async def test_create_webhook_subscription_answer_without_object_is_reported(make_settings):
    respx.post(SUBSCRIPTION_URL).mock(return_value=httpx.Response(200, json=EMPTY))
    text = await call_tool_text(
        writable(make_settings),
        "cnc_create_webhook_subscription",
        {"client_url": SINK_URL, "topic": "alarm"},
    )
    assert not text.startswith("Error:")
    assert text.startswith(f"The platform accepted the alarm subscription for {SINK_URL}")
    assert "cnc_list_notification_subscriptions" in text


# --- cnc_delete_notification_subscription ------------------------------------


@respx.mock
async def test_delete_subscription_success_text(make_settings):
    route = respx.delete(f"{SUBSCRIPTION_URL}/12").mock(
        return_value=httpx.Response(200, text="Success")
    )
    text = await call_tool_text(
        writable(make_settings), "cnc_delete_notification_subscription", {"subscription_id": 12}
    )
    assert route.call_count == 1
    assert route.calls[0].request.method == "DELETE"
    assert accept_of(route) == ["application/json"]
    assert text == "Notification subscription 12 deleted. Platform said: Success"


@respx.mock
async def test_delete_subscription_200_without_success_text_is_reported(make_settings):
    # Only the verified "Success" text confirms a delete: this platform rides
    # application failures inside HTTP 200 (alarm/v1 state Fail, NSO result:false).
    mcp = writable(make_settings)
    route = respx.delete(f"{SUBSCRIPTION_URL}/5")
    cases = (
        ({"text": "Failed"}, "Failed"),
        ({"text": ""}, "(empty body)"),
        ({"text": '{"status":"Failed"}'}, '{"status":"Failed"}'),
    )
    for calls, (body, echoed) in enumerate(cases, start=1):
        route.mock(return_value=httpx.Response(200, **body))
        text = await call_tool_text(
            mcp, "cnc_delete_notification_subscription", {"subscription_id": 5}
        )
        assert route.call_count == calls, body  # one DELETE each; a 2xx is never retried
        assert text.startswith(
            "Error: the platform answered HTTP 200 to the delete of subscription 5 but not "
            f'the verified "Success" text: {echoed}. The delete is unconfirmed'
        ), body
        assert not text.startswith("Notification subscription"), body
        assert "cnc_get_notification_subscription" in text, body
    # A 204 with no body is unconfirmed too (the verified answer is 200 "Success").
    respx.delete(f"{SUBSCRIPTION_URL}/5").mock(return_value=httpx.Response(204))
    text = await call_tool_text(mcp, "cnc_delete_notification_subscription", {"subscription_id": 5})
    assert text.startswith("Error: the platform answered HTTP 204")
    assert "(empty body)" in text
    # Case and a JSON-encoded "Success" are tolerated.
    for body in ({"text": " success \n"}, {"json": "Success"}):
        respx.delete(f"{SUBSCRIPTION_URL}/5").mock(return_value=httpx.Response(200, **body))
        text = await call_tool_text(
            mcp, "cnc_delete_notification_subscription", {"subscription_id": 5}
        )
        assert text.startswith("Notification subscription 5 deleted. Platform said:"), body


@respx.mock
async def test_delete_subscription_other_rc_errors_render_the_service_tags(make_settings):
    respx.delete(f"{SUBSCRIPTION_URL}/5").mock(
        return_value=httpx.Response(500, json=rc_errors("NOT.0099", "Internal failure"))
    )
    text = await call_tool_text(
        writable(make_settings), "cnc_delete_notification_subscription", {"subscription_id": 5}
    )
    assert text.startswith(
        "Error: EMF RESTCONF rejected the request (HTTP 500): operation-failed [NOT.0099]: "
        "Internal failure"
    )


@respx.mock
async def test_delete_subscription_unknown_id_is_not_found(make_settings):
    respx.delete(f"{SUBSCRIPTION_URL}/99").mock(return_value=httpx.Response(400, json=NOT_0037))
    text = await call_tool_text(
        writable(make_settings), "cnc_delete_notification_subscription", {"subscription_id": 99}
    )
    assert text == "Error: no subscription 99 (list with cnc_list_notification_subscriptions)"


@respx.mock
async def test_delete_subscription_other_errors_are_strings(make_settings):
    respx.delete(f"{SUBSCRIPTION_URL}/3").mock(
        return_value=httpx.Response(403, text="Unauthorized request")
    )
    text = await call_tool_text(
        writable(make_settings, max_retries=0),
        "cnc_delete_notification_subscription",
        {"subscription_id": 3},
    )
    assert text.startswith("Error:") and "403" in text


async def test_delete_subscription_schema_requires_an_integer(make_settings):
    with pytest.raises(ToolError, match="subscription_id"):
        await call_tool_text(
            writable(make_settings), "cnc_delete_notification_subscription", {"subscription_id": -1}
        )


# --- external (Kafka/gRPC) subscription helpers ------------------------------


def test_kafka_line_carries_subscription_data_and_filter():
    entry = {
        **KAFKA_LISTED["subscriptionList"][0],
        "topicName": "phase-d-inv",
        "subscriptionDataType": "Inventory_Changes",
        "filter": "Routers",
    }
    assert kafka_line(entry) == (
        "- phase-d-inv -> kafkadest (Kafka; data Inventory_Changes; filter Routers; user admin; "
        "created Thu Sep 11 06:06:07 UTC 2025)"
    )
    entry = {**entry, "subscriptionDataType": "Network_Performance_Monitoring"}
    entry["subscriptionData"] = "SR_PM_Interface"
    entry["filter"] = None
    assert "data Network_Performance_Monitoring SR_PM_Interface; user" in kafka_line(entry)


def test_match_choice_canonicalises_known_values_and_passes_others_through():
    assert match_choice(" sr_pm_interface ", ("SR_PM_Interface", "SR_PM_Policy")) == (
        "SR_PM_Interface"
    )
    assert match_choice("policy_type=X,policy_instance=y", ("A",)) == (
        "policy_type=X,policy_instance=y"
    )
    assert match_choice(None, ("A",)) == ""


def test_build_external_subscription_verified_bodies():
    # Minimal (Alarm): no optional keys at all — the verified accepted body.
    minimal = {
        "destinationName": "phase-d-kafka",
        "destinationType": "Kafka",
        "topicName": "phase-d-alarm",
        "subscriptionDataType": "Alarm",
    }
    assert build_external_subscription(" phase-d-kafka ", "kafka", " phase-d-alarm ", "alarm") == (
        minimal
    )
    # None (the spec example's explicit nulls), "" and whitespace all omit the keys.
    assert build_external_subscription(
        "phase-d-kafka", "Kafka", "phase-d-alarm", "Alarm", None, None
    ) == (minimal)
    assert build_external_subscription(
        "phase-d-kafka", "Kafka", "phase-d-alarm", "Alarm", " ", ""
    ) == (minimal)
    # The destination name is sent verbatim (trimmed only): the lookup is case-sensitive.
    assert build_external_subscription("Phase-D-KAFKA", "Kafka", "t", "Alarm")[
        "destinationName"
    ] == ("Phase-D-KAFKA")
    # NPM on gRPC with the selector canonicalised.
    body = build_external_subscription(
        "phase-d-grpc", "GRPC", "phase-d-gnpm", "network_performance_monitoring", "sr_pm_policy"
    )
    assert body["destinationType"] == "gRPC"
    assert body["subscriptionDataType"] == "Network_Performance_Monitoring"
    assert body["subscriptionData"] == "SR_PM_Policy"
    # Inventory with a filter; SHM selector canonicalised; DPM passed through.
    body = build_external_subscription("d", "Kafka", "t", "Inventory_Changes", "", " Routers ")
    assert body["filter"] == "Routers" and "subscriptionData" not in body
    body = build_external_subscription("d", "Kafka", "t", "Service_Health_Monitoring", "pca_probes")
    assert body["subscriptionData"] == "PCA_Probes"
    body = build_external_subscription(
        "d",
        "Kafka",
        "t",
        "Device_Performance_Monitoring",
        "policy_type=OpticalSFP,policy_instance=i",
    )
    assert body["subscriptionData"] == "policy_type=OpticalSFP,policy_instance=i"


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (("", "Kafka", "t", "Alarm"), "destination_name must not be blank"),
        (("d", "Kafka", " ", "Alarm"), "topic_name must not be blank"),
        (("d", "", "t", "Alarm"), "destination_type must not be blank"),
        (("d", "MQTT", "t", "Alarm"), "Unknown destination_type 'MQTT'"),
        (("d", "Kafka", "t", ""), "data_type must not be blank"),
        (("d", "Kafka", "t", "Bogus_Type"), "Unknown data_type 'Bogus_Type'"),
        (("d", "gRPC", "t", "Alarm"), "a gRPC destination cannot receive Alarm"),
        (("d", "gRPC", "t", "System_Audit"), "gRPC subscriptions take only"),
        (
            ("d", "Kafka", "t", "Network_Performance_Monitoring"),
            "Network_Performance_Monitoring needs subscription_data",
        ),
        (
            ("d", "Kafka", "t", "Network_Performance_Monitoring", "SR_PM_Nope"),
            "'SR_PM_Interface' or 'SR_PM_Policy' (got 'SR_PM_Nope'",
        ),
        (("d", "Kafka", "t", "Alarm", "", "Routers"), "filter is only accepted with data_type"),
        (
            ("d", "Kafka", "t", "Service_Health_Monitoring", "Bogus"),
            "Service_Health_Monitoring needs subscription_data 'Y1731_Probes' or 'PCA_Probes' "
            "(got 'Bogus'",
        ),
        (("d", "Kafka", "t", "Service_Health_Monitoring"), "(got ''"),
        (
            ("d", "Kafka", "t", "Device_Performance_Monitoring"),
            "needs subscription_data 'policy_type=",
        ),
        (
            ("d", "Kafka", "t", "Alarm", "SR_PM_Interface"),
            "subscription_data is only accepted with the performance-monitoring data types",
        ),
        (
            ("d", "Kafka", "t", "Inventory_Changes", "x", "Routers"),
            "Inventory_Changes with a subscriptionData",
        ),
    ],
)
def test_build_external_subscription_refuses_what_the_platform_refuses(args, message):
    with pytest.raises(PlatformError, match=re.escape(message)):
        build_external_subscription(*args)


def test_external_result_and_result_is():
    assert external_result(EXT_CREATE_OK) == "Create Successful"
    assert external_result(EXT_INVALID).startswith("Following param(s)")
    assert external_result({"result": "", "error": " x "}) == "x"
    assert external_result({"other": 1}) == "" and external_result("text") == ""
    assert external_result(None) == ""
    assert result_is(" create successful. ", "Create Successful")
    assert not result_is("Delete Successful", "Create Successful")


def test_invalid_params_error_adds_the_rule_per_named_parameter():
    err = invalid_params_error(400, external_result(EXT_INVALID), {"topicName": "t"})
    text = str(err)
    assert text.startswith("the platform rejected the subscription (HTTP 400): Following param(s)")
    assert "subscriptionDataType must be one of Inventory_Changes, Alarm" in text
    assert "subscriptionData is required for Network_Performance_Monitoring" in text
    assert 'Body sent: {\n  "topicName": "t"\n}' in text
    # An unknown parameter name: the platform words alone, still with the body.
    err = invalid_params_error(400, "Following param(s) are invalid : Colour", {})
    assert "Colour" in str(err) and "Body sent" in str(err)
    for name, rule in (
        ("Topic Name", "topicName must not be blank"),
        ("Destination Name", "destinationName must not be blank"),
        ("Destination Type", "exactly 'Kafka' or 'gRPC' (case-sensitive)"),
        ("Filter", "only accepted with subscriptionDataType Inventory_Changes"),
    ):
        assert rule in str(
            invalid_params_error(400, f"Following param(s) are invalid : {name}", {})
        )


def test_destination_diagnosis_names_the_verified_cause():
    dests = DESTINATIONS["data"]
    text = destination_diagnosis(dests, "nope", "Kafka")
    assert text.startswith("no Data Destination is named 'nope' (known: CW_KAFKA_DESTINATION, ")
    assert "cnc_list_data_destinations" in text
    text = destination_diagnosis(dests, "CW_KAFKA_DESTINATION", "Kafka")
    assert "exists but its DISPATCH_SOURCE is 'datagateway'" in text
    assert "'application' or 'any'" in text
    text = destination_diagnosis(dests, "phase-d-grpc", "Kafka")
    assert "it is a gRPC destination (DESTINATION_TYPE destination_type_grpc)" in text
    assert "while destination_type 'Kafka' was requested" in text
    # The right destination in the wrong case (verified live: refused — the platform's
    # lookup is case-sensitive): name the exact spelling to retry with.
    text = destination_diagnosis(dests, " Phase-D-KAFKA ", "Kafka")
    assert text == (
        "Data Destination 'phase-d-kafka' exists but the name was sent as 'Phase-D-KAFKA' — "
        "the platform looks the destination up by exact, case-sensitive name (verified live); "
        "retry with destination_name 'phase-d-kafka'."
    )
    # ... and alongside the other causes when they apply too.
    text = destination_diagnosis(dests, "cw_kafka_destination", "Kafka")
    assert text.startswith(
        "Data Destination 'CW_KAFKA_DESTINATION' exists but the name was sent as "
        "'cw_kafka_destination'"
    )
    assert "retry with destination_name 'CW_KAFKA_DESTINATION'; and its DISPATCH_SOURCE" in text
    # Both problems at once are both named.
    both = [{"name": "x", "properties": {"DESTINATION_TYPE": "destination_type_grpc"}}]
    text = destination_diagnosis(both, "x", "Kafka")
    assert "DISPATCH_SOURCE is 'unset'" in text and "; and it is a gRPC destination" in text
    # Nothing wrong that this tool knows: say so and show the properties.
    text = destination_diagnosis(dests, "phase-d-kafka", "Kafka")
    assert text.startswith("Data Destination 'phase-d-kafka' exists, its DISPATCH_SOURCE is")
    assert "cause this tool does not know" in text and '"DISPATCH_SOURCE": "application"' in text
    assert destination_diagnosis([], "x", "Kafka").startswith(
        "no Data Destination is named 'x' (known: none)"
    )


def test_clear_confirmed_and_subscriptions_of_topic():
    assert clear_confirmed("Clear successful")
    assert clear_confirmed(' "clear successful" \n')
    assert not clear_confirmed("") and not clear_confirmed(None) and not clear_confirmed("Success")
    subs = [SUB, SUB2]
    assert subscriptions_of_topic(subs, "Inventory") == [SUB2]
    assert subscriptions_of_topic(subs, "alarm") == [SUB]
    assert subscriptions_of_topic([{"x": 1}], "alarm") == []


# --- cnc_create_external_subscription ----------------------------------------


@respx.mock
async def test_create_external_subscription_sends_the_verified_body(make_settings):
    route = respx.post(KAFKA_URL).mock(return_value=httpx.Response(200, json=EXT_CREATE_OK))
    text = await call_tool_text(
        writable(make_settings),
        "cnc_create_external_subscription",
        {
            "destination_name": "phase-d-kafka",
            "destination_type": "kafka",
            "topic_name": "phase-d-audit",
            "data_type": "system_audit",
        },
    )
    assert route.call_count == 1
    request = route.calls[0].request
    assert request.method == "POST"
    assert request.headers["Content-Type"] == "application/json"
    assert sent(route) == {
        "destinationName": "phase-d-kafka",
        "destinationType": "Kafka",
        "topicName": "phase-d-audit",
        "subscriptionDataType": "System_Audit",
    }
    assert text.startswith(
        "External subscription created: topic phase-d-audit -> phase-d-kafka (Kafka), data "
        "System_Audit. Platform said: Create Successful\n\n"
    )
    assert json.loads(text.split("\n\n", 1)[1]) == sent(route)


@respx.mock
async def test_create_external_subscription_accepts_null_optional_arguments(make_settings):
    """The spec's own example sends "filter": null, "subscriptionData": null; an agent
    copying it must get the verified minimal body, not a schema error."""
    route = respx.post(KAFKA_URL).mock(return_value=httpx.Response(200, json=EXT_CREATE_OK))
    text = await call_tool_text(
        writable(make_settings),
        "cnc_create_external_subscription",
        {
            "destination_name": "phase-d-kafka",
            "destination_type": "Kafka",
            "topic_name": "phase-d-nulls",
            "data_type": "System_Audit",
            "subscription_data": None,
            "filter": None,
        },
    )
    assert route.call_count == 1
    assert sent(route) == {
        "destinationName": "phase-d-kafka",
        "destinationType": "Kafka",
        "topicName": "phase-d-nulls",
        "subscriptionDataType": "System_Audit",
    }
    assert text.startswith("External subscription created: topic phase-d-nulls -> phase-d-kafka")
    # Empty strings are the same as null.
    await call_tool_text(
        writable(make_settings),
        "cnc_create_external_subscription",
        {
            "destination_name": "phase-d-kafka",
            "destination_type": "Kafka",
            "topic_name": "phase-d-nulls",
            "data_type": "System_Audit",
            "subscription_data": "",
            "filter": " ",
        },
    )
    assert sent(route, 1) == sent(route)


@respx.mock
async def test_create_external_subscription_grpc_npm_with_selector_and_filter(make_settings):
    route = respx.post(KAFKA_URL).mock(return_value=httpx.Response(200, json=EXT_CREATE_OK))
    text = await call_tool_text(
        writable(make_settings),
        "cnc_create_external_subscription",
        {
            "destination_name": "phase-d-grpc",
            "destination_type": "gRPC",
            "topic_name": "phase-d-gnpm",
            "data_type": "Network_Performance_Monitoring",
            "subscription_data": "sr_pm_interface",
        },
    )
    assert sent(route)["subscriptionData"] == "SR_PM_Interface"
    assert sent(route)["destinationType"] == "gRPC"
    assert "data Network_Performance_Monitoring SR_PM_Interface. Platform said" in text
    text = await call_tool_text(
        writable(make_settings),
        "cnc_create_external_subscription",
        {
            "destination_name": "phase-d-kafka",
            "destination_type": "Kafka",
            "topic_name": "phase-d-inv",
            "data_type": "Inventory_Changes",
            "filter": "Routers",
        },
    )
    assert sent(route, 1)["filter"] == "Routers"
    assert "data Inventory_Changes, filter Routers. Platform said" in text


@respx.mock
async def test_create_external_subscription_refuses_before_sending(make_settings):
    route = respx.post(KAFKA_URL).mock(return_value=httpx.Response(200, json=EXT_CREATE_OK))
    mcp = writable(make_settings)
    base = {"destination_name": "d", "destination_type": "Kafka", "topic_name": "t"}
    text = await call_tool_text(
        mcp, "cnc_create_external_subscription", {**base, "data_type": "Alarm", "filter": "R"}
    )
    assert text.startswith("Error: filter is only accepted with data_type Inventory_Changes")
    text = await call_tool_text(
        mcp,
        "cnc_create_external_subscription",
        {**base, "destination_type": "gRPC", "data_type": "Alarm"},
    )
    assert text.startswith("Error: a gRPC destination cannot receive Alarm")
    text = await call_tool_text(
        mcp,
        "cnc_create_external_subscription",
        {**base, "data_type": "Network_Performance_Monitoring"},
    )
    assert text.startswith("Error: Network_Performance_Monitoring needs subscription_data")
    text = await call_tool_text(
        mcp, "cnc_create_external_subscription", {**base, "data_type": "Bogus"}
    )
    assert text.startswith("Error: Unknown data_type 'Bogus'")
    assert route.call_count == 0
    # Schema: the four required arguments.
    with pytest.raises(ToolError, match="data_type"):
        await call_tool_text(mcp, "cnc_create_external_subscription", base)


@respx.mock
async def test_create_external_subscription_duplicate_topic_is_a_200(make_settings):
    respx.post(KAFKA_URL).mock(return_value=httpx.Response(200, json=EXT_DUPLICATE))
    text = await call_tool_text(
        writable(make_settings),
        "cnc_create_external_subscription",
        {
            "destination_name": "phase-d-kafka",
            "destination_type": "Kafka",
            "topic_name": "phase-d-audit",
            "data_type": "Alarm",
        },
    )
    assert text.startswith("Error: a subscription with topic 'phase-d-audit' already exists")
    assert "cnc_delete_external_subscription" in text
    assert "Platform said: A subscription with this topic name already exists" in text


@respx.mock
async def test_create_external_subscription_refused_destination_is_diagnosed(make_settings):
    create = respx.post(KAFKA_URL).mock(return_value=httpx.Response(200, json=EXT_BAD_DESTINATION))
    dests = respx.post(DESTINATIONS_URL).mock(return_value=httpx.Response(200, json=DESTINATIONS))
    mcp = writable(make_settings)
    args = {"destination_type": "Kafka", "topic_name": "t", "data_type": "Alarm"}
    text = await call_tool_text(
        mcp,
        "cnc_create_external_subscription",
        {**args, "destination_name": "CW_KAFKA_DESTINATION"},
    )
    assert dests.call_count == 1
    assert sent(dests) == {"limit": 100, "filter": {}}
    assert text.startswith(
        "Error: the platform refused destination 'CW_KAFKA_DESTINATION' as a Kafka destination: "
        "Data Destination 'CW_KAFKA_DESTINATION' exists but its DISPATCH_SOURCE is 'datagateway'"
    )
    assert text.endswith("Platform said: " + EXT_BAD_DESTINATION["result"])
    text = await call_tool_text(
        mcp, "cnc_create_external_subscription", {**args, "destination_name": "nope"}
    )
    assert "no Data Destination is named 'nope' (known: CW_KAFKA_DESTINATION, phase-d-grpc" in text
    text = await call_tool_text(
        mcp, "cnc_create_external_subscription", {**args, "destination_name": "phase-d-grpc"}
    )
    assert "it is a gRPC destination" in text and "while destination_type 'Kafka'" in text
    # The name in the wrong case is sent verbatim (the platform refused it live) and the
    # diagnosis names the exact spelling.
    text = await call_tool_text(
        mcp, "cnc_create_external_subscription", {**args, "destination_name": "Phase-D-KAFKA"}
    )
    assert sent(create, 3)["destinationName"] == "Phase-D-KAFKA"
    assert text.startswith(
        "Error: the platform refused destination 'Phase-D-KAFKA' as a Kafka destination: Data "
        "Destination 'phase-d-kafka' exists but the name was sent as 'Phase-D-KAFKA'"
    )
    assert "retry with destination_name 'phase-d-kafka'" in text


@respx.mock
async def test_create_external_subscription_diagnosis_lookup_failure_keeps_the_refusal(
    make_settings,
):
    respx.post(KAFKA_URL).mock(return_value=httpx.Response(200, json=EXT_BAD_DESTINATION))
    respx.post(DESTINATIONS_URL).mock(return_value=httpx.Response(403, text="Unauthorized"))
    text = await call_tool_text(
        writable(make_settings, max_retries=0),
        "cnc_create_external_subscription",
        {
            "destination_name": "x",
            "destination_type": "Kafka",
            "topic_name": "t",
            "data_type": "Alarm",
        },
    )
    assert text.startswith("Error: the platform refused destination 'x' as a Kafka destination: ")
    assert "the lookup for this hint failed" in text
    assert "cnc_list_data_destinations" in text
    assert text.endswith("Platform said: " + EXT_BAD_DESTINATION["result"])


@respx.mock
async def test_create_external_subscription_400_invalid_params_carries_the_rules(make_settings):
    respx.post(KAFKA_URL).mock(
        return_value=httpx.Response(
            400, json={"error": "Following param(s) are invalid : Destination Type"}
        )
    )
    text = await call_tool_text(
        writable(make_settings, max_retries=0),
        "cnc_create_external_subscription",
        {
            "destination_name": "d",
            "destination_type": "Kafka",
            "topic_name": "t",
            "data_type": "Alarm",
        },
    )
    assert text.startswith(
        "Error: the platform rejected the subscription (HTTP 400): Following param(s) are "
        "invalid : Destination Type. destinationType must be exactly 'Kafka' or 'gRPC'"
    )
    assert '"topicName": "t"' in text


@respx.mock
async def test_create_external_subscription_other_answers(make_settings):
    mcp = writable(make_settings, max_retries=0)
    args = {
        "destination_name": "d",
        "destination_type": "Kafka",
        "topic_name": "t",
        "data_type": "Alarm",
    }
    # A 2xx without the verified text: unconfirmed, never "created".
    respx.post(KAFKA_URL).mock(return_value=httpx.Response(200, json={"result": "Queued"}))
    text = await call_tool_text(mcp, "cnc_create_external_subscription", args)
    assert text.startswith(
        "Error: the platform answered HTTP 200 to the subscription request but not the verified "
        '"Create Successful" text: Queued.'
    )
    assert "cnc_list_kafka_subscriptions" in text
    respx.post(KAFKA_URL).mock(return_value=httpx.Response(200, text=""))
    text = await call_tool_text(mcp, "cnc_create_external_subscription", args)
    assert "(empty body)" in text
    # Other HTTP errors take the generic hint; the POST is not auto-retried (503 is
    # in the client's RETRYABLE_STATUS set: a GET would be sent four times).
    route = respx.post(KAFKA_URL).mock(return_value=httpx.Response(503, text=""))
    before = route.call_count
    text = await call_tool_text(
        writable(make_settings, max_retries=3), "cnc_create_external_subscription", args
    )
    assert text.startswith("Error: API request failed with status 503")
    assert route.call_count == before + 1


# --- cnc_delete_external_subscription ----------------------------------------


@respx.mock
async def test_delete_external_subscription_by_topic_alone(make_settings):
    route = respx.delete(KAFKA_URL).mock(return_value=httpx.Response(200, json=EXT_DELETE_OK))
    text = await call_tool_text(
        writable(make_settings),
        "cnc_delete_external_subscription",
        {"topic_name": " phase-d-audit "},
    )
    assert route.call_count == 1
    assert route.calls[0].request.method == "DELETE"
    assert route.calls[0].request.headers["Content-Type"] == "application/json"
    assert sent(route) == {"subscriptionList": [{"topicName": "phase-d-audit"}]}
    assert text == (
        "External subscription for topic 'phase-d-audit' deleted. Platform said: Delete Successful"
    )
    # Optional fields are sent verbatim (type canonicalised) when given.
    await call_tool_text(
        writable(make_settings),
        "cnc_delete_external_subscription",
        {"topic_name": "t", "destination_name": "phase-d-kafka", "destination_type": "kafka"},
    )
    assert sent(route, 1) == {
        "subscriptionList": [
            {"topicName": "t", "destinationName": "phase-d-kafka", "destinationType": "Kafka"}
        ]
    }
    # Explicit nulls (and blanks) omit them — no schema error.
    await call_tool_text(
        writable(make_settings),
        "cnc_delete_external_subscription",
        {"topic_name": "t", "destination_name": None, "destination_type": None},
    )
    assert sent(route, 2) == {"subscriptionList": [{"topicName": "t"}]}
    await call_tool_text(
        writable(make_settings),
        "cnc_delete_external_subscription",
        {"topic_name": "t", "destination_name": " ", "destination_type": ""},
    )
    assert sent(route, 3) == {"subscriptionList": [{"topicName": "t"}]}


@respx.mock
async def test_delete_external_subscription_unknown_topic_is_not_found(make_settings):
    route = respx.delete(KAFKA_URL).mock(return_value=httpx.Response(400, json=EXT_NOT_FOUND))
    text = await call_tool_text(
        writable(make_settings),
        "cnc_delete_external_subscription",
        {"topic_name": "phase-d-audit"},
    )
    assert route.call_count == 1
    assert text == (
        "Error: no external subscription for topic 'phase-d-audit' (list with "
        "cnc_list_kafka_subscriptions)"
    )


@respx.mock
async def test_delete_external_subscription_other_answers(make_settings):
    mcp = writable(make_settings, max_retries=0)
    respx.delete(KAFKA_URL).mock(return_value=httpx.Response(200, json={"result": "Failed"}))
    text = await call_tool_text(mcp, "cnc_delete_external_subscription", {"topic_name": "t"})
    assert text.startswith(
        "Error: the platform answered HTTP 200 to the delete of topic 't' but not the verified "
        '"Delete Successful" text: Failed.'
    )
    respx.delete(KAFKA_URL).mock(
        return_value=httpx.Response(
            400, json={"result": "Please provide at least one valid subscription data to delete"}
        )
    )
    text = await call_tool_text(mcp, "cnc_delete_external_subscription", {"topic_name": "t"})
    assert text.startswith("Error:") and "400" in text
    respx.delete(KAFKA_URL).mock(return_value=httpx.Response(415, json={"status": 415}))
    text = await call_tool_text(mcp, "cnc_delete_external_subscription", {"topic_name": "t"})
    assert text.startswith("Error:") and "415" in text
    text = await call_tool_text(
        mcp, "cnc_delete_external_subscription", {"topic_name": "t", "destination_type": "MQTT"}
    )
    assert text.startswith("Error: Unknown destination_type 'MQTT'")
    with pytest.raises(ToolError, match="topic_name"):
        await call_tool_text(mcp, "cnc_delete_external_subscription", {"topic_name": ""})


# --- cnc_clear_notification_subscriptions_by_topic ---------------------------


def admin_answers(*bodies):
    """Mock the admin list to answer ``bodies`` in order (the last one repeats)."""
    return respx.get(ADMIN_URL).mock(
        side_effect=[httpx.Response(200, json=b) for b in bodies]
        + [httpx.Response(200, json=bodies[-1])]
    )


@respx.mock
async def test_clear_by_topic_lists_before_and_after(make_settings):
    # Before: an alarm and an inventory subscription; after: only the alarm one.
    admin = admin_answers(LISTED, envelope(SUB, 0))
    clear = respx.post(f"{CLEAR_URL}/inventory").mock(
        return_value=httpx.Response(200, text="Clear successful")
    )
    text = await call_tool_text(
        writable(make_settings),
        "cnc_clear_notification_subscriptions_by_topic",
        {"topic": "Inventory"},
    )
    assert clear.call_count == 1
    assert clear.calls[0].request.method == "POST"
    assert accept_of(clear) == ["application/json"]
    assert clear.calls[0].request.content == b""
    assert admin.call_count == 2
    assert admin.calls[0].request.url.params[".maxCount"] == "100"
    assert text == (
        "Cleared 1 notification subscription(s) of topic inventory (ids 13 "
        "(https://sink.example:443/inv, user ops)). Platform said: Clear successful"
    )


@respx.mock
async def test_clear_by_topic_sends_nothing_when_the_topic_has_none(make_settings):
    admin_answers(SINGLE)  # only an alarm subscription
    clear = respx.post(f"{CLEAR_URL}/inventory").mock(
        return_value=httpx.Response(200, text="Clear successful")
    )
    text = await call_tool_text(
        writable(make_settings),
        "cnc_clear_notification_subscriptions_by_topic",
        {"topic": "inventory"},
    )
    assert clear.call_count == 0
    assert text == (
        "No notification subscriptions of topic inventory to clear (every user's view); "
        "nothing sent."
    )
    admin_answers(EMPTY)
    text = await call_tool_text(
        writable(make_settings), "cnc_clear_notification_subscriptions_by_topic", {"topic": "alarm"}
    )
    assert text.startswith("No notification subscriptions of topic alarm to clear")
    assert clear.call_count == 0


@respx.mock
async def test_clear_by_topic_refuses_unknown_topic_before_sending(make_settings):
    admin = respx.get(ADMIN_URL).mock(return_value=httpx.Response(200, json=LISTED))
    clear = respx.post(url__startswith=CLEAR_URL).mock(
        return_value=httpx.Response(200, text="Clear successful")
    )
    text = await call_tool_text(
        writable(make_settings), "cnc_clear_notification_subscriptions_by_topic", {"topic": "nope"}
    )
    assert text == "Error: Unknown topic 'nope'. Use one of: alarm, inventory."
    text = await call_tool_text(
        writable(make_settings), "cnc_clear_notification_subscriptions_by_topic", {"topic": " "}
    )
    assert text == "Error: topic must not be blank. Use one of: alarm, inventory."
    assert admin.call_count == 0 and clear.call_count == 0


@respx.mock
async def test_clear_by_topic_unconfirmed_and_remaining_are_errors(make_settings):
    mcp = writable(make_settings, max_retries=0)
    # 2xx without the verified text.
    admin_answers(LISTED)
    respx.post(f"{CLEAR_URL}/alarm").mock(return_value=httpx.Response(200, text=""))
    text = await call_tool_text(
        mcp, "cnc_clear_notification_subscriptions_by_topic", {"topic": "alarm"}
    )
    assert text.startswith(
        "Error: the platform answered HTTP 200 to clear-by-topic/alarm but not the verified "
        '"Clear successful" text: (empty body).'
    )
    # "Clear successful" but the topic's subscriptions are still listed afterwards.
    admin_answers(LISTED, LISTED)
    respx.post(f"{CLEAR_URL}/alarm").mock(return_value=httpx.Response(200, text="Clear successful"))
    text = await call_tool_text(
        mcp, "cnc_clear_notification_subscriptions_by_topic", {"topic": "alarm"}
    )
    assert text.startswith(
        'Error: the platform said "Clear successful" for topic alarm but 1 subscription(s) of '
        f"that topic remain in the admin view: 12 ({SINK_URL}, user admin)."
    )
    assert "cnc_delete_notification_subscription" in text
    # rc.errors on the clear renders the service tag; a failing admin list is an error too.
    admin_answers(LISTED)
    respx.post(f"{CLEAR_URL}/alarm").mock(
        return_value=httpx.Response(403, json=rc_errors("NOT.0099", "Not permitted"))
    )
    text = await call_tool_text(
        mcp, "cnc_clear_notification_subscriptions_by_topic", {"topic": "alarm"}
    )
    assert text.startswith(
        "Error: EMF RESTCONF rejected the request (HTTP 403): operation-failed [NOT.0099]: "
        "Not permitted."
    )
    respx.get(ADMIN_URL).mock(return_value=httpx.Response(500, text=""))
    text = await call_tool_text(
        mcp, "cnc_clear_notification_subscriptions_by_topic", {"topic": "alarm"}
    )
    assert text.startswith("Error:") and "500" in text


@respx.mock
async def test_clear_by_topic_notes_a_full_admin_page(make_settings):
    # 100 inventory subscriptions before (a full page), none after.
    many = [{**SUB2, f"{NS}subscription-id": 1000 + i} for i in range(100)]
    admin_answers(envelope(many, 99), EMPTY)
    respx.post(f"{CLEAR_URL}/inventory").mock(
        return_value=httpx.Response(200, text="Clear successful")
    )
    text = await call_tool_text(
        writable(make_settings),
        "cnc_clear_notification_subscriptions_by_topic",
        {"topic": "inventory"},
    )
    assert text.startswith(
        "Cleared 100 notification subscription(s) of topic inventory (ids 1000 ("
    )
    assert text.endswith("so the count is a lower bound.")
    # A full page with none of the topic: the "may have more" note, nothing sent.
    alarms = [{**SUB, f"{NS}subscription-id": 2000 + i} for i in range(100)]
    admin_answers(envelope(alarms, 99))
    text = await call_tool_text(
        writable(make_settings),
        "cnc_clear_notification_subscriptions_by_topic",
        {"topic": "inventory"},
    )
    assert text == (
        "No notification subscriptions of topic inventory to clear (every user's view) (the "
        "admin view was a full page of 100 — the topic may have more beyond it); nothing sent."
    )
