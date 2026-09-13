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
"""

from __future__ import annotations

import json

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
    KAFKA_SUBSCRIPTION_PATH,
    NOTIFICATIONS,
    NS,
    STREAMS_PATH,
    SUBSCRIPTION_ADMIN_PATH,
    SUBSCRIPTION_PATH,
    bare_500_error,
    delete_confirmed,
    emf_body,
    emf_rejection,
    error_matches,
    is_rc_error,
    kafka_entries,
    rc_error,
    rejection,
    streams_from,
    subscription_items,
    subscription_line,
    subscription_markdown,
    subscription_with_id,
    validate_client_url,
)
from tests.conftest import BASE_URL, call_tool_text

STREAMS_URL = f"{BASE_URL}{STREAMS_PATH}"
SUBSCRIPTION_URL = f"{BASE_URL}{SUBSCRIPTION_PATH}"
ADMIN_URL = f"{BASE_URL}{SUBSCRIPTION_ADMIN_PATH}"
KAFKA_URL = f"{BASE_URL}{KAFKA_SUBSCRIPTION_PATH}"

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

# Documented (NOT verified live) non-empty Kafka/gRPC answer.
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
WRITE_TOOLS = {"cnc_create_webhook_subscription", "cnc_delete_notification_subscription"}


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


def test_base_path_is_the_verified_one():
    assert NOTIFICATIONS == "/crosswork/notification/restconf/data/v2"
    assert STREAMS_PATH.endswith("/ietf-restconf-monitoring:restconf-state/streams")
    assert SUBSCRIPTION_PATH.endswith("/notifications:subscription")
    assert SUBSCRIPTION_ADMIN_PATH.endswith("/notifications:subscription-admin")
    assert KAFKA_SUBSCRIPTION_PATH == "/crosswork/notification/v2/subscription"


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
    assert "not been verified live" in text
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
    assert text.startswith("# Kafka/gRPC subscriptions (shape not the documented one")
    assert "not been verified live" in text
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
