"""Routing detection: classify() signatures, probe_path(), and the Availability cache.

Fixture bodies marked "verified" reproduce a response shape observed live on the
Crosswork 7.2 eval build (platform notes, "Routing detection, refined"); the
ones marked "extrapolated" pin the module's documented defensive readings of
cases that have not been seen live.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
import respx

from cnc_mcp.auth import CrossworkCasAuth, StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.errors import PlatformError
from cnc_mcp.probe import (
    PER_PATH_PREFIXES,
    Availability,
    Routing,
    classify,
    explain,
    home_app_fallback_path,
    prefix_of,
    probe_path,
)
from tests.conftest import BASE_URL

# --- verified bodies ---------------------------------------------------------------
YAML_UNROUTED = (
    "--- !<java.util.LinkedHashMap>\n"
    'timestamp: "2026-09-12T10:00:00.000+00:00"\n'
    "status: 404\n"
    'error: "Not Found"\n'
    'path: "/crosswork/sso/login/crosswork/aa/v1/dashboard/serviceCount"\n'
)
JSON_UNROUTED = {
    "timestamp": "2026-09-12T10:00:00.000+00:00",
    "status": 404,
    "error": "Not Found",
    "path": "/crosswork/sso/login/crosswork/hi/v1/kpis",
}
GO_404 = "404 page not found\n"
SPRING_404_STATIC = {
    "timestamp": "2026-09-12T10:00:00.000+00:00",
    "status": 404,
    "error": "Not Found",
    "message": "No static resource crosswork/swim/v1/images.",
    "path": "/crosswork/swim/v1/images",
}
SPRING_404_EXCEPTION = {
    "status": 404,
    "exception": "org.springframework.web.servlet.resource.NoResourceFoundException",
}
SPRING_500_STATIC = {"code": 500, "errorMessage": "No static resource crosswork/config/v1/x."}
UNAUTHORIZED = {"error": "Unauthorized request"}
MISSING_AUTH_HEADER = {"error": "Missing Authorization header"}
MIDDLEWARE_ERROR = {"error": "Middleware error"}
NATS = {"error": "NATS request failed"}
UNMARSHAL = {"error": 'unable to unmarshal payload to proto, err: unknown field "x" in dg.Query'}
RESTCONF_409 = {
    "errors": {"error": [{"error-tag": "data-missing", "error-message": "node nope not found"}]}
}
NSO_415 = {
    "ietf-restconf:errors": {
        "error": [
            {
                "error-tag": "malformed-message",
                "error-message": "Unsupported media type: application/json",
            }
        ]
    }
}
ALARM_200_ERROR = {"error": "Fail", "code": 0, "message": "Input Request is invalid"}
EMF_EMPTY_ENVELOPE = {
    "com.response-message": {
        "com.header": {"com.firstIndex": 0, "com.lastIndex": -1, "com.iteratorId": 0}
    }
}
# --- extrapolated bodies (documented as such in probe.py) --------------------------
SPRING_404_PATH_ONLY = {"status": 404, "error": "Not Found", "path": "/crosswork/grouping/v1/x"}
SPRING_404_NO_MESSAGE_PLACEHOLDER = {
    "status": 404,
    "error": "Not Found",
    "message": "No message available",
    "path": "/crosswork/grouping/v1/x",
}
SPRING_404_APP_LEVEL = {
    "status": 404,
    "error": "Not Found",
    "message": "Subscription 42 not found",
    "path": "/crosswork/notification/v2/subscriptions/42",
}


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        # UNROUTED: the home app's fallback, YAML or Spring-JSON form (verified).
        (404, YAML_UNROUTED, Routing.UNROUTED),
        (404, json.dumps(JSON_UNROUTED), Routing.UNROUTED),
        # ROUTED_NO_PATH: a real service answered "no such path" (verified).
        (404, GO_404, Routing.ROUTED_NO_PATH),
        (404, json.dumps(SPRING_404_STATIC), Routing.ROUTED_NO_PATH),
        (404, json.dumps(SPRING_404_EXCEPTION), Routing.ROUTED_NO_PATH),
        (500, json.dumps(SPRING_500_STATIC), Routing.ROUTED_NO_PATH),
        # ROUTED_NO_RBAC: Tyk has no RBAC entry (token already refreshed by the client).
        (403, json.dumps(UNAUTHORIZED), Routing.ROUTED_NO_RBAC),
        # ROUTED_BAD_BODY: the path exists, the body was rejected (verified).
        (500, json.dumps(NATS), Routing.ROUTED_BAD_BODY),
        (400, json.dumps(UNMARSHAL), Routing.ROUTED_BAD_BODY),
        # INCONCLUSIVE: an empty-bodied 500 proves nothing (verified: list-opm-package
        # and the wrong base nbi/optima/v2 both answer this) ...
        (500, "", Routing.INCONCLUSIVE),
        (500, "  \n", Routing.INCONCLUSIVE),
        # ... and auth-layer answers that survived the one re-login (extrapolated).
        (403, json.dumps(MISSING_AUTH_HEADER), Routing.INCONCLUSIVE),
        (500, json.dumps(MIDDLEWARE_ERROR), Routing.INCONCLUSIVE),
        (
            401,
            json.dumps({"authentication_exceptions": ["Invalid credentials"]}),
            Routing.INCONCLUSIVE,
        ),
        # AVAILABLE: 2xx, and application errors clearly from the target service (verified).
        (200, json.dumps({"data": []}), Routing.AVAILABLE),
        (200, "", Routing.AVAILABLE),
        (200, json.dumps(EMF_EMPTY_ENVELOPE), Routing.AVAILABLE),
        (409, json.dumps(RESTCONF_409), Routing.AVAILABLE),
        (415, json.dumps(NSO_415), Routing.AVAILABLE),
        (200, json.dumps(ALARM_200_ERROR), Routing.AVAILABLE),
        (
            400,
            json.dumps({"errors": {"error": [{"error-tag": "unknown-element"}]}}),
            Routing.AVAILABLE,
        ),
        (404, json.dumps({"error": "not found"}), Routing.AVAILABLE),  # app-level 404, no path
    ],
)
def test_classify_every_verified_signature(status, body, expected):
    assert classify(status, body) is expected


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        # Spring's default document for an unmapped path carries no message ...
        (SPRING_404_PATH_ONLY, Routing.ROUTED_NO_PATH),
        ({**SPRING_404_PATH_ONLY, "message": ""}, Routing.ROUTED_NO_PATH),
        ({**SPRING_404_PATH_ONLY, "message": None}, Routing.ROUTED_NO_PATH),
        (SPRING_404_NO_MESSAGE_PLACEHOLDER, Routing.ROUTED_NO_PATH),
        # ... whereas a served endpoint raising an app-level 404 (bad ID) puts its own
        # text there, and must NOT poison the whole prefix as ROUTED_NO_PATH.
        (SPRING_404_APP_LEVEL, Routing.AVAILABLE),
    ],
)
def test_classify_spring_404_with_path_elsewhere_is_extrapolated_from_message(body, expected):
    assert classify(404, json.dumps(body)) is expected


@pytest.mark.parametrize(
    ("status", "body"),
    [
        # A marker string inside a successful body is data, not a signature.
        (200, json.dumps({"data": [{"note": "NATS request failed"}]})),
        (200, json.dumps({"alarms": [{"Description": "Unauthorized request"}]})),
        (200, json.dumps({"log": "No static resource / 404 page not found"})),
        (200, YAML_UNROUTED),
        (201, json.dumps(MIDDLEWARE_ERROR)),
        # Markers only count with their verified status code.
        (400, json.dumps(NATS)),
        (404, json.dumps(UNAUTHORIZED)),
        (500, json.dumps(UNMARSHAL)),
    ],
)
def test_classify_markers_only_count_with_their_status(status, body):
    assert classify(status, body) is Routing.AVAILABLE


def test_classify_yaml_path_may_be_unquoted_and_is_case_insensitive_on_markers():
    unquoted = (
        "--- !<java.util.LinkedHashMap>\nstatus: 404\n"
        "path: /crosswork/sso/login/crosswork/nca/v1/x\n"
    )
    assert classify(404, unquoted) is Routing.UNROUTED
    # YAML fallback body that is NOT the sso/login redirect: some service answered
    # (extrapolated — the YAML form has only ever been seen from the home app).
    other = "--- !<java.util.LinkedHashMap>\nstatus: 404\npath: /crosswork/other/v1/x\n"
    assert classify(404, other) is Routing.ROUTED_NO_PATH
    assert classify(403, '{"ERROR":"UNAUTHORIZED REQUEST"}') is Routing.ROUTED_NO_RBAC
    assert classify(500, "NATS Request Failed") is Routing.ROUTED_BAD_BODY
    assert classify(403, "MISSING AUTHORIZATION HEADER") is Routing.INCONCLUSIVE


def test_classify_is_lenient_about_garbage_bodies():
    assert classify(404, "<html>Not Found</html>") is Routing.AVAILABLE
    assert classify(404, "[1, 2, 3]") is Routing.AVAILABLE
    assert classify(404, "--- just some yaml\npath: /crosswork/sso/login/x\n") is Routing.AVAILABLE
    assert classify(403, "") is Routing.AVAILABLE  # a 403 without the Tyk body is app-level
    assert classify(503, None) is Routing.AVAILABLE  # type: ignore[arg-type]


def test_home_app_fallback_path_is_the_single_shared_signature():
    login = "/crosswork/sso/login/crosswork/hi/v1/kpis"
    assert home_app_fallback_path(JSON_UNROUTED, json.dumps(JSON_UNROUTED)) == login
    assert home_app_fallback_path(None, YAML_UNROUTED) == (
        "/crosswork/sso/login/crosswork/aa/v1/dashboard/serviceCount"
    )
    # A Spring 404 from a real service carries the requested path: not a fallback.
    assert home_app_fallback_path(SPRING_404_STATIC, json.dumps(SPRING_404_STATIC)) is None
    assert home_app_fallback_path(None, "--- !<java.util.LinkedHashMap>\nstatus: 404\n") is None
    # A bare ``---`` is any YAML document, not the home app's marker.
    assert home_app_fallback_path(None, f"---\npath: {login}\n") is None
    assert home_app_fallback_path([1, 2], "[1, 2]") is None
    assert home_app_fallback_path({"path": 42}, '{"path": 42}') is None


def test_explain_gives_a_distinct_actionable_sentence_per_routing():
    path = "/crosswork/aa/v1/dashboard/serviceCount"
    texts = {r: explain(r, path) for r in Routing}
    assert len(set(texts.values())) == len(Routing)
    assert all(path in t for t in texts.values())
    assert "not installed or not licensed" in texts[Routing.UNROUTED]
    assert "Service Health, Change Automation and Health Insights" in texts[Routing.UNROUTED]
    assert "alarms, sso, notification" in texts[Routing.UNROUTED]
    assert "API version/base path" in texts[Routing.ROUTED_NO_PATH]
    assert "no RBAC entry" in texts[Routing.ROUTED_NO_RBAC]
    assert "fix the payload" in texts[Routing.ROUTED_BAD_BODY]
    assert "inconclusive" in texts[Routing.INCONCLUSIVE]
    assert texts[Routing.AVAILABLE].endswith("is available on this Crosswork instance.")


def test_served_and_conclusive_properties():
    assert Routing.AVAILABLE.served and Routing.ROUTED_BAD_BODY.served
    assert Routing.INCONCLUSIVE.served  # benefit of the doubt: the real call decides
    assert not (Routing.UNROUTED.served or Routing.ROUTED_NO_PATH.served)
    assert not Routing.ROUTED_NO_RBAC.served
    assert not Routing.INCONCLUSIVE.conclusive
    assert all(r.conclusive for r in Routing if r is not Routing.INCONCLUSIVE)


def test_prefix_of_is_the_service_prefix_except_for_per_path_services():
    assert prefix_of("/crosswork/aa/v1/dashboard/serviceCount") == "/crosswork/aa"
    assert prefix_of("/crosswork/nbi/topology/v3/restconf/data") == "/crosswork/nbi"
    assert prefix_of("/crosswork/inventory") == "/crosswork/inventory"
    assert prefix_of("/crosswork/inventory/v1/nodes/query?x=1") == "/crosswork/inventory"
    assert prefix_of("/hello") == "/hello"
    # Verified per-path services key by full path (query string / fragment dropped).
    assert PER_PATH_PREFIXES == {"alarms", "sso", "notification"}
    assert prefix_of("/crosswork/alarms/v1/query") == "/crosswork/alarms/v1/query"
    assert prefix_of("/crosswork/alarms/v1/query?limit=1#x") == "/crosswork/alarms/v1/query"
    assert prefix_of("/crosswork/alarms/v1/x") != prefix_of("/crosswork/alarms/v1/query")
    assert prefix_of("/crosswork/sso/v1/tickets") == "/crosswork/sso/v1/tickets"


def test_prefix_of_keeps_the_two_notification_bases_apart():
    """Verified: notification/v2/... answers a Spring 404 (routed) while
    notification/restconf/data/v2 falls through to the home app (unrouted); one
    prefix-wide verdict would be wrong for whichever base is probed second."""
    routed = prefix_of("/crosswork/notification/v2/subscriptions")
    unrouted = prefix_of("/crosswork/notification/restconf/data/v2/subscriptions")
    assert routed != unrouted
    assert routed == "/crosswork/notification/v2/subscriptions"
    assert unrouted == "/crosswork/notification/restconf/data/v2/subscriptions"


def make_client(settings) -> ApiClient:
    return ApiClient(settings, StaticTokenAuth("test-token"))


def mock_cas_login(fresh_tokens: list[str]) -> respx.Route:
    """Mock both CAS legs; leg 2 hands out ``fresh_tokens`` in order. Returns the leg-2 route."""
    tickets = f"{BASE_URL}/crosswork/sso/v1/tickets"
    respx.post(tickets).mock(return_value=httpx.Response(201, text="TGT-1-x"))
    return respx.post(f"{tickets}/TGT-1-x").mock(
        side_effect=[httpx.Response(200, text=t) for t in fresh_tokens]
    )


@respx.mock
async def test_probe_path_classifies_unrouted_without_raising(settings):
    respx.get(f"{BASE_URL}/crosswork/aa/v1/dashboard/serviceCount").mock(
        return_value=httpx.Response(404, text=YAML_UNROUTED)
    )
    client = make_client(settings)
    try:
        routing = await probe_path(client, "/crosswork/aa/v1/dashboard/serviceCount")
        assert routing is Routing.UNROUTED
    finally:
        await client.aclose()


@respx.mock
async def test_probe_path_posts_the_body_and_reads_bad_body_as_served(settings):
    route = respx.post(f"{BASE_URL}/crosswork/dg-manager/v1/hapool/query").mock(
        return_value=httpx.Response(400, json=UNMARSHAL)
    )
    client = make_client(settings)
    try:
        routing = await probe_path(
            client,
            "/crosswork/dg-manager/v1/hapool/query",
            method="POST",
            json_body={"filterData": {"bogus": 1}},
        )
        assert routing is Routing.ROUTED_BAD_BODY and routing.served
        assert json.loads(route.calls.last.request.content) == {"filterData": {"bogus": 1}}
        assert route.calls.last.request.headers["Authorization"] == "Bearer test-token"
    finally:
        await client.aclose()


@respx.mock
@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (403, UNAUTHORIZED, Routing.ROUTED_NO_RBAC),
        (500, NATS, Routing.ROUTED_BAD_BODY),
        (500, SPRING_500_STATIC, Routing.ROUTED_NO_PATH),
        (409, RESTCONF_409, Routing.AVAILABLE),
        (415, NSO_415, Routing.AVAILABLE),
        (200, ALARM_200_ERROR, Routing.AVAILABLE),
    ],
)
async def test_probe_path_never_raises_on_http_errors(settings, status, body, expected):
    respx.get(f"{BASE_URL}/crosswork/x/v1/y").mock(return_value=httpx.Response(status, json=body))
    client = make_client(settings)
    try:
        assert await probe_path(client, "/crosswork/x/v1/y") is expected
    finally:
        await client.aclose()


@respx.mock
async def test_probe_path_with_cas_auth_reads_403_as_no_rbac_only_after_one_relogin(
    make_settings,
):
    """The docstring's central premise: Crosswork answers 403 'Unauthorized request' for
    a bad token AND for an unknown path. With CrossworkCasAuth the client re-logs in
    once and retries; only a 403 that survives the fresh token reaches classify()."""
    settings = make_settings(api_token="", username="mcp-admin", password="secret")
    leg2 = mock_cas_login(["a.stale.jwt", "a.fresh.jwt"])
    api = respx.get(f"{BASE_URL}/crosswork/inventory/v1/made-up").mock(
        return_value=httpx.Response(403, json=UNAUTHORIZED)
    )
    client = ApiClient(settings, CrossworkCasAuth("mcp-admin", "secret"))
    try:
        assert await probe_path(client, "/crosswork/inventory/v1/made-up") is Routing.ROUTED_NO_RBAC
        assert leg2.call_count == 2  # initial login + exactly one re-authentication
        assert api.call_count == 2
        assert api.calls[0].request.headers["Authorization"] == "Bearer a.stale.jwt"
        assert api.calls[1].request.headers["Authorization"] == "Bearer a.fresh.jwt"
    finally:
        await client.aclose()


@respx.mock
async def test_availability_require_blocks_no_rbac_with_the_fresh_token_explanation(
    make_settings,
):
    settings = make_settings(api_token="", username="mcp-admin", password="secret")
    leg2 = mock_cas_login(["a.stale.jwt", "a.fresh.jwt"])
    api = respx.get(f"{BASE_URL}/crosswork/inventory/v1/made-up").mock(
        return_value=httpx.Response(403, json=UNAUTHORIZED)
    )
    avail = Availability()
    client = ApiClient(settings, CrossworkCasAuth("mcp-admin", "secret"))
    try:
        with pytest.raises(PlatformError, match="no RBAC entry for this path"):
            await avail.require(client, "/crosswork/inventory/v1/made-up")
        assert leg2.call_count == 2 and api.call_count == 2
        assert avail.get("/crosswork/inventory") is Routing.ROUTED_NO_RBAC
        # Cached: a second require() re-raises without touching the network.
        with pytest.raises(PlatformError, match="no RBAC entry"):
            await avail.require(client, "/crosswork/inventory/v1/nodes/query", method="POST")
        assert api.call_count == 2
    finally:
        await client.aclose()


@respx.mock
async def test_probe_path_propagates_transport_failure_as_platform_error(make_settings):
    respx.get(f"{BASE_URL}/crosswork/x/v1/y").mock(side_effect=httpx.ConnectError("boom"))
    client = make_client(make_settings(max_retries=0))
    try:
        with pytest.raises(PlatformError, match="Could not reach the platform"):
            await probe_path(client, "/crosswork/x/v1/y")
    finally:
        await client.aclose()


@respx.mock
async def test_availability_probes_once_per_prefix_and_remembers(settings):
    route = respx.get(f"{BASE_URL}/crosswork/aa/v1/dashboard/serviceCount").mock(
        return_value=httpx.Response(404, text=YAML_UNROUTED)
    )
    avail = Availability()
    client = make_client(settings)
    try:
        assert avail.get("/crosswork/aa") is None
        first = await avail.ensure(client, "/crosswork/aa/v1/dashboard/serviceCount")
        second = await avail.ensure(client, "/crosswork/aa/v1/other")  # same prefix: cached
        assert first is second is Routing.UNROUTED
        assert route.call_count == 1
        assert avail.get("/crosswork/aa") is Routing.UNROUTED
        assert avail.get("/crosswork/aa/v1/anything") is Routing.UNROUTED

        avail.forget("/crosswork/aa")
        assert avail.get("/crosswork/aa") is None
        await avail.ensure(client, "/crosswork/aa/v1/dashboard/serviceCount")
        assert route.call_count == 2
    finally:
        await client.aclose()


@respx.mock
async def test_availability_keys_per_path_services_by_full_path(settings):
    """alarms/v1/query works while alarms/v1/x is unrouted (verified): the verdict for
    one alarms path must not be served from the cache for another."""
    query = respx.post(f"{BASE_URL}/crosswork/alarms/v1/query").mock(
        return_value=httpx.Response(200, json={"state": "Success", "alarms": []})
    )
    bogus = respx.get(f"{BASE_URL}/crosswork/alarms/v1/x").mock(
        return_value=httpx.Response(404, text=YAML_UNROUTED)
    )
    avail = Availability()
    client = make_client(settings)
    try:
        ok = await avail.ensure(client, "/crosswork/alarms/v1/query", method="POST", json_body={})
        bad = await avail.ensure(client, "/crosswork/alarms/v1/x")
        assert ok is Routing.AVAILABLE and bad is Routing.UNROUTED
        assert query.call_count == 1 and bogus.call_count == 1
        assert avail.get("/crosswork/alarms/v1/query") is Routing.AVAILABLE
        assert avail.get("/crosswork/alarms/v1/query?limit=1") is Routing.AVAILABLE
        assert avail.get("/crosswork/alarms/v1/x") is Routing.UNROUTED
        assert avail.get("/crosswork/alarms") is None
        assert len(avail.describe().splitlines()) == 2
    finally:
        await client.aclose()


@respx.mock
async def test_availability_explicit_crosswork_prefix_round_trips_through_get_and_forget(
    settings,
):
    """An explicit key under /crosswork/ (the shape the docstring recommends for per-path
    services) must be honoured verbatim by get()/forget(), not reduced to its service
    prefix — otherwise forget() is a no-op and a re-ensure() is served from cache."""
    route = respx.post(f"{BASE_URL}/crosswork/alarms/v1/query").mock(
        return_value=httpx.Response(200, json={"state": "Success", "alarms": []})
    )
    avail = Availability()
    client = make_client(settings)
    key = "/crosswork/alarms/v1/query"
    try:
        routing = await avail.ensure(
            client, "/crosswork/alarms/v1/query", prefix=key, method="POST", json_body={}
        )
        assert routing is Routing.AVAILABLE
        assert avail.get(key) is Routing.AVAILABLE
        assert avail.describe().startswith(f"- {key}: available (probed {key})")

        avail.forget(key)
        assert avail.get(key) is None
        assert avail.describe().startswith("No Crosswork service prefixes")
        await avail.ensure(client, "/crosswork/alarms/v1/query", prefix=key, method="POST")
        assert route.call_count == 2

        # A deeper explicit key is not reduced either, and "" is a real (if odd) key.
        deep = "/crosswork/inventory/restconf/data/v2"
        await avail.ensure(client, "/crosswork/alarms/v1/query", prefix=deep, method="POST")
        assert avail.get(deep) is Routing.AVAILABLE
        assert avail.get("/crosswork/inventory") is None
        await avail.ensure(client, "/crosswork/alarms/v1/query", prefix="", method="POST")
        assert route.call_count == 4
        assert avail.get("") is Routing.AVAILABLE
        avail.forget("")
        assert avail.get("") is None
    finally:
        await client.aclose()


@respx.mock
async def test_availability_explicit_prefix_and_concurrent_ensure_share_one_probe(settings):
    route = respx.post(f"{BASE_URL}/crosswork/alarms/v1/query").mock(
        return_value=httpx.Response(200, json={"state": "Success", "alarms": []})
    )
    avail = Availability()
    client = make_client(settings)
    try:
        results = await asyncio.gather(
            *(
                avail.ensure(
                    client,
                    "/crosswork/alarms/v1/query",
                    prefix="alarms-query",
                    method="POST",
                    json_body={"openAlarmsOnly": True, "criteria": "select * from alarm limit 1"},
                )
                for _ in range(3)
            )
        )
        assert results == [Routing.AVAILABLE] * 3
        assert route.call_count == 1
        assert avail.get("alarms-query") is Routing.AVAILABLE
    finally:
        await client.aclose()


@respx.mock
async def test_availability_does_not_cache_inconclusive_probes_but_lets_them_through(
    settings,
):
    """An empty-bodied 500 proves nothing about the path (verified: the right and the
    wrong COE base both answer it), so it is neither remembered nor a reason to block."""
    route = respx.post(
        f"{BASE_URL}/crosswork/nbi/optimization/v3/restconf/operations/list-opm-package"
    ).mock(return_value=httpx.Response(500, text=""))
    avail = Availability()
    client = make_client(settings)
    path = "/crosswork/nbi/optimization/v3/restconf/operations/list-opm-package"
    try:
        routing = await avail.require(client, path, method="POST", json_body={"input": {}})
        assert routing is Routing.INCONCLUSIVE and routing.served
        assert avail.get("/crosswork/nbi") is None
        assert avail.describe().startswith("No Crosswork service prefixes")
        await avail.ensure(client, path, method="POST", json_body={"input": {}})
        assert route.call_count == 2  # probed again: nothing was remembered
    finally:
        await client.aclose()


@respx.mock
async def test_availability_require_raises_with_explanation_when_not_served(settings):
    respx.get(f"{BASE_URL}/crosswork/hi/v1/kpis").mock(
        return_value=httpx.Response(404, json=JSON_UNROUTED)
    )
    respx.get(f"{BASE_URL}/crosswork/swim/v1/images").mock(
        return_value=httpx.Response(404, json=SPRING_404_STATIC)
    )
    respx.post(f"{BASE_URL}/crosswork/dg-manager/v1/hapool/query").mock(
        return_value=httpx.Response(400, json=UNMARSHAL)
    )
    avail = Availability()
    client = make_client(settings)
    try:
        with pytest.raises(PlatformError, match="not installed or not licensed"):
            await avail.require(client, "/crosswork/hi/v1/kpis")
        with pytest.raises(PlatformError, match="check the API version/base path"):
            await avail.require(client, "/crosswork/swim/v1/images")
        # A rejected body still proves the path is served: require() passes.
        routing = await avail.require(
            client, "/crosswork/dg-manager/v1/hapool/query", method="POST", json_body={"x": 1}
        )
        assert routing is Routing.ROUTED_BAD_BODY
    finally:
        await client.aclose()


@respx.mock
async def test_availability_describe_lists_cached_results(settings):
    respx.get(f"{BASE_URL}/crosswork/hi/v1/kpis").mock(
        return_value=httpx.Response(404, json=JSON_UNROUTED)
    )
    respx.get(f"{BASE_URL}/crosswork/inventory/v1/nodes/count").mock(
        return_value=httpx.Response(200, json={"count": 5})
    )
    avail = Availability()
    assert avail.describe() == "No Crosswork service prefixes have been probed yet."
    client = make_client(settings)
    try:
        await avail.ensure(client, "/crosswork/hi/v1/kpis")
        await avail.ensure(client, "/crosswork/inventory/v1/nodes/count")
    finally:
        await client.aclose()
    text = avail.describe()
    lines = text.splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("- /crosswork/hi: unrouted (probed /crosswork/hi/v1/kpis)")
    assert "not installed or not licensed" in lines[0]
    assert lines[1].startswith(
        "- /crosswork/inventory: available (probed /crosswork/inventory/v1/nodes/count)"
    )
    avail.forget()
    assert avail.describe().startswith("No Crosswork service prefixes")
