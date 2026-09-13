"""ApiClient behavior: retries, 401 re-auth, error mapping."""

from __future__ import annotations

import httpx
import pytest
import respx

from cnc_mcp.auth import LoginTokenAuth, StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.errors import PlatformError
from tests.conftest import BASE_URL


def make_client(settings, auth=None) -> ApiClient:
    return ApiClient(settings, auth or StaticTokenAuth("test-token"))


@respx.mock
async def test_retries_5xx_then_succeeds(settings):
    route = respx.get(f"{BASE_URL}/v1/thing").mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    client = make_client(settings)
    try:
        assert await client.request_json("GET", "/v1/thing") == {"ok": True}
        assert route.call_count == 2
    finally:
        await client.aclose()


@respx.mock
async def test_retries_429_honoring_retry_after(settings):
    route = respx.get(f"{BASE_URL}/v1/thing").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "0"}),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    client = make_client(settings)
    try:
        assert await client.request_json("GET", "/v1/thing") == {"ok": True}
        assert route.call_count == 2
    finally:
        await client.aclose()


@respx.mock
async def test_retries_exhausted_returns_last_error(make_settings):
    settings = make_settings(max_retries=1)
    respx.get(f"{BASE_URL}/v1/thing").mock(return_value=httpx.Response(503))
    client = make_client(settings)
    try:
        with pytest.raises(PlatformError, match="status 503"):
            await client.request_json("GET", "/v1/thing")
    finally:
        await client.aclose()


@respx.mock
async def test_transport_error_retried_then_fails_actionably(make_settings):
    settings = make_settings(max_retries=1)
    respx.get(f"{BASE_URL}/v1/thing").mock(side_effect=httpx.ConnectError("boom"))
    client = make_client(settings)
    try:
        with pytest.raises(PlatformError, match="Could not reach the platform"):
            await client.request_json("GET", "/v1/thing")
    finally:
        await client.aclose()


@respx.mock
async def test_404_maps_to_actionable_message(settings):
    respx.get(f"{BASE_URL}/v1/thing").mock(
        return_value=httpx.Response(404, json={"message": "no such thing"})
    )
    client = make_client(settings)
    try:
        with pytest.raises(PlatformError) as excinfo:
            await client.request_json("GET", "/v1/thing")
        message = str(excinfo.value)
        assert "404" in message and "no such thing" in message
    finally:
        await client.aclose()


@respx.mock
async def test_401_triggers_reauth_and_retry(make_settings):
    settings = make_settings(api_token="", username="admin", password="secret")
    respx.post(f"{BASE_URL}/auth/login").mock(
        side_effect=[
            httpx.Response(200, json={"token": "stale"}),
            httpx.Response(200, json={"token": "fresh"}),
        ]
    )
    api_route = respx.get(f"{BASE_URL}/v1/thing").mock(
        side_effect=[
            httpx.Response(401),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    auth = LoginTokenAuth(
        "/auth/login", "admin", "secret", login_style="json", token_location="json"
    )
    client = ApiClient(settings, auth)
    try:
        assert await client.request_json("GET", "/v1/thing") == {"ok": True}
        assert api_route.call_count == 2
        assert api_route.calls[1].request.headers["Authorization"] == "Bearer fresh"
    finally:
        await client.aclose()


@respx.mock
async def test_post_not_retried_on_5xx(make_settings):
    """A POST may already have been applied when a 5xx/timeout arrives — never re-send."""
    route = respx.post(f"{BASE_URL}/v1/thing").mock(
        side_effect=[httpx.Response(503), httpx.Response(201, json={"id": 1})]
    )
    client = make_client(make_settings())
    try:
        with pytest.raises(PlatformError, match="status 503"):
            await client.request_json("POST", "/v1/thing", json_body={})
        assert route.call_count == 1
    finally:
        await client.aclose()


@respx.mock
async def test_post_retried_on_429(settings):
    """429 means the platform rejected the request before processing: safe for POST."""
    route = respx.post(f"{BASE_URL}/v1/thing").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "0"}),
            httpx.Response(201, json={"id": 1}),
        ]
    )
    client = make_client(settings)
    try:
        assert await client.request_json("POST", "/v1/thing", json_body={}) == {"id": 1}
        assert route.call_count == 2
    finally:
        await client.aclose()


@respx.mock
async def test_post_opt_in_retry(settings):
    route = respx.post(f"{BASE_URL}/v1/thing").mock(
        side_effect=[httpx.Response(503), httpx.Response(201, json={"id": 1})]
    )
    client = make_client(settings)
    try:
        result = await client.request_json("POST", "/v1/thing", json_body={}, retryable=True)
        assert result == {"id": 1}
        assert route.call_count == 2
    finally:
        await client.aclose()


async def test_backoff_caps_server_supplied_retry_after(make_settings, monkeypatch):
    """A huge Retry-After must not stall the client: 30s cap applies before jitter."""
    settings = make_settings(retry_backoff_seconds=1.0)
    client = make_client(settings)
    slept: list[float] = []

    async def fake_sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr("cnc_mcp.client.asyncio.sleep", fake_sleep)
    try:
        await client._backoff(0, retry_after="3600")
        await client._backoff(9)  # deep exponential attempt
    finally:
        await client.aclose()
    assert all(delay <= 30.0 * 1.25 for delay in slept), slept


@respx.mock
async def test_non_json_response_raises_toolerror(settings):
    respx.get(f"{BASE_URL}/v1/thing").mock(
        return_value=httpx.Response(200, text="<html>login page</html>")
    )
    client = make_client(settings)
    try:
        with pytest.raises(PlatformError, match="non-JSON"):
            await client.request_json("GET", "/v1/thing")
    finally:
        await client.aclose()


@respx.mock
async def test_crosswork_403_unauthorized_request_triggers_reauth(make_settings):
    """Crosswork never answers 401: an expired JWT surfaces as 403 'Unauthorized request'.
    The client must let the strategy classify it and re-authenticate once."""
    from cnc_mcp.auth import CrossworkCasAuth

    settings = make_settings(api_token="", username="mcp-admin", password="secret")
    tickets = f"{BASE_URL}/crosswork/sso/v1/tickets"
    respx.post(tickets).mock(return_value=httpx.Response(201, text="TGT-1-x"))
    leg2 = respx.post(f"{tickets}/TGT-1-x").mock(
        side_effect=[
            httpx.Response(200, text="a.stale.jwt"),
            httpx.Response(200, text="a.fresh.jwt"),
        ]
    )
    api = respx.post(f"{BASE_URL}/crosswork/inventory/v1/nodes/query").mock(
        side_effect=[
            httpx.Response(403, json={"error": "Unauthorized request"}),
            httpx.Response(200, json={"data": []}),
        ]
    )
    client = ApiClient(settings, CrossworkCasAuth("mcp-admin", "secret"))
    try:
        result = await client.request_json(
            "POST", "/crosswork/inventory/v1/nodes/query", json_body={}
        )
        assert result == {"data": []}
        assert api.call_count == 2
        assert leg2.call_count == 2
        assert api.calls[1].request.headers["Authorization"] == "Bearer a.fresh.jwt"
    finally:
        await client.aclose()


@respx.mock
async def test_crosswork_genuine_403_does_not_reauth(make_settings):
    from cnc_mcp.auth import CrossworkCasAuth

    settings = make_settings(api_token="", username="mcp-admin", password="secret")
    tickets = f"{BASE_URL}/crosswork/sso/v1/tickets"
    respx.post(tickets).mock(return_value=httpx.Response(201, text="TGT-1-x"))
    leg2 = respx.post(f"{tickets}/TGT-1-x").mock(return_value=httpx.Response(200, text="a.b.c"))
    respx.get(f"{BASE_URL}/crosswork/aaa/v1/user").mock(
        return_value=httpx.Response(403, json={"error": "User lacks role for this operation"})
    )
    client = ApiClient(settings, CrossworkCasAuth("mcp-admin", "secret"))
    try:
        with pytest.raises(PlatformError, match="Permission denied"):
            await client.request_json("GET", "/crosswork/aaa/v1/user")
        assert leg2.call_count == 1  # logged in once; no re-auth storm on real RBAC denials
    finally:
        await client.aclose()


@pytest.mark.parametrize(
    ("status", "body", "fragment"),
    [
        (403, {"error": "Unauthorized request"}, "rejected bearer"),
        (403, {"error": "Missing Authorization header"}, "no bearer token"),
        (500, {"error": "Middleware error"}, "gateway rejected the bearer token"),
        (500, {"error": "NATS request failed"}, "malformed request body"),
        (500, {"error": "something else"}, "server error"),
        (403, {"error": "no such role"}, "Permission denied"),
    ],
)
def test_crosswork_error_hints(status, body, fragment):
    from cnc_mcp.errors import http_error

    msg = str(http_error(httpx.Response(status, json=body)))
    assert fragment in msg
    assert body["error"] in msg  # the platform's own words are preserved


# --- module 0: raw bodies, Content-Type override, ok_statuses ------------------------------


# The only documented raw-body consumer: Inventory Job Scheduler (job_scheduler_ap_is_7_2_0.json),
# whose runJob/suspendJob/resumeJob take an unquoted string under application/json. UNVERIFIED
# live — the ``rs`` prefix is unrouted on the lab instance.
JOB_SCHEDULER = "/crosswork/rs/json/jobSchedulerServiceInv/v1"


@respx.mock
async def test_raw_content_body_on_the_wire_defaults_to_documented_media_type(settings):
    """A content= body goes out verbatim (no JSON quoting) as application/json, the media
    type the Job Scheduler document declares; httpx sets no Content-Type for it itself."""
    from cnc_mcp.client import DEFAULT_RAW_CONTENT_TYPE

    route = respx.post(f"{BASE_URL}{JOB_SCHEDULER}/runJob").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    client = make_client(settings)
    try:
        result = await client.request_json(
            "POST", f"{JOB_SCHEDULER}/runJob", content="Switch Inventory:Inventory"
        )
        assert result == {"ok": True}
        sent = route.calls[0].request
        assert sent.content == b"Switch Inventory:Inventory"  # unquoted, not JSON-encoded
        assert DEFAULT_RAW_CONTENT_TYPE == "application/json"
        assert sent.headers.get_list("Content-Type") == ["application/json"]
    finally:
        await client.aclose()


@respx.mock
async def test_raw_content_body_survives_reauth_intact(make_settings):
    """After the transparent re-auth the content= body and its Content-Type must be re-sent
    unchanged, with only the bearer token differing."""
    from cnc_mcp.auth import CrossworkCasAuth

    settings = make_settings(api_token="", username="mcp-admin", password="secret")
    tickets = f"{BASE_URL}/crosswork/sso/v1/tickets"
    respx.post(tickets).mock(return_value=httpx.Response(201, text="TGT-1-x"))
    leg2 = respx.post(f"{tickets}/TGT-1-x").mock(
        side_effect=[
            httpx.Response(200, text="a.stale.jwt"),
            httpx.Response(200, text="a.fresh.jwt"),
        ]
    )
    api = respx.post(f"{BASE_URL}{JOB_SCHEDULER}/suspendJob").mock(
        side_effect=[
            httpx.Response(403, json={"error": "Unauthorized request"}),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    client = ApiClient(settings, CrossworkCasAuth("mcp-admin", "secret"))
    try:
        result = await client.request_json(
            "POST",
            f"{JOB_SCHEDULER}/suspendJob",
            content="internalSchedule:Inventory",
            headers={"Content-Type": "text/plain"},
        )
        assert result == {"ok": True}
        assert api.call_count == 2 and leg2.call_count == 2
        first, second = (c.request for c in api.calls)
        assert first.content == second.content == b"internalSchedule:Inventory"
        assert first.headers.get_list("Content-Type") == ["text/plain"]
        assert second.headers.get_list("Content-Type") == ["text/plain"]
        assert first.headers["Authorization"] == "Bearer a.stale.jwt"
        assert second.headers["Authorization"] == "Bearer a.fresh.jwt"
    finally:
        await client.aclose()


@respx.mock
async def test_raw_content_body_keeps_caller_content_type(settings):
    route = respx.post(f"{BASE_URL}/v1/raw").mock(return_value=httpx.Response(204))
    client = make_client(settings)
    try:
        response = await client.request(
            "POST", "/v1/raw", content=b"<a/>", headers={"content-type": "application/xml"}
        )
        assert response.status_code == 204
        sent = route.calls[0].request
        assert sent.content == b"<a/>"
        assert sent.headers["Content-Type"] == "application/xml"
        assert "text/plain" not in sent.headers.get_list("Content-Type")
    finally:
        await client.aclose()


@respx.mock
async def test_json_body_content_type_overridden_per_call(settings):
    """RESTCONF RPC bodies must go out as application/yang-data+json, not httpx's default."""
    path = "/crosswork/nbi/optimization/v3/restconf/operations/coe:get-plan"
    route = respx.post(f"{BASE_URL}{path}").mock(
        return_value=httpx.Response(200, json={"coe:output": {"status": "ok"}})
    )
    client = make_client(settings)
    try:
        result = await client.request_json(
            "POST",
            path,
            json_body={"input": {"version": "current"}},
            headers={"Content-Type": "application/yang-data+json"},
        )
        assert result == {"coe:output": {"status": "ok"}}
        sent = route.calls[0].request
        assert sent.headers["Content-Type"] == "application/yang-data+json"
        assert sent.headers.get_list("Content-Type") == ["application/yang-data+json"]
        assert sent.content == b'{"input":{"version":"current"}}'
        assert sent.headers["Accept"] == "application/json"  # client default survives
    finally:
        await client.aclose()


@respx.mock
async def test_json_body_default_content_type_is_json(settings):
    route = respx.post(f"{BASE_URL}/v1/thing").mock(return_value=httpx.Response(200, json={}))
    client = make_client(settings)
    try:
        await client.request_json("POST", "/v1/thing", json_body={"a": 1})
        assert route.calls[0].request.headers["Content-Type"] == "application/json"
    finally:
        await client.aclose()


@respx.mock
async def test_content_and_json_body_are_mutually_exclusive(settings):
    route = respx.post(f"{BASE_URL}/v1/thing").mock(return_value=httpx.Response(200, json={}))
    client = make_client(settings)
    try:
        with pytest.raises(ValueError, match="either json_body or content"):
            await client.request("POST", "/v1/thing", json_body={}, content="x")
        assert route.call_count == 0  # rejected before anything was sent
    finally:
        await client.aclose()


@respx.mock
async def test_ok_statuses_returns_parsed_body_instead_of_raising(settings):
    """A keyed RESTCONF GET that finds nothing answers 409 data-missing (verified)."""
    path = (
        "/crosswork/nbi/topology/v3/restconf/data/ietf-network-state:networks/network=x/node=nope"
    )
    body = {"errors": {"error": [{"error-tag": "data-missing", "error-message": "no node"}]}}
    respx.get(f"{BASE_URL}{path}").mock(return_value=httpx.Response(409, json=body))
    client = make_client(settings)
    try:
        with pytest.raises(PlatformError, match="status 409"):
            await client.request_json("GET", path)
        assert await client.request_json("GET", path, ok_statuses={409}) == body
        response = await client.request("GET", path, ok_statuses={409})
        assert response.status_code == 409
    finally:
        await client.aclose()


@respx.mock
async def test_ok_statuses_accepts_206_range_response(settings):
    route = respx.get(f"{BASE_URL}/v1/paged").mock(
        return_value=httpx.Response(206, json=[{"id": 1}], headers={"Content-Range": "items 0-0/5"})
    )
    client = make_client(settings)
    try:
        result = await client.request_json(
            "GET", "/v1/paged", headers={"Range": "items=0-0"}, ok_statuses={206}
        )
        assert result == [{"id": 1}]
        assert route.calls[0].request.headers["Range"] == "items=0-0"
    finally:
        await client.aclose()


@respx.mock
async def test_ok_statuses_are_not_retried(settings):
    """An accepted status is the answer, even when it is normally a retry trigger."""
    route = respx.get(f"{BASE_URL}/v1/thing").mock(
        side_effect=[httpx.Response(503, json={"busy": True}), httpx.Response(200, json={})]
    )
    client = make_client(settings)
    try:
        assert await client.request_json("GET", "/v1/thing", ok_statuses={503}) == {"busy": True}
        assert route.call_count == 1
    finally:
        await client.aclose()


@respx.mock
async def test_ok_statuses_still_get_the_one_reauth_pass(make_settings):
    """An accepted status skips the backoff loop but NOT the transparent re-auth: a 403
    'Unauthorized request' is re-sent once with a fresh token (that retry is what tells a
    stale JWT from an unrouted path), and the second 403 is then returned, not raised."""
    from cnc_mcp.auth import CrossworkCasAuth

    settings = make_settings(api_token="", username="mcp-admin", password="secret")
    tickets = f"{BASE_URL}/crosswork/sso/v1/tickets"
    respx.post(tickets).mock(return_value=httpx.Response(201, text="TGT-1-x"))
    leg2 = respx.post(f"{tickets}/TGT-1-x").mock(
        side_effect=[
            httpx.Response(200, text="a.stale.jwt"),
            httpx.Response(200, text="a.fresh.jwt"),
        ]
    )
    api = respx.get(f"{BASE_URL}/crosswork/inventory/v1/no-such-path").mock(
        return_value=httpx.Response(403, json={"error": "Unauthorized request"})
    )
    client = ApiClient(settings, CrossworkCasAuth("mcp-admin", "secret"))
    try:
        response = await client.request(
            "GET", "/crosswork/inventory/v1/no-such-path", ok_statuses={403}
        )
        assert response.status_code == 403
        assert api.call_count == 2  # one re-auth retry, no backoff retries
        assert leg2.call_count == 2  # both SSO legs ran again
        assert api.calls[1].request.headers["Authorization"] == "Bearer a.fresh.jwt"
    finally:
        await client.aclose()


@respx.mock
async def test_ok_statuses_does_not_widen_other_failures(settings):
    respx.get(f"{BASE_URL}/v1/thing").mock(return_value=httpx.Response(404, json={"error": "x"}))
    client = make_client(settings)
    try:
        with pytest.raises(PlatformError, match="status 404"):
            await client.request_json("GET", "/v1/thing", ok_statuses={409})
    finally:
        await client.aclose()


# --- module 0: error hints for the other API dialects ----------------------------------


_HOME_APP_YAML = (
    "--- !<java.util.LinkedHashMap>\n"
    "timestamp: '2026-09-12T10:00:00.000+00:00'\n"
    "status: 404\n"
    "error: Not Found\n"
    "path: /crosswork/sso/login/crosswork/aa/v1/x\n"
)


@pytest.mark.parametrize(
    ("status", "body", "fragment", "detail"),
    [
        # (a) RESTCONF error documents, bare "errors" key (verified on nbi/topology/v3)
        (
            400,
            {"errors": {"error": [{"error-tag": "unknown-element", "error-message": "bad"}]}},
            "path or key problem",
            "RESTCONF unknown-element: bad",
        ),
        (
            400,
            {
                "errors": {
                    "error": [
                        {
                            "error-type": "protocol",
                            "error-tag": "missing-attribute",
                            "error-message": "parent key required",
                        }
                    ]
                }
            },
            "required key is missing",
            "RESTCONF missing-attribute: parent key required",
        ),
        (
            400,
            {
                "errors": {
                    "error": [
                        {
                            "error-tag": "invalid-value",
                            "error-message": "Invalid value 'PE1' for (...)headend",
                        }
                    ]
                }
            },
            "wrong type for the YANG model",
            "RESTCONF invalid-value: Invalid value 'PE1' for (...)headend",
        ),
        (
            409,
            {"errors": {"error": [{"error-tag": "data-missing", "error-message": "no node"}]}},
            "no such object",
            "RESTCONF data-missing: no node",
        ),
        # EMF RESTCONF form: rc.errors with a single error OBJECT (verified live on the
        # inventory RESTCONF: an unknown ndFdn)
        (
            400,
            {
                "rc.errors": {
                    "error": {
                        "error-type": "application",
                        "error-tag": "invalid-value",
                        "error-app-tag": "FW.0089",
                        "error-message": "Cannot find device with Node Name: nope",
                    }
                }
            },
            "wrong type for the YANG model",
            "RESTCONF invalid-value: Cannot find device with Node Name: nope",
        ),
        # RFC 8040 namespaced form (NSO proxy)
        (
            409,
            {"ietf-restconf:errors": {"error": [{"error-tag": "data-missing"}]}},
            "no such object",
            "RESTCONF data-missing",
        ),
        # NSO proxy answers an application/json body with 415 (verified live): the fix is
        # the Content-Type header, not the path or body.
        (
            415,
            {
                "ietf-restconf:errors": {
                    "error": [
                        {
                            "error-type": "protocol",
                            "error-tag": "malformed-message",
                            "error-message": "Unsupported media type application/json",
                        }
                    ]
                }
            },
            "Content-Type: application/yang-data+json",
            "RESTCONF malformed-message: Unsupported media type",
        ),
        # an unmapped tag still gets a RESTCONF hint and the platform's words
        (
            400,
            {"errors": {"error": [{"error-tag": "bad-attribute", "error-message": "nope"}]}},
            "RESTCONF service rejected",
            "RESTCONF bad-attribute: nope",
        ),
        # (b) dg-manager rejects unknown fields
        (
            400,
            {"error": 'unable to unmarshal payload to proto, err: unknown field "x" in ...'},
            "rejects unknown fields",
            "unable to unmarshal payload to proto",
        ),
        # (c) Spring "No static resource" in both observed forms
        (
            500,
            {"code": 500, "errorMessage": "No static resource crosswork/config/v1/x."},
            "does not serve this path on this build",
            "No static resource crosswork/config/v1/x.",
        ),
        (
            404,
            {
                "timestamp": "2026-09-12T10:00:00.000+00:00",
                "status": 404,
                "error": "Not Found",
                "message": "No static resource crosswork/swim/v1/x.",
                "path": "/crosswork/swim/v1/x",
            },
            "does not serve this path on this build",
            "No static resource crosswork/swim/v1/x.",
        ),
        (
            404,
            {
                "status": 404,
                "error": "Not Found",
                "exception": "org.springframework.web.servlet.resource.NoResourceFoundException",
                "path": "/crosswork/grouping/v1/x",
            },
            "does not serve this path on this build",
            "Not Found",
        ),
        # (d) home-app fallback, Spring-JSON form
        (
            404,
            {
                "status": 404,
                "error": "Not Found",
                "path": "/crosswork/sso/login/crosswork/hi/v1/x",
            },
            "not routed on this Crosswork instance",
            "Not Found",
        ),
    ],
)
def test_dialect_error_hints_json(status, body, fragment, detail):
    from cnc_mcp.errors import http_error

    msg = str(http_error(httpx.Response(status, json=body)))
    assert f"status {status}" in msg
    assert fragment in msg
    assert detail in msg


@pytest.mark.parametrize(
    ("path", "application"),
    [
        ("/crosswork/sso/login/crosswork/hi/v1/alerts/device/devices", "Health Insights"),
        ("/crosswork/sso/login/crosswork/nca/v1/mops/query", "Change Automation"),
        ("/crosswork/sso/login/crosswork/aa/aaapp/v1/services", "Service Health"),
        ("/crosswork/sso/login/crosswork/path_analytics/v1/paths", "Path Analytics"),
    ],
)
def test_unrouted_hint_names_the_missing_application(path, application):
    """Verified live 2026-09-13: these prefixes fall through to the home app on a
    single-VM 7.2 build; the hint names the application so the agent stops probing."""
    from cnc_mcp.errors import http_error

    msg = str(
        http_error(httpx.Response(404, json={"status": 404, "error": "Not Found", "path": path}))
    )
    assert "not routed on this Crosswork instance" in msg
    assert f"that prefix belongs to {application}" in msg


def test_unrouted_hint_without_a_known_application():
    from cnc_mcp.errors import http_error

    msg = str(
        http_error(
            httpx.Response(
                404,
                json={
                    "status": 404,
                    "error": "Not Found",
                    "path": "/crosswork/sso/login/crosswork/zzz/v1",
                },
            )
        )
    )
    assert "not routed on this Crosswork instance" in msg
    assert "prefix belongs to" not in msg


@pytest.mark.parametrize(
    ("status", "text", "fragment", "detail"),
    [
        # Go-mux services (probemgr, authconfig) answer an unknown path with plain text
        # (verified live): the prefix is routed, the path is not — not a bad ID.
        (
            404,
            "404 page not found\n",
            "does not serve this path on this build",
            "404 page not found",
        ),
    ],
)
def test_dialect_error_hints_text(status, text, fragment, detail):
    from cnc_mcp.errors import http_error

    msg = str(http_error(httpx.Response(status, text=text)))
    assert f"status {status}" in msg
    assert fragment in msg
    assert detail in msg
    assert "ID or name is correct" not in msg  # the generic 404 hint would mislead here


def test_nso_415_does_not_get_the_generic_yang_hint():
    from cnc_mcp.errors import http_error

    body = {
        "ietf-restconf:errors": {
            "error": [{"error-tag": "malformed-message", "error-message": "Unsupported media type"}]
        }
    }
    msg = str(http_error(httpx.Response(415, json=body)))
    assert "application/yang-data+json" in msg
    assert "against the YANG model" not in msg  # path and body are fine; the header is not
    # a 415 without a RESTCONF document still names the media type as the problem
    assert "Unsupported media type" in str(http_error(httpx.Response(415, json={"error": "x"})))


def test_home_app_yaml_fallback_hint_without_dumping_yaml():
    from cnc_mcp.errors import http_error

    msg = str(http_error(httpx.Response(404, text=_HOME_APP_YAML)))
    assert "not routed on this Crosswork instance" in msg
    assert "LinkedHashMap" not in msg and "Platform said" not in msg


def test_yaml_body_is_not_dumped_for_other_statuses():
    from cnc_mcp.errors import _extract_detail, http_error

    yaml_500 = "--- !<java.util.LinkedHashMap>\nstatus: 500\npath: /crosswork/x\n"
    assert _extract_detail(httpx.Response(500, text=yaml_500)) == ""
    msg = str(http_error(httpx.Response(500, text=yaml_500)))
    assert "server error" in msg and "LinkedHashMap" not in msg


def test_spring_404_from_a_real_service_is_not_called_unrouted():
    """A Spring 404 carrying the requested path means the service answered."""
    from cnc_mcp.errors import http_error

    msg = str(
        http_error(httpx.Response(404, json={"error": "Not Found", "path": "/crosswork/swim/v1/x"}))
    )
    assert "not routed" not in msg
    assert "Resource not found" in msg


def test_empty_500_means_backend_unavailable():
    from cnc_mcp.errors import http_error

    msg = str(http_error(httpx.Response(500)))
    assert "EMPTY body" in msg and "not available here" in msg
    assert msg.endswith("the feature is not available here.")  # no dangling "Platform said:"
    # a 500 WITH a body keeps the generic/marker hints
    msg = str(http_error(httpx.Response(500, json={"error": "boom"})))
    assert "EMPTY body" not in msg and "boom" in msg


def test_restconf_multiple_errors_are_joined():
    from cnc_mcp.errors import _extract_detail

    body = {
        "errors": {
            "error": [
                {"error-tag": "unknown-element", "error-message": "a"},
                {"error-tag": "invalid-value", "error-message": "b"},
                "garbage",
            ]
        }
    }
    assert _extract_detail(httpx.Response(400, json=body)) == (
        "RESTCONF unknown-element: a; RESTCONF invalid-value: b"
    )


@respx.mock
async def test_restconf_error_surfaces_through_client(settings):
    path = "/crosswork/nbi/topology/v3/restconf/data/ietf-network-state:networks/node=P1"
    respx.get(f"{BASE_URL}{path}").mock(
        return_value=httpx.Response(
            400,
            json={
                "errors": {
                    "error": [{"error-tag": "missing-attribute", "error-message": "network key"}]
                }
            },
        )
    )
    client = make_client(settings)
    try:
        with pytest.raises(PlatformError) as excinfo:
            await client.request_json("GET", path)
        assert "RESTCONF missing-attribute: network key" in str(excinfo.value)
        assert "required key is missing" in str(excinfo.value)
    finally:
        await client.aclose()


@respx.mock
async def test_aclose_logs_the_auth_strategy_out(make_settings):
    """ApiClient.aclose() releases the platform session before closing the pool."""
    from cnc_mcp.auth import CrossworkCasAuth

    settings = make_settings(api_token="", username="mcp-admin", password="secret")
    tickets = f"{BASE_URL}/crosswork/sso/v1/tickets"
    respx.post(tickets).mock(return_value=httpx.Response(201, text="TGT-1-x"))
    respx.post(f"{tickets}/TGT-1-x").mock(return_value=httpx.Response(200, text="a.b.c"))
    respx.get(f"{BASE_URL}/v1/thing").mock(return_value=httpx.Response(200, json={}))
    logout = respx.delete(f"{tickets}/TGT-1-x").mock(return_value=httpx.Response(200))
    client = ApiClient(settings, CrossworkCasAuth("mcp-admin", "secret"))
    await client.request_json("GET", "/v1/thing")
    await client.aclose()
    assert logout.call_count == 1
