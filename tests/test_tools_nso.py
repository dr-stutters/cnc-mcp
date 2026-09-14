"""NSO tools end-to-end through MCPServer (schema validation included).

The module is registered directly (not through build_server) so the test does
not depend on tools/__init__.py's module list. All HTTP is mocked with respx.
Fixtures mirror the shapes verified live on Crosswork 7.2 with its embedded NSO
(2026-09-13, see the platform notes): the DLM job envelope for the NSO actions,
the node's nso_state / nso_timestamp / NsoMsg / providers_family fields, the
DLM->NSO policy, and the proxy's ``tailf-ncs:device`` entries and
``ietf-restconf:errors`` documents.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from mcp.server.mcpserver import MCPServer

from cnc_mcp import polling
from cnc_mcp.auth import StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.config import Settings
from cnc_mcp.errors import PlatformError
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import nso
from cnc_mcp.tools.nso import (
    NSO_FAILURE_STATES,
    NSO_STATES,
    is_stale,
    ned_id_of,
    normalize_action,
    nso_summary,
    parse_after_timestamp,
    parse_targets,
    sync_verdict,
)
from tests.conftest import BASE_URL, call_tool_text

INVENTORY = f"{BASE_URL}/crosswork/inventory/v1"
NODES_QUERY_URL = f"{INVENTORY}/nodes/query"
NSO_BASE = f"{INVENTORY}/nso"
POLICY_QUERY_URL = f"{NSO_BASE}/policy/query"
SYNC_URL = f"{NSO_BASE}/sync"
SYNC_TO_URL = f"{NSO_BASE}/sync-to"
CHECK_SYNC_URL = f"{NSO_BASE}/check-sync"
IS_NSO_CONFIGURED_URL = f"{BASE_URL}/crosswork/aaa/v1/isNSOConfigured"
PROXY_DEVICES_URL = f"{BASE_URL}/crosswork/proxy/nso/restconf/data/tailf-ncs:devices/device"
# Verified live request form: the ``fields`` selector with ';' unencoded.
PROXY_DEVICE_FIELDS = "name;address;port;authgroup;device-type;state"
PROXY_DEVICES_LIST_URL = f"{PROXY_DEVICES_URL}?fields={PROXY_DEVICE_FIELDS}"
YANG_JSON = "application/yang-data+json"


def proxy_device_url(encoded_name: str) -> str:
    """The keyed proxy GET the get tool must send: same ``fields`` selector as the list."""
    return f"{PROXY_DEVICES_URL}={encoded_name}?fields={PROXY_DEVICE_FIELDS}"


PE1_UUID = "2a9b7c1e-0f3d-4b8a-9c6e-1d2f3a4b5c6d"
P1_UUID = "7f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f"
NSO_PROVIDER_UUID = "c0ffee00-0000-4000-8000-00000000nso1"


def node(
    uuid: str,
    host: str,
    ip: str,
    nso_state: str = "SYNCED",
    nso_msg: str = "",
    errors: list[str] | None = None,
) -> dict:
    """An inventory node with the NSO fields as nodes/query returns them (verified keys)."""
    return {
        "uuid": uuid,
        "host_name": host,
        "node_ip": {"inet_af": "ROBOT_INET_ADDR_TYPE_v4", "inet_addr": ip, "mask": "18"},
        "admin_state": "ROBOT_ADMIN_STATE_UP",
        "reachability_state": "CONN_STATE_REACHABLE",
        "operational_state": "ROBOT_OPER_STATE_OK",
        "profile": "cml-xrd",
        "dg_name": "EMBEDDED_DEF_POOL-1",
        "nso_state": nso_state,
        "nso_timestamp": "1757772000",
        "NsoMsg": nso_msg,
        "providers_family": {
            "ROBOT_PROVIDER_NSO": {
                "providers": {
                    "nso": {
                        "provider_name": "nso",
                        "provider_node_id": host,
                        "provider_uuid": NSO_PROVIDER_UUID,
                    }
                }
            }
        },
        "ned_id": "cisco-iosxr-cli-7.70",
        "errors": errors or [],
    }


CONNECT_FAILED_MSG = (
    "NSO connect to the device failed: Failed to connect to device P1: connection refused"
)
PE1 = node(PE1_UUID, "PE1", "198.18.140.11")
P1 = node(P1_UUID, "P1", "198.18.140.12", nso_state="CONNECT_FAILED", nso_msg=CONNECT_FAILED_MSG)
ONE_NODE = {"data": [PE1], "total_count": 5, "result_count": 1}
TWO_NODES = {"data": [PE1, P1], "total_count": 5, "result_count": 2}
NO_NODES: dict = {}  # verified: an empty match is a bare {} with no data key


def query_of(selector: dict) -> dict:
    """The exact nodes/query body the tools send for a selector (page 0 of 100)."""
    return {"filter": selector, "filterData": {"PageSize": 100, "PageNum": 0, "Criteria": ""}}


# Verified: every DLM NSO action answers this immediately (asynchronous).
JOB_ACCEPTED = {
    "job_id": "3f7c1a2e-1111-4222-8333-444455556666",
    "state": "JOB_ACCEPTED",
    "type": "NSO device connect",
}
# Verified: POST nso/sync is synchronous.
JOB_SYNC_COMPLETED = {
    "job_id": "5a6b7c8d-1111-4222-8333-444455557777",
    "state": "JOB_COMPLETED",
    "type": "NSO sync",
    "completion_time": "1757772010",
    "creation_time": "1757772009",
    "created_by": "admin",
    "impacted": [f"{PE1_UUID} PE1"],
}
JOB_FAILED = {
    "job_id": "9e8d7c6b-1111-4222-8333-444455558888",
    "state": "JOB_FAILED",
    "type": "NSO device sync-from",
    "error": "NSO provider is not reachable",
}

# Verified: POST nso/policy/query {} -> this object.
POLICY = {
    "name": "default",
    "providers_criteria": "*",
    "provider_policy": {
        "nso": {
            "match": True,
            "matchRule": "*",
            "onboardTo": True,
            "onboardToRule": "*",
            "onboardFromRule": "*",
            "syncFrom": True,
            "syncFromRule": "*",
            "checkSync": True,
            "checkSyncRule": "*",
        }
    },
    "policy": {
        "auto_onboard_rfs": True,
        "rfs_spread_method": "ARBITRARY_USER_CONTROL",
        "rfs_spread_value": 0,
    },
    "lsa": False,
}

# Verified: GET .../tailf-ncs:devices/device?fields=... -> {"tailf-ncs:device": [...]}.
NSO_PE1 = {
    "name": "PE1",
    "address": "198.18.140.11",
    "port": 22,
    "authgroup": "cml-xrd",
    "device-type": {"cli": {"ned-id": "cisco-iosxr-cli-7.70:cisco-iosxr-cli-7.70"}},
    "state": {
        "oper-state": "enabled",
        "admin-state": "unlocked",
        "transaction-mode": "ned",
        "last-transaction-id": "1757772000-123456789",
    },
}
NSO_P1 = {
    "name": "P1",
    "address": "198.18.140.12",
    "port": 22,
    "authgroup": "cml-xrd",
    "device-type": {"cli": {"ned-id": "cisco-iosxr-cli-7.70:cisco-iosxr-cli-7.70"}},
    "state": {
        "oper-state": "disabled",
        "oper-state-error-tag": "connection-refused",
        "admin-state": "unlocked",
        "transaction-mode": "ned",
    },
}
NSO_DEVICES = {"tailf-ncs:device": [NSO_PE1, NSO_P1]}

# Verified: a missing device on the proxy is 404 WITH a RESTCONF error document.
PROXY_404 = httpx.Response(
    404,
    json={
        "ietf-restconf:errors": {
            "error": [
                {
                    "error-type": "application",
                    "error-tag": "invalid-value",
                    "error-message": "uri keypath not found",
                }
            ]
        }
    },
)
# Verified: the proxy's answer to a body that is not application/yang-data+json.
PROXY_415 = httpx.Response(
    415,
    json={
        "ietf-restconf:errors": {
            "error": [
                {
                    "error-type": "protocol",
                    "error-tag": "malformed-message",
                    "error-message": "Unsupported media type: application/json",
                }
            ]
        }
    },
)
NATS_500 = httpx.Response(500, json={"error": "NATS request failed"})


def build(settings: Settings) -> MCPServer:
    mcp = MCPServer("test")
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    nso.register(mcp, ctx)
    return mcp


def sent(route: respx.Route, index: int = 0) -> dict:
    return json.loads(route.calls[index].request.content)


def mock_nodes(*responses: dict) -> respx.Route:
    """nodes/query answering the given bodies in order; the last one repeats forever."""
    replies = [httpx.Response(200, json=r) for r in responses]

    def answer(_request: httpx.Request) -> httpx.Response:
        return replies.pop(0) if len(replies) > 1 else replies[0]

    return respx.post(NODES_QUERY_URL).mock(side_effect=answer)


class _FakeClock:
    """Stands in for both ``time`` and ``asyncio`` inside cnc_mcp.polling."""

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def fake_clock(monkeypatch) -> _FakeClock:
    clock = _FakeClock()
    monkeypatch.setattr(polling, "time", clock)
    monkeypatch.setattr(polling, "asyncio", clock)
    return clock


READ_TOOLS = {
    "cnc_is_nso_configured",
    "cnc_get_nso_policy",
    "cnc_list_nso_devices",
    "cnc_get_nso_device",
    "cnc_check_device_nso_state",
    "cnc_check_nso_device_sync",  # check-sync changes no configuration: a read
    "cnc_wait_for_device_nso_state",
}
WRITE_TOOLS = {"cnc_nso_device_action", "cnc_nso_sync_to_device", "cnc_sync_inventory_with_nso"}


# --- registration / gating ---------------------------------------------------


async def test_write_tools_hidden_unless_enabled(make_settings):
    names = {t.name for t in await build(make_settings(enable_writes=False)).list_tools()}
    assert names == READ_TOOLS
    names = {t.name for t in await build(make_settings(enable_writes=True)).list_tools()}
    assert names == READ_TOOLS | WRITE_TOOLS


async def test_annotations(make_settings):
    tools = {t.name: t for t in await build(make_settings(enable_writes=True)).list_tools()}
    for name in READ_TOOLS:
        assert tools[name].annotations.read_only_hint is True, name
        assert tools[name].annotations.idempotent_hint is True, name
    for name in WRITE_TOOLS:
        assert tools[name].annotations.read_only_hint is False, name
        assert tools[name].annotations.idempotent_hint is True, name
    assert tools["cnc_nso_device_action"].annotations.destructive_hint is False
    assert tools["cnc_sync_inventory_with_nso"].annotations.destructive_hint is False
    assert tools["cnc_nso_sync_to_device"].annotations.destructive_hint is True
    # The global re-association takes no device selector at all (its body is ignored).
    assert tools["cnc_sync_inventory_with_nso"].input_schema.get("properties", {}) == {}
    # The wait tool exposes the stale-reading guard.
    assert "after_timestamp" in tools["cnc_wait_for_device_nso_state"].input_schema["properties"]
    # The read-only check-sync says what it does and does not change.
    check = tools["cnc_check_nso_device_sync"]
    assert check.annotations.destructive_hint is False
    assert "changes nothing on the device and nothing in NSO's CDB" in (check.description or "")
    assert "What it does do on the platform: it creates a job" in (check.description or "")
    # The failure outcome of a check-sync was never observed (no CHECK_SYNC_FAILED in the
    # enum) and the tool itself has not been run live: the docstring must say so.
    assert "this tool itself has NOT been" in (check.description or "")
    assert "UNVERIFIED: what a check-sync that" in (check.description or "")
    assert "may equally stay" in (check.description or "")
    assert check.input_schema["properties"]["wait_seconds"]["default"] == 60
    # The cached-verdict tool says its verdict is a cache and how to refresh it.
    cached = tools["cnc_check_device_nso_state"].description or ""
    assert "THE VERDICT IS A CACHE, NOT A LIVE CHECK" in cached
    assert "cnc_check_nso_device_sync" in cached


# --- pure helpers ------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("connect", "connect"),
        ("sync_from", "sync-from"),
        (" Fetch-SSH-Keys ", "fetch-ssh-keys"),
        ("CHECK_SYNC", "check-sync"),
        ("compare_config", "compare-config"),
    ],
)
def test_normalize_action_accepts_friendly_forms(value, expected):
    assert normalize_action(value) == expected


@pytest.mark.parametrize("value", ["sync-to", "reboot", ""])
def test_normalize_action_rejects_unknown_and_sync_to(value):
    with pytest.raises(PlatformError, match="Unknown NSO device action"):
        normalize_action(value)


def test_parse_targets():
    assert parse_targets("synced, match") == {"SYNCED", "MATCH"}
    assert parse_targets("SYNCED") == {"SYNCED"}
    with pytest.raises(PlatformError, match="target is empty"):
        parse_targets(" , ")
    with pytest.raises(PlatformError, match="Unknown nso_state value\\(s\\) BOGUS"):
        parse_targets("SYNCED,bogus")


def test_parse_after_timestamp():
    assert parse_after_timestamp(None) is None
    assert parse_after_timestamp("") is None and parse_after_timestamp("  ") is None
    assert parse_after_timestamp("1757772000") == 1757772000
    assert parse_after_timestamp(" 1757772000 ") == 1757772000
    assert parse_after_timestamp(1757772000) == 1757772000  # the wire value may be an int
    for bad in ("2025-09-13T14:00:00Z", "-5", "1.5", "soon"):
        with pytest.raises(PlatformError, match="after_timestamp must be the epoch value"):
            parse_after_timestamp(bad)


def test_is_stale_compares_numerically_and_never_judges_a_missing_stamp():
    assert is_stale({"nso_timestamp": "1757772000"}, 1757772000) is True  # equal = pre-action
    assert is_stale({"nso_timestamp": "1757771999"}, 1757772000) is True
    assert is_stale({"nso_timestamp": "1757772001"}, 1757772000) is False
    assert is_stale({"nso_timestamp": 1757772030}, 1757772000) is False
    assert is_stale({"nso_timestamp": "999"}, 1757772000) is True  # numeric, not lexical
    assert is_stale({"nso_timestamp": "1757772000"}, None) is False  # no guard requested
    assert is_stale({}, 1757772000) is False and is_stale({"nso_timestamp": ""}, 1) is False
    assert is_stale({"nso_timestamp": "soon"}, 1757772000) is False


def test_sync_verdict_reads_settled_states_and_ignores_stale_readings():
    synced = {**PE1, "nso_timestamp": "1757772010"}
    assert sync_verdict(synced, 1757772000) == "in-sync"
    assert sync_verdict(synced, 1757772010) == "pending"  # not newer than the pre-check stamp
    assert sync_verdict(synced, None) == "in-sync"  # nothing to compare against
    assert sync_verdict({**synced, "nso_state": "NOT_SYNCED"}, 1757772000) == "out-of-sync"
    assert sync_verdict({**synced, "nso_state": "CONNECT_FAILED"}, 1757772000) == "failed"
    assert sync_verdict({**synced, "nso_state": "CHECK_SYNC_STARTED"}, 1757772000) == "pending"
    assert sync_verdict({**synced, "nso_state": "ASSOCIATED"}, 1757772000) == "pending"


def test_state_tables_cover_the_documented_enum():
    documented = {
        "INVALID_NSO_OPER_STATE", "ASSOCIATED", "NOT_ASSOCIATED", "MATCH", "NO_MATCH",
        "ONBOARD_FAIL", "FETCH_SSH_KEYS_SCHEDULED", "FETCH_SSH_KEYS_STARTED",
        "FETCH_SSH_KEYS_FAILED", "CONNECT_SCHEDULED", "CONNECT_STARTED", "CONNECT_FAILED",
        "SYNC_FROM_SCHEDULED", "SYNC_FROM_STARTED", "SYNC_TO_SCHEDULED", "SYNC_TO_STARTED",
        "SYNCED", "SYNC_FAILED", "CHECK_SYNC_SCHEDULED", "CHECK_SYNC_STARTED", "NOT_SYNCED",
        "COMPARE_CONFIG_SCHEDULED", "COMPARE_CONFIG_STARTED",
    }  # fmt: skip
    assert set(NSO_STATES) == documented and len(NSO_STATES) == len(documented)
    assert NSO_FAILURE_STATES <= documented


def test_ned_id_of_reads_any_device_type_container():
    assert ned_id_of(NSO_PE1) == "cisco-iosxr-cli-7.70:cisco-iosxr-cli-7.70"
    assert ned_id_of({"device-type": {"netconf": {"ned-id": "juniper-junos_nc-4.5"}}}) == (
        "juniper-junos_nc-4.5"
    )
    assert ned_id_of({"device-type": {"generic": {"ned-id": "gen-1.0"}}}) == "gen-1.0"
    assert ned_id_of({"device-type": {}}) is None
    assert ned_id_of({}) is None


def test_nso_summary_shape():
    summary = nso_summary(P1)
    assert summary["host_name"] == "P1" and summary["uuid"] == P1_UUID
    assert summary["nso_state"] == "CONNECT_FAILED"
    assert summary["nso_timestamp"] == "1757772000"
    assert summary["nso_timestamp_iso"] == "2025-09-13T14:00:00Z"
    assert summary["NsoMsg"] == CONNECT_FAILED_MSG
    assert summary["errors"] == []
    assert summary["providers_family"] == ["ROBOT_PROVIDER_NSO"]
    assert summary["nso_providers"] == {"nso": "P1"}
    assert summary["ned_id"] == "cisco-iosxr-cli-7.70"
    bare = nso_summary({"host_name": "X", "uuid": "u", "nso_state": "NOT_ASSOCIATED"})
    assert bare["providers_family"] == [] and bare["nso_providers"] == {}
    assert bare["errors"] == [] and bare["nso_timestamp_iso"] == "-" and "ned_id" not in bare


# --- cnc_is_nso_configured ---------------------------------------------------


@respx.mock
async def test_is_nso_configured_true(settings):
    route = respx.get(IS_NSO_CONFIGURED_URL).mock(
        return_value=httpx.Response(200, json={"nsoConfigured": True})
    )
    text = await call_tool_text(build(settings), "cnc_is_nso_configured", {})
    assert route.call_count == 1
    assert text.startswith("NSO is configured on this Crosswork instance.")
    assert '"nsoConfigured": true' in text


@respx.mock
async def test_is_nso_configured_false(settings):
    respx.get(IS_NSO_CONFIGURED_URL).mock(
        return_value=httpx.Response(200, json={"nsoConfigured": False})
    )
    text = await call_tool_text(build(settings), "cnc_is_nso_configured", {})
    assert text.startswith("NSO is NOT configured on this Crosswork instance")
    assert not text.startswith("Error:")


@respx.mock
async def test_is_nso_configured_forbidden_is_error(make_settings):
    respx.get(IS_NSO_CONFIGURED_URL).mock(return_value=httpx.Response(403, json={}))
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_is_nso_configured", {})
    assert text.startswith("Error:") and "403" in text


# --- cnc_get_nso_policy ------------------------------------------------------


@respx.mock
async def test_get_nso_policy_markdown_sends_empty_body(settings):
    route = respx.post(POLICY_QUERY_URL).mock(return_value=httpx.Response(200, json=POLICY))
    text = await call_tool_text(build(settings), "cnc_get_nso_policy", {})
    assert sent(route) == {}
    assert "sync policy 'default'" in text
    assert "- providers_criteria: *" in text
    assert "- lsa: False" in text
    assert "auto_onboard_rfs=True rfs_spread_method=ARBITRARY_USER_CONTROL" in text
    assert (
        "- nso: match=True (rule '*') onboardTo=True (rule '*') onboardFrom=? (rule '*') "
        "syncFrom=True (rule '*') checkSync=True (rule '*')"
    ) in text


@respx.mock
async def test_get_nso_policy_json_is_verbatim(settings):
    respx.post(POLICY_QUERY_URL).mock(return_value=httpx.Response(200, json=POLICY))
    text = await call_tool_text(build(settings), "cnc_get_nso_policy", {"response_format": "json"})
    assert json.loads(text) == POLICY


@respx.mock
async def test_get_nso_policy_api_error_is_string(make_settings):
    respx.post(POLICY_QUERY_URL).mock(return_value=NATS_500)
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_get_nso_policy", {})
    assert text.startswith("Error:") and "500" in text and "malformed request body" in text


# --- cnc_list_nso_devices ----------------------------------------------------


@respx.mock
async def test_list_nso_devices_markdown_url_and_accept(settings):
    route = respx.get(PROXY_DEVICES_LIST_URL).mock(
        return_value=httpx.Response(200, json=NSO_DEVICES)
    )
    text = await call_tool_text(build(settings), "cnc_list_nso_devices", {})
    request = route.calls[0].request
    assert str(request.url) == PROXY_DEVICES_LIST_URL  # fields with ';' verbatim
    assert request.headers["Accept"] == YANG_JSON
    assert "# NSO devices (2)" in text
    assert (
        "- **PE1** 198.18.140.11:22 authgroup=cml-xrd "
        "ned=cisco-iosxr-cli-7.70:cisco-iosxr-cli-7.70 oper=enabled admin=unlocked"
    ) in text
    assert "- **P1** 198.18.140.12:22 authgroup=cml-xrd" in text
    assert "oper=disabled (connection-refused) admin=unlocked" in text
    assert "NSO's own view" in text and "nso_state" in text


@respx.mock
async def test_list_nso_devices_json(settings):
    respx.get(PROXY_DEVICES_LIST_URL).mock(return_value=httpx.Response(200, json=NSO_DEVICES))
    text = await call_tool_text(
        build(settings), "cnc_list_nso_devices", {"response_format": "json"}
    )
    data = json.loads(text)
    assert data["count"] == 2 and data["items"] == [NSO_PE1, NSO_P1]


@respx.mock
async def test_list_nso_devices_empty_is_not_error(settings):
    respx.get(PROXY_DEVICES_LIST_URL).mock(return_value=httpx.Response(204))
    text = await call_tool_text(build(settings), "cnc_list_nso_devices", {})
    assert "NSO holds no devices." in text and not text.startswith("Error:")


@respx.mock
async def test_list_nso_devices_415_names_the_media_type(make_settings):
    respx.get(PROXY_DEVICES_LIST_URL).mock(return_value=PROXY_415)
    text = await call_tool_text(build(make_settings(max_retries=0)), "cnc_list_nso_devices", {})
    assert text.startswith("Error:") and "415" in text
    assert "application/yang-data+json" in text
    assert "Unsupported media type" in text


# --- cnc_get_nso_device ------------------------------------------------------


@respx.mock
async def test_get_nso_device_markdown_encodes_name_and_sends_accept(settings):
    route = respx.get(proxy_device_url("PE%201%2Fa")).mock(
        return_value=httpx.Response(200, json={"tailf-ncs:device": [{**NSO_PE1, "name": "PE 1/a"}]})
    )
    text = await call_tool_text(build(settings), "cnc_get_nso_device", {"name": "PE 1/a"})
    request = route.calls[0].request
    # The key is one percent-encoded list key AND the GET is limited to the same ``fields``
    # as the list tool — never the whole entry, whose ``config`` subtree is the device's
    # entire running configuration.
    assert str(request.url) == proxy_device_url("PE%201%2Fa")
    assert request.url.raw_path.decode().endswith(
        "/tailf-ncs:devices/device=PE%201%2Fa?fields=name;address;port;authgroup;device-type;state"
    )
    assert request.headers["Accept"] == YANG_JSON
    assert "# NSO device PE 1/a" in text
    assert "- **PE 1/a** 198.18.140.11:22 authgroup=cml-xrd" in text
    assert '"oper-state": "enabled"' in text and '"transaction-mode": "ned"' in text


@respx.mock
async def test_get_nso_device_json_is_the_entry(settings):
    respx.get(proxy_device_url("P1")).mock(
        return_value=httpx.Response(200, json={"tailf-ncs:device": [NSO_P1]})
    )
    text = await call_tool_text(
        build(settings), "cnc_get_nso_device", {"name": "P1", "response_format": "json"}
    )
    assert json.loads(text) == NSO_P1


@respx.mock
async def test_get_nso_device_proxy_404_with_restconf_document_is_not_found(settings):
    respx.get(proxy_device_url("ghost")).mock(return_value=PROXY_404)
    text = await call_tool_text(build(settings), "cnc_get_nso_device", {"name": "ghost"})
    assert text.startswith("Error: NSO has no device named 'ghost'")
    assert "cnc_list_nso_devices" in text


@respx.mock
async def test_get_nso_device_bare_404_is_a_routing_error_not_not_found(settings):
    respx.get(proxy_device_url("PE1")).mock(
        return_value=httpx.Response(404, text="404 page not found")
    )
    text = await call_tool_text(build(settings), "cnc_get_nso_device", {"name": "PE1"})
    assert text.startswith("Error:") and "404" in text
    assert "NSO has no device" not in text


@respx.mock
async def test_get_nso_device_filters_client_side_when_the_key_is_ignored(settings):
    # Belt and braces: a keyed GET that answers the whole list is re-filtered on name.
    respx.get(proxy_device_url("P1")).mock(return_value=httpx.Response(200, json=NSO_DEVICES))
    text = await call_tool_text(
        build(settings), "cnc_get_nso_device", {"name": "P1", "response_format": "json"}
    )
    assert json.loads(text) == NSO_P1
    respx.get(proxy_device_url("pe1")).mock(return_value=httpx.Response(200, json=NSO_DEVICES))
    text = await call_tool_text(build(settings), "cnc_get_nso_device", {"name": "pe1"})
    assert text.startswith("Error: NSO has no device named 'pe1'")  # case-sensitive


@respx.mock
async def test_get_nso_device_415_is_error_with_media_type(make_settings):
    respx.get(proxy_device_url("PE1")).mock(return_value=PROXY_415)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_get_nso_device", {"name": "PE1"}
    )
    assert text.startswith("Error:") and "415" in text and "application/yang-data+json" in text


# --- cnc_check_device_nso_state ----------------------------------------------


@respx.mock
async def test_check_device_nso_state_markdown_and_body(settings):
    route = mock_nodes(TWO_NODES)
    text = await call_tool_text(build(settings), "cnc_check_device_nso_state", {"host_name": "P*"})
    assert sent(route) == query_of({"host_name": "P*"})
    assert "# NSO state of 2 device(s) matching host_name 'P*' (2 match in total)" in text
    assert (
        f"- **PE1** ({PE1_UUID}) nso_state=SYNCED since 2025-09-13T14:00:00Z "
        "providers=ROBOT_PROVIDER_NSO nso_node_id=PE1 ned=cisco-iosxr-cli-7.70"
    ) in text
    assert f"- **P1** ({P1_UUID}) nso_state=CONNECT_FAILED since" in text
    assert f"  message: {CONNECT_FAILED_MSG}" in text


@respx.mock
async def test_check_device_nso_state_json_by_uuid(settings):
    route = mock_nodes(ONE_NODE)
    text = await call_tool_text(
        build(settings),
        "cnc_check_device_nso_state",
        {"uuid": PE1_UUID, "response_format": "json"},
    )
    assert sent(route) == query_of({"uuid": PE1_UUID})
    data = json.loads(text)
    assert data["selector"] == {"uuid": PE1_UUID}
    assert data["total"] == 1 and data["count"] == 1
    assert data["items"] == [nso_summary(PE1)]


@respx.mock
async def test_check_device_nso_state_errors_sub_line(settings):
    failing = node(P1_UUID, "P1", "198.18.140.12", nso_state="SYNC_FAILED",
                   errors=["NSO sync-from failed: timeout"])  # fmt: skip
    mock_nodes({"data": [failing], "result_count": 1})
    text = await call_tool_text(build(settings), "cnc_check_device_nso_state", {"host_name": "P1"})
    assert "  errors: NSO sync-from failed: timeout" in text


@respx.mock
async def test_check_device_nso_state_zero_match_is_error(settings):
    mock_nodes(NO_NODES)
    text = await call_tool_text(
        build(settings), "cnc_check_device_nso_state", {"host_name": "ghost"}
    )
    assert text.startswith("Error: no device matches host_name 'ghost'")


@pytest.mark.parametrize("args", [{}, {"uuid": PE1_UUID, "host_name": "PE1"}, {"host_name": "  "}])
@respx.mock
async def test_check_device_nso_state_requires_exactly_one_selector(settings, args):
    route = mock_nodes(ONE_NODE)
    text = await call_tool_text(build(settings), "cnc_check_device_nso_state", args)
    assert text.startswith("Error:") and "exactly one" in text
    assert route.call_count == 0


@respx.mock
async def test_check_device_nso_state_api_error_is_string(make_settings):
    respx.post(NODES_QUERY_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_check_device_nso_state", {"host_name": "PE1"}
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_check_nso_device_sync ------------------------------------------------


@respx.mock
async def test_check_nso_device_sync_is_a_read_that_posts_check_sync_and_waits(
    settings, fake_clock
):
    """Registered without writes; resolves the selector, POSTs exactly that filter to
    nso/check-sync, then polls until every device's nso_state is newer than the
    pre-check stamp and settled (SYNCED / NOT_SYNCED)."""
    pe1_before = {**PE1, "nso_timestamp": "1757772000"}
    p1_before = {**P1, "nso_state": "SYNCED", "NsoMsg": "", "nso_timestamp": "1757772000"}
    nodes = mock_nodes(
        {"data": [pe1_before, p1_before], "result_count": 2},  # the selector resolve
        {"data": [pe1_before, p1_before], "result_count": 2},  # first poll: still stale
        {  # second poll: PE1 mid-check, P1 already settled
            "data": [
                {**pe1_before, "nso_state": "CHECK_SYNC_STARTED", "nso_timestamp": "1757772003"},
                {**p1_before, "nso_state": "NOT_SYNCED", "nso_timestamp": "1757772004"},
            ],
            "result_count": 2,
        },
        {  # third poll: both settled
            "data": [
                {**pe1_before, "nso_timestamp": "1757772008"},
                {**p1_before, "nso_state": "NOT_SYNCED", "nso_timestamp": "1757772004"},
            ],
            "result_count": 2,
        },
    )
    action = respx.post(CHECK_SYNC_URL).mock(
        return_value=httpx.Response(200, json={**JOB_ACCEPTED, "type": "NSO device check-sync"})
    )
    text = await call_tool_text(
        build(settings),  # writes disabled: the tool must still be there
        "cnc_check_nso_device_sync",
        {"host_name": "P*", "wait_seconds": 60, "interval_seconds": 5},
    )
    assert sent(nodes) == query_of({"host_name": "P*"})
    assert action.call_count == 1 and sent(action) == {"filter": {"host_name": "P*"}}
    assert nodes.call_count == 4
    head, body = text.split("\n", 1)
    assert head.startswith(
        "check-sync of 2 device(s): 1 in-sync, 1 out-of-sync, 0 failed, 0 pending (after 10s)."
    )
    assert "compare-config" in head  # an out-of-sync device gets the reconcile hint
    data = json.loads(body)
    assert data["job_id"] == JOB_ACCEPTED["job_id"] and data["state"] == "JOB_ACCEPTED"
    assert data["action"] == "check-sync" and data["filter"] == {"host_name": "P*"}
    assert data["settled"] is True and data["elapsed_seconds"] == 10
    assert data["matched_total"] == 2 and "next" not in data and "matched_devices" not in data
    by_name = {d["host_name"]: d for d in data["devices"]}
    assert by_name["PE1"]["verdict"] == "in-sync" and by_name["PE1"]["nso_state"] == "SYNCED"
    assert by_name["PE1"]["nso_timestamp"] == "1757772008"
    assert by_name["PE1"]["nso_timestamp_before"] == "1757772000"
    assert by_name["PE1"]["nso_state_before"] == "SYNCED"
    assert by_name["P1"]["verdict"] == "out-of-sync" and by_name["P1"]["nso_state"] == "NOT_SYNCED"


@respx.mock
async def test_check_nso_device_sync_wait_zero_returns_pending_with_a_follow_up(settings):
    nodes = mock_nodes(ONE_NODE)
    action = respx.post(CHECK_SYNC_URL).mock(return_value=httpx.Response(200, json=JOB_ACCEPTED))
    text = await call_tool_text(
        build(settings), "cnc_check_nso_device_sync", {"uuid": PE1_UUID, "wait_seconds": 0}
    )
    assert nodes.call_count == 1 and sent(action) == {"filter": {"uuid": PE1_UUID}}
    head, body = text.split("\n", 1)
    assert (
        head
        == "check-sync of 1 device(s): 0 in-sync, 0 out-of-sync, 0 failed, 1 pending (after 0s)."
    )
    data = json.loads(body)
    assert data["settled"] is False
    assert data["devices"][0]["verdict"] == "pending"
    assert data["devices"][0]["nso_state"] == "SYNCED"  # the pre-check (cached) reading
    assert data["next"].startswith("Still pending: PE1.")
    assert "cnc_check_device_nso_state" in data["next"]


@respx.mock
async def test_check_nso_device_sync_timeout_is_not_an_error_and_names_pending(
    settings, fake_clock
):
    # The DLM never moves nso_timestamp past the pre-check stamp within the budget.
    mock_nodes(ONE_NODE)
    respx.post(CHECK_SYNC_URL).mock(return_value=httpx.Response(200, json=JOB_ACCEPTED))
    text = await call_tool_text(
        build(settings),
        "cnc_check_nso_device_sync",
        {"host_name": "PE1", "wait_seconds": 10, "interval_seconds": 5},
    )
    assert not text.startswith("Error")
    head, body = text.split("\n", 1)
    assert "0 in-sync, 0 out-of-sync, 0 failed, 1 pending" in head
    data = json.loads(body)
    assert data["settled"] is False and data["devices"][0]["verdict"] == "pending"
    assert data["next"].startswith("Still pending: PE1.")


@respx.mock
async def test_check_nso_device_sync_failure_state_is_a_per_device_verdict(settings, fake_clock):
    # Hypothetical (unverified live — only connect was seen to fail): if a check NSO could
    # not run lands in a known failure state, it is reported as 'failed', not as Error.
    before = {**P1, "nso_state": "SYNCED", "NsoMsg": "", "nso_timestamp": "1757772000"}
    mock_nodes(
        {"data": [before], "result_count": 1},
        {"data": [{**P1, "nso_timestamp": "1757772005"}], "result_count": 1},
    )
    respx.post(CHECK_SYNC_URL).mock(return_value=httpx.Response(200, json=JOB_ACCEPTED))
    text = await call_tool_text(
        build(settings), "cnc_check_nso_device_sync", {"host_name": "P1", "wait_seconds": 30}
    )
    assert not text.startswith("Error")
    head, body = text.split("\n", 1)
    assert "0 in-sync, 0 out-of-sync, 1 failed, 0 pending" in head
    data = json.loads(body)
    assert data["devices"][0]["verdict"] == "failed"
    assert data["devices"][0]["nso_state"] == "CONNECT_FAILED"
    assert data["devices"][0]["NsoMsg"] == CONNECT_FAILED_MSG


@respx.mock
async def test_check_nso_device_sync_zero_match_never_posts(settings):
    nodes = mock_nodes(NO_NODES)
    action = respx.post(CHECK_SYNC_URL).mock(return_value=httpx.Response(200, json=JOB_ACCEPTED))
    text = await call_tool_text(build(settings), "cnc_check_nso_device_sync", {"host_name": "PE9"})
    assert text.startswith("Error: no device matches host_name 'PE9'; nothing was sent to NSO.")
    assert nodes.call_count == 1 and action.call_count == 0


@respx.mock
async def test_check_nso_device_sync_requires_one_selector_and_reports_job_failures(settings):
    route = respx.post(CHECK_SYNC_URL).mock(return_value=httpx.Response(200, json=JOB_FAILED))
    nodes = mock_nodes(ONE_NODE)
    mcp = build(settings)
    text = await call_tool_text(mcp, "cnc_check_nso_device_sync", {})
    assert text == "Error: Pass exactly one of 'uuid' or 'host_name' to select the device(s)."
    assert nodes.call_count == 0 and route.call_count == 0
    text = await call_tool_text(mcp, "cnc_check_nso_device_sync", {"host_name": "PE1"})
    assert text.startswith("Error: NSO check-sync failed (job ")
    assert "NSO provider is not reachable" in text


@respx.mock
async def test_check_nso_device_sync_post_is_not_retried_on_503(make_settings):
    mock_nodes(ONE_NODE)
    route = respx.post(CHECK_SYNC_URL).mock(
        return_value=httpx.Response(503, text="Service Unavailable")
    )
    text = await call_tool_text(
        build(make_settings(max_retries=3)), "cnc_check_nso_device_sync", {"host_name": "PE1"}
    )
    assert route.call_count == 1
    assert text.startswith("Error:") and "503" in text


# --- cnc_nso_device_action ---------------------------------------------------


@respx.mock
async def test_nso_device_action_resolves_then_posts_the_same_filter(make_settings):
    nodes = mock_nodes(ONE_NODE)
    action = respx.post(f"{NSO_BASE}/connect").mock(
        return_value=httpx.Response(200, json=JOB_ACCEPTED)
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_nso_device_action",
        {"action": "connect", "host_name": "PE1"},
    )
    assert sent(nodes) == query_of({"host_name": "PE1"})
    assert action.call_count == 1
    assert sent(action) == {"filter": {"host_name": "PE1"}}
    assert action.calls[0].request.headers["Content-Type"] == "application/json"
    data = json.loads(text)
    assert data["job_id"] == JOB_ACCEPTED["job_id"] and data["state"] == "JOB_ACCEPTED"
    assert data["pending"] is True and data["action"] == "connect"
    assert data["filter"] == {"host_name": "PE1"}
    assert data["matched_devices"] == [
        {
            "host_name": "PE1",
            "uuid": PE1_UUID,
            "nso_state_before": "SYNCED",
            "nso_timestamp_before": "1757772000",
        }
    ]
    assert data["matched_total"] == 1 and "note" not in data
    # The hint carries the pre-action timestamp so the wait can ignore the stale reading.
    assert data["next"].startswith("Asynchronous: poll with cnc_wait_for_device_nso_state")
    assert "host_name='PE1', after_timestamp='1757772000'" in data["next"]


@respx.mock
async def test_nso_device_action_hint_omits_after_timestamp_when_the_device_has_none(make_settings):
    fresh = {k: v for k, v in PE1.items() if k != "nso_timestamp"}
    mock_nodes({"data": [{**fresh, "nso_state": "NOT_ASSOCIATED"}], "result_count": 1})
    respx.post(f"{NSO_BASE}/connect").mock(return_value=httpx.Response(200, json=JOB_ACCEPTED))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_nso_device_action",
        {"action": "connect", "host_name": "PE1"},
    )
    data = json.loads(text)
    assert data["matched_devices"][0]["nso_timestamp_before"] is None
    assert "(host_name='PE1')" in data["next"]  # no after_timestamp='None'


@respx.mock
async def test_nso_device_action_fetch_ssh_keys_on_the_wire(make_settings):
    nodes = mock_nodes(ONE_NODE)
    action = respx.post(f"{NSO_BASE}/fetch-ssh-keys").mock(
        return_value=httpx.Response(200, json={**JOB_ACCEPTED, "type": "NSO device fetch-ssh-keys"})
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_nso_device_action",
        {"action": "fetch_ssh_keys", "uuid": PE1_UUID},
    )
    assert nodes.call_count == 1 and action.call_count == 1
    assert sent(action) == {"filter": {"uuid": PE1_UUID}}
    data = json.loads(text)
    assert data["action"] == "fetch-ssh-keys" and data["pending"] is True
    assert data["type"] == "NSO device fetch-ssh-keys"


@pytest.mark.parametrize(
    ("tool", "args", "url"),
    [
        (
            "cnc_nso_device_action",
            {"action": "sync-from", "host_name": "PE1"},
            f"{NSO_BASE}/sync-from",
        ),
        ("cnc_nso_sync_to_device", {"host_name": "PE1"}, SYNC_TO_URL),
        ("cnc_sync_inventory_with_nso", {}, SYNC_URL),
    ],
)
@respx.mock
async def test_nso_action_post_is_not_retried_on_503(make_settings, tool, args, url):
    """A DLM action POST is sent exactly once even with retries enabled: a lost answer
    must not become a second job. (429 is the only status retried for every method.)"""
    mock_nodes(ONE_NODE)
    route = respx.post(url).mock(return_value=httpx.Response(503, text="Service Unavailable"))
    text = await call_tool_text(build(make_settings(enable_writes=True, max_retries=3)), tool, args)
    assert route.call_count == 1
    assert text.startswith("Error:") and "503" in text


@respx.mock
async def test_nso_device_action_underscore_name_and_uuid_selector(make_settings):
    nodes = mock_nodes(ONE_NODE)
    action = respx.post(f"{NSO_BASE}/sync-from").mock(
        return_value=httpx.Response(200, json={**JOB_ACCEPTED, "type": "NSO device sync-from"})
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_nso_device_action",
        {"action": "sync_from", "uuid": PE1_UUID},
    )
    assert sent(nodes)["filter"] == {"uuid": PE1_UUID}
    assert sent(action) == {"filter": {"uuid": PE1_UUID}}
    assert json.loads(text)["action"] == "sync-from"


@respx.mock
async def test_nso_device_action_wildcard_reports_every_match(make_settings):
    mock_nodes(TWO_NODES)
    action = respx.post(f"{NSO_BASE}/check-sync").mock(
        return_value=httpx.Response(200, json=JOB_ACCEPTED)
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_nso_device_action",
        {"action": "check-sync", "host_name": "P*"},
    )
    assert sent(action) == {"filter": {"host_name": "P*"}}
    data = json.loads(text)
    assert [d["host_name"] for d in data["matched_devices"]] == ["PE1", "P1"]
    assert data["matched_devices"][1]["nso_state_before"] == "CONNECT_FAILED"
    assert data["matched_devices"][1]["nso_timestamp_before"] == "1757772000"
    assert data["matched_total"] == 2 and "note" not in data
    assert (
        "one call per device, passing that device's nso_timestamp_before as after_timestamp "
        "(host_name=PE1, P1)"
    ) in data["next"]


@respx.mock
async def test_nso_device_action_wildcard_beyond_the_page_adds_a_note(make_settings):
    """result_count larger than the listed page: the DLM acts on all matches, the tool says so."""
    mock_nodes({"data": [PE1, P1], "total_count": 7, "result_count": 5})
    action = respx.post(f"{NSO_BASE}/connect").mock(
        return_value=httpx.Response(200, json=JOB_ACCEPTED)
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_nso_device_action",
        {"action": "connect", "host_name": "*"},
    )
    assert sent(action) == {"filter": {"host_name": "*"}}
    data = json.loads(text)
    assert data["matched_total"] == 5 and len(data["matched_devices"]) == 2
    assert data["note"] == (
        "The filter matches 5 devices; the DLM acts on all of them but only the first 2 "
        "are listed here."
    )


@respx.mock
async def test_nso_device_action_zero_match_refuses_and_never_posts(make_settings):
    mock_nodes(NO_NODES)
    action = respx.post(f"{NSO_BASE}/connect").mock(
        return_value=httpx.Response(200, json=JOB_ACCEPTED)
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_nso_device_action",
        {"action": "connect", "host_name": "ghost"},
    )
    assert text.startswith("Error: no device matches host_name 'ghost'")
    assert "nothing was sent to NSO" in text
    assert action.call_count == 0


@pytest.mark.parametrize("action", ["sync-to", "reboot"])
@respx.mock
async def test_nso_device_action_unknown_action_is_error_before_any_call(make_settings, action):
    nodes = mock_nodes(ONE_NODE)
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_nso_device_action",
        {"action": action, "host_name": "PE1"},
    )
    assert text.startswith("Error: Unknown NSO device action")
    assert "cnc_nso_sync_to_device" in text
    assert nodes.call_count == 0


@respx.mock
async def test_nso_device_action_requires_one_selector(make_settings):
    nodes = mock_nodes(ONE_NODE)
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_nso_device_action",
        {"action": "connect"},
    )
    assert text.startswith("Error:") and "exactly one" in text
    assert nodes.call_count == 0


@respx.mock
async def test_nso_device_action_job_failed_is_error(make_settings):
    mock_nodes(ONE_NODE)
    respx.post(f"{NSO_BASE}/sync-from").mock(return_value=httpx.Response(200, json=JOB_FAILED))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_nso_device_action",
        {"action": "sync-from", "host_name": "PE1"},
    )
    assert text.startswith("Error: NSO sync-from failed")
    assert "JOB_FAILED" in text and "NSO provider is not reachable" in text


@respx.mock
async def test_nso_device_action_job_rejected_is_error(make_settings):
    """JOB_REJECTED (documented RobotNodeJob state) is a failure, not a pending job."""
    mock_nodes(ONE_NODE)
    respx.post(f"{NSO_BASE}/connect").mock(
        return_value=httpx.Response(
            200,
            json={
                "job_id": "0c1d2e3f-1111-4222-8333-444455559999",
                "state": "JOB_REJECTED",
                "type": "NSO device connect",
                "error": "device is locked by another operation",
            },
        )
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_nso_device_action",
        {"action": "connect", "host_name": "PE1"},
    )
    assert text.startswith("Error: NSO connect failed")
    assert "JOB_REJECTED" in text and "device is locked by another operation" in text
    assert "pending" not in text


@respx.mock
async def test_nso_device_action_api_error_is_string(make_settings):
    mock_nodes(ONE_NODE)
    respx.post(f"{NSO_BASE}/compare-config").mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=0)),
        "cnc_nso_device_action",
        {"action": "compare-config", "host_name": "PE1"},
    )
    assert text.startswith("Error:") and "500" in text


@respx.mock
async def test_nso_device_action_non_envelope_answer_is_error(make_settings):
    mock_nodes(ONE_NODE)
    respx.post(f"{NSO_BASE}/connect").mock(return_value=httpx.Response(200, json={"ok": True}))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)),
        "cnc_nso_device_action",
        {"action": "connect", "host_name": "PE1"},
    )
    assert text.startswith("Error:") and "did not return a job envelope" in text


# --- cnc_nso_sync_to_device --------------------------------------------------


@respx.mock
async def test_nso_sync_to_device_posts_resolved_filter(make_settings):
    nodes = mock_nodes(ONE_NODE)
    action = respx.post(SYNC_TO_URL).mock(
        return_value=httpx.Response(200, json={**JOB_ACCEPTED, "type": "NSO device sync-to"})
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_nso_sync_to_device", {"host_name": "PE1"}
    )
    assert sent(nodes) == query_of({"host_name": "PE1"})
    assert sent(action) == {"filter": {"host_name": "PE1"}}
    data = json.loads(text)
    assert data["state"] == "JOB_ACCEPTED" and data["action"] == "sync-to"
    assert data["matched_devices"][0]["uuid"] == PE1_UUID
    assert data["matched_devices"][0]["nso_timestamp_before"] == "1757772000"
    assert "Asynchronous" in data["next"] and "after_timestamp='1757772000'" in data["next"]


@respx.mock
async def test_nso_sync_to_device_zero_match_never_posts(make_settings):
    mock_nodes(NO_NODES)
    action = respx.post(SYNC_TO_URL).mock(return_value=httpx.Response(200, json=JOB_ACCEPTED))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_nso_sync_to_device", {"uuid": "nope"}
    )
    assert text.startswith("Error: no device matches uuid 'nope'")
    assert action.call_count == 0


@respx.mock
async def test_nso_sync_to_device_job_failed_is_error(make_settings):
    mock_nodes(ONE_NODE)
    respx.post(SYNC_TO_URL).mock(
        return_value=httpx.Response(200, json={**JOB_FAILED, "type": "NSO device sync-to"})
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_nso_sync_to_device", {"host_name": "PE1"}
    )
    assert text.startswith("Error: NSO sync-to failed") and "NSO provider is not reachable" in text


# --- cnc_sync_inventory_with_nso ---------------------------------------------
# The 7.2 document (Nso_DLMNSOSync): "Input should be empty body, e.g. {} ...
# RobotNodeGetReq is just to satisfy API" — a global re-association, no device filter.


@respx.mock
async def test_sync_inventory_with_nso_is_global_and_synchronous(make_settings):
    nodes = mock_nodes(ONE_NODE)
    action = respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=JOB_SYNC_COMPLETED))
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_sync_inventory_with_nso", {}
    )
    assert nodes.call_count == 0  # nothing to resolve: there is no selector
    assert action.call_count == 1
    assert sent(action) == {}  # the documented empty body, never a device filter
    assert action.calls[0].request.headers["Content-Type"] == "application/json"
    data = json.loads(text)
    assert data["state"] == "JOB_COMPLETED" and data["completion_time"] == "1757772010"
    assert data["impacted_objects"] == [{"uuid": PE1_UUID, "name": "PE1"}]
    assert "pending" not in data and "Asynchronous" not in text
    assert data["action"] == "sync"
    assert data["scope"].startswith("the whole inventory")
    assert "body is ignored per the 7.2 API document" in data["scope"]
    assert data["next"].startswith("Completed synchronously")
    assert "cnc_check_device_nso_state" in data["next"]
    # It never claims a per-device scope.
    assert "matched_devices" not in data and "matched_total" not in data and "filter" not in data


@respx.mock
async def test_sync_inventory_with_nso_pending_points_at_per_device_checks(make_settings):
    respx.post(SYNC_URL).mock(
        return_value=httpx.Response(200, json={**JOB_ACCEPTED, "type": "NSO sync"})
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_sync_inventory_with_nso", {}
    )
    data = json.loads(text)
    assert data["pending"] is True
    assert "still running" in data["next"]
    assert "cnc_check_device_nso_state" in data["next"] and "after_timestamp" in data["next"]


@respx.mock
async def test_sync_inventory_with_nso_job_failed_is_error(make_settings):
    respx.post(SYNC_URL).mock(
        return_value=httpx.Response(200, json={**JOB_FAILED, "error": "policy has no provider"})
    )
    text = await call_tool_text(
        build(make_settings(enable_writes=True)), "cnc_sync_inventory_with_nso", {}
    )
    assert text.startswith("Error: Sync with NSO failed") and "policy has no provider" in text


@respx.mock
async def test_sync_inventory_with_nso_api_error_is_string(make_settings):
    respx.post(SYNC_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(enable_writes=True, max_retries=0)), "cnc_sync_inventory_with_nso", {}
    )
    assert text.startswith("Error:") and "500" in text


# --- cnc_wait_for_device_nso_state -------------------------------------------


@respx.mock
async def test_wait_for_device_nso_state_polls_until_synced(settings, fake_clock):
    started = {**PE1, "nso_state": "SYNC_FROM_STARTED"}
    route = mock_nodes(
        {"data": [{**started, "nso_state": "SYNC_FROM_SCHEDULED"}], "result_count": 1},
        {"data": [started], "result_count": 1},
        {"data": [PE1], "result_count": 1},
    )
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_device_nso_state",
        {"host_name": "PE1", "timeout_seconds": 60, "interval_seconds": 5},
    )
    assert route.call_count == 3
    assert sent(route) == query_of({"host_name": "PE1"})
    assert text.startswith(f"Device PE1 ({PE1_UUID}) reached nso_state SYNCED after 10s.")
    assert '"nso_state": "SYNCED"' in text and '"nso_providers"' in text


@respx.mock
async def test_wait_for_device_nso_state_connect_failed_is_error_with_message(settings, fake_clock):
    route = mock_nodes(
        {"data": [{**P1, "nso_state": "CONNECT_STARTED", "NsoMsg": ""}], "result_count": 1},
        {"data": [{**P1, "errors": ["connect failed"]}], "result_count": 1},
    )
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_device_nso_state",
        {"uuid": P1_UUID, "timeout_seconds": 120, "interval_seconds": 5},
    )
    assert route.call_count == 2
    assert text.startswith(
        f"Error: Device P1 ({P1_UUID}) ended in nso_state CONNECT_FAILED after 5s"
    )
    assert "(waiting for SYNCED)" in text
    assert f"NsoMsg: {CONNECT_FAILED_MSG}" in text
    assert "Device errors: connect failed" in text
    assert "XRd SSH flakiness" in text
    assert '"nso_state": "CONNECT_FAILED"' in text


@respx.mock
async def test_wait_for_device_nso_state_after_timestamp_ignores_stale_target(settings, fake_clock):
    """The race: right after JOB_ACCEPTED the first poll still reads the PRE-action state.

    A device that was SYNCED before a 'connect' must not be reported 'reached SYNCED
    after 0s' — the reading with the old nso_timestamp is skipped and the wait reports
    the second (post-action) one.
    """
    route = mock_nodes(
        {"data": [PE1], "result_count": 1},  # stale: SYNCED at 1757772000 (pre-action)
        {"data": [{**PE1, "nso_state": "CONNECT_STARTED", "nso_timestamp": "1757772031"}],
         "result_count": 1},
        {"data": [{**PE1, "nso_timestamp": "1757772034"}], "result_count": 1},
    )  # fmt: skip
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_device_nso_state",
        {
            "host_name": "PE1",
            "after_timestamp": "1757772000",
            "timeout_seconds": 60,
            "interval_seconds": 5,
        },
    )
    assert route.call_count == 3
    assert text.startswith(f"Device PE1 ({PE1_UUID}) reached nso_state SYNCED after 10s.")
    assert '"nso_timestamp": "1757772034"' in text


@respx.mock
async def test_wait_for_device_nso_state_after_timestamp_ignores_stale_failure(
    settings, fake_clock
):
    """A retried connect on a CONNECT_FAILED device: the first poll still shows the OLD
    failure with the OLD NsoMsg. It must be skipped, and the new outcome reported."""
    route = mock_nodes(
        {"data": [P1], "result_count": 1},  # stale CONNECT_FAILED + old message
        {"data": [{**P1, "nso_state": "SYNCED", "NsoMsg": "", "nso_timestamp": "1757772040"}],
         "result_count": 1},
    )  # fmt: skip
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_device_nso_state",
        {"uuid": P1_UUID, "after_timestamp": 1757772000, "timeout_seconds": 60},
    )
    assert route.call_count == 2
    assert text.startswith(f"Device P1 ({P1_UUID}) reached nso_state SYNCED after 5s.")
    assert CONNECT_FAILED_MSG not in text


@respx.mock
async def test_wait_for_device_nso_state_after_timestamp_reports_the_new_failure(
    settings, fake_clock
):
    """Same retry, but this time it fails again: the error carries the NEW message only."""
    new_msg = "NSO connect to the device failed: Failed to authenticate to device P1"
    route = mock_nodes(
        {"data": [P1], "result_count": 1},  # stale CONNECT_FAILED + old message
        {"data": [{**P1, "NsoMsg": new_msg, "nso_timestamp": "1757772040"}], "result_count": 1},
    )
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_device_nso_state",
        {"uuid": P1_UUID, "after_timestamp": "1757772000"},
    )
    assert route.call_count == 2
    assert text.startswith(
        f"Error: Device P1 ({P1_UUID}) ended in nso_state CONNECT_FAILED after 5s"
    )
    assert f"NsoMsg: {new_msg}" in text and CONNECT_FAILED_MSG not in text


@respx.mock
async def test_wait_for_device_nso_state_timeout_while_still_stale_says_not_started(
    settings, fake_clock
):
    route = mock_nodes({"data": [PE1], "result_count": 1})  # never moves off the old stamp
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_device_nso_state",
        {
            "host_name": "PE1",
            "after_timestamp": "1757772000",
            "timeout_seconds": 10,
            "interval_seconds": 5,
        },
    )
    assert route.call_count == 3
    assert not text.startswith("Error:")
    assert text.startswith(
        "Not SYNCED after 10s; nso_state=SYNCED is still the pre-action reading "
        "(nso_timestamp 1757772000 is not after after_timestamp 1757772000): "
        "the DLM has not started the action yet."
    )


@respx.mock
async def test_wait_for_device_nso_state_without_after_timestamp_keeps_the_old_behaviour(
    settings, fake_clock
):
    """Documented race: with no after_timestamp the first (possibly stale) reading counts."""
    route = mock_nodes({"data": [PE1], "result_count": 1})
    text = await call_tool_text(
        build(settings), "cnc_wait_for_device_nso_state", {"host_name": "PE1"}
    )
    assert route.call_count == 1
    assert text.startswith(f"Device PE1 ({PE1_UUID}) reached nso_state SYNCED after 0s.")


@respx.mock
async def test_wait_for_device_nso_state_bad_after_timestamp_is_error_before_any_call(settings):
    route = mock_nodes(ONE_NODE)
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_device_nso_state",
        {"host_name": "PE1", "after_timestamp": "2025-09-13T14:00:00Z"},
    )
    assert text.startswith("Error: after_timestamp must be the epoch value")
    assert route.call_count == 0


@respx.mock
async def test_wait_for_device_nso_state_not_synced_is_error_with_hint(settings, fake_clock):
    mock_nodes({"data": [{**PE1, "nso_state": "NOT_SYNCED", "NsoMsg": "out of sync"}],
                "result_count": 1})  # fmt: skip
    text = await call_tool_text(
        build(settings), "cnc_wait_for_device_nso_state", {"host_name": "PE1"}
    )
    assert text.startswith(f"Error: Device PE1 ({PE1_UUID}) ended in nso_state NOT_SYNCED")
    assert "compare-config" in text and "cnc_nso_sync_to_device" in text


@respx.mock
async def test_wait_for_device_nso_state_failure_state_in_target_is_success(settings, fake_clock):
    mock_nodes({"data": [{**PE1, "nso_state": "NOT_SYNCED"}], "result_count": 1})
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_device_nso_state",
        {"host_name": "PE1", "target": "synced,not_synced"},
    )
    assert text.startswith(f"Device PE1 ({PE1_UUID}) reached nso_state NOT_SYNCED after 0s.")


@respx.mock
async def test_wait_for_device_nso_state_timeout_is_not_an_error(settings, fake_clock):
    mock_nodes({"data": [{**PE1, "nso_state": "CONNECT_STARTED", "NsoMsg": "connecting"}],
                "result_count": 1})  # fmt: skip
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_device_nso_state",
        {"host_name": "PE1", "timeout_seconds": 10, "interval_seconds": 10},
    )
    assert not text.startswith("Error:")
    assert text.startswith(
        "Not SYNCED after 10s; current nso_state=CONNECT_STARTED, last message=connecting."
    )
    assert '"nso_state": "CONNECT_STARTED"' in text


@respx.mock
async def test_wait_for_device_nso_state_custom_targets_in_message(settings, fake_clock):
    mock_nodes({"data": [{**PE1, "nso_state": "CHECK_SYNC_STARTED"}], "result_count": 1})
    text = await call_tool_text(
        build(settings),
        "cnc_wait_for_device_nso_state",
        {
            "host_name": "PE1",
            "target": "MATCH,SYNCED",
            "timeout_seconds": 10,
            "interval_seconds": 10,
        },
    )
    assert text.startswith("Not MATCH,SYNCED after 10s; current nso_state=CHECK_SYNC_STARTED")


@respx.mock
async def test_wait_for_device_nso_state_unknown_target_is_error_before_any_call(settings):
    route = mock_nodes(ONE_NODE)
    text = await call_tool_text(
        build(settings), "cnc_wait_for_device_nso_state", {"host_name": "PE1", "target": "DONE"}
    )
    assert text.startswith("Error: Unknown nso_state value(s) DONE")
    assert route.call_count == 0


@respx.mock
async def test_wait_for_device_nso_state_missing_device_is_error(settings, fake_clock):
    mock_nodes(NO_NODES)
    text = await call_tool_text(
        build(settings), "cnc_wait_for_device_nso_state", {"host_name": "ghost"}
    )
    assert text.startswith("Error: no device matches host_name 'ghost'")


@respx.mock
async def test_wait_for_device_nso_state_ambiguous_selector_is_error(settings, fake_clock):
    mock_nodes(TWO_NODES)
    text = await call_tool_text(
        build(settings), "cnc_wait_for_device_nso_state", {"host_name": "P*"}
    )
    assert text.startswith("Error: host_name 'P*' matched 2 devices (PE1, P1, ...)")
    assert "exactly one" in text


@respx.mock
async def test_wait_for_device_nso_state_survives_a_gateway_503(make_settings, fake_clock):
    """The nodes/query read is retried, so one 503 does not abort the wait."""
    route = respx.post(NODES_QUERY_URL).mock(
        side_effect=[
            httpx.Response(503, text="Service Unavailable"),
            httpx.Response(200, json=ONE_NODE),
        ]
    )
    text = await call_tool_text(
        build(make_settings(max_retries=2)),
        "cnc_wait_for_device_nso_state",
        {"uuid": PE1_UUID, "timeout_seconds": 60, "interval_seconds": 5},
    )
    assert route.call_count == 2
    assert text.startswith(f"Device PE1 ({PE1_UUID}) reached nso_state SYNCED after 0s.")


@respx.mock
async def test_wait_for_device_nso_state_api_failure_is_error(make_settings, fake_clock):
    respx.post(NODES_QUERY_URL).mock(return_value=NATS_500)
    text = await call_tool_text(
        build(make_settings(max_retries=0)), "cnc_wait_for_device_nso_state", {"uuid": PE1_UUID}
    )
    assert text.startswith("Error:") and "500" in text


@respx.mock
async def test_sync_to_refuses_wildcards_and_multi_matches(make_settings):
    """The destructive push takes exactly one device: wildcards are refused before any call."""
    mcp = build(make_settings(enable_writes=True))
    two = {
        "data": [PE1, node("u-2", "PE2", "198.18.140.13")],
        "total_count": 2,
        "result_count": 2,
    }
    query = respx.post(NODES_QUERY_URL).mock(return_value=httpx.Response(200, json=two))
    action = respx.post(SYNC_TO_URL).mock(return_value=httpx.Response(200, json=JOB_ACCEPTED))
    text = await call_tool_text(mcp, "cnc_nso_sync_to_device", {"host_name": "PE*"})
    assert text.startswith("Error:") and "wildcards are refused" in text
    assert query.call_count == 0 and action.call_count == 0
    text = await call_tool_text(mcp, "cnc_nso_sync_to_device", {"uuid": PE1_UUID})
    assert text.startswith("Error:") and "exactly one device" in text
    assert query.call_count == 1 and action.call_count == 0
