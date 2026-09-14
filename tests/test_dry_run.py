"""Global dry-run mode (CNC_MCP_DRY_RUN=true) through the FULL server.

The server is built with ``build_server`` so the real write tools are wrapped:
a tool with a ``dry_run`` argument runs with it forced to true (respx sees the
``?dry-run=native`` request), any other write is recorded and never reaches the
platform (its respx route is not called), read tools are untouched. The
wrapper's own rules (JSON / Error answers unprefixed, the get_tool-failure
path) are covered on a minimal server in test_safety.py; the composites'
behaviour in this mode in test_tools_composite.py.
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
from cnc_mcp.safety import DRY_RUN_PREVIEW_SUFFIX, DRY_RUN_RECORDED_SUFFIX, AppContext
from cnc_mcp.server import build_server
from cnc_mcp.tools import register_all_tools
from tests.conftest import BASE_URL, call_tool_text

INVENTORY = f"{BASE_URL}/crosswork/inventory/v1"
SR_POLICY_CREATE = (
    f"{BASE_URL}/crosswork/nbi/optimization/v3/restconf/operations/"
    "cisco-crosswork-optimization-engine-sr-policy-operations:sr-policy-create"
)
NSO_DATA = f"{BASE_URL}/crosswork/proxy/nso/restconf/data"
L3VPN = f"{NSO_DATA}/ietf-l3vpn-ntw:l3vpn-ntw/vpn-services/vpn-service"
L3VPN_CLI = "vrf mcp-l3vpn-1\n address-family ipv4 unicast\n  import route-target\n   0:65091:91\n"
DRY_RUN_L3VPN = {"dry-run-result": {"native": {"device": [{"name": "PE1", "data": L3VPN_CLI}]}}}
L3VPN_ARGS = {
    "vpn_id": "mcp-l3vpn-1",
    "route_distinguisher": "0:65091:91",
    "route_target": "0:65091:91",
    "endpoints": json.dumps(
        [
            {
                "node": "PE1",
                "interface": "Loopback91",
                "address": "10.91.1.1",
                "prefix_length": 30,
                "local_as": 65000,
            }
        ]
    ),
}
SECRET = "S3cret-XYZ-9"
COMMUNITY = "c0mmunity-xyz"
BANNER = (
    "DRY-RUN MODE (CNC_MCP_DRY_RUN=true): nothing was committed — the answer below is the preview."
)


@pytest.fixture
def dry(make_settings) -> MCPServer:
    return build_server(make_settings(enable_writes=True, dry_run=True, max_retries=0))


async def test_writes_stay_registered_with_the_mode_in_their_descriptions(dry, make_settings):
    live = {t.name for t in await build_server(make_settings(enable_writes=True)).list_tools()}
    tools = {t.name: t for t in await dry.list_tools()}
    assert set(tools) == live  # dry-run mode hides nothing
    for name, tool in tools.items():
        if tool.annotations.read_only_hint:
            assert "DRY-RUN MODE" not in tool.description, name
        elif "dry_run" in tool.input_schema["properties"]:
            assert tool.description.endswith(f"\n\n{DRY_RUN_PREVIEW_SUFFIX}"), name
        else:
            assert tool.description.endswith(f"\n\n{DRY_RUN_RECORDED_SUFFIX}"), name
    assert tools["cnc_create_l3vpn_service"].description.endswith(DRY_RUN_PREVIEW_SUFFIX)
    assert tools["cnc_create_tag"].description.endswith(DRY_RUN_RECORDED_SUFFIX)
    assert tools["cnc_provision_l3vpn_e2e"].description.endswith(DRY_RUN_PREVIEW_SUFFIX)
    # The annotations and schemas are the originals'.
    assert tools["cnc_create_tag"].annotations.read_only_hint is False
    assert tools["cnc_create_l3vpn_service"].input_schema["additionalProperties"] is False


@respx.mock
async def test_dry_run_capable_write_is_forced_to_preview(dry):
    """cnc_create_l3vpn_service(dry_run=false) is sent as ?dry-run=native
    (service_provisioning.DRY_RUN_PARAMS): the CFP validates, NSO commits nothing."""
    put = respx.put(f"{L3VPN}=mcp-l3vpn-1").mock(
        return_value=httpx.Response(201, json=DRY_RUN_L3VPN)
    )
    text = await call_tool_text(dry, "cnc_create_l3vpn_service", {**L3VPN_ARGS, "dry_run": False})
    assert put.call_count == 1
    assert put.calls[0].request.url.params.get("dry-run") == "native"
    assert text.startswith(f"{BANNER}\n\nDry run only — nothing was committed")
    assert "vrf mcp-l3vpn-1" in text
    # Without the argument, and with dry_run=true, the same.
    for arguments in (L3VPN_ARGS, {**L3VPN_ARGS, "dry_run": True}):
        text = await call_tool_text(dry, "cnc_create_l3vpn_service", arguments)
        assert text.startswith(BANNER)
    assert all(c.request.url.params.get("dry-run") == "native" for c in put.calls)
    assert put.call_count == 3


@respx.mock
async def test_dry_run_capable_write_error_is_not_prefixed(dry):
    """The CFP's rejection of the preview stays an 'Error:' answer (the prefix is what
    callers key on), not a banner over an error."""
    respx.put(f"{L3VPN}=mcp-l3vpn-1").mock(
        return_value=httpx.Response(
            400,
            json={
                "ietf-restconf:errors": {
                    "error": [
                        {
                            "error-tag": "malformed-message",
                            "error-message": "STATUS_CODE: TSDN-L3VPN-415\nREASON: BGP routing "
                            "process is not configured on the device\nCATEGORY: validation",
                        }
                    ]
                }
            },
        )
    )
    text = await call_tool_text(dry, "cnc_create_l3vpn_service", L3VPN_ARGS)
    assert text.startswith("Error:") and "BGP" in text
    assert "DRY-RUN MODE" not in text


@respx.mock
async def test_write_without_a_preview_form_is_recorded_not_sent(dry):
    tags = respx.post(f"{INVENTORY}/tags").mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(dry, "cnc_create_tag", {"name": "site-a"})
    assert not tags.called
    assert text == (
        "NOT EXECUTED — DRY-RUN MODE (CNC_MCP_DRY_RUN=true): cnc_create_tag has no preview "
        "form, so the call was recorded, not sent. It would have run with: "
        '{"name": "site-a", "category": "default"}. Unset CNC_MCP_DRY_RUN to execute writes.'
    )
    # The recorded answer is not an error, and argument validation still runs first.
    assert not text.startswith("Error:")
    with pytest.raises(ToolError, match="unknown argument 'nam'"):
        await dry.call_tool("cnc_create_tag", {"nam": "site-a"})
    assert not tags.called


@respx.mock
async def test_recorded_answer_carries_the_preview_hint(dry):
    create = respx.post(SR_POLICY_CREATE).mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(
        dry,
        "cnc_create_sr_policy",
        {"headend": "PE1", "endpoint": "PE2", "color": 200, "path_name": "mcp-dyn-200"},
    )
    assert not create.called
    assert text.startswith(
        "NOT EXECUTED — DRY-RUN MODE (CNC_MCP_DRY_RUN=true): cnc_create_sr_policy"
    )
    assert '"headend": "PE1", "endpoint": "PE2", "color": 200, "path_name": "mcp-dyn-200"' in text
    assert "Preview instead: preview the computed path with cnc_dryrun_sr_policy." in text
    text = await call_tool_text(dry, "cnc_nso_sync_to_device", {"host_name": "PE1"})
    assert (
        "Preview instead: cnc_check_nso_device_sync (read-only) says whether the device "
        "differs from NSO's CDB; the diff itself is the compare-config device action — a "
        "write too, so it needs CNC_MCP_DRY_RUN unset, and it shows the diff in the CNC UI. "
        "Unset CNC_MCP_DRY_RUN to execute writes." in text
    )


async def test_every_dry_run_hint_names_a_tool_that_works_in_dry_run_mode(make_settings):
    """A hint is shown INSTEAD of executing a write in dry-run mode, so every tool it
    sends the agent to must answer in that mode: a read-only tool, or a write with its
    own dry_run argument (forced to preview). cnc_nso_sync_to_device used to point at
    cnc_nso_device_action compare-config, which is itself recorded, not run."""
    settings = make_settings(enable_writes=True, dry_run=True)
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    mcp = MCPServer("test")
    register_all_tools(mcp, ctx)
    schemas = {t.name: t.input_schema for t in await mcp.list_tools()}
    hinted = {name: r.dry_run_hint for name, r in ctx.tools.items() if r.dry_run_hint}
    assert {"cnc_nso_sync_to_device", "cnc_create_sr_policy", "cnc_update_sr_policy"} <= set(hinted)
    for name, hint in hinted.items():
        record = ctx.tools[name]
        assert not record.read_only and record.dry_run_form == "recorded", name
        named = re.findall(r"\bcnc_[a-z0-9_]+", hint)
        assert named, f"{name}: the hint names no tool"
        for target in named:
            assert target in ctx.tools and ctx.tools[target].registered, f"{name} -> {target}"
            works = ctx.tools[target].read_only or "dry_run" in schemas[target]["properties"]
            assert works, f"{name}: hint sends the agent to {target}, which is recorded too"


@respx.mock
async def test_recorded_answer_never_echoes_secrets(dry):
    """cnc_create_credential_profile / cnc_update_credential_profile take passwords and
    communities: the echo shows *** for them, and nothing reaches the platform."""
    query = respx.post(f"{INVENTORY}/credentials/query").mock(
        return_value=httpx.Response(200, json={"total_count": 0})
    )
    write = respx.post(f"{INVENTORY}/credentials").mock(return_value=httpx.Response(200, json={}))
    arguments = {
        "profile": "lab",
        "ssh_username": "cisco",
        "ssh_password": SECRET,
        "snmpv2_read_community": COMMUNITY,
        "enable_password": SECRET,
    }
    text = await call_tool_text(dry, "cnc_create_credential_profile", arguments)
    assert not query.called and not write.called  # not even the safety read
    assert SECRET not in text and COMMUNITY not in text
    assert (
        '"profile": "lab", "ssh_username": "cisco", "ssh_password": "***"' in text
        and '"snmpv2_read_community": "***"' in text
        and '"enable_password": "***"' in text
    )
    update = respx.put(f"{INVENTORY}/credentials").mock(return_value=httpx.Response(200, json={}))
    text = await call_tool_text(
        dry,
        "cnc_update_credential_profile",
        {"profile": "lab", "gnmi_username": "cisco", "gnmi_password": SECRET},
    )
    assert not update.called and not query.called
    assert SECRET not in text and '"gnmi_password": "***"' in text


@respx.mock
async def test_recorded_answer_withholds_free_text_bodies_named_in_redact(dry):
    """The argument-name markers cannot see a secret inside a configlet ('username
    ... password', 'snmp-server community'), template variables or a webhook URL's
    userinfo: those tools name the arguments in register_tool(redact=...), and the
    recorded answer summarises each by size instead of echoing it."""
    config = f"{BASE_URL}/crosswork/config/v1"
    routes = [
        respx.post(f"{config}/templates").mock(return_value=httpx.Response(200, json={})),
        respx.post(f"{config}/templates/deploy-template").mock(
            return_value=httpx.Response(200, json={})
        ),
        respx.post(
            f"{BASE_URL}/crosswork/notification/restconf/data/v2/notifications:subscription"
        ).mock(return_value=httpx.Response(200, json={})),
        respx.post(f"{INVENTORY}/nodes/query").mock(
            return_value=httpx.Response(200, json={"data": [], "total_count": 0})
        ),
    ]
    configlet = f"username admin secret {SECRET}\nsnmp-server community {COMMUNITY} RO\n"
    variables = json.dumps({"tacacs_key": SECRET, "vrf": "mgmt"})
    text = await call_tool_text(
        dry,
        "cnc_create_config_template",
        {"name": "mcp-aaa", "configlet": configlet, "variables": variables},
    )
    assert text.startswith(
        "NOT EXECUTED — DRY-RUN MODE (CNC_MCP_DRY_RUN=true): cnc_create_config_template"
    )
    assert SECRET not in text and COMMUNITY not in text and "username admin" not in text
    assert f'"configlet": "<withheld: {len(configlet)} chars>"' in text
    assert f'"variables": "<withheld: {len(variables)} chars>"' in text
    assert '"name": "mcp-aaa"' in text  # the harmless arguments are still echoed

    text = await call_tool_text(
        dry,
        "cnc_deploy_config_template",
        {"name": "mcp-aaa", "host_name": "PE1", "variables": variables},
    )
    assert SECRET not in text and f'"variables": "<withheld: {len(variables)} chars>"' in text
    assert '"host_name": "PE1"' in text

    url = f"https://hook:{SECRET}@sink.example:443/crosswork"
    text = await call_tool_text(
        dry, "cnc_create_webhook_subscription", {"client_url": url, "topic": "alarm"}
    )
    assert SECRET not in text and f'"client_url": "<withheld: {len(url)} chars>"' in text
    assert '"topic": "alarm"' in text
    # The tool's default ('' — no variables) is summarised like any value, and nothing
    # was sent to the platform by any of the calls.
    text = await call_tool_text(dry, "cnc_deploy_config_template", {"name": "mcp-aaa"})
    assert '"variables": "<withheld: 0 chars>"' in text
    assert not any(route.called for route in routes)


@respx.mock
async def test_read_tools_are_untouched(dry):
    query = respx.post(f"{INVENTORY}/nodes/query").mock(
        return_value=httpx.Response(200, json={"data": [], "total_count": 0})
    )
    text = await call_tool_text(dry, "cnc_list_devices", {"response_format": "json"})
    assert query.called
    assert json.loads(text)["items"] == [] and json.loads(text)["count"] == 0
    assert "DRY-RUN" not in text
