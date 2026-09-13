"""Server wiring and write-safety gating across the real tool set."""

from __future__ import annotations

import logging

from cnc_mcp.server import build_instructions, build_server, quiet_http_logging

READ_TOOLS = {
    "cnc_list_devices",
    "cnc_get_device",
    "cnc_list_credential_profiles",
    "cnc_list_providers",
    "cnc_get_topology_summary",
    "cnc_list_topology_nodes",
    "cnc_get_topology_link",
    "cnc_list_sr_policies",
    "cnc_get_te_summary",
    "cnc_list_alarms",
}
WRITE_TOOLS = {
    "cnc_create_device",
    "cnc_update_device",
    "cnc_delete_device",
    "cnc_create_credential_profile",
    "cnc_delete_credential_profile",
    "cnc_create_provider",
    "cnc_delete_provider",
}


async def test_write_tools_hidden_by_default(make_settings):
    mcp = build_server(make_settings(enable_writes=False))
    names = {tool.name for tool in await mcp.list_tools()}
    assert READ_TOOLS <= names
    assert not (WRITE_TOOLS & names)


async def test_write_tools_registered_when_enabled(make_settings):
    mcp = build_server(make_settings(enable_writes=True))
    names = {tool.name for tool in await mcp.list_tools()}
    assert READ_TOOLS | WRITE_TOOLS <= names


async def test_every_tool_has_annotations_and_docs(make_settings):
    mcp = build_server(make_settings(enable_writes=True))
    tools = await mcp.list_tools()
    assert len(tools) >= 25
    for tool in tools:
        assert tool.name.startswith("cnc_"), tool.name
        assert tool.annotations is not None, tool.name
        assert tool.description and len(tool.description) > 40, tool.name
        # Flat parameters: enum $refs (ResponseFormat) are fine, object models are not.
        defs = tool.input_schema.get("$defs", {})
        for prop_name, prop in tool.input_schema.get("properties", {}).items():
            ref = prop.get("$ref", "")
            if ref:
                target = defs.get(ref.rsplit("/", 1)[-1], {})
                assert target.get("type") != "object", f"{tool.name}.{prop_name} wraps a model"


async def test_destructive_annotations(make_settings):
    mcp = build_server(make_settings(enable_writes=True))
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    assert tools["cnc_list_devices"].annotations.read_only_hint is True
    for name in ("cnc_delete_device", "cnc_delete_credential_profile", "cnc_delete_provider"):
        assert tools[name].annotations.read_only_hint is False, name
        assert tools[name].annotations.destructive_hint is True, name
    assert tools["cnc_create_device"].annotations.destructive_hint is False


def test_instructions_state_write_mode(make_settings):
    assert "READ-ONLY" in build_instructions(make_settings(enable_writes=False))
    assert "ENABLED" in build_instructions(make_settings(enable_writes=True))


def test_http_client_loggers_never_log_request_urls():
    """The CAS leg-2 URL carries the TGT; httpx must not log it even at DEBUG."""
    logging.getLogger("httpx").setLevel(logging.DEBUG)
    quiet_http_logging()
    assert not logging.getLogger("httpx").isEnabledFor(logging.INFO)
    assert not logging.getLogger("httpcore").isEnabledFor(logging.INFO)
