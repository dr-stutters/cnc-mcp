"""Server wiring and write-safety gating."""

from __future__ import annotations

from cnc_mcp.server import build_instructions, build_server

READ_TOOLS = {"cnc_list_widgets", "cnc_get_widget"}
WRITE_TOOLS = {"cnc_create_widget", "cnc_delete_widget"}


async def test_write_tools_hidden_by_default(make_settings):
    mcp = build_server(make_settings(enable_writes=False))
    names = {tool.name for tool in await mcp.list_tools()}
    assert READ_TOOLS <= names
    assert not (WRITE_TOOLS & names)


async def test_write_tools_registered_when_enabled(make_settings):
    mcp = build_server(make_settings(enable_writes=True))
    names = {tool.name for tool in await mcp.list_tools()}
    assert READ_TOOLS | WRITE_TOOLS <= names


async def test_annotations_present(make_settings):
    mcp = build_server(make_settings(enable_writes=True))
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    list_tool = tools["cnc_list_widgets"]
    assert list_tool.annotations is not None
    assert list_tool.annotations.read_only_hint is True
    delete_tool = tools["cnc_delete_widget"]
    assert delete_tool.annotations.read_only_hint is False
    assert delete_tool.annotations.destructive_hint is True


def test_instructions_state_write_mode(make_settings):
    assert "READ-ONLY" in build_instructions(make_settings(enable_writes=False))
    assert "ENABLED" in build_instructions(make_settings(enable_writes=True))
