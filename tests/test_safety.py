"""register_tool(): write gating and strict argument names, on a minimal server.

The real tool set is covered by test_server_safety.py; here a three-tool server
isolates what register_tool itself adds on top of @mcp.tool.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import Annotated

import pytest
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.mcpserver.tools.tool_manager import ToolManager
from pydantic import AfterValidator, Field
from pydantic_core import PydanticCustomError

from cnc_mcp.safety import AppContext, describe_unknown_arguments, register_tool
from tests.conftest import call_tool_text


def build(make_settings, *, enable_writes: bool = False) -> tuple[MCPServer, AppContext]:
    mcp = MCPServer("test")
    ctx = AppContext(settings=make_settings(enable_writes=enable_writes), client=object())  # type: ignore[arg-type]

    @register_tool(mcp, ctx, name="cnc_echo", title="Echo", read_only=True)
    async def echo(
        host_name: Annotated[str | None, Field(description="e.g. PE1")] = None,
        page_size: Annotated[int, Field(ge=1, le=10)] = 5,
        schema: Annotated[str, Field(description="shadows BaseModel.schema")] = "CPU",
    ) -> str:
        return f"host_name={host_name} page_size={page_size} schema={schema}"

    @register_tool(
        mcp, ctx, name="cnc_delete_thing", title="Delete", read_only=False, destructive=True
    )
    async def delete_thing(uuid: Annotated[str, Field(min_length=1)]) -> str:
        return f"deleted {uuid}"

    @register_tool(mcp, ctx, name="cnc_create_profile", title="Create", read_only=False)
    async def create_profile(
        profile: Annotated[str, Field(min_length=1)],
        password: Annotated[str | None, Field(description="e.g. s3cret")] = None,
    ) -> str:
        return f"created {profile}"

    return mcp, ctx


# --- write gating ---------------------------------------------------------------


async def test_write_tool_hidden_unless_writes_enabled(make_settings):
    mcp, _ = build(make_settings, enable_writes=False)
    assert {t.name for t in await mcp.list_tools()} == {"cnc_echo"}
    mcp, _ = build(make_settings, enable_writes=True)
    tools = {t.name: t for t in await mcp.list_tools()}
    assert set(tools) == {"cnc_echo", "cnc_delete_thing", "cnc_create_profile"}
    assert tools["cnc_delete_thing"].annotations.destructive_hint is True
    assert tools["cnc_create_profile"].annotations.destructive_hint is False
    assert tools["cnc_echo"].annotations.read_only_hint is True


# --- unknown argument names ------------------------------------------------------


async def test_unknown_argument_is_rejected_by_name_with_hint(make_settings):
    mcp, _ = build(make_settings)
    with pytest.raises(ToolError) as info:
        await mcp.call_tool("cnc_echo", {"host_names": "PE1,PE2"})
    text = str(info.value)
    assert "unknown argument 'host_names'" in text
    assert "did you mean 'host_name'?" in text
    assert "accepted: host_name, page_size, schema" in text
    # The unknown key's value is not echoed back (it may be a credential on other tools).
    assert "PE1,PE2" not in text


async def test_unknown_argument_without_close_match_still_named(make_settings):
    mcp, _ = build(make_settings)
    with pytest.raises(ToolError) as info:
        await mcp.call_tool("cnc_echo", {"host_name": "PE1", "zzz": 1, "colour": "red"})
    text = str(info.value)
    assert "unknown arguments 'zzz', 'colour'" in text
    assert "did you mean" not in text


async def test_known_arguments_unaffected(make_settings):
    mcp, _ = build(make_settings)
    assert await call_tool_text(mcp, "cnc_echo", {}) == "host_name=None page_size=5 schema=CPU"
    out = await call_tool_text(mcp, "cnc_echo", {"host_name": "PE1", "page_size": 2, "schema": "X"})
    assert out == "host_name=PE1 page_size=2 schema=X"


async def test_field_errors_keep_pydantic_report_with_input_echo(make_settings):
    """A per-field error is pydantic's own report: field name, message, input echo, URL."""
    mcp, _ = build(make_settings)
    with pytest.raises(ToolError) as info:
        await mcp.call_tool("cnc_echo", {"page_size": 99})
    text = str(info.value)
    assert "page_size" in text
    assert "Input should be less than or equal to 10" in text
    assert "input_value=99, input_type=int" in text
    assert "https://errors.pydantic.dev/" in text


async def test_field_errors_reported_alongside_unknown_arguments(make_settings):
    """Unknown keys and field errors surface in one round trip; only the unknown
    key's value is withheld."""
    mcp, _ = build(make_settings)
    with pytest.raises(ToolError) as info:
        await mcp.call_tool("cnc_echo", {"page_size": 99, "zzz": "s3cret"})
    text = str(info.value)
    assert "2 validation errors" in text
    assert "unknown argument 'zzz'" in text
    assert "input_value=99, input_type=int" in text
    assert "https://errors.pydantic.dev/" in text  # the field error keeps its known type
    assert "s3cret" not in text


async def test_missing_required_argument_does_not_echo_the_other_arguments(make_settings):
    """pydantic's 'missing' error carries the whole argument dict as its input; that
    echo (a password included) is withheld while the field name and message stay."""
    mcp, _ = build(make_settings, enable_writes=True)
    with pytest.raises(ToolError) as info:
        await mcp.call_tool("cnc_create_profile", {"password": "s3cret"})
    text = str(info.value)
    assert "profile" in text
    assert "Field required" in text
    assert "s3cret" not in text
    with pytest.raises(ToolError, match="uuid"):
        await mcp.call_tool("cnc_delete_thing", {})


def only_red(value: str) -> str:
    if value != "red":
        raise PydanticCustomError("not_red", "colour {given} is not red", {"given": value})
    return value


async def test_custom_validator_errors_survive_the_rebuild(make_settings):
    """A validator's own error type (not one pydantic knows) keeps its message when
    it is rebuilt next to an unknown-argument error."""
    mcp = MCPServer("test")
    ctx = AppContext(settings=make_settings(), client=object())  # type: ignore[arg-type]

    @register_tool(mcp, ctx, name="cnc_custom", title="Custom", read_only=True)
    async def custom(colour: Annotated[str, AfterValidator(only_red), Field()] = "red") -> str:
        return colour

    assert await call_tool_text(mcp, "cnc_custom", {"colour": "red"}) == "red"
    with pytest.raises(ToolError) as info:
        await mcp.call_tool("cnc_custom", {"colour": "blue", "colours": "green"})
    text = str(info.value)
    assert "unknown argument 'colours' (did you mean 'colour'?)" in text
    assert "colour blue is not red [type=not_red, input_value='blue', input_type=str]" in text
    assert "green" not in text


async def test_schema_publishes_additional_properties_false(make_settings):
    mcp, _ = build(make_settings, enable_writes=True)
    for tool in await mcp.list_tools():
        assert tool.input_schema.get("additionalProperties") is False, tool.name
    echo = next(t for t in await mcp.list_tools() if t.name == "cnc_echo")
    # The wire names (alias 'schema', not the SDK's internal 'field_schema') are what is published.
    assert set(echo.input_schema["properties"]) == {"host_name", "page_size", "schema"}
    assert echo.input_schema["title"] == "echoArguments"


@pytest.mark.parametrize(
    "get_tool",
    [
        pytest.param(lambda self, name: None, id="tool-not-found"),
        pytest.param(lambda self, name: SimpleNamespace(parameters={}), id="no-fn_metadata"),
    ],
)
async def test_sdk_internals_missing_keeps_registration(
    make_settings, monkeypatch, caplog, get_tool
):
    """Without the SDK hooks the tool still registers and works, with a logged warning.

    The SDK seam is patched only for the registration: ToolManager.get_tool answers
    None (LookupError) or a Tool without fn_metadata (AttributeError).
    """
    mcp = MCPServer("test")
    ctx = AppContext(settings=make_settings(), client=object())  # type: ignore[arg-type]

    with caplog.at_level(logging.WARNING, logger="cnc_mcp.safety"), monkeypatch.context() as m:
        m.setattr(ToolManager, "get_tool", get_tool)

        @register_tool(mcp, ctx, name="cnc_plain", title="Plain", read_only=True)
        async def plain(x: Annotated[int, Field()] = 1) -> str:
            return f"x={x}"

    assert "cnc_plain keeps the SDK's default argument handling" in caplog.text
    assert await call_tool_text(mcp, "cnc_plain", {"x": 2, "extra": 1}) == "x=2"
    (tool,) = await mcp.list_tools()
    assert "additionalProperties" not in tool.input_schema


def test_describe_unknown_arguments():
    accepted = ["host_name", "response_format", "uuid"]
    assert (
        describe_unknown_arguments(["host_names"], accepted)
        == "unknown argument 'host_names' (did you mean 'host_name'?); "
        "accepted: host_name, response_format, uuid"
    )
    assert describe_unknown_arguments(["q", "uuids"], accepted).startswith(
        "unknown arguments 'q', 'uuids' (did you mean 'uuid'?);"
    )
