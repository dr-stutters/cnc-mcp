"""register_tool(): write gating, area allowlists, disabled tools, global dry-run mode
and strict argument names, on a minimal server.

The real tool set is covered by test_server_safety.py and test_dry_run.py; here a
small server isolates what register_tool itself adds on top of @mcp.tool. The tools
defined in this module belong to the area ``test_safety`` (their module's name).
"""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace
from typing import Annotated, Any

import pytest
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.mcpserver.tools.tool_manager import ToolManager
from pydantic import AfterValidator, Field
from pydantic_core import PydanticCustomError

from cnc_mcp.safety import (
    DRY_RUN_PREVIEW_SUFFIX,
    DRY_RUN_RECORDED_SUFFIX,
    NOT_EXECUTED_MAX_CHARS,
    AppContext,
    ToolRecord,
    absent_tool_reasons,
    describe_unknown_arguments,
    not_executed_text,
    redact_arguments,
    register_tool,
    safety_mode_lines,
    tool_area,
)
from tests.conftest import call_tool_text

AREA = "test_safety"  # this module's name: the area of every tool defined here
SENT: list[tuple[str, dict[str, Any]]] = []  # what the write tools "sent" to the platform


def build(
    make_settings, *, enable_writes: bool = False, **overrides: Any
) -> tuple[MCPServer, AppContext]:
    mcp = MCPServer("test")
    settings = make_settings(enable_writes=enable_writes, **overrides)
    ctx = AppContext(settings=settings, client=object())  # type: ignore[arg-type]

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
        SENT.append(("cnc_delete_thing", {"uuid": uuid}))
        return f"deleted {uuid}"

    @register_tool(
        mcp,
        ctx,
        name="cnc_create_profile",
        title="Create",
        read_only=False,
        dry_run_hint="cnc_get_profile shows what exists",
    )
    async def create_profile(
        profile: Annotated[str, Field(min_length=1)],
        password: Annotated[str | None, Field(description="e.g. s3cret")] = None,
        snmp_community: Annotated[str | None, Field(description="e.g. public")] = None,
    ) -> str:
        SENT.append(("cnc_create_profile", {"profile": profile, "password": password}))
        return f"created {profile}"

    @register_tool(mcp, ctx, name="cnc_provision_thing", title="Provision", read_only=False)
    async def provision_thing(
        name: Annotated[str, Field(min_length=1)],
        dry_run: Annotated[bool, Field(description="preview only")] = False,
        response_format: Annotated[str, Field(description="markdown|json")] = "markdown",
    ) -> str:
        """Provision a thing."""
        if name == "boom":
            return "Error: the CFP rejected it"
        SENT.append(("cnc_provision_thing", {"name": name, "dry_run": dry_run}))
        if response_format == "json":
            return json.dumps({"name": name, "dry_run": dry_run})
        return f"{'Dry run only' if dry_run else 'Committed'}: {name}"

    @register_tool(
        mcp,
        ctx,
        name="cnc_playbook",
        title="Playbook",
        read_only=False,
        requires=("cnc_provision_thing",),
    )
    async def playbook(name: Annotated[str, Field(min_length=1)]) -> str:
        return f"playbook {name}"

    @register_tool(
        mcp,
        ctx,
        name="cnc_push_config",
        title="Push config",
        read_only=False,
        redact=("configlet", "variables"),
    )
    async def push_config(
        name: Annotated[str, Field(min_length=1)],
        configlet: Annotated[str, Field(description="device config text")],
        variables: Annotated[str | None, Field(description="JSON object")] = None,
    ) -> str:
        SENT.append(("cnc_push_config", {"name": name}))
        return f"pushed {name}"

    return mcp, ctx


@pytest.fixture(autouse=True)
def _clear_sent():
    SENT.clear()
    yield
    SENT.clear()


async def names(mcp: MCPServer) -> set[str]:
    return {t.name for t in await mcp.list_tools()}


ALL = {
    "cnc_echo",
    "cnc_delete_thing",
    "cnc_create_profile",
    "cnc_provision_thing",
    "cnc_playbook",
    "cnc_push_config",
}


# --- write gating ---------------------------------------------------------------


async def test_write_tool_hidden_unless_writes_enabled(make_settings, caplog):
    with caplog.at_level(logging.INFO, logger="cnc_mcp.safety"):
        mcp, ctx = build(make_settings, enable_writes=False)
    assert await names(mcp) == {"cnc_echo"}
    assert "Tool cnc_delete_thing not registered (enable_writes is false)" in caplog.text
    # The playbook's own reason is the write gate, not its missing sibling.
    assert ctx.tools["cnc_playbook"].skipped_reason == "enable_writes is false"
    mcp, _ = build(make_settings, enable_writes=True)
    tools = {t.name: t for t in await mcp.list_tools()}
    assert set(tools) == ALL
    assert tools["cnc_delete_thing"].annotations.destructive_hint is True
    assert tools["cnc_create_profile"].annotations.destructive_hint is False
    assert tools["cnc_echo"].annotations.read_only_hint is True


# --- the registry ------------------------------------------------------------------


def test_tool_area_is_the_defining_module():
    async def fn() -> str:
        return ""

    assert tool_area(fn) == AREA
    fn.__module__ = "cnc_mcp.tools.devices"
    assert tool_area(fn) == "devices"


async def test_every_register_tool_call_is_recorded(make_settings):
    _, ctx = build(make_settings, enable_writes=False)
    assert set(ctx.tools) == ALL
    assert ctx.tools["cnc_echo"] == ToolRecord(
        name="cnc_echo", area=AREA, read_only=True, destructive=False, registered=True
    )
    assert ctx.tools["cnc_delete_thing"] == ToolRecord(
        name="cnc_delete_thing",
        area=AREA,
        read_only=False,
        destructive=True,
        registered=False,
        skipped_reason="enable_writes is false",
    )
    # The register_tool arguments startup validation and the tests reason about.
    assert ctx.tools["cnc_playbook"].requires == ("cnc_provision_thing",)
    assert ctx.tools["cnc_create_profile"].dry_run_hint == "cnc_get_profile shows what exists"
    assert ctx.tools["cnc_echo"].requires == () and ctx.tools["cnc_echo"].dry_run_hint is None
    _, ctx = build(make_settings, enable_writes=True)
    assert all(r.registered and r.skipped_reason is None for r in ctx.tools.values())
    assert all(r.dry_run_form is None for r in ctx.tools.values())  # not in dry-run mode
    assert AppContext(settings=make_settings(), client=object()).tools == {}  # type: ignore[arg-type]


def test_registering_a_tool_name_twice_is_an_error(make_settings):
    """The SDK keeps the FIRST tool on a duplicate add; wrapping the second (dry-run,
    strict arguments) would then act on a tool whose schema is the first's."""
    mcp, ctx = build(make_settings, enable_writes=True)
    with pytest.raises(ValueError, match=f"tool cnc_echo registered twice \\(areas {AREA} and"):

        @register_tool(mcp, ctx, name="cnc_echo", title="Echo again", read_only=True)
        async def echo_again() -> str:
            return ""

    assert ctx.tools["cnc_echo"].registered is True  # the first record stands untouched


def test_absent_tool_reasons_quote_the_registry(make_settings):
    """What the prompts say about a write tool that is missing from the tool list:
    the reason that actually applies, not a blanket 'set ENABLE_WRITES'."""
    _, ctx = build(make_settings, enable_writes=False)
    assert absent_tool_reasons(ctx, ["cnc_delete_thing", "cnc_echo", "cnc_nope"]) == {
        "cnc_delete_thing": "enable_writes is false",
        "cnc_nope": "not a tool of this build",
    }
    _, ctx = build(
        make_settings, enable_writes=True, write_areas="other", disabled_tools="cnc_echo"
    )
    assert absent_tool_reasons(ctx, ["cnc_delete_thing", "cnc_echo", "cnc_playbook"]) == {
        "cnc_delete_thing": f"area '{AREA}' is not in CNC_MCP_WRITE_AREAS (other)",
        "cnc_echo": "disabled by CNC_MCP_DISABLED_TOOLS",
        "cnc_playbook": f"area '{AREA}' is not in CNC_MCP_WRITE_AREAS (other)",
    }
    _, ctx = build(make_settings, enable_writes=True, disabled_tools="cnc_provision_thing")
    assert absent_tool_reasons(ctx, ["cnc_playbook"]) == {
        "cnc_playbook": f"needs cnc_provision_thing (area {AREA})"
    }
    # Dry-run mode registers the writes: nothing is absent, the form says how they answer.
    _, ctx = build(make_settings, enable_writes=True, dry_run=True)
    assert absent_tool_reasons(ctx, ALL) == {}
    assert ctx.tools["cnc_provision_thing"].dry_run_form == "preview"
    assert ctx.tools["cnc_delete_thing"].dry_run_form == "recorded"
    assert ctx.tools["cnc_echo"].dry_run_form is None


def test_safety_mode_lines_state_the_mode(make_settings):
    """Shared by the instructions and the prompts (moved here from server.py so the
    prompts can import it without a circular import); the wording is checked on the
    instructions in test_server_safety.py."""
    assert safety_mode_lines(make_settings())[0].startswith("This server is READ-ONLY")
    lines = safety_mode_lines(
        make_settings(enable_writes=True, dry_run=True, write_areas="fault", disabled_tools="cnc_x")
    )
    assert len(lines) == 3
    assert lines[0].startswith(
        "Write tools are ENABLED only for the areas fault (CNC_MCP_WRITE_AREAS)"
    )
    assert lines[1].startswith("DRY-RUN MODE is active (CNC_MCP_DRY_RUN=true)")
    assert lines[2].startswith("1 tool is disabled by configuration (CNC_MCP_DISABLED_TOOLS)")
    # Dry-run without writes is moot; the disabled line stands alone with the read-only one.
    assert len(safety_mode_lines(make_settings(dry_run=True, disabled_tools="cnc_x"))) == 2


# --- disabled tools ----------------------------------------------------------------


async def test_disabled_tools_are_never_registered_read_or_write(make_settings, caplog):
    with caplog.at_level(logging.INFO, logger="cnc_mcp.safety"):
        mcp, ctx = build(
            make_settings, enable_writes=True, disabled_tools="CNC_ECHO, cnc_delete_thing"
        )
    assert await names(mcp) == ALL - {"cnc_echo", "cnc_delete_thing"}
    assert "Tool cnc_echo not registered (disabled by CNC_MCP_DISABLED_TOOLS)" in caplog.text
    assert ctx.tools["cnc_echo"].skipped_reason == "disabled by CNC_MCP_DISABLED_TOOLS"
    # Disabled wins over the write gate: the reason names the policy, not the gate.
    _, ctx = build(make_settings, enable_writes=False, disabled_tools="cnc_delete_thing")
    assert ctx.tools["cnc_delete_thing"].skipped_reason == "disabled by CNC_MCP_DISABLED_TOOLS"


# --- write areas -------------------------------------------------------------------


async def test_write_areas_gate_writes_by_the_defining_module(make_settings, caplog):
    mcp, ctx = build(make_settings, enable_writes=True, write_areas=f"other, {AREA.upper()}")
    assert await names(mcp) == ALL
    with caplog.at_level(logging.INFO, logger="cnc_mcp.safety"):
        mcp, ctx = build(make_settings, enable_writes=True, write_areas="other")
    assert await names(mcp) == {"cnc_echo"}  # reads are never area-gated
    reason = ctx.tools["cnc_delete_thing"].skipped_reason
    assert reason == f"area '{AREA}' is not in CNC_MCP_WRITE_AREAS (other)"
    assert f"Tool cnc_delete_thing not registered ({reason})" in caplog.text
    # Without writes the areas are irrelevant (and the reason is the write gate).
    _, ctx = build(make_settings, enable_writes=False, write_areas=AREA)
    assert ctx.tools["cnc_delete_thing"].skipped_reason == "enable_writes is false"


# --- requires ----------------------------------------------------------------------


async def test_tool_requiring_an_unregistered_sibling_is_skipped(make_settings, caplog):
    with caplog.at_level(logging.INFO, logger="cnc_mcp.safety"):
        mcp, ctx = build(make_settings, enable_writes=True, disabled_tools="cnc_provision_thing")
    assert "cnc_playbook" not in await names(mcp)
    assert ctx.tools["cnc_playbook"].skipped_reason == f"needs cnc_provision_thing (area {AREA})"
    assert f"Tool cnc_playbook not registered (needs cnc_provision_thing (area {AREA}))" in (
        caplog.text
    )
    mcp, _ = build(make_settings, enable_writes=True)
    assert "cnc_playbook" in await names(mcp)


async def test_requires_is_resolved_in_registration_order(make_settings):
    """A required tool with no record yet (defined later, or a typo) reads 'area
    unknown' and the requiring tool is skipped: tools.validate_gating turns that into
    a startup failure for the real modules (test_server_safety.py)."""
    mcp, ctx = build(make_settings, enable_writes=True)

    @register_tool(
        mcp, ctx, name="cnc_early", title="Early", read_only=False, requires=("cnc_late",)
    )
    async def early() -> str:
        return ""

    @register_tool(mcp, ctx, name="cnc_late", title="Late", read_only=False)
    async def late() -> str:
        return ""

    assert "cnc_late" in await names(mcp) and "cnc_early" not in await names(mcp)
    assert ctx.tools["cnc_early"].skipped_reason == "needs cnc_late (area unknown)"
    assert ctx.tools["cnc_early"].requires == ("cnc_late",)


# --- global dry-run mode -----------------------------------------------------------


async def test_dry_run_forces_the_preview_and_prefixes_the_answer(make_settings):
    mcp, ctx = build(make_settings, enable_writes=True, dry_run=True)
    assert await names(mcp) == ALL  # the writes stay registered
    assert all(r.registered for r in ctx.tools.values())
    text = await call_tool_text(mcp, "cnc_provision_thing", {"name": "svc", "dry_run": False})
    assert text == (
        "DRY-RUN MODE (CNC_MCP_DRY_RUN=true): nothing was committed — the answer below is "
        "the preview.\n\nDry run only: svc"
    )
    assert SENT == [("cnc_provision_thing", {"name": "svc", "dry_run": True})]
    # The input schema is the original's: dry_run is still declared, unknown keys rejected.
    tool = next(t for t in await mcp.list_tools() if t.name == "cnc_provision_thing")
    assert set(tool.input_schema["properties"]) == {"name", "dry_run", "response_format"}
    assert tool.input_schema["additionalProperties"] is False
    with pytest.raises(ToolError, match="unknown argument 'nam'"):
        await mcp.call_tool("cnc_provision_thing", {"nam": "svc"})


async def test_dry_run_leaves_json_and_error_answers_unprefixed(make_settings):
    """A prefix would break a JSON answer for its parser and hide an 'Error:' answer
    from callers that key on the prefix (the composites' Composer.call)."""
    mcp, _ = build(make_settings, enable_writes=True, dry_run=True)
    text = await call_tool_text(
        mcp, "cnc_provision_thing", {"name": "svc", "response_format": "json"}
    )
    assert json.loads(text) == {"name": "svc", "dry_run": True}
    text = await call_tool_text(mcp, "cnc_provision_thing", {"name": "boom"})
    assert text == "Error: the CFP rejected it"


async def test_dry_run_records_a_write_without_a_preview_form_and_redacts_secrets(
    make_settings,
):
    mcp, _ = build(make_settings, enable_writes=True, dry_run=True)
    text = await call_tool_text(mcp, "cnc_delete_thing", {"uuid": "u-1"})
    assert text == (
        "NOT EXECUTED — DRY-RUN MODE (CNC_MCP_DRY_RUN=true): cnc_delete_thing has no preview "
        'form, so the call was recorded, not sent. It would have run with: {"uuid": "u-1"}. '
        "Unset CNC_MCP_DRY_RUN to execute writes."
    )
    text = await call_tool_text(
        mcp,
        "cnc_create_profile",
        {"profile": "lab", "password": "S3cret-XYZ", "snmp_community": "c0mmunity"},
    )
    assert "S3cret-XYZ" not in text and "c0mmunity" not in text
    assert '"profile": "lab", "password": "***", "snmp_community": "***"' in text
    assert "Preview instead: cnc_get_profile shows what exists. Unset CNC_MCP_DRY_RUN" in text
    assert not text.startswith("Error:")
    assert SENT == []  # neither write reached the platform
    # Argument validation still runs before the recording.
    with pytest.raises(ToolError, match="uuid"):
        await mcp.call_tool("cnc_delete_thing", {})


async def test_dry_run_withholds_the_arguments_a_tool_names_in_redact(make_settings):
    """A free-text body may carry a credential the argument name does not betray
    (a configlet's 'username x password y'): register_tool(redact=...) names it and
    the recorded answer shows its size instead. An absent one is reported absent."""
    mcp, _ = build(make_settings, enable_writes=True, dry_run=True)
    configlet = "hostname PE1\nusername admin password 0 S3cret-XYZ\nsnmp-server community c0mm"
    text = await call_tool_text(
        mcp, "cnc_push_config", {"name": "t1", "configlet": configlet, "variables": "vrf=blue"}
    )
    assert "S3cret-XYZ" not in text and "c0mm" not in text and "hostname" not in text
    assert (
        f'{{"name": "t1", "configlet": "<withheld: {len(configlet)} chars>", '
        '"variables": "<withheld: 8 chars>"}' in text
    )
    text = await call_tool_text(mcp, "cnc_push_config", {"name": "t1", "configlet": "x"})
    assert '"configlet": "<withheld: 1 chars>", "variables": null}' in text
    assert SENT == []
    # Without dry-run mode the tool runs as written.
    mcp, _ = build(make_settings, enable_writes=True)
    assert await call_tool_text(mcp, "cnc_push_config", {"name": "t1", "configlet": "x"}) == (
        "pushed t1"
    )


async def test_dry_run_descriptions_say_which_form_applies_and_reads_are_untouched(
    make_settings,
):
    mcp, _ = build(make_settings, enable_writes=True, dry_run=True)
    tools = {t.name: t for t in await mcp.list_tools()}
    assert tools["cnc_provision_thing"].description == (
        f"Provision a thing.\n\n{DRY_RUN_PREVIEW_SUFFIX}"
    )
    assert tools["cnc_delete_thing"].description.endswith(f"\n\n{DRY_RUN_RECORDED_SUFFIX}")
    assert "DRY-RUN MODE" not in (tools["cnc_echo"].description or "")
    assert await call_tool_text(mcp, "cnc_echo", {"host_name": "PE1"}) == (
        "host_name=PE1 page_size=5 schema=CPU"
    )
    # The wrapper is a functools.wraps wrapper over the original.
    registered = mcp._tool_manager.get_tool("cnc_delete_thing")
    assert registered is not None and registered.is_async is True
    assert registered.fn.__wrapped__.__name__ == "delete_thing"
    # Not in dry-run mode: no suffix, the original function.
    mcp, _ = build(make_settings, enable_writes=True)
    tools = {t.name: t for t in await mcp.list_tools()}
    assert "DRY-RUN MODE" not in tools["cnc_delete_thing"].description
    assert not hasattr(mcp._tool_manager.get_tool("cnc_delete_thing").fn, "__wrapped__")


async def test_dry_run_unregisters_a_write_it_cannot_wrap(make_settings, monkeypatch, caplog):
    """If the SDK seam is gone the write must not stay live in dry-run mode: it is
    removed (through the public remove_tool) and recorded as skipped."""
    mcp = MCPServer("test")
    ctx = AppContext(settings=make_settings(enable_writes=True, dry_run=True), client=object())  # type: ignore[arg-type]
    with caplog.at_level(logging.WARNING, logger="cnc_mcp.safety"), monkeypatch.context() as m:
        m.setattr(ToolManager, "get_tool", lambda self, name: None)

        @register_tool(mcp, ctx, name="cnc_write", title="Write", read_only=False)
        async def write(x: Annotated[int, Field()] = 1) -> str:
            return f"wrote x={x}"

        @register_tool(mcp, ctx, name="cnc_read", title="Read", read_only=True)
        async def read(x: Annotated[int, Field()] = 1) -> str:
            return f"read x={x}"

    assert await names(mcp) == {"cnc_read"}
    assert "Write tool cnc_write not registered: dry-run wrapper could not be installed" in (
        caplog.text
    )
    record = ctx.tools["cnc_write"]
    assert record.registered is False
    assert record.skipped_reason is not None
    assert record.skipped_reason.startswith("dry-run wrapper could not be installed")
    with pytest.raises(ToolError, match="Unknown tool"):
        await mcp.call_tool("cnc_write", {"x": 2})
    assert ctx.tools["cnc_read"].registered is True


def test_redact_arguments_by_name_marker_and_by_explicit_name():
    assert redact_arguments(
        {"configlet": "a\nb", "vars": {"k": 1}}, redact=("Configlet", "vars")
    ) == {
        "configlet": "<withheld: 3 chars>",
        "vars": "<withheld: 8 chars>",
    }
    assert redact_arguments({"configlet": None}, redact=("configlet",)) == {"configlet": None}
    arguments = {
        "profile": "lab",
        "ssh_password": "p",
        "api_token": "t",
        "secret_id": "s",
        "ssh_key": "k",
        "passphrase": "pp",
        "snmpv2_read_community": "c",
        "Password": "P",
        "http_password": None,
        "hops": "P1,P2",
    }
    assert redact_arguments(arguments) == {
        "profile": "lab",
        "ssh_password": "***",
        "api_token": "***",
        "secret_id": "***",
        "ssh_key": "***",
        "passphrase": "***",
        "snmpv2_read_community": "***",
        "Password": "***",
        "http_password": None,  # an absent secret is reported absent
        "hops": "P1,P2",
    }


def test_not_executed_text_is_capped_and_json_friendly():
    from enum import Enum

    class Fmt(Enum):
        JSON = "json"

    text = not_executed_text("cnc_x", {"fmt": Fmt.JSON, "n": 1, "flag": True}, None, "P_")
    assert text == (
        "NOT EXECUTED — DRY-RUN MODE (P_DRY_RUN=true): cnc_x has no preview form, so the "
        'call was recorded, not sent. It would have run with: {"fmt": "json", "n": 1, '
        '"flag": true}. Unset P_DRY_RUN to execute writes.'
    )
    long = not_executed_text("cnc_x", {"body": "x" * 5000}, "hint", "P_")
    assert len(long) <= NOT_EXECUTED_MAX_CHARS
    assert "more characters of arguments not shown]. Preview instead: hint. Unset" in long


def test_not_executed_text_truncation_note_counts_exactly_what_is_hidden():
    """The figure in the note is the echo characters actually dropped — the note's own
    length is taken off the room BEFORE the count, not after."""
    import re

    arguments = {"body": "x" * 5000}
    echo = json.dumps(redact_arguments(arguments), separators=(", ", ": "))
    text = not_executed_text("cnc_x", arguments, "hint", "P_")
    shown = text.split("It would have run with: ", 1)[1].split(" [... ", 1)[0]
    match = re.search(r"\[\.\.\. (\d+) more characters of arguments not shown\]", text)
    assert match is not None
    assert echo.startswith(shown)
    assert int(match.group(1)) == len(echo) - len(shown)
    assert NOT_EXECUTED_MAX_CHARS - 2 <= len(text) <= NOT_EXECUTED_MAX_CHARS
    # Values named in redact never reach the echo, however long.
    text = not_executed_text("cnc_x", arguments, None, "P_", redact=("body",))
    assert text.endswith('{"body": "<withheld: 5000 chars>"}. Unset P_DRY_RUN to execute writes.')


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
