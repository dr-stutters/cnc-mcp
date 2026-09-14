"""Server wiring and write-safety gating across the real tool set."""

from __future__ import annotations

import logging

import pytest

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
    "cnc_list_services",
    "cnc_get_service_plan",
    "cnc_list_function_packs",
    "cnc_list_performance_policies",
    "cnc_get_performance_top_n",
    "cnc_get_lsp_utilization",
    "cnc_get_oam_trace_route",
    "cnc_get_probe_status",
    "cnc_list_software_images",
    "cnc_list_ztp_profiles",
    "cnc_list_inventory_scheduler_jobs",
}
WRITE_TOOLS = {
    "cnc_create_device",
    "cnc_update_device",
    "cnc_delete_device",
    "cnc_create_credential_profile",
    "cnc_delete_credential_profile",
    "cnc_create_provider",
    "cnc_delete_provider",
    "cnc_create_sr_policy",
    "cnc_delete_sr_policy",
    "cnc_set_maintenance_mode",
    "cnc_restart_microservice",
    "cnc_assign_tags",
    "cnc_lock_device",
    "cnc_acknowledge_alarm",
    "cnc_clear_alarm",
    "cnc_deploy_config_template",
    "cnc_delete_device_backup",
    "cnc_create_webhook_subscription",
    "cnc_delete_notification_subscription",
    "cnc_pause_lcm_recommendations",
    "cnc_create_odn_template",
    "cnc_delete_odn_template",
    "cnc_create_sr_policy_service",
    "cnc_provision_service",
    "cnc_delete_service",
    "cnc_start_oam_trace_route",
    "cnc_reactivate_probe",
    "cnc_run_inventory_scheduler_job",
    "cnc_suspend_inventory_scheduler_job",
    "cnc_update_credential_profile",
    "cnc_enable_device_gnmi",
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
        # Unknown argument names are rejected (register_tool), and the schema says so.
        assert tool.input_schema.get("additionalProperties") is False, tool.name
        # Flat parameters: enum $refs (ResponseFormat) are fine, object models are not.
        defs = tool.input_schema.get("$defs", {})
        for prop_name, prop in tool.input_schema.get("properties", {}).items():
            ref = prop.get("$ref", "")
            if ref:
                target = defs.get(ref.rsplit("/", 1)[-1], {})
                assert target.get("type") != "object", f"{tool.name}.{prop_name} wraps a model"


async def test_unknown_argument_name_is_rejected_not_dropped(make_settings):
    """Agent scenario 2026-09-14: {"host_names": ...} used to answer 'Pass exactly one
    of uuid or host_name' as if nothing had been passed."""
    from mcp.server.mcpserver.exceptions import ToolError

    mcp = build_server(make_settings(enable_writes=False))
    with pytest.raises(ToolError) as info:
        await mcp.call_tool("cnc_check_device_nso_state", {"host_names": "PE1,PE2"})
    assert "unknown argument 'host_names' (did you mean 'host_name'?)" in str(info.value)
    assert "PE1,PE2" not in str(info.value)
    # The aliased parameter of cnc_get_performance_statistics ('schema' shadows a
    # BaseModel method, so the SDK stores it as field_schema) is still accepted by its
    # wire name — it must not be reported as unknown.
    with pytest.raises(ToolError) as info:
        await mcp.call_tool("cnc_get_performance_statistics", {"schema": "CPU", "hour": 1})
    assert "unknown argument 'hour' (did you mean 'hours'?)" in str(info.value)
    assert "'schema'" not in str(info.value).split("accepted:")[0]


async def test_field_validation_errors_echo_the_offending_value(make_settings):
    """Strict argument names must not cost the per-field input echo pydantic gives
    every other MCP server (response_format='JSON' -> input_value='JSON')."""
    from mcp.server.mcpserver.exceptions import ToolError

    mcp = build_server(make_settings(enable_writes=False))
    with pytest.raises(ToolError) as info:
        await mcp.call_tool("cnc_list_devices", {"response_format": "JSON"})
    text = str(info.value)
    assert "response_format" in text
    assert "Input should be 'markdown' or 'json'" in text
    assert "input_value='JSON'" in text


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


def test_instructions_end_with_the_shared_safety_mode_lines(make_settings):
    """safety_mode_lines lives in safety.py so the prompts' writes_note() can say the
    same thing without importing server (circular); the instructions still end with it."""
    from cnc_mcp import safety, server

    assert server.safety_mode_lines is safety.safety_mode_lines
    for settings in (
        make_settings(),
        make_settings(enable_writes=True, dry_run=True, write_areas="fault"),
        make_settings(disabled_tools="cnc_delete_device"),
    ):
        lines = safety.safety_mode_lines(settings)
        assert lines and build_instructions(settings).endswith("\n".join(lines))


def test_instructions_state_the_exact_safety_mode(make_settings):
    read_only = build_instructions(make_settings(enable_writes=False))
    assert (
        "This server is READ-ONLY: write tools are not registered. To enable them, set the "
        "CNC_MCP_ENABLE_WRITES=true environment variable and restart." in read_only
    )
    assert "DRY-RUN" not in read_only and "disabled by configuration" not in read_only
    all_areas = build_instructions(make_settings(enable_writes=True))
    assert "Write tools are ENABLED for all areas and modify the live platform." in all_areas
    assert "READ-ONLY" not in all_areas
    some = build_instructions(make_settings(enable_writes=True, write_areas="nso, fault"))
    assert (
        "Write tools are ENABLED only for the areas fault, nso (CNC_MCP_WRITE_AREAS); the "
        "write tools of every other area are not registered." in some
    )
    assert "ENABLED for all areas" not in some
    dry = build_instructions(make_settings(enable_writes=True, dry_run=True))
    assert "DRY-RUN MODE is active (CNC_MCP_DRY_RUN=true)" in dry
    assert "forced to true" in dry and "'NOT EXECUTED'" in dry
    # Dry-run without writes is moot: the read-only statement stands alone.
    assert "DRY-RUN" not in build_instructions(make_settings(enable_writes=False, dry_run=True))
    one = build_instructions(make_settings(disabled_tools="cnc_delete_device"))
    assert (
        "1 tool is disabled by configuration (CNC_MCP_DISABLED_TOOLS) and not registered: "
        "cnc_delete_device." in one
    )
    two = build_instructions(
        make_settings(
            enable_writes=True, disabled_tools="cnc_restart_microservice,cnc_delete_device"
        )
    )
    assert (
        "2 tools are disabled by configuration (CNC_MCP_DISABLED_TOOLS) and not registered: "
        "cnc_delete_device, cnc_restart_microservice." in two
    )


# --- write areas / disabled tools on the real tool set ---------------------------------

FAULT_WRITES = {
    "cnc_acknowledge_alarm",
    "cnc_annotate_alarm",
    "cnc_clear_alarm",
    "cnc_create_alarm_suppression_policy",
    "cnc_delete_alarm_suppression_policy",
}


async def test_write_areas_register_only_that_areas_writes(make_settings, caplog):
    with caplog.at_level(logging.INFO, logger="cnc_mcp.tools"):
        mcp = build_server(make_settings(enable_writes=True, write_areas="Fault"))
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    writes = {name for name, tool in tools.items() if not tool.annotations.read_only_hint}
    assert writes == FAULT_WRITES
    assert READ_TOOLS <= set(tools)  # every read tool is still there
    assert "cnc_provision_l3vpn_e2e" not in tools and "cnc_create_sr_policy_e2e" not in tools
    # The read-only server registers exactly the same reads.
    reads = {name for name, tool in tools.items() if tool.annotations.read_only_hint}
    read_only = {tool.name for tool in await build_server(make_settings()).list_tools()}
    assert reads == read_only
    assert "writes on for areas fault; disabled tools: none; dry-run off" in caplog.text


async def test_write_areas_accept_several_areas(make_settings):
    mcp = build_server(make_settings(enable_writes=True, write_areas="devices, credentials"))
    writes = {t.name for t in await mcp.list_tools() if not t.annotations.read_only_hint}
    assert writes == {
        "cnc_create_device",
        "cnc_update_device",
        "cnc_delete_device",
        "cnc_enable_device_gnmi",
        "cnc_create_credential_profile",
        "cnc_update_credential_profile",
        "cnc_delete_credential_profile",
    }


async def test_disabled_tools_remove_a_read_and_a_write_tool(make_settings, caplog):
    with caplog.at_level(logging.INFO, logger="cnc_mcp"):
        mcp = build_server(
            make_settings(enable_writes=True, disabled_tools="cnc_list_devices, CNC_DELETE_DEVICE")
        )
    names = {tool.name for tool in await mcp.list_tools()}
    assert "cnc_list_devices" not in names and "cnc_delete_device" not in names
    assert (READ_TOOLS - {"cnc_list_devices"}) | (WRITE_TOOLS - {"cnc_delete_device"}) <= names
    assert "Tool cnc_list_devices not registered (disabled by CNC_MCP_DISABLED_TOOLS)" in (
        caplog.text
    )
    assert "disabled tools: cnc_delete_device, cnc_list_devices; dry-run off" in caplog.text
    # Disabled applies in read-only mode too.
    mcp = build_server(make_settings(disabled_tools="cnc_list_devices"))
    assert "cnc_list_devices" not in {tool.name for tool in await mcp.list_tools()}


def test_unknown_write_area_fails_startup_with_a_hint(make_settings):
    from cnc_mcp.errors import PlatformError

    with pytest.raises(PlatformError) as info:
        build_server(make_settings(enable_writes=True, write_areas="fault,falt,sr_te"))
    text = str(info.value)
    assert "CNC_MCP_WRITE_AREAS names an unknown area 'falt' (did you mean 'fault'?)." in text
    assert "names an unknown area 'sr_te' (did you mean 'sr_te_operations'?)." in text
    assert "Valid area names: devices, credentials, providers, " in text
    assert "composite." in text
    # The names are validated even when writes are off: a typo must never wait for
    # the day writes are enabled.
    with pytest.raises(PlatformError, match="unknown area 'falt'"):
        build_server(make_settings(enable_writes=False, write_areas="falt"))


def test_unknown_disabled_tool_fails_startup_with_a_hint(make_settings):
    """The message carries the did-you-mean and the few closest names, not the whole
    245-name list (6.5 KB on one stderr line)."""
    from cnc_mcp.errors import PlatformError
    from cnc_mcp.tools import CLOSE_TOOL_NAMES, FULL_TOOL_LIST_HINT

    with pytest.raises(PlatformError) as info:
        build_server(make_settings(disabled_tools="cnc_delete_devices,cnc_delete_device"))
    text = str(info.value)
    assert (
        "CNC_MCP_DISABLED_TOOLS names an unknown tool 'cnc_delete_devices' "
        "(did you mean 'cnc_delete_device'?)." in text
    )
    assert "Valid tool names:" not in text and "cnc_acknowledge_alarm" not in text
    closest = text.split("Closest tool names: ", 1)[1].split(".", 1)[0].split(", ")
    assert closest[0] == "cnc_delete_device"  # a write tool counts even while writes are off
    assert 1 < len(closest) <= CLOSE_TOOL_NAMES
    assert f"245 tool names in this build; {FULL_TOOL_LIST_HINT}." in text
    assert len(text) < 600
    with pytest.raises(PlatformError) as info:
        build_server(make_settings(disabled_tools="zzz"))
    text = str(info.value)
    assert "names an unknown tool 'zzz'. 245 tool names in this build; run" in text
    assert "Closest" not in text and "did you mean" not in text
    # The area list (24 names) is still printed in full.
    with pytest.raises(PlatformError) as info:
        build_server(make_settings(write_areas="zzz"))
    assert "Valid area names: devices, credentials, " in str(info.value)


async def test_write_area_with_no_write_tools_warns_at_startup(make_settings, caplog):
    """CNC_MCP_WRITE_AREAS=topology enables nothing (the area's tools are all
    read-only) while the instructions still claim writes are enabled for it: the
    server starts — the configuration is harmless — with a WARNING naming the area
    and the areas that do have write tools."""
    from cnc_mcp.errors import PlatformError

    with caplog.at_level(logging.WARNING, logger="cnc_mcp.tools"):
        mcp = build_server(make_settings(enable_writes=True, write_areas="topology"))
    writes = {t.name for t in await mcp.list_tools() if not t.annotations.read_only_hint}
    assert writes == set()
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    text = warnings[0]
    assert text.startswith(
        "CNC_MCP_WRITE_AREAS names the area topology, whose tools are all read-only — the "
        "entry enables nothing. Areas with write tools: admin, "
    )
    assert "topology" not in text.split("Areas with write tools: ", 1)[1]
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="cnc_mcp.tools"):
        build_server(make_settings(enable_writes=True, write_areas="fault, te_state,topology"))
    assert "names the areas te_state, topology, whose tools are all read-only" in caplog.text
    # Logged with writes off too (like an unknown name is checked), so the typo-class
    # mistake is visible before the day writes are enabled.
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="cnc_mcp.tools"):
        build_server(make_settings(enable_writes=False, write_areas="topology"))
    assert "area topology, whose tools are all read-only" in caplog.text
    # An unknown name next to it still fails startup — that one IS a configuration error.
    with pytest.raises(PlatformError) as info:
        build_server(make_settings(enable_writes=True, write_areas="falt,topology"))
    assert "unknown area 'falt'" in str(info.value)
    assert "whose tools are all read-only" not in str(info.value)
    # A properly configured server logs no warning at all.
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="cnc_mcp.tools"):
        build_server(make_settings(enable_writes=True, write_areas="fault, devices"))
        build_server(make_settings(enable_writes=True))
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    # A disabled write tool does not empty its area: the record counts, registered or not.
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="cnc_mcp.tools"):
        mcp = build_server(
            make_settings(
                enable_writes=True,
                write_areas="ems_jobs",
                disabled_tools="cnc_run_inventory_scheduler_job,"
                "cnc_suspend_inventory_scheduler_job,cnc_resume_inventory_scheduler_job",
            )
        )
    writes = {t.name for t in await mcp.list_tools() if not t.annotations.read_only_hint}
    assert writes == set()
    assert "read-only" not in caplog.text


def test_read_only_areas_are_the_ones_with_no_write_record(make_settings):
    from mcp.server.mcpserver import MCPServer

    from cnc_mcp.auth import StaticTokenAuth
    from cnc_mcp.client import ApiClient
    from cnc_mcp.safety import AppContext
    from cnc_mcp.tools import (
        all_areas,
        read_only_areas_warning,
        register_all_tools,
        write_areas_without_writes,
    )

    settings = make_settings(enable_writes=False)
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    register_all_tools(MCPServer("test"), ctx)
    assert write_areas_without_writes(ctx) == []  # nothing listed, nothing to complain about
    assert read_only_areas_warning(ctx) is None
    ctx.settings = make_settings(enable_writes=False, write_areas=",".join(all_areas()))
    read_only_areas = write_areas_without_writes(ctx)
    assert {"topology", "te_state", "physical_inventory", "services"} <= set(read_only_areas)
    assert not {"devices", "fault", "nso", "composite", "oam", "ems_jobs"} & set(read_only_areas)
    assert read_only_areas == sorted(read_only_areas)
    warning = read_only_areas_warning(ctx)
    assert warning is not None and warning.startswith(
        f"CNC_MCP_WRITE_AREAS names the areas {', '.join(read_only_areas)}, whose tools are "
        "all read-only — the entry enables nothing. Areas with write tools: "
    )
    # An unknown name is not a read-only area (validate_gating reports it separately).
    ctx.settings = make_settings(enable_writes=False, write_areas="zzz")
    assert write_areas_without_writes(ctx) == ["zzz"] and read_only_areas_warning(ctx) is None


def test_requires_naming_a_later_module_fails_startup(make_settings, monkeypatch):
    """`requires` is resolved at decoration time, so the module that defines a required
    tool must register before the requiring one; putting composite first would skip the
    write playbooks with 'needs ... (area unknown)' — validate_gating names the bug."""
    from cnc_mcp import tools
    from cnc_mcp.tools import composite

    reordered = [composite, *[m for m in tools.ALL_MODULES if m is not composite]]
    monkeypatch.setattr(tools, "ALL_MODULES", reordered)
    with pytest.raises(RuntimeError) as info:
        build_server(make_settings(enable_writes=True))
    text = str(info.value)
    assert text.startswith("tool registration order: ")
    assert (
        "tool cnc_provision_l3vpn_e2e (area composite) was skipped for needing "
        "cnc_create_l3vpn_service, which area service_provisioning defines later: "
        "service_provisioning must come before composite in ALL_MODULES" in text
    )
    assert (
        "cnc_create_sr_policy_e2e (area composite) was skipped for needing "
        "cnc_create_sr_policy" in text
    )
    # The symptom is caught even when the later tool ends up gated (its area not allowed):
    # a bug in this package, not a configuration error, so not a PlatformError.
    with pytest.raises(RuntimeError, match="which area sr_te_operations defines later"):
        build_server(
            make_settings(enable_writes=True, write_areas="composite,service_provisioning")
        )


def test_requires_naming_an_undefined_tool_is_reported(make_settings):
    from mcp.server.mcpserver import MCPServer

    from cnc_mcp.auth import StaticTokenAuth
    from cnc_mcp.client import ApiClient
    from cnc_mcp.safety import AppContext, register_tool
    from cnc_mcp.tools import register_all_tools, requirement_problems

    settings = make_settings(enable_writes=True)
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    mcp = MCPServer("test")
    register_all_tools(mcp, ctx)
    assert requirement_problems(ctx) == []

    @register_tool(mcp, ctx, name="cnc_x", title="X", read_only=False, requires=("cnc_nope",))
    async def x() -> str:
        return ""

    assert ctx.tools["cnc_x"].skipped_reason == "needs cnc_nope (area unknown)"
    assert requirement_problems(ctx) == [
        "tool cnc_x (area test_server_safety) requires cnc_nope, which no tool module defines"
    ]


def test_main_reports_a_gating_error_as_a_configuration_error(monkeypatch, capsys):
    """server.main() exits 1 with 'Configuration error: ...' on an unknown area."""
    from cnc_mcp import server

    monkeypatch.setenv("CNC_MCP_BASE_URL", "https://box.example.test")
    monkeypatch.setenv("CNC_MCP_API_TOKEN", "t")
    monkeypatch.setenv("CNC_MCP_WRITE_AREAS", "falt")
    monkeypatch.setattr(
        server.Settings, "model_config", {**server.Settings.model_config, "env_file": None}
    )
    with pytest.raises(SystemExit) as info:
        server.main()
    assert info.value.code == 1
    assert "Configuration error: CNC_MCP_WRITE_AREAS names an unknown area 'falt'" in (
        capsys.readouterr().err
    )


async def test_registry_covers_every_tool_registered_or_not(make_settings):
    """AppContext.tools records every register_tool decision on the real tool set."""
    from mcp.server.mcpserver import MCPServer

    from cnc_mcp.auth import StaticTokenAuth
    from cnc_mcp.client import ApiClient
    from cnc_mcp.safety import AppContext
    from cnc_mcp.tools import ALL_MODULES, all_areas, register_all_tools

    settings = make_settings(enable_writes=False)
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    mcp = MCPServer("test")
    register_all_tools(mcp, ctx)
    names = {tool.name for tool in await mcp.list_tools()}
    assert {n for n, r in ctx.tools.items() if r.registered} == names
    skipped = {n: r for n, r in ctx.tools.items() if not r.registered}
    assert WRITE_TOOLS <= set(skipped)
    assert all(r.skipped_reason == "enable_writes is false" for r in skipped.values())
    assert all(not r.read_only for r in skipped.values())
    assert {r.area for r in ctx.tools.values()} <= set(all_areas())
    assert len(all_areas()) == len(ALL_MODULES) and "composite" in all_areas()
    assert ctx.tools["cnc_delete_device"].destructive is True
    assert ctx.tools["cnc_delete_device"].area == "devices"


async def test_instructions_paging_claims_match_the_tool_schemas(make_settings):
    """Round 2: the instructions said every list tool pages with page_size/page while the
    alarm tools take 'limit'. The sentence must name the exceptions and stay true to the
    schemas; the unknown-argument hint is stated once (not duplicated)."""
    text = build_instructions(make_settings(enable_writes=False))
    assert "Most list tools page with page_size/page" in text
    assert "take 'limit' instead of page_size" in text
    assert text.count("unknown argument name is rejected by name") == 1
    mcp = build_server(make_settings(enable_writes=False))
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    for name in ("cnc_list_alarms", "cnc_list_events", "cnc_list_device_alarms"):
        assert name in text, name
        props = tools[name].input_schema["properties"]
        assert "limit" in props and "page_size" not in props, name
    assert "page" in tools["cnc_list_alarms"].input_schema["properties"]
    assert "offset" in tools["cnc_list_device_alarms"].input_schema["properties"]
    assert "page_size" in tools["cnc_list_microservices"].input_schema["properties"]
    # Round 3: the exception clause names the offset-based, limit-only and token-paged
    # tools too — each named tool must actually take what the sentence says it takes.
    for name in (
        "cnc_list_ems_nodes",
        "cnc_list_services",
        "cnc_list_notification_subscriptions",
    ):
        assert name in text, name
        props = tools[name].input_schema["properties"]
        assert "limit" in props and "offset" in props and "page_size" not in props, name
    assert "cnc_list_app_manager_jobs" in text
    props = tools["cnc_list_app_manager_jobs"].input_schema["properties"]
    assert "limit" in props and "offset" not in props and "page" not in props
    for name in ("cnc_list_sensor_templates", "cnc_get_collection_job_summary"):
        assert name in text, name
        props = tools[name].input_schema["properties"]
        assert "page_token" in props and "page_size" in props, name
    assert "cnc_list_config_templates" in text
    props = tools["cnc_list_config_templates"].input_schema["properties"]
    assert "page" in props and "size" in props and "page_size" not in props


def test_http_client_loggers_never_log_request_urls():
    """The CAS leg-2 URL carries the TGT; httpx must not log it even at DEBUG."""
    logging.getLogger("httpx").setLevel(logging.DEBUG)
    quiet_http_logging()
    assert not logging.getLogger("httpx").isEnabledFor(logging.INFO)
    assert not logging.getLogger("httpcore").isEnabledFor(logging.INFO)


async def test_build_server_does_not_close_a_client_it_was_given(make_settings):
    """An embedding that owns the client (the smoke runner) closes it itself."""
    from cnc_mcp.auth import StaticTokenAuth
    from cnc_mcp.client import ApiClient

    settings = make_settings(enable_writes=False)
    client = ApiClient(settings, StaticTokenAuth("t"))
    closed = []

    async def fake_aclose():
        closed.append(True)

    client.aclose = fake_aclose  # type: ignore[method-assign]
    mcp = build_server(settings, client=client)
    lowlevel = mcp._lowlevel_server  # noqa: SLF001 - exercising the lifespan directly
    async with lowlevel.lifespan(lowlevel):
        pass
    assert closed == []
    mcp = build_server(settings)  # a client built by the server IS closed by its lifespan
    lowlevel = mcp._lowlevel_server  # noqa: SLF001
    async with lowlevel.lifespan(lowlevel):
        pass
