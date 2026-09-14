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
