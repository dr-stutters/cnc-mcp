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
