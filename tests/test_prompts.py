"""MCP prompts: registration through build_server, argument contracts (including the
unknown-argument guard), rendering with and without the composite tools, and the
guarantee that every tool — and every argument key — a prompt names actually exists.

Prompts never touch the network, so nothing is mocked; the server is built with the
static test token from conftest. The one-call composites (tools/composite.py) are built
separately and may or may not be registered in this run, so both renderings are
exercised deterministically: ``with_composites`` registers a stub under each missing
composite name, ``without_composites`` removes any that are registered. Every other
``cnc_*`` token must be a registered tool of the server that rendered the text.
"""

from __future__ import annotations

import re

import pytest
from mcp.server.mcpserver import MCPServer
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS

from cnc_mcp.prompts import COMPOSITE_TOOLS, PROMPT_NAMES, register_prompts, writes_note
from cnc_mcp.server import build_instructions, build_server

TOOL_TOKEN = re.compile(r"\bcnc_[a-z0-9_]+")
# cnc_tool(key=value, key='literal') — a call spelled with its arguments (may wrap lines)
CALL = re.compile(r"\b(cnc_[a-z0-9_]+)\s*\(([^()]*)\)")
# cnc_tool key='literal' — the bare form (cnc_nso_device_action action='sync-from')
BARE = re.compile(r"\b(cnc_[a-z0-9_]+)\s+([a-z_]+)=('[^']*'|[^\s,)]+)")
KEY = re.compile(r"\b([a-z_]+)\s*=\s*('[^']*'|[^,\s]*)")

# Fields whose accepted spellings the tool description lists (none is a JSON-schema
# enum): a quoted literal the prompt gives for one of these must be among them.
LITERAL_FIELDS = {"reachability", "health", "oper_state", "action", "schema", "metric"}

# The composites that are write tools: registered (once built) only with writes enabled.
WRITE_COMPOSITES = {"cnc_provision_l3vpn_e2e", "cnc_create_sr_policy_e2e"}

# name -> (required arguments, optional arguments) as designed
ARGUMENTS = {
    "troubleshoot_device": ({"device"}, {"hours"}),
    "network_health_check": (set(), set()),
    "explain_sr_policy": ({"headend", "endpoint", "color"}, {"hours"}),
    "provision_l3vpn": ({"vpn_id", "endpoints"}, {"route_target", "route_distinguisher"}),
    "alarm_triage": (set(), set()),
    "explain_service": ({"service"}, set()),
}

# Arguments that render every prompt (the required ones plus one optional).
SAMPLE_ARGUMENTS = {
    "troubleshoot_device": {"device": "edge-router-7", "hours": "6"},
    "network_health_check": {},
    "explain_sr_policy": {"headend": "edge-router-7", "endpoint": "edge-router-9", "color": "100"},
    "provision_l3vpn": {
        "vpn_id": "customer-a-vpn",
        "endpoints": '[{"node": "edge-router-7", "interface": "Loopback91", '
        '"address": "10.91.1.1", "prefix_length": 30, "local_as": 65000}]',
        "route_target": "0:65000:100",
    },
    "alarm_triage": {},
    "explain_service": {"service": "customer-a-vpn"},
}

# Names that belong to one lab and must never leak into a prompt (the platform-wide
# conventions 'MD=CISCO_EMS!ND=<host name>' and ROBOT_* states are fine).
LAB_NAMES = ("PE1", "PE2", "P1", "198.18.", "mcp-l3vpn", "EMBEDDED_DEF_CDG")


def _stub() -> str:
    return ""


async def registered_names(mcp: MCPServer) -> set[str]:
    return {tool.name for tool in await mcp.list_tools()}


async def with_composites(mcp: MCPServer, *, enable_writes: bool) -> set[str]:
    """Register a stub under every composite name this server lacks (the write
    composites only when writes are enabled, as the real ones would be). Returns the
    stubbed names — their argument schemas are empty and must not be checked."""
    wanted = COMPOSITE_TOOLS if enable_writes else COMPOSITE_TOOLS - WRITE_COMPOSITES
    stubbed = wanted - await registered_names(mcp)
    for name in stubbed:
        mcp.tool(name=name)(_stub)
    return stubbed


async def without_composites(mcp: MCPServer) -> None:
    """Remove every registered composite so the fallback rendering is exercised."""
    for name in COMPOSITE_TOOLS & await registered_names(mcp):
        mcp.remove_tool(name)


async def prompt_text(mcp: MCPServer, name: str, arguments: dict[str, str]) -> str:
    result = await mcp.get_prompt(name, arguments)
    assert result.messages, name
    return "\n".join(m.content.text for m in result.messages)


async def all_prompt_texts(mcp: MCPServer) -> dict[str, str]:
    return {name: await prompt_text(mcp, name, args) for name, args in SAMPLE_ARGUMENTS.items()}


async def test_build_server_registers_the_six_prompts_with_their_arguments(make_settings):
    mcp = build_server(make_settings(enable_writes=False))
    prompts = {p.name: p for p in await mcp.list_prompts()}
    assert set(prompts) == set(PROMPT_NAMES) == set(ARGUMENTS)
    for name, (required, optional) in ARGUMENTS.items():
        prompt = prompts[name]
        assert prompt.title, name
        assert prompt.description and len(prompt.description) > 40, name
        args = {a.name: a for a in prompt.arguments or []}
        assert set(args) == required | optional, name
        for arg_name, arg in args.items():
            assert arg.required is (arg_name in required), f"{name}.{arg_name}"
            assert arg.description, f"{name}.{arg_name} has no description"


async def test_get_prompt_renders_the_arguments_into_one_user_message(make_settings):
    mcp = build_server(make_settings(enable_writes=False))
    for name, arguments in SAMPLE_ARGUMENTS.items():
        result = await mcp.get_prompt(name, arguments)
        assert [m.role for m in result.messages] == ["user"], name
        text = result.messages[0].content.text
        for value in arguments.values():
            assert value in text, f"{name}: {value!r} not rendered"
        assert len(text) > 800, name  # a playbook, not a one-liner


async def test_optional_arguments_default_when_omitted(make_settings):
    mcp = build_server(make_settings(enable_writes=False))
    text = await prompt_text(mcp, "troubleshoot_device", {"device": "edge-router-7"})
    assert "looking back 24 hours" in text
    # explain_sr_policy's window defaults to the composite's 6 h and is threaded through
    # to every windowed drill-in call, so the series stay comparable.
    text = await prompt_text(
        mcp,
        "explain_sr_policy",
        {"headend": "edge-router-7", "endpoint": "edge-router-9", "color": "100"},
    )
    assert "measured over the last 6 hours" in text
    assert "cnc_get_lsp_delay(hours=6," in text and "cnc_get_lsp_utilization(hours=6," in text
    assert "pass hours=6 to every drill-in call" in text
    text = await prompt_text(
        mcp,
        "explain_sr_policy",
        {"headend": "edge-router-7", "endpoint": "edge-router-9", "color": "100", "hours": "3"},
    )
    assert "measured over the last 3 hours" in text and "hours=3" in text and "hours=6" not in text
    text = await prompt_text(mcp, "provision_l3vpn", {"vpn_id": "v1", "endpoints": "[]"})
    assert "route_target: (not given" in text
    assert "route_distinguisher: (not given" in text
    assert "never invent one" in text
    # A given value replaces the placeholder.
    text = await prompt_text(
        mcp, "provision_l3vpn", {"vpn_id": "v1", "endpoints": "[]", "route_target": "0:65000:1"}
    )
    assert "route_target: 0:65000:1" in text
    assert "route_distinguisher: (not given" in text


async def test_missing_required_argument_is_an_error(make_settings):
    mcp = build_server(make_settings(enable_writes=False))
    with pytest.raises(ValueError, match="Missing required arguments"):
        await mcp.get_prompt("troubleshoot_device", {})
    with pytest.raises(ValueError, match="Missing required arguments"):
        await mcp.get_prompt("explain_sr_policy", {"headend": "a", "endpoint": "b"})


async def test_unknown_argument_is_named_with_a_hint(make_settings):
    """A misspelt argument name is rejected by name with a did-you-mean hint — the same
    standard as the tools (safety._forbid_unknown_arguments) — as an MCPError with
    INVALID_PARAMS, not the SDK's opaque 'Error rendering prompt <name>'."""
    mcp = build_server(make_settings(enable_writes=False))
    with pytest.raises(MCPError) as info:
        await mcp.get_prompt("troubleshoot_device", {"device": "edge-router-7", "hour": "6"})
    assert info.value.code == INVALID_PARAMS
    assert info.value.message == (
        "prompt troubleshoot_device: unknown argument 'hour' (did you mean 'hours'?); "
        "accepted: device, hours"
    )
    # Several unknown names, no close match for one of them.
    with pytest.raises(MCPError) as info:
        await mcp.get_prompt(
            "explain_sr_policy",
            {"headend": "a", "endpoint": "b", "color": "1", "colour": "1", "zzzz": "x"},
        )
    assert info.value.code == INVALID_PARAMS
    assert "unknown arguments 'colour' (did you mean 'color'?), 'zzzz'" in info.value.message
    assert "accepted: headend, endpoint, color, hours" in info.value.message
    # A prompt with no arguments says so instead of listing an empty set.
    with pytest.raises(MCPError) as info:
        await mcp.get_prompt("alarm_triage", {"foo": "bar"})
    assert info.value.code == INVALID_PARAMS
    assert (
        info.value.message
        == "prompt alarm_triage: unknown argument 'foo'; this prompt takes no arguments"
    )
    # The SDK's required-argument check runs first (test_missing_required_argument_is_an_error
    # covers it); the guard sees what passes it. A correct call still works.
    assert "edge-router-7" in await prompt_text(
        mcp, "troubleshoot_device", {"device": "edge-router-7"}
    )


async def test_the_composites_the_prompts_start_from_are_registered(make_settings):
    """The seven one-call composites the prompts are built around must be registered
    tools. While tools/composite.py is not built the gap shows as an xfail in the
    summary rather than a silent pass; once it lands, delete the xfail so the assertion
    is unconditional."""
    mcp = build_server(make_settings(enable_writes=True))
    missing = COMPOSITE_TOOLS - await registered_names(mcp)
    if missing:
        pytest.xfail(f"composites not registered yet: {sorted(missing)}")
    assert missing == set()


async def test_every_tool_named_in_a_prompt_exists(make_settings):
    """Every cnc_* token in every rendered prompt is a registered tool of the server that
    rendered it — in the fallback rendering (no composites) and in the composite one."""
    mcp = build_server(make_settings(enable_writes=True))
    await without_composites(mcp)
    registered = await registered_names(mcp)
    for name, text in (await all_prompt_texts(mcp)).items():
        tokens = set(TOOL_TOKEN.findall(text))
        assert tokens, f"{name} names no tool"
        unknown = tokens - registered
        assert not unknown, (
            f"{name} (no composites) names tools that do not exist: {sorted(unknown)}"
        )
        assert not tokens & COMPOSITE_TOOLS, f"{name} names an absent composite"

    await with_composites(mcp, enable_writes=True)
    registered = await registered_names(mcp)
    named: set[str] = set()
    for name, text in (await all_prompt_texts(mcp)).items():
        tokens = set(TOOL_TOKEN.findall(text))
        unknown = tokens - registered
        assert not unknown, f"{name} (composites) names tools that do not exist: {sorted(unknown)}"
        named |= tokens
    # The prompts are the on-ramp to the composites: each composite is named somewhere.
    assert COMPOSITE_TOOLS - {"cnc_create_sr_policy_e2e"} <= named


def _spelled_arguments(text: str) -> list[tuple[str, str, str | None]]:
    """(tool, key, quoted literal or None) for every argument a prompt spells out."""
    found: list[tuple[str, str, str | None]] = []
    for tool, body in CALL.findall(text):
        for key, value in KEY.findall(body):
            found.append((tool, key, value[1:-1] if value.startswith("'") else None))
    for tool, key, value in BARE.findall(text):
        found.append((tool, key, value[1:-1] if value.startswith("'") else None))
    return found


def _accepted_spellings(schema: dict, key: str) -> tuple[list[str] | None, str]:
    prop = schema["properties"][key]
    enum = prop.get("enum")
    refs = [prop.get("$ref")] + [a.get("$ref") for a in prop.get("anyOf", [])]
    for ref in refs:
        if ref and not enum:
            enum = schema.get("$defs", {}).get(ref.split("/")[-1], {}).get("enum")
    return enum, prop.get("description", "")


async def test_every_argument_a_prompt_spells_out_is_accepted(make_settings):
    """The argument keys the playbooks spell next to a tool — cnc_get_device(host_name=),
    cnc_list_devices(reachability='unreachable'), cnc_nso_device_action action='sync-from'
    — exist in that tool's input schema, and a quoted literal for an enumerated field is
    an accepted spelling, so a parameter rename in a tool module fails here, not in an
    agent's hands. Stubbed composites have no schema and are skipped."""
    mcp = build_server(make_settings(enable_writes=True))
    await without_composites(mcp)
    texts = list((await all_prompt_texts(mcp)).items())
    stubbed = await with_composites(mcp, enable_writes=True)
    texts += list((await all_prompt_texts(mcp)).items())
    schemas = {tool.name: tool.input_schema for tool in await mcp.list_tools()}
    checked = 0
    for name, text in texts:
        for tool, key, literal in _spelled_arguments(text):
            if tool in stubbed:
                continue
            assert tool in schemas, f"{name}: {tool} is not registered"
            properties = schemas[tool].get("properties", {})
            assert key in properties, f"{name}: {tool} has no argument {key!r}"
            checked += 1
            if literal is None or key not in LITERAL_FIELDS:
                continue
            enum, description = _accepted_spellings(schemas[tool], key)
            if enum is not None:
                assert literal in enum, f"{name}: {tool}({key}={literal!r}) not in {enum}"
            else:
                assert re.search(rf"\b{re.escape(literal)}\b", description, re.IGNORECASE), (
                    f"{name}: {tool}({key}={literal!r}) is not a spelling the description lists"
                )
    assert checked >= 24, checked  # the pairs the playbooks spell out today


async def test_each_prompt_starts_from_its_composite_and_says_how_to_answer(make_settings):
    mcp = build_server(make_settings(enable_writes=False))
    await with_composites(mcp, enable_writes=False)
    text = await prompt_text(mcp, "troubleshoot_device", SAMPLE_ARGUMENTS["troubleshoot_device"])
    assert "Start with ONE call: cnc_investigate_device" in text
    assert text.index("cnc_investigate_device") < text.index("cnc_get_device(")
    for heading in ("Verdict", "Evidence", "Recommended action", "Not checked"):
        assert heading in text, heading
    assert "possibly stale" in text
    # The per-device PM tool with its selector, not the network-wide ranking (which needs
    # a metric token and has no per-device filter).
    assert "cnc_get_performance_statistics(schema='CEPMINTERFACE' | 'CPU'" in text
    assert "device_uuid=<the device uuid from the inventory record>" in text
    assert "cnc_get_performance_top_n(metric='CEPMINTERFACE_ifInUtilization') only" in text

    text = await prompt_text(mcp, "network_health_check", {})
    assert "Start with ONE call: cnc_network_health_report" in text
    assert text.index("cnc_network_health_report") < text.index("cnc_alarm_triage")
    for row in ("Devices", "Collection", "Topology feed", "Policies", "Controller", "Alarms"):
        assert row in text, row
    assert "LIVE" in text and "POSSIBLY STALE" in text

    text = await prompt_text(mcp, "explain_sr_policy", SAMPLE_ARGUMENTS["explain_sr_policy"])
    assert "cnc_explain_sr_policy(headend='edge-router-7', endpoint='edge-router-9'" in text
    # color is an integer in the policy tools' schemas: rendered unquoted, and said so.
    assert "color=100, hours=6)" in text and "color='100'" not in text
    assert "color\n   is an integer" in text or "color is an integer" in text
    for topic in ("Origin", "Delegation", "Path", "Constraints", "MEASURED", "MODELLED"):
        assert topic in text, topic
    assert "pcep-flag-c 1 = PCE-initiated" in text
    assert "host names" in text

    text = await prompt_text(mcp, "alarm_triage", {})
    assert "Start with ONE call: cnc_alarm_triage" in text
    for bucket in ("ACT NOW", "POSSIBLY STALE", "INFORMATIONAL"):
        assert bucket in text, bucket
    assert "cnc_list_microservices" in text  # the check before calling a pod alarm an outage

    text = await prompt_text(mcp, "explain_service", SAMPLE_ARGUMENTS["explain_service"])
    assert "Start with ONE call: cnc_explain_service" in text
    assert text.index("cnc_explain_service") < text.index("cnc_get_service(")
    assert "init -> config-apply -> ready" in text


async def test_without_the_composites_each_prompt_starts_from_the_individual_tools(
    make_settings,
):
    """On a build without tools/composite.py the prompts never send the assistant to a
    tool it does not have: step 1 says so and names the individual tools instead, and
    the answer shape is unchanged."""
    mcp = build_server(make_settings(enable_writes=False))
    await without_composites(mcp)
    texts = await all_prompt_texts(mcp)
    for name, text in texts.items():
        assert "Start with ONE call" not in text, name
        assert not set(TOOL_TOKEN.findall(text)) & COMPOSITE_TOOLS, name
        if name != "provision_l3vpn":  # a stepwise workflow; its composite is step 4's option
            assert "This build has no one-call" in text, name

    text = texts["troubleshoot_device"]
    assert "over the last 6 hours" in text
    assert "cnc_get_device(host_name=...)" in text
    for heading in ("Verdict", "Evidence", "Recommended action", "Not checked"):
        assert heading in text, heading

    text = texts["network_health_check"]
    assert "cnc_get_device_summary" in text and "cnc_search_alarms" in text
    assert "cnc_list_microservices (health='down'" in text  # the pod-health check
    assert "LIVE" in text and "POSSIBLY STALE" in text

    text = texts["explain_sr_policy"]
    assert "cnc_get_sr_policy(headend='edge-router-7', endpoint='edge-router-9', color=100)" in text
    assert "color='100'" not in text  # an integer in the schema
    assert text.index("cnc_get_sr_policy(") < text.index("cnc_get_sr_policy_routes")
    assert "MEASURED" in text and "MODELLED" in text
    assert "cnc_get_lsp_delay(hours=6," in text and "pass hours=6 to every drill-in call" in text

    text = texts["alarm_triage"]
    assert "cnc_search_alarms" in text and "cnc_list_device_alarms" in text
    assert "cnc_list_microservices(health='down')" in text
    for bucket in ("ACT NOW", "POSSIBLY STALE", "INFORMATIONAL"):
        assert bucket in text, bucket

    text = texts["explain_service"]
    assert text.index("cnc_list_services(name_prefix=...)") < text.index(
        "cnc_get_service(yang_path=...)"
    )
    assert "init -> config-apply -> ready" in text


async def test_provision_prompt_dry_runs_confirms_and_never_deletes(make_settings):
    for composites in (False, True):
        mcp = build_server(make_settings(enable_writes=True))
        if composites:
            await with_composites(mcp, enable_writes=True)
        else:
            await without_composites(mcp)
        text = await prompt_text(mcp, "provision_l3vpn", SAMPLE_ARGUMENTS["provision_l3vpn"])
        dry_run = text.index("dry_run=true")
        confirm = text.index("STOP and ask for confirmation")
        if composites:
            commit = text.index("cnc_provision_l3vpn_e2e (it commits")
        else:
            assert "cnc_provision_l3vpn_e2e" not in text
            commit = text.index("commit and verify with the individual tools")
        individual = text.index("cnc_create_l3vpn_service with dry_run=false")
        verify = text.index("verification evidence")
        assert dry_run < confirm < commit < individual < verify, composites
        assert "cnc_create_l3vpn_service(vpn_id='customer-a-vpn'" in text
        assert "Never delete anything (cnc_delete_vpn_service" in text
        assert "explicitly asks" in text
        # cnc_wait_for_service_plan takes plan_yang_path — the prompt says so by name.
        assert "cnc_wait_for_service_plan on the" in text and "plan_yang_path" in text


async def test_provision_note_names_the_e2e_composite_only_when_registered(make_settings):
    """cnc_provision_l3vpn_e2e is a write tool AND optional on a build, so its absence
    must never be read as 'writes are disabled': the closing paragraph names it only
    when it is registered."""
    mcp = build_server(make_settings(enable_writes=True))
    await without_composites(mcp)
    text = await prompt_text(mcp, "provision_l3vpn", SAMPLE_ARGUMENTS["provision_l3vpn"])
    assert "Write tools (cnc_create_l3vpn_service, cnc_nso_device_action): " in text
    assert "ENABLED" in text and "cnc_provision_l3vpn_e2e" not in text
    await with_composites(mcp, enable_writes=True)
    text = await prompt_text(mcp, "provision_l3vpn", SAMPLE_ARGUMENTS["provision_l3vpn"])
    assert (
        "Write tools (cnc_create_l3vpn_service, cnc_provision_l3vpn_e2e, cnc_nso_device_action): "
        in text
    )
    # Read-only server: the write composites are not registered, so not named either.
    mcp = build_server(make_settings(enable_writes=False))
    await with_composites(mcp, enable_writes=False)
    text = await prompt_text(mcp, "provision_l3vpn", SAMPLE_ARGUMENTS["provision_l3vpn"])
    assert "READ-ONLY" in text and "cnc_provision_l3vpn_e2e" not in text


async def test_prompts_explain_absent_write_tools_in_both_modes(make_settings):
    prefix = "CNC_MCP_"
    for enable_writes, phrase in ((False, "READ-ONLY"), (True, "ENABLED")):
        mcp = build_server(make_settings(enable_writes=enable_writes))
        for name, arguments in SAMPLE_ARGUMENTS.items():
            text = await prompt_text(mcp, name, arguments)
            assert phrase in text, (name, enable_writes)
            assert "missing from your tool list, writes are disabled" in text, name
            assert f"{prefix}ENABLE_WRITES=true" in text, name
            assert "never claim to have made a change" in text, name


async def test_prompts_carry_no_lab_specific_names(make_settings):
    mcp = build_server(make_settings(enable_writes=True))
    for composites in (False, True):
        if composites:
            await with_composites(mcp, enable_writes=True)
        else:
            await without_composites(mcp)
        for name, text in (await all_prompt_texts(mcp)).items():
            for lab in LAB_NAMES:
                assert lab not in text, f"{name} mentions {lab!r}"
    prompts = await mcp.list_prompts()
    for prompt in prompts:
        blob = (prompt.title or "") + (prompt.description or "")
        for lab in LAB_NAMES:
            assert lab not in blob, f"{prompt.name} metadata mentions {lab!r}"


def test_writes_note_reflects_the_server_mode(make_settings):
    off = writes_note(make_settings(enable_writes=False), write_tools="cnc_delete_device")
    on = writes_note(make_settings(enable_writes=True), write_tools="cnc_delete_device")
    assert "READ-ONLY" in off and "ENABLED" not in off
    assert "ENABLED" in on and "READ-ONLY" not in on
    assert "cnc_delete_device" in off
    assert "CNC_MCP_ENABLE_WRITES=true" in off


async def test_register_prompts_is_idempotent_per_server(make_settings):
    """A second registration on the same server is a no-op (the SDK warns and keeps the
    first), so an embedding that calls build_server twice does not double-register."""
    from cnc_mcp.auth import StaticTokenAuth
    from cnc_mcp.client import ApiClient
    from cnc_mcp.safety import AppContext

    settings = make_settings(enable_writes=False)
    mcp = build_server(settings)
    ctx = AppContext(settings=settings, client=ApiClient(settings, StaticTokenAuth("t")))
    register_prompts(mcp, ctx)
    assert len(await mcp.list_prompts()) == len(PROMPT_NAMES)


def test_instructions_name_the_prompts(make_settings):
    text = build_instructions(make_settings(enable_writes=False))
    for name in PROMPT_NAMES:
        assert name in text, name
