"""MCP prompts — playbooks for the outcomes agents ask for most often.

Two rounds of blind agent scenarios against this server showed the same
investigations costing 20–45 tool calls each (a health overview, a "device X
looks degraded" investigation, "explain policy A->B colour N", alarm triage,
an L3VPN create-verify-trace-delete). The one-call composite tools
(:data:`COMPOSITE_TOOLS`; ``tools/composite.py``, built separately and optional
on a build) collapse each of those into one call. The prompts here tell the
assistant which composite to start with when this build registers it — and
which individual tools build the same picture when it does not — which tools
to drill in with when a section is missing or degraded, what shape the answer
takes, and what to say when a write tool is absent — with the reason the registry
recorded for it (writes off, its area not in ``CNC_MCP_WRITE_AREAS``, disabled by
name), never a blanket "writes are disabled".

Prompts are text only — they never call the platform — so they render with
writes disabled and with no credentials. Each is built with
``Prompt.from_function`` (SDK 2.x): the function's parameters become the
prompt's arguments (``required`` when they have no default; the
``Field(description=...)`` becomes the argument description) and the returned
``str`` becomes one user message. MCP prompt arguments are strings on the
wire, so every parameter is a ``str``. Like the tools (``safety.py``), a prompt
rejects an argument name it does not declare — by name, with a did-you-mean
hint — instead of the SDK's opaque "Error rendering prompt".

Every tool name in the rendered text is real: ``tests/test_prompts.py`` checks
each ``cnc_*`` token, and the argument keys spelled next to it, against the
registered tools, and keeps lab-specific names out of the text.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.prompts.base import Prompt
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS
from pydantic import Field

from cnc_mcp.safety import (
    AppContext,
    absent_tool_reasons,
    describe_unknown_arguments,
    safety_mode_lines,
)

logger = logging.getLogger(__name__)

# The one-call composites (tools/composite.py) the prompts start from. That module is
# optional on a build: each prompt checks the registered tools at render time and, when
# its composite is absent, says how to build the same picture from the individual tools
# instead of sending the assistant to a tool it does not have.
COMPOSITE_TOOLS = frozenset(
    {
        "cnc_investigate_device",
        "cnc_network_health_report",
        "cnc_explain_sr_policy",
        "cnc_alarm_triage",
        "cnc_explain_service",
        "cnc_srv6_readiness",
        "cnc_provision_l3vpn_e2e",
        "cnc_create_sr_policy_e2e",
    }
)

PROMPT_NAMES = (
    "troubleshoot_device",
    "network_health_check",
    "explain_sr_policy",
    "provision_l3vpn",
    "alarm_triage",
    "explain_service",
    "srv6_readiness",
)

_NOT_GIVEN = "(not given — ask the operator for it before the dry run; never invent one)"

_PromptFn = Callable[..., Awaitable[str]]


_NEVER_CLAIM = (
    "show the exact call you would have made and what it would change, and never claim "
    "to have made a change you could not make."
)


def writes_note(ctx: AppContext, *, write_tools: str) -> str:
    """The paragraph every prompt ends with: the exact safety mode this server runs in
    (the same lines the server instructions carry — ``safety.safety_mode_lines``), then,
    for each write tool named in ``write_tools`` that is not registered, the reason the
    registry recorded (``safety.absent_tool_reasons``: ``enable_writes is false``,
    ``area 'nso' is not in CNC_MCP_WRITE_AREAS (fault)``, ``disabled by
    CNC_MCP_DISABLED_TOOLS``, ``needs cnc_create_sr_policy (...)``) — so the remedy the
    assistant explains is the one that applies, not a blanket "set ENABLE_WRITES". In
    global dry-run mode the named writes are registered, and the note says which of them
    previews and which is recorded, not executed."""
    settings = ctx.settings
    names = [name.strip() for name in write_tools.split(",") if name.strip()]
    lines = [f"Write tools ({write_tools}): " + " ".join(safety_mode_lines(settings))]
    absent = absent_tool_reasons(ctx, names)
    if absent:
        by_reason: dict[str, list[str]] = {}
        for name, reason in absent.items():
            by_reason.setdefault(reason, []).append(name)
        listed = "; ".join(f"{', '.join(tools)} ({reason})" for reason, tools in by_reason.items())
        lines.append(
            f"Of those, not registered on this server: {listed}. Do not try to call them; if "
            f"the task needs one, say plainly that it is not registered and why, {_NEVER_CLAIM}"
        )
    else:
        lines.append(
            "If a write tool named above is nevertheless missing from your tool list, say so "
            f"plainly, {_NEVER_CLAIM}"
        )
    if settings.enable_writes and settings.dry_run:
        previews = [n for n in names if _dry_run_form(ctx, n) == "preview"]
        recorded = [n for n in names if _dry_run_form(ctx, n) == "recorded"]
        forms = []
        if previews:
            verb = "answers" if len(previews) == 1 else "answer"
            forms.append(f"{', '.join(previews)} {verb} the preview (dry_run forced to true)")
        if recorded:
            verb = "is" if len(recorded) == 1 else "are"
            forms.append(f"{', '.join(recorded)} {verb} recorded, not executed")
        if forms:
            lines.append(f"In this dry-run mode {'; '.join(forms)}.")
    return " ".join(lines)


def _dry_run_form(ctx: AppContext, name: str) -> str | None:
    record = ctx.tools.get(name)
    return record.dry_run_form if record is not None and record.registered else None


def _arg(value: str) -> str:
    """Render a user-supplied argument inside single quotes without breaking them."""
    return value.strip().replace("'", "’")


async def registered_tool_names(mcp: MCPServer) -> frozenset[str]:
    """The names of the tools registered on ``mcp`` at this moment (the composites are
    optional on a build, and the write tools exist only with writes enabled)."""
    return frozenset(tool.name for tool in await mcp.list_tools())


def _playbook(
    mcp: MCPServer, *, name: str, title: str, description: str
) -> Callable[[_PromptFn], _PromptFn]:
    """Register ``fn`` as the prompt ``name``: ``mcp.prompt()`` plus the unknown-argument
    guard the tools have (``safety._forbid_unknown_arguments``).

    ``Prompt.from_function`` derives the argument list from the signature; the render
    function it stores is wrapped so that an argument name outside that list raises
    ``MCPError(INVALID_PARAMS, ...)`` naming it, with the closest accepted name as a
    hint. An ``MCPError`` passes through the SDK's render wrapper unchanged; any other
    exception is reported as the opaque "Error rendering prompt <name>". (``**extra`` on
    the function would not do: the SDK turns it into a required argument.)
    """

    def decorator(fn: _PromptFn) -> _PromptFn:
        prompt = Prompt.from_function(fn, name=name, title=title, description=description)
        accepted = [argument.name for argument in prompt.arguments or []]
        render = prompt.fn

        async def guarded(**arguments: Any) -> str:
            unknown = sorted(set(arguments) - set(accepted))
            if unknown:
                if accepted:
                    detail = describe_unknown_arguments(unknown, accepted)
                else:
                    noun = "argument" if len(unknown) == 1 else "arguments"
                    names = ", ".join(f"'{key}'" for key in unknown)
                    detail = f"unknown {noun} {names}; this prompt takes no arguments"
                raise MCPError(INVALID_PARAMS, f"prompt {name}: {detail}")
            return await render(**arguments)

        prompt.fn = guarded
        mcp.add_prompt(prompt)
        return fn

    return decorator


def register_prompts(mcp: MCPServer, ctx: AppContext) -> None:
    """Register the seven playbook prompts on ``mcp`` (called after the tools, whose
    registry ``ctx.tools`` the closing paragraph of every prompt reads)."""

    @_playbook(
        mcp,
        name="troubleshoot_device",
        title="Troubleshoot a device",
        description="Investigate one Crosswork-managed device end to end — inventory, "
        "reachability, collection, NSO state, topology, SR policies, alarms — and answer "
        "with a verdict, the evidence, a recommended action and what was not checked.",
    )
    async def troubleshoot_device(
        device: Annotated[
            str,
            Field(description="Host name of the device as the inventory lists it (or its uuid)."),
        ],
        hours: Annotated[
            str,
            Field(description="How far back to look for alarms, events and metrics, in hours."),
        ] = "24",
    ) -> str:
        device = _arg(device)
        hours = _arg(hours) or "24"
        registered = await registered_tool_names(mcp)
        head = f"Troubleshoot the Crosswork-managed device '{device}', looking back {hours} hours."
        note = writes_note(
            ctx,
            write_tools="cnc_nso_device_action, cnc_unlock_device, cnc_update_device",
        )
        if "cnc_investigate_device" in registered:
            start = f"""\
1. Start with ONE call: cnc_investigate_device for device '{device}' with a {hours}-hour
   window (read its input schema for the exact argument names). It gathers, in one answer:
   the inventory record (admin/oper state, reachability per transport, credential profile,
   data gateway, NSO state), collection status, a fresh NSO check-sync, the EMF node
   state, the topology node (PCEP sessions, SR), the newest config backup, interface
   error/discard statistics, and the alarms and events that mention the device. It does
   NOT read the device's links or the SR policies it carries — use step 2 for those.
2. Read every section. For each section that is unavailable (an 'Error:' line, or an
   application that is not installed), degraded, or contradicts another section — and
   for links and SR policies, which the composite leaves out — drill in with the
   individual tool it names — typically:"""
        else:
            start = f"""\
1. This build has no one-call device investigation tool, so build the picture yourself
   from the individual tools in step 2, one section each, over the last {hours} hours:
   the inventory record (admin/oper state, reachability, credential profile, data gateway,
   NSO state), collection status, the topology node and its links, the SR policies the
   device heads, terminates or transits, and the alarms and events that mention it.
2. Gather every section, and look again at any that is unavailable (an 'Error:' line, or
   an application that is not installed), degraded, or contradicts another section. The
   tools:"""
        return f"""{head}

{start}
   cnc_get_device(host_name=...) for the inventory record;
   cnc_check_device_nso_state / cnc_check_nso_device_sync for NSO;
   cnc_get_topology_node (node_id = the host name) and cnc_list_topology_links(node=...)
   for the topology; cnc_list_sr_policies_on_nodes(nodes=...) for the policies;
   cnc_list_device_alarms(node_fdn='MD=CISCO_EMS!ND=<host name>') for device alarms and
   cnc_search_alarms(text=...) / cnc_list_events(text=...) for Crosswork's own alarms and
   events; cnc_get_performance_statistics(schema='CEPMINTERFACE' | 'CPU',
   device_uuid=<the device uuid from the inventory record>) for its interface utilisation
   and CPU, and cnc_get_performance_top_n(metric='CEPMINTERFACE_ifInUtilization') only
   to see whether it is among the busiest network-wide. Do not repeat a call already made.
3. Interpretation rules: reachability 'unreachable' and operational state 'error' are
   different faults — name both; ROBOT_OPER_STATE_CHECKING right after onboarding or a
   PATCH is transient (up to two minutes); an nso_state ending in _STARTED is an action in
   flight; links that are all ETHERNET with no IS-IS links mean the SR-PCE feed, not the
   device, is the problem; an open Crosswork alarm with 0 events unchanged for a week or
   more is possibly stale — confirm it before treating it as current. Refer to devices by
   host name; give TE router-ids only as evidence.

Answer with exactly these four headings:
- Verdict — one sentence: healthy / degraded / down, and why.
- Evidence — the facts (tool, field, value) the verdict rests on, nothing inferred.
- Recommended action — the next step, with the exact tool call an operator would run
  (cnc_nso_device_action action='sync-from', cnc_unlock_device, cnc_update_device, ...) or
  the device-side step when no tool covers it.
- Not checked — what this investigation could not see (unavailable sections, applications
  not installed, windows not covered) so that silence is not mistaken for health.

{note}"""

    @_playbook(
        mcp,
        name="network_health_check",
        title="Network health check",
        description="One-call status board for the whole deployment — devices, collection, "
        "topology feed, SR policies, the controller itself and the alarms — with live alarms "
        "separated from possibly-stale ones.",
    )
    async def network_health_check() -> str:
        registered = await registered_tool_names(mcp)
        note = writes_note(
            ctx,
            write_tools="cnc_restart_microservice, cnc_acknowledge_alarm, cnc_clear_alarm",
        )
        if "cnc_network_health_report" in registered:
            report = """\
1. Start with ONE call: cnc_network_health_report. It covers, in one answer: devices
   (counts by operational state and reachability), collection status, the topology feed
   (SR-PCE gRPC and LLDP), TE state (SR policies, Tree-SID, RSVP-TE), the controller
   itself (cluster nodes, applications, microservices) and the open alarms."""
            drill = (
                "3. Drill into a red or amber section only with the individual tool the "
                "report names:"
            )
        else:
            report = """\
1. This build has no one-call health report, so build the board yourself from the
   individual tools in step 3, one section each: devices (counts by operational state
   and reachability), collection status, the topology feed (SR-PCE gRPC and LLDP), TE
   state (SR policies, Tree-SID, RSVP-TE), the controller itself (cluster nodes,
   applications, microservices) and the open alarms."""
            drill = (
                "3. The tools, one per section (look again only where a section is red or amber):"
            )
        if "cnc_alarm_triage" in registered:
            triage = """\
2. If any section is red or amber, run cnc_alarm_triage once — it separates the alarms to
   act on from possibly-stale and informational ones, checking the microservice behind
   each pod-health alarm."""
        else:
            triage = """\
2. If any section is red or amber, sort the open alarms yourself: cnc_search_alarms for
   Crosswork's own alarms, then cnc_list_microservices (health='down' lists what is
   unhealthy now) to check the microservice behind each pod-health alarm before calling
   it an outage, per the LIVE / POSSIBLY STALE rule below."""
        return f"""Give me a status board for this Crosswork Network Controller deployment.

{report}
{triage}
{drill}
   cnc_get_device_summary and cnc_list_devices(reachability='unreachable') for devices;
   cnc_get_device_collection_summary and cnc_get_collection_health for collection;
   cnc_get_topology_summary (links that are all ETHERNET mean the SR-PCE gRPC feed is not
   up) and cnc_list_providers for the topology feed; cnc_get_te_summary and
   cnc_list_sr_policies(oper_state='down') for policies; cnc_get_cluster_health,
   cnc_list_application_status and cnc_list_microservices(health='down') for the
   controller; cnc_search_alarms for alarms. Do not repeat a call already made.

Present a short status board — one line per row, each with a green / amber / red mark and
the number that justifies it:
  Devices · Collection · Topology feed · Policies · Controller · Alarms
Under Alarms give two lists: LIVE (recent events, or a component a live check confirms
unhealthy) and POSSIBLY STALE (open, 0 events, unchanged for a week or more — Crosswork
does not auto-clear pod-health alarms, and a pod that cnc_list_microservices reports
healthy makes its old alarm stale, not an outage). End with one line on what was not
checked (applications not installed, sections that answered an error).

This is a read-only check: do not restart, acknowledge or clear anything unless asked.
{note}"""

    @_playbook(
        mcp,
        name="explain_sr_policy",
        title="Explain an SR-TE policy",
        description="Explain one SR-TE policy (head-end, end-point, color): origin, "
        "delegation, path, constraints, measured vs modelled metrics, and the services "
        "riding it — in device names.",
    )
    async def explain_sr_policy(
        headend: Annotated[
            str,
            Field(description="Head-end router: host name or TE router-id."),
        ],
        endpoint: Annotated[
            str,
            Field(description="End-point router: host name or TE router-id."),
        ],
        color: Annotated[str, Field(description="The policy color, e.g. '100'.")],
        hours: Annotated[
            str,
            Field(
                description="Window for the measured NPM series (delay, utilisation), in "
                "hours; at most 6 answers 5-minute samples, longer windows hourly roll-ups."
            ),
        ] = "6",
    ) -> str:
        headend, endpoint, color = _arg(headend), _arg(endpoint), _arg(color)
        hours = _arg(hours) or "6"
        registered = await registered_tool_names(mcp)
        head = (
            f"Explain the SR-TE policy from head-end '{headend}' to end-point '{endpoint}' "
            f"with color {color}, measured over the last {hours} hours."
        )
        note = writes_note(ctx, write_tools="cnc_update_sr_policy, cnc_delete_sr_policy")
        # color is an integer in every policy tool's schema: render it unquoted so the
        # assistant does not copy a string where the schema wants a number.
        if "cnc_explain_sr_policy" in registered:
            start = f"""\
1. Start with ONE call: cnc_explain_sr_policy(headend='{headend}', endpoint='{endpoint}',
   color={color}, hours={hours}) (read its input schema for the exact argument names; color
   is an integer). It joins the PCE's view of the policy (state, origin, delegation,
   candidate paths and hops), the Optimization Engine's route and metrics, the
   performance-monitoring entry, the measured NPM series, and the VPN services that
   ride the policy.
2. Drill in only where a section is missing or unclear: cnc_get_sr_policy for the PCE
   state and paths, cnc_get_sr_policy_routes for the hop-by-hop route,"""
        else:
            start = f"""\
1. This build has no one-call policy explainer, so join the pieces yourself, starting
   with cnc_get_sr_policy(headend='{headend}', endpoint='{endpoint}', color={color}) (color
   is an integer) for the PCE's view of the policy (state, origin, delegation, candidate
   paths and hops).
2. Then, section by section: cnc_get_sr_policy_routes for the hop-by-hop route,"""
        return f"""{head}

{start}
   cnc_get_sr_policy_metrics for the Optimization Engine's metrics,
   cnc_get_sr_policy_performance_metrics for the PM entry, cnc_get_lsp_delay(hours={hours},
   ...) and cnc_get_lsp_utilization(hours={hours}, ...) for measured NPM time series —
   pass hours={hours} to every drill-in call that takes a window, so it covers the same
   window as step 1 (a tool's own default is not necessarily {hours}, and a window over
   6 h answers hourly roll-ups instead of 5-minute samples, so the series would not be
   comparable) — cnc_find_services_on_transport for the services,
   cnc_list_topology_nodes to map a TE router-id to its host name.

Explain, in this order, using device host names (translate router-ids, giving the router-id
in parentheses once):
- Origin: pcep-flag-c 1 = PCE-initiated (created through Crosswork / the SR-PCE), 0 =
  configured on the head-end router (PCC-initiated); say which, and what that means for who
  can change or remove it.
- Delegation: pce-controlled true = the PCE computes the path and may re-optimise it;
  false = the router owns the path.
- Path: the active candidate path, its preference, the SID list / hops by name, and whether
  it follows the shortest IGP path or is diverted.
- Constraints: the optimisation metric (IGP / TE / delay), affinities, disjointness,
  bandwidth, protection, and any ODN template behind it.
- Metrics: separate MEASURED figures (NPM delay and utilisation series; SR-PM when it is
  configured) from MODELLED ones (the PCE's computed delay in the PM entry when SR-PM is
  not configured; the Optimization Engine's metrics) and label every number as one or the
  other.
- Services riding it: the VPNs from cnc_find_services_on_transport, or 'none found'.
- State: oper-state up / down, and the last change when known.

If the policy does not exist, say so and list the policies that head-end does have
(cnc_list_sr_policies(headend='{headend}')) instead of guessing. This is an explanation, not
a change: cnc_update_sr_policy / cnc_delete_sr_policy only on an explicit request, and a
PCC-initiated policy cannot be removed through the PCE at all.

{note}"""

    @_playbook(
        mcp,
        name="provision_l3vpn",
        title="Provision an L3VPN",
        description="Safely provision an IPv4 L3VPN through the NSO function pack: "
        "pre-flight checks, a dry run showing the device CLI, explicit confirmation, "
        "commit, then verification evidence. Never deletes without being asked.",
    )
    async def provision_l3vpn(
        vpn_id: Annotated[
            str,
            Field(description="Service name / NSO list key for the new L3VPN."),
        ],
        endpoints: Annotated[
            str,
            Field(
                description="The PE attachments: a JSON list of {node, interface, address, "
                "prefix_length, local_as?, id?} or a plain-language description of them."
            ),
        ],
        route_target: Annotated[
            str,
            Field(description="Route target, imported and exported (e.g. '0:65000:100')."),
        ] = "",
        route_distinguisher: Annotated[
            str,
            Field(description="The VRF's route distinguisher (e.g. '0:65000:100')."),
        ] = "",
        srv6_locator: Annotated[
            str,
            Field(
                description="Optional: the SRv6 locator name every PE uses for the VRF's "
                "per-VRF SIDs (the name under 'segment-routing srv6 locators' on the routers) "
                "— the VPN then rides SRv6 instead of MPLS. Leave empty for MPLS transport."
            ),
        ] = "",
    ) -> str:
        vpn_id, endpoints = _arg(vpn_id), endpoints.strip()
        rt = _arg(route_target) or _NOT_GIVEN
        rd = _arg(route_distinguisher) or _NOT_GIVEN
        locator = _arg(srv6_locator)
        registered = await registered_tool_names(mcp)
        transport = f"over SRv6 (locator '{locator}')" if locator else "over MPLS"
        head = (
            f"Provision the IPv4 L3VPN '{vpn_id}' {transport} through Crosswork's NSO L3VPN "
            "function pack, safely."
        )
        # The e2e composite is a write tool AND optional on a build: name it only when it
        # is actually registered, so its absence is never read as "that write is off".
        e2e = "cnc_provision_l3vpn_e2e" in registered
        write_tools = "cnc_create_l3vpn_service, cnc_nso_device_action"
        if e2e:
            write_tools = "cnc_create_l3vpn_service, cnc_provision_l3vpn_e2e, cnc_nso_device_action"
        note = writes_note(ctx, write_tools=write_tools)
        if e2e:
            commit = """\
4. Only after an explicit yes: cnc_provision_l3vpn_e2e (it commits, waits for the plan and
   verifies in one call — read its input schema), or the individual tools:"""
        else:
            commit = "4. Only after an explicit yes, commit and verify with the individual tools:"
        if locator:
            readiness_tool = (
                "cnc_srv6_readiness"
                if "cnc_srv6_readiness" in registered
                else "cnc_list_srv6_locators"
            )
            srv6_input = f"""\
- srv6_locator: {locator} (SRv6 transport: pass it as srv6_locator to the create tool;
  NSO puts the L3NM's srv6 container on the vpn-instance-profile and the dry run must show
  'segment-routing srv6 / locator {locator} / alloc mode per-vrf' under router bgp / vrf /
  address-family ipv4 unicast on EVERY PE — if it does not, stop.)"""
            srv6_preflight = f"""
   SRv6 pre-flight: {readiness_tool} must show every endpoint node advertising an SRv6
   locator (the topology carries the locator PREFIX, never its name — no tool can show
   the name '{locator}' there); confirm the name '{locator}' maps to that prefix on each
   PE with cnc_get_nso_device_config(host_name=<PE>, subtree='segment-routing/srv6')
   — its locators/locator <name> / prefix is the name-to-prefix map; a 404 'uri keypath
   not found' there means the router has no 'segment-routing srv6' at all. NSO does not
   check the name against the routers — a locator no PE holds renders fine in the dry
   run and fails on the box. No locator anywhere means the underlay is SR-MPLS only:
   stop and say what the routers need (locators + IS-IS IPv6);
   never provision over a locator that does not exist."""
            srv6_dry_run = ", srv6_locator='" + locator + "'"
            skipped_by = " (cnc_provision_l3vpn_e2e skips it and says so)" if e2e else ""
            srv6_trace = f"""
   For an SRv6 VPN skip the OAM trace: on this release it is MPLS LSP-ping and would trace
   the SR-MPLS LSP, not the SRv6 path{skipped_by} — verify on the routers or with
   cnc_get_srv6_locator_statistics(host_name=...) once an SRV6LOCATOR performance policy
   collects."""
        else:
            srv6_input = "- srv6_locator: (not given — MPLS transport)"
            srv6_preflight = ""
            srv6_dry_run = ""
            srv6_trace = ""
        return f"""{head}

Inputs:
- vpn_id: {vpn_id}
- endpoints: {endpoints}
  (cnc_create_l3vpn_service takes them as a JSON list of {{"node": <NSO device name>,
  "interface", "address", "prefix_length", "local_as" (optional), "id" (optional),
  "srv6_locator" (optional per-node override)}}; convert what you were given into that
  shape and show it before the dry run.)
- route_target: {rt}
- route_distinguisher: {rd}
{srv6_input}

Do it in this order and stop where told:
0. Check your tool list. If cnc_create_l3vpn_service is absent, it is not registered on
   this server (the last paragraph says why): say so, show the call you would have made,
   and stop.
1. Pre-flight, read-only: every endpoint node must be an NSO device that is in sync —
   cnc_check_device_nso_state(host_name=...) and, when in doubt, cnc_check_nso_device_sync;
   a head-end NSO considers out of sync answers 502 on commit (cnc_nso_device_action
   action='sync-from' fixes that, on an explicit request). A PE with no BGP process needs
   local_as in its endpoint entry, or the function pack rejects the service.
   cnc_get_vpn_service(vpn_id='{vpn_id}') tells you whether the name is already taken —
   creating an existing name REPLACES it wholesale, so stop and ask if it exists.{srv6_preflight}
2. Dry run: cnc_create_l3vpn_service(vpn_id='{vpn_id}', route_distinguisher=...,
   route_target=..., endpoints=<the JSON list>{srv6_dry_run}, dry_run=true). Show the
   operator the device CLI it returns, per PE, verbatim, and point out anything
   surprising: an extra auto-allocated route-target from the function pack's pool, a
   'router bgp' process it would create, an interface already in another VRF, a
   validation error.
3. STOP and ask for confirmation. Do not commit until the operator says yes to that CLI.
{commit}
   cnc_create_l3vpn_service with dry_run=false; cnc_wait_for_service_plan on the
   plan_yang_path the create returns (init -> config-apply -> ready);
   cnc_get_vpn_service_health and cnc_get_vpn_underlay_transport for the service; and,
   when the PEs have gNMI onboarded, cnc_start_oam_trace_route then
   cnc_wait_for_oam_trace_route for a data-plane trace. 'Error: the function pack rejected
   the service' is a verdict to report, not something to retry with guessed values.{srv6_trace}
5. Never delete anything (cnc_delete_vpn_service, cnc_delete_service) unless the operator
   explicitly asks — not to clean up, not to retry a failed commit.

End with the verification evidence: the plan state, the oper-status (op-unknown is normal
when Service Health is not monitoring the VPN), the transport it rides, and the trace
result — or, if you stopped earlier, exactly where and why.

{note}"""

    @_playbook(
        mcp,
        name="alarm_triage",
        title="Alarm triage",
        description="Sort the open alarms into act-now, possibly-stale and informational "
        "lists, confirming pod-health alarms against the live microservice state before "
        "reporting any outage.",
    )
    async def alarm_triage() -> str:
        registered = await registered_tool_names(mcp)
        note = writes_note(
            ctx,
            write_tools="cnc_acknowledge_alarm, cnc_annotate_alarm, cnc_clear_alarm",
        )
        if "cnc_alarm_triage" in registered:
            start = """\
1. Start with ONE call: cnc_alarm_triage. It reads Crosswork's own (system) alarms and the
   device alarms from the fault manager, checks the microservice behind each pod-health
   alarm, and sorts everything into act-now / possibly stale / informational.
2. Drill in only where needed: cnc_get_alarm(alarm_id=...) for one alarm's events and
   notes, cnc_search_alarms(text=..., open_only=...) for related alarms,
   cnc_list_device_alarms for the device side, cnc_list_events for the raw event stream,
   cnc_get_cluster_health / cnc_list_microservices(health='down') to confirm or refute a
   platform-health alarm."""
        else:
            start = """\
1. This build has no one-call triage tool, so read both lists yourself: cnc_search_alarms
   (open_only=true) for Crosswork's own (system) alarms and cnc_list_device_alarms for the
   device alarms from the fault manager; then cnc_list_microservices(health='down') for
   the microservice behind each pod-health alarm; and sort everything into act-now /
   possibly stale / informational by the rules below.
2. Drill in only where needed: cnc_get_alarm(alarm_id=...) for one alarm's events and
   notes, cnc_search_alarms(text=..., open_only=...) for related alarms, cnc_list_events
   for the raw event stream, cnc_get_cluster_health to confirm or refute a
   platform-health alarm."""
        return f"""Triage the open alarms on this Crosswork Network Controller.

{start}

Rules:
- Never report a pod-health alarm ('<pod> is down.') as a current outage without the
  microservice check: Crosswork does not auto-clear these, so an open one with 0 events,
  unchanged for a week or more, whose pod cnc_list_microservices reports healthy is stale,
  not an outage. up_time there is container age, not time since it was last healthy.
- A Cleared alarm's description is its clearing event's text; the fault is in its events.
- Device alarms (interface down, adjacency down) and Crosswork's own alarms are two
  separate lists; say which list each finding came from.

Answer with three lists, newest first, each entry 'severity · what · since · evidence':
- ACT NOW — live faults with recent events, or a component a live check confirms unhealthy.
- POSSIBLY STALE — open, old, no events, and contradicted by a live check (say what the
  check saw).
- INFORMATIONAL — everything else: cleared, acknowledged, or purely notification.
Then one line: what was not checked.

Do not acknowledge, annotate or clear anything (cnc_acknowledge_alarm, cnc_annotate_alarm,
cnc_clear_alarm) unless asked explicitly — notes and acknowledgements are permanent.

{note}"""

    @_playbook(
        mcp,
        name="explain_service",
        title="Explain a service",
        description="Explain one service from the service inventory (VPN, SR policy, ODN "
        "template, slice, tunnel): what it is, its intent, plan state, operational state "
        "and the transport it rides.",
    )
    async def explain_service(
        service: Annotated[
            str,
            Field(description="Service name as the inventory lists it, or its NSO yang-path."),
        ],
    ) -> str:
        service = _arg(service)
        registered = await registered_tool_names(mcp)
        note = writes_note(
            ctx,
            write_tools="cnc_provision_service, cnc_delete_service, cnc_delete_vpn_service",
        )
        if "cnc_explain_service" in registered:
            start = f"""\
1. Start with ONE call: cnc_explain_service for '{service}' — pass a bare service name as
   name=..., an NSO yang-path as yang_path=..., or an L3/L2 VPN id as vpn_id=... (read the
   input schema). It finds the service in the inventory, reads the NSO intent and the
   plan, and — for a VPN — its oper-status and the underlay transport.
2. Drill in only where a section is missing: cnc_list_services(name_prefix=...) when the
   name is ambiguous, cnc_get_service(yang_path=...) for the intent and NSO bookkeeping,
   cnc_get_service_plan / cnc_wait_for_service_plan for the plan, cnc_list_sub_services
   for the services it created, cnc_get_vpn_service / cnc_get_vpn_service_health /
   cnc_get_vpn_underlay_transport for VPN operational data, cnc_get_sr_policy for a policy
   it rides, cnc_find_services_on_transport for the reverse question (what rides a policy)."""
        else:
            start = f"""\
1. This build has no one-call service explainer, so assemble it yourself: find
   '{service}' with cnc_list_services(name_prefix=...) (a service name; skip this when you
   were given its NSO yang-path), read the intent and NSO bookkeeping with
   cnc_get_service(yang_path=...), the plan with cnc_get_service_plan, and — for a VPN —
   its oper-status and the underlay transport with cnc_get_vpn_service /
   cnc_get_vpn_service_health / cnc_get_vpn_underlay_transport.
2. Drill in only where a section is missing: cnc_wait_for_service_plan for a plan still
   converging, cnc_list_sub_services for the services it created, cnc_get_sr_policy for a
   policy it rides, cnc_find_services_on_transport for the reverse question (what rides a
   policy)."""
        return f"""Explain the service '{service}' in Crosswork's service inventory.

{start}

Explain, using device host names:
- What it is: the type (policy, odn-template, cs-sr-te-policy, ietf-l3vpn, ietf-l2vpn,
  slice-service, tunnel), who created it, when it was last modified.
- Intent: the endpoints / head-ends and the attachment (VRF, interfaces, route targets and
  distinguisher; color and constraints for a policy), in plain words.
- Plan: init -> config-apply -> ready; whether every component is ready and which devices
  NSO touched. A failed component is the first thing to report.
- Operational state: oper-status (op-unknown is normal when Service Health is not
  monitoring it), the transport it rides, and whether that transport is up.
- What to watch: anything the evidence shows as degraded, unverified, or not installed.

If the service does not exist, say so and offer the closest names from cnc_list_services.
This is an explanation, not a change: cnc_provision_service, cnc_delete_service and
cnc_delete_vpn_service only on an explicit request.

{note}"""

    @_playbook(
        mcp,
        name="srv6_readiness",
        title="SRv6 readiness check",
        description="Is the network ready for SRv6 services? Locators on every SR-capable "
        "router, End.X SIDs on every adjacency, SRv6 policies, locator-traffic collection — "
        "with a READY / PARTIAL / NONE verdict and what the routers still need.",
    )
    async def srv6_readiness() -> str:
        registered = await registered_tool_names(mcp)
        note = writes_note(
            ctx,
            write_tools="cnc_create_performance_policy, cnc_create_l3vpn_service, "
            "cnc_create_sr_policy_service, cnc_create_odn_template",
        )
        explain = "cnc_explain_sr_policy"
        policy_tool = explain if explain in registered else "cnc_get_sr_policy"
        if "cnc_srv6_readiness" in registered:
            start = """\
1. Start with ONE call: cnc_srv6_readiness (read its input schema; the topology network
   defaults to the standard one). It joins the topology summary's SRv6 flags, the locators
   derived from every node's SRv6 node SIDs, per-node and per-adjacency SRv6 state (End.X
   coverage), the SRv6 SR policies, whether an SRV6LOCATOR performance policy collects
   locator traffic, and which routers are IOS XR — and answers READY / PARTIAL / NONE.
2. Drill in only where a section is unavailable or a finding needs detail:"""
        else:
            start = """\
1. This build has no one-call readiness tool, so assemble the picture yourself:
   cnc_get_topology_summary (its srv6_network_type / srv6_capable_nodes /
   srv6_adjacency_links / node_dataplanes counters), cnc_list_srv6_locators (one row per
   node and locator, derived from the SRv6 node SIDs), cnc_list_topology_links (the
   adjacencies and which carry an End.X SID), cnc_list_sr_policies(dataplane='srv6'),
   cnc_list_performance_policies (is there a policy on the SRV6LOCATOR template?) and
   cnc_list_devices (which routers are IOS XR — the family that runs SRv6 here).
2. Then, where a finding needs detail:"""
        return f"""Check whether this Crosswork-managed network is ready for SRv6 services.

{start}
   cnc_get_topology_node(node_id=...) for one router's SRv6 node SIDs, their structure
   (block / node / function lengths — the locator is the SID masked to block + node) and
   its Flex-Algos; cnc_get_topology_link(link_id=...) for one adjacency's End.X SIDs;
   cnc_get_srv6_locator_statistics(host_name=...) for a locator's measured egress rate
   (empty until an SRV6LOCATOR performance policy collects); cnc_get_performance_policy
   for that policy; {policy_tool} for an SRv6 policy (keyed by the nodes' IPv6 TE
   router-ids). Do not repeat a call already made.
3. Interpretation rules: the topology model has no locator object — a 'locator' is derived
   from each node's SRv6 node SID and its SID structure, so 'no locator' means the router
   advertises no SRv6 locator in the IGP (or the SR-PCE feed carries no SRv6 state yet),
   never a Crosswork setting. SR-MPLS and SRv6 coexist on a node (dataplane 'both'); a node
   with SR-MPLS only is not broken, it is simply not SRv6-capable yet. An adjacency is
   listed once per direction — both directions need an End.X SID. Only IOS XR routers are
   expected to advertise SRv6; say which routers are not XR rather than counting them as
   missing. An SR policy's dataplane is derived (SRv6 binding SID / SRv6 hop objects / IPv6
   keys) because the NBI has no dataplane leaf; SRv6 policies come from the NSO SR-TE
   function pack (cnc_create_sr_policy_service / cnc_create_odn_template with
   srv6_locator), never from the Optimization Engine, which is SR-MPLS only. The OAM trace
   route is MPLS-only on this release: it cannot verify an SRv6 path.

Answer with exactly these four headings:
- Verdict — READY / PARTIAL / NONE in one sentence, and what it rests on (nodes with a
  locator out of the SR-capable XR nodes, adjacencies with End.X, SRv6 policies, locator
  collection).
- Evidence — the facts (tool, field, value) per node and per adjacency, nothing inferred;
  name every node without a locator and every adjacency without End.X.
- What the routers still need — for NONE: SRv6 locators ('segment-routing srv6 locators')
  and IS-IS IPv6 (IPv6 loopbacks / router-ids, the IPv6 address-family advertising the
  locator) on the routers — the SR-PCE feed then carries the locators, End SIDs and End.X
  SIDs to Crosswork by itself, nothing is configured on Crosswork; for PARTIAL: the same,
  per named node or link, plus cnc_create_performance_policy(template='SRV6LOCATOR', ...)
  when locator traffic is not collected; for READY: the next step (an L3VPN or SR policy
  over SRv6 through the provisioning tools with srv6_locator, dry_run=true first).
- Not checked — sections that answered an error, pages not scanned, and the standing
  caveat that the SRv6 renderings follow the platform's 7.2 model and are unverified
  until a live SRv6 feed has been seen.

This is a read-only check: create nothing (cnc_create_performance_policy,
cnc_create_l3vpn_service, cnc_create_sr_policy_service, cnc_create_odn_template) unless
the operator asks, and then dry_run=true first.
{note}"""

    logger.debug("Registered %d prompts", len(PROMPT_NAMES))
