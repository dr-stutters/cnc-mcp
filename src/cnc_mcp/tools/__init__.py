"""Tool registry.

Each tool module exposes register(mcp, ctx). One module per Crosswork API area;
the module name is the tool AREA that ``CNC_MCP_WRITE_AREAS`` selects by.
``register_all_tools`` registers every module, then validates the gating
configuration against what was registered (an unknown area or tool name fails
startup; so does a ``requires`` that names a tool registered by a later module; an
area listed in ``CNC_MCP_WRITE_AREAS`` whose tools are all read-only is a WARNING —
the entry enables nothing) and logs one summary line.
"""

from __future__ import annotations

import difflib
import logging
from types import ModuleType

from mcp.server.mcpserver import MCPServer

from cnc_mcp.errors import PlatformError
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import (
    admin,
    collection,
    composite,
    credentials,
    data_gateway,
    device_config,
    devices,
    ems_jobs,
    fault,
    grouping,
    inventory_extras,
    lcm_csm,
    notifications,
    nso,
    oam,
    performance,
    physical_inventory,
    platform,
    providers,
    service_provisioning,
    services,
    sr_te_operations,
    swim_ztp,
    te_state,
    topology,
)

ALL_MODULES = [
    devices,  # network devices (inventory nodes)
    credentials,  # credential profiles
    providers,  # SR-PCE / NSO / ... providers
    topology,  # topology graph on the RESTCONF NBI (SR-PCE gRPC feed + LLDP)
    te_state,  # TE state on the NBI: SR / P2MP / RSVP-TE policies, performance metrics
    sr_te_operations,  # Optimization Engine: SR policy create/modify/delete, dry run, routes
    platform,  # tags, users, applications, alarms, inventory jobs
    data_gateway,  # Crosswork Data Gateway: gateways, pools, metrics, destinations, mapping
    nso,  # NSO integration: device actions, policy, NSO's own device view, sync waits
    admin,  # platform admin: cluster/node/microservice health, app manager, certs, RBAC
    inventory_extras,  # device summaries, tags assign/unassign, device lock, geo-coordinates
    fault,  # alarm lifecycle (ack/note/clear), events, settings, suppression policies
    device_config,  # config backups and jobs, templates and deployments
    physical_inventory,  # EMF RESTCONF inventory: nodes, termination points
    notifications,  # webhook subscriptions, notification streams
    collection,  # collection-service job status
    grouping,  # device/port groups: rule conditions, root groups, hierarchies, members
    lcm_csm,  # LCM domains/config/recommendations, CSM bandwidth pools and CS policy paths
    services,  # CAT service inventory reads, VPN operational data, plans, function packs
    service_provisioning,  # T-SDN CFP writes through the NSO proxy (ODN, policies, SID lists, VPN)
    performance,  # PM policies, dashboards, retention; NPM LSP / interface analytics
    oam,  # Optimization Engine OAM trace routes; Service Health probe status
    swim_ztp,  # SWIM repository / preferences / jobs; ZTP profiles, devices, serials, files, images
    ems_jobs,  # EMS inventory scheduler jobs: list, run now, suspend, resume, wait
    composite,  # one-call playbooks composed from the tools above (keep last: `requires`)
]

# How many close matches an unknown DISABLED_TOOLS name is answered with: the full
# tool list (245 names, ~6.5 KB) is unreadable in a one-line startup error.
CLOSE_TOOL_NAMES = 5
FULL_TOOL_LIST_HINT = "run `uv run python scripts/mcp_cli.py list` for the full tool list"

logger = logging.getLogger(__name__)


def area_name(module: ModuleType) -> str:
    """The area a tool module is selected by: its bare name (``devices``)."""
    return module.__name__.rsplit(".", 1)[-1]


def all_areas() -> list[str]:
    return [area_name(module) for module in ALL_MODULES]


def register_all_tools(mcp: MCPServer, ctx: AppContext) -> None:
    for module in ALL_MODULES:
        module.register(mcp, ctx)
    validate_gating(ctx)
    logger.info("%s", gating_summary(ctx))


def closest_name(value: str, valid: list[str]) -> str | None:
    """The valid name closest to ``value``: difflib's best match, else the first valid
    name that starts with it (``sr_te`` -> ``sr_te_operations``), else None."""
    match = difflib.get_close_matches(value, valid, n=1, cutoff=0.6)
    if match:
        return match[0]
    return next((name for name in valid if name.startswith(value)), None)


def _unknown_names(
    bad: list[str], valid: list[str], what: str, variable: str, *, list_all: bool = True
) -> str:
    """One sentence per unknown name with its closest valid name, then the valid list —
    or, with ``list_all`` false (the tool list), the few closest names and where to
    see the whole list."""
    lines = []
    for value in bad:
        match = closest_name(value, valid)
        hint = f" (did you mean '{match}'?)" if match else ""
        lines.append(f"{variable} names an unknown {what} '{value}'{hint}.")
    if list_all:
        lines.append(f"Valid {what} names: {', '.join(valid)}.")
        return " ".join(lines)
    close: list[str] = []
    for value in bad:
        for name in difflib.get_close_matches(value, valid, n=CLOSE_TOOL_NAMES, cutoff=0.6):
            if name not in close:
                close.append(name)
    if close:
        lines.append(f"Closest {what} names: {', '.join(close)}.")
    lines.append(f"{len(valid)} {what} names in this build; {FULL_TOOL_LIST_HINT}.")
    return " ".join(lines)


def write_areas_without_writes(ctx: AppContext) -> list[str]:
    """The areas ``write_areas`` names whose tools are all read-only (registered or
    not): such an entry enables nothing."""
    areas_with_writes = {r.area.lower() for r in ctx.tools.values() if not r.read_only}
    return sorted(ctx.settings.write_area_set - areas_with_writes)


def requirement_problems(ctx: AppContext) -> list[str]:
    """Programming errors in ``register_tool(requires=...)``, visible only once every
    module has registered: a required name no module defines (a typo, or a module
    missing from ALL_MODULES), or a required tool that IS registered while the
    requiring tool was skipped for needing it — the required tool's module comes
    after the requiring one in ALL_MODULES, so the check ran before it existed."""
    problems: list[str] = []
    for record in ctx.tools.values():
        reason = record.skipped_reason or ""
        for required in record.requires:
            needed = ctx.tools.get(required)
            skipped_for_it = reason.startswith(f"needs {required} (")
            if needed is None:
                problems.append(
                    f"tool {record.name} (area {record.area}) requires {required}, which no "
                    "tool module defines"
                )
            elif skipped_for_it and (needed.registered or reason.endswith("(area unknown)")):
                problems.append(
                    f"tool {record.name} (area {record.area}) was skipped for needing "
                    f"{required}, which area {needed.area} defines later: {needed.area} must "
                    f"come before {record.area} in ALL_MODULES"
                )
    return problems


def read_only_areas_warning(ctx: AppContext) -> str | None:
    """The WARNING for a ``write_areas`` entry that names a real area whose tools are
    all read-only (``CNC_MCP_WRITE_AREAS=topology``): the entry enables nothing, and
    the instructions still say writes are on for it. A warning, not a failure — the
    configuration is harmless, only surprising — logged by ``validate_gating``."""
    prefix = ctx.settings.env_prefix
    areas = set(all_areas())
    read_only_areas = [a for a in write_areas_without_writes(ctx) if a in areas]
    if not read_only_areas:
        return None
    with_writes = sorted({r.area for r in ctx.tools.values() if not r.read_only})
    noun = "the area" if len(read_only_areas) == 1 else "the areas"
    return (
        f"{prefix}WRITE_AREAS names {noun} {', '.join(read_only_areas)}, whose tools are "
        "all read-only — the entry enables nothing. Areas with write tools: "
        f"{', '.join(with_writes)}."
    )


def validate_gating(ctx: AppContext) -> None:
    """Fail startup (PlatformError, reported as a configuration error) when
    ``write_areas`` names an area that is not a tools/ module, or ``disabled_tools``
    names a tool no module registers (registered or skipped): a misspelt entry would
    otherwise silently gate nothing. An area whose tools are all read-only is logged
    as a WARNING (``read_only_areas_warning``), not fatal. A ``requires`` that cannot
    be satisfied by registration order is a bug in this package, not in the
    configuration, and raises RuntimeError."""
    settings = ctx.settings
    prefix = settings.env_prefix
    problems: list[str] = []
    areas = all_areas()
    bad_areas = sorted(settings.write_area_set - set(areas))
    if bad_areas:
        problems.append(_unknown_names(bad_areas, areas, "area", f"{prefix}WRITE_AREAS"))
    names = sorted(ctx.tools)
    bad_tools = sorted(settings.disabled_tool_set - {n.lower() for n in names})
    if bad_tools:
        problems.append(
            _unknown_names(bad_tools, names, "tool", f"{prefix}DISABLED_TOOLS", list_all=False)
        )
    if problems:
        raise PlatformError(" ".join(problems))
    bugs = requirement_problems(ctx)
    if bugs:
        raise RuntimeError("tool registration order: " + "; ".join(bugs))
    warning = read_only_areas_warning(ctx)
    if warning:
        logger.warning("%s", warning)


def gating_summary(ctx: AppContext) -> str:
    """The startup line: counts, write areas in force, disabled tools, dry-run state."""
    settings = ctx.settings
    records = list(ctx.tools.values())
    registered = [r for r in records if r.registered]
    reads = sum(1 for r in registered if r.read_only)
    writes = len(registered) - reads
    if not settings.enable_writes:
        write_mode = "off"
    elif settings.write_area_set:
        write_mode = "on for areas " + ", ".join(sorted(settings.write_area_set))
    else:
        write_mode = "on for all areas"
    disabled = sorted(settings.disabled_tool_set)
    return (
        f"Registered {len(registered)} of {len(records)} tools ({reads} read, {writes} write); "
        f"writes {write_mode}; disabled tools: {', '.join(disabled) if disabled else 'none'}; "
        f"dry-run {'ON' if settings.dry_run else 'off'}"
    )
