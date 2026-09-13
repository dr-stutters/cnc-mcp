"""Tool registry.

Each tool module exposes register(mcp, ctx). One module per Crosswork API area.
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from cnc_mcp.safety import AppContext
from cnc_mcp.tools import (
    admin,
    credentials,
    data_gateway,
    device_config,
    devices,
    fault,
    inventory_extras,
    nso,
    physical_inventory,
    platform,
    providers,
    sr_te_operations,
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
]


def register_all_tools(mcp: MCPServer, ctx: AppContext) -> None:
    for module in ALL_MODULES:
        module.register(mcp, ctx)
