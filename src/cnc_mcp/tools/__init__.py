"""Tool registry.

Each tool module exposes register(mcp, ctx). One module per Crosswork API area.
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from cnc_mcp.safety import AppContext
from cnc_mcp.tools import credentials, devices, platform, providers, topology

ALL_MODULES = [
    devices,  # network devices (inventory nodes)
    credentials,  # credential profiles
    providers,  # SR-PCE / NSO / ... providers
    topology,  # topology graph (LLDP + SR-PCE)
    platform,  # tags, users, applications, alarms, inventory jobs
]


def register_all_tools(mcp: MCPServer, ctx: AppContext) -> None:
    for module in ALL_MODULES:
        module.register(mcp, ctx)
