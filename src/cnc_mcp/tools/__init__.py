"""Tool registry.

Each tool module exposes register(mcp, ctx). Add new modules to ALL_MODULES —
one module per platform API area (e.g. devices, policies, labs).
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from cnc_mcp.safety import AppContext
from cnc_mcp.tools import example_widgets

ALL_MODULES = [
    example_widgets,  # TEMPLATE: delete once real tool modules exist
]


def register_all_tools(mcp: MCPServer, ctx: AppContext) -> None:
    for module in ALL_MODULES:
        module.register(mcp, ctx)
