"""Write-safety gating and tool registration.

Every tool in this server is registered through register_tool(), which:
- forces a decision on read_only/destructive/idempotent annotations
- refuses to register write tools unless settings.enable_writes is true

With writes disabled (the default), agents never even see the write tools, so a
misbehaving prompt can't touch production systems or their
configuration. Enable writes per-deployment with *_ENABLE_WRITES=true.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from mcp.server.mcpserver import MCPServer

from cnc_mcp.client import ApiClient
from cnc_mcp.config import Settings

logger = logging.getLogger(__name__)


@dataclass
class AppContext:
    """Dependencies handed to every tool module's register() function."""

    settings: Settings
    client: ApiClient


def register_tool(
    mcp: MCPServer,
    ctx: AppContext,
    *,
    name: str,
    title: str,
    read_only: bool,
    destructive: bool = False,
    idempotent: bool = False,
    open_world: bool = True,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator factory used instead of @mcp.tool for every tool in this server.

    Write tools (read_only=False) are silently skipped when writes are disabled;
    the function is returned unregistered so module import still succeeds.
    """
    if not read_only and not ctx.settings.enable_writes:

        def skip(fn: Callable[..., Any]) -> Callable[..., Any]:
            logger.info("Write tool %s not registered (enable_writes is false)", name)
            return fn

        return skip

    return mcp.tool(
        name=name,
        title=title,
        annotations={
            "read_only_hint": read_only,
            "destructive_hint": destructive,
            "idempotent_hint": idempotent,
            "open_world_hint": open_world,
        },
    )
