"""Server assembly and entry point.

This is a stdio MCP server: stdout belongs to the protocol, so ALL logging goes
to stderr. Never print() from tool code.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp.server.mcpserver import MCPServer
from pydantic import ValidationError

from cnc_mcp.auth import AuthStrategy, LoginTokenAuth, NoAuth, StaticTokenAuth
from cnc_mcp.client import ApiClient
from cnc_mcp.config import Settings
from cnc_mcp.errors import PlatformError
from cnc_mcp.safety import AppContext
from cnc_mcp.tools import register_all_tools

SERVER_NAME = "cnc_mcp"

logger = logging.getLogger(__name__)


def create_auth(settings: Settings) -> AuthStrategy:
    """Choose the auth strategy for this platform.

    TEMPLATE: replace this with the real strategy during specialization (see the
    strategy overview in auth.py). The default below only exists so the
    template runs out of the box:
    - api_token set        -> StaticTokenAuth (Authorization: Bearer <token>)
    - username/password    -> LoginTokenAuth against a placeholder /auth/login
    - neither              -> NoAuth
    """
    if settings.api_token:
        return StaticTokenAuth(settings.api_token)
    if settings.username:
        return LoginTokenAuth(
            "/auth/login",
            settings.username,
            settings.password,
            login_style="json",
            token_location="json",
            token_field="token",
        )
    return NoAuth()


def build_instructions(settings: Settings) -> str:
    """Server-level instructions shown to connecting agents."""
    # TEMPLATE: describe the platform, what the tools cover, and any conventions
    # (ID formats, object model quirks, pagination) the agent should know.
    prefix = Settings.model_config.get("env_prefix", "")
    lines = [
        "Tools for the Cnc platform API.",
        "List tools support limit/offset pagination and a response_format of "
        "'markdown' (default, human-readable) or 'json' (complete data).",
    ]
    if settings.enable_writes:
        lines.append(
            "Write tools are ENABLED and modify the live platform. Confirm intent "
            "before creating, changing, or deleting anything."
        )
    else:
        lines.append(
            "This server is READ-ONLY: write tools are not registered. To enable "
            f"them, set the {prefix}ENABLE_WRITES=true environment variable and restart."
        )
    return "\n".join(lines)


def build_server(settings: Settings | None = None) -> MCPServer:
    """Wire settings, auth, client, and tools into an MCPServer."""
    settings = settings or Settings()  # type: ignore[call-arg]  # env supplies base_url
    auth = create_auth(settings)
    client = ApiClient(settings, auth)
    ctx = AppContext(settings=settings, client=client)

    @asynccontextmanager
    async def lifespan(_server: MCPServer) -> AsyncIterator[AppContext]:
        try:
            yield ctx
        finally:
            await client.aclose()

    mcp = MCPServer(SERVER_NAME, instructions=build_instructions(settings), lifespan=lifespan)
    register_all_tools(mcp, ctx)
    return mcp


def main() -> None:
    """Console entry point (stdio transport)."""
    try:
        settings = Settings()  # type: ignore[call-arg]  # env supplies base_url
    except ValidationError as e:
        missing = ", ".join(str(err["loc"][0]).upper() for err in e.errors())
        prefix = Settings.model_config.get("env_prefix", "")
        print(
            f"Configuration error — check environment variables ({prefix}{missing}).\n{e}",
            file=sys.stderr,
        )
        raise SystemExit(1) from e

    logging.basicConfig(
        stream=sys.stderr,
        level=settings.log_level.upper(),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    logger.info("Starting %s (writes %s)", SERVER_NAME, "ON" if settings.enable_writes else "off")
    try:
        server = build_server(settings)
    except PlatformError as e:
        # Auth strategies raise PlatformError for incomplete credentials — fail fast
        # with a clean message, not a traceback.
        print(f"Configuration error: {e}", file=sys.stderr)
        raise SystemExit(1) from e
    server.run()


if __name__ == "__main__":
    main()
