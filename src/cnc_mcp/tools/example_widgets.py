"""EXAMPLE tool module — the canonical pattern for every real tool module.

TEMPLATE: delete this module (and its entry in tools/__init__.py) once real
tool modules exist. It demonstrates, against a fictional /v1/widgets API:

- list tool: pagination envelope + markdown/json response_format
- get tool: single resource by ID
- create tool: write-gated, non-destructive
- delete tool: write-gated, destructive

Conventions every tool must follow:
- tool names: {service}_{action}_{resource}, snake_case
- inputs: FLAT function parameters, each `Annotated[type, Field(...)]` with a
  description (give an example value) and constraints (ge/le/min_length/...).
  Never wrap the arguments in a single Pydantic model: that buries the schema
  behind a $ref, forces agents to nest arguments under one key, and turns their
  most common mistake (flat arguments) into a raw validation traceback.
- returns: str; errors returned as "Error: ..." strings via format_error, never raised
- every response passes through finalize() for the size cap
- registration via register_tool() so annotations and write-gating are enforced
"""

from __future__ import annotations

from typing import Annotated

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cnc_mcp.errors import format_error
from cnc_mcp.formatting import ResponseFormat, finalize, pagination_envelope, to_json
from cnc_mcp.safety import AppContext, register_tool


def _widgets_markdown(widgets: list[dict], envelope: dict) -> str:
    lines = [f"# Widgets ({envelope['count']} shown, total {envelope['total']})", ""]
    for w in widgets:
        lines.append(f"- **{w.get('name', '?')}** ({w.get('id', '?')})")
        if w.get("description"):
            lines.append(f"  - {w['description']}")
    if envelope["has_more"]:
        lines.append("")
        lines.append(f"More available: repeat with offset={envelope['next_offset']}.")
    return "\n".join(lines)


def register(mcp: MCPServer, ctx: AppContext) -> None:
    settings, client = ctx.settings, ctx.client

    @register_tool(
        mcp,
        ctx,
        name="cnc_list_widgets",
        title="List Widgets",
        read_only=True,
        idempotent=True,
    )
    async def cnc_list_widgets(
        name_filter: Annotated[
            str | None,
            Field(
                description="Case-insensitive substring to filter widget names (e.g. 'edge').",
                max_length=200,
            ),
        ] = None,
        limit: Annotated[
            int, Field(description="Maximum results to return.", ge=1, le=100)
        ] = 20,
        offset: Annotated[
            int, Field(description="Results to skip, for pagination.", ge=0)
        ] = 0,
        response_format: Annotated[
            ResponseFormat,
            Field(description="'markdown' for human-readable output, 'json' for complete data."),
        ] = ResponseFormat.MARKDOWN,
    ) -> str:
        """List widgets on the platform, with optional name filtering and pagination.

        Read-only. Use this to discover widgets before fetching details with
        cnc_get_widget.

        Returns:
            str: Markdown listing, or JSON:
            {"total": int|null, "count": int, "offset": int,
             "items": [{"id": str, "name": str, "description": str}, ...],
             "has_more": bool, "next_offset": int|null}
            On failure: "Error: <actionable message>".
        """
        try:
            query: dict = {"limit": limit, "offset": offset}
            if name_filter:
                query["name"] = name_filter
            data = await client.request_json("GET", "/v1/widgets", params=query)
            items = data.get("items", [])
            envelope = pagination_envelope(
                items, total=data.get("total"), offset=offset, limit=limit
            )
            if response_format is ResponseFormat.JSON:
                return finalize(to_json(envelope), settings)
            return finalize(_widgets_markdown(items, envelope), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_get_widget",
        title="Get Widget Details",
        read_only=True,
        idempotent=True,
    )
    async def cnc_get_widget(
        widget_id: Annotated[
            str, Field(description="Widget ID (e.g. 'w-1234').", min_length=1, max_length=100)
        ],
    ) -> str:
        """Get full details for one widget by ID.

        Read-only. Find IDs with cnc_list_widgets first.

        Returns:
            str: JSON object with all widget fields, or "Error: ..." on failure
            (404 -> the ID doesn't exist; check it with cnc_list_widgets).
        """
        try:
            data = await client.request_json("GET", f"/v1/widgets/{widget_id}")
            return finalize(to_json(data), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_create_widget",
        title="Create Widget",
        read_only=False,
        destructive=False,
        idempotent=False,
    )
    async def cnc_create_widget(
        name: Annotated[
            str, Field(description="Name for the new widget.", min_length=1, max_length=100)
        ],
        description: Annotated[
            str | None, Field(description="Optional description.", max_length=500)
        ] = None,
    ) -> str:
        """Create a new widget on the platform.

        WRITE operation — only registered when *_ENABLE_WRITES=true. The POST is
        not auto-retried (default for non-idempotent methods), so a lost response
        can't silently create duplicates.

        Returns:
            str: JSON of the created widget (including its new ID), or
            "Error: ..." (409 -> a widget with this name may already exist).
        """
        try:
            body: dict = {"name": name}
            if description:
                body["description"] = description
            data = await client.request_json("POST", "/v1/widgets", json_body=body)
            return finalize(to_json(data), settings)
        except Exception as e:
            return format_error(e)

    @register_tool(
        mcp,
        ctx,
        name="cnc_delete_widget",
        title="Delete Widget",
        read_only=False,
        destructive=True,
        idempotent=True,
    )
    async def cnc_delete_widget(
        widget_id: Annotated[
            str,
            Field(description="ID of the widget to delete (e.g. 'w-1234').", min_length=1,
                  max_length=100),
        ],
    ) -> str:
        """Permanently delete a widget by ID.

        DESTRUCTIVE write — only registered when *_ENABLE_WRITES=true. Verify the
        target with cnc_get_widget before deleting.

        Returns:
            str: Confirmation message, or "Error: ..." on failure.
        """
        try:
            await client.request_json("DELETE", f"/v1/widgets/{widget_id}")
            return f"Widget {widget_id} deleted."
        except Exception as e:
            return format_error(e)
