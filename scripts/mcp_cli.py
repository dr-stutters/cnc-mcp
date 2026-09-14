"""Drive the cnc-mcp server over the real MCP stdio protocol from the command line.

The server is started exactly as an MCP client would start it (``uv run
cnc-mcp`` in this checkout, credentials from ``.env``), the MCP handshake is
performed, and the tool is called through ``tools/call`` — so what you see is
what an agent sees: the tool list, the input schemas, the ``instructions``
text, and the tool's text answer.

    uv run python scripts/mcp_cli.py instructions
    uv run python scripts/mcp_cli.py list [--json] [--writes]
    uv run python scripts/mcp_cli.py schema <tool>
    uv run python scripts/mcp_cli.py call <tool> '<json arguments>' [--writes]
    uv run python scripts/mcp_cli.py prompts
    uv run python scripts/mcp_cli.py prompt <name> ['<json arguments>'] [--writes]

``prompts`` lists the server's MCP prompts (name, title, description, arguments)
through ``prompts/list``; ``prompt`` renders one through ``prompts/get`` and
prints each message's role and text — with ``--writes`` the rendered text says
the write tools are enabled, without it that the server is read-only.
``--writes`` (before or after the command) starts the server with
``CNC_MCP_ENABLE_WRITES=true`` so the write tools are registered. The server's
own logging is held at WARNING unless ``CNC_MCP_LOG_LEVEL`` is set. Exit status
is 1 when the tool answered an ``Error:`` text or the call itself failed, so
shell loops can branch on it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from mcp import types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError

REPO = Path(__file__).resolve().parent.parent


def server_params(writes: bool) -> StdioServerParameters:
    env = dict(os.environ)
    env["CNC_MCP_ENABLE_WRITES"] = "true" if writes else "false"
    env.setdefault("CNC_MCP_LOG_LEVEL", "WARNING")  # keep stderr quiet unless asked for
    return StdioServerParameters(command="uv", args=["run", "cnc-mcp"], cwd=str(REPO), env=env)


async def with_session(writes: bool, action):
    async with stdio_client(server_params(writes)) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            return await action(session, init)


async def cmd_instructions(args) -> int:
    async def action(session, init):
        print(init.instructions or "(no instructions)")
        return 0

    return await with_session(args.writes, action)


async def cmd_list(args) -> int:
    async def action(session, init):
        result = await session.list_tools()
        tools = sorted(result.tools, key=lambda t: t.name)
        if args.json:
            print(
                json.dumps(
                    [
                        {
                            "name": t.name,
                            "title": t.title,
                            "description": t.description,
                            "inputSchema": t.input_schema,
                            "annotations": t.annotations.model_dump(exclude_none=True)
                            if t.annotations
                            else None,
                        }
                        for t in tools
                    ],
                    indent=1,
                )
            )
        else:
            for t in tools:
                first = (t.description or "").strip().splitlines()[0] if t.description else ""
                ann = t.annotations
                kind = "read " if ann and ann.read_only_hint else "WRITE"
                print(f"{kind} {t.name}: {first}")
            print(f"\n{len(tools)} tools", file=sys.stderr)
        return 0

    return await with_session(args.writes, action)


async def cmd_schema(args) -> int:
    async def action(session, init):
        result = await session.list_tools()
        for t in result.tools:
            if t.name == args.tool:
                print(t.description or "")
                print("\n--- input schema ---")
                print(json.dumps(t.input_schema, indent=1))
                if t.annotations:
                    print("\n--- annotations ---")
                    print(json.dumps(t.annotations.model_dump(exclude_none=True)))
                return 0
        print(f"no tool named {args.tool}", file=sys.stderr)
        return 1

    return await with_session(True, action)


async def cmd_call(args) -> int:
    try:
        arguments = json.loads(args.arguments) if args.arguments else {}
    except json.JSONDecodeError as e:
        print(f"arguments are not valid JSON: {e}", file=sys.stderr)
        return 2

    async def action(session, init):
        result = await session.call_tool(args.tool, arguments)
        text = ""
        if isinstance(result, types.CallToolResult):
            text = "".join(
                block.text for block in result.content if isinstance(block, types.TextContent)
            )
            print(text, flush=True)
            if result.is_error:
                return 1
        else:
            print(result, flush=True)
        return 1 if text.startswith("Error:") else 0

    return await with_session(args.writes, action)


async def cmd_prompts(args) -> int:
    async def action(session, init):
        result = await session.list_prompts()
        for p in sorted(result.prompts, key=lambda p: p.name):
            title = f" — {p.title}" if p.title else ""
            print(f"{p.name}{title}")
            if p.description:
                print(f"    {p.description}")
            for a in p.arguments or []:
                flag = "required" if a.required else "optional"
                desc = f": {a.description}" if a.description else ""
                print(f"    - {a.name} ({flag}){desc}")
        print(f"\n{len(result.prompts)} prompts", file=sys.stderr)
        return 0

    return await with_session(args.writes, action)


async def cmd_prompt(args) -> int:
    try:
        arguments = json.loads(args.arguments) if args.arguments else {}
    except json.JSONDecodeError as e:
        print(f"arguments are not valid JSON: {e}", file=sys.stderr)
        return 2
    if not isinstance(arguments, dict) or not all(isinstance(v, str) for v in arguments.values()):
        print("prompt arguments must be a JSON object of strings", file=sys.stderr)
        return 2

    async def action(session, init):
        try:
            result = await session.get_prompt(args.name, arguments)
        except MCPError as e:  # unknown prompt, missing required argument
            print(f"error: {e.message}", file=sys.stderr)
            return 1
        if not isinstance(result, types.GetPromptResult):  # an input-required round trip
            print(result, flush=True)
            return 1
        if result.description:
            print(f"# {result.description}\n")
        for message in result.messages:
            content = message.content
            text = content.text if isinstance(content, types.TextContent) else str(content)
            print(f"--- {message.role} ---")
            print(text, flush=True)
        return 0

    return await with_session(args.writes, action)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    commands = {
        "instructions": sub.add_parser(
            "instructions", help="print the server's connect-time instructions"
        ),
        "list": sub.add_parser("list", help="list the tools"),
        "schema": sub.add_parser("schema", help="print one tool's description and input schema"),
        "call": sub.add_parser("call", help="call one tool"),
        "prompts": sub.add_parser("prompts", help="list the MCP prompts and their arguments"),
        "prompt": sub.add_parser("prompt", help="render one prompt (prompts/get)"),
    }
    # --writes works before or after the command: the sub-parsers SUPPRESS their default so
    # that a flag given before the command is not clobbered by the sub-parser's False.
    parser.add_argument(
        "--writes", action="store_true", default=False, help="register the write tools too"
    )
    for sub_parser in commands.values():
        sub_parser.add_argument(
            "--writes", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS
        )
    commands["list"].add_argument("--json", action="store_true", help="full schemas as JSON")
    commands["schema"].add_argument("tool")
    commands["call"].add_argument("tool")
    commands["call"].add_argument(
        "arguments", nargs="?", default="{}", help="JSON object of arguments"
    )
    commands["prompt"].add_argument("name")
    commands["prompt"].add_argument(
        "arguments", nargs="?", default="{}", help="JSON object of string arguments"
    )
    args = parser.parse_args()
    handler = {
        "instructions": cmd_instructions,
        "list": cmd_list,
        "schema": cmd_schema,
        "call": cmd_call,
        "prompts": cmd_prompts,
        "prompt": cmd_prompt,
    }[args.command]
    sys.exit(asyncio.run(handler(args)))


if __name__ == "__main__":
    main()
