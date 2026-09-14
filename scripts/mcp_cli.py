"""Drive the cnc-mcp server over the real MCP stdio protocol from the command line.

The server is started exactly as an MCP client would start it (``uv run
cnc-mcp`` in this checkout, credentials from ``.env``), the MCP handshake is
performed, and the tool is called through ``tools/call`` — so what you see is
what an agent sees: the tool list, the input schemas, the ``instructions``
text, and the tool's text answer.

    uv run python scripts/mcp_cli.py instructions [--writes] [--env NAME=VALUE ...]
    uv run python scripts/mcp_cli.py list [--json] [--writes] [--env NAME=VALUE ...]
    uv run python scripts/mcp_cli.py schema <tool> [--env NAME=VALUE ...]
    uv run python scripts/mcp_cli.py call <tool> '<json arguments>' [--writes] [--env ...]
    uv run python scripts/mcp_cli.py prompts
    uv run python scripts/mcp_cli.py prompt <name> ['<json arguments>'] [--writes]

``prompts`` lists the server's MCP prompts (name, title, description, arguments)
through ``prompts/list``; ``prompt`` renders one through ``prompts/get`` and
prints each message's role and text — with ``--writes`` the rendered text says
the write tools are enabled, without it that the server is read-only.
``--writes`` (before or after the command) starts the server with
``CNC_MCP_ENABLE_WRITES=true`` so the write tools are registered. ``--env
NAME=VALUE`` (repeatable, before or after the command) sets extra environment
variables for the spawned server — the way to try the other safety controls::

    uv run python scripts/mcp_cli.py --writes --env CNC_MCP_DRY_RUN=true \\
        call cnc_create_tag '{"name": "site-a"}'
    uv run python scripts/mcp_cli.py --writes --env CNC_MCP_WRITE_AREAS=fault list
    uv run python scripts/mcp_cli.py --env CNC_MCP_DISABLED_TOOLS=cnc_delete_device \\
        instructions

``--env`` values are applied after ``--writes``, so ``--env
CNC_MCP_ENABLE_WRITES=true`` is another way to spell it. The server's own
logging is held at WARNING unless ``CNC_MCP_LOG_LEVEL`` is set (``--env
CNC_MCP_LOG_LEVEL=INFO`` shows the registration summary and every skipped
tool). Exit status is 1 when the tool answered an ``Error:`` text or the call
itself failed, so shell loops can branch on it.
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


def parse_env_assignments(assignments: list[str]) -> dict[str, str]:
    """``NAME=VALUE`` strings -> mapping; a malformed one is an argument error."""
    extra: dict[str, str] = {}
    for assignment in assignments:
        name, sep, value = assignment.partition("=")
        if not sep or not name.strip():
            raise SystemExit(f"--env expects NAME=VALUE, got {assignment!r}")
        extra[name.strip()] = value
    return extra


def server_params(writes: bool, extra_env: dict[str, str] | None = None) -> StdioServerParameters:
    env = dict(os.environ)
    env["CNC_MCP_ENABLE_WRITES"] = "true" if writes else "false"
    env.setdefault("CNC_MCP_LOG_LEVEL", "WARNING")  # keep stderr quiet unless asked for
    env.update(extra_env or {})  # --env wins, ENABLE_WRITES and LOG_LEVEL included
    return StdioServerParameters(command="uv", args=["run", "cnc-mcp"], cwd=str(REPO), env=env)


async def with_session(writes: bool, action, extra_env: dict[str, str] | None = None):
    async with stdio_client(server_params(writes, extra_env)) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            return await action(session, init)


async def cmd_instructions(args) -> int:
    async def action(session, init):
        print(init.instructions or "(no instructions)")
        return 0

    return await with_session(args.writes, action, args.env)


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

    return await with_session(args.writes, action, args.env)


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

    return await with_session(True, action, args.env)


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

    return await with_session(args.writes, action, args.env)


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

    return await with_session(args.writes, action, args.env)


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

    return await with_session(args.writes, action, args.env)


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
    # --writes and --env work before or after the command: the sub-parsers SUPPRESS their
    # default so that a flag given before the command is not clobbered by the sub-parser's
    # default; --env given after the command lands in its own dest and is merged below.
    parser.add_argument(
        "--writes", action="store_true", default=False, help="register the write tools too"
    )
    parser.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="extra environment variable for the server (repeatable), e.g. "
        "CNC_MCP_DRY_RUN=true, CNC_MCP_WRITE_AREAS=fault,devices, "
        "CNC_MCP_DISABLED_TOOLS=cnc_delete_device",
    )
    for sub_parser in commands.values():
        sub_parser.add_argument(
            "--writes", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS
        )
        sub_parser.add_argument(
            "--env",
            action="append",
            dest="env_after",
            default=argparse.SUPPRESS,
            metavar="NAME=VALUE",
            help=argparse.SUPPRESS,
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
    args.env = parse_env_assignments(list(args.env) + list(getattr(args, "env_after", [])))
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
