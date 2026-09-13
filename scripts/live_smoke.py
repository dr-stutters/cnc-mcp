#!/usr/bin/env python3
"""Live smoke test: drive the real server stack against a live platform instance.

Connection settings come from .env / the environment (same as the server).
Tool calls come from scripts/smoke_plan.json — copy smoke_plan.example.json and
fill in real calls for this platform. Read-phase steps must be side-effect free;
write-phase steps run only with --write and must leave the platform exactly as
found (create -> verify -> delete).

Steps may chain: a step with "capture": {"var": "dotted.path.0.to.value"} stores
values from its JSON result, and later steps may use "$var" (or "$var" inside a
string) in their args — e.g. capture the uuid a create returned, then delete it.

Usage (from the project root):
    uv run python scripts/live_smoke.py            # read phase only
    uv run python scripts/live_smoke.py --write    # read + write phases
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path


async def run() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="include write-phase steps")
    parser.add_argument(
        "--plan",
        default=str(Path(__file__).with_name("smoke_plan.json")),
        help="path to the smoke plan JSON",
    )
    args = parser.parse_args()

    plan_path = Path(args.plan)
    if not plan_path.exists():
        print(f"No smoke plan at {plan_path} — copy smoke_plan.example.json and fill it in.")
        return 2
    plan = json.loads(plan_path.read_text())

    # Import late so the env tweak below lands before Settings() reads it.
    from cnc_mcp.config import Settings

    if args.write:
        prefix = Settings.model_config.get("env_prefix", "")
        os.environ[f"{prefix}ENABLE_WRITES"] = "true"

    from cnc_mcp.client import ApiClient
    from cnc_mcp.server import build_server, create_auth

    # The runner never enters the server lifespan, so it owns (and closes) the client:
    # closing releases the platform SSO session, which Crosswork caps per user.
    settings = Settings()
    client = ApiClient(settings, create_auth(settings))
    try:
        return await _run_plan(build_server(settings, client=client), plan, args)
    finally:
        await client.aclose()


async def _run_plan(mcp, plan: dict, args) -> int:
    tools = await mcp.list_tools()
    print(f"{len(tools)} tools registered (writes {'ON' if args.write else 'off'})")

    failures = 0
    captured: dict[str, str] = {}
    for step in plan["steps"]:
        if step.get("phase", "read") == "write" and not args.write:
            continue
        name = step["tool"]
        call_args = _substitute(step.get("args", {}), captured)
        result = await mcp.call_tool(name, call_args)
        text = "".join(getattr(block, "text", "") for block in result.content)
        ok = not text.startswith("Error:")
        if step.get("expect_error"):
            ok = not ok
        failures += 0 if ok else 1
        print(f"{'OK  ' if ok else 'FAIL'} {name}: {text[:140]!r}")
        for var, path in (step.get("capture") or {}).items():
            value = _dig(text, path)
            if value is None:
                failures += 1
                print(f"FAIL capture {var}: path {path!r} not found in result")
            else:
                captured[var] = value  # raw JSON value: a whole-string "$var" keeps its type
                print(f"     captured {var}={value!r}")

    print(f"\n{'PASS' if not failures else f'{failures} FAILURE(S)'}")
    return 1 if failures else 0


def _dig(text: str, path: str):
    """Follow a dotted path (list indexes as integers) into a JSON result.

    A tool answer that is a sentence followed by a JSON block is parsed from its
    first "{" or "[". Keys that themselves contain dots (RESTCONF names such as
    "ietf-restconf:notification.subscription-id") match when the remaining path
    equals the key, so "items.0.ietf-restconf:notification.subscription-id" works.
    """
    node = _parse_json_block(text)
    if node is None:
        return None
    parts = path.split(".")
    i = 0
    while i < len(parts):
        part = parts[i]
        if isinstance(node, dict):
            rest = ".".join(parts[i:])
            if rest in node:  # a key with dots in it
                return node[rest]
            node = node.get(part)
        elif isinstance(node, list) and part.isdigit():
            idx = int(part)
            node = node[idx] if idx < len(node) else None
        else:
            return None
        if node is None:
            return None
        i += 1
    return node


def _parse_json_block(text: str):
    try:
        return json.loads(text)
    except ValueError:
        pass
    starts = [i for i in (text.find("{"), text.find("[")) if i >= 0]
    if not starts:
        return None
    try:
        return json.loads(text[min(starts) :])
    except ValueError:
        return None


def _substitute(value, captured: dict[str, object]):
    """Replace "$var" references in step args with captured values.

    An argument that is exactly "$var" takes the captured value with its JSON type
    (an integer subscription id stays an integer); "$var" inside a longer string is
    interpolated as text.
    """
    if isinstance(value, dict):
        return {k: _substitute(v, captured) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v, captured) for v in value]
    if isinstance(value, str) and "$" in value:
        if value.startswith("$") and value[1:] in captured:
            return captured[value[1:]]
        # Longest names first so "$job" never clobbers the prefix of "$job_id".
        for var in sorted(captured, key=len, reverse=True):
            value = value.replace(f"${var}", str(captured[var]))
    return value


if __name__ == "__main__":
    sys.exit(asyncio.run(run()))
