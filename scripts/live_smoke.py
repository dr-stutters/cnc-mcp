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
        "--plan", default=str(Path(__file__).with_name("smoke_plan.json")),
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

    from cnc_mcp.server import build_server

    mcp = build_server(Settings())
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
                captured[var] = str(value)
                print(f"     captured {var}={captured[var]}")

    print(f"\n{'PASS' if not failures else f'{failures} FAILURE(S)'}")
    return 1 if failures else 0


def _dig(text: str, path: str):
    """Follow a dotted path (list indexes as integers) into a JSON result."""
    try:
        node = json.loads(text)
    except ValueError:
        return None
    for part in path.split("."):
        if isinstance(node, list) and part.isdigit():
            idx = int(part)
            node = node[idx] if idx < len(node) else None
        elif isinstance(node, dict):
            node = node.get(part)
        else:
            return None
        if node is None:
            return None
    return node


def _substitute(value, captured: dict[str, str]):
    """Replace "$var" references in step args with captured values."""
    if isinstance(value, dict):
        return {k: _substitute(v, captured) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v, captured) for v in value]
    if isinstance(value, str) and "$" in value:
        for var, val in captured.items():
            value = value.replace(f"${var}", val)
    return value


if __name__ == "__main__":
    sys.exit(asyncio.run(run()))
