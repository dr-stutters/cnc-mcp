#!/usr/bin/env python3
"""Live smoke test: drive the real server stack against a live platform instance.

Connection settings come from .env / the environment (same as the server).
Tool calls come from scripts/smoke_plan.json — copy smoke_plan.example.json and
fill in real calls for this platform. Read-phase steps must be side-effect free;
write-phase steps run only with --write and must leave the platform exactly as
found (create -> verify -> delete).

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
    for step in plan["steps"]:
        if step.get("phase", "read") == "write" and not args.write:
            continue
        name = step["tool"]
        result = await mcp.call_tool(name, step.get("args", {}))
        text = "".join(getattr(block, "text", "") for block in result.content)
        ok = not text.startswith("Error:")
        if step.get("expect_error"):
            ok = not ok
        failures += 0 if ok else 1
        print(f"{'OK  ' if ok else 'FAIL'} {name}: {text[:140]!r}")

    print(f"\n{'PASS' if not failures else f'{failures} FAILURE(S)'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(run()))
