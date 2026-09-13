#!/usr/bin/env python3
"""One-shot rename of the skeleton into a platform server.

Usage (from a fresh copy of the template directory):

    python3 scripts/specialize.py <service>     # e.g. acme, acme_cloud

Renames the package, console script, env prefix, and tool-name prefix across
all files, then renames the package directory. Stdlib only; run before making
any other changes so `make test` verifies the rename in isolation.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

SKIP_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache", "node_modules"}
SKIP_FILES = {"uv.lock", "specialize.py"}


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: python3 scripts/specialize.py <service>  (e.g. acme, acme_cloud)")
    service = sys.argv[1].lower()
    if not re.fullmatch(r"[a-z][a-z0-9]*(_[a-z0-9]+)*", service):
        fail("service must be snake_case: lowercase letters/digits/underscores, e.g. acme_cloud")
    if service in ("skeleton", "mcp"):
        fail(f"'{service}' is not a usable service name")

    root = Path(__file__).resolve().parent.parent
    old_pkg = root / "src" / "skeleton_mcp"
    if not old_pkg.is_dir():
        fail("src/skeleton_mcp not found — was this copy already specialized?")

    snake = service
    dashed = service.replace("_", "-")
    upper = service.upper()
    title = service.replace("_", " ").title()

    # Ordered by specificity: longer/more-specific patterns first; the bare
    # lowercase catch-all last (covers e.g. the .mcp.json server key in README).
    replacements = [
        ("mcp-skeleton", f"{dashed}-mcp"),
        ("skeleton_mcp", f"{snake}_mcp"),
        ("skeleton-mcp", f"{dashed}-mcp"),
        ("SKELETON_MCP_", f"{upper}_MCP_"),
        ("skeleton_", f"{snake}_"),
        ("Skeleton", title),
        ("skeleton", snake),
    ]

    changed = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts) or path.name in SKIP_FILES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable; leave alone
        new = text
        for old, repl in replacements:
            new = new.replace(old, repl)
        if new != text:
            path.write_text(new, encoding="utf-8")
            changed.append(path.relative_to(root))

    old_pkg.rename(root / "src" / f"{snake}_mcp")

    print(
        f"Specialized as '{service}': package {snake}_mcp, env prefix {upper}_MCP_, "
        f"script {dashed}-mcp. {len(changed)} files rewritten."
    )
    print("Next: uv sync && make test  (the suite must pass before changing logic)")

    # Post-rename sanity check: nothing (outside skips) should mention skeleton now.
    leftovers = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts) or path.name in SKIP_FILES:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if "skeleton" in str(path.relative_to(root)).lower() or "skeleton" in content.lower():
            leftovers.append(str(path.relative_to(root)))
    if leftovers:
        print(f"warning: 'skeleton' still present in: {leftovers}", file=sys.stderr)


if __name__ == "__main__":
    main()
