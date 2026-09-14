"""scripts/mcp_cli.py: the argument contract of the stdio driver — ``--env NAME=VALUE``
before or after the command, its merge with ``--writes`` (``--env`` wins), and the
malformed-assignment error. The server is never spawned: the ``cmd_*`` handlers are
replaced with stubs that capture the parsed arguments.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "mcp_cli.py"
COMMANDS = ("instructions", "list", "schema", "call", "prompts", "prompt")


@pytest.fixture(scope="module")
def cli() -> ModuleType:
    spec = importlib.util.spec_from_file_location("mcp_cli_under_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def run(cli, monkeypatch):
    """Run ``main()`` with ``argv``; returns the argparse namespace the handler got."""
    seen: dict[str, object] = {}

    def stub(command: str):
        async def handler(args) -> int:
            seen["command"] = command
            seen["args"] = args
            return 0

        return handler

    for command in COMMANDS:
        monkeypatch.setattr(cli, f"cmd_{command}", stub(command))

    def _run(*argv: str):
        monkeypatch.setattr(sys, "argv", ["mcp_cli.py", *argv])
        with pytest.raises(SystemExit) as info:
            cli.main()
        assert info.value.code == 0
        return seen["args"]

    return _run


def test_parse_env_assignments(cli):
    assert cli.parse_env_assignments([]) == {}
    assert cli.parse_env_assignments(["A=1", " B =2=3", "C="]) == {"A": "1", "B": "2=3", "C": ""}
    with pytest.raises(SystemExit, match="--env expects NAME=VALUE, got 'NOEQUALS'"):
        cli.parse_env_assignments(["A=1", "NOEQUALS"])
    with pytest.raises(SystemExit, match="--env expects NAME=VALUE, got '=x'"):
        cli.parse_env_assignments(["=x"])


def test_env_before_and_after_the_command_are_merged(run):
    args = run("--env", "A=1", "--writes", "call", "x", "{}", "--env", "B=2=3")
    assert args.command == "call" and args.tool == "x" and args.arguments == "{}"
    assert args.writes is True
    assert args.env == {"A": "1", "B": "2=3"}
    # After the command only, and none at all.
    assert run("list", "--env", "CNC_MCP_DRY_RUN=true").env == {"CNC_MCP_DRY_RUN": "true"}
    assert run("prompts").env == {}
    # A later assignment of the same name wins, wherever it stands.
    args = run("--env", "A=1", "instructions", "--env", "A=2")
    assert args.env == {"A": "2"}


def test_writes_flag_works_before_or_after_the_command(run):
    assert run("--writes", "list").writes is True
    assert run("list", "--writes").writes is True
    assert run("list").writes is False
    assert run("--writes", "prompt", "provision_l3vpn", '{"vpn_id": "v"}').writes is True


def test_malformed_env_assignment_exits(cli, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["mcp_cli.py", "list", "--env", "NOEQUALS"])
    with pytest.raises(SystemExit) as info:
        cli.main()
    assert info.value.code == "--env expects NAME=VALUE, got 'NOEQUALS'"


def test_server_params_env_precedence(cli, monkeypatch):
    """--writes sets ENABLE_WRITES, LOG_LEVEL defaults to WARNING, and --env overrides
    both (so --env CNC_MCP_ENABLE_WRITES=false beats --writes)."""
    monkeypatch.delenv("CNC_MCP_LOG_LEVEL", raising=False)
    params = cli.server_params(True)
    assert params.env["CNC_MCP_ENABLE_WRITES"] == "true"
    assert params.env["CNC_MCP_LOG_LEVEL"] == "WARNING"
    assert params.command == "uv" and params.args == ["run", "cnc-mcp"]
    assert params.cwd == str(SCRIPT.parent.parent)
    assert cli.server_params(False).env["CNC_MCP_ENABLE_WRITES"] == "false"
    params = cli.server_params(
        True,
        {"CNC_MCP_ENABLE_WRITES": "false", "CNC_MCP_DRY_RUN": "true", "CNC_MCP_LOG_LEVEL": "INFO"},
    )
    assert params.env["CNC_MCP_ENABLE_WRITES"] == "false"
    assert params.env["CNC_MCP_DRY_RUN"] == "true"
    assert params.env["CNC_MCP_LOG_LEVEL"] == "INFO"
    # An ambient LOG_LEVEL is kept (setdefault), the process environment is inherited.
    monkeypatch.setenv("CNC_MCP_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("SOME_OTHER_VAR", "kept")
    params = cli.server_params(False)
    assert params.env["CNC_MCP_LOG_LEVEL"] == "DEBUG" and params.env["SOME_OTHER_VAR"] == "kept"
