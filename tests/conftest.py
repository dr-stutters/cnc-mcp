"""Shared test fixtures.

Tests never touch the network: all HTTP is mocked with respx. retry_backoff_seconds
defaults to 0 here so retry tests don't sleep.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from mcp.server.mcpserver import MCPServer

from cnc_mcp.config import Settings

BASE_URL = "https://api.example.test"


@pytest.fixture(autouse=True)
def _clean_prefixed_env(monkeypatch):
    """Strip ambient prefixed env vars (e.g. from a sourced .env) so a developer's
    live-server configuration can never leak into — or silently alter — the tests."""
    prefix = Settings.model_config["env_prefix"]
    for key in list(os.environ):
        if key.startswith(prefix):
            monkeypatch.delenv(key)


@pytest.fixture
def make_settings():
    """Factory for Settings that ignores any local .env file."""

    def _make(**overrides: Any) -> Settings:
        values: dict[str, Any] = {
            "base_url": BASE_URL,
            "api_token": "test-token",
            "retry_backoff_seconds": 0.0,
        }
        values.update(overrides)
        return Settings(_env_file=None, **values)

    return _make


@pytest.fixture
def settings(make_settings) -> Settings:
    return make_settings()


async def call_tool_text(mcp: MCPServer, name: str, arguments: dict[str, Any]) -> str:
    """Call a tool through MCPServer (validates the input schema) and flatten to text."""
    result = await mcp.call_tool(name, arguments)
    return "".join(getattr(block, "text", "") for block in result.content)
