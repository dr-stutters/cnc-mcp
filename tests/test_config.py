"""Settings behavior: env prefix, defaults, validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from cnc_mcp.config import Settings


def test_reads_prefixed_env_vars(monkeypatch):
    monkeypatch.setenv("CNC_MCP_BASE_URL", "https://box.example.com/api")
    monkeypatch.setenv("CNC_MCP_ENABLE_WRITES", "true")
    monkeypatch.setenv("CNC_MCP_VERIFY_TLS", "false")
    settings = Settings(_env_file=None)
    assert settings.base_url == "https://box.example.com/api"
    assert settings.enable_writes is True
    assert settings.verify_tls is False


def test_writes_disabled_by_default(make_settings):
    assert make_settings().enable_writes is False


def test_base_url_required(monkeypatch):
    monkeypatch.delenv("CNC_MCP_BASE_URL", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_base_url_trailing_slash_stripped(make_settings):
    assert make_settings(base_url="https://x.example.com/api/").base_url == (
        "https://x.example.com/api"
    )


def test_base_url_must_be_http(make_settings):
    with pytest.raises(ValidationError):
        make_settings(base_url="ssh://x.example.com")
