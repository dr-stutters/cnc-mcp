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


# --- safety controls: write areas, disabled tools, dry-run --------------------------


def test_safety_controls_default_to_everything_enabled_nothing_dry(make_settings):
    settings = make_settings()
    assert settings.write_areas == "" and settings.write_area_set == frozenset()
    assert settings.disabled_tools == "" and settings.disabled_tool_set == frozenset()
    assert settings.dry_run is False
    assert settings.env_prefix == "CNC_MCP_"


def test_write_areas_parsed_case_and_whitespace_tolerant_and_deduplicated(make_settings):
    settings = make_settings(write_areas=" Fault, devices ,,FAULT\tnso ")
    assert settings.write_area_set == frozenset({"fault", "devices", "nso"})
    assert make_settings(write_areas=",, ,").write_area_set == frozenset()


def test_disabled_tools_parsed_case_and_whitespace_tolerant(make_settings):
    settings = make_settings(disabled_tools="cnc_delete_device, CNC_Restart_Microservice ")
    assert settings.disabled_tool_set == frozenset(
        {"cnc_delete_device", "cnc_restart_microservice"}
    )


def test_safety_controls_read_from_prefixed_env(monkeypatch):
    monkeypatch.setenv("CNC_MCP_BASE_URL", "https://box.example.com/api")
    monkeypatch.setenv("CNC_MCP_WRITE_AREAS", "fault,devices")
    monkeypatch.setenv("CNC_MCP_DISABLED_TOOLS", "cnc_delete_device")
    monkeypatch.setenv("CNC_MCP_DRY_RUN", "true")
    settings = Settings(_env_file=None)
    assert settings.write_area_set == frozenset({"fault", "devices"})
    assert settings.disabled_tool_set == frozenset({"cnc_delete_device"})
    assert settings.dry_run is True


def test_parse_name_list():
    from cnc_mcp.config import parse_name_list

    assert parse_name_list("") == frozenset()
    assert parse_name_list("a,b;c") == frozenset({"a", "b;c"})  # ';' is not a separator
    assert parse_name_list("A\n b, a") == frozenset({"a", "b"})
