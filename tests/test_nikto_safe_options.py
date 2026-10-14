"""Nikto receives only selected informational checks and bounded options."""

from pathlib import Path

import pytest

from tests.test_mcp_servers import load_server_module


nikto = load_server_module("tools/web-security", "nikto-observer-mcp")


def test_selected_checks_and_delays_become_fixed_argv():
    command = nikto.build_nikto_command(
        "https://example.com/", Path("/tmp/out.json"),
        checks=["misconfiguration", "software_identification"],
        pause_seconds=2, request_timeout=4, max_time=120,
    )
    assert command[0] == "nikto"
    assert command[command.index("-Tuning") + 1] == "2b"
    assert command[command.index("-Pause") + 1] == "2"
    assert command[command.index("-timeout") + 1] == "4"
    assert command[command.index("-maxtime") + 1] == "120s"
    assert command[command.index("-host") + 1] == "example.com"
    assert "-ssl" in command
    assert "-nocheck" in command


@pytest.mark.parametrize("kwargs", [
    {"checks": ["injection"]},
    {"checks": ["interesting_files", "interesting_files"]},
    {"checks": ["interesting_files", ["bad"]]},
    {"pause_seconds": "0;id"},
    {"request_timeout": True},
    {"max_time": 301},
])
def test_unreviewed_checks_and_flags_are_rejected(kwargs):
    with pytest.raises(ValueError):
        nikto.build_nikto_command("https://example.com/", Path("/tmp/out.json"), **kwargs)


@pytest.mark.parametrize("value", [
    "https://example.com/a", "https://example.com/?x=1",
    "https://user:pass@example.com/", "https://example.com\n-Plugins all",
    "http://example.com:9999/", "--host=example.com",
])
def test_target_cannot_supply_an_option_or_extra_path(value):
    with pytest.raises(ValueError):
        nikto.build_nikto_command(value, Path("/tmp/out.json"))
