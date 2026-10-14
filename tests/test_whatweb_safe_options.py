"""WhatWeb options stay within a single-request, same-target profile."""

from pathlib import Path

import pytest

from tests.test_mcp_servers import load_server_module


whatweb = load_server_module("tools/reconnaissance", "whatweb-mcp")


def test_options_are_explicit_argv_elements():
    command = whatweb.build_whatweb_command(
        "https://example.com/", Path("/tmp/result.json"),
        wait_seconds=2, open_timeout=5, read_timeout=10, no_errors=True,
    )
    assert command[0] == "whatweb"
    assert command[-2:] == ["--", "https://example.com/"]
    assert command[command.index("--wait") + 1] == "2"
    assert command[command.index("--open-timeout") + 1] == "5"
    assert "--follow-redirect=never" in command
    assert "--max-threads" in command
    assert command[command.index("--max-threads") + 1] == "1"
    assert "--no-errors" in command


@pytest.mark.parametrize("kwargs", [
    {"aggression": "aggressive"},
    {"wait_seconds": "1;id"},
    {"open_timeout": True},
    {"read_timeout": 31},
    {"no_errors": "true"},
])
def test_unreviewed_or_unbounded_options_fail(kwargs):
    with pytest.raises(ValueError):
        whatweb.build_whatweb_command("https://example.com", Path("/tmp/result.json"), **kwargs)


@pytest.mark.parametrize("target", [
    "--plugin=unsafe", "https://example.com\n--plugin=unsafe",
    "https://example.com@internal.example", "file:///etc/passwd",
])
def test_agent_text_cannot_become_a_flag_or_non_http_target(target):
    with pytest.raises(ValueError):
        whatweb.build_whatweb_command(target, Path("/tmp/result.json"))
