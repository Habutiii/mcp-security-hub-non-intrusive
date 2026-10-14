"""Bounded Masscan flags and targets are passed as fixed argv elements."""

from pathlib import Path

import pytest

from tests.test_mcp_servers import load_server_module


masscan = load_server_module("tools/reconnaissance", "masscan-mcp")


def test_custom_ports_and_rate_are_bounded_argv_values():
    command = masscan.build_masscan_command(
        "10.10.1.0/24", "22,80,8000-8010", 20, Path("/tmp/result.json")
    )
    assert command == [
        "masscan", "10.10.1.0/24", "-p", "22,80,8000-8010",
        "--rate", "20", "-oJ", str(Path("/tmp/result.json")),
    ]


@pytest.mark.parametrize("target,ports,rate", [
    ("--interactive", "80", 10),
    ("10.10.0.0/16", "80", 10),
    ("10.10.1.1-10.10.1.255", "80", 10),
    ("10.10.1.1", "80,--wait=0", 10),
    ("10.10.1.1", "1-1000", 10),
    ("10.10.1.1", "80", 51),
    ("10.10.1.1", "80", "10;id"),
])
def test_rejects_injected_or_disruptive_values(target, ports, rate):
    with pytest.raises(ValueError):
        masscan.build_masscan_command(target, ports, rate, Path("/tmp/result.json"))
