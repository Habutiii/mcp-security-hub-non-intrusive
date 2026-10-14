"""ExternalAttacker MCP options remain bounded and become fixed argv."""

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).parent.parent


@pytest.fixture
def externalattacker():
    path = ROOT / "tools/reconnaissance/externalattacker-mcp/server.py"
    spec = importlib.util.spec_from_file_location("externalattacker_option_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
async def test_selected_ports_rate_and_concurrency_reach_argv(externalattacker, monkeypatch):
    captured = []

    class Process:
        returncode = 0

        async def communicate(self):
            return b"{}", b""

    async def start(*argv, **kwargs):
        captured.append(argv)
        return Process()

    monkeypatch.setattr(externalattacker.asyncio, "create_subprocess_exec", start)
    response = await externalattacker.call_tool("scan_ports", {
        "host": "example.com", "ports": "80,443,8000-8002",
        "rate": 10, "concurrency": 2, "timeout": 15,
    })
    assert '"returncode": 0' in response[0].text
    argv = captured[0]
    assert argv[0] == "naabu"
    for flag, value in (("-host", "example.com"), ("-p", "80,443,8000-8002"),
                        ("-rate", "10"), ("-c", "2")):
        assert argv[argv.index(flag) + 1] == value


@pytest.mark.asyncio
async def test_metadata_choices_are_fixed_flags(externalattacker, monkeypatch):
    calls = []

    async def fake_run(executable, arguments, *, timeout):
        calls.append((executable, arguments, timeout))
        return {"returncode": 0}

    monkeypatch.setattr(externalattacker, "run", fake_run)
    await externalattacker.call_tool("analyze_http", {
        "host": "example.com", "include_technology": False, "rate": 2, "concurrency": 3,
    })
    await externalattacker.call_tool("analyze_tls", {
        "host": "example.com", "port": 8443, "include_cipher": False,
    })
    assert calls[0][0] == "httpx" and "-tech-detect" not in calls[0][1]
    assert calls[0][1][calls[0][1].index("-rate-limit") + 1] == "2"
    assert calls[1][0] == "tlsx" and "-cipher" not in calls[1][1]
    assert calls[1][1][calls[1][1].index("-p") + 1] == "8443"


@pytest.mark.parametrize("name,args", [
    ("scan_ports", {"host": "example.com", "ports": "80;id"}),
    ("scan_ports", {"host": "example.com", "ports": "1-17"}),
    ("scan_ports", {"host": "example.com", "rate": "5;id"}),
    ("scan_ports", {"host": "example.com", "concurrency": True}),
    ("analyze_http", {"host": "example.com", "include_technology": "false"}),
    ("analyze_tls", {"host": "example.com", "port": "443 -X POST"}),
    ("check_cdn", {"domain": "example.com\n--flag"}),
    ("discover_subdomains", {"domain": "example.com", "timeout": 121}),
    ("analyze_http", {"host": "example.com", "headers": {"X-Test": "x"}}),
])
def test_invalid_options_rejected(externalattacker, name, args):
    with pytest.raises(ValueError):
        externalattacker.scan_options(name, args)
