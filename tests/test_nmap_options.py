"""Nmap options are bounded fields, never caller-supplied command fragments."""

import importlib.util
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location(
    "nmap_options_server", ROOT / "tools/reconnaissance/nmap-mcp/server.py"
)
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


def command(**options):
    return server.build_nmap_command(
        options.pop("target", "example.com"),
        options.pop("scan_type", "service"),
        Path("scan.xml"), Path("scan.txt"), **options,
    )


def test_typed_options_produce_only_fixed_nmap_flags():
    argv = command(
        target="192.0.2.0/24", ports="22,80-82", timing=2,
        max_rate=12, max_retries=1, show_reasons=True, open_only=True,
        version_intensity=2,
    )
    assert argv == [
        "nmap", "-oX", "scan.xml", "-oN", "scan.txt", "-T2",
        "--max-rate", "12", "--max-retries", "1", "-sV",
        "--version-intensity", "2", "-p", "22,80-82", "--reason",
        "--open", "--", "192.0.2.0/24",
    ]


def test_script_choice_is_fixed_and_wrapped_as_one_argv_value():
    argv = command(scan_type="script", scripts=["banner", "http-title"])
    assert argv[argv.index("--script") + 1] == "banner,http-title"
    assert argv[-2:] == ["--", "example.com"]


@pytest.mark.parametrize("options", [
    {"target": "--script=unsafe"},
    {"target": "example.com;touch /tmp/owned"},
    {"target": "0.0.0.0/0"},
    {"ports": "80,--script=unsafe"},
    {"ports": "1-65535"},
    {"ports": "U:53"},
    {"timing": 4},
    {"timing": True},
    {"max_rate": 1000},
    {"max_retries": -1},
    {"show_reasons": "true"},
    {"version_intensity": 9},
    {"scan_type": "script", "scripts": ["default"]},
    {"scan_type": "script", "scripts": ["banner;touch /tmp/owned"]},
    {"scan_type": "script", "scripts": ["banner"] * 5},
    {"scan_type": "quick", "ports": "80"},
])
def test_rejects_unsafe_or_unbounded_values(options):
    with pytest.raises(ValueError):
        command(**options)


@pytest.mark.asyncio
async def test_invalid_timeout_fails_before_subprocess(monkeypatch):
    async def unexpected(*_args, **_kwargs):
        raise AssertionError("subprocess must not run")

    monkeypatch.setattr(server.asyncio, "create_subprocess_exec", unexpected)
    with pytest.raises(ValueError, match="timeout"):
        await server.run_nmap_scan("example.com", timeout=601)


@pytest.mark.asyncio
async def test_timeout_stops_scanner_process(monkeypatch):
    class Process:
        killed = False
        waited = False

        async def communicate(self):
            raise TimeoutError

        def kill(self):
            self.killed = True

        async def wait(self):
            self.waited = True

    process = Process()

    async def spawn(*_args, **_kwargs):
        return process

    monkeypatch.setattr(server.asyncio, "create_subprocess_exec", spawn)
    result = await server.run_nmap_scan("example.com", timeout=10)
    assert result.status == "timeout"
    assert process.killed and process.waited


@pytest.mark.asyncio
async def test_mcp_call_rejects_unadvertised_option():
    response = await server.call_tool("port_scan", {"target": "example.com", "raw_flags": "--script all"})
    assert "unsupported scan option" in response[0].text
