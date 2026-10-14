"""ProjectDiscovery adapter only constructs bounded, fixed argv."""

import importlib.util
import json
from pathlib import Path

import pytest


SERVER = Path(__file__).resolve().parents[1] / "tools/reconnaissance/pd-tools-mcp/server.py"
spec = importlib.util.spec_from_file_location("pd_options_server", SERVER)
pd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pd)


@pytest.fixture
def calls(monkeypatch):
    seen = []

    async def fake_run(executable, arguments, stdin=""):
        seen.append((executable, arguments, stdin))
        return {"returncode": 0}

    monkeypatch.setattr(pd, "run", fake_run)
    return seen


@pytest.mark.asyncio
@pytest.mark.parametrize("name,args,executable,expected", [
    ("pd_subfinder", {"domain": "Example.COM", "rate_limit": 3}, "subfinder", ["-d", "example.com", "-silent", "-json", "-rl", "3"]),
    ("pd_dns_resolve", {"hosts": ["Example.COM"], "record_types": ["MX", "AAAA"], "rate_limit": 12, "threads": 2}, "dnsx", ["-silent", "-json", "-rl", "12", "-t", "2", "-aaaa", "-mx"]),
    ("pd_port_scan", {"hosts": ["example.com"], "ports": [443, 80, 80], "rate_limit": 20, "concurrency": 2}, "naabu", ["-silent", "-json", "-rate", "20", "-c", "2", "-p", "80,443"]),
    ("pd_http_probe", {"urls": ["https://example.com/"], "rate_limit": 4, "threads": 3, "title": True, "tech_detect": True}, "httpx", ["-silent", "-json", "-no-color", "-nfs", "-threads", "3", "-rate-limit", "4", "-title", "-tech-detect"]),
    ("pd_crawl", {"urls": ["https://example.com/"], "depth": 1, "rate_limit": 2, "concurrency": 2, "parallelism": 1}, "katana", ["-silent", "-jsonl", "-d", "1", "-c", "2", "-p", "1", "-rl", "2", "-fs", "fqdn"]),
])
async def test_typed_options_build_expected_argv(name, args, executable, expected, calls):
    result = await pd.call_tool(name, args)
    assert json.loads(result[0].text) == {"returncode": 0}
    assert calls[0][0:2] == (executable, expected)
    if name != "pd_subfinder":
        assert calls[0][2].endswith("\n")


@pytest.mark.asyncio
@pytest.mark.parametrize("name,args", [
    ("pd_subfinder", {"domain": "-all"}),
    ("pd_subfinder", {"domain": "example.com\n-active"}),
    ("pd_subfinder", {"domain": "example.com", "rate_limit": True}),
    ("pd_dns_resolve", {"hosts": ["example.com"], "record_types": ["AXFR"]}),
    ("pd_dns_resolve", {"hosts": ["example.com\n-update"]}),
    ("pd_port_scan", {"hosts": ["example.com"], "rate_limit": 101}),
    ("pd_port_scan", {"hosts": ["example.com"], "ports": ["-top-ports"]}),
    ("pd_http_probe", {"urls": ["https://example.com/?action=delete"]}),
    ("pd_http_probe", {"urls": ["https://@example.com/"]}),
    ("pd_http_probe", {"urls": ["https://example.com/"], "title": "yes"}),
    ("pd_http_probe", {"urls": ["https://example.com/"], "headers": ["X: y"]}),
    ("pd_crawl", {"urls": ["https://example.com/"], "depth": 4}),
    ("pd_crawl", {"urls": ["https://example.com/"], "flags": "-jc"}),
])
async def test_rejects_unapproved_or_ambiguous_input(name, args, calls):
    result = await pd.call_tool(name, args)
    assert result[0].text.startswith("Rejected:")
    assert calls == []


@pytest.mark.asyncio
async def test_advertised_options_have_strict_schema():
    for tool in await pd.list_tools():
        assert tool.inputSchema["additionalProperties"] is False
        assert all(isinstance(key, str) for key in tool.inputSchema["properties"])
