"""FFUF options remain typed, bounded, and separate argv elements."""

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).parent.parent


@pytest.fixture
def ffuf():
    path = ROOT / "tools/web-security/ffuf-mcp/server.py"
    spec = importlib.util.spec_from_file_location("ffuf_option_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
async def test_scan_options_map_to_fixed_argv(ffuf, monkeypatch, tmp_path):
    captured = []

    class Process:
        returncode = 0

        async def communicate(self):
            return b"", b""

    async def start(*args, **kwargs):
        captured.append(args)
        return Process()

    monkeypatch.setattr(ffuf.asyncio, "create_subprocess_exec", start)
    monkeypatch.setattr(ffuf.settings, "output_dir", str(tmp_path))
    response = await ffuf.call_tool("ffuf_dir", {
        "url": "https://example.com/FUZZ",
        "match_codes": [200, 301], "filter_codes": [404],
        "filter_words": 10, "filter_lines": 2, "filter_size": 0,
        "threads": 4, "rate": 5, "timeout": 20,
    })
    assert "completed" in response[0].text
    argv = captured[0]
    for flag, value in (("-mc", "200,301"), ("-fc", "404"), ("-fw", "10"),
                        ("-fl", "2"), ("-fs", "0"), ("-t", "4"), ("-rate", "5")):
        assert argv[argv.index(flag) + 1] == value
    assert "-X" not in argv and "-d" not in argv and "-r" not in argv


@pytest.mark.parametrize("name,args", [
    ("ffuf_dir", {"url": "https://example.com/FUZZ", "rate": "1; touch /tmp/owned"}),
    ("ffuf_dir", {"url": "https://example.com/FUZZ", "threads": True}),
    ("ffuf_dir", {"url": "https://example.com/FUZZ", "match_codes": [200, "300;id"]}),
    ("ffuf_dir", {"url": "https://example.com/FUZZ", "filter_size": -1}),
    ("ffuf_dir", {"url": "https://example.com/FUZZ", "method": "POST"}),
    ("ffuf_dir", {"url": "https://example.com/FUZZ\n-H Evil: x"}),
    ("ffuf_dir", {"url": "https://example.com/FUZZ", "wordlist": "../../etc/passwd"}),
    ("ffuf_vhost", {"url": "https://example.com", "domain": "example.com\r\nX-Evil: yes"}),
    ("ffuf_param", {"url": "https://example.com/?a=b", "data": "FUZZ=x"}),
])
def test_invalid_options_rejected(ffuf, name, args):
    with pytest.raises((ValueError, KeyError)):
        ffuf.validate_scan_options(name, args)
