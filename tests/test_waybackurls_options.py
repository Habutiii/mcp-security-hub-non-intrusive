"""Archive-only Wayback option validation and argv tests."""

import importlib.util
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location(
    "wayback_options_server", ROOT / "tools/web-security/waybackurls-mcp/server.py"
)
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


@pytest.mark.parametrize("domain", [
    "example.com\n-other.example", "-get-subs", "example.com;id",
    "https://example.com", "example.com/path", " example.com", "example.com\x00",
])
def test_rejects_domain_injection(domain):
    with pytest.raises(ValueError):
        server.validate_domain(domain)


@pytest.mark.asyncio
async def test_fixed_argv_and_domain_on_stdin(monkeypatch, tmp_path):
    calls = []

    class Process:
        returncode = 0

        async def communicate(self, input):
            calls.append(("stdin", input))
            return (
                b"http://example.com/a\nhttps://example.com/b\nhttps://example.com/b\n",
                b"",
            )

    async def exec_process(*argv, **kwargs):
        calls.append(("argv", argv, kwargs))
        return Process()

    monkeypatch.setattr(server.asyncio, "create_subprocess_exec", exec_process)
    monkeypatch.setattr(server.settings, "output_dir", str(tmp_path))
    result = await server.run_waybackurls(
        "Example.COM", get_subs=True, dates=True, https_only=True,
        unique_urls=True, timeout=30,
    )
    assert calls[0][1] == ("waybackurls", "-get-subs", "-dates")
    assert calls[1] == ("stdin", b"example.com")
    assert result.urls == ["https://example.com/b"]
    assert result.status == "completed"


@pytest.mark.asyncio
@pytest.mark.parametrize("options", [
    {"get_subs": "yes"}, {"no_subs": 1}, {"dates": "true"},
    {"unique_urls": None}, {"https_only": 1},
    {"get_subs": True, "no_subs": True},
    {"timeout": 0}, {"timeout": 601}, {"timeout": True},
])
async def test_bad_options_rejected_before_process(monkeypatch, options):
    async def unexpected(*args, **kwargs):
        raise AssertionError("process should not start")

    monkeypatch.setattr(server.asyncio, "create_subprocess_exec", unexpected)
    with pytest.raises(ValueError):
        await server.run_waybackurls("example.com", **options)


@pytest.mark.asyncio
@pytest.mark.parametrize("options", [
    {"limit": 0}, {"limit": 1001}, {"limit": "10"},
    {"include_urls": "false"}, {"raw_flags": "-dates"},
])
async def test_mcp_rejects_bad_response_or_raw_options(options):
    response = await server.call_tool("fetch_wayback_urls", {"domain": "example.com", **options})
    assert response[0].text.startswith("Error:")


@pytest.mark.asyncio
async def test_result_query_rejects_invalid_id_and_limit():
    for options in ({"fetch_id": "abc\n", "limit": 10},
                    {"fetch_id": "deadbeef", "limit": 1001}):
        response = await server.call_tool("get_fetch_results", options)
        assert response[0].text.startswith("Error:")


def test_archive_selection_is_bounded():
    urls = [f"https://example.com/{i}" for i in range(10001)]
    assert len(server.select_urls(urls, unique_urls=False, https_only=False)) == 10000
