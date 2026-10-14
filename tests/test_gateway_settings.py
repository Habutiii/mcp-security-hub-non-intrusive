"""Exercise gateway switch enforcement without launching scanner processes."""

import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


sys.path.insert(0, str(Path(__file__).parent.parent / "gateway-mcp"))
import server as gateway  # noqa: E402
from tool_settings import ToolSettings  # noqa: E402


def response(contents):
    return json.loads(contents[0].text)


@pytest.mark.asyncio
async def test_disabled_tool_disappears_and_cannot_start_child(monkeypatch):
    enabled = dict(gateway.SETTINGS.enabled_tools)
    enabled["ffuf"] = enabled["ffuf"] - {"ffuf_dir"}
    monkeypatch.setattr(gateway, "SETTINGS", ToolSettings(gateway.SETTINGS.enabled_components, enabled))

    async def unexpected_start(_component_id):
        raise AssertionError("disabled tool must not start a child")

    monkeypatch.setattr(gateway, "start_component", unexpected_start)
    caps = response(await gateway.call_tool("gateway_list_capabilities", {}))
    assert "ffuf_dir" not in caps["ffuf"]["allowed_tools"]
    result = response(await gateway.call_tool("gateway_call", {
        "mcp_id": "ffuf", "tool_name": "ffuf_dir", "arguments": {"url": "https://example.com"},
    }))
    assert "not permitted" in result["error"]


@pytest.mark.asyncio
async def test_targetless_result_query_does_not_require_target(monkeypatch):
    class Session:
        async def call_tool(self, name, arguments):
            assert name == "get_scan_results"
            assert arguments == {"scan_id": "saved"}
            return SimpleNamespace(model_dump=lambda **_kwargs: {"content": []})

    instance = SimpleNamespace(
        session=Session(), tools={"get_scan_results": object()},
        lock=asyncio.Lock(), active_calls=0, last_used=0,
    )

    async def fake_start(_component_id):
        return instance

    def unexpected_scope(*_args):
        raise AssertionError("local result access must not require a target")

    monkeypatch.setattr(gateway, "start_component", fake_start)
    monkeypatch.setattr(gateway, "validate_scope", unexpected_scope)
    result = response(await gateway.call_tool("gateway_call", {
        "mcp_id": "nmap", "tool_name": "get_scan_results", "arguments": {"scan_id": "saved"},
    }))
    assert result["tool_name"] == "get_scan_results"


@pytest.mark.asyncio
async def test_target_facing_call_still_rejects_out_of_scope(monkeypatch):
    monkeypatch.setenv("AGW_ALLOWED_TARGETS", "example.com")

    async def unexpected_start(_component_id):
        raise AssertionError("out-of-scope call must not start a child")

    monkeypatch.setattr(gateway, "start_component", unexpected_start)
    result = response(await gateway.call_tool("gateway_call", {
        "mcp_id": "ffuf", "tool_name": "ffuf_dir",
        "arguments": {"url": "https://other.example.net/FUZZ"},
    }))
    assert "outside AGW_ALLOWED_TARGETS" in result["error"]
