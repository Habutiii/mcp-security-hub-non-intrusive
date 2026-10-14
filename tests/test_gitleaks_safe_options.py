"""Local Gitleaks calls reject arbitrary paths/options and redact reports."""

import importlib.util
import json
from datetime import datetime
from pathlib import Path

import pytest


SERVER = Path(__file__).resolve().parents[1] / "tools/secrets/gitleaks-mcp/server.py"
spec = importlib.util.spec_from_file_location("gitleaks_safe_server", SERVER)
gitleaks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gitleaks)


@pytest.fixture
def approved_root(tmp_path, monkeypatch):
    root = tmp_path / "approved"
    root.mkdir()
    monkeypatch.setattr(gitleaks, "ALLOWED_INPUT_ROOTS", (root.resolve(),))
    return root


@pytest.mark.asyncio
async def test_directory_scan_passes_resolved_approved_path_and_bounded_options(approved_root, monkeypatch):
    folder = approved_root / "source"
    folder.mkdir()
    seen = []

    async def fake_scan(**kwargs):
        seen.append(kwargs)
        return gitleaks.ScanResult(scan_id="aabbccdd", target=kwargs["target"], scan_type="dir", started_at=datetime.now(), status="completed")

    monkeypatch.setattr(gitleaks, "run_gitleaks_scan", fake_scan)
    response = await gitleaks.call_tool("gitleaks_scan_dir", {"dir_path": str(folder), "timeout": 45, "max_findings": 7})
    assert json.loads(response[0].text)["status"] == "completed"
    assert seen == [{"target": str(folder.resolve()), "scan_type": "dir", "timeout": 45, "no_git": True}]


@pytest.mark.asyncio
@pytest.mark.parametrize("arguments", [
    {"dir_path": "../outside"},
    {"dir_path": "-update"},
    {"dir_path": "../outside", "timeout": 10},
    {"dir_path": "x", "flags": "--config /etc/passwd"},
    {"dir_path": "x", "timeout": True},
    {"dir_path": "x", "timeout": 301},
    {"dir_path": "x", "max_findings": 0},
])
async def test_invalid_directory_arguments_never_scan(arguments, approved_root, monkeypatch):
    async def fail_scan(**kwargs):
        pytest.fail("scan executed after invalid arguments")

    monkeypatch.setattr(gitleaks, "run_gitleaks_scan", fail_scan)
    response = await gitleaks.call_tool("gitleaks_scan_dir", arguments)
    assert response[0].text.startswith("Error:")


def test_path_traversal_and_symlink_escape_are_rejected(approved_root, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (approved_root / "link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pass  # Windows may require developer mode or elevated symlink privileges.
    else:
        with pytest.raises(ValueError):
            gitleaks.approved_directory(str(approved_root / "link"))
    with pytest.raises(ValueError):
        gitleaks.approved_directory(str(approved_root / ".." / "outside"))


@pytest.mark.asyncio
async def test_content_and_query_options_are_typed(monkeypatch):
    calls = []

    async def fake_content(content, timeout):
        calls.append((content, timeout))
        return gitleaks.ScanResult(scan_id="aabbccdd", target="<content>", scan_type="content", started_at=datetime.now(), status="completed")

    monkeypatch.setattr(gitleaks, "scan_content", fake_content)
    accepted = await gitleaks.call_tool("gitleaks_detect", {"content": "test text", "timeout": 3})
    rejected = await gitleaks.call_tool("gitleaks_detect", {"content": "x" * 64001})
    assert json.loads(accepted[0].text)["status"] == "completed"
    assert rejected[0].text.startswith("Error:")
    assert calls == [("test text", 3)]


def test_raw_report_contains_only_redacted_fields():
    secret = "aaaaabbbbb"
    parsed = gitleaks.parse_gitleaks_json(json.dumps([{"RuleID": "test", "Secret": secret, "Match": "password=" + secret, "File": "x"}]))
    safe = gitleaks.safe_raw_findings(parsed)
    assert secret not in safe
    assert "password=" not in safe
    assert json.loads(safe)[0]["Secret"] == secret[:4] + "*" * (len(secret) - 4)


@pytest.mark.asyncio
async def test_tool_schemas_disallow_unknown_fields():
    for tool in await gitleaks.list_tools():
        assert tool.inputSchema["additionalProperties"] is False
