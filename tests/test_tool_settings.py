"""Deployment switches must match and only narrow the fixed registry."""

import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "gateway-mcp"))
from capability_policy import CAPABILITIES  # noqa: E402
from tool_settings import load_tool_settings  # noqa: E402


def test_default_settings_cover_every_local_component_and_tool():
    settings = load_tool_settings()
    expected = {cap.component_id: cap.allowed_tools for cap in CAPABILITIES}
    assert settings.enabled_components == set(expected)
    assert settings.enabled_tools == expected
    assert len(expected) == 13
    assert sum(map(len, expected.values())) == 47


def test_switches_disable_only_selected_component_or_tool(tmp_path):
    source = (ROOT / "tool_setting.ini").read_text(encoding="utf-8")
    path = tmp_path / "tool_setting.ini"
    path.write_text(source.replace("nmap = true", "nmap = false").replace(
        "ffuf.ffuf_dir = true", "ffuf.ffuf_dir = false"
    ), encoding="utf-8")
    settings = load_tool_settings(path)
    assert "nmap" not in settings.enabled_components
    assert not settings.tools_for("nmap")
    assert "ffuf.ffuf_dir" not in {f"ffuf.{name}" for name in settings.tools_for("ffuf")}
    assert "ffuf.ffuf_vhost" in {f"ffuf.{name}" for name in settings.tools_for("ffuf")}


@pytest.mark.parametrize("change", [
    lambda source: source.replace("nmap.port_scan = true\n", ""),
    lambda source: source + "\nnmap.unreviewed = true\n",
    lambda source: source.replace("nmap.port_scan = true", "nmap.port_scan = maybe"),
])
def test_malformed_or_unreviewed_settings_fail_closed(tmp_path, change):
    path = tmp_path / "tool_setting.ini"
    path.write_text(change((ROOT / "tool_setting.ini").read_text(encoding="utf-8")), encoding="utf-8")
    with pytest.raises(ValueError):
        load_tool_settings(path)
