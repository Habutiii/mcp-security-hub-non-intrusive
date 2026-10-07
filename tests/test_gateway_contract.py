"""Static contract checks for the lazy single-image gateway."""

from pathlib import Path


ROOT_DIR = Path(__file__).parent.parent
GATEWAY_SOURCE = (ROOT_DIR / "gateway-mcp" / "server.py").read_text(encoding="utf-8")


def test_gateway_uses_a_fixed_component_registry():
    assert "COMPONENTS: dict[str, Component]" in GATEWAY_SOURCE
    assert "CAPABILITY_BY_COMPONENT" in GATEWAY_SOURCE
    assert 'command=sys.executable' in GATEWAY_SOURCE
    assert '"/opt/security-hub/gateway-mcp/launcher.py"' in GATEWAY_SOURCE
    assert '"docker", "run"' not in GATEWAY_SOURCE
    assert 'arguments.get("command")' not in GATEWAY_SOURCE
    assert "validate_scope(component_id" in GATEWAY_SOURCE
    assert "reap_idle_components" in GATEWAY_SOURCE


def test_gateway_has_required_lifecycle_controls_and_cleanup():
    for control in (
        "gateway_list_capabilities",
        "gateway_prewarm",
        "gateway_shutdown",
        "gateway_list_component_tools",
        "gateway_call",
        "await stop_all_components()",
    ):
        assert control in GATEWAY_SOURCE


def test_gateway_fails_closed_on_capability_drift():
    assert "Capability contract drift" in GATEWAY_SOURCE
    assert "set(tools) != expected_tools" in GATEWAY_SOURCE
    assert "Tool is not permitted by the reviewed capability contract" in GATEWAY_SOURCE
