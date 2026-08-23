"""Static contract checks for the lazy Docker gateway."""

from pathlib import Path


ROOT_DIR = Path(__file__).parent.parent
GATEWAY_SOURCE = (ROOT_DIR / "gateway-mcp" / "server.py").read_text(encoding="utf-8")


def test_gateway_uses_a_fixed_component_registry():
    assert "COMPONENTS: dict[str, Component]" in GATEWAY_SOURCE
    assert 'args=["run", "--name", container_name, "-i", "--rm", *component.docker_args, component.image]' in GATEWAY_SOURCE
    assert 'arguments.get("image")' not in GATEWAY_SOURCE
    assert 'arguments.get("docker_args")' not in GATEWAY_SOURCE


def test_gateway_has_required_lifecycle_controls_and_cleanup():
    for control in (
        "gateway_prewarm",
        "gateway_shutdown",
        "gateway_list_component_tools",
        "gateway_call",
        "await stop_all_components()",
    ):
        assert control in GATEWAY_SOURCE
