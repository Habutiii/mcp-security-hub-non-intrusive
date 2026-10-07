"""Static checks for the immutable single-image AGW runtime."""

from pathlib import Path


DOCKERFILE = (Path(__file__).parent.parent / "Dockerfile").read_text(encoding="utf-8")
COMPOSE = (Path(__file__).parent.parent / "docker-compose.yml").read_text(encoding="utf-8")


def test_packaged_code_and_assets_are_not_tool_writable():
    assert "chown -R root:root /opt/security-hub /app" in DOCKERFILE
    assert "chmod -R a-w /opt/security-hub /app" in DOCKERFILE
    assert "chown -R mcpuser:mcpuser /var/lib/security-hub" in DOCKERFILE


def test_compose_uses_an_immutable_root_filesystem():
    assert "read_only: true" in COMPOSE
    assert "cap_drop:" in COMPOSE
    assert "no-new-privileges:true" in COMPOSE
