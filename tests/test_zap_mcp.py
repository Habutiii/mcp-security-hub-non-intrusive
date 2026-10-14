"""The ZAP adapter exposes only configured login and bounded passive observation."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location("zap_test_server", ROOT / "tools/web-security/zap-mcp/server.py")
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


def profile():
    return {
        "origin": "https://example.com", "login_path": "/login",
        "verify_path": "/account/", "verify_contains": "My account",
        "username": "approved-test-user", "username_field": "username",
        "password_field": "password", "allowed_path_prefixes": ["/account/"],
    }


def test_profile_is_exact_and_deployment_owned(tmp_path, monkeypatch):
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps({"profiles": {"test": profile()}}), encoding="utf-8")
    monkeypatch.setattr(server, "PROFILE_PATH", path)
    assert server.load_profile("test")["login_path"] == "/login"
    with pytest.raises(ValueError):
        server.load_profile("../../test")
    bad = profile() | {"custom_request": "POST /admin/delete"}
    path.write_text(json.dumps({"profiles": {"test": bad}}), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported fields"):
        server.load_profile("test")


@pytest.mark.parametrize("target", [
    "https://example.com/?delete=1", "https://example.com/%2fadmin",
    "https://@example.com/", "https://example.com\\@elsewhere.test/",
])
def test_ambiguous_or_query_targets_fail(target):
    with pytest.raises(ValueError):
        server.validate_target(target)


@pytest.mark.asyncio
async def test_login_uses_only_profiled_form_and_verification(monkeypatch, tmp_path):
    calls = []

    class Jar:
        has_cookie = False

        def __iter__(self):
            return iter(["cookie"] if self.has_cookie else [])

    async def ready():
        pass

    def fetch(target, jar, *, form=None):
        calls.append((target, form))
        if form is not None:
            jar.has_cookie = True
            return {"status": 302, "body": "", "truncated": False, "content_type": ""}
        return {"status": 200, "body": "My account", "truncated": False, "content_type": "text/html"}

    monkeypatch.setattr(server, "load_profile", lambda _id: profile())
    monkeypatch.setattr(server, "ensure_zap", ready)
    monkeypatch.setattr(server, "_fetch", fetch)
    monkeypatch.setattr(server.http.cookiejar, "CookieJar", Jar)
    monkeypatch.setattr(server, "SESSIONS", {})
    monkeypatch.setattr(server, "ZAP_HOME", tmp_path)
    monkeypatch.setattr(server, "BUDGET_PATH", tmp_path / "budget.json")
    response = await server.call_tool("zap_login", {
        "target": "https://example.com", "profile_id": "test", "password": "a&b=1",
    })
    payload = json.loads(response[0].text)
    assert payload["session_id"] in server.SESSIONS
    assert calls == [
        ("https://example.com/login", b"username=approved-test-user&password=a%26b%3D1"),
        ("https://example.com/account/", None),
    ]
    assert "a&b=1" not in response[0].text


@pytest.mark.asyncio
async def test_login_budget_blocks_before_zap_start(monkeypatch, tmp_path):
    async def unexpected():
        raise AssertionError("ZAP must not start")

    monkeypatch.setattr(server, "load_profile", lambda _id: profile())
    budget = tmp_path / "budget.json"
    budget.write_text(json.dumps({"observations": 0, "login_attempts": {"test": server.MAX_LOGIN_ATTEMPTS}}), encoding="utf-8")
    monkeypatch.setattr(server, "ZAP_HOME", tmp_path)
    monkeypatch.setattr(server, "BUDGET_PATH", budget)
    monkeypatch.setattr(server, "ensure_zap", unexpected)
    response = await server.call_tool("zap_login", {
        "target": "https://example.com", "profile_id": "test", "password": "wrong",
    })
    assert "budget exhausted" in response[0].text


def test_budget_survives_component_restart(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "ZAP_HOME", tmp_path)
    monkeypatch.setattr(server, "BUDGET_PATH", tmp_path / "budget.json")
    for _ in range(server.MAX_LOGIN_ATTEMPTS):
        server.charge_budget("login", "test")
    with pytest.raises(ValueError, match="budget exhausted"):
        server.charge_budget("login", "test")


@pytest.mark.asyncio
async def test_unapproved_method_or_path_cannot_reach_zap(monkeypatch):
    async def unexpected():
        raise AssertionError("ZAP must not start")

    monkeypatch.setattr(server, "ensure_zap", unexpected)
    denied = await server.call_tool("zap_observe", {"target": "https://example.com", "method": "POST"})
    assert "Rejected" in denied[0].text
    denied = await server.call_tool("zap_active_scan", {"target": "https://example.com"})
    assert "Rejected" in denied[0].text
