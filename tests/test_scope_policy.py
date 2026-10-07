"""Tests for deployment-owned AGW target scope enforcement."""

import importlib.util
from pathlib import Path

import pytest


PATH = Path(__file__).parent.parent / "gateway-mcp" / "scope_policy.py"
SPEC = importlib.util.spec_from_file_location("scope_policy", PATH)
assert SPEC and SPEC.loader
scope_policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scope_policy)


def test_rejects_target_calls_without_configured_scope(monkeypatch):
    monkeypatch.delenv("AGW_ALLOWED_TARGETS", raising=False)
    with pytest.raises(scope_policy.ScopeError):
        scope_policy.validate_scope("nmap", {"target": "example.com"})


def test_allows_domain_and_subdomains_but_rejects_other_domains(monkeypatch):
    monkeypatch.setenv("AGW_ALLOWED_TARGETS", "example.com")
    scope_policy.validate_scope("ffuf", {"url": "https://app.example.com/login"})
    with pytest.raises(scope_policy.ScopeError):
        scope_policy.validate_scope("ffuf", {"url": "https://example.net"})


def test_allows_only_ip_subnets_within_the_configured_network(monkeypatch):
    monkeypatch.setenv("AGW_ALLOWED_TARGETS", "10.10.0.0/16")
    scope_policy.validate_scope("nmap", {"target": "10.10.4.0/24"})
    with pytest.raises(scope_policy.ScopeError):
        scope_policy.validate_scope("nmap", {"target": "10.11.0.1"})


def test_rejects_wildcard_scope(monkeypatch):
    monkeypatch.setenv("AGW_ALLOWED_TARGETS", "0.0.0.0/0")
    with pytest.raises(scope_policy.ScopeError):
        scope_policy.validate_scope("nmap", {"target": "10.10.0.1"})


def test_masscan_rejects_broad_networks(monkeypatch):
    monkeypatch.setenv("AGW_ALLOWED_TARGETS", "10.10.0.0/16")
    scope_policy.validate_scope("masscan", {"targets": "10.10.1.0/24"})
    with pytest.raises(scope_policy.ScopeError):
        scope_policy.validate_scope("masscan", {"targets": "10.10.0.0/16"})


def test_nikto_target_uses_the_standard_target_scope(monkeypatch):
    monkeypatch.setenv("AGW_ALLOWED_TARGETS", "example.com")
    scope_policy.validate_scope("nikto", {"target": "https://app.example.com"})
    with pytest.raises(scope_policy.ScopeError):
        scope_policy.validate_scope("nikto", {"target": "https://example.net"})
