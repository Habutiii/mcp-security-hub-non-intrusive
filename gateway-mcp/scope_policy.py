"""Immutable, deployment-owned target scope enforcement for the AGW."""

import ipaddress
import os
import socket
from urllib.parse import urlparse


class ScopeError(ValueError):
    """Raised when a target-bearing call is outside the configured scope."""


def _configured_scope() -> tuple[str, ...]:
    values = tuple(value.strip().lower().rstrip(".") for value in os.environ.get("AGW_ALLOWED_TARGETS", "").split(",") if value.strip())
    if not values:
        raise ScopeError("AGW_ALLOWED_TARGETS must be configured before target-facing tools can run")
    if any(value in {"*", "0.0.0.0/0", "::/0"} for value in values):
        raise ScopeError("AGW_ALLOWED_TARGETS must contain explicit domains or bounded IP networks")
    return values


def _hostname(value: str) -> str:
    parsed = urlparse(value)
    hostname = parsed.hostname if parsed.scheme else value.split("/", 1)[0].split(":", 1)[0]
    if not hostname:
        raise ScopeError("target has no hostname")
    return hostname.lower().rstrip(".")


def _in_scope(value: str, allowed: tuple[str, ...]) -> bool:
    hostname = _hostname(value)
    try:
        candidate = ipaddress.ip_network(hostname, strict=False)
    except ValueError:
        return any(hostname == entry or hostname.endswith("." + entry) for entry in allowed if "/" not in entry)
    for entry in allowed:
        try:
            if candidate.subnet_of(ipaddress.ip_network(entry, strict=False)):
                return True
        except ValueError:
            continue
    return False


def _allowed_networks(allowed: tuple[str, ...]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks = []
    for entry in allowed:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            continue
    return tuple(networks)


def _resolved_addresses(hostname: str) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve a hostname immediately before tool startup.

    The lookup is deliberately performed for every authorized domain request so
    a DNS answer cannot silently move a domain-scoped operation onto a local or
    private network.
    """
    try:
        results = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise ScopeError("target hostname could not be resolved") from error
    addresses = {ipaddress.ip_address(result[4][0]) for result in results}
    if not addresses:
        raise ScopeError("target hostname did not resolve to an IP address")
    return addresses


def _validate_resolved_target(value: str, allowed: tuple[str, ...]) -> None:
    """Reject domain names that currently resolve to unsafe network addresses.

    Private addresses remain supported only when the deployment explicitly
    includes the matching CIDR in ``AGW_ALLOWED_TARGETS``. This prevents a
    domain allowlist entry from being used as a DNS-rebinding path to local
    services while retaining intentional internal assessments.
    """
    hostname = _hostname(value)
    try:
        ipaddress.ip_address(hostname)
        return
    except ValueError:
        pass
    networks = _allowed_networks(allowed)
    for address in _resolved_addresses(hostname):
        unsafe = (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        )
        if unsafe and not any(address in network for network in networks):
            raise ScopeError("target hostname resolved to an address outside explicit IP scope")


TARGET_FIELDS: dict[str, tuple[str, ...]] = {
    "waybackurls": ("domain",),
    "nmap": ("target",),
    "whatweb": ("target",),
    "ffuf": ("url", "domain"),
    "pd_tools": ("domain", "hosts", "urls"),
    "externalattacker": ("domain", "host"),
    "masscan": ("targets",),
    "nikto": ("target",),
}


def validate_scope(component_id: str, arguments: dict[str, object]) -> dict[str, object]:
    """Reject every target-bearing value that is not inside deployment scope."""
    fields = TARGET_FIELDS.get(component_id, ())
    if not fields:
        return {"targets": []}
    allowed = _configured_scope()
    targets: list[str] = []
    for field in fields:
        value = arguments.get(field)
        if isinstance(value, str):
            targets.append(value)
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            targets.extend(value)
    if not targets:
        raise ScopeError("a target within AGW_ALLOWED_TARGETS is required")
    rejected = [target for target in targets if not _in_scope(target, allowed)]
    if rejected:
        raise ScopeError("target is outside AGW_ALLOWED_TARGETS")
    for target in targets:
        _validate_resolved_target(target, allowed)
    if component_id == "masscan":
        for target in targets:
            try:
                network = ipaddress.ip_network(target, strict=False)
            except ValueError as error:
                raise ScopeError("Masscan targets must be an IP address or CIDR") from error
            if network.prefixlen < (24 if network.version == 4 else 64):
                raise ScopeError("Masscan is limited to at most a /24 IPv4 or /64 IPv6 target range")
    return {"targets": targets, "scope": list(allowed)}
