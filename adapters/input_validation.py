"""Validate agent-provided values before constructing fixed scanner argv.

Shell quoting is not a security boundary here: adapters pass each validated
value as one argv element to create_subprocess_exec, without a shell.
"""

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit


HOSTNAME = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z"
)
PORT_LIST = re.compile(r"[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*\Z")


def bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def strict_bool(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{name} must be a boolean")
    return value


def host(value: Any, *, allow_cidr: bool = False) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 253:
        raise ValueError("target must be a hostname or IP address")
    if any(ord(char) < 33 or ord(char) == 127 for char in value):
        raise ValueError("target contains a control character")
    try:
        if allow_cidr and "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not HOSTNAME.fullmatch(value) or value.startswith("-"):
            raise ValueError("target must be a hostname or IP address") from None
        return value.lower()


def http_url(value: Any, *, allow_query: bool = True, max_length: int = 2048) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise ValueError("target must be a bounded HTTP or HTTPS URL")
    if any(ord(char) < 33 or ord(char) == 127 for char in value):
        raise ValueError("target URL contains whitespace or control characters")
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("target must be an HTTP or HTTPS URL")
        if parsed.username or parsed.password or parsed.fragment or (parsed.query and not allow_query):
            raise ValueError("target URL contains unsupported credentials, query, or fragment")
        host(parsed.hostname)
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("target URL has an invalid port")
    except ValueError as error:
        raise ValueError(str(error)) from None
    return value


def tcp_ports(value: Any, *, max_ports: int = 1024) -> str:
    if not isinstance(value, str) or not PORT_LIST.fullmatch(value):
        raise ValueError("ports must be a comma-separated list of TCP ports or ranges")
    total = 0
    for item in value.split(","):
        first, _, last = item.partition("-")
        start = int(first)
        end = int(last) if last else start
        if not 1 <= start <= end <= 65535:
            raise ValueError("ports must be from 1 to 65535 in ascending ranges")
        total += end - start + 1
        if total > max_ports:
            raise ValueError(f"ports may cover at most {max_ports} TCP ports")
    return value
