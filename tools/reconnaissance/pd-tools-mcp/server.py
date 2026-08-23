#!/usr/bin/env python3
"""Restricted, non-mutating wrapper for vetted ProjectDiscovery discovery tools."""

import asyncio
import ipaddress
import json
import re
from typing import Any
from urllib.parse import urlparse

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool
from pydantic_settings import BaseSettings

app = Server("restricted-pd-tools-mcp")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
MAX_TARGETS = 20
MAX_OUTPUT = 200_000


class Settings(BaseSettings):
    timeout: int = 120
    max_concurrent: int = 1

    class Config:
        env_prefix = "PD_"


settings = Settings()
scan_lock = asyncio.Semaphore(settings.max_concurrent)


def host(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 253 or not value or value.startswith("-"):
        raise ValueError("target must be a hostname or IP address")
    candidate = value.strip().rstrip(".")
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        if not HOST_RE.fullmatch(candidate):
            raise ValueError("target must be a hostname or IP address")
        return candidate.lower()


def url(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("target must be an HTTP or HTTPS URL")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("target must be an HTTP or HTTPS URL without credentials")
    host(parsed.hostname)
    if parsed.fragment:
        raise ValueError("URL fragments are not permitted")
    return value


def targets(values: Any, validator) -> list[str]:
    if not isinstance(values, list) or not 1 <= len(values) <= MAX_TARGETS:
        raise ValueError(f"provide between 1 and {MAX_TARGETS} targets")
    return [validator(value) for value in values]


def ports(value: Any) -> str:
    if value is None:
        return "80,443"
    if not isinstance(value, list) or not 1 <= len(value) <= 20:
        raise ValueError("ports must contain between 1 and 20 TCP port numbers")
    parsed = []
    for port in value:
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError("ports must contain integers from 1 through 65535")
        parsed.append(port)
    return ",".join(str(port) for port in sorted(set(parsed)))


async def run(executable: str, arguments: list[str], stdin: str = "") -> dict[str, Any]:
    if executable not in {"subfinder", "dnsx", "naabu", "httpx", "katana"}:
        raise ValueError("unapproved executable")
    command = [executable, *arguments]
    async with scan_lock:
        process = await asyncio.create_subprocess_exec(*command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(stdin.encode()), timeout=settings.timeout)
        except TimeoutError:
            process.kill()
            await process.wait()
            raise ValueError(f"{executable} timed out after {settings.timeout} seconds")
    output = stdout.decode(errors="replace")
    return {"returncode": process.returncode, "stdout": output[:MAX_OUTPUT], "stderr": stderr.decode(errors="replace")[:20_000], "truncated": len(output) > MAX_OUTPUT}


async def list_tools() -> list[Tool]:
    return [
        Tool(name="pd_subfinder", description="Passive subdomain discovery. No active source mode is enabled.", inputSchema={"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"], "additionalProperties": False}),
        Tool(name="pd_dns_resolve", description="Resolve DNS records for at most 20 supplied hostnames.", inputSchema={"type": "object", "properties": {"hosts": {"type": "array", "items": {"type": "string"}, "maxItems": 20}}, "required": ["hosts"], "additionalProperties": False}),
        Tool(name="pd_port_scan", description="Low-rate TCP discovery on explicitly supplied hosts and up to 20 ports.", inputSchema={"type": "object", "properties": {"hosts": {"type": "array", "items": {"type": "string"}, "maxItems": 20}, "ports": {"type": "array", "items": {"type": "integer", "minimum": 1, "maximum": 65535}, "maxItems": 20}}, "required": ["hosts"], "additionalProperties": False}),
        Tool(name="pd_http_probe", description="Bounded HTTP(S) fingerprinting. Redirects, screenshots, custom methods, bodies, and headers are unavailable.", inputSchema={"type": "object", "properties": {"urls": {"type": "array", "items": {"type": "string"}, "maxItems": 20}}, "required": ["urls"], "additionalProperties": False}),
        Tool(name="pd_crawl", description="Same-registrable-domain HTTP(S) crawl at fixed depth and rate. Only GET-style discovery is exposed.", inputSchema={"type": "object", "properties": {"urls": {"type": "array", "items": {"type": "string"}, "maxItems": 20}}, "required": ["urls"], "additionalProperties": False}),
    ]


@app.list_tools()
async def _list_tools() -> list[Tool]:
    return await list_tools()


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        if name == "pd_subfinder":
            result = await run("subfinder", ["-d", host(arguments.get("domain")), "-silent", "-json"])
        elif name == "pd_dns_resolve":
            result = await run("dnsx", ["-silent", "-json"], "\n".join(targets(arguments.get("hosts"), host)) + "\n")
        elif name == "pd_port_scan":
            result = await run("naabu", ["-silent", "-json", "-rate", "50", "-c", "5", "-p", ports(arguments.get("ports"))], "\n".join(targets(arguments.get("hosts"), host)) + "\n")
        elif name == "pd_http_probe":
            result = await run("httpx", ["-silent", "-json", "-no-color", "-threads", "5", "-rate-limit", "5"], "\n".join(targets(arguments.get("urls"), url)) + "\n")
        elif name == "pd_crawl":
            result = await run("katana", ["-silent", "-jsonl", "-d", "2", "-c", "5", "-p", "5", "-rl", "5", "-fs", "rdn"], "\n".join(targets(arguments.get("urls"), url)) + "\n")
        else:
            raise ValueError("unknown tool")
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except (TypeError, ValueError) as error:
        return [TextContent(type="text", text=f"Rejected: {error}")]


async def main() -> None:
    async with stdio_server() as streams:
        await app.run(streams[0], streams[1], app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
