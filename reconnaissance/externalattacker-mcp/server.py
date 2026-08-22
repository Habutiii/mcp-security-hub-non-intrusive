#!/usr/bin/env python3
"""Restricted, non-mutating replacement for the upstream ExternalAttacker runtime."""

import asyncio
import ipaddress
import json
import re
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool
from pydantic_settings import BaseSettings

app = Server("restricted-externalattacker-mcp")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
MAX_OUTPUT = 200_000


class Settings(BaseSettings):
    timeout: int = 120
    max_concurrent: int = 1

    class Config:
        env_prefix = "EXTERNALATTACKER_"


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


def port(value: Any) -> str:
    if value is None:
        return "443"
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
        raise ValueError("port must be an integer from 1 through 65535")
    return str(value)


async def run(executable: str, arguments: list[str]) -> dict[str, Any]:
    if executable not in {"subfinder", "naabu", "httpx", "cdncheck", "tlsx"}:
        raise ValueError("unapproved executable")
    command = [executable, *arguments]
    async with scan_lock:
        process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=settings.timeout)
        except TimeoutError:
            process.kill()
            await process.wait()
            raise ValueError(f"{executable} timed out after {settings.timeout} seconds")
    output = stdout.decode(errors="replace")
    return {"returncode": process.returncode, "stdout": output[:MAX_OUTPUT], "stderr": stderr.decode(errors="replace")[:20_000], "truncated": len(output) > MAX_OUTPUT}


async def list_tools() -> list[Tool]:
    return [
        Tool(name="discover_subdomains", description="Passive subdomain discovery for one authorized domain.", inputSchema={"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"], "additionalProperties": False}),
        Tool(name="scan_ports", description="Low-rate TCP port discovery on one host. Port list is fixed to 80 and 443.", inputSchema={"type": "object", "properties": {"host": {"type": "string"}}, "required": ["host"], "additionalProperties": False}),
        Tool(name="analyze_http", description="Bounded HTTP(S) technology and response metadata probe. Custom requests are unavailable.", inputSchema={"type": "object", "properties": {"host": {"type": "string"}}, "required": ["host"], "additionalProperties": False}),
        Tool(name="check_cdn", description="Identify the CDN serving one domain.", inputSchema={"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"], "additionalProperties": False}),
        Tool(name="analyze_tls", description="Read TLS certificate and protocol metadata from one host and optional port.", inputSchema={"type": "object", "properties": {"host": {"type": "string"}, "port": {"type": "integer", "minimum": 1, "maximum": 65535}}, "required": ["host"], "additionalProperties": False}),
    ]


@app.list_tools()
async def _list_tools() -> list[Tool]:
    return await list_tools()


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        if name == "discover_subdomains":
            result = await run("subfinder", ["-d", host(arguments.get("domain")), "-silent", "-json"])
        elif name == "scan_ports":
            result = await run("naabu", ["-host", host(arguments.get("host")), "-p", "80,443", "-silent", "-json", "-rate", "50", "-c", "5"])
        elif name == "analyze_http":
            result = await run("httpx", ["-target", host(arguments.get("host")), "-silent", "-json", "-no-color", "-threads", "5", "-rate-limit", "5", "-title", "-status-code", "-content-length", "-server", "-tech-detect"])
        elif name == "check_cdn":
            result = await run("cdncheck", ["-input", host(arguments.get("domain")), "-silent", "-jsonl"])
        elif name == "analyze_tls":
            result = await run("tlsx", ["-u", host(arguments.get("host")), "-p", port(arguments.get("port")), "-silent", "-json", "-c", "5", "-tls-version", "-cipher"])
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
