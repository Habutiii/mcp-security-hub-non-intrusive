#!/usr/bin/env python3
"""Restricted, non-mutating replacement for the upstream ExternalAttacker runtime."""

import asyncio
import json
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool
from pydantic_settings import BaseSettings

from adapters.input_validation import bounded_int, host, strict_bool, tcp_ports

app = Server("restricted-externalattacker-mcp")
MAX_OUTPUT = 200_000


class Settings(BaseSettings):
    timeout: int = 120
    max_concurrent: int = 1

    class Config:
        env_prefix = "EXTERNALATTACKER_"


settings = Settings()
scan_lock = asyncio.Semaphore(settings.max_concurrent)
OPTION_FIELDS = {
    "discover_subdomains": frozenset({"domain", "timeout"}),
    "scan_ports": frozenset({"host", "ports", "rate", "concurrency", "timeout"}),
    "analyze_http": frozenset({"host", "rate", "concurrency", "include_technology", "timeout"}),
    "check_cdn": frozenset({"domain", "timeout"}),
    "analyze_tls": frozenset({"host", "port", "concurrency", "include_cipher", "timeout"}),
}


def scan_options(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Validate typed fields before mapping them to fixed scanner flags."""
    if name not in OPTION_FIELDS:
        raise ValueError("unknown tool")
    unknown = set(arguments) - OPTION_FIELDS[name]
    if unknown:
        raise ValueError(f"unsupported options: {', '.join(sorted(unknown))}")
    target_field = "domain" if name in {"discover_subdomains", "check_cdn"} else "host"
    options: dict[str, Any] = {target_field: host(arguments.get(target_field))}
    timeout_limit = min(max(settings.timeout, 1), 120)
    options["timeout"] = bounded_int(arguments.get("timeout", timeout_limit), "timeout", 1, timeout_limit)
    if name == "scan_ports":
        options["ports"] = tcp_ports(arguments.get("ports", "80,443"), max_ports=16)
        options["rate"] = bounded_int(arguments.get("rate", 50), "rate", 1, 50)
        options["concurrency"] = bounded_int(arguments.get("concurrency", 5), "concurrency", 1, 5)
    elif name == "analyze_http":
        options["rate"] = bounded_int(arguments.get("rate", 5), "rate", 1, 5)
        options["concurrency"] = bounded_int(arguments.get("concurrency", 5), "concurrency", 1, 5)
        options["include_technology"] = strict_bool(arguments.get("include_technology", True), "include_technology")
    elif name == "analyze_tls":
        options["port"] = bounded_int(arguments.get("port", 443), "port", 1, 65535)
        options["concurrency"] = bounded_int(arguments.get("concurrency", 5), "concurrency", 1, 5)
        options["include_cipher"] = strict_bool(arguments.get("include_cipher", True), "include_cipher")
    return options


async def run(executable: str, arguments: list[str], *, timeout: int) -> dict[str, Any]:
    if executable not in {"subfinder", "naabu", "httpx", "cdncheck", "tlsx"}:
        raise ValueError("unapproved executable")
    command = [executable, *arguments]
    async with scan_lock:
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except TimeoutError:
            process.kill()
            await process.wait()
            raise ValueError(f"{executable} timed out after {timeout} seconds")
    output = stdout.decode(errors="replace")
    return {
        "returncode": process.returncode, "stdout": output[:MAX_OUTPUT],
        "stderr": stderr.decode(errors="replace")[:20_000], "truncated": len(output) > MAX_OUTPUT,
    }


async def list_tools() -> list[Tool]:
    timeout = {"type": "integer", "minimum": 1, "maximum": 120, "default": 120, "description": "Maximum scan duration in seconds."}
    rate50 = {"type": "integer", "minimum": 1, "maximum": 50, "default": 50, "description": "Maximum probes per second."}
    rate5 = {"type": "integer", "minimum": 1, "maximum": 5, "default": 5, "description": "Maximum requests per second."}
    concurrency = {"type": "integer", "minimum": 1, "maximum": 5, "default": 5}
    return [
        Tool(name="discover_subdomains", description="Passive subdomain discovery for one authorized domain.", inputSchema={"type": "object", "properties": {"domain": {"type": "string"}, "timeout": timeout}, "required": ["domain"], "additionalProperties": False}),
        Tool(name="scan_ports", description="Low-rate TCP port discovery on one host, limited to 16 selected ports.", inputSchema={"type": "object", "properties": {"host": {"type": "string"}, "ports": {"type": "string", "description": "Comma-separated TCP ports or ranges covering at most 16 ports.", "default": "80,443"}, "rate": rate50, "concurrency": concurrency, "timeout": timeout}, "required": ["host"], "additionalProperties": False}),
        Tool(name="analyze_http", description="Bounded HTTP(S) response metadata probe. Custom requests are unavailable.", inputSchema={"type": "object", "properties": {"host": {"type": "string"}, "rate": rate5, "concurrency": concurrency, "include_technology": {"type": "boolean", "default": True, "description": "Include technology detection in response metadata."}, "timeout": timeout}, "required": ["host"], "additionalProperties": False}),
        Tool(name="check_cdn", description="Identify the CDN serving one domain.", inputSchema={"type": "object", "properties": {"domain": {"type": "string"}, "timeout": timeout}, "required": ["domain"], "additionalProperties": False}),
        Tool(name="analyze_tls", description="Read TLS certificate and protocol metadata from one host and optional port.", inputSchema={"type": "object", "properties": {"host": {"type": "string"}, "port": {"type": "integer", "minimum": 1, "maximum": 65535, "default": 443}, "concurrency": concurrency, "include_cipher": {"type": "boolean", "default": True, "description": "Include negotiated cipher metadata."}, "timeout": timeout}, "required": ["host"], "additionalProperties": False}),
    ]


@app.list_tools()
async def _list_tools() -> list[Tool]:
    return await list_tools()


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        options = scan_options(name, arguments)
        timeout = options["timeout"]
        if name == "discover_subdomains":
            result = await run("subfinder", ["-d", options["domain"], "-silent", "-json"], timeout=timeout)
        elif name == "scan_ports":
            result = await run("naabu", ["-host", options["host"], "-p", options["ports"], "-silent", "-json", "-rate", str(options["rate"]), "-c", str(options["concurrency"])], timeout=timeout)
        elif name == "analyze_http":
            argv = ["-target", options["host"], "-silent", "-json", "-no-color", "-threads", str(options["concurrency"]), "-rate-limit", str(options["rate"]), "-title", "-status-code", "-content-length", "-server"]
            if options["include_technology"]:
                argv.append("-tech-detect")
            result = await run("httpx", argv, timeout=timeout)
        elif name == "check_cdn":
            result = await run("cdncheck", ["-input", options["domain"], "-silent", "-jsonl"], timeout=timeout)
        elif name == "analyze_tls":
            argv = ["-u", options["host"], "-p", str(options["port"]), "-silent", "-json", "-c", str(options["concurrency"]), "-tls-version"]
            if options["include_cipher"]:
                argv.append("-cipher")
            result = await run("tlsx", argv, timeout=timeout)
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
