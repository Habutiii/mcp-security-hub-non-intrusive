#!/usr/bin/env python3
"""Local MCP adapter for vetted ProjectDiscovery discovery binaries."""

import asyncio
import json
from typing import Any
from urllib.parse import urlsplit

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool
from pydantic_settings import BaseSettings
from adapters.input_validation import bounded_int, host as validated_host, http_url, strict_bool

app = Server("restricted-pd-tools-mcp")
MAX_TARGETS = 20
MAX_OUTPUT = 200_000
DNS_RECORD_FLAGS = {"A": "-a", "AAAA": "-aaaa", "CNAME": "-cname", "MX": "-mx", "NS": "-ns", "TXT": "-txt", "SOA": "-soa", "CAA": "-caa"}


class Settings(BaseSettings):
    timeout: int = 120
    max_concurrent: int = 1

    class Config:
        env_prefix = "PD_"


settings = Settings()
scan_lock = asyncio.Semaphore(settings.max_concurrent)


def host(value: Any) -> str:
    return validated_host(value)


def url(value: Any) -> str:
    result = http_url(value, allow_query=False)
    # Empty userinfo and encoded separators are ambiguous to downstream parsers.
    authority = urlsplit(result).netloc
    if "@" in authority or "%" in authority or "\\" in result:
        raise ValueError("target URL contains unsupported authority characters")
    return result


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


def option_int(arguments: dict[str, Any], key: str, default: int, maximum: int) -> str:
    return str(bounded_int(arguments.get(key, default), key, 1, maximum))


def option_bool(arguments: dict[str, Any], key: str, default: bool = False) -> bool:
    return strict_bool(arguments.get(key, default), key)


def known_options(arguments: dict[str, Any], allowed: set[str]) -> None:
    if not isinstance(arguments, dict) or arguments.keys() - allowed:
        raise ValueError("unsupported tool option")


def dns_record_flags(value: Any) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 8 or any(type(item) is not str or item not in DNS_RECORD_FLAGS for item in value):
        raise ValueError("record_types must be a list of supported DNS record names")
    return [flag for name, flag in DNS_RECORD_FLAGS.items() if name in value]


def int_schema(default: int, maximum: int) -> dict[str, Any]:
    return {"type": "integer", "minimum": 1, "maximum": maximum, "default": default}


def bool_schema(default: bool = False) -> dict[str, Any]:
    return {"type": "boolean", "default": default}


def schema(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}


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
        Tool(name="pd_subfinder", description="Passive subdomain discovery with bounded provider request rate.", inputSchema=schema({"domain": {"type": "string"}, "rate_limit": int_schema(5, 10)}, ["domain"])),
        Tool(name="pd_dns_resolve", description="Resolve selected safe DNS record types for at most 20 supplied hosts.", inputSchema=schema({"hosts": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 20}, "record_types": {"type": "array", "items": {"type": "string", "enum": list(DNS_RECORD_FLAGS)}, "minItems": 1, "maxItems": 8, "default": ["A"]}, "rate_limit": int_schema(20, 50), "threads": int_schema(5, 10)}, ["hosts"])),
        Tool(name="pd_port_scan", description="Low-rate TCP discovery on supplied hosts and at most 20 ports.", inputSchema=schema({"hosts": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 20}, "ports": {"type": "array", "items": {"type": "integer", "minimum": 1, "maximum": 65535}, "minItems": 1, "maxItems": 20}, "rate_limit": int_schema(50, 100), "concurrency": int_schema(5, 10)}, ["hosts"])),
        Tool(name="pd_http_probe", description="Bounded HTTP(S) fingerprinting of supplied URLs; no redirects or custom requests.", inputSchema=schema({"urls": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 20}, "rate_limit": int_schema(5, 10), "threads": int_schema(5, 10), "status_code": bool_schema(), "title": bool_schema(), "tech_detect": bool_schema(), "content_length": bool_schema(), "web_server": bool_schema()}, ["urls"])),
        Tool(name="pd_crawl", description="Same-host GET-style HTTP(S) crawl with bounded depth and rate.", inputSchema=schema({"urls": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 20}, "depth": int_schema(2, 3), "rate_limit": int_schema(5, 10), "concurrency": int_schema(5, 10), "parallelism": int_schema(5, 10)}, ["urls"])),
    ]


@app.list_tools()
async def _list_tools() -> list[Tool]:
    return await list_tools()


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        if name == "pd_subfinder":
            known_options(arguments, {"domain", "rate_limit"})
            result = await run("subfinder", ["-d", host(arguments.get("domain")), "-silent", "-json", "-rl", option_int(arguments, "rate_limit", 5, 10)])
        elif name == "pd_dns_resolve":
            known_options(arguments, {"hosts", "record_types", "rate_limit", "threads"})
            input_hosts = targets(arguments.get("hosts"), host)
            flags = dns_record_flags(arguments.get("record_types", ["A"]))
            result = await run("dnsx", ["-silent", "-json", "-rl", option_int(arguments, "rate_limit", 20, 50), "-t", option_int(arguments, "threads", 5, 10), *flags], "\n".join(input_hosts) + "\n")
        elif name == "pd_port_scan":
            known_options(arguments, {"hosts", "ports", "rate_limit", "concurrency"})
            input_hosts = targets(arguments.get("hosts"), host)
            result = await run("naabu", ["-silent", "-json", "-rate", option_int(arguments, "rate_limit", 50, 100), "-c", option_int(arguments, "concurrency", 5, 10), "-p", ports(arguments.get("ports"))], "\n".join(input_hosts) + "\n")
        elif name == "pd_http_probe":
            known_options(arguments, {"urls", "rate_limit", "threads", "status_code", "title", "tech_detect", "content_length", "web_server"})
            input_urls = targets(arguments.get("urls"), url)
            flags = [flag for key, flag in (("status_code", "-status-code"), ("title", "-title"), ("tech_detect", "-tech-detect"), ("content_length", "-content-length"), ("web_server", "-web-server")) if option_bool(arguments, key)]
            result = await run("httpx", ["-silent", "-json", "-no-color", "-nfs", "-threads", option_int(arguments, "threads", 5, 10), "-rate-limit", option_int(arguments, "rate_limit", 5, 10), *flags], "\n".join(input_urls) + "\n")
        elif name == "pd_crawl":
            known_options(arguments, {"urls", "depth", "rate_limit", "concurrency", "parallelism"})
            input_urls = targets(arguments.get("urls"), url)
            result = await run("katana", ["-silent", "-jsonl", "-d", option_int(arguments, "depth", 2, 3), "-c", option_int(arguments, "concurrency", 5, 10), "-p", option_int(arguments, "parallelism", 5, 10), "-rl", option_int(arguments, "rate_limit", 5, 10), "-fs", "fqdn"], "\n".join(input_urls) + "\n")
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
