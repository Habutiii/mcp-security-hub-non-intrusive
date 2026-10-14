#!/usr/bin/env python3
"""Restricted, read-only Nikto MCP for the single-image AGW."""

import asyncio
import json
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from adapters.runtime import run_fixed_command
from adapters.input_validation import bounded_int, host as validate_host, http_url
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

app = Server("nikto-observer-mcp")
OUTPUT_DIR = Path("/var/lib/security-hub/nikto")
TIMEOUT_SECONDS = 300
# Informational file, configuration, disclosure, and software-identification
# checks only. DoS, RCE, injection, upload, auth-bypass, and user-selected
# plugin/tuning modes are deliberately unavailable.
CHECK_TYPES = {
    "interesting_files": "1",
    "misconfiguration": "2",
    "information_disclosure": "3",
    "software_identification": "b",
}
results: dict[str, dict[str, Any]] = {}


def target(value: Any) -> tuple[str, int, bool]:
    http_url(value, allow_query=False)
    parsed = urlparse(value)
    if parsed.path not in {"", "/"}:
        raise ValueError("target must be an origin URL without a path")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in {80, 443, 8080, 8443}:
        raise ValueError("target port must be one of 80, 443, 8080, or 8443")
    return validate_host(parsed.hostname), port, parsed.scheme == "https"


def build_nikto_command(
    value: str, output: Path, *, checks: list[str] | None = None,
    pause_seconds: int = 0, request_timeout: int = 10,
    max_time: int = 300,
) -> list[str]:
    target_host, port, use_tls = target(value)
    if checks is None:
        checks = list(CHECK_TYPES)
    if (not isinstance(checks, list) or not checks or len(checks) > len(CHECK_TYPES)
            or not all(isinstance(name, str) for name in checks)
            or len(set(checks)) != len(checks) or not set(checks).issubset(CHECK_TYPES)):
        raise ValueError("checks must select unique reviewed observation categories")
    pause_seconds = bounded_int(pause_seconds, "pause_seconds", 0, 3)
    request_timeout = bounded_int(request_timeout, "request_timeout", 1, 10)
    max_time = bounded_int(max_time, "max_time", 30, 300)
    tuning = "".join(CHECK_TYPES[name] for name in CHECK_TYPES if name in checks)
    command = [
        "nikto", "-host", target_host, "-port", str(port), "-Tuning", tuning,
        "-Format", "json", "-output", str(output), "-nointeractive",
        "-nocheck", "-Pause", str(pause_seconds), "-timeout", str(request_timeout),
        "-maxtime", f"{max_time}s",
    ]
    if use_tls:
        command.append("-ssl")
    return command


async def observe(
    value: str, *, checks: list[str] | None = None,
    pause_seconds: int = 0, request_timeout: int = 10, max_time: int = 300,
) -> dict[str, Any]:
    scan_id = uuid.uuid4().hex[:12]
    output = OUTPUT_DIR / f"{scan_id}.json"
    command = build_nikto_command(
        value, output, checks=checks, pause_seconds=pause_seconds,
        request_timeout=request_timeout, max_time=max_time,
    )
    command_result = await run_fixed_command(command, timeout=TIMEOUT_SECONDS)
    raw = output.read_text(errors="replace")[:200_000] if output.exists() else "{}"
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = {"raw": raw}
    record = {
        "scan_id": scan_id, "target": value, "returncode": command_result.returncode,
        "result": parsed, "stderr": command_result.stderr[:10_000],
    }
    results[scan_id] = record
    return record


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="nikto_observe",
            description="Run fixed read-only Nikto checks for files, configuration, disclosure, and software identification.",
            inputSchema={"type": "object", "properties": {
                "target": {"type": "string", "description": "HTTP(S) origin URL on an approved port"},
                "checks": {"type": "array", "items": {"type": "string", "enum": list(CHECK_TYPES)},
                           "minItems": 1, "maxItems": 4, "uniqueItems": True,
                           "description": "Subset of reviewed information-gathering test categories"},
                "pause_seconds": {"type": "integer", "minimum": 0, "maximum": 3, "default": 0},
                "request_timeout": {"type": "integer", "minimum": 1, "maximum": 10, "default": 10},
                "max_time": {"type": "integer", "minimum": 30, "maximum": 300, "default": 300},
            }, "required": ["target"], "additionalProperties": False},
        ),
        Tool(
            name="nikto_get_result",
            description="Retrieve a stored Nikto observation result.",
            inputSchema={"type": "object", "properties": {"scan_id": {"type": "string"}}, "required": ["scan_id"], "additionalProperties": False},
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        if name == "nikto_observe":
            payload = await observe(
                arguments.get("target"), checks=arguments.get("checks"),
                pause_seconds=arguments.get("pause_seconds", 0),
                request_timeout=arguments.get("request_timeout", 10),
                max_time=arguments.get("max_time", 300),
            )
        elif name == "nikto_get_result":
            payload = results.get(arguments.get("scan_id"), {"error": "result not found"})
        else:
            payload = {"error": "tool is not permitted"}
        return [TextContent(type="text", text=json.dumps(payload, indent=2))]
    except (TypeError, ValueError) as error:
        return [TextContent(type="text", text=json.dumps({"error": str(error)}))]


async def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    async with stdio_server() as streams:
        await app.run(streams[0], streams[1], app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
