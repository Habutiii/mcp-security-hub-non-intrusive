#!/usr/bin/env python3
"""Restricted, read-only Nikto MCP for the single-image AGW."""

import asyncio
import json
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from adapters.runtime import run_fixed_command
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

app = Server("nikto-observer-mcp")
OUTPUT_DIR = Path("/var/lib/security-hub/nikto")
TIMEOUT_SECONDS = 300
# Informational file, configuration, disclosure, and software-identification
# checks only. DoS, RCE, injection, upload, auth-bypass, and user-selected
# plugin/tuning modes are deliberately unavailable.
SAFE_TUNING = "123b"
results: dict[str, dict[str, Any]] = {}


def target(value: Any) -> tuple[str, int, bool]:
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("target must be an HTTP or HTTPS URL")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("target must be an HTTP or HTTPS URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("target cannot include credentials, query, or fragment")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in {80, 443, 8080, 8443}:
        raise ValueError("target port must be one of 80, 443, 8080, or 8443")
    return parsed.hostname, port, parsed.scheme == "https"


async def observe(value: str) -> dict[str, Any]:
    host, port, use_tls = target(value)
    scan_id = uuid.uuid4().hex[:12]
    output = OUTPUT_DIR / f"{scan_id}.json"
    command = [
        "nikto", "-host", host, "-port", str(port), "-Tuning", SAFE_TUNING,
        "-Format", "json", "-output", str(output), "-nointeractive",
    ]
    if use_tls:
        command.append("-ssl")
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
            inputSchema={"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"], "additionalProperties": False},
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
            payload = await observe(arguments.get("target"))
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
