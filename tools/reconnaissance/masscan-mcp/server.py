#!/usr/bin/env python3
"""
Masscan MCP Server

A Model Context Protocol server that provides fast port scanning
using masscan (the fastest Internet port scanner).

Tools:
    - masscan_scan: Fast port scan on target(s)
    - masscan_top_ports: Scan common ports
    - get_scan_results: Retrieve previous scan results
    - list_active_scans: Show running scans
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Resource, TextContent, Tool
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("masscan-mcp")


class Settings(BaseSettings):
    output_dir: str = Field(default="/app/output", alias="MASSCAN_OUTPUT_DIR")
    default_timeout: int = Field(default=600, alias="MASSCAN_TIMEOUT")
    max_concurrent_scans: int = Field(default=1, alias="MASSCAN_MAX_CONCURRENT")
    default_rate: int = Field(default=1000, alias="MASSCAN_RATE")

    class Config:
        env_prefix = "MASSCAN_"


settings = Settings()


class PortResult(BaseModel):
    ip: str
    port: int
    proto: str
    status: str
    reason: str | None = None
    ttl: int | None = None


class ScanResult(BaseModel):
    scan_id: str
    targets: str
    ports: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str = "running"
    results: list[PortResult] = []
    stats: dict[str, Any] = {}
    error: str | None = None
    raw_output: str | None = None


scan_results: dict[str, ScanResult] = {}
active_scans: set[str] = set()

TOP_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"


def parse_masscan_json(output: str) -> list[PortResult]:
    results = []
    try:
        data = json.loads(output)
        for entry in data:
            ip = entry.get("ip", "")
            for port_info in entry.get("ports", []):
                results.append(PortResult(
                    ip=ip,
                    port=port_info.get("port", 0),
                    proto=port_info.get("proto", "tcp"),
                    status=port_info.get("status", "open"),
                    reason=port_info.get("reason"),
                    ttl=port_info.get("ttl"),
                ))
    except json.JSONDecodeError:
        pass
    return results


async def run_masscan(
    targets: str,
    ports: str,
    rate: int | None = None,
    timeout: int | None = None,
) -> ScanResult:
    scan_id = str(uuid.uuid4())[:8]
    output_file = Path(settings.output_dir) / f"masscan_{scan_id}.json"

    result = ScanResult(
        scan_id=scan_id,
        targets=targets,
        ports=ports,
        started_at=datetime.now(),
    )
    scan_results[scan_id] = result
    active_scans.add(scan_id)

    cmd = [
        "masscan",
        targets,
        "-p", ports,
        "--rate", str(rate or settings.default_rate),
        "-oJ", str(output_file),
    ]

    logger.info(f"Starting masscan {scan_id} for targets: {targets}")

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=float(timeout or settings.default_timeout),
        )

        result.completed_at = datetime.now()

        if output_file.exists():
            output_content = output_file.read_text()
            result.raw_output = output_content
            result.results = parse_masscan_json(output_content)

        port_counts = {}
        for r in result.results:
            port_counts[r.port] = port_counts.get(r.port, 0) + 1

        result.stats = {
            "total_open_ports": len(result.results),
            "unique_hosts": len(set(r.ip for r in result.results)),
            "ports_found": dict(sorted(port_counts.items())),
        }

        result.status = "completed"

    except asyncio.TimeoutError:
        result.status = "timeout"
        result.error = f"Scan timed out"
        result.completed_at = datetime.now()

    except Exception as e:
        result.status = "error"
        result.error = str(e)
        result.completed_at = datetime.now()

    finally:
        active_scans.discard(scan_id)
        scan_results[scan_id] = result

    return result


def format_scan_summary(result: ScanResult) -> dict[str, Any]:
    return {
        "scan_id": result.scan_id,
        "targets": result.targets,
        "ports": result.ports,
        "status": result.status,
        "stats": result.stats,
        "results": [{"ip": r.ip, "port": r.port, "proto": r.proto, "status": r.status} for r in result.results[:200]],
        "error": result.error,
    }


app = Server("masscan-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="masscan_scan",
            description="Fast port scan using masscan. Can scan millions of hosts per minute. "
            "Requires root/NET_RAW capability for raw packet transmission.",
            inputSchema={
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "string",
                        "description": "Target IP, range, or CIDR (e.g., 10.0.0.1, 10.0.0.0/24, 10.0.0.1-10.0.0.255)",
                    },
                    "ports": {
                        "type": "string",
                        "description": "Ports to scan (e.g., 80, 80,443, 1-1000, 0-65535)",
                    },
                    "rate": {
                        "type": "integer",
                        "description": "Packets per second (default 1000, max depends on network)",
                        "default": 1000,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds",
                        "default": 600,
                    },
                },
                "required": ["targets", "ports"],
            },
        ),
        Tool(
            name="masscan_top_ports",
            description="Scan the top 20 most common ports on target(s).",
            inputSchema={
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "string",
                        "description": "Target IP, range, or CIDR",
                    },
                    "rate": {
                        "type": "integer",
                        "description": "Packets per second",
                        "default": 1000,
                    },
                },
                "required": ["targets"],
            },
        ),
        Tool(
            name="get_scan_results",
            description="Retrieve results from a previous scan.",
            inputSchema={
                "type": "object",
                "properties": {"scan_id": {"type": "string"}},
                "required": ["scan_id"],
            },
        ),
        Tool(
            name="list_active_scans",
            description="List running scans.",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        if name == "masscan_scan":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [TextContent(type="text", text="Max concurrent scans reached.")]

            result = await run_masscan(
                targets=arguments["targets"],
                ports=arguments["ports"],
                rate=arguments.get("rate"),
                timeout=arguments.get("timeout"),
            )
            return [TextContent(type="text", text=json.dumps(format_scan_summary(result), indent=2))]

        elif name == "masscan_top_ports":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [TextContent(type="text", text="Max concurrent scans reached.")]

            result = await run_masscan(
                targets=arguments["targets"],
                ports=TOP_PORTS,
                rate=arguments.get("rate"),
            )
            return [TextContent(type="text", text=json.dumps(format_scan_summary(result), indent=2))]

        elif name == "get_scan_results":
            result = scan_results.get(arguments["scan_id"])
            if result:
                return [TextContent(type="text", text=json.dumps(format_scan_summary(result), indent=2))]
            return [TextContent(type="text", text="Scan not found")]

        elif name == "list_active_scans":
            active = [{"scan_id": s, "targets": scan_results[s].targets} for s in active_scans if s in scan_results]
            return [TextContent(type="text", text=json.dumps({"active_scans": active}, indent=2))]

        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]


@app.list_resources()
async def list_resources() -> list[Resource]:
    return [
        Resource(uri=f"masscan://results/{scan_id}", name=f"Masscan: {result.targets}", mimeType="application/json")
        for scan_id, result in scan_results.items() if result.status == "completed"
    ]


@app.read_resource()
async def read_resource(uri: str) -> str:
    if uri.startswith("masscan://results/"):
        scan_id = uri.replace("masscan://results/", "")
        result = scan_results.get(scan_id)
        if result:
            return json.dumps(format_scan_summary(result), indent=2)
    return json.dumps({"error": "Resource not found"})


async def main():
    logger.info("Starting Masscan MCP Server")
    Path(settings.output_dir).mkdir(parents=True, exist_ok=True)

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
