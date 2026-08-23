#!/usr/bin/env python3
"""
Nmap MCP Server

A Model Context Protocol server that provides network reconnaissance
capabilities using Nmap.

Tools:
    - port_scan: Scan ports on a target
    - service_scan: Detect service versions
    - os_detection: Fingerprint operating system
    - script_scan: Run NSE scripts
    - quick_scan: Fast scan of common ports
    - get_scan_results: Retrieve previous scan results
"""

import asyncio
import json
import logging
import os
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    TextContent,
    Tool,
)
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("nmap-mcp")


class Settings(BaseSettings):
    """Server configuration from environment variables."""

    output_dir: str = Field(default="/app/output", alias="NMAP_OUTPUT_DIR")
    default_timeout: int = Field(default=300, alias="NMAP_TIMEOUT")
    max_concurrent_scans: int = Field(default=3, alias="NMAP_MAX_CONCURRENT")

    class Config:
        env_prefix = "NMAP_"


settings = Settings()


class ScanResult(BaseModel):
    """Model for scan results."""

    scan_id: str
    target: str
    scan_type: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str = "running"
    hosts: list[dict[str, Any]] = []
    stats: dict[str, Any] = {}
    error: str | None = None
    raw_output: str | None = None


# In-memory storage for scan results
scan_results: dict[str, ScanResult] = {}
active_scans: set[str] = set()

# Reviewed information-gathering scripts only.  Do not replace this with a
# category (such as "default" or "vuln"), because categories can include
# state-changing scripts as Nmap evolves.
SAFE_NSE_SCRIPTS = frozenset({
    "banner", "dns-brute", "dns-recursion", "http-headers", "http-methods",
    "http-robots.txt", "http-server-header", "http-title", "ssh-hostkey",
    "ssl-cert", "ssl-enum-ciphers", "ssl-known-key", "ssl-date",
})


def parse_nmap_xml(xml_path: Path) -> dict[str, Any]:
    """Parse nmap XML output into structured data."""
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        hosts = []
        for host in root.findall("host"):
            host_data = {
                "status": host.find("status").get("state") if host.find("status") is not None else "unknown",
                "addresses": [],
                "hostnames": [],
                "ports": [],
                "os": None,
            }

            # Parse addresses
            for addr in host.findall("address"):
                host_data["addresses"].append({
                    "addr": addr.get("addr"),
                    "addrtype": addr.get("addrtype"),
                })

            # Parse hostnames
            hostnames = host.find("hostnames")
            if hostnames is not None:
                for hostname in hostnames.findall("hostname"):
                    host_data["hostnames"].append({
                        "name": hostname.get("name"),
                        "type": hostname.get("type"),
                    })

            # Parse ports
            ports = host.find("ports")
            if ports is not None:
                for port in ports.findall("port"):
                    port_data = {
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "state": None,
                        "service": None,
                    }

                    state = port.find("state")
                    if state is not None:
                        port_data["state"] = {
                            "state": state.get("state"),
                            "reason": state.get("reason"),
                        }

                    service = port.find("service")
                    if service is not None:
                        port_data["service"] = {
                            "name": service.get("name"),
                            "product": service.get("product"),
                            "version": service.get("version"),
                            "extrainfo": service.get("extrainfo"),
                        }

                    # Parse scripts
                    scripts = []
                    for script in port.findall("script"):
                        scripts.append({
                            "id": script.get("id"),
                            "output": script.get("output"),
                        })
                    if scripts:
                        port_data["scripts"] = scripts

                    host_data["ports"].append(port_data)

            # Parse OS detection
            os_elem = host.find("os")
            if os_elem is not None:
                osmatch = os_elem.find("osmatch")
                if osmatch is not None:
                    host_data["os"] = {
                        "name": osmatch.get("name"),
                        "accuracy": osmatch.get("accuracy"),
                    }

            hosts.append(host_data)

        # Parse run stats
        runstats = root.find("runstats")
        stats = {}
        if runstats is not None:
            finished = runstats.find("finished")
            if finished is not None:
                stats["elapsed"] = finished.get("elapsed")
                stats["exit"] = finished.get("exit")

            hosts_stat = runstats.find("hosts")
            if hosts_stat is not None:
                stats["hosts_up"] = hosts_stat.get("up")
                stats["hosts_down"] = hosts_stat.get("down")
                stats["hosts_total"] = hosts_stat.get("total")

        return {"hosts": hosts, "stats": stats}

    except Exception as e:
        logger.error(f"Error parsing XML: {e}")
        return {"hosts": [], "stats": {}, "error": str(e)}


async def run_nmap_scan(
    target: str,
    scan_type: str = "port",
    ports: str | None = None,
    scripts: list[str] | None = None,
    timing: int = 3,
    timeout: int | None = None,
) -> ScanResult:
    """Execute an nmap scan asynchronously."""
    scan_id = str(uuid.uuid4())[:8]
    xml_output = Path(settings.output_dir) / f"scan_{scan_id}.xml"
    txt_output = Path(settings.output_dir) / f"scan_{scan_id}.txt"

    result = ScanResult(
        scan_id=scan_id,
        target=target,
        scan_type=scan_type,
        started_at=datetime.now(),
    )
    scan_results[scan_id] = result
    active_scans.add(scan_id)

    # Build nmap command
    cmd = ["nmap", "-oX", str(xml_output), "-oN", str(txt_output)]

    # Add timing template
    cmd.append(f"-T{timing}")

    # Add scan type specific options
    if scan_type == "port":
        cmd.append("-sS")  # SYN scan (requires root/cap)
    elif scan_type == "service":
        cmd.extend(["-sV", "--version-intensity", "5"])
    elif scan_type == "os":
        cmd.append("-O")
    elif scan_type == "script":
        if scripts:
            cmd.extend(["--script", ",".join(scripts)])
    elif scan_type == "quick":
        cmd.extend(["-F", "-sV"])  # Fast scan with version detection

    # Add port specification
    if ports:
        cmd.extend(["-p", ports])

    # Add target
    cmd.extend(["--", target])

    logger.info(f"Starting {scan_type} scan {scan_id} for target: {target}")
    logger.debug(f"Command: {' '.join(cmd)}")

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

        if process.returncode == 0:
            result.status = "completed"

            # Parse XML results
            if xml_output.exists():
                parsed = parse_nmap_xml(xml_output)
                result.hosts = parsed.get("hosts", [])
                result.stats = parsed.get("stats", {})

            # Store raw output
            if txt_output.exists():
                result.raw_output = txt_output.read_text()

            logger.info(f"Scan {scan_id} completed: {len(result.hosts)} hosts found")
        else:
            result.status = "failed"
            result.error = stderr.decode() if stderr else "Unknown error"
            logger.error(f"Scan {scan_id} failed: {result.error}")

    except asyncio.TimeoutError:
        result.status = "timeout"
        result.error = f"Scan timed out after {timeout or settings.default_timeout} seconds"
        result.completed_at = datetime.now()
        logger.error(f"Scan {scan_id} timed out")

    except Exception as e:
        result.status = "error"
        result.error = str(e)
        result.completed_at = datetime.now()
        logger.exception(f"Scan {scan_id} error: {e}")

    finally:
        active_scans.discard(scan_id)
        scan_results[scan_id] = result

    return result


def format_scan_summary(result: ScanResult) -> dict[str, Any]:
    """Format scan result for response."""
    summary = {
        "scan_id": result.scan_id,
        "target": result.target,
        "scan_type": result.scan_type,
        "status": result.status,
        "stats": result.stats,
        "error": result.error,
    }

    # Add host summaries
    host_summaries = []
    for host in result.hosts:
        host_summary = {
            "addresses": host.get("addresses", []),
            "status": host.get("status"),
            "os": host.get("os"),
            "open_ports": [
                {
                    "port": p.get("port"),
                    "protocol": p.get("protocol"),
                    "service": p.get("service", {}).get("name"),
                    "version": p.get("service", {}).get("version"),
                }
                for p in host.get("ports", [])
                if p.get("state", {}).get("state") == "open"
            ],
        }
        host_summaries.append(host_summary)

    summary["hosts"] = host_summaries
    return summary


# Create MCP server
app = Server("nmap-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="port_scan",
            description="Scan ports on a target host or network. "
            "Discovers open ports using SYN scan.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP, hostname, or CIDR range (e.g., 192.168.1.1, example.com, 10.0.0.0/24)",
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port specification (e.g., '22,80,443', '1-1000', 'U:53,T:21-25,80')",
                    },
                    "timing": {
                        "type": "integer",
                        "description": "Timing template 0-5 (0=paranoid, 3=normal, 5=insane)",
                        "default": 3,
                        "minimum": 0,
                        "maximum": 5,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Scan timeout in seconds",
                        "default": 300,
                    },
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="service_scan",
            description="Detect service versions on target ports. "
            "Identifies software and versions running on open ports.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname",
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port specification (default: common ports)",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Scan timeout in seconds",
                        "default": 300,
                    },
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="os_detection",
            description="Fingerprint the operating system of the target. "
            "Requires at least one open and one closed port.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Scan timeout in seconds",
                        "default": 300,
                    },
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="script_scan",
            description="Run NSE (Nmap Scripting Engine) scripts against target. "
            "Scripts can detect vulnerabilities, gather information, and more.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname",
                    },
                    "scripts": {
                        "type": "array",
                        "items": {"type": "string", "enum": sorted(SAFE_NSE_SCRIPTS)},
                        "description": "Reviewed read-only NSE scripts.",
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port specification",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Scan timeout in seconds",
                        "default": 300,
                    },
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="quick_scan",
            description="Fast scan of the 100 most common ports with service detection.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname",
                    },
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="get_scan_results",
            description="Retrieve results from a previous scan by scan ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Scan ID returned from a previous scan",
                    },
                    "include_raw": {
                        "type": "boolean",
                        "description": "Include raw nmap output",
                        "default": False,
                    },
                },
                "required": ["scan_id"],
            },
        ),
        Tool(
            name="list_active_scans",
            description="List currently running scans.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    try:
        if name == "port_scan":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            result = await run_nmap_scan(
                target=arguments["target"],
                scan_type="port",
                ports=arguments.get("ports"),
                timing=arguments.get("timing", 3),
                timeout=arguments.get("timeout"),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "service_scan":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            result = await run_nmap_scan(
                target=arguments["target"],
                scan_type="service",
                ports=arguments.get("ports"),
                timeout=arguments.get("timeout"),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "os_detection":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            result = await run_nmap_scan(
                target=arguments["target"],
                scan_type="os",
                timeout=arguments.get("timeout"),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "script_scan":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            scripts = arguments.get("scripts", [])
            if not scripts or not set(scripts).issubset(SAFE_NSE_SCRIPTS):
                return [TextContent(type="text", text="Choose one or more reviewed read-only NSE scripts.")]

            result = await run_nmap_scan(
                target=arguments["target"],
                scan_type="script",
                scripts=scripts,
                ports=arguments.get("ports"),
                timeout=arguments.get("timeout"),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "quick_scan":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            result = await run_nmap_scan(
                target=arguments["target"],
                scan_type="quick",
                timing=4,
                timeout=120,
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "get_scan_results":
            scan_id = arguments["scan_id"]
            result = scan_results.get(scan_id)

            if result:
                output = format_scan_summary(result)
                if arguments.get("include_raw") and result.raw_output:
                    output["raw_output"] = result.raw_output
                return [
                    TextContent(
                        type="text",
                        text=json.dumps(output, indent=2),
                    )
                ]
            else:
                return [
                    TextContent(type="text", text=f"Scan '{scan_id}' not found")
                ]

        elif name == "list_active_scans":
            active = [
                {
                    "scan_id": scan_id,
                    "target": scan_results[scan_id].target,
                    "scan_type": scan_results[scan_id].scan_type,
                    "started_at": scan_results[scan_id].started_at.isoformat(),
                }
                for scan_id in active_scans
                if scan_id in scan_results
            ]

            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "active_scans": active,
                            "count": len(active),
                            "max_concurrent": settings.max_concurrent_scans,
                        },
                        indent=2,
                    ),
                )
            ]

        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:
        logger.exception(f"Error executing tool {name}: {e}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]


@app.list_resources()
async def list_resources() -> list[Resource]:
    """List available resources."""
    resources = []

    # Add resources for completed scans
    for scan_id, result in scan_results.items():
        if result.status == "completed":
            resources.append(
                Resource(
                    uri=f"nmap://results/{scan_id}",
                    name=f"Scan Results: {result.target}",
                    description=f"{result.scan_type} scan completed at {result.completed_at}",
                    mimeType="application/json",
                )
            )

    return resources


@app.read_resource()
async def read_resource(uri: str) -> str:
    """Read a resource."""
    if uri.startswith("nmap://results/"):
        scan_id = uri.replace("nmap://results/", "")
        result = scan_results.get(scan_id)
        if result:
            return json.dumps(format_scan_summary(result), indent=2)

    return json.dumps({"error": "Resource not found"})


async def main():
    """Run the MCP server."""
    logger.info("Starting Nmap MCP Server")
    logger.info(f"Output directory: {settings.output_dir}")

    # Ensure output directory exists
    Path(settings.output_dir).mkdir(parents=True, exist_ok=True)

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
