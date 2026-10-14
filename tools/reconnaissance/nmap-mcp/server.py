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
import ipaddress
import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as ET
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    TextContent,
    Tool,
)
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
from adapters.input_validation import bounded_int, host, strict_bool, tcp_ports

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
    "banner", "dns-recursion", "http-headers", "http-methods",
    "http-robots.txt", "http-server-header", "http-title", "ssh-hostkey",
    "ssl-cert", "ssl-enum-ciphers", "ssl-known-key", "ssl-date",
})


def build_nmap_command(
    target: str,
    scan_type: str,
    xml_output: Path,
    txt_output: Path,
    *,
    ports: str | None = None,
    scripts: list[str] | None = None,
    timing: int = 3,
    max_rate: int = 25,
    max_retries: int = 1,
    show_reasons: bool = False,
    open_only: bool = False,
    version_intensity: int = 3,
) -> list[str]:
    """Build an explicit argv after validating every agent-controlled value."""
    target = host(target, allow_cidr=True)
    if "/" in target:
        network = ipaddress.ip_network(target)
        if network.num_addresses > 256:
            raise ValueError("target CIDR may contain at most 256 addresses")
    if scan_type not in {"port", "service", "os", "script", "quick"}:
        raise ValueError("unsupported scan type")
    timing = bounded_int(timing, "timing", 0, 3)
    max_rate = bounded_int(max_rate, "max_rate", 1, 50)
    max_retries = bounded_int(max_retries, "max_retries", 0, 2)
    show_reasons = strict_bool(show_reasons, "show_reasons")
    open_only = strict_bool(open_only, "open_only")
    version_intensity = bounded_int(version_intensity, "version_intensity", 0, 5)
    if ports is not None:
        if scan_type == "quick":
            raise ValueError("quick_scan uses its fixed common-port selection")
        ports = tcp_ports(ports, max_ports=1024)
    if scripts is not None:
        if scan_type != "script" or not isinstance(scripts, list) or not 1 <= len(scripts) <= 4 or any(
            not isinstance(script, str) or script not in SAFE_NSE_SCRIPTS for script in scripts
        ):
            raise ValueError("choose 1 to 4 reviewed read-only NSE scripts")
    if scan_type == "script" and not scripts:
        raise ValueError("choose 1 to 4 reviewed read-only NSE scripts")

    cmd = ["nmap", "-oX", str(xml_output), "-oN", str(txt_output), f"-T{timing}",
           "--max-rate", str(max_rate), "--max-retries", str(max_retries)]
    if scan_type == "port":
        cmd.append("-sS")
    elif scan_type == "service":
        cmd.extend(["-sV", "--version-intensity", str(version_intensity)])
    elif scan_type == "os":
        cmd.append("-O")
    elif scan_type == "script":
        cmd.extend(["--script", ",".join(scripts)])
    elif scan_type == "quick":
        cmd.extend(["-F", "-sV", "--version-intensity", str(version_intensity)])
    if ports is not None:
        cmd.extend(["-p", ports])
    if show_reasons:
        cmd.append("--reason")
    if open_only:
        cmd.append("--open")
    cmd.extend(["--", target])
    return cmd


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
    max_rate: int = 25,
    max_retries: int = 1,
    show_reasons: bool = False,
    open_only: bool = False,
    version_intensity: int = 3,
) -> ScanResult:
    """Execute an nmap scan asynchronously."""
    effective_timeout = bounded_int(
        settings.default_timeout if timeout is None else timeout, "timeout", 10, 600
    )
    scan_id = str(uuid.uuid4())[:8]
    xml_output = Path(settings.output_dir) / f"scan_{scan_id}.xml"
    txt_output = Path(settings.output_dir) / f"scan_{scan_id}.txt"
    cmd = build_nmap_command(
        target, scan_type, xml_output, txt_output, ports=ports, scripts=scripts,
        timing=timing, max_rate=max_rate, max_retries=max_retries,
        show_reasons=show_reasons, open_only=open_only,
        version_intensity=version_intensity,
    )

    result = ScanResult(
        scan_id=scan_id,
        target=target,
        scan_type=scan_type,
        started_at=datetime.now(),
    )
    scan_results[scan_id] = result
    active_scans.add(scan_id)

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
            timeout=float(effective_timeout),
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
        process.kill()
        await process.wait()
        result.status = "timeout"
        result.error = f"Scan timed out after {effective_timeout} seconds"
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
    target = {"type": "string", "description": "Hostname, IP, or CIDR of at most 256 addresses"}
    ports = {"type": "string", "description": "TCP port list or ranges covering at most 1024 ports"}
    common = {
        "timing": {"type": "integer", "minimum": 0, "maximum": 3, "default": 3},
        "timeout": {"type": "integer", "minimum": 10, "maximum": 600, "default": 300},
        "max_rate": {"type": "integer", "minimum": 1, "maximum": 50, "default": 25,
                     "description": "Maximum packets per second"},
        "max_retries": {"type": "integer", "minimum": 0, "maximum": 2, "default": 1},
        "show_reasons": {"type": "boolean", "default": False,
                         "description": "Include Nmap's reason for each state"},
        "open_only": {"type": "boolean", "default": False,
                      "description": "Report only open ports"},
    }
    version = {"version_intensity": {"type": "integer", "minimum": 0, "maximum": 5,
                                      "default": 3,
                                      "description": "Bounded service probe intensity"}}
    return [
        Tool(
            name="port_scan",
            description="Bounded TCP SYN port discovery.",
            inputSchema={"type": "object", "properties": {"target": target, "ports": ports, **common},
                         "required": ["target"], "additionalProperties": False},
        ),
        Tool(
            name="service_scan",
            description="Bounded service version detection.",
            inputSchema={"type": "object", "properties": {"target": target, "ports": ports, **common, **version},
                         "required": ["target"], "additionalProperties": False},
        ),
        Tool(
            name="os_detection",
            description="Bounded operating-system fingerprinting.",
            inputSchema={"type": "object", "properties": {"target": target, "ports": ports, **common},
                         "required": ["target"], "additionalProperties": False},
        ),
        Tool(
            name="script_scan",
            description="Run up to four reviewed information-gathering NSE scripts.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": target,
                    "scripts": {
                        "type": "array",
                        "items": {"type": "string", "enum": sorted(SAFE_NSE_SCRIPTS)},
                        "minItems": 1,
                        "maxItems": 4,
                        "description": "Reviewed read-only NSE scripts",
                    },
                    "ports": ports,
                    **common,
                },
                "required": ["target", "scripts"],
                "additionalProperties": False,
            },
        ),
        Tool(
            name="quick_scan",
            description="Fast scan of the 100 most common ports with service detection.",
            inputSchema={"type": "object", "properties": {"target": target, **common,
                         "timeout": {"type": "integer", "minimum": 10, "maximum": 600, "default": 120},
                         **version},
                         "required": ["target"], "additionalProperties": False},
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
        scan_names = {"port_scan", "service_scan", "os_detection", "script_scan", "quick_scan"}
        common_keys = {"target", "timing", "timeout", "max_rate", "max_retries",
                       "show_reasons", "open_only"}
        allowed_keys = {
            "port_scan": common_keys | {"ports"},
            "service_scan": common_keys | {"ports", "version_intensity"},
            "os_detection": common_keys | {"ports"},
            "script_scan": common_keys | {"ports", "scripts"},
            "quick_scan": common_keys | {"version_intensity"},
        }
        if name in scan_names:
            if not isinstance(arguments, dict) or set(arguments) - allowed_keys[name]:
                raise ValueError("unsupported scan option")
            options = {key: arguments[key] for key in common_keys - {"target"} if key in arguments}
            for key in allowed_keys[name] - common_keys:
                if key in arguments:
                    options[key] = arguments[key]
        else:
            options = {}
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
                **options,
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
                **options,
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
                **options,
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

            result = await run_nmap_scan(
                target=arguments["target"],
                scan_type="script",
                **options,
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
                **({"timeout": 120} | options),
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
