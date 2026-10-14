#!/usr/bin/env python3
"""
Waybackurls MCP Server

A Model Context Protocol server that fetches all URLs from the Wayback Machine
for a given domain using waybackurls by @tomnomnom.

Tools:
    - fetch_wayback_urls: Fetch URLs for a domain from the Wayback Machine
    - get_fetch_results: Retrieve results from a previous fetch
    - list_active_fetches: Show currently running fetches
"""

import asyncio
import json
import logging
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    TextContent,
    Tool,
)
from pydantic import BaseModel, Field, ConfigDict
from pydantic_settings import BaseSettings
from adapters.input_validation import bounded_int, host, strict_bool

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("waybackurls-mcp")


class Settings(BaseSettings):
    """Server configuration from environment variables."""

    model_config = ConfigDict(env_prefix="WAYBACKURLS_")

    output_dir: str = Field(default="/app/output", alias="WAYBACKURLS_OUTPUT_DIR")
    default_timeout: int = Field(default=300, alias="WAYBACKURLS_TIMEOUT")
    max_concurrent_fetches: int = Field(default=3, alias="WAYBACKURLS_MAX_CONCURRENT")


settings = Settings()


class FetchResult(BaseModel):
    """Model for fetch results."""

    fetch_id: str
    domain: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str = "running"
    urls: list[str] = []
    total_urls: int = 0
    stats: dict[str, Any] = {}
    error: str | None = None


# In-memory storage for fetch results
fetch_results: dict[str, FetchResult] = {}
active_fetches: set[str] = set()
FETCH_ID = re.compile(r"[0-9a-f]{8}\Z")


def validate_domain(domain: Any) -> str:
    """Only one plain domain or IP may be passed to waybackurls stdin."""
    return host(domain)


def select_urls(urls: list[str], *, unique_urls: bool, https_only: bool) -> list[str]:
    """Apply local, archive-result-only selection without making target requests."""
    selected = []
    seen = set()
    for record in urls:
        # waybackurls -dates prefixes a timestamp before the URL.
        url = record.split()[-1] if record.split() else ""
        if https_only and urlparse(url).scheme.lower() != "https":
            continue
        if unique_urls and record in seen:
            continue
        seen.add(record)
        selected.append(record)
        if len(selected) >= 10000:
            break
    return selected


def analyze_urls(urls: list[str]) -> dict[str, Any]:
    """Analyze fetched URLs and generate statistics."""
    stats = {
        "total": len(urls),
        "by_extension": {},
        "by_subdomain": {},
        "by_path_depth": {},
        "protocols": {"http": 0, "https": 0},
        "with_params": 0,
    }

    for url in urls:
        try:
            parsed = urlparse(url)
            
            # Protocol stats
            if parsed.scheme == "http":
                stats["protocols"]["http"] += 1
            elif parsed.scheme == "https":
                stats["protocols"]["https"] += 1
            
            # Subdomain stats
            domain = parsed.netloc
            stats["by_subdomain"][domain] = stats["by_subdomain"].get(domain, 0) + 1
            
            # Extension stats
            path = parsed.path
            if "." in path:
                ext = path.split(".")[-1].split("?")[0].split("#")[0].lower()
                if ext and len(ext) <= 5:
                    stats["by_extension"][ext] = stats["by_extension"].get(ext, 0) + 1
            
            # Path depth
            depth = len([p for p in path.split("/") if p])
            stats["by_path_depth"][depth] = stats["by_path_depth"].get(depth, 0) + 1
            
            # Parameters
            if parsed.query:
                stats["with_params"] += 1
                
        except Exception as e:
            logger.debug(f"Error analyzing URL {url}: {e}")
            continue

    # Sort and limit top entries
    stats["by_extension"] = dict(sorted(
        stats["by_extension"].items(), 
        key=lambda x: x[1], 
        reverse=True
    )[:20])
    
    stats["by_subdomain"] = dict(sorted(
        stats["by_subdomain"].items(), 
        key=lambda x: x[1], 
        reverse=True
    )[:20])
    
    stats["by_path_depth"] = dict(sorted(
        stats["by_path_depth"].items(), 
        key=lambda x: x[0]
    ))

    return stats


async def run_waybackurls(
    domain: str,
    get_subs: bool = False,
    no_subs: bool = False,
    dates: bool = False,
    timeout: int | None = None,
    unique_urls: bool = False,
    https_only: bool = False,
) -> FetchResult:
    """Execute waybackurls asynchronously."""
    domain = validate_domain(domain)
    get_subs = strict_bool(get_subs, "get_subs")
    no_subs = strict_bool(no_subs, "no_subs")
    dates = strict_bool(dates, "dates")
    unique_urls = strict_bool(unique_urls, "unique_urls")
    https_only = strict_bool(https_only, "https_only")
    if get_subs and no_subs:
        raise ValueError("get_subs and no_subs cannot both be true")
    effective_timeout = bounded_int(
        settings.default_timeout if timeout is None else timeout, "timeout", 5, 600
    )
    fetch_id = str(uuid.uuid4())[:8]
    output_file = Path(settings.output_dir) / f"wayback_{fetch_id}.txt"

    result = FetchResult(
        fetch_id=fetch_id,
        domain=domain,
        started_at=datetime.now(),
    )
    fetch_results[fetch_id] = result
    active_fetches.add(fetch_id)

    # Build waybackurls command
    # waybackurls accepts domains on stdin
    cmd = ["waybackurls"]
    
    if get_subs:
        cmd.append("-get-subs")
    if no_subs:
        cmd.append("-no-subs")
    if dates:
        cmd.append("-dates")

    logger.info(f"Starting waybackurls fetch {fetch_id} for domain: {domain}")
    logger.debug("Command: waybackurls with validated domain on stdin")

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Send domain to stdin
        stdout, stderr = await asyncio.wait_for(
            process.communicate(input=domain.encode()),
            timeout=float(effective_timeout),
        )

        result.completed_at = datetime.now()

        # Parse output
        stdout_text = stdout.decode()
        if stdout_text.strip():
            urls = select_urls(
                [line.strip() for line in stdout_text.splitlines() if line.strip()],
                unique_urls=unique_urls, https_only=https_only,
            )
            result.urls = urls
            result.total_urls = len(urls)
            
            # Save to file
            output_file.write_text("\n".join(urls))
            
            # Generate statistics
            result.stats = analyze_urls(urls)

        stderr_text = stderr.decode()
        if stderr_text:
            logger.debug(f"Waybackurls stderr: {stderr_text}")

        if process.returncode == 0:
            result.status = "completed"
            logger.info(f"Fetch {fetch_id} completed: {result.total_urls} URLs found")
        else:
            if result.total_urls > 0:
                result.status = "completed"
            else:
                result.status = "failed"
                result.error = stderr_text or "No output from waybackurls"
                logger.error(f"Fetch {fetch_id} failed: {result.error}")

    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        result.status = "timeout"
        result.error = f"Fetch timed out after {effective_timeout} seconds"
        result.completed_at = datetime.now()
        logger.error(f"Fetch {fetch_id} timed out")

    except Exception as e:
        result.status = "error"
        result.error = str(e)
        result.completed_at = datetime.now()
        logger.exception(f"Fetch {fetch_id} error: {e}")

    finally:
        active_fetches.discard(fetch_id)
        fetch_results[fetch_id] = result

    return result


def format_fetch_summary(result: FetchResult, include_urls: bool = False, limit: int = 100) -> dict[str, Any]:
    """Format fetch result for response."""
    include_urls = strict_bool(include_urls, "include_urls")
    limit = bounded_int(limit, "limit", 1, 1000)
    summary = {
        "fetch_id": result.fetch_id,
        "domain": result.domain,
        "status": result.status,
        "total_urls": result.total_urls,
        "started_at": result.started_at.isoformat(),
        "completed_at": result.completed_at.isoformat() if result.completed_at else None,
        "stats": result.stats,
        "error": result.error,
    }
    
    if include_urls:
        summary["urls"] = result.urls[:limit]
        if len(result.urls) > limit:
            summary["urls_truncated"] = f"Showing {limit} of {len(result.urls)} URLs"
    
    return summary


# Create MCP server
app = Server("waybackurls-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="fetch_wayback_urls",
            description="Fetch all URLs from the Wayback Machine for a given domain. "
            "Returns historical URLs that were archived for the domain.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Plain domain or IP (e.g., example.com); no URL or line breaks",
                    },
                    "get_subs": {
                        "type": "boolean",
                        "description": "Also fetch subdomains (e.g., *.example.com)",
                        "default": False,
                    },
                    "no_subs": {
                        "type": "boolean",
                        "description": "Don't include subdomains, only the exact domain",
                        "default": False,
                    },
                    "dates": {
                        "type": "boolean",
                        "description": "Show timestamps for when URLs were archived",
                        "default": False,
                    },
                    "unique_urls": {
                        "type": "boolean",
                        "description": "Keep one copy of each returned archive record",
                        "default": False,
                    },
                    "https_only": {
                        "type": "boolean",
                        "description": "Keep only archived HTTPS URLs",
                        "default": False,
                    },
                    "include_urls": {
                        "type": "boolean",
                        "description": "Include the actual URLs in the response (default: true)",
                        "default": True,
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of URLs to return in response (default: 100)",
                        "default": 100,
                        "minimum": 1,
                        "maximum": 1000,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds",
                        "default": 300,
                        "minimum": 5,
                        "maximum": 600,
                    },
                },
                "required": ["domain"],
                "additionalProperties": False,
            },
        ),
        Tool(
            name="get_fetch_results",
            description="Retrieve results from a previous waybackurls fetch by fetch ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "fetch_id": {
                        "type": "string",
                        "description": "Fetch ID returned from a previous fetch",
                    },
                    "include_urls": {
                        "type": "boolean",
                        "description": "Include the actual URLs in the response",
                        "default": True,
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of URLs to return",
                        "default": 100,
                        "minimum": 1,
                        "maximum": 1000,
                    },
                },
                "required": ["fetch_id"],
                "additionalProperties": False,
            },
        ),
        Tool(
            name="list_active_fetches",
            description="List currently running waybackurls fetches.",
            inputSchema={
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    try:
        if name == "fetch_wayback_urls":
            if not isinstance(arguments, dict) or set(arguments) - {
                "domain", "get_subs", "no_subs", "dates", "unique_urls", "https_only",
                "include_urls", "limit", "timeout",
            }:
                raise ValueError("unsupported fetch option")
            domain = validate_domain(arguments["domain"])
            include_urls = strict_bool(arguments.get("include_urls", True), "include_urls")
            limit = bounded_int(arguments.get("limit", 100), "limit", 1, 1000)
            get_subs = strict_bool(arguments.get("get_subs", False), "get_subs")
            no_subs = strict_bool(arguments.get("no_subs", False), "no_subs")
            dates = strict_bool(arguments.get("dates", False), "dates")
            unique_urls = strict_bool(arguments.get("unique_urls", False), "unique_urls")
            https_only = strict_bool(arguments.get("https_only", False), "https_only")
            if get_subs and no_subs:
                raise ValueError("get_subs and no_subs cannot both be true")
            timeout = bounded_int(
                arguments.get("timeout", settings.default_timeout), "timeout", 5, 600
            )
            if len(active_fetches) >= settings.max_concurrent_fetches:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent fetches ({settings.max_concurrent_fetches}) reached. "
                        f"Please wait for active fetches to complete.",
                    )
                ]

            result = await run_waybackurls(
                domain=domain,
                get_subs=get_subs,
                no_subs=no_subs,
                dates=dates,
                timeout=timeout,
                unique_urls=unique_urls,
                https_only=https_only,
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        format_fetch_summary(
                            result,
                            include_urls=include_urls,
                            limit=limit,
                        ),
                        indent=2,
                    ),
                )
            ]

        elif name == "get_fetch_results":
            if not isinstance(arguments, dict) or set(arguments) - {"fetch_id", "include_urls", "limit"}:
                raise ValueError("unsupported result option")
            fetch_id = arguments["fetch_id"]
            if not isinstance(fetch_id, str) or not FETCH_ID.fullmatch(fetch_id):
                raise ValueError("fetch_id must be an eight-character hex ID")
            include_urls = strict_bool(arguments.get("include_urls", True), "include_urls")
            limit = bounded_int(arguments.get("limit", 100), "limit", 1, 1000)
            result = fetch_results.get(fetch_id)

            if result:
                return [
                    TextContent(
                        type="text",
                        text=json.dumps(
                            format_fetch_summary(
                                result,
                                include_urls=include_urls,
                                limit=limit,
                            ),
                            indent=2,
                        ),
                    )
                ]
            else:
                return [
                    TextContent(type="text", text=f"Fetch '{fetch_id}' not found")
                ]

        elif name == "list_active_fetches":
            if arguments != {}:
                raise ValueError("list_active_fetches accepts no options")
            active = [
                {
                    "fetch_id": fetch_id,
                    "domain": fetch_results[fetch_id].domain,
                    "started_at": fetch_results[fetch_id].started_at.isoformat(),
                }
                for fetch_id in active_fetches
                if fetch_id in fetch_results
            ]

            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "active_fetches": active,
                            "count": len(active),
                            "max_concurrent": settings.max_concurrent_fetches,
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

    for fetch_id, result in fetch_results.items():
        if result.status == "completed":
            resources.append(
                Resource(
                    uri=f"waybackurls://results/{fetch_id}",
                    name=f"Wayback URLs: {result.domain} ({result.total_urls} URLs)",
                    description=f"Fetched at {result.completed_at}",
                    mimeType="text/plain",
                )
            )

    return resources


@app.read_resource()
async def read_resource(uri: str) -> str:
    """Read a resource."""
    if uri.startswith("waybackurls://results/"):
        fetch_id = uri.replace("waybackurls://results/", "")
        result = fetch_results.get(fetch_id)
        if result:
            return "\n".join(result.urls)

    return json.dumps({"error": "Resource not found"})


async def main():
    """Run the MCP server."""
    logger.info("Starting Waybackurls MCP Server")
    logger.info(f"Output directory: {settings.output_dir}")

    # Ensure directories exist
    Path(settings.output_dir).mkdir(parents=True, exist_ok=True)

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
