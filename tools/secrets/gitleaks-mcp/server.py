#!/usr/bin/env python3
"""
Gitleaks MCP Server

A Model Context Protocol server that provides secrets detection
capabilities using Gitleaks.

Tools:
    - gitleaks_scan_repo: Scan a git repository for secrets
    - gitleaks_scan_dir: Scan a directory for secrets
    - gitleaks_detect: Quick scan provided content for secrets
    - get_scan_results: Retrieve previous scan results
    - list_active_scans: Show running scans
"""

import asyncio
import json
import logging
import os
import tempfile
import uuid
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
from adapters.input_validation import bounded_int, strict_bool

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("gitleaks-mcp")


class Settings(BaseSettings):
    """Server configuration from environment variables."""

    output_dir: str = Field(default="/app/output", alias="GITLEAKS_OUTPUT_DIR")
    default_timeout: int = Field(default=300, alias="GITLEAKS_TIMEOUT")
    max_concurrent_scans: int = Field(default=2, alias="GITLEAKS_MAX_CONCURRENT")

    class Config:
        env_prefix = "GITLEAKS_"


settings = Settings()
ALLOWED_INPUT_ROOTS = (Path("/opt/security-hub"), Path("/var/lib/security-hub/gitleaks/input"))
MAX_CONTENT = 64_000


def approved_directory(value: Any, *, repository: bool = False) -> str:
    """Resolve an existing directory within a deployment-owned input root."""
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise ValueError("path must be an absolute directory within an approved input root")
    candidate = Path(value)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("path must be absolute and cannot contain traversal")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("scan path must be a directory")
    if not any(resolved == root or resolved.is_relative_to(root) for root in ALLOWED_INPUT_ROOTS):
        raise ValueError("scan path is outside approved input roots")
    if repository and not (resolved / ".git").is_dir():
        raise ValueError("scan path is not a git repository")
    return str(resolved)


def scan_options(arguments: dict[str, Any], allowed: set[str], default_timeout: int) -> tuple[int, int]:
    if not isinstance(arguments, dict) or arguments.keys() - allowed:
        raise ValueError("unsupported tool option")
    timeout = bounded_int(arguments.get("timeout", default_timeout), "timeout", 1, 300)
    max_findings = bounded_int(arguments.get("max_findings", 50), "max_findings", 1, 50)
    return timeout, max_findings


def safe_raw_findings(findings: list["SecretFinding"]) -> str:
    """Never retain or return Gitleaks' unredacted report content."""
    return json.dumps([{"RuleID": f.rule_id, "Description": f.description,
                        "Secret": f.secret, "File": f.file, "StartLine": f.line}
                       for f in findings])


class SecretFinding(BaseModel):
    """Model for a single secret finding."""

    rule_id: str
    description: str | None = None
    secret: str | None = None
    file: str | None = None
    line: int | None = None
    start_column: int | None = None
    end_column: int | None = None
    commit: str | None = None
    author: str | None = None
    email: str | None = None
    date: str | None = None
    message: str | None = None
    fingerprint: str | None = None
    tags: list[str] = []


class ScanResult(BaseModel):
    """Model for scan results."""

    scan_id: str
    target: str
    scan_type: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str = "running"
    findings: list[SecretFinding] = []
    stats: dict[str, Any] = {}
    error: str | None = None
    raw_output: str | None = None


# In-memory storage for scan results
scan_results: dict[str, ScanResult] = {}
active_scans: set[str] = set()


def parse_gitleaks_json(output: str) -> list[SecretFinding]:
    """Parse gitleaks JSON output into findings."""
    findings = []

    try:
        data = json.loads(output)
        if isinstance(data, list):
            for item in data:
                finding = SecretFinding(
                    rule_id=item.get("RuleID", "unknown"),
                    description=item.get("Description"),
                    secret=mask_secret(item.get("Secret", "")),
                    file=item.get("File"),
                    line=item.get("StartLine"),
                    start_column=item.get("StartColumn"),
                    end_column=item.get("EndColumn"),
                    commit=item.get("Commit"),
                    author=item.get("Author"),
                    email=item.get("Email"),
                    date=item.get("Date"),
                    message=item.get("Message"),
                    fingerprint=item.get("Fingerprint"),
                    tags=item.get("Tags", []),
                )
                findings.append(finding)
    except json.JSONDecodeError:
        logger.warning("Failed to parse gitleaks JSON output")

    return findings


def mask_secret(secret: str, visible_chars: int = 4) -> str:
    """Mask a secret, showing only first few characters."""
    if not secret or len(secret) <= visible_chars:
        return "****"
    return secret[:visible_chars] + "*" * (len(secret) - visible_chars)


async def run_gitleaks_scan(
    target: str,
    scan_type: str = "dir",
    timeout: int | None = None,
    no_git: bool = False,
) -> ScanResult:
    """Execute a gitleaks scan asynchronously."""
    scan_id = str(uuid.uuid4())[:8]
    output_file = Path(settings.output_dir) / f"scan_{scan_id}.json"

    result = ScanResult(
        scan_id=scan_id,
        target=target,
        scan_type=scan_type,
        started_at=datetime.now(),
    )
    scan_results[scan_id] = result
    active_scans.add(scan_id)

    # Build gitleaks command
    cmd = [
        "gitleaks",
        "detect",
        "--source", target,
        "--report-format", "json",
        "--report-path", str(output_file),
        "--exit-code", "0",  # Don't fail on findings
    ]

    if no_git:
        cmd.append("--no-git")

    logger.info(f"Starting gitleaks {scan_type} scan {scan_id} for target: {target}")
    logger.debug(f"Command: {' '.join(cmd)}")

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=float(timeout),
        )

        result.completed_at = datetime.now()

        # Read output file if exists
        if output_file.exists():
            output_content = output_file.read_text()
            result.findings = parse_gitleaks_json(output_content)
            result.raw_output = safe_raw_findings(result.findings)
        else:
            # No findings
            result.findings = []

        # Generate stats
        rules_triggered = {}
        for finding in result.findings:
            rule = finding.rule_id
            rules_triggered[rule] = rules_triggered.get(rule, 0) + 1

        files_with_secrets = set(f.file for f in result.findings if f.file)

        result.stats = {
            "total_findings": len(result.findings),
            "unique_rules_triggered": len(rules_triggered),
            "files_with_secrets": len(files_with_secrets),
            "rules_breakdown": rules_triggered,
        }

        result.status = "completed"
        logger.info(f"Scan {scan_id} completed: {len(result.findings)} findings")

        if stderr:
            stderr_text = stderr.decode()
            if "error" in stderr_text.lower():
                logger.warning(f"Scan {scan_id} warnings: {stderr_text}")

    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        result.status = "timeout"
        result.error = f"Scan timed out after {timeout} seconds"
        result.completed_at = datetime.now()
        logger.error(f"Scan {scan_id} timed out")

    except Exception as e:
        result.status = "error"
        result.error = str(e)
        result.completed_at = datetime.now()
        logger.exception(f"Scan {scan_id} error: {e}")

    finally:
        output_file.unlink(missing_ok=True)
        active_scans.discard(scan_id)
        scan_results[scan_id] = result

    return result


async def scan_content(content: str, timeout: int | None = None) -> ScanResult:
    """Scan provided content for secrets."""
    scan_id = str(uuid.uuid4())[:8]

    result = ScanResult(
        scan_id=scan_id,
        target="<content>",
        scan_type="content",
        started_at=datetime.now(),
    )
    scan_results[scan_id] = result
    active_scans.add(scan_id)

    # Write content to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(content)
        temp_path = f.name

    output_file = Path(settings.output_dir) / f"scan_{scan_id}.json"

    try:
        cmd = [
            "gitleaks",
            "detect",
            "--source", temp_path,
            "--report-format", "json",
            "--report-path", str(output_file),
            "--exit-code", "0",
            "--no-git",
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        await asyncio.wait_for(
            process.communicate(),
            timeout=float(timeout),
        )

        result.completed_at = datetime.now()

        if output_file.exists():
            output_content = output_file.read_text()
            result.findings = parse_gitleaks_json(output_content)
            result.raw_output = safe_raw_findings(result.findings)

        rules_triggered = {}
        for finding in result.findings:
            rule = finding.rule_id
            rules_triggered[rule] = rules_triggered.get(rule, 0) + 1

        result.stats = {
            "total_findings": len(result.findings),
            "rules_breakdown": rules_triggered,
        }

        result.status = "completed"

    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        result.status = "timeout"
        result.error = f"Scan timed out after {timeout} seconds"
        result.completed_at = datetime.now()

    except Exception as e:
        result.status = "error"
        result.error = str(e)
        result.completed_at = datetime.now()

    finally:
        output_file.unlink(missing_ok=True)
        active_scans.discard(scan_id)
        scan_results[scan_id] = result
        # Clean up temp file
        Path(temp_path).unlink(missing_ok=True)

    return result


def format_scan_summary(result: ScanResult, *, max_findings: int = 50) -> dict[str, Any]:
    """Format scan result for response."""
    findings_summary = []
    for finding in result.findings[:max_findings]:
        findings_summary.append({
            "rule_id": finding.rule_id,
            "description": finding.description,
            "secret": finding.secret,
            "file": finding.file,
            "line": finding.line,
            "commit": finding.commit[:8] if finding.commit else None,
            "author": finding.author,
        })

    return {
        "scan_id": result.scan_id,
        "target": result.target,
        "scan_type": result.scan_type,
        "status": result.status,
        "stats": result.stats,
        "findings": findings_summary,
        "error": result.error,
    }


# Create MCP server
app = Server("gitleaks-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="gitleaks_scan_repo",
            description="Scan a git repository for secrets and credentials. "
            "Analyzes commit history for leaked API keys, passwords, tokens, etc.",
            inputSchema={
                "type": "object",
                "properties": {
                    "repo_path": {
                        "type": "string",
                        "description": "Path to the git repository to scan",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Scan timeout in seconds",
                        "default": 300,
                        "minimum": 1,
                        "maximum": 300,
                    },
                    "max_findings": {"type": "integer", "minimum": 1, "maximum": 50, "default": 50},
                },
                "required": ["repo_path"],
                "additionalProperties": False,
            },
        ),
        Tool(
            name="gitleaks_scan_dir",
            description="Scan a directory for secrets without git history analysis. "
            "Useful for scanning non-git directories or specific folders.",
            inputSchema={
                "type": "object",
                "properties": {
                    "dir_path": {
                        "type": "string",
                        "description": "Directory path to scan",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Scan timeout in seconds",
                        "default": 300,
                        "minimum": 1,
                        "maximum": 300,
                    },
                    "max_findings": {"type": "integer", "minimum": 1, "maximum": 50, "default": 50},
                },
                "required": ["dir_path"],
                "additionalProperties": False,
            },
        ),
        Tool(
            name="gitleaks_detect",
            description="Quick scan provided content (text/code) for secrets. "
            "Useful for checking config files, environment variables, etc.",
            inputSchema={
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "Text content to scan for secrets",
                        "minLength": 1,
                        "maxLength": 64000,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Scan timeout in seconds",
                        "default": 60,
                        "minimum": 1,
                        "maximum": 300,
                    },
                    "max_findings": {"type": "integer", "minimum": 1, "maximum": 50, "default": 50},
                },
                "required": ["content"],
                "additionalProperties": False,
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
                        "description": "Include a redacted JSON report with only safe finding fields",
                        "default": False,
                    },
                    "max_findings": {"type": "integer", "minimum": 1, "maximum": 50, "default": 50},
                },
                "required": ["scan_id"],
                "additionalProperties": False,
            },
        ),
        Tool(
            name="list_active_scans",
            description="List currently running scans.",
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
        if name == "gitleaks_scan_repo":
            timeout, max_findings = scan_options(arguments, {"repo_path", "timeout", "max_findings"}, 300)
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            repo_path = approved_directory(arguments.get("repo_path"), repository=True)

            result = await run_gitleaks_scan(
                target=repo_path,
                scan_type="repo",
                timeout=timeout,
                no_git=False,
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result, max_findings=max_findings), indent=2),
                )
            ]

        elif name == "gitleaks_scan_dir":
            timeout, max_findings = scan_options(arguments, {"dir_path", "timeout", "max_findings"}, 300)
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            dir_path = approved_directory(arguments.get("dir_path"))

            result = await run_gitleaks_scan(
                target=dir_path,
                scan_type="dir",
                timeout=timeout,
                no_git=True,
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result, max_findings=max_findings), indent=2),
                )
            ]

        elif name == "gitleaks_detect":
            timeout, max_findings = scan_options(arguments, {"content", "timeout", "max_findings"}, 60)
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            content = arguments.get("content")
            if not isinstance(content, str) or not content.strip() or len(content) > MAX_CONTENT:
                raise ValueError(f"content must contain 1 to {MAX_CONTENT} characters")

            result = await scan_content(
                content=content,
                timeout=timeout,
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result, max_findings=max_findings), indent=2),
                )
            ]

        elif name == "get_scan_results":
            if not isinstance(arguments, dict) or arguments.keys() - {"scan_id", "include_raw", "max_findings"}:
                raise ValueError("unsupported tool option")
            scan_id = arguments.get("scan_id")
            if not isinstance(scan_id, str) or len(scan_id) != 8 or any(c not in "0123456789abcdef" for c in scan_id):
                raise ValueError("scan_id must be eight lowercase hexadecimal characters")
            include_raw = strict_bool(arguments.get("include_raw", False), "include_raw")
            max_findings = bounded_int(arguments.get("max_findings", 50), "max_findings", 1, 50)
            result = scan_results.get(scan_id)

            if result:
                output = format_scan_summary(result, max_findings=max_findings)
                if include_raw and result.raw_output:
                    output["raw_output"] = result.raw_output[:10000]
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
            if not isinstance(arguments, dict) or arguments:
                raise ValueError("unsupported tool option")
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

    for scan_id, result in scan_results.items():
        if result.status == "completed":
            finding_count = len(result.findings)
            resources.append(
                Resource(
                    uri=f"gitleaks://results/{scan_id}",
                    name=f"Scan Results: {result.target} ({finding_count} secrets)",
                    description=f"{result.scan_type} scan completed at {result.completed_at}",
                    mimeType="application/json",
                )
            )

    return resources


@app.read_resource()
async def read_resource(uri: str) -> str:
    """Read a resource."""
    if uri.startswith("gitleaks://results/"):
        scan_id = uri.replace("gitleaks://results/", "")
        result = scan_results.get(scan_id)
        if result:
            return json.dumps(format_scan_summary(result), indent=2)

    return json.dumps({"error": "Resource not found"})


async def main():
    """Run the MCP server."""
    logger.info("Starting Gitleaks MCP Server")
    logger.info(f"Output directory: {settings.output_dir}")

    # Ensure output directory exists
    Path(settings.output_dir).mkdir(parents=True, exist_ok=True)

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
