#!/usr/bin/env python3
"""
Boofuzz MCP Server

A Model Context Protocol server for network protocol fuzzing using Boofuzz.
"""

import json
import logging
import re
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool
from pydantic_settings import BaseSettings, SettingsConfigDict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("boofuzz-mcp")


class Settings(BaseSettings):
    """Server configuration."""
    model_config = SettingsConfigDict(env_prefix="BOOFUZZ_")
    
    results_dir: str = "/app/results"


settings = Settings()
app = Server("boofuzz-mcp")

@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="boofuzz_list_scripts",
            description="List built-in Boofuzz profiles. Custom Python scripts are deliberately unsupported.",
            inputSchema={"type": "object", "properties": {}}
        ),
        Tool(
            name="boofuzz_get_results",
            description="Retrieve the crash log or audit results from a fuzzing session.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "The session ID returned by a supported built-in profile."
                    }
                },
                "required": ["session_id"]
            }
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    
    if name == "boofuzz_list_scripts":
        return [TextContent(type="text", text=json.dumps({
            "profiles": [],
            "notice": "Custom Python scripts and their execution are disabled to prevent arbitrary code execution.",
        }, indent=2))]

    elif name == "boofuzz_get_results":
        session_id = arguments.get("session_id")
        if not isinstance(session_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", session_id):
            return [TextContent(type="text", text="Invalid session ID.")]
        results_root = Path(settings.results_dir).resolve()
        result_path = (results_root / session_id).resolve()
        if not result_path.is_relative_to(results_root) or not result_path.is_dir():
            return [TextContent(type="text", text=f"Session {session_id} not found.")]

        results = {"session_id": session_id, "files": {}}
        for f in result_path.glob("*"):
            try:
                if f.is_file() and f.resolve().is_relative_to(result_path):
                    with f.open("rb") as stream:
                        results["files"][f.name] = stream.read(5000).decode("utf-8", errors="replace")
            except OSError:
                continue
        
        return [TextContent(type="text", text=json.dumps(results, indent=2))]

    return [TextContent(type="text", text="Unknown tool.")]


async def main():
    """Run the MCP server."""
    logger.info("Starting Boofuzz MCP Server")
    
    Path(settings.results_dir).mkdir(parents=True, exist_ok=True)

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
