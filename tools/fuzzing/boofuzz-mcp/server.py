#!/usr/bin/env python3
"""
Boofuzz MCP Server

A Model Context Protocol server for network protocol fuzzing using Boofuzz.
"""

import json
import logging
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
        result_path = Path(settings.results_dir) / session_id
        
        if not result_path.exists():
            return [TextContent(type="text", text=f"Session {session_id} not found.")]

        results = {"session_id": session_id, "files": {}}
        for f in result_path.glob("*"):
            try:
                results["files"][f.name] = f.read_text()[:5000] # Limit size
            except: pass
        
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
