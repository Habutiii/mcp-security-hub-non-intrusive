#!/usr/bin/env python3
"""Lazy, single-endpoint gateway for the security-hub MCP collection.

The gateway never accepts Docker commands, images, or container names from an
agent. It uses the fixed COMPONENTS registry below and starts a registered
child only when requested by a lifecycle operation or first tool call.
"""

import asyncio
import json
import logging
import uuid
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("security-hub-gateway")


@dataclass(frozen=True)
class Component:
    """A fixed, reviewed child-MCP launch specification."""

    image: str
    docker_args: tuple[str, ...] = ()
    description: str = ""


# Only these identifiers can be started, prewarmed, or shut down. The image and
# Docker arguments are deliberately code-owned instead of MCP tool inputs.
COMPONENTS: dict[str, Component] = {
    "nmap": Component("nmap-mcp:latest", ("--cap-add=NET_RAW", "--cap-add=NET_ADMIN"), "Bounded network reconnaissance"),
    "shodan": Component("shodan-mcp:latest", description="Shodan intelligence"),
    "pd_tools": Component("pd-tools-mcp:latest", description="Bounded ProjectDiscovery discovery"),
    "whatweb": Component("whatweb-mcp:latest", description="HTTP technology fingerprinting"),
    "masscan": Component("masscan-mcp:latest", ("--cap-add=NET_RAW",), "Bounded SYN discovery"),
    "zoomeye": Component("zoomeye-mcp:latest", description="ZoomEye intelligence"),
    "networksdb": Component("networksdb-mcp:latest", description="NetworksDB intelligence"),
    "externalattacker": Component("externalattacker-mcp:latest", description="Restricted attack-surface discovery"),
    "nikto": Component("nikto-mcp:latest", description="Fixed web-server checks"),
    "ffuf": Component("ffuf-mcp:latest", description="GET-only web discovery"),
    "waybackurls": Component("waybackurls-mcp:latest", description="Historical URL retrieval"),
    "dharma": Component("dharma-mcp:latest", description="Local test-case generation"),
    "boofuzz": Component("boofuzz-mcp:latest", description="Stored-result and status tools"),
    "gitleaks": Component("gitleaks-mcp:latest", description="Read-only local secret scanning"),
    "otx": Component("otx-mcp:latest", description="OTX intelligence"),
    "maigret": Component("maigret-mcp:latest", description="Public profile lookup"),
    "dnstwist": Component("dnstwist-mcp:latest", description="Domain permutation reconnaissance"),
    "virustotal": Component("virustotal-mcp:latest", description="Threat intelligence"),
    "bloodhound": Component("bloodhound-mcp:latest", description="Fixed read-only graph queries"),
    "mcp_scan": Component("mcp-scan:latest", description="Local MCP configuration inspection"),
    "hashcat": Component("hashcat-mcp:latest", description="Local dictionary-only recovery"),
}

GATEWAY_SESSION = uuid.uuid4().hex[:10]


@dataclass
class RunningComponent:
    component_id: str
    container_name: str
    stack: AsyncExitStack
    session: ClientSession
    tools: dict[str, Tool]
    active_calls: int = 0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


running: dict[str, RunningComponent] = {}
start_lock = asyncio.Lock()
app = Server("security-hub-gateway")


async def docker_remove(container_name: str) -> None:
    """Remove only a gateway-created container; ignore an already-removed one."""
    process = await asyncio.create_subprocess_exec(
        "docker", "rm", "-f", container_name,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await process.wait()


async def start_component(component_id: str) -> RunningComponent:
    """Start and initialize one registry-owned child MCP exactly once."""
    if component_id not in COMPONENTS:
        raise ValueError("Unknown registered MCP identifier")

    async with start_lock:
        existing = running.get(component_id)
        if existing:
            return existing

        component = COMPONENTS[component_id]
        container_name = f"security-hub-{GATEWAY_SESSION}-{component_id}"
        parameters = StdioServerParameters(
            command="docker",
            args=["run", "--name", container_name, "-i", "--rm", *component.docker_args, component.image],
        )
        stack = AsyncExitStack()
        try:
            read_stream, write_stream = await stack.enter_async_context(stdio_client(parameters))
            session = await stack.enter_async_context(ClientSession(read_stream, write_stream))
            await session.initialize()
            response = await session.list_tools()
            tools = {tool.name: tool for tool in response.tools}
            instance = RunningComponent(component_id, container_name, stack, session, tools)
            running[component_id] = instance
            logger.info("Started %s with %d advertised tools", component_id, len(tools))
            return instance
        except Exception:
            await stack.aclose()
            await docker_remove(container_name)
            raise


async def stop_component(component_id: str) -> str:
    """Gracefully close a child only when it has no active gateway call."""
    instance = running.get(component_id)
    if not instance:
        return "not_running"

    async with instance.lock:
        if instance.active_calls:
            raise RuntimeError("The MCP has active work and cannot be stopped")
        running.pop(component_id, None)
        await instance.stack.aclose()
        await docker_remove(instance.container_name)
        logger.info("Stopped %s", component_id)
        return "stopped"


async def stop_all_components() -> None:
    for component_id in list(running):
        try:
            await stop_component(component_id)
        except Exception:
            logger.exception("Failed to stop %s during gateway cleanup", component_id)


def text(data: Any) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(data, indent=2, default=str))]


@app.list_tools()
async def list_tools() -> list[Tool]:
    component_ids = sorted(COMPONENTS)
    return [
        Tool(name="gateway_list_components", description="List registered MCPs and their current lifecycle state.", inputSchema={"type": "object", "properties": {}}),
        Tool(
            name="gateway_prewarm",
            description="Start a registered MCP without sending target traffic. Reuses it for later calls.",
            inputSchema={"type": "object", "properties": {"mcp_id": {"type": "string", "enum": component_ids}}, "required": ["mcp_id"]},
        ),
        Tool(
            name="gateway_shutdown",
            description="Stop an idle registered MCP to release resources. Active work is never interrupted.",
            inputSchema={"type": "object", "properties": {"mcp_id": {"type": "string", "enum": component_ids}}, "required": ["mcp_id"]},
        ),
        Tool(
            name="gateway_list_component_tools",
            description="Start a registered MCP if needed and list its currently advertised tools and schemas.",
            inputSchema={"type": "object", "properties": {"mcp_id": {"type": "string", "enum": component_ids}}, "required": ["mcp_id"]},
        ),
        Tool(
            name="gateway_call",
            description="Call one advertised tool on a registered MCP. The child tool name is validated against its initialized tool list.",
            inputSchema={
                "type": "object",
                "properties": {
                    "mcp_id": {"type": "string", "enum": component_ids},
                    "tool_name": {"type": "string"},
                    "arguments": {"type": "object", "additionalProperties": True},
                },
                "required": ["mcp_id", "tool_name", "arguments"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        if name == "gateway_list_components":
            return text({
                component_id: {
                    "description": component.description,
                    "state": "running" if component_id in running else "stopped",
                    "active_calls": running[component_id].active_calls if component_id in running else 0,
                }
                for component_id, component in COMPONENTS.items()
            })

        component_id = arguments.get("mcp_id")
        if component_id not in COMPONENTS:
            return text({"error": "Unknown registered MCP identifier"})

        if name == "gateway_prewarm":
            instance = await start_component(component_id)
            return text({"mcp_id": component_id, "state": "running", "tool_count": len(instance.tools)})

        if name == "gateway_shutdown":
            return text({"mcp_id": component_id, "state": await stop_component(component_id)})

        if name == "gateway_list_component_tools":
            instance = await start_component(component_id)
            return text({
                "mcp_id": component_id,
                "tools": [tool.model_dump(mode="json") for tool in instance.tools.values()],
            })

        if name == "gateway_call":
            instance = await start_component(component_id)
            tool_name = arguments.get("tool_name")
            if tool_name not in instance.tools:
                return text({"error": "Tool is not advertised by this registered MCP"})
            async with instance.lock:
                instance.active_calls += 1
            try:
                result = await instance.session.call_tool(tool_name, arguments.get("arguments", {}))
                return text({"mcp_id": component_id, "tool_name": tool_name, "result": result.model_dump(mode="json")})
            finally:
                async with instance.lock:
                    instance.active_calls -= 1

        return text({"error": "Unknown gateway tool"})
    except Exception as error:
        logger.exception("Gateway operation failed")
        return text({"error": str(error)})


async def main() -> None:
    try:
        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())
    finally:
        await stop_all_components()


if __name__ == "__main__":
    asyncio.run(main())
