#!/usr/bin/env python3
"""Lazy, single-endpoint gateway for the security-hub MCP collection.

The gateway never accepts Docker commands, images, or container names from an
agent. It uses the fixed COMPONENTS registry below and starts a registered
child only when requested by a lifecycle operation or first tool call.
"""

import asyncio
import json
import logging
import os
import sys
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from capability_policy import CAPABILITIES, CAPABILITY_BY_COMPONENT, Capability, PrivilegeProfile
from scope_policy import ScopeError, validate_scope

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("security-hub-gateway")


@dataclass(frozen=True)
class Component:
    """A fixed local-process launch specification from the reviewed capability."""

    capability: Capability
    working_directory: str
    environment: tuple[tuple[str, str], ...] = ()
    memory_bytes: int = 1_073_741_824
    cpu_seconds: int = 600
    file_bytes: int = 134_217_728


# Only a capability-policy entry can make a child gateway-callable. Paths and
# environment are code-owned; agents cannot select commands or executables.
COMPONENTS: dict[str, Component] = {
    "dharma": Component(CAPABILITY_BY_COMPONENT["dharma"], "/opt/security-hub/tools/dharma", (("DHARMA_GRAMMAR_DIR", "/app/grammars"), ("DHARMA_CUSTOM_DIR", "/var/lib/security-hub/dharma"))),
    "boofuzz": Component(CAPABILITY_BY_COMPONENT["boofuzz"], "/opt/security-hub/tools/boofuzz", (("BOOFUZZ_RESULTS_DIR", "/var/lib/security-hub/boofuzz"),)),
    "hashcat": Component(CAPABILITY_BY_COMPONENT["hashcat"], "/opt/security-hub/tools/hashcat", memory_bytes=2_147_483_648),
    "gitleaks": Component(CAPABILITY_BY_COMPONENT["gitleaks"], "/opt/security-hub/tools/gitleaks", (("GITLEAKS_OUTPUT_DIR", "/var/lib/security-hub/gitleaks"),)),
    "waybackurls": Component(CAPABILITY_BY_COMPONENT["waybackurls"], "/opt/security-hub/tools/waybackurls", (("WAYBACKURLS_OUTPUT_DIR", "/var/lib/security-hub/waybackurls"),)),
    "nmap": Component(CAPABILITY_BY_COMPONENT["nmap"], "/opt/security-hub/tools/nmap", (("NMAP_OUTPUT_DIR", "/var/lib/security-hub/nmap"),)),
    "whatweb": Component(CAPABILITY_BY_COMPONENT["whatweb"], "/opt/security-hub/tools/whatweb", (("WHATWEB_OUTPUT_DIR", "/var/lib/security-hub/whatweb"),)),
    "ffuf": Component(CAPABILITY_BY_COMPONENT["ffuf"], "/opt/security-hub/tools/ffuf", (("FFUF_OUTPUT_DIR", "/var/lib/security-hub/ffuf"),)),
    "pd_tools": Component(CAPABILITY_BY_COMPONENT["pd_tools"], "/opt/security-hub/tools/pd_tools"),
    "externalattacker": Component(CAPABILITY_BY_COMPONENT["externalattacker"], "/opt/security-hub/tools/externalattacker"),
    "masscan": Component(CAPABILITY_BY_COMPONENT["masscan"], "/opt/security-hub/tools/masscan", (("MASSCAN_OUTPUT_DIR", "/var/lib/security-hub/masscan"),)),
    "sqlmap": Component(CAPABILITY_BY_COMPONENT["sqlmap"], "/opt/security-hub/tools/sqlmap", (("SQLMAP_OUTPUT_DIR", "/var/lib/security-hub/sqlmap"),)),
    "nikto": Component(CAPABILITY_BY_COMPONENT["nikto"], "/opt/security-hub/tools/nikto", memory_bytes=1_610_612_736),
}


@dataclass
class RunningComponent:
    component_id: str
    stack: AsyncExitStack
    session: ClientSession
    tools: dict[str, Tool]
    active_calls: int = 0
    last_used: float = field(default_factory=time.monotonic)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


running: dict[str, RunningComponent] = {}
start_lock = asyncio.Lock()
app = Server("security-hub-gateway")
# Keep started MCP processes for the gateway session by default. Deployments may
# opt into reaping with a positive timeout; zero means no automatic shutdown.
IDLE_TIMEOUT_SECONDS = max(0, int(os.environ.get("AGW_IDLE_TIMEOUT_SECONDS", "0")))
MAX_WARM_PROCESSES = max(1, int(os.environ.get("AGW_MAX_WARM_PROCESSES", str(len(COMPONENTS)))) )
RAW_NETWORK_ENABLED = os.environ.get("AGW_RAW_NETWORK_ENABLED", "false").lower() == "true"


async def start_component(component_id: str) -> RunningComponent:
    """Start and initialize one registry-owned child MCP exactly once."""
    if component_id not in COMPONENTS:
        raise ValueError("Unknown registered MCP identifier")

    async with start_lock:
        existing = running.get(component_id)
        if existing:
            existing.last_used = time.monotonic()
            return existing

        while len(running) >= MAX_WARM_PROCESSES:
            idle = [instance for instance in running.values() if not instance.active_calls]
            if not idle:
                raise RuntimeError("maximum warm MCP process count reached")
            await stop_component(min(idle, key=lambda instance: instance.last_used).component_id)

        component = COMPONENTS[component_id]
        if component.capability.privilege_profile == PrivilegeProfile.RAW_NETWORK and not RAW_NETWORK_ENABLED:
            raise RuntimeError("raw-network tools are disabled; enable AGW_RAW_NETWORK_ENABLED only in an authorized deployment")
        environment = os.environ.copy()
        environment.update(dict(component.environment))
        parameters = StdioServerParameters(
            command=sys.executable,
            args=[
                "/opt/security-hub/gateway-mcp/launcher.py", component_id,
                component.working_directory, str(component.memory_bytes),
                str(component.cpu_seconds), str(component.file_bytes),
            ],
            env=environment,
        )
        stack = AsyncExitStack()
        try:
            read_stream, write_stream = await stack.enter_async_context(stdio_client(parameters))
            session = await stack.enter_async_context(ClientSession(read_stream, write_stream))
            await session.initialize()
            response = await session.list_tools()
            tools = {tool.name: tool for tool in response.tools}
            expected_tools = component.capability.allowed_tools
            if set(tools) != expected_tools:
                raise RuntimeError(
                    f"Capability contract drift for {component_id}: "
                    f"expected {sorted(expected_tools)}, received {sorted(tools)}"
                )
            instance = RunningComponent(component_id, stack, session, tools)
            running[component_id] = instance
            logger.info("Started %s with %d advertised tools", component_id, len(tools))
            return instance
        except Exception:
            await stack.aclose()
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
        logger.info("Stopped %s", component_id)
        return "stopped"


async def stop_all_components() -> None:
    for component_id in list(running):
        try:
            await stop_component(component_id)
        except Exception:
            logger.exception("Failed to stop %s during gateway cleanup", component_id)


async def reap_idle_components() -> None:
    """Release warmed processes after their deployment-configured idle period."""
    while True:
        await asyncio.sleep(min(30, max(5, IDLE_TIMEOUT_SECONDS or 30)))
        if not IDLE_TIMEOUT_SECONDS:
            continue
        now = time.monotonic()
        for component_id, instance in list(running.items()):
            if not instance.active_calls and now - instance.last_used >= IDLE_TIMEOUT_SECONDS:
                await stop_component(component_id)


def text(data: Any) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(data, indent=2, default=str))]


@app.list_tools()
async def list_tools() -> list[Tool]:
    component_ids = sorted(COMPONENTS)
    return [
        Tool(
            name="gateway_list_capabilities",
            description="List the reviewed capability types, target-effect labels, and permitted child tools.",
            inputSchema={"type": "object", "properties": {}},
        ),
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
        if name == "gateway_list_capabilities":
            return text({capability.component_id: capability.public() for capability in CAPABILITIES})

        if name == "gateway_list_components":
            return text({
                component_id: {
                    "description": component.capability.description,
                    "capability_type": component.capability.capability_type.value,
                    "target_effect": component.capability.target_effect.value,
                    "scope_required": component.capability.scope_required,
                    "privilege_profile": component.capability.privilege_profile.value,
                    "state": "running" if component_id in running else "stopped",
                    "active_calls": running[component_id].active_calls if component_id in running else 0,
                    "idle_timeout_seconds": IDLE_TIMEOUT_SECONDS,
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
            capability = CAPABILITY_BY_COMPONENT[component_id]
            if capability.scope_required:
                decision = validate_scope(component_id, arguments.get("arguments", {}))
                logger.info("audit=%s", json.dumps({"event": "scope_allowed", "component": component_id, "tool": arguments.get("tool_name"), **decision}, sort_keys=True))
            instance = await start_component(component_id)
            tool_name = arguments.get("tool_name")
            if tool_name not in capability.allowed_tools or tool_name not in instance.tools:
                return text({"error": "Tool is not permitted by the reviewed capability contract"})
            async with instance.lock:
                instance.active_calls += 1
            try:
                result = await instance.session.call_tool(tool_name, arguments.get("arguments", {}))
                return text({"mcp_id": component_id, "tool_name": tool_name, "result": result.model_dump(mode="json")})
            finally:
                async with instance.lock:
                    instance.active_calls -= 1
                    instance.last_used = time.monotonic()

        return text({"error": "Unknown gateway tool"})
    except ScopeError as error:
        logger.warning("audit=%s", json.dumps({"event": "scope_rejected", "error": str(error)}, sort_keys=True))
        return text({"error": str(error)})
    except Exception as error:
        logger.exception("Gateway operation failed")
        return text({"error": str(error)})


async def main() -> None:
    reaper = asyncio.create_task(reap_idle_components())
    try:
        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())
    finally:
        reaper.cancel()
        await asyncio.gather(reaper, return_exceptions=True)
        await stop_all_components()


if __name__ == "__main__":
    asyncio.run(main())
