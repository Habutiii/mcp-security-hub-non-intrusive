"""Small, fixed-command runtime shared by AGW Python adapters.

Adapters construct argument vectors from validated fields; this module never
accepts an executable or command string from an MCP request.
"""

import asyncio
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


async def run_fixed_command(command: Sequence[str], *, timeout: int, max_output: int = 200_000) -> CommandResult:
    """Run a preconstructed argument vector with bounded output and lifetime."""
    if not command or any(not isinstance(part, str) or not part for part in command):
        raise ValueError("adapter command is invalid")
    process = await asyncio.create_subprocess_exec(
        *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        process.kill()
        await process.wait()
        raise ValueError("adapter command timed out")
    return CommandResult(
        returncode=process.returncode,
        stdout=stdout.decode(errors="replace")[:max_output],
        stderr=stderr.decode(errors="replace")[:max_output],
    )
