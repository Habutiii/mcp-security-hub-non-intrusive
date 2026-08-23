#!/usr/bin/env python3
"""A deliberately dictionary-only Hashcat MCP server for authorized recovery."""

import asyncio
import tempfile
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

app = Server("hashcat-mcp")
HASHCAT_PATH = "/usr/bin/hashcat"
WORDLIST_PATH = Path("/app/wordlists/10k-most-common.txt")
MAX_TIMEOUT_SECONDS = 300


def _valid_hash_mode(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > 9_999_999:
        raise ValueError("hash_mode must be a non-negative integer")
    return value


async def _crack_dictionary(password_hash: str, hash_mode: int, timeout: int) -> str:
    if not isinstance(password_hash, str) or not password_hash.strip() or len(password_hash) > 4096:
        raise ValueError("password_hash must be a non-empty string no longer than 4096 characters")
    if not 1 <= timeout <= MAX_TIMEOUT_SECONDS:
        raise ValueError(f"timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds")
    if not WORDLIST_PATH.is_file() or WORDLIST_PATH.stat().st_size == 0:
        raise RuntimeError("The SecLists dictionary is unavailable")

    with tempfile.TemporaryDirectory(prefix="hashcat-") as temporary_dir:
        workdir = Path(temporary_dir)
        hash_file = workdir / "hashes.txt"
        output_file = workdir / "recovered.txt"
        hash_file.write_text(password_hash.strip() + "\n", encoding="utf-8")

        # Attack mode 0 is Hashcat's dictionary attack. No masks, rules, hybrids,
        # restore files, or user-controlled command-line arguments are accepted.
        command = [
            HASHCAT_PATH,
            "--attack-mode", "0",
            "--hash-type", str(hash_mode),
            "--quiet",
            "--potfile-disable",
            "--outfile", str(output_file),
            str(hash_file),
            str(WORDLIST_PATH),
        ]
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(workdir),
        )
        try:
            _, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return "Dictionary attack timed out without returning a recovered password."

        if output_file.exists():
            recovered = output_file.read_text(encoding="utf-8", errors="replace").strip()
            if recovered:
                return f"Recovered credential: {recovered}"
        if process.returncode not in (0, 1):
            return f"Hashcat failed: {stderr.decode(errors='replace')[:1000]}"
        return "No password was recovered from the configured SecLists dictionary."


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="hashcat_dictionary_crack",
            description="Attempt authorized password recovery using only the runtime-downloaded SecLists dictionary.",
            inputSchema={
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "password_hash": {"type": "string", "maxLength": 4096},
                    "hash_mode": {"type": "integer", "minimum": 0},
                    "timeout": {"type": "integer", "minimum": 1, "maximum": MAX_TIMEOUT_SECONDS, "default": 300},
                },
                "required": ["password_hash", "hash_mode"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if name != "hashcat_dictionary_crack":
        return [TextContent(type="text", text="Unknown tool")]
    try:
        result = await _crack_dictionary(
            arguments["password_hash"],
            _valid_hash_mode(arguments["hash_mode"]),
            arguments.get("timeout", MAX_TIMEOUT_SECONDS),
        )
        return [TextContent(type="text", text=result)]
    except (KeyError, ValueError, RuntimeError) as exc:
        return [TextContent(type="text", text=f"Error: {exc}")]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
