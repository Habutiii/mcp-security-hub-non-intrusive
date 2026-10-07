#!/usr/bin/env python3
"""Code-owned child-process launcher with fixed POSIX resource limits."""

import os
import resource
import sys


def main() -> None:
    if len(sys.argv) != 6:
        raise SystemExit("invalid gateway launcher invocation")
    _, component_id, working_directory, memory_bytes, cpu_seconds, file_bytes = sys.argv
    if component_id not in {
        "dharma", "boofuzz", "hashcat", "gitleaks", "waybackurls", "nmap",
        "whatweb", "ffuf", "pd_tools", "externalattacker", "masscan", "sqlmap", "nikto",
    }:
        raise SystemExit("unregistered component")
    resource.setrlimit(resource.RLIMIT_AS, (int(memory_bytes), int(memory_bytes)))
    resource.setrlimit(resource.RLIMIT_CPU, (int(cpu_seconds), int(cpu_seconds)))
    resource.setrlimit(resource.RLIMIT_FSIZE, (int(file_bytes), int(file_bytes)))
    os.chdir(working_directory)
    os.execve(sys.executable, [sys.executable, "server.py"], os.environ)


if __name__ == "__main__":
    main()
