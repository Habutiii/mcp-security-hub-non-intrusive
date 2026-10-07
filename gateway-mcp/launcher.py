#!/usr/bin/env python3
"""Code-owned child-process launcher with fixed POSIX resource limits."""

import os
import resource
import sys


BASE_ENVIRONMENT = {
    "HOME": "/home/mcpuser",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "PYTHONPATH": "/opt/security-hub",
    "PYTHONUNBUFFERED": "1",
    "TMPDIR": "/tmp",
}
OUTPUT_DIRECTORY_VARIABLES = frozenset({
    "BOOFUZZ_RESULTS_DIR", "DHARMA_CUSTOM_DIR", "FFUF_OUTPUT_DIR",
    "GITLEAKS_OUTPUT_DIR", "MASSCAN_OUTPUT_DIR", "NMAP_OUTPUT_DIR",
    "SQLMAP_OUTPUT_DIR", "WAYBACKURLS_OUTPUT_DIR", "WHATWEB_OUTPUT_DIR",
})


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
    environment = BASE_ENVIRONMENT.copy()
    for name in OUTPUT_DIRECTORY_VARIABLES:
        value = os.environ.get(name)
        if value is None:
            continue
        if not value.startswith("/var/lib/security-hub/"):
            raise SystemExit("invalid child output directory")
        environment[name] = value
    # Replace the inherited process environment before executing the fixed
    # interpreter and script. This closes the launcher's environment boundary
    # even if it is invoked outside the gateway.
    os.environ.clear()
    os.environ.update(environment)
    os.execv(sys.executable, [sys.executable, "server.py"])


if __name__ == "__main__":
    main()
