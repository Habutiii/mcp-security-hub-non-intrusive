# Offensive Security MCP Servers

[![Build Status](https://github.com/FuzzingLabs/mcp-security-hub/actions/workflows/build.yml/badge.svg)](https://github.com/FuzzingLabs/mcp-security-hub/actions/workflows/build.yml)
[![Security Scan](https://github.com/FuzzingLabs/mcp-security-hub/actions/workflows/security-scan.yml/badge.svg)](https://github.com/FuzzingLabs/mcp-security-hub/actions/workflows/security-scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP Protocol](https://img.shields.io/badge/MCP-Protocol-blue.svg)](https://modelcontextprotocol.io/)

Production-ready, Dockerized MCP (Model Context Protocol) servers for offensive security tools. Enable AI assistants like Claude to perform security assessments and vulnerability scanning.

<p align="center">
  <img src="https://img.shields.io/badge/MCPs-24-brightgreen" alt="24 MCPs"/>
  <img src="https://img.shields.io/badge/Tools-300+-orange" alt="300+ Tools"/>
  <img src="https://img.shields.io/badge/Docker-Ready-blue" alt="Docker Ready"/>
</p>

## Features

- **24 MCP Servers** covering reconnaissance, web security, secrets detection, threat intelligence, OSINT, Active Directory, fuzzing, and more
- **300+ Security Tools** accessible via natural language through Claude or other MCP clients
- **Production Hardened** - Non-root containers, minimal images, Trivy-scanned
- **Docker Compose** orchestration for multi-tool workflows
- **CI/CD Ready** with GitHub Actions for automated builds and security scanning

## Operating Policy

This project supports authorized, **non-destructive** security assessment. Active reconnaissance and detection scans are allowed even when they create normal target-side audit logs. The boundary is that an MCP tool must not be able to alter the analyzed target's state or escape its intended operation.

- Allowed: scoped port and service discovery, HTTP fingerprinting and crawling, DNS enumeration, read-only vulnerability checks, and local payload generation.
- Not allowed for agent use: changing database content, writing or deleting files, creating or changing accounts, modifying configuration, deploying payloads, or executing commands on a target.
- A tool must not expose arbitrary shell arguments, arbitrary code/script execution, or an unrestricted template/plugin selection mechanism.
- High-risk or state-changing actions remain a human responsibility, performed outside this MCP collection after explicit authorization.

See [Tool Use Principles](./TOOL-USE-PRINCIPLES.md) for the mandatory restrictions for existing and new MCP servers.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/FuzzingLabs/mcp-security-hub
cd mcp-security-hub

# Build all MCP servers
docker-compose build

# Run an MCP in the foreground (for example, Nmap)
# Ctrl+C sends a graceful stop; --rm removes the stopped container.
docker run -i --rm --cap-add=NET_RAW --cap-add=NET_ADMIN nmap-mcp:latest
```

These MCP servers use standard input/output, so do not start them with
`docker compose up -d`: detached Compose closes stdin and the server exits. For
an MCP client, use the `docker run -i --rm ...` configuration shown below. When
the client stops it (including with Ctrl+C), Docker stops the process and removes
the container because of `--rm`.

### Configure Claude Desktop / Claude Code

**Important:** You must build the images first with `docker-compose build` before using them.

Copy the example config to your Claude Desktop configuration:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "nmap": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--cap-add=NET_RAW", "nmap-mcp:latest"]
    },
    "nuclei": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "nuclei-mcp:latest"]
    },
    "gitleaks": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "-v", "/path/to/repos:/app/target:ro", "gitleaks-mcp:latest"]
    },
  }
}
```

For project-level config, copy `.mcp.json` to your project root. See [examples/](./examples/) for full configuration templates with all MCPs and volume mount patterns.

## Available MCP Servers

### Reconnaissance (8 servers)

| Server | Tools | Description |
|--------|-------|-------------|
| [nmap-mcp](./reconnaissance/nmap-mcp) | 8 | Port scanning, service detection, OS fingerprinting, NSE scripts |
| [shodan-mcp](./reconnaissance/shodan-mcp) | - | Wrapper for [official Shodan MCP](https://github.com/BurtTheCoder/mcp-shodan) |
| [pd-tools-mcp](./reconnaissance/pd-tools-mcp) | 5 | Restricted, vendored ProjectDiscovery discovery tools (subfinder, dnsx, naabu, httpx, katana) |
| [whatweb-mcp](./reconnaissance/whatweb-mcp) | 5 | Web technology fingerprinting and CMS detection |
| [masscan-mcp](./reconnaissance/masscan-mcp) | 6 | High-speed port scanning for large networks |
| [zoomeye-mcp](./reconnaissance/zoomeye-mcp) | - | Wrapper for [ZoomEye MCP](https://github.com/zoomeye-ai/mcp_zoomeye) - Cyberspace search engine |
| [networksdb-mcp](./reconnaissance/networksdb-mcp) | 4 | IP/ASN/DNS lookups via [NetworksDB](https://github.com/MorDavid/NetworksDB-MCP) |
| [externalattacker-mcp](./reconnaissance/externalattacker-mcp) | 5 | Restricted, vendored external attack-surface discovery |

### Web Security (6 servers)

| Server | Tools | Description |
|--------|-------|-------------|
| [nuclei-mcp](./web-security/nuclei-mcp) | 7 | Template-based vulnerability scanning with 8000+ templates |
| [sqlmap-mcp](./web-security/sqlmap-mcp) | 8 | SQL injection detection and exploitation |
| [nikto-mcp](./web-security/nikto-mcp) | - | Wrapper for [Nikto MCP](https://github.com/weldpua2008/nikto-mcp) web server scanner |
| [ffuf-mcp](./web-security/ffuf-mcp) | 9 | Web fuzzing for directories, files, parameters, and virtual hosts |
| [waybackurls-mcp](./web-security/waybackurls-mcp) | 3 | Fetch historical URLs from Wayback Machine for reconnaissance |
| [burp-mcp](./web-security/burp-mcp) | - | Wrapper for [official Burp Suite MCP](https://github.com/PortSwigger/mcp-server) |

### Secrets Detection (1 server)

| Server | Tools | Description |
|--------|-------|-------------|
| [gitleaks-mcp](./secrets/gitleaks-mcp) | 5 | Find secrets and credentials in git repos and files |

### Fuzzing (2 servers)

| Server | Tools | Description |
|--------|-------|-------------|
| [boofuzz-mcp](./fuzzing/boofuzz-mcp) | 4 | Network protocol fuzzing using Boofuzz |
| [dharma-mcp](./fuzzing/dharma-mcp) | 2 | Grammar-based test case generation |

### OSINT (2 servers)

| Server | Tools | Description |
|--------|-------|-------------|
| [maigret-mcp](./osint/maigret-mcp) | - | Wrapper for [mcp-maigret](https://github.com/BurtTheCoder/mcp-maigret) - Username OSINT across 2500+ sites |
| [dnstwist-mcp](./osint/dnstwist-mcp) | - | Wrapper for [mcp-dnstwist](https://github.com/BurtTheCoder/mcp-dnstwist) - Typosquatting/phishing detection |

### Threat Intelligence (2 servers)

| Server | Tools | Description |
|--------|-------|-------------|
| [virustotal-mcp](./threat-intel/virustotal-mcp) | - | Wrapper for [mcp-virustotal](https://github.com/BurtTheCoder/mcp-virustotal) - Malware analysis and threat intel |
| [otx-mcp](./threat-intel/otx-mcp) | - | Wrapper for [OTX MCP](https://github.com/mrwadams/otx-mcp) - AlienVault Open Threat Exchange |

### Active Directory (1 server)

| Server | Tools | Description |
|--------|-------|-------------|
| [bloodhound-mcp](./active-directory/bloodhound-mcp) | 75+ | Wrapper for [BloodHound-MCP-AI](https://github.com/MorDavid/BloodHound-MCP-AI) - AD attack path analysis |

### Password Cracking (1 server)

| Server | Tools | Description |
|--------|-------|-------------|
| [hashcat-mcp](./password-cracking/hashcat-mcp) | 1 | Dictionary-only, authorized password recovery using a runtime-downloaded SecLists wordlist |

### Meta (1 server)

| Server | Tools | Description |
|--------|-------|-------------|
| [mcp-scan](./meta/mcp-scan) | - | Wrapper for [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) - Scan MCP servers for vulnerabilities |

## Usage Examples

### Network Reconnaissance

```
You: "Scan 192.168.1.0/24 for web servers and identify technologies"

Claude: I'll perform a network scan and technology fingerprinting.
[Uses nmap-mcp to scan ports 80,443,8080]
[Uses whatweb-mcp to fingerprint discovered hosts]

Found 12 web servers:
- 192.168.1.10: Apache 2.4.52, WordPress 6.4
- 192.168.1.15: nginx 1.24, React application
...
```

### Vulnerability Assessment

```
You: "Check example.com for common vulnerabilities"

Claude: I'll run a vulnerability scan using nuclei templates.
[Uses nuclei-mcp with cves, exposures, and misconfigurations templates]

Found 3 issues:
- HIGH: CVE-2024-1234 - Outdated jQuery version
- MEDIUM: Exposed .git directory
- INFO: Missing security headers
```

## Security Hardening

All containers implement defense-in-depth:

| Control | Implementation |
|---------|----------------|
| **Non-root execution** | Runs as `mcpuser` (UID 1000) |
| **Minimal images** | Alpine/Debian slim base images |
| **Dropped capabilities** | `cap_drop: ALL`, selective `cap_add` |
| **No privilege escalation** | `security_opt: no-new-privileges:true` |
| **Read-only mounts** | Sample directories mounted read-only |
| **Resource limits** | CPU and memory constraints |
| **Health checks** | Built-in container health monitoring |
| **Vulnerability scanning** | Trivy scans in CI/CD pipeline |

## Project Structure

```
mcp-security-hub/
├── reconnaissance/
│   ├── nmap-mcp/           # Port scanning
│   ├── shodan-mcp/         # Internet device search (wrapper)
│   ├── pd-tools-mcp/       # ProjectDiscovery tools (wrapper)
│   ├── whatweb-mcp/        # Web fingerprinting
│   ├── masscan-mcp/        # High-speed scanning
│   ├── zoomeye-mcp/        # Cyberspace search (wrapper)
│   ├── networksdb-mcp/     # IP/ASN/DNS lookups
│   └── externalattacker-mcp/ # Attack surface mapping
├── web-security/
│   ├── nuclei-mcp/         # Vulnerability scanning
│   ├── sqlmap-mcp/         # SQL injection
│   ├── nikto-mcp/          # Web server scanning (wrapper)
│   ├── ffuf-mcp/           # Web fuzzing
│   └── burp-mcp/           # Burp Suite (wrapper)
├── secrets/
│   └── gitleaks-mcp/       # Secrets detection
├── fuzzing/
│   ├── boofuzz-mcp/        # Network protocol fuzzing using Boofuzz
│   └── dharma-mcp/         # Grammar-based test case generation
├── osint/
│   ├── maigret-mcp/        # Username OSINT (wrapper)
│   └── dnstwist-mcp/       # Typosquatting detection (wrapper)
├── threat-intel/
│   ├── virustotal-mcp/     # Malware analysis (wrapper)
│   └── otx-mcp/            # AlienVault OTX (wrapper)
├── active-directory/
│   └── bloodhound-mcp/     # AD attack paths (wrapper)
├── password-cracking/
│   └── hashcat-mcp/        # Hash cracking (wrapper)
├── meta/
│   └── mcp-scan/           # MCP security scanning
├── scripts/
│   ├── setup.sh            # Quick setup
│   └── healthcheck.sh      # Health verification
├── tests/
│   └── test_mcp_servers.py # Unit tests
├── docker-compose.yml      # Orchestration
└── .github/workflows/      # CI/CD
```

## Testing

```bash
# Run unit tests
pytest tests/ -v

# Build and test all Docker images
./scripts/test_builds.sh

# Test MCP protocol (after building)
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | \
  docker run -i --rm nmap-mcp:latest
```

## Legal & Compliance

**These tools are for authorized security testing only.**

Before using:

1. **Obtain written authorization** from the target owner
2. **Define scope** - targets, timeline, allowed activities
3. **Maintain audit logs** of all operations
4. **Follow responsible disclosure** for any findings

Unauthorized access to computer systems is illegal. Users are responsible for compliance with applicable laws.

## Contributing

Contributions welcome! To add a new MCP server:

1. Use `Dockerfile.template` as your starting point
2. Follow security hardening practices (non-root, minimal image)
3. Include health checks and comprehensive README
4. Ensure Trivy scan passes (no HIGH/CRITICAL vulnerabilities)
5. Add tests to `tests/test_mcp_servers.py`

## Acknowledgments

- [Model Context Protocol](https://modelcontextprotocol.io/) - Protocol specification
- [awesome-mcp-security](https://github.com/Puliczek/awesome-mcp-security) - MCP security catalog
- Upstream tool maintainers: nmap, nuclei, radare2, sqlmap, and all others

## License

MIT License - See [LICENSE](./LICENSE)

---

<p align="center">
  <strong>Maintained by <a href="https://fuzzinglabs.com">FuzzingLabs</a></strong>
  <br>
  <sub>Making AI-powered security testing accessible</sub>
</p>
