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

- **One AGW image** containing the reviewed, non-intrusive MCP implementations
- **Lazy local tool processes** so the gateway is warm while unused tools consume no process resources
- **Production Hardened** - non-root execution, fixed capability registry, and Trivy-scannable image
- **CI/CD Ready** with GitHub Actions for automated builds and security scanning

## Operating Policy

This project supports authorized, **non-destructive** security assessment. Active reconnaissance and detection scans are allowed even when they create normal target-side audit logs. The boundary is that an MCP tool must not be able to alter the analyzed target's state or escape its intended operation.

- Allowed: scoped port and service discovery, HTTP fingerprinting and crawling, DNS enumeration, read-only vulnerability checks, and local payload generation.
- Not allowed for agent use: changing database content, writing or deleting files, creating or changing accounts, modifying configuration, deploying payloads, or executing commands on a target.
- A tool must not expose arbitrary shell arguments, arbitrary code/script execution, or an unrestricted template/plugin selection mechanism.
- High-risk or state-changing actions remain a human responsibility, performed outside this MCP collection after explicit authorization.

See [Tool Use Principles](./TOOL-USE-PRINCIPLES.md) for the mandatory restrictions for existing and new MCP servers.
For an external agent orchestrator, see the [capability contract](./CAPABILITIES.md) and reusable [skills](./skills/). The gateway exposes reviewed labels through `gateway_list_capabilities` and rejects child-tool drift.

### Orchestrator safety boundary

For agentic use, connect the orchestrator **only** to the single gateway endpoint.
The gateway is the enforcement point for the reviewed component and tool set;
connecting directly to an individual MCP implementation bypasses capability labels and
schema-drift detection. The orchestrator must enforce immutable target scope
and call limits before dispatch. Follow the [skills integration guide](./skills/README.md).

## Quick Start

```bash
# Clone the repository
git clone https://github.com/FuzzingLabs/mcp-security-hub
cd mcp-security-hub

# Build the single gateway image once, ahead of use.
docker compose build

# Run the warmed gateway. It starts an approved MCP process only on demand.
docker run -i --rm \
  --read-only --tmpfs /tmp:rw,size=128m --tmpfs /var/lib/security-hub:rw,size=512m \
  --cap-drop=ALL --security-opt=no-new-privileges \
  -e AGW_ALLOWED_TARGETS=example.com,10.10.0.0/16 security-hub-agw:latest
```

The gateway uses standard input/output, so do not start it with `docker compose
up -d`: detached Compose closes stdin and it exits. Keep a single gateway
container running for the MCP client session.

### Configure an MCP client

Build the image before using it, then configure the gateway as the only MCP
endpoint. It enforces the reviewed capability contract and scope labels.

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "security-hub": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--read-only", "--tmpfs", "/tmp:rw,size=128m", "--tmpfs", "/var/lib/security-hub:rw,size=512m", "--cap-drop=ALL", "--security-opt=no-new-privileges", "-e", "AGW_ALLOWED_TARGETS=example.com,10.10.0.0/16", "security-hub-agw:latest"]
    }
  }
}
```

For project-level config, copy `.mcp.json` to your project root.

### Single, warmed gateway endpoint

The [security-hub AGW](./gateway-mcp/) is the only image to build and the only
MCP endpoint to configure. It advertises registered components immediately and
starts a local child process lazily on its first call; by default it keeps every
started process warm for the remainder of the gateway session. Multiple tool
processes can run concurrently. No Docker socket is mounted.
Target-facing calls require an explicit `AGW_ALLOWED_TARGETS` allowlist; wildcard
scope (`*`, `0.0.0.0/0`, or `::/0`) is rejected. See [future work](./FUTURE-TASKS.md)
for the optional screening-agent stage.

An orchestrator starts by calling `gateway_list_capabilities`, then loads the
relevant skill and may use only the exact component/tool bindings returned.

## Available MCP Servers

### Reconnaissance (8 servers)

| Server | Tools | Description |
|--------|-------|-------------|
| [nmap-mcp](./tools/reconnaissance/nmap-mcp) | 8 | Port scanning, service detection, OS fingerprinting, NSE scripts |
| [shodan-mcp](./tools/reconnaissance/shodan-mcp) | - | Wrapper for [official Shodan MCP](https://github.com/BurtTheCoder/mcp-shodan) |
| [pd-tools-mcp](./tools/reconnaissance/pd-tools-mcp) | 5 | AGW-owned bounded ProjectDiscovery discovery adapter (subfinder, dnsx, naabu, httpx, katana) |
| [whatweb-mcp](./tools/reconnaissance/whatweb-mcp) | 5 | Web technology fingerprinting and CMS detection |
| [masscan-mcp](./tools/reconnaissance/masscan-mcp) | 6 | High-speed port scanning for large networks |
| [zoomeye-mcp](./tools/reconnaissance/zoomeye-mcp) | - | Wrapper for [ZoomEye MCP](https://github.com/zoomeye-ai/mcp_zoomeye) - Cyberspace search engine |
| [networksdb-mcp](./tools/reconnaissance/networksdb-mcp) | 4 | IP/ASN/DNS lookups via [NetworksDB](https://github.com/MorDavid/NetworksDB-MCP) |
| [externalattacker-mcp](./tools/reconnaissance/externalattacker-mcp) | 5 | AGW-owned bounded external attack-surface discovery adapter |

### Web Security (6 servers)

| Server | Tools | Description |
|--------|-------|-------------|
| [sqlmap-mcp](./tools/web-security/sqlmap-mcp) | 2 | Disabled execution; stored-result and status tools only |
| `nikto-observer-mcp` | 2 | AGW-owned fixed-function observer backed by a pinned Nikto scanner binary |
| [ffuf-mcp](./tools/web-security/ffuf-mcp) | 9 | Web fuzzing for directories, files, parameters, and virtual hosts |
| [waybackurls-mcp](./tools/web-security/waybackurls-mcp) | 3 | Fetch historical URLs from Wayback Machine for reconnaissance |
| [burp-mcp](./tools/web-security/burp-mcp) | - | Wrapper for [official Burp Suite MCP](https://github.com/PortSwigger/mcp-server) |

### Secrets Detection (1 server)

| Server | Tools | Description |
|--------|-------|-------------|
| [gitleaks-mcp](./tools/secrets/gitleaks-mcp) | 5 | Find secrets and credentials in git repos and files |

### Fuzzing (2 servers)

| Server | Tools | Description |
|--------|-------|-------------|
| [boofuzz-mcp](./tools/fuzzing/boofuzz-mcp) | 4 | Network protocol fuzzing using Boofuzz |
| [dharma-mcp](./tools/fuzzing/dharma-mcp) | 2 | Grammar-based test case generation |

### OSINT (2 servers)

| Server | Tools | Description |
|--------|-------|-------------|
| [maigret-mcp](./tools/osint/maigret-mcp) | - | Wrapper for [mcp-maigret](https://github.com/BurtTheCoder/mcp-maigret) - Username OSINT across 2500+ sites |
| [dnstwist-mcp](./tools/osint/dnstwist-mcp) | - | Wrapper for [mcp-dnstwist](https://github.com/BurtTheCoder/mcp-dnstwist) - Typosquatting/phishing detection |

### Threat Intelligence (2 servers)

| Server | Tools | Description |
|--------|-------|-------------|
| [virustotal-mcp](./tools/threat-intel/virustotal-mcp) | - | Wrapper for [mcp-virustotal](https://github.com/BurtTheCoder/mcp-virustotal) - Malware analysis and threat intel |
| [otx-mcp](./tools/threat-intel/otx-mcp) | - | Wrapper for [OTX MCP](https://github.com/mrwadams/otx-mcp) - AlienVault Open Threat Exchange |

### Active Directory (1 server)

| Server | Tools | Description |
|--------|-------|-------------|
| [bloodhound-mcp](./tools/active-directory/bloodhound-mcp) | 75+ | Wrapper for [BloodHound-MCP-AI](https://github.com/MorDavid/BloodHound-MCP-AI) - AD attack path analysis |

### Password Cracking (1 server)

| Server | Tools | Description |
|--------|-------|-------------|
| [hashcat-mcp](./tools/password-cracking/hashcat-mcp) | 1 | Dictionary-only, authorized password recovery using a pinned, bundled SecLists wordlist |

### Meta (1 server)

| Server | Tools | Description |
|--------|-------|-------------|
| [mcp-scan](./tools/meta/mcp-scan) | - | Wrapper for [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) - Scan MCP servers for vulnerabilities |

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
| **Fixed dispatcher** | Agent input cannot select executable paths or arguments |
| **Capability contract** | Only positive, reviewed component/tool bindings are exposed |
| **Dropped capabilities** | `cap_drop: ALL`; add `NET_RAW` only when required for Nmap |
| **No privilege escalation** | `security_opt: no-new-privileges:true` |
| **Read-only root filesystem** | Compose uses tmpfs for temporary and result data |
| **Vulnerability scanning** | Trivy scans in CI/CD pipeline |

## Project Structure

```text
mcp-security-hub/
+-- Dockerfile                # single AGW image and reviewed tool binaries
+-- gateway-mcp/              # fixed-registry local-process MCP gateway
+-- tools/                    # source; only reviewed implementations are copied into AGW
+-- tests/                    # unit and gateway contract tests
`-- docker-compose.yml        # single AGW image build/run settings
```

## Testing
```bash
# Run unit tests
pytest tests/ -v

# Build the single image
docker compose build

# Test MCP protocol (after building)
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | \
  docker run -i --rm security-hub-agw:latest
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
- Upstream tool maintainers: nmap, radare2, sqlmap, and all others

## License

MIT License - See [LICENSE](./LICENSE)

---

<p align="center">
  <strong>Maintained by <a href="https://fuzzinglabs.com">FuzzingLabs</a></strong>
  <br>
  <sub>Making AI-powered security testing accessible</sub>
</p>
