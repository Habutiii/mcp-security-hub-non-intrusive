# Security Hub: local MCP tools behind one gateway

This repository builds one Docker image containing 13 locally maintained MCP
servers. The gateway is the only endpoint for an agent. It starts a tool process
on demand, checks its advertised tool names against a fixed registry, and
applies deployment-owned target scope before target-facing calls.

The operating policy permits authorized, bounded observation and local review.
It excludes target writes, arbitrary commands, caller-supplied scripts, and
unrestricted scanners. See [Tool Use Principles](./TOOL-USE-PRINCIPLES.md) and
the [capability contract](./CAPABILITIES.md).

## Build and connect

```bash
docker compose build
docker run -i --rm --read-only \
  --tmpfs /tmp:rw,size=128m --tmpfs /var/lib/security-hub:rw,size=512m \
  --cap-drop=ALL --security-opt=no-new-privileges \
  -e AGW_ALLOWED_TARGETS=example.com,10.10.0.0/16 \
  security-hub-agw:latest
```

Use the gateway as the sole MCP endpoint; see [client examples](./examples/).
Keep stdin open for the MCP session. `docker compose up -d` closes stdin and
does not keep this stdio gateway running. Target-facing tools require an
explicit `AGW_ALLOWED_TARGETS` list. Wildcard scope is rejected. Nmap and
Masscan additionally require `AGW_RAW_NETWORK_ENABLED=true` and a deployment
that supplies only the `NET_RAW` capability.

## Tool switches

The complete local component and tool registry is in
[`gateway-mcp/capability_policy.py`](./gateway-mcp/capability_policy.py).
[`tool_setting.ini`](./tool_setting.ini) has one Boolean switch for each entry.
Set a component or tool to `false` and restart the gateway to hide and block it.
The file is copied into the image during build. For deployment-specific settings,
mount a reviewed copy read-only at `/opt/security-hub/tool_setting.ini`.

```bash
docker run -i --rm --read-only \
  --tmpfs /tmp:rw,size=128m --tmpfs /var/lib/security-hub:rw,size=512m \
  --cap-drop=ALL --security-opt=no-new-privileges \
  -v /absolute/path/tool_setting.ini:/opt/security-hub/tool_setting.ini:ro \
  -e AGW_ALLOWED_TARGETS=example.com security-hub-agw:latest
```

Switches only remove reviewed capabilities. They cannot add new commands,
bypass scope, or enable raw network privileges. At startup, unknown, missing,
or malformed settings are rejected.

## Available MCP servers

These 13 servers are implemented in this repository and packaged in the one
gateway image. The 46 tool bindings below are the reviewed gateway surface;
individual switches can reduce the active set.

### Reconnaissance (5 servers)

| Server | Tools | Description |
|---|---:|---|
| [nmap-mcp](./tools/reconnaissance/nmap-mcp) | 7 | Scoped port and service observation with fixed NSE scripts |
| [pd-tools-mcp](./tools/reconnaissance/pd-tools-mcp) | 5 | Bounded ProjectDiscovery discovery adapter |
| [whatweb-mcp](./tools/reconnaissance/whatweb-mcp) | 3 | HTTP technology fingerprinting |
| [masscan-mcp](./tools/reconnaissance/masscan-mcp) | 3 | Bounded top-port scanning and result access |
| [externalattacker-mcp](./tools/reconnaissance/externalattacker-mcp) | 5 | Bounded external attack-surface observation |

### Web Security (4 servers)

| Server | Tools | Description |
|---|---:|---|
| [sqlmap-mcp](./tools/web-security/sqlmap-mcp) | 2 | Stored-result and status access only; SQLMap execution is disabled |
| [nikto-observer-mcp](./tools/web-security/nikto-observer-mcp) | 2 | Fixed Nikto observation checks and result access |
| [ffuf-mcp](./tools/web-security/ffuf-mcp) | 6 | Bounded GET discovery with fixed wordlists |
| [waybackurls-mcp](./tools/web-security/waybackurls-mcp) | 3 | Historical URL retrieval and result access |

### Secrets Detection (1 server)

| Server | Tools | Description |
|---|---:|---|
| [gitleaks-mcp](./tools/secrets/gitleaks-mcp) | 5 | Local secret scanning and result access |

### Fuzzing (2 servers)

| Server | Tools | Description |
|---|---:|---|
| [boofuzz-mcp](./tools/fuzzing/boofuzz-mcp) | 2 | Stored-result and script-list access; fuzzer execution is disabled |
| [dharma-mcp](./tools/fuzzing/dharma-mcp) | 2 | Local grammar-based test case generation |

### Password Cracking (1 server)

| Server | Tools | Description |
|---|---:|---|
| [hashcat-mcp](./tools/password-cracking/hashcat-mcp) | 1 | Local dictionary recovery using the bundled wordlist |

## Agent use

Call `gateway_list_capabilities` first, then
`gateway_list_component_tools` for a selected component, then `gateway_call`.
Disabled entries are absent from discovery and blocked at dispatch. The
orchestrator must establish authorization, enforce engagement limits, and
record evidence as described in [skills/README.md](./skills/README.md).
Connecting directly to a child process bypasses the gateway policy.

## Verification

```bash
pytest tests/ -v
docker compose build
```

[AGW CI](./.github/workflows/agw-ci.yml) runs tests, builds the image, and
scans it for high and critical vulnerabilities. The code and bundled assets
are root-owned; runtime processes use an unprivileged account and a dedicated
temporary data directory.

## License

MIT. See [LICENSE](./LICENSE).
