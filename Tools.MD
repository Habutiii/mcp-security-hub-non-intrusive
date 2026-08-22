# Tool Inventory and Target-Impact Boundary

`External MCP` means the Docker build or runtime fetches and executes an upstream MCP server, package, or image. It does **not** include ordinary scanner binaries installed by a local MCP implementation. `Can alter target state` means the exposed interface can perform a target-side write/action; active read-only probes and their audit logs are classified as **No**.

| MCP | External MCP used by Docker/runtime? | Can alter target state? | Reason |
| --- | --- | --- | --- |
| `active-directory/bloodhound-mcp` | No | No | Runs the vendored, fixed-query wrapper with Neo4j read access only. |
| `fuzzing/boofuzz-mcp` | No | No | Custom profiles and fuzz-session execution are disabled; it only reports that restriction and stored results. |
| `fuzzing/dharma-mcp` | No | No | Dharma generates test cases locally and has no network-send tool. |
| `meta/mcp-scan` | No | No | It is built from vendored scanner code and assesses MCP configurations rather than the pentest target. |
| `osint/dnstwist-mcp` | No | No | It is built from vendored code and generates lookalike domains plus reconnaissance lookups. |
| `osint/maigret-mcp` | No | No | It is built from vendored code and performs public-profile OSINT lookups only. |
| `password-cracking/hashcat-mcp` | No | No | It performs dictionary-only recovery against locally supplied hash material. |
| `reconnaissance/externalattacker-mcp` | No | No | Runs the restricted vendored entrypoint with fixed discovery commands; the upstream generic command runner is not used. |
| `reconnaissance/masscan-mcp` | No | No | It sends SYN discovery probes only, although an excessive rate can still affect availability. |
| `reconnaissance/networksdb-mcp` | No | No | It is built from vendored code and queries the NetworksDB intelligence API. |
| `reconnaissance/nmap-mcp` | No | Yes | The `script_scan` interface accepts NSE script names, and some NSE scripts can be intrusive or state-changing. |
| `reconnaissance/pd-tools-mcp` | No | No | Runs the restricted vendored entrypoint with bounded discovery only; Nuclei and unrestricted templates are excluded. |
| `reconnaissance/shodan-mcp` | No | No | It is built from vendored code and queries Shodan's existing internet-intelligence data. |
| `reconnaissance/whatweb-mcp` | No | No | It performs HTTP technology fingerprinting; requests can create logs but expose no write controls. |
| `reconnaissance/zoomeye-mcp` | No | No | It is built from vendored code and queries ZoomEye's indexed asset data. |
| `secrets/gitleaks-mcp` | No | No | It scans locally mounted repositories, directories, or supplied text for secrets. |
| `threat-intel/otx-mcp` | No | No | It is built from vendored code and retrieves AlienVault OTX threat-intelligence data. |
| `threat-intel/virustotal-mcp` | No | No | It is built from vendored code and retrieves VirusTotal intelligence. |
| `web-security/burp-mcp` | No | Yes | It is built from vendored code but can issue active user-controlled request workflows through Burp. |
| `web-security/ffuf-mcp` | No | Yes | `ffuf_custom` accepts arbitrary HTTP methods, headers, and request bodies, including state-changing requests. |
| `web-security/nikto-mcp` | No | No | It is built from vendored MCP and Nikto sources and exposes web-server checks only. |
| `web-security/nuclei-mcp` | No | Yes | Its enabled template categories include fuzzing and are not individually restricted to a reviewed non-mutating allowlist. |
| `web-security/sqlmap-mcp` | No | Yes | SQLMap can send database-altering injection payloads; this conflicts with the repository's target-state policy. |
| `web-security/waybackurls-mcp` | No | No | It retrieves historical URLs from the Internet Archive instead of interacting with the target. |

## Required follow-up for `Yes`

`nmap-mcp`, `burp-mcp`, `ffuf-mcp`, `nuclei-mcp`, and `sqlmap-mcp` do not currently meet the target-state restriction. They must be removed, or redesigned behind fixed non-mutating allowlists, before being made agent-callable under the project policy.
