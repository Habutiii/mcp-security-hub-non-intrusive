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
| `reconnaissance/nmap-mcp` | No | No | `script_scan` accepts only a fixed catalog of reviewed information-gathering NSE scripts; no NSE category or arbitrary script name is exposed. |
| `reconnaissance/pd-tools-mcp` | No | No | Runs the restricted vendored entrypoint with bounded discovery only; Nuclei and unrestricted templates are excluded. |
| `reconnaissance/shodan-mcp` | No | No | It is built from vendored code and queries Shodan's existing internet-intelligence data. |
| `reconnaissance/whatweb-mcp` | No | No | It performs HTTP technology fingerprinting; requests can create logs but expose no write controls. |
| `reconnaissance/zoomeye-mcp` | No | No | It is built from vendored code and queries ZoomEye's indexed asset data. |
| `secrets/gitleaks-mcp` | No | No | It scans locally mounted repositories, directories, or supplied text for secrets. |
| `threat-intel/otx-mcp` | No | No | It is built from vendored code and retrieves AlienVault OTX threat-intelligence data. |
| `threat-intel/virustotal-mcp` | No | No | It is built from vendored code and retrieves VirusTotal intelligence. |
| `web-security/burp-mcp` | No | No | Deliberately disabled: the image no longer builds or exposes the upstream MCP, which has no reviewed non-mutating allowlist. |
| `web-security/ffuf-mcp` | No | No | Only fixed GET directory discovery is exposed; custom methods, request bodies, caller headers, and arbitrary wordlist paths are unavailable. |
| `web-security/nikto-mcp` | No | No | It is built from vendored MCP and Nikto sources and exposes web-server checks only. |
| `web-security/sqlmap-mcp` | No | No | SQLMap execution, enumeration, and extraction are disabled; it exposes stored-result/status tools only. |
| `web-security/waybackurls-mcp` | No | No | It retrieves historical URLs from the Internet Archive instead of interacting with the target. |

## Callable-tool boundaries

This is the authoritative agent-callable boundary. A listed operation may create normal target-side audit logs, but it must not expose a target-side write, an arbitrary command, arbitrary scanner arguments, arbitrary scripts/templates/plugins, or caller-controlled state-changing HTTP requests.

| MCP | Callable tools / boundary |
| --- | --- |
| `active-directory/bloodhound-mcp` | Fixed read-only graph queries only: Domain Admins, Kerberoastable and AS-REP-roastable users, paths to Domain Admin, unconstrained delegation, and GPO permissions. |
| `fuzzing/boofuzz-mcp` | Stored-results and restriction-status operations only. Creating caller Python, custom profiles, and running fuzz sessions are unavailable. |
| `fuzzing/dharma-mcp` | Local grammar-based test-case generation only; it never sends generated values to a target. |
| `meta/mcp-scan` | Local MCP-configuration inspection only. It does not invoke the configuration's servers or execute their commands. |
| `osint/dnstwist-mcp` | Domain permutation generation and public DNS/HTTP reconnaissance only. |
| `osint/maigret-mcp` | Public username/profile lookup only. |
| `password-cracking/hashcat-mcp` | Dictionary-only recovery against locally supplied hashes; no live-service credential attempts. |
| `reconnaissance/externalattacker-mcp` | Fixed discovery operations only. No generic upstream command runner, file targets, arbitrary wordlists, methods, or output paths. |
| `reconnaissance/masscan-mcp` | Bounded SYN port discovery and stored-result/status tools only; no arbitrary scanner arguments. |
| `reconnaissance/networksdb-mcp` | Read-only IP, ASN, DNS, and intelligence API lookups only. |
| `reconnaissance/nmap-mcp` | `port_scan`, `service_scan`, `os_detection`, `quick_scan`, results/status, plus `script_scan` limited to the reviewed `SAFE_NSE_SCRIPTS` catalog. No NSE categories or arbitrary script names. |
| `reconnaissance/pd-tools-mcp` | Fixed Subfinder, DNSx, Naabu, HTTPx, and Katana discovery modes only; no Nuclei or free-form templates. |
| `reconnaissance/shodan-mcp` | Read-only Shodan search, IP, DNS, CPE, and CVE intelligence lookups only. |
| `reconnaissance/whatweb-mcp` | HTTP technology fingerprinting and stored-result/status tools only. |
| `reconnaissance/zoomeye-mcp` | Read-only ZoomEye indexed-intelligence queries only. |
| `secrets/gitleaks-mcp` | Read-only scanning of approved mounted repositories/directories or supplied text, plus stored-result/status tools. |
| `threat-intel/otx-mcp` | Read-only AlienVault OTX intelligence lookups only. |
| `threat-intel/virustotal-mcp` | Read-only reputation/intelligence retrieval for supplied hashes, URLs, domains, and IPs. Submission or upload must not be agent-callable. |
| `web-security/burp-mcp` | No callable tools. The image is deliberately disabled because the upstream interface is not locally constrainable to a reviewed read-only set. |
| `web-security/ffuf-mcp` | `ffuf_dir`, `ffuf_vhost`, `ffuf_param`, `list_wordlists`, results/status only. Every request is GET; vhost uses an internally generated Host header from a validated hostname; parameter discovery requires `FUZZ`; wordlists and extensions come from fixed catalogs. |
| `web-security/nikto-mcp` | Fixed web-server checks only; no generic command or plugin selection interface. |
| `web-security/sqlmap-mcp` | Stored-result and status operations only. Injection testing, enumeration, dumping, request bodies, cookies, and DBMS options are unavailable. |
| `web-security/waybackurls-mcp` | Historical URL retrieval and stored-result/status tools only. |

`web-security/nuclei-mcp` has been removed. It has no callable tools or Compose service.

## Execution controls

The interfaces above use positive capability sets. Nmap and FFUF expose only reviewed non-mutating operations; SQLMap does not expose execution; and the Burp wrapper is deliberately disabled. Re-enabling any removed or disabled capability requires a reviewed, pinned allowlist rather than a denylist.
