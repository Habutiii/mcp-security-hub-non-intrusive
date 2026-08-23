# Tool Inventory and Target-Impact Boundary

`External MCP` means the Docker build or runtime fetches and executes an upstream MCP server, package, or image. It does **not** include ordinary scanner binaries installed by a local MCP implementation. `Can alter target state` means the exposed interface can perform a target-side write/action; active read-only probes and their audit logs are classified as **No**.

| MCP | External MCP used by Docker/runtime? | Can alter target state? | Reason |
| --- | --- | --- | --- |
| `tools/active-directory/bloodhound-mcp` | No | No | Runs the vendored, fixed-query wrapper with Neo4j read access only. |
| `tools/fuzzing/boofuzz-mcp` | No | No | Custom profiles and fuzz-session execution are disabled; it only reports that restriction and stored results. |
| `tools/fuzzing/dharma-mcp` | No | No | Dharma generates test cases locally and has no network-send tool. |
| `tools/meta/mcp-scan` | No | No | It is built from vendored scanner code and assesses MCP configurations rather than the pentest target. |
| `tools/osint/dnstwist-mcp` | No | No | It is built from vendored code and generates lookalike domains plus reconnaissance lookups. |
| `tools/osint/maigret-mcp` | No | No | It is built from vendored code and performs public-profile OSINT lookups only. |
| `tools/password-cracking/hashcat-mcp` | No | No | It performs dictionary-only recovery against locally supplied hash material. |
| `tools/reconnaissance/externalattacker-mcp` | No | No | Runs the restricted vendored entrypoint with fixed discovery commands; the upstream generic command runner is not used. |
| `tools/reconnaissance/masscan-mcp` | No | No | It sends SYN discovery probes only, although an excessive rate can still affect availability. |
| `tools/reconnaissance/networksdb-mcp` | No | No | It is built from vendored code and queries the NetworksDB intelligence API. |
| `tools/reconnaissance/nmap-mcp` | No | No | `script_scan` accepts only a fixed catalog of reviewed information-gathering NSE scripts; no NSE category or arbitrary script name is exposed. |
| `tools/reconnaissance/pd-tools-mcp` | No | No | Runs the restricted vendored entrypoint with bounded discovery only; Nuclei and unrestricted templates are excluded. |
| `tools/reconnaissance/shodan-mcp` | No | No | It is built from vendored code and queries Shodan's existing internet-intelligence data. |
| `tools/reconnaissance/whatweb-mcp` | No | No | It performs HTTP technology fingerprinting; requests can create logs but expose no write controls. |
| `tools/reconnaissance/zoomeye-mcp` | No | No | It is built from vendored code and queries ZoomEye's indexed asset data. |
| `tools/secrets/gitleaks-mcp` | No | No | It scans locally mounted repositories, directories, or supplied text for secrets. |
| `tools/threat-intel/otx-mcp` | No | No | It is built from vendored code and retrieves AlienVault OTX threat-intelligence data. |
| `tools/threat-intel/virustotal-mcp` | No | No | It is built from vendored code and retrieves VirusTotal intelligence. |
| `tools/web-security/burp-mcp` | No | No | Deliberately disabled: the image no longer builds or exposes the upstream MCP, which has no reviewed non-mutating allowlist. |
| `tools/web-security/ffuf-mcp` | No | No | Only fixed GET directory discovery is exposed; custom methods, request bodies, caller headers, and arbitrary wordlist paths are unavailable. |
| `tools/web-security/nikto-mcp` | No | No | It is built from vendored MCP and Nikto sources and exposes web-server checks only. |
| `tools/web-security/sqlmap-mcp` | No | No | SQLMap execution, enumeration, and extraction are disabled; it exposes stored-result/status tools only. |
| `tools/web-security/waybackurls-mcp` | No | No | It retrieves historical URLs from the Internet Archive instead of interacting with the target. |

## Callable-tool boundaries

This is the authoritative agent-callable boundary. A listed operation may create normal target-side audit logs, but it must not expose a target-side write, an arbitrary command, arbitrary scanner arguments, arbitrary scripts/templates/plugins, or caller-controlled state-changing HTTP requests.

| MCP | Callable tools / boundary |
| --- | --- |
| `tools/active-directory/bloodhound-mcp` | Fixed read-only graph queries only: Domain Admins, Kerberoastable and AS-REP-roastable users, paths to Domain Admin, unconstrained delegation, and GPO permissions. |
| `tools/fuzzing/boofuzz-mcp` | Stored-results and restriction-status operations only. Creating caller Python, custom profiles, and running fuzz sessions are unavailable. |
| `tools/fuzzing/dharma-mcp` | Local grammar-based test-case generation only; it never sends generated values to a target. |
| `tools/meta/mcp-scan` | Local MCP-configuration inspection only. It does not invoke the configuration's servers or execute their commands. |
| `tools/osint/dnstwist-mcp` | Domain permutation generation and public DNS/HTTP reconnaissance only. |
| `tools/osint/maigret-mcp` | Public username/profile lookup only. |
| `tools/password-cracking/hashcat-mcp` | Dictionary-only recovery against locally supplied hashes; no live-service credential attempts. |
| `tools/reconnaissance/externalattacker-mcp` | Fixed discovery operations only. No generic upstream command runner, file targets, arbitrary wordlists, methods, or output paths. |
| `tools/reconnaissance/masscan-mcp` | Bounded SYN port discovery and stored-result/status tools only; no arbitrary scanner arguments. |
| `tools/reconnaissance/networksdb-mcp` | Read-only IP, ASN, DNS, and intelligence API lookups only. |
| `tools/reconnaissance/nmap-mcp` | `port_scan`, `service_scan`, `os_detection`, `quick_scan`, results/status, plus `script_scan` limited to the reviewed `SAFE_NSE_SCRIPTS` catalog. No NSE categories or arbitrary script names. |
| `tools/reconnaissance/pd-tools-mcp` | Fixed Subfinder, DNSx, Naabu, HTTPx, and Katana discovery modes only; no Nuclei or free-form templates. |
| `tools/reconnaissance/shodan-mcp` | Read-only Shodan search, IP, DNS, CPE, and CVE intelligence lookups only. |
| `tools/reconnaissance/whatweb-mcp` | HTTP technology fingerprinting and stored-result/status tools only. |
| `tools/reconnaissance/zoomeye-mcp` | Read-only ZoomEye indexed-intelligence queries only. |
| `tools/secrets/gitleaks-mcp` | Read-only scanning of approved mounted repositories/directories or supplied text, plus stored-result/status tools. |
| `tools/threat-intel/otx-mcp` | Read-only AlienVault OTX intelligence lookups only. |
| `tools/threat-intel/virustotal-mcp` | Read-only reputation/intelligence retrieval for supplied hashes, URLs, domains, and IPs. Submission or upload must not be agent-callable. |
| `tools/web-security/burp-mcp` | No callable tools. The image is deliberately disabled because the upstream interface is not locally constrainable to a reviewed read-only set. |
| `tools/web-security/ffuf-mcp` | `ffuf_dir`, `ffuf_vhost`, `ffuf_param`, `list_wordlists`, results/status only. Every request is GET; vhost uses an internally generated Host header from a validated hostname; parameter discovery requires `FUZZ`; wordlists and extensions come from fixed catalogs. |
| `tools/web-security/nikto-mcp` | Fixed web-server checks only; no generic command or plugin selection interface. |
| `tools/web-security/sqlmap-mcp` | Stored-result and status operations only. Injection testing, enumeration, dumping, request bodies, cookies, and DBMS options are unavailable. |
| `tools/web-security/waybackurls-mcp` | Historical URL retrieval and stored-result/status tools only. |

`tools/web-security/nuclei-mcp` has been removed. It has no callable tools or Compose service.

## Gateway lifecycle boundary

The single-endpoint gateway uses the registered MCP identifiers in
this document as its only lifecycle inputs. It starts a child container lazily
on the first tool call. The agent may prewarm an approved tool for anticipated
use, which starts local resources only and must not create target traffic. The
agent may shut down an idle, no-longer-needed tool to release resources; the
gateway must refuse to stop a child with active work. Gateway exit must
gracefully stop and remove every child it started.

The gateway's own callable controls are `gateway_list_components`,
`gateway_prewarm`, `gateway_shutdown`, `gateway_list_component_tools`, and
`gateway_call`. The final control validates a child tool name against the
initialized child MCP's advertised tool list; lifecycle controls accept only
the fixed registry identifiers.

## Execution controls

The interfaces above use positive capability sets. Nmap and FFUF expose only reviewed non-mutating operations; SQLMap does not expose execution; and the Burp wrapper is deliberately disabled. Re-enabling any removed or disabled capability requires a reviewed, pinned allowlist rather than a denylist.
