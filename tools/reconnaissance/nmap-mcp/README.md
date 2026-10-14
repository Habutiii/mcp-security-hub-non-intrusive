# nmap-mcp

Reviewed network discovery and fixed NSE catalog.

Gateway component ID: `nmap`.

## Tools

| Tool | Description |
|---|---|
| `port_scan` | Scan ports on a target host or network. Discovers open ports using SYN scan. |
| `service_scan` | Detect service versions on target ports. Identifies software and versions running on open ports. |
| `os_detection` | Fingerprint the operating system of the target. Requires at least one open and one closed port. |
| `script_scan` | Run up to four reviewed information-gathering NSE scripts. |
| `quick_scan` | Fast scan of the 100 most common ports with service detection. |
| `get_scan_results` | Retrieve results from a previous scan by scan ID. |
| `list_active_scans` | List currently running scans. |

## Agent-selectable options

Scan calls accept separate, typed fields. `target` is a hostname, IP address, or
CIDR covering no more than 256 addresses. `ports` accepts TCP port numbers and
ascending ranges such as `22,80-82`, covering at most 1024 ports; it is not
available for `quick_scan`. All scan calls accept `timing` (0–3), `timeout`
(10–600 seconds), `max_rate` (1–50 packets per second), `max_retries` (0–2),
`show_reasons` (boolean), and `open_only` (boolean). `service_scan` and
`quick_scan` also accept `version_intensity` (0–5). Defaults are timing 3,
timeout 300 seconds (120 for quick scans), max rate 25, one retry, and version
intensity 3. `script_scan` accepts one to four names from its fixed NSE catalog.

Inputs are checked again when a call executes. The server constructs a fixed
argument vector for Nmap and places `--` before the validated target. Arbitrary
flags, NSE categories, script arguments, and broad CIDRs are not accepted.

## Use through the gateway

Build the single image from the repository root with `docker compose build`.
Connect the MCP client only to `security-hub-agw:latest` using the
[client examples](../../../examples/). Call `gateway_list_capabilities`,
`gateway_list_component_tools`, and then `gateway_call` with this
component ID and one of the listed tool names.

The component and each tool can be disabled in
[`tool_setting.ini`](../../../tool_setting.ini). Settings are read when
the gateway starts. Direct child connections bypass gateway policy.

Target-facing calls require the deployment-owned `AGW_ALLOWED_TARGETS`
scope. Local result and status queries do not require a target.

Raw-network operations additionally require `AGW_RAW_NETWORK_ENABLED=true`
and `NET_RAW` supplied by the deployment.

Capability: `bounded_observation`. Expected target effect:
`audit_logs_only`. See the [capability contract](../../../CAPABILITIES.md).
