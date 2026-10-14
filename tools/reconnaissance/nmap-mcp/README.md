# nmap-mcp

Reviewed network discovery and fixed NSE catalog.

Gateway component ID: `nmap`.

## Tools

| Tool | Description |
|---|---|
| `port_scan` | Scan ports on a target host or network. Discovers open ports using SYN scan. |
| `service_scan` | Detect service versions on target ports. Identifies software and versions running on open ports. |
| `os_detection` | Fingerprint the operating system of the target. Requires at least one open and one closed port. |
| `script_scan` | Run NSE (Nmap Scripting Engine) scripts against target. Scripts can detect vulnerabilities, gather information, and more. |
| `quick_scan` | Fast scan of the 100 most common ports with service detection. |
| `get_scan_results` | Retrieve results from a previous scan by scan ID. |
| `list_active_scans` | List currently running scans. |

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
