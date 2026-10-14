# masscan-mcp

Low-rate scan of a bounded CIDR using a fixed top-port set.

Gateway component ID: `masscan`.

## Tools

| Tool | Description |
|---|---|
| `masscan_top_ports` | Scan the top 20 most common ports on target(s). |
| `get_scan_results` | Retrieve results from a previous scan. |
| `list_active_scans` | List running scans. |

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
