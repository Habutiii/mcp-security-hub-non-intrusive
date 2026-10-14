# masscan-mcp

Low-rate scan of a bounded CIDR using a fixed top-port set.

Gateway component ID: `masscan`.

## Tools

| Tool | Description |
|---|---|
| `masscan_scan` | Scan one bounded IP/CIDR on up to 32 selected TCP ports at 1–50 packets per second. |
| `masscan_top_ports` | Scan the top 20 most common ports on target(s). |
| `get_scan_results` | Retrieve results from a previous scan. |
| `list_active_scans` | List running scans. |

Both scan tools accept bounded `rate` and `timeout` options. Targets must be
literal IP addresses or CIDRs no broader than /24 IPv4 or /64 IPv6. Port text
is parsed as a list of TCP numbers/ranges before it becomes one argv value;
raw flags and range syntax outside that grammar are rejected.

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
