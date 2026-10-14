# sqlmap-mcp

Read existing SQLMap result state only; execution and extraction are disabled.

Gateway component ID: `sqlmap`.

## Tools

| Tool | Description |
|---|---|
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

Capability: `local_read`. Expected target effect:
`none`. See the [capability contract](../../../CAPABILITIES.md).
