# nikto-observer-mcp

Fixed read-only Nikto observation checks.

Gateway component ID: `nikto`.

## Tools

| Tool | Description |
|---|---|
| `nikto_observe` | Run fixed read-only Nikto checks for files, configuration, disclosure, and software identification. |
| `nikto_get_result` | Retrieve a stored Nikto observation result. |

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

Capability: `bounded_observation`. Expected target effect:
`audit_logs_only`. See the [capability contract](../../../CAPABILITIES.md).
