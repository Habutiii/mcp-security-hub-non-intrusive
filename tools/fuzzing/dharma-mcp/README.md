# dharma-mcp

Generate test cases locally; never sends them.

Gateway component ID: `dharma`.

## Tools

| Tool | Description |
|---|---|
| `dharma_generate` | Generate test cases using a Dharma grammar file located on the server. |
| `dharma_generate_custom` | Generate test cases from a custom Dharma grammar provided as a string. Useful for dynamically generated grammars or quick testing without saving files. |

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
