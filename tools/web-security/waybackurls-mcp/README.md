# waybackurls-mcp

Retrieve historical URLs from the archive, not the target.

Gateway component ID: `waybackurls`.

## Tools

| Tool | Description |
|---|---|
| `fetch_wayback_urls` | Fetch all URLs from the Wayback Machine for a given domain. Returns historical URLs that were archived for the domain. |
| `get_fetch_results` | Retrieve results from a previous waybackurls fetch by fetch ID. |
| `list_active_fetches` | List currently running waybackurls fetches. |

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

Capability: `passive_intelligence`. Expected target effect:
`none`. See the [capability contract](../../../CAPABILITIES.md).
