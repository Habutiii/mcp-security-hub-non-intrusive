# externalattacker-mcp

Fixed, low-rate attack-surface discovery.

Gateway component ID: `externalattacker`.

## Tools

| Tool | Description |
|---|---|
| `discover_subdomains` | Passive subdomain discovery for one authorized domain. |
| `scan_ports` | Low-rate TCP port discovery on one host. Port list is fixed to 80 and 443. |
| `analyze_http` | Bounded HTTP(S) technology and response metadata probe. Custom requests are unavailable. |
| `check_cdn` | Identify the CDN serving one domain. |
| `analyze_tls` | Read TLS certificate and protocol metadata from one host and optional port. |

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
