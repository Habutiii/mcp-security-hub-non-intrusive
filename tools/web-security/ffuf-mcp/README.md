# ffuf-mcp

Bounded GET discovery with reviewed wordlists.

Gateway component ID: `ffuf`.

## Tools

| Tool | Description |
|---|---|
| `ffuf_dir` | Directory and file discovery fuzzing. Discovers hidden directories, files, and endpoints on web servers. |
| `ffuf_vhost` | Virtual host discovery. Discovers subdomains and virtual hosts by fuzzing the Host header. |
| `ffuf_param` | GET parameter-name discovery only. |
| `list_wordlists` | List available wordlists for fuzzing. |
| `get_fuzz_results` | Retrieve results from a previous fuzzing session by scan ID. |
| `list_active_scans` | List currently running fuzzing sessions. |

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
