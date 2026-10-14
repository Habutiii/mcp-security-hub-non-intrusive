# ffuf-mcp

Bounded GET discovery with reviewed wordlists.

The three scanning tools accept typed MCP options for `match_codes`,
`filter_codes`, `filter_size`, `filter_words`, and `filter_lines` to select
or hide responses. `ffuf_dir` also accepts reviewed `extensions`. The
`threads` option is limited to 1–40, `rate` to 1–100 requests per second,
and `timeout` to 1–600 seconds. If omitted, the rate defaults to the bounded
deployment setting (one request per second when unset). Agent values are validated
before they are passed as individual ffuf arguments. Free-form flags, request
bodies, HTTP methods, headers, and wordlist paths are not accepted.

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
