# gitleaks-mcp

Read-only secret scanning of approved local input.

Gateway component ID: `gitleaks`.

## Tools

| Tool | Description |
|---|---|
| `gitleaks_scan_repo` | Scan a git repository for secrets and credentials. Analyzes commit history for leaked API keys, passwords, tokens, etc. |
| `gitleaks_scan_dir` | Scan a directory for secrets without git history analysis. Useful for scanning non-git directories or specific folders. |
| `gitleaks_detect` | Quick scan provided content (text/code) for secrets. Useful for checking config files, environment variables, etc. |
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
