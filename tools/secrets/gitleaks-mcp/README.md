# gitleaks-mcp

Read-only secret scanning of approved local input.

Gateway component ID: `gitleaks`.

## Tools

| Tool | Description |
|---|---|
| `gitleaks_scan_repo` | Scan an approved local Git directory and its history. `timeout` is 1–300 seconds; `max_findings` is 1–50 in the response. |
| `gitleaks_scan_dir` | Scan an approved local directory without Git history. The same bounded options apply. |
| `gitleaks_detect` | Scan supplied text of at most 64,000 characters, with the same bounded response options. Default timeout is 60 seconds. |
| `get_scan_results` | Retrieve a previous scan by ID, optionally including a redacted JSON report. `max_findings` limits summary findings. |
| `list_active_scans` | List currently running scans. |

Directory scans accept absolute paths under `/opt/security-hub` or `/var/lib/security-hub/gitleaks/input` only. Deployments that need a separate local input directory must mount it at the latter path. Path traversal and symlinks escaping these roots are rejected. Gitleaks receives fixed argv without a shell or agent supplied flags. Reports are redacted in memory and the temporary unredacted report file is removed after each scan. No target network requests are made by these tools.

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
