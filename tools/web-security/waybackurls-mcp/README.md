# waybackurls-mcp

Retrieve historical URLs from the archive, not the target.

Gateway component ID: `waybackurls`.

## Tools

| Tool | Description |
|---|---|
| `fetch_wayback_urls` | Fetch all URLs from the Wayback Machine for a given domain. Returns historical URLs that were archived for the domain. |
| `get_fetch_results` | Retrieve results from a previous waybackurls fetch by fetch ID. |
| `list_active_fetches` | List currently running waybackurls fetches. |

## Options and limits

`fetch_wayback_urls` accepts a plain hostname or IP in `domain` (no URL,
whitespace, line break, or command text). The binary receives this value on
stdin. Its only selectable flags are `get_subs`, `no_subs`, and `dates`, each a
boolean; `get_subs` and `no_subs` cannot be combined. The timeout is 5–600
seconds. `unique_urls` removes duplicate archive records and `https_only`
selects archived HTTPS URLs locally, without contacting those URLs. At most
10,000 selected records are retained from one fetch.

Both `fetch_wayback_urls` and `get_fetch_results` accept `include_urls` as a
boolean and `limit` from 1 to 1000 to bound the URLs returned in one response.
The default limit is 100. Agent supplied values are checked when the call runs;
arbitrary flags are rejected.

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
