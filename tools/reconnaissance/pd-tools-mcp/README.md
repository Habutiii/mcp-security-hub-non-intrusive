# pd-tools-mcp

Bounded ProjectDiscovery reconnaissance operations.

Gateway component ID: `pd_tools`.

## Tools

| Tool | Description |
|---|---|
| `pd_subfinder` | Passive subdomain discovery with `rate_limit` (1–10 requests/sec, default 5). |
| `pd_dns_resolve` | Resolve at most 20 supplied hosts. Choose `record_types` from A, AAAA, CNAME, MX, NS, TXT, SOA, CAA; set `rate_limit` (1–50, default 20) and `threads` (1–10, default 5). AXFR is excluded. |
| `pd_port_scan` | Scan up to 20 TCP ports on up to 20 hosts. Set `rate_limit` (1–100, default 50) and `concurrency` (1–10, default 5). |
| `pd_http_probe` | Probe up to 20 HTTP(S) URLs. Set `rate_limit` and `threads` (each 1–10, default 5); choose boolean `status_code`, `title`, `tech_detect`, `content_length`, and `web_server` metadata fields. |
| `pd_crawl` | Crawl up to 20 HTTP(S) URLs within each supplied host. Set `depth` (1–3, default 2), `rate_limit`, `concurrency`, and `parallelism` (each 1–10, default 5). |

All options are typed MCP fields, validated again at execution, and mapped to fixed argv elements without a shell. Target text is supplied as a single validated argument or newline-delimited stdin. URL inputs cannot contain credentials, fragments, queries, whitespace, or control characters. Arbitrary flags, request methods, headers, bodies, templates, and HTTP probe redirects are unavailable. Crawling follows discovered links on the supplied host; as with any GET request, a poorly designed target application could still have a side effect.

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
