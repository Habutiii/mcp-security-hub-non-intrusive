# Deliberately disabled. The upstream Burp MCP exposes active scans, Repeater,
# and Intruder without a local, reviewed non-mutating allowlist.
FROM alpine:3.20
CMD ["sh", "-c", "echo 'burp-mcp is disabled by the non-intrusive policy' >&2; exit 1"]
