# SQLMap MCP Server (Execution Disabled)

SQLMap execution is deliberately disabled by this repository's non-intrusive policy.

## Tools

| Tool | Description |
|------|-------------|
| `get_scan_results` | Retrieve previous results |
| `list_active_scans` | Show running scans |

## Usage

### Docker

```bash
docker build -t sqlmap-mcp .
docker run -it --rm sqlmap-mcp
```

### Claude Desktop

```json
{
  "mcpServers": {
    "sqlmap": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "sqlmap-mcp:latest"]
    }
  }
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SQLMAP_OUTPUT_DIR` | `/app/output` | Directory for scan output |
| `SQLMAP_TIMEOUT` | `300` | Default scan timeout (seconds) |
| `SQLMAP_MAX_CONCURRENT` | `2` | Max concurrent scans |
| `SQLMAP_LEVEL` | `1` | Default test level (1-5) |
| `SQLMAP_RISK` | `1` | Default risk level (1-3) |

## Security Notice

Injection testing, database enumeration, and data extraction are not callable.
This MCP only exposes stored-result and status operations.

## License

MIT
