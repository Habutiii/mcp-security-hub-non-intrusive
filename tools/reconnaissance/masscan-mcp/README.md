# Masscan MCP Server

Fast port scanning using [masscan](https://github.com/robertdavidgraham/masscan).

## Tools

| Tool | Description |
|------|-------------|
| `masscan_scan` | Fast port scan on targets |
| `masscan_top_ports` | Scan top 20 common ports |
| `get_scan_results` | Retrieve previous scan |
| `list_active_scans` | Show running scans |

## Features

- Scan millions of hosts per minute
- Asynchronous transmission
- TCP SYN scanning
- Banner grabbing support

## Docker

```bash
docker build -t masscan-mcp .
# Requires NET_RAW capability
docker run --rm -i --cap-add=NET_RAW masscan-mcp
```

## Example Usage

```
Scan 10.0.0.0/24 for ports 80, 443, and 22
```

## Security Notice

Masscan can generate significant network traffic. Use responsibly.

## License

MIT
