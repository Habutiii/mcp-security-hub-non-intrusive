# ExternalAttacker MCP Server

Restricted, vendored implementation based on [MorDavid/ExternalAttacker-MCP](https://github.com/MorDavid/ExternalAttacker-MCP). It supports non-mutating external attack-surface discovery only.

## Features

- Subdomain discovery with subfinder
- Port scanning with naabu
- HTTP analysis with httpx
- CDN detection with cdncheck
- TLS analysis with tlsx

## Tools

| Tool | Description |
|------|-------------|
| discover_subdomains | Find subdomains for a target domain |
| scan_ports | Scan for open ports on targets |
| analyze_http | Analyze HTTP responses and headers |
| check_cdn | Detect CDN providers |
| analyze_tls | Analyze TLS certificates |

## Usage

### Docker

```bash
docker build -t externalattacker-mcp .
docker run -i --rm externalattacker-mcp
```

### Claude Desktop

```json
{
  "mcpServers": {
    "externalattacker": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "externalattacker-mcp:latest"]
    }
  }
}
```

## Restrictions

The upstream generic command runner and updater are not part of the runtime. Endpoint fuzzing, Gobuster modes, Nuclei, file inputs, custom wordlists, methods, resolvers, thread counts, and output paths are not exposed. Ports are fixed to 80 and 443, while HTTP and port scanning use fixed low rates.

The reviewed upstream source is retained in [`vendor/`](./vendor/) for provenance. The restricted runtime is [`server.py`](./server.py); see [`UPSTREAM.md`](./UPSTREAM.md).

## Security Notice

Use only for authorized, non-destructive reconnaissance. Active discovery traffic and scan logs are expected, but no target state-changing capability is exposed.

## License

MIT
