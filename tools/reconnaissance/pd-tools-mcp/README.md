# PD-Tools MCP Server

A restricted, vendored implementation based on [pd-tools-mcp](https://github.com/intelligent-ears/pd-tools-mcp). It exposes only bounded, non-mutating ProjectDiscovery discovery operations.

## Included Tools

| Tool | Description |
|------|-------------|
| **subfinder** | Fast passive subdomain enumeration |
| **httpx** | HTTP probing and fingerprinting |
| **katana** | Next-generation web crawler |
| **dnsx** | Fast DNS toolkit |
| **naabu** | Fast port scanner |

## Features

The MCP intentionally excludes Nuclei, unrestricted templates, screenshots, redirects, and the automated bug-bounty workflow. Its tools use fixed options: 20 targets maximum, one concurrent run, 120-second timeout, low HTTP/port-scan rates, a crawl depth of two, and no caller-supplied executable arguments.

The reviewed upstream source is retained in [`vendor/`](./vendor/) for provenance. The restricted runtime is [`server.py`](./server.py); see [`UPSTREAM.md`](./UPSTREAM.md).

## Docker

### Build

```bash
docker build -t pd-tools-mcp .
```

### Run

```bash
docker run --rm -i pd-tools-mcp
```

## Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "pd-tools": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "pd-tools-mcp"]
    }
  }
}
```

## Example Usage

### Subdomain enumeration

```
Find all subdomains of example.com using subfinder
```

### HTTP probing

```
Probe these hosts with httpx to find live web servers
```

### Web crawling

```
Crawl https://example.com with katana to discover endpoints
```

### DNS reconnaissance

```
Resolve DNS records for these domains using dnsx
```

### Port scanning

```
Scan ports on 192.168.1.1 using naabu
```

## Upstream

This is a Docker wrapper for:
- Repository: [intelligent-ears/pd-tools-mcp](https://github.com/intelligent-ears/pd-tools-mcp)
- Tools: [ProjectDiscovery](https://projectdiscovery.io/)

## Security Notice

These tools are designed for authorized, non-destructive security testing only. They generate active discovery traffic and target-side logs, but do not expose database changes, target-side command execution, arbitrary request controls, or arbitrary scanner options.

## License

MIT
