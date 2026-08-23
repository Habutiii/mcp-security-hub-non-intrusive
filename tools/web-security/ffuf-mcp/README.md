# FFUF MCP Server

A Model Context Protocol server that provides web fuzzing capabilities using [ffuf](https://github.com/ffuf/ffuf) (Fuzz Faster U Fool).

## Tools

| Tool | Description |
|------|-------------|
| `ffuf_dir` | Directory and file discovery fuzzing |
| `ffuf_vhost` | Virtual host / subdomain discovery |
| `ffuf_param` | GET-only parameter-name discovery |
| `list_wordlists` | List available wordlists |
| `get_fuzz_results` | Retrieve results from previous session |
| `list_active_scans` | Show running fuzzing sessions |

## Features

- **Directory Discovery**: Find hidden files, directories, and endpoints
- **Virtual Host Discovery**: Enumerate subdomains via Host header fuzzing
- **Parameter Fuzzing**: Discover hidden GET parameter names
- **Fixed Wordlists**: Uses the reviewed, container-owned wordlist catalog
- **Filtering**: Filter by status code, response size, word count
- **Rate Limiting**: Control request rate to avoid detection

## Pre-installed Wordlists

| Name | Description |
|------|-------------|
| `common` | Common directory/file names |
| `dirb-common` | DIRB common wordlist |
| `raft-large-dirs` | Raft large directories |
| `raft-large-files` | Raft large files |
| `subdomains-top1mil` | Top 5000 subdomains |
| `params-top` | Common parameter names |

## Docker

### Build

```bash
docker build -t ffuf-mcp .
```

### Run

```bash
docker run --rm -i ffuf-mcp
```

## Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ffuf": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "ffuf-mcp"]
    }
  }
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FFUF_OUTPUT_DIR` | `/app/output` | Results directory |
| `FFUF_WORDLISTS_DIR` | `/app/wordlists` | Wordlists directory |
| `FFUF_TIMEOUT` | `600` | Default timeout (seconds) |
| `FFUF_MAX_CONCURRENT` | `2` | Max concurrent scans |
| `FFUF_THREADS` | `40` | Default thread count |
| `FFUF_RATE` | `0` | Rate limit (0 = unlimited) |

All requests are GET. The server does not accept custom HTTP methods, bodies,
caller-controlled headers, or arbitrary wordlist paths. Vhost discovery builds
its Host header internally from a validated domain.

## Example Usage

### Directory fuzzing

```
Fuzz https://example.com for hidden directories using common wordlist
```

### Directory fuzzing with extensions

```
Fuzz https://example.com/FUZZ for php, html, and txt files
```

### Virtual host discovery

```
Discover virtual hosts on 10.10.10.10 for domain example.com
```

### Parameter discovery

```
Find hidden parameters on https://example.com/page.php?FUZZ=test
```

### Custom fuzzing

```
Fuzz https://example.com/api/FUZZ with custom headers and POST method
```

## FUZZ Keyword

The `FUZZ` keyword marks where wordlist entries are substituted:

- **URL**: `https://example.com/FUZZ`
- **Parameter**: `https://example.com/page?FUZZ=value`
- **Header**: Via `ffuf_vhost` which sets `Host: FUZZ.domain.com`
- **POST data**: `username=admin&password=FUZZ`

## Security Notice

FFUF is designed for authorized security testing only. Never fuzz systems without explicit permission. High thread counts can cause denial of service.

## License

MIT
