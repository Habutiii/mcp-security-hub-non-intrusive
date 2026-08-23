# Nikto MCP Server

A Dockerized wrapper for [nikto-mcp](https://github.com/weldpua2008/nikto-mcp) that provides web server vulnerability scanning capabilities.

## Features

- **Web Server Scanning**: Detect vulnerabilities, misconfigurations, and outdated software
- **Plugin System**: Extensive plugin library for different vulnerability checks
- **Multiple Output Formats**: JSON, XML, HTML, CSV output
- **SSL/TLS Analysis**: Certificate and cipher suite checking

## Nikto Capabilities

- 6700+ potentially dangerous files/programs
- Outdated server versions (1250+ servers)
- Version specific problems (270+ servers)
- Server configuration checks
- HTTP methods testing
- Default file and program detection

## Docker

### Build

```bash
docker build -t nikto-mcp .
```

### Run

```bash
docker run --rm -i nikto-mcp
```

## Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "nikto": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "nikto-mcp"]
    }
  }
}
```

## Example Usage

### Basic web server scan

```
Scan https://example.com for web server vulnerabilities using nikto
```

### Scan with specific tuning

```
Run nikto scan on example.com focusing on misconfiguration and default files
```

### Scan multiple ports

```
Scan example.com ports 80, 443, and 8080 with nikto
```

## Tuning Options

Nikto supports tuning to focus on specific vulnerability types:

| Option | Description |
|--------|-------------|
| 1 | Interesting File / Seen in logs |
| 2 | Misconfiguration / Default File |
| 3 | Information Disclosure |
| 4 | Injection (XSS/Script/HTML) |
| 5 | Remote File Retrieval - Inside Web Root |
| 6 | Denial of Service |
| 7 | Remote File Retrieval - Server Wide |
| 8 | Command Execution / Remote Shell |
| 9 | SQL Injection |
| 0 | File Upload |
| a | Authentication Bypass |
| b | Software Identification |
| c | Remote Source Inclusion |
| x | Reverse Tuning Options (exclude) |

## Upstream

This is a Docker wrapper for:
- Repository: [weldpua2008/nikto-mcp](https://github.com/weldpua2008/nikto-mcp)
- Tool: [Nikto Web Scanner](https://github.com/sullo/nikto)

## Security Notice

Nikto is designed for authorized security testing only. Never scan systems without explicit permission.

## License

MIT
