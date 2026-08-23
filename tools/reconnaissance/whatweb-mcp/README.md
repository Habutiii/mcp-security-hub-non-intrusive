# WhatWeb MCP Server

Web technology fingerprinting using [WhatWeb](https://github.com/urbanadventurer/WhatWeb).

## Tools

| Tool | Description |
|------|-------------|
| `whatweb_scan` | Identify web technologies on target |
| `get_scan_results` | Retrieve previous scan results |
| `list_active_scans` | Show running scans |

## Features

- Identifies CMS (WordPress, Drupal, Joomla, etc.)
- Detects web frameworks (Django, Rails, Laravel, etc.)
- Server software (Apache, nginx, IIS)
- JavaScript libraries (jQuery, React, Angular)
- 1800+ plugins for technology detection

## Docker

```bash
docker build -t whatweb-mcp .
docker run --rm -i whatweb-mcp
```

## Example Usage

```
Identify what technologies example.com is using
```

## License

MIT
