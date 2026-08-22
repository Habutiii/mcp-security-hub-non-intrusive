# MCP-Scan Server
# Scan MCP servers for security vulnerabilities
# Based on: https://github.com/invariantlabs-ai/mcp-scan

FROM python:3.13-alpine

RUN addgroup -g 1000 mcpuser && \
    adduser -D -u 1000 -G mcpuser mcpuser

RUN apk add --no-cache tini

WORKDIR /app
COPY vendor/ ./
RUN pip install --no-cache-dir . && chown -R mcpuser:mcpuser /app

USER mcpuser

ENV PATH="/usr/local/bin:$PATH"

ENTRYPOINT ["/sbin/tini", "--", "snyk-agent-scan"]
CMD ["--help"]
