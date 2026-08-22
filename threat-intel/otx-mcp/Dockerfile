# OTX MCP Server
# Built from mrwadams/otx-mcp source for multi-arch support
# Based on: https://github.com/mrwadams/otx-mcp

FROM python:3.12-alpine

RUN addgroup -g 1000 mcpuser && \
    adduser -D -u 1000 -G mcpuser mcpuser

RUN apk add --no-cache tini

WORKDIR /app

COPY vendor/ ./
RUN pip install --no-cache-dir -r requirements.txt && \
    chown -R mcpuser:mcpuser /app

USER mcpuser

ENV OTX_API_KEY=

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["python", "main.py"]
