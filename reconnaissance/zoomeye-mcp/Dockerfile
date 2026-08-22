# Internally built ZoomEye MCP. Upstream source is vendored in vendor/.
FROM python:3.12-alpine
RUN addgroup -g 1000 mcpuser && adduser -D -u 1000 -G mcpuser mcpuser && apk add --no-cache tini
WORKDIR /app
COPY vendor/ ./
RUN pip install --no-cache-dir . && chown -R mcpuser:mcpuser /app
USER mcpuser
ENV ZOOMEYE_API_KEY=""
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["mcp-server-zoomeye"]
