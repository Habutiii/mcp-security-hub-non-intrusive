# Nmap MCP Server
# Production-ready Docker image with security hardening

FROM python:3.12-alpine AS production

# Labels

# Security: Create non-root user
RUN addgroup -g 1000 mcpuser && \
    adduser -D -u 1000 -G mcpuser mcpuser

# Install nmap and runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tini \
    nmap \
    nmap-scripts \
    && rm -rf /var/cache/apk/*

# Verify nmap installation
RUN nmap --version

WORKDIR /app

# Copy requirements first for layer caching
COPY --chown=mcpuser:mcpuser requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY --chown=mcpuser:mcpuser . .

# Create output directory
RUN mkdir -p /app/output && chown -R mcpuser:mcpuser /app

# Switch to non-root user
USER mcpuser

# Environment variables
ENV NMAP_OUTPUT_DIR=/app/output
ENV MCP_SERVER_HOST=0.0.0.0
ENV MCP_SERVER_PORT=3000
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ps aux | grep -v grep | grep "python.*server.py" > /dev/null || exit 1

# Expose MCP server port
EXPOSE 3000

# Use tini for proper signal handling
ENTRYPOINT ["/sbin/tini", "--"]

# Start MCP server
CMD ["python", "server.py"]
