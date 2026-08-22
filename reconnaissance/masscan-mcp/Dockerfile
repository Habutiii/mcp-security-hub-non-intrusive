# Masscan MCP Server
# Fast port scanner

FROM python:3.12-alpine

RUN addgroup -g 1000 mcpuser && \
    adduser -D -u 1000 -G mcpuser mcpuser

RUN apk add --no-cache \
    ca-certificates \
    tini \
    masscan \
    libpcap \
    && rm -rf /var/cache/apk/*

# Note: masscan --version returns exit code 1 without root/NET_RAW
RUN masscan --version || true

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=mcpuser:mcpuser . .
RUN mkdir -p /app/output && chown -R mcpuser:mcpuser /app

# Note: masscan requires NET_RAW capability or root
USER mcpuser

ENV MASSCAN_OUTPUT_DIR=/app/output
ENV MASSCAN_TIMEOUT=600
ENV MASSCAN_RATE=1000
ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD pgrep -f "python.*server.py" > /dev/null || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["python", "server.py"]
