# Restricted ExternalAttacker reconnaissance MCP.
# Upstream source is vendored at vendor/ (commit 62df49ef500ec113bd7ee47e98caafb70dc7fae7).

FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends golang-go tini ca-certificates libpcap-dev gcc libc6-dev && \
    rm -rf /var/lib/apt/lists/*

ENV GOPATH=/go
ENV PATH="/go/bin:$PATH"
ENV CGO_ENABLED=1

# Install only reviewed discovery tools. Nuclei, ffuf, and gobuster are intentionally absent.
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.9.0 && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1 && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@v1.9.0 && \
    go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@v1.2.9 && \
    go install github.com/projectdiscovery/tlsx/cmd/tlsx@v1.3.0

RUN useradd -m -u 1000 mcpuser

WORKDIR /app

COPY requirements.txt server.py ./
COPY vendor/ ./vendor/
RUN pip install --no-cache-dir -r requirements.txt && \
    chown -R mcpuser:mcpuser /app

USER mcpuser

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "server.py"]
