# Restricted ProjectDiscovery reconnaissance MCP.
# Upstream source is vendored at vendor/ (commit 0698fb966114435233bf20e85483694d6ef0e450).
FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates golang-go tini && \
    rm -rf /var/lib/apt/lists/*

ENV GOPATH=/go
ENV PATH=/go/bin:$PATH

# Only discovery tools are installed. Nuclei and its unrestricted template engine are excluded.
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.9.0 && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.0 && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1 && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@v1.9.0 && \
    go install github.com/projectdiscovery/katana/cmd/katana@v1.7.0

RUN useradd --create-home --uid 1000 mcpuser
WORKDIR /app

COPY requirements.txt server.py ./
COPY vendor/ ./vendor/
RUN pip install --no-cache-dir -r requirements.txt && chown -R mcpuser:mcpuser /app

USER mcpuser
ENV PD_TIMEOUT=120
ENV PD_MAX_CONCURRENT=1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "server.py"]
