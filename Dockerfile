# Single-image, local-process security hub. Only gateway-reviewed MCPs are
# included; upstream wrappers that are not in capability_policy.py stay out.
FROM golang:1.24-trixie AS go-builder

ENV CGO_ENABLED=0 GOPATH=/go PATH=/go/bin:$PATH
RUN go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.9.0 && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.0 && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1 && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@v1.9.0 && \
    go install github.com/projectdiscovery/katana/cmd/katana@v1.7.0 && \
    go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@v1.2.9 && \
    go install github.com/projectdiscovery/tlsx/cmd/tlsx@v1.3.0

# Track the current supported Python feature release; all AGW adapters use the
# standard Python APIs and do not require the legacy Dharma runtime.
FROM python:3.14-slim-trixie

ARG FFUF_VERSION=2.1.0
ARG GITLEAKS_VERSION=8.30.0
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git hashcat masscan nikto nmap ruby-full ruby-bundler tini \
    && rm -rf /var/lib/apt/lists/*

COPY --from=go-builder /go/bin/ /usr/local/bin/
RUN arch="$(dpkg --print-architecture)" && \
    case "$arch" in amd64) ffuf_arch=amd64; gitleaks_arch=x64 ;; arm64) ffuf_arch=arm64; gitleaks_arch=arm64 ;; *) exit 1 ;; esac && \
    curl -fsSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${ffuf_arch}.tar.gz" | tar -xz -C /usr/local/bin ffuf && \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gitleaks_arch}.tar.gz" | tar -xz -C /usr/local/bin gitleaks && \
    git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && \
    cd /opt/whatweb && bundle config set without 'development test' && bundle install && \
    ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb

WORKDIR /opt/security-hub
COPY gateway-mcp/requirements.txt /tmp/gateway-requirements.txt
COPY tools/fuzzing/boofuzz-mcp/requirements.txt tools/fuzzing/boofuzz-mcp/requirements.txt
COPY tools/fuzzing/dharma-mcp/requirements.txt tools/fuzzing/dharma-mcp/requirements.txt
COPY tools/secrets/gitleaks-mcp/requirements.txt tools/secrets/gitleaks-mcp/requirements.txt
COPY tools/web-security/waybackurls-mcp/requirements.txt tools/web-security/waybackurls-mcp/requirements.txt
COPY tools/reconnaissance/nmap-mcp/requirements.txt tools/reconnaissance/nmap-mcp/requirements.txt
COPY tools/reconnaissance/whatweb-mcp/requirements.txt tools/reconnaissance/whatweb-mcp/requirements.txt
COPY tools/web-security/ffuf-mcp/requirements.txt tools/web-security/ffuf-mcp/requirements.txt
COPY tools/fuzzing/boofuzz-mcp/requirements.txt /tmp/boofuzz-requirements.txt
RUN pip install --no-cache-dir -r /tmp/gateway-requirements.txt -r /tmp/boofuzz-requirements.txt && \
    git clone --depth 1 https://github.com/MozillaSecurity/dharma.git /tmp/dharma && \
    pip install --no-cache-dir /tmp/dharma && \
    mkdir -p /app/grammars /app/wordlists /app/wordlists/dirb /app/wordlists/seclists/Discovery/Web-Content /app/wordlists/seclists/Discovery/DNS && \
    cp -r /tmp/dharma/dharma/grammars/. /app/grammars/ && rm -rf /tmp/dharma && \
    curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt -o /app/wordlists/10k-most-common.txt && \
    curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -o /app/wordlists/common.txt && \
    curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt -o /app/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt && \
    curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-files.txt -o /app/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt && \
    curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt -o /app/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt && \
    curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt -o /app/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt && \
    curl -fsSL https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt -o /app/wordlists/dirb/common.txt

COPY gateway-mcp/ ./gateway-mcp/
COPY adapters/ ./adapters/
COPY tools/fuzzing/dharma-mcp/ ./tools/dharma/
COPY tools/fuzzing/boofuzz-mcp/ ./tools/boofuzz/
COPY tools/password-cracking/hashcat-mcp/ ./tools/hashcat/
COPY tools/secrets/gitleaks-mcp/ ./tools/gitleaks/
COPY tools/web-security/waybackurls-mcp/ ./tools/waybackurls/
COPY tools/reconnaissance/nmap-mcp/ ./tools/nmap/
COPY tools/reconnaissance/whatweb-mcp/ ./tools/whatweb/
COPY tools/web-security/ffuf-mcp/ ./tools/ffuf/
COPY tools/reconnaissance/pd-tools-mcp/ ./tools/pd_tools/
COPY tools/reconnaissance/externalattacker-mcp/ ./tools/externalattacker/
COPY tools/reconnaissance/masscan-mcp/ ./tools/masscan/
COPY tools/web-security/sqlmap-mcp/ ./tools/sqlmap/
COPY tools/web-security/nikto-observer-mcp/ ./tools/nikto/

# Code, vendored assets, wordlists, and grammar files are root-owned and
# read-only to every tool process. Only the dedicated runtime directory is
# writable by the unprivileged MCP account.
RUN useradd --create-home --uid 1000 mcpuser && \
    mkdir -p /var/lib/security-hub && \
    chown -R root:root /opt/security-hub /app && \
    chmod -R a-w /opt/security-hub /app && \
    chown -R mcpuser:mcpuser /var/lib/security-hub
USER mcpuser
ENV PYTHONUNBUFFERED=1 PYTHONPATH=/opt/security-hub
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "/opt/security-hub/gateway-mcp/server.py"]
