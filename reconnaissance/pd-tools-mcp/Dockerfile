# PD-Tools MCP Server
# Wrapper for ProjectDiscovery tools (subfinder, httpx, katana, nuclei, dnsx, naabu)
# Based on: https://github.com/intelligent-ears/pd-tools-mcp

FROM node:20-alpine

# Note: node:20-alpine already has user 'node' with UID/GID 1000

# Install Go and build dependencies
RUN apk add --no-cache \
    ca-certificates \
    tini \
    git \
    go \
    curl \
    libpcap-dev \
    build-base \
    && rm -rf /var/cache/apk/*

# Set Go environment
ENV GOPATH=/home/node/go
ENV PATH=$PATH:$GOPATH/bin

# Switch to non-root user for Go installations
USER node

# Install ProjectDiscovery tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Verify installations
RUN subfinder -version && \
    httpx -version && \
    katana -version && \
    nuclei -version && \
    dnsx -version && \
    naabu -version

# Clone and build pd-tools-mcp
WORKDIR /app
USER root
RUN git clone --depth 1 https://github.com/intelligent-ears/pd-tools-mcp.git /app && \
    chown -R node:node /app

USER node
RUN npm install && npm run build

# Create output directories
RUN mkdir -p /app/output

# Environment variables
ENV NODE_ENV=production
ENV PATH=$PATH:/home/node/go/bin

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD pgrep -f "node.*index.js" > /dev/null || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "build/index.js"]
