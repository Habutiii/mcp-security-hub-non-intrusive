# DNStwist MCP Server
# Wrapper for BurtTheCoder/mcp-dnstwist
# Based on: https://github.com/BurtTheCoder/mcp-dnstwist

FROM node:20-alpine

RUN apk add --no-cache \
    tini \
    git \
    docker-cli \
    && rm -rf /var/cache/apk/*

WORKDIR /app

# Clone mcp-dnstwist
RUN git clone --depth 1 https://github.com/BurtTheCoder/mcp-dnstwist.git /tmp/mcp-dnstwist && \
    cp -r /tmp/mcp-dnstwist/* /app/ && \
    rm -rf /tmp/mcp-dnstwist

# Install dependencies and build
RUN npm ci && npm run build

ENV NODE_ENV=production

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "build/index.js"]
