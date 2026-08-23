# DNStwist MCP Server
# Wrapper for BurtTheCoder/mcp-dnstwist
# Based on: https://github.com/BurtTheCoder/mcp-dnstwist

FROM node:20-alpine

RUN apk add --no-cache tini && rm -rf /var/cache/apk/*

WORKDIR /app

COPY vendor/ ./

# Install dependencies and build
RUN npm ci && npm run build

ENV NODE_ENV=production

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "build/index.js"]
