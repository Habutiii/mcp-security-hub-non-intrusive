# Shodan MCP Server
# Wrapper around BurtTheCoder/mcp-shodan
# https://github.com/BurtTheCoder/mcp-shodan

FROM node:20-alpine

RUN apk add --no-cache tini

WORKDIR /home/node

COPY vendor/ ./
RUN npm ci && npm run build && chown -R node:node /home/node

# Use existing node user (non-root, uid 1000)
USER node

# Required environment variable
ENV SHODAN_API_KEY=""

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD pgrep -f "node" > /dev/null || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "build/index.js"]
