# Burp Suite MCP Server
# Wrapper for PortSwigger/mcp-server
# Based on: https://github.com/PortSwigger/mcp-server
#
# NOTE: Requires Burp Suite Professional/Community installed on host.
# The MCP server runs as a Burp Suite extension.

# Build stage - use JDK for compilation
FROM eclipse-temurin:21-jdk-alpine AS builder

WORKDIR /app

COPY vendor/ ./

# Build with Gradle
RUN ./gradlew build -x test

# Runtime stage - use JRE for smaller image
FROM eclipse-temurin:21-jre-alpine

RUN apk add --no-cache tini && rm -rf /var/cache/apk/*

WORKDIR /app

# Copy built artifacts
COPY --from=builder /app/libs/mcp-proxy-all.jar /app/

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["java", "-jar", "/app/mcp-proxy-all.jar"]
