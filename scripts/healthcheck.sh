#!/bin/bash
# Health check script for running MCP servers

echo "=== MCP Server Health Check ==="
echo

# Get running containers
containers=$(docker-compose ps -q 2>/dev/null)

if [ -z "$containers" ]; then
    echo "No MCP servers running"
    echo "Start with: docker-compose up -d"
    exit 0
fi

# Check each container
echo "Running containers:"
echo

docker-compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null

echo
echo "Health status:"
echo

for container in $containers; do
    name=$(docker inspect --format '{{.Name}}' "$container" | sed 's/\///')
    health=$(docker inspect --format '{{.State.Health.Status}}' "$container" 2>/dev/null || echo "no healthcheck")

    if [ "$health" = "healthy" ]; then
        echo "  [OK] $name"
    elif [ "$health" = "unhealthy" ]; then
        echo "  [FAIL] $name"
    elif [ "$health" = "starting" ]; then
        echo "  [STARTING] $name"
    else
        echo "  [?] $name ($health)"
    fi
done

echo
