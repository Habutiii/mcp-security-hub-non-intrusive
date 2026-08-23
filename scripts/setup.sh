#!/bin/bash
# Quick setup script for Offensive Security MCP Servers

set -e

echo "=== Offensive Security MCP Servers Setup ==="
echo

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed"
    exit 1
fi

echo "[+] Docker found: $(docker --version)"

# Check Docker Compose
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "Error: Docker Compose is not installed"
    exit 1
fi

echo "[+] Docker Compose found"
echo

# Build images
echo "[+] Building MCP server images..."
echo

# Build only MCPs that have Dockerfiles
for mcp_dir in */*/; do
    if [ -f "${mcp_dir}Dockerfile" ]; then
        mcp_name=$(basename "$mcp_dir")
        echo "  Building $mcp_name..."
        docker-compose build "$mcp_name" 2>/dev/null || echo "  Skipped $mcp_name (not in compose)"
    fi
done

echo
echo "[+] Setup complete!"
echo
echo "Usage:"
echo "  docker-compose up -d              # Start all services"
echo "  docker-compose up nmap-mcp -d     # Start specific service"
echo "  docker-compose logs -f            # View logs"
echo "  ./scripts/healthcheck.sh          # Check service health"
echo
