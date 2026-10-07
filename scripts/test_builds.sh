#!/bin/bash
# Test Docker builds for all MCP servers
# Usage: ./scripts/test_builds.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$ROOT_DIR"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "ERROR: Docker daemon is not running"
    echo "Please start Docker and try again"
    exit 1
fi

MCPS=(
    # Reconnaissance
    "tools/reconnaissance/nmap-mcp"
    "tools/reconnaissance/shodan-mcp"
    "tools/reconnaissance/pd-tools-mcp"
    "tools/reconnaissance/whatweb-mcp"
    "tools/reconnaissance/masscan-mcp"
    "tools/reconnaissance/zoomeye-mcp"
    "tools/reconnaissance/networksdb-mcp"
    "tools/reconnaissance/externalattacker-mcp"
    # Web Security
    "tools/web-security/sqlmap-mcp"
    "tools/web-security/nikto-mcp"
    "tools/web-security/ffuf-mcp"
    "tools/web-security/waybackurls-mcp"
    "tools/web-security/burp-mcp"
    # Secrets Detection
    "tools/secrets/gitleaks-mcp"
    # Fuzzing
    "tools/fuzzing/boofuzz-mcp"
    "tools/fuzzing/dharma-mcp"
    # OSINT
    "tools/osint/maigret-mcp"
    "tools/osint/dnstwist-mcp"
    # Threat Intelligence
    "tools/threat-intel/virustotal-mcp"
    "tools/threat-intel/otx-mcp"
    # Active Directory
    "tools/active-directory/bloodhound-mcp"
    # Password Cracking
    "tools/password-cracking/hashcat-mcp"
    # Meta
    "tools/meta/mcp-scan"
)

PASSED=0
FAILED=0
FAILED_MCPS=()

echo "=========================================="
echo "Testing Docker builds for all MCP servers"
echo "=========================================="
echo ""

for mcp in "${MCPS[@]}"; do
    name=$(basename "$mcp")
    printf "Building %-25s ... " "$name"

    if [ ! -d "$mcp" ]; then
        echo "SKIP (not found)"
        continue
    fi

    if docker build -q -t "test-$name" "./$mcp" > /dev/null 2>&1; then
        echo "OK"
        ((PASSED++))
        # Clean up test image
        docker rmi "test-$name" > /dev/null 2>&1 || true
    else
        echo "FAILED"
        ((FAILED++))
        FAILED_MCPS+=("$name")
    fi
done

echo ""
echo "=========================================="
echo "Results: $PASSED passed, $FAILED failed"
echo "=========================================="

if [ $FAILED -gt 0 ]; then
    echo ""
    echo "Failed MCPs:"
    for mcp in "${FAILED_MCPS[@]}"; do
        echo "  - $mcp"
    done
    exit 1
fi

echo ""
echo "All builds passed!"
exit 0
