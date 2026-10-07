#!/usr/bin/env bash
#
# run-tests.sh - Test runner for Offensive Security MCP Servers
#
# Usage:
#   ./scripts/run-tests.sh                    # Run all tests
#   ./scripts/run-tests.sh --unit             # Run only unit tests
#   ./scripts/run-tests.sh --integration      # Run only integration tests
#   ./scripts/run-tests.sh --container        # Run only container structure tests
#   ./scripts/run-tests.sh --no-build         # Skip Docker build step
#
# Exit codes:
#   0 - All tests passed
#   1 - One or more tests failed
#   2 - Configuration or setup error

set -eo pipefail

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.yml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
HEALTH_CHECK_TIMEOUT=60
HEALTH_CHECK_INTERVAL=5

# Services to test (add more as they are implemented)
AVAILABLE_SERVICES=""
# Uncomment as services are implemented:
# AVAILABLE_SERVICES="nmap-mcp shodan-mcp sqlmap-mcp"

# =============================================================================
# Service Configuration Functions (portable alternative to associative arrays)
# =============================================================================

get_service_port() {
    local service="$1"
    case "${service}" in
        nmap-mcp)       echo 3001 ;;
        shodan-mcp)     echo 3002 ;;
        sqlmap-mcp)     echo 3004 ;;
        metasploit-mcp) echo 3005 ;;
        mobsf-mcp)      echo 3008 ;;
        *)              echo 3000 ;;
    esac
}

get_service_dir() {
    local service="$1"
    case "${service}" in
        nmap-mcp)       echo "tools/reconnaissance/nmap-mcp" ;;
        shodan-mcp)     echo "tools/reconnaissance/shodan-mcp" ;;
        sqlmap-mcp)     echo "tools/web-security/sqlmap-mcp" ;;
        metasploit-mcp) echo "exploitation/metasploit-mcp" ;;
        mobsf-mcp)      echo "mobile-security/mobsf-mcp" ;;
        *)              echo "" ;;
    esac
}

# =============================================================================
# Utility Functions
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_header() {
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# =============================================================================
# Test Functions
# =============================================================================

# Run unit tests for a service
run_unit_tests() {
    local service="$1"
    local service_dir
    service_dir="${PROJECT_ROOT}/$(get_service_dir "${service}")"

    log_info "Running unit tests for ${service}..."

    if [[ ! -d "${service_dir}" ]]; then
        log_warn "Service directory not found: ${service_dir}"
        return 1
    fi

    # Check if tests exist
    if [[ ! -d "${service_dir}/tests" ]]; then
        log_warn "No tests directory found for ${service}"
        return 0
    fi

    # Check if pytest is available in the image
    if ! docker run --rm --entrypoint "" "ghcr.io/fuzzinglabs/${service}:latest" python -c "import pytest" 2>/dev/null; then
        log_warn "pytest not installed in ${service} image, skipping unit tests"
        log_info "  To run unit tests, install test dependencies or use a test image"
        return 0
    fi

    # Run tests inside Docker container
    if docker run --rm \
        -v "${service_dir}:/app" \
        -w /app \
        --entrypoint "" \
        "ghcr.io/fuzzinglabs/${service}:latest" \
        python -m pytest tests/ -v --tb=short 2>&1; then
        log_success "Unit tests passed for ${service}"
        return 0
    else
        log_error "Unit tests failed for ${service}"
        return 1
    fi
}

# Run container structure tests
run_container_structure_tests() {
    local service="$1"
    local service_dir
    service_dir="${PROJECT_ROOT}/$(get_service_dir "${service}")"
    local config_file="${service_dir}/container-structure-test.yaml"

    log_info "Running container structure tests for ${service}..."

    if [[ ! -f "${config_file}" ]]; then
        log_warn "No container-structure-test.yaml found for ${service}"
        return 0
    fi

    # Check if container-structure-test is available
    if ! command_exists container-structure-test; then
        log_warn "container-structure-test not installed, running via Docker..."

        if docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v "${service_dir}:/workspace" \
            gcr.io/gcp-runtimes/container-structure-test:latest \
            test \
            --image "ghcr.io/fuzzinglabs/${service}:latest" \
            --config /workspace/container-structure-test.yaml 2>&1; then
            log_success "Container structure tests passed for ${service}"
            return 0
        else
            log_error "Container structure tests failed for ${service}"
            return 1
        fi
    else
        if container-structure-test test \
            --image "ghcr.io/fuzzinglabs/${service}:latest" \
            --config "${config_file}" 2>&1; then
            log_success "Container structure tests passed for ${service}"
            return 0
        else
            log_error "Container structure tests failed for ${service}"
            return 1
        fi
    fi
}

# Wait for service health check
wait_for_health() {
    local service="$1"
    local port
    port="$(get_service_port "${service}")"
    local elapsed=0

    log_info "Waiting for ${service} to be healthy..."

    while [[ ${elapsed} -lt ${HEALTH_CHECK_TIMEOUT} ]]; do
        # Check if container is running
        local container_status
        container_status=$(docker inspect --format='{{.State.Status}}' "${service}" 2>/dev/null || echo "not_found")

        if [[ "${container_status}" == "running" ]]; then
            # Check Docker health status if available
            local health_status
            health_status=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}no_healthcheck{{end}}' "${service}" 2>/dev/null || echo "unknown")

            if [[ "${health_status}" == "healthy" ]]; then
                log_success "${service} is healthy (Docker health check)"
                return 0
            elif [[ "${health_status}" == "no_healthcheck" ]]; then
                # No Docker health check defined, try HTTP endpoints
                if curl -sf "http://localhost:${port}/health" >/dev/null 2>&1; then
                    log_success "${service} is healthy (HTTP)"
                    return 0
                fi
                # For stdio-based MCP servers, check if process is running
                local pid_count
                pid_count=$(docker exec "${service}" pgrep -f "python.*server" 2>/dev/null | wc -l || echo "0")
                if [[ ${pid_count} -gt 0 ]]; then
                    log_success "${service} is running (process check)"
                    return 0
                fi
            elif [[ "${health_status}" == "starting" ]]; then
                log_info "  ${service} health check starting..."
            fi
        elif [[ "${container_status}" == "exited" ]]; then
            log_error "${service} container exited unexpectedly"
            docker logs "${service}" 2>&1 | tail -20
            return 1
        fi

        sleep ${HEALTH_CHECK_INTERVAL}
        elapsed=$((elapsed + HEALTH_CHECK_INTERVAL))
    done

    log_error "${service} health check timed out after ${HEALTH_CHECK_TIMEOUT}s"
    # Show logs for debugging
    log_info "Container logs:"
    docker logs "${service}" 2>&1 | tail -30
    return 1
}

# Run integration tests (requires running containers)
run_integration_tests() {
    local service="$1"
    local port
    port="$(get_service_port "${service}")"

    log_info "Running integration tests for ${service}..."

    # Service-specific integration tests
    case "${service}" in
        nmap-mcp)
            run_nmap_integration_tests "${service}"
            ;;
        *)
            log_info "No specific integration tests for ${service}, container is running"
            return 0
            ;;
    esac
}

# Nuclei-specific integration tests
run_nuclei_integration_tests() {
    local service="$1"
    local image="ghcr.io/fuzzinglabs/${service}:latest"
    local passed=0
    local failed=0

    log_info "Testing Nuclei MCP functionality..."

    # Test: Nuclei binary works
    if docker run --rm --entrypoint "" "${image}" nuclei -version 2>&1 | grep -qi "nuclei"; then
        log_success "  Nuclei binary works"
        ((passed++)) || true
    else
        log_error "  Nuclei binary failed"
        ((failed++)) || true
    fi

    # Test: Templates are available
    local template_count
    template_count=$(docker run --rm --entrypoint "" "${image}" sh -c "find /app/templates -name '*.yaml' 2>/dev/null | wc -l" | tr -d ' ')
    if [[ ${template_count} -gt 0 ]]; then
        log_success "  Templates available: ${template_count} files"
        ((passed++)) || true
    else
        log_warn "  No templates found (may need to download)"
    fi

    # Test: Python MCP server module can be imported
    if docker run --rm --entrypoint "" "${image}" python -c "from server import app; print('OK')" 2>/dev/null | grep -q "OK"; then
        log_success "  MCP server module imports correctly"
        ((passed++)) || true
    else
        log_error "  MCP server module import failed"
        ((failed++)) || true
    fi

    # Test: Health check script works
    if docker run --rm --entrypoint "" "${image}" python /app/healthcheck.py 2>&1 | grep -q "OK"; then
        log_success "  Health check script works"
        ((passed++)) || true
    else
        log_warn "  Health check script returned warnings"
    fi

    if [[ ${failed} -gt 0 ]]; then
        log_error "Nuclei integration tests: ${passed} passed, ${failed} failed"
        return 1
    else
        log_success "Nuclei integration tests: ${passed} passed"
        return 0
    fi
}

# Nmap-specific integration tests
run_nmap_integration_tests() {
    local service="$1"
    local image="ghcr.io/fuzzinglabs/${service}:latest"

    log_info "Testing Nmap MCP functionality..."

    # Test: Nmap binary works
    if docker run --rm --entrypoint "" "${image}" nmap --version 2>&1 | grep -qi "nmap"; then
        log_success "  Nmap binary works"
        return 0
    else
        log_error "  Nmap binary failed"
        return 1
    fi
}

# Build Docker images
build_images() {
    local service="$1"

    log_info "Building Docker image for ${service}..."

    if docker-compose -f "${COMPOSE_FILE}" build "${service}" 2>&1; then
        log_success "Successfully built ${service}"
        return 0
    else
        log_error "Failed to build ${service}"
        return 1
    fi
}

# Start a service
start_service() {
    local service="$1"

    log_info "Starting ${service}..."

    if docker-compose -f "${COMPOSE_FILE}" up -d "${service}" 2>&1; then
        log_success "Started ${service}"
        return 0
    else
        log_error "Failed to start ${service}"
        return 1
    fi
}

# Stop a service
stop_service() {
    local service="$1"

    log_info "Stopping ${service}..."
    docker-compose -f "${COMPOSE_FILE}" stop "${service}" >/dev/null 2>&1 || true
    docker-compose -f "${COMPOSE_FILE}" rm -f "${service}" >/dev/null 2>&1 || true
}

# =============================================================================
# Test Runners
# =============================================================================

# Run all tests for a single service
test_service() {
    local service="$1"
    local run_unit="${2:-true}"
    local run_container="${3:-true}"
    local run_integration="${4:-true}"
    local skip_build="${5:-false}"
    local results=0

    log_header "Testing: ${service}"

    # Build image (unless skipped)
    if [[ "${skip_build}" != "true" ]]; then
        if ! build_images "${service}"; then
            log_error "Build failed for ${service}, skipping tests"
            return 1
        fi
    fi

    # Unit tests
    if [[ "${run_unit}" == "true" ]]; then
        if ! run_unit_tests "${service}"; then
            ((results++)) || true
        fi
    fi

    # Container structure tests
    if [[ "${run_container}" == "true" ]]; then
        if ! run_container_structure_tests "${service}"; then
            ((results++)) || true
        fi
    fi

    # Integration tests
    # Note: MCP servers use stdio transport, so they exit immediately when run
    # as a daemon (no stdin). We run integration tests directly with docker run.
    if [[ "${run_integration}" == "true" ]]; then
        if ! run_integration_tests "${service}"; then
            ((results++)) || true
        fi
    fi

    return ${results}
}

# =============================================================================
# Main
# =============================================================================

main() {
    local run_unit=true
    local run_container=true
    local run_integration=true
    local skip_build=false
    local specific_service=""
    local total_passed=0
    local total_failed=0

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --unit)
                run_container=false
                run_integration=false
                shift
                ;;
            --container)
                run_unit=false
                run_integration=false
                shift
                ;;
            --integration)
                run_unit=false
                run_container=false
                shift
                ;;
            --no-build)
                skip_build=true
                shift
                ;;
            --service)
                specific_service="$2"
                shift 2
                ;;
            -h|--help)
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  --unit           Run only unit tests"
                echo "  --container      Run only container structure tests"
                echo "  --integration    Run only integration tests"
                echo "  --no-build       Skip Docker build step"
                echo "  --service NAME   Test specific service only"
                echo "  -h, --help       Show this help message"
                echo ""
                echo "Available services:"
                for svc in ${AVAILABLE_SERVICES}; do
                    echo "  - ${svc}"
                done
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 2
                ;;
        esac
    done

    # Header
    log_header "Offensive Security MCP Servers - Test Suite"
    log_info "Project root: ${PROJECT_ROOT}"
    log_info "Tests: unit=${run_unit}, container=${run_container}, integration=${run_integration}"

    # Check prerequisites
    if ! command_exists docker; then
        log_error "Docker is not installed"
        exit 2
    fi

    if ! command_exists docker-compose; then
        # Try docker compose (v2)
        if ! docker compose version >/dev/null 2>&1; then
            log_error "docker-compose is not installed"
            exit 2
        fi
        # Create alias function for docker compose v2
        docker-compose() {
            docker compose "$@"
        }
    fi

    # Determine services to test
    local services_to_test=""
    if [[ -n "${specific_service}" ]]; then
        # Validate service exists
        local found=false
        for svc in ${AVAILABLE_SERVICES}; do
            if [[ "${svc}" == "${specific_service}" ]]; then
                found=true
                break
            fi
        done

        if [[ "${found}" != "true" ]]; then
            log_error "Unknown service: ${specific_service}"
            log_info "Available services: ${AVAILABLE_SERVICES}"
            exit 2
        fi

        services_to_test="${specific_service}"
    else
        services_to_test="${AVAILABLE_SERVICES}"
    fi

    # Count services
    local service_count=0
    for _ in ${services_to_test}; do
        ((service_count++)) || true
    done

    # Run tests for each service
    for service in ${services_to_test}; do
        if test_service "${service}" "${run_unit}" "${run_container}" "${run_integration}" "${skip_build}"; then
            ((total_passed++)) || true
        else
            ((total_failed++)) || true
        fi
    done

    # Summary
    log_header "Test Summary"
    echo -e "Services tested: ${service_count}"
    echo -e "${GREEN}Passed: ${total_passed}${NC}"
    echo -e "${RED}Failed: ${total_failed}${NC}"
    echo ""

    if [[ ${total_failed} -gt 0 ]]; then
        log_error "Some tests failed!"
        exit 1
    else
        log_success "All tests passed!"
        exit 0
    fi
}

# Run main
main "$@"
