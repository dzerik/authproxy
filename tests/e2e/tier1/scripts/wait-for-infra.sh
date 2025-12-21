#!/bin/bash
# Wait for Infrastructure Services
# Comprehensive health checking with HTTP endpoint verification
#
# Usage:
#   ./wait-for-infra.sh [timeout_seconds]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMEOUT="${1:-180}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Check HTTP endpoint
check_http() {
    local url="$1"
    local expected="${2:-200}"
    curl -sf -o /dev/null -w "%{http_code}" "$url" 2>/dev/null | grep -q "$expected"
}

# Check TCP port
check_tcp() {
    local host="$1"
    local port="$2"
    timeout 2 bash -c "cat < /dev/null > /dev/tcp/${host}/${port}" 2>/dev/null
}

# Wait for service
wait_for_service() {
    local name="$1"
    local check_cmd="$2"
    local start_time
    start_time=$(date +%s)

    printf "  %-20s " "${name}..."

    while true; do
        local current_time
        current_time=$(date +%s)
        local elapsed=$((current_time - start_time))

        if [[ $elapsed -ge $TIMEOUT ]]; then
            echo -e "${RED}TIMEOUT (${elapsed}s)${NC}"
            return 1
        fi

        if eval "$check_cmd" 2>/dev/null; then
            echo -e "${GREEN}READY (${elapsed}s)${NC}"
            return 0
        fi

        sleep 2
    done
}

# Main
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "          Waiting for Infrastructure Services"
echo "          Timeout: ${TIMEOUT}s"
echo "═══════════════════════════════════════════════════════════════"
echo ""

FAILED=0

# PostgreSQL
wait_for_service "PostgreSQL" "check_tcp localhost 5432" || ((FAILED++))

# Redis
wait_for_service "Redis" "check_tcp localhost ${REDIS_PORT:-6379}" || ((FAILED++))

# Keycloak (wait for health endpoint)
wait_for_service "Keycloak" "check_http http://localhost:${KEYCLOAK_PORT:-8180}/health/ready" || ((FAILED++))

# OPA
wait_for_service "OPA" "check_http http://localhost:${OPA_PORT:-8181}/health" || ((FAILED++))

# Jaeger
wait_for_service "Jaeger" "check_http http://localhost:${JAEGER_UI_PORT:-16686}" || ((FAILED++))

# Prometheus
wait_for_service "Prometheus" "check_http http://localhost:${PROMETHEUS_PORT:-9090}/-/healthy" || ((FAILED++))

# Grafana
wait_for_service "Grafana" "check_http http://localhost:${GRAFANA_PORT:-3000}/api/health" || ((FAILED++))

# Mock Services (optional - may not be running)
if check_tcp localhost "${MOCK_USER_PORT:-8081}" 2>/dev/null; then
    wait_for_service "Mock User Svc" "check_http http://localhost:${MOCK_USER_PORT:-8081}/__admin/health" || log_warn "Mock User Service not ready"
fi

if check_tcp localhost "${MOCK_ADMIN_PORT:-8082}" 2>/dev/null; then
    wait_for_service "Mock Admin Svc" "check_http http://localhost:${MOCK_ADMIN_PORT:-8082}/__admin/health" || log_warn "Mock Admin Service not ready"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"

if [[ $FAILED -gt 0 ]]; then
    log_error "${FAILED} service(s) failed to become ready"
    exit 1
else
    log_success "All infrastructure services are ready!"
    echo ""

    # Additional Keycloak readiness check
    log_info "Verifying Keycloak realm..."
    if check_http "http://localhost:${KEYCLOAK_PORT:-8180}/realms/test/.well-known/openid-configuration"; then
        log_success "Keycloak 'test' realm is available"
    else
        log_warn "Keycloak 'test' realm not yet configured (may need import)"
    fi

    echo ""
fi
