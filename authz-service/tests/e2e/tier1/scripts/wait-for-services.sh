#!/bin/bash
# Wait for all services to be healthy before running tests
# Usage: ./wait-for-services.sh [timeout_seconds]

set -e

TIMEOUT=${1:-300}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Service health check endpoints
declare -A SERVICES=(
    ["keycloak"]="http://localhost:8180/health/ready"
    ["authz-service"]="http://localhost:15020/healthz/ready"
    ["authz-service-external"]="http://localhost:25020/healthz/ready"
    ["redis"]="localhost:6379"
    ["opa"]="http://localhost:8181/health"
    ["jaeger"]="http://localhost:16686"
    ["prometheus"]="http://localhost:9090/-/ready"
    ["grafana"]="http://localhost:3000/api/health"
)

# Check if a service is healthy
check_service() {
    local name=$1
    local endpoint=$2

    case $name in
        redis)
            # Redis uses TCP check
            if command -v redis-cli &> /dev/null; then
                redis-cli -h localhost -p 6379 ping &> /dev/null
            else
                nc -z localhost 6379 &> /dev/null
            fi
            ;;
        *)
            # HTTP health check
            curl -sf "$endpoint" &> /dev/null
            ;;
    esac
}

# Wait for a single service
wait_for_service() {
    local name=$1
    local endpoint=$2
    local elapsed=0
    local interval=2

    while [ $elapsed -lt $TIMEOUT ]; do
        if check_service "$name" "$endpoint"; then
            log_info "$name is healthy"
            return 0
        fi

        sleep $interval
        elapsed=$((elapsed + interval))

        if [ $((elapsed % 10)) -eq 0 ]; then
            log_warn "$name not ready yet (${elapsed}s elapsed)..."
        fi
    done

    log_error "$name failed to become healthy within ${TIMEOUT}s"
    return 1
}

# Main execution
main() {
    log_info "Waiting for services to become healthy (timeout: ${TIMEOUT}s)..."
    echo ""

    local failed=0

    # Wait for services in order of dependency
    local order=("redis" "keycloak" "opa" "authz-service" "authz-service-external" "jaeger" "prometheus" "grafana")

    for service in "${order[@]}"; do
        if [ -n "${SERVICES[$service]}" ]; then
            if ! wait_for_service "$service" "${SERVICES[$service]}"; then
                failed=1
            fi
        fi
    done

    echo ""

    if [ $failed -eq 0 ]; then
        log_info "All services are healthy!"
        echo ""
        echo "Service URLs:"
        echo "  - Keycloak Admin:     http://localhost:8180 (admin/admin)"
        echo "  - authz-service:      http://localhost:8080"
        echo "  - authz-external:     http://localhost:9080"
        echo "  - Jaeger UI:          http://localhost:16686"
        echo "  - Prometheus:         http://localhost:9090"
        echo "  - Grafana:            http://localhost:3000 (admin/admin)"
        echo ""
        return 0
    else
        log_error "Some services failed to start"
        echo ""
        echo "Check logs with: docker compose logs <service-name>"
        return 1
    fi
}

main "$@"
