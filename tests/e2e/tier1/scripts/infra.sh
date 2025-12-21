#!/bin/bash
# Infrastructure Management Script
# Supports Docker and Podman with automatic detection
#
# Usage:
#   ./infra.sh up       - Start infrastructure
#   ./infra.sh down     - Stop infrastructure
#   ./infra.sh destroy  - Stop and remove all data
#   ./infra.sh status   - Show status
#   ./infra.sh logs     - Follow logs
#   ./infra.sh wait     - Wait for all services to be ready
#   ./infra.sh clean    - Clean volumes and orphans

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="${SCRIPT_DIR}/../compose"
COMPOSE_FILE="${COMPOSE_DIR}/docker-compose.infra.yaml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Detect container runtime
detect_runtime() {
    if command -v podman &>/dev/null && podman info &>/dev/null 2>&1; then
        echo "podman"
    elif command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        echo "docker"
    else
        log_error "No container runtime found (docker or podman)"
        exit 1
    fi
}

# Detect compose command
detect_compose() {
    local runtime
    runtime=$(detect_runtime)

    if [[ "$runtime" == "podman" ]]; then
        if command -v podman-compose &>/dev/null; then
            echo "podman-compose"
        else
            log_error "podman-compose not found. Install with: pip install podman-compose"
            exit 1
        fi
    else
        if docker compose version &>/dev/null 2>&1; then
            echo "docker compose"
        elif command -v docker-compose &>/dev/null; then
            echo "docker-compose"
        else
            log_error "docker compose not found"
            exit 1
        fi
    fi
}

RUNTIME=$(detect_runtime)
COMPOSE=$(detect_compose)

log_info "Using runtime: ${RUNTIME}"
log_info "Using compose: ${COMPOSE}"

# Run compose command
compose_cmd() {
    cd "${COMPOSE_DIR}"
    ${COMPOSE} -f docker-compose.infra.yaml "$@"
}

# Start infrastructure
cmd_up() {
    local profiles="${1:-}"
    log_info "Starting infrastructure..."

    if [[ -n "$profiles" ]]; then
        compose_cmd --profile "$profiles" up -d
    else
        compose_cmd up -d
    fi

    log_success "Infrastructure started"
    log_info "Waiting for services to be healthy..."
    cmd_wait
}

# Stop infrastructure
cmd_down() {
    log_info "Stopping infrastructure..."
    compose_cmd down
    log_success "Infrastructure stopped"
}

# Destroy everything (including volumes)
cmd_destroy() {
    log_warn "This will remove all containers, volumes, and images!"
    read -p "Are you sure? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Destroying infrastructure..."
        compose_cmd down -v --rmi local --remove-orphans

        # Clean named volumes
        for vol in infra-postgres-data infra-redis-data infra-prometheus-data infra-grafana-data; do
            if ${RUNTIME} volume inspect "$vol" &>/dev/null; then
                ${RUNTIME} volume rm "$vol" 2>/dev/null || true
            fi
        done

        log_success "Infrastructure destroyed"
    else
        log_info "Cancelled"
    fi
}

# Show status
cmd_status() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "                    Infrastructure Status"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    compose_cmd ps
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "                         Endpoints"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  Identity Provider:"
    echo "    Keycloak Admin:    http://localhost:${KEYCLOAK_PORT:-8180}"
    echo "                       Login: admin / admin"
    echo ""
    echo "  Cache:"
    echo "    Redis:             localhost:${REDIS_PORT:-6379}"
    echo ""
    echo "  Policy Engine:"
    echo "    OPA:               http://localhost:${OPA_PORT:-8181}"
    echo ""
    echo "  Observability:"
    echo "    Jaeger UI:         http://localhost:${JAEGER_UI_PORT:-16686}"
    echo "    Prometheus:        http://localhost:${PROMETHEUS_PORT:-9090}"
    echo "    Grafana:           http://localhost:${GRAFANA_PORT:-3000}"
    echo "                       Login: admin / admin"
    echo ""
    echo "  Mock Services:"
    echo "    User Service:      http://localhost:${MOCK_USER_PORT:-8081}"
    echo "    Admin Service:     http://localhost:${MOCK_ADMIN_PORT:-8082}"
    echo "    External API:      http://localhost:${MOCK_EXTERNAL_PORT:-8083}"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
}

# Follow logs
cmd_logs() {
    local service="${1:-}"
    if [[ -n "$service" ]]; then
        compose_cmd logs -f "$service"
    else
        compose_cmd logs -f
    fi
}

# Wait for services
cmd_wait() {
    local timeout="${1:-180}"
    local services=(
        "infra-postgres:5432"
        "infra-keycloak:8080"
        "infra-redis:6379"
        "infra-opa:8181"
        "infra-jaeger:16686"
        "infra-prometheus:9090"
        "infra-grafana:3000"
    )

    log_info "Waiting for services (timeout: ${timeout}s)..."

    local start_time
    start_time=$(date +%s)

    for service_port in "${services[@]}"; do
        local container="${service_port%%:*}"
        local port="${service_port##*:}"

        printf "  %-25s " "${container}..."

        while true; do
            local current_time
            current_time=$(date +%s)
            local elapsed=$((current_time - start_time))

            if [[ $elapsed -ge $timeout ]]; then
                echo -e "${RED}TIMEOUT${NC}"
                log_error "Service ${container} did not become healthy in ${timeout}s"
                exit 1
            fi

            # Check if container is running and healthy
            local health
            health=$(${RUNTIME} inspect --format='{{.State.Health.Status}}' "$container" 2>/dev/null || echo "not_found")

            case "$health" in
                "healthy")
                    echo -e "${GREEN}READY${NC}"
                    break
                    ;;
                "unhealthy")
                    echo -e "${RED}UNHEALTHY${NC}"
                    log_error "Service ${container} is unhealthy"
                    exit 1
                    ;;
                "not_found")
                    # Container might not have started yet
                    ;;
            esac

            sleep 2
        done
    done

    log_success "All infrastructure services are ready!"
}

# Clean orphans and dangling resources
cmd_clean() {
    log_info "Cleaning orphaned containers and dangling resources..."
    compose_cmd down --remove-orphans

    # Remove dangling images
    ${RUNTIME} image prune -f

    # Remove unused networks
    ${RUNTIME} network prune -f

    log_success "Cleanup complete"
}

# Restart service
cmd_restart() {
    local service="${1:-}"
    if [[ -n "$service" ]]; then
        log_info "Restarting ${service}..."
        compose_cmd restart "$service"
    else
        log_info "Restarting all services..."
        compose_cmd restart
    fi
    log_success "Restart complete"
}

# Health check
cmd_health() {
    echo ""
    echo "Infrastructure Health Check"
    echo "============================"
    echo ""

    local services=(
        "infra-postgres|PostgreSQL|5432"
        "infra-keycloak|Keycloak|8080"
        "infra-redis|Redis|6379"
        "infra-opa|OPA|8181"
        "infra-jaeger|Jaeger|16686"
        "infra-prometheus|Prometheus|9090"
        "infra-grafana|Grafana|3000"
    )

    for service_info in "${services[@]}"; do
        IFS='|' read -r container name port <<< "$service_info"
        printf "  %-15s " "${name}:"

        local health
        health=$(${RUNTIME} inspect --format='{{.State.Health.Status}}' "$container" 2>/dev/null || echo "not_running")

        case "$health" in
            "healthy")
                echo -e "${GREEN}HEALTHY${NC}"
                ;;
            "starting")
                echo -e "${YELLOW}STARTING${NC}"
                ;;
            "unhealthy")
                echo -e "${RED}UNHEALTHY${NC}"
                ;;
            *)
                echo -e "${RED}NOT RUNNING${NC}"
                ;;
        esac
    done
    echo ""
}

# Main
case "${1:-help}" in
    up)
        shift
        cmd_up "$@"
        ;;
    down)
        cmd_down
        ;;
    destroy)
        cmd_destroy
        ;;
    status)
        cmd_status
        ;;
    logs)
        shift
        cmd_logs "$@"
        ;;
    wait)
        shift
        cmd_wait "$@"
        ;;
    clean)
        cmd_clean
        ;;
    restart)
        shift
        cmd_restart "$@"
        ;;
    health)
        cmd_health
        ;;
    help|--help|-h)
        echo "Infrastructure Management Script"
        echo ""
        echo "Usage: $0 <command> [options]"
        echo ""
        echo "Commands:"
        echo "  up [profile]    Start infrastructure (optional: chaos, mail)"
        echo "  down            Stop infrastructure"
        echo "  destroy         Stop and remove all data (volumes included)"
        echo "  status          Show status and endpoints"
        echo "  logs [service]  Follow logs (all or specific service)"
        echo "  wait [timeout]  Wait for services to be healthy (default: 180s)"
        echo "  clean           Clean orphans and dangling resources"
        echo "  restart [svc]   Restart all or specific service"
        echo "  health          Show health status of all services"
        echo ""
        echo "Examples:"
        echo "  $0 up                    # Start core infrastructure"
        echo "  $0 up chaos              # Start with ToxiProxy"
        echo "  $0 logs keycloak         # Follow Keycloak logs"
        echo "  $0 wait 300              # Wait up to 5 minutes"
        echo ""
        ;;
    *)
        log_error "Unknown command: $1"
        echo "Run '$0 help' for usage"
        exit 1
        ;;
esac
