#!/bin/bash
# Detect container runtime (Docker or Podman)
# Usage: ./detect-runtime.sh [command]
#
# Commands:
#   detect   - Detect and print runtime (default)
#   compose  - Print compose command (docker compose or podman-compose)
#   version  - Print runtime version
#   check    - Check if runtime is available (exit 0 or 1)

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Check if Docker is available and running
check_docker() {
    if command -v docker &> /dev/null; then
        if docker info &> /dev/null; then
            return 0
        else
            log_warn "Docker is installed but daemon is not running"
            return 1
        fi
    fi
    return 1
}

# Check if Podman is available
check_podman() {
    if command -v podman &> /dev/null; then
        if podman info &> /dev/null; then
            return 0
        else
            log_warn "Podman is installed but not functioning"
            return 1
        fi
    fi
    return 1
}

# Check if docker compose (v2) is available
check_docker_compose() {
    if docker compose version &> /dev/null; then
        return 0
    fi
    return 1
}

# Check if podman-compose is available
check_podman_compose() {
    if command -v podman-compose &> /dev/null; then
        return 0
    fi
    return 1
}

# Detect preferred runtime
detect_runtime() {
    # Prefer Docker (as per requirements)
    if check_docker; then
        echo "docker"
        return 0
    fi

    # Fall back to Podman
    if check_podman; then
        echo "podman"
        return 0
    fi

    log_error "No container runtime found. Please install Docker or Podman."
    return 1
}

# Get compose command
get_compose_command() {
    local runtime
    runtime=$(detect_runtime 2>/dev/null)

    case $runtime in
        docker)
            if check_docker_compose; then
                echo "docker compose"
            else
                log_error "docker compose (v2) is required. Please update Docker."
                return 1
            fi
            ;;
        podman)
            if check_podman_compose; then
                echo "podman-compose"
            else
                log_error "podman-compose is required. Install with: pip install podman-compose"
                return 1
            fi
            ;;
        *)
            return 1
            ;;
    esac
}

# Get runtime version
get_version() {
    local runtime
    runtime=$(detect_runtime 2>/dev/null)

    case $runtime in
        docker)
            docker version --format '{{.Server.Version}}'
            ;;
        podman)
            podman version --format '{{.Version}}'
            ;;
        *)
            return 1
            ;;
    esac
}

# Print detailed info
print_info() {
    echo "Container Runtime Detection"
    echo "============================"
    echo ""

    echo "Docker:"
    if check_docker; then
        echo "  Status:  ✓ Available"
        echo "  Version: $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo 'unknown')"
        if check_docker_compose; then
            echo "  Compose: ✓ docker compose v$(docker compose version --short 2>/dev/null)"
        else
            echo "  Compose: ✗ Not available"
        fi
    else
        echo "  Status:  ✗ Not available"
    fi

    echo ""
    echo "Podman:"
    if check_podman; then
        echo "  Status:  ✓ Available"
        echo "  Version: $(podman version --format '{{.Version}}' 2>/dev/null || echo 'unknown')"
        if check_podman_compose; then
            echo "  Compose: ✓ podman-compose $(podman-compose version 2>/dev/null | head -1)"
        else
            echo "  Compose: ✗ Not available"
        fi
    else
        echo "  Status:  ✗ Not available"
    fi

    echo ""
    echo "Selected Runtime:"
    local runtime
    if runtime=$(detect_runtime 2>/dev/null); then
        echo "  $runtime"
        echo ""
        echo "Compose Command:"
        echo "  $(get_compose_command 2>/dev/null)"
    else
        echo "  None available"
    fi
}

# Main
main() {
    local command=${1:-detect}

    case $command in
        detect)
            detect_runtime
            ;;
        compose)
            get_compose_command
            ;;
        version)
            get_version
            ;;
        check)
            if detect_runtime &> /dev/null; then
                exit 0
            else
                exit 1
            fi
            ;;
        info)
            print_info
            ;;
        help|--help|-h)
            cat << EOF
Usage: $0 [command]

Commands:
  detect   - Detect and print runtime name (docker/podman)
  compose  - Print compose command (docker compose / podman-compose)
  version  - Print runtime version
  check    - Check if runtime available (exit code only)
  info     - Print detailed runtime information

Environment:
  CONTAINER_RUNTIME - Override detection (docker/podman)

Examples:
  RUNTIME=\$($0 detect)
  COMPOSE=\$($0 compose)
  \$COMPOSE up -d
EOF
            ;;
        *)
            log_error "Unknown command: $command"
            exit 1
            ;;
    esac
}

# Allow override via environment
if [ -n "$CONTAINER_RUNTIME" ]; then
    case $CONTAINER_RUNTIME in
        docker|podman)
            echo "$CONTAINER_RUNTIME"
            exit 0
            ;;
    esac
fi

main "$@"
