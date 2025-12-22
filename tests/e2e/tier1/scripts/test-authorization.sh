#!/bin/bash
# Authorization Test Script for E2E Tier 1
# Tests RBAC policies through authz-service with OPA and Builtin engines
#
# Two services run in parallel:
#   - authz-service (port 8088) - OPA sidecar engine
#   - authz-service-external (port 9088) - Builtin engine
#
# Usage:
#   ./test-authorization.sh                    # Test both engines
#   ./test-authorization.sh --engine opa       # Test only OPA sidecar
#   ./test-authorization.sh --engine builtin   # Test only builtin engine

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8180}"
CLIENT_ID="${CLIENT_ID:-authz-service}"
CLIENT_SECRET="${CLIENT_SECRET:-dnFt52FBc4itFrdGagSZRXw3JR6oomQJ}"
REALM="${REALM:-test}"

# Service URLs
# OPA sidecar runs proxy on port 8088
# Builtin runs proxy on port 9088 (same functionality, different engine)
OPA_SERVICE_URL="${OPA_SERVICE_URL:-http://localhost:8088}"
BUILTIN_SERVICE_URL="${BUILTIN_SERVICE_URL:-http://localhost:9088}"

# Engine selection (opa, builtin, or both)
ENGINE="${ENGINE:-both}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Counters
PASS=0
FAIL=0
TOTAL_PASS=0
TOTAL_FAIL=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --engine)
            ENGINE="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--engine opa|builtin|both]"
            echo ""
            echo "Options:"
            echo "  --engine opa      Test OPA sidecar engine (port 8088)"
            echo "  --engine builtin  Test builtin engine (port 9088)"
            echo "  --engine both     Test both engines (default)"
            echo ""
            echo "Environment variables:"
            echo "  OPA_SERVICE_URL      URL for OPA sidecar service (default: http://localhost:8088)"
            echo "  BUILTIN_SERVICE_URL  URL for builtin engine service (default: http://localhost:9088)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Functions
log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
log_header() { echo -e "\n${BLUE}=== $1 ===${NC}"; }

get_token() {
    local username=$1
    local password=$2
    curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -d "grant_type=password&client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&username=${username}&password=${password}" \
        | jq -r '.access_token'
}

test_endpoint() {
    local service_url=$1
    local description=$2
    local method=$3
    local endpoint=$4
    local token=$5
    local expected_code=$6

    local auth_header=""
    if [ -n "$token" ] && [ "$token" != "null" ]; then
        auth_header="-H \"Authorization: Bearer ${token}\""
    fi

    local response=$(eval curl -s -o /dev/null -w '%{http_code}' -X ${method} \"${service_url}${endpoint}\" ${auth_header} -H \"Content-Type: application/json\")

    if [ "$response" == "$expected_code" ]; then
        log_pass "${description}: ${method} ${endpoint} -> ${response}"
    else
        log_fail "${description}: ${method} ${endpoint} -> ${response} (expected ${expected_code})"
    fi
}

check_service_health() {
    local url=$1
    local name=$2
    local health_response=$(curl -s -o /dev/null -w '%{http_code}' "${url}/health" 2>/dev/null)
    if [ "$health_response" == "200" ]; then
        log_info "${name} is healthy"
        return 0
    else
        log_fail "${name} is not responding (${health_response})"
        return 1
    fi
}

run_tests_for_engine() {
    local engine_name=$1
    local service_url=$2

    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo -e "║  ${CYAN}Authorization E2E Test Suite${NC}                              ║"
    echo -e "║  Engine: ${BLUE}${engine_name}${NC}                                          ║"
    echo -e "║  URL: ${service_url}                               ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""

    # Reset counters
    PASS=0
    FAIL=0

    # Check service health
    if ! check_service_health "$service_url" "$engine_name"; then
        log_fail "Service not available, skipping tests"
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
        return 1
    fi

    log_info "Getting tokens for test users..."

    # Get tokens (reuse from previous calls if available)
    if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" == "null" ]; then
        ADMIN_TOKEN=$(get_token "admin-user" "admin-password")
    fi
    if [ -z "$USER_TOKEN" ] || [ "$USER_TOKEN" == "null" ]; then
        USER_TOKEN=$(get_token "test-user" "test-password")
    fi
    if [ -z "$VIEWER_TOKEN" ] || [ "$VIEWER_TOKEN" == "null" ]; then
        VIEWER_TOKEN=$(get_token "viewer" "viewer")
    fi

    if [ "$ADMIN_TOKEN" == "null" ] || [ -z "$ADMIN_TOKEN" ]; then
        log_fail "Failed to get admin-user token"
        return 1
    fi
    log_info "admin-user token obtained"

    if [ "$USER_TOKEN" == "null" ] || [ -z "$USER_TOKEN" ]; then
        log_fail "Failed to get test-user token"
        return 1
    fi
    log_info "test-user token obtained"

    if [ "$VIEWER_TOKEN" == "null" ] || [ -z "$VIEWER_TOKEN" ]; then
        log_fail "Failed to get viewer token"
        return 1
    fi
    log_info "viewer token obtained"

    log_header "Public Endpoints (no auth)"
    test_endpoint "$service_url" "Anonymous health check" "GET" "/health" "" "200"

    log_header "Admin User (roles: admin, user)"
    test_endpoint "$service_url" "Admin: GET /admin/dashboard" "GET" "/admin/dashboard" "$ADMIN_TOKEN" "200"
    test_endpoint "$service_url" "Admin: GET /api/v1/users" "GET" "/api/v1/users" "$ADMIN_TOKEN" "200"
    test_endpoint "$service_url" "Admin: POST /api/v1/users" "POST" "/api/v1/users" "$ADMIN_TOKEN" "201"
    test_endpoint "$service_url" "Admin: GET /api/v1/users/me" "GET" "/api/v1/users/me" "$ADMIN_TOKEN" "200"
    test_endpoint "$service_url" "Admin: PUT /api/v1/users/me" "PUT" "/api/v1/users/me" "$ADMIN_TOKEN" "200"

    log_header "Test User (role: user only)"
    test_endpoint "$service_url" "User: GET /admin (denied)" "GET" "/admin" "$USER_TOKEN" "403"
    test_endpoint "$service_url" "User: GET /api/v1/users/me" "GET" "/api/v1/users/me" "$USER_TOKEN" "200"
    test_endpoint "$service_url" "User: PUT /api/v1/users/me" "PUT" "/api/v1/users/me" "$USER_TOKEN" "200"

    # Different behavior based on engine
    if [ "$engine_name" == "opa-sidecar" ]; then
        # OPA: api_v1_read rule allows 'user' role to GET /api/v1/*
        test_endpoint "$service_url" "User: GET /api/v1/users (OPA: allowed)" "GET" "/api/v1/users" "$USER_TOKEN" "200"
    else
        # Builtin: users-list requires 'admin' role for /api/v1/users
        test_endpoint "$service_url" "User: GET /api/v1/users (builtin: denied)" "GET" "/api/v1/users" "$USER_TOKEN" "403"
    fi
    test_endpoint "$service_url" "User: POST /api/v1/users (denied)" "POST" "/api/v1/users" "$USER_TOKEN" "403"

    log_header "Viewer User (role: viewer - read only)"
    test_endpoint "$service_url" "Viewer: GET /admin (denied)" "GET" "/admin" "$VIEWER_TOKEN" "403"
    test_endpoint "$service_url" "Viewer: GET /api/v1/users" "GET" "/api/v1/users" "$VIEWER_TOKEN" "200"
    test_endpoint "$service_url" "Viewer: POST /api/v1/users (denied)" "POST" "/api/v1/users" "$VIEWER_TOKEN" "403"
    test_endpoint "$service_url" "Viewer: DELETE /api/v1/users/1 (denied)" "DELETE" "/api/v1/users/1" "$VIEWER_TOKEN" "403"

    log_header "Unauthorized Access"
    test_endpoint "$service_url" "No token: GET /admin" "GET" "/admin" "" "403"
    test_endpoint "$service_url" "No token: GET /api/v1/users" "GET" "/api/v1/users" "" "403"
    test_endpoint "$service_url" "No token: POST /api/v1/users" "POST" "/api/v1/users" "" "403"

    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo -e "  Engine: ${BLUE}${engine_name}${NC}"
    echo -e "  Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
    echo "════════════════════════════════════════════════════════════════"

    TOTAL_PASS=$((TOTAL_PASS + PASS))
    TOTAL_FAIL=$((TOTAL_FAIL + FAIL))

    return $FAIL
}

# Main execution
echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo -e "║  ${CYAN}E2E Authorization Testing${NC}                                     ║"
echo "║                                                                  ║"
echo -e "║  OPA Sidecar:  ${OPA_SERVICE_URL}                              ║"
echo -e "║  Builtin:      ${BUILTIN_SERVICE_URL}                              ║"
echo "╚════════════════════════════════════════════════════════════════╝"

case "$ENGINE" in
    opa|opa-sidecar)
        run_tests_for_engine "opa-sidecar" "$OPA_SERVICE_URL"
        ;;
    builtin)
        run_tests_for_engine "builtin" "$BUILTIN_SERVICE_URL"
        ;;
    both|*)
        # Test OPA sidecar
        run_tests_for_engine "opa-sidecar" "$OPA_SERVICE_URL"

        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

        # Test builtin
        run_tests_for_engine "builtin" "$BUILTIN_SERVICE_URL"

        echo ""
        echo "╔════════════════════════════════════════════════════════════════╗"
        echo -e "║  ${CYAN}COMBINED RESULTS${NC}                                             ║"
        echo "╠════════════════════════════════════════════════════════════════╣"
        echo -e "║  OPA Sidecar + Builtin                                         ║"
        echo -e "║  Total: ${GREEN}${TOTAL_PASS} passed${NC}, ${RED}${TOTAL_FAIL} failed${NC}                                   ║"
        echo "╚════════════════════════════════════════════════════════════════╝"
        ;;
esac

if [ $TOTAL_FAIL -gt 0 ]; then
    exit 1
fi
exit 0
