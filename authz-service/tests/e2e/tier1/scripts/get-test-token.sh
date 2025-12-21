#!/bin/bash
# Get test tokens from Keycloak for E2E testing
# Usage: ./get-test-token.sh [user_type] [format]
#
# User types: admin, user, service, external, agent
# Format: token (default), json, header

set -e

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8180}"
REALM="${REALM:-test}"

# Default credentials
CLIENT_ID="${CLIENT_ID:-authz-service}"
CLIENT_SECRET="${CLIENT_SECRET:-test-secret}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" >&2
}

# User credentials by type
get_credentials() {
    local user_type=$1

    case $user_type in
        admin)
            echo "admin-user admin-password"
            ;;
        user)
            echo "test-user test-password"
            ;;
        service)
            # Service account (client credentials grant)
            echo "__client_credentials__ __client_credentials__"
            ;;
        external)
            echo "external-user external-password"
            ;;
        agent)
            echo "agent-user agent-password"
            ;;
        *)
            log_error "Unknown user type: $user_type"
            echo "Available types: admin, user, service, external, agent"
            exit 1
            ;;
    esac
}

# Get token using password grant
get_password_token() {
    local username=$1
    local password=$2

    curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=password" \
        -d "client_id=${CLIENT_ID}" \
        -d "client_secret=${CLIENT_SECRET}" \
        -d "username=${username}" \
        -d "password=${password}" \
        -d "scope=openid profile email"
}

# Get token using client credentials grant
get_client_credentials_token() {
    curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        -d "client_id=${CLIENT_ID}" \
        -d "client_secret=${CLIENT_SECRET}" \
        -d "scope=openid"
}

# Exchange token (RFC 8693)
exchange_token() {
    local subject_token=$1
    local target_audience=${2:-authz-service-external}

    curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
        -d "client_id=${CLIENT_ID}" \
        -d "client_secret=${CLIENT_SECRET}" \
        -d "subject_token=${subject_token}" \
        -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
        -d "requested_token_type=urn:ietf:params:oauth:token-type:access_token" \
        -d "audience=${target_audience}"
}

# Get delegation token for agent
get_delegation_token() {
    local actor_token=$1
    local subject_token=$2

    curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
        -d "client_id=${CLIENT_ID}" \
        -d "client_secret=${CLIENT_SECRET}" \
        -d "subject_token=${subject_token}" \
        -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
        -d "actor_token=${actor_token}" \
        -d "actor_token_type=urn:ietf:params:oauth:token-type:access_token" \
        -d "requested_token_type=urn:ietf:params:oauth:token-type:access_token"
}

# Extract access token from response
extract_token() {
    local response=$1
    echo "$response" | jq -r '.access_token // empty'
}

# Format output
format_output() {
    local token=$1
    local format=$2
    local response=$3

    case $format in
        token)
            echo "$token"
            ;;
        json)
            echo "$response" | jq .
            ;;
        header)
            echo "Authorization: Bearer $token"
            ;;
        decoded)
            # Decode JWT payload (without verification)
            echo "$token" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
            ;;
        curl)
            echo "-H 'Authorization: Bearer $token'"
            ;;
        *)
            echo "$token"
            ;;
    esac
}

# Show usage
usage() {
    cat << EOF
Usage: $0 [user_type] [format]

User types:
  admin      - Admin user with full permissions
  user       - Regular user with limited permissions
  service    - Service account (client credentials)
  external   - External partner user
  agent      - Agent user for delegation chains

Formats:
  token      - Raw access token (default)
  json       - Full token response as JSON
  header     - Authorization header format
  decoded    - Decoded JWT payload
  curl       - curl -H flag format

Environment variables:
  KEYCLOAK_URL    - Keycloak URL (default: http://localhost:8180)
  REALM           - Realm name (default: test)
  CLIENT_ID       - OAuth client ID (default: authz-service)
  CLIENT_SECRET   - OAuth client secret (default: test-secret)

Examples:
  $0 user                    # Get user token
  $0 admin header            # Get admin token as header
  $0 service json            # Get service token as JSON
  $0 user decoded            # Decode user token JWT

Advanced:
  TOKEN=\$($0 user)
  EXCHANGED=\$($0 exchange \$TOKEN target-audience)
  DELEGATED=\$($0 delegate \$ACTOR_TOKEN \$SUBJECT_TOKEN)
EOF
}

# Main
main() {
    local user_type=${1:-user}
    local format=${2:-token}

    # Special commands
    case $user_type in
        help|--help|-h)
            usage
            exit 0
            ;;
        exchange)
            # Token exchange
            local subject_token=$2
            local target_audience=${3:-authz-service-external}
            if [ -z "$subject_token" ]; then
                log_error "Subject token required for exchange"
                exit 1
            fi
            local response
            response=$(exchange_token "$subject_token" "$target_audience")
            local token
            token=$(extract_token "$response")
            if [ -z "$token" ]; then
                log_error "Token exchange failed"
                echo "$response" | jq . >&2
                exit 1
            fi
            format_output "$token" "${4:-token}" "$response"
            exit 0
            ;;
        delegate)
            # Delegation (actor + subject)
            local actor_token=$2
            local subject_token=$3
            if [ -z "$actor_token" ] || [ -z "$subject_token" ]; then
                log_error "Both actor and subject tokens required for delegation"
                exit 1
            fi
            local response
            response=$(get_delegation_token "$actor_token" "$subject_token")
            local token
            token=$(extract_token "$response")
            if [ -z "$token" ]; then
                log_error "Token delegation failed"
                echo "$response" | jq . >&2
                exit 1
            fi
            format_output "$token" "${4:-token}" "$response"
            exit 0
            ;;
    esac

    # Get credentials
    local creds
    creds=$(get_credentials "$user_type")
    local username password
    username=$(echo "$creds" | cut -d' ' -f1)
    password=$(echo "$creds" | cut -d' ' -f2)

    # Get token
    local response
    if [ "$username" = "__client_credentials__" ]; then
        response=$(get_client_credentials_token)
    else
        response=$(get_password_token "$username" "$password")
    fi

    # Extract token
    local token
    token=$(extract_token "$response")

    if [ -z "$token" ]; then
        log_error "Failed to get token for $user_type"
        echo "$response" | jq . >&2
        exit 1
    fi

    format_output "$token" "$format" "$response"
}

main "$@"
