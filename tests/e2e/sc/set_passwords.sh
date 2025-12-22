#!/bin/bash
TOKEN=$(cat /tmp/admin_token.txt)
KC_URL="http://localhost:8180"

set_password() {
    local username="$1"
    local password="$2"
    user_id=$(curl -s -H "Authorization: Bearer $TOKEN" \
        "$KC_URL/admin/realms/test/users?username=$username" | jq -r '.[0].id')
    if [ "$user_id" != "null" ] && [ -n "$user_id" ]; then
        echo "Setting password for $username..."
        curl -s -X PUT -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            "$KC_URL/admin/realms/test/users/$user_id/reset-password" \
            -d "{\"type\":\"password\",\"value\":\"$password\",\"temporary\":false}"
        echo " Done"
    else
        echo "User $username not found"
    fi
}

set_password "admin-user" "admin-password"
set_password "test-user" "test-password"
set_password "developer" "developer"
set_password "viewer" "viewer"
set_password "external-user" "external-password"
set_password "agent-user" "agent-password"
echo "All passwords set!"
