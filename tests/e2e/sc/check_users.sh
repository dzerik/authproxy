#!/bin/bash
ACCESS_TOKEN=$(curl -s -X POST "http://localhost:8180/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin&grant_type=password&client_id=admin-cli" | jq -r '.access_token')

echo "=== Users in test realm ==="
curl -s "http://localhost:8180/admin/realms/test/users" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" | jq -r '.[] | "\(.username) | enabled: \(.enabled) | credentials: \(.credentials | length)"'
