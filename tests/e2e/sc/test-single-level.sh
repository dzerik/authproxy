#!/bin/bash
TOKEN=$(curl -s -X POST "http://localhost:8180/realms/test/protocol/openid-connect/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=password&client_id=authz-service&client_secret=dnFt52FBc4itFrdGagSZRXw3JR6oomQJ&username=admin-user&password=admin-password" \
  | jq -r '.access_token')

echo "Testing external (9088):"
echo "1. /mock/admin/health:"
curl -s -w "\nHTTP: %{http_code}\n" -H "Authorization: Bearer $TOKEN" http://localhost:9088/mock/admin/health | head -2

echo -e "\n2. /mock/admin/admin:"
curl -s -w "\nHTTP: %{http_code}\n" -H "Authorization: Bearer $TOKEN" http://localhost:9088/mock/admin/admin | head -2

echo -e "\n3. /mock/admin/test:"
curl -s -w "\nHTTP: %{http_code}\n" -H "Authorization: Bearer $TOKEN" http://localhost:9088/mock/admin/test | head -2
