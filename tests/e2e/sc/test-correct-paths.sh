#!/bin/bash

TOKEN=$(curl -s -X POST "http://localhost:8180/realms/test/protocol/openid-connect/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=password&client_id=authz-service&client_secret=dnFt52FBc4itFrdGagSZRXw3JR6oomQJ&username=admin-user&password=admin-password" \
  | jq -r '.access_token')

echo "Token: ${TOKEN:0:50}..."

echo -e "\n=== Internal authz-service (8088) ==="
echo "1. /mock/user/health (->  /health):"
curl -s -w "\nHTTP: %{http_code}\n" -H "Authorization: Bearer $TOKEN" http://localhost:8088/mock/user/health | head -2

echo -e "\n2. /mock/admin/admin/dashboard (-> /admin/dashboard):"
curl -s -w "\nHTTP: %{http_code}\n" -H "Authorization: Bearer $TOKEN" http://localhost:8088/mock/admin/admin/dashboard | head -2

echo -e "\n3. /mock/external/health (-> /health):"
curl -s -w "\nHTTP: %{http_code}\n" -H "Authorization: Bearer $TOKEN" http://localhost:8088/mock/external/health | head -2

echo -e "\n=== External authz-service (9088) ==="
echo "1. /mock/user/health:"
curl -s -w "\nHTTP: %{http_code}\n" -H "Authorization: Bearer $TOKEN" http://localhost:9088/mock/user/health | head -2

echo -e "\n2. /mock/admin/admin/dashboard:"
curl -s -w "\nHTTP: %{http_code}\n" -H "Authorization: Bearer $TOKEN" http://localhost:9088/mock/admin/admin/dashboard | head -2

echo -e "\n3. /mock/external/health:"
curl -s -w "\nHTTP: %{http_code}\n" -H "Authorization: Bearer $TOKEN" http://localhost:9088/mock/external/health | head -2
