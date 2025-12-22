#!/bin/bash

echo "Getting admin token..."
TOKEN=$(curl -s -X POST "http://localhost:8180/realms/test/protocol/openid-connect/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=password&client_id=authz-service&client_secret=dnFt52FBc4itFrdGagSZRXw3JR6oomQJ&username=admin-user&password=admin-password" \
  | jq -r '.access_token')

if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
  echo "Failed to get token"
  exit 1
fi

echo "Token obtained: ${TOKEN:0:50}..."

echo -e "\n=== Testing mock routes through authz-service (port 8088) ==="

echo "1. /mock/user:"
RESP=$(curl -s -w "\nHTTP: %{http_code}" -H "Authorization: Bearer $TOKEN" http://localhost:8088/mock/user/__admin/health)
echo "$RESP"

echo -e "\n2. /mock/admin:"
RESP=$(curl -s -w "\nHTTP: %{http_code}" -H "Authorization: Bearer $TOKEN" http://localhost:8088/mock/admin/__admin/health)
echo "$RESP"

echo -e "\n3. /mock/external:"
RESP=$(curl -s -w "\nHTTP: %{http_code}" -H "Authorization: Bearer $TOKEN" http://localhost:8088/mock/external/__admin/health)
echo "$RESP"

echo -e "\n=== Testing mock routes through authz-service-external (port 9088) ==="

echo "1. /mock/user:"
RESP=$(curl -s -w "\nHTTP: %{http_code}" -H "Authorization: Bearer $TOKEN" http://localhost:9088/mock/user/__admin/health)
echo "$RESP"

echo -e "\n2. /mock/admin:"
RESP=$(curl -s -w "\nHTTP: %{http_code}" -H "Authorization: Bearer $TOKEN" http://localhost:9088/mock/admin/__admin/health)
echo "$RESP"

echo -e "\n3. /mock/external:"
RESP=$(curl -s -w "\nHTTP: %{http_code}" -H "Authorization: Bearer $TOKEN" http://localhost:9088/mock/external/__admin/health)
echo "$RESP"

echo -e "\nDone!"
