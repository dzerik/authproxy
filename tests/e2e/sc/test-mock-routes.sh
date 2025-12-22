#!/bin/bash
set -e

SCRIPT_DIR="/home/dzerik/Development/keycloack/tests/e2e/tier1/scripts"

echo "Getting admin token..."
TOKEN=$("$SCRIPT_DIR/get-test-token.sh" admin)
echo "Token obtained: ${TOKEN:0:50}..."

echo -e "\n=== Testing mock routes through authz-service (port 8088) ==="
echo "1. /mock/user:"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8088/mock/user/__admin/health | head -1
echo
echo "2. /mock/admin:"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8088/mock/admin/__admin/health | head -1
echo
echo "3. /mock/external:"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8088/mock/external/__admin/health | head -1
echo

echo -e "\n=== Testing mock routes through authz-service-external (port 9088) ==="
echo "1. /mock/user:"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:9088/mock/user/__admin/health | head -1
echo
echo "2. /mock/admin:"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:9088/mock/admin/__admin/health | head -1
echo
echo "3. /mock/external:"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:9088/mock/external/__admin/health | head -1
echo

echo -e "\nAll tests completed!"
