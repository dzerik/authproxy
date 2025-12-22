#!/bin/bash
TOKEN=$(curl -s -X POST "http://localhost:8180/realms/test/protocol/openid-connect/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=password&client_id=auth-portal&client_secret=test-client-secret&username=admin-user&password=admin-password" \
  | jq -r '.access_token')

echo "Token audience info:"
echo "$TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '{aud, azp, iss}'
