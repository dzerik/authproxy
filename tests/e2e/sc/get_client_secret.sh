#!/bin/bash
ACCESS_TOKEN=$(curl -s -X POST "http://localhost:8180/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin&grant_type=password&client_id=admin-cli" | jq -r '.access_token')

CLIENT_ID=$(curl -s "http://localhost:8180/admin/realms/test/clients?clientId=auth-portal" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" | jq -r '.[0].id')

echo "Client UUID: $CLIENT_ID"

SECRET=$(curl -s "http://localhost:8180/admin/realms/test/clients/${CLIENT_ID}/client-secret" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" | jq -r '.value')

echo "Current secret in Keycloak: $SECRET"
echo "Expected secret: test-client-secret"

if [ "$SECRET" = "test-client-secret" ]; then
  echo "MATCH!"
else
  echo "MISMATCH! Regenerating..."
  curl -s -X POST "http://localhost:8180/admin/realms/test/clients/${CLIENT_ID}/client-secret" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    -H "Content-Type: application/json"

  # Set specific secret
  curl -s -X PUT "http://localhost:8180/admin/realms/test/clients/${CLIENT_ID}" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"id\":\"${CLIENT_ID}\",\"clientId\":\"auth-portal\",\"secret\":\"test-client-secret\"}"

  echo "Secret updated"
fi
