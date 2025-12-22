#!/bin/bash
echo "Testing with Basic Auth..."

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "http://localhost:8180/realms/test/protocol/openid-connect/token" \
  -u "auth-portal:test-client-secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY" | jq '.' 2>/dev/null || echo "$BODY"

echo ""
echo "Testing password grant with Basic Auth..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "http://localhost:8180/realms/test/protocol/openid-connect/token" \
  -u "auth-portal:test-client-secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=developer&password=developer123")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY" | jq '{access_token: .access_token[0:30], error}' 2>/dev/null || echo "$BODY"
