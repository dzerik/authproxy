#!/bin/bash
echo "Testing token endpoint with client_credentials..."

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "http://localhost:8180/realms/test/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=auth-portal&client_secret=test-client-secret")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY" | jq '.' 2>/dev/null || echo "$BODY"
