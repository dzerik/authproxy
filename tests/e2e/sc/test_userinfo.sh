#!/bin/bash
echo "Getting access token..."
TOKEN_RESPONSE=$(curl -s -X POST "http://localhost:8180/realms/test/protocol/openid-connect/token" \
  -u "auth-portal:test-client-secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=developer&password=developer123")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

if [ "$ACCESS_TOKEN" = "null" ] || [ -z "$ACCESS_TOKEN" ]; then
  echo "Failed to get token"
  echo "$TOKEN_RESPONSE" | jq '.'
  exit 1
fi

echo "Token obtained, testing userinfo..."
USERINFO=$(curl -s "http://localhost:8180/realms/test/protocol/openid-connect/userinfo" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

echo "UserInfo response:"
echo "$USERINFO" | jq '.'
