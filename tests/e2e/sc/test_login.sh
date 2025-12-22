#!/bin/bash
echo "Testing developer login..."
RESULT=$(curl -s -X POST "http://localhost:8180/realms/test/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=developer&password=developer123&grant_type=password&client_id=auth-portal&client_secret=test-client-secret")

if echo "$RESULT" | jq -e '.access_token' > /dev/null 2>&1; then
  echo "SUCCESS: Got access token"
  echo "$RESULT" | jq '{token_type, expires_in, scope}'
else
  echo "FAILED:"
  echo "$RESULT" | jq '.'
fi
