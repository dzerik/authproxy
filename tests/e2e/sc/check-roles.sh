#!/bin/bash
TOKEN=$(curl -s -X POST "http://localhost:8180/realms/test/protocol/openid-connect/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=password&client_id=authz-service&client_secret=dnFt52FBc4itFrdGagSZRXw3JR6oomQJ&username=admin-user&password=admin-password" \
  | jq -r '.access_token')

echo "Roles in token:"
echo "$TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '.realm_access.roles'
