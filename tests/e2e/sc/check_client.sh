#\!/bin/bash
ADMIN_TOKEN=$(cat /tmp/admin_master_token.txt)
curl -s -X GET "http://localhost:8180/admin/realms/test/clients" -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.[] | select(.clientId == "authz-service") | {clientId, directAccessGrantsEnabled, publicClient, id}'
