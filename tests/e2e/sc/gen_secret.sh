#\!/bin/bash
ADMIN_TOKEN=$(cat /tmp/admin_master_token.txt)
curl -s -X POST "http://localhost:8180/admin/realms/test/clients/fe9ae7eb-70ab-4bd9-882f-d6e6e22df01d/client-secret" -H "Authorization: Bearer $ADMIN_TOKEN" | jq
