#!/bin/bash
curl -s -X POST "http://localhost:8180/realms/test/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=auth-portal" \
  -d "client_secret=test-client-secret" \
  -d "username=admin-user" \
  -d "password=password" \
  -d "scope=openid"
