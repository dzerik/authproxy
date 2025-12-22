#!/bin/sh
# Generate nginx configuration from auth-portal config

# Set config path
CONFIG="${AUTH_PORTAL_CONFIG:-/app/configs/auth-portal.yaml}"

# Wait for auth-portal to be ready
sleep 2

# Generate nginx config using auth-portal
/app/auth-portal -generate-nginx -config "$CONFIG" -output /etc/nginx/nginx.conf

# Test nginx configuration
nginx -t -c /etc/nginx/nginx.conf
