# Auth-Portal Dockerfile
# Multi-stage build with s6-overlay for process supervision

# =============================================================================
# Stage 1: Build Go binary
# =============================================================================
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.Version=$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')" \
    -o auth-portal \
    ./cmd/auth-portal

# =============================================================================
# Stage 2: s6-overlay base
# =============================================================================
FROM alpine:3.19 AS s6-base

# s6-overlay version
ARG S6_OVERLAY_VERSION=3.1.6.2

# Install s6-overlay
ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz /tmp
ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-x86_64.tar.xz /tmp
RUN apk add --no-cache xz \
    && tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz \
    && tar -C / -Jxpf /tmp/s6-overlay-x86_64.tar.xz \
    && rm -f /tmp/s6-overlay-*.tar.xz

# =============================================================================
# Stage 3: Final image
# =============================================================================
FROM alpine:3.19

# Labels
LABEL maintainer="auth-portal" \
      description="Authentication Portal with Nginx and Go backend" \
      version="1.0.0"

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    nginx \
    curl \
    && rm -rf /var/cache/apk/*

# Copy s6-overlay from s6-base
COPY --from=s6-base /command /command
COPY --from=s6-base /package /package
COPY --from=s6-base /etc/s6-overlay /etc/s6-overlay

# Create directories
RUN mkdir -p \
    /app \
    /app/configs \
    /app/templates \
    /var/log/nginx \
    /var/lib/nginx \
    /run/nginx \
    /etc/nginx/conf.d \
    && chown -R nginx:nginx /var/log/nginx /var/lib/nginx /run/nginx

# Copy Go binary
COPY --from=builder /build/auth-portal /app/auth-portal

# Copy configuration files
COPY configs/ /app/configs/

# Copy nginx templates
COPY nginx/templates/ /app/templates/nginx/

# Copy s6 service definitions
COPY s6-rc.d/ /etc/s6-overlay/s6-rc.d/

# Set permissions
RUN chmod +x /app/auth-portal \
    && chmod -R 755 /etc/s6-overlay/s6-rc.d

# Environment variables
ENV TZ=UTC \
    S6_BEHAVIOUR_IF_STAGE2_FAILS=2 \
    S6_CMD_WAIT_FOR_SERVICES_MAXTIME=30000 \
    AUTH_PORTAL_CONFIG=/app/configs/auth-portal.yaml \
    AUTH_PORTAL_NGINX_CONFIG=/etc/nginx/nginx.conf

# Expose ports
# 80 - HTTP (nginx)
# 443 - HTTPS (nginx)
# 8081 - Go backend (internal)
EXPOSE 80 443

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost/health || exit 1

# Use s6-overlay as init
ENTRYPOINT ["/command/s6-svscan", "/run/service"]

# Default command (can be overridden)
CMD []
