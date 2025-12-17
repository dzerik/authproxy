# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build arguments for version info
ARG VERSION=dev
ARG BUILD_TIME
ARG GIT_COMMIT

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GitCommit=${GIT_COMMIT}" \
    -o /app/bin/authz \
    ./cmd/authz

# Final stage
FROM alpine:3.20

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 authz && \
    adduser -u 1000 -G authz -s /bin/sh -D authz

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/bin/authz /app/authz

# Copy default config
COPY --from=builder /app/configs/config.yaml /etc/authz/config.yaml
COPY --from=builder /app/configs/rules.yaml /etc/authz/rules.yaml

# Set ownership
RUN chown -R authz:authz /app /etc/authz

# Switch to non-root user
USER authz

# Expose ports
EXPOSE 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Set entrypoint
ENTRYPOINT ["/app/authz"]

# Default command
CMD ["--config", "/etc/authz/config.yaml"]
