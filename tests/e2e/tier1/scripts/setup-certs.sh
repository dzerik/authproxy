#!/bin/bash
# Setup TLS certificates using mkcert for local development
# Requires: mkcert (https://github.com/FiloSottile/mkcert)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/../certs"

mkdir -p "$CERTS_DIR"

echo "=== Setting up TLS certificates with mkcert ==="

# Check if mkcert is installed
if ! command -v mkcert &> /dev/null; then
    echo "mkcert not found. Installing..."

    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux - download binary
        MKCERT_VERSION=$(curl -s https://api.github.com/repos/FiloSottile/mkcert/releases/latest | grep tag_name | cut -d '"' -f 4)
        curl -JLO "https://github.com/FiloSottile/mkcert/releases/download/${MKCERT_VERSION}/mkcert-${MKCERT_VERSION}-linux-amd64"
        chmod +x mkcert-*-linux-amd64
        sudo mv mkcert-*-linux-amd64 /usr/local/bin/mkcert
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        brew install mkcert
    else
        echo "Unsupported OS. Please install mkcert manually."
        exit 1
    fi

    # Install local CA
    echo "Installing local CA..."
    mkcert -install
fi

echo "Generating certificates..."

# Server certificate for authz-service (internal)
echo "  - authz-service (internal)"
mkcert -cert-file "$CERTS_DIR/authz-service.crt" \
       -key-file "$CERTS_DIR/authz-service.key" \
       authz-service localhost 127.0.0.1 ::1

# Server certificate for authz-service-external
echo "  - authz-service-external"
mkcert -cert-file "$CERTS_DIR/authz-external.crt" \
       -key-file "$CERTS_DIR/authz-external.key" \
       authz-service-external localhost 127.0.0.1 ::1

# Client certificate for internal service (mTLS)
echo "  - client-internal (mTLS)"
mkcert -client \
       -cert-file "$CERTS_DIR/client-internal.crt" \
       -key-file "$CERTS_DIR/client-internal.key" \
       "internal-service" "spiffe://cluster.local/ns/default/sa/internal"

# Client certificate for external partner (mTLS)
echo "  - client-external (mTLS)"
mkcert -client \
       -cert-file "$CERTS_DIR/client-external.crt" \
       -key-file "$CERTS_DIR/client-external.key" \
       "external-partner" "spiffe://partner.local/ns/default/sa/partner"

# Copy CA certificate
echo "  - CA certificate"
cp "$(mkcert -CAROOT)/rootCA.pem" "$CERTS_DIR/ca.crt"

# Set permissions
chmod 644 "$CERTS_DIR"/*.crt
chmod 600 "$CERTS_DIR"/*.key

echo ""
echo "=== Certificates created successfully ==="
echo "Location: $CERTS_DIR"
ls -la "$CERTS_DIR/"
