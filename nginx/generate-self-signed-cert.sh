#!/bin/sh
# Generate a self-signed TLS certificate for development/testing.
# For production, use Let's Encrypt (certbot) or your own CA.
#
# Usage: ./nginx/generate-self-signed-cert.sh [domain]

set -e

DOMAIN="${1:-mail.example.com}"
CERT_DIR="$(dirname "$0")/certs"

mkdir -p "$CERT_DIR"

if [ -f "$CERT_DIR/cert.pem" ] && [ -f "$CERT_DIR/key.pem" ]; then
  echo "Certificates already exist in $CERT_DIR"
  echo "  cert.pem: $(openssl x509 -in "$CERT_DIR/cert.pem" -noout -subject -dates 2>/dev/null)"
  echo ""
  echo "Delete them to regenerate:"
  echo "  rm $CERT_DIR/cert.pem $CERT_DIR/key.pem"
  exit 0
fi

echo "Generating self-signed certificate for: $DOMAIN"

openssl req -x509 -nodes -days 3650 \
  -newkey rsa:2048 \
  -keyout "$CERT_DIR/key.pem" \
  -out "$CERT_DIR/cert.pem" \
  -subj "/CN=$DOMAIN" \
  -addext "subjectAltName=DNS:$DOMAIN,DNS:*.$DOMAIN,IP:127.0.0.1" \
  2>/dev/null

chmod 600 "$CERT_DIR/key.pem"
chmod 644 "$CERT_DIR/cert.pem"

echo ""
echo "Done. Certificates written to:"
echo "  $CERT_DIR/cert.pem"
echo "  $CERT_DIR/key.pem"
echo ""
echo "These are self-signed — your browser will warn. Fine for dev."
echo "For production, replace with Let's Encrypt:"
echo "  certbot certonly --webroot -w /var/www/certbot -d $DOMAIN"
