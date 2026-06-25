#!/bin/sh
# Generate a self-signed TLS certificate for development/testing.
# Outputs to the certbot live directory structure so nginx can find it.
#
# Usage: ./nginx/generate-self-signed-cert.sh [domain]

set -e

DOMAIN="${1:-mail.example.com}"
LIVE_DIR="$(dirname "$0")/certs/live/$DOMAIN"

mkdir -p "$LIVE_DIR"

if [ -f "$LIVE_DIR/fullchain.pem" ] && [ -f "$LIVE_DIR/privkey.pem" ]; then
  echo "Certificates already exist for $DOMAIN"
  echo "  $LIVE_DIR/fullchain.pem: $(openssl x509 -in "$LIVE_DIR/fullchain.pem" -noout -subject -dates 2>/dev/null)"
  echo ""
  echo "Delete them to regenerate:"
  echo "  rm $LIVE_DIR/fullchain.pem $LIVE_DIR/privkey.pem"
  exit 0
fi

echo "Generating self-signed certificate for: $DOMAIN"

openssl req -x509 -nodes -days 3650 \
  -newkey rsa:2048 \
  -keyout "$LIVE_DIR/privkey.pem" \
  -out "$LIVE_DIR/fullchain.pem" \
  -subj "/CN=$DOMAIN" \
  -addext "subjectAltName=DNS:$DOMAIN,DNS:*.$DOMAIN,IP:127.0.0.1" \
  2>/dev/null

chmod 600 "$LIVE_DIR/privkey.pem"
chmod 644 "$LIVE_DIR/fullchain.pem"

echo ""
echo "Done. Certificates written to:"
echo "  $LIVE_DIR/fullchain.pem"
echo "  $LIVE_DIR/privkey.pem"
echo ""
echo "These are self-signed — your browser will warn. Fine for dev."
echo "For production, replace with Let's Encrypt:"
echo "  certbot certonly --webroot -w /var/www/certbot -d $DOMAIN"
