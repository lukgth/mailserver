#!/bin/sh
# Quick-start: generate certs, set up .env, and bring up the stack.
#
# Usage:
#   ./quickstart.sh mail.yourdomain.com
#
# Then open https://mail.yourdomain.com in your browser.

set -e

DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then
  echo "Usage: $0 <mail-domain>"
  echo ""
  echo "Example:"
  echo "  $0 mail.example.com"
  echo ""
  echo "This will:"
  echo "  1. Create .env from .env.example (with your domain)"
  echo "  2. Generate a self-signed TLS certificate"
  echo "  3. Start the full stack (PostgreSQL + mailserver + nginx)"
  exit 1
fi

cd "$(dirname "$0")"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Mail Server Quick Start"
echo "  Domain: $DOMAIN"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Step 1: Create .env
if [ ! -f .env ]; then
  echo "▸ Creating .env from .env.example..."
  cp .env.example .env
  sed -i "s/HOSTNAME=mail.example.com/HOSTNAME=$DOMAIN/" .env
  # Generate a random DB password
  DB_PASS=$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 24)
  sed -i "s/DB_PASSWORD=changeme/DB_PASSWORD=$DB_PASS/" .env
  echo "  .env created (DB password auto-generated)"
else
  echo "▸ .env already exists, skipping"
fi
echo ""

# Step 2: Generate self-signed cert
echo "▸ Generating TLS certificate..."
./nginx/generate-self-signed-cert.sh "$DOMAIN"
echo ""

# Step 3: Start the stack
echo "▸ Starting services..."
docker compose -f docker-compose.prod.yml up -d --build
echo ""

# Wait for health
echo "▸ Waiting for services to be ready..."
for i in $(seq 1 60); do
  if docker compose -f docker-compose.prod.yml exec -T mailserver curl -sf http://localhost:8080/ >/dev/null 2>&1; then
    break
  fi
  if [ "$i" -eq 60 ]; then
    echo "  Services are still starting — check with:"
    echo "  docker compose -f docker-compose.prod.yml logs -f"
    exit 1
  fi
  sleep 2
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✓ Stack is running!"
echo ""
echo "  Dashboard:  https://$DOMAIN"
echo "  Login:      admin / $(grep SEED_PASS .env | cut -d= -f2)"
echo ""
echo "  Mail ports (direct):"
echo "    SMTP:   25, 587 (submission), 465 (SMTPS)"
echo "    IMAP:   143, 993 (IMAPS)"
echo "    POP3:   110, 995 (POP3S)"
echo ""
echo "  Logs:     docker compose -f docker-compose.prod.yml logs -f"
echo "  Stop:     docker compose -f docker-compose.prod.yml down"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
