#!/bin/sh
# Quick-start: set up .env, get TLS certs, and bring up the stack.
#
# Usage:
#   ./quickstart.sh mail.yourdomain.com              # Let's Encrypt (needs public DNS)
#   ./quickstart.sh mail.yourdomain.com --self-signed  # Self-signed (dev/internal)

set -e

DOMAIN="${1:-}"
MODE="${2:-letsencrypt}"

if [ -z "$DOMAIN" ]; then
  echo "Usage: $0 <mail-domain> [--self-signed]"
  echo ""
  echo "Examples:"
  echo "  $0 mail.example.com              # Let's Encrypt (production)"
  echo "  $0 mail.example.com --self-signed  # Self-signed (dev/testing)"
  echo ""
  echo "This will:"
  echo "  1. Create .env from .env.example"
  echo "  2. Get TLS certificate (Let's Encrypt or self-signed)"
  echo "  3. Start: PostgreSQL + mailserver + nginx + certbot"
  exit 1
fi

cd "$(dirname "$0")"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Mail Server Quick Start"
echo "  Domain: $DOMAIN"
echo "  TLS:    $MODE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Step 1: Create .env ──────────────────────────────────────────────────────

if [ ! -f .env ]; then
  echo "▸ Creating .env from .env.example..."
  cp .env.example .env
  sed -i "s/HOSTNAME=mail.example.com/HOSTNAME=$DOMAIN/" .env
  DB_PASS=$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 24)
  SEED_PASS=$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 20)
  sed -i "s/DB_PASSWORD=MUST-BE-CHANGED/DB_PASSWORD=$DB_PASS/" .env
  sed -i "s/SEED_PASS=MUST-BE-CHANGED/SEED_PASS=$SEED_PASS/" .env
  echo "  .env created (DB password and admin password auto-generated)"
else
  echo "▸ .env already exists, skipping"
fi
echo ""

# ── Step 2: Get TLS certificate ──────────────────────────────────────────────

if [ "$MODE" = "--self-signed" ]; then
  echo "▸ Generating self-signed certificate..."
  ./nginx/generate-self-signed-cert.sh "$DOMAIN"
  echo ""
else
  # Let's Encrypt
  echo "▸ Starting nginx for ACME challenge..."
  docker compose -f docker-compose.prod.yml up -d nginx
  sleep 3

  # Check if port 80 is reachable from outside (required for HTTP-01 challenge)
  echo "▸ Requesting Let's Encrypt certificate..."
  docker compose -f docker-compose.prod.yml run --rm certbot certonly \
    --webroot \
    --webroot-path=/var/www/certbot \
    --email "admin@${DOMAIN}" \
    --agree-tos \
    --no-eff-email \
    -d "$DOMAIN" \
    2>&1 || {
      echo ""
      echo "  ✗ Let's Encrypt failed. This usually means:"
      echo "    - DNS not pointing to this server's public IP"
      echo "    - Port 80 not reachable from the internet"
      echo "    - Rate limit hit"
      echo ""
      echo "  Falling back to self-signed certificate..."
      ./nginx/generate-self-signed-cert.sh "$DOMAIN"
    }

  # Stop nginx (will restart with the full stack)
  docker compose -f docker-compose.prod.yml down nginx 2>/dev/null || true
  echo ""
fi

# ── Step 3: Start the stack ──────────────────────────────────────────────────

echo "▸ Starting services..."
docker compose -f docker-compose.prod.yml up -d --build
echo ""

# Wait for health
echo "▸ Waiting for services to be ready..."
for i in $(seq 1 60); do
  if docker compose -f docker-compose.prod.yml exec -T nginx curl -sf http://mailserver:8080/pixel >/dev/null 2>&1; then
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
if [ "$MODE" != "--self-signed" ]; then
  echo "  TLS certs: Let's Encrypt (auto-renews every 12h)"
  echo "  Renew:     docker compose -f docker-compose.prod.yml run --rm certbot renew"
  echo "  Force:     docker compose -f docker-compose.prod.yml restart nginx"
fi
echo ""
echo "  Logs:     docker compose -f docker-compose.prod.yml logs -f"
echo "  Stop:     docker compose -f docker-compose.prod.yml down"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
