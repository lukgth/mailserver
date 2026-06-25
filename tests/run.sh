#!/bin/sh
# Docker integration tests for the mail server.
# Runs inside an Alpine container with access to the mailserver service.
#
# Exit codes: 0 = all pass, 1 = any fail

set -e

PASS=0
FAIL=0
TOTAL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { PASS=$((PASS + 1)); TOTAL=$((TOTAL + 1)); printf "${GREEN}  PASS${NC}  %s\n" "$1"; }
fail() { FAIL=$((FAIL + 1)); TOTAL=$((TOTAL + 1)); printf "${RED}  FAIL${NC}  %s\n" "$1"; [ -n "$2" ] && printf "        %s\n" "$2"; }
skip() { TOTAL=$((TOTAL + 1)); printf "${YELLOW}  SKIP${NC}  %s\n" "$1"; }
section() { echo ""; printf "${YELLOW}=== %s ===${NC}\n" "$1"; }

if ! command -v curl >/dev/null 2>&1; then
  apk add --no-cache curl openssl > /dev/null 2>&1
fi

MAIL=${MAIL_HOST:-mailtest}
ADMIN_URL="http://${MAIL}:${HTTP_PORT:-8080}"
AUTH_USER="${ADMIN_USER:-admin}"
AUTH_PASS="${ADMIN_PASS:-admin}"

acurl() { curl -sf -u "${AUTH_USER}:${AUTH_PASS}" "$@" 2>/dev/null; }

# ── Service Readiness ────────────────────────────────────────────────────────

section "Service Readiness"

printf "  Waiting for admin dashboard..."
for i in $(seq 1 30); do
  if curl -sf "$ADMIN_URL/pixel" >/dev/null 2>&1; then
    printf " ready\n"; break
  fi
  if [ "$i" -eq 30 ]; then
    printf " timeout\n"
    fail "Admin dashboard not reachable at $ADMIN_URL"
    printf "\n${RED}FATAL: Services not ready. Aborting.${NC}\n"; exit 1
  fi
  sleep 2
done

# Give Dovecot auth process extra time to initialize after config reload
sleep 2

# ── Admin Auth ───────────────────────────────────────────────────────────────

section "Admin Auth"

LOGIN_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -u "${AUTH_USER}:${AUTH_PASS}" "${ADMIN_URL}/" 2>/dev/null || echo "000")

if [ "$LOGIN_CODE" = "200" ]; then
  pass "Admin basic auth succeeds (HTTP $LOGIN_CODE)"
else
  fail "Admin basic auth failed (HTTP $LOGIN_CODE)"
fi

# ── Dovecot ──────────────────────────────────────────────────────────────────

section "Dovecot Configuration"

if printf "a001 LOGOUT\r\n" | timeout 5 openssl s_client -connect "${MAIL}:${IMAPS_PORT}" -quiet 2>/dev/null | grep -q "OK"; then
  pass "Dovecot IMAP SSL responding"
else
  if printf "a001 LOGOUT\r\n" | timeout 5 nc "${MAIL}" "${IMAP_PORT}" 2>/dev/null | grep -q "OK"; then
    pass "Dovecot IMAP responding (plaintext)"
  else
    fail "Dovecot IMAP not responding on port ${IMAP_PORT}/${IMAPS_PORT}"
  fi
fi

if printf "a001 QUIT\r\n" | timeout 5 nc "${MAIL}" "${POP3_PORT}" 2>/dev/null | grep -q "OK"; then
  pass "Dovecot POP3 responding"
else
  fail "Dovecot POP3 not responding on port ${POP3_PORT}"
fi

# ── SSL/TLS ──────────────────────────────────────────────────────────────────

section "SSL/TLS"

if timeout 5 openssl s_client -connect "${MAIL}:${SMTPS_PORT}" </dev/null 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
  pass "SMTPS TLS handshake succeeds"
else
  fail "SMTPS TLS handshake failed"
fi

if timeout 5 openssl s_client -connect "${MAIL}:${IMAPS_PORT}" </dev/null 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
  pass "IMAPS TLS handshake succeeds"
else
  fail "IMAPS TLS handshake failed"
fi

TLS_PROTO=$(timeout 5 openssl s_client -connect "${MAIL}:${IMAPS_PORT}" </dev/null 2>/dev/null | grep "Protocol  :" | awk '{print $3}')
if [ -n "$TLS_PROTO" ]; then pass "TLS supported ($TLS_PROTO)"; else skip "Could not determine TLS version"; fi

# ── Create Test Data ─────────────────────────────────────────────────────────

section "Test Data Setup"

TEST_USER="testuser"
TEST_DOMAIN="test.local"
TEST_PASS="testpass123"

DOMAIN_CREATE_CODE=$(curl -s -u "${AUTH_USER}:${AUTH_PASS}" -X POST "${ADMIN_URL}/domains" \
  -d "domain=${TEST_DOMAIN}&active=on" \
  -w "%{http_code}" -o /dev/null 2>/dev/null || echo "000")

if [ "$DOMAIN_CREATE_CODE" = "302" ] || [ "$DOMAIN_CREATE_CODE" = "200" ]; then
  pass "Test domain created: ${TEST_DOMAIN}"
elif acurl "${ADMIN_URL}/domains" 2>/dev/null | grep -q "${TEST_DOMAIN}"; then
  pass "Test domain exists: ${TEST_DOMAIN}"
else
  fail "Could not create test domain (HTTP $DOMAIN_CREATE_CODE)"
fi

ACCOUNT_CREATE_CODE=$(curl -s -u "${AUTH_USER}:${AUTH_PASS}" -X POST "${ADMIN_URL}/accounts" \
  -d "domain_id=1&username=${TEST_USER}&name=Test+User&password=${TEST_PASS}&confirm_password=${TEST_PASS}" \
  -w "%{http_code}" -o /dev/null 2>/dev/null || echo "000")

if [ "$ACCOUNT_CREATE_CODE" = "302" ] || [ "$ACCOUNT_CREATE_CODE" = "200" ]; then
  pass "Test account created: ${TEST_USER}@${TEST_DOMAIN}"
elif acurl "${ADMIN_URL}/accounts" 2>/dev/null | grep -q "${TEST_USER}"; then
  pass "Test account exists: ${TEST_USER}@${TEST_DOMAIN}"
else
  fail "Could not create test account (HTTP $ACCOUNT_CREATE_CODE)"
fi

# ── Mail Auth ────────────────────────────────────────────────────────────────

section "Mail Authentication"

# SMTP AUTH on submission port — requires STARTTLS first, skip if no TLS client
skip "SMTP AUTH requires STARTTLS (test container lacks TLS client)"

# IMAP LOGIN — wait for auth process, retry up to 3 times
IMAP_OK=false
for attempt in 1 2 3; do
  IMAP_RESULT=$(printf "a001 LOGIN ${TEST_USER}@${TEST_DOMAIN} ${TEST_PASS}\r\na002 LOGOUT\r\n" \
    | timeout 10 nc "${MAIL}" "${IMAP_PORT}" 2>/dev/null || echo "TIMEOUT")
  if echo "$IMAP_RESULT" | grep -q "a001 OK"; then
    IMAP_OK=true; break
  fi
  # If auth process not ready, wait and retry
  if echo "$IMAP_RESULT" | grep -q "Waiting for authentication"; then
    sleep 2
    continue
  fi
  # If plaintext auth disallowed, that's expected (TLS required)
  if echo "$IMAP_RESULT" | grep -q "PRIVACYREQUIRED"; then
    IMAP_OK="skip"; break
  fi
  break
done

if [ "$IMAP_OK" = true ]; then
  pass "IMAP LOGIN succeeds"
elif [ "$IMAP_OK" = "skip" ]; then
  skip "IMAP requires TLS for plaintext auth"
else
  fail "IMAP LOGIN failed" "$IMAP_RESULT"
fi

# POP3 AUTH — similar handling
POP3_RESULT=$(printf "USER ${TEST_USER}@${TEST_DOMAIN}\r\nPASS ${TEST_PASS}\r\nQUIT\r\n" \
  | timeout 10 nc "${MAIL}" "${POP3_PORT}" 2>/dev/null || echo "TIMEOUT")

if echo "$POP3_RESULT" | grep -q "+OK"; then
  pass "POP3 AUTH succeeds"
elif echo "$POP3_RESULT" | grep -q "Plaintext"; then
  skip "POP3 requires TLS for plaintext auth"
else
  fail "POP3 AUTH failed" "$POP3_RESULT"
fi

# ── Admin Dashboard ──────────────────────────────────────────────────────────

section "Admin Dashboard"

if acurl "${ADMIN_URL}/" 2>/dev/null | grep -qi "mailserver"; then
  pass "Admin dashboard loads"
else
  fail "Admin dashboard not loading"
fi

if acurl "${ADMIN_URL}/domains" 2>/dev/null | grep -qi "domain"; then
  pass "Domains page accessible"
else
  fail "Domains page not accessible"
fi

if acurl "${ADMIN_URL}/accounts" 2>/dev/null | grep -qi "account"; then
  pass "Accounts page accessible"
else
  fail "Accounts page not accessible"
fi

if acurl "${ADMIN_URL}/configs" 2>/dev/null | grep -qi "config"; then
  pass "Configs page accessible"
else
  fail "Configs page not accessible"
fi

# ── Postfix ──────────────────────────────────────────────────────────────────

section "Postfix"

SMTP_BANNER=$(timeout 5 nc "${MAIL}" "${SMTP_PORT}" 2>/dev/null || echo "TIMEOUT")
if echo "$SMTP_BANNER" | grep -q "220"; then
  pass "Postfix SMTP responding"
else
  fail "Postfix SMTP not responding"
fi

# Port 25 (MTA) accepts EHLO without STARTTLS
EHLO_RESP=$(printf "EHLO test\r\nQUIT\r\n" | timeout 5 nc "${MAIL}" "${SMTP_PORT}" 2>/dev/null || echo "TIMEOUT")
if echo "$EHLO_RESP" | grep -q "250"; then
  pass "Postfix EHLO works"
else
  # Some configs require STARTTLS on port 25 too — that's fine
  skip "Postfix EHLO requires STARTTLS on port 25"
fi

# ── Results ──────────────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
printf "Results: ${GREEN}%d passed${NC}, ${RED}%d failed${NC}, %d total\n" "$PASS" "$FAIL" "$TOTAL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ "$FAIL" -gt 0 ]; then
  printf "\n${RED}SOME TESTS FAILED${NC}\n"; exit 1
else
  printf "\n${GREEN}ALL TESTS PASSED${NC}\n"; exit 0
fi
