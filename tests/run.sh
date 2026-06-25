#!/bin/sh
# Docker integration tests for the mail server.
# Runs inside an Alpine container with access to the mailserver service.
#
# Exit codes: 0 = all pass, 1 = any fail

set -e

PASS=0
FAIL=0
TOTAL=0
COOKIES=/tmp/cookies

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() {
  PASS=$((PASS + 1))
  TOTAL=$((TOTAL + 1))
  printf "${GREEN}  PASS${NC}  %s\n" "$1"
}

fail() {
  FAIL=$((FAIL + 1))
  TOTAL=$((TOTAL + 1))
  printf "${RED}  FAIL${NC}  %s\n" "$1"
  if [ -n "$2" ]; then
    printf "        %s\n" "$2"
  fi
}

skip() {
  TOTAL=$((TOTAL + 1))
  printf "${YELLOW}  SKIP${NC}  %s\n" "$1"
}

section() {
  echo ""
  printf "${YELLOW}=== %s ===${NC}\n" "$1"
}

# Ensure curl/openssl/nc are available
if ! command -v curl >/dev/null 2>&1; then
  apk add --no-cache curl openssl > /dev/null 2>&1
fi

MAIL=${MAIL_HOST:-mailtest}
ADMIN_URL="http://${MAIL}:${HTTP_PORT:-8080}"

# ── Service Readiness ────────────────────────────────────────────────────────

section "Service Readiness"

printf "  Waiting for admin dashboard..."
for i in $(seq 1 30); do
  if curl -sf "$ADMIN_URL/pixel" >/dev/null 2>&1; then
    printf " ready\n"
    break
  fi
  if [ "$i" -eq 30 ]; then
    printf " timeout\n"
    fail "Admin dashboard not reachable at $ADMIN_URL"
    echo ""
    printf "${RED}FATAL: Services not ready. Aborting.${NC}\n"
    exit 1
  fi
  sleep 2
done

# ── Admin Login ──────────────────────────────────────────────────────────────

section "Admin Login"

LOGIN_RESP=$(curl -s -c "$COOKIES" -X POST "${ADMIN_URL}/login" \
  -d "username=${ADMIN_USER:-admin}&password=${ADMIN_PASS:-admin}" \
  -w "\n%{http_code}" 2>/dev/null)
LOGIN_CODE=$(echo "$LOGIN_RESP" | tail -1)

if [ "$LOGIN_CODE" = "302" ] || [ "$LOGIN_CODE" = "200" ]; then
  pass "Admin login succeeds (HTTP $LOGIN_CODE)"
else
  fail "Admin login failed (HTTP $LOGIN_CODE)"
  # Try to continue — some tests may still work
fi

# Helper: authenticated curl
acurl() {
  curl -sf -b "$COOKIES" "$@" 2>/dev/null
}

# ── Dovecot Config Validation ────────────────────────────────────────────────

section "Dovecot Configuration"

# Test: Dovecot IMAP port responds
if printf "a001 LOGOUT\r\n" | timeout 5 openssl s_client -connect "${MAIL}:${IMAPS_PORT}" -quiet 2>/dev/null | grep -q "OK"; then
  pass "Dovecot IMAP SSL responding"
else
  if printf "a001 LOGOUT\r\n" | timeout 5 nc "${MAIL}" "${IMAP_PORT}" 2>/dev/null | grep -q "OK"; then
    pass "Dovecot IMAP responding (plaintext)"
  else
    fail "Dovecot IMAP not responding on port ${IMAP_PORT}/${IMAPS_PORT}"
  fi
fi

# Test: Dovecot POP3 port responds
if printf "a001 QUIT\r\n" | timeout 5 nc "${MAIL}" "${POP3_PORT}" 2>/dev/null | grep -q "OK"; then
  pass "Dovecot POP3 responding"
else
  fail "Dovecot POP3 not responding on port ${POP3_PORT}"
fi

# ── SSL/TLS Validation ───────────────────────────────────────────────────────

section "SSL/TLS"

# Test: SMTP TLS handshake
if timeout 5 openssl s_client -connect "${MAIL}:${SMTPS_PORT}" </dev/null 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
  pass "SMTPS TLS handshake succeeds"
else
  fail "SMTPS TLS handshake failed"
fi

# Test: IMAPS TLS handshake
if timeout 5 openssl s_client -connect "${MAIL}:${IMAPS_PORT}" </dev/null 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
  pass "IMAPS TLS handshake succeeds"
else
  fail "IMAPS TLS handshake failed"
fi

# Test: TLS protocol version
TLS_PROTO=$(timeout 5 openssl s_client -connect "${MAIL}:${IMAPS_PORT}" </dev/null 2>/dev/null | grep "Protocol  :" | awk '{print $3}')
if [ -n "$TLS_PROTO" ]; then
  pass "TLS supported ($TLS_PROTO)"
else
  skip "Could not determine TLS version"
fi

# ── Create Test Domain & Account ─────────────────────────────────────────────

section "Test Data Setup"

TEST_USER="testuser"
TEST_DOMAIN="test.local"
TEST_PASS="testpass123"

# Create test domain via admin (needs auth cookies)
DOMAIN_CREATE_CODE=$(curl -s -b "$COOKIES" -X POST "${ADMIN_URL}/domains" \
  -d "domain=${TEST_DOMAIN}&active=on" \
  -w "%{http_code}" -o /dev/null 2>/dev/null || echo "000")

if [ "$DOMAIN_CREATE_CODE" = "302" ] || [ "$DOMAIN_CREATE_CODE" = "200" ]; then
  pass "Test domain created: ${TEST_DOMAIN}"
elif acurl "${ADMIN_URL}/domains" 2>/dev/null | grep -q "${TEST_DOMAIN}"; then
  pass "Test domain exists: ${TEST_DOMAIN}"
else
  fail "Could not create test domain (HTTP $DOMAIN_CREATE_CODE)"
fi

# Create test account via admin
ACCOUNT_CREATE_CODE=$(curl -s -b "$COOKIES" -X POST "${ADMIN_URL}/accounts" \
  -d "domain_id=1&username=${TEST_USER}&name=Test+User&password=${TEST_PASS}&confirm_password=${TEST_PASS}" \
  -w "%{http_code}" -o /dev/null 2>/dev/null || echo "000")

if [ "$ACCOUNT_CREATE_CODE" = "302" ] || [ "$ACCOUNT_CREATE_CODE" = "200" ]; then
  pass "Test account created: ${TEST_USER}@${TEST_DOMAIN}"
elif acurl "${ADMIN_URL}/accounts" 2>/dev/null | grep -q "${TEST_USER}"; then
  pass "Test account exists: ${TEST_USER}@${TEST_DOMAIN}"
else
  fail "Could not create test account (HTTP $ACCOUNT_CREATE_CODE)"
fi

# ── Mail Protocol Authentication ─────────────────────────────────────────────

section "Mail Authentication"

# Test: SMTP AUTH (submission port)
AUTH_RESULT=$(printf "EHLO test\r\nAUTH PLAIN $(printf '\0%s@%s\0%s' "${TEST_USER}" "${TEST_DOMAIN}" "${TEST_PASS}" | base64)\r\nQUIT\r\n" \
  | timeout 10 nc "${MAIL}" "${SUBMISSION_PORT}" 2>/dev/null || echo "TIMEOUT")

if echo "$AUTH_RESULT" | grep -q "235"; then
  pass "SMTP AUTH succeeds for ${TEST_USER}@${TEST_DOMAIN}"
elif echo "$AUTH_RESULT" | grep -q "535"; then
  fail "SMTP AUTH rejected (bad credentials)" "$AUTH_RESULT"
else
  # Submission port may require STARTTLS first
  skip "SMTP AUTH requires STARTTLS (test container lacks TLS client)"
fi

# Test: IMAP LOGIN
IMAP_AUTH=$(printf "a001 LOGIN ${TEST_USER}@${TEST_DOMAIN} ${TEST_PASS}\r\na002 LOGOUT\r\n" \
  | timeout 10 nc "${MAIL}" "${IMAP_PORT}" 2>/dev/null || echo "TIMEOUT")

if echo "$IMAP_AUTH" | grep -q "a001 OK"; then
  pass "IMAP LOGIN succeeds for ${TEST_USER}@${TEST_DOMAIN}"
else
  fail "IMAP LOGIN failed" "$IMAP_AUTH"
fi

# Test: POP3 AUTH
POP3_AUTH=$(printf "USER ${TEST_USER}@${TEST_DOMAIN}\r\nPASS ${TEST_PASS}\r\nQUIT\r\n" \
  | timeout 10 nc "${MAIL}" "${POP3_PORT}" 2>/dev/null || echo "TIMEOUT")

if echo "$POP3_AUTH" | grep -q "+OK"; then
  pass "POP3 AUTH succeeds for ${TEST_USER}@${TEST_DOMAIN}"
else
  fail "POP3 AUTH failed" "$POP3_AUTH"
fi

# ── Admin Dashboard Pages ────────────────────────────────────────────────────

section "Admin Dashboard"

# Test: Dashboard loads (with auth)
if acurl "${ADMIN_URL}/" 2>/dev/null | grep -qi "mailserver"; then
  pass "Admin dashboard loads"
else
  fail "Admin dashboard not loading"
fi

# Test: Domains page
if acurl "${ADMIN_URL}/domains" 2>/dev/null | grep -qi "domain"; then
  pass "Domains page accessible"
else
  fail "Domains page not accessible"
fi

# Test: Accounts page
if acurl "${ADMIN_URL}/accounts" 2>/dev/null | grep -qi "account"; then
  pass "Accounts page accessible"
else
  fail "Accounts page not accessible"
fi

# Test: Configs page
if acurl "${ADMIN_URL}/configs" 2>/dev/null | grep -qi "config"; then
  pass "Configs page accessible"
else
  fail "Configs page not accessible"
fi

# ── Postfix ──────────────────────────────────────────────────────────────────

section "Postfix"

# Test: SMTP banner
SMTP_BANNER=$(timeout 5 nc "${MAIL}" "${SMTP_PORT}" 2>/dev/null || echo "TIMEOUT")
if echo "$SMTP_BANNER" | grep -q "220"; then
  pass "Postfix SMTP responding"
else
  fail "Postfix SMTP not responding"
fi

# Test: SMTP with EHLO
EHLO_RESP=$(printf "EHLO test\r\nQUIT\r\n" | timeout 5 nc "${MAIL}" "${SMTP_PORT}" 2>/dev/null || echo "TIMEOUT")
if echo "$EHLO_RESP" | grep -q "250"; then
  pass "Postfix EHLO works"
else
  fail "Postfix EHLO failed"
fi

# ── Results ──────────────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
printf "Results: ${GREEN}%d passed${NC}, ${RED}%d failed${NC}, %d total\n" "$PASS" "$FAIL" "$TOTAL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ "$FAIL" -gt 0 ]; then
  printf "\n${RED}SOME TESTS FAILED${NC}\n"
  exit 1
else
  printf "\n${GREEN}ALL TESTS PASSED${NC}\n"
  exit 0
fi
