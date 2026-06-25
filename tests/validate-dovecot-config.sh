#!/bin/sh
# Validate the generated Dovecot configuration for 2.4 syntax.
# Run on the mail server (or in the mailserver container) after `mailserver genconfig`.
#
# Usage:
#   ./tests/validate-dovecot-config.sh [path/to/dovecot.conf]
#
# Defaults to /etc/dovecot/dovecot.conf

CONF="${1:-/etc/dovecot/dovecot.conf}"
PASS=0
FAIL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { PASS=$((PASS + 1)); printf "${GREEN}  PASS${NC}  %s\n" "$1"; }
fail() { FAIL=$((FAIL + 1)); printf "${RED}  FAIL${NC}  %s\n" "$1"; [ -n "$2" ] && printf "        %s\n" "$2"; }
warn() { printf "${YELLOW}  WARN${NC}  %s\n" "$1"; }

echo "Validating: $CONF"
echo ""

if [ ! -f "$CONF" ]; then
  printf "${RED}Config file not found: %s${NC}\n" "$CONF"
  exit 1
fi

# ── Required headers ────────────────────────────────────────────────────────

echo "=== Required Headers ==="

# dovecot_config_version must be first non-comment line
FIRST_LINE=$(grep -v '^#' "$CONF" | head -1 | tr -d '[:space:]')
if echo "$FIRST_LINE" | grep -q '^dovecot_config_version='; then
  pass "dovecot_config_version is first non-comment line"
else
  fail "dovecot_config_version is NOT first non-comment line" "Got: $FIRST_LINE"
fi

# dovecot_storage_version must exist
if grep -q '^dovecot_storage_version' "$CONF"; then
  pass "dovecot_storage_version present"
else
  fail "dovecot_storage_version missing"
fi

# ── Mail location (2.4 syntax) ─────────────────────────────────────────────

echo ""
echo "=== Mail Location ==="

# mail_location must NOT be used (split into mail_driver/mail_home/mail_path)
if grep -q '^mail_location' "$CONF"; then
  fail "mail_location used (deprecated in 2.4, use mail_driver/mail_home/mail_path)"
else
  pass "No mail_location (using 2.4 split syntax)"
fi

if grep -q '^mail_driver' "$CONF"; then
  pass "mail_driver present"
else
  fail "mail_driver missing"
fi

if grep -q '^mail_home' "$CONF"; then
  pass "mail_home present"
else
  fail "mail_home missing"
fi

if grep -q '^mail_path' "$CONF"; then
  pass "mail_path present"
else
  fail "mail_path missing"
fi

# Check for old %d/%n variables
if grep -q '%d' "$CONF" || grep -q '%n' "$CONF"; then
  fail "Old %d/%n variables found (use %{user | domain}/%{user | username} in 2.4)"
else
  pass "No old %d/%n variables"
fi

# ── SSL (2.4 syntax) ───────────────────────────────────────────────────────

echo ""
echo "=== SSL ==="

# Check for angle bracket prefix (must be removed)
if grep -q 'ssl.*= *<' "$CONF"; then
  fail "Angle bracket < found in SSL settings (removed in 2.4)"
else
  pass "No angle bracket prefix in SSL paths"
fi

# Check for new SSL setting names
if grep -q 'ssl_server_cert_file' "$CONF"; then
  pass "ssl_server_cert_file used (2.4 name)"
elif grep -q 'ssl_cert ' "$CONF"; then
  warn "ssl_cert used (deprecated alias, prefer ssl_server_cert_file)"
else
  fail "No SSL certificate setting found"
fi

if grep -q 'ssl_server_key_file' "$CONF"; then
  pass "ssl_server_key_file used (2.4 name)"
elif grep -q 'ssl_key ' "$CONF"; then
  warn "ssl_key used (deprecated alias, prefer ssl_server_key_file)"
else
  fail "No SSL key setting found"
fi

if grep -q 'ssl_server_dh_file' "$CONF"; then
  pass "ssl_server_dh_file used (2.4 name)"
elif grep -q 'ssl_dh ' "$CONF"; then
  warn "ssl_dh used (deprecated alias, prefer ssl_server_dh_file)"
else
  warn "No SSL DH setting found (optional)"
fi

# ── Deprecated settings ─────────────────────────────────────────────────────

echo ""
echo "=== Deprecated Settings ==="

for setting in verbose_ssl auth_verbose auth_verbose_passwords first_valid_uid first_valid_gid; do
  if grep -q "^${setting}" "$CONF"; then
    fail "Deprecated setting found: $setting"
  else
    pass "No deprecated setting: $setting"
  fi
done

# ── Passdb / Userdb (2.4 syntax) ────────────────────────────────────────────

echo ""
echo "=== Passdb / Userdb ==="

# Check for old passdb syntax
if grep -q 'passdb_args\|passdb_driver' "$CONF"; then
  fail "Old passdb syntax (passdb_args/passdb_driver) found"
else
  pass "No old passdb syntax"
fi

if grep -q 'passdb_passwd_file' "$CONF" || grep -q 'passdb {' "$CONF"; then
  pass "passdb uses 2.4 syntax"
else
  fail "passdb syntax unclear"
fi

# Check for old userdb syntax
if grep -q 'userdb_args\|userdb_driver' "$CONF"; then
  fail "Old userdb syntax (userdb_args/userdb_driver) found"
else
  pass "No old userdb syntax"
fi

if grep -q 'userdb_uid\|userdb_gid\|userdb_home\|userdb static' "$CONF"; then
  pass "userdb uses 2.4 syntax"
else
  warn "userdb syntax unclear (may be valid)"
fi

# ── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
printf "Results: ${GREEN}%d passed${NC}, ${RED}%d failed${NC}\n" "$PASS" "$FAIL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ "$FAIL" -gt 0 ]; then
  printf "\n${RED}CONFIG HAS ISSUES${NC}\n"
  exit 1
else
  printf "\n${GREEN}CONFIG VALID${NC}\n"
  exit 0
fi
