#!/bin/sh
# Validate the generated Dovecot configuration.
# Detects the installed Dovecot version and validates against the correct syntax.
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

# Detect installed Dovecot version
DOVECOT_VER=""
if command -v dovecot >/dev/null 2>&1; then
  DOVECOT_VER=$(dovecot --version 2>/dev/null | head -1)
fi
IS_V24=false
case "$DOVECOT_VER" in
  2.4*|2.5*|3.*) IS_V24=true ;;
esac

if [ -n "$DOVECOT_VER" ]; then
  echo "Detected Dovecot version: $DOVECOT_VER"
else
  echo "Dovecot not installed, validating for 2.3 syntax (default)"
fi
echo ""

# ── Required headers ────────────────────────────────────────────────────────

echo "=== Required Headers ==="

FIRST_LINE=$(grep -v '^#' "$CONF" | head -1 | tr -d '[:space:]')
if echo "$FIRST_LINE" | grep -q '^dovecot_config_version='; then
  pass "dovecot_config_version is first non-comment line"
else
  fail "dovecot_config_version is NOT first non-comment line" "Got: $FIRST_LINE"
fi

# ── Version-specific checks ─────────────────────────────────────────────────

if [ "$IS_V24" = true ]; then
  echo ""
  echo "=== Dovecot 2.4 Checks ==="

  if grep -q '^dovecot_storage_version' "$CONF"; then
    pass "dovecot_storage_version present (required for 2.4)"
  else
    fail "dovecot_storage_version missing (required for 2.4)"
  fi

  # mail_location → mail_driver/mail_home/mail_path
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

  # SSL
  if grep -q 'ssl.*= *<' "$CONF"; then
    fail "Angle bracket < found in SSL settings (removed in 2.4)"
  else
    pass "No angle bracket prefix in SSL paths"
  fi

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

  # Deprecated settings
  for setting in verbose_ssl auth_verbose auth_verbose_passwords first_valid_uid first_valid_gid; do
    if grep -q "^${setting}" "$CONF"; then
      fail "Deprecated setting found: $setting"
    else
      pass "No deprecated setting: $setting"
    fi
  done

  # Passdb / Userdb
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

else
  echo ""
  echo "=== Dovecot 2.3 Checks ==="

  # 2.3 should NOT have 2.4-only settings
  if grep -q '^dovecot_storage_version' "$CONF"; then
    fail "dovecot_storage_version found (not valid in 2.3)"
  else
    pass "No dovecot_storage_version (correct for 2.3)"
  fi

  # mail_location
  if grep -q '^mail_location' "$CONF"; then
    pass "mail_location present (correct for 2.3)"
  else
    fail "mail_location missing (required for 2.3)"
  fi

  if grep -q '^mail_driver' "$CONF"; then
    warn "mail_driver found (2.4 syntax, not used by 2.3)"
  else
    pass "No mail_driver (correct for 2.3)"
  fi

  # SSL — 2.3 uses angle bracket syntax
  if grep -q 'ssl_cert = </' "$CONF"; then
    pass "ssl_cert with angle bracket (correct for 2.3)"
  elif grep -q 'ssl_cert ' "$CONF"; then
    pass "ssl_cert present"
  else
    fail "ssl_cert missing"
  fi

  if grep -q 'ssl_key = </' "$CONF"; then
    pass "ssl_key with angle bracket (correct for 2.3)"
  elif grep -q 'ssl_key ' "$CONF"; then
    pass "ssl_key present"
  else
    fail "ssl_key missing"
  fi

  # 2.3-specific settings
  if grep -q '^first_valid_uid' "$CONF"; then
    pass "first_valid_uid present (correct for 2.3)"
  else
    warn "first_valid_uid missing (optional for 2.3)"
  fi

  if grep -q '^auth_verbose' "$CONF"; then
    pass "auth_verbose present (correct for 2.3)"
  else
    warn "auth_verbose missing (optional for 2.3)"
  fi

  # Passdb / Userdb
  if grep -q 'passdb_args\|driver = passwd-file' "$CONF"; then
    pass "passdb uses 2.3 syntax"
  else
    fail "passdb syntax unclear"
  fi

  if grep -q 'userdb_args\|driver = static' "$CONF"; then
    pass "userdb uses 2.3 syntax"
  else
    fail "userdb syntax unclear"
  fi

  # Should NOT have 2.4 syntax
  if grep -q 'ssl_server_cert_file\|ssl_server_key_file' "$CONF"; then
    fail "2.4 SSL names found (not valid in 2.3)"
  else
    pass "No 2.4 SSL names"
  fi

  if grep -q 'passdb_passwd_file\|userdb_passwd_file' "$CONF"; then
    fail "2.4 passdb/userdb syntax found (not valid in 2.3)"
  else
    pass "No 2.4 passdb/userdb syntax"
  fi
fi

# ── Common checks ───────────────────────────────────────────────────────────

echo ""
echo "=== Common ==="

if grep -q '^auth_mechanisms' "$CONF"; then
  pass "auth_mechanisms present"
else
  fail "auth_mechanisms missing"
fi

if grep -q 'namespace inbox' "$CONF"; then
  pass "namespace inbox present"
else
  fail "namespace inbox missing"
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
