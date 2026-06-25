#!/bin/sh
# Run the Docker integration test suite.
#
# Usage:
#   ./tests/run-docker-tests.sh              # Full test suite
#   ./tests/run-docker-tests.sh --no-build   # Skip image build
#   ./tests/run-docker-tests.sh --validate   # Config validation only (no Docker)

set -e

cd "$(dirname "$0")/.."

if [ "$1" = "--validate" ]; then
  echo "Running config validation (no Docker required)..."
  echo ""
  # Generate a test config to a temp file and validate it
  TMPDIR=$(mktemp -d)
  trap "rm -rf $TMPDIR" EXIT

  # Simulate what generate_dovecot_conf does with the 2.3 template
  # (current Alpine image ships Dovecot 2.3.x)
  TEMPLATE="templates/config/dovecot.conf.txt"
  if [ ! -f "$TEMPLATE" ]; then
    echo "ERROR: $TEMPLATE not found"
    exit 1
  fi

  # Detect dovecot version (same logic as config.rs)
  DOVECOT_VER=$(dovecot --version 2>/dev/null | head -1 || true)
  IS_V24=false
  case "$DOVECOT_VER" in
    2.4*|2.5*|3.*) IS_V24=true ;;
  esac

  if [ "$IS_V24" = true ] && [ -f "templates/config/dovecot24.conf.txt" ]; then
    TEMPLATE="templates/config/dovecot24.conf.txt"
    echo "Dovecot 2.4+ detected, using $TEMPLATE"
  else
    echo "Dovecot 2.3 (or not installed), using $TEMPLATE"
  fi

  # Render template with placeholder substitutions (mimic config.rs)
  CONFIG_VERSION_LINE="dovecot_config_version = ${DOVECOT_VER:-2.3.24}"
  STORAGE_VERSION_LINE=""
  if [ "$IS_V24" = true ]; then
    STORAGE_VERSION_LINE="dovecot_storage_version = 2.4.0"
  fi

  sed \
    -e "s|{{ dovecot_config_version_line }}|${CONFIG_VERSION_LINE}|" \
    -e "s|{{ dovecot_storage_version_line }}|${STORAGE_VERSION_LINE}|" \
    -e "s|{{ generated_at }}|$(date -u +%Y-%m-%dT%H:%M:%SZ)|" \
    -e "s|{{ hostname }}|mail.test.local|" \
    -e "s|{{ log_path_line }}|# log_path = /dev/stdout|" \
    "$TEMPLATE" > "$TMPDIR/dovecot.conf"

  echo "Generated test config:"
  head -5 "$TMPDIR/dovecot.conf"
  echo "..."
  echo ""

  exec ./tests/validate-dovecot-config.sh "$TMPDIR/dovecot.conf"
fi

# Docker test suite
BUILD_FLAG=""
if [ "$1" = "--no-build" ]; then
  BUILD_FLAG="--no-build"
fi

echo "Building and starting test services..."
docker compose -f docker-compose.test.yml up --build $BUILD_FLAG \
  --abort-on-container-exit --exit-code-from test 2>&1

EXIT_CODE=$?

echo ""
echo "Tearing down test services..."
docker compose -f docker-compose.test.yml down -v 2>/dev/null

exit $EXIT_CODE
