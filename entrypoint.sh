#!/bin/sh -eu
set -eu

for v in SEED_PASS HOSTNAME DB_PASSWORD; do
  val=$(eval "echo \${${v}:-}")
  if [ -z "$val" ] || echo "$val" | grep -Eq '^(admin|MUST-BE-CHANGED|YOUR_[A-Z_]+_HERE|mailserver)$'; then
    echo "[entrypoint] FATAL: $v is missing or set to a default/placeholder value" >&2
    exit 1
  fi
done

echo "[entrypoint] INFO: creating data directories"
mkdir -p /data/ssl /data/dkim /data/mail /data/db

# Ensure required users exist (safety net for pre-built images)
echo "[entrypoint] INFO: ensuring required system users exist"
id vmail >/dev/null 2>&1 || { echo "[entrypoint] INFO: creating vmail user"; addgroup -S vmail 2>/dev/null; adduser -S -D -H -G vmail -s /sbin/nologin vmail 2>/dev/null; }
id opendkim >/dev/null 2>&1 || { echo "[entrypoint] INFO: creating opendkim user"; addgroup -S opendkim 2>/dev/null; adduser -S -D -H -G opendkim -s /sbin/nologin opendkim 2>/dev/null; }

if [ ! -f /data/ssl/cert.pem ] || [ ! -f /data/ssl/dh.pem ]; then
    echo "[entrypoint] INFO: generating TLS certificates and DH parameters for hostname=${HOSTNAME:-mailserver}"
    /usr/local/bin/mailserver gencerts
else
    echo "[entrypoint] INFO: TLS certificates and DH parameters already exist, skipping generation"
    # Ensure symlink exists for dovecot (may be missing if gencerts was skipped)
    if [ ! -L /usr/share/dovecot/dh.pem ] && [ ! -f /usr/share/dovecot/dh.pem ]; then
        echo "[entrypoint] INFO: creating symlink for DH parameters"
        ln -sf /data/ssl/dh.pem /usr/share/dovecot/dh.pem
    fi
fi

# If Let's Encrypt certs exist, copy them to /data/ssl/ for Postfix/Dovecot
if [ -f "/etc/letsencrypt/live/${HOSTNAME}/fullchain.pem" ] && [ -f "/etc/letsencrypt/live/${HOSTNAME}/privkey.pem" ]; then
    echo "[entrypoint] INFO: using Let's Encrypt certificates for ${HOSTNAME}"
    cp -p "/etc/letsencrypt/live/${HOSTNAME}/fullchain.pem" /data/ssl/cert.pem
    cp -p "/etc/letsencrypt/live/${HOSTNAME}/privkey.pem" /data/ssl/key.pem
    chmod 600 /data/ssl/key.pem
    chmod 644 /data/ssl/cert.pem
fi

echo "[entrypoint] INFO: seeding database"
/usr/local/bin/mailserver seed

echo "[entrypoint] INFO: generating mail service configs"
/usr/local/bin/mailserver genconfig

echo "[entrypoint] INFO: setting directory ownership"
chown -R vmail:vmail /data/mail
chown -R opendkim:opendkim /data/dkim

echo "[entrypoint] INFO: starting services"
# Trap signals for clean container shutdown
trap 'trap - TERM; kill 0' SIGTERM SIGINT SIGQUIT

# Postfix and Dovecot log to stdout directly (via /dev/stdout)
# tee duplicates output to /var/log/mail.log for fail2ban monitoring
touch /var/log/mail.log

dovecot -F 2>&1 | tee -a /var/log/mail.log &
DOVECOT_PID=$!
opendkim -f -P /var/run/opendkim/opendkim.pid &
OPENDKIM_PID=$!
/usr/local/bin/mailserver serve &
MAILSERVER_PID=$!
postfix start-fg 2>&1 | tee -a /var/log/mail.log &
POSTFIX_PID=$(cat /var/spool/postfix/pid/master.pid 2>/dev/null || echo $!)

# Monitor all services — exit if any process dies
while true; do
  for pid_info in "$DOVECOT_PID:dovecot" "$OPENDKIM_PID:opendkim" "$MAILSERVER_PID:mailserver" "$POSTFIX_PID:postfix"; do
    pid="${pid_info%%:*}"
    label="${pid_info#*:}"
    if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
      echo "[entrypoint] ERROR: $label (PID $pid) has exited, shutting down"
      kill 0
      exit 1
    fi
  done
  sleep 5
done

