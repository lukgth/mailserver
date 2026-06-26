#!/bin/sh
set -e

echo "Starting SpamAssassin..."

# Start spamd in background (no daemon, listen on 783)
/usr/sbin/spamd -d -c -m --allow-tell &
SPAMD_PID=$!
echo "spamd started (PID: $SPAMD_PID)"

# Wait for spamd to be ready on port 783
for i in $(seq 1 20); do
  if nc -z 127.0.0.1 783 2>/dev/null; then
    echo "spamd is ready on port 783"
    break
  fi
  echo "Waiting for spamd... ($i/20)"
  sleep 1
done

# Start spamass-milter (-p = milter port, no -d flag)
spamass-milter -p 9999 &
MILTER_PID=$!
echo "spamass-milter started (PID: $MILTER_PID)"

# Keep running
while kill -0 $SPAMD_PID 2>/dev/null && kill -0 $MILTER_PID 2>/dev/null; do
  sleep 5
done
echo "A process died, exiting"
exit 1
