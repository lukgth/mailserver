#!/bin/sh
set -e

echo "Starting SpamAssassin..."

# Find spamd binary
SPAMD_BIN=$(which spamd 2>/dev/null || echo "/usr/bin/spamd")
echo "Using spamd: $SPAMD_BIN"

# Start spamd in background (foreground mode, no daemon)
$SPAMD_BIN -d -c -m --allow-tell &
SPAMD_PID=$!
echo "spamd started (PID: $SPAMD_PID)"

# Wait for spamd to be ready on port 783
for i in $(seq 1 15); do
  if nc -z 127.0.0.1 783 2>/dev/null; then
    echo "spamd is ready on port 783"
    break
  fi
  echo "Waiting for spamd... ($i/15)"
  sleep 1
done

# Start spamass-milter (-s = spamd socket, -p = milter port)
spamass-milter -p 9999 -s 127.0.0.1:783 &
MILTER_PID=$!
echo "spamass-milter started (PID: $MILTER_PID) -> spamd at 127.0.0.1:783"

# Keep running
while kill -0 $SPAMD_PID 2>/dev/null && kill -0 $MILTER_PID 2>/dev/null; do
  sleep 5
done
echo "A process died, exiting"
exit 1
