#!/bin/sh
set -e

echo "Starting SpamAssassin..."

# Start spamd in background
spamd -d -c -m -u spamd --allow-tell &
SPAMD_PID=$!
echo "spamd started (PID: $SPAMD_PID)"

# Wait for spamd to be ready
for i in $(seq 1 10); do
  if nc -z 127.0.0.1 783 2>/dev/null; then
    echo "spamd is ready on port 783"
    break
  fi
  sleep 1
done

# Start spamass-milter
spamass-milter -m -p 9999 -d 127.0.0.1 &
MILTER_PID=$!
echo "spamass-milter started (PID: $MILTER_PID)"

# Keep running
exec tail -f /dev/null --pid=$SPAMD_PID --pid=$MILTER_PID
