#!/bin/sh
set -e

echo "Starting spamass-milter..."
echo "Connecting to spamd at spamd:783"

# Start spamass-milter connecting to spamd container
# -p = milter port, -s = spamd socket/host
spamass-milter -p 9999 -s spamd:783 &
MILTER_PID=$!
echo "spamass-milter started (PID: $MILTER_PID) -> spamd:783"

# Keep running
while kill -0 $MILTER_PID 2>/dev/null; do
  sleep 5
done
echo "spamass-milter died, exiting"
exit 1
