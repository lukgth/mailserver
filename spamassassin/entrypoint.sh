#!/bin/sh
set -e

echo "Starting spamass-milter..."
echo "Connecting to spamd at spamd:783"

# -p = milter port
# -- = pass remaining args to spamc
# -d spamd = spamc connects to remote spamd host
spamass-milter -p 9999 -- -d spamd &
MILTER_PID=$!
echo "spamass-milter started (PID: $MILTER_PID) -> spamd:783 via spamc"

# Keep running
while kill -0 $MILTER_PID 2>/dev/null; do
  sleep 5
done
echo "spamass-milter died, exiting"
exit 1
