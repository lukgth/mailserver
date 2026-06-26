#!/bin/sh
# Start spamd and spamass-milter

# Start spamd in background
spamd -d -c -m -u spamd --allow-tell &
SPAMD_PID=$!

# Wait for spamd to start
sleep 2

# Start spamass-milter in background
# -m = milter mode, -p = port, -d = spamd host
spamass-milter -m -p 9999 -d 127.0.0.1 -r /etc/mail/spamassassin/spamass-milter.conf &
MILTER_PID=$!

echo "spamd PID: $SPAMD_PID"
echo "spamass-milter PID: $MILTER_PID"

# Wait for either to exit
wait $SPAMD_PID $MILTER_PID
