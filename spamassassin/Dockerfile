FROM debian:bookworm-slim

# Install SpamAssassin + spamass-milter
RUN apt-get update && apt-get install -y --no-install-recommends \
    spamassassin spamass-milter procps \
    && rm -rf /var/lib/apt/lists/*

# Create spamd user
RUN adduser --disabled-password --no-create-home --gecos "" spamd

# Configure spamass-milter to listen on port 9999
# and connect to spamd on localhost:783
RUN echo "SPAMASSASSIN_SOCKET=inet:9999" > /etc/default/spamass-milter

# Start both spamd and spamass-milter
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 783 9999

ENTRYPOINT ["/entrypoint.sh"]
