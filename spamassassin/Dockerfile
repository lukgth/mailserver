FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    spamassassin spamass-milter \
    && rm -rf /var/lib/apt/lists/*

# Create spamd user
RUN adduser --disabled-password --no-create-home --gecos "" spamd || true

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 783 9999

ENTRYPOINT ["/entrypoint.sh"]
