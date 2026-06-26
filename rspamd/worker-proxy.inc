# Rspamd milter worker (proxy) configuration
# Postfix connects here to scan emails
bind_socket = "0.0.0.0:11333";
count = 1;
# Timeout for milter connections (seconds)
timeout = 60;
