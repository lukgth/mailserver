# Rspamd controller configuration
# Password protects the quarantine API and web interface.
# Change this in production: docker compose exec rspamd rspamadm configwizard
password = "mailserver";
enable_password = "mailserver";
# Bind to all interfaces (internal Docker network only)
bind_socket = "0.0.0.0:11334";
