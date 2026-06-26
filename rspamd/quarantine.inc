# Rspamd quarantine configuration
# Store quarantined messages in Redis
quarantine {
  redis_key = "bloom_quarantine";
  messages_key = "quarantine_messages";
  max_size = 1M;
  max_num_of_messages = 1000;
  max_duration = 2d;
  settings_prefix = "QUARANTINE_";
}
