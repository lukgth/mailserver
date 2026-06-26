-- Add 'web' service to fail2ban_settings for admin panel auth failure tracking.
INSERT INTO fail2ban_settings (service, max_attempts, ban_duration_minutes, find_time_minutes, enabled, created_at)
VALUES ('web', 5, 15, 15, true, NOW())
ON CONFLICT DO NOTHING;
