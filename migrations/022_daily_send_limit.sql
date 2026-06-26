-- Track daily send count per account for rate limiting
ALTER TABLE accounts ADD COLUMN daily_send_count INTEGER DEFAULT 0;
ALTER TABLE accounts ADD COLUMN daily_send_date TEXT DEFAULT '';

-- Default: 100 emails per day per user
INSERT INTO settings (key, value) VALUES ('daily_send_limit', '100')
    ON CONFLICT (key) DO NOTHING;
