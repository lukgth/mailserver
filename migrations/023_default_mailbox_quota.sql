-- Set default quota to 1024 MB (1048576 bytes) for all accounts with no quota set
UPDATE accounts SET quota = 1048576 WHERE quota = 0;

-- Store default quota in settings
INSERT INTO settings (key, value) VALUES ('default_mailbox_quota', '1048576')
    ON CONFLICT (key) DO NOTHING;
