-- Invite codes for gated self-registration.
-- Each code is a 16-char hex string. Once used, the code is consumed.
CREATE TABLE IF NOT EXISTS invite_codes (
    id BIGSERIAL PRIMARY KEY,
    code TEXT UNIQUE NOT NULL,
    used_by TEXT,
    used_at TEXT,
    created_by TEXT NOT NULL DEFAULT 'admin',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_invite_codes_code ON invite_codes(code);
