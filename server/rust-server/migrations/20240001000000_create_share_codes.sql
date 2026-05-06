CREATE TABLE IF NOT EXISTS share_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    share_code TEXT NOT NULL UNIQUE,
    item_type TEXT NOT NULL,
    item_id UUID NOT NULL,
    item_name TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS share_codes_user_id_idx ON share_codes(user_id);
CREATE INDEX IF NOT EXISTS share_codes_share_code_idx ON share_codes(share_code);
