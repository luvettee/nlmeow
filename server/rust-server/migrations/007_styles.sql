CREATE TABLE IF NOT EXISTS styles (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    entry_id    INTEGER NOT NULL,
    name        TEXT NOT NULL DEFAULT '',
    content     TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_styles_user_entry ON styles(user_id, entry_id);
