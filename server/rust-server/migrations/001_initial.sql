-- Combined SQLite migration for Neverlose server
-- Replaces all PostgreSQL migrations with a single SQLite-compatible schema

CREATE TABLE IF NOT EXISTS base_modules (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE,
    version             INTEGER NOT NULL DEFAULT 0,
    author              TEXT NOT NULL DEFAULT '',
    checksum            INTEGER NOT NULL DEFAULT 0,
    buffer_capacity     INTEGER NOT NULL DEFAULT 0,
    enabled             INTEGER NOT NULL DEFAULT 1,
    skin_data_msgpack   BLOB NOT NULL,
    languages_json      TEXT NOT NULL,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    auth_token      TEXT NOT NULL UNIQUE,
    base_module_id  TEXT NOT NULL,
    avatar_png      BLOB,
    serial          TEXT NOT NULL DEFAULT '',
    type7_blob      TEXT,
    type7_updated_at TEXT,
    password_hash   TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (base_module_id) REFERENCES base_modules(id)
);

CREATE TABLE IF NOT EXISTS log_entries (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    entry_id    INTEGER NOT NULL,
    timestamp   INTEGER NOT NULL,
    entry_type  TEXT NOT NULL CHECK (entry_type IN ('Config', 'Script', 'Style')),
    author      TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scripts (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    entry_id    INTEGER NOT NULL,
    name        TEXT NOT NULL DEFAULT '',
    content     TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS configs (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    entry_id    INTEGER NOT NULL,
    name        TEXT NOT NULL DEFAULT '',
    content     TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS styles (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    entry_id    INTEGER NOT NULL,
    name        TEXT NOT NULL DEFAULT '',
    content     TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS share_codes (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    share_code  TEXT NOT NULL UNIQUE,
    item_type   TEXT NOT NULL,
    item_id     TEXT NOT NULL,
    item_name   TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_log_entries_user_type ON log_entries(user_id, entry_type);
CREATE INDEX IF NOT EXISTS idx_users_auth_token ON users(auth_token);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scripts_user_entry ON scripts(user_id, entry_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_configs_user_entry ON configs(user_id, entry_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_styles_user_entry ON styles(user_id, entry_id);
CREATE INDEX IF NOT EXISTS idx_share_codes_user_id ON share_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_share_codes_share_code ON share_codes(share_code);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);