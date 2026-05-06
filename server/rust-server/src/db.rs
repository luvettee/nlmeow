use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{
    BaseModuleRow, ConfigRow, LogEntryRow, ScriptRow, ShareCodeRow, StyleRow, UserRow,
};

// ── Users ──

pub async fn get_user_by_auth_token(pool: &PgPool, token: &str) -> Result<Option<UserRow>> {
    let user = sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE auth_token = $1")
        .bind(token)
        .fetch_optional(pool)
        .await?;
    Ok(user)
}

pub async fn get_user_by_username(pool: &PgPool, username: &str) -> Result<Option<UserRow>> {
    let user = sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    Ok(user)
}

pub async fn get_user_by_id(pool: &PgPool, id: Uuid) -> Result<Option<UserRow>> {
    let user = sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(user)
}

pub async fn create_user(
    pool: &PgPool,
    username: &str,
    auth_token: &str,
    base_module_id: Uuid,
    serial: &str,
) -> Result<UserRow> {
    let user = sqlx::query_as::<_, UserRow>(
        "INSERT INTO users (username, auth_token, base_module_id, serial)
         VALUES ($1, $2, $3, $4) RETURNING *",
    )
    .bind(username)
    .bind(auth_token)
    .bind(base_module_id)
    .bind(serial)
    .fetch_one(pool)
    .await?;
    Ok(user)
}

pub async fn create_user_with_password_hash(
    pool: &PgPool,
    username: &str,
    password_hash: &str,
    base_module_id: Uuid,
    serial: &str,
) -> Result<UserRow> {
    let auth_token = Uuid::new_v4().to_string();
    let user = sqlx::query_as::<_, UserRow>(
        "INSERT INTO users (username, auth_token, base_module_id, serial, password_hash)
         VALUES ($1, $2, $3, $4, $5) RETURNING *",
    )
    .bind(username)
    .bind(auth_token)
    .bind(base_module_id)
    .bind(serial)
    .bind(password_hash)
    .fetch_one(pool)
    .await?;
    Ok(user)
}

pub async fn update_user_avatar(
    pool: &PgPool,
    user_id: Uuid,
    avatar_png: Option<&[u8]>,
) -> Result<Option<UserRow>> {
    let user =
        sqlx::query_as::<_, UserRow>("UPDATE users SET avatar_png = $2 WHERE id = $1 RETURNING *")
            .bind(user_id)
            .bind(avatar_png)
            .fetch_optional(pool)
            .await?;
    Ok(user)
}

pub async fn update_user_type7_blob(
    pool: &PgPool,
    user_id: Uuid,
    type7_blob: Option<&str>,
) -> Result<Option<UserRow>> {
    let user = sqlx::query_as::<_, UserRow>(
        "UPDATE users SET type7_blob = $2, type7_updated_at = NOW() WHERE id = $1 RETURNING *",
    )
    .bind(user_id)
    .bind(type7_blob)
    .fetch_optional(pool)
    .await?;
    Ok(user)
}

pub async fn list_users(pool: &PgPool) -> Result<Vec<UserRow>> {
    let users = sqlx::query_as::<_, UserRow>("SELECT * FROM users ORDER BY created_at")
        .fetch_all(pool)
        .await?;
    Ok(users)
}

// ── Base modules ──

pub async fn get_base_module(pool: &PgPool, id: Uuid) -> Result<Option<BaseModuleRow>> {
    let module = sqlx::query_as::<_, BaseModuleRow>("SELECT * FROM base_modules WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(module)
}

pub async fn get_first_base_module(pool: &PgPool) -> Result<Option<BaseModuleRow>> {
    let module = sqlx::query_as::<_, BaseModuleRow>(
        "SELECT * FROM base_modules ORDER BY created_at, id LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(module)
}

pub async fn insert_base_module(
    pool: &PgPool,
    name: &str,
    version: i32,
    author: &str,
    checksum: i64,
    buffer_capacity: i64,
    enabled: i32,
    skin_data_msgpack: &[u8],
    languages_json: &serde_json::Value,
) -> Result<BaseModuleRow> {
    // Serialize to string and bind as text so PostgreSQL stores the raw JSON
    // without JSONB normalization (which reorders keys alphabetically).
    let json_text = serde_json::to_string(languages_json)?;
    let module = sqlx::query_as::<_, BaseModuleRow>(
        "INSERT INTO base_modules (name, version, author, checksum, buffer_capacity, enabled, skin_data_msgpack, languages_json)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::json) RETURNING *",
    )
    .bind(name)
    .bind(version)
    .bind(author)
    .bind(checksum)
    .bind(buffer_capacity)
    .bind(enabled)
    .bind(skin_data_msgpack)
    .bind(&json_text)
    .fetch_one(pool)
    .await?;
    Ok(module)
}

pub async fn upsert_base_module(
    pool: &PgPool,
    name: &str,
    version: i32,
    author: &str,
    checksum: i64,
    buffer_capacity: i64,
    enabled: i32,
    skin_data_msgpack: &[u8],
    languages_json: &serde_json::Value,
) -> Result<BaseModuleRow> {
    let json_text = serde_json::to_string(languages_json)?;
    let module = sqlx::query_as::<_, BaseModuleRow>(
        "INSERT INTO base_modules (name, version, author, checksum, buffer_capacity, enabled, skin_data_msgpack, languages_json)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::json)
         ON CONFLICT (name) DO UPDATE SET
             version = EXCLUDED.version,
             author = EXCLUDED.author,
             checksum = EXCLUDED.checksum,
             buffer_capacity = EXCLUDED.buffer_capacity,
             enabled = EXCLUDED.enabled,
             skin_data_msgpack = EXCLUDED.skin_data_msgpack,
             languages_json = EXCLUDED.languages_json,
             updated_at = NOW()
         RETURNING *",
    )
    .bind(name)
    .bind(version)
    .bind(author)
    .bind(checksum)
    .bind(buffer_capacity)
    .bind(enabled)
    .bind(skin_data_msgpack)
    .bind(&json_text)
    .fetch_one(pool)
    .await?;
    Ok(module)
}

// ── Log entries ──

pub async fn get_user_log_entries(pool: &PgPool, user_id: Uuid) -> Result<Vec<LogEntryRow>> {
    let entries = sqlx::query_as::<_, LogEntryRow>(
        "SELECT * FROM log_entries WHERE user_id = $1 ORDER BY entry_id",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(entries)
}

pub async fn get_user_log_entry(
    pool: &PgPool,
    user_id: Uuid,
    entry_id: i32,
) -> Result<Option<LogEntryRow>> {
    let entry = sqlx::query_as::<_, LogEntryRow>(
        "SELECT * FROM log_entries WHERE user_id = $1 AND entry_id = $2",
    )
    .bind(user_id)
    .bind(entry_id)
    .fetch_optional(pool)
    .await?;
    Ok(entry)
}

pub async fn create_log_entry(
    pool: &PgPool,
    user_id: Uuid,
    entry_id: i32,
    timestamp: i32,
    entry_type: &str,
    author: &str,
) -> Result<LogEntryRow> {
    let entry = sqlx::query_as::<_, LogEntryRow>(
        "INSERT INTO log_entries (user_id, entry_id, timestamp, entry_type, author)
         VALUES ($1, $2, $3, $4, $5) RETURNING *",
    )
    .bind(user_id)
    .bind(entry_id)
    .bind(timestamp)
    .bind(entry_type)
    .bind(author)
    .fetch_one(pool)
    .await?;
    Ok(entry)
}

pub async fn update_log_entry(
    pool: &PgPool,
    id: Uuid,
    entry_id: i32,
    timestamp: i32,
    entry_type: &str,
    author: &str,
) -> Result<Option<LogEntryRow>> {
    let entry = sqlx::query_as::<_, LogEntryRow>(
        "UPDATE log_entries SET entry_id = $2, timestamp = $3, entry_type = $4, author = $5
         WHERE id = $1 RETURNING *",
    )
    .bind(id)
    .bind(entry_id)
    .bind(timestamp)
    .bind(entry_type)
    .bind(author)
    .fetch_optional(pool)
    .await?;
    Ok(entry)
}

pub async fn delete_log_entry(pool: &PgPool, id: Uuid) -> Result<bool> {
    let result = sqlx::query("DELETE FROM log_entries WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn delete_log_entry_by_user_entry_id(
    pool: &PgPool,
    user_id: Uuid,
    entry_id: i32,
) -> Result<bool> {
    let result = sqlx::query("DELETE FROM log_entries WHERE user_id = $1 AND entry_id = $2")
        .bind(user_id)
        .bind(entry_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn update_log_entry_timestamp(
    pool: &PgPool,
    user_id: Uuid,
    entry_id: i32,
    timestamp: i32,
) -> Result<bool> {
    let result =
        sqlx::query("UPDATE log_entries SET timestamp = $3 WHERE user_id = $1 AND entry_id = $2")
            .bind(user_id)
            .bind(entry_id)
            .bind(timestamp)
            .execute(pool)
            .await?;
    Ok(result.rows_affected() > 0)
}

// ── Scripts ──

pub async fn next_entry_id(pool: &PgPool, user_id: Uuid) -> Result<i32> {
    let row: (Option<i32>,) =
        sqlx::query_as("SELECT MAX(entry_id) FROM log_entries WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await?;
    Ok(row.0.unwrap_or(0) + 1)
}

pub async fn get_user_scripts(pool: &PgPool, user_id: Uuid) -> Result<Vec<ScriptRow>> {
    let scripts = sqlx::query_as::<_, ScriptRow>(
        "SELECT * FROM scripts WHERE user_id = $1 ORDER BY entry_id",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(scripts)
}

pub async fn get_user_script_by_name(
    pool: &PgPool,
    user_id: Uuid,
    name: &str,
) -> Result<Option<ScriptRow>> {
    let script = sqlx::query_as::<_, ScriptRow>(
        "SELECT * FROM scripts WHERE user_id = $1 AND name = $2 ORDER BY updated_at DESC LIMIT 1",
    )
    .bind(user_id)
    .bind(name)
    .fetch_optional(pool)
    .await?;
    Ok(script)
}

pub async fn get_user_script(
    pool: &PgPool,
    user_id: Uuid,
    entry_id: i32,
) -> Result<Option<ScriptRow>> {
    let script = sqlx::query_as::<_, ScriptRow>(
        "SELECT * FROM scripts WHERE user_id = $1 AND entry_id = $2",
    )
    .bind(user_id)
    .bind(entry_id)
    .fetch_optional(pool)
    .await?;
    Ok(script)
}

pub async fn get_user_configs(pool: &PgPool, user_id: Uuid) -> Result<Vec<ConfigRow>> {
    let configs = sqlx::query_as::<_, ConfigRow>(
        "SELECT * FROM configs WHERE user_id = $1 ORDER BY entry_id",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(configs)
}

pub async fn get_user_styles(pool: &PgPool, user_id: Uuid) -> Result<Vec<StyleRow>> {
    let styles =
        sqlx::query_as::<_, StyleRow>("SELECT * FROM styles WHERE user_id = $1 ORDER BY entry_id")
            .bind(user_id)
            .fetch_all(pool)
            .await?;
    Ok(styles)
}

pub async fn get_user_style(
    pool: &PgPool,
    user_id: Uuid,
    entry_id: i32,
) -> Result<Option<StyleRow>> {
    let style =
        sqlx::query_as::<_, StyleRow>("SELECT * FROM styles WHERE user_id = $1 AND entry_id = $2")
            .bind(user_id)
            .bind(entry_id)
            .fetch_optional(pool)
            .await?;
    Ok(style)
}

pub async fn create_script(
    pool: &PgPool,
    user_id: Uuid,
    entry_id: i32,
    name: &str,
) -> Result<ScriptRow> {
    let script = sqlx::query_as::<_, ScriptRow>(
        "INSERT INTO scripts (user_id, entry_id, name) VALUES ($1, $2, $3) RETURNING *",
    )
    .bind(user_id)
    .bind(entry_id)
    .bind(name)
    .fetch_one(pool)
    .await?;
    Ok(script)
}

pub async fn create_config(
    pool: &PgPool,
    user_id: Uuid,
    entry_id: i32,
    name: &str,
) -> Result<ConfigRow> {
    let config = sqlx::query_as::<_, ConfigRow>(
        "INSERT INTO configs (user_id, entry_id, name) VALUES ($1, $2, $3) RETURNING *",
    )
    .bind(user_id)
    .bind(entry_id)
    .bind(name)
    .fetch_one(pool)
    .await?;
    Ok(config)
}

pub async fn create_style(
    pool: &PgPool,
    user_id: Uuid,
    entry_id: i32,
    name: &str,
) -> Result<StyleRow> {
    let style = sqlx::query_as::<_, StyleRow>(
        "INSERT INTO styles (user_id, entry_id, name)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id, entry_id) DO UPDATE SET
             name = EXCLUDED.name,
             updated_at = NOW()
         RETURNING *",
    )
    .bind(user_id)
    .bind(entry_id)
    .bind(name)
    .fetch_one(pool)
    .await?;
    Ok(style)
}

pub async fn update_script_name(
    pool: &PgPool,
    user_id: Uuid,
    entry_id: i32,
    name: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE scripts SET name = $3, updated_at = NOW() WHERE user_id = $1 AND entry_id = $2",
    )
    .bind(user_id)
    .bind(entry_id)
    .bind(name)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn update_config_name(
    pool: &PgPool,
    user_id: Uuid,
    entry_id: i32,
    name: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE configs SET name = $3, updated_at = NOW() WHERE user_id = $1 AND entry_id = $2",
    )
    .bind(user_id)
    .bind(entry_id)
    .bind(name)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn update_style_name(
    pool: &PgPool,
    user_id: Uuid,
    entry_id: i32,
    name: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE styles SET name = $3, updated_at = NOW() WHERE user_id = $1 AND entry_id = $2",
    )
    .bind(user_id)
    .bind(entry_id)
    .bind(name)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn update_script_content(
    pool: &PgPool,
    user_id: Uuid,
    entry_id: i32,
    content: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE scripts SET content = $3, updated_at = NOW() WHERE user_id = $1 AND entry_id = $2",
    )
    .bind(user_id)
    .bind(entry_id)
    .bind(content)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn update_config_content(
    pool: &PgPool,
    user_id: Uuid,
    entry_id: i32,
    content: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE configs SET content = $3, updated_at = NOW() WHERE user_id = $1 AND entry_id = $2",
    )
    .bind(user_id)
    .bind(entry_id)
    .bind(content)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn update_style_content(
    pool: &PgPool,
    user_id: Uuid,
    entry_id: i32,
    content: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE styles SET content = $3, updated_at = NOW() WHERE user_id = $1 AND entry_id = $2",
    )
    .bind(user_id)
    .bind(entry_id)
    .bind(content)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn delete_script(pool: &PgPool, user_id: Uuid, entry_id: i32) -> Result<bool> {
    let result = sqlx::query("DELETE FROM scripts WHERE user_id = $1 AND entry_id = $2")
        .bind(user_id)
        .bind(entry_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn delete_config(pool: &PgPool, user_id: Uuid, entry_id: i32) -> Result<bool> {
    let result = sqlx::query("DELETE FROM configs WHERE user_id = $1 AND entry_id = $2")
        .bind(user_id)
        .bind(entry_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn delete_style(pool: &PgPool, user_id: Uuid, entry_id: i32) -> Result<bool> {
    let result = sqlx::query("DELETE FROM styles WHERE user_id = $1 AND entry_id = $2")
        .bind(user_id)
        .bind(entry_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn get_user_config(
    pool: &PgPool,
    user_id: Uuid,
    entry_id: i32,
) -> Result<Option<ConfigRow>> {
    let config = sqlx::query_as::<_, ConfigRow>(
        "SELECT * FROM configs WHERE user_id = $1 AND entry_id = $2",
    )
    .bind(user_id)
    .bind(entry_id)
    .fetch_optional(pool)
    .await?;
    Ok(config)
}

pub async fn create_share_code(
    pool: &PgPool,
    user_id: Uuid,
    item_type: &str,
    item_id: Uuid,
    item_name: &str,
) -> Result<ShareCodeRow> {
    for _ in 0..5 {
        let share_code = Uuid::new_v4()
            .simple()
            .to_string()
            .chars()
            .take(10)
            .collect::<String>();

        let inserted = sqlx::query_as::<_, ShareCodeRow>(
            "INSERT INTO share_codes (user_id, share_code, item_type, item_id, item_name)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (share_code) DO NOTHING
             RETURNING *",
        )
        .bind(user_id)
        .bind(&share_code)
        .bind(item_type)
        .bind(item_id)
        .bind(item_name)
        .fetch_optional(pool)
        .await?;

        if let Some(row) = inserted {
            return Ok(row);
        }
    }

    anyhow::bail!("failed to generate unique share code")
}

pub async fn list_user_share_codes(pool: &PgPool, user_id: Uuid) -> Result<Vec<ShareCodeRow>> {
    let shares = sqlx::query_as::<_, ShareCodeRow>(
        "SELECT * FROM share_codes WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(shares)
}

pub async fn get_share_code(pool: &PgPool, share_code: &str) -> Result<Option<ShareCodeRow>> {
    let share =
        sqlx::query_as::<_, ShareCodeRow>("SELECT * FROM share_codes WHERE share_code = $1")
            .bind(share_code)
            .fetch_optional(pool)
            .await?;
    Ok(share)
}

pub async fn delete_share_code(pool: &PgPool, share_code: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM share_codes WHERE share_code = $1")
        .bind(share_code)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn get_shared_item(
    pool: &PgPool,
    share_code: &str,
) -> Result<
    Option<(
        ShareCodeRow,
        Option<ScriptRow>,
        Option<StyleRow>,
        Option<ConfigRow>,
    )>,
> {
    let Some(share) = get_share_code(pool, share_code).await? else {
        return Ok(None);
    };

    let script = if share.item_type == "Script" {
        sqlx::query_as::<_, ScriptRow>("SELECT * FROM scripts WHERE id = $1")
            .bind(share.item_id)
            .fetch_optional(pool)
            .await?
    } else {
        None
    };

    let style = if share.item_type == "Style" {
        sqlx::query_as::<_, StyleRow>("SELECT * FROM styles WHERE id = $1")
            .bind(share.item_id)
            .fetch_optional(pool)
            .await?
    } else {
        None
    };

    let config = if share.item_type == "Config" {
        sqlx::query_as::<_, ConfigRow>("SELECT * FROM configs WHERE id = $1")
            .bind(share.item_id)
            .fetch_optional(pool)
            .await?
    } else {
        None
    };

    Ok(Some((share, script, style, config)))
}
