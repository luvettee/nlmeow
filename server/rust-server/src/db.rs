use anyhow::Result;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::config::DEFAULT_USER_TOKEN;
use crate::models::{
    BaseModuleRow, ConfigRow, LogEntryRow, ScriptRow, ShareCodeRow, StyleRow, UserRow,
};

// ── Users ──

pub async fn get_user_by_auth_token(pool: &SqlitePool, token: &str) -> Result<Option<UserRow>> {
    // Check for hardcoded default token
    if token == DEFAULT_USER_TOKEN {
        if let Some(user) = get_user_by_username(pool, "astolfo").await? {
            return Ok(Some(user));
        }
    }

    let user = sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE auth_token = ?")
        .bind(token)
        .fetch_optional(pool)
        .await?;
    Ok(user)
}

pub async fn get_user_by_username(pool: &SqlitePool, username: &str) -> Result<Option<UserRow>> {
    let user = sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    Ok(user)
}

pub async fn get_user_by_id(pool: &SqlitePool, id: Uuid) -> Result<Option<UserRow>> {
    let user = sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await?;
    Ok(user)
}

pub async fn create_user(
    pool: &SqlitePool,
    username: &str,
    auth_token: &str,
    base_module_id: Uuid,
    serial: &str,
) -> Result<UserRow> {
    let id = Uuid::new_v4().to_string();
    let user = sqlx::query_as::<_, UserRow>(
        "INSERT INTO users (id, username, auth_token, base_module_id, serial)
         VALUES (?, ?, ?, ?, ?) RETURNING *",
    )
    .bind(&id)
    .bind(username)
    .bind(auth_token)
    .bind(base_module_id.to_string())
    .bind(serial)
    .fetch_one(pool)
    .await?;
    Ok(user)
}

pub async fn create_user_with_password_hash(
    pool: &SqlitePool,
    username: &str,
    password_hash: &str,
    base_module_id: Uuid,
    serial: &str,
) -> Result<UserRow> {
    let id = Uuid::new_v4().to_string();
    let auth_token = Uuid::new_v4().to_string();
    let user = sqlx::query_as::<_, UserRow>(
        "INSERT INTO users (id, username, auth_token, base_module_id, serial, password_hash)
         VALUES (?, ?, ?, ?, ?, ?) RETURNING *",
    )
    .bind(&id)
    .bind(username)
    .bind(&auth_token)
    .bind(base_module_id.to_string())
    .bind(serial)
    .bind(password_hash)
    .fetch_one(pool)
    .await?;
    Ok(user)
}

pub async fn update_user_avatar(
    pool: &SqlitePool,
    user_id: Uuid,
    avatar_png: Option<&[u8]>,
) -> Result<Option<UserRow>> {
    let user =
        sqlx::query_as::<_, UserRow>("UPDATE users SET avatar_png = ? WHERE id = ? RETURNING *")
            .bind(avatar_png)
            .bind(user_id.to_string())
            .fetch_optional(pool)
            .await?;
    Ok(user)
}

pub async fn update_user_type7_blob(
    pool: &SqlitePool,
    user_id: Uuid,
    type7_blob: Option<&str>,
) -> Result<Option<UserRow>> {
    let user = sqlx::query_as::<_, UserRow>(
        "UPDATE users SET type7_blob = ?, type7_updated_at = datetime('now') WHERE id = ? RETURNING *",
    )
    .bind(type7_blob)
    .bind(user_id.to_string())
    .fetch_optional(pool)
    .await?;
    Ok(user)
}

pub async fn list_users(pool: &SqlitePool) -> Result<Vec<UserRow>> {
    let users = sqlx::query_as::<_, UserRow>("SELECT * FROM users ORDER BY created_at")
        .fetch_all(pool)
        .await?;
    Ok(users)
}

// ── Base modules ──

pub async fn get_base_module(pool: &SqlitePool, id: Uuid) -> Result<Option<BaseModuleRow>> {
    let module = sqlx::query_as::<_, BaseModuleRow>("SELECT * FROM base_modules WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await?;
    Ok(module)
}

pub async fn get_first_base_module(pool: &SqlitePool) -> Result<Option<BaseModuleRow>> {
    let module = sqlx::query_as::<_, BaseModuleRow>(
        "SELECT * FROM base_modules ORDER BY created_at, id LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(module)
}

pub async fn insert_base_module(
    pool: &SqlitePool,
    name: &str,
    version: i32,
    author: &str,
    checksum: i64,
    buffer_capacity: i64,
    enabled: i32,
    skin_data_msgpack: &[u8],
    languages_json: &serde_json::Value,
) -> Result<BaseModuleRow> {
    let id = Uuid::new_v4().to_string();
    let json_text = serde_json::to_string(languages_json)?;
    let module = sqlx::query_as::<_, BaseModuleRow>(
        "INSERT INTO base_modules (id, name, version, author, checksum, buffer_capacity, enabled, skin_data_msgpack, languages_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *",
    )
    .bind(&id)
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
    pool: &SqlitePool,
    name: &str,
    version: i32,
    author: &str,
    checksum: i64,
    buffer_capacity: i64,
    enabled: i32,
    skin_data_msgpack: &[u8],
    languages_json: &serde_json::Value,
) -> Result<BaseModuleRow> {
    let id = Uuid::new_v4().to_string();
    let json_text = serde_json::to_string(languages_json)?;

    // SQLite doesn't support ON CONFLICT with RETURNING in all versions,
    // so we try insert first, then update if it fails
    let result = sqlx::query_as::<_, BaseModuleRow>(
        "INSERT INTO base_modules (id, name, version, author, checksum, buffer_capacity, enabled, skin_data_msgpack, languages_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *",
    )
    .bind(&id)
    .bind(name)
    .bind(version)
    .bind(author)
    .bind(checksum)
    .bind(buffer_capacity)
    .bind(enabled)
    .bind(skin_data_msgpack)
    .bind(&json_text)
    .fetch_one(pool)
    .await;

    match result {
        Ok(module) => Ok(module),
        Err(_) => {
            // Try to update existing
            sqlx::query(
                "UPDATE base_modules SET version = ?, author = ?, checksum = ?, buffer_capacity = ?, enabled = ?, skin_data_msgpack = ?, languages_json = ?, updated_at = datetime('now') WHERE name = ?",
            )
            .bind(version)
            .bind(author)
            .bind(checksum)
            .bind(buffer_capacity)
            .bind(enabled)
            .bind(skin_data_msgpack)
            .bind(&json_text)
            .bind(name)
            .execute(pool)
            .await?;

            get_base_module_by_name(pool, name).await.ok().flatten().ok_or_else(|| {
                anyhow::anyhow!("failed to find base module '{}' after upsert", name)
            })
        }
    }
}

async fn get_base_module_by_name(pool: &SqlitePool, name: &str) -> Result<Option<BaseModuleRow>> {
    let module = sqlx::query_as::<_, BaseModuleRow>("SELECT * FROM base_modules WHERE name = ?")
        .bind(name)
        .fetch_optional(pool)
        .await?;
    Ok(module)
}

// ── Log entries ──

pub async fn get_user_log_entries(pool: &SqlitePool, user_id: Uuid) -> Result<Vec<LogEntryRow>> {
    let entries = sqlx::query_as::<_, LogEntryRow>(
        "SELECT * FROM log_entries WHERE user_id = ? ORDER BY entry_id",
    )
    .bind(user_id.to_string())
    .fetch_all(pool)
    .await?;
    Ok(entries)
}

pub async fn get_user_log_entry(
    pool: &SqlitePool,
    user_id: Uuid,
    entry_id: i32,
) -> Result<Option<LogEntryRow>> {
    let entry = sqlx::query_as::<_, LogEntryRow>(
        "SELECT * FROM log_entries WHERE user_id = ? AND entry_id = ?",
    )
    .bind(user_id.to_string())
    .bind(entry_id)
    .fetch_optional(pool)
    .await?;
    Ok(entry)
}

pub async fn create_log_entry(
    pool: &SqlitePool,
    user_id: Uuid,
    entry_id: i32,
    timestamp: i32,
    entry_type: &str,
    author: &str,
) -> Result<LogEntryRow> {
    let id = Uuid::new_v4().to_string();
    let entry = sqlx::query_as::<_, LogEntryRow>(
        "INSERT INTO log_entries (id, user_id, entry_id, timestamp, entry_type, author)
         VALUES (?, ?, ?, ?, ?, ?) RETURNING *",
    )
    .bind(&id)
    .bind(user_id.to_string())
    .bind(entry_id)
    .bind(timestamp)
    .bind(entry_type)
    .bind(author)
    .fetch_one(pool)
    .await?;
    Ok(entry)
}

pub async fn update_log_entry(
    pool: &SqlitePool,
    id: Uuid,
    entry_id: i32,
    timestamp: i32,
    entry_type: &str,
    author: &str,
) -> Result<Option<LogEntryRow>> {
    let entry = sqlx::query_as::<_, LogEntryRow>(
        "UPDATE log_entries SET entry_id = ?, timestamp = ?, entry_type = ?, author = ?
         WHERE id = ? RETURNING *",
    )
    .bind(entry_id)
    .bind(timestamp)
    .bind(entry_type)
    .bind(author)
    .bind(id.to_string())
    .fetch_optional(pool)
    .await?;
    Ok(entry)
}

pub async fn delete_log_entry(pool: &SqlitePool, id: Uuid) -> Result<bool> {
    let result = sqlx::query("DELETE FROM log_entries WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn delete_log_entry_by_user_entry_id(
    pool: &SqlitePool,
    user_id: Uuid,
    entry_id: i32,
) -> Result<bool> {
    let result = sqlx::query("DELETE FROM log_entries WHERE user_id = ? AND entry_id = ?")
        .bind(user_id.to_string())
        .bind(entry_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn update_log_entry_timestamp(
    pool: &SqlitePool,
    user_id: Uuid,
    entry_id: i32,
    timestamp: i32,
) -> Result<bool> {
    let result =
        sqlx::query("UPDATE log_entries SET timestamp = ? WHERE user_id = ? AND entry_id = ?")
            .bind(timestamp)
            .bind(user_id.to_string())
            .bind(entry_id)
            .execute(pool)
            .await?;
    Ok(result.rows_affected() > 0)
}

// ── Scripts ──

pub async fn next_entry_id(pool: &SqlitePool, user_id: Uuid) -> Result<i32> {
    let row: (Option<i32>,) =
        sqlx::query_as("SELECT MAX(entry_id) FROM log_entries WHERE user_id = ?")
            .bind(user_id.to_string())
            .fetch_one(pool)
            .await?;
    Ok(row.0.unwrap_or(0) + 1)
}

pub async fn get_user_scripts(pool: &SqlitePool, user_id: Uuid) -> Result<Vec<ScriptRow>> {
    let scripts = sqlx::query_as::<_, ScriptRow>(
        "SELECT * FROM scripts WHERE user_id = ? ORDER BY entry_id",
    )
    .bind(user_id.to_string())
    .fetch_all(pool)
    .await?;
    Ok(scripts)
}

pub async fn get_user_script_by_name(
    pool: &SqlitePool,
    user_id: Uuid,
    name: &str,
) -> Result<Option<ScriptRow>> {
    let script = sqlx::query_as::<_, ScriptRow>(
        "SELECT * FROM scripts WHERE user_id = ? AND name = ? ORDER BY updated_at DESC LIMIT 1",
    )
    .bind(user_id.to_string())
    .bind(name)
    .fetch_optional(pool)
    .await?;
    Ok(script)
}

pub async fn get_user_script(
    pool: &SqlitePool,
    user_id: Uuid,
    entry_id: i32,
) -> Result<Option<ScriptRow>> {
    let script = sqlx::query_as::<_, ScriptRow>(
        "SELECT * FROM scripts WHERE user_id = ? AND entry_id = ?",
    )
    .bind(user_id.to_string())
    .bind(entry_id)
    .fetch_optional(pool)
    .await?;
    Ok(script)
}

pub async fn get_user_configs(pool: &SqlitePool, user_id: Uuid) -> Result<Vec<ConfigRow>> {
    let configs = sqlx::query_as::<_, ConfigRow>(
        "SELECT * FROM configs WHERE user_id = ? ORDER BY entry_id",
    )
    .bind(user_id.to_string())
    .fetch_all(pool)
    .await?;
    Ok(configs)
}

pub async fn get_user_styles(pool: &SqlitePool, user_id: Uuid) -> Result<Vec<StyleRow>> {
    let styles =
        sqlx::query_as::<_, StyleRow>("SELECT * FROM styles WHERE user_id = ? ORDER BY entry_id")
            .bind(user_id.to_string())
            .fetch_all(pool)
            .await?;
    Ok(styles)
}

pub async fn get_user_style(
    pool: &SqlitePool,
    user_id: Uuid,
    entry_id: i32,
) -> Result<Option<StyleRow>> {
    let style =
        sqlx::query_as::<_, StyleRow>("SELECT * FROM styles WHERE user_id = ? AND entry_id = ?")
            .bind(user_id.to_string())
            .bind(entry_id)
            .fetch_optional(pool)
            .await?;
    Ok(style)
}

pub async fn create_script(
    pool: &SqlitePool,
    user_id: Uuid,
    entry_id: i32,
    name: &str,
) -> Result<ScriptRow> {
    let id = Uuid::new_v4().to_string();
    let script = sqlx::query_as::<_, ScriptRow>(
        "INSERT INTO scripts (id, user_id, entry_id, name) VALUES (?, ?, ?, ?) RETURNING *",
    )
    .bind(&id)
    .bind(user_id.to_string())
    .bind(entry_id)
    .bind(name)
    .fetch_one(pool)
    .await?;
    Ok(script)
}

pub async fn create_config(
    pool: &SqlitePool,
    user_id: Uuid,
    entry_id: i32,
    name: &str,
) -> Result<ConfigRow> {
    let id = Uuid::new_v4().to_string();
    let config = sqlx::query_as::<_, ConfigRow>(
        "INSERT INTO configs (id, user_id, entry_id, name) VALUES (?, ?, ?, ?) RETURNING *",
    )
    .bind(&id)
    .bind(user_id.to_string())
    .bind(entry_id)
    .bind(name)
    .fetch_one(pool)
    .await?;
    Ok(config)
}

pub async fn create_style(
    pool: &SqlitePool,
    user_id: Uuid,
    entry_id: i32,
    name: &str,
) -> Result<StyleRow> {
    let id = Uuid::new_v4().to_string();

    // Try to insert, handle conflict with update
    let result = sqlx::query_as::<_, StyleRow>(
        "INSERT INTO styles (id, user_id, entry_id, name) VALUES (?, ?, ?, ?) RETURNING *",
    )
    .bind(&id)
    .bind(user_id.to_string())
    .bind(entry_id)
    .bind(name)
    .fetch_one(pool)
    .await;

    match result {
        Ok(style) => Ok(style),
        Err(_) => {
            // Update existing
            sqlx::query(
                "UPDATE styles SET name = ?, updated_at = datetime('now') WHERE user_id = ? AND entry_id = ?",
            )
            .bind(name)
            .bind(user_id.to_string())
            .bind(entry_id)
            .execute(pool)
            .await?;

            get_user_style(pool, user_id, entry_id).await.ok().flatten().ok_or_else(|| {
                anyhow::anyhow!("failed to find style after upsert")
            })
        }
    }
}

pub async fn update_script_name(
    pool: &SqlitePool,
    user_id: Uuid,
    entry_id: i32,
    name: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE scripts SET name = ?, updated_at = datetime('now') WHERE user_id = ? AND entry_id = ?",
    )
    .bind(name)
    .bind(user_id.to_string())
    .bind(entry_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn update_config_name(
    pool: &SqlitePool,
    user_id: Uuid,
    entry_id: i32,
    name: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE configs SET name = ?, updated_at = datetime('now') WHERE user_id = ? AND entry_id = ?",
    )
    .bind(name)
    .bind(user_id.to_string())
    .bind(entry_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn update_style_name(
    pool: &SqlitePool,
    user_id: Uuid,
    entry_id: i32,
    name: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE styles SET name = ?, updated_at = datetime('now') WHERE user_id = ? AND entry_id = ?",
    )
    .bind(name)
    .bind(user_id.to_string())
    .bind(entry_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn update_script_content(
    pool: &SqlitePool,
    user_id: Uuid,
    entry_id: i32,
    content: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE scripts SET content = ?, updated_at = datetime('now') WHERE user_id = ? AND entry_id = ?",
    )
    .bind(content)
    .bind(user_id.to_string())
    .bind(entry_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn update_config_content(
    pool: &SqlitePool,
    user_id: Uuid,
    entry_id: i32,
    content: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE configs SET content = ?, updated_at = datetime('now') WHERE user_id = ? AND entry_id = ?",
    )
    .bind(content)
    .bind(user_id.to_string())
    .bind(entry_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn update_style_content(
    pool: &SqlitePool,
    user_id: Uuid,
    entry_id: i32,
    content: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE styles SET content = ?, updated_at = datetime('now') WHERE user_id = ? AND entry_id = ?",
    )
    .bind(content)
    .bind(user_id.to_string())
    .bind(entry_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn delete_script(pool: &SqlitePool, user_id: Uuid, entry_id: i32) -> Result<bool> {
    let result = sqlx::query("DELETE FROM scripts WHERE user_id = ? AND entry_id = ?")
        .bind(user_id.to_string())
        .bind(entry_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn delete_config(pool: &SqlitePool, user_id: Uuid, entry_id: i32) -> Result<bool> {
    let result = sqlx::query("DELETE FROM configs WHERE user_id = ? AND entry_id = ?")
        .bind(user_id.to_string())
        .bind(entry_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn delete_style(pool: &SqlitePool, user_id: Uuid, entry_id: i32) -> Result<bool> {
    let result = sqlx::query("DELETE FROM styles WHERE user_id = ? AND entry_id = ?")
        .bind(user_id.to_string())
        .bind(entry_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn get_user_config(
    pool: &SqlitePool,
    user_id: Uuid,
    entry_id: i32,
) -> Result<Option<ConfigRow>> {
    let config = sqlx::query_as::<_, ConfigRow>(
        "SELECT * FROM configs WHERE user_id = ? AND entry_id = ?",
    )
    .bind(user_id.to_string())
    .bind(entry_id)
    .fetch_optional(pool)
    .await?;
    Ok(config)
}

pub async fn create_share_code(
    pool: &SqlitePool,
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

        let id = Uuid::new_v4().to_string();

        let inserted = sqlx::query_as::<_, ShareCodeRow>(
            "INSERT INTO share_codes (id, user_id, share_code, item_type, item_id, item_name)
             VALUES (?, ?, ?, ?, ?, ?) RETURNING *",
        )
        .bind(&id)
        .bind(user_id.to_string())
        .bind(&share_code)
        .bind(item_type)
        .bind(item_id.to_string())
        .bind(item_name)
        .fetch_optional(pool)
        .await;

        match inserted {
            Ok(Some(row)) => return Ok(row),
            Ok(None) => continue, // Conflict, try again
            Err(_) => continue,  // Try again on error too
        }
    }

    anyhow::bail!("failed to generate unique share code")
}

pub async fn list_user_share_codes(pool: &SqlitePool, user_id: Uuid) -> Result<Vec<ShareCodeRow>> {
    let shares = sqlx::query_as::<_, ShareCodeRow>(
        "SELECT * FROM share_codes WHERE user_id = ? ORDER BY created_at DESC",
    )
    .bind(user_id.to_string())
    .fetch_all(pool)
    .await?;
    Ok(shares)
}

pub async fn get_share_code(pool: &SqlitePool, share_code: &str) -> Result<Option<ShareCodeRow>> {
    let share =
        sqlx::query_as::<_, ShareCodeRow>("SELECT * FROM share_codes WHERE share_code = ?")
            .bind(share_code)
            .fetch_optional(pool)
            .await?;
    Ok(share)
}

pub async fn delete_share_code(pool: &SqlitePool, share_code: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM share_codes WHERE share_code = ?")
        .bind(share_code)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn get_shared_item(
    pool: &SqlitePool,
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
        sqlx::query_as::<_, ScriptRow>("SELECT * FROM scripts WHERE id = ?")
            .bind(&share.item_id)
            .fetch_optional(pool)
            .await?
    } else {
        None
    };

    let style = if share.item_type == "Style" {
        sqlx::query_as::<_, StyleRow>("SELECT * FROM styles WHERE id = ?")
            .bind(&share.item_id)
            .fetch_optional(pool)
            .await?
    } else {
        None
    };

    let config = if share.item_type == "Config" {
        sqlx::query_as::<_, ConfigRow>("SELECT * FROM configs WHERE id = ?")
            .bind(&share.item_id)
            .fetch_optional(pool)
            .await?
    } else {
        None
    };

    Ok(Some((share, script, style, config)))
}