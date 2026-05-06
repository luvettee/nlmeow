use std::net::SocketAddr;

use axum::{
    Router,
    extract::{
        ConnectInfo, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
    routing::any,
};
use anyhow::Context;
use serde_json::json;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::config::{AUTH_DATA, AUTH_MESSAGE};
use crate::data::KEY_BIN;
use crate::{AppState, db, module_builder};

pub fn router(state: AppState) -> Router {
    Router::new().fallback(any(ws_upgrade)).with_state(state)
}

async fn ws_upgrade(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    tracing::info!("[WS] New WebSocket upgrade request from {}", addr);
    ws.max_message_size(50 * 1024 * 1024)
        .on_upgrade(move |socket| handle_ws(socket, state, addr))
}

async fn handle_ws(mut socket: WebSocket, state: AppState, addr: SocketAddr) {
    tracing::info!(
        "[WS] Connection established from {}, waiting for first message...",
        addr
    );

    // Wait for client's first message — contains "token\nclient\ngame"
    let first = socket.recv().await;
    let token = match first {
        Some(Ok(ref msg)) => {
            tracing::info!("[WS] <- First message: {}", msg_summary(msg));
            match msg {
                Message::Text(t) => t.lines().next().unwrap_or("").trim().to_string(),
                _ => String::new(),
            }
        }
        Some(Err(e)) => {
            tracing::warn!("[WS] <- Recv error on first message: {e}");
            return;
        }
        None => {
            tracing::info!("[WS] <- Client disconnected before sending");
            return;
        }
    };

    if token.is_empty() {
        tracing::warn!("[WS] No token found in first message, closing");
        return;
    }

    tracing::info!("[WS] Token from first message: {token}");

    // Store IP → token mapping for avatar lookups
    state
        .ip_tokens
        .write()
        .await
        .insert(addr.ip(), token.clone());
    tracing::info!("[WS] Stored IP→token mapping: {} → {}", addr.ip(), token);

    // Frame 1: Auth JSON
    let auth = json!({
        "Type": "Auth",
        "Message": AUTH_MESSAGE,
        "Data": AUTH_DATA,
    });
    tracing::info!("[WS] -> Auth JSON: {}", auth);
    if socket
        .send(Message::Text(auth.to_string().into()))
        .await
        .is_err()
    {
        tracing::error!("[WS] Failed to send auth frame");
        return;
    }

    // Frame 2: module blob — raw file override or build from DB
    let module_bin = if let Some(ref raw) = state.raw_module {
        tracing::info!("[WS] Using raw module override ({} bytes)", raw.len());
        raw.clone()
    } else {
        match build_user_module(&state, &token).await {
            Ok(bin) => bin,
            Err(e) => {
                tracing::error!("[WS] Failed to build module for token={}: {:?}", token, e);
                return;
            }
        }
    };

    tracing::info!("[WS] -> Module blob ({} bytes)", module_bin.len());
    if socket
        .send(Message::Binary(module_bin.into()))
        .await
        .is_err()
    {
        tracing::error!("[WS] Failed to send module blob");
        return;
    }

    // Frame 3: Key blob
    tracing::info!("[WS] -> Key blob ({} bytes)", KEY_BIN.len());
    if socket
        .send(Message::Binary(KEY_BIN.to_vec().into()))
        .await
        .is_err()
    {
        tracing::error!("[WS] Failed to send key blob");
        return;
    }

    tracing::info!("[WS] All 3 frames sent, processing client messages...");

    // Look up user for DB operations
    let user = match db::get_user_by_auth_token(&state.db, &token).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            tracing::warn!("[WS] No user for token {}, will log but not persist", token);
            drain_messages(&mut socket).await;
            return;
        }
        Err(e) => {
            tracing::error!("[WS] DB error looking up user: {e}");
            drain_messages(&mut socket).await;
            return;
        }
    };

    let live_conn_id = Uuid::new_v4();
    let (live_tx, mut live_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    state
        .live_replies
        .write()
        .await
        .entry(token.clone())
        .or_default()
        .insert(live_conn_id, live_tx);
    tracing::info!(
        "[WS] Registered live reply channel id={} user={}",
        live_conn_id,
        user.username
    );

    let mut msg_count = 0u32;
    loop {
        tokio::select! {
            maybe_reply = live_rx.recv() => {
                match maybe_reply {
                    Some(reply) => send_reply(&mut socket, &reply, "[WS] Live").await,
                    None => break,
                }
            }
            maybe_msg = socket.recv() => {
                let Some(msg) = maybe_msg else {
                    break;
                };

                match msg {
                    Ok(msg) => {
                        if matches!(msg, Message::Close(_)) {
                            tracing::info!("[WS] <- Close: {}", msg_summary(&msg));
                            break;
                        }
                        msg_count += 1;

                        if let Message::Binary(ref data) = msg {
                            handle_binary_msg(&state, &user, data, msg_count, &mut socket).await;
                        } else {
                            tracing::info!("[WS] <- Msg #{}: {}", msg_count, msg_summary(&msg));
                        }
                    }
                    Err(e) => {
                        tracing::warn!("[WS] <- Error: {e}");
                        break;
                    }
                }
            }
        }
    }

    unregister_live_reply(&state, &token, live_conn_id).await;

    tracing::info!(
        "[WS] Disconnected (received {} post-auth messages)",
        msg_count
    );
}

async fn build_user_module(state: &AppState, token: &str) -> anyhow::Result<Vec<u8>> {
    let user = db::get_user_by_auth_token(&state.db, token)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no user found for token"))?;

    let base_module = db::get_base_module(&state.db, user.base_module_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("base module not found"))?;

    let log_entries = db::get_user_log_entries(&state.db, user.id).await?;
    let scripts = db::get_user_scripts(&state.db, user.id).await?;
    let styles = db::get_user_styles(&state.db, user.id).await?;

    module_builder::build_module_bin(
        &base_module,
        &user.username,
        user.type7_blob.as_deref(),
        &log_entries,
        &scripts,
        &styles,
    )
}

async fn drain_messages(socket: &mut WebSocket) {
    while let Some(msg) = socket.recv().await {
        match msg {
            Ok(msg) if matches!(msg, Message::Close(_)) => break,
            Err(_) => break,
            _ => {}
        }
    }
}

async fn handle_binary_msg(
    state: &AppState,
    user: &crate::models::UserRow,
    data: &[u8],
    msg_num: u32,
    socket: &mut WebSocket,
) {
    use nl_parser::pipeline;

    let prefix = format!("[WS] Msg #{msg_num}");

    // Decrypt + decompress
    let decompressed = match pipeline::decrypt(data) {
        Ok(decrypted) => match pipeline::decompress(&decrypted) {
            Ok(d) => d,
            Err(_) => {
                tracing::debug!("{prefix} decrypt ok but decompress failed");
                return;
            }
        },
        Err(_) => {
            tracing::debug!("{prefix} decrypt failed, ignoring");
            return;
        }
    };

    // Parse as client message
    match crate::client_msg::parse(&decompressed) {
        Ok(msg) => {
            tracing::info!("{prefix} parsed: {msg:?}");
            if let crate::client_msg::ClientMsg::Unknown { msg_type: 7, payload } = &msg {
                if let Err(e) = save_type7_blob(state, user.id, payload, &prefix).await {
                    tracing::error!("{prefix} failed to persist type7 blob: {e}");
                }
            }
            let reply = handle_client_msg(state, user, &msg, &prefix).await;
            if let Some(reply_bytes) = reply {
                send_reply(socket, &reply_bytes, &prefix).await;
            }
        }
        Err(e) => {
            tracing::warn!(
                "{prefix} parse error: {e}, hex: {}",
                hex_preview(&decompressed, 128)
            );
        }
    }
}

async fn send_reply(socket: &mut WebSocket, flatbuffer: &[u8], prefix: &str) {
    use nl_parser::pipeline;
    let compressed = pipeline::compress(flatbuffer);
    match pipeline::encrypt(&compressed) {
        Ok(encrypted) => {
            tracing::info!(
                "{prefix} -> Reply ({} bytes plaintext, {} encrypted)",
                flatbuffer.len(),
                encrypted.len()
            );
            if socket
                .send(Message::Binary(encrypted.into()))
                .await
                .is_err()
            {
                tracing::error!("{prefix} Failed to send reply");
            }
        }
        Err(e) => {
            tracing::error!("{prefix} Failed to encrypt reply: {e}");
        }
    }
}

async fn unregister_live_reply(state: &AppState, token: &str, conn_id: Uuid) {
    let mut live_replies = state.live_replies.write().await;
    if let Some(conns) = live_replies.get_mut(token) {
        conns.remove(&conn_id);
        if conns.is_empty() {
            live_replies.remove(token);
        }
    }
}

pub async fn push_live_insert(
    state: &AppState,
    token: &str,
    entry_id: u32,
    timestamp: u32,
    entry_type: &str,
    name: &str,
    author: &str,
) -> anyhow::Result<usize> {
    let reply = build_create_response(entry_id, timestamp, entry_type, name, author, None)?;
    let mut live_replies = state.live_replies.write().await;
    let Some(conns) = live_replies.get_mut(token) else {
        return Ok(0);
    };

    let mut sent = 0usize;
    conns.retain(|_, tx| {
        let did_send = tx.send(reply.clone()).is_ok();
        if did_send {
            sent += 1;
        }
        did_send
    });

    if conns.is_empty() {
        live_replies.remove(token);
    }

    Ok(sent)
}

/// Handle a parsed client message. Returns a FlatBuffer reply to send back, if any.
async fn handle_client_msg(
    state: &AppState,
    user: &crate::models::UserRow,
    msg: &crate::client_msg::ClientMsg,
    prefix: &str,
) -> Option<Vec<u8>> {
    use crate::client_msg::ClientMsg;

    match msg {
        ClientMsg::Init { steam_id } => {
            tracing::info!("{prefix} Init: steam_id={steam_id} user={}", user.username);
            None
        }

        ClientMsg::ConfigAck { entry_id } => {
            tracing::info!(
                "{prefix} ConfigAck: entry_id={entry_id} user={}",
                user.username
            );

            let configs = match db::get_user_configs(&state.db, user.id).await {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::error!("{prefix} failed to load configs for ConfigAck: {e}");
                    return None;
                }
            };

            let config = match configs
                .iter()
                .find(|config| config.entry_id == *entry_id as i32)
            {
                Some(row) => row,
                None => {
                    tracing::warn!(
                        "{prefix} ConfigAck entry_id={entry_id} had no matching stored config"
                    );
                    return None;
                }
            };

            tracing::info!(
                "{prefix} ConfigAck -> case11 entry_id={} content_len={}",
                entry_id,
                config.content.len()
            );

            match build_case11_response(*entry_id, &config.content) {
                Ok(reply) => Some(reply),
                Err(e) => {
                    tracing::error!("{prefix} failed to build case11 config reply: {e}");
                    None
                }
            }
        }

        ClientMsg::CreateEntry {
            name,
            entry_type,
            expected_count,
            content,
        } => {
            let type_str = entry_type_name(*entry_type);
            tracing::info!(
                "{prefix} CreateEntry: name={name:?} type={type_str} expected_count={expected_count} content_len={} user={}",
                content.as_ref().map(|c| c.len()).unwrap_or(0),
                user.username
            );
            if *entry_type == 2 {
                if let Some(style_content) = content.as_deref() {
                    tracing::info!(
                        "{prefix} Style create content preview: {}",
                        content_preview(style_content, 2048)
                    );
                }
            }

            // Assign next entry_id
            let entry_id = match db::next_entry_id(&state.db, user.id).await {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!("{prefix} failed to get next entry_id: {e}");
                    return None;
                }
            };

            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i32;

            // Create log entry
            if let Err(e) = db::create_log_entry(
                &state.db,
                user.id,
                entry_id,
                now_ts,
                type_str,
                &user.username,
            )
            .await
            {
                tracing::error!("{prefix} failed to create log entry: {e}");
                return None;
            }

            // Create backing row for the new entry.
            if let Err(e) = create_entry_row(&state.db, user.id, entry_id, *entry_type, name).await
            {
                tracing::error!("{prefix} failed to create {type_str}: {e}");
                return None;
            }
            if let Some(initial_content) = content.as_deref() {
                update_entry_content(
                    state,
                    user,
                    entry_id,
                    *entry_type,
                    initial_content,
                    type_str,
                    prefix,
                )
                .await;
            }

            tracing::info!("{prefix} Created entry_id={entry_id} type={type_str} name={name:?}");

            // Build the live-insert response using the standard LogEntry vector shape.
            match build_create_response(
                entry_id as u32,
                now_ts as u32,
                type_str,
                name,
                &user.username,
                content.as_deref(),
            ) {
                Ok(reply) => Some(reply),
                Err(e) => {
                    tracing::error!("{prefix} failed to build create response: {e}");
                    None
                }
            }
        }

        ClientMsg::UpdateEntry {
            entry_id,
            entry_type,
            content,
            name,
            timestamp,
        } => {
            let type_str = entry_type_name(*entry_type);
            tracing::info!(
                "{prefix} UpdateEntry: entry_id={entry_id} type={type_str} name={name:?} content_len={} ts={timestamp:?} user={}",
                content.as_ref().map(|c| c.len()).unwrap_or(0),
                user.username
            );

            // Update log entry timestamp if provided
            if let Some(ts) = timestamp {
                if let Err(e) =
                    db::update_log_entry_timestamp(&state.db, user.id, *entry_id as i32, *ts as i32)
                        .await
                {
                    tracing::error!("{prefix} failed to update log entry timestamp: {e}");
                }
            }

            if let Some(new_name) = name {
                update_entry_name(
                    state,
                    user,
                    *entry_id as i32,
                    *entry_type,
                    new_name,
                    type_str,
                    prefix,
                )
                .await;
            }

            if let Some(new_content) = content {
                if *entry_type == 2 {
                    tracing::info!(
                        "{prefix} Style content preview entry_id={entry_id}: {}",
                        content_preview(new_content, 2048)
                    );
                }
                update_entry_content(
                    state,
                    user,
                    *entry_id as i32,
                    *entry_type,
                    new_content,
                    type_str,
                    prefix,
                )
                .await;
            }

            None
        }

        ClientMsg::DuplicateEntry {
            entry_id,
            entry_type,
            name,
        } => {
            let type_str = entry_type_name(*entry_type);
            tracing::info!(
                "{prefix} DuplicateEntry: entry_id={entry_id} type={type_str} name={name:?} user={}",
                user.username
            );

            let new_entry_id = match db::next_entry_id(&state.db, user.id).await {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!("{prefix} failed to get next entry_id for duplicate: {e}");
                    return None;
                }
            };

            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i32;

            let source_author = match db::get_user_log_entry(&state.db, user.id, *entry_id as i32)
                .await
            {
                Ok(Some(entry)) => entry.author,
                Ok(None) => {
                    tracing::warn!(
                        "{prefix} duplicate source log entry_id={entry_id} not found; using current user as author"
                    );
                    user.username.clone()
                }
                Err(e) => {
                    tracing::error!(
                        "{prefix} failed to load duplicate source log entry; using current user as author: {e}"
                    );
                    user.username.clone()
                }
            };

            let duplicate_name = match duplicate_entry_content(
                state,
                user,
                *entry_id as i32,
                *entry_type,
                new_entry_id,
                name.as_deref(),
                prefix,
            )
            .await
            {
                Some(name) => name,
                None => return None,
            };

            if let Err(e) = db::create_log_entry(
                &state.db,
                user.id,
                new_entry_id,
                now_ts,
                type_str,
                &source_author,
            )
            .await
            {
                tracing::error!("{prefix} failed to create duplicate log entry: {e}");
                return None;
            }

            tracing::info!(
                "{prefix} Duplicated entry_id={entry_id} -> {new_entry_id} type={type_str} name={duplicate_name:?}"
            );

            match build_create_response(
                new_entry_id as u32,
                now_ts as u32,
                type_str,
                &duplicate_name,
                &source_author,
                None,
            ) {
                Ok(reply) => Some(reply),
                Err(e) => {
                    tracing::error!("{prefix} failed to build duplicate live insert response: {e}");
                    None
                }
            }
        }

        ClientMsg::DeleteEntry {
            entry_id,
            entry_type,
        } => {
            let type_str = entry_type_name(*entry_type);
            tracing::info!(
                "{prefix} DeleteEntry: entry_id={entry_id} type={type_str} user={}",
                user.username
            );

            let deleted_row = match entry_type {
                1 => db::delete_script(&state.db, user.id, *entry_id as i32).await,
                2 => db::delete_style(&state.db, user.id, *entry_id as i32).await,
                _ => db::delete_config(&state.db, user.id, *entry_id as i32).await,
            };

            match deleted_row {
                Ok(true) => tracing::info!("{prefix} Deleted {type_str} row entry_id={entry_id}"),
                Ok(false) => {
                    tracing::warn!("{prefix} No backing {type_str} row found for entry_id={entry_id}");
                }
                Err(e) => {
                    tracing::error!("{prefix} failed to delete {type_str} row: {e}");
                    return None;
                }
            }

            if let Err(e) = db::delete_log_entry_by_user_entry_id(&state.db, user.id, *entry_id as i32).await {
                tracing::error!("{prefix} failed to delete log entry: {e}");
            }

            None
        }

        ClientMsg::Unknown { msg_type, .. } => {
            if *msg_type == 7 {
                tracing::info!("{prefix} type7 received");
            }
            tracing::warn!("{prefix} Unknown message type {msg_type}");
            None
        }
    }
}

async fn save_type7_blob(
    state: &AppState,
    user_id: Uuid,
    payload: &[u8],
    prefix: &str,
) -> anyhow::Result<()> {
    let blob = extract_type7_blob_text(payload)?;

    db::update_user_type7_blob(&state.db, user_id, Some(&blob))
        .await?
        .ok_or_else(|| anyhow::anyhow!("type7 blob update affected no rows"))?;

    tracing::info!(
        "{prefix} saved type7 blob len={} preview={}",
        blob.len(),
        content_preview(&blob, 160)
    );
    Ok(())
}

fn extract_type7_blob_text(payload: &[u8]) -> anyhow::Result<String> {
    fn is_b64ish(b: u8) -> bool {
        matches!(b,
            b'A'..=b'Z' |
            b'a'..=b'z' |
            b'0'..=b'9' |
            b'+' | b'/' | b'=' |
            b'-' | b'_')
    }

    let mut best = (0usize, 0usize);
    let mut start = None;

    for (idx, &byte) in payload.iter().enumerate() {
        if is_b64ish(byte) {
            if start.is_none() {
                start = Some(idx);
            }
        } else if let Some(s) = start.take() {
            let len = idx - s;
            if len > best.1 {
                best = (s, len);
            }
        }
    }

    if let Some(s) = start {
        let len = payload.len() - s;
        if len > best.1 {
            best = (s, len);
        }
    }

    anyhow::ensure!(best.1 > 32, "type7 blob text not found");
    let text = std::str::from_utf8(&payload[best.0..best.0 + best.1])
        .context("type7 blob candidate was not UTF-8")?
        .trim_matches('\0')
        .to_string();
    anyhow::ensure!(!text.is_empty(), "type7 blob text empty");
    Ok(text)
}

fn entry_type_name(entry_type: u32) -> &'static str {
    match entry_type {
        1 => "Script",
        2 => "Style",
        _ => "Config",
    }
}

fn entry_type_id_from_name(entry_type: &str) -> u32 {
    match entry_type {
        "Script" => 1,
        "Style" => 2,
        _ => 0,
    }
}

async fn create_entry_row(
    db_pool: &sqlx::PgPool,
    user_id: Uuid,
    entry_id: i32,
    entry_type: u32,
    name: &str,
) -> anyhow::Result<()> {
    match entry_type {
        1 => {
            db::create_script(db_pool, user_id, entry_id, name).await?;
        }
        2 => {
            db::create_style(db_pool, user_id, entry_id, name).await?;
        }
        _ => {
            db::create_config(db_pool, user_id, entry_id, name).await?;
        }
    }
    Ok(())
}

async fn update_entry_name(
    state: &AppState,
    user: &crate::models::UserRow,
    entry_id: i32,
    entry_type: u32,
    new_name: &str,
    type_str: &str,
    prefix: &str,
) {
    let updated = match entry_type {
        1 => db::update_script_name(&state.db, user.id, entry_id, new_name).await,
        2 => db::update_style_name(&state.db, user.id, entry_id, new_name).await,
        _ => db::update_config_name(&state.db, user.id, entry_id, new_name).await,
    };

    match updated {
        Ok(true) => tracing::info!("{prefix} Renamed {type_str} {entry_id} to {new_name:?}"),
        Ok(false) => {
            tracing::info!(
                "{prefix} {type_str} {entry_id} not found, creating with name {new_name:?}"
            );
            let _ = create_entry_row(&state.db, user.id, entry_id, entry_type, new_name).await;
        }
        Err(e) => tracing::error!("{prefix} failed to update {type_str} name: {e}"),
    }
}

async fn update_entry_content(
    state: &AppState,
    user: &crate::models::UserRow,
    entry_id: i32,
    entry_type: u32,
    new_content: &str,
    type_str: &str,
    prefix: &str,
) {
    let updated = match entry_type {
        1 => db::update_script_content(&state.db, user.id, entry_id, new_content).await,
        2 => db::update_style_content(&state.db, user.id, entry_id, new_content).await,
        _ => db::update_config_content(&state.db, user.id, entry_id, new_content).await,
    };

    match updated {
        Ok(true) => tracing::info!(
            "{prefix} Updated {type_str} {entry_id} content ({} bytes)",
            new_content.len()
        ),
        Ok(false) => {
            tracing::info!("{prefix} {type_str} {entry_id} not found for content update, creating");
            if create_entry_row(&state.db, user.id, entry_id, entry_type, "")
                .await
                .is_ok()
            {
                let _ = match entry_type {
                    1 => db::update_script_content(&state.db, user.id, entry_id, new_content).await,
                    2 => db::update_style_content(&state.db, user.id, entry_id, new_content).await,
                    _ => db::update_config_content(&state.db, user.id, entry_id, new_content).await,
                };
            }
        }
        Err(e) => tracing::error!("{prefix} failed to update {type_str} content: {e}"),
    }
}

async fn duplicate_entry_content(
    state: &AppState,
    user: &crate::models::UserRow,
    source_entry_id: i32,
    entry_type: u32,
    new_entry_id: i32,
    requested_name: Option<&str>,
    prefix: &str,
) -> Option<String> {
    match entry_type {
        1 => {
            let source = match db::get_user_script(&state.db, user.id, source_entry_id).await {
                Ok(Some(script)) => script,
                Ok(None) => {
                    tracing::warn!(
                        "{prefix} duplicate source script entry_id={source_entry_id} not found"
                    );
                    return None;
                }
                Err(e) => {
                    tracing::error!("{prefix} failed to load duplicate source script: {e}");
                    return None;
                }
            };
            let duplicate_name = duplicate_name(requested_name, &source.name);
            if let Err(e) =
                db::create_script(&state.db, user.id, new_entry_id, &duplicate_name).await
            {
                tracing::error!("{prefix} failed to create duplicate script: {e}");
                return None;
            }
            if let Err(e) =
                db::update_script_content(&state.db, user.id, new_entry_id, &source.content).await
            {
                tracing::error!("{prefix} failed to copy duplicate script content: {e}");
                return None;
            }
            Some(duplicate_name)
        }
        2 => {
            let source = match db::get_user_style(&state.db, user.id, source_entry_id).await {
                Ok(Some(style)) => style,
                Ok(None) => {
                    tracing::warn!(
                        "{prefix} duplicate source style entry_id={source_entry_id} not found"
                    );
                    return None;
                }
                Err(e) => {
                    tracing::error!("{prefix} failed to load duplicate source style: {e}");
                    return None;
                }
            };
            let duplicate_name = duplicate_name(requested_name, &source.name);
            if let Err(e) =
                db::create_style(&state.db, user.id, new_entry_id, &duplicate_name).await
            {
                tracing::error!("{prefix} failed to create duplicate style: {e}");
                return None;
            }
            if let Err(e) =
                db::update_style_content(&state.db, user.id, new_entry_id, &source.content).await
            {
                tracing::error!("{prefix} failed to copy duplicate style content: {e}");
                return None;
            }
            Some(duplicate_name)
        }
        _ => {
            let source = match db::get_user_config(&state.db, user.id, source_entry_id).await {
                Ok(Some(config)) => config,
                Ok(None) => {
                    tracing::warn!(
                        "{prefix} duplicate source config entry_id={source_entry_id} not found"
                    );
                    return None;
                }
                Err(e) => {
                    tracing::error!("{prefix} failed to load duplicate source config: {e}");
                    return None;
                }
            };
            let duplicate_name = duplicate_name(requested_name, &source.name);
            if let Err(e) =
                db::create_config(&state.db, user.id, new_entry_id, &duplicate_name).await
            {
                tracing::error!("{prefix} failed to create duplicate config: {e}");
                return None;
            }
            if let Err(e) =
                db::update_config_content(&state.db, user.id, new_entry_id, &source.content).await
            {
                tracing::error!("{prefix} failed to copy duplicate config content: {e}");
                return None;
            }
            Some(duplicate_name)
        }
    }
}

fn duplicate_name(requested_name: Option<&str>, source_name: &str) -> String {
    requested_name
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| source_name.to_string())
}

fn content_preview(content: &str, max_chars: usize) -> String {
    let mut preview = content.chars().take(max_chars).collect::<String>();
    if content.chars().count() > max_chars {
        preview.push_str("...");
    }
    preview
}

fn build_create_response(
    entry_id: u32,
    timestamp: u32,
    entry_type: &str,
    name: &str,
    author: &str,
    content: Option<&str>,
) -> anyhow::Result<Vec<u8>> {
    use nl_parser::flatcc_builder::FlatccBuilder;

    let entry_type_id = entry_type_id_from_name(entry_type);

    let mut ib = FlatccBuilder::new();

    let name_str = ib.create_string(name);
    let author_str = ib.create_string(author);
    let content_str = content.map(|value| ib.create_string(value));
    ib.start_table(if content_str.is_some() { 6 } else { 5 });
    ib.table_add_u32(0, entry_id, 0);
    ib.table_add_u32(1, timestamp, 0);
    ib.table_add_offset(3, name_str);
    ib.table_add_offset(4, author_str);
    if let Some(content_str) = content_str {
        ib.table_add_offset(5, content_str);
    }
    let log_entry = ib.end_table();

    let entries = ib.create_vector_offsets(&[log_entry]);

    ib.start_table(3);
    ib.table_add_u32(0, entry_type_id, 0);
    ib.table_add_offset(1, entries);
    let root = ib.end_table();
    let inner_bytes = ib.finish_minimal(root);

    let mut ob = FlatccBuilder::new();
    let payload = ob.create_vector_u8(&inner_bytes);
    ob.start_table(2);
    ob.table_add_u32(0, 3, 0); // type = 3
    ob.table_add_offset(1, payload);
    let wrapper = ob.end_table();
    Ok(ob.finish_minimal(wrapper))
}

fn build_case11_response(entry_id: u32, payload: &str) -> anyhow::Result<Vec<u8>> {
    use nl_parser::flatcc_builder::FlatccBuilder;

    let inner_bytes = build_case11_inner(entry_id, None, Some(payload));

    let mut ob = FlatccBuilder::new();
    let payload_vec = ob.create_vector_u8(&inner_bytes);
    ob.start_table(2);
    ob.table_add_u32(0, 11, 0); // type = 11
    ob.table_add_offset(1, payload_vec);
    let wrapper = ob.end_table();
    Ok(ob.finish_minimal(wrapper))
}

fn build_case11_inner(entry_id: u32, apply: Option<u32>, payload: Option<&str>) -> Vec<u8> {
    use nl_parser::flatcc_builder::FlatccBuilder;
    let mut ib = FlatccBuilder::new();
    let p = payload.map(|s| ib.create_string(s));
    ib.start_table(3);
    ib.table_add_u32(0, entry_id, 0);
    if let Some(a) = apply {
        ib.table_add_u32(1, a, 0);
    }
    if let Some(val) = p {
        ib.table_add_offset(2, val);
    }
    let root = ib.end_table();
    ib.finish_minimal(root)
}

fn hex_preview(data: &[u8], max_bytes: usize) -> String {
    let preview: String = data
        .iter()
        .take(max_bytes)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    if data.len() > max_bytes {
        format!("{}... ({} bytes total)", preview, data.len())
    } else {
        preview
    }
}

fn msg_summary(msg: &Message) -> String {
    match msg {
        Message::Text(t) => {
            let s = t.as_str();
            if s.len() > 200 {
                format!("text({}B): {}...", s.len(), &s[..200])
            } else {
                format!("text({}B): {s}", s.len())
            }
        }
        Message::Binary(b) => {
            let hex_preview: String = b
                .iter()
                .take(32)
                .map(|byte| format!("{:02x}", byte))
                .collect::<Vec<_>>()
                .join(" ");
            format!("binary({}B): {}", b.len(), hex_preview)
        }
        Message::Ping(b) => format!("ping({}B)", b.len()),
        Message::Pong(b) => format!("pong({}B)", b.len()),
        Message::Close(c) => format!("close({c:?})"),
    }
}
