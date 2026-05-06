use std::{
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use argon2::{
    Argon2, PasswordHasher, PasswordVerifier,
    password_hash::{PasswordHash, SaltString},
};
use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Path as AxumPath, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand_core::OsRng;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use tower::ServiceBuilder;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::config::{self, DEFAULT_SERIAL};
use crate::data::{DEFAULT_AVATAR_PNG, SEED_MODULE_BIN};
use crate::error::AppError;
use crate::models::UserRow;
use crate::{AppState, db, ws};

pub fn router(state: AppState) -> Router {
    let middleware = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(SetResponseHeaderLayer::overriding(
            header::HeaderName::from_static("x-powered-by"),
            HeaderValue::from_static("Express"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONNECTION,
            HeaderValue::from_static("keep-alive"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::HeaderName::from_static("keep-alive"),
            HeaderValue::from_static("timeout=5"),
        ));

    Router::new()
        .route("/", get(index_handler))
        .route("/api/signup", post(signup_handler))
        .route("/api/login", post(login_handler))
        .route("/api/me", get(me_handler))
        .route("/api/avatar", post(update_avatar_handler))
        .route("/api/config", get(config_handler))
        .route("/api/getavatar", get(avatar_handler))
        .route("/getavatar", get(avatar_handler))
        .route("/api/sendlog", get(sendlog_handler))
        .route("/sendlog", get(sendlog_handler))
        .route("/lua/{*name}", get(lua_handler))
        .route("/api/reqitem", get(reqitem_handler))
        .route("/api/items", get(items_handler))
        .route("/api/share", post(share_handler))
        .route("/api/myshares", get(myshares_handler))
        .route("/api/unshare", post(unshare_handler))
        .route("/api/shared/{code}", get(shared_handler))
        .route("/api/import_to_account", post(import_to_account_handler))
        // Admin endpoints
        .route("/admin/seed", post(admin_seed))
        .route(
            "/admin/users",
            post(admin_create_user).get(admin_list_users),
        )
        .route(
            "/admin/users/{id}/logs",
            get(admin_get_logs).post(admin_create_log),
        )
        .route(
            "/admin/users/{user_id}/logs/{log_id}",
            axum::routing::put(admin_update_log).delete(admin_delete_log),
        )
        .fallback(fallback_handler)
        .layer(middleware)
        .with_state(state)
}

async fn index_handler() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}

async fn config_handler(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    tracing::info!("[HTTP] GET /api/config params={:?}", params);
    let resp = json!({
        "status": "ok",
        "version": "2.0",
        "update": false,
        "config": {
            "glow": true,
            "esp": true,
            "aimbot": true,
            "misc": true,
        }
    });
    tracing::debug!("[HTTP] -> config response: {}", resp);
    axum::Json(resp)
}

async fn signup_handler(
    State(state): State<AppState>,
    axum::Json(req): axum::Json<AuthReq>,
) -> Result<Response, AppError> {
    let username = normalize_username(&req.username)?;
    validate_password(&req.password)?;

    if db::get_user_by_username(&state.db, &username)
        .await?
        .is_some()
    {
        return Ok(response_json(
            StatusCode::CONFLICT,
            json!({"error": "username already exists"}),
        ));
    }

    let base = get_or_create_signup_base_module(&state).await?;

    let password_hash = hash_password(&req.password)?;
    let user = db::create_user_with_password_hash(
        &state.db,
        &username,
        &password_hash,
        base.id,
        DEFAULT_SERIAL,
    )
    .await?;

    Ok(response_json(
        StatusCode::CREATED,
        json!({
            "status": "ok",
            "username": user.username,
            "token": user.auth_token,
            "avatar_url": format!("/api/getavatar?token={}", user.auth_token),
        }),
    ))
}

async fn get_or_create_signup_base_module(
    state: &AppState,
) -> Result<crate::models::BaseModuleRow, AppError> {
    if let Some(base) = db::get_first_base_module(&state.db).await? {
        return Ok(base);
    }

    use nl_parser::module::Module;
    use nl_parser::pipeline;

    let flat = pipeline::load_module(SEED_MODULE_BIN)?;
    let module = Module::from_flatbuffer(&flat)?;
    let skin_data_msgpack = Module::extract_raw_skin_data(&flat)?;
    let languages_json = serde_json::to_value(&module.languages)?;

    db::upsert_base_module(
        &state.db,
        "default",
        module.version as i32,
        &module.author,
        module.checksum as i64,
        module.buffer_capacity as i64,
        module.enabled as i32,
        &skin_data_msgpack,
        &languages_json,
    )
    .await
    .map_err(AppError)
}

async fn login_handler(
    State(state): State<AppState>,
    axum::Json(req): axum::Json<AuthReq>,
) -> Result<Response, AppError> {
    let username = normalize_username(&req.username)?;
    let Some(user) = db::get_user_by_username(&state.db, &username).await? else {
        return Ok(invalid_credentials());
    };

    let Some(password_hash) = user.password_hash.as_deref() else {
        return Ok(invalid_credentials());
    };

    if !verify_password(password_hash, &req.password)? {
        return Ok(invalid_credentials());
    }

    Ok(response_json(
        StatusCode::OK,
        json!({
            "status": "ok",
            "username": user.username,
            "token": user.auth_token,
            "has_avatar": user.avatar_png.is_some(),
            "avatar_url": format!("/api/getavatar?token={}", user.auth_token),
        }),
    ))
}

async fn me_handler(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let user = match require_query_user(&state, &params).await? {
        Ok(user) => user,
        Err(response) => return Ok(response),
    };

    Ok(response_json(
        StatusCode::OK,
        json!({
            "status": "ok",
            "username": user.username,
            "token": user.auth_token,
            "has_avatar": user.avatar_png.is_some(),
            "avatar_url": format!("/api/getavatar?token={}", user.auth_token),
        }),
    ))
}

async fn update_avatar_handler(
    State(state): State<AppState>,
    axum::Json(req): axum::Json<AvatarReq>,
) -> Result<Response, AppError> {
    let token = req.token.trim();
    let user = match require_user_by_token(&state, token).await? {
        Ok(user) => user,
        Err(response) => return Ok(response),
    };

    let avatar_png = match req.image_base64.as_deref().map(str::trim) {
        Some("") | None => None,
        Some(image_base64) => Some(decode_avatar_png(image_base64)?),
    };

    db::update_user_avatar(&state.db, user.id, avatar_png.as_deref()).await?;

    Ok(response_json(
        StatusCode::OK,
        json!({
            "status": "ok",
            "has_avatar": avatar_png.is_some(),
            "avatar_url": format!("/api/getavatar?token={}", user.auth_token),
        }),
    ))
}

async fn avatar_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let size = params.get("size").cloned().unwrap_or_default();
    let requested_token = extract_token(&params);
    tracing::info!(
        "[HTTP] GET /api/getavatar size={} token={:?} from={}",
        size,
        requested_token,
        addr
    );

    if let Some(ref token) = requested_token {
        if let Ok(Some(user)) = db::get_user_by_auth_token(&state.db, token).await {
            if let Some(avatar) = user.avatar_png {
                return avatar_response(avatar);
            }
            return default_avatar();
        }
    }

    let fallback_token = state.ip_tokens.read().await.get(&addr.ip()).cloned();
    let fallback_user = match fallback_token {
        Some(token) => db::get_user_by_auth_token(&state.db, &token)
            .await
            .ok()
            .flatten(),
        None => None,
    };

    if let Some(user) = fallback_user {
        if let Some(avatar) = user.avatar_png {
            return avatar_response(avatar);
        }
    }

    default_avatar()
}

async fn sendlog_handler(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    tracing::info!("[HTTP] GET /api/sendlog params={:?}", params);
    tracing::debug!("[HTTP] -> sendlog OK");
    axum::Json(json!({"status": "ok"}))
}

async fn lua_handler(
    State(state): State<AppState>,
    AxumPath(name): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    tracing::info!("[HTTP] GET /lua/{} params={:?}", name, params);
    let body = if let Some(token) = extract_token(&params) {
        match db::get_user_by_auth_token(&state.db, &token).await {
            Ok(Some(user)) => db::get_user_script_by_name(&state.db, user.id, &name)
                .await
                .ok()
                .flatten()
                .map(|script| script.content)
                .filter(|content| !content.is_empty())
                .unwrap_or_else(|| format!("-- lua library: {name}\n"))
                .into_bytes(),
            _ => "-- invalid token\n".as_bytes().to_vec(),
        }
    } else {
        format!("-- lua library: {name}\n").into_bytes()
    };
    tracing::debug!("[HTTP] -> lua response ({} bytes)", body.len());
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn reqitem_handler(Query(params): Query<HashMap<String, String>>) -> Response {
    let name_preview = params
        .get("name")
        .map(|name| preview_text(name, 120))
        .unwrap_or_else(|| "<missing>".to_string());
    tracing::info!(
        "[HTTP] GET /api/reqitem name_preview={} cheat={:?} token_present={}",
        name_preview,
        params.get("cheat"),
        params.get("token").is_some()
    );

    let requested = params
        .get("name")
        .and_then(|name| requested_lua_library_name(name));

    let Some(name) = requested else {
        tracing::debug!("[HTTP] /api/reqitem non-library payload acknowledged");
        return empty_ok();
    };

    let Some(library) = lua_library_response(&name) else {
        tracing::warn!("[HTTP] /api/reqitem missing library {}", name);
        return empty_ok();
    };

    tracing::debug!(
        "[HTTP] -> reqitem library={} file={} bytes={}",
        name,
        library.path.display(),
        library.body.len()
    );
    let body = reqitem_library_json(&name, &library.body);
    let content_len = body.len().to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .header(header::CONTENT_LENGTH, content_len)
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[derive(Clone)]
struct LuaLibrary {
    path: PathBuf,
    body: Vec<u8>,
}

fn requested_lua_library_name(name: &str) -> Option<String> {
    let trimmed = name.trim();
    let library_name = trimmed
        .strip_prefix("-- lua library:")
        .map(str::trim)
        .unwrap_or(trimmed);

    sanitize_lua_library_name(library_name)
}

fn sanitize_lua_library_name(name: &str) -> Option<String> {
    let normalized = name.trim().trim_matches('/').replace('\\', "/");
    if normalized.is_empty()
        || normalized.len() > 160
        || normalized
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
        || normalized
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || normalized.contains(':')
    {
        return None;
    }
    Some(normalized)
}

fn lua_library_response(name: &str) -> Option<LuaLibrary> {
    let name = sanitize_lua_library_name(name)?;
    for candidate in lua_library_candidates(&name) {
        match fs::read(&candidate) {
            Ok(body) => {
                tracing::info!(
                    "[HTTP] lua library {} -> {} ({} bytes)",
                    name,
                    candidate.display(),
                    body.len()
                );
                return Some(LuaLibrary {
                    path: candidate,
                    body,
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                tracing::warn!(
                    "[HTTP] failed reading lua library candidate {}: {}",
                    candidate.display(),
                    err
                );
            }
        }
    }
    None
}

fn lua_library_candidates(name: &str) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let base_dirs = lua_library_dirs();
    let requested = Path::new(name);
    let has_extension = requested.extension().is_some();

    for dir in base_dirs {
        candidates.push(dir.join(requested));
        if !has_extension {
            candidates.push(dir.join(format!("{name}.bin")));
            candidates.push(dir.join(format!("{name}.lua")));
        }
    }

    candidates
}

fn lua_library_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    if let Ok(extra_dirs) = env::var("LUA_LIBRARY_DIRS") {
        dirs.extend(env::split_paths(&extra_dirs).filter(|path| !path.as_os_str().is_empty()));
    }

    dirs.push(PathBuf::from("libraries/open_source"));

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dirs.push(manifest_dir.join("../../libraries/open_source"));
    dirs
}

fn reqitem_library_json(name: &str, body: &[u8]) -> Vec<u8> {
    let body_text = String::from_utf8_lossy(body);
    let item = json!({
        "succ": true,
        "closure": 0,
        "name": name,
        "type": "library",
        "content": body_text,
        "source": body_text,
        "data": body_text,
        "body": body_text,
        "code": body_text,
    });
    let payload = json!({
        "succ": true,
        "closure": 0,
        "name": name,
        "type": "library",
        "content": body_text,
        "source": body_text,
        "data": body_text,
        "item": item,
        "library": item,
        "body": body_text,
        "script": item,
        "code": body_text,
    });

    serde_json::to_vec(&payload).unwrap_or_else(|_| b"{\"succ\":false}".to_vec())
}

fn preview_text(text: &str, max_chars: usize) -> String {
    let mut preview: String = text.chars().take(max_chars).collect();
    if text.chars().count() > max_chars {
        preview.push_str("...");
    }
    preview.escape_debug().to_string()
}

fn empty_ok() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn items_handler(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let user = match require_query_user(&state, &params).await? {
        Ok(user) => user,
        Err(response) => return Ok(response),
    };

    let scripts = db::get_user_scripts(&state.db, user.id).await?;
    let configs = db::get_user_configs(&state.db, user.id).await?;
    let styles = db::get_user_styles(&state.db, user.id).await?;

    Ok(response_json(
        StatusCode::OK,
        json!({
            "status": "ok",
            "scripts": scripts,
            "configs": configs,
            "styles": styles,
        }),
    ))
}

async fn share_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<ShareReq>,
) -> Result<Response, AppError> {
    let token = req.token.trim();
    let user = match require_user_by_token(&state, token).await? {
        Ok(user) => user,
        Err(response) => return Ok(response),
    };

    let item_id =
        Uuid::parse_str(&req.item_id).map_err(|_| AppError(anyhow::anyhow!("invalid item_id")))?;

    let (item_name, item_exists) = match req.item_type.as_str() {
        "Script" => {
            let scripts = db::get_user_scripts(&state.db, user.id).await?;
            let found = scripts.iter().find(|s| s.id == item_id);
            (
                found.map(|s| s.name.clone()).unwrap_or_default(),
                found.is_some(),
            )
        }
        "Config" => {
            let configs = db::get_user_configs(&state.db, user.id).await?;
            let found = configs.iter().find(|c| c.id == item_id);
            (
                found.map(|c| c.name.clone()).unwrap_or_default(),
                found.is_some(),
            )
        }
        "Style" => {
            let styles = db::get_user_styles(&state.db, user.id).await?;
            let found = styles.iter().find(|s| s.id == item_id);
            (
                found.map(|s| s.name.clone()).unwrap_or_default(),
                found.is_some(),
            )
        }
        _ => {
            return Ok(response_json(
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid item type"}),
            ));
        }
    };

    if !item_exists {
        return Ok(response_json(
            StatusCode::NOT_FOUND,
            json!({"error": "item not found"}),
        ));
    }

    let share =
        db::create_share_code(&state.db, user.id, &req.item_type, item_id, &item_name).await?;
    let share_url = share_url_from_headers(&headers, &share.share_code);
    Ok(response_json(
        StatusCode::CREATED,
        json!({
            "status": "ok",
            "share_code": share.share_code,
            "share_url": share_url,
            "item_type": share.item_type,
            "item_name": share.item_name,
        }),
    ))
}

async fn myshares_handler(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let user = match require_query_user(&state, &params).await? {
        Ok(user) => user,
        Err(response) => return Ok(response),
    };
    let shares = db::list_user_share_codes(&state.db, user.id).await?;
    Ok(response_json(
        StatusCode::OK,
        json!({"status": "ok", "shares": shares}),
    ))
}

async fn unshare_handler(
    State(state): State<AppState>,
    axum::Json(req): axum::Json<UnshareReq>,
) -> Result<Response, AppError> {
    let token = req.token.trim();
    let user = match require_user_by_token(&state, token).await? {
        Ok(user) => user,
        Err(response) => return Ok(response),
    };

    let Some(share) = db::get_share_code(&state.db, &req.share_code).await? else {
        return Ok(response_json(
            StatusCode::NOT_FOUND,
            json!({"error": "share code not found"}),
        ));
    };
    if share.user_id != user.id {
        return Ok(response_json(
            StatusCode::FORBIDDEN,
            json!({"error": "share code does not belong to you"}),
        ));
    }

    db::delete_share_code(&state.db, &req.share_code).await?;
    Ok(response_json(StatusCode::OK, json!({"status": "ok"})))
}

async fn shared_handler(
    State(state): State<AppState>,
    AxumPath(code): AxumPath<String>,
) -> Response {
    match db::get_shared_item(&state.db, &code).await {
        Ok(Some((share, script, style, config))) => match share.item_type.as_str() {
            "Script" => match script {
                Some(s) => response_json(
                    StatusCode::OK,
                    json!({"type": "Script", "name": s.name, "content": s.content, "shared_by": share.user_id}),
                ),
                None => response_json(
                    StatusCode::NOT_FOUND,
                    json!({"error": "script content not found"}),
                ),
            },
            "Config" => match config {
                Some(c) => response_json(
                    StatusCode::OK,
                    json!({"type": "Config", "name": c.name, "content": c.content, "shared_by": share.user_id}),
                ),
                None => response_json(
                    StatusCode::NOT_FOUND,
                    json!({"error": "config content not found"}),
                ),
            },
            "Style" => match style {
                Some(s) => response_json(
                    StatusCode::OK,
                    json!({"type": "Style", "name": s.name, "content": s.content, "shared_by": share.user_id}),
                ),
                None => response_json(
                    StatusCode::NOT_FOUND,
                    json!({"error": "style content not found"}),
                ),
            },
            _ => response_json(
                StatusCode::BAD_REQUEST,
                json!({"error": "unknown item type"}),
            ),
        },
        Ok(None) => response_json(
            StatusCode::NOT_FOUND,
            json!({"error": "share code not found"}),
        ),
        Err(_) => response_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "database error"}),
        ),
    }
}

async fn import_to_account_handler(
    State(state): State<AppState>,
    axum::Json(req): axum::Json<ImportToAccountReq>,
) -> Result<Response, AppError> {
    let token = req.token.trim();
    let user = match require_user_by_token(&state, token).await? {
        Ok(user) => user,
        Err(response) => return Ok(response),
    };

    let (share, script, style, config) = db::get_shared_item(&state.db, &req.share_code)
        .await?
        .ok_or_else(|| AppError(anyhow::anyhow!("share code not found")))?;

    let author_name = db::get_user_by_id(&state.db, share.user_id)
        .await?
        .map(|u| u.username)
        .unwrap_or_else(|| "Unknown".to_string());
    let new_entry_id = db::next_entry_id(&state.db, user.id).await?;
    let now_ts = chrono::Utc::now().timestamp() as i32;

    let imported_name = match share.item_type.as_str() {
        "Script" => {
            let s = script.ok_or_else(|| AppError(anyhow::anyhow!("content missing")))?;
            let name = s.name;
            let content = s.content;
            db::create_script(&state.db, user.id, new_entry_id, &name).await?;
            db::update_script_content(&state.db, user.id, new_entry_id, &content).await?;
            name
        }
        "Config" => {
            let c = config.ok_or_else(|| AppError(anyhow::anyhow!("content missing")))?;
            let name = c.name;
            let content = c.content;
            db::create_config(&state.db, user.id, new_entry_id, &name).await?;
            db::update_config_content(&state.db, user.id, new_entry_id, &content).await?;
            name
        }
        "Style" => {
            let s = style.ok_or_else(|| AppError(anyhow::anyhow!("content missing")))?;
            let name = s.name;
            let content = s.content;
            db::create_style(&state.db, user.id, new_entry_id, &name).await?;
            db::update_style_content(&state.db, user.id, new_entry_id, &content).await?;
            name
        }
        _ => {
            return Ok(response_json(
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid type"}),
            ));
        }
    };

    db::create_log_entry(
        &state.db,
        user.id,
        new_entry_id,
        now_ts,
        &share.item_type,
        &author_name,
    )
    .await?;

    let live_insert_sent = if matches!(share.item_type.as_str(), "Script" | "Config" | "Style") {
        let sent = ws::push_live_insert(
            &state,
            token,
            new_entry_id as u32,
            now_ts as u32,
            &share.item_type,
            &imported_name,
            &author_name,
        )
        .await?;
        tracing::info!(
            "[HTTP] import_to_account live insert entry_id={} type={} sent_to={} sockets",
            new_entry_id,
            share.item_type,
            sent
        );
        sent
    } else {
        tracing::info!(
            "[HTTP] import_to_account skipped live insert for unsupported type={}",
            share.item_type
        );
        0
    };

    Ok(response_json(
        StatusCode::OK,
        json!({"status": "ok", "live_insert_sent": live_insert_sent}),
    ))
}

async fn fallback_handler(State(state): State<AppState>, req: Request) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<binary>").to_owned()))
        .collect();

    tracing::info!(
        "[HTTP] {} {} query={} headers={:?}",
        method,
        path,
        query,
        headers
    );

    // Check for POST with type:4 auth body → per-user serial
    if method == axum::http::Method::POST {
        let body_bytes = match axum::body::to_bytes(req.into_body(), 1024 * 1024).await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("[HTTP] Failed to read POST body: {e}");
                return express_404(method.as_str(), &path);
            }
        };

        // Try as JSON first
        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            tracing::info!("[HTTP] POST JSON ({} bytes): {}", body_bytes.len(), val);
            if val.get("type").and_then(|t| t.as_i64()) == Some(4) {
                let token = val.get("token").and_then(|t| t.as_str()).unwrap_or("");
                let serial = if !token.is_empty() {
                    match db::get_user_by_auth_token(&state.db, token).await {
                        Ok(Some(user)) => user.serial,
                        _ => String::new(),
                    }
                } else {
                    String::new()
                };

                tracing::info!(
                    "[HTTP] -> GetSerial (type=4), returning serial ({} bytes)",
                    serial.len()
                );
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body(Body::from(serial))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
        } else {
            // Not JSON — log raw and try decrypt+decompress
            tracing::info!(
                "[HTTP] POST binary ({} bytes): {}",
                body_bytes.len(),
                hex_preview(&body_bytes, 64)
            );
            try_decrypt_and_log("[HTTP] POST", &body_bytes);
        }
    }

    tracing::warn!("[HTTP] -> 404 (unknown route)");
    express_404(method.as_str(), &path)
}

fn express_404(method: &str, path: &str) -> Response {
    let html = format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n\
         <meta charset=\"utf-8\">\n<title>Error</title>\n\
         </head>\n<body>\n\
         <pre>Cannot {method} {path}</pre>\n\
         </body>\n</html>\n"
    );
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::CONTENT_SECURITY_POLICY, "default-src 'none'")
        .header("x-content-type-options", "nosniff")
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(html))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn default_avatar() -> Response {
    avatar_response(DEFAULT_AVATAR_PNG.to_vec())
}

fn avatar_response(bytes: Vec<u8>) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "image/png")
        .header(
            header::CACHE_CONTROL,
            "no-store, no-cache, must-revalidate, max-age=0",
        )
        .header(header::PRAGMA, "no-cache")
        .header(header::EXPIRES, "0")
        .body(Body::from(bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn response_json(status: StatusCode, value: serde_json::Value) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(value.to_string()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn invalid_credentials() -> Response {
    response_json(
        StatusCode::UNAUTHORIZED,
        json!({"error": "invalid credentials"}),
    )
}

async fn require_query_user(
    state: &AppState,
    params: &HashMap<String, String>,
) -> Result<Result<UserRow, Response>, AppError> {
    let Some(token) = extract_token(params) else {
        return Ok(Err(missing_token_response()));
    };

    require_user_by_token(state, &token).await
}

async fn require_user_by_token(
    state: &AppState,
    token: &str,
) -> Result<Result<UserRow, Response>, AppError> {
    if token.trim().is_empty() {
        return Ok(Err(missing_token_response()));
    }

    match db::get_user_by_auth_token(&state.db, token.trim()).await? {
        Some(user) => Ok(Ok(user)),
        None => Ok(Err(invalid_token_response())),
    }
}

fn missing_token_response() -> Response {
    response_json(StatusCode::UNAUTHORIZED, json!({"error": "missing token"}))
}

fn invalid_token_response() -> Response {
    response_json(StatusCode::UNAUTHORIZED, json!({"error": "invalid token"}))
}

#[derive(Deserialize)]
struct AuthReq {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct AvatarReq {
    token: String,
    image_base64: Option<String>,
}

#[derive(Deserialize)]
struct ShareReq {
    token: String,
    item_type: String,
    item_id: String,
}

#[derive(Deserialize)]
struct UnshareReq {
    token: String,
    share_code: String,
}

#[derive(Deserialize)]
struct ImportToAccountReq {
    token: String,
    share_code: String,
}

fn extract_token(params: &HashMap<String, String>) -> Option<String> {
    params
        .get("token")
        .cloned()
        .or_else(|| params.get("auth_token").cloned())
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
}

pub(crate) fn share_url_from_headers(headers: &HeaderMap, share_code: &str) -> String {
    if let Ok(base_url) =
        std::env::var("PUBLIC_SHARE_BASE_URL").or_else(|_| std::env::var("PUBLIC_BASE_URL"))
    {
        let base_url = base_url.trim().trim_end_matches('/');
        if !base_url.is_empty() {
            return format!("{}/?share={}", base_url, url_encode_component(share_code));
        }
    }

    let host = header_string(headers, "x-forwarded-host")
        .or_else(|| header_string(headers, "host"))
        .unwrap_or_else(|| format!("localhost:{}", config::HTTPS_PORT));
    let proto = header_string(headers, "x-forwarded-proto").unwrap_or_else(|| {
        if host.ends_with(&format!(":{}", config::HTTP_PORT)) {
            "http".to_string()
        } else {
            "https".to_string()
        }
    });

    format!(
        "{}://{}/?share={}",
        proto,
        website_host(&host),
        url_encode_component(share_code)
    )
}

fn header_string(headers: &HeaderMap, name: &'static str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn website_host(host: &str) -> String {
    let ws_port = format!(":{}", config::WS_PORT);
    if let Some(base) = host.strip_suffix(&ws_port) {
        format!("{}:{}", base, config::HTTPS_PORT)
    } else {
        host.to_string()
    }
}

fn url_encode_component(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

fn normalize_username(username: &str) -> Result<String, AppError> {
    let username = username.trim();
    if username.len() < 3 || username.len() > 32 {
        return Err(AppError(anyhow::anyhow!(
            "username must be between 3 and 32 characters"
        )));
    }
    if !username
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return Err(AppError(anyhow::anyhow!(
            "username can only contain letters, numbers, '_' or '-'"
        )));
    }
    Ok(username.to_string())
}

fn validate_password(password: &str) -> Result<(), AppError> {
    if password.len() < 8 {
        return Err(AppError(anyhow::anyhow!(
            "password must be at least 8 characters"
        )));
    }
    Ok(())
}

fn hash_password(password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| AppError(anyhow::anyhow!("failed to hash password: {e}")))
}

fn verify_password(password_hash: &str, password: &str) -> Result<bool, AppError> {
    let parsed_hash = PasswordHash::new(password_hash)
        .map_err(|_| AppError(anyhow::anyhow!("invalid stored password hash")))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

fn decode_avatar_png(image_base64: &str) -> Result<Vec<u8>, AppError> {
    let payload = image_base64
        .split_once(',')
        .map(|(_, data)| data)
        .unwrap_or(image_base64);
    let bytes = STANDARD
        .decode(payload)
        .map_err(|_| AppError(anyhow::anyhow!("invalid image data")))?;
    const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if !bytes.starts_with(PNG_SIGNATURE) {
        return Err(AppError(anyhow::anyhow!("avatar must be a png image")));
    }
    if bytes.len() > 1_500_000 {
        return Err(AppError(anyhow::anyhow!("avatar is too large")));
    }
    Ok(bytes)
}

// ── Decryption helpers ──

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

fn try_decrypt_and_log(prefix: &str, data: &[u8]) {
    use nl_parser::module::Module;
    use nl_parser::pipeline;

    // Try AES decrypt only
    match pipeline::decrypt(data) {
        Ok(decrypted) => {
            tracing::info!(
                "{} decrypted ({} bytes): {}",
                prefix,
                decrypted.len(),
                hex_preview(&decrypted, 64)
            );
            // Try LZ4 decompress
            match pipeline::decompress(&decrypted) {
                Ok(decompressed) => {
                    tracing::info!("{} decompressed ({} bytes)", prefix, decompressed.len());
                    // Try as UTF-8 text
                    if let Ok(text) = std::str::from_utf8(&decompressed) {
                        let preview = if text.len() > 1000 {
                            format!("{}...", &text[..1000])
                        } else {
                            text.to_string()
                        };
                        tracing::info!("{} plaintext: {}", prefix, preview);
                    }
                    // Try as FlatBuffer module
                    match Module::from_flatbuffer(&decompressed) {
                        Ok(module) => {
                            tracing::info!(
                                "{} parsed as Module: version={} author={} token={} checksum={} enabled={} config_log={} script_log={} languages={}",
                                prefix,
                                module.version,
                                module.author,
                                module.auth_token,
                                module.checksum,
                                module.enabled,
                                module.config_log.len(),
                                module.script_log.len(),
                                module.languages.len(),
                            );
                        }
                        Err(_) => {
                            tracing::debug!(
                                "{} not a valid Module FlatBuffer, raw hex: {}",
                                prefix,
                                hex_preview(&decompressed, 128)
                            );
                        }
                    }
                }
                Err(_) => {
                    // Not LZ4 — just show decrypted as text or hex
                    if let Ok(text) = std::str::from_utf8(&decrypted) {
                        let preview = if text.len() > 1000 {
                            format!("{}...", &text[..1000])
                        } else {
                            text.to_string()
                        };
                        tracing::info!("{} decrypted text: {}", prefix, preview);
                    }
                }
            }
        }
        Err(_) => {
            tracing::debug!("{} not AES-encrypted (decrypt failed)", prefix);
        }
    }
}

// ── Admin endpoints ──

async fn admin_seed(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    use nl_parser::module::Module;
    use nl_parser::pipeline;

    tracing::info!("[HTTP] POST /admin/seed — parsing SEED_MODULE_BIN");

    let flat = pipeline::load_module(SEED_MODULE_BIN)?;
    let module = Module::from_flatbuffer(&flat)?;

    // Extract raw skin_data bytes directly from FlatBuffer (no struct round-trip)
    let skin_data_msgpack = Module::extract_raw_skin_data(&flat)?;
    let languages_json = serde_json::to_value(&module.languages)?;

    let base = db::insert_base_module(
        &state.db,
        "default",
        module.version as i32,
        &module.author,
        module.checksum as i64,
        module.buffer_capacity as i64,
        module.enabled as i32,
        &skin_data_msgpack,
        &languages_json,
    )
    .await?;

    // Create default user from the module's author + hardcoded default token
    let user = db::create_user(
        &state.db,
        &module.author,
        config::DEFAULT_USER_TOKEN,
        base.id,
        DEFAULT_SERIAL,
    )
    .await?;

    // Seed that user's log entries from the module
    for (entry_type, entries) in [
        ("Config", &module.config_log),
        ("Script", &module.script_log),
    ] {
        for entry in entries {
            db::create_log_entry(
                &state.db,
                user.id,
                entry.entry_id as i32,
                entry.timestamp as i32,
                entry_type,
                &entry.author,
            )
            .await?;

            match entry_type {
                "Config" => {
                    let _ =
                        db::create_config(&state.db, user.id, entry.entry_id as i32, &entry.name)
                            .await;
                }
                "Script" => {
                    let _ =
                        db::create_script(&state.db, user.id, entry.entry_id as i32, &entry.name)
                            .await;
                }
                _ => {}
            }
        }
    }

    tracing::info!(
        "[HTTP] -> Seed complete, base_module id={}, user id={} ({})",
        base.id,
        user.id,
        user.username
    );
    Ok(axum::Json(json!({
        "status": "ok",
        "base_module_id": base.id,
        "user_id": user.id,
        "username": user.username,
        "auth_token": user.auth_token,
        "version": base.version,
    })))
}

#[derive(Deserialize)]
struct CreateUserReq {
    username: String,
    auth_token: String,
    base_module_id: Uuid,
    #[serde(default)]
    serial: String,
}

async fn admin_create_user(
    State(state): State<AppState>,
    axum::Json(req): axum::Json<CreateUserReq>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("[HTTP] POST /admin/users username={}", req.username);
    let user = db::create_user(
        &state.db,
        &req.username,
        &req.auth_token,
        req.base_module_id,
        &req.serial,
    )
    .await?;
    Ok((StatusCode::CREATED, axum::Json(json!(user))))
}

async fn admin_list_users(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    tracing::info!("[HTTP] GET /admin/users");
    let users = db::list_users(&state.db).await?;
    Ok(axum::Json(json!(users)))
}

async fn admin_get_logs(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("[HTTP] GET /admin/users/{}/logs", id);
    let logs = db::get_user_log_entries(&state.db, id).await?;
    Ok(axum::Json(json!(logs)))
}

#[derive(Deserialize)]
struct CreateLogReq {
    entry_id: i32,
    timestamp: i32,
    entry_type: String,
    author: String,
}

async fn admin_create_log(
    State(state): State<AppState>,
    AxumPath(user_id): AxumPath<Uuid>,
    axum::Json(req): axum::Json<CreateLogReq>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("[HTTP] POST /admin/users/{}/logs", user_id);
    let entry = db::create_log_entry(
        &state.db,
        user_id,
        req.entry_id,
        req.timestamp,
        &req.entry_type,
        &req.author,
    )
    .await?;
    Ok((StatusCode::CREATED, axum::Json(json!(entry))))
}

#[derive(Deserialize)]
struct UpdateLogReq {
    entry_id: i32,
    timestamp: i32,
    entry_type: String,
    author: String,
}

async fn admin_update_log(
    State(state): State<AppState>,
    AxumPath((user_id, log_id)): AxumPath<(Uuid, Uuid)>,
    axum::Json(req): axum::Json<UpdateLogReq>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("[HTTP] PUT /admin/users/{}/logs/{}", user_id, log_id);
    let entry = db::update_log_entry(
        &state.db,
        log_id,
        req.entry_id,
        req.timestamp,
        &req.entry_type,
        &req.author,
    )
    .await?;
    match entry {
        Some(e) => Ok(axum::Json(json!(e)).into_response()),
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

async fn admin_delete_log(
    State(state): State<AppState>,
    AxumPath((user_id, log_id)): AxumPath<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("[HTTP] DELETE /admin/users/{}/logs/{}", user_id, log_id);
    let deleted = db::delete_log_entry(&state.db, log_id).await?;
    if deleted {
        Ok(axum::Json(json!({"status": "deleted"})).into_response())
    } else {
        Ok(StatusCode::NOT_FOUND.into_response())
    }
}
