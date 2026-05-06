mod client_msg;
mod config;
mod data;
mod db;
mod error;
mod http;
mod models;
mod module_builder;
mod tls;
mod ws;

use anyhow::Context;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{RwLock, mpsc};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[cfg(windows)]
fn hide_console_window() {
    use windows_sys::Win32::Foundation::GetConsoleWindow;
    use windows_sys::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE};

    unsafe {
        let window = GetConsoleWindow();
        if window != 0 {
            ShowWindow(window, SW_HIDE);
        }
    }
}

#[cfg(not(windows))]
fn hide_console_window() {}

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub raw_module: Option<Vec<u8>>,
    pub ip_tokens: Arc<RwLock<HashMap<IpAddr, String>>>,
    pub live_replies: Arc<RwLock<HashMap<String, HashMap<Uuid, mpsc::UnboundedSender<Vec<u8>>>>>>,
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    // Hide console window on Windows
    hide_console_window();

    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_env_filter(EnvFilter::new("debug"))
        .init();

    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| config::DEFAULT_DATABASE_URL.to_string());

    let db = SqlitePool::connect(&database_url)
        .await
        .expect("failed to connect to SQLite");

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .expect("failed to run database migrations");

    tracing::info!("Database connected and migrations applied");

    // Seed default "astolfo" user if no users exist
    seed_default_user(&db).await.expect("failed to seed default user");

    let raw_module = load_raw_module_arg().expect("failed to load raw module override");

    let state = AppState {
        db,
        raw_module,
        ip_tokens: Arc::new(RwLock::new(HashMap::new())),
        live_replies: Arc::new(RwLock::new(HashMap::new())),
    };

    let http_addr = SocketAddr::from(([0, 0, 0, 0], config::HTTP_PORT));
    let https_addr = SocketAddr::from(([0, 0, 0, 0], config::HTTPS_PORT));
    let ws_addr = SocketAddr::from(([0, 0, 0, 0], config::WS_PORT));

    let ws_tls = std::env::var("WS_TLS").unwrap_or_else(|_| "true".to_string());
    let ws_tls_enabled = ws_tls != "false";

    let cert_path = std::env::var("TLS_CERT").unwrap_or_else(|_| config::TLS_CERT_PATH.to_string());
    let key_path = std::env::var("TLS_KEY").unwrap_or_else(|_| config::TLS_KEY_PATH.to_string());

    let http_listener = TcpListener::bind(http_addr)
        .await
        .expect("failed to bind HTTP port");

    tracing::info!("HTTP server on http://{http_addr}");

    let http_server = axum::serve(
        http_listener,
        http::router(state.clone()).into_make_service_with_connect_info::<SocketAddr>(),
    );

    if ws_tls_enabled {
        tls::ensure_self_signed_certs(&cert_path, &key_path)
            .expect("failed to ensure TLS certificates");

        let rustls_config = tls::load_rustls_config(&cert_path, &key_path)
            .await
            .expect("failed to load TLS config");

        tracing::info!("HTTPS server on https://{https_addr}");
        tracing::info!("WS server on wss://{ws_addr}");

        let https_server = axum_server::bind_rustls(https_addr, rustls_config.clone())
            .serve(http::router(state.clone()).into_make_service_with_connect_info::<SocketAddr>());

        let ws_server = axum_server::bind_rustls(ws_addr, rustls_config)
            .serve(ws::router(state).into_make_service_with_connect_info::<SocketAddr>());

        tokio::select! {
            r = http_server => {
                if let Err(e) = r { tracing::error!("HTTP server error: {e}"); }
            }
            r = https_server => {
                if let Err(e) = r { tracing::error!("HTTPS server error: {e}"); }
            }
            r = ws_server => {
                if let Err(e) = r { tracing::error!("WSS server error: {e}"); }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Shutting down");
            }
        }
    } else {
        let ws_listener = TcpListener::bind(ws_addr)
            .await
            .expect("failed to bind WS port");

        tracing::info!("WS server on ws://{ws_addr}");

        let ws_server = axum::serve(
            ws_listener,
            ws::router(state).into_make_service_with_connect_info::<SocketAddr>(),
        );

        tokio::select! {
            r = http_server => {
                if let Err(e) = r { tracing::error!("HTTP server error: {e}"); }
            }
            r = ws_server => {
                if let Err(e) = r { tracing::error!("WS server error: {e}"); }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Shutting down");
            }
        }
    }
}

async fn seed_default_user(db: &SqlitePool) -> anyhow::Result<()> {
    // Check if any users exist
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(db)
        .await
        .context("failed to count users")?;

    if user_count > 0 {
        tracing::info!("Users exist in database, skipping default user creation");
        return Ok(());
    }

    tracing::info!("No users found, attempting to seed default 'astolfo' user");

    // Try to load and parse the seed module
    let flat = match nl_parser::pipeline::load_module(data::SEED_MODULE_BIN) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!("Failed to load seed module (flatbuffers parsing failed): {e}");
            tracing::warn!("Skipping user seeding - server will start without default user");
            return Ok(());
        }
    };

    let module = match nl_parser::module::Module::from_flatbuffer(&flat) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("Failed to parse seed module: {e}");
            tracing::warn!("Skipping user seeding - server will start without default user");
            return Ok(());
        }
    };

    let skin_data_msgpack = match nl_parser::module::Module::extract_raw_skin_data(&flat) {
        Ok(data) => data,
        Err(e) => {
            tracing::warn!("Failed to extract skin data: {e}");
            tracing::warn!("Skipping user seeding - server will start without default user");
            return Ok(());
        }
    };

    let languages_json = serde_json::to_value(&module.languages)?;
    let base_module = db::insert_base_module(
        db,
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
    .context("failed to insert base module")?;

    // Create "astolfo" user with the hardcoded token
    let user = db::create_user(
        db,
        config::DEFAULT_USERNAME,
        config::DEFAULT_USER_TOKEN,
        base_module.id,
        config::DEFAULT_SERIAL,
    )
    .await
    .context("failed to create astolfo user")?;

    tracing::info!(
        "Created default user: id={}, username={}, auth_token={}",
        user.id,
        user.username,
        user.auth_token
    );

    // Seed log entries from the module
    for (entry_type, entries) in [
        ("Config", &module.config_log),
        ("Script", &module.script_log),
    ] {
        for entry in entries {
            let _ = db::create_log_entry(
                db,
                user.id,
                entry.entry_id as i32,
                entry.timestamp as i32,
                entry_type,
                &entry.author,
            )
            .await;

            match entry_type {
                "Config" => {
                    let _ = db::create_config(db, user.id, entry.entry_id as i32, &entry.name).await;
                }
                "Script" => {
                    let _ = db::create_script(db, user.id, entry.entry_id as i32, &entry.name).await;
                }
                _ => {}
            }
        }
    }

    tracing::info!(
        "Seeded {} config entries and {} script entries for user {}",
        module.config_log.len(),
        module.script_log.len(),
        user.username
    );

    Ok(())
}

fn arg_value(args: &[String], flag: &str) -> anyhow::Result<Option<String>> {
    let Some(index) = args.iter().position(|arg| arg == flag) else {
        return Ok(None);
    };

    args.get(index + 1)
        .cloned()
        .map(Some)
        .ok_or_else(|| anyhow::anyhow!("{flag} requires a path"))
}

fn read_file(path: impl AsRef<Path>, label: &str) -> anyhow::Result<Vec<u8>> {
    let path = path.as_ref();
    std::fs::read(path).with_context(|| format!("failed to read {label} {}", path.display()))
}

fn load_raw_module_arg() -> anyhow::Result<Option<Vec<u8>>> {
    let args: Vec<String> = std::env::args().collect();

    if let Some(path) = arg_value(&args, "--raw-module")? {
        let data = read_file(&path, "raw module")?;
        tracing::info!(
            "Raw module override (encrypted): {} ({} bytes)",
            path,
            data.len()
        );
        return Ok(Some(data));
    }

    if let Some(path) = arg_value(&args, "--raw-decrypted-module")? {
        let data = read_file(&path, "decrypted module")?;
        tracing::info!(
            "Raw module override (decrypted flatbuffer): {} ({} bytes), compressing+encrypting...",
            path,
            data.len()
        );
        let encrypted =
            nl_parser::pipeline::save_module(&data).context("failed to compress+encrypt module")?;
        tracing::info!("Encrypted module: {} bytes", encrypted.len());
        return Ok(Some(encrypted));
    }

    if let Some(path) = arg_value(&args, "--reencrypt-module")? {
        let data = read_file(&path, "module")?;
        tracing::info!(
            "Re-encrypt module: {} ({} bytes), decrypting+decompressing...",
            path,
            data.len()
        );
        let decompressed = nl_parser::pipeline::load_module(&data)
            .context("failed to decrypt+decompress module")?;
        tracing::info!(
            "Decompressed flatbuffer: {} bytes, re-compressing+encrypting...",
            decompressed.len()
        );
        let encrypted = nl_parser::pipeline::save_module(&decompressed)
            .context("failed to compress+encrypt module")?;
        tracing::info!("Re-encrypted module: {} bytes", encrypted.len());
        return Ok(Some(encrypted));
    }

    Ok(None)
}