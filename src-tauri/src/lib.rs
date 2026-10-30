pub mod model;
pub mod pii;
mod platform;
pub mod proxy;
mod store;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{RwLock, mpsc, oneshot};

use crate::model::{ActivityDraft, ActivityEvent, normalize_host};
use crate::pii::{PiiType, Rules, TypeRule};

struct ProxyControl {
    shutdown: Option<oneshot::Sender<()>>,
    port: u16,
}

pub struct AppState {
    db: Mutex<rusqlite::Connection>,
    rules: Arc<RwLock<Rules>>,
    bypass: Arc<RwLock<HashSet<String>>>,
    events_tx: mpsc::UnboundedSender<ActivityDraft>,
    proxy: Mutex<Option<ProxyControl>>,
    data_dir: PathBuf,
    notice: Mutex<Option<String>>,
    cert_trusted: Mutex<bool>,
    proxy_installed: Mutex<bool>,
    pending_restore: Mutex<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    protection_on: bool,
    cert_trusted: bool,
    proxy_installed: bool,
    port: Option<u16>,
    notice: Option<String>,
    pending_restore: bool,
    rules: Rules,
    bypass_hosts: Vec<String>,
    events: Vec<ActivityEvent>,
}

#[tauri::command]
fn snapshot(state: State<'_, AppState>) -> Snapshot {
    build_snapshot(&state)
}

#[tauri::command]
async fn set_protection(app: AppHandle, on: bool) -> Result<Snapshot, String> {
    if on {
        enable(&app).await?;
    } else {
        disable(&app);
    }
    Ok(build_snapshot(app.state::<AppState>().inner()))
}

#[tauri::command]
async fn set_rule(
    state: State<'_, AppState>,
    pii_type: String,
    mask: bool,
    alert: bool,
) -> Result<Snapshot, String> {
    let kind = PiiType::parse(&pii_type).ok_or_else(|| format!("Unknown PII type: {pii_type}"))?;
    let rule = TypeRule { mask, alert };
    {
        let db = lock_db(&state);
        store::save_rule(&db, kind, rule)?;
    }
    state.rules.write().await.set(kind, rule);
    Ok(build_snapshot(&state))
}

#[tauri::command]
async fn add_bypass(state: State<'_, AppState>, host: String) -> Result<Snapshot, String> {
    let host = normalize_host(&host)
        .ok_or_else(|| "Enter an exact host, such as api.example.com.".to_string())?;
    {
        let db = lock_db(&state);
        store::add_bypass(&db, &host)?;
    }
    state.bypass.write().await.insert(host);
    Ok(build_snapshot(&state))
}

#[tauri::command]
async fn remove_bypass(state: State<'_, AppState>, host: String) -> Result<Snapshot, String> {
    let host = normalize_host(&host).unwrap_or(host);
    {
        let db = lock_db(&state);
        store::remove_bypass(&db, &host)?;
    }
    state.bypass.write().await.remove(&host);
    Ok(build_snapshot(&state))
}

#[tauri::command]
fn mark_seen(state: State<'_, AppState>, id: String) -> Result<Snapshot, String> {
    let db = lock_db(&state);
    store::mark_seen(&db, &id)?;
    Ok(build_snapshot(&state))
}

#[tauri::command]
fn mark_all_seen(state: State<'_, AppState>) -> Result<Snapshot, String> {
    let db = lock_db(&state);
    store::mark_all_seen(&db)?;
    Ok(build_snapshot(&state))
}

#[tauri::command]
fn restore_network(state: State<'_, AppState>) -> Result<Snapshot, String> {
    let saved = {
        let db = lock_db(&state);
        store::load_session(&db)?
    };
    let Some(saved) = saved else {
        *state
            .pending_restore
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = false;
        return Ok(build_snapshot(&state));
    };
    platform::restore_proxy(&saved)?;
    let db = lock_db(&state);
    store::save_session(&db, &None)?;
    drop(db);
    *state
        .proxy_installed
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = false;
    *state
        .pending_restore
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = false;
    *state
        .notice
        .lock()
        .unwrap_or_else(|error| error.into_inner()) =
        Some("Network proxy settings were restored.".to_string());
    Ok(build_snapshot(&state))
}

fn enable(app: &AppHandle) -> impl std::future::Future<Output = Result<(), String>> + Send {
    let app = app.clone();
    async move {
        let state = app.state::<AppState>();
        let ca_dir = state.data_dir.join("ca");
        let paths = tauri::async_runtime::spawn_blocking(move || proxy::ensure_ca(&ca_dir))
            .await
            .map_err(|error| error.to_string())??;
        let cert = paths.cert.clone();
        tauri::async_runtime::spawn_blocking(move || platform::ensure_trusted(&cert))
            .await
            .map_err(|error| error.to_string())??;
        *state
            .cert_trusted
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = true;

        if state
            .proxy
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .is_some()
        {
            return Ok(());
        }
        let running = proxy::start_proxy(
            state.rules.clone(),
            state.bypass.clone(),
            state.events_tx.clone(),
            &state.data_dir.join("ca"),
        )
        .await?;
        let port = running.port;
        let saved =
            match tauri::async_runtime::spawn_blocking(move || platform::install_proxy(port))
                .await
                .map_err(|error| error.to_string())?
            {
                Ok(saved) => saved,
                Err(error) => {
                    let _ = running.shutdown.send(());
                    return Err(error);
                }
            };
        {
            let db = lock_db(&state);
            store::save_session(&db, &Some(saved))?;
        }
        *state
            .proxy
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(ProxyControl {
            shutdown: Some(running.shutdown),
            port,
        });
        *state
            .proxy_installed
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = true;
        *state
            .pending_restore
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = false;
        *state
            .notice
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = None;
        Ok(())
    }
}

fn disable(app: &AppHandle) {
    let state = app.state::<AppState>();
    if let Some(mut control) = state
        .proxy
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take()
        && let Some(shutdown) = control.shutdown.take()
    {
        let _ = shutdown.send(());
    }
    let saved = {
        let db = lock_db(&state);
        store::load_session(&db).ok().flatten()
    };
    if let Some(saved) = saved {
        match platform::restore_proxy(&saved) {
            Ok(()) => {
                let db = lock_db(&state);
                let _ = store::save_session(&db, &None);
                *state
                    .proxy_installed
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = false;
                *state
                    .pending_restore
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = false;
            }
            Err(error) => {
                *state
                    .pending_restore
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = true;
                *state
                    .notice
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = Some(format!(
                    "Protection stopped, but the system proxy could not be restored: {error}"
                ));
            }
        }
    } else {
        *state
            .proxy_installed
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = false;
    }
}

fn build_snapshot(state: &AppState) -> Snapshot {
    let db = lock_db(state);
    let rules = store::load_rules(&db).unwrap_or_default();
    let bypass_hosts = store::load_bypass(&db).unwrap_or_default();
    let events = store::list_events(&db).unwrap_or_default();
    drop(db);
    let protection_on = state
        .proxy
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .is_some();
    let port = state
        .proxy
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_ref()
        .map(|control| control.port);
    Snapshot {
        protection_on,
        cert_trusted: *state
            .cert_trusted
            .lock()
            .unwrap_or_else(|error| error.into_inner()),
        proxy_installed: *state
            .proxy_installed
            .lock()
            .unwrap_or_else(|error| error.into_inner()),
        port,
        notice: state
            .notice
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone(),
        pending_restore: *state
            .pending_restore
            .lock()
            .unwrap_or_else(|error| error.into_inner()),
        rules,
        bypass_hosts,
        events,
    }
}

fn box_err(message: String) -> Box<dyn std::error::Error> {
    message.into()
}

fn lock_db(state: &AppState) -> std::sync::MutexGuard<'_, rusqlite::Connection> {
    state.db.lock().unwrap_or_else(|error| error.into_inner())
}

fn recover_stale_proxy(state: &AppState) {
    let saved = {
        let db = lock_db(state);
        match store::load_session(&db) {
            Ok(saved) => saved,
            Err(error) => {
                *state.notice.lock().unwrap_or_else(|err| err.into_inner()) = Some(error);
                return;
            }
        }
    };
    let Some(saved) = saved else {
        return;
    };
    match platform::restore_proxy(&saved) {
        Ok(()) => {
            let db = lock_db(state);
            let _ = store::save_session(&db, &None);
            *state.notice.lock().unwrap_or_else(|error| error.into_inner()) = Some(
                "Protection was still on after the last exit. Network proxy settings were restored."
                    .to_string(),
            );
        }
        Err(error) => {
            *state
                .pending_restore
                .lock()
                .unwrap_or_else(|err| err.into_inner()) = true;
            *state.notice.lock().unwrap_or_else(|err| err.into_inner()) = Some(format!(
                "Protection was still on after the last exit, and the system proxy could not be restored: {error}"
            ));
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    tauri::Builder::default()
        .manage(events_tx)
        .setup(move |app| {
            let events_tx = app
                .state::<mpsc::UnboundedSender<ActivityDraft>>()
                .inner()
                .clone();
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            let db_path = dir.join("sniffer.sqlite");
            let connection = store::open(&db_path).map_err(box_err)?;
            let rules = store::load_rules(&connection).map_err(box_err)?;
            let bypass_list = store::load_bypass(&connection).map_err(box_err)?;
            let cert = dir.join("ca").join("ca.cert.pem");
            let cert_trusted = cert.exists() && platform::cert_is_trusted(&cert);
            let state = AppState {
                db: Mutex::new(connection),
                rules: Arc::new(RwLock::new(rules)),
                bypass: Arc::new(RwLock::new(bypass_list.into_iter().collect())),
                events_tx,
                proxy: Mutex::new(None),
                data_dir: dir,
                notice: Mutex::new(None),
                cert_trusted: Mutex::new(cert_trusted),
                proxy_installed: Mutex::new(false),
                pending_restore: Mutex::new(false),
            };
            recover_stale_proxy(&state);
            app.manage(state);
            let handle = app.handle().clone();
            let mut events_rx: mpsc::UnboundedReceiver<ActivityDraft> = events_rx;
            tauri::async_runtime::spawn(async move {
                while let Some(draft) = events_rx.recv().await {
                    if draft.alert {
                        platform::beep();
                    }
                    let inserted = {
                        let state = handle.state::<AppState>();
                        let db = lock_db(&state);
                        store::insert_event(&db, &draft)
                    };
                    if let Ok(event) = inserted {
                        let _ = handle.emit("activity", &event);
                    }
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            snapshot,
            set_protection,
            set_rule,
            add_bypass,
            remove_bypass,
            mark_seen,
            mark_all_seen,
            restore_network
        ])
        .build(tauri::generate_context!())
        .expect("error while building PII Sniffer")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event
                && app.try_state::<AppState>().is_some()
            {
                disable(app);
            }
        });
}
