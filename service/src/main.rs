//! AntiCheat real-time protection service.

mod clipboard_monitor;
mod game_mode;
mod ipc;
mod network_monitor;
mod notifications;
mod process_monitor;
mod scheduler;
mod watcher;

use std::sync::{Arc, Mutex};

use anyhow::Result;
use tokio::sync::broadcast;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use anticheat_engine::{AntiCheatEngine, EngineConfig};

use crate::clipboard_monitor::ClipboardMonitor;
use crate::game_mode::GameModeDetector;
use crate::network_monitor::NetworkMonitor;
use crate::process_monitor::ProcessMonitor;
use crate::scheduler::{ScanScheduler, ScheduleConfig};
use crate::watcher::{FileWatcher, WatchConfig};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    info!("AntiCheat service starting");

    let engine = Arc::new(Mutex::new(AntiCheatEngine::init(EngineConfig::default())?));
    let (shutdown_tx, _) = broadcast::channel::<()>(16);

    // Spawn all background components.
    let (file_handle, pause_tx) =
        FileWatcher::start(WatchConfig::default(), Arc::clone(&engine), shutdown_tx.subscribe());
    let process_handle = ProcessMonitor::start(Arc::clone(&engine), shutdown_tx.subscribe());
    let network_handle = NetworkMonitor::start(shutdown_tx.subscribe());
    let clipboard_handle = ClipboardMonitor::start(shutdown_tx.subscribe());
    let scheduler_handle =
        ScanScheduler::start(ScheduleConfig::default(), Arc::clone(&engine), shutdown_tx.subscribe());
    let (game_handle, mut game_rx) =
        GameModeDetector::start(Arc::clone(&engine), shutdown_tx.subscribe());
    let ipc_handle = ipc::start(
        ipc::default_socket_path(),
        Arc::clone(&engine),
        shutdown_tx.subscribe(),
    );

    // React to game-mode changes by pausing or resuming the file watcher.
    let pause_tx_clone = pause_tx.clone();
    let game_task = tokio::spawn(async move {
        while let Some(in_game) = game_rx.recv().await {
            if pause_tx_clone.send(in_game).await.is_err() {
                break;
            }
        }
    });

    // Wait for Ctrl-C
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(e) = result {
                warn!(error = %e, "failed to listen for ctrl-c");
            }
            info!("ctrl-c received, shutting down");
        }
    }

    // Broadcast shutdown to all background tasks.
    let _ = shutdown_tx.send(());

    // Wait for tasks to finish.
    let _ = file_handle.await;
    let _ = process_handle.await;
    let _ = network_handle.await;
    let _ = clipboard_handle.await;
    let _ = scheduler_handle.await;
    let _ = game_handle.await;
    let _ = ipc_handle.await;
    game_task.abort();

    info!("AntiCheat service stopped");
    Ok(())
}
