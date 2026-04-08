//! Game-mode detection: pauses scanning while a known game is running.

use std::collections::HashSet;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info};

use crate::watcher::SharedEngine;

/// Detector that watches for running game processes and notifies subscribers.
pub struct GameModeDetector;

impl GameModeDetector {
    /// Start the game-mode detector. The returned receiver yields `true` when
    /// a game starts and `false` when no games are running.
    pub fn start(
        engine: SharedEngine,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> (JoinHandle<()>, mpsc::Receiver<bool>) {
        let (tx, rx) = mpsc::channel::<bool>(16);

        let handle = tokio::spawn(async move {
            info!("game mode detector starting");
            let check_interval = Duration::from_secs(15);
            let mut in_game_mode = false;

            loop {
                tokio::select! {
                    _ = shutdown.recv() => {
                        info!("game mode detector shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(check_interval) => {
                        let game_set: HashSet<String> = {
                            let guard = engine.lock().unwrap();
                            guard
                                .database
                                .game_db
                                .list_all()
                                .iter()
                                .map(|g| g.executable_name.to_lowercase())
                                .collect()
                        };
                        let running = current_process_names().await;
                        let game_running = running
                            .iter()
                            .any(|name| game_set.contains(&name.to_lowercase()));

                        if game_running != in_game_mode {
                            in_game_mode = game_running;
                            if in_game_mode {
                                info!("game detected - entering game mode");
                            } else {
                                info!("no games running - leaving game mode");
                            }
                            let _ = tx.send(in_game_mode).await;
                        } else {
                            debug!(in_game_mode, "game mode unchanged");
                        }
                    }
                }
            }
        });

        (handle, rx)
    }
}

#[cfg(target_os = "linux")]
async fn current_process_names() -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.filter_map(|e| e.ok()) {
            let fname = entry.file_name();
            let fname = fname.to_string_lossy();
            if !fname.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            if let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) {
                names.push(comm.trim().to_string());
            }
        }
    }
    names
}

#[cfg(not(target_os = "linux"))]
async fn current_process_names() -> Vec<String> {
    Vec::new()
}
