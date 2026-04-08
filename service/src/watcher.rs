use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use anticheat_engine::AntiCheatEngine;

use crate::notifications::Notifier;

/// Shared, lock-protected reference to the engine. The rusqlite connections
/// inside `AntiCheatEngine` are not `Sync`, so we serialize all access through
/// a `Mutex` instead.
pub type SharedEngine = Arc<Mutex<AntiCheatEngine>>;

/// Configuration for the file system watcher.
#[derive(Debug, Clone)]
pub struct WatchConfig {
    /// Directories to watch for file changes.
    pub watched_paths: Vec<PathBuf>,
    /// File extensions to scan (without the leading dot).
    pub scan_extensions: Vec<String>,
}

impl Default for WatchConfig {
    fn default() -> Self {
        let mut watched_paths = Vec::new();

        // Platform-specific default watched directories
        if cfg!(windows) {
            if let Ok(userprofile) = std::env::var("USERPROFILE") {
                let base = PathBuf::from(&userprofile);
                watched_paths.push(base.join("Downloads"));
                watched_paths.push(base.join("Desktop"));
                watched_paths.push(base.join("AppData").join("Local").join("Temp"));
            }
            if let Ok(temp) = std::env::var("TEMP") {
                let temp_path = PathBuf::from(&temp);
                if !watched_paths.contains(&temp_path) {
                    watched_paths.push(temp_path);
                }
            }
        } else {
            if let Ok(home) = std::env::var("HOME") {
                let base = PathBuf::from(&home);
                watched_paths.push(base.join("Downloads"));
                watched_paths.push(base.join("Desktop"));
            }
            watched_paths.push(PathBuf::from("/tmp"));
        }

        Self {
            watched_paths,
            scan_extensions: vec![
                "exe", "dll", "sys", "bat", "cmd", "ps1", "zip", "rar", "7z", "lua", "msi", "scr",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        }
    }
}

/// File system watcher that auto-scans new or modified files.
pub struct FileWatcher;

impl FileWatcher {
    /// Start the file watcher in a background task.
    ///
    /// Returns a `JoinHandle` and a channel sender that can be used to pause/resume the watcher.
    pub fn start(
        config: WatchConfig,
        engine: SharedEngine,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> (JoinHandle<()>, mpsc::Sender<bool>) {
        let (pause_tx, mut pause_rx) = mpsc::channel::<bool>(16);

        let handle = tokio::spawn(async move {
            info!("file watcher starting");

            let (tx, mut rx) = mpsc::channel::<Event>(256);

            // Set up the notify watcher
            let watcher_result: Result<RecommendedWatcher, _> =
                notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
                    if let Ok(event) = res {
                        let _ = tx.blocking_send(event);
                    }
                });

            let mut watcher = match watcher_result {
                Ok(w) => w,
                Err(e) => {
                    error!(error = %e, "failed to create file watcher");
                    return;
                }
            };

            // Watch configured directories
            for path in &config.watched_paths {
                if path.exists() {
                    match watcher.watch(path, RecursiveMode::Recursive) {
                        Ok(()) => info!(path = %path.display(), "watching directory"),
                        Err(e) => warn!(path = %path.display(), error = %e, "failed to watch directory"),
                    }
                } else {
                    debug!(path = %path.display(), "watch path does not exist, skipping");
                }
            }

            let mut paused = false;
            let debounce_duration = Duration::from_millis(500);
            let mut pending_scans: HashMap<PathBuf, Instant> = HashMap::new();

            loop {
                tokio::select! {
                    _ = shutdown.recv() => {
                        info!("file watcher shutting down");
                        break;
                    }
                    Some(should_pause) = pause_rx.recv() => {
                        paused = should_pause;
                        if paused {
                            info!("file watcher paused (game mode)");
                        } else {
                            info!("file watcher resumed");
                        }
                    }
                    Some(event) = rx.recv() => {
                        if paused {
                            continue;
                        }

                        match event.kind {
                            EventKind::Create(_) | EventKind::Modify(_) => {
                                for path in event.paths {
                                    if should_scan_file(&path, &config.scan_extensions) {
                                        pending_scans.insert(path, Instant::now());
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(250)) => {
                        // Process debounced scans
                        let now = Instant::now();
                        let ready: Vec<PathBuf> = pending_scans
                            .iter()
                            .filter(|(_, last_event)| now.duration_since(**last_event) >= debounce_duration)
                            .map(|(path, _)| path.clone())
                            .collect();

                        for path in ready {
                            pending_scans.remove(&path);

                            if !path.exists() {
                                continue;
                            }

                            let engine = Arc::clone(&engine);
                            let scan_path = path.clone();
                            let notifier = Notifier::new();
                            tokio::task::spawn_blocking(move || {
                                info!(path = %scan_path.display(), "auto-scanning file");
                                let guard = engine.lock().unwrap();
                                match guard.scan_file(&scan_path) {
                                    Ok(result) => {
                                        let level = &result.threat_info.threat_level;
                                        if *level != anticheat_engine::ThreatLevel::Clean {
                                            warn!(
                                                path = %result.file_path,
                                                threat = %result.threat_info.threat_name,
                                                level = ?level,
                                                "threat detected in auto-scan"
                                            );
                                            notifier.notify_threat(
                                                &result.file_path,
                                                &result.threat_info.threat_name,
                                            );
                                        } else {
                                            debug!(
                                                path = %result.file_path,
                                                "auto-scan clean"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        warn!(path = %scan_path.display(), error = %e, "auto-scan failed");
                                    }
                                }
                            });
                        }
                    }
                }
            }
        });

        (handle, pause_tx)
    }
}

/// Check if a file should be scanned based on its extension.
fn should_scan_file(path: &PathBuf, extensions: &[String]) -> bool {
    if !path.is_file() {
        return false;
    }

    let ext = match path.extension().and_then(|e| e.to_str()) {
        Some(e) => e.to_lowercase(),
        None => return false,
    };

    extensions.iter().any(|scan_ext| scan_ext.to_lowercase() == ext)
}
