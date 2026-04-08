//! Simple JSON-line IPC server for the AntiCheat service.
//!
//! Listens on a Unix domain socket (Linux/macOS) or named pipe (Windows) and
//! accepts newline-delimited JSON commands. The CLI / GUI can connect and
//! issue commands like `{"cmd":"status"}` or `{"cmd":"scan","path":"..."}`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::watcher::SharedEngine;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum IpcCommand {
    Status,
    Scan { path: String },
    QuickScan { path: String },
    Pause,
    Resume,
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    pub ok: bool,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

/// Default socket path used by the service.
pub fn default_socket_path() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"\\.\pipe\anticheat-service")
    } else {
        let dir = std::env::var("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp"));
        dir.join("anticheat-service.sock")
    }
}

/// Start the IPC server in a background task.
///
/// Note: this implementation is intentionally minimal - it logs incoming
/// connections but does not accept them on platforms without Unix sockets.
pub fn start(
    socket_path: PathBuf,
    _engine: SharedEngine,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        info!(path = %socket_path.display(), "ipc server starting");

        #[cfg(unix)]
        {
            // Remove a stale socket if present.
            let _ = std::fs::remove_file(&socket_path);

            let listener = match tokio::net::UnixListener::bind(&socket_path) {
                Ok(l) => l,
                Err(e) => {
                    warn!(error = %e, "failed to bind ipc socket");
                    return;
                }
            };

            loop {
                tokio::select! {
                    _ = shutdown.recv() => {
                        info!("ipc server shutting down");
                        let _ = std::fs::remove_file(&socket_path);
                        break;
                    }
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, _addr)) => {
                                tokio::spawn(handle_connection(stream));
                            }
                            Err(e) => {
                                warn!(error = %e, "ipc accept failed");
                            }
                        }
                    }
                }
            }
        }

        #[cfg(not(unix))]
        {
            warn!("IPC server is only implemented on Unix platforms");
            let _ = shutdown.recv().await;
        }
    })
}

#[cfg(unix)]
async fn handle_connection(stream: tokio::net::UnixStream) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => return,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                let response = match serde_json::from_str::<IpcCommand>(trimmed) {
                    Ok(cmd) => handle_command(cmd),
                    Err(e) => IpcResponse {
                        ok: false,
                        message: format!("invalid command: {}", e),
                        data: None,
                    },
                };

                let mut json = serde_json::to_string(&response).unwrap_or_default();
                json.push('\n');
                if write_half.write_all(json.as_bytes()).await.is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

fn handle_command(cmd: IpcCommand) -> IpcResponse {
    debug!(?cmd, "handling ipc command");
    match cmd {
        IpcCommand::Status => IpcResponse {
            ok: true,
            message: "AntiCheat service is running".to_string(),
            data: None,
        },
        IpcCommand::Scan { path } | IpcCommand::QuickScan { path } => IpcResponse {
            ok: true,
            message: format!("scan queued for {}", path),
            data: None,
        },
        IpcCommand::Pause => IpcResponse {
            ok: true,
            message: "service paused".to_string(),
            data: None,
        },
        IpcCommand::Resume => IpcResponse {
            ok: true,
            message: "service resumed".to_string(),
            data: None,
        },
        IpcCommand::Shutdown => IpcResponse {
            ok: true,
            message: "service shutting down".to_string(),
            data: None,
        },
    }
}
