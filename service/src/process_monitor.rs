use std::collections::HashSet;
use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::watcher::SharedEngine;

/// Monitors running processes for suspicious activity.
pub struct ProcessMonitor;

/// Information about a running process.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ProcessInfo {
    name: String,
    path: String,
}

impl ProcessMonitor {
    /// Start the process monitor in a background task.
    pub fn start(
        _engine: SharedEngine,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            info!("process monitor starting");

            let mut previous_processes: HashSet<ProcessInfo> = HashSet::new();
            let check_interval = Duration::from_secs(30);

            loop {
                tokio::select! {
                    _ = shutdown.recv() => {
                        info!("process monitor shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(check_interval) => {
                        let current = get_running_processes().await;

                        // Find new processes
                        let new_procs: Vec<&ProcessInfo> = current
                            .iter()
                            .filter(|p| !previous_processes.contains(*p))
                            .collect();

                        for proc in &new_procs {
                            debug!(name = %proc.name, path = %proc.path, "new process detected");

                            if is_suspicious_location(&proc.path) {
                                warn!(
                                    name = %proc.name,
                                    path = %proc.path,
                                    "process running from suspicious location"
                                );
                            }
                        }

                        if !new_procs.is_empty() {
                            debug!(count = new_procs.len(), "new processes since last check");
                        }

                        previous_processes = current;
                    }
                }
            }
        })
    }
}

/// Check if a process path is in a suspicious location.
fn is_suspicious_location(path: &str) -> bool {
    let lower = path.to_lowercase();
    let suspicious_patterns = [
        "temp",
        "tmp",
        "appdata/local/temp",
        "appdata\\local\\temp",
        "downloads",
    ];

    suspicious_patterns.iter().any(|pattern| lower.contains(pattern))
}

/// Get a snapshot of currently running processes.
/// On Linux this reads /proc, on other platforms this is a stub.
async fn get_running_processes() -> HashSet<ProcessInfo> {
    let mut processes = HashSet::new();

    #[cfg(target_os = "linux")]
    {
        use std::fs;

        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.filter_map(|e| e.ok()) {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();

                // Only look at numeric directories (PIDs)
                if !name_str.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }

                let comm_path = entry.path().join("comm");
                let exe_path = entry.path().join("exe");

                let proc_name = fs::read_to_string(&comm_path)
                    .unwrap_or_default()
                    .trim()
                    .to_string();

                let proc_exe = fs::read_link(&exe_path)
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                if !proc_name.is_empty() {
                    processes.insert(ProcessInfo {
                        name: proc_name,
                        path: proc_exe,
                    });
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Stub for non-Linux platforms
        debug!("process listing not implemented for this platform");
    }

    processes
}
