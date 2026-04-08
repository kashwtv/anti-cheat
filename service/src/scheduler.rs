use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::watcher::SharedEngine;

/// Configuration for scheduled scans.
#[derive(Debug, Clone)]
pub struct ScheduleConfig {
    /// How often to run quick scans (hash-only). None to disable.
    pub quick_scan_interval: Option<Duration>,
    /// How often to run full scans. None to disable.
    pub full_scan_interval: Option<Duration>,
    /// Whether to run scans when system is idle.
    pub idle_scan: bool,
    /// Directories to scan during scheduled scans.
    pub scan_paths: Vec<PathBuf>,
}

impl Default for ScheduleConfig {
    fn default() -> Self {
        let mut scan_paths = Vec::new();

        if cfg!(windows) {
            if let Ok(userprofile) = std::env::var("USERPROFILE") {
                let base = PathBuf::from(&userprofile);
                scan_paths.push(base.join("Downloads"));
                scan_paths.push(base.join("Desktop"));
            }
        } else {
            if let Ok(home) = std::env::var("HOME") {
                let base = PathBuf::from(&home);
                scan_paths.push(base.join("Downloads"));
                scan_paths.push(base.join("Desktop"));
            }
        }

        Self {
            quick_scan_interval: Some(Duration::from_secs(4 * 3600)), // 4 hours
            full_scan_interval: Some(Duration::from_secs(24 * 3600)), // 24 hours
            idle_scan: true,
            scan_paths,
        }
    }
}

/// Manages scheduled scan execution.
pub struct ScanScheduler;

impl ScanScheduler {
    /// Start the scan scheduler in a background task.
    pub fn start(
        config: ScheduleConfig,
        engine: SharedEngine,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            info!("scan scheduler starting");

            let mut last_quick_scan = Instant::now();
            let mut last_full_scan = Instant::now();
            let mut idle_start: Option<Instant> = None;
            let idle_threshold = Duration::from_secs(300); // 5 minutes

            // Use a 30-second tick to check if any scan is due
            let tick_interval = Duration::from_secs(30);

            loop {
                tokio::select! {
                    _ = shutdown.recv() => {
                        info!("scan scheduler shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(tick_interval) => {
                        let now = Instant::now();

                        // Simulate idle detection (in a real implementation, we would
                        // query the OS for user input idle time)
                        let is_idle = simulate_idle_check(&mut idle_start, now);

                        // Check if quick scan is due
                        if let Some(interval) = config.quick_scan_interval {
                            if now.duration_since(last_quick_scan) >= interval {
                                let should_scan = !config.idle_scan || is_idle;
                                if should_scan || now.duration_since(last_quick_scan) >= interval * 2 {
                                    info!("scheduled quick scan starting");
                                    run_quick_scan(&engine, &config.scan_paths).await;
                                    last_quick_scan = Instant::now();
                                }
                            }
                        }

                        // Check if full scan is due
                        if let Some(interval) = config.full_scan_interval {
                            if now.duration_since(last_full_scan) >= interval {
                                let should_scan = !config.idle_scan || is_idle;
                                if should_scan || now.duration_since(last_full_scan) >= interval * 2 {
                                    info!("scheduled full scan starting");
                                    run_full_scan(&engine, &config.scan_paths).await;
                                    last_full_scan = Instant::now();
                                }
                            }
                        }

                        // Idle scan: if idle and haven't scanned recently
                        if config.idle_scan && is_idle {
                            let idle_dur = idle_start
                                .map(|s| now.duration_since(s))
                                .unwrap_or_default();

                            if idle_dur >= idle_threshold
                                && now.duration_since(last_quick_scan) >= Duration::from_secs(1800)
                            {
                                info!("idle scan triggered");
                                run_quick_scan(&engine, &config.scan_paths).await;
                                last_quick_scan = Instant::now();
                            }
                        }
                    }
                }
            }
        })
    }
}

/// Simulate idle detection. In production this would check OS-level input idle time.
fn simulate_idle_check(idle_start: &mut Option<Instant>, _now: Instant) -> bool {
    // Stub: treat the system as always active unless we've been running > 10 minutes
    // In a real implementation this would query the OS
    if idle_start.is_none() {
        *idle_start = Some(Instant::now());
    }
    false
}

/// Run a quick (hash-only) scan on the configured paths.
async fn run_quick_scan(engine: &SharedEngine, paths: &[PathBuf]) {
    for path in paths {
        if !path.exists() {
            continue;
        }

        let engine = Arc::clone(engine);
        let scan_path = path.clone();

        let result = tokio::task::spawn_blocking(move || {
            let mut scanned = 0u32;
            let mut threats = 0u32;
            let guard = engine.lock().unwrap();

            let walker = walkdir::WalkDir::new(&scan_path).max_depth(2);
            for entry in walker.into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    match guard.quick_scan(entry.path()) {
                        Ok(result) => {
                            scanned += 1;
                            if result.threat_info.threat_level != anticheat_engine::ThreatLevel::Clean {
                                threats += 1;
                                warn!(
                                    path = %result.file_path,
                                    threat = %result.threat_info.threat_name,
                                    "threat found in scheduled quick scan"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::debug!(
                                path = %entry.path().display(),
                                error = %e,
                                "quick scan failed for file"
                            );
                        }
                    }
                }
            }

            (scanned, threats)
        })
        .await;

        match result {
            Ok((scanned, threats)) => {
                info!(
                    path = %path.display(),
                    scanned,
                    threats,
                    "quick scan completed"
                );
            }
            Err(e) => {
                error!(error = %e, "quick scan task failed");
            }
        }
    }
}

/// Run a full scan on the configured paths.
async fn run_full_scan(engine: &SharedEngine, paths: &[PathBuf]) {
    for path in paths {
        if !path.exists() {
            continue;
        }

        let engine = Arc::clone(engine);
        let scan_path = path.clone();

        let result = tokio::task::spawn_blocking(move || {
            let guard = engine.lock().unwrap();
            match guard.scan_directory(&scan_path, true) {
                Ok(results) => {
                    let threats: Vec<_> = results
                        .iter()
                        .filter(|r| r.threat_info.threat_level != anticheat_engine::ThreatLevel::Clean)
                        .collect();

                    if !threats.is_empty() {
                        for t in &threats {
                            warn!(
                                path = %t.file_path,
                                threat = %t.threat_info.threat_name,
                                "threat found in scheduled full scan"
                            );
                        }
                    }

                    (results.len(), threats.len())
                }
                Err(e) => {
                    error!(error = %e, "full scan failed");
                    (0, 0)
                }
            }
        })
        .await;

        match result {
            Ok((scanned, threats)) => {
                info!(
                    path = %path.display(),
                    scanned,
                    threats,
                    "full scan completed"
                );
            }
            Err(e) => {
                error!(error = %e, "full scan task failed");
            }
        }
    }
}
