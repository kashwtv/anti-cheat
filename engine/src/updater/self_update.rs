//! Application self-update mechanism.
//!
//! Checks for new versions of the anticheat engine binary itself and
//! orchestrates download + replacement.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Metadata about an available application update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppUpdateInfo {
    /// Semantic version of the new release.
    pub version: String,
    /// Markdown-formatted release notes.
    pub release_notes: String,
    /// Direct download URL for the update binary/package.
    pub download_url: String,
    /// SHA-256 checksum of the download artifact.
    pub checksum: String,
    /// Size of the download artifact in bytes.
    pub size_bytes: u64,
}

/// Handles checking for and applying updates to the anticheat application
/// itself.
#[derive(Debug, Clone)]
pub struct SelfUpdater {
    /// Base URL for the application update server.
    update_url: String,
    /// Reusable HTTP client.
    client: reqwest::Client,
}

impl SelfUpdater {
    /// Create a new `SelfUpdater` pointing at `update_url`.
    pub fn new(update_url: impl Into<String>) -> Self {
        Self {
            update_url: update_url.into(),
            client: reqwest::Client::new(),
        }
    }

    /// Query the update server for a newer application version.
    ///
    /// Returns `Ok(Some(info))` when an update is available, `Ok(None)` when
    /// the running version is current. Network errors are handled gracefully.
    pub async fn check_for_app_update(&self) -> Result<Option<AppUpdateInfo>> {
        let url = format!("{}/latest.json", self.update_url);
        debug!(%url, "checking for application update");

        let response = match self.client.get(&url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                warn!("failed to reach app update server: {e}");
                return Ok(None);
            }
        };

        if !response.status().is_success() {
            warn!(status = %response.status(), "app update server returned non-success status");
            return Ok(None);
        }

        let info: AppUpdateInfo = response
            .json()
            .await
            .context("failed to parse app update response")?;

        let current = env!("CARGO_PKG_VERSION");
        if info.version == current {
            debug!("application is up to date ({current})");
            return Ok(None);
        }

        info!(
            current_version = current,
            available_version = %info.version,
            "application update available"
        );
        Ok(Some(info))
    }

    /// Download the update artifact to a temporary file and return its path.
    ///
    /// Stub implementation - returns a placeholder path.
    pub async fn download_update(&self) -> Result<PathBuf> {
        debug!("download_update called (stub)");
        // In a real implementation this would stream the download to a temp
        // file, verify the checksum, and return the path.
        Ok(PathBuf::from("/tmp/anticheat-update.tar.gz"))
    }

    /// Replace the running application with the update at `update_path`.
    ///
    /// Stub implementation - logs the intent and returns Ok.
    pub async fn apply_update(&self, update_path: PathBuf) -> Result<()> {
        info!(path = %update_path.display(), "apply_update called (stub)");
        // In a real implementation this would:
        // 1. Verify the download checksum again.
        // 2. Extract the archive.
        // 3. Replace the current binary (possibly via a helper process).
        // 4. Signal the caller to restart.
        Ok(())
    }
}
