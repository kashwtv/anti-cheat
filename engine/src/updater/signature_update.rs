//! Signature database update logic.
//!
//! Fetches the latest malware-signature manifest from a remote server,
//! compares it against the locally installed version, and downloads /
//! applies the update when one is available.

use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Metadata about an available signature update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    /// Semantic version of the signature set (e.g. "2026.04.03.1").
    pub version: String,
    /// When this signature set was published.
    pub release_date: DateTime<Utc>,
    /// Human-readable change summary.
    pub description: String,
    /// Download size in bytes.
    pub size_bytes: u64,
    /// SHA-256 checksum of the update payload.
    pub checksum: String,
}

/// Outcome of a successful signature update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateResult {
    /// Whether the update completed without error.
    pub success: bool,
    /// Number of detection rules added or changed.
    pub rules_updated: u64,
    /// Number of malware hashes added or changed.
    pub hashes_updated: u64,
    /// Version string before the update.
    pub previous_version: String,
    /// Version string after the update.
    pub new_version: String,
}

/// Local version state persisted to disk between runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VersionState {
    version: String,
    last_update: DateTime<Utc>,
}

/// Handles downloading and applying signature-database updates.
#[derive(Debug, Clone)]
pub struct SignatureUpdater {
    /// Base URL of the update server (e.g. `https://updates.example.com/signatures`).
    update_url: String,
    /// Directory where signatures and version metadata are stored locally.
    local_path: PathBuf,
    /// HTTP client reused across requests.
    client: reqwest::Client,
}

impl SignatureUpdater {
    /// Create a new `SignatureUpdater`.
    ///
    /// * `update_url` - base URL for the remote signature server.
    /// * `local_path` - directory where local signature data lives.
    pub fn new(update_url: impl Into<String>, local_path: impl Into<PathBuf>) -> Self {
        Self {
            update_url: update_url.into(),
            local_path: local_path.into(),
            client: reqwest::Client::new(),
        }
    }

    /// Check the remote server for a newer signature version.
    ///
    /// Returns `Ok(Some(info))` when an update is available, `Ok(None)` when
    /// the local version is already current, and an error only for
    /// non-recoverable failures (network errors are handled gracefully and
    /// logged as warnings).
    pub async fn check_for_updates(&self) -> Result<Option<UpdateInfo>> {
        let manifest_url = format!("{}/manifest.json", self.update_url);
        debug!(%manifest_url, "checking for signature updates");

        let response = match self.client.get(&manifest_url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                warn!("failed to reach update server: {e}");
                return Ok(None);
            }
        };

        if !response.status().is_success() {
            warn!(status = %response.status(), "update server returned non-success status");
            return Ok(None);
        }

        let info: UpdateInfo = response
            .json()
            .await
            .context("failed to parse update manifest")?;

        let current = self.get_current_version();
        if info.version == current {
            debug!(version = %current, "signatures are up to date");
            return Ok(None);
        }

        info!(
            current_version = %current,
            available_version = %info.version,
            "signature update available"
        );
        Ok(Some(info))
    }

    /// Download and apply the latest signature update.
    ///
    /// This is currently a stub that simulates a successful update.
    pub async fn download_and_apply(&self) -> Result<UpdateResult> {
        let previous_version = self.get_current_version();

        // In a real implementation this would:
        // 1. Download the update payload from self.update_url
        // 2. Verify the checksum
        // 3. Replace the local signature database files
        // 4. Persist the new version state

        let new_version = previous_version.clone();

        // Persist a version state file so subsequent calls see the update.
        let state = VersionState {
            version: new_version.clone(),
            last_update: Utc::now(),
        };
        let state_path = self.version_state_path();
        if let Some(parent) = state_path.parent() {
            std::fs::create_dir_all(parent)
                .context("failed to create local state directory")?;
        }
        let json = serde_json::to_string_pretty(&state)
            .context("failed to serialize version state")?;
        std::fs::write(&state_path, json)
            .context("failed to write version state file")?;

        Ok(UpdateResult {
            success: true,
            rules_updated: 0,
            hashes_updated: 0,
            previous_version,
            new_version,
        })
    }

    /// Return the currently installed signature version string.
    pub fn get_current_version(&self) -> String {
        self.read_version_state()
            .map(|s| s.version)
            .unwrap_or_else(|| "0.0.0".to_string())
    }

    /// Return the timestamp of the last successful update, if any.
    pub fn get_last_update_time(&self) -> Option<DateTime<Utc>> {
        self.read_version_state().map(|s| s.last_update)
    }

    // -- internal helpers ---------------------------------------------------

    fn version_state_path(&self) -> PathBuf {
        self.local_path.join("version_state.json")
    }

    fn read_version_state(&self) -> Option<VersionState> {
        let path = self.version_state_path();
        let data = std::fs::read_to_string(&path).ok()?;
        serde_json::from_str(&data).ok()
    }
}
