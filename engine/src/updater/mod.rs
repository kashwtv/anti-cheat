//! Update subsystem for the anticheat engine.
//!
//! Coordinates signature updates, delta patches, and application self-updates
//! through the [`UpdateManager`] facade.

pub mod delta_update;
pub mod self_update;
pub mod signature_update;

pub use delta_update::{DeltaPatch, DeltaUpdater, RuleFileUpdate, SignatureEntry};
pub use self_update::{AppUpdateInfo, SelfUpdater};
pub use signature_update::{SignatureUpdater, UpdateInfo, UpdateResult};

use std::path::PathBuf;

use anyhow::Result;
use tracing::debug;

/// Top-level coordinator for all update channels.
#[derive(Debug)]
pub struct UpdateManager {
    /// Handles signature-database updates.
    pub signature_updater: SignatureUpdater,
    /// Handles delta / incremental patches.
    pub delta_updater: DeltaUpdater,
    /// Handles application self-updates.
    pub self_updater: SelfUpdater,
}

impl UpdateManager {
    /// Initialise the update subsystem.
    ///
    /// * `data_dir`          - root data directory; signatures will live under
    ///                         `<data_dir>/signatures`.
    /// * `signature_url`     - base URL of the signature update server.
    /// * `app_update_url`    - base URL of the application update server.
    pub fn new(
        data_dir: impl Into<PathBuf>,
        signature_url: impl Into<String>,
        app_update_url: impl Into<String>,
    ) -> Self {
        let data_dir = data_dir.into();
        let signatures_dir = data_dir.join("signatures");

        debug!(path = %signatures_dir.display(), "initialising update manager");

        Self {
            signature_updater: SignatureUpdater::new(
                signature_url,
                signatures_dir.clone(),
            ),
            delta_updater: DeltaUpdater::new(signatures_dir),
            self_updater: SelfUpdater::new(app_update_url),
        }
    }

    /// Convenience: check whether a new signature version is available.
    pub async fn check_for_updates(&self) -> Result<Option<UpdateInfo>> {
        self.signature_updater.check_for_updates().await
    }

    /// Convenience: download and install the latest signatures.
    pub async fn update_signatures(&self) -> Result<UpdateResult> {
        self.signature_updater.download_and_apply().await
    }
}
