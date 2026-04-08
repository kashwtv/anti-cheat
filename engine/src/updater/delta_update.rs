//! Delta (incremental) update support.
//!
//! Instead of re-downloading the full signature database every time, delta
//! updates describe only the differences between two consecutive versions.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// A single signature entry to be added to the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureEntry {
    /// SHA-256 hash of the malware sample.
    pub sha256: String,
    /// Optional MD5 hash.
    pub md5: Option<String>,
    /// Optional SHA-1 hash.
    pub sha1: Option<String>,
    /// Human-readable threat name.
    pub threat_name: String,
    /// Confidence score for this entry (0.0 .. 1.0).
    pub confidence: f64,
}

/// An update to a YARA or custom detection rule file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFileUpdate {
    /// Relative path of the rule file inside the signatures directory.
    pub path: String,
    /// New content of the rule file (full replacement).
    pub content: String,
    /// SHA-256 checksum of `content`.
    pub checksum: String,
}

/// A delta patch that transforms a signature database from one version to
/// another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaPatch {
    /// Version the patch applies to.
    pub from_version: String,
    /// Version produced after applying the patch.
    pub to_version: String,
    /// Signature entries to add to the database.
    pub additions: Vec<SignatureEntry>,
    /// SHA-256 hashes of entries to remove from the database.
    pub removals: Vec<String>,
    /// Rule files to create or overwrite.
    pub modified_rules: Vec<RuleFileUpdate>,
}

/// Applies delta patches on top of the local signature database.
#[derive(Debug, Clone)]
pub struct DeltaUpdater {
    /// Path to the local signatures directory.
    signatures_dir: std::path::PathBuf,
}

impl DeltaUpdater {
    /// Create a new `DeltaUpdater` rooted at the given signatures directory.
    pub fn new(signatures_dir: impl Into<std::path::PathBuf>) -> Self {
        Self {
            signatures_dir: signatures_dir.into(),
        }
    }

    /// Apply a delta patch to the local signature database.
    ///
    /// This is currently a stub that logs the patch summary and returns `Ok(())`.
    pub async fn apply_delta(&self, patch: &DeltaPatch) -> Result<()> {
        info!(
            from = %patch.from_version,
            to = %patch.to_version,
            additions = patch.additions.len(),
            removals = patch.removals.len(),
            rule_updates = patch.modified_rules.len(),
            "applying delta patch"
        );

        // Stub: In a real implementation this would:
        // 1. Open the SQLite signature database.
        // 2. Insert rows from `patch.additions`.
        // 3. Delete rows whose SHA-256 is in `patch.removals`.
        // 4. Write `patch.modified_rules` to disk.

        debug!("delta patch applied (stub)");
        Ok(())
    }

    /// Compute the delta between two snapshot versions of the signature
    /// database.
    ///
    /// This is a stub that returns an empty patch.
    pub fn create_delta(&self, old_version: &str, new_version: &str) -> DeltaPatch {
        debug!(%old_version, %new_version, "creating delta (stub)");
        DeltaPatch {
            from_version: old_version.to_string(),
            to_version: new_version.to_string(),
            additions: Vec::new(),
            removals: Vec::new(),
            modified_rules: Vec::new(),
        }
    }
}
