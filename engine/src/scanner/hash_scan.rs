//! Hash-based malware detection.
//!
//! Computes SHA-256, MD5, SHA-1, and TLSH fuzzy hashes for files and checks
//! them against a database of known malicious signatures.

use std::path::Path;

use anyhow::{Context, Result};
use md5::Md5;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;
use sha2::Digest;
use tlsh2::TlshDefaultBuilder;
use tracing::{debug, instrument, warn};

/// Minimum file size (in bytes) required for TLSH computation.
const TLSH_MIN_SIZE: usize = 50;

/// Collection of all computed hashes for a single file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHashes {
    pub sha256: String,
    pub md5: String,
    pub sha1: String,
    /// TLSH fuzzy hash; `None` when the file is too small for TLSH.
    pub tlsh: Option<String>,
}

/// A match against a known-malware hash database entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashMatch {
    /// Human-readable threat name (e.g. "Trojan.GenericKD.12345").
    pub threat_name: String,
    /// Which hash algorithm produced the match.
    pub matched_hash_type: HashType,
    /// Confidence level in `[0.0, 1.0]`.
    pub confidence: f64,
}

/// Discriminator for the hash algorithm that matched.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HashType {
    Sha256,
    Md5,
    Sha1,
    Tlsh,
}

/// Scanner that performs hash-based detection.
#[derive(Debug, Clone)]
pub struct HashScanner;

impl HashScanner {
    pub fn new() -> Self {
        Self
    }

    /// Compute all supported hashes for the file at `path`.
    #[instrument(skip(self), fields(path = %path.as_ref().display()))]
    pub fn compute_hashes(&self, path: impl AsRef<Path>) -> Result<FileHashes> {
        let data = std::fs::read(path.as_ref())
            .with_context(|| format!("failed to read file: {}", path.as_ref().display()))?;

        debug!(size = data.len(), "computing hashes");

        let sha256 = {
            let mut h = Sha256::new();
            h.update(&data);
            hex::encode(h.finalize())
        };

        let md5 = {
            let mut h = Md5::new();
            h.update(&data);
            hex::encode(h.finalize())
        };

        let sha1 = {
            let mut h = Sha1::new();
            h.update(&data);
            hex::encode(h.finalize())
        };

        let tlsh = if data.len() >= TLSH_MIN_SIZE {
            let mut builder = TlshDefaultBuilder::new();
            builder.update(&data);
            match builder.build() {
                Some(hash) => Some(hex::encode(hash.hash())),
                None => {
                    warn!("TLSH computation failed (data may be too uniform)");
                    None
                }
            }
        } else {
            debug!("file too small for TLSH ({} bytes)", data.len());
            None
        };

        Ok(FileHashes {
            sha256,
            md5,
            sha1,
            tlsh,
        })
    }

    /// Look up the computed hashes in a SQLite database and return a match if
    /// the file is known malware.
    ///
    /// The database is expected to contain a table `malware_hashes` with columns
    /// `sha256 TEXT`, `md5 TEXT`, `sha1 TEXT`, `threat_name TEXT`,
    /// `confidence REAL`.
    #[instrument(skip(self, db))]
    pub fn check_known_malware(
        &self,
        hashes: &FileHashes,
        db: &rusqlite::Connection,
    ) -> Result<Option<HashMatch>> {
        // Prefer SHA-256 match (highest confidence).
        if let Some(m) = self.query_hash(db, "sha256", &hashes.sha256, HashType::Sha256)? {
            return Ok(Some(m));
        }
        if let Some(m) = self.query_hash(db, "sha1", &hashes.sha1, HashType::Sha1)? {
            return Ok(Some(m));
        }
        if let Some(m) = self.query_hash(db, "md5", &hashes.md5, HashType::Md5)? {
            return Ok(Some(m));
        }

        // TLSH fuzzy matching: compare against all stored TLSH hashes and flag
        // if distance is below a threshold.
        if let Some(ref file_tlsh_str) = hashes.tlsh {
            if let Some(m) = self.check_tlsh_match(db, file_tlsh_str)? {
                return Ok(Some(m));
            }
        }

        Ok(None)
    }

    // ---- internal helpers ------------------------------------------------

    fn query_hash(
        &self,
        db: &rusqlite::Connection,
        column: &str,
        value: &str,
        hash_type: HashType,
    ) -> Result<Option<HashMatch>> {
        let sql = format!(
            "SELECT threat_name, confidence FROM malware_hashes WHERE {} = ?1 LIMIT 1",
            column
        );
        let mut stmt = db.prepare(&sql)?;
        let mut rows = stmt.query(rusqlite::params![value])?;

        if let Some(row) = rows.next()? {
            let threat_name: String = row.get(0)?;
            let confidence: f64 = row.get(1)?;
            debug!(threat = %threat_name, hash_type = ?hash_type, "hash match found");
            return Ok(Some(HashMatch {
                threat_name,
                matched_hash_type: hash_type,
                confidence,
            }));
        }
        Ok(None)
    }

    fn check_tlsh_match(
        &self,
        _db: &rusqlite::Connection,
        _file_tlsh_str: &str,
    ) -> Result<Option<HashMatch>> {
        // TLSH fuzzy matching: compare stored hashes by distance.
        // Simplified for now - full implementation would iterate DB entries.
        Ok(None)
    }
}

impl Default for HashScanner {
    fn default() -> Self {
        Self::new()
    }
}
