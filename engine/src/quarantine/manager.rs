use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use tracing::info;

use super::vault::{QuarantineMetadata, QuarantineVault};
use crate::detection::ThreatInfo;

/// Status of a quarantine entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuarantineStatus {
    Quarantined,
    Restored,
    Deleted,
}

impl QuarantineStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Quarantined => "Quarantined",
            Self::Restored => "Restored",
            Self::Deleted => "Deleted",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "Restored" => Self::Restored,
            "Deleted" => Self::Deleted,
            _ => Self::Quarantined,
        }
    }
}

/// A quarantine log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub file_name: String,
    pub file_size: u64,
    pub threat_name: String,
    pub threat_level: String,
    pub confidence_score: u8,
    pub quarantine_date: String,
    pub status: QuarantineStatus,
}

/// Manages quarantine operations.
pub struct QuarantineManager {
    vault: QuarantineVault,
    conn: Connection,
}

impl QuarantineManager {
    pub fn init(db_path: impl AsRef<Path>, vault_path: impl Into<PathBuf> + AsRef<Path>) -> Result<Self> {
        let vault = QuarantineVault::init(vault_path)?;
        let conn = Connection::open(db_path.as_ref())?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS quarantine_log (
                id               TEXT PRIMARY KEY,
                original_path    TEXT NOT NULL,
                file_name        TEXT NOT NULL,
                file_size        INTEGER NOT NULL,
                threat_name      TEXT NOT NULL,
                threat_level     TEXT NOT NULL,
                confidence_score INTEGER NOT NULL,
                quarantine_date  TEXT NOT NULL,
                status           TEXT NOT NULL DEFAULT 'Quarantined'
            );",
        )?;

        info!("quarantine manager initialized");
        Ok(Self { vault, conn })
    }

    /// Quarantine a file.
    pub fn quarantine_file(
        &self,
        path: impl AsRef<Path>,
        threat_info: &ThreatInfo,
    ) -> Result<QuarantineEntry> {
        let path = path.as_ref();
        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let file_size = std::fs::metadata(path)
            .map(|m| m.len())
            .unwrap_or(0);
        let now = Utc::now().to_rfc3339();

        let metadata = QuarantineMetadata {
            original_path: path.to_string_lossy().to_string(),
            file_name: file_name.clone(),
            file_size,
            threat_name: threat_info.threat_name.clone(),
            quarantine_date: now.clone(),
        };

        let id = self.vault.encrypt_and_store(path, metadata)?;

        // Remove original file
        std::fs::remove_file(path)
            .with_context(|| format!("failed to remove original: {}", path.display()))?;

        let entry = QuarantineEntry {
            id: id.clone(),
            original_path: path.to_string_lossy().to_string(),
            file_name,
            file_size,
            threat_name: threat_info.threat_name.clone(),
            threat_level: threat_info.threat_level.to_string(),
            confidence_score: threat_info.confidence_score,
            quarantine_date: now,
            status: QuarantineStatus::Quarantined,
        };

        self.conn.execute(
            "INSERT INTO quarantine_log (id, original_path, file_name, file_size, threat_name, threat_level, confidence_score, quarantine_date, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                entry.id, entry.original_path, entry.file_name, entry.file_size,
                entry.threat_name, entry.threat_level, entry.confidence_score,
                entry.quarantine_date, entry.status.as_str()
            ],
        )?;

        info!(id = %id, file = %entry.file_name, "file quarantined");
        Ok(entry)
    }

    /// Restore a quarantined file.
    pub fn restore_file(&self, id: &str, restore_path: Option<PathBuf>) -> Result<()> {
        let entry = self.get_entry(id)
            .ok_or_else(|| anyhow::anyhow!("quarantine entry not found: {id}"))?;

        let target = restore_path.unwrap_or_else(|| PathBuf::from(&entry.original_path));
        self.vault.decrypt_and_restore(id, &target)?;
        self.update_status(id, QuarantineStatus::Restored)?;

        info!(id = %id, path = %target.display(), "file restored from quarantine");
        Ok(())
    }

    /// Permanently delete a quarantined file.
    pub fn delete_file(&self, id: &str) -> Result<()> {
        self.vault.delete(id)?;
        self.update_status(id, QuarantineStatus::Deleted)?;
        info!(id = %id, "quarantine entry deleted");
        Ok(())
    }

    /// List all quarantine entries.
    pub fn list_all(&self) -> Vec<QuarantineEntry> {
        self.query_entries("SELECT id, original_path, file_name, file_size, threat_name, threat_level, confidence_score, quarantine_date, status FROM quarantine_log ORDER BY quarantine_date DESC")
    }

    /// List only active (quarantined) entries.
    pub fn list_active(&self) -> Vec<QuarantineEntry> {
        self.query_entries("SELECT id, original_path, file_name, file_size, threat_name, threat_level, confidence_score, quarantine_date, status FROM quarantine_log WHERE status = 'Quarantined' ORDER BY quarantine_date DESC")
    }

    /// Auto-clean entries older than max_age_days.
    pub fn auto_clean(&self, max_age_days: u32) -> Result<Vec<String>> {
        let cutoff = Utc::now() - chrono::Duration::days(max_age_days as i64);
        let cutoff_str = cutoff.to_rfc3339();
        let mut cleaned = Vec::new();

        let entries = self.list_active();
        for entry in entries {
            if entry.quarantine_date < cutoff_str {
                self.delete_file(&entry.id)?;
                cleaned.push(entry.id);
            }
        }

        if !cleaned.is_empty() {
            info!(count = cleaned.len(), "auto-cleaned old quarantine entries");
        }
        Ok(cleaned)
    }

    pub fn get_entry(&self, id: &str) -> Option<QuarantineEntry> {
        self.conn
            .query_row(
                "SELECT id, original_path, file_name, file_size, threat_name, threat_level, confidence_score, quarantine_date, status
                 FROM quarantine_log WHERE id = ?1",
                params![id],
                |row| Self::row_to_entry(row),
            )
            .ok()
    }

    pub fn vault_size(&self) -> u64 {
        self.vault.get_vault_size()
    }

    fn update_status(&self, id: &str, status: QuarantineStatus) -> Result<()> {
        self.conn.execute(
            "UPDATE quarantine_log SET status = ?1 WHERE id = ?2",
            params![status.as_str(), id],
        )?;
        Ok(())
    }

    fn query_entries(&self, sql: &str) -> Vec<QuarantineEntry> {
        let mut stmt = match self.conn.prepare(sql) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        stmt.query_map([], |row| Self::row_to_entry(row))
            .ok()
            .map(|rows| rows.filter_map(|r| r.ok()).collect())
            .unwrap_or_default()
    }

    fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<QuarantineEntry> {
        Ok(QuarantineEntry {
            id: row.get(0)?,
            original_path: row.get(1)?,
            file_name: row.get(2)?,
            file_size: row.get(3)?,
            threat_name: row.get(4)?,
            threat_level: row.get(5)?,
            confidence_score: row.get(6)?,
            quarantine_date: row.get(7)?,
            status: QuarantineStatus::from_str(&row.get::<_, String>(8)?),
        })
    }
}

impl std::fmt::Debug for QuarantineManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuarantineManager").finish()
    }
}
