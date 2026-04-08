use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::info;

/// Reputation information for a file source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceReputation {
    pub source_identifier: String,
    pub reputation_score: u32,
    pub total_files_seen: u64,
    pub malicious_files_count: u64,
    pub last_updated: String,
}

/// Tracks reputation of file sources (URLs, domains, paths).
pub struct ReputationDatabase {
    conn: Connection,
}

impl ReputationDatabase {
    pub fn init<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS source_reputation (
                source_identifier   TEXT PRIMARY KEY,
                reputation_score    INTEGER NOT NULL DEFAULT 50,
                total_files_seen    INTEGER NOT NULL DEFAULT 0,
                malicious_files_count INTEGER NOT NULL DEFAULT 0,
                last_updated        TEXT NOT NULL
            );",
        )?;

        info!("Reputation database initialized");
        Ok(Self { conn })
    }

    pub fn get_reputation(&self, source: &str) -> Option<SourceReputation> {
        self.conn
            .query_row(
                "SELECT source_identifier, reputation_score, total_files_seen, malicious_files_count, last_updated
                 FROM source_reputation WHERE source_identifier = ?1",
                params![source],
                |row| {
                    Ok(SourceReputation {
                        source_identifier: row.get(0)?,
                        reputation_score: row.get(1)?,
                        total_files_seen: row.get(2)?,
                        malicious_files_count: row.get(3)?,
                        last_updated: row.get(4)?,
                    })
                },
            )
            .ok()
    }

    pub fn update_reputation(&self, source: &str, is_malicious: bool) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let existing = self.get_reputation(source);

        match existing {
            Some(mut rep) => {
                rep.total_files_seen += 1;
                if is_malicious {
                    rep.malicious_files_count += 1;
                }
                let ratio = rep.malicious_files_count as f64 / rep.total_files_seen as f64;
                rep.reputation_score = ((1.0 - ratio) * 100.0) as u32;

                self.conn.execute(
                    "UPDATE source_reputation SET reputation_score = ?1, total_files_seen = ?2,
                     malicious_files_count = ?3, last_updated = ?4 WHERE source_identifier = ?5",
                    params![rep.reputation_score, rep.total_files_seen, rep.malicious_files_count, now, source],
                )?;
            }
            None => {
                let score: u32 = if is_malicious { 30 } else { 70 };
                let mal_count: u64 = if is_malicious { 1 } else { 0 };
                self.conn.execute(
                    "INSERT INTO source_reputation (source_identifier, reputation_score, total_files_seen, malicious_files_count, last_updated)
                     VALUES (?1, ?2, 1, ?3, ?4)",
                    params![source, score, mal_count, now],
                )?;
            }
        }
        Ok(())
    }

    pub fn add_source(&self, entry: &SourceReputation) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO source_reputation
             (source_identifier, reputation_score, total_files_seen, malicious_files_count, last_updated)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                entry.source_identifier,
                entry.reputation_score,
                entry.total_files_seen,
                entry.malicious_files_count,
                entry.last_updated,
            ],
        )?;
        Ok(())
    }

    pub fn get_untrusted_sources(&self) -> Vec<SourceReputation> {
        let mut stmt = match self.conn.prepare(
            "SELECT source_identifier, reputation_score, total_files_seen, malicious_files_count, last_updated
             FROM source_reputation WHERE reputation_score < 40 ORDER BY reputation_score ASC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        stmt.query_map([], |row| {
            Ok(SourceReputation {
                source_identifier: row.get(0)?,
                reputation_score: row.get(1)?,
                total_files_seen: row.get(2)?,
                malicious_files_count: row.get(3)?,
                last_updated: row.get(4)?,
            })
        })
        .ok()
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }
}
