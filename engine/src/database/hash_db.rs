use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{debug, info};

/// Represents a known malware threat entry in the hash database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEntry {
    pub sha256: String,
    pub md5: String,
    pub sha1: String,
    pub threat_name: String,
    pub threat_type: String,
    pub severity: u32,
    pub date_added: String,
    pub source: String,
}

/// Database of known malware hashes backed by SQLite.
pub struct HashDatabase {
    conn: Connection,
}

impl HashDatabase {
    /// Initialize the hash database, creating tables and seeding example data if needed.
    pub fn init<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS known_threats (
                sha256      TEXT PRIMARY KEY,
                md5         TEXT,
                sha1        TEXT,
                threat_name TEXT,
                threat_type TEXT,
                severity    INTEGER,
                date_added  TEXT,
                source      TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_threats_md5 ON known_threats(md5);
            CREATE INDEX IF NOT EXISTS idx_threats_sha1 ON known_threats(sha1);",
        )?;

        let db = Self { conn };

        // Seed example entries when the table is empty.
        if db.count() == 0 {
            info!("Seeding hash database with example threat entries");
            db.seed_examples()?;
        }

        Ok(db)
    }

    /// Look up a threat by its SHA-256 hash.
    pub fn lookup_sha256(&self, hash: &str) -> Option<ThreatEntry> {
        debug!(hash, "Looking up SHA-256");
        self.conn
            .query_row(
                "SELECT sha256, md5, sha1, threat_name, threat_type, severity, date_added, source
                 FROM known_threats WHERE sha256 = ?1",
                params![hash],
                |row| {
                    Ok(ThreatEntry {
                        sha256: row.get(0)?,
                        md5: row.get(1)?,
                        sha1: row.get(2)?,
                        threat_name: row.get(3)?,
                        threat_type: row.get(4)?,
                        severity: row.get(5)?,
                        date_added: row.get(6)?,
                        source: row.get(7)?,
                    })
                },
            )
            .ok()
    }

    /// Look up a threat by its MD5 hash.
    pub fn lookup_md5(&self, hash: &str) -> Option<ThreatEntry> {
        debug!(hash, "Looking up MD5");
        self.conn
            .query_row(
                "SELECT sha256, md5, sha1, threat_name, threat_type, severity, date_added, source
                 FROM known_threats WHERE md5 = ?1",
                params![hash],
                |row| {
                    Ok(ThreatEntry {
                        sha256: row.get(0)?,
                        md5: row.get(1)?,
                        sha1: row.get(2)?,
                        threat_name: row.get(3)?,
                        threat_type: row.get(4)?,
                        severity: row.get(5)?,
                        date_added: row.get(6)?,
                        source: row.get(7)?,
                    })
                },
            )
            .ok()
    }

    /// Add a new threat entry to the database.
    pub fn add_entry(&self, entry: &ThreatEntry) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO known_threats
             (sha256, md5, sha1, threat_name, threat_type, severity, date_added, source)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                entry.sha256,
                entry.md5,
                entry.sha1,
                entry.threat_name,
                entry.threat_type,
                entry.severity,
                entry.date_added,
                entry.source,
            ],
        )?;
        Ok(())
    }

    /// Return the number of entries in the database.
    pub fn count(&self) -> usize {
        self.conn
            .query_row("SELECT COUNT(*) FROM known_threats", [], |row| {
                row.get::<_, usize>(0)
            })
            .unwrap_or(0)
    }

    /// Import threat entries from a JSON file.
    pub fn import_from_json<P: AsRef<Path>>(&self, path: P) -> Result<usize> {
        let data = std::fs::read_to_string(path)?;
        let entries: Vec<ThreatEntry> = serde_json::from_str(&data)?;
        let count = entries.len();
        for entry in &entries {
            self.add_entry(entry)?;
        }
        info!(count, "Imported threat entries from JSON");
        Ok(count)
    }

    /// Export all threat entries to a JSON file.
    pub fn export_to_json<P: AsRef<Path>>(&self, path: P) -> Result<usize> {
        let mut stmt = self.conn.prepare(
            "SELECT sha256, md5, sha1, threat_name, threat_type, severity, date_added, source
             FROM known_threats",
        )?;

        let entries: Vec<ThreatEntry> = stmt
            .query_map([], |row| {
                Ok(ThreatEntry {
                    sha256: row.get(0)?,
                    md5: row.get(1)?,
                    sha1: row.get(2)?,
                    threat_name: row.get(3)?,
                    threat_type: row.get(4)?,
                    severity: row.get(5)?,
                    date_added: row.get(6)?,
                    source: row.get(7)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        let count = entries.len();
        let json = serde_json::to_string_pretty(&entries)?;
        std::fs::write(path, json)?;
        info!(count, "Exported threat entries to JSON");
        Ok(count)
    }

    /// Seed the database with example threat entries for testing.
    fn seed_examples(&self) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let examples = vec![
            ThreatEntry {
                sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
                md5: "d41d8cd98f00b204e9800998ecf8427e".into(),
                sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709".into(),
                threat_name: "Test.EmptyFile.Marker".into(),
                threat_type: "Marker".into(),
                severity: 1,
                date_added: now.clone(),
                source: "seed".into(),
            },
            ThreatEntry {
                sha256: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".into(),
                md5: "a1b2c3d4e5f6a1b2c3d4e5f6".into(),
                sha1: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".into(),
                threat_name: "Trojan.GenericAimbot.A".into(),
                threat_type: "Trojan".into(),
                severity: 8,
                date_added: now.clone(),
                source: "seed".into(),
            },
            ThreatEntry {
                sha256: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
                md5: "deadbeefdeadbeefdeadbeef".into(),
                sha1: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
                threat_name: "HackTool.WallhackInjector.B".into(),
                threat_type: "HackTool".into(),
                severity: 9,
                date_added: now.clone(),
                source: "seed".into(),
            },
            ThreatEntry {
                sha256: "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe".into(),
                md5: "cafebabecafebabecafebabe".into(),
                sha1: "cafebabecafebabecafebabecafebabecafebabe".into(),
                threat_name: "Exploit.KernelDriver.CheatEngine".into(),
                threat_type: "Exploit".into(),
                severity: 10,
                date_added: now.clone(),
                source: "seed".into(),
            },
            ThreatEntry {
                sha256: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".into(),
                md5: "1234567890abcdef12345678".into(),
                sha1: "1234567890abcdef1234567890abcdef12345678".into(),
                threat_name: "Riskware.SpeedHack.Generic".into(),
                threat_type: "Riskware".into(),
                severity: 6,
                date_added: now,
                source: "seed".into(),
            },
        ];

        for entry in &examples {
            self.add_entry(entry)?;
        }
        Ok(())
    }
}
