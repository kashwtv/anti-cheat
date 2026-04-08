use anyhow::Result;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::info;

/// Trust level for a whitelisted entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    Verified,
    UserReported,
    Unverified,
}

impl TrustLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Verified => "Verified",
            Self::UserReported => "UserReported",
            Self::Unverified => "Unverified",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "Verified" => Self::Verified,
            "UserReported" => Self::UserReported,
            _ => Self::Unverified,
        }
    }
}

/// Category of the whitelisted software.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WhitelistCategory {
    CheatTool,
    GameMod,
    Utility,
}

impl WhitelistCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CheatTool => "CheatTool",
            Self::GameMod => "GameMod",
            Self::Utility => "Utility",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "CheatTool" => Self::CheatTool,
            "GameMod" => Self::GameMod,
            _ => Self::Utility,
        }
    }
}

/// Who added this whitelist entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddedBy {
    System,
    User,
    Community,
}

impl AddedBy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::System => "System",
            Self::User => "User",
            Self::Community => "Community",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "System" => Self::System,
            "User" => Self::User,
            "Community" => Self::Community,
            _ => Self::System,
        }
    }
}

/// A whitelisted file entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistEntry {
    pub sha256: String,
    pub name: String,
    pub description: String,
    pub trust_level: TrustLevel,
    pub category: WhitelistCategory,
    pub added_by: AddedBy,
    pub date_added: String,
}

/// Community and user whitelist backed by SQLite.
pub struct WhitelistDatabase {
    conn: Connection,
}

impl WhitelistDatabase {
    /// Initialize the whitelist database, creating tables if needed.
    pub fn init<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS whitelist (
                sha256      TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                description TEXT,
                trust_level TEXT NOT NULL,
                category    TEXT NOT NULL,
                added_by    TEXT NOT NULL,
                date_added  TEXT NOT NULL
            );",
        )?;

        info!("Whitelist database initialized");
        Ok(Self { conn })
    }

    /// Check whether a file is whitelisted by SHA-256.
    pub fn is_whitelisted(&self, sha256: &str) -> Option<WhitelistEntry> {
        self.conn
            .query_row(
                "SELECT sha256, name, description, trust_level, category, added_by, date_added
                 FROM whitelist WHERE sha256 = ?1",
                params![sha256],
                |row| {
                    Ok(WhitelistEntry {
                        sha256: row.get(0)?,
                        name: row.get(1)?,
                        description: row.get(2)?,
                        trust_level: TrustLevel::from_str(&row.get::<_, String>(3)?),
                        category: WhitelistCategory::from_str(&row.get::<_, String>(4)?),
                        added_by: AddedBy::from_str(&row.get::<_, String>(5)?),
                        date_added: row.get(6)?,
                    })
                },
            )
            .ok()
    }

    /// Add a new whitelist entry.
    pub fn add_entry(&self, entry: &WhitelistEntry) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO whitelist
             (sha256, name, description, trust_level, category, added_by, date_added)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                entry.sha256,
                entry.name,
                entry.description,
                entry.trust_level.as_str(),
                entry.category.as_str(),
                entry.added_by.as_str(),
                entry.date_added,
            ],
        )?;
        Ok(())
    }

    /// Remove a whitelist entry by SHA-256.
    pub fn remove_entry(&self, sha256: &str) -> Result<bool> {
        let rows = self
            .conn
            .execute("DELETE FROM whitelist WHERE sha256 = ?1", params![sha256])?;
        Ok(rows > 0)
    }

    /// List all whitelist entries.
    pub fn list_all(&self) -> Vec<WhitelistEntry> {
        let mut stmt = match self.conn.prepare(
            "SELECT sha256, name, description, trust_level, category, added_by, date_added
             FROM whitelist",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        stmt.query_map([], |row| {
            Ok(WhitelistEntry {
                sha256: row.get(0)?,
                name: row.get(1)?,
                description: row.get(2)?,
                trust_level: TrustLevel::from_str(&row.get::<_, String>(3)?),
                category: WhitelistCategory::from_str(&row.get::<_, String>(4)?),
                added_by: AddedBy::from_str(&row.get::<_, String>(5)?),
                date_added: row.get(6)?,
            })
        })
        .ok()
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }

    /// Import whitelist entries from a JSON file.
    pub fn import_json<P: AsRef<Path>>(&self, path: P) -> Result<usize> {
        let data = std::fs::read_to_string(path)?;
        let entries: Vec<WhitelistEntry> = serde_json::from_str(&data)?;
        let count = entries.len();
        for entry in &entries {
            self.add_entry(entry)?;
        }
        info!(count, "Imported whitelist entries from JSON");
        Ok(count)
    }

    /// Export all whitelist entries to a JSON file.
    pub fn export_json<P: AsRef<Path>>(&self, path: P) -> Result<usize> {
        let entries = self.list_all();
        let count = entries.len();
        let json = serde_json::to_string_pretty(&entries)?;
        std::fs::write(path, json)?;
        info!(count, "Exported whitelist entries to JSON");
        Ok(count)
    }

    /// Update the trust level for a given entry.
    pub fn update_trust_level(&self, sha256: &str, level: TrustLevel) -> Result<bool> {
        let rows = self.conn.execute(
            "UPDATE whitelist SET trust_level = ?1 WHERE sha256 = ?2",
            params![level.as_str(), sha256],
        )?;
        Ok(rows > 0)
    }
}
