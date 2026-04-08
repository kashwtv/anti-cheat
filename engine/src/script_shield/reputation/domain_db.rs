//! Built-in domain reputation database.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// High-level reputation category for a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainCategory {
    /// Trusted source (GitHub raw, official Roblox, etc.)
    Trusted,
    /// Code-hosting / paste service that is commonly abused
    /// but not malicious by itself.
    CodeHost,
    /// Generic / unknown
    Unknown,
    /// Known bad - confirmed malware distribution.
    KnownBad,
    /// Suspicious - free hosting / dynamic DNS / cheap TLD.
    Suspicious,
}

/// Reputation entry for a single domain or domain suffix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainReputation {
    /// The domain or suffix.
    pub domain: String,
    /// Category.
    pub category: DomainCategory,
    /// Reputation score in `[-100, 100]`. Higher is better.
    pub score: i32,
    /// Optional notes.
    pub notes: String,
}

/// In-memory reputation database.
#[derive(Debug, Clone)]
pub struct ReputationDb {
    by_suffix: HashMap<String, DomainReputation>,
}

impl Default for ReputationDb {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl ReputationDb {
    /// Create an empty reputation database.
    pub fn empty() -> Self {
        Self {
            by_suffix: HashMap::new(),
        }
    }

    /// Create a new reputation database populated with built-in entries.
    pub fn with_defaults() -> Self {
        let mut db = Self::empty();
        for (domain, category, score, notes) in DEFAULT_ENTRIES {
            db.add(DomainReputation {
                domain: (*domain).to_string(),
                category: *category,
                score: *score,
                notes: (*notes).to_string(),
            });
        }
        db
    }

    /// Add or update a reputation entry.
    pub fn add(&mut self, entry: DomainReputation) {
        self.by_suffix.insert(entry.domain.to_lowercase(), entry);
    }

    /// Look up the most specific matching entry for a host.
    pub fn lookup(&self, host: &str) -> Option<&DomainReputation> {
        let host = host.to_lowercase();
        // Try exact match first, then progressively shorter suffixes.
        if let Some(entry) = self.by_suffix.get(&host) {
            return Some(entry);
        }
        let mut start = 0usize;
        while let Some(idx) = host[start..].find('.') {
            let suffix = &host[start + idx + 1..];
            if let Some(entry) = self.by_suffix.get(suffix) {
                return Some(entry);
            }
            start += idx + 1;
        }
        None
    }

    /// Total number of entries in the database.
    pub fn len(&self) -> usize {
        self.by_suffix.len()
    }

    /// True if the database is empty.
    pub fn is_empty(&self) -> bool {
        self.by_suffix.is_empty()
    }
}

const DEFAULT_ENTRIES: &[(&str, DomainCategory, i32, &str)] = &[
    // Trusted code hosts
    ("raw.githubusercontent.com", DomainCategory::Trusted, 80, "GitHub raw content"),
    ("github.com", DomainCategory::Trusted, 70, "GitHub"),
    ("gitlab.com", DomainCategory::Trusted, 70, "GitLab"),
    ("bitbucket.org", DomainCategory::Trusted, 60, "Bitbucket"),
    // Roblox official
    ("roblox.com", DomainCategory::Trusted, 90, "Roblox official"),
    ("rbxcdn.com", DomainCategory::Trusted, 80, "Roblox CDN"),
    // Pastebin services - frequently abused
    ("pastebin.com", DomainCategory::CodeHost, 20, "Pastebin - often abused"),
    ("paste.ee", DomainCategory::CodeHost, 10, "Paste.ee - often abused"),
    ("hastebin.com", DomainCategory::CodeHost, 20, "Hastebin"),
    ("ghostbin.co", DomainCategory::CodeHost, 0, "Ghostbin"),
    // Discord CDN - very common in malware distribution
    ("cdn.discordapp.com", DomainCategory::CodeHost, -10, "Discord CDN - heavily abused for malware"),
    ("media.discordapp.net", DomainCategory::CodeHost, -10, "Discord media - heavily abused"),
    // Suspicious free hosts and dynamic DNS
    ("000webhost.com", DomainCategory::Suspicious, -40, "Free hosting"),
    ("000webhostapp.com", DomainCategory::Suspicious, -40, "Free hosting"),
    ("herokuapp.com", DomainCategory::Suspicious, -20, "Heroku - often used for C2"),
    ("repl.co", DomainCategory::Suspicious, -20, "Replit hosting"),
    ("glitch.me", DomainCategory::Suspicious, -20, "Glitch hosting"),
    ("ngrok.io", DomainCategory::Suspicious, -50, "Ngrok tunnel - common C2"),
    ("trycloudflare.com", DomainCategory::Suspicious, -40, "Cloudflare tunnel - common C2"),
    ("duckdns.org", DomainCategory::Suspicious, -40, "Dynamic DNS"),
    ("no-ip.com", DomainCategory::Suspicious, -40, "Dynamic DNS"),
    // Telegram bot API (often used for exfil)
    ("api.telegram.org", DomainCategory::CodeHost, -20, "Telegram bot API - common exfil channel"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_exact() {
        let db = ReputationDb::with_defaults();
        let entry = db.lookup("raw.githubusercontent.com").unwrap();
        assert_eq!(entry.category, DomainCategory::Trusted);
    }

    #[test]
    fn test_lookup_subdomain() {
        let db = ReputationDb::with_defaults();
        let entry = db.lookup("foo.bar.github.com").unwrap();
        assert_eq!(entry.domain, "github.com");
    }

    #[test]
    fn test_lookup_unknown() {
        let db = ReputationDb::with_defaults();
        assert!(db.lookup("totally-random-host.example").is_none());
    }
}
