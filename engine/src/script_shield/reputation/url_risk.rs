//! URL risk scoring combining domain reputation with URL structural analysis.

use serde::{Deserialize, Serialize};

use super::domain_db::{DomainCategory, ReputationDb};

/// A single factor contributing to a URL's risk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlRiskFactor {
    pub name: String,
    pub weight: i32,
}

/// Final verdict for a URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlVerdict {
    pub url: String,
    pub host: String,
    pub category: DomainCategory,
    /// Score in `[0, 100]`. Higher = riskier.
    pub risk_score: u32,
    pub factors: Vec<UrlRiskFactor>,
    pub label: String,
}

/// Stateless URL scorer that consults a [`ReputationDb`].
pub struct UrlRiskScorer<'a> {
    db: &'a ReputationDb,
}

impl<'a> UrlRiskScorer<'a> {
    pub fn new(db: &'a ReputationDb) -> Self {
        Self { db }
    }

    /// Score a URL.
    pub fn score(&self, url: &str) -> UrlVerdict {
        let host = extract_host(url).unwrap_or_default();
        let mut score: i32 = 30;
        let mut factors = Vec::new();
        let mut category = DomainCategory::Unknown;

        // Domain reputation lookup
        if let Some(entry) = self.db.lookup(&host) {
            category = entry.category;
            // Convert reputation score [-100, 100] to risk delta.
            // High reputation lowers risk; low reputation raises it.
            let delta = -entry.score / 2;
            score += delta;
            factors.push(UrlRiskFactor {
                name: format!("Domain reputation: {}", entry.domain),
                weight: delta,
            });
        } else {
            factors.push(UrlRiskFactor {
                name: "Unknown domain".to_string(),
                weight: 5,
            });
            score += 5;
        }

        // Suspicious TLDs
        let tld_score = score_tld(&host);
        if tld_score != 0 {
            score += tld_score;
            factors.push(UrlRiskFactor {
                name: "Suspicious TLD".to_string(),
                weight: tld_score,
            });
        }

        // IP address as host
        if is_ip_address(&host) {
            score += 25;
            factors.push(UrlRiskFactor {
                name: "Host is a raw IP address".to_string(),
                weight: 25,
            });
        }

        // URL shortener
        if is_shortener(&host) {
            score += 20;
            factors.push(UrlRiskFactor {
                name: "URL shortener".to_string(),
                weight: 20,
            });
        }

        // Long path / random-looking
        let path_score = score_path(url);
        if path_score != 0 {
            score += path_score;
            factors.push(UrlRiskFactor {
                name: "Suspicious path structure".to_string(),
                weight: path_score,
            });
        }

        // Discord CDN attachments are heavily abused
        if host.ends_with("discordapp.com") || host.ends_with("discordapp.net") {
            if url.contains("/attachments/") {
                score += 15;
                factors.push(UrlRiskFactor {
                    name: "Discord CDN attachment URL".to_string(),
                    weight: 15,
                });
            }
        }

        let risk_score = score.clamp(0, 100) as u32;
        let label = label_for(risk_score);

        UrlVerdict {
            url: url.to_string(),
            host,
            category,
            risk_score,
            factors,
            label,
        }
    }
}

fn extract_host(url: &str) -> Option<String> {
    // Strip scheme
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    // Take everything before the first '/', '?', or '#'
    let end = after_scheme
        .find(|c: char| c == '/' || c == '?' || c == '#')
        .unwrap_or(after_scheme.len());
    let host_port = &after_scheme[..end];
    // Strip port
    let host = host_port.split_once(':').map(|(h, _)| h).unwrap_or(host_port);
    if host.is_empty() {
        None
    } else {
        Some(host.to_lowercase())
    }
}

fn score_tld(host: &str) -> i32 {
    let suspicious_tlds = [
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".cyou", ".rest",
    ];
    for tld in &suspicious_tlds {
        if host.ends_with(tld) {
            return 15;
        }
    }
    0
}

fn is_ip_address(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

fn is_shortener(host: &str) -> bool {
    let shorteners = [
        "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "buff.ly", "adf.ly",
        "shorturl.at", "rebrand.ly", "cutt.ly",
    ];
    shorteners.iter().any(|s| host == *s || host.ends_with(&format!(".{}", s)))
}

fn score_path(url: &str) -> i32 {
    let after_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let path = match after_scheme.find('/') {
        Some(idx) => &after_scheme[idx..],
        None => return 0,
    };
    let mut score = 0;
    if path.len() > 80 {
        score += 5;
    }
    if path.contains(".exe") || path.contains(".dll") || path.contains(".scr") {
        score += 25;
    }
    if path.contains(".lua") {
        score += 5;
    }
    score
}

fn label_for(score: u32) -> String {
    match score {
        0..=20 => "Low".to_string(),
        21..=50 => "Medium".to_string(),
        51..=75 => "High".to_string(),
        _ => "Critical".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_host() {
        assert_eq!(
            extract_host("https://raw.githubusercontent.com/user/repo/main/x.lua"),
            Some("raw.githubusercontent.com".to_string())
        );
        assert_eq!(extract_host("http://1.2.3.4:8080/x"), Some("1.2.3.4".to_string()));
    }

    #[test]
    fn test_score_trusted() {
        let db = ReputationDb::with_defaults();
        let scorer = UrlRiskScorer::new(&db);
        let v = scorer.score("https://raw.githubusercontent.com/x/y/main/cheat.lua");
        assert!(v.risk_score < 30);
    }

    #[test]
    fn test_score_ip_with_exe() {
        let db = ReputationDb::with_defaults();
        let scorer = UrlRiskScorer::new(&db);
        let v = scorer.score("http://1.2.3.4/payload.exe");
        assert!(v.risk_score >= 50);
    }
}
