use std::fmt;

use serde::{Deserialize, Serialize};

/// Tiered alert levels for scan results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ThreatLevel {
    Clean,
    CheatDetected,
    Suspicious,
    LikelyMalicious,
    Malicious,
}

impl ThreatLevel {
    /// Returns the display color name associated with this threat level.
    pub fn color(&self) -> &'static str {
        match self {
            Self::Clean => "green",
            Self::CheatDetected => "blue",
            Self::Suspicious => "yellow",
            Self::LikelyMalicious => "orange",
            Self::Malicious => "red",
        }
    }

    /// Returns the colored indicator emoji for this threat level.
    pub fn indicator(&self) -> &'static str {
        match self {
            Self::Clean => "\u{1f7e2}",           // green circle
            Self::CheatDetected => "\u{1f535}",    // blue circle
            Self::Suspicious => "\u{1f7e1}",       // yellow circle
            Self::LikelyMalicious => "\u{1f7e0}",  // orange circle
            Self::Malicious => "\u{1f534}",         // red circle
        }
    }
}

impl fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Clean => "Clean",
            Self::CheatDetected => "Cheat Detected",
            Self::Suspicious => "Suspicious",
            Self::LikelyMalicious => "Likely Malicious",
            Self::Malicious => "Malicious",
        };
        write!(f, "{} {}", self.indicator(), label)
    }
}

/// A factor that contributed to the overall detection decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionFactor {
    /// High-level category (e.g. "import_analysis", "yara_match").
    pub category: String,
    /// Human-readable explanation.
    pub description: String,
    /// Severity on a 1-10 scale.
    pub severity: u8,
    /// Whether this factor is associated with cheat software rather than malware.
    pub is_cheat_related: bool,
}

/// Action the engine recommends to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecommendedAction {
    None,
    Review,
    Quarantine,
    Delete,
}

impl fmt::Display for RecommendedAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "No action required"),
            Self::Review => write!(f, "Manual review recommended"),
            Self::Quarantine => write!(f, "Quarantine recommended"),
            Self::Delete => write!(f, "Deletion recommended"),
        }
    }
}

/// Complete information about a detected threat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatInfo {
    pub threat_level: ThreatLevel,
    pub threat_name: String,
    pub description: String,
    /// Overall confidence in the classification, from 0 to 100.
    pub confidence_score: u8,
    /// Individual factors that contributed to this detection.
    pub factors: Vec<DetectionFactor>,
    pub recommended_action: RecommendedAction,
}

impl ThreatInfo {
    /// Build a clean result with no threat detected.
    pub fn clean() -> Self {
        Self {
            threat_level: ThreatLevel::Clean,
            threat_name: String::new(),
            description: "No threats detected.".into(),
            confidence_score: 100,
            factors: Vec::new(),
            recommended_action: RecommendedAction::None,
        }
    }
}

impl fmt::Display for ThreatInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] {} (confidence: {}%) - {}",
            self.threat_level,
            self.threat_name,
            self.description,
            self.confidence_score,
            self.recommended_action,
        )
    }
}
