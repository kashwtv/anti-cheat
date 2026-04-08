use serde::{Deserialize, Serialize};

use super::confidence::{ConfidenceResult, ScanEvidence};

/// Context about the file's environment for false-positive analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositiveContext {
    pub is_in_game_directory: bool,
    pub targets_game_processes: bool,
    pub has_game_references: bool,
    pub user_override: bool,
}

impl FalsePositiveContext {
    pub fn from_evidence(evidence: &ScanEvidence) -> Self {
        Self {
            is_in_game_directory: false,
            targets_game_processes: evidence.targets_game_processes,
            has_game_references: evidence.targets_game_processes,
            user_override: false,
        }
    }
}

/// Result of false-positive analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositiveAssessment {
    pub is_likely_false_positive: bool,
    /// Adjustment to apply to the confidence score (negative = lower threat).
    pub confidence_adjustment: i32,
    pub reasons: Vec<String>,
}

/// Analyzes the likelihood of a detection being a false positive,
/// particularly important for cheat software.
#[derive(Debug, Clone)]
pub struct FalsePositiveAnalyzer;

impl FalsePositiveAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(
        &self,
        confidence: &ConfidenceResult,
        context: &FalsePositiveContext,
    ) -> FalsePositiveAssessment {
        let mut is_likely_fp = false;
        let mut adjustment: i32 = 0;
        let mut reasons = Vec::new();

        // If cheat score is much higher than malware score, likely a cheat not malware
        if confidence.cheat_score > confidence.malware_score + 15 {
            adjustment -= 10;
            reasons.push("Cheat indicators significantly outweigh malware indicators".into());
        }

        // Game directory context
        if context.is_in_game_directory {
            adjustment -= 8;
            reasons.push("File located in a game directory".into());
        }

        // Targets game processes exclusively
        if context.targets_game_processes && !context.has_game_references {
            adjustment -= 5;
            reasons.push("Targets game processes, not system processes".into());
        }

        // If user has manually overridden
        if context.user_override {
            is_likely_fp = true;
            adjustment -= 20;
            reasons.push("User has marked this file as safe".into());
        }

        // Determine if likely false positive
        if adjustment <= -15 || (confidence.cheat_score > 30 && confidence.malware_score < 20) {
            is_likely_fp = true;
        }

        FalsePositiveAssessment {
            is_likely_false_positive: is_likely_fp,
            confidence_adjustment: adjustment,
            reasons,
        }
    }
}

impl Default for FalsePositiveAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
