pub mod classifier;
pub mod confidence;
pub mod false_positive;
pub mod threat_level;

pub use classifier::{CheatInfo, CheatType, Classification, Classifier, MalwareInfo, MalwareType};
pub use confidence::{ConfidenceResult, ConfidenceScorer, ScanEvidence};
pub use false_positive::{FalsePositiveAnalyzer, FalsePositiveAssessment, FalsePositiveContext};
pub use threat_level::{
    DetectionFactor, RecommendedAction, ThreatInfo, ThreatLevel,
};

use tracing::debug;

/// Top-level detection engine that combines confidence scoring, classification,
/// and false-positive analysis into a final `ThreatInfo`.
pub struct DetectionEngine {
    scorer: ConfidenceScorer,
    classifier: Classifier,
    fp_analyzer: FalsePositiveAnalyzer,
}

impl DetectionEngine {
    pub fn new() -> Self {
        Self {
            scorer: ConfidenceScorer::new(),
            classifier: Classifier::new(),
            fp_analyzer: FalsePositiveAnalyzer::new(),
        }
    }

    /// Evaluate scan evidence and produce a final threat assessment.
    pub fn evaluate(&self, evidence: &ScanEvidence) -> ThreatInfo {
        let confidence = self.scorer.calculate_confidence(evidence);
        let classification = self.classifier.classify(evidence, &confidence);

        let fp_context = FalsePositiveContext::from_evidence(evidence);
        let fp_assessment = self.fp_analyzer.analyze(&confidence, &fp_context);

        // Adjust confidence based on false-positive analysis
        let adjusted_score = (confidence.overall_score as i32 + fp_assessment.confidence_adjustment)
            .max(0)
            .min(100) as u8;

        let threat_level = Self::determine_threat_level(adjusted_score, &classification);
        let threat_name = Self::determine_threat_name(&classification);
        let description = Self::build_description(&classification, &fp_assessment);
        let recommended_action = Self::determine_action(threat_level);

        let mut factors = Vec::new();
        for (name, weight, score) in &confidence.breakdown {
            if *score > 0.0 || *score < 0.0 {
                factors.push(DetectionFactor {
                    category: name.clone(),
                    description: format!("Weight: {:.0}%, Score: {:.0}", weight * 100.0, score),
                    severity: ((*score / 10.0).ceil() as u8).min(10).max(1),
                    is_cheat_related: name.contains("game"),
                });
            }
        }

        debug!(
            threat_level = %threat_level,
            adjusted_score,
            "detection evaluation complete"
        );

        ThreatInfo {
            threat_level,
            threat_name,
            description,
            confidence_score: adjusted_score,
            factors,
            recommended_action,
        }
    }

    fn determine_threat_level(score: u8, classification: &Classification) -> ThreatLevel {
        match classification {
            Classification::Benign => ThreatLevel::Clean,
            Classification::CheatTool(_) => ThreatLevel::CheatDetected,
            Classification::PotentiallyUnwanted => ThreatLevel::Suspicious,
            Classification::Unknown => {
                if score >= 50 {
                    ThreatLevel::Suspicious
                } else {
                    ThreatLevel::Clean
                }
            }
            Classification::Malware(info) => {
                if info.severity >= 7 || score >= 70 {
                    ThreatLevel::Malicious
                } else {
                    ThreatLevel::LikelyMalicious
                }
            }
        }
    }

    fn determine_threat_name(classification: &Classification) -> String {
        match classification {
            Classification::Benign => String::new(),
            Classification::CheatTool(info) => {
                format!("CheatTool.{:?}", info.cheat_type)
            }
            Classification::Malware(info) => {
                format!("Malware.{:?}", info.malware_type)
            }
            Classification::PotentiallyUnwanted => "PUA.Generic".into(),
            Classification::Unknown => "Unknown.Suspicious".into(),
        }
    }

    fn build_description(
        classification: &Classification,
        fp: &FalsePositiveAssessment,
    ) -> String {
        let base = match classification {
            Classification::Benign => "No threats detected.".into(),
            Classification::CheatTool(info) => {
                let games = if info.target_games.is_empty() {
                    "unknown games".to_string()
                } else {
                    info.target_games.join(", ")
                };
                format!(
                    "Cheat tool detected ({:?}). Targets: {}. {}",
                    info.cheat_type,
                    games,
                    if info.uses_injection { "Uses injection." } else { "" }
                )
            }
            Classification::Malware(info) => {
                format!(
                    "Malware detected ({:?}). Severity: {}/10. Capabilities: {}",
                    info.malware_type,
                    info.severity,
                    info.capabilities.join(", ")
                )
            }
            Classification::PotentiallyUnwanted => {
                "Potentially unwanted application detected.".into()
            }
            Classification::Unknown => "Suspicious file - manual review recommended.".into(),
        };

        if fp.is_likely_false_positive {
            format!("{} Note: Likely false positive - {}", base, fp.reasons.join("; "))
        } else {
            base
        }
    }

    fn determine_action(level: ThreatLevel) -> RecommendedAction {
        match level {
            ThreatLevel::Clean | ThreatLevel::CheatDetected => RecommendedAction::None,
            ThreatLevel::Suspicious => RecommendedAction::Review,
            ThreatLevel::LikelyMalicious => RecommendedAction::Quarantine,
            ThreatLevel::Malicious => RecommendedAction::Quarantine,
        }
    }
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::new()
    }
}
