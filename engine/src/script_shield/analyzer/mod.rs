//! Analyzer modules for Script Shield.
//!
//! Provides script analysis, behavior detection, and API classification
//! for downloaded payloads and Lua cheat scripts.

pub mod api_classifier;
pub mod behavior_detect;
pub mod script_analyzer;

pub use api_classifier::{ApiClassification, ApiClassifier, ApiVerdict};
pub use behavior_detect::{BehaviorCategory, BehaviorDetector, DetectedBehavior};
pub use script_analyzer::{
    BehaviorType, ExfilTarget, PayloadAnalysis, ScriptAnalysis, ScriptAnalyzer, ScriptBehavior,
    ScriptLanguage,
};

use serde::{Deserialize, Serialize};

/// High-level payload analyzer that orchestrates script analysis and behavior detection.
#[derive(Debug, Clone)]
pub struct PayloadAnalyzer {
    script_analyzer: ScriptAnalyzer,
    behavior_detector: BehaviorDetector,
}

impl Default for PayloadAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl PayloadAnalyzer {
    /// Create a new `PayloadAnalyzer`.
    pub fn new() -> Self {
        Self {
            script_analyzer: ScriptAnalyzer::new(),
            behavior_detector: BehaviorDetector::new(),
        }
    }

    /// Analyze a script's content and return a full analysis.
    pub fn analyze_script(&self, content: &str) -> ScriptAnalysis {
        self.script_analyzer.analyze(content)
    }

    /// Analyze a raw payload (binary or text) given its content type.
    pub fn analyze_payload(&self, content: &[u8], content_type: &str) -> PayloadAnalysis {
        self.script_analyzer.analyze_payload(content, content_type)
    }
}

/// Result of analyzing a raw payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadAnalysisReport {
    /// Whether the payload appears to be a script.
    pub is_script: bool,
    /// Script analysis if it is a script.
    pub script_analysis: Option<ScriptAnalysis>,
    /// Detected behaviors.
    pub behaviors: Vec<DetectedBehavior>,
    /// Overall risk score (0-100).
    pub risk_score: u32,
}
