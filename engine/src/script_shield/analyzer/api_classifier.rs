//! Classifies Lua API calls by risk and intent.

use serde::{Deserialize, Serialize};

use crate::script_shield::parser::ApiCall;
use crate::script_shield::parser::lua_parser::ApiCategory;

/// A verdict assigned to a single API call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiVerdict {
    /// The call is benign in any context.
    Benign,
    /// The call is normal for cheats but suspicious in non-cheat contexts.
    CheatNormal,
    /// The call is suspicious regardless of context.
    Suspicious,
    /// The call is highly indicative of malicious intent.
    Malicious,
}

/// A single classified API call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiClassification {
    pub function_name: String,
    pub category: ApiCategory,
    pub verdict: ApiVerdict,
    pub reason: String,
}

/// Stateless API classifier.
#[derive(Debug, Clone, Default)]
pub struct ApiClassifier;

impl ApiClassifier {
    pub fn new() -> Self {
        Self
    }

    /// Classify a slice of API calls.
    pub fn classify(&self, calls: &[ApiCall]) -> Vec<ApiClassification> {
        calls.iter().map(|c| self.classify_one(c)).collect()
    }

    /// Classify a single API call.
    pub fn classify_one(&self, call: &ApiCall) -> ApiClassification {
        let (verdict, reason) = match call.category {
            ApiCategory::WebRequest => (
                ApiVerdict::CheatNormal,
                "Web request - normal for cheat loaders, suspicious otherwise".to_string(),
            ),
            ApiCategory::FileWrite => {
                if call
                    .args
                    .iter()
                    .any(|a| has_dangerous_extension(a))
                {
                    (
                        ApiVerdict::Malicious,
                        "Writes a file with an executable extension".to_string(),
                    )
                } else {
                    (
                        ApiVerdict::Suspicious,
                        "Writes to the file system".to_string(),
                    )
                }
            }
            ApiCategory::SystemCommand => (
                ApiVerdict::Malicious,
                "Executes a system command".to_string(),
            ),
            ApiCategory::ProcessManipulation => (
                ApiVerdict::CheatNormal,
                "Manipulates process / environment - typical of cheats".to_string(),
            ),
            ApiCategory::Persistence => (
                ApiVerdict::Malicious,
                "Establishes persistence on the system".to_string(),
            ),
            ApiCategory::DataExfiltration => (
                ApiVerdict::Malicious,
                "Exfiltrates data".to_string(),
            ),
            ApiCategory::Other => (ApiVerdict::Benign, "Uncategorized API call".to_string()),
        };

        ApiClassification {
            function_name: call.function_name.clone(),
            category: call.category.clone(),
            verdict,
            reason,
        }
    }

    /// Summarize a list of classifications into a single overall verdict.
    pub fn overall_verdict(classifications: &[ApiClassification]) -> ApiVerdict {
        let mut worst = ApiVerdict::Benign;
        for c in classifications {
            worst = worst_of(worst, c.verdict.clone());
        }
        worst
    }
}

fn has_dangerous_extension(s: &str) -> bool {
    let lower = s.to_lowercase();
    [".exe", ".dll", ".bat", ".cmd", ".scr", ".pif", ".vbs", ".ps1"]
        .iter()
        .any(|ext| lower.contains(ext))
}

fn worst_of(a: ApiVerdict, b: ApiVerdict) -> ApiVerdict {
    fn rank(v: &ApiVerdict) -> u8 {
        match v {
            ApiVerdict::Benign => 0,
            ApiVerdict::CheatNormal => 1,
            ApiVerdict::Suspicious => 2,
            ApiVerdict::Malicious => 3,
        }
    }
    if rank(&a) >= rank(&b) {
        a
    } else {
        b
    }
}
