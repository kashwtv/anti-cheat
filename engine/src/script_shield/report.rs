//! Report generation for Script Shield analyses.

use serde::{Deserialize, Serialize};

use super::analyzer::ScriptAnalysis;
use super::fetcher::FetchChainResult;
use super::parser::ParseResult;
use super::reputation::UrlVerdict;

/// A short single-script summary report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptReport {
    pub source: Option<String>,
    pub language: String,
    pub risk_score: u32,
    pub label: String,
    pub url_count: usize,
    pub api_call_count: usize,
    pub obfuscation_detected: bool,
    pub risk_indicators: Vec<String>,
}

/// Full Script Shield report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptShieldReport {
    pub source: Option<String>,
    pub parse: ParseResult,
    pub script_analysis: ScriptAnalysis,
    pub url_verdicts: Vec<UrlVerdict>,
    pub fetch_chain: Option<FetchChainResult>,
    pub overall_risk: u32,
    pub overall_label: String,
}

impl ScriptShieldReport {
    /// Build a short summary view.
    pub fn summary(&self) -> ScriptReport {
        ScriptReport {
            source: self.source.clone(),
            language: format!("{:?}", self.script_analysis.language),
            risk_score: self.overall_risk,
            label: self.overall_label.clone(),
            url_count: self.parse.urls.len(),
            api_call_count: self.parse.api_calls.len(),
            obfuscation_detected: self.parse.obfuscation_detected,
            risk_indicators: self.parse.risk_indicators.clone(),
        }
    }
}

/// Build a full report from intermediate analysis pieces.
pub fn build_report(
    source: Option<String>,
    parse: ParseResult,
    script_analysis: ScriptAnalysis,
    url_verdicts: Vec<UrlVerdict>,
    fetch_chain: Option<FetchChainResult>,
) -> ScriptShieldReport {
    let mut score = script_analysis.risk_score;

    // Boost score based on URL verdicts.
    let max_url_risk = url_verdicts.iter().map(|v| v.risk_score).max().unwrap_or(0);
    score = score.max(max_url_risk);

    // If the fetch chain found executables, escalate.
    if let Some(ref chain) = fetch_chain {
        if chain.malicious_count > 0 {
            score = score.max(85);
        }
    }

    let overall_label = match score {
        0..=20 => "Clean".to_string(),
        21..=40 => "Cheat / Low".to_string(),
        41..=60 => "Suspicious".to_string(),
        61..=80 => "Likely Malicious".to_string(),
        _ => "Malicious".to_string(),
    };

    ScriptShieldReport {
        source,
        parse,
        script_analysis,
        url_verdicts,
        fetch_chain,
        overall_risk: score.min(100),
        overall_label,
    }
}
