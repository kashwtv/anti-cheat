use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeobLevel { None, Partial, Full }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeobfuscationResult {
    pub deobfuscated_code: String,
    pub hidden_urls: Vec<String>,
    pub hidden_api_calls: Vec<String>,
    pub obfuscator_name: Option<String>,
    pub deobfuscation_level: DeobLevel,
}

#[derive(Debug, Clone)]
pub struct LuaDeobfuscator;

impl Default for LuaDeobfuscator {
    fn default() -> Self { Self::new() }
}

impl LuaDeobfuscator {
    pub fn new() -> Self { Self }

    pub fn deobfuscate(&self, script: &str) -> DeobfuscationResult {
        let mut code = script.to_string();
        let mut hidden_urls = Vec::new();
        let mut hidden_api_calls = Vec::new();
        let mut level = DeobLevel::None;

        // Detect obfuscator
        let obfuscator_name = self.detect_obfuscator(script);

        // Resolve string.char sequences
        let char_re = Regex::new(r"string\.char\(([0-9,\s]+)\)").unwrap();
        let mut had_replacements = false;
        let new_code = char_re.replace_all(&code, |caps: &regex::Captures| {
            had_replacements = true;
            let decoded: String = caps[1].split(',')
                .filter_map(|n| n.trim().parse::<u8>().ok())
                .map(|b| b as char)
                .collect();
            if decoded.contains("http") {
                hidden_urls.push(decoded.clone());
            }
            format!("\"{}\"", decoded)
        }).to_string();
        if had_replacements { code = new_code; level = DeobLevel::Partial; }

        // Resolve hex escape sequences in strings
        let hex_re = Regex::new(r#""((?:\\x[0-9a-fA-F]{2})+)""#).unwrap();
        let new_code = hex_re.replace_all(&code, |caps: &regex::Captures| {
            let inner_re = Regex::new(r"\\x([0-9a-fA-F]{2})").unwrap();
            let decoded: String = inner_re.captures_iter(&caps[1])
                .filter_map(|c| c.get(1))
                .filter_map(|h| u8::from_str_radix(h.as_str(), 16).ok())
                .map(|b| b as char)
                .collect();
            if decoded.contains("http") { hidden_urls.push(decoded.clone()); }
            level = DeobLevel::Partial;
            format!("\"{}\"", decoded)
        }).to_string();
        code = new_code;

        // Resolve string.reverse calls
        let rev_re = Regex::new(r#"string\.reverse\(\s*"([^"]*)"\s*\)"#).unwrap();
        let new_code = rev_re.replace_all(&code, |caps: &regex::Captures| {
            let reversed: String = caps[1].chars().rev().collect();
            if reversed.contains("http") { hidden_urls.push(reversed.clone()); }
            level = DeobLevel::Partial;
            format!("\"{}\"", reversed)
        }).to_string();
        code = new_code;

        // Resolve simple string concatenation
        let concat_re = Regex::new(r#""([^"]*)"\s*\.\.\s*"([^"]*)""#).unwrap();
        loop {
            let new_code = concat_re.replace_all(&code, |caps: &regex::Captures| {
                level = DeobLevel::Partial;
                format!("\"{}{}\"", &caps[1], &caps[2])
            }).to_string();
            if new_code == code { break; }
            code = new_code;
        }

        // Extract API calls from deobfuscated code
        let api_patterns = ["loadstring", "HttpGet", "GetAsync", "writefile", "os.execute", "io.popen"];
        for pat in &api_patterns {
            if code.contains(pat) && !script.contains(pat) {
                hidden_api_calls.push(pat.to_string());
            }
        }

        // Extract any URLs that appeared after deobfuscation
        let url_re = Regex::new(r#"https?://[^\s<>'"]+"#).unwrap();
        for m in url_re.find_iter(&code) {
            let url = m.as_str().to_string();
            if !hidden_urls.contains(&url) {
                hidden_urls.push(url);
            }
        }

        DeobfuscationResult {
            deobfuscated_code: code,
            hidden_urls,
            hidden_api_calls,
            obfuscator_name,
            deobfuscation_level: level,
        }
    }

    fn detect_obfuscator(&self, script: &str) -> Option<String> {
        // Luraph: very long lines, specific patterns
        if script.lines().any(|l| l.len() > 5000) && script.contains("(function()") {
            return Some("Luraph (suspected)".into());
        }
        // Ironbrew 2
        if script.contains("IB_") || script.contains("Ironbrew") {
            return Some("Ironbrew 2".into());
        }
        // Moonsec
        if script.contains("Moonsec") || (script.contains("moon_") && script.contains("v2")) {
            return Some("Moonsec".into());
        }
        // PSU/Prometheus
        if script.contains("PSU") || script.contains("Prometheus") {
            return Some("PSU/Prometheus".into());
        }
        None
    }
}
