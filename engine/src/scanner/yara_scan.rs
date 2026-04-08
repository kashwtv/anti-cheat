//! Simplified YARA-like rule scanning engine.
//!
//! This module provides basic pattern matching inspired by YARA rules.  It
//! reads `.yar` files with a simplified syntax and performs string and hex-
//! pattern matching against file contents.
//!
//! **Note:** This is a stub implementation.  A production scanner should use a
//! full YARA library binding.

use std::path::Path;

use anyhow::{Context, Result};
use regex::bytes::Regex as BytesRegex;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument, trace, warn};

/// A single YARA-like rule loaded from a `.yar` file.
#[derive(Debug, Clone)]
pub struct YaraRule {
    /// Rule identifier (e.g. `suspicious_packer`).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Arbitrary tags attached to the rule.
    pub tags: Vec<String>,
    /// Patterns to search for in the file content.
    pub patterns: Vec<Pattern>,
}

/// A pattern that a rule attempts to match.
#[derive(Debug, Clone)]
pub enum Pattern {
    /// Plain text (case-insensitive search).
    Text(String),
    /// Hex byte sequence, e.g. `{ 4D 5A 90 00 }`.
    Hex(Vec<u8>),
    /// A regular expression applied to the raw bytes.
    Regex(String),
}

/// Information about a single matched string inside a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedString {
    /// Offset in the file where the match starts.
    pub offset: usize,
    /// The identifier or literal of the pattern that matched.
    pub identifier: String,
    /// The matched bytes (capped to a reasonable length).
    pub data: Vec<u8>,
}

/// The result of scanning a file with YARA-like rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub description: String,
    pub tags: Vec<String>,
    pub matched_strings: Vec<MatchedString>,
}

/// Scanner that loads and evaluates YARA-like rules.
#[derive(Debug)]
pub struct YaraScanner {
    rules: Vec<YaraRule>,
}

impl YaraScanner {
    /// Create an empty scanner (no rules loaded).
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Load all `.yar` files from the given directory.
    pub fn load_rules_dir(&mut self, rules_dir: impl AsRef<Path>) -> Result<usize> {
        let dir = rules_dir.as_ref();
        if !dir.is_dir() {
            warn!(path = %dir.display(), "rules directory does not exist");
            return Ok(0);
        }

        let mut count = 0usize;
        for entry in walkdir::WalkDir::new(dir)
            .min_depth(1)
            .max_depth(3)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "yar" || ext == "yara") {
                match self.load_rule_file(path) {
                    Ok(n) => count += n,
                    Err(e) => warn!(path = %path.display(), error = %e, "failed to parse rule file"),
                }
            }
        }

        debug!(count, "loaded YARA rules");
        Ok(count)
    }

    /// Scan a file against all loaded rules, returning every rule that matched.
    #[instrument(skip(self), fields(path = %path.as_ref().display()))]
    pub fn scan_file(&self, path: impl AsRef<Path>) -> Result<Vec<YaraMatch>> {
        let data = std::fs::read(path.as_ref())
            .with_context(|| format!("failed to read file: {}", path.as_ref().display()))?;

        let mut matches = Vec::new();

        for rule in &self.rules {
            let matched_strings = self.match_rule(rule, &data);
            if !matched_strings.is_empty() {
                debug!(rule = %rule.name, hit_count = matched_strings.len(), "YARA rule matched");
                matches.push(YaraMatch {
                    rule_name: rule.name.clone(),
                    description: rule.description.clone(),
                    tags: rule.tags.clone(),
                    matched_strings,
                });
            }
        }

        Ok(matches)
    }

    /// Return the number of currently loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Get the paths that were loaded (useful for diagnostics).
    pub fn rules(&self) -> &[YaraRule] {
        &self.rules
    }

    // ---- internals -------------------------------------------------------

    /// Parse a simplified `.yar` file and append the extracted rules.
    ///
    /// Simplified syntax recognised:
    /// ```text
    /// rule <name> : <tag1> <tag2> {
    ///     meta:
    ///         description = "some text"
    ///     strings:
    ///         $s1 = "plain text"
    ///         $h1 = { 4D 5A 90 }
    ///         $r1 = /regex/
    ///     condition:
    ///         any of them
    /// }
    /// ```
    fn load_rule_file(&mut self, path: &Path) -> Result<usize> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read rule file: {}", path.display()))?;

        let mut count = 0usize;
        let mut chars = content.chars().peekable();

        while let Some(rule) = Self::parse_next_rule(&mut chars) {
            self.rules.push(rule);
            count += 1;
        }

        Ok(count)
    }

    fn parse_next_rule(
        chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    ) -> Option<YaraRule> {
        // Advance to the keyword `rule`.
        let remaining: String = chars.clone().collect();
        let rule_start = remaining.find("rule ")?;
        // Skip to just past "rule "
        for _ in 0..(rule_start + 5) {
            chars.next();
        }

        // Collect name and tags.
        let header: String = chars
            .by_ref()
            .take_while(|&c| c != '{')
            .collect();

        let (name, tags) = Self::parse_header(&header);

        // Collect body up to the closing `}`.
        let mut depth = 1u32;
        let mut body = String::new();
        for c in chars.by_ref() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            body.push(c);
        }

        let description = Self::extract_meta_description(&body);
        let patterns = Self::extract_patterns(&body);

        Some(YaraRule {
            name,
            description,
            tags,
            patterns,
        })
    }

    fn parse_header(header: &str) -> (String, Vec<String>) {
        let header = header.trim();
        if let Some(idx) = header.find(':') {
            let name = header[..idx].trim().to_string();
            let tags = header[idx + 1..]
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            (name, tags)
        } else {
            (header.split_whitespace().next().unwrap_or("unknown").to_string(), Vec::new())
        }
    }

    fn extract_meta_description(body: &str) -> String {
        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("description") {
                if let Some(idx) = trimmed.find('=') {
                    let val = trimmed[idx + 1..].trim().trim_matches('"');
                    return val.to_string();
                }
            }
        }
        String::new()
    }

    fn extract_patterns(body: &str) -> Vec<Pattern> {
        let mut patterns = Vec::new();
        let mut in_strings = false;

        for line in body.lines() {
            let trimmed = line.trim();

            if trimmed.starts_with("strings:") {
                in_strings = true;
                continue;
            }
            if trimmed.starts_with("condition:") || trimmed.starts_with("meta:") {
                in_strings = false;
                continue;
            }

            if !in_strings {
                continue;
            }

            // $identifier = <value>
            if let Some(eq_idx) = trimmed.find('=') {
                let value = trimmed[eq_idx + 1..].trim();

                if value.starts_with('{') && value.ends_with('}') {
                    // Hex pattern.
                    let hex_str = value[1..value.len() - 1].trim();
                    if let Some(bytes) = Self::parse_hex_pattern(hex_str) {
                        patterns.push(Pattern::Hex(bytes));
                    }
                } else if value.starts_with('/') && value.len() > 2 {
                    // Regex pattern: strip leading and trailing `/`.
                    let end = value.rfind('/').unwrap_or(value.len());
                    if end > 0 {
                        let regex_str = &value[1..end];
                        patterns.push(Pattern::Regex(regex_str.to_string()));
                    }
                } else if value.starts_with('"') && value.ends_with('"') {
                    // Plain text.
                    let text = &value[1..value.len() - 1];
                    patterns.push(Pattern::Text(text.to_string()));
                }
            }
        }

        patterns
    }

    fn parse_hex_pattern(hex_str: &str) -> Option<Vec<u8>> {
        let tokens: Vec<&str> = hex_str.split_whitespace().collect();
        let mut bytes = Vec::with_capacity(tokens.len());
        for tok in tokens {
            if tok == "??" {
                // Wildcard byte -- not supported in this stub, skip.
                continue;
            }
            match u8::from_str_radix(tok, 16) {
                Ok(b) => bytes.push(b),
                Err(_) => {
                    trace!(token = tok, "ignoring non-hex token in pattern");
                    continue;
                }
            }
        }
        if bytes.is_empty() {
            None
        } else {
            Some(bytes)
        }
    }

    fn match_rule(&self, rule: &YaraRule, data: &[u8]) -> Vec<MatchedString> {
        let mut hits = Vec::new();
        let max_data_capture = 64;

        for (idx, pattern) in rule.patterns.iter().enumerate() {
            match pattern {
                Pattern::Text(text) => {
                    let lower_text = text.to_lowercase();
                    let lower_text_bytes = lower_text.as_bytes();
                    let lower_data: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();

                    let mut start = 0;
                    while let Some(pos) = Self::find_subsequence(&lower_data[start..], lower_text_bytes)
                    {
                        let abs = start + pos;
                        let end = (abs + text.len()).min(data.len());
                        hits.push(MatchedString {
                            offset: abs,
                            identifier: format!("$s{}", idx),
                            data: data[abs..end.min(abs + max_data_capture)].to_vec(),
                        });
                        start = abs + 1;
                    }
                }
                Pattern::Hex(bytes) => {
                    let mut start = 0;
                    while let Some(pos) = Self::find_subsequence(&data[start..], bytes) {
                        let abs = start + pos;
                        let end = (abs + bytes.len()).min(data.len());
                        hits.push(MatchedString {
                            offset: abs,
                            identifier: format!("$h{}", idx),
                            data: data[abs..end.min(abs + max_data_capture)].to_vec(),
                        });
                        start = abs + 1;
                    }
                }
                Pattern::Regex(re_str) => {
                    if let Ok(re) = BytesRegex::new(re_str) {
                        for m in re.find_iter(data) {
                            let captured = &data[m.start()..m.end().min(m.start() + max_data_capture)];
                            hits.push(MatchedString {
                                offset: m.start(),
                                identifier: format!("$r{}", idx),
                                data: captured.to_vec(),
                            });
                        }
                    }
                }
            }
        }

        hits
    }

    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }
}

impl Default for YaraScanner {
    fn default() -> Self {
        Self::new()
    }
}
