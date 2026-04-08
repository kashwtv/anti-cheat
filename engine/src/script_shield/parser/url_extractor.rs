//! URL extraction from Lua scripts, including obfuscated URLs.

use regex::Regex;
use serde::{Deserialize, Serialize};

/// How a URL was extracted from the script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtractionMethod {
    /// Found as a plain `"https://..."` string literal.
    PlainText,
    /// Reconstructed from Lua `..` string concatenation.
    StringConcat,
    /// Decoded from `string.char(n, n, n, ...)`.
    StringChar,
    /// Decoded from `string.reverse("...")`.
    StringReverse,
    /// Decoded from a base64-encoded string.
    Base64Encoded,
    /// Decoded from hex escape sequences (`\xNN`).
    HexEncoded,
    /// Reconstructed from `table.concat({...})`.
    TableConcat,
    /// Partially resolved from `string.format(...)`.
    FormatString,
}

/// A URL extracted from a script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedUrl {
    /// The resolved URL string.
    pub url: String,
    /// How the URL was found.
    pub extraction_method: ExtractionMethod,
    /// The 1-based line number where the URL (or its encoding) was found.
    pub line_number: usize,
    /// Whether the URL was obfuscated in the source.
    pub is_obfuscated: bool,
    /// Confidence that this is a real URL (0.0 – 1.0).
    pub confidence: f64,
}

/// Extracts URLs from Lua scripts, handling various obfuscation techniques.
#[derive(Debug, Clone)]
pub struct UrlExtractor {
    url_re: Regex,
}

impl Default for UrlExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl UrlExtractor {
    /// Create a new `UrlExtractor`.
    pub fn new() -> Self {
        Self {
            url_re: Regex::new(r#"https?://[^\s"'`,\)\]\}]+"#).expect("valid regex"),
        }
    }

    /// Extract all URLs from a Lua script using multiple strategies.
    pub fn extract_urls(&self, script: &str) -> Vec<ExtractedUrl> {
        let mut urls = Vec::new();

        self.extract_plain_urls(script, &mut urls);
        self.extract_concat_urls(script, &mut urls);
        self.extract_string_char_urls(script, &mut urls);
        self.extract_string_reverse_urls(script, &mut urls);
        self.extract_base64_urls(script, &mut urls);
        self.extract_hex_urls(script, &mut urls);
        self.extract_table_concat_urls(script, &mut urls);
        self.extract_format_string_urls(script, &mut urls);

        // Deduplicate by URL string, keeping the highest-confidence entry.
        urls.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        let mut seen = std::collections::HashSet::new();
        urls.retain(|u| seen.insert(u.url.clone()));

        urls
    }

    // ------------------------------------------------------------------
    // Plain text URLs
    // ------------------------------------------------------------------

    fn extract_plain_urls(&self, script: &str, out: &mut Vec<ExtractedUrl>) {
        for (line_idx, line) in script.lines().enumerate() {
            for m in self.url_re.find_iter(line) {
                out.push(ExtractedUrl {
                    url: m.as_str().to_string(),
                    extraction_method: ExtractionMethod::PlainText,
                    line_number: line_idx + 1,
                    is_obfuscated: false,
                    confidence: 1.0,
                });
            }
        }
    }

    // ------------------------------------------------------------------
    // String concatenation: "https://ex" .. "ample.com/" .. "path"
    // ------------------------------------------------------------------

    fn extract_concat_urls(&self, script: &str, out: &mut Vec<ExtractedUrl>) {
        let concat_re = Regex::new(
            r#"(["'][^"']*["']\s*\.\.\s*){1,}["'][^"']*["']"#,
        )
        .expect("valid regex");
        let part_re = Regex::new(r#"["']([^"']*)["']"#).expect("valid regex");

        for (line_idx, line) in script.lines().enumerate() {
            for m in concat_re.find_iter(line) {
                let full_match = m.as_str();
                let mut assembled = String::new();
                for cap in part_re.captures_iter(full_match) {
                    if let Some(s) = cap.get(1) {
                        assembled.push_str(s.as_str());
                    }
                }
                if let Some(url) = self.find_url_in(&assembled) {
                    out.push(ExtractedUrl {
                        url,
                        extraction_method: ExtractionMethod::StringConcat,
                        line_number: line_idx + 1,
                        is_obfuscated: true,
                        confidence: 0.95,
                    });
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // string.char(104, 116, 116, 112, ...) encoding
    // ------------------------------------------------------------------

    fn extract_string_char_urls(&self, script: &str, out: &mut Vec<ExtractedUrl>) {
        let char_re = Regex::new(r"string\s*\.\s*char\s*\(([0-9,\s]+)\)").expect("valid regex");

        for (line_idx, line) in script.lines().enumerate() {
            for cap in char_re.captures_iter(line) {
                if let Some(args) = cap.get(1) {
                    let decoded: String = args
                        .as_str()
                        .split(',')
                        .filter_map(|s| {
                            s.trim()
                                .parse::<u32>()
                                .ok()
                                .and_then(char::from_u32)
                        })
                        .collect();

                    if let Some(url) = self.find_url_in(&decoded) {
                        out.push(ExtractedUrl {
                            url,
                            extraction_method: ExtractionMethod::StringChar,
                            line_number: line_idx + 1,
                            is_obfuscated: true,
                            confidence: 0.9,
                        });
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // string.reverse("...") decoding
    // ------------------------------------------------------------------

    fn extract_string_reverse_urls(&self, script: &str, out: &mut Vec<ExtractedUrl>) {
        let rev_re =
            Regex::new(r#"string\s*\.\s*reverse\s*\(\s*["']([^"']+)["']\s*\)"#).expect("valid regex");

        for (line_idx, line) in script.lines().enumerate() {
            for cap in rev_re.captures_iter(line) {
                if let Some(m) = cap.get(1) {
                    let reversed: String = m.as_str().chars().rev().collect();
                    if let Some(url) = self.find_url_in(&reversed) {
                        out.push(ExtractedUrl {
                            url,
                            extraction_method: ExtractionMethod::StringReverse,
                            line_number: line_idx + 1,
                            is_obfuscated: true,
                            confidence: 0.9,
                        });
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Base64-encoded URLs
    // ------------------------------------------------------------------

    fn extract_base64_urls(&self, script: &str, out: &mut Vec<ExtractedUrl>) {
        // Look for base64 strings inside string literals that are at least
        // 16 chars long (a URL encoded in base64 is fairly long).
        let b64_re = Regex::new(r#"["']([A-Za-z0-9+/=]{16,})["']"#).expect("valid regex");

        for (line_idx, line) in script.lines().enumerate() {
            for cap in b64_re.captures_iter(line) {
                if let Some(m) = cap.get(1) {
                    if let Ok(decoded_bytes) =
                        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, m.as_str())
                    {
                        if let Ok(decoded) = String::from_utf8(decoded_bytes) {
                            if let Some(url) = self.find_url_in(&decoded) {
                                out.push(ExtractedUrl {
                                    url,
                                    extraction_method: ExtractionMethod::Base64Encoded,
                                    line_number: line_idx + 1,
                                    is_obfuscated: true,
                                    confidence: 0.85,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Hex escape sequences: "\x68\x74\x74\x70\x73\x3a\x2f\x2f"
    // ------------------------------------------------------------------

    fn extract_hex_urls(&self, script: &str, out: &mut Vec<ExtractedUrl>) {
        let hex_string_re =
            Regex::new(r#"["']((?:\\x[0-9a-fA-F]{2})+)["']"#).expect("valid regex");
        let hex_byte_re = Regex::new(r"\\x([0-9a-fA-F]{2})").expect("valid regex");

        for (line_idx, line) in script.lines().enumerate() {
            for cap in hex_string_re.captures_iter(line) {
                if let Some(m) = cap.get(1) {
                    let bytes: Vec<u8> = hex_byte_re
                        .captures_iter(m.as_str())
                        .filter_map(|hc| {
                            hc.get(1)
                                .and_then(|h| u8::from_str_radix(h.as_str(), 16).ok())
                        })
                        .collect();

                    if let Ok(decoded) = String::from_utf8(bytes) {
                        if let Some(url) = self.find_url_in(&decoded) {
                            out.push(ExtractedUrl {
                                url,
                                extraction_method: ExtractionMethod::HexEncoded,
                                line_number: line_idx + 1,
                                is_obfuscated: true,
                                confidence: 0.9,
                            });
                        }
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // table.concat({"https://", "example", ".com/"})
    // ------------------------------------------------------------------

    fn extract_table_concat_urls(&self, script: &str, out: &mut Vec<ExtractedUrl>) {
        let tc_re = Regex::new(
            r#"table\s*\.\s*concat\s*\(\s*\{([^}]*)\}\s*\)"#,
        )
        .expect("valid regex");
        let part_re = Regex::new(r#"["']([^"']*)["']"#).expect("valid regex");

        for (line_idx, line) in script.lines().enumerate() {
            for cap in tc_re.captures_iter(line) {
                if let Some(inner) = cap.get(1) {
                    let mut assembled = String::new();
                    for pcap in part_re.captures_iter(inner.as_str()) {
                        if let Some(s) = pcap.get(1) {
                            assembled.push_str(s.as_str());
                        }
                    }
                    if let Some(url) = self.find_url_in(&assembled) {
                        out.push(ExtractedUrl {
                            url,
                            extraction_method: ExtractionMethod::TableConcat,
                            line_number: line_idx + 1,
                            is_obfuscated: true,
                            confidence: 0.85,
                        });
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // string.format("https://%s/%s", domain, path)
    // ------------------------------------------------------------------

    fn extract_format_string_urls(&self, script: &str, out: &mut Vec<ExtractedUrl>) {
        let fmt_re = Regex::new(
            r#"string\s*\.\s*format\s*\(\s*["']([^"']+)["']\s*(?:,\s*["']([^"']+)["']\s*)*\)"#,
        )
        .expect("valid regex");

        for (line_idx, line) in script.lines().enumerate() {
            for cap in fmt_re.captures_iter(line) {
                if let Some(format_str) = cap.get(1) {
                    let mut result = format_str.as_str().to_string();

                    // Collect all string literal arguments.
                    let args_re = Regex::new(r#"["']([^"']+)["']"#).expect("valid regex");
                    let full_match = cap.get(0).unwrap().as_str();

                    // Skip the first string (the format string itself).
                    let arg_values: Vec<String> = args_re
                        .captures_iter(full_match)
                        .skip(1)
                        .filter_map(|ac| ac.get(1).map(|m| m.as_str().to_string()))
                        .collect();

                    // Replace %s placeholders with captured string arguments.
                    for arg in &arg_values {
                        if let Some(pos) = result.find("%s") {
                            result.replace_range(pos..pos + 2, arg);
                        }
                    }

                    if let Some(url) = self.find_url_in(&result) {
                        // Only report if we actually resolved at least one placeholder.
                        let is_obfuscated = !arg_values.is_empty();
                        out.push(ExtractedUrl {
                            url,
                            extraction_method: ExtractionMethod::FormatString,
                            line_number: line_idx + 1,
                            is_obfuscated,
                            confidence: if is_obfuscated { 0.75 } else { 0.9 },
                        });
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// Search for an HTTP(S) URL within a decoded/assembled string.
    fn find_url_in(&self, text: &str) -> Option<String> {
        self.url_re.find(text).map(|m| m.as_str().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_url() {
        let ext = UrlExtractor::new();
        let urls = ext.extract_urls(r#"local u = "https://example.com/payload.lua""#);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].url, "https://example.com/payload.lua");
        assert_eq!(urls[0].extraction_method, ExtractionMethod::PlainText);
        assert!(!urls[0].is_obfuscated);
    }

    #[test]
    fn test_string_concat() {
        let ext = UrlExtractor::new();
        let script = r#"local u = "https://exam" .. "ple.com/" .. "script.lua""#;
        let urls = ext.extract_urls(script);
        assert!(urls.iter().any(|u| u.url == "https://example.com/script.lua"
            && u.extraction_method == ExtractionMethod::StringConcat));
    }

    #[test]
    fn test_string_char() {
        let ext = UrlExtractor::new();
        // "https://" encoded as char codes
        let script = "local u = string.char(104,116,116,112,115,58,47,47,101,120,46,99,111,109)";
        let urls = ext.extract_urls(script);
        assert!(urls.iter().any(|u| u.url.starts_with("https://")
            && u.extraction_method == ExtractionMethod::StringChar));
    }

    #[test]
    fn test_string_reverse() {
        let ext = UrlExtractor::new();
        let script = r#"local u = string.reverse("moc.elpmaxe//:sptth")"#;
        let urls = ext.extract_urls(script);
        assert!(urls.iter().any(|u| u.url == "https://example.com"
            && u.extraction_method == ExtractionMethod::StringReverse));
    }

    #[test]
    fn test_hex_encoded() {
        let ext = UrlExtractor::new();
        // "https://x.co" in hex
        let script = r#"local u = "\x68\x74\x74\x70\x73\x3a\x2f\x2f\x78\x2e\x63\x6f""#;
        let urls = ext.extract_urls(script);
        assert!(urls.iter().any(|u| u.extraction_method == ExtractionMethod::HexEncoded));
    }

    #[test]
    fn test_table_concat() {
        let ext = UrlExtractor::new();
        let script = r#"local u = table.concat({"https://", "example", ".com/", "path"})"#;
        let urls = ext.extract_urls(script);
        assert!(urls.iter().any(|u| u.url == "https://example.com/path"
            && u.extraction_method == ExtractionMethod::TableConcat));
    }

    #[test]
    fn test_base64_encoded() {
        let ext = UrlExtractor::new();
        // base64 of "https://evil.com/payload"
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "https://evil.com/payload",
        );
        let script = format!(r#"local u = "{}""#, encoded);
        let urls = ext.extract_urls(&script);
        assert!(urls.iter().any(|u| u.url == "https://evil.com/payload"
            && u.extraction_method == ExtractionMethod::Base64Encoded));
    }

    #[test]
    fn test_no_duplicates() {
        let ext = UrlExtractor::new();
        let script = r#"local u = "https://example.com""#;
        let urls = ext.extract_urls(script);
        let unique: std::collections::HashSet<_> = urls.iter().map(|u| &u.url).collect();
        assert_eq!(unique.len(), urls.len());
    }
}
