//! Safe HTTP fetcher for Script Shield.
//!
//! Downloads the content that a URL points to **without** executing anything.
//! Tracks redirects manually, enforces size limits, and classifies the response
//! content type.

use std::collections::HashMap;
use std::time::Instant;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::redirect_tracker::{RedirectHop, RedirectTracker};
use super::FetchConfig;

/// Metadata and body returned from a safe fetch operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchResponse {
    /// HTTP status code of the final response.
    pub status_code: u16,
    /// Response headers as a flat string map.
    pub headers: HashMap<String, String>,
    /// The Content-Type header value (or empty string).
    pub content_type: String,
    /// Raw response body bytes.
    pub body: Vec<u8>,
    /// Body decoded as UTF-8 text (if valid).
    pub body_text: Option<String>,
    /// Size of the response body in bytes.
    pub size_bytes: u64,
    /// Redirect hops that were followed to reach the final URL.
    pub redirect_chain: Vec<RedirectHop>,
    /// Whether the content appears to be a native executable (PE, ELF, Mach-O).
    pub is_executable: bool,
    /// Whether the content appears to be a script (Lua, JS, Python, PowerShell, Batch, VBScript).
    pub is_script: bool,
    /// Whether the content appears to be an archive (ZIP, RAR, 7z, tar, gzip).
    pub is_archive: bool,
    /// Wall-clock time the fetch took, in milliseconds.
    pub fetch_duration_ms: u64,
}

/// The HTTP fetcher. Wraps a `reqwest::Client` configured for safe, non-executing downloads.
#[derive(Debug, Clone)]
pub struct HttpFetcher {
    client: reqwest::Client,
    redirect_tracker: RedirectTracker,
}

impl HttpFetcher {
    /// Build a new `HttpFetcher` whose client follows the constraints in `config`.
    pub fn new(config: &FetchConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            // We track redirects ourselves via RedirectTracker.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .user_agent("Mozilla/5.0 (compatible; AntiCheat-Scanner/1.0)")
            .build()?;

        Ok(Self {
            client,
            redirect_tracker: RedirectTracker::new(),
        })
    }

    /// Provide a reference to the underlying reqwest client (used by chain resolver).
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Safely fetch a single URL.
    ///
    /// * Checks the URL against `config.blocked_domains` before making any request.
    /// * Follows redirects manually (up to `config.max_redirects`), recording each hop.
    /// * Limits the downloaded body to `config.max_response_size` bytes.
    /// * **Never** executes any downloaded content.
    pub async fn fetch_url(&self, url: &str, config: &FetchConfig) -> Result<FetchResponse> {
        let start = Instant::now();

        // --- Domain block-list check ---
        if is_domain_blocked(url, &config.blocked_domains) {
            bail!("URL domain is on the block list: {url}");
        }

        // --- Follow redirects ---
        let (hops, response) = self
            .redirect_tracker
            .track_redirects(url, &self.client, config.max_redirects)
            .await?;

        // Log any suspicious redirect patterns.
        let suspicious = RedirectTracker::flag_suspicious_patterns(&hops);
        for flag in &suspicious {
            warn!(url, flag = %flag, "suspicious redirect pattern detected");
        }

        let status_code = response.status().as_u16();

        // --- Collect headers ---
        let mut headers: HashMap<String, String> = HashMap::new();
        for (name, value) in response.headers().iter() {
            if let Ok(v) = value.to_str() {
                headers.insert(name.to_string(), v.to_string());
            }
        }

        let content_type = headers
            .get("content-type")
            .cloned()
            .unwrap_or_default();

        // --- Read body with size limit ---
        let body = read_body_limited(response, config.max_response_size).await?;
        let size_bytes = body.len() as u64;

        debug!(
            url,
            status_code,
            size_bytes,
            content_type = %content_type,
            redirects = hops.len(),
            "fetch complete"
        );

        // --- Classify content ---
        let is_executable = detect_executable(&content_type, &body);
        let is_script = detect_script(&content_type, &body, url);
        let is_archive = detect_archive(&content_type, &body);

        // --- Attempt UTF-8 decode ---
        let body_text = if is_likely_text(&content_type, &body) {
            String::from_utf8(body.clone()).ok()
        } else {
            None
        };

        let fetch_duration_ms = start.elapsed().as_millis() as u64;

        Ok(FetchResponse {
            status_code,
            headers,
            content_type,
            body,
            body_text,
            size_bytes,
            redirect_chain: hops,
            is_executable,
            is_script,
            is_archive,
            fetch_duration_ms,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read the response body up to `max_bytes`, returning an error if the limit is exceeded.
async fn read_body_limited(response: reqwest::Response, max_bytes: u64) -> Result<Vec<u8>> {
    // If the server advertises a Content-Length that already exceeds our limit, bail early.
    if let Some(cl) = response.content_length() {
        if cl > max_bytes {
            bail!(
                "response Content-Length ({cl} bytes) exceeds the maximum allowed ({max_bytes} bytes)"
            );
        }
    }

    let bytes = response.bytes().await?;
    if bytes.len() as u64 > max_bytes {
        bail!(
            "response body ({} bytes) exceeds the maximum allowed ({max_bytes} bytes)",
            bytes.len()
        );
    }

    Ok(bytes.to_vec())
}

/// Check whether a URL's domain matches any entry in the blocked list.
fn is_domain_blocked(url: &str, blocked: &[String]) -> bool {
    let domain = match reqwest::Url::parse(url) {
        Ok(u) => u.host_str().unwrap_or_default().to_lowercase(),
        Err(_) => return false,
    };

    blocked.iter().any(|b| {
        let b_lower = b.to_lowercase();
        domain == b_lower || domain.ends_with(&format!(".{b_lower}"))
    })
}

// ---------------------------------------------------------------------------
// Content-type detection helpers
// ---------------------------------------------------------------------------

/// Detect native executables via Content-Type header and magic bytes.
fn detect_executable(content_type: &str, body: &[u8]) -> bool {
    let ct = content_type.to_lowercase();
    if ct.contains("application/x-msdownload")
        || ct.contains("application/x-dosexec")
        || ct.contains("application/x-executable")
        || ct.contains("application/vnd.microsoft.portable-executable")
        || ct.contains("application/x-mach-binary")
        || ct.contains("application/x-elf")
    {
        return true;
    }

    // Magic bytes: PE (MZ), ELF (\x7fELF), Mach-O (0xFEEDFACE / 0xFEEDFACF / 0xCAFEBABE).
    if body.len() >= 4 {
        if body.starts_with(b"MZ") {
            return true;
        }
        if body.starts_with(b"\x7fELF") {
            return true;
        }
        let magic32 = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        if matches!(magic32, 0xFEEDFACE | 0xFEEDFACF | 0xCAFEBABE | 0xCEFAEDFE | 0xCFFAEDFE) {
            return true;
        }
    }

    false
}

/// Detect scripts via Content-Type and shebang / common markers.
fn detect_script(content_type: &str, body: &[u8], url: &str) -> bool {
    let ct = content_type.to_lowercase();
    if ct.contains("text/javascript")
        || ct.contains("application/javascript")
        || ct.contains("application/x-javascript")
        || ct.contains("text/x-lua")
        || ct.contains("text/x-python")
        || ct.contains("application/x-python")
        || ct.contains("text/x-powershell")
        || ct.contains("application/x-powershell")
        || ct.contains("text/vbscript")
    {
        return true;
    }

    // Check URL extension.
    let lower_url = url.to_lowercase();
    let script_extensions = [
        ".lua", ".js", ".mjs", ".cjs", ".py", ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".wsf",
        ".wsh", ".sh", ".bash",
    ];
    if script_extensions.iter().any(|ext| lower_url.ends_with(ext)) {
        return true;
    }

    // Shebang detection.
    if body.len() >= 2 && body.starts_with(b"#!") {
        return true;
    }

    false
}

/// Detect archives via Content-Type and magic bytes.
fn detect_archive(content_type: &str, body: &[u8]) -> bool {
    let ct = content_type.to_lowercase();
    if ct.contains("application/zip")
        || ct.contains("application/x-zip")
        || ct.contains("application/x-rar")
        || ct.contains("application/x-7z")
        || ct.contains("application/gzip")
        || ct.contains("application/x-gzip")
        || ct.contains("application/x-tar")
        || ct.contains("application/x-bzip2")
        || ct.contains("application/x-xz")
    {
        return true;
    }

    // Magic bytes.
    if body.len() >= 4 {
        // ZIP (PK\x03\x04)
        if body.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
            return true;
        }
        // RAR (Rar!)
        if body.starts_with(b"Rar!") {
            return true;
        }
        // 7z (\x37\x7A\xBC\xAF)
        if body.len() >= 6 && body.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
            return true;
        }
        // GZIP (\x1F\x8B)
        if body.starts_with(&[0x1F, 0x8B]) {
            return true;
        }
    }

    false
}

/// Best-effort guess at whether the body is textual.
fn is_likely_text(content_type: &str, body: &[u8]) -> bool {
    let ct = content_type.to_lowercase();
    if ct.starts_with("text/") || ct.contains("json") || ct.contains("xml") || ct.contains("javascript") {
        return true;
    }
    // Heuristic: check first 512 bytes for non-text bytes.
    let sample = &body[..body.len().min(512)];
    sample.iter().all(|&b| b == b'\n' || b == b'\r' || b == b'\t' || (b >= 0x20 && b < 0x7F))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_domain_blocked() {
        let blocked = vec!["evil.com".to_string(), "malware.io".to_string()];
        assert!(is_domain_blocked("https://evil.com/payload", &blocked));
        assert!(is_domain_blocked("https://sub.evil.com/x", &blocked));
        assert!(!is_domain_blocked("https://example.com/x", &blocked));
    }

    #[test]
    fn test_detect_executable_pe() {
        let body = b"MZ\x90\x00\x03\x00\x00\x00";
        assert!(detect_executable("application/octet-stream", body));
    }

    #[test]
    fn test_detect_script_shebang() {
        let body = b"#!/usr/bin/env python3\nprint('hi')";
        assert!(detect_script("text/plain", body, "http://example.com/run"));
    }

    #[test]
    fn test_detect_archive_zip() {
        let body = &[0x50, 0x4B, 0x03, 0x04, 0x00, 0x00];
        assert!(detect_archive("application/octet-stream", body));
    }
}
