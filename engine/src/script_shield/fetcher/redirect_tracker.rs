//! HTTP redirect tracking for the Script Shield fetcher.
//!
//! Follows redirects manually, recording each hop and flagging suspicious patterns
//! such as URL shorteners, multiple domain changes, and redirects to raw IP addresses.

use std::collections::HashSet;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use tracing::debug;

/// A single redirect hop in a chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectHop {
    /// The URL that issued the redirect.
    pub from_url: String,
    /// The URL being redirected to.
    pub to_url: String,
    /// HTTP status code of the redirect response (e.g. 301, 302, 307, 308).
    pub status_code: u16,
    /// Position of this hop in the redirect chain (1-indexed).
    pub hop_number: u32,
}

/// Tracks HTTP redirects and detects suspicious redirect behaviour.
#[derive(Debug, Clone)]
pub struct RedirectTracker;

/// Well-known URL shortener domains.
const URL_SHORTENER_DOMAINS: &[&str] = &[
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
    "tiny.cc",
];

impl RedirectTracker {
    pub fn new() -> Self {
        Self
    }

    /// Follow redirects manually starting from `initial_url`, recording every hop.
    ///
    /// Returns the collected hops together with the final (non-redirect) response.
    /// The supplied `client` **must** have its redirect policy set to manual so that
    /// redirect responses are returned to us instead of being followed automatically.
    pub async fn track_redirects(
        &self,
        initial_url: &str,
        client: &reqwest::Client,
        max_hops: u32,
    ) -> Result<(Vec<RedirectHop>, reqwest::Response)> {
        let mut hops: Vec<RedirectHop> = Vec::new();
        let mut current_url = initial_url.to_string();
        let mut visited: HashSet<String> = HashSet::new();
        visited.insert(current_url.clone());

        loop {
            let response = client.get(&current_url).send().await?;
            let status = response.status();

            if !status.is_redirection() {
                return Ok((hops, response));
            }

            let hop_number = hops.len() as u32 + 1;
            if hop_number > max_hops {
                bail!(
                    "exceeded maximum number of redirects ({max_hops}) starting from {initial_url}"
                );
            }

            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            let to_url = match location {
                Some(loc) => resolve_redirect_url(&current_url, &loc)?,
                None => bail!("redirect response (HTTP {status}) without Location header"),
            };

            // Detect redirect loop.
            if visited.contains(&to_url) {
                bail!("redirect loop detected: {to_url} was already visited");
            }
            visited.insert(to_url.clone());

            debug!(
                from = %current_url,
                to = %to_url,
                status = status.as_u16(),
                hop = hop_number,
                "following redirect"
            );

            hops.push(RedirectHop {
                from_url: current_url.clone(),
                to_url: to_url.clone(),
                status_code: status.as_u16(),
                hop_number,
            });

            current_url = to_url;
        }
    }

    /// Analyse a completed redirect chain for suspicious patterns.
    pub fn flag_suspicious_patterns(hops: &[RedirectHop]) -> Vec<String> {
        let mut flags: Vec<String> = Vec::new();

        // Track unique domains across the chain.
        let mut domains: Vec<String> = Vec::new();

        for hop in hops {
            // Check for URL shortener usage.
            if let Some(domain) = extract_domain(&hop.from_url) {
                if is_url_shortener(&domain) {
                    flags.push(format!(
                        "hop {}: redirect from URL shortener domain '{domain}'",
                        hop.hop_number
                    ));
                }
                if !domains.contains(&domain) {
                    domains.push(domain);
                }
            }

            // Check if redirecting to a raw IP address.
            if let Some(domain) = extract_domain(&hop.to_url) {
                if is_ip_address(&domain) {
                    flags.push(format!(
                        "hop {}: redirect to raw IP address '{domain}'",
                        hop.hop_number
                    ));
                }
                if !domains.contains(&domain) {
                    domains.push(domain);
                }
            }
        }

        // Flag multiple domain changes (more than 2 unique domains is suspicious).
        if domains.len() > 2 {
            flags.push(format!(
                "redirect chain crosses {} different domains: {}",
                domains.len(),
                domains.join(" -> ")
            ));
        }

        flags
    }
}

/// Resolve a potentially relative redirect URL against the current URL.
fn resolve_redirect_url(current: &str, location: &str) -> Result<String> {
    if location.starts_with("http://") || location.starts_with("https://") {
        return Ok(location.to_string());
    }

    // Relative URL -- combine with the current URL's origin.
    let base = reqwest::Url::parse(current)?;
    let resolved = base.join(location)?;
    Ok(resolved.to_string())
}

/// Extract the host/domain portion of a URL.
fn extract_domain(url: &str) -> Option<String> {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_lowercase()))
}

/// Check whether a domain belongs to a known URL shortener service.
fn is_url_shortener(domain: &str) -> bool {
    URL_SHORTENER_DOMAINS
        .iter()
        .any(|&short| domain == short || domain.ends_with(&format!(".{short}")))
}

/// Heuristic check for whether a string looks like a raw IP address (v4 or v6).
fn is_ip_address(domain: &str) -> bool {
    // Strip surrounding brackets for IPv6 literals.
    let d = domain.trim_start_matches('[').trim_end_matches(']');
    d.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_url_shortener() {
        assert!(is_url_shortener("bit.ly"));
        assert!(is_url_shortener("tinyurl.com"));
        assert!(!is_url_shortener("example.com"));
    }

    #[test]
    fn test_is_ip_address() {
        assert!(is_ip_address("192.168.1.1"));
        assert!(is_ip_address("::1"));
        assert!(!is_ip_address("example.com"));
    }

    #[test]
    fn test_flag_suspicious_redirect_to_ip() {
        let hops = vec![RedirectHop {
            from_url: "https://example.com/dl".into(),
            to_url: "http://192.168.1.100/payload.exe".into(),
            status_code: 302,
            hop_number: 1,
        }];

        let flags = RedirectTracker::flag_suspicious_patterns(&hops);
        assert!(flags.iter().any(|f| f.contains("raw IP address")));
    }

    #[test]
    fn test_resolve_relative_url() {
        let resolved =
            resolve_redirect_url("https://example.com/dir/page", "/other/path").unwrap();
        assert_eq!(resolved, "https://example.com/other/path");
    }
}
