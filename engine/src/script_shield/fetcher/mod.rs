//! Script Shield fetcher module.
//!
//! Safely downloads what URLs point to **without** executing anything.
//! Follows download chains where script A downloads script B which downloads
//! an executable, building a tree of all discovered resources.

pub mod chain_resolver;
pub mod redirect_tracker;
pub mod safe_fetch;

pub use chain_resolver::{ChainResolver, ContentType};
pub use redirect_tracker::{RedirectHop, RedirectTracker};
pub use safe_fetch::{FetchResponse, HttpFetcher};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

/// Configuration for the safe fetcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchConfig {
    /// Maximum number of HTTP redirects to follow for a single URL.
    pub max_redirects: u32,
    /// Maximum depth when recursively following download chains.
    pub max_chain_depth: u32,
    /// Per-request timeout in seconds.
    pub timeout_secs: u64,
    /// Maximum response body size in bytes.
    pub max_response_size: u64,
    /// Domain block list -- URLs whose host matches any entry are refused.
    pub blocked_domains: Vec<String>,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            max_redirects: 5,
            max_chain_depth: 5,
            timeout_secs: 10,
            max_response_size: 50 * 1024 * 1024, // 50 MB
            blocked_domains: Vec::new(),
        }
    }
}

/// A single node in a download-chain tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEntry {
    /// The URL that was fetched.
    pub url: String,
    /// Depth in the download chain (0 = root).
    pub depth: u32,
    /// The fetch response, if the download succeeded.
    pub response: Option<FetchResponse>,
    /// Child entries discovered by parsing this response for further URLs.
    pub children: Vec<ChainEntry>,
    /// Error message, if the fetch or parsing failed.
    pub error: Option<String>,
}

/// Aggregated result of fetching an entire chain of URLs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchChainResult {
    /// The tree of chain entries (one root per initial URL).
    pub entries: Vec<ChainEntry>,
    /// Total number of unique URLs discovered across the chain.
    pub total_urls_found: usize,
    /// Number of URLs that were blocked by the domain block list.
    pub blocked_count: usize,
    /// Number of URLs whose content was classified as potentially malicious
    /// (executables or suspicious scripts).
    pub malicious_count: usize,
}

/// The main safe-fetcher facade.
///
/// Combines [`HttpFetcher`] and [`ChainResolver`] to download URL targets,
/// recursively parse scripts for further URLs, and produce a comprehensive
/// [`FetchChainResult`].
#[derive(Debug, Clone)]
pub struct SafeFetcher {
    config: FetchConfig,
    http_fetcher: HttpFetcher,
    chain_resolver: ChainResolver,
}

impl SafeFetcher {
    /// Create a new `SafeFetcher` with the given configuration.
    pub fn new(config: FetchConfig) -> Result<Self> {
        let http_fetcher = HttpFetcher::new(&config)?;
        let chain_resolver = ChainResolver::new();
        Ok(Self {
            config,
            http_fetcher,
            chain_resolver,
        })
    }

    /// Fetch all supplied URLs, recursively following download chains found in
    /// script content, and return an aggregated result.
    pub async fn fetch_chain(&self, urls: Vec<String>) -> Result<FetchChainResult> {
        info!(url_count = urls.len(), "starting fetch chain");

        let entries = self
            .chain_resolver
            .resolve_chain(urls, &self.http_fetcher, &self.config)
            .await?;

        // Walk the tree to compute summary statistics.
        let mut total_urls_found: usize = 0;
        let mut blocked_count: usize = 0;
        let mut malicious_count: usize = 0;

        fn walk(
            entry: &ChainEntry,
            total: &mut usize,
            blocked: &mut usize,
            malicious: &mut usize,
        ) {
            *total += 1;

            if let Some(ref err) = entry.error {
                if err.contains("block list") {
                    *blocked += 1;
                }
            }

            if let Some(ref resp) = entry.response {
                if resp.is_executable {
                    *malicious += 1;
                }
            }

            for child in &entry.children {
                walk(child, total, blocked, malicious);
            }
        }

        for entry in &entries {
            walk(entry, &mut total_urls_found, &mut blocked_count, &mut malicious_count);
        }

        info!(
            total_urls_found,
            blocked_count,
            malicious_count,
            "fetch chain complete"
        );

        Ok(FetchChainResult {
            entries,
            total_urls_found,
            blocked_count,
            malicious_count,
        })
    }

    /// Access the underlying configuration.
    pub fn config(&self) -> &FetchConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_config_defaults() {
        let config = FetchConfig::default();
        assert_eq!(config.max_redirects, 5);
        assert_eq!(config.max_chain_depth, 5);
        assert_eq!(config.timeout_secs, 10);
        assert_eq!(config.max_response_size, 50 * 1024 * 1024);
        assert!(config.blocked_domains.is_empty());
    }

    #[test]
    fn test_safe_fetcher_new() {
        let config = FetchConfig::default();
        let fetcher = SafeFetcher::new(config);
        assert!(fetcher.is_ok());
    }
}
