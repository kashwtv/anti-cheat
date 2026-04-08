//! Script Shield: parses, fetches, and analyzes Lua/PowerShell/etc cheat scripts
//! and the URLs they download from.
//!
//! Cheat distribution typically uses a "loadstring + HttpGet" pattern: a small
//! Lua snippet downloads a script which downloads a payload which sometimes
//! drops an executable. Script Shield parses the loader, extracts and
//! deobfuscates URLs, safely fetches the chain of resources without executing
//! anything, and analyzes the payloads to determine whether the chain is a
//! benign cheat or actually malicious.

pub mod analyzer;
pub mod fetcher;
pub mod parser;
pub mod reputation;
pub mod report;

pub use analyzer::{PayloadAnalyzer, PayloadAnalysisReport};
pub use fetcher::{ChainEntry, FetchChainResult, FetchConfig, SafeFetcher};
pub use parser::{ParseResult, ScriptParser};
pub use reputation::{DomainReputation, ReputationDb, UrlRiskScorer, UrlVerdict};
pub use report::{ScriptReport, ScriptShieldReport};

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

/// Top-level Script Shield orchestrator.
///
/// Combines a [`ScriptParser`], [`SafeFetcher`], [`PayloadAnalyzer`] and
/// reputation database into a single entry point.
pub struct ScriptShield {
    parser: ScriptParser,
    fetcher: SafeFetcher,
    analyzer: PayloadAnalyzer,
    reputation: ReputationDb,
}

/// Configuration for the Script Shield.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptShieldConfig {
    /// Configuration for the safe fetcher.
    pub fetch: FetchConfig,
    /// Whether to follow URL chains discovered in payloads.
    pub follow_chain: bool,
}

impl Default for ScriptShieldConfig {
    fn default() -> Self {
        Self {
            fetch: FetchConfig::default(),
            follow_chain: true,
        }
    }
}

impl ScriptShield {
    /// Create a new Script Shield with the given configuration.
    pub fn new(config: ScriptShieldConfig) -> Result<Self> {
        let fetcher = SafeFetcher::new(config.fetch.clone())
            .context("failed to construct safe fetcher")?;
        Ok(Self {
            parser: ScriptParser::new(),
            fetcher,
            analyzer: PayloadAnalyzer::new(),
            reputation: ReputationDb::with_defaults(),
        })
    }

    /// Analyze a Lua script file from disk and (optionally) fetch any URLs it
    /// references.
    pub async fn analyze_file(
        &self,
        path: impl AsRef<Path>,
        follow_chain: bool,
    ) -> Result<ScriptShieldReport> {
        let path = path.as_ref();
        let script = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read script: {}", path.display()))?;
        self.analyze_text(&script, Some(path.display().to_string()), follow_chain)
            .await
    }

    /// Analyze a script's text content.
    pub async fn analyze_text(
        &self,
        script: &str,
        source: Option<String>,
        follow_chain: bool,
    ) -> Result<ScriptShieldReport> {
        info!("script shield analyzing script");

        let parse = self.parser.parse(script)?;
        let script_analysis = self.analyzer.analyze_script(script);

        // Score every extracted URL through the reputation database.
        let scorer = UrlRiskScorer::new(&self.reputation);
        let url_verdicts: Vec<UrlVerdict> = parse
            .urls
            .iter()
            .map(|u| scorer.score(&u.url))
            .collect();

        let chain = if follow_chain && !parse.urls.is_empty() {
            let urls: Vec<String> = parse.urls.iter().map(|u| u.url.clone()).collect();
            match self.fetcher.fetch_chain(urls).await {
                Ok(chain) => Some(chain),
                Err(e) => {
                    tracing::warn!(error = %e, "fetch chain failed");
                    None
                }
            }
        } else {
            None
        };

        Ok(report::build_report(
            source,
            parse,
            script_analysis,
            url_verdicts,
            chain,
        ))
    }

    /// Just fetch a list of URLs without parsing a host script.
    pub async fn fetch_urls(&self, urls: Vec<String>) -> Result<FetchChainResult> {
        self.fetcher.fetch_chain(urls).await
    }

    /// Access the reputation database.
    pub fn reputation(&self) -> &ReputationDb {
        &self.reputation
    }
}
