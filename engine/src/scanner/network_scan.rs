use std::path::Path;

use anyhow::{Context, Result};
use regex::bytes::Regex as BytesRegex;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Network-related indicators extracted from a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIndicators {
    pub urls: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub domains: Vec<String>,
    pub suspicious_ports: Vec<u16>,
}

/// Analyzes files for network-related indicators.
#[derive(Debug, Clone)]
pub struct NetworkAnalyzer;

impl NetworkAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Extract network indicators from a file's content.
    pub fn analyze_file(&self, path: impl AsRef<Path>) -> Result<NetworkIndicators> {
        let data = std::fs::read(path.as_ref())
            .with_context(|| format!("failed to read: {}", path.as_ref().display()))?;
        Ok(self.analyze_bytes(&data))
    }

    pub fn analyze_bytes(&self, data: &[u8]) -> NetworkIndicators {
        let urls = self.extract_urls(data);
        let ip_addresses = self.extract_ips(data);
        let domains = self.extract_domains(data);
        let suspicious_ports = self.extract_ports(data);

        debug!(
            urls = urls.len(),
            ips = ip_addresses.len(),
            domains = domains.len(),
            ports = suspicious_ports.len(),
            "network analysis complete"
        );

        NetworkIndicators {
            urls,
            ip_addresses,
            domains,
            suspicious_ports,
        }
    }

    fn extract_urls(&self, data: &[u8]) -> Vec<String> {
        let mut results = Vec::new();
        if let Ok(re) = BytesRegex::new(r#"https?://[^\x00-\x1f\x7f-\xff\s"'<>]{4,256}"#) {
            for m in re.find_iter(data).take(50) {
                if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                    results.push(s.to_string());
                }
            }
        }
        results
    }

    fn extract_ips(&self, data: &[u8]) -> Vec<String> {
        let mut results = Vec::new();
        if let Ok(re) = BytesRegex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b") {
            for m in re.find_iter(data).take(50) {
                if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                    if s != "0.0.0.0" && s != "127.0.0.1" && !s.starts_with("255.") {
                        results.push(s.to_string());
                    }
                }
            }
        }
        results
    }

    fn extract_domains(&self, data: &[u8]) -> Vec<String> {
        let mut results = Vec::new();
        if let Ok(re) = BytesRegex::new(r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:com|net|org|io|xyz|tk|ml|ga|cf|pw|cc|top|ru|cn|info|biz)\b") {
            for m in re.find_iter(data).take(50) {
                if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                    results.push(s.to_string());
                }
            }
        }
        results
    }

    fn extract_ports(&self, data: &[u8]) -> Vec<u16> {
        let suspicious = [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345, 54321];
        let mut found = Vec::new();
        if let Ok(re) = BytesRegex::new(r":(\d{2,5})\b") {
            for m in re.find_iter(data).take(100) {
                if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                    if let Ok(port) = s.trim_start_matches(':').parse::<u16>() {
                        if suspicious.contains(&port) && !found.contains(&port) {
                            found.push(port);
                        }
                    }
                }
            }
        }
        found
    }
}

impl Default for NetworkAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
