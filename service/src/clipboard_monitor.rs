use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// Monitors clipboard for crypto address replacement attacks (clipboard hijacking).
pub struct ClipboardMonitor;

/// Crypto address patterns.
struct CryptoPattern {
    name: &'static str,
    prefix_check: fn(&str) -> bool,
    length_range: (usize, usize),
}

const CRYPTO_PATTERNS: &[CryptoPattern] = &[
    CryptoPattern {
        name: "Bitcoin",
        prefix_check: |s| {
            s.starts_with('1') || s.starts_with('3') || s.starts_with("bc1")
        },
        length_range: (26, 62),
    },
    CryptoPattern {
        name: "Ethereum",
        prefix_check: |s| s.starts_with("0x"),
        length_range: (42, 42),
    },
    CryptoPattern {
        name: "Monero",
        prefix_check: |s| s.starts_with('4') || s.starts_with('8'),
        length_range: (95, 106),
    },
    CryptoPattern {
        name: "Litecoin",
        prefix_check: |s| {
            s.starts_with('L') || s.starts_with('M') || s.starts_with("ltc1")
        },
        length_range: (26, 62),
    },
    CryptoPattern {
        name: "Solana",
        prefix_check: |s| {
            s.chars().all(|c| c.is_alphanumeric())
                && !s.starts_with("0x")
                && s.len() >= 32
                && s.len() <= 44
        },
        length_range: (32, 44),
    },
];

impl ClipboardMonitor {
    /// Start clipboard monitoring in a background task.
    pub fn start(
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            info!("clipboard monitor starting");

            let check_interval = Duration::from_secs(2);
            let mut last_clipboard: Option<String> = None;
            let mut last_crypto_type: Option<&'static str> = None;

            loop {
                tokio::select! {
                    _ = shutdown.recv() => {
                        info!("clipboard monitor shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(check_interval) => {
                        let content = get_clipboard_content().await;

                        if let Some(ref content) = content {
                            // Check if current clipboard matches a crypto address
                            if let Some(crypto) = detect_crypto_address(content) {
                                // If we previously had a different crypto address of the same type,
                                // this could indicate clipboard hijacking
                                if let (Some(ref prev), Some(prev_type)) = (&last_clipboard, last_crypto_type) {
                                    if prev_type == crypto.name && prev != content {
                                        if let Some(_) = detect_crypto_address(prev) {
                                            warn!(
                                                crypto_type = crypto.name,
                                                previous = %prev,
                                                current = %content,
                                                "ALERT: clipboard crypto address changed unexpectedly - possible clipboard hijacking"
                                            );
                                        }
                                    }
                                }
                                last_crypto_type = Some(crypto.name);
                                debug!(
                                    crypto_type = crypto.name,
                                    "clipboard contains crypto address"
                                );
                            } else {
                                last_crypto_type = None;
                            }
                        }

                        last_clipboard = content;
                    }
                }
            }
        })
    }
}

/// Detect if a string matches a known crypto address pattern.
fn detect_crypto_address(s: &str) -> Option<&'static CryptoPattern> {
    let trimmed = s.trim();

    // Skip if it contains spaces (not an address)
    if trimmed.contains(' ') {
        return None;
    }

    for pattern in CRYPTO_PATTERNS {
        let len = trimmed.len();
        if len >= pattern.length_range.0
            && len <= pattern.length_range.1
            && (pattern.prefix_check)(trimmed)
        {
            return Some(pattern);
        }
    }

    None
}

/// Get current clipboard content.
/// This is a stub - real implementation would use platform-specific APIs.
async fn get_clipboard_content() -> Option<String> {
    // On Linux, try xclip/xsel; on Windows, use win32 API; on macOS, use pbpaste.
    // For now this is a stub that returns None.
    #[cfg(target_os = "linux")]
    {
        let output = tokio::process::Command::new("xclip")
            .args(["-selection", "clipboard", "-o"])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                let content = String::from_utf8_lossy(&out.stdout).to_string();
                if content.is_empty() {
                    None
                } else {
                    Some(content)
                }
            }
            _ => None,
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}
