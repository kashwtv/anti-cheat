use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// Results from scanning an archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveEntry {
    pub filename: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub is_executable: bool,
}

/// Result of archive analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveScanResult {
    pub entries: Vec<ArchiveEntry>,
    pub is_zip_bomb: bool,
    pub total_files: usize,
    pub total_uncompressed_size: u64,
}

/// Scanner for archive files (.zip).
#[derive(Debug, Clone)]
pub struct ArchiveScanner {
    max_depth: u32,
    max_files: usize,
}

impl ArchiveScanner {
    pub fn new(max_depth: u32, max_files: usize) -> Self {
        Self { max_depth, max_files }
    }

    /// Analyze a zip archive without fully extracting.
    pub fn analyze_archive(&self, path: impl AsRef<Path>) -> Result<ArchiveScanResult> {
        let path = path.as_ref();
        let file = std::fs::File::open(path)
            .with_context(|| format!("failed to open archive: {}", path.display()))?;
        let mut archive = zip::ZipArchive::new(file)
            .with_context(|| "failed to parse zip archive")?;

        let mut entries = Vec::new();
        let mut total_uncompressed: u64 = 0;
        let mut is_zip_bomb = false;

        let file_count = archive.len().min(self.max_files);

        for i in 0..file_count {
            let file = match archive.by_index(i) {
                Ok(f) => f,
                Err(e) => {
                    warn!(index = i, error = %e, "failed to read archive entry");
                    continue;
                }
            };

            let name = file.name().to_string();
            let compressed = file.compressed_size();
            let uncompressed = file.size();
            total_uncompressed += uncompressed;

            // Zip bomb detection: ratio > 100:1
            if compressed > 0 && uncompressed / compressed > 100 {
                is_zip_bomb = true;
            }

            let is_executable = name.ends_with(".exe")
                || name.ends_with(".dll")
                || name.ends_with(".sys")
                || name.ends_with(".bat")
                || name.ends_with(".cmd")
                || name.ends_with(".ps1")
                || name.ends_with(".scr");

            entries.push(ArchiveEntry {
                filename: name,
                compressed_size: compressed,
                uncompressed_size: uncompressed,
                is_executable,
            });
        }

        // Global zip bomb check
        let total_compressed: u64 = entries.iter().map(|e| e.compressed_size).sum();
        if total_compressed > 0 && total_uncompressed / total_compressed > 200 {
            is_zip_bomb = true;
        }

        debug!(
            files = entries.len(),
            total_uncompressed,
            is_zip_bomb,
            "archive analysis complete"
        );

        Ok(ArchiveScanResult {
            total_files: entries.len(),
            entries,
            is_zip_bomb,
            total_uncompressed_size: total_uncompressed,
        })
    }

    /// Check if a path is a supported archive format.
    pub fn is_archive(path: impl AsRef<Path>) -> bool {
        let ext = path
            .as_ref()
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        matches!(ext.to_lowercase().as_str(), "zip" | "jar" | "apk")
    }
}

impl Default for ArchiveScanner {
    fn default() -> Self {
        Self::new(5, 100)
    }
}
