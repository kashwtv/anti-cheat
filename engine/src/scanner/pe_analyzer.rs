//! PE (Portable Executable) file analysis using goblin.
//!
//! Parses PE headers, sections, imports, exports, overlay data, and checks
//! for Authenticode signatures.

use std::path::Path;

use anyhow::{bail, Context, Result};
use goblin::pe::PE;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument, warn};

/// Full analysis result for a PE file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeAnalysis {
    /// Whether the file is a DLL.
    pub is_dll: bool,
    /// Whether the file is 64-bit.
    pub is_64bit: bool,
    /// Parsed section information.
    pub sections: Vec<SectionInfo>,
    /// Imported DLLs and their functions.
    pub imports: Vec<ImportEntry>,
    /// Exported function names.
    pub exports: Vec<String>,
    /// PE timestamp from the COFF header.
    pub timestamp: u32,
    /// Image subsystem (e.g. GUI = 2, Console = 3).
    pub subsystem: u16,
    /// Address of entry point (RVA).
    pub entry_point: u64,
    /// Whether data exists past the end of the PE structure.
    pub has_overlay: bool,
    /// Size of overlay data in bytes.
    pub overlay_size: u64,
    /// Whether the file contains a certificate table entry (Authenticode).
    pub is_signed: bool,
}

/// Information about a single PE section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_size: u32,
    pub raw_size: u32,
    /// Shannon entropy of the section data in `[0.0, 8.0]`.
    pub entropy: f64,
    /// Section characteristics flags.
    pub characteristics: u32,
}

/// A single imported DLL and the functions it exposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEntry {
    pub dll_name: String,
    pub functions: Vec<String>,
}

/// Analyser for PE (Portable Executable) files.
#[derive(Debug, Clone)]
pub struct PeAnalyzer;

impl PeAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Analyse the PE file at `path`.
    #[instrument(skip(self), fields(path = %path.as_ref().display()))]
    pub fn analyze(&self, path: impl AsRef<Path>) -> Result<PeAnalysis> {
        let data = std::fs::read(path.as_ref())
            .with_context(|| format!("failed to read file: {}", path.as_ref().display()))?;

        let pe = match goblin::Object::parse(&data)
            .with_context(|| "failed to parse PE")?
        {
            goblin::Object::PE(pe) => pe,
            _ => bail!("file is not a valid PE"),
        };

        let is_dll = pe
            .header
            .coff_header
            .characteristics
            & 0x2000 // IMAGE_FILE_DLL
            != 0;

        let is_64bit = pe.is_64;

        let timestamp = pe.header.coff_header.time_date_stamp;

        let (subsystem, entry_point) = match pe.header.optional_header {
            Some(ref opt) => (
                opt.windows_fields.subsystem,
                u64::from(opt.standard_fields.address_of_entry_point),
            ),
            None => (0u16, 0u64),
        };

        // Sections
        let sections = self.parse_sections(&pe, &data);

        // Imports
        let imports = self.parse_imports(&pe);

        // Exports
        let exports = self.parse_exports(&pe);

        // Overlay detection
        let (has_overlay, overlay_size) = self.detect_overlay(&pe, &data);

        // Signature (certificate table entry)
        let is_signed = self.detect_signature(&pe);

        debug!(
            is_dll,
            is_64bit,
            section_count = sections.len(),
            import_dlls = imports.len(),
            export_count = exports.len(),
            has_overlay,
            is_signed,
            "PE analysis complete"
        );

        Ok(PeAnalysis {
            is_dll,
            is_64bit,
            sections,
            imports,
            exports,
            timestamp,
            subsystem,
            entry_point,
            has_overlay,
            overlay_size,
            is_signed,
        })
    }

    // ---- internal helpers ------------------------------------------------

    fn parse_sections(&self, pe: &PE<'_>, data: &[u8]) -> Vec<SectionInfo> {
        pe.sections
            .iter()
            .map(|sec| {
                let name = String::from_utf8_lossy(
                    &sec.name[..sec.name.iter().position(|&b| b == 0).unwrap_or(sec.name.len())],
                )
                .to_string();

                let raw_offset = sec.pointer_to_raw_data as usize;
                let raw_size = sec.size_of_raw_data;
                let end = (raw_offset + raw_size as usize).min(data.len());
                let section_data = if raw_offset < data.len() {
                    &data[raw_offset..end]
                } else {
                    &[]
                };

                let entropy = shannon_entropy(section_data);

                SectionInfo {
                    name,
                    virtual_size: sec.virtual_size,
                    raw_size,
                    entropy,
                    characteristics: sec.characteristics,
                }
            })
            .collect()
    }

    fn parse_imports(&self, pe: &PE<'_>) -> Vec<ImportEntry> {
        let mut result = Vec::new();

        for import in &pe.imports {
            let dll_name = import.dll.to_string();

            // Find or create entry for this DLL.
            let entry = result
                .iter_mut()
                .find(|e: &&mut ImportEntry| e.dll_name == dll_name);

            let func_name = import.name.to_string();

            match entry {
                Some(e) => e.functions.push(func_name),
                None => result.push(ImportEntry {
                    dll_name,
                    functions: vec![func_name],
                }),
            }
        }

        result
    }

    fn parse_exports(&self, pe: &PE<'_>) -> Vec<String> {
        pe.exports
            .iter()
            .filter_map(|exp| exp.name.map(|n| n.to_string()))
            .collect()
    }

    /// Detect overlay data (bytes past the last section's raw data).
    fn detect_overlay(&self, pe: &PE<'_>, data: &[u8]) -> (bool, u64) {
        let pe_end = pe
            .sections
            .iter()
            .map(|sec| (sec.pointer_to_raw_data as u64) + (sec.size_of_raw_data as u64))
            .max()
            .unwrap_or(0);

        let file_size = data.len() as u64;
        if pe_end > 0 && file_size > pe_end {
            let overlay_size = file_size - pe_end;
            (true, overlay_size)
        } else {
            (false, 0)
        }
    }

    /// Check whether the PE has a certificate table directory entry.
    fn detect_signature(&self, pe: &PE<'_>) -> bool {
        if let Some(ref opt) = pe.header.optional_header {
            // Certificate table is data directory index 4.
            if let Some(Some((_idx, dir))) = opt.data_directories.data_directories.get(4) {
                return dir.virtual_address != 0 && dir.size != 0;
            }
        }
        false
    }
}

impl Default for PeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute Shannon entropy for a byte slice.  Returns a value in `[0.0, 8.0]`.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0f64;

    for &count in &freq {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }

    entropy
}
