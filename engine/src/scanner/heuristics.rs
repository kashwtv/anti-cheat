//! Heuristic analysis for suspicious patterns in executable files.
//!
//! Examines imports, embedded strings, section entropy, packer signatures,
//! and file-type mismatches to produce a suspiciousness assessment.

use std::path::Path;

use anyhow::{Context, Result};
use regex::bytes::Regex as BytesRegex;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

use crate::scanner::pe_analyzer::{PeAnalysis, shannon_entropy};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Aggregated heuristic analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeuristicResult {
    /// Imports that are commonly associated with malicious behaviour.
    pub suspicious_imports: Vec<SuspiciousImport>,
    /// Interesting strings extracted from the file body.
    pub suspicious_strings: Vec<SuspiciousString>,
    /// Average Shannon entropy across all sections (0.0 -- 8.0).
    pub entropy_score: f64,
    /// Name of a known packer if detected, or `None`.
    pub packer_detected: Option<String>,
    /// Whether the file extension disagrees with magic-byte identification.
    pub file_type_mismatch: bool,
}

/// A single suspicious API import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousImport {
    pub function_name: String,
    pub category: ImportCategory,
    pub reason: String,
}

/// Category of suspicious API calls.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ImportCategory {
    Injection,
    Credential,
    Persistence,
    Networking,
    AntiDebug,
    Other,
}

/// A suspicious string found in the file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousString {
    pub value: String,
    pub kind: StringKind,
    pub offset: usize,
}

/// What kind of suspicious string was found.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StringKind {
    Url,
    IpAddress,
    FilePath,
    RegistryKey,
    Base64Blob,
}

// ---------------------------------------------------------------------------
// Suspicious API definitions
// ---------------------------------------------------------------------------

struct ApiSignature {
    name: &'static str,
    category: ImportCategory,
    reason: &'static str,
}

const SUSPICIOUS_APIS: &[ApiSignature] = &[
    // Injection
    ApiSignature { name: "CreateRemoteThread", category: ImportCategory::Injection, reason: "Creates a thread in another process (code injection)" },
    ApiSignature { name: "VirtualAllocEx", category: ImportCategory::Injection, reason: "Allocates memory in another process (shellcode injection)" },
    ApiSignature { name: "WriteProcessMemory", category: ImportCategory::Injection, reason: "Writes to another process's memory" },
    ApiSignature { name: "NtCreateThreadEx", category: ImportCategory::Injection, reason: "Low-level thread creation in another process" },
    ApiSignature { name: "QueueUserAPC", category: ImportCategory::Injection, reason: "APC injection technique" },
    ApiSignature { name: "SetWindowsHookEx", category: ImportCategory::Injection, reason: "Can be used for DLL injection via hooks" },
    // Credential theft
    ApiSignature { name: "CredRead", category: ImportCategory::Credential, reason: "Reads stored credentials" },
    ApiSignature { name: "CryptUnprotectData", category: ImportCategory::Credential, reason: "Decrypts DPAPI-protected data (credential theft)" },
    ApiSignature { name: "LsaRetrievePrivateData", category: ImportCategory::Credential, reason: "Retrieves LSA secrets" },
    // Persistence
    ApiSignature { name: "RegSetValueEx", category: ImportCategory::Persistence, reason: "Modifies registry values (possible persistence via Run keys)" },
    ApiSignature { name: "RegCreateKeyEx", category: ImportCategory::Persistence, reason: "Creates registry keys (possible persistence)" },
    ApiSignature { name: "CreateService", category: ImportCategory::Persistence, reason: "Creates a Windows service (persistence)" },
    // Networking
    ApiSignature { name: "URLDownloadToFile", category: ImportCategory::Networking, reason: "Downloads a file from the internet" },
    ApiSignature { name: "InternetOpenUrl", category: ImportCategory::Networking, reason: "Opens an internet URL" },
    ApiSignature { name: "HttpSendRequest", category: ImportCategory::Networking, reason: "Sends an HTTP request" },
    ApiSignature { name: "WinHttpSendRequest", category: ImportCategory::Networking, reason: "Sends an HTTP request via WinHTTP" },
    ApiSignature { name: "InternetOpen", category: ImportCategory::Networking, reason: "Initializes WinINet (network communication)" },
    // Anti-debug
    ApiSignature { name: "IsDebuggerPresent", category: ImportCategory::AntiDebug, reason: "Checks for attached debugger" },
    ApiSignature { name: "CheckRemoteDebuggerPresent", category: ImportCategory::AntiDebug, reason: "Checks for remote debugger" },
    ApiSignature { name: "NtQueryInformationProcess", category: ImportCategory::AntiDebug, reason: "Can be used for anti-debug checks" },
];

// ---------------------------------------------------------------------------
// Packer section-name signatures
// ---------------------------------------------------------------------------

struct PackerSignature {
    section_name: &'static str,
    packer: &'static str,
}

const PACKER_SIGNATURES: &[PackerSignature] = &[
    PackerSignature { section_name: "UPX0", packer: "UPX" },
    PackerSignature { section_name: "UPX1", packer: "UPX" },
    PackerSignature { section_name: "UPX2", packer: "UPX" },
    PackerSignature { section_name: ".themida", packer: "Themida" },
    PackerSignature { section_name: ".vmp0", packer: "VMProtect" },
    PackerSignature { section_name: ".vmp1", packer: "VMProtect" },
    PackerSignature { section_name: ".enigma1", packer: "Enigma Protector" },
    PackerSignature { section_name: ".enigma2", packer: "Enigma Protector" },
    PackerSignature { section_name: ".aspack", packer: "ASPack" },
    PackerSignature { section_name: ".adata", packer: "ASPack" },
    PackerSignature { section_name: ".nsp0", packer: "NsPack" },
    PackerSignature { section_name: ".nsp1", packer: "NsPack" },
    PackerSignature { section_name: "PECompact2", packer: "PECompact" },
    PackerSignature { section_name: ".petite", packer: "Petite" },
    PackerSignature { section_name: ".mpress1", packer: "MPRESS" },
    PackerSignature { section_name: ".mpress2", packer: "MPRESS" },
];

// ---------------------------------------------------------------------------
// Magic-byte table for mismatch detection
// ---------------------------------------------------------------------------

struct MagicBytes {
    magic: &'static [u8],
    expected_extensions: &'static [&'static str],
}

const MAGIC_TABLE: &[MagicBytes] = &[
    MagicBytes { magic: b"MZ",    expected_extensions: &["exe", "dll", "sys", "drv", "scr", "ocx"] },
    MagicBytes { magic: b"\x7fELF", expected_extensions: &["so", "elf", "bin", "o"] },
    MagicBytes { magic: b"PK\x03\x04", expected_extensions: &["zip", "jar", "apk", "docx", "xlsx", "pptx"] },
    MagicBytes { magic: b"\x89PNG", expected_extensions: &["png"] },
    MagicBytes { magic: b"\xff\xd8\xff", expected_extensions: &["jpg", "jpeg"] },
    MagicBytes { magic: b"GIF8", expected_extensions: &["gif"] },
    MagicBytes { magic: b"%PDF", expected_extensions: &["pdf"] },
];

// ---------------------------------------------------------------------------
// Analyser
// ---------------------------------------------------------------------------

/// Performs heuristic analysis on a file, optionally using an existing PE
/// analysis result.
#[derive(Debug, Clone)]
pub struct HeuristicAnalyzer;

impl HeuristicAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Run all heuristic checks on the file at `path`.
    ///
    /// If `pe_analysis` is `Some`, it will be reused to avoid re-parsing the
    /// PE.  Otherwise, import and section checks are skipped for non-PE files.
    #[instrument(skip(self, pe_analysis), fields(path = %path.as_ref().display()))]
    pub fn analyze(
        &self,
        path: impl AsRef<Path>,
        pe_analysis: Option<&PeAnalysis>,
    ) -> Result<HeuristicResult> {
        let data = std::fs::read(path.as_ref())
            .with_context(|| format!("failed to read file: {}", path.as_ref().display()))?;

        let suspicious_imports = pe_analysis
            .map(|pe| self.check_imports(pe))
            .unwrap_or_default();

        let suspicious_strings = self.extract_suspicious_strings(&data);

        let entropy_score = pe_analysis
            .map(|pe| self.average_entropy(pe))
            .unwrap_or_else(|| shannon_entropy(&data));

        let packer_detected = pe_analysis.and_then(|pe| self.detect_packer(pe));

        let file_type_mismatch = self.check_file_type_mismatch(path.as_ref(), &data);

        debug!(
            suspicious_import_count = suspicious_imports.len(),
            suspicious_string_count = suspicious_strings.len(),
            entropy_score,
            packer = ?packer_detected,
            file_type_mismatch,
            "heuristic analysis complete"
        );

        Ok(HeuristicResult {
            suspicious_imports,
            suspicious_strings,
            entropy_score,
            packer_detected,
            file_type_mismatch,
        })
    }

    // ---- internals -------------------------------------------------------

    fn check_imports(&self, pe: &PeAnalysis) -> Vec<SuspiciousImport> {
        let mut result = Vec::new();

        for import_entry in &pe.imports {
            for func in &import_entry.functions {
                for sig in SUSPICIOUS_APIS {
                    if func.eq_ignore_ascii_case(sig.name) {
                        result.push(SuspiciousImport {
                            function_name: func.clone(),
                            category: match &sig.category {
                                ImportCategory::Injection => ImportCategory::Injection,
                                ImportCategory::Credential => ImportCategory::Credential,
                                ImportCategory::Persistence => ImportCategory::Persistence,
                                ImportCategory::Networking => ImportCategory::Networking,
                                ImportCategory::AntiDebug => ImportCategory::AntiDebug,
                                ImportCategory::Other => ImportCategory::Other,
                            },
                            reason: sig.reason.to_string(),
                        });
                    }
                }
            }
        }

        result
    }

    fn extract_suspicious_strings(&self, data: &[u8]) -> Vec<SuspiciousString> {
        let mut results = Vec::new();

        // URL extraction
        if let Ok(re) = BytesRegex::new(r#"https?://[^\x00-\x1f\x7f-\xff\s"'<>]{4,256}"#) {
            for m in re.find_iter(data) {
                if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                    results.push(SuspiciousString {
                        value: s.to_string(),
                        kind: StringKind::Url,
                        offset: m.start(),
                    });
                }
            }
        }

        // IP addresses
        if let Ok(re) = BytesRegex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b") {
            for m in re.find_iter(data) {
                if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                    // Skip common non-suspicious IPs.
                    if s == "0.0.0.0" || s == "127.0.0.1" || s.starts_with("255.") {
                        continue;
                    }
                    results.push(SuspiciousString {
                        value: s.to_string(),
                        kind: StringKind::IpAddress,
                        offset: m.start(),
                    });
                }
            }
        }

        // Windows file paths
        if let Ok(re) = BytesRegex::new(r"[A-Za-z]:\\[\x20-\x7e]{4,260}") {
            for m in re.find_iter(data) {
                if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                    results.push(SuspiciousString {
                        value: s.to_string(),
                        kind: StringKind::FilePath,
                        offset: m.start(),
                    });
                }
            }
        }

        // Registry keys
        if let Ok(re) = BytesRegex::new(
            r"(?i)(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_CLASSES_ROOT|HKCR)\\[\x20-\x7e]{4,512}",
        ) {
            for m in re.find_iter(data) {
                if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                    results.push(SuspiciousString {
                        value: s.to_string(),
                        kind: StringKind::RegistryKey,
                        offset: m.start(),
                    });
                }
            }
        }

        // Base64-encoded blobs (at least 32 chars long, heuristic).
        if let Ok(re) = BytesRegex::new(r"[A-Za-z0-9+/]{32,}={0,2}") {
            for m in re.find_iter(data) {
                if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                    // Only flag if it actually decodes.
                    if base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        s,
                    )
                    .is_ok()
                    {
                        results.push(SuspiciousString {
                            value: if s.len() > 128 {
                                format!("{}...", &s[..128])
                            } else {
                                s.to_string()
                            },
                            kind: StringKind::Base64Blob,
                            offset: m.start(),
                        });
                    }
                }
            }
        }

        results
    }

    fn average_entropy(&self, pe: &PeAnalysis) -> f64 {
        if pe.sections.is_empty() {
            return 0.0;
        }
        let total: f64 = pe.sections.iter().map(|s| s.entropy).sum();
        total / pe.sections.len() as f64
    }

    fn detect_packer(&self, pe: &PeAnalysis) -> Option<String> {
        for section in &pe.sections {
            let sec_name = section.name.trim_end_matches('\0');
            for sig in PACKER_SIGNATURES {
                if sec_name.eq_ignore_ascii_case(sig.section_name) {
                    return Some(sig.packer.to_string());
                }
            }
        }

        // Additional heuristic: very high entropy in first section with low
        // raw size compared to virtual size is a sign of packing.
        if let Some(first) = pe.sections.first() {
            if first.entropy > 7.5
                && first.virtual_size > 0
                && first.raw_size as f64 / first.virtual_size as f64 > 0.9
            {
                return Some("Unknown packer (high entropy)".to_string());
            }
        }

        None
    }

    fn check_file_type_mismatch(&self, path: &Path, data: &[u8]) -> bool {
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase());

        let extension = match extension {
            Some(e) => e,
            None => return false,
        };

        for magic in MAGIC_TABLE {
            if data.len() >= magic.magic.len() && data.starts_with(magic.magic) {
                // The file matches this magic; check if extension is expected.
                if !magic.expected_extensions.iter().any(|&e| e == extension) {
                    debug!(
                        extension = %extension,
                        expected = ?magic.expected_extensions,
                        "file type mismatch detected"
                    );
                    return true;
                }
                return false;
            }
        }

        false
    }
}

impl Default for HeuristicAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
