use serde::{Deserialize, Serialize};

/// All evidence gathered during a file scan.
///
/// This struct is the primary input for both the confidence scorer and the
/// classifier. It is defined here and re-exported from the detection module
/// root so that every sub-module can reference it without circular imports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanEvidence {
    /// SHA-256 hash match against the known-threat database (if any).
    pub hash_match: Option<String>,
    /// Names/identifiers of YARA rules that matched, paired with their severity (1-10).
    pub yara_matches: Vec<(String, u8)>,
    /// Win32/NT API imports considered suspicious (e.g. `WriteProcessMemory`).
    pub suspicious_imports: Vec<String>,
    /// Suspicious plaintext strings extracted from the binary.
    pub suspicious_strings: Vec<String>,
    /// Shannon entropy of the file (0.0 - 8.0).
    pub entropy_score: f64,
    /// Name of the packer/protector if detected.
    pub packer_info: Option<String>,
    /// Whether the file carries a valid Authenticode / code-signing signature.
    pub has_signature: bool,
    /// Network-related indicators (URLs, IPs, domains) found in the binary.
    pub network_indicators: Vec<String>,
    /// The binary references or targets game processes (e.g. `csgo.exe`).
    pub targets_game_processes: bool,
    /// The binary references or targets system-critical processes (e.g. `lsass.exe`).
    pub targets_system_processes: bool,
}

impl Default for ScanEvidence {
    fn default() -> Self {
        Self {
            hash_match: None,
            yara_matches: Vec::new(),
            suspicious_imports: Vec::new(),
            suspicious_strings: Vec::new(),
            entropy_score: 0.0,
            packer_info: None,
            has_signature: false,
            network_indicators: Vec::new(),
            targets_game_processes: false,
            targets_system_processes: false,
        }
    }
}

/// Breakdown of the confidence calculation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceResult {
    /// Overall confidence that the file is threatening (0-100).
    pub overall_score: u8,
    /// Sub-score: likelihood of being actual malware (0-100).
    pub malware_score: u8,
    /// Sub-score: likelihood of being a cheat tool (0-100).
    pub cheat_score: u8,
    /// Per-factor breakdown: (factor_name, weight, raw_score).
    pub breakdown: Vec<(String, f64, f64)>,
}

/// Stateless scorer that turns [`ScanEvidence`] into a [`ConfidenceResult`].
#[derive(Debug, Clone)]
pub struct ConfidenceScorer;

impl ConfidenceScorer {
    pub fn new() -> Self {
        Self
    }

    /// Calculate confidence scores from the collected scan evidence.
    pub fn calculate_confidence(&self, evidence: &ScanEvidence) -> ConfidenceResult {
        let mut breakdown: Vec<(String, f64, f64)> = Vec::new();
        let mut malware_raw: f64 = 0.0;
        let mut cheat_raw: f64 = 0.0;
        let mut overall_raw: f64 = 0.0;

        // --- Hash match (weight 0.35) ---
        let hash_score = if evidence.hash_match.is_some() {
            95.0
        } else {
            0.0
        };
        let hash_weight = 0.35;
        overall_raw += hash_score * hash_weight;
        malware_raw += hash_score * hash_weight;
        breakdown.push(("hash_match".into(), hash_weight, hash_score));

        // --- YARA matches (weight 0.25) ---
        let yara_score = if evidence.yara_matches.is_empty() {
            0.0
        } else {
            let total_severity: f64 = evidence
                .yara_matches
                .iter()
                .map(|(_, sev)| f64::from(*sev))
                .sum();
            let avg_severity = total_severity / evidence.yara_matches.len() as f64;
            // Scale average severity (1-10) to 0-100 with a count boost.
            let count_boost = (evidence.yara_matches.len() as f64).ln_1p() * 10.0;
            (avg_severity * 10.0 + count_boost).min(100.0)
        };
        let yara_weight = 0.25;
        overall_raw += yara_score * yara_weight;
        malware_raw += yara_score * yara_weight;
        breakdown.push(("yara_matches".into(), yara_weight, yara_score));

        // --- Suspicious imports (weight 0.15) ---
        let import_score = (evidence.suspicious_imports.len() as f64 * 12.0).min(100.0);
        let import_weight = 0.15;
        overall_raw += import_score * import_weight;

        // Injection-related imports contribute to the cheat score as well.
        let injection_imports: usize = evidence
            .suspicious_imports
            .iter()
            .filter(|i| {
                let lower = i.to_lowercase();
                lower.contains("writeprocessmemory")
                    || lower.contains("virtualalloc")
                    || lower.contains("createremotethread")
                    || lower.contains("ntwritevirtualmemory")
            })
            .count();
        let injection_score = (injection_imports as f64 * 20.0).min(80.0);
        cheat_raw += injection_score * import_weight;
        malware_raw += import_score * import_weight;
        breakdown.push(("suspicious_imports".into(), import_weight, import_score));

        // --- Network indicators (weight 0.10) ---
        let network_score = (evidence.network_indicators.len() as f64 * 15.0).min(100.0);
        let network_weight = 0.10;
        overall_raw += network_score * network_weight;
        malware_raw += network_score * network_weight;
        breakdown.push(("network_indicators".into(), network_weight, network_score));

        // --- Entropy / packer (weight 0.05) ---
        let entropy_score: f64 = if evidence.entropy_score > 7.5 {
            80.0
        } else if evidence.entropy_score > 7.0 {
            50.0
        } else {
            0.0
        };
        let packer_bonus: f64 = if evidence.packer_info.is_some() {
            20.0
        } else {
            0.0
        };
        let entropy_combined: f64 = (entropy_score + packer_bonus).min(100.0);
        let entropy_weight = 0.05;
        overall_raw += entropy_combined * entropy_weight;
        malware_raw += entropy_combined * entropy_weight;
        cheat_raw += entropy_combined * entropy_weight; // packers common in cheats too
        breakdown.push(("entropy_packer".into(), entropy_weight, entropy_combined));

        // --- Signature (weight 0.05) ---
        let sig_score = if evidence.has_signature { 0.0 } else { 30.0 };
        let sig_weight = 0.05;
        overall_raw += sig_score * sig_weight;
        malware_raw += sig_score * sig_weight;
        breakdown.push(("missing_signature".into(), sig_weight, sig_score));

        // --- Suspicious strings (weight 0.05) ---
        let strings_score = (evidence.suspicious_strings.len() as f64 * 8.0).min(100.0);
        let strings_weight = 0.05;
        overall_raw += strings_score * strings_weight;
        malware_raw += strings_score * strings_weight;
        breakdown.push(("suspicious_strings".into(), strings_weight, strings_score));

        // --- Game-process targeting adjustment ---
        // Targeting game processes is a strong cheat signal and REDUCES malware score.
        if evidence.targets_game_processes {
            cheat_raw += 30.0;
            malware_raw = (malware_raw - 15.0).max(0.0);
            breakdown.push(("targets_game_processes".into(), 0.0, -15.0));
        }

        // --- System-process targeting adjustment ---
        // Targeting system processes is a strong malware signal.
        if evidence.targets_system_processes {
            malware_raw += 25.0;
            overall_raw += 10.0;
            breakdown.push(("targets_system_processes".into(), 0.0, 25.0));
        }

        let clamp = |v: f64| (v.round() as u8).min(100);

        ConfidenceResult {
            overall_score: clamp(overall_raw),
            malware_score: clamp(malware_raw),
            cheat_score: clamp(cheat_raw),
            breakdown,
        }
    }
}

impl Default for ConfidenceScorer {
    fn default() -> Self {
        Self::new()
    }
}
