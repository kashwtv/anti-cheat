//! Lua script parser that extracts API calls and structure without building a full AST.

use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Category of a Lua API call indicating what kind of operation it performs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiCategory {
    /// HTTP/web requests (HttpGet, GetAsync, PostAsync, request, etc.)
    WebRequest,
    /// File system write operations (writefile, appendfile, makefolder)
    FileWrite,
    /// System command execution (os.execute, io.popen)
    SystemCommand,
    /// Process / environment manipulation (getgenv, getrenv, getrawmetatable)
    ProcessManipulation,
    /// Persistence mechanisms
    Persistence,
    /// Data exfiltration (clipboard access, etc.)
    DataExfiltration,
    /// Other / uncategorized
    Other,
}

/// A single API call extracted from a Lua script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCall {
    /// The function name as it appears in the script.
    pub function_name: String,
    /// Arguments passed to the function (best-effort extraction of string literals).
    pub args: Vec<String>,
    /// The 1-based line number where the call was found.
    pub line_number: usize,
    /// Whether this call is considered dangerous.
    pub is_dangerous: bool,
    /// The category of the API call.
    pub category: ApiCategory,
}

/// Parser for extracting Lua API calls from script source text.
#[derive(Debug, Clone)]
pub struct LuaParser {
    patterns: Vec<ApiPattern>,
}

/// Internal representation of an API pattern to search for.
#[derive(Debug, Clone)]
struct ApiPattern {
    regex: Regex,
    function_name: String,
    category: ApiCategory,
    is_dangerous: bool,
}

impl Default for LuaParser {
    fn default() -> Self {
        Self::new()
    }
}

impl LuaParser {
    /// Create a new `LuaParser` with all known dangerous API patterns.
    pub fn new() -> Self {
        let patterns = Self::build_patterns();
        Self { patterns }
    }

    /// Parse a Lua script and return all identified API calls.
    pub fn parse_api_calls(&self, script: &str) -> Vec<ApiCall> {
        let mut calls = Vec::new();

        for (line_idx, line) in script.lines().enumerate() {
            let line_number = line_idx + 1;

            for pattern in &self.patterns {
                for cap in pattern.regex.captures_iter(line) {
                    let args = Self::extract_args_from_capture(&cap);

                    calls.push(ApiCall {
                        function_name: pattern.function_name.clone(),
                        args,
                        line_number,
                        is_dangerous: pattern.is_dangerous,
                        category: pattern.category.clone(),
                    });
                }
            }
        }

        calls
    }

    /// Build the set of regex patterns for known API calls.
    fn build_patterns() -> Vec<ApiPattern> {
        let mut patterns = Vec::new();

        // Helper macro to reduce boilerplate.
        macro_rules! add_pattern {
            ($regex:expr, $name:expr, $cat:expr, $dangerous:expr) => {
                patterns.push(ApiPattern {
                    regex: Regex::new($regex).expect("valid regex"),
                    function_name: $name.to_string(),
                    category: $cat,
                    is_dangerous: $dangerous,
                });
            };
        }

        // -- Web request patterns --
        add_pattern!(
            r#"game\s*:\s*HttpGet\s*\(([^)]*)\)"#,
            "game:HttpGet",
            ApiCategory::WebRequest,
            true
        );
        add_pattern!(
            r#"game\s*:\s*GetService\s*\(\s*["']HttpService["']\s*\)"#,
            "game:GetService(\"HttpService\")",
            ApiCategory::WebRequest,
            true
        );
        add_pattern!(
            r#"HttpService\s*:\s*GetAsync\s*\(([^)]*)\)"#,
            "HttpService:GetAsync",
            ApiCategory::WebRequest,
            true
        );
        add_pattern!(
            r#"HttpService\s*:\s*PostAsync\s*\(([^)]*)\)"#,
            "HttpService:PostAsync",
            ApiCategory::WebRequest,
            true
        );
        add_pattern!(
            r#"\brequest\s*\(\s*\{([^}]*)\}\s*\)"#,
            "request",
            ApiCategory::WebRequest,
            true
        );
        add_pattern!(
            r#"\bhttp_request\s*\(([^)]*)\)"#,
            "http_request",
            ApiCategory::WebRequest,
            true
        );
        add_pattern!(
            r#"syn\s*\.\s*request\s*\(([^)]*)\)"#,
            "syn.request",
            ApiCategory::WebRequest,
            true
        );
        add_pattern!(
            r#"http\s*\.\s*request\s*\(([^)]*)\)"#,
            "http.request",
            ApiCategory::WebRequest,
            true
        );

        // -- Dynamic code execution --
        add_pattern!(
            r#"\bloadstring\s*\(([^)]*)\)"#,
            "loadstring",
            ApiCategory::Other,
            true
        );

        // -- File system access --
        add_pattern!(
            r#"\bwritefile\s*\(([^)]*)\)"#,
            "writefile",
            ApiCategory::FileWrite,
            true
        );
        add_pattern!(
            r#"\bappendfile\s*\(([^)]*)\)"#,
            "appendfile",
            ApiCategory::FileWrite,
            true
        );
        add_pattern!(
            r#"\bmakefolder\s*\(([^)]*)\)"#,
            "makefolder",
            ApiCategory::FileWrite,
            true
        );

        // -- System commands --
        add_pattern!(
            r#"os\s*\.\s*execute\s*\(([^)]*)\)"#,
            "os.execute",
            ApiCategory::SystemCommand,
            true
        );
        add_pattern!(
            r#"io\s*\.\s*popen\s*\(([^)]*)\)"#,
            "io.popen",
            ApiCategory::SystemCommand,
            true
        );

        // -- Clipboard / data exfiltration --
        add_pattern!(
            r#"\bsetclipboard\s*\(([^)]*)\)"#,
            "setclipboard",
            ApiCategory::DataExfiltration,
            true
        );
        add_pattern!(
            r#"\bgetclipboard\s*\(\s*\)"#,
            "getclipboard",
            ApiCategory::DataExfiltration,
            true
        );

        // -- Environment manipulation --
        add_pattern!(
            r#"\bgetgenv\s*\(\s*\)"#,
            "getgenv",
            ApiCategory::ProcessManipulation,
            true
        );
        add_pattern!(
            r#"\bgetrenv\s*\(\s*\)"#,
            "getrenv",
            ApiCategory::ProcessManipulation,
            true
        );
        add_pattern!(
            r#"\bgetrawmetatable\s*\(([^)]*)\)"#,
            "getrawmetatable",
            ApiCategory::ProcessManipulation,
            true
        );

        patterns
    }

    /// Extract string arguments from a regex capture.
    ///
    /// Looks for the first capture group (the parenthesized arguments) and
    /// extracts any string literals from it.
    fn extract_args_from_capture(cap: &regex::Captures<'_>) -> Vec<String> {
        let mut args = Vec::new();

        // Try to get the first capture group which should contain the arguments.
        let raw = match cap.get(1) {
            Some(m) => m.as_str(),
            None => return args,
        };

        // Extract string literals (both single and double quoted).
        let string_re =
            Regex::new(r#"["']([^"']*?)["']"#).expect("valid regex");
        for string_cap in string_re.captures_iter(raw) {
            if let Some(m) = string_cap.get(1) {
                args.push(m.as_str().to_string());
            }
        }

        // If no string literals found, include the raw text trimmed.
        if args.is_empty() {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                args.push(trimmed.to_string());
            }
        }

        args
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_http_get() {
        let parser = LuaParser::new();
        let calls = parser.parse_api_calls(r#"game:HttpGet("https://example.com")"#);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function_name, "game:HttpGet");
        assert!(calls[0].is_dangerous);
        assert_eq!(calls[0].category, ApiCategory::WebRequest);
        assert!(calls[0].args.contains(&"https://example.com".to_string()));
    }

    #[test]
    fn test_detect_loadstring() {
        let parser = LuaParser::new();
        let calls = parser.parse_api_calls("loadstring(data)()");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function_name, "loadstring");
        assert!(calls[0].is_dangerous);
    }

    #[test]
    fn test_detect_file_operations() {
        let parser = LuaParser::new();
        let script = r#"
            writefile("hack.lua", code)
            appendfile("log.txt", info)
            makefolder("scripts")
        "#;
        let calls = parser.parse_api_calls(script);
        assert_eq!(calls.len(), 3);
        assert!(calls.iter().all(|c| c.category == ApiCategory::FileWrite));
    }

    #[test]
    fn test_detect_system_commands() {
        let parser = LuaParser::new();
        let calls = parser.parse_api_calls(r#"os.execute("rm -rf /")"#);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].category, ApiCategory::SystemCommand);
    }

    #[test]
    fn test_line_numbers() {
        let parser = LuaParser::new();
        let script = "print('hello')\nloadstring(x)()\nwritefile('a','b')";
        let calls = parser.parse_api_calls(script);
        assert!(calls.iter().any(|c| c.function_name == "loadstring" && c.line_number == 2));
        assert!(calls.iter().any(|c| c.function_name == "writefile" && c.line_number == 3));
    }

    #[test]
    fn test_syn_request() {
        let parser = LuaParser::new();
        let calls = parser.parse_api_calls(r#"syn.request({Url = "https://evil.com"})"#);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function_name, "syn.request");
    }

    #[test]
    fn test_environment_manipulation() {
        let parser = LuaParser::new();
        let script = "local env = getgenv()\ngetrenv()\ngetrawmetatable(game)";
        let calls = parser.parse_api_calls(script);
        assert_eq!(calls.len(), 3);
        assert!(calls.iter().all(|c| c.category == ApiCategory::ProcessManipulation));
    }
}
