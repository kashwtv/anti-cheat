use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;

use anticheat_engine::{AntiCheatEngine, EngineConfig, ScanResult, ThreatLevel};

#[derive(Parser)]
#[command(
    name = "anticheat",
    about = "AntiCheat - Antivirus for Gamers",
    version,
    long_about = "A full-featured antivirus built for gamers who download cheat software.\nProtects against RATs, stealers, miners, and other malware bundled with cheats."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Custom data directory
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan files or directories for threats
    Scan {
        /// File or directory to scan
        path: Option<PathBuf>,
        /// Deep scan with full heuristics
        #[arg(long)]
        deep: bool,
        /// Quick hash-only scan
        #[arg(long)]
        quick: bool,
        /// Full system scan
        #[arg(long)]
        system: bool,
        /// Scan running processes
        #[arg(long)]
        running: bool,
    },
    /// Manage quarantined files
    Quarantine {
        #[command(subcommand)]
        action: QuarantineAction,
    },
    /// Add a file to the trusted whitelist
    Trust {
        /// File to trust
        path: Option<PathBuf>,
        /// Trust all files in a folder
        #[arg(long)]
        folder: Option<PathBuf>,
    },
    /// Remove a file from the whitelist by hash
    Untrust {
        /// SHA-256 hash to remove
        hash: String,
    },
    /// Manage whitelist import/export
    Whitelist {
        #[command(subcommand)]
        action: WhitelistAction,
    },
    /// Update signature database
    Update {
        /// Only check for updates
        #[arg(long)]
        check: bool,
        /// Roll back to previous signatures
        #[arg(long)]
        rollback: bool,
    },
    /// Show detailed file analysis
    Info {
        /// File to analyze
        path: PathBuf,
    },
    /// Generate scan report
    Report {
        /// File to report on
        path: PathBuf,
        /// Output format (json, html)
        #[arg(long, default_value = "json")]
        format: String,
    },
    /// Show detection statistics
    Stats,
    /// Show recent activity log
    Log,
}

#[derive(Subcommand)]
enum QuarantineAction {
    /// List quarantined files
    List,
    /// Restore a quarantined file
    Restore { id: String },
    /// Delete a quarantined file permanently
    Delete { id: String },
    /// Clean old quarantine entries (>30 days)
    Clean,
}

#[derive(Subcommand)]
enum WhitelistAction {
    /// Export whitelist to JSON
    Export,
    /// Import whitelist from JSON
    Import { path: PathBuf },
}

fn print_banner() {
    println!("{}", "╔══════════════════════════════════════╗".bright_green());
    println!("{}", "║      AntiCheat - AV for Gamers       ║".bright_green());
    println!("{}", "╚══════════════════════════════════════╝".bright_green());
    println!();
}

fn print_scan_result(result: &ScanResult) {
    let level = &result.threat_info.threat_level;
    let indicator = level.indicator();
    let name = &result.file_name;

    let colored_level = match level {
        ThreatLevel::Clean => "CLEAN".green().bold(),
        ThreatLevel::CheatDetected => "CHEAT DETECTED".blue().bold(),
        ThreatLevel::Suspicious => "SUSPICIOUS".yellow().bold(),
        ThreatLevel::LikelyMalicious => "LIKELY MALICIOUS".truecolor(255, 165, 0).bold(),
        ThreatLevel::Malicious => "MALICIOUS".red().bold(),
    };

    println!(
        "  {indicator} {colored_level}  {name}",
    );

    if *level != ThreatLevel::Clean {
        println!("    Threat:     {}", result.threat_info.threat_name);
        println!("    Confidence: {}%", result.threat_info.confidence_score);
        println!("    Details:    {}", result.threat_info.description);
        println!("    Action:     {}", result.threat_info.recommended_action);

        if !result.threat_info.factors.is_empty() {
            println!("    Factors:");
            for factor in &result.threat_info.factors {
                let marker = if factor.is_cheat_related { "🎮" } else { "⚠️" };
                println!("      {marker} {}: {}", factor.category, factor.description);
            }
        }
    }

    println!(
        "    SHA-256:    {}",
        &result.hashes.sha256[..16].dimmed()
    );
    println!(
        "    Scanned in: {}ms",
        result.scan_duration_ms
    );
    println!();
}

fn init_engine(cli: &Cli) -> Result<AntiCheatEngine> {
    let mut config = EngineConfig::default();
    if let Some(ref dir) = cli.data_dir {
        config.data_dir = dir.clone();
    }
    AntiCheatEngine::init(config)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.verbose {
        tracing_subscriber::fmt()
            .with_env_filter("anticheat=debug")
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter("anticheat=warn")
            .init();
    }

    match &cli.command {
        Commands::Scan {
            path,
            deep,
            quick,
            system,
            running,
        } => {
            print_banner();
            let engine = init_engine(&cli)?;

            if *running {
                println!("{}", "Scanning running processes is not yet supported on this platform.".yellow());
                return Ok(());
            }

            let scan_path = if *system {
                println!("{}", "Starting system scan...".cyan());
                PathBuf::from("/")
            } else if let Some(p) = path {
                p.clone()
            } else {
                println!("{}", "Error: Please provide a path or use --system".red());
                return Ok(());
            };

            let start = Instant::now();

            if scan_path.is_file() {
                let result = if *quick {
                    println!("{}", "Quick scan (hash-only)...".cyan());
                    engine.quick_scan(&scan_path)?
                } else {
                    println!(
                        "{}",
                        if *deep { "Deep scan..." } else { "Scanning..." }.cyan()
                    );
                    engine.scan_file(&scan_path)?
                };
                print_scan_result(&result);
            } else if scan_path.is_dir() {
                println!("Scanning directory: {}", scan_path.display().to_string().cyan());
                let results = engine.scan_directory(&scan_path, true)?;

                let mut threats = 0;
                let mut cheats = 0;
                let total = results.len();

                for result in &results {
                    match result.threat_info.threat_level {
                        ThreatLevel::Clean => {}
                        ThreatLevel::CheatDetected => {
                            cheats += 1;
                            print_scan_result(result);
                        }
                        _ => {
                            threats += 1;
                            print_scan_result(result);
                        }
                    }
                }

                let elapsed = start.elapsed();
                println!("{}", "═══ Scan Summary ═══".bright_green());
                println!("  Files scanned: {total}");
                println!("  Threats found: {}", if threats > 0 { threats.to_string().red() } else { "0".green() });
                println!("  Cheats found:  {}", if cheats > 0 { cheats.to_string().blue() } else { "0".green() });
                println!("  Duration:      {:.2}s", elapsed.as_secs_f64());
            } else {
                println!("{}", "Error: Path not found".red());
            }
        }

        Commands::Quarantine { action } => {
            let engine = init_engine(&cli)?;
            match action {
                QuarantineAction::List => {
                    let entries = engine.quarantine.list_all();
                    if entries.is_empty() {
                        println!("{}", "No quarantined files.".green());
                    } else {
                        println!("{}", "═══ Quarantine ═══".bright_yellow());
                        println!(
                            "  {:<36}  {:<30}  {:<20}  {:<12}",
                            "ID".bold(),
                            "File".bold(),
                            "Threat".bold(),
                            "Status".bold()
                        );
                        for entry in &entries {
                            let status_colored = match entry.status {
                                anticheat_engine::quarantine::QuarantineStatus::Quarantined => {
                                    "Quarantined".yellow()
                                }
                                anticheat_engine::quarantine::QuarantineStatus::Restored => {
                                    "Restored".green()
                                }
                                anticheat_engine::quarantine::QuarantineStatus::Deleted => {
                                    "Deleted".red()
                                }
                            };
                            println!(
                                "  {:<36}  {:<30}  {:<20}  {}",
                                &entry.id[..36.min(entry.id.len())],
                                &entry.file_name,
                                &entry.threat_name,
                                status_colored,
                            );
                        }
                        println!(
                            "\n  Vault size: {} bytes",
                            engine.quarantine.vault_size()
                        );
                    }
                }
                QuarantineAction::Restore { id } => {
                    engine.quarantine.restore_file(id, None)?;
                    println!("{} File restored: {id}", "✓".green());
                }
                QuarantineAction::Delete { id } => {
                    engine.quarantine.delete_file(id)?;
                    println!("{} File deleted: {id}", "✓".green());
                }
                QuarantineAction::Clean => {
                    let cleaned = engine.quarantine.auto_clean(30)?;
                    println!(
                        "{} Cleaned {} entries older than 30 days",
                        "✓".green(),
                        cleaned.len()
                    );
                }
            }
        }

        Commands::Trust { path, folder } => {
            let engine = init_engine(&cli)?;
            if let Some(folder_path) = folder {
                let mut count = 0;
                for entry in walkdir::WalkDir::new(folder_path)
                    .max_depth(1)
                    .into_iter()
                    .filter_map(|e| e.ok())
                {
                    if entry.file_type().is_file() {
                        if let Err(e) = engine.trust_file(entry.path()) {
                            eprintln!("  Failed to trust {}: {e}", entry.path().display());
                        } else {
                            count += 1;
                        }
                    }
                }
                println!("{} Trusted {count} files", "✓".green());
            } else if let Some(p) = path {
                engine.trust_file(p)?;
                println!("{} File trusted: {}", "✓".green(), p.display());
            } else {
                println!("{}", "Error: Provide a file path or --folder".red());
            }
        }

        Commands::Untrust { hash } => {
            let engine = init_engine(&cli)?;
            engine.untrust_file(hash)?;
            println!("{} Removed from whitelist: {hash}", "✓".green());
        }

        Commands::Whitelist { action } => {
            let engine = init_engine(&cli)?;
            match action {
                WhitelistAction::Export => {
                    let output = "whitelist_export.json";
                    engine.database.whitelist_db.export_json(output)?;
                    println!("{} Whitelist exported to {output}", "✓".green());
                }
                WhitelistAction::Import { path } => {
                    let count = engine.database.whitelist_db.import_json(path)?;
                    println!("{} Imported {count} whitelist entries", "✓".green());
                }
            }
        }

        Commands::Update { check, rollback } => {
            let engine = init_engine(&cli)?;
            if *rollback {
                println!("{}", "Signature rollback is not yet implemented.".yellow());
            } else if *check {
                match engine.check_updates().await? {
                    Some(info) => {
                        println!("{} Update available: v{}", "!".yellow(), info.version);
                        println!("  Released: {}", info.release_date);
                        println!("  Size: {} bytes", info.size_bytes);
                        println!("  {}", info.description);
                    }
                    None => println!("{} Signatures are up to date.", "✓".green()),
                }
            } else {
                println!("{}", "Updating signatures...".cyan());
                let result = engine.update_signatures().await?;
                if result.success {
                    println!("{} Signatures updated: {} -> {}", "✓".green(), result.previous_version, result.new_version);
                    println!("  Rules updated:  {}", result.rules_updated);
                    println!("  Hashes updated: {}", result.hashes_updated);
                } else {
                    println!("{} Update failed", "✗".red());
                }
            }
        }

        Commands::Info { path } => {
            print_banner();
            let engine = init_engine(&cli)?;
            let info = engine.get_file_info(path)?;

            println!("{}", "═══ File Analysis ═══".bright_cyan());
            println!("  Path:    {}", info.file_path);
            println!("  Size:    {} bytes", info.file_size);
            println!("  SHA-256: {}", info.hashes.sha256);
            println!("  MD5:     {}", info.hashes.md5);
            println!("  SHA-1:   {}", info.hashes.sha1);
            if let Some(ref tlsh) = info.hashes.tlsh {
                println!("  TLSH:    {tlsh}");
            }

            if let Some(ref pe) = info.pe_analysis {
                println!("\n{}", "  PE Analysis:".bold());
                println!("    Type:       {}", if pe.is_dll { "DLL" } else { "EXE" });
                println!("    Arch:       {}", if pe.is_64bit { "x64" } else { "x86" });
                println!("    Signed:     {}", if pe.is_signed { "Yes".green() } else { "No".yellow() });
                println!("    Overlay:    {}", if pe.has_overlay { format!("Yes ({} bytes)", pe.overlay_size).yellow().to_string() } else { "No".to_string() });
                println!("    Sections:");
                for sec in &pe.sections {
                    let entropy_colored = if sec.entropy > 7.5 {
                        format!("{:.2}", sec.entropy).red()
                    } else if sec.entropy > 7.0 {
                        format!("{:.2}", sec.entropy).yellow()
                    } else {
                        format!("{:.2}", sec.entropy).normal()
                    };
                    println!(
                        "      {:<10} vsize={:<10} rsize={:<10} entropy={}",
                        sec.name, sec.virtual_size, sec.raw_size, entropy_colored
                    );
                }
                if !pe.imports.is_empty() {
                    println!("    Imports: {} DLLs", pe.imports.len());
                    for imp in &pe.imports {
                        println!("      {} ({} functions)", imp.dll_name, imp.functions.len());
                    }
                }
            }

            if let Some(ref hr) = info.heuristic_result {
                println!("\n{}", "  Heuristics:".bold());
                println!("    Entropy:    {:.2}", hr.entropy_score);
                if let Some(ref packer) = hr.packer_detected {
                    println!("    Packer:     {}", packer.yellow());
                }
                println!("    Mismatch:   {}", hr.file_type_mismatch);
                if !hr.suspicious_imports.is_empty() {
                    println!("    Suspicious imports:");
                    for imp in &hr.suspicious_imports {
                        println!("      [{:?}] {} - {}", imp.category, imp.function_name, imp.reason);
                    }
                }
                if !hr.suspicious_strings.is_empty() {
                    println!("    Suspicious strings: {}", hr.suspicious_strings.len());
                    for s in hr.suspicious_strings.iter().take(10) {
                        println!("      [{:?}] {}", s.kind, &s.value[..s.value.len().min(80)]);
                    }
                }
            }

            if let Some(ref ni) = info.network_indicators {
                if !ni.urls.is_empty() || !ni.ip_addresses.is_empty() {
                    println!("\n{}", "  Network Indicators:".bold());
                    for url in ni.urls.iter().take(10) {
                        println!("    URL: {}", url.red());
                    }
                    for ip in ni.ip_addresses.iter().take(10) {
                        println!("    IP:  {}", ip.yellow());
                    }
                    for domain in ni.domains.iter().take(10) {
                        println!("    DNS: {domain}");
                    }
                }
            }
        }

        Commands::Report { path, format } => {
            let engine = init_engine(&cli)?;
            let result = engine.scan_file(path)?;
            let output_file = format!("report.{format}");

            match format.as_str() {
                "json" => {
                    let json = serde_json::to_string_pretty(&result)?;
                    std::fs::write(&output_file, json)?;
                }
                "html" => {
                    let html = format!(
                        r#"<!DOCTYPE html><html><head><title>AntiCheat Report</title>
<style>body{{font-family:sans-serif;background:#0a0a0f;color:#e0e0e0;padding:20px}}
h1{{color:#00ff88}}.threat{{color:#ff4444}}.clean{{color:#00ff88}}</style></head>
<body><h1>AntiCheat Scan Report</h1>
<p>File: {}</p><p>Size: {} bytes</p><p>SHA-256: {}</p>
<p>Threat Level: <span class="{}">{}</span></p>
<p>Confidence: {}%</p><p>{}</p></body></html>"#,
                        result.file_name,
                        result.file_size,
                        result.hashes.sha256,
                        if result.threat_info.threat_level == ThreatLevel::Clean { "clean" } else { "threat" },
                        result.threat_info.threat_level,
                        result.threat_info.confidence_score,
                        result.threat_info.description,
                    );
                    std::fs::write(&output_file, html)?;
                }
                _ => {
                    println!("{}", "Unsupported format. Use 'json' or 'html'.".red());
                    return Ok(());
                }
            }
            println!("{} Report saved to {output_file}", "✓".green());
        }

        Commands::Stats => {
            let engine = init_engine(&cli)?;
            println!("{}", "═══ AntiCheat Statistics ═══".bright_green());
            println!("  Threat signatures: {}", engine.database.hash_db.count());
            println!(
                "  Whitelist entries: {}",
                engine.database.whitelist_db.list_all().len()
            );
            println!(
                "  Game processes:    {}",
                engine.database.game_db.list_all().len()
            );
            println!(
                "  Quarantine files:  {}",
                engine.quarantine.list_active().len()
            );
            println!(
                "  Quarantine size:   {} bytes",
                engine.quarantine.vault_size()
            );
        }

        Commands::Log => {
            println!("{}", "═══ Recent Activity ═══".bright_cyan());
            println!("  Activity log will be available in a future version.");
            println!("  Use 'anticheat quarantine list' to view quarantine history.");
        }
    }

    Ok(())
}
