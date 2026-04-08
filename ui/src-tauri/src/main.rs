// Prevents an additional console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::Mutex;

use anticheat_engine::{AntiCheatEngine, EngineConfig, ScanResult};
use serde::Serialize;
use tauri::State;

/// Shared engine handle. rusqlite connections are not `Sync`, so a `Mutex` is
/// required to hold it across Tauri's async boundaries.
struct EngineState(Mutex<AntiCheatEngine>);

#[derive(Serialize)]
struct Stats {
    signatures: usize,
    whitelist: usize,
    games: usize,
    quarantine_files: usize,
    quarantine_bytes: u64,
}

#[derive(Serialize)]
struct ScriptSummaryView {
    source: Option<String>,
    language: String,
    risk_score: u32,
    label: String,
    url_count: usize,
    api_call_count: usize,
    obfuscation_detected: bool,
    risk_indicators: Vec<String>,
}

#[tauri::command]
fn scan_file(path: String, state: State<'_, EngineState>) -> Result<ScanResult, String> {
    let engine = state.0.lock().map_err(|e| e.to_string())?;
    engine.scan_file(PathBuf::from(path)).map_err(|e| e.to_string())
}

#[tauri::command]
fn quick_scan(path: String, state: State<'_, EngineState>) -> Result<ScanResult, String> {
    let engine = state.0.lock().map_err(|e| e.to_string())?;
    engine.quick_scan(PathBuf::from(path)).map_err(|e| e.to_string())
}

#[tauri::command]
fn scan_directory(
    path: String,
    state: State<'_, EngineState>,
) -> Result<Vec<ScanResult>, String> {
    let engine = state.0.lock().map_err(|e| e.to_string())?;
    engine
        .scan_directory(PathBuf::from(path), true)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn get_stats(state: State<'_, EngineState>) -> Result<Stats, String> {
    let engine = state.0.lock().map_err(|e| e.to_string())?;
    Ok(Stats {
        signatures: engine.database.hash_db.count(),
        whitelist: engine.database.whitelist_db.list_all().len(),
        games: engine.database.game_db.list_all().len(),
        quarantine_files: engine.quarantine.list_active().len(),
        quarantine_bytes: engine.quarantine.vault_size(),
    })
}

#[tauri::command]
fn trust_file(path: String, state: State<'_, EngineState>) -> Result<(), String> {
    let engine = state.0.lock().map_err(|e| e.to_string())?;
    engine.trust_file(PathBuf::from(path)).map_err(|e| e.to_string())
}

#[tauri::command]
async fn analyze_script(path: String) -> Result<ScriptSummaryView, String> {
    use anticheat_engine::script_shield::{ScriptShield, ScriptShieldConfig};

    let shield = ScriptShield::new(ScriptShieldConfig::default())
        .map_err(|e| e.to_string())?;
    let report = shield
        .analyze_file(PathBuf::from(&path), false)
        .await
        .map_err(|e| e.to_string())?;
    let summary = report.summary();
    Ok(ScriptSummaryView {
        source: summary.source,
        language: summary.language,
        risk_score: summary.risk_score,
        label: summary.label,
        url_count: summary.url_count,
        api_call_count: summary.api_call_count,
        obfuscation_detected: summary.obfuscation_detected,
        risk_indicators: summary.risk_indicators,
    })
}

fn main() {
    let engine = AntiCheatEngine::init(EngineConfig::default())
        .expect("failed to initialize AntiCheat engine");

    tauri::Builder::default()
        .manage(EngineState(Mutex::new(engine)))
        .invoke_handler(tauri::generate_handler![
            scan_file,
            quick_scan,
            scan_directory,
            get_stats,
            trust_file,
            analyze_script,
        ])
        .run(tauri::generate_context!())
        .expect("error while running AntiCheat desktop");
}
