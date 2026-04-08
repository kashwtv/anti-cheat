// AntiCheat desktop frontend. Uses the Tauri v2 core invoke API.
const invoke = window.__TAURI__?.core?.invoke;

// --- Navigation ---
document.querySelectorAll("nav button").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("nav button").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("view-" + btn.dataset.view).classList.add("active");
  });
});

// --- Dashboard ---
async function refreshStats() {
  if (!invoke) {
    document.getElementById("stat-sigs").textContent = "—";
    return;
  }
  try {
    const stats = await invoke("get_stats");
    document.getElementById("stat-sigs").textContent = stats.signatures;
    document.getElementById("stat-wl").textContent = stats.whitelist;
    document.getElementById("stat-games").textContent = stats.games;
    document.getElementById("stat-qf").textContent = stats.quarantine_files;
  } catch (e) {
    console.error("get_stats failed", e);
  }
}
document.getElementById("refresh-stats").addEventListener("click", refreshStats);

// --- Scan ---
async function runScan(cmd) {
  const path = document.getElementById("scan-path").value.trim();
  const out = document.getElementById("scan-result");
  if (!path) {
    out.textContent = "Please enter a file path.";
    return;
  }
  if (!invoke) {
    out.textContent = "Tauri runtime not available.";
    return;
  }
  out.textContent = "Scanning...";
  try {
    const result = await invoke(cmd, { path });
    out.textContent = JSON.stringify(result, null, 2);
  } catch (e) {
    out.textContent = "Error: " + e;
  }
}
document.getElementById("btn-scan").addEventListener("click", () => runScan("scan_file"));
document.getElementById("btn-qscan").addEventListener("click", () => runScan("quick_scan"));

// --- Script Shield ---
document.getElementById("btn-script").addEventListener("click", async () => {
  const path = document.getElementById("script-path").value.trim();
  const out = document.getElementById("script-result");
  if (!path) {
    out.textContent = "Please enter a script path.";
    return;
  }
  if (!invoke) {
    out.textContent = "Tauri runtime not available.";
    return;
  }
  out.textContent = "Analyzing...";
  try {
    const report = await invoke("analyze_script", { path });
    out.textContent = JSON.stringify(report, null, 2);
  } catch (e) {
    out.textContent = "Error: " + e;
  }
});

// Initial load
refreshStats();
