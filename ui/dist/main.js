// AntiCheat desktop frontend — Tauri v2 core invoke API.

const invoke = window.__TAURI__?.core?.invoke;

// ------------------------- Toast helper -------------------------
const toastEl = document.getElementById("toast");
let toastTimer = null;
function toast(msg, kind = "info") {
  toastEl.textContent = msg;
  toastEl.classList.add("show");
  toastEl.dataset.kind = kind;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toastEl.classList.remove("show"), 2400);
}

// ------------------------- Navigation -------------------------
function go(view) {
  document.querySelectorAll(".nav-btn").forEach((b) => b.classList.remove("active"));
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  const btn = document.querySelector(`.nav-btn[data-view="${view}"]`);
  if (btn) btn.classList.add("active");
  const sec = document.getElementById("view-" + view);
  if (sec) sec.classList.add("active");
}
document.querySelectorAll(".nav-btn").forEach((btn) => {
  btn.addEventListener("click", () => go(btn.dataset.view));
});
document.querySelectorAll("[data-go]").forEach((el) => {
  el.addEventListener("click", () => go(el.dataset.go));
});

// ------------------------- Dashboard -------------------------

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

    // Derive a simple protection score.
    const q = stats.quarantine_files || 0;
    const base = 92;
    const score = Math.max(0, base - q * 6);
    setScore(score, stats);
  } catch (e) {
    console.error("get_stats failed", e);
  }
}

function setScore(score, stats) {
  const ring = document.getElementById("score-ring");
  const label = document.getElementById("score-value");
  const title = document.getElementById("hero-title");
  const sub = document.getElementById("hero-sub");
  const pill = document.getElementById("sidebar-status");

  const circumference = 2 * Math.PI * 54;
  const offset = circumference * (1 - score / 100);
  ring.style.strokeDashoffset = offset;
  label.textContent = String(score);

  pill.classList.remove("warn", "bad");
  if (score >= 85) {
    title.textContent = "Systems nominal";
    sub.textContent = `No active threats detected. ${stats?.signatures ?? 0} signatures loaded.`;
    pill.querySelector(".text").textContent = "Protected";
  } else if (score >= 60) {
    title.textContent = "Attention needed";
    sub.textContent = `${stats?.quarantine_files ?? 0} file(s) in quarantine. Review and decide.`;
    pill.classList.add("warn");
    pill.querySelector(".text").textContent = "Review";
  } else {
    title.textContent = "Action required";
    sub.textContent = "Multiple threats isolated. Run a deep scan.";
    pill.classList.add("bad");
    pill.querySelector(".text").textContent = "At risk";
  }
}

document.getElementById("refresh-stats").addEventListener("click", refreshStats);
document.getElementById("btn-open-scan").addEventListener("click", () => go("scan"));
document.getElementById("btn-quickscan-home").addEventListener("click", async () => {
  const home = window.__TAURI__?.path ? "" : "";
  toast("Quick scan — enter a folder in the Scan view");
  go("scan");
});

// ------------------------- Scan -------------------------

function renderVerdict(result, target) {
  const v = document.getElementById(target);
  if (!result) { v.classList.add("hidden"); return; }
  v.classList.remove("hidden", "clean", "warn", "bad");
  const level = result.threat_info?.threat_level ?? "Clean";
  let kind = "clean";
  if (level === "Clean") kind = "clean";
  else if (level === "Suspicious" || level === "CheatDetected") kind = "warn";
  else kind = "bad";
  v.classList.add(kind);
  const name = result.file_name ?? "file";
  const score = result.threat_info?.confidence_score ?? 0;
  v.innerHTML = `
    <span class="badge">${level}</span>
    <div>
      <div style="font-weight:600">${escapeHtml(name)}</div>
      <div style="color:var(--muted); font-size:12px">Confidence ${score}% · ${escapeHtml(result.threat_info?.description ?? "")}</div>
    </div>
  `;
}

async function runScan(cmd) {
  const path = document.getElementById("scan-path").value.trim();
  const out = document.getElementById("scan-result");
  if (!path) { toast("Please enter a file path"); return; }
  if (!invoke) { out.textContent = "Tauri runtime not available."; return; }
  out.textContent = "Scanning...";
  renderVerdict(null, "scan-verdict");
  try {
    const result = await invoke(cmd, { path });
    out.textContent = JSON.stringify(result, null, 2);
    renderVerdict(result, "scan-verdict");
  } catch (e) {
    out.textContent = "Error: " + e;
    toast("Scan failed");
  }
}
document.getElementById("btn-scan").addEventListener("click", () => runScan("scan_file"));
document.getElementById("btn-qscan").addEventListener("click", () => runScan("quick_scan"));

// Drag & drop — Tauri v2 emits custom file-drop events via window.
const drop = document.getElementById("drop-card");
["dragenter", "dragover"].forEach((ev) =>
  drop.addEventListener(ev, (e) => {
    e.preventDefault();
    drop.classList.add("hover");
  })
);
["dragleave", "drop"].forEach((ev) =>
  drop.addEventListener(ev, (e) => {
    e.preventDefault();
    drop.classList.remove("hover");
  })
);
drop.addEventListener("drop", (e) => {
  if (e.dataTransfer?.files?.length) {
    const f = e.dataTransfer.files[0];
    document.getElementById("scan-path").value = f.path || f.name || "";
    toast("File attached");
  }
});

// ------------------------- Tune -------------------------

async function runTune(apply) {
  if (!invoke) { toast("Tauri runtime not available"); return; }
  const list = document.getElementById("tune-list");
  list.innerHTML = `<div class="empty">Working…</div>`;
  try {
    const cmd = apply ? "tune_apply" : "tune_plan";
    const report = await invoke(cmd);
    renderTune(report);
    toast(apply ? "Safe tweaks applied" : "Tune plan generated");
  } catch (e) {
    list.innerHTML = `<div class="empty">Error: ${escapeHtml(String(e))}</div>`;
    toast("Tune failed");
  }
}

function renderTune(report) {
  document.getElementById("tune-before").textContent = report.score_before;
  document.getElementById("tune-after").textContent = report.score_after;
  document.getElementById("tune-fill").style.width = report.score_after + "%";

  const list = document.getElementById("tune-list");
  if (!report.suggestions.length) {
    list.innerHTML = `<div class="empty">No suggestions — your system is already tuned.</div>`;
    return;
  }
  list.innerHTML = report.suggestions
    .map((s) => {
      const impact = (s.impact || "Low").toLowerCase();
      const tag = impact === "high" ? "high" : impact === "medium" ? "med" : "low";
      const applied = s.applied ? "applied" : "";
      return `
      <div class="suggestion">
        <span class="tag ${tag}">${impact}</span>
        <div>
          <div class="title">${escapeHtml(s.title)}</div>
          <div class="desc">${escapeHtml(s.description)}</div>
          <div class="cat">${escapeHtml(formatCategory(s.category))} · revert: ${escapeHtml(s.revert_hint)}</div>
        </div>
        <div class="check ${applied}">${s.applied ? "✓ Done" : "Pending"}</div>
      </div>`;
    })
    .join("");
}

function formatCategory(c) {
  if (!c) return "";
  return String(c).replace(/([A-Z])/g, " $1").trim();
}

document.getElementById("btn-tune-plan").addEventListener("click", () => runTune(false));
document.getElementById("btn-tune-apply").addEventListener("click", () => runTune(true));

// ------------------------- Deep Clean -------------------------

let lastCleanReport = null;

async function runCleanScan() {
  if (!invoke) { toast("Tauri runtime not available"); return; }
  const list = document.getElementById("clean-list");
  list.innerHTML = `<div class="empty">Scanning…</div>`;
  try {
    const report = await invoke("clean_scan");
    lastCleanReport = report;
    renderClean(report);
    toast(`Found ${formatBytes(report.total_bytes)}`);
  } catch (e) {
    list.innerHTML = `<div class="empty">Error: ${escapeHtml(String(e))}</div>`;
    toast("Scan failed");
  }
}

async function runCleanSweep() {
  if (!invoke) { toast("Tauri runtime not available"); return; }
  if (!lastCleanReport) { toast("Run a scan first"); return; }
  if (!confirm("Delete the selected reclaimable files? This cannot be undone.")) return;
  try {
    const result = await invoke("clean_sweep", { report: lastCleanReport });
    toast(`Freed ${formatBytes(result.bytes_freed)} (${result.files_deleted} files)`);
    runCleanScan();
  } catch (e) {
    toast("Sweep failed: " + e);
  }
}

function renderClean(report) {
  document.getElementById("clean-bytes").textContent = formatBytes(report.total_bytes);
  const breakdown = document.getElementById("clean-breakdown");
  const byCat = {};
  for (const t of report.targets) {
    byCat[t.category] = (byCat[t.category] || 0) + t.size_bytes;
  }
  breakdown.innerHTML = Object.entries(byCat)
    .sort((a, b) => b[1] - a[1])
    .map(([c, b]) => `<div class="chip">${escapeHtml(formatCategory(c))}<span class="dim">${formatBytes(b)}</span></div>`)
    .join("") || `<div style="color:var(--muted); font-size:12px">Nothing to show.</div>`;

  const list = document.getElementById("clean-list");
  if (!report.targets.length) {
    list.innerHTML = `<div class="empty">Nothing to reclaim. System is tidy.</div>`;
    return;
  }
  list.innerHTML = report.targets
    .map(
      (t, i) => `
    <div class="target ${t.selected ? "selected" : ""}" data-idx="${i}">
      <div class="check-box">✓</div>
      <div>
        <div class="title">${escapeHtml(t.description)}</div>
        <div class="path">${escapeHtml(t.path)} · ${t.file_count} files</div>
        <div class="cat">${escapeHtml(formatCategory(t.category))}</div>
      </div>
      <div class="size">${formatBytes(t.size_bytes)}</div>
    </div>`
    )
    .join("");

  list.querySelectorAll(".target").forEach((el) => {
    el.addEventListener("click", () => {
      const idx = parseInt(el.dataset.idx, 10);
      lastCleanReport.targets[idx].selected = !lastCleanReport.targets[idx].selected;
      el.classList.toggle("selected");
    });
  });
}

document.getElementById("btn-clean-scan").addEventListener("click", runCleanScan);
document.getElementById("btn-clean-sweep").addEventListener("click", runCleanSweep);

// ------------------------- Script Shield -------------------------

document.getElementById("btn-script").addEventListener("click", async () => {
  const path = document.getElementById("script-path").value.trim();
  const out = document.getElementById("script-result");
  if (!path) { toast("Enter a script path"); return; }
  if (!invoke) { out.textContent = "Tauri runtime not available."; return; }
  out.textContent = "Analyzing...";
  try {
    const report = await invoke("analyze_script", { path });
    out.textContent = JSON.stringify(report, null, 2);
    const verdict = document.getElementById("script-verdict");
    verdict.classList.remove("hidden", "clean", "warn", "bad");
    const risk = report.risk_score ?? 0;
    const kind = risk >= 70 ? "bad" : risk >= 40 ? "warn" : "clean";
    verdict.classList.add(kind);
    verdict.innerHTML = `
      <span class="badge">${escapeHtml(report.label ?? "Analyzed")}</span>
      <div>
        <div style="font-weight:600">${escapeHtml(report.language ?? "script")} · risk ${risk}/100</div>
        <div style="color:var(--muted); font-size:12px">${report.url_count ?? 0} URLs · ${report.api_call_count ?? 0} API calls · obfuscated: ${!!report.obfuscation_detected}</div>
      </div>
    `;
  } catch (e) {
    out.textContent = "Error: " + e;
  }
});

// ------------------------- AC Compat -------------------------

async function refreshCompat(full = false) {
  if (!invoke) return;
  try {
    const status = await invoke("compat_status");
    const summary = document.getElementById("compat-summary");
    const pill = document.getElementById("sidebar-status");
    if (!status.active_products.length) {
      summary.innerHTML = `<div><b>No game anti-cheat running.</b><br><span style="color:var(--muted)">Full protection is active. You're all clear.</span></div>`;
    } else {
      const list = status.active_products.map((p) => humanizeProduct(p)).join(", ");
      const safe = status.safe_mode ? "Safe mode enabled" : "Normal";
      summary.innerHTML = `
        <div><b>${escapeHtml(list)}</b> — ${escapeHtml(safe)}</div>
        <div style="color:var(--muted); margin-top:6px; font-size:12px">${escapeHtml(status.explanation)}</div>
      `;
      if (status.kernel_mode_active) {
        pill.classList.add("warn");
        pill.querySelector(".text").textContent = "AC safe mode";
      }
    }

    if (full) {
      const box = document.getElementById("compat-full");
      if (!status.active_products.length) {
        box.innerHTML = `<div class="panel-body"><b style="color:var(--green)">✓ No game anti-cheat detected.</b><br><span style="color:var(--muted)">AntiCheat is running at full capability.</span></div>`;
      } else {
        const rows = status.active_products
          .map((p) => `<div style="display:flex; align-items:center; gap:8px; margin:4px 0"><span style="width:8px; height:8px; border-radius:99px; background: ${isKernel(p) ? "var(--red)" : "var(--yellow)"}"></span><b>${escapeHtml(humanizeProduct(p))}</b> <span style="color:var(--muted); font-size:12px">${isKernel(p) ? "kernel-mode" : "user-mode"}</span></div>`)
          .join("");
        box.innerHTML = `
          <div class="panel-body">
            ${rows}
            <hr style="border:none; border-top:1px solid var(--border); margin:14px 0">
            <div><b>Safe mode:</b> ${status.safe_mode ? "enabled" : "off"}</div>
            <div style="color:var(--muted); margin-top:6px">${escapeHtml(status.explanation)}</div>
            <div style="color:var(--muted); margin-top:14px; font-size:12px">
              When safe mode is on, AntiCheat does not open process handles to games,
              does not load drivers, and only scans guarded game directories on demand.
              This is what keeps EAC, BattlEye, and Vanguard from treating us like a cheat.
            </div>
          </div>`;
      }
    }
  } catch (e) {
    console.error("compat_status failed", e);
  }
}

function humanizeProduct(p) {
  const map = {
    EasyAntiCheat: "Easy Anti-Cheat",
    BattlEye: "BattlEye",
    RiotVanguard: "Riot Vanguard",
    FaceitAc: "FACEIT AC",
    EsportsAc: "ESEA",
    PunkBuster: "PunkBuster",
    XignCode3: "XIGNCODE3",
    MiHoYoAc: "miHoYo AC",
    Ricochet: "Ricochet",
    Denuvo: "Denuvo",
    Steam: "VAC",
  };
  return map[p] ?? p;
}
function isKernel(p) {
  return ["RiotVanguard", "Ricochet", "MiHoYoAc", "XignCode3", "FaceitAc"].includes(p);
}

document.getElementById("refresh-compat").addEventListener("click", () => refreshCompat(false));
document.getElementById("btn-compat-refresh").addEventListener("click", () => refreshCompat(true));

// ------------------------- Helpers -------------------------

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = bytes;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 ? 2 : 1)} ${units[i]}`;
}

function escapeHtml(s) {
  if (s == null) return "";
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

// ------------------------- Initial load -------------------------
refreshStats();
refreshCompat(false);
refreshCompat(true);
