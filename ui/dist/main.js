// ═══════════════════════════════════════════════════════════════════════
// AntiCheat — frontend logic.
// Tauri v2 invoke API + animated particle background + counters.
// ═══════════════════════════════════════════════════════════════════════

const invoke = window.__TAURI__?.core?.invoke;

// ────────────── Particle background ──────────────
(function initParticles() {
  const c = document.getElementById("bg-canvas");
  if (!c) return;
  const ctx = c.getContext("2d");
  let W, H, particles = [], mouse = { x: -999, y: -999 };
  const COUNT = 60, CONNECT_DIST = 140, MOUSE_DIST = 180;

  function resize() {
    W = c.width = window.innerWidth;
    H = c.height = window.innerHeight;
  }
  window.addEventListener("resize", resize);
  resize();

  for (let i = 0; i < COUNT; i++) {
    particles.push({
      x: Math.random() * W,
      y: Math.random() * H,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      r: Math.random() * 1.5 + 0.5,
    });
  }

  document.addEventListener("mousemove", (e) => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
  });

  function draw() {
    ctx.clearRect(0, 0, W, H);
    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0 || p.x > W) p.vx *= -1;
      if (p.y < 0 || p.y > H) p.vy *= -1;

      // Mouse repulsion
      const dx = p.x - mouse.x, dy = p.y - mouse.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < MOUSE_DIST) {
        const force = (MOUSE_DIST - dist) / MOUSE_DIST * 0.015;
        p.vx += dx * force;
        p.vy += dy * force;
      }
      // Dampen
      p.vx *= 0.999;
      p.vy *= 0.999;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(167,139,250,0.35)";
      ctx.fill();

      // Connections
      for (let j = i + 1; j < particles.length; j++) {
        const q = particles[j];
        const dx2 = p.x - q.x, dy2 = p.y - q.y;
        const d = Math.sqrt(dx2 * dx2 + dy2 * dy2);
        if (d < CONNECT_DIST) {
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(q.x, q.y);
          const alpha = (1 - d / CONNECT_DIST) * 0.12;
          ctx.strokeStyle = `rgba(167,139,250,${alpha})`;
          ctx.lineWidth = 0.6;
          ctx.stroke();
        }
      }
    }
    requestAnimationFrame(draw);
  }
  draw();
})();

// ────────────── Toast ──────────────
const toastInner = document.getElementById("toast-inner");
let toastTimer = null;
function toast(msg) {
  toastInner.textContent = msg;
  toastInner.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toastInner.classList.remove("show"), 2600);
}

// ────────────── Navigation ──────────────
function go(view) {
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  const btn = document.querySelector(`.nav-item[data-view="${view}"]`);
  if (btn) btn.classList.add("active");
  const sec = document.getElementById("view-" + view);
  if (sec) sec.classList.add("active");
}
document.querySelectorAll(".nav-item").forEach((b) =>
  b.addEventListener("click", () => go(b.dataset.view))
);
document.querySelectorAll("[data-go]").forEach((el) =>
  el.addEventListener("click", () => go(el.dataset.go))
);
document.getElementById("btn-go-scan").addEventListener("click", () => go("scan"));
document.getElementById("btn-home-scan").addEventListener("click", () => go("scan"));

// ────────────── Animated counter ──────────────
function animateCounter(el, to, duration = 600) {
  const from = parseInt(el.textContent) || 0;
  if (from === to) { el.textContent = to; return; }
  const start = performance.now();
  function tick(now) {
    const t = Math.min((now - start) / duration, 1);
    const ease = 1 - Math.pow(1 - t, 3); // ease-out cubic
    el.textContent = Math.round(from + (to - from) * ease);
    if (t < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

// ────────────── Dashboard ──────────────
async function refreshStats() {
  if (!invoke) return;
  try {
    const s = await invoke("get_stats");
    animateCounter(document.getElementById("stat-sigs"), s.signatures);
    animateCounter(document.getElementById("stat-wl"), s.whitelist);
    animateCounter(document.getElementById("stat-games"), s.games);
    animateCounter(document.getElementById("stat-qf"), s.quarantine_files);

    const q = s.quarantine_files || 0;
    const score = Math.max(0, Math.min(100, 92 - q * 8));
    setScore(score, s);
  } catch (e) {
    console.error("get_stats", e);
  }
}

function setScore(score, stats) {
  const ring = document.getElementById("ring-progress");
  const ringTop = document.getElementById("ring-progress-top");
  const label = document.getElementById("ring-score");
  const title = document.getElementById("hero-title");
  const sub = document.getElementById("hero-subtitle");
  const pill = document.getElementById("status-indicator");

  const circ = 2 * Math.PI * 88;
  const offset = circ * (1 - score / 100);
  ring.style.strokeDashoffset = offset;
  ringTop.style.strokeDashoffset = offset;

  animateCounter(label, score, 900);

  pill.classList.remove("warn");
  if (score >= 80) {
    title.textContent = "Systems nominal";
    sub.textContent = `No active threats. ${stats?.signatures ?? 0} signatures loaded.`;
    pill.querySelector(".status-text").textContent = "Protected";
  } else if (score >= 50) {
    title.textContent = "Review needed";
    sub.textContent = `${stats?.quarantine_files ?? 0} files quarantined. Consider reviewing.`;
    pill.classList.add("warn");
    pill.querySelector(".status-text").textContent = "Review";
  } else {
    title.textContent = "Action required";
    sub.textContent = "Multiple threats detected. Run a deep scan.";
    pill.classList.add("warn");
    pill.querySelector(".status-text").textContent = "At risk";
  }
}

document.getElementById("refresh-stats").addEventListener("click", () => {
  refreshStats();
  toast("Stats refreshed");
});

// ────────────── Scan ──────────────
function showVerdict(result, targetId) {
  const el = document.getElementById(targetId);
  if (!result) { el.classList.add("hidden"); return; }
  el.classList.remove("hidden", "clean", "warn", "bad");
  const level = result.threat_info?.threat_level ?? "Clean";
  const kind = level === "Clean" ? "clean"
    : (level === "Suspicious" || level === "CheatDetected") ? "warn" : "bad";
  el.classList.add(kind);
  el.innerHTML = `
    <span class="verdict-badge">${esc(level)}</span>
    <div>
      <div style="font-weight:700">${esc(result.file_name ?? "file")}</div>
      <div style="color:var(--text-3);font-size:12px;margin-top:2px">
        Confidence ${result.threat_info?.confidence_score ?? 0}%
        · ${esc(result.threat_info?.description ?? "")}
      </div>
    </div>`;
}

async function doScan(cmd) {
  const path = document.getElementById("scan-path").value.trim();
  const out = document.getElementById("scan-output");
  if (!path) { toast("Enter a file path first"); return; }
  if (!invoke) { out.textContent = "Tauri runtime not available."; return; }
  out.textContent = "Scanning…";
  showVerdict(null, "scan-verdict");
  try {
    const r = await invoke(cmd, { path });
    out.textContent = JSON.stringify(r, null, 2);
    showVerdict(r, "scan-verdict");
    toast("Scan complete");
  } catch (e) {
    out.textContent = "Error: " + e;
    toast("Scan failed");
  }
}
document.getElementById("btn-deep-scan").addEventListener("click", () => doScan("scan_file"));
document.getElementById("btn-quick-scan").addEventListener("click", () => doScan("quick_scan"));

// Drop zone
const dz = document.getElementById("drop-zone");
["dragenter", "dragover"].forEach((e) => dz.addEventListener(e, (ev) => { ev.preventDefault(); dz.classList.add("hovering"); }));
["dragleave", "drop"].forEach((e) => dz.addEventListener(e, (ev) => { ev.preventDefault(); dz.classList.remove("hovering"); }));
dz.addEventListener("drop", (e) => {
  if (e.dataTransfer?.files?.length) {
    document.getElementById("scan-path").value = e.dataTransfer.files[0].path || e.dataTransfer.files[0].name || "";
    toast("File attached — click scan");
  }
});

// ────────────── Tune ──────────────
async function runTune(apply) {
  if (!invoke) { toast("Tauri not available"); return; }
  const list = document.getElementById("tune-list");
  list.innerHTML = `<div class="empty-state glass"><div class="empty-icon">⏳</div><div class="empty-title">Working…</div></div>`;
  try {
    const report = await invoke(apply ? "tune_apply" : "tune_plan");
    renderTune(report);
    toast(apply ? "Safe tweaks applied" : "Tune plan ready");
  } catch (e) {
    list.innerHTML = `<div class="empty-state glass"><div class="empty-title">Error: ${esc(String(e))}</div></div>`;
  }
}

function renderTune(r) {
  document.getElementById("tune-score-before").textContent = r.score_before;
  document.getElementById("tune-score-after").textContent = r.score_after;
  document.getElementById("tune-bar-fill").style.width = r.score_after + "%";

  const list = document.getElementById("tune-list");
  if (!r.suggestions.length) {
    list.innerHTML = `<div class="empty-state glass"><div class="empty-icon">🎉</div><div class="empty-title">Nothing to tune</div><div class="empty-hint">Your system is already optimized</div></div>`;
    return;
  }
  list.innerHTML = r.suggestions.map((s) => {
    const imp = (s.impact || "Low").toLowerCase();
    const tag = imp === "high" ? "high" : imp === "medium" ? "med" : "low";
    return `
    <div class="suggestion-card">
      <span class="impact-tag ${tag}">${imp}</span>
      <div>
        <div class="sug-title">${esc(s.title)}</div>
        <div class="sug-desc">${esc(s.description)}</div>
        <div class="sug-meta">${esc(fmtCat(s.category))} · revert: ${esc(s.revert_hint)}</div>
      </div>
      <div class="sug-status ${s.applied ? "done" : ""}">${s.applied ? "✓ Applied" : "Pending"}</div>
    </div>`;
  }).join("");
}

document.getElementById("btn-tune-plan").addEventListener("click", () => runTune(false));
document.getElementById("btn-tune-apply").addEventListener("click", () => runTune(true));

// ────────────── Deep Clean ──────────────
let cleanReport = null;

async function runCleanScan() {
  if (!invoke) { toast("Tauri not available"); return; }
  const list = document.getElementById("clean-list");
  list.innerHTML = `<div class="empty-state glass"><div class="empty-icon">⏳</div><div class="empty-title">Scanning…</div></div>`;
  try {
    const r = await invoke("clean_scan");
    cleanReport = r;
    renderClean(r);
    toast(`Found ${fmtBytes(r.total_bytes)} reclaimable`);
  } catch (e) {
    list.innerHTML = `<div class="empty-state glass"><div class="empty-title">Error: ${esc(String(e))}</div></div>`;
  }
}

async function runCleanSweep() {
  if (!invoke || !cleanReport) { toast("Run a scan first"); return; }
  if (!confirm("Delete selected reclaimable files? This can't be undone.")) return;
  try {
    const r = await invoke("clean_sweep", { report: cleanReport });
    toast(`Freed ${fmtBytes(r.bytes_freed)} (${r.files_deleted} files)`);
    runCleanScan(); // refresh
  } catch (e) { toast("Sweep error: " + e); }
}

function renderClean(r) {
  document.getElementById("clean-amount").textContent = fmtBytes(r.total_bytes);
  const byCat = {};
  for (const t of r.targets) byCat[t.category] = (byCat[t.category] || 0) + t.size_bytes;
  document.getElementById("clean-chips").innerHTML = Object.entries(byCat)
    .sort((a, b) => b[1] - a[1])
    .map(([c, b]) => `<div class="chip">${esc(fmtCat(c))}<span class="dim">${fmtBytes(b)}</span></div>`)
    .join("");

  const list = document.getElementById("clean-list");
  if (!r.targets.length) {
    list.innerHTML = `<div class="empty-state glass"><div class="empty-icon">🎉</div><div class="empty-title">Squeaky clean</div><div class="empty-hint">Nothing to reclaim</div></div>`;
    return;
  }
  list.innerHTML = r.targets.map((t, i) => `
    <div class="target-card ${t.selected ? "selected" : ""}" data-idx="${i}">
      <div class="check-box">✓</div>
      <div>
        <div class="target-title">${esc(t.description)}</div>
        <div class="target-path">${esc(t.path)} · ${t.file_count} files</div>
        <div class="target-cat">${esc(fmtCat(t.category))}</div>
      </div>
      <div class="target-size">${fmtBytes(t.size_bytes)}</div>
    </div>`).join("");

  list.querySelectorAll(".target-card").forEach((el) => {
    el.addEventListener("click", () => {
      const i = +el.dataset.idx;
      cleanReport.targets[i].selected = !cleanReport.targets[i].selected;
      el.classList.toggle("selected");
    });
  });
}

document.getElementById("btn-clean-scan").addEventListener("click", runCleanScan);
document.getElementById("btn-clean-sweep").addEventListener("click", runCleanSweep);

// ────────────── Script Shield ──────────────
document.getElementById("btn-script-analyze").addEventListener("click", async () => {
  const path = document.getElementById("script-path").value.trim();
  const out = document.getElementById("script-output");
  if (!path) { toast("Enter a script path"); return; }
  if (!invoke) { out.textContent = "Tauri not available."; return; }
  out.textContent = "Analyzing…";
  try {
    const r = await invoke("analyze_script", { path });
    out.textContent = JSON.stringify(r, null, 2);
    const v = document.getElementById("script-verdict");
    v.classList.remove("hidden", "clean", "warn", "bad");
    const risk = r.risk_score ?? 0;
    v.classList.add(risk >= 70 ? "bad" : risk >= 40 ? "warn" : "clean");
    v.innerHTML = `
      <span class="verdict-badge">${esc(r.label ?? "Analyzed")}</span>
      <div>
        <div style="font-weight:700">${esc(r.language ?? "script")} · risk ${risk}/100</div>
        <div style="color:var(--text-3);font-size:12px;margin-top:2px">
          ${r.url_count ?? 0} URLs · ${r.api_call_count ?? 0} API calls · obfuscated: ${!!r.obfuscation_detected}
        </div>
      </div>`;
    toast("Analysis complete");
  } catch (e) {
    out.textContent = "Error: " + e;
  }
});

// ────────────── AC Compat ──────────────
async function refreshCompat(full = false) {
  if (!invoke) return;
  try {
    const s = await invoke("compat_status");
    const dash = document.getElementById("compat-dash");
    if (!s.active_products.length) {
      dash.innerHTML = `<div style="display:flex;align-items:center;gap:10px">
        <span style="color:var(--emerald);font-size:18px">✓</span>
        <div><b>No game anti-cheat running</b><br><span style="color:var(--text-3);font-size:12px">Full protection active</span></div>
      </div>`;
    } else {
      const names = s.active_products.map(humanAC).join(", ");
      dash.innerHTML = `<div>
        <b style="color:var(--amber)">${esc(names)}</b>
        <div style="color:var(--text-3);font-size:12px;margin-top:4px">${esc(s.explanation)}</div>
      </div>`;
    }

    if (full) {
      const box = document.getElementById("compat-full");
      if (!s.active_products.length) {
        box.innerHTML = `<div class="panel-content" style="padding:32px;text-align:center">
          <div style="font-size:32px;margin-bottom:8px;opacity:.6">🛡</div>
          <div style="font-weight:700;color:var(--emerald)">No game anti-cheat detected</div>
          <div style="color:var(--text-3);margin-top:4px">AntiCheat is running at full capability.</div>
        </div>`;
      } else {
        const rows = s.active_products.map(p => {
          const k = isKernel(p);
          return `<div style="display:flex;align-items:center;gap:10px;padding:8px 0">
            <span style="width:10px;height:10px;border-radius:50%;background:${k ? "var(--red)" : "var(--amber)"};box-shadow:0 0 8px ${k ? "var(--red)" : "var(--amber)"}"></span>
            <b>${esc(humanAC(p))}</b>
            <span style="font-size:11px;padding:2px 8px;border-radius:99px;background:${k ? "var(--red-dim)" : "var(--amber-dim)"};color:${k ? "var(--red)" : "var(--amber)"}">${k ? "kernel" : "user"}</span>
          </div>`;
        }).join("");
        box.innerHTML = `<div class="panel-content">
          ${rows}<hr>
          <div><b>Safe mode:</b> ${s.safe_mode ? '<span style="color:var(--emerald)">ON</span>' : "OFF"}</div>
          <div style="color:var(--text-3);margin-top:8px">${esc(s.explanation)}</div>
          <div style="color:var(--text-3);margin-top:16px;font-size:12px;padding:14px;background:var(--surface-2);border-radius:var(--r-xs)">
            When safe mode is active, AntiCheat never opens process handles to games,
            never loads drivers, and only scans guarded game directories on explicit demand.
            This is how we stay invisible to EAC, BattlEye, Vanguard, and other kernel anti-cheats.
          </div>
        </div>`;
      }
    }
  } catch (e) {
    console.error("compat", e);
  }
}

document.getElementById("dash-compat-refresh").addEventListener("click", () => refreshCompat(false));
document.getElementById("btn-compat-refresh").addEventListener("click", () => refreshCompat(true));

// ────────────── Helpers ──────────────
function fmtBytes(b) {
  if (!b) return "0 B";
  const u = ["B","KB","MB","GB","TB"];
  let i = 0, v = b;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v < 10 ? v.toFixed(2) : v.toFixed(1)} ${u[i]}`;
}
function fmtCat(c) {
  if (!c) return "";
  return String(c).replace(/([A-Z])/g, " $1").trim();
}
function esc(s) {
  if (s == null) return "";
  return String(s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
}
function humanAC(p) {
  return {EasyAntiCheat:"Easy Anti-Cheat",BattlEye:"BattlEye",RiotVanguard:"Riot Vanguard",
    FaceitAc:"FACEIT AC",EsportsAc:"ESEA",PunkBuster:"PunkBuster",XignCode3:"XIGNCODE3",
    MiHoYoAc:"miHoYo AC",Ricochet:"Ricochet",Denuvo:"Denuvo",Steam:"VAC"}[p] ?? p;
}
function isKernel(p) {
  return ["RiotVanguard","Ricochet","MiHoYoAc","XignCode3","FaceitAc"].includes(p);
}

// ────────────── Boot ──────────────
refreshStats();
refreshCompat(false);
refreshCompat(true);
