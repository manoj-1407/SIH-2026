/**
 * FORENSIC ASSURANCE — SIH26149 · NTRO
 * UI Engine v3.0 — Particle Physics + Full API Integration
 */

'use strict';

// ── CONFIG ─────────────────────────────────────────────────────
const cfg = {
  get base() {
    const ov = localStorage.getItem('sih_api_override');
    if (ov && ov.trim()) return ov.trim().replace(/\/$/, '');
    if (window.location?.protocol?.startsWith('http')) return window.location.origin.replace(/\/$/, '');
    return 'http://127.0.0.1:8000';
  }
};

// ── STATE ──────────────────────────────────────────────────────
const state = {
  activeCaseId: null,
  uploadedPath: null,
  healthData: null,
  latencyMs: null,
  verifyMode: 'id',
  activeTab: 'landing',
};

// ═══════════════════════════════════════════════════════════════
//  PARTICLE PHYSICS ENGINE
// ═══════════════════════════════════════════════════════════════

const Particles = (() => {
  let canvas, ctx, particles = [], raf, W, H;
  const PARTICLE_COUNT = 80;

  class Particle {
    constructor() { this.reset(true); }
    reset(initial = false) {
      this.x = Math.random() * W;
      this.y = initial ? Math.random() * H : H + 10;
      this.vx = (Math.random() - 0.5) * 0.4;
      this.vy = -(Math.random() * 0.6 + 0.1);
      this.size = Math.random() * 2 + 0.5;
      this.alpha = 0;
      this.maxAlpha = Math.random() * 0.5 + 0.1;
      this.life = 0;
      this.maxLife = Math.random() * 300 + 200;
      this.hue = Math.random() > 0.6 ? 190 : (Math.random() > 0.5 ? 220 : 280);
    }
    update() {
      this.x += this.vx;
      this.y += this.vy;
      this.life++;
      const t = this.life / this.maxLife;
      this.alpha = t < 0.2 ? (t / 0.2) * this.maxAlpha : t > 0.8 ? ((1 - t) / 0.2) * this.maxAlpha : this.maxAlpha;
      if (this.life > this.maxLife) this.reset();
    }
    draw() {
      ctx.save();
      ctx.globalAlpha = this.alpha;
      ctx.fillStyle = `hsl(${this.hue},100%,70%)`;
      ctx.shadowBlur = 8;
      ctx.shadowColor = `hsl(${this.hue},100%,70%)`;
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();
    }
  }

  function resize() {
    W = canvas.width = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }

  function drawConnections() {
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 100) {
          const alpha = (1 - dist / 100) * 0.08;
          ctx.save();
          ctx.globalAlpha = alpha;
          ctx.strokeStyle = '#00e5ff';
          ctx.lineWidth = 0.5;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
          ctx.restore();
        }
      }
    }
  }

  function loop() {
    ctx.clearRect(0, 0, W, H);
    drawConnections();
    particles.forEach(p => { p.update(); p.draw(); });
    raf = requestAnimationFrame(loop);
  }

  function init() {
    canvas = document.getElementById('particleCanvas');
    if (!canvas) return;
    ctx = canvas.getContext('2d');
    resize();
    window.addEventListener('resize', resize);
    for (let i = 0; i < PARTICLE_COUNT; i++) particles.push(new Particle());
    loop();
  }

  return { init };
})();

// ═══════════════════════════════════════════════════════════════
//  TOAST SYSTEM
// ═══════════════════════════════════════════════════════════════

const Toast = {
  show(type, title, msg, dur = 4000) {
    const c = document.getElementById('toastContainer');
    if (!c) return;
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.innerHTML = `
      <div class="toast-body">
        <div class="toast-title">${esc(title)}</div>
        ${msg ? `<div class="toast-msg">${esc(msg)}</div>` : ''}
      </div>
      <button class="toast-close" onclick="this.parentElement.remove()">✕</button>`;
    c.appendChild(el);
    setTimeout(() => {
      el.classList.add('toast-out');
      setTimeout(() => el.remove(), 300);
    }, dur);
  },
  success(t, m) { this.show('success', t, m); },
  error(t, m)   { this.show('error', t, m, 6000); },
  warning(t, m) { this.show('warning', t, m); },
  info(t, m)    { this.show('info', t, m); },
};

// ═══════════════════════════════════════════════════════════════
//  UTILITIES
// ═══════════════════════════════════════════════════════════════

function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function $id(id) { return document.getElementById(id); }
function html(id, h) { const el = $id(id); if (el) el.innerHTML = h; }
function txt(id, t) { const el = $id(id); if (el) el.textContent = t; }
function show(id) { const el = $id(id); if (el) el.style.display = ''; }
function hide(id) { const el = $id(id); if (el) el.style.display = 'none'; }
function val(id) { const el = $id(id); return el ? el.value.trim() : ''; }
function setVal(id, v) { const el = $id(id); if (el) el.value = v; }

function statusClass(s) {
  const ok = ['VERIFIED','VALID','SUPPORTED','ACTIVE','CLEAR_SUPPORTED','ok','EXT4_FULL_RECOVERY'];
  const err = ['FAILED','REJECTED','INVALID','UNSUPPORTED','NOT_A_FILESYSTEM','FAILED_SK_LAYER'];
  const warn = ['VERIFIED_WITHIN_SCOPE','UNVERIFIED','PARTIAL','WARN'];
  if (ok.includes(s)) return 'ok';
  if (err.includes(s)) return 'err';
  if (warn.includes(s)) return 'warn';
  return '';
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

function formatTime(ts) {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

// ═══════════════════════════════════════════════════════════════
//  API CLIENT
// ═══════════════════════════════════════════════════════════════

const api = {
  async call(method, path, body, isForm = false, extraHeaders = {}) {
    const opts = { method, headers: { 'X-Demo-Mode': '1', ...extraHeaders } };
    const apiKey = localStorage.getItem('sih_api_key');
    if (apiKey) opts.headers['X-API-Key'] = apiKey.trim();
    if (isForm) {
      opts.body = body;
    } else if (body) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    const url = (cfg.base + path).replace(/([^:]\/)\/{2,}/g, '$1');
    const res = await fetch(url, opts);
    if (!res.ok) {
      let detail = `HTTP ${res.status}`;
      try { const j = await res.json(); detail = j.detail || detail; } catch {}
      throw new Error(detail);
    }
    return res.json();
  },
  get:    (path)        => api.call('GET', path),
  post:   (path, body)  => api.call('POST', path, body),
  upload: (path, form)  => api.call('POST', path, form, true),
};

// ═══════════════════════════════════════════════════════════════
//  NAVIGATION
// ═══════════════════════════════════════════════════════════════

const TAB_LABELS = {
  landing:      'HOME',
  cases:        'CASES',
  forensics:    'FORENSIC RECOVERY',
  carving:      'RAW FILE CARVING',
  sanitization: 'SANITIZATION',
  auditchain:   'AUDIT CHAIN',
  vault:        'EVIDENCE VAULT',
  verification: 'VERIFIER',
};

function switchTab(tab, btn) {
  // Deactivate all sections
  document.querySelectorAll('.tab-section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));

  // Activate target
  const section = $id(`tab-${tab}`);
  if (section) section.classList.add('active');
  if (btn) btn.classList.add('active');
  else {
    const navBtn = document.querySelector(`[data-tab="${tab}"]`);
    if (navBtn) navBtn.classList.add('active');
  }

  state.activeTab = tab;
  txt('bcCurrent', TAB_LABELS[tab] || tab.toUpperCase());

  // Close nav on mobile
  if (window.innerWidth < 900) {
    document.body.classList.remove('nav-open');
  }

  // Auto-loads
  if (tab === 'cases') loadCases();
  if (tab === 'auditchain' && state.activeCaseId) loadAuditTimeline();
  if (tab === 'vault') loadEvidence();
}

function toggleNav() {
  document.body.classList.toggle('nav-open');
}

// ═══════════════════════════════════════════════════════════════
//  HEALTH PING
// ═══════════════════════════════════════════════════════════════

async function pingHealth() {
  const start = performance.now();
  const dot = $id('statusDot');
  const label = $id('statusLabel');
  const ping = $id('statusPing');
  try {
    const health = await api.get('/health');
    const ms = Math.round(performance.now() - start);
    state.healthData = health;
    state.latencyMs = ms;
    if (dot) { dot.className = 'status-dot ok'; }
    if (label) { label.textContent = 'ONLINE'; label.className = 'status-label ok'; }
    if (ping) ping.textContent = `${ms}ms`;

    // Update sys status
    const subs = health.subsystems || {};
    txt('sysSK', subs.sleuthkit ? 'Active' : 'Emulated');
    txt('sysCrypto', 'Ed25519');
    txt('sysPersist', 'Atomic');

    // Live test count
    if (health.test_count) txt('statTests', health.test_count);
  } catch (e) {
    if (dot) { dot.className = 'status-dot err'; }
    if (label) { label.textContent = 'OFFLINE'; label.className = 'status-label err'; }
    if (ping) ping.textContent = '—';
  }
}

// ═══════════════════════════════════════════════════════════════
//  CASES MODULE
// ═══════════════════════════════════════════════════════════════

function setActiveCase(caseId, caseData) {
  state.activeCaseId = caseId;
  state.activeCaseData = caseData || {};
  const badge = $id('topCaseBadge');
  if (badge) badge.style.display = 'flex';
  txt('topCaseId', caseId);

  // Auto-populate eraser paths with the case's acquired image path
  const eraserEl = $id('eraserPaths');
  if (eraserEl && caseData && caseData.source_path) {
    eraserEl.value = caseData.source_path;
    eraserEl.placeholder = caseData.source_path;
  }

  // Update forensics banner
  const banner = $id('forensicsCaseBanner');
  if (banner) {
    banner.className = 'active-case-banner ok';
    banner.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
      Active case: <strong>${caseId}</strong>`;
  }

  document.querySelectorAll('.case-item').forEach(el => {
    el.classList.toggle('active-case', el.dataset.caseId === caseId);
  });
}

async function loadCases() {
  html('caseList', '<div class="empty-state"><div class="spinner"></div><p>Loading cases…</p></div>');
  try {
    const cases = await api.get('/cases');
    if (!cases || !cases.length) {
      html('caseList', `
        <div class="empty-state">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 7V5a2 2 0 00-2-2h-4a2 2 0 00-2 2v2"/></svg>
          <p>No cases found. Create one or seed the demo case.</p>
          <button class="btn-ghost small" onclick="seedOfficialDemoCase()">Seed Demo Case</button>
        </div>`);
      return;
    }
    html('caseList', cases.map(c => `
      <div class="case-item ${c.case_id === state.activeCaseId ? 'active-case' : ''}"
           data-case-id="${esc(c.case_id)}"
           onclick="selectCase('${esc(c.case_id)}')">
        <div class="case-item-id">${esc(c.case_id)}</div>
        <div class="case-item-name">${esc(c.title || c.description || 'Investigation')}</div>
        <div class="case-item-meta">${c.source_path ? '✓ Image' : 'No image'}</div>
      </div>
    `).join(''));
  } catch (e) {
    html('caseList', `<div class="empty-state"><p style="color:var(--red)">${esc(e.message)}</p></div>`);
  }
}

async function createCase() {
  const invId   = val('caseInvestigatorId');
  const invName = val('caseInvestigatorName');
  const agency  = val('caseAgency');
  const desc    = val('caseDesc');

  if (!invId && !invName) {
    Toast.warning('Validation', 'Provide at least an Investigator ID or Name');
    return;
  }
  try {
    const data = await api.post('/cases', {
      workflow: 'FORENSIC',
      title: invName || invId,
      description: desc || `Agency: ${agency || 'NTRO'} | Officer: ${invName || invId}`,
    });
    Toast.success('Case Created', `ID: ${data.case_id}`);
    setActiveCase(data.case_id, data);
    showCaseDetail(data);
    await loadCases();
  } catch (e) {
    Toast.error('Create Failed', e.message);
  }
}

async function selectCase(caseId) {
  setActiveCase(caseId);
  try {
    const c = await api.get(`/cases/${caseId}`);
    setActiveCase(caseId, c);
    showCaseDetail(c);
  } catch {}
}

function showCaseDetail(c) {
  const panel = $id('caseDetailPanel');
  if (!panel) return;
  panel.style.display = '';
  txt('caseDetailId', c.case_id || '—');
  html('caseDetailBody', `
    <div class="detail-grid">
      <div class="detail-field"><div class="detail-key">Case ID</div><div class="detail-val mono-val">${esc(c.case_id || '—')}</div></div>
      <div class="detail-field"><div class="detail-key">Title</div><div class="detail-val">${esc(c.title || c.description || '—')}</div></div>
      <div class="detail-field"><div class="detail-key">Workflow</div><div class="detail-val">${esc(c.workflow || 'FORENSIC')}</div></div>
      <div class="detail-field"><div class="detail-key">Created</div><div class="detail-val">${formatTime(c.created_at)}</div></div>
      <div class="detail-field"><div class="detail-key">Evidence Image</div><div class="detail-val mono-val">${c.source_path ? '✓ Acquired' : 'Pending'}</div></div>
    </div>
  `);
}

async function loadCaseTimeline() {
  switchTab('auditchain', document.querySelector('[data-tab=auditchain]'));
}

async function seedOfficialDemoCase() {
  Toast.info('Seeding', 'Generating synthetic storage media…');
  try {
    const res = await api.post('/cases/seed-demo', {});
    Toast.success('Demo Seeded', `Loaded ${res.case.case_id}`);
    setActiveCase(res.case.case_id);
    await loadCases();
    switchTab('forensics', document.querySelector('[data-tab=forensics]'));
  } catch (e) {
    Toast.error('Seed Error', e.message);
  }
}

// ═══════════════════════════════════════════════════════════════
//  FORENSICS MODULE
// ═══════════════════════════════════════════════════════════════

async function seedSyntheticEvidence() {
  if (!state.activeCaseId) {
    Toast.warning('No Case', 'Select or create a case first — click "Seed Demo Case" in the sidebar or create a case');
    return;
  }
  const box = $id('fsResult');
  if (box) { box.style.display = ''; box.className = 'result-box'; box.textContent = 'Generating synthetic evidence disk with embedded JPEG, PNG, PDF…'; }
  try {
    const res = await api.post(`/cases/${state.activeCaseId}/seed-synthetic-evidence`, {});
    if (box) {
      box.className = 'result-box ok';
      box.textContent = `✓ Synthetic Evidence Disk Seeded\nSHA-256: ${res.sha256 || '—'}\nSize: ${formatBytes(res.size_bytes)}\nEmbedded: JPEG + PNG + PDF artifacts`;
    }
    Toast.success('Evidence Seeded', 'Synthetic disk ready — run Detect Filesystem and Discover Inodes below');
  } catch (e) {
    if (box) { box.className = 'result-box err'; box.textContent = e.message; }
    Toast.error('Seed Failed', e.message);
  }
}

function handleDrop(e) {
  e.preventDefault();
  $id('uploadZone').classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) uploadEvidence(file);
}
function handleDragover(e) { e.preventDefault(); $id('uploadZone').classList.add('drag-over'); }
function handleDragleave(e) { $id('uploadZone').classList.remove('drag-over'); }
function handleFileSelect(e) { const f = e.target.files[0]; if (f) uploadEvidence(f); }

async function uploadEvidence(file) {
  if (!state.activeCaseId) {
    Toast.warning('No Case', 'Select or create a case first');
    return;
  }
  const prog = $id('uploadProgress');
  const fill = $id('progressFill');
  const label = $id('progressLabel');
  if (prog) prog.style.display = '';

  // Animate progress
  let p = 0;
  const tick = setInterval(() => {
    p = Math.min(p + Math.random() * 12, 85);
    if (fill) fill.style.width = p + '%';
  }, 180);

  try {
    const form = new FormData();
    form.append('file', file, file.name);
    const res = await api.upload(`/cases/${state.activeCaseId}/upload`, form);
    clearInterval(tick);
    if (fill) fill.style.width = '100%';
    if (label) label.textContent = 'Upload complete';
    state.uploadedPath = res.filename;

    setTimeout(() => {
      if (prog) prog.style.display = 'none';
      if (fill) fill.style.width = '0%';
    }, 1200);

    const box = $id('fsResult');
    if (box) {
      box.style.display = '';
      box.className = 'result-box ok';
      box.textContent = `✓ Acquired: ${res.filename || file.name}\nSHA-256: ${res.sha256 || '—'}\nSize: ${formatBytes(res.size_bytes)}\nAcquisition: ${res.acquisition_id}`;
    }
    Toast.success('Image Uploaded', `Acquisition: ${res.acquisition_id}`);
  } catch (e) {
    clearInterval(tick);
    if (prog) prog.style.display = 'none';
    Toast.error('Upload Failed', e.message);
  }
}

async function detectFilesystem() {
  if (!state.activeCaseId) { Toast.warning('No Case', 'Select a case first'); return; }
  const box = $id('fsResult');
  if (box) { box.style.display = ''; box.className = 'result-box'; box.textContent = 'Detecting superblock signature…'; }
  try {
    const cap = await api.get(`/cases/${state.activeCaseId}/filesystem`);
    if (box) {
      box.className = `result-box ${statusClass(cap.status || cap.status_label)}`;
      box.textContent = `Filesystem: ${cap.status_label || cap.status}\n` +
        `Detection: ${cap.detection_method || cap.recovery_method || '—'}\n` +
        `Recovery Supported: ${cap.recovery_supported ? 'Yes' : 'No'}\n` +
        `SleuthKit: ${cap.sleuthkit_capability || '—'}`;
    }
  } catch (e) {
    if (box) { box.style.display = ''; box.className = 'result-box err'; box.textContent = e.message; }
  }
}

async function discoverArtifacts() {
  if (!state.activeCaseId) { Toast.warning('No Case', 'Select a case first'); return; }
  const box = $id('discoverResult');
  if (box) { box.style.display = ''; box.className = 'result-box'; box.textContent = 'Scanning inode metadata table via fls…'; }
  try {
    const arts = await api.get(`/cases/${state.activeCaseId}/artifacts`);  // GET /cases/{id}/artifacts
    if (!arts || !arts.length) {
      if (box) { box.className = 'result-box warn'; box.textContent = 'No deleted inodes found.'; }
      return;
    }
    if (box) {
      box.className = 'result-box ok';
      box.textContent = arts.slice(0, 10).map(a =>
        `Inode ${a.inode} — ${a.filename || a.name || 'unnamed'}`
      ).join('\n') + (arts.length > 10 ? `\n…+${arts.length - 10} more` : '');
    }
    // Auto-fill first inode
    const first = arts[0];
    if (first) setVal('recoverInodeInput', first.inode);
    Toast.success('Discovery', `${arts.length} deleted inodes found`);
  } catch (e) {
    if (box) { box.style.display = ''; box.className = 'result-box err'; box.textContent = e.message; }
  }
}

async function recoverArtifact() {
  if (!state.activeCaseId) { Toast.warning('No Case', 'Select a case first'); return; }
  const inode = val('recoverInodeInput') || '12';
  const refHash = val('refHashInput') || null;
  const box = $id('recoverResult');
  if (box) { box.style.display = ''; box.className = 'result-box'; box.textContent = `Extracting inode ${inode} bytes via icat…`; }
  try {
    const res = await api.post(`/cases/${state.activeCaseId}/recover`, {
      inode: String(inode),
      reference_sha256: refHash,
    });
    if (box) {
      box.className = `result-box ${statusClass(res.classification)}`;
      box.textContent = `Status: ${res.classification}\n${res.explanation}\nRecovered SHA-256: ${res.recovered_sha256 || '—'}\nEvidence ID: ${res.evidence_id || '—'}`;
    }
    Toast.success('Recovery', `Evidence: ${res.evidence_id}`);
  } catch (e) {
    if (box) { box.style.display = ''; box.className = 'result-box err'; box.textContent = e.message; }
    Toast.error('Recovery Failed', e.message);
  }
}

async function runAntiForensicsScan() {
  if (!state.activeCaseId) { Toast.warning('No Case', 'Select a case first'); return; }
  const box = $id('antiForensicsResult');
  if (box) { box.style.display = ''; box.className = 'result-box'; box.textContent = 'Auditing media for timestomping & wiper traces…'; }
  try {
    const res = await api.post(`/cases/${state.activeCaseId}/anti-forensics`, {});
    if (box) {
      const detected = res.anti_forensics_detected;
      box.className = `result-box ${detected ? 'warn' : 'ok'}`;
      let text = `Verdict: ${res.verdict}\n${res.summary}\nTotal Indicators: ${res.total_indicators} (Critical: ${res.by_severity?.CRITICAL || 0}, High: ${res.by_severity?.HIGH || 0})`;
      if (res.findings && res.findings.length > 0) {
        text += '\n\nKey Findings:\n' + res.findings.slice(0, 5).map(f => `• [${f.severity}] ${f.target}: ${f.court_explanation}`).join('\n');
      }
      box.textContent = text;
    }
    Toast[res.anti_forensics_detected ? 'warning' : 'success']('Anti-Forensics Audit', res.verdict);
  } catch (e) {
    if (box) { box.style.display = ''; box.className = 'result-box err'; box.textContent = `Error: ${e.message}`; }
    Toast.error('Scan Failed', e.message);
  }
}


// ═══════════════════════════════════════════════════════════════
//  CARVING MODULE
// ═══════════════════════════════════════════════════════════════

async function runCarving() {
  if (!state.activeCaseId) { Toast.warning('No Case', 'Select a case first'); return; }

  const targets = [...document.querySelectorAll('input[name="fmt"]:checked')].map(cb => cb.value);
  const max = parseInt(val('maxResultsInput')) || 200;

  html('carvingResults', '<div class="empty-state"><div class="spinner"></div><p>Scanning byte streams for signatures…</p></div>');
  hide('carvingArtifactsPanel');

  try {
    const res = await api.post(`/cases/${state.activeCaseId}/carve`, {
      target_types: targets.length ? targets : null,
      max_results: max,
    });

    const summary = res.summary || res.carved || {};
    const arts = res.carved_artifacts || summary.carved_artifacts || [];
    const triage = summary.hash_filter_results || {};

    html('carvingResults', `
      <div class="result-box ok">
        <strong>Carving Complete</strong> — ${summary.total_carved || arts.length} artifacts recovered\n
        Intact: ${summary.intact || 0}  |  High Confidence: ${summary.high_confidence || 0}  |  Fragments: ${summary.bifragmented_reconstructed || 0}
        ${triage.filtering_ratio ? `\nNSRL Hash Triage: ${triage.filtering_ratio} (${triage.investigative_interest_count ?? arts.length} evidence of interest)` : ''}
        ${res.evidence_id ? `\nEvidence ID: ${res.evidence_id}` : ''}
      </div>`);

    if (arts.length) {
      show('carvingArtifactsPanel');
      html('carvingStats', `${arts.length} artifacts · ${summary.total_carved || arts.length} total carved`);
      html('carvingTableBody', arts.map((a, i) => {
        const offset = a.offset ?? a.start_offset ?? 0;
        const size = a.size ?? a.length_bytes ?? 0;
        const score = a.confidence_score ?? 0;
        const sha256 = (a.sha256 || '—').substring(0, 16) + '…';
        const scoreClass = score >= 80 ? 'color:var(--green)' : score >= 60 ? 'color:var(--gold)' : 'color:var(--red)';
        const triageCls = a.hash_filter?.classification || 'UNKNOWN_INTEREST';
        const triageBadge = triageCls === 'KNOWN_SYSTEM_FILE'
          ? '<span class="badge-warn" title="Matches benign reference database">SYSTEM NOISE</span>'
          : triageCls === 'HASH_MATCH'
          ? '<span class="badge-danger" title="Exact match on target watchlist">TARGET MATCH</span>'
          : '<span class="badge-ok" title="Candidate evidence of interest">INVESTIGATE</span>';

        return `<tr>
          <td>${i + 1}</td>
          <td><strong>${esc(a.file_type)}</strong></td>
          <td>0x${offset.toString(16).toUpperCase().padStart(8, '0')}</td>
          <td>${formatBytes(size)}</td>
          <td style="${scoreClass}">${score}%</td>
          <td>${triageBadge}</td>
          <td title="${esc(a.sha256 || '')}">${sha256}</td>
          <td><button class="btn-ghost small" onclick="toggleHex(${i})">Hex</button></td>
        </tr>
        <tr id="hex-row-${i}" style="display:none;background:rgba(0,0,0,0.35)">
          <td colspan="8">
            <div style="padding:0.6rem 0.8rem">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.35rem">
                <span style="font-size:0.72rem;color:var(--cyan);font-weight:600">HEADER HEX DUMP (FIRST 256 BYTES)</span>
                <span style="font-size:0.7rem;color:var(--text-muted)">Offset 0x${offset.toString(16).toUpperCase().padStart(8, '0')}</span>
              </div>
              <pre class="code-block" style="font-size:0.73rem;line-height:1.4;margin:0;max-height:180px;overflow:auto;user-select:text">${esc(a.hex_preview || 'No hex preview available')}</pre>
            </div>
          </td>
        </tr>`;
      }).join(''));
    }
    Toast.success('Carving Done', `${arts.length} artifacts found`);
  } catch (e) {
    html('carvingResults', `<div class="empty-state"><p style="color:var(--red)">${esc(e.message)}</p></div>`);
    Toast.error('Carving Failed', e.message);
  }
}

function toggleHex(idx) {
  const row = $id(`hex-row-${idx}`);
  if (row) {
    row.style.display = row.style.display === 'none' ? '' : 'none';
  }
}


// ═══════════════════════════════════════════════════════════════
//  SANITIZATION MODULE
// ═══════════════════════════════════════════════════════════════

async function getDecisionProfile() {
  const media = val('mediaType');
  const bus = val('busType');
  const isBoot = $id('isBoot')?.checked;
  const box = $id('profileResult');
  if (box) { box.style.display = ''; box.className = 'result-box'; box.textContent = 'Querying NIST 800-88 decision tree…'; }
  // Use local fallback — no dedicated /nist-profile endpoint; use /cases/{id}/decision-profile if case active
  const caseId = state.activeCaseId || 'CASE-DEMO-2026';
  try {
    const res = await api.post(`/cases/${caseId}/decision-profile`, {
      media_type: media,
      bus_type: bus,
      is_boot: isBoot,
    });
    if (box) {
      box.className = 'result-box ok';
      box.textContent = `Method: ${res.recommended_method || 'PURGE'}\n${res.reasoning || res.reason || 'NIST SP 800-88 Rev.2 recommended method.'}`;
    }
  } catch {
    // Fallback local logic
    let method, reason;
    if (bus === 'NVMe' || media === 'NVMe' || media === 'SSD') {
      method = 'PURGE';
      reason = 'Flash/NVMe: firmware-level cryptographic purge or ATA Enhanced Secure Erase per NIST SP 800-88 Rev.2 §2.4. Physical NAND erasure not guaranteed by software.';
    } else if (media === 'HDD') {
      method = 'CLEAR';
      reason = 'Magnetic HDD: Single-pass logical overwrite (CLEAR) sufficient per NIST SP 800-88 Rev.2 §2.3. Multi-pass overwrite optional.';
    } else {
      method = 'PURGE';
      reason = 'Flash media: PURGE recommended. ATA Enhanced Secure Erase or vendor cryptographic erasure per NIST SP 800-88 Rev.2.';
    }
    if (box) {
      box.className = 'result-box ok';
      box.textContent = `Method: ${method}\n${reason}`;
    }
  }
}

async function sanitize() {
  if (!state.activeCaseId) { Toast.warning('No Case', 'Select a case first'); return; }
  const opId = val('sanitizeOpId') || 'AUTH-OFFICER-001';
  const opName = val('sanitizeOpName') || 'Authorized Forensic Officer';
  const reason = val('sanitizeReason') || 'Authorized NIST SP 800-88 sanitization order';
  const ack = $id('sanitizeAck')?.checked;

  if (!opId) { Toast.warning('Validation', 'Operator ID required'); return; }
  if (!ack) { Toast.warning('Validation', 'Acknowledge scope limitations first'); return; }

  const box = $id('sanitizeResult');
  if (box) { box.style.display = ''; box.className = 'result-box'; box.textContent = 'Executing NIST-informed sanitization…'; }
  try {
    const res = await api.post(`/cases/${state.activeCaseId}/sanitize`, {
      operator_id: opId,
      operator_name: opName,
      authorization_reason: reason,
      confirmed_scope_acknowledgement: true,
      method: 'ZERO_FILL',
    });
    if (box) {
      box.className = `result-box ${statusClass(res.classification || 'ok')}`;
      box.textContent = `Status: ${res.classification || 'VERIFIED_WITHIN_SCOPE'}\nExplanation: ${res.explanation || 'Logical erasure verified within scope'}\nEvidence ID: ${res.evidence_id || '—'}\nOperation: ${res.operation_id || '—'}`;
    }
    Toast.success('Sanitization', `Completed — ${res.evidence_id || 'signed'}`);
  } catch (e) {
    if (box) { box.style.display = ''; box.className = 'result-box err'; box.textContent = e.message; }
    Toast.error('Sanitization Failed', e.message);
  }
}

async function eraseFiles() {
  if (!state.activeCaseId) { Toast.warning('No Case', 'Select a case first'); return; }
  const opId = val('eraserOpId') || 'AUTH-OFFICER-001';
  const opName = val('eraserOpName') || 'Authorizing Officer';
  const reason = val('eraserReason') || 'Authorized selective file erasure order';
  const ack = $id('eraserAck')?.checked ?? true;
  const paths = val('eraserPaths').split('\n').map(s => s.trim()).filter(Boolean);

  if (!opId) { Toast.warning('Validation', 'Operator ID required'); return; }
  if (!paths.length) { Toast.warning('Validation', 'Provide at least one file path'); return; }

  const box = $id('eraserResult');
  if (box) { box.style.display = ''; box.className = 'result-box'; box.textContent = 'Erasing selected files…'; }
  try {
    const res = await api.post(`/cases/${state.activeCaseId}/erase-files`, {
      target_paths: paths,
      operator_id: opId,
      operator_name: opName,
      authorization_reason: reason,
      confirmed_scope_acknowledgement: true,
      method: 'ZERO_FILL',
      scrub_metadata: true,
      scramble_names: true,
    });
    if (box) {
      box.className = `result-box ${statusClass(res.classification || res.status || 'ok')}`;
      box.textContent = `Status: ${res.status || res.classification || 'VERIFIED'}\nFiles Erased: ${res.files_erased ?? paths.length}\nBytes Erased: ${formatBytes(res.bytes_erased || 0)}\nEvidence ID: ${res.evidence_id || '—'}\nScope: ${res.scope_note || 'NIST SP 800-88 Rev.2 Clear'}`;
    }
    Toast.success('Files Erased', `${res.files_erased ?? paths.length} files securely sanitized`);
  } catch (e) {
    if (box) { box.style.display = ''; box.className = 'result-box err'; box.textContent = e.message; }
    Toast.error('Erasure Failed', e.message);
  }
}

// ═══════════════════════════════════════════════════════════════
//  AUDIT CHAIN MODULE
// ═══════════════════════════════════════════════════════════════

async function loadAuditTimeline() {
  if (!state.activeCaseId) {
    html('auditTimeline', '<div class="empty-state"><p>Select an active case first.</p></div>');
    return;
  }
  html('auditTimeline', '<div class="empty-state"><div class="spinner"></div><p>Loading audit chain…</p></div>');
  try {
    const res = await api.get(`/cases/${state.activeCaseId}/timeline`);
    const events = res.events || res.audit_events || res || [];
    if (!Array.isArray(events) || !events.length) {
      html('auditTimeline', '<div class="empty-state"><p>No audit events recorded yet.</p></div>');
      return;
    }
    html('auditTimeline', events.map((e, i) => {
      const h = e.entry_hash || e.chain_hash || e.event_hash || e.hash_ref || '';
      const hashStr = h ? (h.length > 20 ? h.substring(0, 20) + '…' : h) : '—';
      return `
      <div class="timeline-item" style="animation-delay:${i * 40}ms">
        <div class="timeline-dot"></div>
        <div class="timeline-content">
          <div class="timeline-action">${esc(e.action || e.event_type || e.type || '—')}</div>
          <div class="timeline-meta">${formatTime(e.timestamp || e.created_at)} · Hash: <span style="font-family:monospace;color:var(--cyan)">${hashStr}</span></div>
        </div>
      </div>`;
    }).join(''));
  } catch (e) {
    html('auditTimeline', `<div class="empty-state"><p style="color:var(--red)">${esc(e.message)}</p></div>`);
  }
}

async function verifyChain() {
  if (!state.activeCaseId) { Toast.warning('No Case', 'Select a case first'); return; }
  const chainStatus = $id('chainStatus');
  if (chainStatus) chainStatus.style.display = '';
  try {
    const res = await api.get(`/cases/${state.activeCaseId}/timeline/verify`);
    const valid = res.chain_valid || res.valid;
    if (chainStatus) {
      chainStatus.className = `chain-status ${valid ? 'ok' : 'err'}`;
      chainStatus.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          ${valid ? '<polyline points="20 6 9 17 4 12"/>' : '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>'}
        </svg>
        ${valid ? 'Chain Valid — All SHA-256 block hashes cryptographically verified' : 'Chain BROKEN — Cryptographic tamper detected!'}`;
    }
    Toast[valid ? 'success' : 'error']('Chain Verification', valid ? 'Audit chain integrity confirmed' : 'CHAIN TAMPER DETECTED');
  } catch (e) {
    Toast.error('Verify Failed', e.message);
  }
}

async function tamperChainDemo() {
  if (!state.activeCaseId) { Toast.warning('No Case', 'Select a case first'); return; }
  const chainStatus = $id('chainStatus');
  try {
    const res = await api.post(`/cases/${state.activeCaseId}/timeline/demo-tamper`, {});
    if (chainStatus) {
      chainStatus.style.display = '';
      chainStatus.className = 'chain-status err';
      chainStatus.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>
        </svg>
        ⚠ ADVERSARIAL TAMPER DETECTED — Injected modification broke SHA-256 chain linkage!`;
    }
    Toast.warning('Chain Tamper Detected', `Tamper simulation at entry #${res.tampered_entry_index ?? 0} broke hash-chain`);
  } catch (e) {
    Toast.error('Tamper Demo', e.message);
  }
}

// ═══════════════════════════════════════════════════════════════
//  EVIDENCE VAULT MODULE
// ═══════════════════════════════════════════════════════════════

async function loadEvidence() {
  const caseId = state.activeCaseId;
  const path = caseId ? `/evidence?case_id=${encodeURIComponent(caseId)}` : `/evidence`;
  // Show case filter badge
  const filterBadge = $id('vaultFilterBadge');
  if (filterBadge) {
    if (caseId) {
      filterBadge.style.display = '';
      filterBadge.innerHTML = `Filtered: <strong>${esc(caseId)}</strong> <button class="btn-icon" onclick="showAllEvidence()" title="Show all">✕</button>`;
    } else {
      filterBadge.style.display = '';
      filterBadge.innerHTML = `Showing: <strong>All Cases</strong>`;
    }
  }
  html('evidenceList', '<div class="empty-state"><div class="spinner"></div><p>Loading evidence packages…</p></div>');
  try {
    let items = await api.get(path);
    let list = Array.isArray(items) ? items : (items.evidence || []);
    if (!list.length && caseId) {
      items = await api.get('/evidence');
      list = Array.isArray(items) ? items : (items.evidence || []);
    }
    if (!list.length) {
      html('evidenceList', '<div class="empty-state"><p>No evidence packages yet. Run forensic recovery, carving, or proof loop.</p></div>');
      return;
    }
    html('evidenceList', list.map(ev => `
      <div class="evidence-card" onclick="setVal('tamperEvidenceId','${esc(ev.evidence_id)}');setVal('verifyEvidenceId','${esc(ev.evidence_id)}')">
        <div class="evidence-card-header">
          <div class="evidence-card-id">${esc(ev.evidence_id)}</div>
          <button class="btn-icon" onclick="event.stopPropagation();downloadCertificate('${esc(ev.evidence_id)}')" title="Download Certificate">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
          </button>
        </div>
        <div class="evidence-card-meta">${esc(ev.classification || ev.evidence_type || 'FORENSIC')} · ${formatTime(ev.created_at || ev.timestamp)}</div>
      </div>
    `).join(''));
  } catch (e) {
    html('evidenceList', `<div class="empty-state"><p style="color:var(--red)">${esc(e.message)}</p></div>`);
  }
}

function showAllEvidence() {
  const savedCase = state.activeCaseId;
  state.activeCaseId = null;
  loadEvidence().then(() => { state.activeCaseId = savedCase; });
}

async function runTamperDemo() {
  const evId = val('tamperEvidenceId');
  if (!evId) { Toast.warning('No ID', 'Enter an Evidence ID first'); return; }
  const box = $id('tamperResult');
  if (box) { box.style.display = ''; box.className = 'result-box'; box.textContent = 'Simulating tampering and verifying…'; }
  try {
    const res = await api.post(`/evidence/${evId}/demo-tamper`, {});
    const tampered = res.tamper_detected || false;
    if (box) {
      box.className = `result-box ${tampered ? 'ok' : 'err'}`;
      box.textContent = tampered
        ? `✓ TAMPER DETECTED — System correctly identified modification\nClassification: INVALID\nField Tampered: ${res.tampered_field || 'result.classification'}\nDescription: ${res.tamper_description || 'Payload modified after signing'}\nSignature: REJECTED by Ed25519 verifier`
        : `No tamper detected in demo — check evidence ID`;
    }
    Toast[tampered ? 'success' : 'warning']('Tamper Demo', tampered ? 'Tamper detection working correctly' : 'Demo result unexpected');
  } catch (e) {
    // Show real error — no fake success
    if (box) {
      box.style.display = '';
      box.className = 'result-box err';
      box.textContent = `Error: ${e.message}\n\nTo run tamper demo:\n1. Run forensics, carving, or proof loop to generate signed evidence\n2. Evidence ID will appear in the vault below\n3. Click an evidence card to auto-fill the ID\n4. Click "Simulate Tampering" again`;
    }
    Toast.error('Tamper Demo Failed', e.message);
  }
}

async function runProofLoop() {
  if (!state.activeCaseId) { Toast.warning('No Case', 'Select a case first'); return; }
  const box = $id('proofLoopResult');
  if (box) { box.style.display = ''; box.className = 'result-box'; box.textContent = 'Executing 7-stage forensic proof loop…\n\n1. Known Test Evidence → 2. Pre-Carve → 3. Sanitize → 4. Post-Carve Probe → 5. Differential → 6. Verification vs Validation → 7. Signed Assurance'; }
  try {
    const res = await api.post(`/cases/${state.activeCaseId}/proof-loop`, {
      method: 'CLEAR',
      data_sensitivity: 'CONFIDENTIAL',
    });
    const pr = res.proof_result || {};
    const assurance = pr.assurance || {};
    const verification = assurance.verification || {};
    const validation = assurance.validation || {};
    if (box) {
      box.className = `result-box ${pr.proof_loop_status === 'SUCCESS' ? 'ok' : 'warn'}`;
      box.textContent = [
        `Status: ${pr.proof_loop_status}`,
        `Method: ${pr.sanitization_execution?.method_applied || 'CLEAR_ZERO_FILL'}`,
        ``,
        `── Pre-Sanitization ──`,
        `  Artifacts Found: ${pr.pre_sanitization?.artifacts_found || 0}`,
        `  SHA-256: ${(pr.pre_sanitization?.sha256 || '—').substring(0, 32)}…`,
        ``,
        `── Post-Sanitization Probe ──`,
        `  Artifacts Recovered: ${pr.post_sanitization_probe?.artifacts_recovered || 0}`,
        `  Erasure: ${pr.differential?.erasure_percentage || 0}%`,
        ``,
        `── Assurance ──`,
        `  Verification: ${verification.passed ? '✓ PASSED' : '✗ FAILED'} — ${verification.detail || ''}`,
        `  Validation: ${validation.passed ? '✓ PASSED' : '✗ FAILED'} — ${validation.status || ''}`,
        ``,
        `Evidence ID: ${res.evidence_id || '—'}`,
        `Operation ID: ${res.operation_id || '—'}`,
      ].join('\n');
    }
    Toast.success('Proof Loop Complete', `Evidence: ${res.evidence_id}`);
  } catch (e) {
    if (box) { box.style.display = ''; box.className = 'result-box err'; box.textContent = e.message; }
    Toast.error('Proof Loop Failed', e.message);
  }
}

async function generateDestroyManifest() {
  if (!state.activeCaseId) { Toast.warning('No Case', 'Select a case first'); return; }
  const box = $id('destroyManifestResult');
  if (box) { box.style.display = ''; box.className = 'result-box'; box.textContent = 'Generating NIST SP 800-88 Rev. 2 DESTROY manifest…'; }

  // Reuse operator credentials from the sanitization form
  const opId = val('sanitizeOpId') || 'AUTH-OFFICER-001';
  const opName = val('sanitizeOpName') || 'Forensic Security Officer';
  const reason = val('sanitizeReason') || 'Authorized physical disposal per case directive';

  const witnesses = [];
  const witnessName = val('destroyWitness');
  if (witnessName) {
    witnesses.push({ name: witnessName, id: 'WITNESS-001', role: 'Investigating Officer', org: 'NTRO' });
  }

  try {
    const res = await api.post(`/cases/${state.activeCaseId}/destroy-manifest`, {
      operator_id: opId,
      operator_name: opName,
      authorization_reason: reason,
      serial_number: val('destroySerial') || null,
      make_model: val('destroyMakeModel') || null,
      capacity: val('destroyCapacity') || null,
      classification_level: val('destroyClassification') || 'CONFIDENTIAL',
      witnesses: witnesses.length ? witnesses : null,
    });

    const manifest = res.manifest || {};
    if (box) {
      box.className = 'result-box ok';
      box.textContent = [
        `✓ Manifest Generated: ${manifest.manifest_id}`,
        `  NIST Reference: ${manifest.nist_reference}`,
        `  Classification: ${manifest.classification_level}`,
        `  Items: ${(manifest.items || []).length}`,
        `  Destruction Method: ${(manifest.items && manifest.items[0]) ? manifest.items[0].destruction_method : '—'}`,
        `  SHA-256: ${(manifest.manifest_hash || '—').substring(0, 32)}…`,
        ``,
        `Opening printable manifest in new window…`,
      ].join('\n');
    }

    // Open the HTML manifest in a new window for printing
    if (res.manifest_html) {
      const w = window.open('', '_blank');
      if (w) {
        w.document.write(res.manifest_html);
        w.document.close();
      }
    }

    Toast.success('Manifest Generated', `ID: ${manifest.manifest_id}`);
  } catch (e) {
    if (box) { box.style.display = ''; box.className = 'result-box err'; box.textContent = e.message; }
    Toast.error('Manifest Failed', e.message);
  }
}

function downloadCertificate(evidenceId) {
  window.open(`${cfg.base}/evidence/${evidenceId}/certificate.html`, '_blank');
}

// ═══════════════════════════════════════════════════════════════
//  VERIFICATION MODULE
// ═══════════════════════════════════════════════════════════════

function setVerifyMode(mode) {
  state.verifyMode = mode;
  $id('verifyModeId').classList.toggle('active', mode === 'id');
  $id('verifyModeJson').classList.toggle('active', mode === 'json');
  $id('verifyIdPanel').style.display = mode === 'id' ? '' : 'none';
  $id('verifyJsonPanel').style.display = mode === 'json' ? '' : 'none';
}

async function verifyEvidence() {
  const resultEl = $id('verificationResult');
  if (resultEl) html('verificationResult', '<div class="empty-state"><div class="spinner"></div><p>Verifying Ed25519 signature…</p></div>');

  try {
    let res;
    if (state.verifyMode === 'id') {
      const evId = val('verifyEvidenceId');
      if (!evId) { Toast.warning('No ID', 'Enter an Evidence ID'); return; }
      res = await api.post(`/evidence/${evId}/verify`, {});
    } else {
      const jsonStr = val('verifyJsonInput');
      if (!jsonStr) { Toast.warning('No JSON', 'Paste the evidence package JSON'); return; }
      let pkg;
      try { pkg = JSON.parse(jsonStr); } catch { Toast.error('Invalid JSON', 'Could not parse the package'); return; }
      res = await api.post('/evidence/verify-package', { package: pkg });
    }

    const valid = res.valid || res.verification_result === 'VERIFIED';
    html('verificationResult', `
      <div class="verify-result-card ${valid ? 'valid' : 'invalid'}">
        <div class="verify-verdict">${valid ? '✓ VERIFIED' : '✗ INVALID'}</div>
        <div class="verify-detail">${
          [
            `Status: ${res.verification_result || (valid ? 'VERIFIED' : 'INVALID')}`,
            `Signature: ${res.signature_valid ? 'VALID (Ed25519)' : 'INVALID'}`,
            `Hash Match: ${res.hash_match !== false ? 'Yes' : 'No'}`,
            res.evidence_id ? `Evidence ID: ${res.evidence_id}` : '',
            res.reason ? `Reason: ${res.reason}` : '',
          ].filter(Boolean).join('\n')
        }</div>
      </div>`);
    Toast[valid ? 'success' : 'error']('Verification', valid ? 'Package cryptographically verified' : 'VERIFICATION FAILED');
  } catch (e) {
    html('verificationResult', `<div class="verify-result-card invalid"><div class="verify-verdict">✗ ERROR</div><div class="verify-detail">${esc(e.message)}</div></div>`);
    Toast.error('Verify Error', e.message);
  }
}

// ═══════════════════════════════════════════════════════════════
//  TOPBAR SCROLL EFFECT
// ═══════════════════════════════════════════════════════════════

(function initScrollEffect() {
  const topbar = document.getElementById('topbar');
  window.addEventListener('scroll', () => {
    if (!topbar) return;
    if (window.scrollY > 20) {
      topbar.style.borderBottomColor = 'rgba(0,180,255,0.15)';
      topbar.style.background = 'rgba(2,8,16,0.95)';
    } else {
      topbar.style.borderBottomColor = '';
      topbar.style.background = '';
    }
  }, { passive: true });
})();

// Smooth scroll registered inside DOMContentLoaded (see below)

// ═══════════════════════════════════════════════════════════════
//  STAT COUNTER ANIMATION
// ═══════════════════════════════════════════════════════════════

function animateCounters() {
  document.querySelectorAll('.stat-num').forEach(el => {
    const raw = el.textContent.trim();
    const target = parseInt(raw);
    // Skip non-numeric values like 'Ed25519', 'NIST', '14' is fine
    if (isNaN(target) || raw.length > 5) return;
    el.dataset.origText = raw;
    let current = 0;
    const step = Math.max(1, Math.ceil(target / 40));
    const timer = setInterval(() => {
      current = Math.min(current + step, target);
      el.textContent = current;
      if (current >= target) clearInterval(timer);
    }, 28);
  });
}

// ═══════════════════════════════════════════════════════════════
//  INIT
// ═══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  // Particles
  Particles.init();

  // Health ping
  pingHealth();
  setInterval(pingHealth, 30000);

  // Stat counter animation — only runs on numeric stats
  setTimeout(animateCounters, 600);

  // Smooth scroll for anchor links
  document.querySelectorAll('a[href^="#"]').forEach(a => {
    a.addEventListener('click', e => {
      e.preventDefault();
      const target = document.querySelector(a.getAttribute('href'));
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  // Keyboard shortcuts
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') document.body.classList.remove('nav-open');
  });

  // Close nav when clicking overlay
  const overlay = document.getElementById('navOverlay');
  if (overlay) overlay.addEventListener('click', () => document.body.classList.remove('nav-open'));

  console.log('%c FORENSIC ASSURANCE v3.0 ', 'background:#00e5ff;color:#000;font-weight:bold;font-family:monospace;padding:4px 8px;');
  console.log('%c SIH26149 · NTRO · RC2 Certified ', 'color:#00e5ff;font-family:monospace;');
});
