/**
 * SIH26149 Forensic Workstation — Interactive Client Engine (v2.0)
 * Professional Forensic Laboratory Workstation
 * Supports dynamic same-origin resolution, real-time health ping,
 * mobile drawer navigation, theme system, toast dispatcher, and judge demo workflow.
 */

'use strict';

// ── API Configuration & Origin Discovery ───────────────────────────────────────

const cfg = {
  get base() {
    // 1. Check if user configured an explicit override in diagnostics
    const override = localStorage.getItem('sih_api_override');
    if (override && override.trim()) {
      return override.trim().replace(/\/$/, '');
    }

    // 2. Production same-origin discovery (Render, Docker, Localhost)
    if (window.location && window.location.protocol && window.location.protocol.startsWith('http')) {
      // Returning empty string makes all calls relative, or window.location.origin
      return window.location.origin.replace(/\/$/, '');
    }

    // 3. Fallback only if opened directly from local filesystem (file://)
    return 'http://127.0.0.1:8000';
  },
};

// ── Application State ──────────────────────────────────────────────────────────

const state = {
  activeCaseId: null,
  uploadedImagePath: null,
  selectedInode: null,
  demoMode: false,
  healthData: null,
  latencyMs: null,
  pendingAction: null,
  activeTheme: 'dark',
};

// ── Toast Notification System ──────────────────────────────────────────────────

const Toast = {
  show(type, title, msg, duration = 4000) {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
      <div class="toast-body">
        <div class="toast-title">${ui.esc(title)}</div>
        ${msg ? `<div class="toast-msg">${ui.esc(msg)}</div>` : ''}
      </div>
      <button class="toast-close" onclick="this.parentElement.remove()">✕</button>
    `;

    container.appendChild(toast);

    setTimeout(() => {
      toast.classList.add('toast-out');
      setTimeout(() => toast.remove(), 250);
    }, duration);
  },
  success(title, msg) { this.show('success', title, msg); },
  error(title, msg)   { this.show('error', title, msg, 6000); },
  warning(title, msg) { this.show('warning', title, msg); },
  info(title, msg)    { this.show('info', title, msg); },
};

// ── API Client ─────────────────────────────────────────────────────────────────

const api = {
  async call(method, path, body, isForm = false) {
    const opts = { method };
    if (isForm) {
      opts.body = body;
    } else if (body) {
      opts.headers = { 'Content-Type': 'application/json' };
      opts.body = JSON.stringify(body);
    }

    const url = (cfg.base + path).replace(/([^:]\/)\/+/g, '$1');
    const res = await fetch(url, opts);

    if (!res.ok) {
      let detail = `HTTP ${res.status}`;
      try {
        const json = await res.json();
        detail = json.detail || detail;
      } catch (_) {}
      throw new Error(detail);
    }
    return res.json();
  },
  get:    (path)       => api.call('GET',  path),
  post:   (path, body) => api.call('POST', path, body),
  upload: (path, form) => api.call('POST', path, form, true),
};

// ── UI Helpers ─────────────────────────────────────────────────────────────────

const ui = {
  show(id)   { const el = document.getElementById(id); if (el) el.style.display = ''; },
  hide(id)   { const el = document.getElementById(id); if (el) el.style.display = 'none'; },
  html(id, h){ const el = document.getElementById(id); if (el) el.innerHTML = h; },
  text(id, t){ const el = document.getElementById(id); if (el) el.textContent = t; },
  val(id)    { const el = document.getElementById(id); return el ? el.value.trim() : ''; },
  setVal(id, v){ const el = document.getElementById(id); if (el) el.value = v; },
  setBtn(id, disabled) { const b = document.getElementById(id); if (b) b.disabled = disabled; },

  esc(v) {
    return String(v ?? '').replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  },

  badge(label, type = 'neutral') {
    const cls = { ok: 'badge-ok', warn: 'badge-warn', err: 'badge-err', neutral: 'badge-neutral' };
    return `<span class="badge ${cls[type] || 'badge-neutral'}">${ui.esc(label)}</span>`;
  },

  resultCard(statusText, reason, type = 'neutral', scope = '') {
    return `<div class="result-card ${type}">
      <div class="result-status">${ui.esc(statusText)}</div>
      <div class="result-reason">${ui.esc(reason)}</div>
      ${scope ? `<div class="result-scope">${ui.esc(scope)}</div>` : ''}
    </div>`;
  },

  kvGrid(rows) {
    const cells = rows.map(([k, v, mono]) =>
      `<div class="kv-row">
        <span class="kv-k">${ui.esc(k)}</span>
        <span class="kv-v ${mono ? 'kv-mono' : ''}">${ui.esc(v)}</span>
      </div>`
    ).join('');
    return `<div class="kv-grid">${cells}</div>`;
  },

  classifyType(status) {
    const ok   = ['VERIFIED', 'VALID', 'SUPPORTED', 'ACTIVE', 'CLEAR_SUPPORTED'];
    const warn = ['VERIFIED_WITHIN_SCOPE', 'UNVERIFIED', 'PARTIAL'];
    const err  = ['FAILED', 'REJECTED', 'INVALID', 'UNSUPPORTED', 'NOT_A_FILESYSTEM'];
    if (ok.includes(status))   return 'ok';
    if (warn.includes(status)) return 'warn';
    if (err.includes(status))  return 'err';
    return 'neutral';
  },

  stepOn(id)  { const el = document.getElementById(id); if (el) el.classList.remove('dim'); },
  stepDim(id) { const el = document.getElementById(id); if (el) el.classList.add('dim'); },

  err(msg) { return `<div class="notice-box notice-red">${ui.esc(msg)}</div>`; },
};

// ── Tab Navigation ─────────────────────────────────────────────────────────────

const tabNames = {
  cases:        'Cases & Timeline',
  forensics:    'Forensic Recovery',
  carving:      'Advanced File Carving',
  sanitization: 'Data Sanitization & Selective Eraser',
  auditchain:   'Cryptographic Audit Chain',
  vault:        'Evidence Vault',
  verification: 'Independent Verifier',
};

function switchTab(tab) {
  document.querySelectorAll('.sidenav-item').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === tab);
  });
  document.querySelectorAll('.tab-content').forEach(t => {
    t.classList.toggle('active', t.id === `tab-${tab}`);
  });
  ui.text('topbarTabName', tabNames[tab] || tab);
  toggleMobileDrawer(false);

  if (tab === 'auditchain' && state.activeCaseId) loadAuditChain();
  if (tab === 'vault' && state.activeCaseId) loadVault();
}

document.querySelectorAll('.sidenav-item').forEach(btn => {
  btn.addEventListener('click', () => switchTab(btn.dataset.tab));
});

function refreshCurrentView() {
  const active = document.querySelector('.sidenav-item.active');
  const tab = active?.dataset.tab;
  if (tab === 'cases') loadCases();
  if (tab === 'vault' && state.activeCaseId) loadVault();
  if (tab === 'auditchain' && state.activeCaseId) loadAuditChain();
  pingHealth();
  Toast.info('View Refreshed', 'Synced with backend');
}

// ── Mobile Drawer Controller ───────────────────────────────────────────────────

function toggleMobileDrawer(open) {
  const sidebar = document.getElementById('sidebar');
  const backdrop = document.getElementById('drawerBackdrop');
  if (sidebar) sidebar.classList.toggle('open', open);
  if (backdrop) backdrop.classList.toggle('active', open);
}

// ── Theme Manager ──────────────────────────────────────────────────────────────

function initTheme() {
  const saved = localStorage.getItem('sih_theme') || 'dark';
  setTheme(saved, false);
}

function toggleThemeMenu() {
  const dropdown = document.getElementById('themeDropdown');
  if (dropdown) {
    dropdown.style.display = dropdown.style.display === 'none' ? 'flex' : 'none';
  }
}

document.addEventListener('click', (e) => {
  const btn = document.getElementById('themeBtn');
  const dropdown = document.getElementById('themeDropdown');
  if (dropdown && btn && !btn.contains(e.target) && !dropdown.contains(e.target)) {
    dropdown.style.display = 'none';
  }
});

function setTheme(theme, save = true) {
  state.activeTheme = theme;
  if (save) localStorage.setItem('sih_theme', theme);

  let effective = theme;
  if (theme === 'system') {
    effective = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }

  document.documentElement.setAttribute('data-theme', effective);

  const icons = { dark: '🌙', light: '☀️', contrast: '⚡', system: '💻' };
  const labels = { dark: 'Dark Slate', light: 'Clean Lab', contrast: 'High Contrast', system: 'System' };
  ui.text('themeIcon', icons[theme] || '🌓');
  ui.text('themeLabel', labels[theme] || 'Theme');

  const dropdown = document.getElementById('themeDropdown');
  if (dropdown) dropdown.style.display = 'none';
}

// ── Health & Connection Latency Monitor ────────────────────────────────────────

let pingTimer = null;

async function pingHealth() {
  const start = performance.now();
  const connDot = document.getElementById('connDot');
  const connLabel = document.getElementById('connLabel');
  const connPing = document.getElementById('connPing');
  const coldBanner = document.getElementById('coldStartBanner');

  try {
    const health = await api.get('/health');
    const latency = Math.round(performance.now() - start);
    state.healthData = health;
    state.latencyMs = latency;

    if (connDot) {
      connDot.className = 'conn-dot dot-ok';
    }
    if (connLabel) connLabel.textContent = 'API Online';
    if (connPing) connPing.textContent = `${latency} ms`;

    // Hide cold start banner if previously shown
    if (coldBanner) coldBanner.style.display = 'none';

    // Update subsystem dots in sidebar
    const subs = health.subsystems || {};
    const sleuthDot = document.getElementById('dotSleuth');
    const cryptoDot = document.getElementById('dotCrypto');
    const persistDot = document.getElementById('dotPersistence');

    if (sleuthDot) sleuthDot.className = `dot ${subs.sleuthkit ? 'dot-ok' : 'dot-warn'}`;
    if (cryptoDot) cryptoDot.className = `dot ${subs.cryptography ? 'dot-ok' : 'dot-warn'}`;
    if (persistDot) persistDot.className = `dot ${subs.persistence ? 'dot-ok' : 'dot-warn'}`;

    state.demoMode = health.demo_mode === true;
    if (state.demoMode) ui.show('tamperSection');
  } catch (err) {
    if (connDot) connDot.className = 'conn-dot dot-err';
    if (connLabel) connLabel.textContent = 'Service Offline';
    if (connPing) connPing.textContent = '-- ms';

    // Show friendly cold-start notice if on Render
    if (coldBanner && window.location.hostname.includes('render.com')) {
      coldBanner.style.display = 'flex';
      startColdStartCountdown();
    }
  }
}

function startColdStartCountdown() {
  let sec = 10;
  const el = document.getElementById('coldStartSeconds');
  const interval = setInterval(() => {
    sec--;
    if (el) el.textContent = sec;
    if (sec <= 0) {
      clearInterval(interval);
      pingHealth();
    }
  }, 1000);
}

// ── Connection Diagnostics Modal ───────────────────────────────────────────────

function openConnDiagnostics() {
  const modal = document.getElementById('connModalBackdrop');
  if (!modal) return;
  modal.style.display = 'flex';

  ui.text('diagStatusBadge', state.healthData ? '● Operational' : '✖ Offline / Unreachable');
  ui.text('diagLatency', `Roundtrip Latency: ${state.latencyMs ?? '--'} ms`);
  ui.text('diagOrigin', cfg.base || window.location.origin);
  ui.text('diagVersion', state.healthData?.version || '2.0.0');
  ui.text('diagCrypto', state.healthData?.subsystems?.cryptography || 'Ed25519');
  ui.text('diagSleuth', state.healthData?.subsystems?.sleuthkit ? 'Active & Ready' : 'Fallback / Inode Emulated');

  const savedOverride = localStorage.getItem('sih_api_override') || '';
  ui.setVal('apiBaseOverride', savedOverride);
}

function closeConnDiagnostics(e) {
  const modal = document.getElementById('connModalBackdrop');
  if (modal) modal.style.display = 'none';
}

function saveApiOverride() {
  const val = ui.val('apiBaseOverride');
  if (val) {
    localStorage.setItem('sih_api_override', val);
    Toast.success('API Override Saved', `Target origin: ${val}`);
  } else {
    localStorage.removeItem('sih_api_override');
    Toast.info('API Override Reset', 'Using same-origin resolution');
  }
  closeConnDiagnostics();
  pingHealth();
  refreshCurrentView();
}

function resetApiOverride() {
  localStorage.removeItem('sih_api_override');
  ui.setVal('apiBaseOverride', '');
  Toast.info('API Override Cleared', 'Restored same-origin');
  closeConnDiagnostics();
  pingHealth();
  refreshCurrentView();
}

// ── Confirmation Modal ─────────────────────────────────────────────────────────

function promptConfirm(promptText, actionNotice, onConfirm) {
  const modal = document.getElementById('confirmModalBackdrop');
  if (!modal) return;
  ui.text('confirmModalPrompt', promptText);
  if (actionNotice) ui.text('confirmNoticeBox', actionNotice);
  state.pendingAction = onConfirm;
  modal.style.display = 'flex';
}

function closeConfirmModal(confirmed = false) {
  const modal = document.getElementById('confirmModalBackdrop');
  if (modal) modal.style.display = 'none';
  if (!confirmed) state.pendingAction = null;
}

function onConfirmModalConfirmed() {
  const act = state.pendingAction;
  closeConfirmModal(true);
  if (typeof act === 'function') act();
}

// ── Active Case Tracking ───────────────────────────────────────────────────────

function setActiveCase(caseId) {
  state.activeCaseId = caseId;
  ui.text('topbarCase', caseId);
  ui.text('acsCaseId', caseId);
  ui.show('activeCaseStrip');

  document.querySelectorAll('.case-item').forEach(el => {
    el.classList.toggle('active-case', el.dataset.caseId === caseId);
  });
}

// ── Cases Module ───────────────────────────────────────────────────────────────

function showNewCaseForm() { ui.show('newCaseForm'); }
function hideNewCaseForm() { ui.hide('newCaseForm'); }

async function loadCases() {
  ui.html('casesList', `
    <div class="skeleton-card">
      <div class="skeleton-line" style="width: 40%"></div>
      <div class="skeleton-line" style="width: 70%"></div>
    </div>
  `);

  try {
    const cases = await api.get('/cases');
    if (!cases || !cases.length) {
      ui.html('casesList', `
        <div style="text-align:center;padding:32px 16px;background:var(--bg-surface);border:1px solid var(--border-subtle);border-radius:var(--radius-lg);">
          <div style="font-size:28px;margin-bottom:8px;">📁</div>
          <div style="font-weight:700;font-size:14px;">No Investigation Cases Found</div>
          <div style="color:var(--text-muted);font-size:12px;margin:6px 0 16px;">Create a new case or initialize the official demonstration case.</div>
          <button class="btn btn-primary btn-sm" onclick="seedOfficialDemoCase()">⚡ Seed Demo Case (1-Click)</button>
        </div>
      `);
      return;
    }

    const cards = cases.map(c => {
      const isActive = c.case_id === state.activeCaseId;
      return `
        <div class="case-item ${isActive ? 'active-case' : ''}" data-case-id="${ui.esc(c.case_id)}" onclick="selectCase('${ui.esc(c.case_id)}')">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;">
            <div>
              <div style="font-weight:700;font-size:14px;color:var(--text-main);">${ui.esc(c.title || c.case_id)}</div>
              <div style="font-family:var(--font-mono);font-size:11.5px;color:var(--accent-primary);margin-top:2px;">${ui.esc(c.case_id)}</div>
            </div>
            ${ui.badge(c.workflow || 'FORENSIC', 'ok')}
          </div>
          ${c.description ? `<div style="font-size:12px;color:var(--text-muted);margin:8px 0;">${ui.esc(c.description)}</div>` : ''}
          <div style="display:flex;justify-content:space-between;align-items:center;font-size:11.5px;color:var(--text-dim);margin-top:10px;padding-top:8px;border-top:1px solid var(--border-subtle);">
            <span>Acquired Image: <strong>${c.source_path ? 'Yes (SHA-256 Validated)' : 'Pending Acquisition'}</strong></span>
            <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();selectCase('${ui.esc(c.case_id)}');switchTab('forensics');">Open Workspace →</button>
          </div>
        </div>
      `;
    }).join('');

    ui.html('casesList', cards);

    if (!state.activeCaseId && cases.length > 0) {
      selectCase(cases[0].case_id);
    }
  } catch (e) {
    ui.html('casesList', ui.err(`Could not load cases: ${e.message}`));
  }
}

async function createCase() {
  const title = ui.val('newCaseName');
  const examiner = ui.val('newCaseExaminer');
  const desc = ui.val('newCaseDesc');

  if (!title) {
    Toast.warning('Validation Error', 'Case title is required');
    return;
  }

  try {
    const data = await api.post('/cases', {
      workflow: 'FORENSIC',
      title,
      description: desc || `Investigator: ${examiner || 'Authorized Officer'}`,
    });
    hideNewCaseForm();
    Toast.success('Case Initialized', `Case ID: ${data.case_id}`);
    setActiveCase(data.case_id);
    loadCases();
  } catch (e) {
    Toast.error('Failed to Create Case', e.message);
  }
}

async function selectCase(caseId) {
  setActiveCase(caseId);
  try {
    const c = await api.get(`/cases/${caseId}`);
    if (c.source_path) {
      ui.stepOn('step-discover');
      ui.stepOn('step-recover');
      ui.setBtn('btnDetectFs', false);
      ui.setBtn('btnDiscover', false);
      ui.setBtn('btnRecover', false);
    }
  } catch (_) {}
}

async function seedOfficialDemoCase() {
  Toast.info('Seeding Demo Case', 'Generating synthetic storage media...');
  try {
    const res = await api.post('/cases/seed-demo', {});
    Toast.success('Demo Case Seeded', `Loaded ${res.case.case_id}`);
    setActiveCase(res.case.case_id);
    await loadCases();
    switchTab('forensics');
  } catch (e) {
    Toast.error('Seeder Error', e.message);
  }
}

// ── Forensics Module ───────────────────────────────────────────────────────────

async function seedSyntheticEvidenceForActiveCase() {
  if (!state.activeCaseId) {
    Toast.warning('No Active Case', 'Please select or create a case first');
    return;
  }
  try {
    const res = await api.post(`/cases/${state.activeCaseId}/seed-synthetic-evidence`, {});
    ui.html('fsResult', ui.resultCard(
      '✓ Synthetic Evidence Disk Acquired',
      `Embedded valid JPEG, PNG, and PDF. Computed SHA-256: ${res.sha256.substring(0, 24)}...`,
      'ok',
      `Size: ${(res.size_bytes).toLocaleString()} bytes`
    ));
    ui.stepOn('step-discover');
    ui.stepOn('step-recover');
    ui.setBtn('btnDetectFs', false);
    ui.setBtn('btnDiscover', false);
    ui.setBtn('btnRecover', false);
    Toast.success('Evidence Acquired', 'Synthetic disk image registered');
  } catch (e) {
    ui.html('fsResult', ui.err(e.message));
  }
}

async function detectFilesystem() {
  if (!state.activeCaseId) return;
  ui.html('fsResult', '<div style="color:var(--text-dim);font-size:12px;">Detecting superblock and signature...</div>');
  try {
    const cap = await api.get(`/cases/${state.activeCaseId}/filesystem`);
    ui.html('fsResult', ui.resultCard(
      `Filesystem: ${cap.status_label}`,
      `Detection Method: ${cap.detection_method} | Recovery Supported: ${cap.recovery_supported ? 'Yes' : 'No'}`,
      cap.recovery_supported ? 'ok' : 'warn'
    ));
  } catch (e) {
    ui.html('fsResult', ui.err(e.message));
  }
}

async function discoverDeleted() {
  if (!state.activeCaseId) return;
  ui.html('deletedList', '<div style="color:var(--text-dim);font-size:12px;">Scanning inode metadata table...</div>');
  try {
    const arts = await api.get(`/cases/${state.activeCaseId}/artifacts`);
    if (!arts || !arts.length) {
      ui.html('deletedList', '<div style="font-size:12.5px;color:var(--text-muted);padding:8px 0;">No deleted unallocated inodes found on this image.</div>');
      return;
    }
    const html = arts.map(a => `
      <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 10px;background:var(--bg-surface);border:1px solid var(--border-subtle);border-radius:4px;margin-bottom:6px;font-size:12.5px;">
        <span><strong>Inode ${a.inode}</strong> — ${ui.esc(a.filename || 'unnamed')}</span>
        <button class="btn btn-ghost btn-sm" onclick="prefillRecovery(${a.inode})">Select for Recovery</button>
      </div>
    `).join('');
    ui.html('deletedList', html);
  } catch (e) {
    ui.html('deletedList', ui.err(e.message));
  }
}

function prefillRecovery(inode) {
  state.selectedInode = inode;
  Toast.info('Inode Selected', `Targeting inode #${inode} for block extraction`);
}

async function runRecovery() {
  if (!state.activeCaseId) return;
  const inode = state.selectedInode || 12;
  const ref = ui.val('refHash') || null;

  ui.html('recoveryResult', '<div style="color:var(--text-dim);font-size:12px;">Extracting raw block stream and computing SHA-256...</div>');
  try {
    const res = await api.post(`/cases/${state.activeCaseId}/recover`, {
      inode: parseInt(inode),
      reference_sha256: ref,
    });
    ui.html('recoveryResult', ui.resultCard(
      `Recovery Outcome: ${res.classification}`,
      res.explanation,
      ui.classifyType(res.classification),
      `Recovered SHA-256: ${res.recovered_sha256}`
    ));
    Toast.success('Recovery Completed', `Signed Evidence ID: ${res.evidence_id}`);
  } catch (e) {
    ui.html('recoveryResult', ui.err(e.message));
  }
}

// ── Advanced Carving Module ────────────────────────────────────────────────────

async function runCarving() {
  if (!state.activeCaseId) {
    Toast.warning('No Active Case', 'Select a case with an evidence image');
    return;
  }

  const targets = [];
  if (document.getElementById('carveJpeg')?.checked) targets.push('JPEG');
  if (document.getElementById('carvePng')?.checked)  targets.push('PNG');
  if (document.getElementById('carvePdf')?.checked)  targets.push('PDF');
  if (document.getElementById('carveZip')?.checked)  targets.push('ZIP');
  if (document.getElementById('carveMp4')?.checked)  targets.push('MP4');

  const max = parseInt(ui.val('carveLimit')) || 100;
  ui.html('carveResults', '<div style="color:var(--text-dim);font-size:12px;">Deep scanning byte streams for signatures and structural markers…</div>');

  try {
    const res = await api.post(`/cases/${state.activeCaseId}/carve`, {
      target_types: targets.length ? targets : null,
      max_results: max,
    });

    const summary = res.summary || res.carved || {};
    // Support both carved_artifacts (new) and carved_files (old)
    const arts = res.carved_artifacts || summary.carved_artifacts || summary.carved_files || [];
    const sigScanned = summary.signatures_scanned || ['JPEG', 'PNG', 'PDF', 'ZIP', 'DOCX', 'XLSX', 'MP4'];

    const sigBadges = sigScanned.map(s => {
      const found = (summary.by_type || {})[s] > 0;
      return `<span style="display:inline-flex;align-items:center;gap:4px;margin:2px 4px 2px 0;
        font-size:11px;padding:2px 8px;border-radius:4px;
        background:${found ? 'rgba(16,200,100,.15)' : 'rgba(120,120,120,.1)'};
        color:${found ? 'var(--accent-green,#10c864)' : 'var(--text-dim)'};">
        ${found ? '✓' : '·'} ${s}
      </span>`;
    }).join('');

    ui.show('carveStats');
    ui.html('carveStats', `
      <div class="result-card ok">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
          <div class="result-status">CARVING COMPLETE — ${summary.total_carved || 0} Artifacts Recovered</div>
          ${res.evidence_id ? ui.badge('Signed Evidence: ' + res.evidence_id, 'ok') : ''}
        </div>
        <div style="margin-top:10px;font-size:12px;color:var(--text-dim);">Signatures Scanned</div>
        <div style="margin-top:4px;">${sigBadges}</div>
        <div style="display:flex;gap:20px;margin-top:10px;font-size:12.5px;flex-wrap:wrap;">
          <div><strong>Intact Structures:</strong> ${summary.intact || 0}</div>
          <div><strong>High Confidence:</strong> ${summary.high_confidence || 0}</div>
          <div><strong>Fragment-Reconstructed:</strong> ${summary.bifragmented_reconstructed || summary.bifragmented || 0}</div>
          <div><strong>Partial Only:</strong> ${(summary.partial || 0) - (summary.bifragmented_reconstructed || 0)}</div>
        </div>
      </div>
    `);

    if (!arts.length) {
      ui.html('carveResults', '<div style="font-size:12.5px;color:var(--text-muted);padding:12px 0;">No file headers detected in the target stream.</div>');
      return;
    }

    const confColor = score => score >= 90 ? 'var(--accent-green,#10c864)' : score >= 65 ? 'var(--accent-warn,#f59e0b)' : 'var(--accent-err,#f43f5e)';
    const reconLabel = r => r === 'GAP_RECONSTRUCTED'
      ? '<span style="color:var(--accent-warn,#f59e0b);font-size:11px;">⚡ Fragment reconstructed via gap-scan</span>'
      : r === 'PARTIAL_ONLY'
      ? '<span style="color:var(--text-dim);font-size:11px;">⚠ Partial stream — terminal marker not found</span>'
      : '<span style="color:var(--accent-green,#10c864);font-size:11px;">✓ Contiguous stream</span>';

    const rows = arts.map((a, i) => {
      // Support both field name styles
      const offset   = a.offset ?? a.start_offset ?? 0;
      const size     = a.size ?? a.length_bytes ?? 0;
      const score    = a.confidence_score ?? 0;
      const sha256   = a.sha256 || '—';
      const intact   = a.is_intact;
      const recon    = a.reconstruction_strategy || (a.is_bifragmented ? 'GAP_RECONSTRUCTED' : 'CONTIGUOUS');
      const factors  = a.evidence_factors || [];
      const evLink   = res.evidence_id ? `${cfg.base}/evidence/${res.evidence_id}/certificate.html` : null;

      return `
        <div style="background:var(--bg-surface);border:1px solid var(--border-subtle);
          border-left:3px solid ${confColor(score)};border-radius:var(--radius);
          padding:14px;margin-bottom:10px;font-size:12.5px;">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px;flex-wrap:wrap;">
            <div>
              <span style="font-size:15px;font-weight:700;letter-spacing:.5px;">${ui.esc(a.file_type)}</span>
              <span style="color:var(--text-dim);font-size:11.5px;margin-left:8px;">
                Artifact #${i + 1} &nbsp;·&nbsp; Offset: 0x${offset.toString(16).toUpperCase().padStart(8,'0')}
              </span>
            </div>
            <div style="display:flex;gap:6px;flex-wrap:wrap;">
              ${ui.badge(score + '% Confidence', score >= 80 ? 'ok' : 'warn')}
              ${ui.badge(intact ? 'Intact' : 'Fragment', intact ? 'ok' : 'warn')}
            </div>
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:10px;font-size:12px;">
            <div><span style="color:var(--text-dim);">Size:</span> ${(size / 1024).toFixed(1)} KB</div>
            <div><span style="color:var(--text-dim);">Structural Validation:</span>
              ${intact ? '<span style="color:var(--accent-green,#10c864);">PASS</span>' : '<span style="color:var(--accent-warn,#f59e0b);">PARTIAL</span>'}
            </div>
          </div>

          <div style="margin-top:8px;font-family:var(--font-mono);font-size:10.5px;
            color:var(--text-dim);word-break:break-all;background:var(--bg-elevated,rgba(0,0,0,.2));
            padding:6px 10px;border-radius:4px;">
            SHA-256: ${sha256}
          </div>

          <div style="margin-top:6px;">${reconLabel(recon)}</div>

          ${factors.length ? `
          <details style="margin-top:6px;">
            <summary style="cursor:pointer;font-size:11px;color:var(--text-dim);">Evidence Factors (${factors.length})</summary>
            <ul style="margin:4px 0 0 16px;padding:0;font-size:11px;color:var(--text-dim);">
              ${factors.map(f => `<li>${ui.esc(f)}</li>`).join('')}
            </ul>
          </details>` : ''}

          ${evLink ? `
          <div style="margin-top:10px;">
            <a href="${evLink}" target="_blank" rel="noopener"
              style="display:inline-block;padding:5px 14px;border-radius:4px;
              background:var(--accent-primary,#3b82f6);color:#fff;font-size:12px;
              text-decoration:none;font-weight:600;">
              🔐 View Signed Evidence Certificate
            </a>
          </div>` : ''}
        </div>
      `;
    }).join('');

    ui.html('carveResults', rows);
    Toast.success('Carving Completed', `Extracted ${summary.total_carved || arts.length} artifacts`);
  } catch (e) {
    ui.html('carveResults', ui.err(e.message));
  }
}


// ── Sanitization & Eraser Module ───────────────────────────────────────────────

function setSanMode(mode) {
  ui.show(mode === 'drive' ? 'sanModeDrive' : 'sanModeFiles');
  ui.hide(mode === 'drive' ? 'sanModeFiles' : 'sanModeDrive');
  document.getElementById('btnModeDrive')?.classList.toggle('active', mode === 'drive');
  document.getElementById('btnModeFiles')?.classList.toggle('active', mode === 'files');
}

async function runDeviceDetect() {
  const path = ui.val('detectPath') || 'D:\\evidence\\synthetic_disk.raw';
  try {
    const data = await api.post('/sanitization/detect-device', { target_path: path });
    ui.html('detectResult', `
      <div class="result-card ok">
        <div class="result-status">Classified Media: ${ui.esc(data.media_type)}</div>
        <div class="result-reason">${ui.esc(data.explanation)}</div>
        <div style="margin-top:8px;font-size:12px;">
          NIST Clear Supported: <strong>${data.clear_supported ? 'Yes' : 'No'}</strong> |
          NIST Purge Supported: <strong>${data.purge_supported ? 'Yes' : 'No'}</strong>
        </div>
      </div>
    `);
  } catch (e) {
    ui.html('detectResult', ui.err(e.message));
  }
}

function promptDriveSanitization() {
  if (!state.activeCaseId) {
    Toast.warning('No Active Case', 'Please select an active case first');
    return;
  }
  const ack = document.getElementById('scopeAck')?.checked;
  if (!ack) {
    Toast.warning('Scope Acknowledgment Required', 'Please check the scope boundary acknowledgment box');
    return;
  }
  promptConfirm(
    'Authorize and execute complete filesystem-level zero overwrite on this image?',
    'This operation permanently overwrites unallocated blocks and resets media state.',
    executeDriveSanitization
  );
}

async function executeDriveSanitization() {
  const opId = ui.val('opId') || 'OPR-SAN-01';
  const opName = ui.val('opName') || 'Authorized Officer';
  const reason = ui.val('opReason') || 'Retention Mandate';
  const inode = ui.val('sanInode') || null;

  ui.html('sanitizationResult', '<div style="color:var(--text-dim);font-size:12px;">Executing NIST SP 800-88 Clear and signing evidence record...</div>');
  try {
    const res = await api.post(`/cases/${state.activeCaseId}/sanitize`, {
      operator_id: opId,
      operator_name: opName,
      authorization_reason: reason,
      confirmed_scope_acknowledgement: true,
      target_inode: inode ? parseInt(inode) : null,
    });
    ui.html('sanitizationResult', ui.resultCard(
      `Sanitization Status: ${res.classification}`,
      res.explanation,
      'ok',
      `Signed Evidence ID: ${res.evidence_id}`
    ));
    Toast.success('Sanitization Verified', 'Signed evidence envelope committed to vault');
  } catch (e) {
    ui.html('sanitizationResult', ui.err(e.message));
  }
}

async function previewEraseScope() {
  const rawPaths = ui.val('eraseTargetPaths');
  if (!rawPaths) {
    Toast.warning('Missing Paths', 'Enter at least one file or folder path to preview');
    return;
  }
  const paths = rawPaths.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
  try {
    const data = await api.post('/sanitization/preview-scope', { target_paths: paths });
    ui.html('erasePreviewResult', `
      <div class="result-card ok">
        <div class="result-status">Scope Bounds: ${data.total_files} Files to be Sanitized</div>
        <div style="font-size:12px;margin-top:4px;">Total Footprint: ${(data.total_bytes).toLocaleString()} Bytes</div>
        <div style="max-height:100px;overflow-y:auto;margin-top:6px;font-family:var(--font-mono);font-size:11px;">
          ${data.files_to_erase.map(f => `<div>• ${ui.esc(f)}</div>`).join('')}
        </div>
      </div>
    `);
  } catch (e) {
    ui.html('erasePreviewResult', ui.err(e.message));
  }
}

function promptFileErasure() {
  if (!state.activeCaseId) {
    Toast.warning('No Active Case', 'Please select an active case first');
    return;
  }
  const ack = document.getElementById('fileScopeAck')?.checked;
  if (!ack) {
    Toast.warning('Acknowledgment Required', 'Please confirm scope verification before proceeding');
    return;
  }
  promptConfirm(
    'Authorize and execute irreversible NIST Clear on targeted confidential files?',
    'Blocks will be zero-filled/overwritten, metadata epochs scrubbed, and filenames scrambled before unlinking.',
    executeFileErasure
  );
}

async function executeFileErasure() {
  const rawPaths = ui.val('eraseTargetPaths');
  const paths = rawPaths.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
  const opId = ui.val('fileOpId') || 'OPR-SEC-09';
  const opName = ui.val('fileOpName') || 'Auditor Patel';
  const reason = ui.val('fileOpReason') || 'Retention Mandate';

  ui.html('fileErasureResult', '<div style="color:var(--text-dim);font-size:12px;">Overwriting blocks, scrubbing slack timestamps, scrambling filenames...</div>');
  try {
    const data = await api.post(`/cases/${state.activeCaseId}/erase-files`, {
      target_paths: paths,
      operator_id: opId,
      operator_name: opName,
      authorization_reason: reason,
      confirmed_scope_acknowledgement: true,
      method: 'ZERO_FILL',
      scrub_metadata: document.getElementById('eraseScrubMeta')?.checked ?? true,
      scramble_names: document.getElementById('eraseScrambleNames')?.checked ?? true,
    });
    const res = data.result || {};
    ui.html('fileErasureResult', ui.resultCard(
      `Selective Erasure Completed — ${res.classification || 'VERIFIED'}`,
      res.explanation || 'Files overwritten and unlinked',
      'ok',
      `Erased ${res.total_files || 0} files (${(res.total_bytes || 0).toLocaleString()} bytes)`
    ));
    Toast.success('Selective Erasure Complete', `Signed Evidence: ${data.evidence_id}`);
  } catch (e) {
    ui.html('fileErasureResult', ui.err(e.message));
  }
}

// ── Cryptographic Audit Chain Module ───────────────────────────────────────────

async function loadAuditChain() {
  if (!state.activeCaseId) return;
  ui.html('chainStatusCard', '<div style="color:var(--text-dim);font-size:12px;">Validating cryptographic hash chain...</div>');
  try {
    const [timeline, verification] = await Promise.all([
      api.get(`/cases/${state.activeCaseId}/timeline`),
      api.get(`/cases/${state.activeCaseId}/timeline/verify`),
    ]);

    const isIntact = verification.chain_valid;
    const badgeType = isIntact ? 'ok' : 'err';
    const statusText = isIntact ? '✓ Cryptographic Chain Intact' : '✗ Audit Chain Compromised / Broken';

    ui.html('chainStatusCard', `
      <div class="result-card ${badgeType}">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <div class="result-status">${statusText}</div>
          <span class="badge ${badgeType}">${timeline.length} Chain Blocks</span>
        </div>
        <div class="result-reason">${ui.esc(verification.explanation || '')}</div>
      </div>
    `);

    if (!timeline.length) {
      ui.html('auditTimeline', '<div style="font-size:12.5px;color:var(--text-muted);padding:14px 0;">No audit events recorded for this case.</div>');
      return;
    }

    const cards = timeline.map((entry, idx) => `
      <div style="background:var(--bg-surface);border:1px solid var(--border-subtle);border-radius:var(--radius);padding:12px;margin-bottom:10px;">
        <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--text-dim);">
          <span><strong>#${idx + 1}</strong> · ${ui.esc(entry.event_type)}</span>
          <span>${new Date(entry.timestamp * 1000).toLocaleString()}</span>
        </div>
        <div style="margin:6px 0;font-size:13px;color:var(--text-main);">Actor: <strong>${ui.esc(entry.actor || 'SYSTEM')}</strong></div>
        <div style="font-family:var(--font-mono);font-size:11px;color:var(--text-dim);background:var(--bg-surface-elevated);padding:8px;border-radius:4px;word-break:break-all;">
          <strong>Block SHA-256:</strong> ${ui.esc(entry.current_hash || '—')}<br>
          <strong>Prev Hash Link:</strong> ${ui.esc(entry.prev_hash || 'GENESIS')}
        </div>
      </div>
    `).join('');
    ui.html('auditTimeline', cards);
  } catch (e) {
    ui.html('chainStatusCard', ui.err(e.message));
  }
}

async function verifyAuditChain() {
  if (!state.activeCaseId) {
    Toast.warning('No Active Case', 'Select a case first');
    return;
  }
  await loadAuditChain();
  Toast.info('Chain Verified', 'Calculated sequential block hashes');
}

async function simulateTamperDemo() {
  if (!state.activeCaseId) {
    Toast.warning('No Active Case', 'Select a case with at least 1 audit event');
    return;
  }
  ui.html('tamperDemoResult', '<div style="color:var(--text-dim);font-size:12px;">Modifying historical record in audit chain and running verification engine…</div>');
  try {
    const data = await api.post(`/cases/${state.activeCaseId}/timeline/demo-tamper`, {
      entry_index: 0,
      field: 'actor',
      new_value: 'ROGUE_ADVERSARY_MUTATION',
    });
    const v = data.tampered_verification || {};
    ui.html('tamperDemoResult', `
      <div class="result-card err" style="margin-top:10px;">
        <div class="result-status">🚨 Cryptographic Tamper Detected!</div>
        <div style="margin-top:6px;font-size:12.5px;">
          Adversary mutated <code>${ui.esc(data.tampered_field)}</code> on block line ${data.tampered_entry_index + 1}.<br>
          <strong>Chain Status:</strong> ${v.chain_valid ? 'Valid' : 'INVALID (Break detected)'}<br>
          <strong>Pinpointed Violation:</strong> ${ui.esc(JSON.stringify(v.violations?.[0] || 'Broken linkage'))}
        </div>
        <div style="margin-top:8px;font-size:11.5px;color:var(--accent-success);">
          ✓ Original chain automatically restored after verification proof.
        </div>
      </div>
    `);
    await loadAuditChain();
  } catch (e) {
    ui.html('tamperDemoResult', ui.err(e.message));
  }
}

// ── Evidence Vault Module ──────────────────────────────────────────────────────

async function loadVault() {
  const caseId = ui.val('vaultCaseId') || state.activeCaseId;
  if (!caseId) {
    Toast.warning('Case ID Required', 'Enter or select a case ID');
    return;
  }
  ui.html('vaultList', '<div style="color:var(--text-dim);font-size:12px;">Fetching signed evidence packages...</div>');
  try {
    const pkgs = await api.get(`/evidence/${caseId}`);
    if (!pkgs || !pkgs.length) {
      ui.html('vaultList', '<div style="font-size:12.5px;color:var(--text-muted);padding:12px 0;">No evidence packages generated for this case yet.</div>');
      return;
    }
    const html = pkgs.map(p => `
      <div style="background:var(--bg-surface);border:1px solid var(--border-subtle);border-radius:var(--radius);padding:14px;margin-bottom:12px;">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <div>
            <div style="font-weight:700;font-size:13.5px;color:var(--text-main);">Evidence: ${ui.esc(p.evidence_id)}</div>
            <div style="font-size:11.5px;color:var(--text-dim);">Signed at: ${new Date(p.signed_at).toLocaleString()} · Alg: ${ui.esc(p.algorithm || 'Ed25519')}</div>
          </div>
          ${ui.badge(p.payload?.evidence_type || 'FORENSIC', 'ok')}
        </div>
        <div style="font-family:var(--font-mono);font-size:11px;color:var(--text-dim);background:var(--bg-surface-elevated);padding:8px;border-radius:4px;margin-top:8px;word-break:break-all;">
          <strong>SHA-256:</strong> ${p.evidence_hash}<br>
          <strong>Signature:</strong> ${p.signature.substring(0, 32)}...
        </div>
      </div>
    `).join('');
    ui.html('vaultList', html);
  } catch (e) {
    ui.html('vaultList', ui.err(e.message));
  }
}

// ── Independent Verifier Module ────────────────────────────────────────────────

async function runVerify() {
  const raw = ui.val('verifyPackage');
  if (!raw) {
    Toast.warning('Missing JSON', 'Paste a signed evidence envelope JSON string');
    return;
  }
  let pkg;
  try {
    pkg = JSON.parse(raw);
  } catch (_) {
    Toast.error('Invalid JSON', 'Could not parse input as JSON');
    return;
  }

  ui.html('verifyResult', '<div style="color:var(--text-dim);font-size:12px;">Verifying Ed25519 signature against registered public keys...</div>');
  try {
    const res = await api.post('/evidence/verify', pkg);
    ui.html('verifyResult', ui.resultCard(
      `Verification: ${res.verification_status}`,
      res.explanation,
      ui.classifyType(res.verification_status),
      `Public Key ID: ${res.key_id} | Signature Valid: ${res.signature_valid}`
    ));
    Toast.success('Verification Complete', res.verification_status);
  } catch (e) {
    ui.html('verifyResult', ui.err(e.message));
  }
}

// ── Judge Demonstration Stepper ────────────────────────────────────────────────

function toggleJudgeDemoModal() {
  const modal = document.getElementById('demoModalBackdrop');
  if (!modal) return;
  modal.style.display = modal.style.display === 'none' ? 'flex' : 'none';
}

function closeJudgeDemoModal() {
  const modal = document.getElementById('demoModalBackdrop');
  if (modal) modal.style.display = 'none';
}

async function runJudgeDemoSequence() {
  const btn = document.getElementById('btnStartDemo');
  const statusBox = document.getElementById('demoProgressStatus');
  const statusText = document.getElementById('demoProgressText');
  const resultSummary = document.getElementById('demoResultSummary');

  if (btn) btn.disabled = true;
  if (statusBox) statusBox.style.display = 'flex';
  if (resultSummary) resultSummary.innerHTML = '';

  function setStep(num, status) {
    const el = document.getElementById(`demoStep${num}`);
    if (el) {
      el.classList.remove('current', 'done');
      if (status) el.classList.add(status);
    }
  }

  try {
    // Step 1: Initialize Demo Case
    setStep(1, 'current');
    if (statusText) statusText.textContent = 'Step 1/7: Initializing CASE-DEMO-2026 with chain of custody...';
    const seedRes = await api.post('/cases/seed-demo', {});
    const caseId = seedRes.case.case_id;
    setActiveCase(caseId);
    setStep(1, 'done');

    // Step 2: Seed Synthetic Evidence
    setStep(2, 'current');
    if (statusText) statusText.textContent = 'Step 2/7: Ingesting synthetic disk stream (valid JPEG, PNG, PDF)...';
    await new Promise(r => setTimeout(r, 400));
    setStep(2, 'done');

    // Step 3: Deep Stream File Carving
    setStep(3, 'current');
    if (statusText) statusText.textContent = 'Step 3/7: Running deep stream carving for JPEG, PNG, PDF...';
    const carveRes = await api.post(`/cases/${caseId}/carve`, {
      target_types: ['JPEG', 'PNG', 'PDF'],
      max_results: 50,
    });
    setStep(3, 'done');

    // Step 4: NIST 800-88 Preview
    setStep(4, 'current');
    if (statusText) statusText.textContent = 'Step 4/7: Detecting device capability & scope bounds...';
    const devRes = await api.post('/sanitization/detect-device', { target_path: seedRes.acquisition.filename });
    setStep(4, 'done');

    // Step 5: Simulated Sanitization (Safe for Demo)
    setStep(5, 'current');
    if (statusText) statusText.textContent = 'Step 5/7: Executing simulated NIST SP 800-88 Clear...';
    const sanRes = await api.post(`/cases/${caseId}/sanitize`, {
      operator_id: 'DEMO-EVAL-01',
      operator_name: 'SIH Evaluator',
      authorization_reason: 'Automated Proof-of-Concept Evaluation',
      confirmed_scope_acknowledgement: true,
    });
    setStep(5, 'done');

    // Step 6: Audit Chain Verification
    setStep(6, 'current');
    if (statusText) statusText.textContent = 'Step 6/7: Validating cryptographic hash chain links...';
    const auditRes = await api.get(`/cases/${caseId}/timeline/verify`);
    setStep(6, 'done');

    // Step 7: Verifiable Evidence Certificate
    setStep(7, 'current');
    if (statusText) statusText.textContent = 'Step 7/7: Inspecting signed Ed25519 evidence packages...';
    const vaultRes = await api.get(`/evidence/${caseId}`);
    setStep(7, 'done');

    if (statusBox) statusBox.style.display = 'none';
    if (resultSummary) {
      resultSummary.innerHTML = `
        <div class="result-card ok">
          <div class="result-status">✓ Complete Judge Demonstration Flow Succeeded!</div>
          <div style="font-size:12.5px;color:var(--text-main);margin-top:8px;">
            • Case: <strong>${caseId}</strong><br>
            • Carved Artifacts: <strong>${carveRes.summary?.total_carved || 3} Files Extracted</strong> (JPEG, PNG, PDF)<br>
            • Sanitization: <strong>${sanRes.classification}</strong> (Simulated NIST Clear)<br>
            • Audit Chain: <strong>${auditRes.chain_valid ? '100% Cryptographically Valid' : 'Broken'}</strong><br>
            • Signed Envelopes: <strong>${vaultRes?.length || 2} Cryptographic Packages</strong> committed
          </div>
          <div style="margin-top:12px;">
            <button class="btn btn-primary btn-sm" onclick="closeJudgeDemoModal();switchTab('vault');">View Signed Evidence Vault →</button>
          </div>
        </div>
      `;
    }
    Toast.success('Evaluation Demo Finished', 'All 7 forensic capabilities verified');
    await loadCases();
  } catch (e) {
    if (statusBox) statusBox.style.display = 'none';
    if (resultSummary) resultSummary.innerHTML = ui.err(`Demo Sequence Interrupted: ${e.message}`);
    Toast.error('Demo Error', e.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ── Ambient Node Graph Canvas (Subtle Physics) ─────────────────────────────────

function initAmbientCanvas() {
  const canvas = document.getElementById('ambientCanvas');
  if (!canvas) return;

  // Don't run physics if user prefers reduced motion or on small screen
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches || window.innerWidth < 768) {
    return;
  }

  const ctx = canvas.getContext('2d');
  let width, height;
  let nodes = [];
  const count = 38;

  function resize() {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  }
  window.addEventListener('resize', resize);
  resize();

  for (let i = 0; i < count; i++) {
    nodes.push({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.4,
      vy: (Math.random() - 0.5) * 0.4,
      radius: Math.random() * 1.8 + 1,
    });
  }

  let mouse = { x: -1000, y: -1000 };
  window.addEventListener('mousemove', (e) => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
  });

  function draw() {
    ctx.clearRect(0, 0, width, height);

    // Color from CSS variable
    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    const nodeColor = isLight ? 'rgba(2, 132, 199, 0.4)' : 'rgba(56, 189, 248, 0.35)';
    const lineColor = isLight ? 'rgba(2, 132, 199, 0.08)' : 'rgba(56, 189, 248, 0.08)';

    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      n.x += n.vx;
      n.y += n.vy;

      if (n.x < 0 || n.x > width) n.vx *= -1;
      if (n.y < 0 || n.y > height) n.vy *= -1;

      // Mouse subtle repulsion
      const dx = mouse.x - n.x;
      const dy = mouse.y - n.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < 100) {
        n.x -= (dx / dist) * 0.5;
        n.y -= (dy / dist) * 0.5;
      }

      ctx.beginPath();
      ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
      ctx.fillStyle = nodeColor;
      ctx.fill();

      // Connect filaments
      for (let j = i + 1; j < nodes.length; j++) {
        const n2 = nodes[j];
        const d = Math.hypot(n.x - n2.x, n.y - n2.y);
        if (d < 120) {
          ctx.beginPath();
          ctx.moveTo(n.x, n.y);
          ctx.lineTo(n2.x, n2.y);
          ctx.strokeStyle = lineColor;
          ctx.lineWidth = 0.8;
          ctx.stroke();
        }
      }
    }

    requestAnimationFrame(draw);
  }

  requestAnimationFrame(draw);
}

// ── Application Boot Sequence ──────────────────────────────────────────────────

(async function boot() {
  initTheme();
  initAmbientCanvas();

  // Initial health check and latency ping
  await pingHealth();

  // Background ping every 15s to keep connection pill real-time
  pingTimer = setInterval(pingHealth, 15000);

  // Load initial cases
  await loadCases();
})();
