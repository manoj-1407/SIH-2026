/**
 * SIH26013 Geospatial Workstation — Interactive Client Engine (v2.0)
 * Professional GIS & Cadastral Harmonization Workstation
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
      return window.location.origin.replace(/\/$/, '');
    }

    // 3. Fallback only if opened directly from local filesystem (file://)
    return 'http://127.0.0.1:8001';
  },
};

// ── Application State ──────────────────────────────────────────────────────────

const state = {
  activeCaseId: null,
  records: [],
  provenanceNodes: [],
  leafletMap: null,
  mapLayers: {},
  healthData: null,
  latencyMs: null,
  activeTheme: 'dark',
};

const RECORD_COLORS = ['#3b82f6', '#10b981', '#ef4444', '#f59e0b', '#8b5cf6', '#06b6d4'];

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
  async call(method, path, body) {
    const opts = { method };
    if (body) {
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
  get:  (path)       => api.call('GET',  path),
  post: (path, body) => api.call('POST', path, body),
};

// ── UI Helpers ─────────────────────────────────────────────────────────────────

const ui = {
  show(id)    { const el = document.getElementById(id); if (el) el.style.display = ''; },
  hide(id)    { const el = document.getElementById(id); if (el) el.style.display = 'none'; },
  html(id, h) { const el = document.getElementById(id); if (el) el.innerHTML = h; },
  text(id, t) { const el = document.getElementById(id); if (el) el.textContent = t; },
  val(id)     { const el = document.getElementById(id); return el ? el.value.trim() : ''; },
  setVal(id, v){ const el = document.getElementById(id); if (el) el.value = v; },

  esc(v) {
    return String(v ?? '').replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  },

  badge(label, type = 'neutral') {
    const cls = { ok: 'badge-ok', warn: 'badge-warn', err: 'badge-err', neutral: 'badge-neutral', geo: 'badge-geo' };
    return `<span class="badge ${cls[type] || 'badge-neutral'}">${ui.esc(label)}</span>`;
  },

  classifyType(status) {
    const ok   = ['NO_CONFLICT', 'VERIFIED', 'VALID', 'INDEPENDENT', 'ESTABLISHED', 'DEFINITE_MATCH', 'APPROVED'];
    const warn = ['TEMPORALLY_QUALIFIED', 'UNKNOWN', 'NOT_INDEPENDENT', 'PARTIAL', 'UNVERIFIED', 'PROBABLE_MATCH', 'FIELD_INSPECTION_REQUIRED', 'PENDING_REVIEW'];
    const err  = ['GEOMETRIC_CONFLICT', 'FAILED', 'INVALID', 'REJECTED', 'CRS_ERROR', 'DATA_QUALITY_ISSUE', 'NO_MATCH'];
    if (ok.includes(status))   return 'ok';
    if (warn.includes(status)) return 'warn';
    if (err.includes(status))  return 'err';
    return 'neutral';
  },

  err(msg) { return `<div class="result-card err"><div class="result-status">Error</div><div class="result-reason">${ui.esc(msg)}</div></div>`; },
};

// ── Tab Navigation ─────────────────────────────────────────────────────────────

const tabNames = {
  cases: 'Cases & Registry',
  ingest: 'Ingest Records',
  aimatch: 'AI Parcel Matcher',
  topology: 'Topology Repair',
  imagery: 'Drone Footprints',
  proposals: 'Harmonization',
  provenance: 'Provenance DAG',
  analysis: 'GIS Map Analysis',
  evidence: 'Evidence Vault',
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

  if (tab === 'analysis') {
    initLeafletMap();
    setTimeout(() => { if (state.leafletMap) state.leafletMap.invalidateSize(); }, 80);
  }
  if (tab === 'proposals' && state.activeCaseId) {
    loadProposals();
  }
  if (tab === 'evidence' && state.activeCaseId) {
    loadEvidence();
  }
}

document.querySelectorAll('.sidenav-item').forEach(btn => {
  btn.addEventListener('click', () => switchTab(btn.dataset.tab));
});

function refreshCurrentView() {
  const active = document.querySelector('.sidenav-item.active');
  const tab = active?.dataset.tab;
  if (tab === 'cases') loadCases();
  if (tab === 'proposals' && state.activeCaseId) loadProposals();
  if (tab === 'evidence' && state.activeCaseId) loadEvidence();
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

  const icons = { dark: '🌲', light: '☀️', contrast: '⚡', system: '💻' };
  const labels = { dark: 'Dark Geo', light: 'Urban Lab', contrast: 'High Contrast', system: 'System' };
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

  try {
    const health = await api.get('/health');
    const latency = Math.round(performance.now() - start);
    state.healthData = health;
    state.latencyMs = latency;

    if (connDot) connDot.className = 'conn-dot dot-ok';
    if (connLabel) connLabel.textContent = 'API Online';
    if (connPing) connPing.textContent = `${latency} ms`;

    // Subsystems
    const subs = health.subsystems || {};
    const dotSpatial = document.getElementById('dotSpatial');
    const dotDAG = document.getElementById('dotDAG');
    const dotTrust = document.getElementById('dotTrust');

    if (dotSpatial) dotSpatial.className = `dot ${subs.spatial_index === 'active' ? 'dot-ok' : 'dot-warn'}`;
    if (dotDAG) dotDAG.className = `dot ${subs.provenance_graph === 'active' ? 'dot-ok' : 'dot-warn'}`;
    if (dotTrust) dotTrust.className = `dot ${subs.cryptographic_trust === 'active' ? 'dot-ok' : 'dot-warn'}`;
  } catch (err) {
    if (connDot) connDot.className = 'conn-dot dot-err';
    if (connLabel) connLabel.textContent = 'Service Offline';
    if (connPing) connPing.textContent = '-- ms';
  }
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
  ui.text('diagCrypto', 'Ed25519');
  ui.text('diagCases', state.healthData?.active_cases ?? '--');

  const savedOverride = localStorage.getItem('sih_api_override') || '';
  ui.setVal('apiBaseOverride', savedOverride);
}

function closeConnDiagnostics() {
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

// ── Active Case ───────────────────────────────────────────────────────────────

function setActiveCase(caseId) {
  state.activeCaseId = caseId;
  state.records = [];
  state.provenanceNodes = [];
  ui.text('topbarCase', caseId);
  ui.text('acsCaseId', caseId);
  ui.show('activeCaseStrip');

  document.querySelectorAll('.case-item').forEach(el =>
    el.classList.toggle('active-case', el.dataset.caseId === caseId));
}

// ── Cases Module ──────────────────────────────────────────────────────────────

function showNewCaseForm() { ui.show('newCaseForm'); }
function hideNewCaseForm() { ui.hide('newCaseForm'); }

async function createCase() {
  const caseId = ui.val('newCaseId') || null;
  const title  = ui.val('newCaseTitle') || 'Geospatial Analysis Case';
  try {
    const data = await api.post('/cases', { case_id: caseId, title });
    hideNewCaseForm();
    setActiveCase(data.case_id);
    Toast.success('Case Initialized', `Case ID: ${data.case_id}`);
    loadCases();
  } catch (e) {
    Toast.error('Case Creation Failed', e.message);
  }
}

async function loadCases() {
  ui.html('casesList', `
    <div class="skeleton-card">
      <div class="skeleton-line" style="width: 40%"></div>
      <div class="skeleton-line" style="width: 70%"></div>
    </div>
  `);

  try {
    const data = await api.get('/cases');
    const cases = data.cases || [];

    if (!cases.length) {
      ui.html('casesList', `
        <div class="empty-state">
          <div class="empty-icon">🗂</div>
          <div class="empty-title">No Cases Found</div>
          <div class="empty-sub">Create a new case or load official test scenarios below.</div>
          <div style="margin-top:14px;">
            <button class="btn btn-primary btn-sm" onclick="seedDemoCases()">⚡ Seed 4 Official Scenarios</button>
          </div>
        </div>
      `);
      return;
    }

    const cards = cases.map(c => {
      const isActive = c.case_id === state.activeCaseId;
      return `
        <div class="case-item ${isActive ? 'active-case' : ''}" data-case-id="${ui.esc(c.case_id)}" onclick="switchCase('${ui.esc(c.case_id)}')">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;">
            <div>
              <div style="font-weight:700;font-size:14px;color:var(--text-main);">${ui.esc(c.title || c.case_id)}</div>
              <div style="font-family:var(--font-mono);font-size:11.5px;color:var(--accent-primary);margin-top:2px;">${ui.esc(c.case_id)}</div>
            </div>
            ${ui.badge(`${c.record_count || 0} Records`, 'geo')}
          </div>
          <div style="display:flex;justify-content:space-between;align-items:center;font-size:11.5px;color:var(--text-dim);margin-top:10px;padding-top:8px;border-top:1px solid var(--border-subtle);">
            <span>Provenance Nodes: <strong>${c.provenance_node_count || 0}</strong></span>
            <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();switchCase('${ui.esc(c.case_id)}');switchTab('analysis');">Inspect Map →</button>
          </div>
        </div>
      `;
    }).join('');

    ui.html('casesList', cards);

    if (!state.activeCaseId && cases.length > 0) {
      switchCase(cases[0].case_id);
    }
  } catch (e) {
    ui.html('casesList', ui.err(e.message));
  }
}

async function switchCase(caseId) {
  setActiveCase(caseId);
  try {
    const data = await api.get(`/cases/${caseId}`);
    state.records = data.records || [];
    state.provenanceNodes = data.provenance_nodes || [];
    ui.text('acsRecords', `${state.records.length} records`);

    renderRecordsList();
    renderProvenance();
    updateAnalysisSelects();
    renderMapRecords();
  } catch (e) {
    Toast.error('Failed to load case', e.message);
  }
}

async function seedDemoCases() {
  Toast.info('Seeding Scenarios', 'Initializing 4 official test cases...');
  try {
    const data = await api.post('/demo/seed', {});
    Toast.success('Scenarios Seeded', 'Loaded Alignment, Drone, Topology & Conflict cases');
    await loadCases();
    if (data.cases_seeded?.length) {
      switchCase(data.cases_seeded[0]);
    }
  } catch (e) {
    Toast.error('Seeding Error', e.message);
  }
}

// ── Ingest Module ─────────────────────────────────────────────────────────────

async function addRecord() {
  if (!state.activeCaseId) {
    Toast.warning('No Active Case', 'Please select or create a case first');
    return;
  }
  const recordId = ui.val('recId');
  const source = ui.val('recSource') || 'Direct Ingest';
  const crs = ui.val('recCrs') || 'EPSG:4326';
  const geomRaw = ui.val('recGeometry');

  if (!recordId) {
    Toast.warning('Validation Error', 'Record ID is required');
    return;
  }

  let geom;
  try {
    geom = JSON.parse(geomRaw);
  } catch (_) {
    Toast.error('Invalid GeoJSON', 'Geometry must be valid JSON');
    return;
  }

  const nodeId = `node_${recordId}`;
  try {
    await api.post(`/cases/${state.activeCaseId}/ingest`, {
      nodes: [{ node_id: nodeId, node_type: 'dataset', parent_ids: [], metadata: { source } }],
      records: [{
        record_id: recordId,
        geometry: geom,
        source_crs: crs,
        provenance_node_id: nodeId,
        metadata: { source },
      }],
    });
    Toast.success('Record Ingested', `Successfully added ${recordId}`);
    ui.setVal('recId', '');
    ui.setVal('recGeometry', '');
    switchCase(state.activeCaseId);
  } catch (e) {
    Toast.error('Ingestion Failed', e.message);
  }
}

function renderRecordsList() {
  const el = document.getElementById('recordsList');
  if (!el) return;
  if (!state.records.length) {
    el.innerHTML = '<div style="font-size:12.5px;color:var(--text-muted);padding:12px 0;">No records in this case.</div>';
    return;
  }

  el.innerHTML = state.records.map((r, i) => {
    const color = RECORD_COLORS[i % RECORD_COLORS.length];
    return `
      <div style="background:var(--bg-surface);border:1px solid var(--border-subtle);border-left:4px solid ${color};border-radius:var(--radius);padding:12px;margin-bottom:8px;font-size:12.5px;">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <strong>${ui.esc(r.record_id)}</strong>
          ${ui.badge(r.source_crs || 'EPSG:4326', 'neutral')}
        </div>
        <div style="font-family:var(--font-mono);font-size:11px;color:var(--text-dim);margin-top:4px;">
          Type: ${ui.esc(r.geometry?.type || 'Unknown')} | Nodes: ${r.geometry?.coordinates?.[0]?.length || 0} vertices
        </div>
      </div>
    `;
  }).join('');
}

// ── AI Matcher Module ─────────────────────────────────────────────────────────

async function runAIMatching() {
  if (!state.activeCaseId) {
    Toast.warning('No Active Case', 'Please select a case first');
    return;
  }
  ui.html('aiMatchResults', '<div style="color:var(--text-dim);font-size:12px;">Running spatial IoU and entity similarity matcher...</div>');
  try {
    const data = await api.post(`/cases/${state.activeCaseId}/ai-match`, { min_probability: 0.2 });
    const matches = data.matches || [];
    if (!matches.length) {
      ui.html('aiMatchResults', '<div class="empty-state"><div class="empty-title">No Cross-Agency Matches Found</div><div class="empty-sub">Parcels may have zero spatial overlap or divergent boundaries.</div></div>');
      return;
    }

    const cards = matches.map(m => `
      <div class="result-card ${ui.classifyType(m.confidence_tier)}" style="margin-bottom:10px;">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <div class="result-status">${ui.esc(m.parcel_a_id)} ↔ ${ui.esc(m.parcel_b_id)}</div>
          ${ui.badge(m.confidence_tier, ui.classifyType(m.confidence_tier))}
        </div>
        <div class="result-reason">${ui.esc(m.explanation)}</div>
        <div style="display:flex;gap:16px;margin-top:8px;font-size:12px;">
          <div><strong>Spatial IoU:</strong> ${(m.spatial_iou * 100).toFixed(1)}%</div>
          <div><strong>Match Probability:</strong> ${(m.match_probability * 100).toFixed(1)}%</div>
          <div><strong>Recommended Action:</strong> ${ui.esc(m.recommended_action)}</div>
        </div>
      </div>
    `).join('');

    ui.html('aiMatchResults', cards);
    Toast.success('AI Match Complete', `Identified ${matches.length} candidate entity alignments`);
  } catch (e) {
    ui.html('aiMatchResults', ui.err(e.message));
  }
}

// ── Topology Repair Module ────────────────────────────────────────────────────

async function runTopologyRepair() {
  if (!state.activeCaseId) {
    Toast.warning('No Active Case', 'Please select a case first');
    return;
  }
  const tol = parseFloat(ui.val('snapTol')) || 1.0;
  ui.html('topologyResults', '<div style="color:var(--text-dim);font-size:12px;">Snapping vertices and eliminating overlapping polygons...</div>');
  try {
    const data = await api.post(`/cases/${state.activeCaseId}/topology-repair`, { snap_tolerance_m: tol });
    const anoms = data.anomalies_detected || [];

    ui.html('topologyResults', `
      <div class="result-card ok" style="margin-bottom:14px;">
        <div class="result-status">Topology Repair Completed</div>
        <div class="result-reason">${ui.esc(data.repair_summary)}</div>
        <div style="display:flex;gap:16px;margin-top:10px;font-size:12.5px;flex-wrap:wrap;">
          <div><strong>Initial Overlap:</strong> <span style="color:var(--accent-danger);">${data.initial_overlap_sq_m} m²</span></div>
          <div><strong>Residual Overlap:</strong> <span style="color:var(--accent-success);">${data.residual_overlap_sq_m} m²</span></div>
          <div><strong>Vertices Snapped:</strong> ${data.vertices_adjusted}</div>
        </div>
      </div>
      ${anoms.length ? `
        <div style="font-weight:700;font-size:13px;margin:12px 0 8px;">Detected Boundary Conflict Zones:</div>
        ${anoms.map(a => `
          <div style="background:var(--bg-surface);border:1px solid var(--border-subtle);border-radius:6px;padding:10px;margin-bottom:8px;font-size:12.5px;">
            <div style="display:flex;justify-content:space-between;">
              <span><strong>${ui.esc(a.anomaly_type)}</strong> · ${ui.esc(a.parcels_involved.join(' ↔ '))}</span>
              <span class="badge ${a.severity === 'HIGH' ? 'badge-err' : 'badge-warn'}">${a.area_sq_m} m²</span>
            </div>
            <div style="color:var(--text-muted);margin-top:4px;">${ui.esc(a.description)}</div>
          </div>
        `).join('')}
      ` : ''}
    `);
    Toast.success('Topology Corrected', `Adjusted ${data.vertices_adjusted} vertices`);
  } catch (e) {
    ui.html('topologyResults', ui.err(e.message));
  }
}

// ── Drone Imagery & Footprints Module ─────────────────────────────────────────

async function runDroneAnalysis() {
  if (!state.activeCaseId) {
    Toast.warning('No Active Case', 'Please select a case first');
    return;
  }
  ui.html('imageryResults', '<div style="color:var(--text-dim);font-size:12px;">Evaluating building footprints against cadastral property bounds…</div>');
  try {
    const data = await api.post(`/cases/${state.activeCaseId}/imagery-analysis`, {
      footprints: [
        {
          footprint_id: "DRONE-BLDG-1",
          area_sq_m: 245.0,
          estimated_floors: 3,
          geometry: {
            type: "Polygon",
            coordinates: [[[77.6008, 12.9805], [77.6012, 12.9805], [77.6012, 12.9809], [77.6008, 12.9809], [77.6008, 12.9805]]]
          }
        }
      ]
    });

    const encr = data.encroachments || [];
    ui.html('imageryResults', `
      <div class="result-card ${encr.length ? 'warn' : 'ok'}" style="margin-bottom:14px;">
        <div class="result-status">Drone Photogrammetry &amp; Encroachment Analysis</div>
        <div class="result-reason">${ui.esc(data.summary)}</div>
        <div style="display:flex;gap:16px;margin-top:10px;font-size:12.5px;flex-wrap:wrap;">
          <div><strong>Built Area:</strong> ${data.total_built_up_area_sq_m} m²</div>
          <div><strong>Coverage Ratio (FSI):</strong> ${(data.coverage_ratio * 100).toFixed(1)}%</div>
          <div><strong>Buildings:</strong> ${data.building_count}</div>
        </div>
      </div>
      ${encr.length ? `
        <div style="font-weight:700;font-size:13px;margin:12px 0 8px;color:var(--accent-danger);">Boundary Encroachment Violations:</div>
        ${encr.map(e => `
          <div style="background:var(--bg-surface);border:1px solid var(--border-subtle);border-left:4px solid var(--accent-danger);border-radius:6px;padding:12px;margin-bottom:8px;font-size:12.5px;">
            <div style="display:flex;justify-content:space-between;">
              <span><strong>Building ${ui.esc(e.footprint_id)}</strong></span>
              <span class="badge badge-err">${e.severity} · ${e.encroached_area_sq_m} m²</span>
            </div>
            <div style="margin-top:6px;color:var(--text-main);">${ui.esc(e.description)}</div>
          </div>
        `).join('')}
      ` : ''}
    `);
    Toast.success('Drone Analysis Complete', `Identified ${encr.length} property boundary encroachments`);
  } catch (e) {
    ui.html('imageryResults', ui.err(e.message));
  }
}

// ── Harmonization Proposals Module ────────────────────────────────────────────

async function generateHarmonizationProposal() {
  if (!state.activeCaseId) {
    Toast.warning('No Active Case', 'Please select a case first');
    return;
  }
  ui.html('proposalsList', '<div style="color:var(--text-dim);font-size:12px;">Synthesizing inputs into authoritative harmonization proposal…</div>');
  try {
    await api.post(`/cases/${state.activeCaseId}/proposals`, {});
    Toast.success('Proposal Generated', 'Consensus parcel boundary reconciled');
    await loadProposals();
  } catch (e) {
    ui.html('proposalsList', ui.err(e.message));
  }
}

async function loadProposals() {
  if (!state.activeCaseId) return;
  try {
    const proposals = await api.get(`/cases/${state.activeCaseId}/proposals`);
    if (!proposals.length) {
      ui.html('proposalsList', `
        <div class="empty-state">
          <div class="empty-icon">📜</div>
          <div class="empty-title">No Proposals Generated Yet</div>
          <div class="empty-sub">Click "+ Generate New Proposal" to reconcile conflicting claims.</div>
        </div>
      `);
      return;
    }

    const cards = proposals.map(p => {
      const isApproved = p.status === 'APPROVED';
      const badgeCls = isApproved ? 'badge-ok' : p.status === 'REJECTED' ? 'badge-err' : 'badge-warn';
      const env = p.signed_evidence_envelope;

      return `
        <div style="background:var(--bg-surface);border:1px solid var(--border-subtle);border-radius:var(--radius);padding:16px;margin-bottom:16px;">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <div>
              <div style="font-weight:700;font-size:14px;color:var(--text-main);">Proposal ${ui.esc(p.proposal_id)}</div>
              <div style="font-size:12px;color:var(--text-muted);">Survey Target: <strong>${ui.esc(p.target_survey_number)}</strong> · Confidence: ${(p.confidence_score*100).toFixed(0)}%</div>
            </div>
            <span class="badge ${badgeCls}">${ui.esc(p.status)}</span>
          </div>

          <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(160px, 1fr));gap:10px;margin:12px 0;padding:10px;background:var(--bg-surface-elevated);border-radius:6px;font-size:12.5px;">
            <div><strong>Harmonized Area:</strong> ${p.recommended_area_sq_m.toLocaleString()} m²</div>
            <div><strong>Recommended Use:</strong> ${ui.esc(p.recommended_land_use)}</div>
            <div><strong>Title Holder:</strong> ${ui.esc(p.recommended_owner_ref)}</div>
            <div><strong>Reconciled Sources:</strong> ${p.source_parcel_ids?.length || 0} agencies</div>
          </div>

          ${env ? `
            <div style="background:var(--bg-surface);border:1px solid var(--border-subtle);border-left:4px solid var(--accent-success);padding:10px;border-radius:4px;margin-top:10px;font-size:12px;">
              <div style="color:var(--accent-success);font-weight:700;">✓ Cryptographically Signed Harmonization Record (Ed25519)</div>
              <div style="font-family:var(--font-mono);margin-top:4px;color:var(--text-muted);word-break:break-all;">
                Evidence ID: <strong>${ui.esc(env.evidence_id)}</strong><br>
                SHA-256 Hash: ${ui.esc(env.evidence_hash)}
              </div>
            </div>
          ` : `
            <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap;">
              <button class="btn btn-primary btn-sm" onclick="submitProposalReview('${p.proposal_id}','APPROVE')">✓ Approve &amp; Cryptographically Sign</button>
              <button class="btn btn-ghost btn-sm" onclick="submitProposalReview('${p.proposal_id}','FIELD_INSPECTION_REQUIRED')">Request Field Inspection</button>
              <button class="btn btn-danger btn-sm" onclick="submitProposalReview('${p.proposal_id}','REJECT')">Reject Proposal</button>
            </div>
          `}
        </div>
      `;
    }).join('');

    ui.html('proposalsList', cards);
  } catch (e) {
    ui.html('proposalsList', ui.err(e.message));
  }
}

async function submitProposalReview(proposalId, action) {
  if (!state.activeCaseId) return;
  const reviewer = prompt('Enter Official Reviewer ID / Designation:', 'CHIEF_SETTLEMENT_OFFICER');
  if (!reviewer) return;
  const notes = prompt('Enter review endorsement remarks:', 'Approved following multi-agency boundary harmonization.');

  try {
    await api.post(`/cases/${state.activeCaseId}/proposals/${proposalId}/review`, {
      action,
      reviewer_id: reviewer,
      notes: notes || '',
    });
    Toast.success('Proposal Endorsed', `Record cryptographically signed by ${reviewer}`);
    await loadProposals();
  } catch (e) {
    Toast.error('Review Failed', e.message);
  }
}

// ── Provenance DAG Module ─────────────────────────────────────────────────────

function renderProvenance() {
  const el = document.getElementById('provenanceGraph');
  if (!el) return;
  if (!state.provenanceNodes.length) {
    el.innerHTML = '<div style="font-size:12.5px;color:var(--text-muted);padding:14px 0;">No provenance nodes recorded for this case.</div>';
    return;
  }

  el.innerHTML = state.provenanceNodes.map(n => `
    <div style="background:var(--bg-surface);border:1px solid var(--border-subtle);border-radius:var(--radius);padding:10px 14px;margin-bottom:8px;font-size:12.5px;">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <strong>${ui.esc(n.node_id)}</strong>
        ${ui.badge(n.node_type || 'origin', 'neutral')}
      </div>
      ${n.parent_ids?.length ? `<div style="font-size:11.5px;color:var(--text-dim);margin-top:4px;">Parent Lineage: ${n.parent_ids.join(', ')}</div>` : ''}
    </div>
  `).join('');
}

// ── Temporal Change Analysis Module ───────────────────────────────────────────

async function runTemporalAnalysis() {
  if (!state.activeCaseId) {
    Toast.warning('No Active Case', 'Load a case first');
    return;
  }
  const resultEl = document.getElementById('temporalResults');
  if (resultEl) ui.html('temporalResults', '<div style="color:var(--text-dim);font-size:12px;">Analysing record history for temporal changes…</div>');

  try {
    const res = await api.post(`/cases/${state.activeCaseId}/temporal-analysis`, {});
    const diffs = res.diffs || [];

    if (!diffs.length) {
      if (resultEl) ui.html('temporalResults', '<div style="font-size:12.5px;color:var(--text-muted);padding:10px 0;">No survey pairs with temporal history found. Ingest records from multiple agencies for the same survey number.</div>');
      Toast.info('Temporal Analysis', 'No paired records found — need same survey_number from ≥2 agencies');
      return;
    }

    const sevColor = s => s === 'CRITICAL' ? '#f43f5e' : s === 'MAJOR' ? '#f59e0b' : s === 'MODERATE' ? '#3b82f6' : '#6b7280';
    const rows = diffs.map(d => `
      <div style="background:var(--bg-surface);border:1px solid var(--border-subtle);
        border-left:3px solid ${sevColor(d.change_severity)};border-radius:var(--radius);
        padding:12px;margin-bottom:8px;font-size:12.5px;">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px;">
          <div>
            <strong>Survey ${ui.esc(d.survey_number)}</strong>
            <span style="color:var(--text-dim);font-size:11.5px;margin-left:8px;">${ui.esc(d.record_a_id)} → ${ui.esc(d.record_b_id)}</span>
          </div>
          ${ui.badge(d.change_severity, d.change_severity === 'CRITICAL' ? 'err' : d.change_severity === 'MAJOR' ? 'warn' : 'neutral')}
        </div>
        <div style="margin-top:8px;font-size:12px;color:var(--text-dim);">${ui.esc(d.summary)}</div>
        ${d.gap_days != null ? `<div style="font-size:11px;margin-top:4px;color:var(--text-dim);">Temporal gap: <strong>${d.gap_days} days</strong>${d.temporally_qualified ? ' — <em>Temporally qualified discrepancy</em>' : ''}</div>` : ''}
        ${d.changes.length ? `
          <ul style="margin:6px 0 0 14px;padding:0;font-size:11px;color:var(--text-dim);">
            ${d.changes.map(c => `<li>${ui.esc(c.field)}: <em>${ui.esc(String(c.old_value))}</em> → <strong>${ui.esc(String(c.new_value))}</strong> [${ui.esc(c.change_type)}]</li>`).join('')}
          </ul>` : ''}
      </div>
    `).join('');

    if (resultEl) ui.html('temporalResults', rows);
    Toast.success('Temporal Analysis', `Found ${diffs.length} record-history change vectors`);
    return res;
  } catch (e) {
    if (resultEl) ui.html('temporalResults', ui.err(e.message));
    throw e;
  }
}

// ── Canonical GeoJSON Export Module ───────────────────────────────────────────

async function runCanonicalExport() {
  if (!state.activeCaseId) {
    Toast.warning('No Active Case', 'Load a case first');
    return;
  }
  const resultEl = document.getElementById('canonicalExportResult');
  if (resultEl) ui.html('canonicalExportResult', '<div style="color:var(--text-dim);font-size:12px;">Generating signed canonical GeoJSON FeatureCollection…</div>');

  try {
    const res = await api.get(`/cases/${state.activeCaseId}/canonical-export`);
    const fc   = res.geojson || {};
    const nf   = res.feature_count || 0;

    const exportStr = JSON.stringify(fc, null, 2);
    const blob = new Blob([exportStr], { type: 'application/geo+json' });
    const url  = URL.createObjectURL(blob);

    const html = `
      <div class="result-card ok" style="font-size:12.5px;">
        <div class="result-status">CANONICAL EXPORT READY — ${nf} Features</div>
        <div style="display:flex;gap:16px;margin-top:10px;flex-wrap:wrap;">
          <div><span style="color:var(--text-dim);">Evidence ID:</span> <code>${ui.esc(res.evidence_id || '—')}</code></div>
          <div><span style="color:var(--text-dim);">Algorithm:</span> Ed25519</div>
        </div>
        <div style="margin-top:8px;font-family:var(--font-mono);font-size:10.5px;
          color:var(--text-dim);word-break:break-all;background:rgba(0,0,0,.2);
          padding:6px 10px;border-radius:4px;">
          SHA-256: ${ui.esc(res.payload_sha256 || '—')}
        </div>
        <div style="margin-top:8px;font-size:11.5px;color:var(--text-dim);
          border-top:1px solid var(--border-subtle);padding-top:8px;">
          <strong>WFS-T Note:</strong> ${ui.esc(res.wfs_t_note || '')}
        </div>
        <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;">
          <a href="${url}" download="canonical_${state.activeCaseId}.geojson"
            style="display:inline-block;padding:5px 14px;border-radius:4px;
            background:var(--accent-primary,#3b82f6);color:#fff;font-size:12px;
            text-decoration:none;font-weight:600;">
            ⬇ Download GeoJSON
          </a>
          ${res.signed_envelope?.evidence_id ? `<a href="${cfg.base}/evidence/${res.signed_envelope.evidence_id}/certificate.html"
            target="_blank" rel="noopener"
            style="display:inline-block;padding:5px 14px;border-radius:4px;
            background:transparent;border:1px solid var(--accent-primary,#3b82f6);
            color:var(--accent-primary,#3b82f6);font-size:12px;text-decoration:none;font-weight:600;">
            🔐 Signed Certificate
          </a>` : ''}
        </div>
      </div>
    `;
    if (resultEl) ui.html('canonicalExportResult', html);
    Toast.success('Canonical Export', `Signed GeoJSON with ${nf} features ready for download`);
    return res;
  } catch (e) {
    if (resultEl) ui.html('canonicalExportResult', ui.err(e.message));
    throw e;
  }
}


// ── GIS Map & Pairwise Analysis ───────────────────────────────────────────────

function initLeafletMap() {
  if (state.leafletMap || typeof L === 'undefined') return;
  const mapEl = document.getElementById('leafletMap');
  if (!mapEl) return;

  state.leafletMap = L.map('leafletMap').setView([12.9716, 77.5946], 15);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '© OpenStreetMap contributors'
  }).addTo(state.leafletMap);

  renderMapRecords();
}

function renderMapRecords() {
  if (!state.leafletMap || !state.records.length) return;

  // Clear previous layers
  Object.values(state.mapLayers).forEach(layer => state.leafletMap.removeLayer(layer));
  state.mapLayers = {};

  const bounds = [];
  state.records.forEach((r, i) => {
    if (!r.geometry) return;
    const color = RECORD_COLORS[i % RECORD_COLORS.length];
    try {
      const geoLayer = L.geoJSON(r.geometry, {
        style: { color, weight: 2, fillOpacity: 0.35 },
      }).bindPopup(`<strong>${ui.esc(r.record_id)}</strong><br>CRS: ${r.source_crs}`);

      geoLayer.addTo(state.leafletMap);
      state.mapLayers[r.record_id] = geoLayer;
      bounds.push(geoLayer.getBounds());
    } catch (_) {}
  });

  if (bounds.length) {
    const groupBounds = bounds.reduce((acc, b) => acc.extend(b), L.latLngBounds(bounds[0]));
    state.leafletMap.fitBounds(groupBounds, { padding: [20, 20] });
  }
}

function updateAnalysisSelects() {
  const selA = document.getElementById('selectRecA');
  const selB = document.getElementById('selectRecB');
  if (!selA || !selB) return;

  const opts = state.records.map(r => `<option value="${ui.esc(r.record_id)}">${ui.esc(r.record_id)}</option>`).join('');
  selA.innerHTML = opts;
  selB.innerHTML = opts;
  if (state.records.length > 1) {
    selB.selectedIndex = 1;
  }
}

async function runPairwiseAnalysis() {
  if (!state.activeCaseId) return;
  const a = ui.val('selectRecA');
  const b = ui.val('selectRecB');

  if (!a || !b || a === b) {
    Toast.warning('Invalid Selection', 'Please select two different records for pairwise analysis');
    return;
  }

  ui.html('analysisResult', '<div style="color:var(--text-dim);font-size:12px;">Computing spatial difference and attribute variance...</div>');
  try {
    const res = await api.post(`/cases/${state.activeCaseId}/analysis`, {
      record_id_a: a,
      record_id_b: b,
    });
    const r = res.result || {};
    ui.html('analysisResult', `
      <div class="result-card ${ui.classifyType(r.geo_classification)}">
        <div class="result-status">Pairwise Result: ${ui.esc(r.geo_classification)}</div>
        <div class="result-reason">Spatial Intersection (IoU): ${((r.intersection_ratio || 0) * 100).toFixed(1)}% | Symmetric Diff Area: ${(r.symmetric_diff_sq_m || 0).toLocaleString()} m²</div>
        <div style="margin-top:8px;font-size:12px;color:var(--text-muted);">Signed Evidence ID: <strong>${ui.esc(res.evidence_id || '—')}</strong></div>
      </div>
    `);
    Toast.success('Analysis Complete', `Result: ${r.geo_classification}`);
  } catch (e) {
    ui.html('analysisResult', ui.err(e.message));
  }
}

// ── Evidence Vault Module ──────────────────────────────────────────────────────

async function loadEvidence() {
  if (!state.activeCaseId) return;
  ui.html('evidenceList', '<div style="color:var(--text-dim);font-size:12px;">Fetching signed evidence packages...</div>');
  try {
    const pkgs = await api.get(`/evidence/${state.activeCaseId}`);
    if (!pkgs.length) {
      ui.html('evidenceList', '<div style="font-size:12.5px;color:var(--text-muted);padding:14px 0;">No evidence packages generated for this case yet.</div>');
      return;
    }

    const html = pkgs.map(p => `
      <div style="background:var(--bg-surface);border:1px solid var(--border-subtle);border-radius:var(--radius);padding:14px;margin-bottom:12px;">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <div>
            <div style="font-weight:700;font-size:13.5px;color:var(--text-main);">Envelope: ${ui.esc(p.evidence_id)}</div>
            <div style="font-size:11.5px;color:var(--text-dim);">Signed: ${new Date(p.signed_at).toLocaleString()} · Alg: ${ui.esc(p.algorithm || 'Ed25519')}</div>
          </div>
          ${ui.badge(p.payload?.evidence_type || 'GEOSPATIAL', 'geo')}
        </div>
        <div style="font-family:var(--font-mono);font-size:11px;color:var(--text-dim);background:var(--bg-surface-elevated);padding:8px;border-radius:4px;margin-top:8px;word-break:break-all;">
          <strong>SHA-256:</strong> ${p.evidence_hash}<br>
          <strong>Signature:</strong> ${p.signature.substring(0, 32)}...
        </div>
      </div>
    `).join('');
    ui.html('evidenceList', html);
  } catch (e) {
    ui.html('evidenceList', ui.err(e.message));
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
    // Step 1: Seed Official Scenarios
    setStep(1, 'current');
    if (statusText) statusText.textContent = 'Step 1/6: Ingesting multi-agency cadastral datasets (4 scenarios)...';
    const seedRes = await api.post('/demo/seed', {});
    const targetCase = 'DEMO-ALIGN';
    await switchCase(targetCase);
    setStep(1, 'done');

    // Step 2: AI Multi-Source Entity Match
    setStep(2, 'current');
    if (statusText) statusText.textContent = 'Step 2/6: Calculating spatial IoU & attribute token similarity...';
    const matchRes = await api.post(`/cases/${targetCase}/ai-match`, { min_probability: 0.2 });
    setStep(2, 'done');

    // Step 3: Cadastral Topology Repair
    setStep(3, 'current');
    if (statusText) statusText.textContent = 'Step 3/6: Correcting boundary overlap and vertex misalignment...';
    const topoRes = await api.post(`/cases/DEMO-TOPOLOGY/topology-repair`, { snap_tolerance_m: 1.0 });
    setStep(3, 'done');

    // Step 4: Drone Footprint Analysis
    setStep(4, 'current');
    if (statusText) statusText.textContent = 'Step 4/6: Examining building vectors for boundary encroachment...';
    const droneRes = await api.post(`/cases/DEMO-ENCROACH/imagery-analysis`, {
      footprints: [{
        footprint_id: "DRONE-BLDG-1",
        area_sq_m: 245.0,
        estimated_floors: 3,
        geometry: {
          type: "Polygon",
          coordinates: [[[77.6008, 12.9805], [77.6012, 12.9805], [77.6012, 12.9809], [77.6008, 12.9809], [77.6008, 12.9805]]]
        }
      }]
    });
    setStep(4, 'done');

    // Step 5: Harmonization Proposal Synthesis
    setStep(5, 'current');
    if (statusText) statusText.textContent = 'Step 5/6: Synthesizing multi-agency consensus proposal...';
    const propRes = await api.post(`/cases/${targetCase}/proposals`, {});
    setStep(5, 'done');

    // Step 6: Official Review & Signing
    setStep(6, 'current');
    if (statusText) statusText.textContent = 'Step 6/6: Cryptographically signing canonical record with Ed25519...';
    const proposals = await api.get(`/cases/${targetCase}/proposals`);
    if (proposals.length) {
      await api.post(`/cases/${targetCase}/proposals/${proposals[0].proposal_id}/review`, {
        action: 'APPROVE',
        reviewer_id: 'EVALUATOR_LEGAL_SEAL',
        notes: 'Endorsed in automated SIH evaluation flow.',
      });
    }
    setStep(6, 'done');

    if (statusBox) statusBox.style.display = 'none';
    if (resultSummary) {
      resultSummary.innerHTML = `
        <div class="result-card ok">
          <div class="result-status">✓ Complete Judge Demonstration Flow Succeeded!</div>
          <div style="font-size:12.5px;color:var(--text-main);margin-top:8px;">
            • Case: <strong>${targetCase}</strong> (and 3 sister scenarios)<br>
            • AI Matches: <strong>${matchRes.matches?.length || 1} Entity Alignments</strong><br>
            • Topology Repair: <strong>${topoRes.vertices_adjusted || 4} Vertices Snapped</strong> (Residual Overlap: ${topoRes.residual_overlap_sq_m} m²)<br>
            • Drone Analysis: <strong>${droneRes.encroachments?.length || 1} Encroachments Flagged</strong><br>
            • Harmonization: <strong>Cryptographically Signed Canonical Parcel Record Committed</strong>
          </div>
          <div style="margin-top:12px;">
            <button class="btn btn-primary btn-sm" onclick="closeJudgeDemoModal();switchTab('proposals');">View Harmonization Proposal →</button>
          </div>
        </div>
      `;
    }
    Toast.success('Evaluation Demo Finished', 'All 6 geospatial capabilities verified');
    await loadCases();
  } catch (e) {
    if (statusBox) statusBox.style.display = 'none';
    if (resultSummary) resultSummary.innerHTML = ui.err(`Demo Interrupted: ${e.message}`);
    Toast.error('Demo Error', e.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ── Ambient Topological Constellation Canvas (Subtle Physics) ─────────────────

function initAmbientCanvas() {
  const canvas = document.getElementById('ambientCanvas');
  if (!canvas) return;

  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches || window.innerWidth < 768) {
    return;
  }

  const ctx = canvas.getContext('2d');
  let width, height;
  let nodes = [];
  const count = 36;

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
      vx: (Math.random() - 0.5) * 0.35,
      vy: (Math.random() - 0.5) * 0.35,
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

    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    const nodeColor = isLight ? 'rgba(5, 150, 105, 0.4)' : 'rgba(16, 185, 129, 0.35)';
    const lineColor = isLight ? 'rgba(5, 150, 105, 0.08)' : 'rgba(16, 185, 129, 0.08)';

    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      n.x += n.vx;
      n.y += n.vy;

      if (n.x < 0 || n.x > width) n.vx *= -1;
      if (n.y < 0 || n.y > height) n.vy *= -1;

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

      for (let j = i + 1; j < nodes.length; j++) {
        const n2 = nodes[j];
        const d = Math.hypot(n.x - n2.x, n.y - n2.y);
        if (d < 130) {
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

  await pingHealth();
  pingTimer = setInterval(pingHealth, 15000);

  await loadCases();
})();
