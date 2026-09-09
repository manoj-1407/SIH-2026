/**
 * SIH26013 Geospatial Workstation — UI
 * Loosely coupled: each module (cases, ingest, provenance, analysis, evidence)
 * is independent. Leaflet map is lazy-initialized on first use.
 */

'use strict';

// ── Config ────────────────────────────────────────────────────────────────────

const cfg = {
  get base() {
    const el = document.getElementById('apiBase');
    return (el && el.value ? el.value : window.location.origin).replace(/\/$/, '');
  },
};

// ── State ─────────────────────────────────────────────────────────────────────

const state = {
  activeCaseId: null,
  records: [],
  provenanceNodes: [],
  leafletMap: null,
  mapLayers: {},
};

const RECORD_COLORS = ['#3b82f6','#10b981','#ef4444','#f59e0b','#8b5cf6','#06b6d4'];

// ── API ───────────────────────────────────────────────────────────────────────

const api = {
  async call(method, path, body) {
    const opts = { method };
    if (body) {
      opts.headers = { 'Content-Type': 'application/json' };
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(cfg.base + path, opts);
    if (!res.ok) {
      let detail = `HTTP ${res.status}`;
      try { detail = (await res.json()).detail || detail; } catch (_) {}
      throw new Error(detail);
    }
    return res.json();
  },
  get:  (path)       => api.call('GET',  path),
  post: (path, body) => api.call('POST', path, body),
};

// ── UI helpers ────────────────────────────────────────────────────────────────

const ui = {
  show(id)    { const el = document.getElementById(id); if (el) el.style.display = ''; },
  hide(id)    { const el = document.getElementById(id); if (el) el.style.display = 'none'; },
  html(id, h) { const el = document.getElementById(id); if (el) el.innerHTML = h; },
  text(id, t) { const el = document.getElementById(id); if (el) el.textContent = t; },
  val(id)     { const el = document.getElementById(id); return el ? el.value.trim() : ''; },

  esc(v) {
    return String(v ?? '').replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  },

  badge(label, type = 'neutral') {
    const cls = { ok:'badge-ok', warn:'badge-warn', err:'badge-err', neutral:'badge-neutral', geo:'badge-geo' };
    return `<span class="badge ${cls[type] || 'badge-neutral'}">${ui.esc(label)}</span>`;
  },

  kv(rows) {
    return `<div class="kv-grid">${rows.map(([k,v,mono]) =>
      `<div class="kv-row"><span class="kv-k">${ui.esc(k)}</span><span class="kv-v ${mono?'kv-mono':''}">${ui.esc(v)}</span></div>`
    ).join('')}</div>`;
  },

  classifyType(status) {
    const ok   = ['NO_CONFLICT','VERIFIED','VALID','INDEPENDENT','ESTABLISHED','DEFINITE_MATCH','APPROVED'];
    const warn = ['TEMPORALLY_QUALIFIED','UNKNOWN','NOT_INDEPENDENT','PARTIAL','UNVERIFIED','PROBABLE_MATCH','FIELD_INSPECTION_REQUIRED','PENDING_REVIEW'];
    const err  = ['GEOMETRIC_CONFLICT','FAILED','INVALID','REJECTED','CRS_ERROR','DATA_QUALITY_ISSUE','NO_MATCH'];
    if (ok.includes(status))   return 'ok';
    if (warn.includes(status)) return 'warn';
    if (err.includes(status))  return 'err';
    return 'neutral';
  },

  err(msg) { return `<div class="notice-box notice-red">${msg}</div>`; },
};

// ── Tab navigation ────────────────────────────────────────────────────────────

const tabNames = {
  cases: 'Cases',
  ingest: 'Ingest Records',
  aimatch: 'AI Parcel Matcher',
  topology: 'Cadastral Topology Repair',
  imagery: 'Drone ORI & Footprint Analysis',
  proposals: 'Authoritative Harmonization Proposals',
  provenance: 'Provenance Graph',
  analysis: 'Pairwise Analysis',
  evidence: 'Evidence Vault',
};

document.querySelectorAll('.sidenav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    const tab = btn.dataset.tab;
    document.querySelectorAll('.sidenav-item').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(`tab-${tab}`)?.classList.add('active');
    ui.text('topbarTabName', tabNames[tab] || tab);
    if (tab === 'analysis' && state.leafletMap) {
      setTimeout(() => state.leafletMap.invalidateSize(), 50);
    }
    if (tab === 'proposals' && state.activeCaseId) {
      loadProposals();
    }
  });
});

// ── Active case ───────────────────────────────────────────────────────────────

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

// ── Cases module ──────────────────────────────────────────────────────────────

function showNewCaseForm() { ui.show('newCaseForm'); }
function hideNewCaseForm() { ui.hide('newCaseForm'); }

async function createCase() {
  const caseId = ui.val('newCaseId') || null;
  const title  = ui.val('newCaseTitle') || 'Geospatial Analysis Case';
  try {
    const data = await api.post('/api/cases', { case_id: caseId, title });
    hideNewCaseForm();
    setActiveCase(data.case_id);
    loadCases();
  } catch (e) {
    ui.html('casesList', ui.err(e.message));
  }
}

async function loadCases() {
  try {
    const data = await api.get('/api/cases');
    const cases = data.cases || [];
    if (!cases.length) {
      ui.html('casesList', `<div class="empty-state">
        <div class="empty-icon">🗂</div>
        <div class="empty-title">No cases yet</div>
        <div class="empty-sub">Create a case or try a demo preset</div>
      </div>`);
      return;
    }
    ui.html('casesList', cases.map(c => `
      <div class="case-item" data-case-id="${ui.esc(c.case_id)}" onclick="setActiveCase('${ui.esc(c.case_id)}')">
        <div class="case-id">${ui.esc(c.case_id)}</div>
        <div class="case-meta">${ui.esc(c.title) || '—'}</div>
      </div>`).join(''));
  } catch (e) {
    ui.html('casesList', ui.err(`Could not load cases: ${e.message}`));
  }
}

// ── Ingest module ─────────────────────────────────────────────────────────────

async function ingestRecord() {
  if (!state.activeCaseId) { ui.html('ingestResult', ui.err('Select a case first.')); return; }
  const recordId = ui.val('recId');
  const source   = ui.val('recSource');
  const crs      = ui.val('recCrs') || 'EPSG:4326';
  const geomRaw  = ui.val('recGeometry');
  const ts       = ui.val('recTs') || null;

  if (!recordId || !geomRaw) { ui.html('ingestResult', ui.err('Record ID and geometry are required.')); return; }

  let geometry;
  try { geometry = JSON.parse(geomRaw); } catch (_) {
    ui.html('ingestResult', ui.err('Invalid GeoJSON geometry. Must be a valid JSON object.'));
    return;
  }

  ui.html('ingestResult', '<div style="color:var(--text3); font-size:12px; margin-top:8px;">Ingesting…</div>');
  try {
    const data = await api.post('/api/cases/' + state.activeCaseId + '/records', {
      record_id: recordId,
      geometry,
      source_crs: crs,
      source_label: source || recordId,
      capture_timestamp: ts,
    });
    state.records.push({ id: recordId, source, geometry });
    ui.text('acsRecords', `${state.records.length} record${state.records.length !== 1 ? 's' : ''}`);
    ui.html('ingestResult', `<div class="notice-box notice-geo" style="margin-top:8px;">
      Record <strong>${ui.esc(recordId)}</strong> ingested · Hash: <span style="font-family:var(--mono);font-size:11px;">${ui.esc((data.content_hash || '').slice(0, 24))}…</span>
    </div>`);
    renderRecordsList();
  } catch (e) {
    ui.html('ingestResult', ui.err(e.message));
  }
}

function renderRecordsList() {
  if (!state.records.length) { ui.html('recordsList', ''); return; }
  ui.html('recordsList', `<div class="form-card">
    <div class="form-section-title">Ingested records (${state.records.length})</div>
    ${state.records.map((r, i) => {
      const color = RECORD_COLORS[i % RECORD_COLORS.length];
      return `<div class="prov-node" style="border-left: 3px solid ${color};">
        <span style="font-weight:700; color:${color};">${ui.esc(r.id)}</span>
        <span style="color:var(--text3);">${ui.esc(r.source) || '—'}</span>
      </div>`;
    }).join('')}
  </div>`);
}

// ── Provenance module ─────────────────────────────────────────────────────────

async function addProvenanceNode() {
  if (!state.activeCaseId) { ui.html('nodeResult', ui.err('Select a case first.')); return; }
  const nodeId  = ui.val('nodeId');
  const type    = ui.val('nodeType');
  const parents = ui.val('nodeParents').split(',').map(s => s.trim()).filter(Boolean);

  if (!nodeId) { ui.html('nodeResult', ui.err('Node ID is required.')); return; }

  try {
    await api.post('/api/cases/' + state.activeCaseId + '/provenance/node', {
      node_id: nodeId,
      node_type: type,
      parent_ids: parents,
      metadata: {},
    });
    state.provenanceNodes.push({ id: nodeId, type, parents });
    ui.html('nodeResult', `<div class="notice-box notice-geo" style="margin-top:8px;">Node <strong>${ui.esc(nodeId)}</strong> (${ui.esc(type.toUpperCase())}) added.</div>`);
    renderProvenanceGraph();
  } catch (e) {
    ui.html('nodeResult', ui.err(e.message));
  }
}

function renderProvenanceGraph() {
  if (!state.provenanceNodes.length) return;
  const nodeHtml = state.provenanceNodes.map(n => `
    <div class="prov-node">
      <span class="prov-type ${ui.esc(n.type.toLowerCase())}">${ui.esc(n.type.toUpperCase())}</span>
      <span style="font-weight:600;">${ui.esc(n.id)}</span>
      ${n.parents.length ? `<span class="prov-arrow">←</span><span style="color:var(--text3);">${ui.esc(n.parents.join(', '))}</span>` : ''}
    </div>`).join('');
  ui.html('provenanceGraph', `<div class="form-card">
    <div class="form-section-title">Declared nodes (${state.provenanceNodes.length})</div>
    <div class="prov-node-list">${nodeHtml}</div>
    <p style="font-size:11.5px; color:var(--text3); margin-top:10px;">The engine traces these edges when computing independence — it does not rely on source names or metadata.</p>
  </div>`);
}

// ── Analysis module ───────────────────────────────────────────────────────────

async function runAnalysis() {
  if (!state.activeCaseId) { ui.html('analysisSummary', ui.err('Select a case first.')); return; }
  ui.html('analysisSummary', '<div style="color:var(--text3); font-size:12px;">Running analysis pipeline…</div>');
  ui.html('candidateResults', '');

  try {
    const data = await api.post('/api/cases/' + state.activeCaseId + '/analyze', {});

    // Summary stats
    const flagged = data.cases_flagged || 0;
    ui.html('analysisSummary', `
      <div class="stat-grid">
        <div class="stat-box"><div class="stat-num">${data.total_ingested || 0}</div><div class="stat-label">Total ingested</div></div>
        <div class="stat-box"><div class="stat-num" style="color:var(--red);">${data.rejected_at_ingestion?.length || 0}</div><div class="stat-label">Rejected</div></div>
        <div class="stat-box"><div class="stat-num">${data.valid_after_ingestion || 0}</div><div class="stat-label">Valid</div></div>
        <div class="stat-box"><div class="stat-num" style="color:var(--geo);">${data.candidate_pairs_examined || 0}</div><div class="stat-label">Candidate pairs</div></div>
        <div class="stat-box"><div class="stat-num" style="color:${flagged > 0 ? 'var(--red)' : 'var(--green)'};">${flagged}</div><div class="stat-label">Flagged</div></div>
      </div>
      <div class="bench-bar">
        <div class="bench-stat"><div class="bench-num">207,467×</div><div class="bench-label">Candidate reduction (100K)</div></div>
        <div class="bench-div"></div>
        <div class="bench-stat"><div class="bench-num">2,921/s</div><div class="bench-label">Ingestion rate (100K)</div></div>
        <div class="bench-div"></div>
        <div style="font-size:11.5px; color:var(--text3); max-width:180px;">Spatial index eliminates ~5B pairs — a correctness requirement, not just performance.</div>
      </div>`);

    // Try to render map from returned geometries
    renderMap(data);

    // Load individual comparison results
    const subCaseIds = data.signed_case_ids || [];
    if (subCaseIds.length) {
      ui.html('candidateResults', `<div style="font-size:12px; color:var(--text3); margin-bottom:8px;">Loading ${subCaseIds.length} comparison results…</div>`);
      const results = await Promise.all(subCaseIds.map(id =>
        api.get(`/api/evidence/${id}`).catch(e => ({ error: e.message, id }))
      ));
      renderCandidateResults(results, subCaseIds);
    }

  } catch (e) {
    ui.html('analysisSummary', ui.err(e.message));
  }
}

function renderCandidateResults(results, ids) {
  if (!results.length) { ui.html('candidateResults', ''); return; }
  ui.html('candidateResults', results.map((r, i) => {
    if (r.error) return `<div class="evidence-item"><div class="ev-id">${ui.esc(ids[i])}</div><div style="color:var(--red); font-size:12px;">${ui.esc(r.error)}</div></div>`;
    const ev = r.signed?.evidence || r.result || {};
    const decision = ev.decision || ev.geometry_result?.decision || '—';
    const indep = ev.provenance_assessment || ev.provenance || {};
    const pType = ui.classifyType(decision);
    return `<div class="evidence-item">
      <div class="ev-header">
        <div>
          <div class="ev-id">${ui.esc(ids[i])}</div>
          <div class="ev-decision" style="color:${pType==='err'?'var(--red)':pType==='warn'?'var(--amber)':'var(--green)'};">${ui.esc(decision)}</div>
        </div>
        <div style="display:flex; gap:6px; align-items:center;">
          ${indep.independence_status ? ui.badge(indep.independence_status, ui.classifyType(indep.independence_status)) : ''}
          ${indep.independent_lineages !== undefined ? `<span style="font-weight:800; font-size:16px; color:var(--text);">${ui.esc(indep.independent_lineages)}</span><span style="font-size:11px; color:var(--text3);">lineage${indep.independent_lineages!==1?'s':''}</span>` : ''}
        </div>
      </div>
      ${ev.geometry_result ? ui.kv([
        ['IoU difference', ev.geometry_result.iou_difference !== undefined ? `${ev.geometry_result.iou_difference.toFixed(6)} (0=identical)` : '—', false],
        ['Boundary displacement', ev.geometry_result.hausdorff_distance !== undefined ? `${ev.geometry_result.hausdorff_distance.toFixed(6)}°` : '—', false],
        ['Evidence hash', r.signed?.evidence_hash || '—', true],
      ]) : ''}
      <button class="btn btn-ghost btn-sm" style="margin-top:10px;" data-ev-id="${ui.esc(ids[i])}" onclick="prefillTamper(this.dataset.evId)">View in Evidence tab</button>
    </div>`;
  }).join(''));
}

// ── Map (lazy) ────────────────────────────────────────────────────────────────

function renderMap(data) {
  if (typeof L === 'undefined') { return; }

  const geometries = extractGeometries(data);
  if (!geometries || !geometries.length) { ui.hide('mapWrap'); return; }

  ui.show('mapWrap');

  if (!state.leafletMap) {
    state.leafletMap = L.map('leafletMap');
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '© OpenStreetMap contributors', maxZoom: 19,
    }).addTo(state.leafletMap);
  } else {
    Object.values(state.mapLayers).forEach(l => state.leafletMap.removeLayer(l));
    state.mapLayers = {};
  }

  const bounds = [];
  const legendItems = [];
  const filterBtns = [`<button class="btn btn-ghost btn-sm" onclick="filterMap('all',this)" style="font-size:11px;">All</button>`];

  geometries.forEach((g, i) => {
    const color = RECORD_COLORS[i % RECORD_COLORS.length];
    const layer = L.geoJSON({ type:'Feature', geometry: g.geojson }, {
      style: { color, weight: g.conflict ? 3 : 1.5, fillOpacity: g.conflict ? 0.2 : 0.08,
               fillColor: color, dashArray: g.conflict ? null : '4 4' },
    }).addTo(state.leafletMap);
    // g.label/g.id trace back to user-supplied record_id/source fields —
    // Leaflet's bindTooltip sets innerHTML from this string, so it must be
    // escaped or a crafted record_id/source executes in the browser.
    layer.bindTooltip(ui.esc(g.label), { sticky: true });
    state.mapLayers[g.id] = layer;
    try { const b = layer.getBounds(); if (b.isValid()) bounds.push(b); } catch (_) {}
    legendItems.push(`<div class="map-legend-item"><div class="map-swatch" style="background:${color};border-color:${color};"></div>${ui.esc(g.label)}</div>`);
    filterBtns.push(`<button class="btn btn-ghost btn-sm" data-layer-id="${ui.esc(g.id)}" onclick="filterMap(this.dataset.layerId,this)" style="font-size:11px;">${ui.esc(g.label)}</button>`);
  });

  if (bounds.length) {
    try { state.leafletMap.fitBounds(bounds.reduce((a, b) => a.extend(b)), { padding: [20, 20] }); }
    catch (_) { state.leafletMap.setView([20.5937, 78.9629], 5); }
  } else {
    state.leafletMap.setView([20.5937, 78.9629], 5);
  }

  ui.html('mapLegend', legendItems.join(''));
  ui.html('mapFilterBtns', filterBtns.join(''));
}

function filterMap(which, btn) {
  document.querySelectorAll('#mapFilterBtns button').forEach(b => b.classList.remove('btn-primary'));
  btn?.classList.add('btn-primary');
  if (!state.leafletMap) return;
  Object.entries(state.mapLayers).forEach(([id, layer]) => {
    const show = which === 'all' || which === id;
    if (show && !state.leafletMap.hasLayer(layer)) state.leafletMap.addLayer(layer);
    if (!show && state.leafletMap.hasLayer(layer)) state.leafletMap.removeLayer(layer);
  });
}

function extractGeometries(data) {
  // Handle different possible API response shapes
  const candidates = [
    data.record_geometries,
    data.geometries,
    data.records?.filter?.(r => r.geometry),
  ].filter(Boolean);

  for (const arr of candidates) {
    if (!Array.isArray(arr) || !arr.length) continue;
    const mapped = arr.map((g, i) => ({
      id:       g.record_id || g.id || String(i),
      label:    g.source_label || g.label || g.record_id || `Record ${i+1}`,
      geojson:  g.geometry || g,
      conflict: g.conflict || g.has_conflict || false,
    })).filter(g => g.geojson?.type);
    if (mapped.length) return mapped;
  }
  return null;
}

// ── Evidence module ───────────────────────────────────────────────────────────

async function loadEvidence() {
  if (!state.activeCaseId) return;
  try {
    const data = await api.get(`/api/cases/${state.activeCaseId}/evidence`);
    const pkgs = data.evidence || data.packages || [];
    if (!pkgs.length) {
      ui.html('evidenceList', `<div class="empty-state">
        <div class="empty-icon">🔐</div>
        <div class="empty-title">No evidence yet</div>
        <div class="empty-sub">Run analysis to generate signed evidence packages</div>
      </div>`);
      return;
    }
    ui.html('evidenceList', pkgs.map(pkg => {
      const decision = pkg.decision || '—';
      const indep = pkg.provenance_assessment || {};
      const valid = pkg.verification?.valid;
      const badgeType = valid === true ? 'ok' : valid === false ? 'err' : 'neutral';
      return `<div class="evidence-item">
        <div class="ev-header">
          <div>
            <div class="ev-id">${pkg.evidence_id || pkg.comparison_id || '—'}</div>
            <div class="ev-decision">${decision}</div>
          </div>
          ${ui.badge(valid === true ? 'VALID' : valid === false ? 'INVALID' : '—', badgeType)}
        </div>
        ${ui.kv([
          ['Independence', indep.independence_status || '—', false],
          ['Lineages', indep.independent_lineages !== undefined ? String(indep.independent_lineages) : '—', false],
          ['Evidence hash', pkg.evidence_hash || '—', true],
          ['Key ID', pkg.key_id || '—', true],
        ])}
        <button class="btn btn-ghost btn-sm" style="margin-top:10px;"
          onclick="prefillTamper('${pkg.evidence_id || pkg.comparison_id}')">Tamper demo</button>
      </div>`;
    }).join(''));
    ui.show('tamperSection');
  } catch (e) {
    ui.html('evidenceList', ui.err(e.message));
  }
}

function prefillTamper(evidenceId) {
  document.getElementById('tamperEvidenceId').value = evidenceId;
  document.getElementById('tamperSection').scrollIntoView({ behavior:'smooth' });
  // Switch to evidence tab
  document.querySelector('[data-tab="evidence"]')?.click();
}

function setTamperPreset(field, value) {
  document.getElementById('tamperField').value = field;
  document.getElementById('tamperValue').value = value;
  ui.html('tamperResult', '');
}

async function runTamper() {
  const evidenceId = ui.val('tamperEvidenceId');
  const field      = ui.val('tamperField');
  const value      = ui.val('tamperValue');
  if (!evidenceId || !field) return;
  try {
    const data = await api.post(`/api/evidence/${evidenceId}/tamper-demo`, {
      field_path: field, new_value: value,
    });
    const valid = data.verification?.valid;
    const type  = valid ? 'ok' : 'err';
    const label = valid ? '✓ Verification still passes' : '✗ Verification FAILED — tamper detected';
    ui.html('tamperResult', `
      <div class="result-card ${type}" style="margin-top:12px;">
        <div class="result-status" style="font-size:15px;">${label}</div>
        <div style="font-family:var(--mono); font-size:11px; margin-top:8px; color:var(--text2);">
          ${field}: ${JSON.stringify(data.original_value)} → ${JSON.stringify(data.tampered_value)}<br>
          ${data.verification?.reason || ''}
        </div>
      </div>`);
  } catch (e) {
    ui.html('tamperResult', ui.err(e.message));
  }
}

// ── Preset loader ─────────────────────────────────────────────────────────────

const PRESETS = {
  1: {
    title: 'Parcel PS-2201 — 3 Records / 1 Origin',
    records: [
      { id:'REC-A', source:'Revenue DB',    geometry:{type:'Polygon',coordinates:[[[78.9,20.5],[78.92,20.5],[78.92,20.518],[78.9,20.518],[78.9,20.5]]]} },
      { id:'REC-B', source:'GIS Export',    geometry:{type:'Polygon',coordinates:[[[78.901,20.5005],[78.921,20.5005],[78.921,20.5185],[78.901,20.5185],[78.901,20.5005]]]} },
      { id:'REC-C', source:'Archive Copy',  geometry:{type:'Polygon',coordinates:[[[78.898,20.498],[78.916,20.498],[78.916,20.521],[78.91,20.525],[78.898,20.521],[78.898,20.498]]]} },
    ],
    nodes: [
      { id:'survey_2021', type:'origin',  parents:[] },
      { id:'revenue_db',  type:'dataset', parents:['survey_2021'] },
      { id:'gis_export',  type:'transformation', parents:['survey_2021'] },
      { id:'archive',     type:'dataset', parents:['survey_2021'] },
      { id:'REC-A',       type:'record',  parents:['revenue_db'] },
      { id:'REC-B',       type:'record',  parents:['gis_export'] },
      { id:'REC-C',       type:'record',  parents:['archive'] },
    ],
  },
  2: {
    title: 'Parcel TG-0512 — Temporal Gap',
    records: [
      { id:'REC-2015', source:'2015 Survey', capture_timestamp:'2015-06-01T00:00:00Z',
        geometry:{type:'Polygon',coordinates:[[[79.1,18.9],[79.12,18.9],[79.12,18.918],[79.1,18.918],[79.1,18.9]]]} },
      { id:'REC-2025', source:'2025 Resurvey', capture_timestamp:'2025-03-15T00:00:00Z',
        geometry:{type:'Polygon',coordinates:[[[79.1,18.9],[79.124,18.9],[79.124,18.922],[79.1,18.922],[79.1,18.9]]]} },
    ],
    nodes: [
      { id:'survey_2015', type:'origin', parents:[] },
      { id:'survey_2025', type:'origin', parents:[] },
      { id:'REC-2015',    type:'record', parents:['survey_2015'] },
      { id:'REC-2025',    type:'record', parents:['survey_2025'] },
    ],
  },
  3: {
    title: 'Parcel KA-0771 — Missing Lineage (UNKNOWN)',
    records: [
      { id:'REC-X', source:'Source X', geometry:{type:'Polygon',coordinates:[[[77.5,12.9],[77.52,12.9],[77.52,12.918],[77.5,12.918],[77.5,12.9]]]} },
      { id:'REC-Y', source:'Source Y', geometry:{type:'Polygon',coordinates:[[[77.5,12.9],[77.523,12.9],[77.523,12.921],[77.5,12.921],[77.5,12.9]]]} },
    ],
    nodes: [],  // Deliberately no provenance → UNKNOWN
  },
};

async function loadPreset(num) {
  const preset = PRESETS[num];
  if (!preset) return;

  try {
    // Create case
    const caseData = await api.post('/api/cases', { title: preset.title });
    const caseId = caseData.case_id;
    setActiveCase(caseId);
    loadCases();

    // Ingest records
    for (const rec of preset.records) {
      await api.post(`/api/cases/${caseId}/records`, {
        record_id: rec.id, geometry: rec.geometry,
        source_label: rec.source, source_crs: 'EPSG:4326',
        capture_timestamp: rec.capture_timestamp || null,
      }).catch(() => {});
      state.records.push(rec);
    }
    ui.text('acsRecords', `${preset.records.length} records`);

    // Add provenance nodes
    for (const node of preset.nodes) {
      await api.post(`/api/cases/${caseId}/provenance/node`, {
        node_id: node.id, node_type: node.type,
        parent_ids: node.parents, metadata: {},
      }).catch(() => {});
      state.provenanceNodes.push(node);
    }

    // Switch to analysis and run
    document.querySelector('[data-tab="analysis"]')?.click();
    setTimeout(runAnalysis, 200);
  } catch (e) {
    alert(`Preset load failed: ${e.message}`);
  }
}

// ── Track A AI & Harmonization Workflows ──────────────────────────────────────

async function seedDemoCases() {
  try {
    const data = await api.post('/api/demo/seed-samples', {});
    await loadCases();
    switchCase('DEMO-ALIGN');
    alert(`Success: ${data.message} Active case switched to DEMO-ALIGN.`);
  } catch (e) {
    alert(`Failed to seed demo cases: ${e.message}`);
  }
}

async function switchCase(caseId) {
  setActiveCase(caseId);
  try {
    const c = await api.get(`/api/cases/${caseId}`);
    ui.text('acsRecords', `${c.records_count || 0} records`);
  } catch (_) {}
}

async function runAIMatch() {
  if (!state.activeCaseId) {
    alert('Please select or create an active case first');
    return;
  }
  ui.html('aimatchResults', '<div style="color:var(--text3);font-size:12px;">Running AI multi-factor parcel matching engine…</div>');
  try {
    const data = await api.post(`/api/cases/${state.activeCaseId}/match-ai`, { min_probability: 0.20 });
    const matches = data.matches || [];
    if (!matches.length) {
      ui.html('aimatchResults', '<div class="empty-state"><div class="empty-icon">🔍</div><div class="empty-title">No candidate matches found</div><div class="empty-sub">Ensure case has at least 2 records with spatial coordinates</div></div>');
      return;
    }

    const cards = matches.map(m => {
      const cls = ui.classifyType(m.classification);
      const pct = Math.round(m.match_probability * 100);
      const feat = m.features || {};
      return `
        <div class="result-card ${cls}" style="margin-bottom:12px;">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <div class="result-status">Match: ${ui.esc(m.source_parcel_id)} ↔ ${ui.esc(m.target_parcel_id)}</div>
            <div style="display:flex;gap:8px;align-items:center;">
              <span style="font-size:15px;font-weight:700;">${pct}%</span>
              ${ui.badge(m.classification, cls)}
            </div>
          </div>
          <div class="result-reason" style="margin-top:6px;">${ui.esc(m.explanation)}</div>
          <div style="margin-top:10px;display:grid;grid-template-columns:repeat(auto-fit, minmax(130px, 1fr));gap:8px;font-size:11.5px;background:var(--surface2);padding:8px;border-radius:6px;">
            <div><strong>Boundary IoU:</strong> ${feat.iou ?? '—'}</div>
            <div><strong>Centroid Δ:</strong> ${feat.centroid_dist_m ?? '—'} m</div>
            <div><strong>Hausdorff:</strong> ${feat.hausdorff_m ?? '—'} m</div>
            <div><strong>Survey Token Sim:</strong> ${Math.round((feat.survey_sim || 0)*100)}%</div>
            <div><strong>Area Ratio:</strong> ${Math.round((feat.area_ratio || 0)*100)}%</div>
            <div><strong>Land-Use Match:</strong> ${feat.land_use_concordance >= 0.8 ? 'Concordant' : 'Divergent'}</div>
          </div>
          ${m.spatial_conflict ? '<div style="color:var(--amber);font-size:12px;margin-top:8px;">⚠️ Spatial Conflict Flagged: High survey identity match but diverging boundary alignment.</div>' : ''}
        </div>
      `;
    }).join('');

    ui.html('aimatchResults', `
      <div style="margin-bottom:10px;font-weight:600;">Candidate Parcel Pairs Analyzed: ${matches.length}</div>
      ${cards}
    `);
  } catch (e) {
    ui.html('aimatchResults', ui.err(e.message));
  }
}

async function runAttributeHarmonize() {
  if (!state.activeCaseId) {
    alert('Please select an active case first');
    return;
  }
  ui.html('attributeHarmonizeResults', '<div style="color:var(--text3);font-size:12px;">Evaluating cross-agency attribute discrepancies…</div>');
  try {
    const data = await api.post(`/api/cases/${state.activeCaseId}/attribute-harmonize`, {});
    const reps = data.discrepancy_reports || [];
    if (!reps.length) {
      ui.html('attributeHarmonizeResults', '<div class="notice-box notice-blue">No attribute discrepancies observed.</div>');
      return;
    }
    const html = reps.map(r => `
      <div class="notice-box ${r.severity === 'CRITICAL' ? 'notice-red' : r.severity === 'WARNING' ? 'notice-amber' : 'notice-blue'}" style="margin-bottom:10px;">
        <div style="display:flex;justify-content:space-between;">
          <strong>Discrepancy Severity: ${ui.esc(r.severity)}</strong>
          <span>Area Δ: ${r.area_delta_sq_m} m² (${r.area_delta_pct}%)</span>
        </div>
        <ul style="margin:6px 0 6px 18px;font-size:12.5px;">
          ${r.discrepancies.map(d => `<li>${ui.esc(d)}</li>`).join('')}
        </ul>
        <div style="font-size:12px;margin-top:4px;"><strong>Statutory Recommendation:</strong> ${ui.esc(r.suggested_resolution)}</div>
      </div>
    `).join('');
    ui.html('attributeHarmonizeResults', html);
  } catch (e) {
    ui.html('attributeHarmonizeResults', ui.err(e.message));
  }
}

async function runTopologyRepair() {
  if (!state.activeCaseId) {
    alert('Please select or create an active case first');
    return;
  }
  const tol = parseFloat(ui.val('snapTol') || '1.0');
  ui.html('topologyResults', '<div style="color:var(--text3);font-size:12px;">Snapping shared edges and trimming overlapping cadastral boundaries…</div>');
  try {
    const data = await api.post(`/api/cases/${state.activeCaseId}/topology-repair`, { snap_tolerance_m: tol });
    const anoms = data.anomalies_detected || [];
    ui.html('topologyResults', `
      <div class="result-card ok" style="margin-bottom:14px;">
        <div class="result-status">Topology Repair Completed</div>
        <div class="result-reason">${ui.esc(data.repair_summary)}</div>
        <div style="display:flex;gap:16px;margin-top:10px;font-size:12.5px;">
          <div><strong>Initial Overlap:</strong> <span style="color:var(--red);">${data.initial_overlap_sq_m} m²</span></div>
          <div><strong>Residual Overlap:</strong> <span style="color:var(--green);">${data.residual_overlap_sq_m} m²</span></div>
          <div><strong>Vertices Snapped:</strong> ${data.vertices_adjusted}</div>
        </div>
      </div>
      ${anoms.length ? `
        <div style="font-weight:600;margin-bottom:8px;">Detected Conflict Zones:</div>
        ${anoms.map(a => `
          <div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:10px;margin-bottom:8px;font-size:12.5px;">
            <div style="display:flex;justify-content:space-between;">
              <span><strong>${ui.esc(a.anomaly_type)}</strong> · ${ui.esc(a.parcels_involved.join(' ↔ '))}</span>
              <span class="badge ${a.severity === 'HIGH' ? 'badge-err' : 'badge-warn'}">${a.area_sq_m} m²</span>
            </div>
            <div style="color:var(--text2);margin-top:4px;">${ui.esc(a.description)}</div>
          </div>
        `).join('')}
      ` : ''}
    `);
  } catch (e) {
    ui.html('topologyResults', ui.err(e.message));
  }
}

async function runDroneAnalysis() {
  if (!state.activeCaseId) {
    alert('Please select an active case first');
    return;
  }
  ui.html('imageryResults', '<div style="color:var(--text3);font-size:12px;">Processing photogrammetric building footprints against parcel boundaries…</div>');
  try {
    const data = await api.post(`/api/cases/${state.activeCaseId}/imagery-analysis`, {
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
        <div class="result-status">Photogrammetric Coverage &amp; Encroachment Analysis</div>
        <div class="result-reason">${ui.esc(data.summary)}</div>
        <div style="display:flex;gap:16px;margin-top:10px;font-size:12.5px;">
          <div><strong>Total Built Area:</strong> ${data.total_built_up_area_sq_m} m²</div>
          <div><strong>Coverage Ratio (FSI):</strong> ${(data.coverage_ratio * 100).toFixed(1)}%</div>
          <div><strong>Building Count:</strong> ${data.building_count}</div>
        </div>
      </div>
      ${encr.length ? `
        <div style="font-weight:600;margin-bottom:8px;color:var(--red);">Boundary Encroachment Violations:</div>
        ${encr.map(e => `
          <div style="background:var(--surface);border:1px solid var(--border);border-left:4px solid var(--red);border-radius:6px;padding:12px;margin-bottom:8px;font-size:12.5px;">
            <div style="display:flex;justify-content:space-between;">
              <span><strong>Building ${ui.esc(e.footprint_id)}</strong></span>
              <span class="badge badge-err">${e.severity} · ${e.encroached_area_sq_m} m²</span>
            </div>
            <div style="margin-top:6px;color:var(--text);">${ui.esc(e.description)}</div>
          </div>
        `).join('')}
      ` : ''}
    `);
  } catch (e) {
    ui.html('imageryResults', ui.err(e.message));
  }
}

async function generateHarmonizationProposal() {
  if (!state.activeCaseId) {
    alert('Please select or create an active case first');
    return;
  }
  ui.html('proposalsList', '<div style="color:var(--text3);font-size:12px;">Synthesizing inputs into authoritative harmonization proposal…</div>');
  try {
    await api.post(`/api/cases/${state.activeCaseId}/proposals`, {});
    await loadProposals();
  } catch (e) {
    ui.html('proposalsList', ui.err(e.message));
  }
}

async function loadProposals() {
  if (!state.activeCaseId) return;
  try {
    const proposals = await api.get(`/api/cases/${state.activeCaseId}/proposals`);
    if (!proposals.length) {
      ui.html('proposalsList', '<div class="empty-state"><div class="empty-icon">📜</div><div class="empty-title">No proposals generated yet</div><div class="empty-sub">Click "+ Generate New Proposal" to reconcile claims for this case.</div></div>');
      return;
    }

    const cards = proposals.map(p => {
      const isApproved = p.status === 'APPROVED';
      const badgeCls = isApproved ? 'badge-ok' : p.status === 'REJECTED' ? 'badge-err' : 'badge-warn';
      const env = p.signed_evidence_envelope;

      return `
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;margin-bottom:16px;">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <div>
              <div style="font-weight:700;font-size:14px;">Proposal ${ui.esc(p.proposal_id)}</div>
              <div style="font-size:12px;color:var(--text2);">Survey Target: <strong>${ui.esc(p.target_survey_number)}</strong> · Confidence: ${(p.confidence_score*100).toFixed(0)}%</div>
            </div>
            <span class="badge ${badgeCls}">${ui.esc(p.status)}</span>
          </div>

          <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(160px, 1fr));gap:10px;margin:12px 0;padding:10px;background:var(--surface2);border-radius:6px;font-size:12.5px;">
            <div><strong>Harmonized Area:</strong> ${p.recommended_area_sq_m.toLocaleString()} m²</div>
            <div><strong>Recommended Use:</strong> ${ui.esc(p.recommended_land_use)}</div>
            <div><strong>Title Holder:</strong> ${ui.esc(p.recommended_owner_ref)}</div>
            <div><strong>Reconciled Sources:</strong> ${p.source_parcel_ids?.length || 0} agencies</div>
          </div>

          ${env ? `
            <div style="background:var(--surface);border:1px solid var(--border);border-left:4px solid var(--green);padding:10px;border-radius:4px;margin-top:10px;font-size:12px;">
              <div style="color:var(--green);font-weight:700;">✓ Cryptographically Signed Harmonization Record (Ed25519)</div>
              <div style="font-family:var(--mono);margin-top:4px;color:var(--text2);word-break:break-all;">
                Evidence ID: <strong>${ui.esc(env.evidence_id)}</strong><br>
                SHA-256 Hash: ${ui.esc(env.evidence_hash)}
              </div>
            </div>
          ` : `
            <div style="display:flex;gap:8px;margin-top:12px;">
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
  const notes = prompt('Enter review endorsement or order remarks:', 'Approved following inter-agency boundary reconciliation.');

  try {
    await api.post(`/api/cases/${state.activeCaseId}/proposals/${proposalId}/review`, {
      action,
      reviewer_id: reviewer,
      notes: notes || '',
    });
    await loadProposals();
  } catch (e) {
    alert(`Review failed: ${e.message}`);
  }
}

// ── Init ──────────────────────────────────────────────────────────────────────

(async function init() {
  loadCases();
  // Wire evidence tab to load on activation
  document.querySelector('[data-tab="evidence"]')?.addEventListener('click', loadEvidence);
})();
