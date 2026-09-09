/**
 * SIH26149 Forensic Workstation — UI
 * Loosely coupled: each module (cases, forensics, sanitization, vault, verifier)
 * is independent. State is minimal and explicit. No global DOM soup.
 */

'use strict';

// ── Config ────────────────────────────────────────────────────────────────────

const cfg = {
  get base() { return document.getElementById('apiBase').value.replace(/\/$/, ''); },
};

// ── Minimal state ─────────────────────────────────────────────────────────────

const state = {
  activeCaseId: null,
  uploadedImagePath: null,
  selectedInode: null,
  demoMode: false,
};

// ── API client ────────────────────────────────────────────────────────────────

const api = {
  async call(method, path, body, isForm = false) {
    const opts = { method };
    if (isForm) {
      opts.body = body;
    } else if (body) {
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
  get:    (path)        => api.call('GET',    path),
  post:   (path, body)  => api.call('POST',   path, body),
  upload: (path, form)  => api.call('POST',   path, form, true),
};

// ── UI helpers ────────────────────────────────────────────────────────────────

const ui = {
  show(id)   { const el = document.getElementById(id); if (el) el.style.display = ''; },
  hide(id)   { const el = document.getElementById(id); if (el) el.style.display = 'none'; },
  html(id, h){ const el = document.getElementById(id); if (el) el.innerHTML = h; },
  text(id, t){ const el = document.getElementById(id); if (el) el.textContent = t; },
  val(id)    { const el = document.getElementById(id); return el ? el.value.trim() : ''; },
  setBtn(id, disabled) { const b = document.getElementById(id); if (b) b.disabled = disabled; },

  // Escapes a value for safe insertion into innerHTML. Case titles, uploaded
  // filenames, and (critically) filenames recovered from a forensic image
  // are all attacker-controlled — a suspect's disk image is untrusted input
  // by definition — so anything derived from them must be escaped before
  // it reaches the DOM. Without this, a deleted file named e.g.
  // `<img src=x onerror=alert(1)>` on the analyzed image would execute
  // in the investigator's browser.
  esc(v) {
    return String(v ?? '').replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  },

  badge(label, type = 'neutral') {
    const cls = { ok: 'badge-ok', warn: 'badge-warn', err: 'badge-err', neutral: 'badge-neutral' };
    return `<span class="badge ${cls[type] || 'badge-neutral'}">${ui.esc(label)}</span>`;
  },

  // reason/scope may echo back client-supplied request fields (e.g. a
  // forensic operation's artifact_name) inside server explanation text, so
  // these are escaped by default rather than trusted as server-only.
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
    const ok   = ['VERIFIED', 'VALID', 'SUPPORTED', 'ACTIVE'];
    const warn = ['VERIFIED_WITHIN_SCOPE', 'UNVERIFIED', 'PARTIAL'];
    const err  = ['FAILED', 'REJECTED', 'INVALID', 'UNSUPPORTED', 'NOT_A_FILESYSTEM'];
    if (ok.includes(status))   return 'ok';
    if (warn.includes(status)) return 'warn';
    if (err.includes(status))  return 'err';
    return 'neutral';
  },

  stepOn(id)  { const el = document.getElementById(id); if (el) el.classList.remove('dim'); },
  stepDim(id) { const el = document.getElementById(id); if (el) el.classList.add('dim'); },

  err(msg) { return `<div class="notice-box notice-red">${msg}</div>`; },
};

// ── Tab navigation (decoupled from business logic) ────────────────────────────

const tabNames = {
  cases:        'Cases & Timeline',
  forensics:    'Forensic Recovery',
  carving:      'Advanced File Carving',
  sanitization: 'Data Sanitization & Selective Eraser',
  auditchain:   'Cryptographic Audit Chain',
  vault:        'Evidence Vault',
  verification: 'Independent Verifier',
};

document.querySelectorAll('.sidenav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    const tab = btn.dataset.tab;
    document.querySelectorAll('.sidenav-item').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(`tab-${tab}`)?.classList.add('active');
    ui.text('topbarTabName', tabNames[tab] || tab);
    if (tab === 'auditchain' && state.activeCaseId) loadAuditChain();
  });
});

function refreshCurrentView() {
  const active = document.querySelector('.sidenav-item.active');
  if (active?.dataset.tab === 'cases') loadCases();
  if (active?.dataset.tab === 'vault' && state.activeCaseId) loadVault();
  if (active?.dataset.tab === 'auditchain' && state.activeCaseId) loadAuditChain();
}

// ── Active case tracking ───────────────────────────────────────────────────────

function setActiveCase(caseId) {
  state.activeCaseId = caseId;
  ui.text('topbarCase', caseId);
  ui.text('acsCaseId', caseId);
  ui.show('activeCaseStrip');
  document.querySelectorAll('.case-item').forEach(el => {
    el.classList.toggle('active-case', el.dataset.caseId === caseId);
  });
}

// ── Cases module ──────────────────────────────────────────────────────────────

function showNewCaseForm() { ui.show('newCaseForm'); }
function hideNewCaseForm() { ui.hide('newCaseForm'); }

async function createCase() {
  const name = ui.val('newCaseName');
  if (!name) return;
  try {
    const data = await api.post('/api/cases', { name });
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
        <div class="empty-icon">📁</div>
        <div class="empty-title">No cases yet</div>
        <div class="empty-sub">Create your first investigation case</div>
      </div>`);
      return;
    }
    ui.html('casesList', cases.map(c => `
      <div class="case-item" data-case-id="${ui.esc(c.case_id)}" onclick="setActiveCase('${ui.esc(c.case_id)}')">
        <div>
          <div class="case-id">${ui.esc(c.case_id)}</div>
          <div class="case-meta">${ui.esc(c.name) || '—'} · Created ${new Date(c.created_at * 1000).toLocaleString()}</div>
        </div>
        <div class="case-actions">
          ${ui.badge(c.status || 'open', 'neutral')}
        </div>
      </div>`).join(''));
  } catch (e) {
    ui.html('casesList', ui.err(`Could not load cases: ${e.message}`));
  }
}

// ── Forensics module ──────────────────────────────────────────────────────────

function onImageSelect() {
  const file = document.getElementById('imageUpload').files[0];
  if (!file) return;
  ui.text('uploadHint', `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`);
  ui.setBtn('btnDetectFs', false);
}

async function detectFilesystem() {
  if (!state.activeCaseId) { alert('Select a case first.'); return; }
  const file = document.getElementById('imageUpload').files[0];
  if (!file) return;
  ui.html('fsResult', '<div style="color:var(--text3); font-size:12px;">Detecting filesystem…</div>');
  try {
    const form = new FormData();
    form.append('file', file);
    const data = await api.upload(`/api/cases/${encodeURIComponent(state.activeCaseId)}/upload`, form);
    state.uploadedImagePath = data.image_path;
    const fs = data.filesystem;
    const type = fs.support_status === 'SUPPORTED' ? 'ok' : 'err';
    ui.html('fsResult', `
      <div class="result-card ${type}" style="margin-top:12px;">
        <div class="result-status">${fs.filesystem} — ${fs.support_status}</div>
        <div class="result-reason">${fs.detail || ''}</div>
      </div>`);
    if (fs.support_status === 'SUPPORTED') {
      ui.stepOn('step-discover');
      ui.setBtn('btnDiscover', false);
    }
  } catch (e) {
    ui.html('fsResult', ui.err(e.message));
  }
}

async function discoverDeleted() {
  if (!state.activeCaseId) return;
  ui.html('deletedList', '<div style="color:var(--text3); font-size:12px; margin-top:10px;">Scanning inodes…</div>');
  try {
    const data = await api.get(`/api/cases/${encodeURIComponent(state.activeCaseId)}/artifacts`);
    const files = data.deleted_files || [];
    if (!files.length) {
      ui.html('deletedList', '<div style="color:var(--text3); font-size:12px; margin-top:10px;">No deleted inodes found.</div>');
      return;
    }
    ui.html('deletedList', `<div style="margin-top:12px; display:flex; flex-wrap:wrap; gap:8px;">
      ${files.map((f, i) => `
        <button class="btn btn-ghost btn-sm" style="font-family:var(--mono);"
          data-inode="${ui.esc(f.inode)}" data-filename="${ui.esc(f.filename || '')}"
          onclick="selectInodeFromBtn(this)">
          ${ui.esc(f.inode)}${f.filename ? ' · ' + ui.esc(f.filename) : ''}
        </button>`).join('')}
    </div>`);
    ui.stepOn('step-recover');
  } catch (e) {
    ui.html('deletedList', ui.err(e.message));
  }
}

function selectInodeFromBtn(btn) {
  selectInode(btn.dataset.inode, btn.dataset.filename, btn);
}

function selectInode(inode, filename, btnEl) {
  state.selectedInode = inode;
  document.querySelectorAll('#deletedList button').forEach(b => b.classList.remove('btn-primary'));
  (btnEl || event.target).classList.add('btn-primary');
  ui.setBtn('btnRecover', false);
}

async function runRecovery() {
  if (!state.selectedInode || !state.activeCaseId) return;
  ui.html('recoveryResult', '<div style="color:var(--text3); font-size:12px; margin-top:10px;">Running recovery…</div>');
  try {
    const refHash = ui.val('refHash') || null;
    const data = await api.post(`/api/cases/${encodeURIComponent(state.activeCaseId)}/forensic`, {
      inode: String(state.selectedInode),
      reference_hash: refHash,
    });
    const o = data.outcome;
    const type = ui.classifyType(o.classification);
    const scope = o.scope_limitation ? `Scope: ${o.scope_limitation}` : '';
    ui.html('recoveryResult', `
      ${ui.resultCard(o.classification, o.reason || '', type, scope)}
      ${ui.kvGrid([
        ['Image SHA-256', data.image_hash || '—', true],
        ['Recovered SHA-256', o.recovered_hash || '—', true],
        ['Reference SHA-256', o.reference_hash || 'not provided', true],
        ['Hash match', o.hash_match !== undefined ? String(o.hash_match) : '—', false],
        ['Evidence ID', data.evidence_id || '—', true],
      ])}
      <div style="margin-top:10px; font-size:12px; color:var(--text3);">
        Evidence signed and stored in vault. View in Evidence Vault tab.
      </div>`);
  } catch (e) {
    ui.html('recoveryResult', ui.err(e.message));
  }
}

// ── Sanitization module ───────────────────────────────────────────────────────

async function runSanitization() {
  if (!state.activeCaseId) { alert('Select a case first.'); return; }
  const opId   = ui.val('opId');
  const opName = ui.val('opName');
  const reason = ui.val('opReason');
  const inode  = ui.val('sanInode');
  const ack    = document.getElementById('scopeAck')?.checked;

  if (!opId || !opName || !reason || !inode) {
    ui.html('sanitizationResult', ui.err('All fields are required.'));
    return;
  }
  if (!ack) {
    ui.html('sanitizationResult', ui.err('You must acknowledge the scope limitation.'));
    return;
  }

  ui.html('sanitizationResult', '<div style="color:var(--text3); font-size:12px; margin-top:10px;">Running sanitization…</div>');
  try {
    const data = await api.post(`/api/cases/${encodeURIComponent(state.activeCaseId)}/sanitize`, {
      operator_id: opId,
      operator_name: opName,
      authorization_reason: reason,
      confirmed_scope_acknowledgement: true,
    });
    const o = data.outcome;
    const type = ui.classifyType(o.classification);
    ui.html('sanitizationResult', `
      ${ui.resultCard(o.classification, o.reason || '', type,
        o.scope_limitation ? `Scope: ${o.scope_limitation}` : '')}
      ${ui.kvGrid([
        ['Authorized by', `${opName} (${opId})`, false],
        ['Method', data.method || 'ZERO_FILL', false],
        ['Evidence ID', data.evidence_id || '—', true],
      ])}`);
  } catch (e) {
    ui.html('sanitizationResult', ui.err(e.message));
  }
}

// ── Evidence Vault module ─────────────────────────────────────────────────────

async function loadVault() {
  const caseId = ui.val('vaultCaseId') || state.activeCaseId;
  if (!caseId) return;
  ui.html('vaultList', '<div style="color:var(--text3); font-size:12px;">Loading evidence…</div>');
  try {
    const data = await api.get(`/api/evidence?case_id=${encodeURIComponent(caseId)}`);
    const packages = data.evidence || [];
    if (!packages.length) {
      ui.html('vaultList', '<div class="empty-state"><div class="empty-icon">🔐</div><div class="empty-title">No evidence yet</div></div>');
      return;
    }
    ui.html('vaultList', packages.map(pkg => {
      const valid = pkg.verification?.valid;
      const badgeType = valid === true ? 'ok' : valid === false ? 'err' : 'neutral';
      const badgeLabel = valid === true ? 'VALID' : valid === false ? 'INVALID' : 'UNVERIFIED';
      return `<div class="evidence-item">
        <div class="ev-header">
          <div>
            <div class="ev-id">${pkg.evidence_id || '—'}</div>
            <div class="ev-type">${pkg.evidence_type || '—'} · ${new Date(pkg.signed_at * 1000).toLocaleString()}</div>
          </div>
          ${ui.badge(badgeLabel, badgeType)}
        </div>
        ${ui.kvGrid([
          ['Classification', pkg.outcome?.classification || '—', false],
          ['Evidence hash', pkg.evidence_hash || '—', true],
          ['Key ID', pkg.key_id || '—', true],
        ])}
        <div style="display: flex; gap: 8px; margin-top: 10px; flex-wrap: wrap;">
          <a href="${cfg.base}/api/evidence/${encodeURIComponent(pkg.evidence_id)}/certificate.html" target="_blank" class="btn btn-primary btn-sm" style="text-decoration:none;display:inline-flex;align-items:center;">
            📜 Court Certificate (HTML + QR)
          </a>
          <a href="${cfg.base}/api/evidence/${encodeURIComponent(pkg.evidence_id)}/certificate.pdf" target="_blank" class="btn btn-ghost btn-sm" style="text-decoration:none;display:inline-flex;align-items:center;">
            📥 Download PDF
          </a>
          <button class="btn btn-ghost btn-sm" onclick="prefillTamper('${pkg.evidence_id}')">Tamper demo</button>
        </div>
      </div>`;
    }).join(''));

    // Show tamper section if demo mode
    if (state.demoMode) ui.show('tamperSection');
  } catch (e) {
    ui.html('vaultList', ui.err(e.message));
  }
}

function prefillTamper(evidenceId) {
  document.getElementById('tamperEvidenceId').value = evidenceId;
  ui.show('tamperSection');
  document.getElementById('tamperSection').scrollIntoView({ behavior: 'smooth' });
}

function setTamperPreset(field, value) {
  document.getElementById('tamperField').value = field;
  document.getElementById('tamperValue').value = value;
  ui.html('tamperResult', '');
}

async function runTamper() {
  const evidenceId = ui.val('tamperEvidenceId');
  const field = ui.val('tamperField');
  const value = ui.val('tamperValue');
  if (!evidenceId || !field) return;
  try {
    const data = await api.post(`/api/evidence/${evidenceId}/tamper-demo`, {
      field_path: field,
      new_value: value,
    });
    const valid = data.verification?.valid;
    const type  = valid ? 'ok' : 'err';
    const label = valid ? '✓ Verification still passes' : '✗ Verification FAILED — tamper detected';
    ui.html('tamperResult', `
      <div class="result-card ${type}" style="margin-top:12px;">
        <div class="result-status" style="font-size:15px;">${label}</div>
        <div style="font-family:var(--mono); font-size:11px; margin-top:8px; color:var(--text2);">
          ${ui.esc(field)}: ${ui.esc(JSON.stringify(data.original_value))} → ${ui.esc(JSON.stringify(data.tampered_value))}<br>
          ${ui.esc(data.verification?.reason || '')}
        </div>
      </div>`);
  } catch (e) {
    ui.html('tamperResult', ui.err(e.message));
  }
}

// ── Independent Verifier module ───────────────────────────────────────────────

async function runVerify() {
  const raw = ui.val('verifyPackage');
  if (!raw) return;
  let pkg;
  try { pkg = JSON.parse(raw); } catch (_) {
    ui.html('verifyResult', ui.err('Invalid JSON'));
    return;
  }
  try {
    const data = await api.post('/api/evidence/verify-package', pkg);
    const valid = data.valid;
    const type  = valid ? 'ok' : 'err';
    const label = valid ? '✓ Package is valid' : '✗ Package verification failed';
    ui.html('verifyResult', `
      <div class="result-card ${type}">
        <div class="result-status" style="font-size:15px;">${label}</div>
        <div class="result-reason">${ui.esc(data.explanation || '')}</div>
      </div>
      ${data.details ? ui.kvGrid(Object.entries(data.details).map(([k, v]) => [k, String(v), false])) : ''}`);
  } catch (e) {
    ui.html('verifyResult', ui.err(e.message));
  }
}

// ── Advanced Carving module ───────────────────────────────────────────────────

async function runCarving() {
  if (!state.activeCaseId) {
    alert('Please select or create an active case first');
    return;
  }
  const types = [];
  if (document.getElementById('carveJpeg')?.checked) types.push('JPEG');
  if (document.getElementById('carvePng')?.checked) types.push('PNG');
  if (document.getElementById('carvePdf')?.checked) types.push('PDF');
  if (document.getElementById('carveZip')?.checked) { types.push('ZIP'); types.push('DOCX'); types.push('XLSX'); }
  if (document.getElementById('carveMp4')?.checked) types.push('MP4');
  const maxResults = parseInt(ui.val('carveLimit') || '100', 10);

  ui.setBtn('btnRunCarve', true);
  ui.html('carveResults', '<div style="color:var(--text3); font-size:12px; margin-top:12px;">Running deep signature & structure carving analysis…</div>');
  try {
    const data = await api.post(`/api/cases/${state.activeCaseId}/carve`, {
      target_types: types.length ? types : null,
      max_results: maxResults,
    });
    ui.setBtn('btnRunCarve', false);
    const c = data.carved || {};
    const items = c.artifacts || [];

    // Stats
    ui.show('carveStats');
    ui.html('carveStats', `
      <div style="display:flex;gap:12px;flex-wrap:wrap;padding:12px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);">
        <div><strong>Total Carved:</strong> ${c.total_carved || 0}</div>
        <div><strong>Intact:</strong> <span style="color:var(--green)">${c.intact || 0}</span></div>
        <div><strong>High Confidence:</strong> <span style="color:var(--blue)">${c.high_confidence || 0}</span></div>
        <div><strong>Partial/Fragmented:</strong> <span style="color:var(--amber)">${(c.partial || 0) + (c.bifragmented || 0)}</span></div>
        <div style="margin-left:auto;">${ui.badge('Signed Evidence: ' + (data.evidence_id || '—'), 'ok')}</div>
      </div>
    `);

    if (!items.length) {
      ui.html('carveResults', '<div class="empty-state"><div class="empty-icon">🔍</div><div class="empty-title">No matching signatures found</div><div class="empty-sub">Ensure the case has an acquired image with target file headers</div></div>');
      return;
    }

    const rows = items.map(a => `
      <tr style="border-bottom: 1px solid var(--border);">
        <td style="padding: 8px; font-family: var(--mono);">${ui.esc(a.artifact_id)}</td>
        <td style="padding: 8px;"><strong>${ui.esc(a.file_type)}</strong></td>
        <td style="padding: 8px; font-family: var(--mono);">0x${(a.start_offset || 0).toString(16).toUpperCase()}</td>
        <td style="padding: 8px;">${(a.size_bytes || 0).toLocaleString()} B</td>
        <td style="padding: 8px;">
          ${a.is_intact ? '<span style="color:var(--green);font-weight:600;">INTACT</span>' : '<span style="color:var(--amber);">PARTIAL</span>'}
        </td>
        <td style="padding: 8px;">${Math.round((a.confidence || 0) * 100)}%</td>
        <td style="padding: 8px; font-family: var(--mono); font-size: 11px;">${(a.sha256 || '—').substring(0, 16)}…</td>
      </tr>
    `).join('');

    ui.html('carveResults', `
      <table style="width: 100%; border-collapse: collapse; font-size: 12.5px; margin-top: 12px; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);">
        <thead>
          <tr style="background: var(--surface2); text-align: left; color: var(--text2);">
            <th style="padding: 8px;">ID</th>
            <th style="padding: 8px;">Format</th>
            <th style="padding: 8px;">Start Offset</th>
            <th style="padding: 8px;">Size</th>
            <th style="padding: 8px;">Integrity</th>
            <th style="padding: 8px;">Confidence</th>
            <th style="padding: 8px;">SHA-256</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    `);
  } catch (e) {
    ui.setBtn('btnRunCarve', false);
    ui.html('carveResults', ui.err(e.message));
  }
}

// ── Selective Eraser & NIST Media Detector module ─────────────────────────────

function setSanMode(mode) {
  const btnDrive = document.getElementById('btnModeDrive');
  const btnFiles = document.getElementById('btnModeFiles');
  const secDrive = document.getElementById('sanModeDrive');
  const secFiles = document.getElementById('sanModeFiles');
  if (mode === 'drive') {
    btnDrive?.classList.add('active');
    btnFiles?.classList.remove('active');
    if (secDrive) secDrive.style.display = '';
    if (secFiles) secFiles.style.display = 'none';
  } else {
    btnDrive?.classList.remove('active');
    btnFiles?.classList.add('active');
    if (secDrive) secDrive.style.display = 'none';
    if (secFiles) secFiles.style.display = '';
  }
}

async function runDeviceDetect() {
  const targetPath = ui.val('detectPath');
  if (!targetPath) {
    alert('Please enter a target path to inspect');
    return;
  }
  const caseId = state.activeCaseId || 'demo';
  ui.html('detectResult', '<div style="color:var(--text3);font-size:12px;">Detecting media capabilities per NIST SP 800-88 Rev. 2…</div>');
  try {
    const data = await api.post(`/api/cases/${caseId}/detect-device`, { target_path: targetPath });
    const levelCls = data.recommended_level === 'PURGE' ? 'badge-ok' : data.recommended_level === 'CLEAR' ? 'badge-warn' : 'badge-err';
    ui.html('detectResult', `
      <div class="result-card ok">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <div class="result-status">Media Classification: ${ui.esc(data.media_type)}</div>
          <span class="badge ${levelCls}">NIST Level: ${ui.esc(data.recommended_level)}</span>
        </div>
        <div class="result-reason" style="margin-top:6px;"><strong>Reference:</strong> ${ui.esc(data.nist_reference || '')}</div>
        <div class="result-scope" style="margin-top:6px;"><strong>Scope:</strong> ${ui.esc(data.scope_statement || '')}</div>
        ${data.warnings?.length ? `<div style="color:var(--amber);margin-top:8px;font-size:12px;"><strong>Standards Advisory:</strong> ${ui.esc(data.warnings.join('; '))}</div>` : ''}
      </div>
    `);
  } catch (e) {
    ui.html('detectResult', ui.err(e.message));
  }
}

async function previewEraseScope() {
  if (!state.activeCaseId) {
    alert('Please select or create an active case first');
    return;
  }
  const rawPaths = ui.val('eraseTargetPaths');
  const targetPaths = rawPaths.split(/[\n,]/).map(s => s.trim()).filter(Boolean);
  if (!targetPaths.length) {
    alert('Please specify at least one target file or folder path');
    return;
  }
  ui.html('erasePreviewResult', '<div style="color:var(--text3);font-size:12px;">Scanning target paths…</div>');
  try {
    const data = await api.post(`/api/cases/${state.activeCaseId}/erase-preview`, {
      target_paths: targetPaths,
    });
    const items = data.scope_items || [];
    const rows = items.map(i => `
      <tr style="border-bottom:1px solid var(--border);">
        <td style="padding:6px;font-family:var(--mono);">${ui.esc(i.path)}</td>
        <td style="padding:6px;">${i.is_dir ? 'Directory (' + i.child_count + ' items)' : 'Regular File'}</td>
        <td style="padding:6px;">${(i.size_bytes || 0).toLocaleString()} bytes</td>
      </tr>
    `).join('');
    ui.html('erasePreviewResult', `
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:10px;">
        <div style="display:flex;justify-content:space-between;margin-bottom:8px;font-weight:600;">
          <span>Target Files: ${data.total_files}</span>
          <span>Aggregate Size: ${(data.total_size_bytes || 0).toLocaleString()} bytes</span>
        </div>
        <table style="width:100%;border-collapse:collapse;font-size:12px;">
          <thead>
            <tr style="color:var(--text2);text-align:left;">
              <th style="padding:4px;">Path</th><th>Type</th><th>Size</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
        <div style="color:var(--amber);margin-top:8px;font-size:11.5px;">⚠️ ${ui.esc(data.warning || '')}</div>
      </div>
    `);
  } catch (e) {
    ui.html('erasePreviewResult', ui.err(e.message));
  }
}

async function runFileErasure() {
  if (!state.activeCaseId) {
    alert('Please select or create an active case first');
    return;
  }
  const rawPaths = ui.val('eraseTargetPaths');
  const targetPaths = rawPaths.split(/[\n,]/).map(s => s.trim()).filter(Boolean);
  const opId = ui.val('fileOpId');
  const opName = ui.val('fileOpName');
  const opReason = ui.val('fileOpReason');
  const ack = document.getElementById('fileScopeAck')?.checked;

  if (!targetPaths.length) { alert('Enter target paths'); return; }
  if (!opId || !opName) { alert('Operator ID and Name are required for sanitization authorization'); return; }
  if (!opReason) { alert('Authorization reason / Court mandate is required'); return; }
  if (!ack) { alert('You must confirm acknowledgement of NIST SP 800-88 erasure scope'); return; }

  ui.html('fileErasureResult', '<div style="color:var(--text3);font-size:12px;">Executing multi-pass zero-fill & unlinking…</div>');
  try {
    const data = await api.post(`/api/cases/${state.activeCaseId}/erase-files`, {
      target_paths: targetPaths,
      operator_id: opId,
      operator_name: opName,
      authorization_reason: opReason,
      confirmed_scope_acknowledgement: true,
      method: 'ZERO_FILL',
      scrub_metadata: document.getElementById('eraseScrubMeta')?.checked ?? true,
      scramble_names: document.getElementById('eraseScrambleNames')?.checked ?? true,
    });
    const res = data.result || {};
    ui.html('fileErasureResult', `
      <div class="result-card ok">
        <div class="result-status">Selective Erasure Completed — ${ui.esc(res.classification || 'VERIFIED')}</div>
        <div class="result-reason">${ui.esc(res.explanation || '')}</div>
        <div style="margin-top:8px;font-size:12px;">
          Files Erased: ${res.total_files || 0} | Bytes Wiped: ${(res.total_bytes || 0).toLocaleString()}
        </div>
        <div style="margin-top:10px;">
          ${ui.badge('Signed Evidence: ' + (data.evidence_id || '—'), 'ok')}
        </div>
      </div>
    `);
  } catch (e) {
    ui.html('fileErasureResult', ui.err(e.message));
  }
}

// ── Cryptographic Audit Chain module ─────────────────────────────────────────

async function loadAuditChain() {
  if (!state.activeCaseId) return;
  ui.html('chainStatusCard', '<div style="color:var(--text3);font-size:12px;">Loading chain…</div>');
  try {
    const [timeline, verification] = await Promise.all([
      api.get(`/api/cases/${state.activeCaseId}/timeline`),
      api.get(`/api/cases/${state.activeCaseId}/timeline/verify`),
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
      ui.html('auditTimeline', '<div class="empty-state"><div class="empty-icon">⛓️</div><div class="empty-title">No audit events recorded</div></div>');
      return;
    }

    const cards = timeline.map((entry, idx) => `
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:12px;margin-bottom:10px;">
        <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--text2);">
          <span><strong>#${idx + 1}</strong> · ${ui.esc(entry.event_type)}</span>
          <span>${new Date(entry.timestamp * 1000).toLocaleString()}</span>
        </div>
        <div style="margin:6px 0;font-size:13px;">Actor: <strong>${ui.esc(entry.actor || 'SYSTEM')}</strong></div>
        <div style="font-family:var(--mono);font-size:11px;color:var(--text3);background:var(--surface2);padding:6px;border-radius:4px;word-break:break-all;">
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
    alert('Please select or create an active case first');
    return;
  }
  await loadAuditChain();
}

async function simulateTamperDemo() {
  if (!state.activeCaseId) {
    alert('Please select an active case with at least 1 audit event');
    return;
  }
  ui.html('tamperDemoResult', '<div style="color:var(--text3);font-size:12px;">Modifying historical record in audit chain and running verification engine…</div>');
  try {
    const data = await api.post(`/api/cases/${state.activeCaseId}/timeline/demo-tamper`, {
      entry_index: 0,
      field: 'actor',
      new_value: 'ROGUE_ACTOR_MUTATION',
    });
    const v = data.tampered_verification || {};
    ui.html('tamperDemoResult', `
      <div class="result-card err" style="margin-top:10px;">
        <div class="result-status">🚨 Cryptographic Tamper Detected!</div>
        <div style="margin-top:6px;font-size:12.5px;">
          Adversary mutated <code>${ui.esc(data.tampered_field)}</code> on line ${data.tampered_entry_index + 1}.<br>
          <strong>Chain Status:</strong> ${v.chain_valid ? 'Valid' : 'INVALID (Break detected)'}<br>
          <strong>Pinpointed Violation:</strong> ${ui.esc(JSON.stringify(v.violations?.[0] || 'Broken linkage'))}
        </div>
        <div style="margin-top:8px;font-size:11.5px;color:var(--green);">
          ✓ Original chain automatically restored after verification proof.
        </div>
      </div>
    `);
    await loadAuditChain();
  } catch (e) {
    ui.html('tamperDemoResult', ui.err(e.message));
  }
}

// ── Init ──────────────────────────────────────────────────────────────────────

(async function init() {
  // Check demo mode from API
  try {
    const health = await api.get('/health');
    state.demoMode = health.demo_mode === true;
  } catch (_) {}

  loadCases();
})();
