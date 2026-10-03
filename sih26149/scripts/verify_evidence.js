#!/usr/bin/env node
/**
 * SIH26149 - Independent Evidence Package Verifier (Node.js)
 *
 * Verifies Ed25519-signed evidence envelopes independently of the
 * Python FastAPI server. Uses only Node.js built-in crypto module.
 *
 * Usage:
 *   node scripts/verify_evidence.js <evidence.json> [public_key.pem]
 *   node scripts/verify_evidence.js <package_dir/manifest.json> [public_key.pem]
 *
 * Standards: Ed25519 (RFC 8032), SHA-256 (FIPS 180-4),
 *            JSON canonical sort_keys serialization (RFC 8785 subset).
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function canonicalize(obj) {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj === 'boolean') return obj ? 'true' : 'false';
  if (typeof obj === 'number') return JSON.stringify(obj);
  if (typeof obj === 'string') return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return '[' + obj.map(v => canonicalize(v)).join(',') + ']';
  }
  if (typeof obj === 'object') {
    const keys = Object.keys(obj).sort();
    const pairs = keys.map(k => JSON.stringify(k) + ':' + canonicalize(obj[k]));
    return '{' + pairs.join(',') + '}';
  }
  return JSON.stringify(obj);
}

function sha256hex(data) {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}

function sha256hexBytes(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function verifyEd25519(publicKeyRaw, message, signatureHex) {
  try {
    const sigBytes = Buffer.from(signatureHex, 'hex');
    const keyObj = crypto.createPublicKey({
      key: Buffer.concat([
        Buffer.from('302a300506032b6570032100', 'hex'),
        publicKeyRaw,
      ]),
      format: 'der',
      type: 'spki',
    });
    const msgBuf = typeof message === 'string' ? Buffer.from(message, 'utf8') : message;
    return crypto.verify(null, msgBuf, keyObj, sigBytes);
  } catch (e) {
    return false;
  }
}

function loadPublicKeyFromPem(pemPath) {
  const pem = fs.readFileSync(pemPath, 'utf8');
  const keyObj = crypto.createPublicKey(pem);
  const der = keyObj.export({ type: 'spki', format: 'der' });
  return der.slice(-32);
}

function loadPublicKeyFromHex(hex) {
  return Buffer.from(hex, 'hex');
}

function resolvePublicKey(keyId, explicitPubKeyPath) {
  if (explicitPubKeyPath && fs.existsSync(explicitPubKeyPath)) {
    return { key: loadPublicKeyFromPem(explicitPubKeyPath), source: path.basename(explicitPubKeyPath) };
  }
  const regCandidates = [
    path.join('data', 'keys', 'trust_registry.json'),
    path.join(__dirname, '..', 'data', 'keys', 'trust_registry.json'),
  ];
  for (const regPath of regCandidates) {
    if (fs.existsSync(regPath)) {
      try {
        const reg = JSON.parse(fs.readFileSync(regPath, 'utf8'));
        if (keyId && reg[keyId]?.public_key_hex) {
          return { key: loadPublicKeyFromHex(reg[keyId].public_key_hex), source: `trust registry [${keyId}]` };
        }
      } catch {}
    }
  }
  const candidates = [];
  if (keyId) {
    candidates.push(path.join('data', 'keys', `${keyId}.pub.pem`));
    candidates.push(path.join(__dirname, '..', 'data', 'keys', `${keyId}.pub.pem`));
  }
  candidates.push(path.join('data', 'keys', 'primary.pub.pem'));
  candidates.push(path.join(__dirname, '..', 'data', 'keys', 'primary.pub.pem'));
  for (const c of candidates) {
    if (fs.existsSync(c)) {
      return { key: loadPublicKeyFromPem(c), source: path.basename(c) };
    }
  }
  return { key: null, source: null };
}

function fail(msg) {
  console.log(`\x1b[31m[INVALID] ${msg}\x1b[0m`);
  process.exit(1);
}

function failAudit(msg) {
  console.log(`\x1b[31m[AUDIT_CHAIN_TAMPER] ${msg}\x1b[0m`);
  process.exit(1);
}

function verifyEnvelope(pkg, jsonPath, pubKeyPath) {
  console.log(`\x1b[36m=== SIH26149 Independent Evidence Verifier (Node.js) ===\x1b[0m`);
  console.log(`File: ${jsonPath}`);
  console.log(`Evidence ID: ${pkg.evidence_id || '-'}`);
  console.log(`Case ID: ${pkg.case_id || '-'}`);
  console.log(`Type: ${pkg.evidence_type || '-'}`);
  console.log();

  const required = ['evidence_id', 'case_id', 'evidence_type', 'created_at_utc',
                     'input', 'operation', 'result', 'scope', 'signing',
                     'evidence_hash', 'signature'];
  for (const f of required) {
    if (!(f in pkg)) fail(`INVALID - Missing required field: ${f}`);
  }

  const payload = {};
  for (const [k, v] of Object.entries(pkg)) {
    if (k !== 'evidence_hash' && k !== 'signature') {
      payload[k] = v;
    }
  }
  const canonicalBytes = canonicalize(payload);
  const computedHash = sha256hex(canonicalBytes);
  const storedHash = pkg.evidence_hash;

  if (computedHash.toLowerCase() !== storedHash.toLowerCase()) {
    console.log(`\x1b[31m[INVALID] Hash mismatch (evidence tampered)\x1b[0m`);
    console.log(`  Stored:   ${storedHash}`);
    console.log(`  Computed: ${computedHash}`);
    process.exit(1);
  }
  console.log(`\x1b[32m[OK] Hash verified: ${computedHash.substring(0, 32)}...\x1b[0m`);

  const signing = pkg.signing || {};
  const resolved = resolvePublicKey(signing.key_id, pubKeyPath);
  if (resolved.key) {
    const sigValid = verifyEd25519(resolved.key, canonicalBytes, pkg.signature);
    if (sigValid) {
      console.log(`\x1b[32m[OK] Ed25519 signature VALID (${resolved.source})\x1b[0m`);
    } else {
      console.log(`\x1b[31m[INVALID] Ed25519 signature INVALID\x1b[0m`);
      process.exit(1);
    }
  } else {
    console.log(`\x1b[33m[WARN] No public key found - hash verified but signature not checked\x1b[0m`);
  }

  console.log();
  console.log(`\x1b[32m[OK] VERIFIED - Evidence envelope integrity confirmed\x1b[0m`);
  console.log(`  Algorithm: ${signing.algorithm || 'Ed25519'}`);
  console.log(`  Key ID: ${signing.key_id || '-'}`);
  console.log();
  console.log(`\x1b[36mThis result was computed by an independent Node.js implementation,\nseparate from the Python verifier in app/core/independent_verifier.py.\x1b[0m`);
}

function walkDir(root) {
  const result = [];
  function walk(cur) {
    const entries = fs.readdirSync(cur, { withFileTypes: true });
    for (const e of entries) {
      const full = path.join(cur, e.name);
      if (e.isDirectory()) walk(full);
      else result.push(full);
    }
  }
  walk(root);
  return result;
}

function verifyDirectoryPackage(manifestPath, pubKeyPath) {
  const root = path.dirname(manifestPath);
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const sigPath = path.join(root, 'cryptography', 'signature.json');
  const pubPkgPath = path.join(root, 'cryptography', 'public_key.pem');
  const auditPath = path.join(root, 'audit', 'events.jsonl');

  console.log(`\x1b[36m=== SIH26149 Independent Evidence Package Verifier (Node.js) ===\x1b[0m`);
  console.log(`Package: ${root}`);
  console.log(`Case ID: ${manifest.case_id || '-'}`);
  console.log(`Schema: ${manifest.schema_version || '-'}`);
  console.log();

  if (!fs.existsSync(sigPath)) fail(`INVALID - Package missing cryptography/signature.json`);
  const sigData = JSON.parse(fs.readFileSync(sigPath, 'utf8'));

  const file_hashes = manifest.file_hashes || {};
  for (const [relPath, expectedHash] of Object.entries(file_hashes)) {
    const absTarget = path.join(root, relPath);
    if (!fs.existsSync(absTarget)) fail(`INVALID - Missing package file: ${relPath}`);
    const computed = sha256hexBytes(fs.readFileSync(absTarget));
    if (computed.toLowerCase() !== expectedHash.toLowerCase()) {
      console.log(`\x1b[31m[INVALID] Artifact tamper detected in '${relPath}'\x1b[0m`);
      console.log(`  Expected: ${expectedHash}`);
      console.log(`  Computed: ${computed}`);
      process.exit(1);
    }
  }
  console.log(`\x1b[32m[OK] ${Object.keys(file_hashes).length} file hashes verified\x1b[0m`);

  const EXCLUDED = new Set([
    'manifest.json',
    'cryptography/signature.json',
    'cryptography/public_key.pem',
  ]);
  const allFiles = walkDir(root);
  for (const absF of allFiles) {
    const rel = absF.slice(root.length + 1).split(path.sep).join('/');
    if (EXCLUDED.has(rel)) continue;
    if (!(rel in file_hashes)) {
      fail(`INVALID - Unexpected file '${rel}' injected after signing`);
    }
  }

  const rawManifestBytes = fs.readFileSync(manifestPath);
  const rawManifestHash = sha256hexBytes(rawManifestBytes);
  const storedManifestHash = sigData.manifest_hash || '';
  if (rawManifestHash.toLowerCase() !== storedManifestHash.toLowerCase()) {
    fail(`INVALID - Manifest on-disk hash does not match signed record`);
  }

  const manifestCanonical = canonicalize(manifest);
  if (sha256hex(manifestCanonical).toLowerCase() !== storedManifestHash.toLowerCase()) {
    fail(`INVALID - Manifest canonical form hash mismatch`);
  }
  console.log(`\x1b[32m[OK] Manifest integrity (raw + canonical) verified\x1b[0m`);

  let resolved = resolvePublicKey(sigData.key_id, pubKeyPath);
  if (resolved.key === null && fs.existsSync(pubPkgPath)) {
    try {
      resolved = { key: loadPublicKeyFromPem(pubPkgPath), source: 'embedded public_key.pem' };
    } catch {}
  }
  if (resolved.key) {
    const sigValid = verifyEd25519(resolved.key, manifestCanonical, sigData.signature);
    if (sigValid) {
      console.log(`\x1b[32m[OK] Ed25519 signature VALID (${resolved.source})\x1b[0m`);
    } else {
      console.log(`\x1b[31m[INVALID] Ed25519 signature INVALID\x1b[0m`);
      process.exit(1);
    }
  } else {
    console.log(`\x1b[33m[WARN] No public key found - hash verified but signature not checked\x1b[0m`);
  }

  if (fs.existsSync(auditPath) && fs.statSync(auditPath).size > 0) {
    const lines = fs.readFileSync(auditPath, 'utf8').split(/\r?\n/);
    let expectedPrev = 'GENESIS';
    let idx = 0;
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line) continue;
      let event;
      try { event = JSON.parse(line); } catch { failAudit(`Malformed audit JSON at event ${idx}`); }
      const storedPrev = event.previous_hash || 'GENESIS';
      if (storedPrev !== expectedPrev) {
        failAudit(`Chain broken at event ${idx}: expected previous_hash=${expectedPrev}, got ${storedPrev}`);
      }
      const sanitized = {};
      for (const [k, v] of Object.entries(event)) if (k !== 'entry_hash') sanitized[k] = v;
      const computedHash = sha256hex(canonicalize(sanitized));
      if (event.entry_hash && event.entry_hash !== computedHash) {
        failAudit(`Entry hash mismatch at event ${idx}`);
      }
      expectedPrev = event.entry_hash;
      idx++;
    }
    console.log(`\x1b[32m[OK] Audit event chain (${idx} events) verified - chain intact\x1b[0m`);
  }

  console.log();
  console.log(`\x1b[32m[OK] VERIFIED - Evidence package integrity confirmed\x1b[0m`);
  console.log(`  Files verified: ${Object.keys(file_hashes).length}`);
  console.log(`  Algorithm: ${sigData.algorithm || 'Ed25519'}`);
  console.log(`  Key ID: ${sigData.key_id || '-'}`);
  console.log();
  console.log(`\x1b[36mThis result was computed by an independent Node.js implementation,\nseparate from the Python verifier in app/core/independent_verifier.py.\x1b[0m`);
}

const jsonArg = process.argv[2];
const keyArg = process.argv[3] || null;

if (!jsonArg || jsonArg === '--help' || jsonArg === '-h') {
  console.log('Usage: node scripts/verify_evidence.js <evidence.json|manifest.json> [public_key.pem]');
  console.log('  node scripts/verify_evidence.js evidence_EVID-ABCD123456.json');
  console.log('  node scripts/verify_evidence.js case-XXXX/manifest.json');
  process.exit(jsonArg ? 0 : 1);
}

if (!fs.existsSync(jsonArg)) {
  console.error(`\x1b[31m[INVALID] File not found: ${jsonArg}\x1b[0m`);
  process.exit(1);
}

let topLevel;
try {
  topLevel = JSON.parse(fs.readFileSync(jsonArg, 'utf8'));
} catch (e) {
  console.error(`\x1b[31m[INVALID] Invalid JSON: ${e.message}\x1b[0m`);
  process.exit(1);
}

const isManifest = ('file_hashes' in topLevel) && ('schema_version' in topLevel);
if (isManifest) {
  verifyDirectoryPackage(jsonArg, keyArg);
} else {
  verifyEnvelope(topLevel, jsonArg, keyArg);
}
