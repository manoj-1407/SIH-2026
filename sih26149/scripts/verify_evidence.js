#!/usr/bin/env node
/**
 * SIH26149 - Independent Evidence Package Verifier (Node.js)
 *
 * Verifies Ed25519-signed evidence envelopes independently of the
 * Python FastAPI server. Uses only Node.js built-in crypto module.
 *
 * Usage:
 *   node scripts/verify_evidence.js <evidence.json> --trusted-key public_key.pem
 *   node scripts/verify_evidence.js <package_dir/manifest.json> --registry trust_registry.json
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
  if (keyObj.asymmetricKeyType !== 'ed25519') {
    throw new Error('Trusted public key must be Ed25519');
  }
  const der = keyObj.export({ type: 'spki', format: 'der' });
  return der.slice(-32);
}

function loadPublicKeyFromHex(hex) {
  if (typeof hex !== 'string' || !/^[0-9a-f]{64}$/i.test(hex)) {
    failTrust('Trusted registry public_key_hex must encode exactly 32 bytes');
  }
  return Buffer.from(hex, 'hex');
}

function resolvePublicKey(keyId, trustedPubKeyPath, registryPath) {
  if (trustedPubKeyPath) {
    if (!fs.existsSync(trustedPubKeyPath)) {
      failTrust(`Trusted public key not found: ${trustedPubKeyPath}`);
    }
    return { key: loadPublicKeyFromPem(trustedPubKeyPath), source: path.basename(trustedPubKeyPath) };
  }
  if (registryPath) {
    if (!fs.existsSync(registryPath)) {
      failTrust(`Trusted key registry not found: ${registryPath}`);
    }
    const registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
    const entry = keyId && registry[keyId];
    if (!entry || entry.status !== 'ACTIVE' || typeof entry.public_key_hex !== 'string') {
      failTrust(`Key ${keyId || '(missing key ID)'} is not present in the supplied trust registry`);
    }
    return { key: loadPublicKeyFromHex(entry.public_key_hex), source: `trust registry [${keyId}]` };
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

function failTrust(msg) {
  console.error(`\x1b[31m[UNTRUSTED] ${msg}\x1b[0m`);
  process.exit(2);
}

function printEnvelopeAssurance(pkg) {
  const scope = typeof pkg.scope === 'string' ? pkg.scope.trim() : '';
  const operation = pkg.operation && typeof pkg.operation === 'object' ? pkg.operation : null;
  const result = pkg.result && typeof pkg.result === 'object' ? pkg.result : null;
  const probe = result && result.post_sanitization_probe;
  const recovered = probe && Number.isInteger(probe.artifacts_recovered)
    ? probe.artifacts_recovered
    : null;

  console.log(`HASH CHAIN : NOT INCLUDED (single-envelope format)`);
  console.log(`SCOPE      : ${scope ? 'PASS (signed scope present)' : 'NOT ATTESTED'}`);
  console.log(`OPERATION  : ${operation && Object.keys(operation).length
    ? 'PASS (signed operation metadata present)' : 'NOT ATTESTED'}`);
  if (recovered !== null) {
    console.log(`POST-PROBE : ${recovered === 0 ? 'PASS' : 'FAIL'} (${recovered} residual artifact(s) reported)`);
    if (result.assurance && result.assurance.operation_scope) {
      console.log(`PROBE SCOPE: ${result.assurance.operation_scope}`);
    }
  } else {
    console.log(`POST-PROBE : NOT ATTESTED`);
  }
}

function verifyEnvelope(pkg, jsonPath, trustedPubKeyPath, registryPath) {
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
  if (signing.algorithm !== 'Ed25519') {
    fail(`INVALID - Unsupported signing algorithm: ${signing.algorithm || '(missing)'}`);
  }
  const resolved = resolvePublicKey(signing.key_id, trustedPubKeyPath, registryPath);
  if (!resolved.key) {
    failTrust('A trusted public key or trust registry is required; an evidence package is not its own trust anchor');
  }
  if (!verifyEd25519(resolved.key, canonicalBytes, pkg.signature)) {
    console.log(`\x1b[31m[INVALID] Ed25519 signature INVALID\x1b[0m`);
    process.exit(1);
  }
  console.log(`\x1b[32m[OK] Ed25519 signature VALID (${resolved.source})\x1b[0m`);

  console.log();
  printEnvelopeAssurance(pkg);
  console.log(`\x1b[32m[OK] CRYPTOGRAPHICALLY VERIFIED - Evidence envelope integrity confirmed\x1b[0m`);
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

function verifyDirectoryPackage(manifestPath, trustedPubKeyPath, registryPath) {
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

  const resolved = resolvePublicKey(sigData.key_id, trustedPubKeyPath, registryPath);
  if (!resolved.key) {
    failTrust('A trusted public key or trust registry is required; embedded package keys are not trust anchors');
  }
  if (fs.existsSync(pubPkgPath)) {
    const embedded = loadPublicKeyFromPem(pubPkgPath);
    if (!embedded.equals(resolved.key)) {
      fail(`INVALID - Embedded public key does not match the independently trusted key`);
    }
  }
  if (!verifyEd25519(resolved.key, manifestCanonical, sigData.signature)) {
    console.log(`\x1b[31m[INVALID] Ed25519 signature INVALID\x1b[0m`);
    process.exit(1);
  }
  console.log(`\x1b[32m[OK] Ed25519 signature VALID (${resolved.source})\x1b[0m`);

  if (fs.existsSync(auditPath) && fs.statSync(auditPath).size > 0) {
    const lines = fs.readFileSync(auditPath, 'utf8').split(/\r?\n/);
    let expectedPrev = 'GENESIS';
    let idx = 0;
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line) continue;
      let event;
      try { event = JSON.parse(line); } catch { failAudit(`Malformed audit JSON at event ${idx}`); }
      const storedPrev = event.previous_hash;
      if (storedPrev !== expectedPrev) {
        failAudit(`Chain broken at event ${idx}: expected previous_hash=${expectedPrev}, got ${storedPrev}`);
      }
      if (typeof event.entry_hash !== 'string' || !/^[0-9a-f]{64}$/i.test(event.entry_hash)) {
        failAudit(`Missing or malformed entry_hash at event ${idx}`);
      }
      const sanitized = {};
      for (const [k, v] of Object.entries(event)) if (k !== 'entry_hash') sanitized[k] = v;
      const computedHash = sha256hex(canonicalize(sanitized));
      if (event.entry_hash !== computedHash) {
        failAudit(`Entry hash mismatch at event ${idx}`);
      }
      expectedPrev = event.entry_hash;
      idx++;
    }
    if (idx === 0) {
      console.log(`\x1b[33m[NOT ATTESTED] Audit chain file is empty\x1b[0m`);
    } else {
      console.log(`\x1b[32m[OK] Audit event chain (${idx} events) verified - chain intact\x1b[0m`);
    }
  } else {
    console.log(`\x1b[33m[NOT ATTESTED] Audit chain is not included in this package\x1b[0m`);
  }

  console.log();
  console.log(`SCOPE      : NOT ATTESTED (generic package manifest has no normalized scope field)`);
  console.log(`OPERATION  : NOT ATTESTED (generic package manifest has no normalized operation field)`);
  console.log(`POST-PROBE : NOT ATTESTED (generic package manifest has no normalized post-probe field)`);
  console.log(`\x1b[32m[OK] CRYPTOGRAPHICALLY VERIFIED - Evidence package integrity confirmed\x1b[0m`);
  console.log(`  Files verified: ${Object.keys(file_hashes).length}`);
  console.log(`  Algorithm: ${sigData.algorithm || 'Ed25519'}`);
  console.log(`  Key ID: ${sigData.key_id || '-'}`);
  console.log();
  console.log(`\x1b[36mThis result was computed by an independent Node.js implementation,\nseparate from the Python verifier in app/core/independent_verifier.py.\x1b[0m`);
}

const args = process.argv.slice(2);
const jsonArg = args[0];
let keyArg = null;
let registryArg = null;
for (let i = 1; i < args.length; i++) {
  if (args[i] === '--trusted-key' && args[i + 1]) {
    keyArg = args[++i];
  } else if (args[i] === '--registry' && args[i + 1]) {
    registryArg = args[++i];
  } else if (!args[i].startsWith('--') && !keyArg) {
    keyArg = args[i];
  } else {
    console.error(`Unknown or incomplete argument: ${args[i]}`);
    process.exit(2);
  }
}

if (!jsonArg || jsonArg === '--help' || jsonArg === '-h') {
  console.log('Usage: node scripts/verify_evidence.js <evidence.json|manifest.json> (--trusted-key public_key.pem | --registry trust_registry.json)');
  console.log('  node scripts/verify_evidence.js evidence.json --trusted-key examiner.pub.pem');
  console.log('  node scripts/verify_evidence.js case-XXXX/manifest.json --registry trust_registry.json');
  process.exit(jsonArg ? 0 : 2);
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
  verifyDirectoryPackage(jsonArg, keyArg, registryArg);
} else {
  verifyEnvelope(topLevel, jsonArg, keyArg, registryArg);
}
