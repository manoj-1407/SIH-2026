#!/usr/bin/env node
/**
 * SIH26149 — Independent Evidence Package Verifier (Node.js)
 *
 * Verifies Ed25519-signed evidence envelopes independently of the
 * Python FastAPI server. Uses only Node.js built-in crypto module.
 *
 * Usage:
 *   node scripts/verify_evidence.js <evidence.json> [public_key.pem]
 *
 * The evidence JSON must contain:
 *   - evidence_id, case_id, evidence_type, created_at_utc
 *   - input, operation, result, scope, signing
 *   - evidence_hash (SHA-256 of canonical payload)
 *   - signature (Ed25519 hex signature)
 *
 * Standards: Ed25519 (RFC 8032), SHA-256 (FIPS 180-4),
 *            JSON canonical sort_keys serialization (RFC 8785 subset).
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * RFC 8785 subset: canonical JSON with sorted keys, no whitespace.
 * Recursively sorts object keys. Arrays preserve order.
 */
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

function verifyEd25519(publicKeyRaw, message, signatureHex) {
  try {
    const sigBytes = Buffer.from(signatureHex, 'hex');
    const keyObj = crypto.createPublicKey({
      key: Buffer.concat([
        // Ed25519 DER prefix for 32-byte raw key
        Buffer.from('302a300506032b6570032100', 'hex'),
        publicKeyRaw,
      ]),
      format: 'der',
      type: 'spki',
    });
    return crypto.verify(null, Buffer.from(message, 'utf8'), keyObj, sigBytes);
  } catch (e) {
    return false;
  }
}

function loadPublicKey(pemPath) {
  const pem = fs.readFileSync(pemPath, 'utf8');
  const keyObj = crypto.createPublicKey(pem);
  // Export raw 32-byte Ed25519 key
  const der = keyObj.export({ type: 'spki', format: 'der' });
  // Last 32 bytes of the DER encoding are the raw key
  return der.slice(-32);
}

function verifyPackage(jsonPath, pubKeyPath) {
  if (!fs.existsSync(jsonPath)) {
    console.error(`\x1b[31m✗ File not found: ${jsonPath}\x1b[0m`);
    process.exit(1);
  }

  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
  } catch (e) {
    console.error(`\x1b[31m✗ Invalid JSON: ${e.message}\x1b[0m`);
    process.exit(1);
  }

  console.log(`\x1b[36m━━━ SIH26149 Independent Evidence Verifier (Node.js) ━━━\x1b[0m`);
  console.log(`File: ${jsonPath}`);
  console.log(`Evidence ID: ${pkg.evidence_id || '—'}`);
  console.log(`Case ID: ${pkg.case_id || '—'}`);
  console.log(`Type: ${pkg.evidence_type || '—'}`);
  console.log();

  // Required fields
  const required = ['evidence_id', 'case_id', 'evidence_type', 'created_at_utc',
                     'input', 'operation', 'result', 'scope', 'signing',
                     'evidence_hash', 'signature'];
  for (const f of required) {
    if (!(f in pkg)) {
      console.log(`\x1b[31m✗ INVALID — Missing required field: ${f}\x1b[0m`);
      process.exit(1);
    }
  }

  // 1. Reconstruct canonical payload (exclude evidence_hash and signature)
  const payload = {};
  for (const [k, v] of Object.entries(pkg)) {
    if (k !== 'evidence_hash' && k !== 'signature') {
      payload[k] = v;
    }
  }
  const canonicalBytes = canonicalize(payload);

  // 2. Verify evidence hash
  const computedHash = sha256hex(canonicalBytes);
  const storedHash = pkg.evidence_hash;

  if (computedHash.toLowerCase() !== storedHash.toLowerCase()) {
    console.log(`\x1b[31m✗ HASH MISMATCH — Evidence has been tampered with\x1b[0m`);
    console.log(`  Stored:   ${storedHash}`);
    console.log(`  Computed: ${computedHash}`);
    process.exit(1);
  }
  console.log(`\x1b[32m✓ Hash verified: ${computedHash.substring(0, 32)}…\x1b[0m`);

  // 3. Verify Ed25519 signature (if public key available)
  if (pubKeyPath) {
    const pubRaw = loadPublicKey(pubKeyPath);
    const sigValid = verifyEd25519(pubRaw, canonicalBytes, pkg.signature);
    if (sigValid) {
      console.log(`\x1b[32m✓ Ed25519 signature VALID\x1b[0m`);
    } else {
      console.log(`\x1b[31m✗ Ed25519 signature INVALID\x1b[0m`);
      process.exit(1);
    }
  } else {
    // Try to find public key in trust_registry.json or data/keys/*.pem
    const keyId = pkg.signing?.key_id;
    const regCandidates = [
      path.join('data', 'keys', 'trust_registry.json'),
      path.join(__dirname, '..', 'data', 'keys', 'trust_registry.json'),
    ];
    const regPath = regCandidates.find(p => fs.existsSync(p));
    let pubRaw = null;
    let keySource = '';
    if (regPath) {
      try {
        const reg = JSON.parse(fs.readFileSync(regPath, 'utf8'));
        if (keyId && reg[keyId]?.public_key_hex) {
          pubRaw = Buffer.from(reg[keyId].public_key_hex, 'hex');
          keySource = `trust registry [${keyId}]`;
        }
      } catch {}
    }
    if (!pubRaw) {
      const candidates = [
        path.join('data', 'keys', `${keyId}.pub.pem`),
        path.join(__dirname, '..', 'data', 'keys', `${keyId}.pub.pem`),
        path.join('data', 'keys', 'primary.pub.pem'),
        path.join(__dirname, '..', 'data', 'keys', 'primary.pub.pem'),
      ];
      const found = candidates.find(p => fs.existsSync(p));
      if (found) {
        pubRaw = loadPublicKey(found);
        keySource = path.basename(found);
      }
    }
    if (pubRaw) {
      const sigValid = verifyEd25519(pubRaw, canonicalBytes, pkg.signature);
      if (sigValid) {
        console.log(`\x1b[32m✓ Ed25519 signature VALID (${keySource})\x1b[0m`);
      } else {
        console.log(`\x1b[31m✗ Ed25519 signature INVALID\x1b[0m`);
        process.exit(1);
      }
    } else {
      console.log(`\x1b[33m⚠ No public key found — hash verified but signature not checked\x1b[0m`);
      console.log(`  Provide key: node verify_evidence.js ${jsonPath} <public_key.pem>`);
    }
  }



  console.log();
  console.log(`\x1b[32m✓ VERIFIED — Evidence package integrity confirmed\x1b[0m`);
  console.log(`  Algorithm: ${pkg.signing?.algorithm || 'Ed25519'}`);
  console.log(`  Key ID: ${pkg.signing?.key_id || '—'}`);
  console.log();
  console.log(`\x1b[36mThis result was computed by an independent Node.js implementation,`);
  console.log(`separate from the Python verifier in app/core/independent_verifier.py.\x1b[0m`);
}

// CLI
const jsonArg = process.argv[2];
const keyArg = process.argv[3] || null;

if (!jsonArg || jsonArg === '--help' || jsonArg === '-h') {
  console.log('Usage: node scripts/verify_evidence.js <evidence.json> [public_key.pem]');
  console.log('  node scripts/verify_evidence.js evidence_EVID-ABCD123456.json');
  console.log('  node scripts/verify_evidence.js package.json data/keys/primary.pub.pem');
  process.exit(jsonArg ? 0 : 1);
}

verifyPackage(jsonArg, keyArg);
