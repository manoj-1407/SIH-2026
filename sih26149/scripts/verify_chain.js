#!/usr/bin/env node
/**
 * SIH26149 — Independent Audit Chain Verifier (Node.js)
 *
 * Verifies SHA-256 hash-chained audit log integrity independently
 * of the Python FastAPI server. Zero dependencies beyond Node.js stdlib.
 *
 * Usage:
 *   node scripts/verify_chain.js <case_id>
 *   node scripts/verify_chain.js CASE-DEMO-2026
 *   node scripts/verify_chain.js data/audit/CASE-DEMO-2026.jsonl
 *
 * This is the SECOND independent implementation of chain verification
 * (the primary is in Python: app/cases/audit.py). Two implementations
 * in different languages agreeing on chain validity is a strong
 * integrity guarantee — no single codebase can mask a bug.
 *
 * Standards: SHA-256 (FIPS 180-4), JSON canonical sort_keys serialization.
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const GENESIS_HASH = 'GENESIS';

/**
 * Lightweight JSON parser that preserves exact number representations
 * (e.g. floats with trailing zeroes like 100.0) so SHA-256 canonical hashing
 * matches Python's json.dumps(sort_keys=True, separators=(',', ':')) byte-for-byte.
 */
function parsePreserveNumbers(str) {
  let idx = 0;
  function skipWs() {
    while (idx < str.length && (str[idx] === ' ' || str[idx] === '\t' || str[idx] === '\n' || str[idx] === '\r')) idx++;
  }
  function parseVal() {
    skipWs();
    const c = str[idx];
    if (c === '{') return parseObj();
    if (c === '[') return parseArr();
    if (c === '"') return parseStr();
    if (c === 't' && str.slice(idx, idx + 4) === 'true') { idx += 4; return { type: 'bool', raw: 'true' }; }
    if (c === 'f' && str.slice(idx, idx + 5) === 'false') { idx += 5; return { type: 'bool', raw: 'false' }; }
    if (c === 'n' && str.slice(idx, idx + 4) === 'null') { idx += 4; return { type: 'null', raw: 'null' }; }
    return parseNum();
  }
  function parseStr() {
    const start = idx;
    idx++; // skip opening '"'
    while (idx < str.length) {
      if (str[idx] === '\\') { idx += 2; }
      else if (str[idx] === '"') { idx++; break; }
      else { idx++; }
    }
    return { type: 'string', raw: str.slice(start, idx) };
  }
  function parseNum() {
    const start = idx;
    if (str[idx] === '-') idx++;
    while (idx < str.length && /[0-9.eE+-]/.test(str[idx])) idx++;
    return { type: 'number', raw: str.slice(start, idx) };
  }
  function parseArr() {
    idx++; // skip '['
    skipWs();
    const items = [];
    if (str[idx] === ']') { idx++; return { type: 'array', items }; }
    while (idx < str.length) {
      items.push(parseVal());
      skipWs();
      if (str[idx] === ',') { idx++; }
      else if (str[idx] === ']') { idx++; break; }
    }
    return { type: 'array', items };
  }
  function parseObj() {
    idx++; // skip '{'
    skipWs();
    const props = [];
    if (str[idx] === '}') { idx++; return { type: 'object', props }; }
    while (idx < str.length) {
      skipWs();
      const keyToken = parseStr();
      skipWs();
      if (str[idx] === ':') idx++;
      const valToken = parseVal();
      props.push({ key: JSON.parse(keyToken.raw), keyRaw: keyToken.raw, val: valToken });
      skipWs();
      if (str[idx] === ',') { idx++; }
      else if (str[idx] === '}') { idx++; break; }
    }
    return { type: 'object', props };
  }
  return parseVal();
}

function serializeCanonical(node, isRoot = false) {
  if (node.type === 'string' || node.type === 'number' || node.type === 'bool' || node.type === 'null') {
    return node.raw;
  }
  if (node.type === 'array') {
    return '[' + node.items.map(it => serializeCanonical(it)).join(',') + ']';
  }
  if (node.type === 'object') {
    const sorted = node.props
      .filter(p => !isRoot || p.key !== 'entry_hash')
      .sort((a, b) => a.key.localeCompare(b.key));
    return '{' + sorted.map(p => JSON.stringify(p.key) + ':' + serializeCanonical(p.val)).join(',') + '}';
  }
  return '';
}

function sha256(data) {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}

function verifyChain(filePath) {
  if (!fs.existsSync(filePath)) {
    console.error(`\x1b[31m✗ File not found: ${filePath}\x1b[0m`);
    process.exit(1);
  }

  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n').filter(l => l.trim());

  if (lines.length === 0) {
    console.log('\x1b[33m⚠ Empty audit log — nothing to verify.\x1b[0m');
    process.exit(0);
  }

  console.log(`\x1b[36m━━━ SIH26149 Independent Chain Verifier (Node.js) ━━━\x1b[0m`);
  console.log(`File: ${filePath}`);
  console.log(`Entries: ${lines.length}`);
  console.log();

  let expectedPrevHash = GENESIS_HASH;
  const violations = [];

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    let entry;
    try {
      entry = JSON.parse(rawLine);
    } catch (e) {
      violations.push({ index: i, type: 'JSON_SYNTAX', detail: e.message });
      continue;
    }

    const storedHash = entry.entry_hash;
    const prevHash = entry.previous_hash;

    // Check 1: previous_hash matches expected
    if (prevHash !== expectedPrevHash) {
      violations.push({
        index: i,
        type: 'CHAIN_BROKEN',
        detail: `expected previous_hash="${expectedPrevHash.substring(0, 16)}…", got "${(prevHash || '').substring(0, 16)}…"`,
      });
    }

    // Check 2: stored entry_hash exists
    if (!storedHash) {
      violations.push({
        index: i,
        type: 'MISSING_ENTRY_HASH',
        detail: 'Entry has no entry_hash field (unhashed or stripped)',
      });
      continue;
    }

    // Check 3: recompute canonical hash and verify
    const parsed = parsePreserveNumbers(rawLine);
    const canonical = serializeCanonical(parsed, true);
    const computedHash = sha256(canonical);

    if (computedHash !== storedHash) {
      violations.push({
        index: i,
        type: 'ENTRY_TAMPERED',
        detail: `stored=${storedHash.substring(0, 16)}… computed=${computedHash.substring(0, 16)}…`,
      });
    }

    // Advance expected previous_hash
    expectedPrevHash = storedHash;
  }

  // Print summary
  if (violations.length === 0) {
    console.log(`\x1b[32m✓ CHAIN VERIFIED — All ${lines.length} events are cryptographically intact.\x1b[0m`);
    console.log(`  Genesis:  ${GENESIS_HASH}`);
    console.log(`  Tip:      ${expectedPrevHash.substring(0, 16)}…`);
    console.log(`  Algorithm: SHA-256 (canonical JSON, sort_keys=True)`);
    console.log();
    console.log(`\x1b[36mThis result was computed by an independent Node.js implementation,`);
    console.log(`separate from the Python verifier in app/cases/audit.py.\x1b[0m`);
    process.exit(0);
  } else {
    console.log(`\x1b[31m✗ CHAIN INVALID — ${violations.length} violation(s) detected.\x1b[0m`);
    for (const v of violations) {
      console.log(`  Entry #${v.index}: ${v.type} — ${v.detail}`);
    }
    process.exit(1);
  }
}

// CLI
const arg = process.argv[2];
if (!arg || arg === '--help' || arg === '-h') {
  console.log('Usage: node scripts/verify_chain.js <case_id_or_path>');
  console.log('  node scripts/verify_chain.js CASE-DEMO-2026');
  console.log('  node scripts/verify_chain.js data/audit/CASE-DEMO-2026.jsonl');
  process.exit(arg ? 0 : 1);
}

let filePath = arg;
if (!filePath.endsWith('.jsonl')) {
  const candidates = [
    path.join('data', 'audit', `${arg}.jsonl`),
    path.join(__dirname, '..', 'data', 'audit', `${arg}.jsonl`),
  ];
  filePath = candidates.find(p => fs.existsSync(p)) || candidates[0];
}

verifyChain(filePath);
