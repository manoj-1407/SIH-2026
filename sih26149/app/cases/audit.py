"""
Chain-of-Custody Timeline & Audit Trail — SIH26149

UPGRADED: Cryptographically hash-chained append-only JSONL audit log.

Every audit entry is linked to the previous entry via its SHA-256 hash,
forming an immutable chain. Any post-hoc modification of any entry is
instantly detectable by re-computing the chain from entry 0.

Chain structure per entry:
  entry_index    — Sequential position in the chain (0-based)
  previous_hash  — SHA-256 of the previous entry's canonical JSON (or
                   'GENESIS' for the first entry)
  entry_hash     — SHA-256 of this entry's canonical JSON (excludes entry_hash field)
  + all existing fields (timestamp, event_type, actor, details, ...)

Verification:
  verify_chain(case_id) → (bool, list_of_violations)
  demo_tamper_chain(case_id, index, field, value) → demonstrates instant detection

NOTE: Canonical serialization uses app.core.canonical.canonicalize()
      (RFC 8785 JCS — byte-identical between audit.py and independent_verifier.py).
      Parity is enforced by test: tests/unit/test_audit_canonical_parity.py
"""
import os
import json
import time
import hashlib
import datetime
import threading
from pathlib import Path
from typing import List, Optional, Tuple

from app.core.canonical import canonicalize


_GENESIS_HASH = "GENESIS"


def _canonical_json(entry: dict) -> bytes:
    """RFC 8785 JCS canonical serialization for audit chain hashing.

    Byte-identical to app.core.canonical.canonicalize() used by the
    independent third-party verifier (app.core.independent_verifier).
    Excludes the 'entry_hash' field itself (it can't be part of its own hash).
    """
    sanitized = {k: v for k, v in entry.items() if k != "entry_hash"}
    return canonicalize(sanitized)


def _sha256_entry(entry: dict) -> str:
    return hashlib.sha256(_canonical_json(entry)).hexdigest()


class AuditLogger:
    def __init__(self, audit_dir: str | Path):
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self._locks_guard = threading.Lock()
        self._case_locks: dict[str, threading.Lock] = {}

    def _lock_for(self, case_id: str) -> threading.Lock:
        with self._locks_guard:
            lock = self._case_locks.get(case_id)
            if lock is None:
                lock = threading.Lock()
                self._case_locks[case_id] = lock
            return lock

    def _log_path(self, case_id: str) -> Path:
        return self.audit_dir / f'{case_id}.jsonl'

    def _get_last_entry_hash(self, case_id: str) -> Tuple[str, int]:
        """Return (last_entry_hash, next_entry_index) for chain continuation."""
        p = self._log_path(case_id)
        if not p.exists():
            return _GENESIS_HASH, 0

        last_hash = _GENESIS_HASH
        count = 0
        try:
            with open(p, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entry = json.loads(line)
                            last_hash = entry.get('entry_hash', _sha256_entry(entry))
                            count += 1
                        except json.JSONDecodeError:
                            continue
        except OSError:
            pass
        return last_hash, count

    def log(
        self,
        case_id: str,
        event_type: str,
        actor: str = 'SYSTEM',
        details: Optional[dict] = None,
        operation_id: Optional[str] = None,
        evidence_id: Optional[str] = None,
        hash_ref: Optional[str] = None,
    ) -> dict:
        """Append a hash-chained audit event to the case timeline."""
        now = time.time()
        iso = datetime.datetime.fromtimestamp(now, datetime.timezone.utc).isoformat()

        with self._lock_for(case_id):
            previous_hash, entry_index = self._get_last_entry_hash(case_id)

            entry = {
                'entry_index': entry_index,
                'previous_hash': previous_hash,
                'timestamp': now,
                'iso_time': iso,
                'event_type': event_type,
                'case_id': case_id,
                'operation_id': operation_id or '',
                'evidence_id': evidence_id or '',
                'actor': actor,
                'details': details or {},
                'hash_ref': hash_ref or '',
            }
            # Compute and embed the entry's own hash AFTER all fields are set
            entry['entry_hash'] = _sha256_entry(entry)

            line = json.dumps(entry) + '\n'
            with open(self._log_path(case_id), 'a', encoding='utf-8') as f:
                f.write(line)

        return entry

    def get_timeline(self, case_id: str) -> List[dict]:
        """Retrieve the chronological chain-of-custody timeline."""
        p = self._log_path(case_id)
        if not p.exists():
            return []
        events = []
        with open(p, 'r', encoding='utf-8') as f:
            for line_idx, line in enumerate(f):
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        events.append({
                            'entry_index': line_idx,
                            'malformed': True,
                            'raw_content': line,
                        })
        return sorted(events, key=lambda x: x.get('entry_index', x.get('timestamp', 0)))

    def verify_chain(self, case_id: str) -> Tuple[bool, List[dict]]:
        """
        Verify the integrity of the entire audit chain for a case.

        Returns (is_valid, violations).
        violations is a list of dicts describing any detected chain breaks.
        """
        events = self.get_timeline(case_id)
        if not events:
            return True, []

        violations = []
        expected_previous = _GENESIS_HASH

        for i, entry in enumerate(events):
            idx = entry.get('entry_index', i)
            if entry.get('malformed'):
                violations.append({
                    'entry_index': idx,
                    'violation': 'MALFORMED_RECORD',
                    'explanation': f"Entry {idx} contains corrupted/unparseable JSON in audit log."
                })
                continue

            stored_hash = entry.get('entry_hash')
            stored_prev = entry.get('previous_hash', _GENESIS_HASH)

            # 1. Check previous_hash linkage
            if stored_prev != expected_previous:
                violations.append({
                    'entry_index': idx,
                    'violation': 'CHAIN_BREAK',
                    'expected_previous_hash': expected_previous[:16] + '…',
                    'found_previous_hash': (stored_prev or '')[:16] + '…',
                    'explanation': f"Entry {idx} previous_hash does not match entry {i-1} entry_hash — chain broken."
                })

            # 2. Verify this entry's own hash
            if stored_hash:
                computed = _sha256_entry(entry)
                if computed != stored_hash:
                    violations.append({
                        'entry_index': idx,
                        'violation': 'ENTRY_TAMPERED',
                        'stored_hash': stored_hash[:16] + '…',
                        'computed_hash': computed[:16] + '…',
                        'explanation': f"Entry {idx} content has been modified — stored hash does not match recomputed hash."
                    })
            else:
                violations.append({
                    'entry_index': idx,
                    'violation': 'MISSING_HASH',
                    'explanation': f"Entry {idx} is missing entry_hash field — predates hash-chaining or was stripped."
                })

            # Advance expected
            expected_previous = stored_hash or _sha256_entry(entry)

        return len(violations) == 0, violations

    def demo_tamper_chain(
        self,
        case_id: str,
        entry_index: int,
        field: str,
        new_value: str,
    ) -> dict:
        """
        [DEMO ONLY] Simulate an adversarial modification of an audit entry.
        Reads the chain, modifies one field in one entry, writes it back,
        then runs verify_chain to demonstrate instant detection.

        Returns a result showing tamper was detected.
        """
        p = self._log_path(case_id)
        if not p.exists():
            return {'error': 'No audit log for this case'}

        lines = p.read_text(encoding='utf-8').splitlines()
        if entry_index >= len(lines):
            return {'error': f'entry_index {entry_index} out of range ({len(lines)} entries)'}

        target_line = lines[entry_index]
        try:
            entry = json.loads(target_line)
        except json.JSONDecodeError:
            return {'error': 'Failed to parse target entry'}

        original_value = entry.get(field, '<not_present>')
        entry[field] = new_value
        lines[entry_index] = json.dumps(entry)

        # Write tampered log
        p.write_text('\n'.join(lines) + '\n', encoding='utf-8')

        # Verify — should detect tamper
        is_valid, violations = self.verify_chain(case_id)

        # Restore original
        entry[field] = original_value
        lines[entry_index] = target_line
        p.write_text('\n'.join(lines) + '\n', encoding='utf-8')

        return {
            'tampered_entry_index': entry_index,
            'field': field,
            'tampered_field': field,
            'original_value': original_value,
            'injected_value': new_value,
            'chain_valid_after_tamper': is_valid,
            'tamper_detected': not is_valid,
            'violations': violations,
            'classification': 'INVALID' if not is_valid else 'VERIFIED',
            'explanation': (
                "Tamper detected — SHA-256 chain integrity failed." if not is_valid
                else "⚠ Tamper NOT detected (unexpected — check chain implementation)."
            ),
            'tampered_verification': {
                'chain_valid': is_valid,
                'valid': is_valid,
                'reason': (
                    "Tamper detected — SHA-256 chain integrity failed." if not is_valid
                    else "⚠ Tamper NOT detected (unexpected — check chain implementation)."
                ),
                'violations': violations,
            },
        }

    def apply_permanent_audit_tamper(self, case_id: str) -> dict:
        """
        [ADVERSARIAL DEMO ONLY] Permanently tamper with audit chain near the end.
        DOES NOT restore. Caller is responsible for snapshot backup/restore.

        Strategy:
        - If chain has >= 2 events: pick second-to-last entry (so it has a NEXT entry)
        - Modify operation_result (or fallback field) by flipping case
        - Recompute entry_hash of THIS tampered entry
        - Do NOT update next entry's previous_hash -> chain linkage broken
        Returns event_id, tampered entry_index, etc.
        """
        with self._lock_for(case_id):
            p = self._log_path(case_id)
            if not p.exists():
                return {'error': 'No audit log for this case'}

            lines = p.read_text(encoding='utf-8').splitlines()
            entries: list[dict] = []
            for line in lines:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        return {'error': 'Malformed audit log entry'}

            n = len(entries)
            if n == 0:
                return {'error': 'No audit events for this case'}

            target_idx = n - 2 if n >= 2 else 0
            entry = entries[target_idx]

            details = entry.get('details') or {}
            op_result = None
            field_path = None
            if 'operation_result' in details and isinstance(details['operation_result'], str):
                op_result = details['operation_result']
                field_path = ('details', 'operation_result')
            elif 'operation_result' in entry and isinstance(entry['operation_result'], str):
                op_result = entry['operation_result']
                field_path = ('operation_result',)
            elif 'event_type' in entry and isinstance(entry['event_type'], str):
                op_result = entry['event_type']
                field_path = ('event_type',)
            elif isinstance(entry.get('actor'), str):
                op_result = entry['actor']
                field_path = ('actor',)

            if op_result is None:
                return {'error': 'No suitable string field found for tamper'}

            if op_result.islower():
                flipped = op_result.upper()
            elif op_result.isupper():
                flipped = op_result.lower()
            else:
                flipped = op_result.swapcase()

            if field_path == ('details', 'operation_result'):
                entry['details']['operation_result'] = flipped
            else:
                entry[field_path[0]] = flipped

            entry['entry_hash'] = _sha256_entry(entry)
            entries[target_idx] = entry

            new_lines = [json.dumps(e) for e in entries]
            p.write_text('\n'.join(new_lines) + '\n', encoding='utf-8')

            _, violations = self.verify_chain(case_id)

            return {
                'tampered': True,
                'event_id': f'{case_id}-{target_idx}',
                'entry_index': target_idx,
                'field': '.'.join(field_path),
                'original_value': op_result,
                'tampered_value': flipped,
                'description': 'Modified operation_result field of last event; next_event.previous_hash no longer matches',
                'violations': violations,
            }
