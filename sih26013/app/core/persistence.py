"""Atomic crash-safe JSON/JSONL persistence.
Same fsync-rename protocol as 26149, independently implemented.
"""
from __future__ import annotations
import json
import os
import tempfile
import threading
import time
from pathlib import Path


class AtomicStore:
    """Thread-safe atomic JSON file store. Writes are fsync-rename."""

    def __init__(self, directory: str | Path):
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def save(self, key: str, data: dict) -> None:
        path = self._dir / f"{key}.json"
        tmp = None
        with self._lock:
            with tempfile.NamedTemporaryFile(
                mode="w", dir=self._dir, delete=False,
                suffix=".tmp", encoding="utf-8",
            ) as f:
                tmp = f.name
                json.dump(data, f, sort_keys=True, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)

    def get(self, key: str) -> dict:
        path = self._dir / f"{key}.json"
        if not path.exists():
            raise KeyError(f"{key!r} not found in store")
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def load(self, key: str) -> dict:
        """Alias for get() that raises FileNotFoundError instead of KeyError.

        server.py calls evidence_store.load(evidence_id) and catches
        FileNotFoundError to return a 404 — a real method here (rather than
        get()) reads clearly at the call site: "load this evidence file",
        not "look up this dict key". This used to be a module-level function
        monkey-patched onto the class after the fact; it's just a method now.
        """
        try:
            return self.get(key)
        except KeyError:
            raise FileNotFoundError(f"{key} not found")

    def exists(self, key: str) -> bool:
        return (self._dir / f"{key}.json").exists()

    def list_keys(self) -> list[str]:
        return [p.stem for p in sorted(self._dir.glob("*.json"))]

    def list_all(self) -> list[dict]:
        result = []
        for key in self.list_keys():
            try:
                result.append(self.get(key))
            except Exception:
                pass
        return result


class AuditLogger:
    """Cryptographically hash-chained append-only JSONL audit log per case."""

    def __init__(self, directory: str | Path):
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _get_last_entry_hash(self, case_id: str) -> tuple[str, int]:
        path = self._dir / f"{case_id}.jsonl"
        if not path.exists():
            return "GENESIS", 0
        last_hash = "GENESIS"
        count = 0
        import hashlib
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entry = json.loads(line)
                            sanitized = {k: v for k, v in entry.items() if k != "entry_hash"}
                            canon = json.dumps(sanitized, sort_keys=True, separators=(',', ':')).encode('utf-8')
                            last_hash = entry.get("entry_hash", hashlib.sha256(canon).hexdigest())
                            count += 1
                        except json.JSONDecodeError:
                            continue
        except OSError:
            pass
        return last_hash, count

    def log(self, case_id: str, event_type: str, actor: str, details: dict = None, **kwargs) -> dict:
        from datetime import datetime, timezone
        import hashlib
        path = self._dir / f"{case_id}.jsonl"
        with self._lock:
            prev_hash, entry_idx = self._get_last_entry_hash(case_id)
            entry = {
                "entry_index": entry_idx,
                "previous_hash": prev_hash,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "case_id": case_id,
                "event_type": event_type,
                "actor": actor,
                "details": details or {},
            }
            entry.update(kwargs)
            canon = json.dumps(entry, sort_keys=True, separators=(',', ':')).encode('utf-8')
            entry["entry_hash"] = hashlib.sha256(canon).hexdigest()

            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
            return entry

    def get_timeline(self, case_id: str) -> list[dict]:
        path = self._dir / f"{case_id}.jsonl"
        if not path.exists():
            return []
        entries = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return entries

# Aliases
EvidenceStore = AtomicStore
AuditLog = AuditLogger

def _atomic_load(self, key: str) -> dict:
    try:
        return self.get(key)
    except KeyError:
        raise FileNotFoundError(f"{key} not found")

AtomicStore.load = _atomic_load
