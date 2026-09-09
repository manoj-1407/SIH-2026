"""
Atomic persistence primitive.
Rule: write temporary file -> flush -> fsync -> atomic rename.
Prevents torn reads/writes under concurrent operations.
Evidence packages are keyed by evidence_id, NOT case_id.
"""
import os
import re
import json
import tempfile
import time
from pathlib import Path
from typing import Any, List, Optional


class PersistenceError(Exception):
    pass


def atomic_write_bytes(dest_path: str | Path, data: bytes) -> None:
    dest = Path(dest_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    temp_fd, temp_path = tempfile.mkstemp(
        dir=dest.parent,
        prefix=f'.{dest.name}.tmp_',
    )
    try:
        with os.fdopen(temp_fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        # On Windows, os.replace can raise PermissionError (WinError 5 / WinError 32)
        # if destination is briefly locked during concurrent rename on NTFS.
        max_retries = 30
        for attempt in range(max_retries):
            try:
                os.replace(temp_path, dest)
                break
            except OSError as replace_err:
                if attempt == max_retries - 1:
                    raise
                time.sleep(0.005 * (attempt + 1))
    except Exception as e:
        if os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass
        raise PersistenceError(f'Atomic write failed for {dest}: {e}') from e


def atomic_write_json(dest_path: str | Path, data: Any) -> None:
    json_bytes = json.dumps(data, indent=2, sort_keys=True).encode('utf-8')
    atomic_write_bytes(dest_path, json_bytes)


def load_json(path: str | Path) -> dict:
    path = Path(path)
    if not path.exists():
        raise PersistenceError(f'File does not exist: {path}')
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        raise PersistenceError(f'Failed to load JSON from {path}: {e}') from e


def list_json_files(directory: str | Path) -> List[Path]:
    d = Path(directory)
    if not d.exists():
        return []
    return [p for p in d.iterdir() if p.is_file() and p.suffix == '.json' and not p.name.startswith('.')]


class EvidenceStore:
    """
    Evidence storage keyed strictly by evidence_id.
    Prevents multiple operations in the same case from overwriting evidence.
    """
    def __init__(self, evidence_dir: str | Path):
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, evidence_id: str) -> Path:
        if not evidence_id or not re.match(r'^[a-zA-Z0-9_\-]+$', str(evidence_id)):
            raise PersistenceError(f'Invalid evidence_id format: {evidence_id!r}')
        dest = (self.evidence_dir / f'{evidence_id}.json').resolve()
        if not dest.is_relative_to(self.evidence_dir.resolve()):
            raise PersistenceError(f'Path traversal in evidence_id: {evidence_id!r}')
        return dest

    def save(self, package: dict) -> str:
        evidence_id = package.get('evidence_id')
        if not evidence_id:
            raise PersistenceError("Package missing required 'evidence_id'")
        dest = self._path(evidence_id)
        atomic_write_json(dest, package)
        return str(dest)

    def get(self, evidence_id: str) -> dict:
        path = self._path(evidence_id)
        if not path.exists():
            raise PersistenceError(f'Evidence not found: {evidence_id}')
        return load_json(path)

    def list_all(self, case_id: Optional[str] = None) -> List[dict]:
        packages = []
        for p in list_json_files(self.evidence_dir):
            try:
                pkg = load_json(p)
                if case_id is None or pkg.get('case_id') == case_id:
                    packages.append(pkg)
            except PersistenceError:
                continue
        return sorted(packages, key=lambda x: x.get('created_at_utc', ''), reverse=True)

def load_bytes(path: str | Path) -> bytes:
    path = Path(path)
    if not path.exists():
        raise PersistenceError(f"File does not exist: {path}")
    try:
        with open(path, "rb") as f:
            return f.read()
    except Exception as e:
        raise PersistenceError(f"Failed to read bytes from {path}: {e}") from e
