"""Case persistence — atomic writes, one JSON file per case."""
import shutil
import threading
import time
from pathlib import Path
from typing import List, Optional

from app.cases.models import Case, CaseStatus, WorkflowType, new_case_id
from app.core.persistence import atomic_write_json, load_json, list_json_files, PersistenceError


class CaseNotFoundError(Exception):
    pass


class CaseStore:
    def __init__(self, cases_dir: str | Path):
        self.cases_dir = Path(cases_dir)
        self.cases_dir.mkdir(parents=True, exist_ok=True)
        # Per-case locks guard the read -> mutate -> write cycle used by
        # update_acquisition/update_filesystem/record_operation_and_evidence.
        # Without this, two concurrent requests against the same case_id can
        # both read the same pre-mutation state and the second save() clobbers
        # the first — silently dropping operation_ids/evidence_ids. Confirmed
        # empirically: ~90% loss under 40 concurrent writers to one case
        # before this lock was added. Keyed by case_id (not a single global
        # lock) so unrelated cases are never serialized against each other.
        self._locks_guard = threading.Lock()
        self._case_locks: dict[str, threading.Lock] = {}

    def _lock_for(self, case_id: str) -> threading.Lock:
        with self._locks_guard:
            lock = self._case_locks.get(case_id)
            if lock is None:
                lock = threading.Lock()
                self._case_locks[case_id] = lock
            return lock

    def _path(self, case_id: str) -> Path:
        return self.cases_dir / f'{case_id}.json'

    def create(self, workflow: WorkflowType, title: str = '', description: str = '') -> Case:
        case = Case(
            case_id=new_case_id(),
            created_at=time.time(),
            status=CaseStatus.ACTIVE,
            workflow=workflow,
            title=title or f'{workflow.value} Case',
            description=description,
            updated_at=time.time(),
        )
        self.save(case)
        return case

    def save(self, case: Case) -> None:
        case.updated_at = time.time()
        atomic_write_json(self._path(case.case_id), case.to_dict())

    def get(self, case_id: str) -> Case:
        p = self._path(case_id)
        if not p.exists():
            raise CaseNotFoundError(f'Case not found: {case_id}')
        data = load_json(p)
        return Case.from_dict(data)

    def list_all(self) -> List[Case]:
        cases = []
        for p in list_json_files(self.cases_dir):
            try:
                data = load_json(p)
                cases.append(Case.from_dict(data))
            except Exception:
                continue
        return sorted(cases, key=lambda c: c.created_at, reverse=True)

    def update_acquisition(
        self,
        case_id: str,
        acquisition_id: str,
        source_path: str,
        sha256: str,
        size_bytes: int,
    ) -> Case:
        with self._lock_for(case_id):
            case = self.get(case_id)
            case.acquisition_id = acquisition_id
            case.source_path = source_path
            case.acquisition_timestamp = time.time()
            case.input_sha256 = sha256
            case.input_size_bytes = size_bytes
            self.save(case)
            return case

    def update_filesystem(self, case_id: str, fs_capability: dict) -> Case:
        with self._lock_for(case_id):
            case = self.get(case_id)
            case.filesystem = fs_capability
            self.save(case)
            return case

    def record_operation_and_evidence(
        self,
        case_id: str,
        operation_id: str,
        evidence_id: str,
        operation_type: str,
        result_data: dict,
    ) -> Case:
        with self._lock_for(case_id):
            try:
                case = self.get(case_id)
            except CaseNotFoundError:
                case = Case(
                    case_id=case_id,
                    created_at=time.time(),
                    status=CaseStatus.ACTIVE,
                    workflow=WorkflowType.FORENSIC,
                    title=f'Auto-created {case_id}',
                    description='Auto-created to capture an operation and evidence trail.',
                    updated_at=time.time(),
                )
                self.save(case)
            if operation_id not in case.operation_ids:
                case.operation_ids.append(operation_id)
            if evidence_id not in case.evidence_ids:
                case.evidence_ids.append(evidence_id)

            if operation_type == 'FORENSIC':
                case.latest_forensic_result = result_data
            elif operation_type == 'SANITIZATION':
                case.latest_sanitization_result = result_data

            self.save(case)
            return case


class CaseDemoSnapshot:
    def __init__(self, cases_dir: str | Path, evidence_dir: str | Path, audit_dir: str | Path, backup_dir: str | Path):
        self.cases_dir = Path(cases_dir)
        self.evidence_dir = Path(evidence_dir)
        self.audit_dir = Path(audit_dir)
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self._lock_guard = threading.Lock()
        self._case_locks: dict[str, threading.Lock] = {}

    def _lock_for(self, case_id: str) -> threading.Lock:
        with self._lock_guard:
            lock = self._case_locks.get(case_id)
            if lock is None:
                lock = threading.Lock()
                self._case_locks[case_id] = lock
            return lock

    def _case_backup_dir(self, case_id: str) -> Path:
        return self.backup_dir / case_id

    def _evidence_ids_for_case(self, case_id: str) -> list[str]:
        ids: list[str] = []
        for p in list_json_files(self.evidence_dir):
            try:
                pkg = load_json(p)
                if pkg.get('case_id') == case_id:
                    ids.append(p.stem)
            except PersistenceError:
                continue
        return ids

    def has_snapshot(self, case_id: str) -> bool:
        return self._case_backup_dir(case_id).is_dir()

    def create_snapshot(self, case_id: str) -> bool:
        with self._lock_for(case_id):
            backup = self._case_backup_dir(case_id)
            if backup.is_dir():
                shutil.rmtree(backup)
            backup.mkdir(parents=True, exist_ok=True)

            (backup / 'cases').mkdir(exist_ok=True)
            (backup / 'evidence').mkdir(exist_ok=True)
            (backup / 'audit').mkdir(exist_ok=True)

            case_src = self.cases_dir / f'{case_id}.json'
            if case_src.exists():
                shutil.copy2(case_src, backup / 'cases' / f'{case_id}.json')

            audit_src = self.audit_dir / f'{case_id}.jsonl'
            if audit_src.exists():
                shutil.copy2(audit_src, backup / 'audit' / f'{case_id}.jsonl')

            for evid in self._evidence_ids_for_case(case_id):
                src = self.evidence_dir / f'{evid}.json'
                if src.exists():
                    shutil.copy2(src, backup / 'evidence' / f'{evid}.json')

            return True

    def restore_snapshot(self, case_id: str) -> bool:
        with self._lock_for(case_id):
            backup = self._case_backup_dir(case_id)
            if not backup.is_dir():
                return False

            case_backup = backup / 'cases' / f'{case_id}.json'
            if case_backup.exists():
                dest = self.cases_dir / f'{case_id}.json'
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(case_backup, dest)

            audit_backup = backup / 'audit' / f'{case_id}.jsonl'
            dest_audit = self.audit_dir / f'{case_id}.jsonl'
            dest_audit.parent.mkdir(parents=True, exist_ok=True)
            if audit_backup.exists():
                shutil.copy2(audit_backup, dest_audit)
            elif dest_audit.exists():
                dest_audit.unlink()

            for evid_p in (backup / 'evidence').glob('*.json'):
                dest = self.evidence_dir / evid_p.name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(evid_p, dest)

            shutil.rmtree(backup)
            return True
