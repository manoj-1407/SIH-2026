"""Case persistence — atomic writes, one JSON file per case."""
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
            case = self.get(case_id)
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
