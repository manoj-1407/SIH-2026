"""Case models, lifecycle, and capability support."""
import uuid
import time
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Any, List, Dict, Optional


class CaseStatus(str, Enum):
    ACTIVE = 'ACTIVE'
    COMPLETED = 'COMPLETED'
    ARCHIVED = 'ARCHIVED'


class WorkflowType(str, Enum):
    FORENSIC = 'FORENSIC'
    SANITIZATION = 'SANITIZATION'


@dataclass
class Case:
    case_id: str
    created_at: float
    status: CaseStatus
    workflow: WorkflowType
    title: str = ''
    description: str = ''

    # Acquisition
    source_path: str = ''
    acquisition_id: str = ''
    acquisition_timestamp: float = 0.0
    input_sha256: str = ''
    input_size_bytes: int = 0

    # Filesystem capability model
    filesystem: dict = field(default_factory=lambda: {
        'detected_type': '',
        'detected': False,
        'recovery_supported': False,
        'sanitization_supported': False,
        'details': {},
    })

    # Discovered artifacts
    discovered_artifacts: list = field(default_factory=list)

    # Operations & Evidence Tracking (Distinct identities!)
    operation_ids: list = field(default_factory=list)
    evidence_ids: list = field(default_factory=list)

    # Last executed recovery or sanitization result
    latest_forensic_result: dict = field(default_factory=dict)
    latest_sanitization_result: dict = field(default_factory=dict)

    updated_at: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d['status'] = self.status.value
        d['workflow'] = self.workflow.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> 'Case':
        d = dict(d)
        d['status'] = CaseStatus(d['status'])
        d['workflow'] = WorkflowType(d['workflow'])
        return cls(**d)


def new_case_id() -> str:
    return f'CASE-{uuid.uuid4().hex[:8].upper()}'
