"""Shared request-input validation for the API routers.

CASE_ID_PATTERN/validate_case_id used to be defined identically in both
cases.py and forensics.py (copy-pasted, not shared) and were missing
entirely from sanitization.py — meaning /cases/{case_id}/sanitize skipped
input validation that every other case-scoped endpoint had. A malformed
case_id there fell through to case_store.get(), which raises
CaseNotFoundError (not an HTTPException), which FastAPI turns into a bare
500 instead of a clean 400/404.
"""
import re
from fastapi import HTTPException

CASE_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]+$')


def validate_case_id(case_id: str):
    if not case_id or not CASE_ID_PATTERN.match(case_id):
        raise HTTPException(status_code=400, detail='Invalid case_id format')
