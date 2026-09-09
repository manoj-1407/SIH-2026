"""Temporal analysis for geospatial records."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Optional


ANCIENT_CUTOFF_YEAR = 1900
FUTURE_TOLERANCE_DAYS = 1
TEMPORAL_QUALIFICATION_DAYS = 365  # conflict spanning >1 year → temporally qualified


@dataclass
class TemporalResult:
    valid: bool
    qualified: bool       # True if temporal gap qualifies the conflict
    gap_days: Optional[float]
    reason: str


def parse_timestamp(ts: Optional[str]) -> Optional[datetime]:
    """Parse ISO 8601 timestamp. Returns None on any failure."""
    if not ts or not isinstance(ts, str):
        return None
    ts = ts.strip()
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt
    except (ValueError, AttributeError):
        return None


def validate_timestamp(ts_str: Optional[str]) -> tuple[bool, Optional[datetime], str]:
    """
    Validate a single timestamp string.
    Returns (valid, datetime_or_none, reason).
    Fails closed: missing/malformed/future/ancient → invalid.
    """
    if not ts_str:
        return False, None, "missing timestamp"

    dt = parse_timestamp(ts_str)
    if dt is None:
        return False, None, f"malformed timestamp: {ts_str!r}"

    now = datetime.now(timezone.utc)
    if dt > now + timedelta(days=FUTURE_TOLERANCE_DAYS):
        return False, None, f"future timestamp: {ts_str!r}"
    if dt.year < ANCIENT_CUTOFF_YEAR:
        return False, None, f"ancient timestamp (year {dt.year}): {ts_str!r}"

    return True, dt, "valid"


def analyze_temporal(ts_a: Optional[str], ts_b: Optional[str]) -> TemporalResult:
    """
    Analyze the temporal relationship between two records.
    Returns qualification status and gap.
    """
    ok_a, dt_a, reason_a = validate_timestamp(ts_a)
    ok_b, dt_b, reason_b = validate_timestamp(ts_b)

    if not ok_a and not ok_b:
        return TemporalResult(False, False, None, f"both timestamps invalid: {reason_a}; {reason_b}")
    if not ok_a:
        return TemporalResult(False, False, None, f"record A timestamp invalid: {reason_a}")
    if not ok_b:
        return TemporalResult(False, False, None, f"record B timestamp invalid: {reason_b}")

    gap = abs((dt_a - dt_b).total_seconds()) / 86400  # days

    if gap > TEMPORAL_QUALIFICATION_DAYS:
        return TemporalResult(
            True, True, round(gap, 2),
            f"temporal gap {gap:.0f} days > {TEMPORAL_QUALIFICATION_DAYS} days: qualifies as temporally qualified discrepancy",
        )
    return TemporalResult(True, False, round(gap, 2), f"temporal gap {gap:.1f} days: same-era conflict")
