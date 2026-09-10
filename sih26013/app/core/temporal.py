"""Temporal analysis for geospatial records — SIH26013.

Provides two layers of temporal reasoning:

1. timestamp_analysis: Validates and compares ISO 8601 timestamps on individual records,
   detecting future timestamps, ancient records, and temporal gaps that qualify a
   discrepancy as "temporally separated" rather than "concurrent conflict".

2. record_history_diff: When the same survey number appears in multiple records from
   different agencies or timestamps, computes a structured change vector:
     - Which attributes changed
     - Direction of change (e.g. AGRICULTURAL → COMMERCIAL)
     - Area delta
     - Temporal gap in days
   This replaces satellite/raster change detection with pure vector/attribute diffing
   on available land record data, which is accurate and appropriate for the PS scope.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any


ANCIENT_CUTOFF_YEAR = 1900
FUTURE_TOLERANCE_DAYS = 1
TEMPORAL_QUALIFICATION_DAYS = 365  # conflict spanning >1 year → temporally qualified


@dataclass
class TemporalResult:
    valid: bool
    qualified: bool       # True if temporal gap qualifies the conflict
    gap_days: Optional[float]
    reason: str


@dataclass
class AttributeChange:
    field: str
    old_value: Any
    new_value: Any
    change_type: str  # LAND_USE_CHANGE | AREA_DELTA | OWNER_CHANGE | BOUNDARY_SHIFT | OTHER


@dataclass
class RecordHistoryDiff:
    """
    Structured change vector between two records sharing the same survey number.

    This is a vector/attribute-level temporal change analysis — not raster/satellite
    imagery diffing. It surfaces what changed between departmental records over time.
    """
    survey_number: str
    record_a_id: str
    record_b_id: str
    timestamp_a: Optional[str]
    timestamp_b: Optional[str]
    gap_days: Optional[float]
    temporally_qualified: bool
    changes: List[AttributeChange]
    area_delta_sq_m: Optional[float]
    area_delta_pct: Optional[float]
    land_use_changed: bool
    owner_changed: bool
    geometry_changed: bool
    change_severity: str  # MINOR | MODERATE | MAJOR | CRITICAL
    summary: str

    def to_dict(self) -> dict:
        return {
            "survey_number": self.survey_number,
            "record_a_id": self.record_a_id,
            "record_b_id": self.record_b_id,
            "timestamp_a": self.timestamp_a,
            "timestamp_b": self.timestamp_b,
            "gap_days": self.gap_days,
            "temporally_qualified": self.temporally_qualified,
            "changes": [
                {
                    "field": c.field,
                    "old_value": c.old_value,
                    "new_value": c.new_value,
                    "change_type": c.change_type,
                }
                for c in self.changes
            ],
            "area_delta_sq_m": self.area_delta_sq_m,
            "area_delta_pct": self.area_delta_pct,
            "land_use_changed": self.land_use_changed,
            "owner_changed": self.owner_changed,
            "geometry_changed": self.geometry_changed,
            "change_severity": self.change_severity,
            "summary": self.summary,
        }


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


def diff_record_history(
    record_a: Dict[str, Any],
    record_b: Dict[str, Any],
    geometry_a: Optional[Dict] = None,
    geometry_b: Optional[Dict] = None,
) -> RecordHistoryDiff:
    """
    Compute a structured change vector between two land records.

    record_a and record_b are metadata dicts (typically from RecordInput.metadata)
    containing fields like: survey_number, area_sq_m, land_use, owner, etc.

    This performs vector/attribute-level temporal change analysis using the
    records actually ingested — no satellite imagery required.
    """
    survey_number = record_a.get("survey_number") or record_b.get("survey_number") or "UNKNOWN"
    rec_a_id = record_a.get("record_id", "record_A")
    rec_b_id = record_b.get("record_id", "record_B")
    ts_a = record_a.get("timestamp") or record_a.get("capture_timestamp")
    ts_b = record_b.get("timestamp") or record_b.get("capture_timestamp")

    temporal = analyze_temporal(ts_a, ts_b)
    changes: List[AttributeChange] = []

    # Land use change
    lu_a = str(record_a.get("land_use", "")).upper()
    lu_b = str(record_b.get("land_use", "")).upper()
    land_use_changed = bool(lu_a and lu_b and lu_a != lu_b)
    if land_use_changed:
        changes.append(AttributeChange(
            field="land_use",
            old_value=lu_a,
            new_value=lu_b,
            change_type="LAND_USE_CHANGE",
        ))

    # Area delta
    area_a = record_a.get("area_sq_m")
    area_b = record_b.get("area_sq_m")
    area_delta_sq_m: Optional[float] = None
    area_delta_pct: Optional[float] = None
    if isinstance(area_a, (int, float)) and isinstance(area_b, (int, float)) and area_a > 0:
        area_delta_sq_m = round(area_b - area_a, 2)
        area_delta_pct  = round(100 * (area_b - area_a) / area_a, 2)
        if abs(area_delta_pct) >= 1.0:
            changes.append(AttributeChange(
                field="area_sq_m",
                old_value=area_a,
                new_value=area_b,
                change_type="AREA_DELTA",
            ))

    # Owner change
    own_a = str(record_a.get("owner", "")).strip().lower()
    own_b = str(record_b.get("owner", "")).strip().lower()
    owner_changed = bool(own_a and own_b and own_a != own_b)
    if owner_changed:
        changes.append(AttributeChange(
            field="owner",
            old_value=record_a.get("owner"),
            new_value=record_b.get("owner"),
            change_type="OWNER_CHANGE",
        ))

    # Geometry changed — use IoU / Hausdorff style metrics, not centroid alone
    geometry_changed = False
    if geometry_a and geometry_b:
        try:
            from shapely.geometry import shape as shapely_shape
            from app.core.geometry import compare_geometries
            ga = shapely_shape(geometry_a)
            gb = shapely_shape(geometry_b)
            if ga is not None and gb is not None and not ga.is_empty and not gb.is_empty:
                cmp = compare_geometries(ga, gb)
                iou = cmp.measurements.get("iou") if cmp.measurements else None
                if iou is None:
                    iou = cmp.iou if cmp.iou >= 0 else None
                hd = cmp.measurements.get("hausdorff_m") if cmp.measurements else cmp.hausdorff_m
                hd = hd or 0.0
                # Material change: IoU drops below 0.98 or Hausdorff > ~2 m
                if (iou is not None and iou < 0.98) or hd > 2.0:
                    geometry_changed = True
                    changes.append(AttributeChange(
                        field="geometry",
                        old_value=f"iou={iou}",
                        new_value=f"hausdorff_m={hd}",
                        change_type="BOUNDARY_SHIFT",
                    ))
        except Exception:
            # Fallback: ring-mean centroid if shapely path fails
            try:
                coords_a = geometry_a.get("coordinates", [[]])[0]
                coords_b = geometry_b.get("coordinates", [[]])[0]
                if coords_a and coords_b:
                    # Exclude closing vertex if duplicated
                    a = coords_a[:-1] if len(coords_a) > 1 and coords_a[0] == coords_a[-1] else coords_a
                    b = coords_b[:-1] if len(coords_b) > 1 and coords_b[0] == coords_b[-1] else coords_b
                    cx_a = sum(c[0] for c in a) / len(a)
                    cy_a = sum(c[1] for c in a) / len(a)
                    cx_b = sum(c[0] for c in b) / len(b)
                    cy_b = sum(c[1] for c in b) / len(b)
                    shift_deg = ((cx_b - cx_a) ** 2 + (cy_b - cy_a) ** 2) ** 0.5
                    if shift_deg > 0.00001:
                        geometry_changed = True
                        changes.append(AttributeChange(
                            field="geometry_centroid",
                            old_value=f"{cx_a:.6f},{cy_a:.6f}",
                            new_value=f"{cx_b:.6f},{cy_b:.6f}",
                            change_type="BOUNDARY_SHIFT",
                        ))
            except (IndexError, TypeError, ZeroDivisionError):
                pass

    # Severity classification
    n_changes = len(changes)
    if land_use_changed and owner_changed:
        severity = "CRITICAL"
    elif land_use_changed or (area_delta_pct is not None and abs(area_delta_pct) > 5):
        severity = "MAJOR"
    elif n_changes >= 2:
        severity = "MODERATE"
    elif n_changes == 1:
        severity = "MINOR"
    else:
        severity = "MINOR"

    # Summary string
    parts = []
    if land_use_changed:
        parts.append(f"land use {lu_a}→{lu_b}")
    if area_delta_pct is not None and abs(area_delta_pct) >= 1.0:
        parts.append(f"area {area_delta_pct:+.1f}%")
    if owner_changed:
        parts.append("ownership change")
    if geometry_changed:
        parts.append("boundary shift")
    if temporal.gap_days:
        parts.append(f"temporal gap {temporal.gap_days:.0f} days")
    summary = (
        f"Survey {survey_number}: {'; '.join(parts) if parts else 'no significant attribute changes detected'}"
    )

    return RecordHistoryDiff(
        survey_number=survey_number,
        record_a_id=rec_a_id,
        record_b_id=rec_b_id,
        timestamp_a=ts_a,
        timestamp_b=ts_b,
        gap_days=temporal.gap_days,
        temporally_qualified=temporal.qualified,
        changes=changes,
        area_delta_sq_m=area_delta_sq_m,
        area_delta_pct=area_delta_pct,
        land_use_changed=land_use_changed,
        owner_changed=owner_changed,
        geometry_changed=geometry_changed,
        change_severity=severity,
        summary=summary,
    )
