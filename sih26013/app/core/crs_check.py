"""CRS and coordinate plausibility checking.

Gate ordering (most specific first, coarser conditions after):
  1. Impossible geographic extents (>90 lat / >180 lon)
  2. Degree/metre confusion (coordinates in likely-projected metre range)
  3. Axis-order suspicion (lat/lon swap heuristic, bbox-qualified)
  4. Plausibility warning (values in range but contextually implausible)

Note: The India geographic blind spot is real. Indias longitude range
is largely below 90E, so a simple >90 axis-swap heuristic will miss swaps.
bbox/contextual plausibility is therefore stronger than a universal threshold.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from shapely.geometry.base import BaseGeometry


@dataclass
class CRSCheckResult:
    ok: bool
    issue: str  # "" if ok
    category: str  # "NONE", "IMPOSSIBLE_EXTENT", "DEGREE_METRE_CONFUSION", "AXIS_ORDER", "PLAUSIBILITY"


# India approximate bbox (WGS84)
INDIA_LON_MIN, INDIA_LON_MAX = 67.0, 98.0
INDIA_LAT_MIN, INDIA_LAT_MAX = 6.0, 38.0

# Projected metre-range indicator: coordinates >> 360 are likely metres not degrees
METRE_RANGE_THRESHOLD = 1000.0


def _bounds(geom: BaseGeometry) -> tuple[float, float, float, float]:
    return geom.bounds  # (minx, miny, maxx, maxy)


def check_crs_plausibility(geom: BaseGeometry, declared_crs: str = "EPSG:4326") -> CRSCheckResult:
    """
    Check if geometry coordinates are plausible for the declared CRS.
    Applied BEFORE geometric comparison, after normalization attempt.
    """
    if declared_crs not in ("EPSG:4326", "WGS84", "urn:ogc:def:crs:EPSG::4326"):
        # Non-WGS84 CRS — we cannot plausibility-check in geographic terms
        return CRSCheckResult(True, "", "NONE")

    minx, miny, maxx, maxy = _bounds(geom)

    # Gate 1: Impossible geographic extents
    if abs(miny) > 90 or abs(maxy) > 90:
        return CRSCheckResult(
            False,
            f"latitude values outside valid range [-90,90]: miny={miny:.3f}, maxy={maxy:.3f}",
            "IMPOSSIBLE_EXTENT",
        )
    if abs(minx) > 180 or abs(maxx) > 180:
        return CRSCheckResult(
            False,
            f"longitude values outside valid range [-180,180]: minx={minx:.3f}, maxx={maxx:.3f}",
            "IMPOSSIBLE_EXTENT",
        )

    # Gate 2: Degree/metre confusion — coordinates implausibly large for degrees
    if max(abs(minx), abs(maxx), abs(miny), abs(maxy)) > METRE_RANGE_THRESHOLD:
        return CRSCheckResult(
            False,
            f"coordinate values >> 360 suggest projected metres declared as degrees: "
            f"range [{minx:.0f},{maxx:.0f}] x [{miny:.0f},{maxy:.0f}]",
            "DEGREE_METRE_CONFUSION",
        )

    # Gate 3: Axis-order suspicion — contextual (India-aware)
    # For India context: lat should be [6,38], lon should be [67,98]
    # If x-coords (supposed lon) look like latitudes and y-coords look like longitudes → swapped
    x_in_lat_range = INDIA_LAT_MIN <= minx <= INDIA_LAT_MAX and INDIA_LAT_MIN <= maxx <= INDIA_LAT_MAX
    y_in_lon_range = INDIA_LON_MIN <= miny <= INDIA_LON_MAX and INDIA_LON_MIN <= maxy <= INDIA_LON_MAX
    if x_in_lat_range and y_in_lon_range:
        return CRSCheckResult(
            False,
            f"coordinates suggest lat/lon axis swap (x={minx:.2f}-{maxx:.2f} looks like latitude, "
            f"y={miny:.2f}-{maxy:.2f} looks like Indian longitude)",
            "AXIS_ORDER",
        )

    # Gate 4: Plausibility warning — in range but implausible for Indian context
    # (e.g., ocean coords when dataset is supposed to be land parcels)
    # We emit a warning but do not fail — analytical engine decides severity
    if not (INDIA_LON_MIN - 10 <= minx and maxx <= INDIA_LON_MAX + 10 and
            INDIA_LAT_MIN - 10 <= miny and maxy <= INDIA_LAT_MAX + 10):
        return CRSCheckResult(
            True,  # not a hard failure
            f"coordinates outside India ±10° buffer: lon [{minx:.2f},{maxx:.2f}], lat [{miny:.2f},{maxy:.2f}]",
            "PLAUSIBILITY",
        )

    return CRSCheckResult(True, "", "NONE")
