"""Geometry validation, normalization, and comparison.
Implements: GeoJSON validation, CRS normalization to WGS84, IoU, Hausdorff.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Optional
import math

from shapely.geometry import shape as shapely_shape, mapping as shapely_mapping
from shapely.geometry.base import BaseGeometry
from shapely.validation import make_valid
import pyproj
from pyproj import Transformer


SUPPORTED_GEOMETRY_TYPES = {
    "Point", "MultiPoint", "LineString", "MultiLineString",
    "Polygon", "MultiPolygon", "GeometryCollection",
}


@dataclass
class GeometryValidationResult:
    valid: bool
    reason: str = ""
    geometry: Optional[BaseGeometry] = None


@dataclass
class ComparisonResult:
    iou: float                  # Intersection-over-Union (0-1), -1 if not polygon
    hausdorff_m: float          # Hausdorff distance in metres at WGS84 centroid
    conflict: bool              # True if geometries meaningfully differ
    reason: str = ""
    measurements: dict = field(default_factory=dict)


def validate_geojson_geometry(geom_dict: Any) -> GeometryValidationResult:
    """Validate a GeoJSON geometry dict."""
    if not isinstance(geom_dict, dict):
        return GeometryValidationResult(False, "geometry must be a JSON object")
    gtype = geom_dict.get("type")
    if gtype not in SUPPORTED_GEOMETRY_TYPES:
        return GeometryValidationResult(False, f"unsupported geometry type: {gtype!r}")
    coords = geom_dict.get("coordinates")
    if gtype != "GeometryCollection" and coords is None:
        return GeometryValidationResult(False, "missing coordinates")
    if gtype == "GeometryCollection":
        # GeometryCollection uses `geometries`, not `coordinates` — the
        # check above doesn't apply to it, so an empty/missing collection
        # would otherwise reach shapely, parse as an empty geometry, and
        # come back as the generic "empty geometry" error below. That's
        # technically true but misleading in a forensic context: the real
        # issue is "empty geometry collection with no sub-geometries", not
        # an ordinary empty geometry, so name it explicitly.
        sub_geoms = geom_dict.get("geometries")
        if not sub_geoms:
            return GeometryValidationResult(False, "empty geometry collection with no sub-geometries")
    try:
        geom = shapely_shape(geom_dict)
    except Exception as e:
        return GeometryValidationResult(False, f"shapely parse error: {e}")
    if geom.is_empty:
        return GeometryValidationResult(False, "empty geometry")
    if not geom.is_valid:
        fixed = make_valid(geom)
        if fixed.is_empty:
            return GeometryValidationResult(False, "invalid and unfixable geometry")
        geom = fixed
    return GeometryValidationResult(True, "valid", geom)


def normalize_to_wgs84(geom: BaseGeometry, source_crs: str = "EPSG:4326") -> BaseGeometry:
    """Reproject geometry to WGS84. No-op if already EPSG:4326."""
    if source_crs in ("EPSG:4326", "WGS84", "urn:ogc:def:crs:EPSG::4326"):
        return geom
    transformer = Transformer.from_crs(source_crs, "EPSG:4326", always_xy=True)
    from shapely.ops import transform
    return transform(transformer.transform, geom)


def compute_iou(geom_a: BaseGeometry, geom_b: BaseGeometry) -> float:
    """Compute Intersection-over-Union. Returns -1 for non-polygon types."""
    if geom_a.geom_type not in ("Polygon", "MultiPolygon") or        geom_b.geom_type not in ("Polygon", "MultiPolygon"):
        return -1.0
    try:
        inter = geom_a.intersection(geom_b).area
        union = geom_a.union(geom_b).area
        if union == 0:
            return 1.0 if inter == 0 else 0.0
        return inter / union
    except Exception:
        return 0.0


def _centroid_metres_per_degree(geom: BaseGeometry) -> tuple[float, float]:
    """Approximate metres-per-degree at centroid latitude."""
    lat = geom.centroid.y
    return _metres_per_degree_at_lat(lat)


def _metres_per_degree_at_lat(lat: float) -> tuple[float, float]:
    lat_rad = math.radians(lat)
    m_per_deg_lat = 111132.92 - 559.82 * math.cos(2 * lat_rad) + 1.175 * math.cos(4 * lat_rad)
    m_per_deg_lon = 111412.84 * math.cos(lat_rad) - 93.5 * math.cos(3 * lat_rad)
    return m_per_deg_lat, m_per_deg_lon


def compute_hausdorff_metres(geom_a: BaseGeometry, geom_b: BaseGeometry) -> float:
    """Approximate Hausdorff distance in metres using a shared scale factor.

    The scale factor (metres-per-degree) varies with latitude, so it must be
    computed at a latitude representative of BOTH geometries — not geom_a
    alone. Using only geom_a's centroid under-/over-states distance whenever
    geom_b sits at a meaningfully different latitude: for two geometries
    ~25 degrees apart in latitude (e.g. south vs. north India), the scale
    factor differs by roughly 5%, which miscalibrates the metre-based
    conflict threshold. Using the midpoint of both centroids' latitudes is a
    reasonable single-scalar approximation without switching to a full
    metric-CRS reprojection.
    """
    try:
        hd_deg = geom_a.hausdorff_distance(geom_b)
        mid_lat = (geom_a.centroid.y + geom_b.centroid.y) / 2
        m_lat, m_lon = _metres_per_degree_at_lat(mid_lat)
        # Use average scale factor as approximation
        scale = (m_lat + m_lon) / 2
        return hd_deg * scale
    except Exception:
        return float("inf")
        return hd_deg * scale
    except Exception:
        return float("inf")


# Conflict thresholds
IOU_CONFLICT_THRESHOLD = 0.95   # IoU below this = potential conflict
HAUSDORFF_NOISE_M = 5.0         # Below this = measurement noise, not conflict
HAUSDORFF_CONFLICT_M = 50.0     # Above this = definite conflict


def compare_geometries(
    geom_a: BaseGeometry,
    geom_b: BaseGeometry,
    iou_threshold: float = IOU_CONFLICT_THRESHOLD,
    hausdorff_noise_m: float = HAUSDORFF_NOISE_M,
    hausdorff_conflict_m: float = HAUSDORFF_CONFLICT_M,
) -> ComparisonResult:
    """Compare two WGS84 geometries. Returns conflict status with measurements."""
    iou = compute_iou(geom_a, geom_b)
    hausdorff_m = compute_hausdorff_metres(geom_a, geom_b)

    measurements = {
        "iou": round(iou, 6) if iou >= 0 else None,
        "hausdorff_m": round(hausdorff_m, 3),
        "iou_threshold": iou_threshold,
        "hausdorff_noise_m": hausdorff_noise_m,
        "hausdorff_conflict_m": hausdorff_conflict_m,
    }

    # Non-polygon: use Hausdorff only
    if iou < 0:
        if hausdorff_m <= hausdorff_noise_m:
            return ComparisonResult(iou, hausdorff_m, False, "within noise tolerance", measurements)
        if hausdorff_m >= hausdorff_conflict_m:
            return ComparisonResult(iou, hausdorff_m, True, "Hausdorff boundary conflict", measurements)
        return ComparisonResult(iou, hausdorff_m, False, "minor boundary difference", measurements)

    # Polygon: IoU + Hausdorff
    iou_conflict = iou < iou_threshold
    hd_conflict = hausdorff_m >= hausdorff_conflict_m
    hd_noise = hausdorff_m < hausdorff_noise_m

    if hd_noise and not iou_conflict:
        return ComparisonResult(iou, hausdorff_m, False, "within noise tolerance", measurements)
    if iou_conflict or hd_conflict:
        return ComparisonResult(iou, hausdorff_m, True,
                                f"geometric conflict (IoU={iou:.3f}, Hausdorff={hausdorff_m:.1f}m)", measurements)
    return ComparisonResult(iou, hausdorff_m, False, "no significant geometric difference", measurements)
