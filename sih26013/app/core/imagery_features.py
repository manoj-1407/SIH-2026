"""
Drone Imagery & Building Footprint Integration — SIH26013

Analyzes photogrammetric/orthomosaic features (ORI, DSM/DTM extracted footprints)
against cadastral boundary geometry to detect:
  1. Encroachment across legal parcel boundaries onto roads or adjacent plots
  2. Unrecorded construction on agricultural/vacant revenue plots
  3. Ground-truth building coverage ratio (FSI / Built-up footprint)
"""
import math
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict

from shapely.geometry import shape as shapely_shape, mapping as shapely_mapping
from shapely.geometry.base import BaseGeometry

from app.core.canonical_model import CanonicalParcel, LandUseType
from app.core.geometry import _centroid_metres_per_degree


@dataclass
class BuildingFootprint:
    footprint_id: str
    geometry: Dict[str, Any]      # GeoJSON Polygon
    area_sq_m: float
    height_m: Optional[float] = None
    capture_source: str = "DRONE_ORTHOMOSAIC_ORI"
    estimated_floors: int = 1


@dataclass
class EncroachmentFinding:
    footprint_id: str
    parcel_id: str
    encroached_area_sq_m: float
    encroachment_ratio: float     # Percentage of building outside legal boundary
    encroaching_geometry: Dict[str, Any]
    severity: str                 # MINOR, SIGNIFICANT, SEVERE
    description: str


@dataclass
class ImageryAnalysisResult:
    parcel_id: str
    total_built_up_area_sq_m: float
    coverage_ratio: float         # Built area / Parcel area
    building_count: int
    encroachments: List[EncroachmentFinding]
    unrecorded_construction: bool
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "parcel_id": self.parcel_id,
            "total_built_up_area_sq_m": round(self.total_built_up_area_sq_m, 2),
            "coverage_ratio": round(self.coverage_ratio, 4),
            "building_count": self.building_count,
            "encroachments": [asdict(e) for e in self.encroachments],
            "unrecorded_construction": self.unrecorded_construction,
            "summary": self.summary,
        }


def _approx_sq_meters(geom: BaseGeometry) -> float:
    """Approximate area in square meters for WGS84 geometry."""
    m_lat, m_lon = _centroid_metres_per_degree(geom)
    scale = m_lat * m_lon
    return geom.area * scale


def analyze_drone_footprints(
    parcel: CanonicalParcel,
    footprints: List[BuildingFootprint],
) -> ImageryAnalysisResult:
    """
    Analyze high-resolution drone-extracted building footprints against a parcel.
    """
    parcel_shape = shapely_shape(parcel.geometry)
    m_lat, m_lon = _centroid_metres_per_degree(parcel_shape)
    scale = m_lat * m_lon

    total_built_sq_m = 0.0
    encroachment_findings = []
    intersecting_count = 0

    for fp in footprints:
        fp_shape = shapely_shape(fp.geometry)
        if not fp_shape.intersects(parcel_shape):
            continue

        intersecting_count += 1
        fp_area_sq_m = fp.area_sq_m or _approx_sq_meters(fp_shape)
        total_built_sq_m += fp_area_sq_m

        # Check encroachment: portion of building footprint outside the parcel
        outside_geom = fp_shape.difference(parcel_shape)
        if outside_geom and not outside_geom.is_empty and outside_geom.area > 0:
            encr_area_sq_m = _approx_sq_meters(outside_geom)
            ratio = encr_area_sq_m / max(0.1, fp_area_sq_m)

            # Minimum 2.0 sq meters to filter boundary digitization noise
            if encr_area_sq_m >= 2.0:
                if ratio > 0.25:
                    severity = "SEVERE"
                elif ratio > 0.10:
                    severity = "SIGNIFICANT"
                else:
                    severity = "MINOR"

                encroachment_findings.append(EncroachmentFinding(
                    footprint_id=fp.footprint_id,
                    parcel_id=parcel.parcel_id,
                    encroached_area_sq_m=round(encr_area_sq_m, 2),
                    encroachment_ratio=round(ratio, 3),
                    encroaching_geometry=shapely_mapping(outside_geom),
                    severity=severity,
                    description=(
                        f"Building {fp.footprint_id} extends {encr_area_sq_m:.1f} m² "
                        f"({ratio*100:.1f}%) outside parcel {parcel.survey_number} boundary."
                    )
                ))

    coverage_ratio = total_built_sq_m / max(1.0, parcel.area_sq_m)

    # Check unrecorded construction: building exists on ground, but revenue record says agricultural/vacant
    unrecorded = False
    if total_built_sq_m > 30.0 and parcel.land_use in (LandUseType.AGRICULTURAL, LandUseType.VACANT):
        unrecorded = True

    # Summary text
    if encroachment_findings:
        summary = (
            f"Detected {len(encroachment_findings)} encroachment(s) totaling "
            f"{sum(e.encroached_area_sq_m for e in encroachment_findings):.1f} m² outside boundary. "
        )
    else:
        summary = "All ground footprints strictly contained within legal boundary. "

    if unrecorded:
        summary += f"ALERT: Unrecorded construction detected on {parcel.land_use.value} parcel ({total_built_sq_m:.1f} m² built-up)."

    return ImageryAnalysisResult(
        parcel_id=parcel.parcel_id,
        total_built_up_area_sq_m=total_built_sq_m,
        coverage_ratio=coverage_ratio,
        building_count=intersecting_count,
        encroachments=encroachment_findings,
        unrecorded_construction=unrecorded,
        summary=summary,
    )
