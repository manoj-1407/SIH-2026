"""
Cross-Agency Attribute Mapping & Harmonization — SIH26013

Harmonizes heterogeneous land record schemas from Revenue, Municipal,
Cadastral, and Survey departments.
Handles:
  1. Departmental column alias resolution (Khasra, CTS, Survey, Plot)
  2. Multi-unit area normalization (Acres, Hectares, Gunthas, Bighas, SqFt -> SqM)
  3. Discrepancy detection (area divergence, land-use conflict, owner name variation)
  4. Severity scoring (CRITICAL, WARNING, NEGLIGIBLE)
"""
import re
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass, field

from app.core.canonical_model import CanonicalParcel, AgencyType, LandUseType


# Area conversion factors to Square Metres
UNIT_TO_SQ_M = {
    'sq_m': 1.0,
    'sq_meter': 1.0,
    'sq_meters': 1.0,
    'sqm': 1.0,
    'sqft': 0.092903,
    'sq_ft': 0.092903,
    'sq_feet': 0.092903,
    'sq_yard': 0.836127,
    'sq_yards': 0.836127,
    'sqyd': 0.836127,
    'acre': 4046.8564,
    'acres': 4046.8564,
    'hectare': 10000.0,
    'hectares': 10000.0,
    'ha': 10000.0,
    'guntha': 101.1714,     # Standard Indian revenue guntha (1/40th acre)
    'gunthas': 101.1714,
    'bigha': 2529.285,      # Pucca Bigha standard (approx 0.625 acre)
    'bighas': 2529.285,
    'cent': 40.4686,        # 1/100th acre (South India)
    'cents': 40.4686,
}


SURVEY_ALIASES = [
    'survey_number', 'survey_no', 'surveyno', 'plot_number', 'plot_no', 'plotno',
    'khasra_no', 'khasra', 'cts_no', 'cts', 'gat_no', 'gat', 'dag_no', 'khata_no'
]

AREA_ALIASES = [
    'area_sq_m', 'area', 'extent', 'total_area', 'plot_area', 'land_area', 'super_area'
]

OWNER_ALIASES = [
    'owner_ref', 'owner', 'owner_name', 'pattadar', 'khatedar', 'title_holder',
    'proprietor', 'applicant_name'
]

LAND_USE_ALIASES = [
    'land_use', 'landuse', 'usage', 'classification', 'zoning', 'category', 'nature_of_land'
]


def normalize_area_to_sq_m(value: float, unit_str: Optional[str] = None) -> float:
    """Normalize area to square meters given an optional unit string."""
    if not unit_str:
        return float(value)
    clean_unit = unit_str.lower().strip().replace(' ', '_').replace('.', '')
    factor = UNIT_TO_SQ_M.get(clean_unit, 1.0)
    return round(float(value) * factor, 2)


def map_raw_record_to_canonical(
    raw_dict: Dict[str, Any],
    source_agency: AgencyType,
    geometry: Dict[str, Any],
    default_crs: str = "EPSG:4326",
) -> CanonicalParcel:
    """
    Intelligently map an arbitrary departmental dict to CanonicalParcel.
    """
    lower_map = {k.lower().strip().replace(' ', '_'): v for k, v in raw_dict.items()}

    # 1. Survey Number
    survey_no = "UNKNOWN"
    for alias in SURVEY_ALIASES:
        if alias in lower_map and lower_map[alias]:
            survey_no = str(lower_map[alias]).strip()
            break

    # 2. Area
    area_val = 0.0
    unit_hint = lower_map.get('unit') or lower_map.get('area_unit') or 'sq_m'
    for alias in AREA_ALIASES:
        if alias in lower_map and lower_map[alias] is not None:
            try:
                area_val = float(lower_map[alias])
                break
            except (ValueError, TypeError):
                continue
    area_sq_m = normalize_area_to_sq_m(area_val, str(unit_hint))

    # 3. Owner
    owner_ref = "UNSPECIFIED"
    for alias in OWNER_ALIASES:
        if alias in lower_map and lower_map[alias]:
            owner_ref = str(lower_map[alias]).strip()
            break

    # 4. Land use
    land_use = LandUseType.UNKNOWN
    for alias in LAND_USE_ALIASES:
        if alias in lower_map and lower_map[alias]:
            val = str(lower_map[alias]).upper().strip()
            for lu in LandUseType:
                if lu.value in val or val in lu.value:
                    land_use = lu
                    break
            break

    reserved = {"survey_number", "source_agency", "area_sq_m", "geometry", "owner_ref", "land_use", "crs", "parcel_id"}
    extra_attrs = {k: v for k, v in raw_dict.items() if k not in reserved}

    return CanonicalParcel.create(
        survey_number=survey_no,
        source_agency=source_agency,
        area_sq_m=area_sq_m,
        geometry=geometry,
        owner_ref=owner_ref,
        land_use=land_use,
        crs=default_crs,
        **extra_attrs
    )


@dataclass
class DiscrepancyReport:
    parcel_a_id: str
    parcel_b_id: str
    area_delta_sq_m: float
    area_delta_pct: float
    land_use_status: str       # CONCORDANT, CONFLICT, UNKNOWN
    ownership_status: str      # MATCH, DIVERGENCE, UNVERIFIED
    severity: str              # NEGLIGIBLE, WARNING, CRITICAL
    discrepancies: List[str]
    suggested_resolution: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "parcel_a_id": self.parcel_a_id,
            "parcel_b_id": self.parcel_b_id,
            "area_delta_sq_m": round(self.area_delta_sq_m, 2),
            "area_delta_pct": round(self.area_delta_pct, 2),
            "land_use_status": self.land_use_status,
            "ownership_status": self.ownership_status,
            "severity": self.severity,
            "discrepancies": self.discrepancies,
            "suggested_resolution": self.suggested_resolution,
        }


def compare_parcel_attributes(p_a: CanonicalParcel, p_b: CanonicalParcel) -> DiscrepancyReport:
    """Analyze discrepancies between two matched multi-source parcels."""
    discrepancies = []
    severity = "NEGLIGIBLE"

    # Area Delta
    max_area = max(0.1, p_a.area_sq_m, p_b.area_sq_m)
    delta_sq_m = abs(p_a.area_sq_m - p_b.area_sq_m)
    delta_pct = (delta_sq_m / max_area) * 100.0

    if delta_pct > 15.0 or delta_sq_m > 500.0:
        severity = "CRITICAL"
        discrepancies.append(
            f"Area discrepancy of {delta_sq_m:.1f} m² ({delta_pct:.1f}%) exceeds configured "
            f"reconciliation threshold (15% or 500 m²). "
            f"({p_a.source_agency.value}: {p_a.area_sq_m} m² vs {p_b.source_agency.value}: {p_b.area_sq_m} m²)"
        )
    elif delta_pct > 5.0:
        if severity != "CRITICAL":
            severity = "WARNING"
        discrepancies.append(
            f"Moderate area variance: {delta_sq_m:.1f} m² ({delta_pct:.1f}%)."
        )

    # Land Use
    lu_status = "CONCORDANT"
    if p_a.land_use != p_b.land_use:
        if p_a.land_use == LandUseType.UNKNOWN or p_b.land_use == LandUseType.UNKNOWN:
            lu_status = "UNKNOWN"
        else:
            lu_status = "CONFLICT"
            if severity != "CRITICAL":
                severity = "WARNING"
            discrepancies.append(
                f"Land-use conflict: {p_a.source_agency.value} states '{p_a.land_use.value}' "
                f"whereas {p_b.source_agency.value} states '{p_b.land_use.value}'."
            )

    # Ownership
    owner_status = "MATCH"
    o1, o2 = p_a.owner_ref.strip().upper(), p_b.owner_ref.strip().upper()
    if o1 == "UNSPECIFIED" or o2 == "UNSPECIFIED":
        owner_status = "UNVERIFIED"
    elif o1 != o2:
        owner_status = "DIVERGENCE"
        if severity != "CRITICAL":
            severity = "WARNING"
        discrepancies.append(f"Recorded owner divergence: '{p_a.owner_ref}' vs '{p_b.owner_ref}'.")

    # Suggested Resolution
    if severity == "CRITICAL":
        resolution = "Requires on-site DGPS / Drone survey resurvey and joint revenue-municipal demarcation."
    elif severity == "WARNING":
        resolution = "Recommend administrative reconciliation with latest tax assessment or sale deed."
    else:
        resolution = "Auto-harmonization permissible within 5% tolerance."

    return DiscrepancyReport(
        parcel_a_id=p_a.parcel_id,
        parcel_b_id=p_b.parcel_id,
        area_delta_sq_m=delta_sq_m,
        area_delta_pct=delta_pct,
        land_use_status=lu_status,
        ownership_status=owner_status,
        severity=severity,
        discrepancies=discrepancies,
        suggested_resolution=resolution,
    )
