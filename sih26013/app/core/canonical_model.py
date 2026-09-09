"""
Canonical Parcel Data Model — SIH26013

Provides a unified, cross-department representation of land parcels across:
- Revenue Department (Records of Rights / RoR)
- Municipal Corporation (Urban Local Body / Tax Registry)
- Cadastral / Survey Department (Tippan / Village Maps)
- Drone / Photogrammetry (ORI / DSM Orthomosaics)
- Utility Infrastructure (Water, Power, Roads)
"""
import uuid
import datetime
from enum import Enum
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field, asdict


class AgencyType(str, Enum):
    REVENUE = "REVENUE"
    MUNICIPAL = "MUNICIPAL"
    CADASTRAL = "CADASTRAL"
    DRONE_SURVEY = "DRONE_SURVEY"
    UTILITY_GIS = "UTILITY_GIS"
    GROUND_TRUTH = "GROUND_TRUTH"


class LandUseType(str, Enum):
    RESIDENTIAL = "RESIDENTIAL"
    COMMERCIAL = "COMMERCIAL"
    INDUSTRIAL = "INDUSTRIAL"
    AGRICULTURAL = "AGRICULTURAL"
    MIXED_USE = "MIXED_USE"
    PUBLIC_INFRA = "PUBLIC_INFRA"
    GOVERNMENT = "GOVERNMENT"
    VACANT = "VACANT"
    UNKNOWN = "UNKNOWN"


@dataclass
class CanonicalParcel:
    parcel_id: str
    survey_number: str
    source_agency: AgencyType
    area_sq_m: float
    land_use: LandUseType
    owner_ref: str
    geometry: Dict[str, Any]  # GeoJSON Polygon / MultiPolygon
    capture_timestamp: str    # ISO 8601 UTC
    crs: str = "EPSG:4326"
    sub_division: Optional[str] = None
    tax_assessment_no: Optional[str] = None
    market_rate_per_sq_m: Optional[float] = None
    raw_attributes: Dict[str, Any] = field(default_factory=dict)
    confidence_weight: float = 1.0

    @classmethod
    def create(
        cls,
        survey_number: str,
        source_agency: AgencyType,
        area_sq_m: float,
        geometry: Dict[str, Any],
        owner_ref: str = "UNSPECIFIED",
        land_use: LandUseType = LandUseType.UNKNOWN,
        parcel_id: Optional[str] = None,
        capture_timestamp: Optional[str] = None,
        crs: str = "EPSG:4326",
        **extra_attrs
    ) -> "CanonicalParcel":
        pid = parcel_id or f"PRCL-{source_agency.value[:3]}-{uuid.uuid4().hex[:8].upper()}"
        ts = capture_timestamp or datetime.datetime.now(datetime.timezone.utc).isoformat()
        return cls(
            parcel_id=pid,
            survey_number=survey_number,
            source_agency=source_agency,
            area_sq_m=float(area_sq_m),
            land_use=land_use,
            owner_ref=owner_ref,
            geometry=geometry,
            capture_timestamp=ts,
            crs=crs,
            raw_attributes=extra_attrs,
        )

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["source_agency"] = self.source_agency.value
        d["land_use"] = self.land_use.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CanonicalParcel":
        d = dict(data)
        if isinstance(d.get("source_agency"), str):
            d["source_agency"] = AgencyType(d["source_agency"])
        if isinstance(d.get("land_use"), str):
            d["land_use"] = LandUseType(d["land_use"])
        return cls(**d)
