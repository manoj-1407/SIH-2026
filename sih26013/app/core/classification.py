"""Evidence classification for geospatial analysis results."""
from __future__ import annotations
from enum import Enum


class GeoClassification(str, Enum):
    GEOMETRIC_CONFLICT             = "GEOMETRIC_CONFLICT"
    TEMPORALLY_QUALIFIED           = "TEMPORALLY_QUALIFIED"
    DATA_QUALITY_ISSUE             = "DATA_QUALITY_ISSUE"
    CRS_ERROR                      = "CRS_ERROR"
    PLAUSIBILITY_WARNING           = "PLAUSIBILITY_WARNING"
    NO_CONFLICT                    = "NO_CONFLICT"
    UNKNOWN                        = "UNKNOWN"


class ProvenanceClassification(str, Enum):
    INDEPENDENT                    = "INDEPENDENT"
    NOT_INDEPENDENT                = "NOT_INDEPENDENT"
    UNKNOWN                        = "UNKNOWN"
