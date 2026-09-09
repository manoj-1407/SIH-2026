"""
AI-Enabled Geospatial Matcher — SIH26013

Hybrid AI + GIS feature matching engine for multi-source land parcels.
Combines:
  1. Geometric topology & boundary similarity (IoU, Hausdorff, Centroid distance, Area ratio)
  2. Syntactic & phonetic survey number token matching (Levenshtein & normalized tokens)
  3. Cross-department attribute correlation (Land use, ownership, tax IDs)
  4. Explainable confidence scoring with factor breakdown
"""
import re
import math
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict

from shapely.geometry import shape as shapely_shape
from app.core.canonical_model import CanonicalParcel
from app.core.geometry import compute_iou, compute_hausdorff_metres, _centroid_metres_per_degree


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev[j + 1] + 1
            deletions = curr[j] + 1
            substitutions = prev[j] + (c1 != c2)
            curr.append(min(insertions, deletions, substitutions))
        prev = curr
    return prev[-1]


def normalize_survey_number(s: str) -> str:
    """Normalize survey/plot strings (e.g., 'Plot No. 42/1-B' -> '42/1-B')."""
    s = s.strip().upper()
    s = re.sub(r'^(PLOT|SURVEY|CTS|SY|NO|NUM|NUMBER)[\s.:#/-]*', '', s, flags=re.IGNORECASE)
    s = re.sub(r'\s+', '', s)
    return s


def survey_number_similarity(s1: str, s2: str) -> float:
    n1 = normalize_survey_number(s1)
    n2 = normalize_survey_number(s2)
    if not n1 or not n2:
        return 0.0
    if n1 == n2:
        return 1.0

    # Token overlap (e.g., '42/1' vs '42-1' -> tokens ['42','1'])
    tok1 = set(re.split(r'[/.\-_]', n1))
    tok2 = set(re.split(r'[/.\-_]', n2))
    if tok1 and tok2 and tok1 == tok2:
        return 0.95

    dist = _levenshtein(n1, n2)
    max_len = max(len(n1), len(n2))
    sim = max(0.0, 1.0 - (dist / max_len))
    return round(sim, 3)


@dataclass
class MatchFeatureVector:
    iou: float
    centroid_dist_m: float
    hausdorff_m: float
    area_ratio: float
    survey_sim: float
    owner_sim: float
    land_use_concordance: float

    def to_dict(self) -> Dict[str, float]:
        return asdict(self)


@dataclass
class MatchResult:
    source_parcel_id: str
    target_parcel_id: str
    match_probability: float
    classification: str  # DEFINITE_MATCH, PROBABLE_MATCH, AMBIGUOUS_REVIEW_REQUIRED, NO_MATCH
    features: MatchFeatureVector
    factor_breakdown: Dict[str, float]
    spatial_conflict: bool
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        rec_action = (
            "Accept Automatic Alignment" if self.match_probability >= 0.82
            else ("Field Inspection Required" if self.spatial_conflict or self.match_probability >= 0.60
                  else "Reconcile Attributes Manually")
        )
        return {
            "source_parcel_id": self.source_parcel_id,
            "target_parcel_id": self.target_parcel_id,
            "parcel_a_id": self.source_parcel_id,
            "parcel_b_id": self.target_parcel_id,
            "match_probability": round(self.match_probability, 4),
            "classification": self.classification,
            "confidence_tier": self.classification,
            "features": self.features.to_dict(),
            "spatial_iou": self.features.iou,
            "recommended_action": rec_action,
            "factor_breakdown": {k: round(v, 4) for k, v in self.factor_breakdown.items()},
            "spatial_conflict": self.spatial_conflict,
            "explanation": self.explanation,
        }


def extract_match_features(p_a: CanonicalParcel, p_b: CanonicalParcel) -> MatchFeatureVector:
    """Extract multi-dimensional similarity features between two parcels."""
    # 1. Geometry features
    try:
        sh_a = shapely_shape(p_a.geometry)
        sh_b = shapely_shape(p_b.geometry)
        iou = max(0.0, min(1.0, compute_iou(sh_a, sh_b)))
        hd = compute_hausdorff_metres(sh_a, sh_b)
        if math.isinf(hd) or math.isnan(hd):
            hd = 999.0

        # Centroid distance in meters
        c_a = sh_a.centroid
        c_b = sh_b.centroid
        m_lat, m_lon = _centroid_metres_per_degree(sh_a)
        d_lat = (c_a.y - c_b.y) * m_lat
        d_lon = (c_a.x - c_b.x) * m_lon
        centroid_m = math.sqrt(d_lat * d_lat + d_lon * d_lon)
    except Exception:
        iou = 0.0
        hd = 999.0
        centroid_m = 999.0

    # 2. Area ratio
    a1, a2 = max(0.1, p_a.area_sq_m), max(0.1, p_b.area_sq_m)
    area_ratio = min(a1, a2) / max(a1, a2)

    # 3. Survey string similarity
    surv_sim = survey_number_similarity(p_a.survey_number, p_b.survey_number)

    # 4. Owner similarity
    o1 = p_a.owner_ref.strip().upper()
    o2 = p_b.owner_ref.strip().upper()
    if o1 and o2 and o1 != "UNSPECIFIED" and o2 != "UNSPECIFIED":
        owner_sim = 1.0 if o1 == o2 else max(0.0, 1.0 - _levenshtein(o1, o2) / max(len(o1), len(o2)))
    else:
        owner_sim = 0.5  # neutral

    # 5. Land use concordance
    if p_a.land_use == p_b.land_use and p_a.land_use.value != "UNKNOWN":
        lu_sim = 1.0
    elif p_a.land_use.value == "UNKNOWN" or p_b.land_use.value == "UNKNOWN":
        lu_sim = 0.7
    else:
        lu_sim = 0.2

    return MatchFeatureVector(
        iou=round(iou, 4),
        centroid_dist_m=round(centroid_m, 2),
        hausdorff_m=round(hd, 2),
        area_ratio=round(area_ratio, 4),
        survey_sim=round(surv_sim, 4),
        owner_sim=round(owner_sim, 4),
        land_use_concordance=round(lu_sim, 4),
    )


def match_parcels(p_a: CanonicalParcel, p_b: CanonicalParcel) -> MatchResult:
    """Compute AI match probability and classification for a parcel pair."""
    feat = extract_match_features(p_a, p_b)

    # Spatial proximity score: decays with centroid distance (100m half-decay)
    spatial_dist_score = max(0.0, 1.0 - (feat.centroid_dist_m / 80.0))
    # Boundary alignment score
    boundary_score = max(0.0, 1.0 - (feat.hausdorff_m / 40.0))
    spatial_score = (0.5 * feat.iou) + (0.3 * spatial_dist_score) + (0.2 * boundary_score)

    # Weights
    w_spatial = 0.45
    w_survey = 0.30
    w_area = 0.15
    w_attr = 0.10

    factors = {
        "spatial_concordance": spatial_score * w_spatial,
        "survey_identifier_match": feat.survey_sim * w_survey,
        "area_shape_correlation": feat.area_ratio * w_area,
        "attribute_concordance": (0.6 * feat.land_use_concordance + 0.4 * feat.owner_sim) * w_attr,
    }

    prob = sum(factors.values())
    prob = max(0.0, min(1.0, prob))

    # Determine classification
    if prob >= 0.82:
        cls = "DEFINITE_MATCH"
    elif prob >= 0.60:
        cls = "PROBABLE_MATCH"
    elif prob >= 0.35:
        cls = "AMBIGUOUS_REVIEW_REQUIRED"
    else:
        cls = "NO_MATCH"

    # Spatial conflict check: strong survey similarity but significant boundary divergence
    spatial_conflict = (feat.survey_sim > 0.8 and feat.iou < 0.70 and feat.centroid_dist_m > 10.0)

    reasons = []
    if feat.iou > 0.85:
        reasons.append(f"High geometric overlap (IoU {feat.iou:.2f})")
    elif feat.iou < 0.50:
        reasons.append(f"Geometric shift observed (IoU {feat.iou:.2f}, Centroid Δ {feat.centroid_dist_m:.1f}m)")

    if feat.survey_sim > 0.9:
        reasons.append(f"Survey identifier match ({p_a.survey_number} vs {p_b.survey_number})")
    elif feat.survey_sim < 0.5:
        reasons.append(f"Survey identifier mismatch ({p_a.survey_number} vs {p_b.survey_number})")

    if feat.land_use_concordance < 0.5:
        reasons.append(f"Land use divergence ({p_a.land_use.value} vs {p_b.land_use.value})")

    explanation = "; ".join(reasons) or "Standard multi-factor comparison completed."

    return MatchResult(
        source_parcel_id=p_a.parcel_id,
        target_parcel_id=p_b.parcel_id,
        match_probability=prob,
        classification=cls,
        features=feat,
        factor_breakdown=factors,
        spatial_conflict=spatial_conflict,
        explanation=explanation,
    )


def match_multi_source_catalog(
    parcels_a: List[CanonicalParcel],
    parcels_b: List[CanonicalParcel],
    min_probability: float = 0.35,
) -> List[MatchResult]:
    """Batch cross-matching between two agency datasets."""
    results = []
    for a in parcels_a:
        for b in parcels_b:
            res = match_parcels(a, b)
            if res.match_probability >= min_probability:
                results.append(res)
    # Sort descending by match probability
    results.sort(key=lambda r: r.match_probability, reverse=True)
    return results
