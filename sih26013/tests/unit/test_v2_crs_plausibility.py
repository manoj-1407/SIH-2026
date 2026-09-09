import pytest
from shapely.geometry import Polygon
from app.core.crs_check import check_crs_plausibility, CRSCheckResult

def test_wgs84_delhi_valid():
    poly = Polygon([[77.1, 28.5], [77.2, 28.5], [77.2, 28.6], [77.1, 28.6], [77.1, 28.5]])
    res = check_crs_plausibility(poly, "EPSG:4326")
    assert res.ok is True
    assert res.category == "NONE"

def test_wgs84_axis_inversion_detected():
    # Lat/Lon swapped: X in [28.5, 28.6], Y in [77.1, 77.2]
    poly = Polygon([[28.5, 77.1], [28.6, 77.1], [28.6, 77.2], [28.5, 77.2], [28.5, 77.1]])
    res = check_crs_plausibility(poly, "EPSG:4326")
    assert res.category in ("AXIS_ORDER", "PLAUSIBILITY") or not res.ok

def test_impossible_coordinates():
    # Longitude > 180 or Latitude > 90 in EPSG:4326
    poly = Polygon([[250.0, 95.0], [250.1, 95.0], [250.1, 95.1], [250.0, 95.1], [250.0, 95.0]])
    res = check_crs_plausibility(poly, "EPSG:4326")
    assert res.ok is False
    assert res.category in ("IMPOSSIBLE_EXTENT", "PLAUSIBILITY", "CRS_ERROR")

def test_projected_metres_labeled_as_degrees():
    # UTM coordinates (e.g. 715000, 3160000) labeled as EPSG:4326 degrees
    poly = Polygon([[715000, 3160000], [715100, 3160000], [715100, 3160100], [715000, 3160100], [715000, 3160000]])
    res = check_crs_plausibility(poly, "EPSG:4326")
    assert res.ok is False
    assert "degree" in res.issue.lower() or "metre" in res.issue.lower() or res.category in ("DEGREE_METRE_CONFUSION", "IMPOSSIBLE_EXTENT")
