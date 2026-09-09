import pytest
from app.core.temporal import analyze_temporal

def test_same_era_small_gap():
    # 2 days apart -> same era, NOT qualified as temporal change
    res = analyze_temporal("2024-01-01T00:00:00Z", "2024-01-03T00:00:00Z")
    assert res.valid is True
    assert res.gap_days == 2.0
    assert res.qualified is False  # Cannot excuse a geometric difference

def test_temporally_qualified_large_gap():
    # 3 years apart -> qualified as temporal discrepancy
    res = analyze_temporal("2020-01-01T00:00:00Z", "2023-01-01T00:00:00Z")
    assert res.valid is True
    assert res.gap_days > 1000
    assert res.qualified is True

def test_malformed_timestamp_fails_closed():
    res = analyze_temporal("not-a-date", "2024-01-01T00:00:00Z")
    assert res.valid is False
    assert res.qualified is False
    assert "malformed" in res.reason.lower() or "invalid" in res.reason.lower()

def test_missing_timestamp_fails_closed():
    res = analyze_temporal(None, "2024-01-01T00:00:00Z")
    assert res.valid is False
    assert res.qualified is False

def test_ancient_timestamp():
    res = analyze_temporal("1800-01-01T00:00:00Z", "2024-01-01T00:00:00Z")
    assert res.valid is False or res.gap_days > 50000

def test_future_timestamp():
    res = analyze_temporal("2099-01-01T00:00:00Z", "2024-01-01T00:00:00Z")
    assert res.valid is False or res.qualified is False
