"""
Tests for Live Storage SMART & Wear-Leveling Telemetry Reader — SIH26149.
"""
import pytest
from app.sanitization.smart_telemetry import (
    get_live_storage_telemetry,
    query_windows_storage_telemetry
)


def test_get_live_storage_telemetry_safe_execution():
    # Must never raise an exception, regardless of environment/privileges
    res = get_live_storage_telemetry()
    assert isinstance(res, dict)
    assert "status" in res
    assert "capture_mode" in res
    assert "advisory" in res
    assert res["status"] in ("LIVE_HARDWARE_CAPTURED", "SANDBOX_RESTRICTED_FALLBACK")


def test_fallback_structure_when_restricted():
    res = get_live_storage_telemetry(device_path="/dev/nonexistent_device_path_test")
    assert isinstance(res, dict)
    if not res.get("telemetry_available"):
        assert res["status"] == "SANDBOX_RESTRICTED_FALLBACK"
        assert "simulated_demo_reference" in res
