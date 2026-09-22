"""Unit tests for anti-forensic timestomp and wiper artifact detection."""
import pytest
from app.forensics.anti_forensics import (
    analyze_ntfs_timestamps,
    scan_entries_for_wipe_artifacts,
    scan_raw_clusters_for_anti_forensics,
    analyze_anti_forensics,
    AntiForensicIndicator,
    AntiForensicSeverity,
)


def test_timestomp_si_modified_before_fn():
    # SI modified backdated by 1 hour (3600 seconds)
    si = {"created": 1700000000.0, "modified": 1700000000.0}
    fn = {"created": 1700000000.0, "modified": 1700003600.0}

    findings = analyze_ntfs_timestamps(si, fn, "suspicious_doc.docx")
    assert len(findings) >= 1
    assert any(f.indicator == AntiForensicIndicator.TIMESTOMP_SI_FN_ANOMALY for f in findings)
    assert any(f.severity == AntiForensicSeverity.CRITICAL for f in findings)


def test_timestomp_subsecond_zeroed():
    # SI has 0 nanoseconds (typical of SetFileTime API) while FN has microsecond precision
    si = {"created": 1700000000.0, "modified": 1700000000.0}
    fn = {"created": 1700000000.123456, "modified": 1700000000.123456}

    findings = analyze_ntfs_timestamps(si, fn, "backdated_file.txt")
    assert any(f.indicator == AntiForensicIndicator.TIMESTOMP_SUBSECOND_ZEROED for f in findings)


def test_sdelete_directory_artifacts():
    entries = [
        "regular_file.txt",
        "AAAAAA.AAA",
        "BBBBBB.BBB",
        "case_notes.pdf",
    ]
    findings = scan_entries_for_wipe_artifacts(entries)
    assert len(findings) == 1
    assert findings[0].indicator == AntiForensicIndicator.WIPE_TOOL_SDELETE_ARTIFACT
    assert findings[0].severity == AntiForensicSeverity.CRITICAL


def test_bleachbit_artifact_detection():
    entries = ["BleachBit_clean.ini", "normal.jpg"]
    findings = scan_entries_for_wipe_artifacts(entries)
    assert len(findings) == 1
    assert findings[0].indicator == AntiForensicIndicator.WIPE_TOOL_BLEACHBIT_TRACE


def test_wipe_pattern_detection_in_bytes():
    # 4KB block containing repeated 0x55 (DoD wipe pass)
    data = b"\x00" * 1024 + (b"\x55" * 128) + b"\x00" * 2944
    findings = scan_raw_clusters_for_anti_forensics(data, cluster_size=4096)
    assert len(findings) >= 1
    assert any(f.indicator == AntiForensicIndicator.WIPE_TOOL_FIXED_PATTERN for f in findings)


def test_analyze_anti_forensics_facade_clean():
    si = {"created": 1700000000.5, "modified": 1700000000.5}
    fn = {"created": 1700000000.5, "modified": 1700000000.5}
    mft_records = [{"name": "clean.txt", "si": si, "fn": fn}]

    res = analyze_anti_forensics(
        image_input=b"\x00" * 4096,
        mft_records=mft_records,
        directory_names=["clean.txt"]
    )
    assert res["anti_forensics_detected"] is False
    assert res["verdict"] == "NO_OVERT_ANTI_FORENSICS_FOUND"


def test_analyze_anti_forensics_facade_tampered():
    si = {"created": 1600000000.0, "modified": 1600000000.0}
    fn = {"created": 1700000000.0, "modified": 1700000000.0}
    mft_records = [{"name": "tampered.txt", "si": si, "fn": fn}]

    res = analyze_anti_forensics(
        image_input=b"\x55" * 4096,
        mft_records=mft_records,
        directory_names=["AAAAAA.AAA", "BBBBBB.BBB"]
    )
    assert res["anti_forensics_detected"] is True
    assert res["verdict"] == "DELIBERATE_CONCEALMENT_DETECTED"
    assert res["by_severity"]["CRITICAL"] >= 1
