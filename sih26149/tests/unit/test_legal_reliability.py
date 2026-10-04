"""
Tests for Legal Forensic Reliability Statement Generator — SIH26149.
"""
import pytest
from app.core.legal_reliability import (
    generate_artifact_admissibility_paragraph,
    generate_sanitization_admissibility_paragraph,
    generate_reliability_statement,
    generate_reliability_statement_html,
)


def test_generate_reliability_statement():
    stmt = generate_reliability_statement(
        examiner_name="Dr. V. K. Sharma",
        lab_organization="NTRO Forensic Division",
        case_id="CASE-TEST-88"
    )
    assert stmt["report_id"].startswith("RELIABILITY-REPORT-")
    assert stmt["system_provenance"]["examiner"] == "Dr. V. K. Sharma"
    assert stmt["system_provenance"]["associated_case_id"] == "CASE-TEST-88"
    assert stmt["empirical_reliability_metrics"]["empirical_error_rate_percentage"] == "NOT MEASURED"
    assert stmt["empirical_reliability_metrics"]["total_adversarial_test_vectors"] is None
    assert stmt["not_a_legal_opinion_or_certificate"] is True
    assert len(stmt["report_integrity_sha256"]) == 64


def test_generate_reliability_statement_html():
    stmt = generate_reliability_statement()
    html = generate_reliability_statement_html(stmt)
    assert "<html" in html
    assert stmt["report_id"] in html
    assert "NOT MEASURED" in html
    assert "not an affidavit" in html
    assert "Bharatiya Sakshya Adhiniyam" in html
    assert "court-presentable" not in html


def test_artifact_record_note_is_cautious_and_handles_header_only():
    note = generate_artifact_admissibility_paragraph(
        {
            "filename": "partial.doc",
            "sha256": "a" * 64,
            "size_bytes": 12,
            "method": "RAW_CARVING_FALLBACK",
            "confidence": "HEADER_ONLY",
        },
        {"case_id": "CASE-1", "title": "Test case"},
        {"examiner_id": "EX-1", "examiner_name": "Examiner"},
    )

    assert "BSA 2023, §39" in note
    assert "BSA 2023, §63(4)" in note
    assert "HEADER_ONLY" in note
    assert "payload integrity and completeness are not established" in note
    assert "not itself an expert opinion" in note
    assert "not the Information Technology Act" in note
    assert "no examiner credential is asserted" in note
    assert "court-admissible" not in note
    assert "NTRO Certified" not in note


def test_sanitization_record_note_does_not_invent_probe_results():
    note = generate_sanitization_admissibility_paragraph(
        {
            "method": "ZERO_FILL",
            "execution_status": "VERIFIED_WITHIN_SCOPE",
            "classification": "VERIFIED_WITHIN_SCOPE",
            "pre_operation_sha256": "b" * 64,
            "verification_details": {},
        },
        {"case_id": "CASE-2"},
        {},
    )

    assert "No erasure percentage was reported." not in note
    assert "No post-operation residual-artifact" not in note
    assert "Read-back verification details were not supplied." in note
    assert "not a physical-media probe" not in note
    assert "bytes containing zero" not in note
    assert "BSA 2023, §63(4)" in note
    assert "not the Information Technology Act" in note
    assert "not a legal opinion" in note


def test_sanitization_record_note_reports_only_supplied_readback_evidence():
    note = generate_sanitization_admissibility_paragraph(
        {
            "method": "ZERO_FILL",
            "execution_status": "VERIFIED_WITHIN_SCOPE",
            "classification": "VERIFIED_WITHIN_SCOPE",
            "bytes_written": 0,
            "pre_operation_sha256": "c" * 64,
            "verification_details": {"bytes_verified_zero": 0},
            "ieee_2883_reference": "IEEE 2883-2022 §5.2",
        },
        {"case_id": "CASE-3"},
        {},
    )

    assert "writing 0 bytes" in note
    assert "reported 0 bytes containing zero" in note
    assert "IEEE 2883-2022 §5.2" in note
    assert "residual artifacts" not in note
