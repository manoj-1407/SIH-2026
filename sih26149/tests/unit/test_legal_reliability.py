"""
Tests for Legal Forensic Reliability Statement Generator — SIH26149.
"""
import pytest
from app.core.legal_reliability import (
    generate_reliability_statement,
    generate_reliability_statement_html,
    TOTAL_VERIFIED_TESTS
)


def test_generate_reliability_statement():
    stmt = generate_reliability_statement(
        examiner_name="Dr. V. K. Sharma",
        lab_organization="NTRO Forensic Division",
        case_id="CASE-TEST-88"
    )
    assert stmt["affidavit_id"].startswith("RELIABILITY-AFFIDAVIT-")
    assert stmt["system_provenance"]["lead_certifier"] == "Dr. V. K. Sharma"
    assert stmt["system_provenance"]["associated_case_id"] == "CASE-TEST-88"
    assert stmt["empirical_reliability_metrics"]["empirical_error_rate_percentage"] == "0.0000%"
    assert stmt["empirical_reliability_metrics"]["total_adversarial_test_vectors"] >= 270
    assert "affidavit_integrity_sha256" in stmt
    assert len(stmt["affidavit_integrity_sha256"]) == 64


def test_generate_reliability_statement_html():
    stmt = generate_reliability_statement()
    html = generate_reliability_statement_html(stmt)
    assert "<html" in html
    assert stmt["affidavit_id"] in html
    assert "0.0000%" in html
    assert "Daubert" in html
    assert "Bharatiya Sakshya Adhiniyam" in html
