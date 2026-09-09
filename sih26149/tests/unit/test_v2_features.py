"""Unit tests for SIH26149 v2 enhancements (Carving, Eraser, Device Detector, Audit Chain, Certificate)."""
import os
import io
import json
import tempfile
import pytest

from app.forensics.carving import carve_bytes, carve_image_summary
from app.sanitization.device_detector import detect_media_type, MediaType, SanitizationLevel
from app.sanitization.file_eraser import erase_paths, preview_scope, EraserMethod
from app.cases.audit import AuditLogger
from app.core.certificate import generate_html_certificate


def test_carving_jpeg_and_png():
    # Build synthetic raw disk stream with padding, JPEG, and PNG
    padding_front = b"\xaa\xbb\xcc\xdd" * 100
    # Minimal valid JPEG
    jpeg_data = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00\x43\x00" + (b"\x01" * 64) + b"\xff\xc0\x00\x0b\x08\x00\x10\x00\x10\x01\x01\x11\x00\xff\xda\x00\x08\x01\x01\x00\x00?\x00\x00\xff\xd9"
    padding_mid = b"\x00" * 256
    # Minimal PNG
    png_ihdr = b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    png_iend = b"\x00\x00\x00\x00IEND\xaeB`\x82"
    png_data = b"\x89PNG\r\n\x1a\n" + png_ihdr + png_iend
    padding_end = b"\x55" * 128

    stream = padding_front + jpeg_data + padding_mid + png_data + padding_end

    results = carve_bytes(stream, target_types=["JPEG", "PNG"])
    types = [r.file_type for r in results]

    assert "JPEG" in types
    assert "PNG" in types

    png_art = [r for r in results if r.file_type == "PNG"][0]
    assert png_art.is_intact is True
    assert png_art.confidence_score >= 80


def test_carving_pdf():
    pdf_stream = (
        b"Random unallocated bytes"
        b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\nxref\n0 2\ntrailer<</Size 2>>\nstartxref\n30\n%%EOF\n"
        b"Trailing disk slack"
    )
    results = carve_bytes(pdf_stream, target_types=["PDF"])
    assert len(results) >= 1
    assert results[0].file_type == "PDF"
    assert results[0].is_intact is True


def test_device_detector():
    # Test path heuristics and virtual image classification
    img_cap = detect_media_type("/tmp/test_disk.img")
    assert img_cap.media_type == MediaType.VIRTUAL_DISK_IMAGE
    assert img_cap.clear_supported is True
    assert img_cap.purge_supported is False

    usb_cap = detect_media_type("E:/usbstor/drive")
    assert usb_cap.media_type == MediaType.USB_FLASH
    assert usb_cap.recommended_level == SanitizationLevel.CLEAR
    assert len(usb_cap.warnings) > 0


def test_file_eraser(tmp_path):
    # Create test files to erase
    f1 = tmp_path / "secret.txt"
    f1.write_text("Top secret confidential investigative notes")
    f2 = tmp_path / "sub" / "data.bin"
    f2.parent.mkdir()
    f2.write_bytes(b"\x99" * 1024)

    # Preview scope
    preview = preview_scope([str(tmp_path)])
    assert len(preview) >= 1

    # Erase
    res = erase_paths(
        paths=[str(f1), str(f2)],
        method=EraserMethod.ZERO_FILL,
        scrub_metadata=True,
        scramble_names=True,
    )
    assert res.total_files == 2
    assert res.classification == "VERIFIED"
    assert not f1.exists()
    assert not f2.exists()


def test_audit_chain_and_tamper(tmp_path):
    logger = AuditLogger(str(tmp_path))
    case_id = "CASE-AUDIT-TEST"

    logger.log(case_id, "EVENT_1", "INVESTIGATOR", {"detail": "Initial ingest"})
    logger.log(case_id, "EVENT_2", "CARVING_ENGINE", {"detail": "Carved 5 files"})
    logger.log(case_id, "EVENT_3", "SIGNING_IDENTITY", {"detail": "Evidence envelope signed"})

    timeline = logger.get_timeline(case_id)
    assert len(timeline) == 3

    # Verify initial chain
    is_valid, violations = logger.verify_chain(case_id)
    assert is_valid is True
    assert len(violations) == 0

    # Demo tamper: mutate middle record
    demo_res = logger.demo_tamper_chain(case_id, entry_index=1, field="actor", new_value="ATTACKER_INJECT")
    assert demo_res["chain_valid_after_tamper"] is False
    assert demo_res["tamper_detected"] is True
    assert len(demo_res["violations"]) > 0

    # Chain should be restored
    is_valid_after, _ = logger.verify_chain(case_id)
    assert is_valid_after is True


def test_html_certificate():
    evidence_pkg = {
        "evidence_id": "EV-TEST-1234",
        "case_id": "CASE-101",
        "evidence_type": "CARVING",
        "evidence_hash": "a1b2c3d4e5f67890" * 4,
        "key_id": "KEY-PRIMARY-ED25519",
        "signed_at_utc": "2026-09-09T10:00:00Z",
        "result": {
            "classification": "VERIFIED",
            "explanation": "Carved intact JPEG stream with valid SOF/EOI markers.",
        },
        "scope": "Raw byte carving on unallocated cluster stream.",
        "signing_algorithm": "Ed25519",
        "signature": "abcd" * 16,
    }
    html = generate_html_certificate(evidence_pkg, case_title="NTRO Forensic Case 101")
    assert "Forensic Evidence Certificate" in html
    assert "EV-TEST-1234" in html
    assert "VERIFIED" in html
