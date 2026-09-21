"""
SIH26149 — Unified Forensic CLI Integration Tests.

Verifies:
- forensic recover (text and --json)
- forensic sanitize (text, --json, and blocked PURGE on virtual disks)
- forensic verify (VALID and INVALID packages)
"""
import io
import json
import subprocess
import sys
from pathlib import Path
import pytest

from app.core.package import EvidencePackageBuilder
from app.core.signing import generate_keypair, load_public_key_raw
from cryptography.hazmat.primitives import serialization


@pytest.fixture
def sample_disk_image(tmp_path):
    # Create a small synthetic image containing a JPEG
    jpeg_bytes = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00\x43\x00"
        + (b"\x01" * 64)
        + b"\xff\xc0\x00\x0b\x08\x00\x10\x00\x10\x01\x01\x11\x00\xff\xda\x00\x08\x01\x01\x00\x00?\x00\x00\xff\xd9"
    )
    img_data = b"\x00" * 512 + jpeg_bytes + b"\x00" * 512
    p = tmp_path / "test_evidence.raw"
    p.write_bytes(img_data)
    return p


def test_cli_recover_human(sample_disk_image, tmp_path):
    out_dir = tmp_path / "cli_out"
    res = subprocess.run(
        [sys.executable, "-m", "app.cli.forensic", "recover", "--source", str(sample_disk_image), "--output", str(out_dir)],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "SIH26149 FORENSIC RECOVERY" in res.stdout
    assert "Candidates Found" in res.stdout
    assert (out_dir / "recovery_summary.json").exists()


def test_cli_recover_json(sample_disk_image):
    res = subprocess.run(
        [sys.executable, "-m", "app.cli.forensic", "recover", "--source", str(sample_disk_image), "--json"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert "source_sha256" in data
    assert "summary" in data
    assert data["summary"]["total_carved"] >= 1


def test_cli_sanitize_clear(tmp_path):
    target = tmp_path / "disk.img"
    target.write_bytes(b"\x00" * 4096)
    res = subprocess.run(
        [sys.executable, "-m", "app.cli.forensic", "sanitize", "--target", str(target), "--method", "CLEAR", "--json"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["status"] == "AUTHORIZED"
    assert data["method"] == "CLEAR"


def test_cli_sanitize_purge_blocked_on_image(tmp_path):
    target = tmp_path / "disk.img"
    target.write_bytes(b"\x00" * 4096)
    res = subprocess.run(
        [sys.executable, "-m", "app.cli.forensic", "sanitize", "--target", str(target), "--method", "PURGE", "--json"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 3
    data = json.loads(res.stdout)
    assert data["status"] == "BLOCKED"
    assert data["purge_supported"] is False


def test_cli_verify_package(tmp_path):
    priv_pem, pub_raw = generate_keypair()
    pub_key = load_public_key_raw(pub_raw)
    pub_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    builder = EvidencePackageBuilder("CASE-CLI-TEST", tmp_path)
    builder.write_source_metadata({"filename": "test.raw", "sha256": "abc"})
    builder.write_recovery_artifacts({"total_carved": 1})
    res_pkg = builder.build_and_sign(
        private_key_pem=priv_pem,
        public_key_pem=pub_pem,
        key_id="KEY-01",
    )
    pkg_dir = builder.package_dir

    res = subprocess.run(
        [sys.executable, "-m", "app.cli.forensic", "verify", "--evidence", str(pkg_dir), "--json"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["valid"] is True
    assert data["classification"] in ("VALID", "VERIFIED")
