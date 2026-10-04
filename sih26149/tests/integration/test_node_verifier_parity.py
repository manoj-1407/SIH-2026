"""
H08 — Cross-Platform Verifier Parity Test (Python ↔ Node.js).

Creates a complete EvidencePackage (directory format with manifest.json),
verifies it independently with both:
  1. Python  app.core.independent_verifier.verify_evidence_package(package_dir)
  2. Node    scripts/verify_evidence.js path/to/manifest.json

Then tampering scenarios prove both verifiers reject consistently:
  A. Flip 1 byte inside a recovered artifact file — hash mismatch → FAILED/INVALID.
  B. Flip 1 byte in the last audit event — AUDIT_CHAIN broken → both reject.

If Node.js is not on PATH, all tests skip gracefully via the module-level skipif.
"""
import os
import sys
import json
import shutil
import struct
import secrets
import shutil as _shutil
import hashlib
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from app.core.package import EvidencePackageBuilder
from app.core.signing import generate_keypair
from app.core.canonical import canonicalize
from app.core.hashing import hash_bytes
from app.core.independent_verifier import verify_evidence_package
from app.core.classification import EvidenceClassification
from tests.corpus.generator import generate_valid_png

pytestmark = pytest.mark.skipif(
    _shutil.which("node") is None,
    reason="Node not on PATH — cross-platform verifier parity skipped",
)


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
NODE_SCRIPT = REPO_ROOT / "scripts" / "verify_evidence.js"


def _run_node(manifest_path: Path, trusted_public_key: Path | None = None) -> tuple[int, str]:
    command = ["node", str(NODE_SCRIPT), str(manifest_path)]
    if trusted_public_key is not None:
        command.extend(["--trusted-key", str(trusted_public_key)])
    proc = subprocess.run(
        command,
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=30,
    )
    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    return proc.returncode, combined


def _build_package(work_dir: Path, artifact_bytes: bytes) -> tuple[Path, Path]:
    work_dir.mkdir(parents=True, exist_ok=True)
    case_id = "CASE-H08-PARITY"
    priv_pem, pub_raw = generate_keypair()
    from cryptography.hazmat.primitives import serialization
    priv_obj = serialization.load_pem_private_key(priv_pem, password=None)
    pub_pem = priv_obj.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    trusted_key_path = work_dir / "trusted-examiner.pub.pem"
    trusted_key_path.write_bytes(pub_pem)

    builder = EvidencePackageBuilder(case_id, work_dir)

    source_meta = {
        "image_sha256": hashlib.sha256(b"synthetic-H08-image").hexdigest(),
        "image_size_bytes": 1024 * 1024,
        "media_type": "SYNTHETIC_FAT32",
    }
    builder.write_source_metadata(source_meta)

    artifact_sha = hashlib.sha256(artifact_bytes).hexdigest()
    artifact_path = builder.recovery_artifacts_dir / f"artifact_0_{artifact_sha[:12]}.png"
    artifact_path.write_bytes(artifact_bytes)
    summary = {
        "total_recovered": 1,
        "recovery_methods": {"FAT32_DIRECTORY_ENTRY": 1},
    }
    artifacts_list = [
        {
            "index": 0,
            "file_type": "PNG",
            "size_bytes": len(artifact_bytes),
            "sha256": artifact_sha,
            "path": f"recovery/artifacts/{artifact_path.name}",
            "recovery_method": "FAT32_DIRECTORY_ENTRY",
            "is_deleted": True,
        }
    ]
    builder.write_recovery_artifacts(summary, artifacts_list)

    san_result = {
        "method": "ZERO_FILL",
        "bytes_written": 1024 * 1024,
        "passes": 1,
        "scope": "ENTIRE_MEDIA",
        "sanitized_sha256": hashlib.sha256(b"\x00" * (1024 * 1024)).hexdigest(),
        "classification": "VERIFIED_WITHIN_SCOPE",
    }
    builder.write_sanitization_result(san_result)

    audit_lines = []
    prev_hash = "GENESIS"
    for i, (event_type, actor, details) in enumerate([
        ("CASE_CREATED", "FORENSIC_AUTOMATION", {"operator": "H08-test-suite"}),
        ("ARTIFACT_RECOVERED", "FAT32_PARSER", {"count": 1, "sha256": artifact_sha}),
        ("SANITIZATION_COMPLETED", "NIST_CLEAR_ENGINE", {"method": "ZERO_FILL"}),
    ]):
        raw = {
            "case_id": case_id,
            "entry_index": i,
            "previous_hash": prev_hash,
            "timestamp_utc": f"2026-10-03T0{i}:00:00.000000+00:00",
            "event_type": event_type,
            "actor": actor,
            "details": details,
        }
        entry_hash = hash_bytes(canonicalize(raw))
        raw["entry_hash"] = entry_hash
        audit_lines.append(json.dumps(raw, sort_keys=True, separators=(",", ":")))
        prev_hash = entry_hash
    audit_p = builder.audit_dir / "events.jsonl"
    audit_p.write_text("\n".join(audit_lines) + "\n", encoding="utf-8")

    builder.write_reports(html_content="<html><body>H08 demo report</body></html>")

    key_id = "KEY-H08-PARITY-001"
    builder.build_and_sign(priv_pem, pub_pem, key_id)

    return builder.package_dir, trusted_key_path


def test_verifier_parity_pristine_package_both_verified(tmp_path):
    artifact = generate_valid_png()
    pkg_dir, trusted_key_path = _build_package(tmp_path, artifact)
    manifest_p = pkg_dir / "manifest.json"
    assert manifest_p.exists()

    public_key_pem = trusted_key_path.read_bytes()
    ok_py, cl_py = verify_evidence_package(pkg_dir, public_key_pem=public_key_pem)
    assert ok_py is True, f"Python verifier rejected pristine package: {cl_py.explanation}"
    assert cl_py.classification == EvidenceClassification.VERIFIED

    exit_code, stdout = _run_node(manifest_p, trusted_key_path)
    assert exit_code == 0, f"Node verifier exit={exit_code} stdout={stdout[:600]}"
    assert "VERIFIED" in stdout, f"Node stdout missing VERIFIED: {stdout[:500]}"
    assert "Audit event chain (3 events) verified" in stdout
    assert "SCOPE      : NOT ATTESTED" in stdout


def test_verifier_parity_artifact_byte_flip_both_reject(tmp_path):
    artifact = bytearray(generate_valid_png())
    pkg_dir, trusted_key_path = _build_package(tmp_path, bytes(artifact))
    manifest_p = pkg_dir / "manifest.json"

    art_dir = pkg_dir / "recovery" / "artifacts"
    target_file = next(iter(p for p in art_dir.iterdir() if p.is_file()))
    with open(target_file, "r+b") as f:
        f.seek(max(0, target_file.stat().st_size // 2))
        b = f.read(1)
        f.seek(max(0, target_file.stat().st_size // 2))
        flipped = bytes([b[0] ^ 0x01])
        f.write(flipped)

    ok_py, cl_py = verify_evidence_package(pkg_dir, public_key_pem=trusted_key_path.read_bytes())
    assert ok_py is False
    assert cl_py.classification == EvidenceClassification.INVALID

    exit_code, stdout = _run_node(manifest_p, trusted_key_path)
    assert exit_code != 0, f"Node verifier accepted tampered artifact (exit=0)"
    haystack = stdout.upper()
    assert ("INVALID" in haystack) or ("FAILED" in haystack), (
        f"Node output missing INVALID/FAILED on tamper: {stdout[:500]}"
    )


def test_verifier_parity_audit_event_tamper_both_reject(tmp_path):
    artifact = generate_valid_png()
    pkg_dir, trusted_key_path = _build_package(tmp_path, artifact)
    manifest_p = pkg_dir / "manifest.json"

    audit_p = pkg_dir / "audit" / "events.jsonl"
    lines = audit_p.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 2
    last_line = lines[-1]
    last_obj = json.loads(last_line)
    detail_key = next(iter(last_obj.get("details", {}).keys()))
    last_obj["details"][detail_key] = last_obj["details"][detail_key] + "_TAMPERED"
    new_last_raw = json.dumps(last_obj, sort_keys=True, separators=(",", ":"))
    b = bytearray(new_last_raw.encode("utf-8"))
    if len(b) > 0:
        b[-1] = (b[-1] ^ 0x01) if b[-1] != 0x00 else 0x41
    lines[-1] = b.decode("utf-8", errors="replace")
    audit_p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok_py, cl_py = verify_evidence_package(pkg_dir, public_key_pem=trusted_key_path.read_bytes())
    assert ok_py is False

    exit_code, stdout = _run_node(manifest_p, trusted_key_path)
    assert exit_code != 0, f"Node verifier accepted audit chain tamper (exit=0)"
    haystack = stdout.upper()
    chain_related = ("AUDIT_CHAIN" in haystack) or ("CHAIN" in haystack) or ("TAMPER" in haystack)
    assert chain_related, (
        f"Node output on audit tamper doesn't mention AUDIT_CHAIN/CHAIN/TAMPER: {stdout[:500]}"
    )


def test_node_verifier_rejects_embedded_key_without_trust_anchor(tmp_path):
    pkg_dir, _ = _build_package(tmp_path, generate_valid_png())
    manifest_p = pkg_dir / "manifest.json"

    exit_code, stdout = _run_node(manifest_p)

    assert exit_code == 2
    assert "UNTRUSTED" in stdout
    assert "CRYPTOGRAPHICALLY VERIFIED" not in stdout


def test_node_and_python_reject_attacker_package_key_against_original_trust(tmp_path):
    _, trusted_original_key = _build_package(tmp_path / "original", generate_valid_png())
    attacker_pkg, _ = _build_package(tmp_path / "attacker", generate_valid_png())
    manifest = attacker_pkg / "manifest.json"

    ok_py, result_py = verify_evidence_package(
        attacker_pkg,
        public_key_pem=trusted_original_key.read_bytes(),
    )
    assert ok_py is False
    assert result_py.classification == EvidenceClassification.INVALID

    exit_code, stdout = _run_node(manifest, trusted_original_key)
    assert exit_code != 0
    assert "INVALID" in stdout.upper() or "UNTRUSTED" in stdout.upper() or "FAILED" in stdout.upper()
