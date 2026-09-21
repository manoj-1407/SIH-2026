"""
Portable Self-Contained Forensic Evidence Package Engine — SIH26149.

Produces a structured, self-contained evidence package directory:
case-XXXX/
├── manifest.json
├── source/
│   └── metadata.json
├── recovery/
│   ├── artifacts.json
│   └── artifacts/
├── sanitization/
│   └── result.json
├── audit/
│   └── events.jsonl
├── cryptography/
│   ├── signature.json
│   └── public_key.pem
├── reports/
│   ├── report.html
│   └── report.pdf
└── verification/
    └── verification.json

The package is completely offline-first, portable, and independently verifiable
without the producer database or application runtime state.
"""
import os
import json
import shutil
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from app.core.canonical import canonicalize, canonicalize_str
from app.core.hashing import hash_bytes, hash_file
from app.core.signing import sign_evidence


class EvidencePackageBuilder:
    def __init__(self, case_id: str, output_base_dir: str | Path):
        self.case_id = case_id
        self.package_dir = Path(output_base_dir) / f"{case_id}_evidence_package"
        self.source_dir = self.package_dir / "source"
        self.recovery_dir = self.package_dir / "recovery"
        self.recovery_artifacts_dir = self.recovery_dir / "artifacts"
        self.sanitization_dir = self.package_dir / "sanitization"
        self.audit_dir = self.package_dir / "audit"
        self.crypto_dir = self.package_dir / "cryptography"
        self.reports_dir = self.package_dir / "reports"
        self.verification_dir = self.package_dir / "verification"

        # Create directory layout
        for d in (self.source_dir, self.recovery_artifacts_dir, self.sanitization_dir,
                  self.audit_dir, self.crypto_dir, self.reports_dir, self.verification_dir):
            d.mkdir(parents=True, exist_ok=True)

    def write_source_metadata(self, metadata: dict) -> Path:
        target = self.source_dir / "metadata.json"
        target.write_bytes(canonicalize(metadata))
        return target

    def write_recovery_artifacts(self, summary: dict, artifacts: Optional[List[dict]] = None) -> Path:
        target = self.recovery_dir / "artifacts.json"
        data = dict(summary)
        if artifacts:
            data["artifacts"] = artifacts
        target.write_bytes(canonicalize(data))
        return target

    def write_sanitization_result(self, result: dict) -> Path:
        target = self.sanitization_dir / "result.json"
        target.write_bytes(canonicalize(result))
        return target

    def copy_audit_log(self, source_jsonl: str | Path) -> Path:
        target = self.audit_dir / "events.jsonl"
        src = Path(source_jsonl)
        if src.exists():
            shutil.copy2(src, target)
        else:
            target.write_text("", encoding='utf-8')
        return target

    def write_reports(self, html_content: Optional[str] = None, pdf_bytes: Optional[bytes] = None) -> None:
        if html_content:
            (self.reports_dir / "report.html").write_text(html_content, encoding='utf-8')
        if pdf_bytes:
            (self.reports_dir / "report.pdf").write_bytes(pdf_bytes)

    def build_and_sign(self, private_key_pem: bytes, public_key_pem: bytes, key_id: str) -> dict:
        """
        Computes SHA-256 digests of all package files, creates canonical manifest.json,
        signs manifest with Ed25519, writes signature.json, and exports public_key.pem.
        """
        # 1. Compute file manifests
        file_hashes = {}
        for root, _, files in os.walk(self.package_dir):
            for f in files:
                full_p = Path(root) / f
                rel_p = str(full_p.relative_to(self.package_dir)).replace("\\", "/")
                # Skip signature and manifest during computation
                if rel_p in ("manifest.json", "cryptography/signature.json", "cryptography/public_key.pem"):
                    continue
                file_hashes[rel_p] = hash_file(str(full_p)).hex_digest

        # Export public key
        pub_path = self.crypto_dir / "public_key.pem"
        pub_path.write_bytes(public_key_pem)

        manifest = {
            "schema_version": "1.0.0",
            "case_id": self.case_id,
            "created_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "standard_references": [
                "NIST SP 800-88 Rev. 2",
                "NIST CFTT",
                "RFC 8032 (Ed25519)",
                "RFC 8785 (JCS)"
            ],
            "file_hashes": file_hashes,
            "signing": {
                "algorithm": "Ed25519",
                "key_id": key_id,
            }
        }

        # Canonicalize and hash manifest
        manifest_bytes = canonicalize(manifest)
        (self.package_dir / "manifest.json").write_bytes(manifest_bytes)
        manifest_hash = hash_bytes(manifest_bytes)

        # Sign manifest hash / bytes
        signature_hex = sign_evidence(private_key_pem, manifest_bytes)

        sig_record = {
            "key_id": key_id,
            "algorithm": "Ed25519",
            "manifest_hash": manifest_hash,
            "signature": signature_hex,
            "signed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        (self.crypto_dir / "signature.json").write_bytes(canonicalize(sig_record))

        return {
            "package_path": str(self.package_dir),
            "manifest_hash": manifest_hash,
            "signature": signature_hex,
            "files_count": len(file_hashes),
        }
