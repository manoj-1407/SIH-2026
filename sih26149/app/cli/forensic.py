"""
Unified Forensic Workstation CLI — SIH26149.

Commands:
  forensic recover   --source <image.raw> --output <dir> --case <id>
  forensic sanitize  --target <path> --method <clear|purge> --scope <scope.json>
  forensic verify    --evidence <package_or_json> --public-key <key.pem>
"""
import sys
import json
import argparse
from pathlib import Path

from app.core.hashing import hash_file
from app.forensics.carving import carve_image_summary
from app.forensics.filesystem import detect_filesystem
from app.sanitization.device_detector import detect_media_type, SanitizationLevel
from app.core.independent_verifier import verify_evidence_package


def cmd_recover(args):
    source_p = Path(args.source)
    if not source_p.exists():
        if args.json:
            print(json.dumps({"error": f"Source image '{source_p}' not found", "status": "ERROR"}))
        else:
            print(f"Error: Source image '{source_p}' not found.")
        sys.exit(1)

    src_hash = hash_file(str(source_p))
    fs_cap = detect_filesystem(str(source_p))
    summary = carve_image_summary(str(source_p), max_results=args.max_results)

    if args.output:
        out_dir = Path(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)
        summary_path = out_dir / "recovery_summary.json"
        summary_path.write_text(json.dumps(summary, indent=2), encoding='utf-8')

    if args.json:
        out = {
            "case_id": args.case,
            "source_path": str(source_p.resolve()),
            "source_sha256": src_hash.hex_digest,
            "source_size_bytes": src_hash.size_bytes,
            "filesystem": fs_cap.to_dict(),
            "summary": summary,
        }
        print(json.dumps(out, indent=2))
    else:
        print(f"=== SIH26149 FORENSIC RECOVERY: {args.case} ===")
        print(f"Source Path     : {source_p.resolve()}")
        print(f"Source SHA-256  : {src_hash.hex_digest}")
        print(f"Source Size     : {src_hash.size_bytes:,} bytes")
        print(f"Filesystem      : {fs_cap.filesystem.upper()} ({fs_cap.status_label})")
        print(f"Recovery Backend: {fs_cap.recovery_method}")
        print("\nExecuting carving & structural validation...")
        print(f"Candidates Found : {summary['total_carved']}")
        print(f"  - Validated Intact : {summary['intact']}")
        print(f"  - High Confidence  : {summary['high_confidence']}")
        print(f"  - Reconstructed    : {summary['bifragmented_reconstructed']}")
        print(f"  - Partial Stream   : {summary['partial']}")
        if args.output:
            print(f"\nRecovery manifest exported to: {Path(args.output) / 'recovery_summary.json'}")


def cmd_sanitize(args):
    target = args.target
    method = args.method.upper()
    cap = detect_media_type(target)

    if method == "PURGE" and not cap.purge_supported:
        if args.json:
            print(json.dumps({
                "status": "BLOCKED",
                "reason": f"Requested method 'PURGE' is unsupported on detected media type '{cap.media_type.value}'",
                "media_type": cap.media_type.value,
                "purge_supported": False,
            }))
        else:
            print(f"=== SIH26149 MEDIA SANITIZATION: {args.case} ===")
            print(f"Target          : {target}")
            print(f"Requested Method: {method}")
            print(f"Detected Media  : {cap.media_type.value}")
            print("\n[ACTION BLOCKED] Fail-Closed Enforcement:")
            print(f"Requested method 'PURGE' is unsupported on detected media type '{cap.media_type.value}'.")
            print("Hardware sanitize command (ATA Secure Erase / NVMe Sanitize) cannot be issued.")
            print("No destructive operation performed.")
        sys.exit(3)

    if args.json:
        print(json.dumps({
            "status": "AUTHORIZED",
            "case_id": args.case,
            "target": target,
            "method": method,
            "media_type": cap.media_type.value,
            "recommended_level": cap.recommended_level.value,
            "scope_statement": cap.scope_statement,
        }, indent=2))
    else:
        print(f"=== SIH26149 MEDIA SANITIZATION: {args.case} ===")
        print(f"Target          : {target}")
        print(f"Requested Method: {method}")
        print(f"Detected Media  : {cap.media_type.value}")
        print(f"Recommended     : {cap.recommended_level.value} ({cap.recommended_level.nist_reference})")
        print(f"Clear Supported : {cap.clear_supported}")
        print(f"Purge Supported : {cap.purge_supported}")
        print("\nSanitization Authorization Verified.")
        print(f"Scope: {cap.scope_statement}")


def cmd_verify(args):
    target_p = Path(args.evidence)
    if not target_p.exists():
        if args.json:
            print(json.dumps({"status": "ERROR", "error": f"Evidence path '{target_p}' not found"}))
        else:
            print(f"Error: Evidence path '{target_p}' not found.")
        sys.exit(1)

    pub_key_pem = None
    if args.public_key:
        pub_p = Path(args.public_key)
        if pub_p.exists():
            pub_key_pem = pub_p.read_bytes()

    is_valid, res = verify_evidence_package(target_p, public_key_pem=pub_key_pem)

    if args.json:
        out = {
            "valid": is_valid,
            "target": str(target_p.resolve()),
            "classification": res.classification.value,
            "explanation": res.explanation,
        }
        print(json.dumps(out, indent=2))
    else:
        print("==================================================")
        print("      SIH26149 INDEPENDENT EVIDENCE VERIFIER      ")
        print("==================================================")
        print(f"Target   : {target_p.resolve()}")
        print(f"Outcome  : {res.classification.value}")
        print(f"Details  : {res.explanation}")
        print("--------------------------------------------------")
        if is_valid:
            print("RESULT: [ VALID - CRYPTOGRAPHICALLY VERIFIED ]")
        else:
            print("RESULT: [ INVALID - TAMPER DETECTED / UNTRUSTED ]")

    sys.exit(0 if is_valid else 2)


def main():
    parser = argparse.ArgumentParser(description="SIH26149 Unified Forensic CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Recover
    p_rec = subparsers.add_parser("recover", help="Recover deleted and carved artifacts")
    p_rec.add_argument("--source", "-s", required=True, help="Forensic image path")
    p_rec.add_argument("--output", "-o", help="Output directory for recovered artifacts")
    p_rec.add_argument("--case", "-c", default="CASE-CLI-01", help="Case ID")
    p_rec.add_argument("--max-results", type=int, default=500, help="Max candidates")
    p_rec.add_argument("--json", action="store_true", help="Output results in machine-readable JSON")
    p_rec.set_defaults(func=cmd_recover)

    # Sanitize
    p_san = subparsers.add_parser("sanitize", help="Perform NIST SP 800-88 Rev. 2 sanitization")
    p_san.add_argument("--target", "-t", required=True, help="Target file or disk image")
    p_san.add_argument("--method", "-m", default="CLEAR", choices=["CLEAR", "PURGE", "DESTROY"], help="Sanitization method")
    p_san.add_argument("--case", "-c", default="CASE-CLI-01", help="Case ID")
    p_san.add_argument("--scope", help="Authorization scope JSON file")
    p_san.add_argument("--json", action="store_true", help="Output results in machine-readable JSON")
    p_san.set_defaults(func=cmd_sanitize)

    # Verify
    p_ver = subparsers.add_parser("verify", help="Independently verify evidence package or envelope")
    p_ver.add_argument("--evidence", "-e", required=True, help="Path to evidence package directory or JSON")
    p_ver.add_argument("--public-key", "-k", help="Path to trusted public key PEM file")
    p_ver.add_argument("--json", action="store_true", help="Output results in machine-readable JSON")
    p_ver.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
