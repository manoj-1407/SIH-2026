import os
"""
Independent Evidence Package Verifier CLI tool.
Allows forensic examiners and court authorities to verify any exported
evidence envelope against a trusted key registry file.
"""
import sys
import json
import argparse
from pathlib import Path

from app.core.trust import TrustRegistry
from app.core.independent_verifier import verify_evidence_package


def main():
    parser = argparse.ArgumentParser(description='SIH26149 Independent Evidence Verifier')
    parser.add_argument('evidence_file', help='Path to signed evidence JSON package')
    parser.add_argument('--registry', '-r', default=str(__import__('pathlib').Path(__import__('os').environ.get('SIH26149_DATA_DIR', '/app/data')) / 'keys' / 'trust_registry.json'),
                        help='Path to trusted key registry JSON')
    args = parser.parse_args()

    ev_path = Path(args.evidence_file)
    if not ev_path.exists():
        print(f"Error: Evidence file not found: {ev_path}")
        sys.exit(1)

    reg_path = Path(args.registry)
    if not reg_path.exists():
        print(f"Error: Trust registry not found: {reg_path}")
        sys.exit(1)

    with open(ev_path, 'r', encoding='utf-8') as f:
        package = json.load(f)

    registry = TrustRegistry(reg_path)
    is_valid, result = verify_evidence_package(package, key_registry=registry)

    print("==================================================")
    print("      SIH26149 INDEPENDENT EVIDENCE VERIFIER      ")
    print("==================================================")
    print(f"Evidence ID   : {package.get('evidence_id')}")
    print(f"Case ID       : {package.get('case_id')}")
    print(f"Operation ID  : {package.get('operation_id')}")
    print(f"Evidence Type : {package.get('evidence_type')}")
    print(f"Signer Key ID : {package.get('signing', {}).get('key_id')}")
    print(f"Algorithm     : {package.get('signing', {}).get('algorithm')}")
    print(f"Evidence Hash : {package.get('evidence_hash')}")
    print("--------------------------------------------------")
    if is_valid:
        print("VERIFICATION RESULT: [ VALID - CRYPTOGRAPHICALLY VERIFIED ]")
        print(f"Outcome : {result.classification.value}")
        print(f"Details : {result.explanation}")
        sys.exit(0)
    else:
        print("VERIFICATION RESULT: [ INVALID - TAMPER DETECTED / UNTRUSTED KEY ]")
        print(f"Outcome : {result.classification.value}")
        print(f"Details : {result.explanation}")
        sys.exit(2)


if __name__ == '__main__':
    main()
