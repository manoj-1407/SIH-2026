"""
Audit Canonicalization Parity Test.

Ensures audit._canonical_json() and canonical.canonicalize() produce
byte-identical output on adversarial inputs (large integers, Unicode
Devanagari keys, negative zero floats, deeply nested objects) so that
audit chain hashes created by audit.py remain verifiable by the
independent third-party verifier.

SIH26149 National-Level Defense: This test exists because audit.py
originally used sort_keys=True which diverges from RFC 8785 JCS for
numbers >= 2^53 (float-64 precision loss) and non-ASCII key ordering
(UTF-8 bytes vs UTF-16 code units). Any divergence = audit chain fails
verification in front of a judge.
"""
import hashlib
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from app.cases.audit import _canonical_json
from app.core.canonical import canonicalize


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def test_parity_large_integer_2pow53_plus3():
    """Integer >= 2^53 is where vanilla sort_keys (Python json.dumps) and
    JCS can diverge if the number is stored as float during JSON roundtrip.
    canonical.canonicalize preserves exact int representation; audit
    previously could lose that precision via default float coercion. We
    verify byte-for-byte identical."""
    entry = {
        "entry_index": 7,
        "previous_hash": "GENESIS",
        "event_type": "evidence_signed",
        "counter": 9007199254740993,  # 2^53 + 3, exactly one beyond safe float
        "actor": {"id": "e-001", "name": "Nitro Examiner"},
        "timestamp_ms": 1790962000000,  # also a large int (millis epoch)
    }
    audit_bytes = _canonical_json(entry)
    jcs_bytes = canonicalize({k: v for k, v in entry.items() if k != "entry_hash"})
    assert audit_bytes == jcs_bytes, (
        f"Large-int parity FAILED.\n"
        f"audit sha256 = {_sha(audit_bytes)}\n"
        f"jcs   sha256 = {_sha(jcs_bytes)}\n"
        f"audit raw = {audit_bytes[:300]!r}\n"
        f"jcs   raw = {jcs_bytes[:300]!r}"
    )
    assert _sha(audit_bytes) == _sha(jcs_bytes)


def test_parity_unicode_devanagari_keys():
    """RFC 8785 JCS sorts by UTF-16 code units. Vanilla sort_keys sorts by
    UTF-8 byte string, which differs for Hindi/Devanagari digits and
    letters. We mix Devanagari keys with Latin and verify sort order."""
    entry = {
        "entry_index": 0,
        "previous_hash": "GENESIS",
        "केस_नंबर_७": "deleted-file-evidence",
        "आरक्षण_स्तर": "CONFIDENTIAL",
        "case_ref_no": "NTRO-2026-PS26149-0042",
        "details": {
            "फाइल_नाम": "Q3-Report.docx",
            "sha256": "a" * 64,
            "साइज_बाइट्स": 134288,
        },
    }
    audit_bytes = _canonical_json(entry)
    jcs_bytes = canonicalize({k: v for k, v in entry.items() if k != "entry_hash"})
    assert audit_bytes == jcs_bytes, (
        f"Unicode-key parity FAILED.\n"
        f"audit sha256 = {_sha(audit_bytes)}\n"
        f"jcs   sha256 = {_sha(jcs_bytes)}\n"
        f"audit raw = {audit_bytes[:500]!r}\n"
        f"jcs   raw = {jcs_bytes[:500]!r}"
    )


def test_parity_negative_zero_and_edge_floats():
    """RFC 8785 JCS normalizes -0.0 -> "0". Vanilla json.dumps keeps -0.0 as -0.0
    on some Python versions. Also test large floats, small floats,
    integers stored as float (3.0 -> "3"), and empty containers."""
    entry = {
        "entry_index": 3,
        "previous_hash": "abc" * 21 + "def",
        "event_type": "sanitization",
        "temp_k": -0.0,
        "exact_integer_as_float": 3.0,
        "exact_huge_int_as_float": 1000000000000000.0,  # 1e15, renders as 1e+15 -> 1000000000000000? JCS canonical form.
        "nan_should_never_appear_but_keep_here_as_flag": 0.0000001,
        "tiny_positive": 1e-7,
        "empty_obj": {},
        "empty_list": [],
        "null_field": None,
        "bools": [True, False, True],
    }
    audit_bytes = _canonical_json(entry)
    jcs_bytes = canonicalize({k: v for k, v in entry.items() if k != "entry_hash"})
    assert audit_bytes == jcs_bytes, (
        f"Float/edge parity FAILED.\n"
        f"audit sha256 = {_sha(audit_bytes)}\n"
        f"jcs   sha256 = {_sha(jcs_bytes)}\n"
        f"audit raw = {audit_bytes[:800]!r}\n"
        f"jcs   raw = {jcs_bytes[:800]!r}"
    )


def test_parity_deeply_nested():
    """Deep nesting + heterogenous types. This is the shape of a real
    audit 'details' block. Catch any recursive canonicalizer drift."""
    entry = {
        "entry_index": 11,
        "previous_hash": _sha(b"prev"),
        "event_type": "verification_result",
        "actor": {"id": "ver-0x01", "roles": ["independent", "offline"]},
        "details": {
            "stages": [
                {"name": "schema", "ok": True},
                {"name": "key_resolution", "ok": True},
                {
                    "name": "manifest_equality",
                    "ok": True,
                    "expected_sha256": "a" * 64,
                    "actual_sha256": "a" * 64,
                },
                {
                    "name": "canonical_equality",
                    "ok": True,
                    "byte_diffs": [],
                    "metadata": {"signed_by_keyid": "ntro-2026-01",
                                 "counter": 9007199254740995},
                },
                {
                    "name": "def005_injected_file_scan",
                    "ok": True,
                    "count_found": 0,
                    "dirs_scanned": ["recovered", "cryptography", "audit"],
                },
                {
                    "name": "audit_chain",
                    "ok": True,
                    "chain_length": 14,
                    "last_event_hash": _sha(b"audit-last"),
                    "anomalies": [],
                },
            ],
            "result": "VERIFIED",
            "confidence": 1.0,
        },
        "timestamp_ms": 1790963000000,
    }
    audit_bytes = _canonical_json(entry)
    jcs_bytes = canonicalize({k: v for k, v in entry.items() if k != "entry_hash"})
    assert audit_bytes == jcs_bytes, (
        f"Deep-nested parity FAILED.\n"
        f"audit sha256 = {_sha(audit_bytes)}\n"
        f"jcs   sha256 = {_sha(jcs_bytes)}"
    )


if __name__ == "__main__":
    test_parity_large_integer_2pow53_plus3()
    test_parity_unicode_devanagari_keys()
    test_parity_negative_zero_and_edge_floats()
    test_parity_deeply_nested()
    print(f"OK — 4 audit-vs-jcs parity scenarios byte-identical ({_sha}).")
