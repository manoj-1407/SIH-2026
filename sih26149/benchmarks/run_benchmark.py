"""
Forensic Assurance Performance Benchmark Suite — SIH26149.

Measures actual throughput and latency across:
1. Source Hashing (SHA-256 chunked throughput)
2. Carving & Multi-Layer File Validation Throughput
3. RFC 8785 Canonicalization & Ed25519 Signing Latency
4. Self-Contained Evidence Package Generation Time
5. Independent Evidence Verification Latency
"""
import time
import platform
import os
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.hashing import hash_bytes
from app.core.canonical import canonicalize
from app.core.signing import generate_keypair, sign_evidence
from app.core.package import EvidencePackageBuilder
from app.core.independent_verifier import verify_evidence_package
from app.forensics.carving import carve_bytes
from tests.corpus.generator import generate_valid_jpeg, generate_valid_png, generate_valid_pdf, generate_valid_zip, generate_valid_mp4


def benchmark():
    print("================================================================================")
    print("         SIH26149 FORENSIC ASSURANCE SYSTEM PERFORMANCE BENCHMARK               ")
    print("================================================================================")
    print(f"Platform       : {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Processor      : {platform.processor() or 'x86_64 / ARM'}")
    print(f"Python Version : {platform.python_version()}")
    print("--------------------------------------------------------------------------------")

    # 1. Hashing Throughput (100 MB payload)
    test_size_mb = 50
    test_data = b"\x5A" * (test_size_mb * 1024 * 1024)
    t0 = time.perf_counter()
    hash_bytes(test_data)
    t_hash = time.perf_counter() - t0
    hash_throughput = test_size_mb / t_hash
    print(f"1. SHA-256 Hashing Throughput       : {hash_throughput:8.2f} MB/s ({test_size_mb} MB in {t_hash*1000:6.2f} ms)")

    # 2. Carving & Multi-Layer Validation Throughput
    # Synthesize composite stream with 50 embedded artifacts
    artifacts = generate_valid_jpeg() + generate_valid_png() + generate_valid_pdf() + generate_valid_zip() + generate_valid_mp4()
    stream = artifacts * 10  # 50 artifacts in stream
    stream_mb = len(stream) / (1024 * 1024)
    t0 = time.perf_counter()
    carved = carve_bytes(stream)
    t_carve = time.perf_counter() - t0
    carve_throughput = stream_mb / t_carve if t_carve > 0 else 0
    print(f"2. Carving & Validation Speed      : {carve_throughput:8.2f} MB/s ({len(carved)} artifacts carved in {t_carve*1000:6.2f} ms)")

    # 3. Canonicalization & Ed25519 Signing Latency
    priv_pem, pub_raw = generate_keypair()
    payload = {"case_id": "BENCH-001", "artifacts": [c.to_dict() for c in carved]}
    t0 = time.perf_counter()
    for _ in range(100):
        canon = canonicalize(payload)
        sig = sign_evidence(priv_pem, canon)
    t_sig = (time.perf_counter() - t0) / 100
    print(f"3. RFC 8785 + Ed25519 Signing Latency: {t_sig*1000:8.3f} ms / envelope")

    # 4. Independent Verification Latency
    tmp_dir = Path(__file__).parent / "bench_workdir"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    from cryptography.hazmat.primitives import serialization
    priv_obj = serialization.load_pem_private_key(priv_pem, password=None)
    pub_pem = priv_obj.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    builder = EvidencePackageBuilder("CASE-BENCH", tmp_dir)
    builder.write_source_metadata({"size": test_size_mb * 1024 * 1024})
    builder.write_recovery_artifacts({"total_carved": len(carved)})
    pkg_meta = builder.build_and_sign(priv_pem, pub_pem, "KEY-BENCH")
    pkg_path = Path(pkg_meta["package_path"])

    t0 = time.perf_counter()
    for _ in range(100):
        verify_evidence_package(pkg_path, public_key_pem=pub_pem)
    t_ver = (time.perf_counter() - t0) / 100
    print(f"4. Independent Package Verification : {t_ver*1000:8.3f} ms / package")

    # Cleanup
    import shutil
    shutil.rmtree(tmp_dir, ignore_errors=True)

    print("================================================================================")
    print("                    BENCHMARK COMPLETED SUCCESSFULLY                            ")
    print("================================================================================")


if __name__ == "__main__":
    benchmark()
