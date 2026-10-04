"""Build the combined assurance report from the two measured JSON outputs."""

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CORPUS_RESULTS = PROJECT_ROOT / "data" / "corpus_results.json"
BENCHMARK_RESULTS = PROJECT_ROOT / "data" / "benchmark_results.json"
REPORT_PATH = PROJECT_ROOT / "docs" / "FINAL_BENCHMARK_REPORT.md"


def build_report() -> None:
    corpus = json.loads(CORPUS_RESULTS.read_text(encoding="utf-8"))
    benchmark = json.loads(BENCHMARK_RESULTS.read_text(encoding="utf-8"))

    corpus_metrics = corpus["metrics"]
    crypto = benchmark["crypto"]
    payload_matrix = benchmark["payload_matrix"]
    environment = benchmark["environment"]
    lines = [
        "# SIH26149 Final Measured Assurance Report",
        "",
        "This report is generated from `data/corpus_results.json` and "
        "`data/benchmark_results.json` by `scripts/build_final_benchmark_report.py`.",
        "Measurements are from deterministic synthetic inputs and temporary "
        "regular files on the recorded workstation; they are not field or "
        "physical-media performance claims.",
        "",
        "## Run environment",
        "",
        f"- Timestamp (UTC): `{environment['timestamp_utc']}`",
        f"- Platform: `{environment['os']}`",
        f"- Python: `{environment['python_version']}`",
        f"- Processor: `{environment['processor']}`",
        "",
        "## Controlled recovery corpus",
        "",
        f"- Cases: **{corpus['sample_count']}**",
        f"- TP / FP / FN / TN: **{corpus_metrics['TP']} / {corpus_metrics['FP']} / "
        f"{corpus_metrics['FN']} / {corpus_metrics['TN']}**",
        f"- Precision: **{corpus_metrics['precision'] * 100:.1f}%**",
        f"- Recall: **{corpus_metrics['recall'] * 100:.1f}%**",
        f"- F1: **{corpus_metrics['f1']:.4f}**",
        f"- Partial-to-intact overclaims: **{corpus_metrics['overclaims']}**",
        f"- Median raw-carving scan latency: **{corpus_metrics['median_scan_ms']:.3f} ms/case**",
        "",
        "These confusion-matrix figures cover only the script's synthetic raw-carving "
        "cases. Filesystem metadata recovery, timestomp indicators, steganography, "
        "anti-forensics, and exFAT fallback are tested separately and are not "
        "included in these precision/recall totals.",
        "",
        "## Additional controlled coverage",
        "",
        "| Area | Evidence in repository | Boundary |",
        "|---|---|---|",
        "| NTFS deleted-file recovery | [40-case matrix](../tests/corpus/test_40_case_national_matrix.py), cases 31-33 | Synthetic MFT/disk images, not real-media validation |",
        "| FAT32 deleted-file recovery | [40-case matrix](../tests/corpus/test_40_case_national_matrix.py), cases 25-30 | Synthetic FAT32 images with byte-hash ground truth |",
        "| exFAT | [roadmap tests](../tests/unit/test_national_roadmap.py) | Detection and raw-carving fallback only; no metadata-aware recovery |",
        "| Renamed, corrupted, and fragmented files | [24-case matrix](../tests/corpus/test_24_case_matrix.py) | Includes bounded synthetic scenarios; no general arbitrary-extent reconstruction |",
        "| Timestomp and anti-forensics | [40-case matrix](../tests/corpus/test_40_case_national_matrix.py), cases 37-40 | Deterministic timestamp/pattern fixtures |",
        "| Steganography | [steganography tests](../tests/unit/test_steganography.py) | Synthetic LSB fixtures; not an accuracy study on field images |",
        "| HDD/SSD and physical sanitization | Not run | No disposable test drives available; capability preview remains non-executing |",
        "",
        "## Performance matrix",
        "",
        "| Payload | Runs | SHA-256 median | Carving median | Logical zero-fill + readback median | SHA-256 rate | Carving rate | Zero-fill rate |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in payload_matrix:
        lines.append(
            f"| {item['size_mib']} MiB | {item['runs']} | "
            f"{item['sha256_time_ms_median']:.3f} ms | "
            f"{item['carving_time_ms_median']:.3f} ms | "
            f"{item['logical_zero_fill_time_ms_median']:.3f} ms | "
            f"{item['sha256_mib_per_sec']['median']:.2f} MiB/s | "
            f"{item['carving_mib_per_sec']['median']:.2f} MiB/s | "
            f"{item['logical_zero_fill_mib_per_sec']['median']:.2f} MiB/s |"
        )

    lines.extend([
        "",
        "## Evidence verification and sanitization scope",
        "",
        f"- Ed25519 signing median / p95: **{crypto['sign_latency_ms']['median']:.3f} / "
        f"{crypto['sign_latency_ms']['p95']:.3f} ms** "
        f"({crypto['sign_latency_ms']['iterations']} iterations).",
        f"- Independent directory-package verification median / p95: "
        f"**{crypto['verify_latency_ms']['median']:.3f} / "
        f"{crypto['verify_latency_ms']['p95']:.3f} ms** "
        f"({crypto['verify_latency_ms']['iterations']} repeated checks of "
        f"{crypto['verify_latency_ms']['distinct_packages']} generated package).",
        "- Cross-implementation integrity tests exercise two tampering cases (artifact-byte "
        "modification and audit-event modification); both Python and Node.js verifiers reject "
        "them. This is a deterministic test result, not a general tamper-detection probability.",
        "- Logical sanitization measurement: single-pass zero-fill/read-back of temporary "
        "regular files only. It does not test remapped sectors, SSD NAND, or controller behavior.",
        "- ATA Secure Erase, NVMe Sanitize, real HDD/SSD operation timing, and physical "
        "post-operation verification: **NOT RUN** (no disposable test drive available).",
        "- Large 1–100 GB workloads and memory RSS: **NOT MEASURED**.",
        "- Real-media recovery rates and broad real-world false-positive/false-negative rates: "
        "**NOT MEASURED**.",
        "- The post-operation proof loop is an in-memory validation probe and is not included "
        "as a physical-device or sanitization benchmark.",
        "",
        "The Node.js verifier requires an independently supplied trusted public key or "
        "trust registry. A key embedded in an evidence package is never used as its own "
        "trust anchor. Scope, operation, and post-probe fields are reported as "
        "`NOT ATTESTED` when they are absent from the signed input.",
        "",
        "## Reproduction",
        "",
        "From `sih26149/`, run:",
        "",
        "```powershell",
        r"..\.venv\Scripts\python.exe scripts\test_real_world_corpus_rc2.py",
        r"..\.venv\Scripts\python.exe scripts\run_benchmark_matrix.py",
        r"..\.venv\Scripts\python.exe scripts\build_final_benchmark_report.py",
        "```",
        "",
        "The benchmark regenerates its JSON result files and `docs/BENCHMARK_REPORT.md`; "
        "the final report is then rebuilt from those JSON outputs.",
        "",
    ])
    REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")
    print(f"Final measured report written to {REPORT_PATH}")


if __name__ == "__main__":
    build_report()
