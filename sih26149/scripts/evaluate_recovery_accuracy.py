"""
SIH26149 — Forensic Recovery Accuracy & Precision/Recall Evaluation Harness.

Constructs a structured ground-truth corpus with known files across 4 categories:
1. Contiguous intact files (JPEG, PNG, PDF)
2. One bounded sequentially fragmented JPEG case
3. Missing fragments / Truncated streams
4. Corrupted files / False magic byte traps

Evaluates the carving and structural validation engine against ground truth,
calculating Precision, Recall, and F1 per category and overall.

Non-sequential fragmentation is covered separately by the corpus tests and is
not scored by this harness.

Outputs: docs/RECOVERY_ACCURACY.md and data/recovery_accuracy_results.json
"""
import io
import json
import os
import sys
import tempfile
import statistics
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.hashing import hash_bytes
from app.forensics.carving import carve_bytes, CarvingConfidence
from app.forensics.synthetic import generate_fragmented_jpeg_case
from app.forensics.validation import validate_carved_file, ValidationOutcome


@dataclass
class GroundTruthItem:
    item_id: str
    category: str
    file_type: str
    expected_outcome: str  # "INTACT", "RECONSTRUCTED", "PARTIAL", "REJECTED"
    data: bytes
    sha256: str
    description: str


def build_evaluation_corpus() -> List[GroundTruthItem]:
    corpus = []

    # 1. Standard Intact Files
    jpeg_intact = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00\x43\x00"
        + (b"\x01" * 64)
        + b"\xff\xc0\x00\x0b\x08\x00\x10\x00\x10\x01\x01\x11\x00\xff\xda\x00\x08\x01\x01\x00\x00?\x00\x00\xff\xd9"
    )
    corpus.append(GroundTruthItem("GT-01", "Contiguous", "JPEG", "INTACT", jpeg_intact, hash_bytes(jpeg_intact), "Valid JFIF JPEG"))

    png_ihdr = b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    png_iend = b"\x00\x00\x00\x00IEND\xaeB`\x82"
    png_intact = b"\x89PNG\r\n\x1a\n" + png_ihdr + png_iend
    corpus.append(GroundTruthItem("GT-02", "Contiguous", "PNG", "INTACT", png_intact, hash_bytes(png_intact), "Valid PNG with IHDR/IEND"))

    pdf_intact = (
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
        b"xref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\n"
        b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n185\n%%EOF\n"
    )
    corpus.append(GroundTruthItem("GT-03", "Contiguous", "PDF", "INTACT", pdf_intact, hash_bytes(pdf_intact), "Valid PDF document"))

    # 2. Sequential Fragmented Files (deterministic known-good two-extent fixture)
    frag_stream, reconstructed_jpeg = generate_fragmented_jpeg_case(gap_size=1024)
    corpus.append(GroundTruthItem("GT-04", "Sequential Fragmented", "JPEG", "RECONSTRUCTED", frag_stream, hash_bytes(reconstructed_jpeg), "JPEG with 1KB gap"))

    # 3. Truncated / Missing Fragments
    jpeg_truncated = jpeg_intact[:jpeg_intact.index(b"\xff\xda")]  # Missing SOS and EOI
    corpus.append(GroundTruthItem("GT-05", "Missing Fragments", "JPEG", "PARTIAL", jpeg_truncated, hash_bytes(jpeg_truncated), "JPEG missing SOS/EOI"))

    pdf_truncated = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>\n"  # No xref/trailer/EOF
    corpus.append(GroundTruthItem("GT-06", "Missing Fragments", "PDF", "PARTIAL", pdf_truncated, hash_bytes(pdf_truncated), "PDF missing xref table"))

    # 4. Corrupted / False Magic Byte Traps
    fake_jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF" + (b"\xde\xad\xbe\xef" * 128) + b"\xff\xd9"
    corpus.append(GroundTruthItem("GT-07", "Corrupted Traps", "JPEG", "REJECTED", fake_jpeg, hash_bytes(fake_jpeg), "JPEG header with garbage body"))

    fake_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + (b"\x00" * 20) + b"\x00\x00\x00\x00IEND\x00\x00\x00\x00"  # Invalid CRC
    corpus.append(GroundTruthItem("GT-08", "Corrupted Traps", "PNG", "REJECTED", fake_png, hash_bytes(fake_png), "PNG with invalid chunk CRC"))

    return corpus


def evaluate_accuracy():
    corpus = build_evaluation_corpus()
    print("=" * 60)
    print("  SIH26149 CONTROLLED SYNTHETIC RECOVERY EVALUATION")
    print("=" * 60)

    category_stats = {}
    evaluations = []
    scan_times_ms = []

    for item in corpus:
        cat = item.category
        if cat not in category_stats:
            category_stats[cat] = {"TP": 0, "FP": 0, "FN": 0, "TN": 0, "total": 0}
        category_stats[cat]["total"] += 1

        # Embed item into isolated buffer with surrounding unallocated noise
        carrier = b"\xaa\xbb\xcc\xdd" * 64 + item.data + b"\x55\x66\x77\x88" * 64
        scan_started = time.perf_counter()
        carved = carve_bytes(carrier, max_results=50)
        elapsed_ms = (time.perf_counter() - scan_started) * 1000
        scan_times_ms.append(elapsed_ms)

        # Analyze carve result
        matching_carve = [c for c in carved if c.file_type == item.file_type]
        exact = [c for c in matching_carve if c.sha256 == item.sha256]
        sample_stats = category_stats[cat]
        label = "FN (ground-truth bytes not recovered)"

        if item.expected_outcome == "INTACT":
            valid = [c for c in exact if c.confidence in (CarvingConfidence.INTACT, CarvingConfidence.HIGH)]
            if valid:
                sample_stats["TP"] += 1
                label = "TP (ground-truth bytes and intact confidence match)"
            else:
                sample_stats["FN"] += 1
                if matching_carve:
                    sample_stats["FP"] += len(matching_carve)
                    label = "FP+FN (wrong bytes or confidence)"

        elif item.expected_outcome == "RECONSTRUCTED":
            valid = [c for c in exact if c.confidence == CarvingConfidence.BIFRAGMENTED]
            if valid:
                sample_stats["TP"] += 1
                label = "TP (ground-truth reconstruction hash matches)"
            else:
                sample_stats["FN"] += 1
                if matching_carve:
                    sample_stats["FP"] += len(matching_carve)
                    label = "FP+FN (no exact fragmented reconstruction)"

        elif item.expected_outcome == "PARTIAL":
            valid = [c for c in exact if c.confidence in (
                CarvingConfidence.PARTIAL_STRUCT,
                CarvingConfidence.HEADER_ONLY,
                CarvingConfidence.BIFRAGMENTED,
            )]
            if valid:
                sample_stats["TP"] += 1
                label = "TP (ground-truth bytes bounded as partial)"
            else:
                sample_stats["FN"] += 1
                if exact and any(c.confidence in (CarvingConfidence.INTACT, CarvingConfidence.HIGH) for c in exact):
                    sample_stats["FP"] += 1
                    label = "FP+FN (partial input promoted to intact/high)"
                elif matching_carve:
                    sample_stats["FP"] += len(matching_carve)
                    label = "FP+FN (wrong candidate bytes)"

        elif item.expected_outcome == "REJECTED":
            if matching_carve:
                sample_stats["FP"] += len(matching_carve)
                label = "FP (candidate emitted for rejected input)"
            else:
                sample_stats["TN"] += 1
                label = "TN (no candidate emitted)"
        evaluations.append({
            "item_id": item.item_id,
            "category": item.category,
            "expected": item.expected_outcome,
            "description": item.description,
            "reference_sha256": item.sha256,
            "recovered_sha256": exact[0].sha256 if exact else None,
            "confidence": exact[0].confidence.value if exact else None,
            "scan_time_ms": round(elapsed_ms, 3),
            "evaluation": label,
        })

    # Calculate metrics
    overall_tp = sum(s["TP"] for s in category_stats.values())
    overall_fp = sum(s["FP"] for s in category_stats.values())
    overall_fn = sum(s["FN"] for s in category_stats.values())
    overall_tn = sum(s["TN"] for s in category_stats.values())

    precision = overall_tp / (overall_tp + overall_fp) if (overall_tp + overall_fp) > 0 else 0.0
    recall = overall_tp / (overall_tp + overall_fn) if (overall_tp + overall_fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    print(f"\nOverall Evaluation Across {len(corpus)} Ground-Truth Scenarios:")
    print(f"  - True Positives  : {overall_tp}")
    print(f"  - True Negatives  : {overall_tn}")
    print(f"  - False Positives : {overall_fp}")
    print(f"  - False Negatives : {overall_fn}")
    print(f"  - Precision       : {precision * 100:.1f}%")
    print(f"  - Recall          : {recall * 100:.1f}%")
    print(f"  - F1 Score        : {f1:.4f}\n")

    # Generate Markdown Documentation
    doc_md = f"""# Controlled Synthetic Forensic Recovery Accuracy Report

## Ground Truth Evaluation Methodology
The SIH26149 evaluation harness subjects the raw carver to deterministic
in-memory fixtures with known byte hashes, partial streams, and rejected traps.
This is not a real-world or physical-media accuracy estimate.

---

## 1. Quantitative Performance Matrix

| Scenario Category | Test Cases | TP | FP | FN | Precision | Recall | Category F1 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
"""
    for cat, s in category_stats.items():
        cat_tp = s["TP"]
        cat_fp = s["FP"]
        cat_fn = s["FN"]
        cat_p = cat_tp / (cat_tp + cat_fp) if (cat_tp + cat_fp) > 0 else 0.0
        cat_r = cat_tp / (cat_tp + cat_fn) if (cat_tp + cat_fn) > 0 else 0.0
        cat_f1 = 2 * (cat_p * cat_r) / (cat_p + cat_r) if (cat_p + cat_r) > 0 else 0.0
        doc_md += f"| **{cat}** | {s['total']} | {cat_tp} | {cat_fp} | {cat_fn} | **{cat_p * 100:.1f}%** | **{cat_r * 100:.1f}%** | **{cat_f1:.4f}** |\n"

    doc_md += f"""
---

## 2. Global Metric Summary

- **Overall Precision**: **{precision * 100:.1f}%**
- **Overall Recall**: **{recall * 100:.1f}%**
- **Overall F1 Score**: **{f1:.4f}**
- **TP / FP / FN / TN**: **{overall_tp} / {overall_fp} / {overall_fn} / {overall_tn}**
- **Median scan latency**: **{statistics.median(scan_times_ms):.3f} ms/case**
- A sample can contribute both FP and FN when an emitted candidate does not match its ground-truth bytes or expected confidence.

---

## 3. Limits
- Each positive requires an exact ground-truth hash and confidence compatible with its expected intact/partial/reconstructed state.
- Rejected cases count any emitted candidate as a false positive.
- Results apply only to these fixtures. They do not estimate field-evidence performance, filesystem metadata recovery, sanitization, or physical media.
- Non-sequential/multi-hop fragmentation is outside this harness.
"""

    report_path = Path(__file__).resolve().parent.parent / "docs" / "RECOVERY_ACCURACY.md"
    report_path.write_text(doc_md, encoding="utf-8")
    print(f"[+] Recovery accuracy report exported to: {report_path.resolve()}")
    data_dir = Path(__file__).resolve().parent.parent / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    results_path = data_dir / "recovery_accuracy_results.json"
    results_path.write_text(json.dumps({
        "evaluation_type": "controlled_synthetic_raw_carving",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sample_count": len(corpus),
        "metrics": {
            "TP": overall_tp,
            "FP": overall_fp,
            "FN": overall_fn,
            "TN": overall_tn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "median_scan_ms": statistics.median(scan_times_ms),
        },
        "samples": evaluations,
        "physical_media_tested": False,
    }, indent=2), encoding="utf-8")
    print(f"[+] Machine-readable results exported to: {results_path.resolve()}")


if __name__ == "__main__":
    evaluate_accuracy()
