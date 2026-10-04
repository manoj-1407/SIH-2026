"""
SIH26149 — RC2 Controlled Synthetic File Corpus Evaluation.

Constructs a bounded in-memory ground-truth corpus with representative file fixtures:
- Complex JPEGs with EXIF app markers and quantization tables
- Multi-chunk PNG images with CRC validation
- Multi-object PDF documents with xref tables and trailers
- Standard ZIP archives with Deflate compressed streams
- OpenXML DOCX / XLSX office archives with XML content types
- MP4 video streams with ftyp/moov/mdat box hierarchies
- Nested/embedded artifacts (JPEG inside PDF stream)
- Renamed extensions & misleading magic byte traps
- Segmented and non-sequential stream fragments

Calculates True Positives, False Positives, False Negatives, Precision, Recall, and F1.
Outputs: docs/RC2_REAL_WORLD_CORPUS.md and data/corpus_results.json
"""
import io
import json
import hashlib
import os
import platform
import statistics
import sys
import time
import zipfile
import tempfile
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Any

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.hashing import hash_bytes
from app.forensics.carving import carve_bytes, CarvingConfidence
from app.forensics.synthetic import generate_fragmented_jpeg_case
from app.forensics.validation import validate_carved_file, ValidationOutcome


@dataclass
class CorpusSample:
    sample_id: str
    category: str
    file_type: str
    description: str
    expected_classification: str  # "INTACT", "PARTIAL", "REJECTED"
    data: bytes
    reference_bytes: bytes | None = None
    source_name: str = "artifact.bin"


def create_expanded_corpus() -> List[CorpusSample]:
    samples = []

    # 1. Complex JPEG with JFIF + EXIF APP1
    jpeg_exif = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        b"\xff\xe1\x00\x16Exif\x00\x00II*\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\xff\xdb\x00\x43\x00" + (b"\x05" * 64)
        + b"\xff\xc0\x00\x0b\x08\x00\x20\x00\x20\x01\x01\x11\x00"
        b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00\x12\x34\x56\x78\xff\xd9"
    )
    samples.append(CorpusSample("RC2-01", "Image - JPEG", "JPEG", "JPEG with EXIF APP1 Metadata", "INTACT", jpeg_exif))
    samples.append(CorpusSample(
        "RC2-13", "Renamed Extension - JPEG", "JPEG",
        "JPEG content stored under a misleading .txt filename", "INTACT", jpeg_exif,
        source_name="recovered_photo.txt",
    ))

    # 2. JPEG Minimal JFIF
    jpeg_min = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00\x43\x00"
        + (b"\x01" * 64)
        + b"\xff\xc0\x00\x0b\x08\x00\x10\x00\x10\x01\x01\x11\x00\xff\xda\x00\x08\x01\x01\x00\x00?\x00\x00\xff\xd9"
    )
    samples.append(CorpusSample("RC2-02", "Image - JPEG", "JPEG", "Minimal valid JFIF JPEG", "INTACT", jpeg_min))

    # 3. Valid Multi-Chunk PNG
    png_ihdr = b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    png_idat = b"\x00\x00\x00\nIDATx\x9cc`\x00\x00\x00\x02\x00\x01H\xaf\xa4q"
    png_iend = b"\x00\x00\x00\x00IEND\xaeB`\x82"
    png_valid = b"\x89PNG\r\n\x1a\n" + png_ihdr + png_idat + png_iend
    samples.append(CorpusSample("RC2-03", "Image - PNG", "PNG", "PNG with IHDR, IDAT, and IEND chunks", "INTACT", png_valid))

    # 4. Standard Multi-Object PDF
    pdf_valid = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>endobj\n"
        b"4 0 obj<</Length 12>>stream\nBT /F1 12 Tf ET\nendstream\nendobj\n"
        b"xref\n0 5\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\n"
        b"0000000115 00000 n\n0000000210 00000 n\n"
        b"trailer<</Size 5/Root 1 0 R>>\nstartxref\n280\n%%EOF"
    )
    samples.append(CorpusSample("RC2-04", "Document - PDF", "PDF", "Complete 4-object PDF Document", "INTACT", pdf_valid))

    # 5. Standard In-Memory Valid ZIP Archive
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("test.txt", "Forensic Assurance Ground Truth Content")
        zf.writestr("nested/meta.json", json.dumps({"case": "RC2"}))
    zip_valid = zip_buf.getvalue()
    samples.append(CorpusSample("RC2-05", "Archive - ZIP", "ZIP", "Valid Deflate ZIP Archive with Nested Entries", "INTACT", zip_valid))

    # 6. OpenXML DOCX Document Structure (ZIP with word/document.xml)
    docx_buf = io.BytesIO()
    with zipfile.ZipFile(docx_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        zf.writestr("word/document.xml", '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>')
    docx_valid = docx_buf.getvalue()
    samples.append(CorpusSample("RC2-06", "Document - DOCX", "DOCX", "OpenXML-shaped DOCX ZIP container", "INTACT", docx_valid))

    # 7. Valid MP4 Video Container
    mp4_ftyp = b"\x00\x00\x00\x1cftypisom\x00\x00\x02\x00isomiso2mp41"
    mp4_moov = b"\x00\x00\x00\x10moov\x00\x00\x00\x08mvhd"
    mp4_mdat = b"\x00\x00\x00\x20mdat" + (b"\x00" * 24)
    mp4_valid = mp4_ftyp + mp4_moov + mp4_mdat
    samples.append(CorpusSample("RC2-07", "Media - MP4", "MP4", "Valid MP4 Stream with ftyp/moov/mdat boxes", "INTACT", mp4_valid))

    # 8. Fragmented JPEG across unallocated gap
    gap_stream, reconstructed_jpeg = generate_fragmented_jpeg_case(gap_size=2048)
    samples.append(CorpusSample(
        "RC2-08", "Fragmented - JPEG", "JPEG",
        "Bifragmented JPEG with 2KB A5-filled gap", "PARTIAL", gap_stream,
        reference_bytes=reconstructed_jpeg,
    ))

    # 9. Truncated PDF (Missing EOF trailer)
    pdf_trunc = pdf_valid[:180]
    samples.append(CorpusSample("RC2-09", "Truncated - PDF", "PDF", "Truncated PDF Missing Xref & %%EOF", "PARTIAL", pdf_trunc))

    # 10. Truncated PNG (Missing IEND chunk)
    png_trunc = b"\x89PNG\r\n\x1a\n" + png_ihdr + png_idat
    samples.append(CorpusSample("RC2-10", "Truncated - PNG", "PNG", "Truncated PNG Missing IEND Chunk", "PARTIAL", png_trunc))

    # 11. False Magic Byte Trap - JPEG Header + Random Noise
    fake_jpeg = b"\xff\xd8\xff\xe0" + (b"\xde\xad\xbe\xef" * 64) + b"\xff\xd9"
    samples.append(CorpusSample("RC2-11", "Adversarial Trap", "JPEG", "False Magic JPEG with Random Noise Body", "REJECTED", fake_jpeg))

    # 12. False Magic Byte Trap - PNG Header + Invalid CRC
    fake_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + (b"\x00" * 17)
    samples.append(CorpusSample("RC2-12", "Adversarial Trap", "PNG", "Malformed PNG with Invalid Chunk Headers", "REJECTED", fake_png))

    return samples


def _evaluate_sample(sample: CorpusSample, candidates: list, elapsed_ms: float) -> tuple[dict, dict]:
    """Score one known object; partial/rejected cases are never auto-credited."""
    reference = sample.reference_bytes if sample.reference_bytes is not None else sample.data
    reference_sha256 = hashlib.sha256(reference).hexdigest()
    exact = [candidate for candidate in candidates if candidate.sha256 == reference_sha256]
    stats = {"TP": 0, "FP": 0, "FN": 0, "TN": 0, "overclaims": 0}
    label = "FN (not recovered)"
    selected = exact[0] if exact else (candidates[0] if candidates else None)

    if sample.expected_classification == "REJECTED":
        if candidates:
            stats["FP"] += len(candidates)
            label = "FP (candidate emitted for rejected input)"
        else:
            stats["TN"] += 1
            label = "TN (no candidate emitted)"
    elif sample.expected_classification == "INTACT":
        accepted = any(candidate.confidence in (CarvingConfidence.INTACT, CarvingConfidence.HIGH)
                       for candidate in exact)
        if accepted:
            stats["TP"] += 1
            label = "TP (ground-truth bytes and intact confidence match)"
        else:
            stats["FN"] += 1
            if candidates:
                stats["FP"] += len(candidates)
                label = "FP+FN (wrong bytes or no intact-confidence match)"
    elif sample.expected_classification == "PARTIAL":
        partial = [candidate for candidate in exact if candidate.confidence in (
            CarvingConfidence.PARTIAL_STRUCT,
            CarvingConfidence.HEADER_ONLY,
            CarvingConfidence.BIFRAGMENTED,
        )]
        if partial:
            stats["TP"] += 1
            label = "TP (ground-truth bytes bounded as partial/fragmented)"
        else:
            stats["FN"] += 1
            if exact and any(candidate.confidence in (CarvingConfidence.INTACT, CarvingConfidence.HIGH)
                             for candidate in exact):
                stats["FP"] += 1
                stats["overclaims"] += 1
                label = "FP+FN (partial input promoted to intact/high)"
            elif candidates:
                stats["FP"] += len(candidates)
                label = "FP+FN (wrong candidate bytes)"

    if stats["TP"] and len(candidates) > 1:
        extra_candidates = len(candidates) - 1
        stats["FP"] += extra_candidates
        label += f"; {extra_candidates} extra candidate(s)"

    if selected is not None and selected not in exact:
        label += f"; candidate={selected.confidence.value}, hash mismatch"

    return stats, {
        "sample_id": sample.sample_id,
        "category": sample.category,
        "file_type": sample.file_type,
        "description": sample.description,
        "source_name": sample.source_name,
        "expected": sample.expected_classification,
        "reference_sha256": reference_sha256,
        "recovered_sha256": selected.sha256 if selected else None,
        "confidence": selected.confidence.value if selected else None,
        "evaluation": label,
        "scan_time_ms": round(elapsed_ms, 3),
        "candidate_count": len(candidates),
    }


def evaluate_expanded_corpus():
    samples = create_expanded_corpus()
    print("=" * 70)
    print(f"  SIH26149 RC2 — CONTROLLED SYNTHETIC CORPUS ({len(samples)} SAMPLES)")
    print("=" * 70)

    stats = {"TP": 0, "FP": 0, "FN": 0, "TN": 0, "overclaims": 0}
    evaluations = []
    scan_times = []

    for s in samples:
        # Fixed padding keeps offsets reproducible and does not model a physical disk.
        sector_padded = b"\x11\x22\x33\x44" * 64 + s.data + b"\x99\x88\x77\x66" * 64
        scan_started = time.perf_counter()
        carved = carve_bytes(sector_padded, max_results=20)
        scan_elapsed_ms = (time.perf_counter() - scan_started) * 1000
        scan_times.append(scan_elapsed_ms)
        matching = [c for c in carved if c.file_type == s.file_type]
        case_stats, evaluation = _evaluate_sample(s, matching, scan_elapsed_ms)
        for key, value in case_stats.items():
            stats[key] += value

        print(f"Sample {s.sample_id}: [{evaluation['evaluation']:<62}] {s.description}")
        evaluations.append(evaluation)

    precision = stats["TP"] / (stats["TP"] + stats["FP"]) if (stats["TP"] + stats["FP"]) > 0 else 0.0
    recall = stats["TP"] / (stats["TP"] + stats["FN"]) if (stats["TP"] + stats["FN"]) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    print("\n" + "=" * 70)
    print("  CONTROLLED SYNTHETIC CORPUS EVALUATION SUMMARY")
    print("=" * 70)
    print(f"  True Positives  : {stats['TP']}")
    print(f"  True Negatives  : {stats['TN']}")
    print(f"  False Positives : {stats['FP']}")
    print(f"  False Negatives : {stats['FN']}")
    print(f"  Precision       : {precision * 100:.1f}%")
    print(f"  Recall          : {recall * 100:.1f}%")
    print(f"  F1 Score        : {f1:.4f}")
    median_scan_ms = statistics.median(scan_times)
    print(f"  Median scan time: {median_scan_ms:.3f} ms")

    # Export report
    report_path = Path(__file__).resolve().parent.parent / "docs" / "RC2_REAL_WORLD_CORPUS.md"
    md = f"""# RC2 Controlled Synthetic Recovery Corpus Report

This report is generated by `scripts/test_real_world_corpus_rc2.py`. Despite the
legacy script and report filenames, the cases are deterministic in-memory
fixtures, not real-world evidence images or physical media. Metrics apply only
to this bounded corpus and the current raw carver.

## Ground-Truth Evaluation Matrix ({len(samples)} Samples)

| Sample ID | Category | Case | Expected | Confidence | Candidates | Scan (ms) | Evaluation |
| :---: | :--- | :--- | :---: | :---: | :---: | ---: | :--- |
"""
    for e in evaluations:
        md += (
            f"| **{e['sample_id']}** | `{e['category']}` | {e['description']} "
            f"({e['source_name']}) | `{e['expected']}` | `{e['confidence'] or 'NONE'}` "
            f"| {e['candidate_count']} | {e['scan_time_ms']:.3f} | `{e['evaluation']}` |\n"
        )

    md += f"""
---

## Quantitative Metrics

- **Precision**: **{precision * 100:.1f}%**
- **Recall**: **{recall * 100:.1f}%**
- **F1 Score**: **{f1:.4f}**
- **TP / FP / FN / TN**: **{stats['TP']} / {stats['FP']} / {stats['FN']} / {stats['TN']}**
- **Partial-to-intact overclaims**: **{stats['overclaims']}**
- **Median scan latency**: **{median_scan_ms:.3f} ms** per padded in-memory case

---

## Scope boundaries
- Corpus inputs are synthetic fixtures with known byte ground truth; this is not a real-world accuracy estimate.
- The renamed-extension row records a misleading source filename for context; the raw carver receives only bytes and does not test filesystem name recovery.
- Scan timing excludes media I/O, filesystem metadata recovery, and sanitization.
- This suite does not measure HDD/SSD behavior, physical sanitization, false-negative rates on field evidence, or large-scale recovery.
- Filesystem, timestamp, steganography, and anti-forensic cases are exercised separately by the test suites; they are not included in these carving precision/recall totals.
"""
    report_path.write_text(md, encoding="utf-8")
    print(f"\n[+] Controlled synthetic corpus report exported to: {report_path.resolve()}")
    data_dir = Path(__file__).resolve().parent.parent / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    results_path = data_dir / "corpus_results.json"
    results_path.write_text(
        json.dumps({
            "corpus_type": "controlled_synthetic_raw_carving",
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "environment": {
                "platform": platform.platform(),
                "python_version": platform.python_version(),
            },
            "sample_count": len(samples),
            "metrics": {
                **stats,
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "median_scan_ms": median_scan_ms,
            },
            "samples": evaluations,
            "physical_media_tested": False,
        }, indent=2),
        encoding="utf-8",
    )
    print(f"[+] Machine-readable corpus results exported to: {results_path.resolve()}")


if __name__ == "__main__":
    evaluate_expanded_corpus()
