# RC2 Expanded Real-World Recovery Corpus Report

## Ground Truth Evaluation Matrix (12 Samples)

| Sample ID | Format Category | Artifact Description | Expected Baseline | Carving Evaluation |
| :---: | :--- | :--- | :---: | :--- |
| **RC2-01** | `Image - JPEG` | JPEG with EXIF APP1 Metadata | `INTACT` | `TP (Validated Intact)` |
| **RC2-02** | `Image - JPEG` | Minimal valid JFIF JPEG | `INTACT` | `TP (Validated Intact)` |
| **RC2-03** | `Image - PNG` | PNG with IHDR, IDAT, and IEND chunks | `INTACT` | `TP (Validated Intact)` |
| **RC2-04** | `Document - PDF` | Complete 4-object PDF Document | `INTACT` | `TP (Validated Intact)` |
| **RC2-05** | `Archive - ZIP` | Valid Deflate ZIP Archive with Nested Entries | `INTACT` | `TP (Validated Intact)` |
| **RC2-06** | `Document - DOCX` | Valid OpenXML DOCX Document Container | `INTACT` | `FN (Missed / Under-classified)` |
| **RC2-07** | `Media - MP4` | Valid MP4 Stream with ftyp/moov/mdat boxes | `INTACT` | `FN (Missed / Under-classified)` |
| **RC2-08** | `Fragmented - JPEG` | Bifragmented JPEG with 2KB Unallocated Gap | `PARTIAL` | `TP (Bounded Stream)` |
| **RC2-09** | `Truncated - PDF` | Truncated PDF Missing Xref & %%EOF | `PARTIAL` | `TP (Bounded to Partial/Fragmented)` |
| **RC2-10** | `Truncated - PNG` | Truncated PNG Missing IEND Chunk | `PARTIAL` | `TP (Bounded to Partial/Fragmented)` |
| **RC2-11** | `Adversarial Trap` | False Magic JPEG with Random Noise Body | `REJECTED` | `TN (Correctly Rejected Trap)` |
| **RC2-12** | `Adversarial Trap` | Malformed PNG with Invalid Chunk Headers | `REJECTED` | `TN (Correctly Rejected Trap)` |

---

## Quantitative Metrics

- **Real-World Precision**: **100.0%**
- **Real-World Recall**: **80.0%**
- **Real-World F1 Score**: **0.8889**
- **False Positive Rate**: **0.0%** (Zero corrupt/partial artifacts promoted to valid)

---

## Defensive Engineering Boundaries
1. **Multi-Chunk & Archive Validation**: Validates ZIP central directories and OpenXML document relations in-memory.
2. **Deterministic Bounded Scoring**: Corrupt streams and missing trailers are prevented from ever generating a `VERIFIED` certificate.
