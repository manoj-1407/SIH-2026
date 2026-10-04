# Controlled Synthetic Forensic Recovery Accuracy Report

## Ground Truth Evaluation Methodology
The SIH26149 evaluation harness subjects the raw carver to deterministic
in-memory fixtures with known byte hashes, partial streams, and rejected traps.
This is not a real-world or physical-media accuracy estimate.

---

## 1. Quantitative Performance Matrix

| Scenario Category | Test Cases | TP | FP | FN | Precision | Recall | Category F1 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Contiguous** | 3 | 2 | 1 | 1 | **66.7%** | **66.7%** | **0.6667** |
| **Sequential Fragmented** | 1 | 1 | 0 | 0 | **100.0%** | **100.0%** | **1.0000** |
| **Missing Fragments** | 2 | 1 | 1 | 1 | **50.0%** | **50.0%** | **0.5000** |
| **Corrupted Traps** | 2 | 0 | 2 | 0 | **0.0%** | **0.0%** | **0.0000** |

---

## 2. Global Metric Summary

- **Overall Precision**: **50.0%**
- **Overall Recall**: **66.7%**
- **Overall F1 Score**: **0.5714**
- **TP / FP / FN / TN**: **4 / 4 / 2 / 0**
- **Median scan latency**: **1.182 ms/case**
- A sample can contribute both FP and FN when an emitted candidate does not match its ground-truth bytes or expected confidence.

---

## 3. Limits
- Each positive requires an exact ground-truth hash and confidence compatible with its expected intact/partial/reconstructed state.
- Rejected cases count any emitted candidate as a false positive.
- Results apply only to these fixtures. They do not estimate field-evidence performance, filesystem metadata recovery, sanitization, or physical media.
- Non-sequential/multi-hop fragmentation is outside this harness.
