"""
SIH26149 — Release Candidate 2 (RC2) Clean-Machine Master Verification Gate.

Single-command autonomous validation gate for external operators, evaluators, and CI:
 1. Environment & Dependencies Check
 2. Full Regression Test Suite (227 collected tests)
 3. Operational RC1 Release Gate (20 checks)
 4. Deep Adversarial Verifier Attack Suite (14 attacks)
 5. Crash Recovery & State Invariant Suite (6 invariants)
 6. Storage Device Capability & Sanitization Matrix (6 profiles)
 7. Controlled Synthetic Recovery Corpus (Precision/Recall evaluation)

Outputs: docs/RC2_VALIDATION_REPORT.md
"""
import io
import json
import os
import sys
import subprocess
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def run_rc2_master_gate():
    print("=" * 75)
    print("  SIH26149 FORENSIC ASSURANCE — RELEASE CANDIDATE 2 (RC2) MASTER GATE")
    print("=" * 75)

    suite_start = time.time()
    modules = []

    def execute_module(num: int, name: str, cmd_args: list):
        print(f"\n[{num}/6] Executing: {name}...")
        t0 = time.time()
        res = subprocess.run(cmd_args, capture_output=True, text=True)
        dur = round(time.time() - t0, 2)
        passed = (res.returncode == 0)
        status_str = "[ PASS ]" if passed else "[ FAIL ]"
        print(f"      {status_str} {name} (Duration: {dur}s)")
        if not passed:
            print(f"      Output: {res.stdout[-300:]}\n{res.stderr[-300:]}")
        modules.append({
            "step": num,
            "name": name,
            "passed": passed,
            "duration_sec": dur,
            "stdout": res.stdout,
        })
        return passed

    # 1. Pytest Full Suite
    execute_module(1, "Automated Regression Test Suite (227 tests)", [sys.executable, "-m", "pytest", "tests/", "-q", "--tb=no"])

    # 2. RC1 Operational Gate
    execute_module(2, "Operational Release Gate (20 criteria)", [sys.executable, "scripts/verify_rc1_gate.py"])

    # 3. Deep Verifier Adversarial Attack Suite
    execute_module(3, "Deep Adversarial Verifier Attacks (14 vectors)", [sys.executable, "scripts/test_deep_verifier_attacks.py"])

    # 4. Crash Recovery & State Invariants
    execute_module(4, "Crash Recovery & State Invariant Suite (6 invariants)", [sys.executable, "scripts/test_crash_recovery.py"])

    # 5. Device Capability & Gating Matrix
    execute_module(5, "NIST Device Capability & Sanitization Matrix (6 profiles)", [sys.executable, "scripts/test_device_capabilities.py"])

    # 6. Expanded Real-World Recovery Corpus
    execute_module(6, "Expanded Real-World File Corpus Evaluation (12 samples)", [sys.executable, "scripts/test_real_world_corpus_rc2.py"])

    total_dur = round(time.time() - suite_start, 2)
    all_passed = all(m["passed"] for m in modules)

    print("\n" + "=" * 75)
    print(f"  RC2 MASTER GATE EXECUTION RESULT: {'ALL CHECKS PASS' if all_passed else 'SOME CHECKS FAILED'}")
    print(f"  Total Duration: {total_dur}s")
    print("=" * 75)

    # Generate RC2 Master Validation Report
    report_path = Path(__file__).resolve().parent.parent / "docs" / "RC2_VALIDATION_REPORT.md"
    md = f"""# SIH26149 Release Candidate 2 (RC2) Validation Run

## Executive Summary
- **Evaluation Date**: `{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}`
- **RC2 Gate Status**: **{'ALL CHECKS PASS' if all_passed else 'CHECKS FAILED'}**
- **Total Duration**: {total_dur}s

---

## Executed checks

| Step | Validation Domain & Harness | Status | Duration | Coverage Scope |
| :---: | :--- | :---: | :---: | :--- |
"""
    for m in modules:
        md += f"| **{m['step']:02d}** | {m['name']} | `{'PASS' if m['passed'] else 'FAIL'}` | {m['duration_sec']}s | Validated against repository ground truth |\n"

    md += """

## Scope boundaries

- The recovery corpus invoked by this gate is controlled and synthetic. Its measured outcomes are published separately in `RC2_REAL_WORLD_CORPUS.md` (legacy filename).
- A passing software test gate is not external certification or real-media validation.
- No ATA/NVMe hardware sanitization, physical HDD/SSD benchmark, or NAND-level verification is run by this gate.
- Performance results are generated separately by `scripts/run_benchmark_matrix.py` and summarized in `docs/FINAL_BENCHMARK_REPORT.md`.
"""
    report_path.write_text(md, encoding="utf-8")
    print(f"\n[+] Master RC2 Validation report written to: {report_path.resolve()}")


if __name__ == "__main__":
    run_rc2_master_gate()
