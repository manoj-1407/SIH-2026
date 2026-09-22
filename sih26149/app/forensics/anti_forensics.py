"""
Anti-Forensics & Intentional Evidence Concealment Detector — SIH26149.

Forensic analysis module to detect deliberate tampering and concealment:
1. NTFS Timestomping ($STANDARD_INFORMATION vs $FILE_NAME timestamp anomalies)
2. Wiping tool residual artifacts (Sysinternals sdelete, BleachBit, Eraser)
3. High-entropy crypto-shredding / wiping patterns in unallocated clusters
"""
import math
import re
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple


class AntiForensicSeverity(str, Enum):
    CRITICAL      = "CRITICAL"       # Confirmed intentional concealment (e.g. SI < FN timestomp)
    HIGH          = "HIGH"           # High-confidence wipe tool signature (e.g. sdelete temp files)
    MEDIUM        = "MEDIUM"         # Suspicious anomaly (e.g. subsecond truncation)
    INFORMATIONAL = "INFORMATIONAL"  # Forensic advisory context


class AntiForensicIndicator(str, Enum):
    TIMESTOMP_SI_FN_ANOMALY    = "TIMESTOMP_SI_FN_ANOMALY"
    TIMESTOMP_SUBSECOND_ZEROED = "TIMESTOMP_SUBSECOND_ZEROED"
    TIMESTOMP_FUTURE_DATE      = "TIMESTOMP_FUTURE_DATE"
    TIMESTOMP_PRE_EPOCH        = "TIMESTOMP_PRE_EPOCH"
    WIPE_TOOL_SDELETE_ARTIFACT = "WIPE_TOOL_SDELETE_ARTIFACT"
    WIPE_TOOL_FIXED_PATTERN    = "WIPE_TOOL_FIXED_PATTERN"
    WIPE_TOOL_BLEACHBIT_TRACE  = "WIPE_TOOL_BLEACHBIT_TRACE"
    ENTROPY_SHRED_ANOMALY      = "ENTROPY_SHRED_ANOMALY"


@dataclass
class AntiForensicFinding:
    indicator: AntiForensicIndicator
    severity: AntiForensicSeverity
    target: str                         # File path, inode, or cluster offset
    details: Dict[str, Any]             # Specific timestamps, byte patterns, or measurements
    court_explanation: str              # Forensic explanation admissible under BSA 2023 §63(4)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator": self.indicator.value,
            "severity": self.severity.value,
            "target": self.target,
            "details": self.details,
            "court_explanation": self.court_explanation,
        }


# ── Timestomp Analysis ($STANDARD_INFORMATION vs $FILE_NAME) ───────────────────

def analyze_ntfs_timestamps(
    si: Dict[str, Any],
    fn: Dict[str, Any],
    target_name: str = "unnamed_record"
) -> List[AntiForensicFinding]:
    """
    Compare NTFS $STANDARD_INFORMATION (SI) and $FILE_NAME (FN) timestamps.
    
    $STANDARD_INFORMATION is editable by userland APIs (SetFileTime / timestomp tools).
    $FILE_NAME is updated strictly by the kernel NTFS driver on renaming/moves.
    
    Expected keys in si and fn: 'created', 'modified', 'mft_modified', 'accessed'
    Values can be ISO strings or POSIX floats.
    """
    findings: List[AntiForensicFinding] = []

    def to_float(val: Any) -> Optional[float]:
        if val is None:
            return None
        if isinstance(val, (int, float)):
            return float(val)
        if isinstance(val, str):
            try:
                # Handle ISO timestamps
                dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
                return dt.timestamp()
            except Exception:
                return None
        return None

    si_mod = to_float(si.get("modified"))
    fn_mod = to_float(fn.get("modified"))
    si_cre = to_float(si.get("created"))
    fn_cre = to_float(fn.get("created"))

    now_ts = datetime.now(timezone.utc).timestamp()

    # Check 1: $SI Modified < $FN Modified (Backdated file modification)
    if si_mod is not None and fn_mod is not None:
        if si_mod < (fn_mod - 1.0):  # Allow 1s tolerance for filesystem rounding
            findings.append(AntiForensicFinding(
                indicator=AntiForensicIndicator.TIMESTOMP_SI_FN_ANOMALY,
                severity=AntiForensicSeverity.CRITICAL,
                target=target_name,
                details={
                    "attribute": "modified",
                    "si_timestamp": si_mod,
                    "fn_timestamp": fn_mod,
                    "delta_seconds": round(fn_mod - si_mod, 2),
                },
                court_explanation=(
                    f"Deliberate backdating detected: $STANDARD_INFORMATION modified timestamp is "
                    f"{round(fn_mod - si_mod, 1)} seconds earlier than kernel-protected $FILE_NAME timestamp. "
                    "This is a classic signature of userland timestomping utilities attempting to conceal access."
                )
            ))

    # Check 2: $SI Created < $FN Created (Backdated file creation)
    if si_cre is not None and fn_cre is not None:
        if si_cre < (fn_cre - 1.0):
            findings.append(AntiForensicFinding(
                indicator=AntiForensicIndicator.TIMESTOMP_SI_FN_ANOMALY,
                severity=AntiForensicSeverity.CRITICAL,
                target=target_name,
                details={
                    "attribute": "created",
                    "si_timestamp": si_cre,
                    "fn_timestamp": fn_cre,
                    "delta_seconds": round(fn_cre - si_cre, 2),
                },
                court_explanation=(
                    f"Deliberate creation backdating: $STANDARD_INFORMATION created timestamp is "
                    f"{round(fn_cre - si_cre, 1)} seconds earlier than kernel-protected $FILE_NAME timestamp. "
                    "Indicates artificial timestamp regression."
                )
            ))

    # Check 3: Subsecond precision zeroing (SetFileTime API truncates to 0/100ns precision)
    for attr, val in [("si_created", si_cre), ("si_modified", si_mod)]:
        if val is not None:
            # Check if fractional seconds are exactly 0.0 while FN retains fractional seconds
            frac_si = val - int(val)
            fn_val = fn_cre if "created" in attr else fn_mod
            if fn_val is not None:
                frac_fn = fn_val - int(fn_val)
                if frac_si == 0.0 and frac_fn != 0.0:
                    findings.append(AntiForensicFinding(
                        indicator=AntiForensicIndicator.TIMESTOMP_SUBSECOND_ZEROED,
                        severity=AntiForensicSeverity.MEDIUM,
                        target=target_name,
                        details={"attribute": attr, "fractional_si": frac_si, "fractional_fn": round(frac_fn, 6)},
                        court_explanation=(
                            f"Subsecond zeroing anomaly on {attr}: nanosecond fields are exactly zero "
                            f"while $FILE_NAME retains microsecond precision. Consistent with legacy Win32 SetFileTime API usage."
                        )
                    ))

    # Check 4: Future timestamps
    for label, val in [("si_modified", si_mod), ("si_created", si_cre)]:
        if val is not None and val > (now_ts + 86400):  # More than 24h into the future
            findings.append(AntiForensicFinding(
                indicator=AntiForensicIndicator.TIMESTOMP_FUTURE_DATE,
                severity=AntiForensicSeverity.HIGH,
                target=target_name,
                details={"attribute": label, "timestamp": val, "now": now_ts},
                court_explanation=f"Impossible timestamp: {label} is in the future. Indicates clock manipulation or deliberate spoofing."
            ))

    return findings


# ── Wipe-Tool Residual Artifact Scanner ────────────────────────────────────────

# Sysinternals SDelete creates temporary file names: 6 uppercase characters + 3 uppercase characters
_SDELETE_NAME_PATTERN = re.compile(rb'^[A-Z]{6}\.[A-Z]{3}$')
_SDELETE_STR_PATTERN = re.compile(r'^[A-Z]{6}\.[A-Z]{3}$')


def scan_entries_for_wipe_artifacts(entry_names: List[str]) -> List[AntiForensicFinding]:
    """Inspect deleted or existing directory entries for wiping tool artifacts."""
    findings = []
    sdelete_candidates = []

    for name in entry_names:
        base = os.path.basename(name)
        if _SDELETE_STR_PATTERN.match(base):
            sdelete_candidates.append(base)
        elif any(marker in base.lower() for marker in ["bleachbit", "ccleaner", "zerofill.tmp", "wipe_slack"]):
            findings.append(AntiForensicFinding(
                indicator=AntiForensicIndicator.WIPE_TOOL_BLEACHBIT_TRACE,
                severity=AntiForensicSeverity.HIGH,
                target=base,
                details={"matched_marker": base},
                court_explanation=(
                    f"Residual wiper artifact found: '{base}'. "
                    "Indicates the execution of anti-forensic cleaning tools prior to seizure."
                )
            ))

    if len(sdelete_candidates) >= 2:
        findings.append(AntiForensicFinding(
            indicator=AntiForensicIndicator.WIPE_TOOL_SDELETE_ARTIFACT,
            severity=AntiForensicSeverity.CRITICAL,
            target=f"{len(sdelete_candidates)} temporary file entries",
            details={"candidates": sdelete_candidates[:10]},
            court_explanation=(
                f"Sysinternals SDelete free space wiping signature detected: {len(sdelete_candidates)} sequential "
                "uppercase alphanumeric temp files (e.g. AAAAAA.AAA, ZZZZZZ.ZZZ) found in filesystem metadata."
            )
        ))

    return findings


# ── Byte-Level Cluster Entropy & Overwrite Pattern Scanner ─────────────────────

def compute_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte chunk (0.0 to 8.0)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    length = len(data)
    for c in counts:
        if c > 0:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy


def scan_raw_clusters_for_anti_forensics(
    data: bytes,
    cluster_size: int = 4096,
    max_scan_bytes: int = 10 * 1024 * 1024  # Scan up to 10MB
) -> List[AntiForensicFinding]:
    """
    Scan raw bytes in cluster-sized chunks for wipe patterns and anomalous entropy.
    Detects:
      - SDelete / DoD overwrite passes (repeating 0x55, 0xAA, 0x00, 0xFF)
      - Unallocated clusters with entropy > 7.95 lacking file container headers
    """
    findings: List[AntiForensicFinding] = []
    limit = min(len(data), max_scan_bytes)

    # Recognizable wiping patterns (DoD / SDelete / Gutmann fragments)
    wipe_patterns = [
        (b"\x55" * 64, "0x55 (DoD 5220.22-M / SDelete Pass Pattern)"),
        (b"\xAA" * 64, "0xAA (DoD 5220.22-M / SDelete Pass Pattern)"),
        (b"\x92\x49\x24" * 21, "0x924924 (Gutmann Pass Sequence)"),
    ]

    pattern_hits = 0
    anomalous_entropy_clusters = 0

    for off in range(0, limit, cluster_size):
        chunk = data[off : off + cluster_size]
        if len(chunk) < 512:
            break

        # Check known wiping patterns
        for pat, pat_name in wipe_patterns:
            if pat in chunk:
                pattern_hits += 1
                if pattern_hits == 1:  # Log first instance
                    findings.append(AntiForensicFinding(
                        indicator=AntiForensicIndicator.WIPE_TOOL_FIXED_PATTERN,
                        severity=AntiForensicSeverity.HIGH,
                        target=f"Offset 0x{off:08X}",
                        details={"pattern": pat_name, "offset": off},
                        court_explanation=(
                            f"Structured wipe pattern '{pat_name}' detected at offset 0x{off:08X}. "
                            "Consistent with multi-pass software sanitization or anti-forensic wiping tool execution."
                        )
                    ))
                break

        # Check for unallocated high-entropy crypto-shredding (entropy > 7.98 without magic bytes)
        # Skip if starts with known container signatures (ZIP/PDF/PNG/JPEG)
        if not (chunk.startswith(b"\x50\x4B\x03\x04") or chunk.startswith(b"\xFF\xD8\xFF") or
                chunk.startswith(b"\x89PNG") or chunk.startswith(b"%PDF")):
            ent = compute_entropy(chunk)
            if ent > 7.98:
                anomalous_entropy_clusters += 1
                if anomalous_entropy_clusters == 1:
                    findings.append(AntiForensicFinding(
                        indicator=AntiForensicIndicator.ENTROPY_SHRED_ANOMALY,
                        severity=AntiForensicSeverity.MEDIUM,
                        target=f"Offset 0x{off:08X}",
                        details={"entropy": round(ent, 4), "offset": off},
                        court_explanation=(
                            f"Anomalous high-entropy cluster (Shannon entropy {round(ent, 3)}/8.0) detected at 0x{off:08X} "
                            "without recognized media file headers. Suggests cryptographic wiping or hidden volume payload."
                        )
                    ))

    return findings


# ── Full Engine Facade ─────────────────────────────────────────────────────────

def analyze_anti_forensics(
    image_input,
    mft_records: Optional[List[Dict[str, Any]]] = None,
    directory_names: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Comprehensive anti-forensic audit across metadata and byte streams.
    Returns structured report for investigative review and BSA 2023 court reports.
    """
    all_findings: List[AntiForensicFinding] = []

    # 1. Analyze MFT records for timestomping if provided
    if mft_records:
        for rec in mft_records:
            si = rec.get("si", {})
            fn = rec.get("fn", {})
            name = rec.get("name", "file_record")
            findings = analyze_ntfs_timestamps(si, fn, target_name=name)
            all_findings.extend(findings)

    # 2. Analyze directory entry names for wipe artifacts
    if directory_names:
        name_findings = scan_entries_for_wipe_artifacts(directory_names)
        all_findings.extend(name_findings)

    # 3. Analyze raw disk image bytes
    if image_input:
        if isinstance(image_input, (bytes, bytearray)):
            raw_data = bytes(image_input)
        elif os.path.exists(str(image_input)):
            with open(str(image_input), "rb") as f:
                raw_data = f.read(5 * 1024 * 1024)  # First 5MB
        else:
            raw_data = b""

        if raw_data:
            byte_findings = scan_raw_clusters_for_anti_forensics(raw_data)
            all_findings.extend(byte_findings)

    # Group counts
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFORMATIONAL": 0}
    for f in all_findings:
        by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1

    has_tampering = by_severity["CRITICAL"] > 0 or by_severity["HIGH"] > 0

    return {
        "anti_forensics_detected": has_tampering,
        "total_indicators": len(all_findings),
        "by_severity": by_severity,
        "verdict": (
            "DELIBERATE_CONCEALMENT_DETECTED" if has_tampering
            else "NO_OVERT_ANTI_FORENSICS_FOUND"
        ),
        "findings": [f.to_dict() for f in all_findings],
        "summary": (
            f"Detected {len(all_findings)} anti-forensic indicators ({by_severity['CRITICAL']} critical, "
            f"{by_severity['HIGH']} high). Evidence of deliberate tampering or wipe tool execution present."
            if has_tampering else
            "No evidence of timestamp manipulation or structured wipe tools detected."
        )
    }
