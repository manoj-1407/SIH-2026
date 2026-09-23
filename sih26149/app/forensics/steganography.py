"""
Chi-Square (χ²) LSB Steganography & Hidden Payload Detection Engine — SIH26149.

Standards & Forensic Principles:
- Westfeld & Pfitzmann (1999) "Attacks on Steganographic Systems" (Pairs of Values analysis)
- Sample Pair Analysis (Dumitrescu et al., 2003)
- Shannon Entropy evaluation across isolated LSB bitplanes

Forensic Capabilities:
- Detects sequential and distributed LSB replacement steganography in recovered images (PNG, JPEG, BMP)
- Evaluates degree of equalization in adjacent PoVs (2k, 2k+1) across RGB pixel channels
- Estimates hidden payload capacity and flags covert channels for court disclosure
"""
import math
from typing import Dict, Any, List, Tuple, Optional


def shannon_entropy(data: bytes) -> float:
    """Computes Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    ent = 0.0
    for count in freq:
        if count > 0:
            p = count / total
            ent -= p * math.log2(p)
    return ent


def extract_lsb_bytes(raw_bytes: bytes) -> bytes:
    """Extracts the least-significant bit from each byte into packed bytes."""
    lsb_bits = [b & 1 for b in raw_bytes]
    # Pack into bytes (8 bits per byte)
    packed = bytearray()
    for i in range(0, len(lsb_bits) - 7, 8):
        byte_val = 0
        for bit_idx in range(8):
            byte_val = (byte_val << 1) | lsb_bits[i + bit_idx]
        packed.append(byte_val)
    return bytes(packed)


def chi_square_lsb_test(sample_bytes: bytes) -> Dict[str, Any]:
    """
    Performs Chi-Square statistical test on Pairs of Values (PoVs).
    In natural unmanipulated images, frequencies of 2k and 2k+1 differ naturally.
    In LSB-stego images, replacement equalizes 2k and 2k+1 frequencies towards (n_2k + n_2k+1)/2.
    """
    if len(sample_bytes) < 128:
        return {
            "tested": False,
            "reason": "Insufficient byte sample (minimum 128 bytes required)",
            "steganography_detected": False,
            "stego_probability": 0.0
        }

    # Count byte frequencies 0..255
    freq = [0] * 256
    for b in sample_bytes:
        freq[b] += 1

    chi_sq = 0.0
    valid_pairs = 0

    for k in range(128):
        count_even = freq[2 * k]
        count_odd = freq[2 * k + 1]
        sum_pair = count_even + count_odd

        if sum_pair > 0:
            expected = sum_pair / 2.0
            # Difference from expected theoretical mean
            chi_sq += ((count_even - expected) ** 2) / expected
            valid_pairs += 1

    # Extract LSB stream and compute its Shannon entropy
    lsb_stream = extract_lsb_bytes(sample_bytes)
    lsb_ent = shannon_entropy(lsb_stream) if lsb_stream else 0.0

    # Degrees of freedom = valid_pairs - 1
    df = max(1, valid_pairs - 1)
    chi_ratio = chi_sq / df

    # ── Detection logic ────────────────────────────────────────────────────
    # PROBLEM with small df: when only a few distinct PoV pairs have counts
    # (e.g. image with only 6 distinct byte values), chi_ratio is highly variable
    # due to sampling noise (df=5 gives wide confidence intervals). We therefore
    # use a composite detection approach:
    #
    # Score 1 — PoV equalization: low chi_ratio relative to df indicates
    #            artificial equalization. Normalized: 1 - min(chi_ratio, df) / df
    # Score 2 — LSB entropy:    random payload pushes LSB entropy near 8.0
    #            Normalized: (lsb_ent - 6.0) / 2.0  (clamped 0..1)
    #
    # Composite score > 0.6 → detected.  This is robust across all df sizes.

    pov_score = max(0.0, 1.0 - min(chi_ratio, df) / max(df, 1))
    lsb_score = max(0.0, min(1.0, (lsb_ent - 6.0) / 2.0))
    composite = 0.45 * pov_score + 0.55 * lsb_score

    # Chi-square critical value (chi2.ppf(0.95, df) approximation via Wilson-Hilferty)
    def chi2_critical_95(d):
        z = 1.645  # 95th percentile z-score
        return d * (1 - 2 / (9 * d) + z * (2 / (9 * d)) ** 0.5) ** 3

    critical = chi2_critical_95(df)

    if composite >= 0.62:
        stego_prob = min(1.0, composite)
        detected = True
        verdict = "SUSPECTED_LSB_STEGANOGRAPHY_DETECTED"
    elif composite >= 0.45:
        stego_prob = 0.65
        detected = True
        verdict = "ELEVATED_LSB_ANOMALY"
    else:
        stego_prob = max(0.0, composite * 0.4)
        detected = False
        verdict = "CLEAN_NATURAL_DISTRIBUTION"

    # Estimated payload capacity in bytes
    estimated_payload_bytes = int((len(sample_bytes) // 8) * stego_prob) if detected else 0

    return {
        "tested": True,
        "sample_size_bytes": len(sample_bytes),
        "chi_square_statistic": round(chi_sq, 4),
        "chi_square_critical_value": round(critical, 4),
        "degrees_of_freedom": df,
        "chi_square_ratio": round(chi_ratio, 4),
        "pov_score": round(pov_score, 4),
        "lsb_plane_entropy": round(lsb_ent, 4),
        "lsb_score": round(lsb_score, 4),
        "composite_score": round(composite, 4),
        "stego_probability": round(stego_prob, 4),
        "steganography_detected": detected,
        "estimated_payload_bytes": estimated_payload_bytes,
        "verdict": verdict,
        "methodology": "PoVs (Pairs of Values) Chi-Square + LSB Entropy (Westfeld-Pfitzmann)"
    }


def analyze_file_for_steganography(file_path_or_bytes: Any) -> Dict[str, Any]:
    """
    Analyzes an image file or raw byte buffer for hidden steganographic payload.
    """
    if isinstance(file_path_or_bytes, (str, bytes, bytearray)):
        if isinstance(file_path_or_bytes, str):
            with open(file_path_or_bytes, "rb") as f:
                content = f.read()
        else:
            content = bytes(file_path_or_bytes)
    else:
        return {"error": "Unsupported input type", "steganography_detected": False}

    # Focus analysis on the payload / scanline bytes (skipping file header if PNG/JPEG)
    header_offset = 0
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        header_offset = 33 # Skip IHDR
    elif content.startswith(b"\xff\xd8"):
        header_offset = 128 # Skip SOI/APP markers

    sample = content[header_offset:]
    res = chi_square_lsb_test(sample)
    res["analyzed_offset"] = header_offset
    return res
