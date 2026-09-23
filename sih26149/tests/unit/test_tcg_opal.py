"""
Unit tests for TCG Opal Self-Encrypting Drive (SED) detection — SIH26149.
"""
import struct
import pytest
from app.sanitization.device_detector import (
    parse_tcg_level0_discovery,
    evaluate_opal_capability,
    SanitizationLevel
)


def synthesize_tcg_level0_discovery(include_opal: bool = True, opal_version: str = "v2") -> bytes:
    """Helper to synthesize a spec-compliant TCG Level 0 Discovery header."""
    buf = bytearray(b"\x00" * 128)
    # Header: length (big-endian), version
    param_len = 124
    struct.pack_into(">IHH", buf, 0, param_len, 1, 0)

    offset = 48
    # 1. TPer Feature (0x0001), len = 12
    struct.pack_into(">HBB", buf, offset, 0x0001, 0x10, 12)
    offset += 4 + 12

    # 2. Locking Feature (0x0002), len = 12
    struct.pack_into(">HBB", buf, offset, 0x0002, 0x10, 12)
    offset += 4 + 12

    # 3. Opal SSC Feature
    if include_opal:
        code = 0x0203 if opal_version == "v2" else 0x0200
        struct.pack_into(">HBB", buf, offset, code, 0x10, 16)
        offset += 4 + 16

    return bytes(buf)


def test_parse_tcg_level0_discovery_opal_v2():
    raw_data = synthesize_tcg_level0_discovery(include_opal=True, opal_version="v2")
    res = parse_tcg_level0_discovery(raw_data)
    assert res["is_sed"] is True
    assert res["opal_capable"] is True
    assert res["opal_version"] == "TCG Opal SSC V2.0"
    assert res["locking_supported"] is True


def test_parse_tcg_level0_discovery_non_sed():
    raw_data = b"\x00" * 64
    res = parse_tcg_level0_discovery(raw_data)
    assert res["opal_capable"] is False


def test_evaluate_opal_capability_promotes_to_purge():
    raw_opal = synthesize_tcg_level0_discovery(include_opal=True, opal_version="v2")
    cap = evaluate_opal_capability("/dev/nvme0n1", raw_discovery_bytes=raw_opal)
    assert cap.is_sed_opal_capable is True
    assert cap.crypto_erase_recommended is True
    assert cap.recommended_level == SanitizationLevel.PURGE
    assert "TCG OPAL CRYPTOGRAPHIC ERASE" in cap.purge_command
    assert "NIST SP 800-88 Rev. 2 §2.4 Purge" in cap.crypto_erase_rationale
