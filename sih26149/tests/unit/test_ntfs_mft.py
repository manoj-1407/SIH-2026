"""
Tests for Native NTFS $MFT Parser and Deleted File Recovery Engine — SIH26149.
"""
import struct
import hashlib
import tempfile
from pathlib import Path
import pytest

from app.forensics.ntfs_mft import (
    parse_mft_record,
    decode_runlist,
    apply_fixups,
    scan_ntfs_image_for_deleted_files,
    MFTRecoveredFile,
    MFT_RECORD_SIZE
)


def pack_resident_attr_header(buf: bytearray, offset: int, attr_type: int, attr_len: int, content_len: int, content_off: int = 0x18):
    """Packs standard 24-byte NTFS resident attribute header."""
    struct.pack_into("<IIBBHHHIHBB", buf, offset, attr_type, attr_len, 0, 0, 0, 0, 0, content_len, content_off, 0, 0)


def create_synthetic_mft_record(
    record_num: int = 42,
    filename: str = "confidential_evidence.pdf",
    data: bytes = b"%PDF-1.4\n%real forensic recovered pdf payload\n%%EOF",
    is_deleted: bool = True,
    is_resident: bool = True
) -> bytes:
    """Helper to synthesize a structurally valid 1024-byte NTFS MFT record."""
    buf = bytearray(b"\x00" * MFT_RECORD_SIZE)

    # Magic: 'FILE'
    buf[0:4] = b"FILE"

    # Fixup array offset = 0x30 (48), count = 3 (1 signature + 2 sectors)
    fixup_offset = 0x30
    fixup_count = 3
    struct.pack_into("<HH", buf, 0x04, fixup_offset, fixup_count)

    # Flags: 0 = DELETED, 1 = IN_USE
    flags = 0x0000 if is_deleted else 0x0001
    first_attr_off = 0x38  # 56
    struct.pack_into("<HH", buf, 0x14, first_attr_off, flags)

    # Fixup signature: 0x4141 ('AA')
    fixup_sig = b"AA"
    buf[fixup_offset:fixup_offset + 2] = fixup_sig

    # Set sector end markers to match fixup sig
    buf[510:512] = fixup_sig
    buf[1022:1024] = fixup_sig

    # Original bytes stored in fixup array
    buf[fixup_offset + 2:fixup_offset + 4] = b"\x11\x22"
    buf[fixup_offset + 4:fixup_offset + 6] = b"\x33\x44"

    curr = first_attr_off

    # 1. $STANDARD_INFORMATION (0x10) - 48 bytes (24 header + 24 content)
    std_content_len = 24
    std_attr_len = 0x18 + std_content_len
    pack_resident_attr_header(buf, curr, 0x10, std_attr_len, std_content_len, 0x18)
    # Timestamps at content offset 0x18 (24)
    struct.pack_into("<Q", buf, curr + 0x18, 133500000000000000) # Created
    struct.pack_into("<Q", buf, curr + 0x18 + 8, 133500000000000000) # Modified
    curr += std_attr_len

    # 2. $FILE_NAME (0x30)
    utf_name = filename.encode("utf-16le")
    fn_char_count = len(filename)
    fn_content_len = 66 + len(utf_name)
    fn_attr_len = (fn_content_len + 0x18 + 7) & ~7
    pack_resident_attr_header(buf, curr, 0x30, fn_attr_len, fn_content_len, 0x18)

    fn_content_start = curr + 0x18
    # Parent record = 5 (Root directory)
    struct.pack_into("<Q", buf, fn_content_start, 5)
    # Filename length & namespace (1 = Win32)
    buf[fn_content_start + 64] = fn_char_count
    buf[fn_content_start + 65] = 1
    # UTF-16LE characters
    buf[fn_content_start + 66:fn_content_start + 66 + len(utf_name)] = utf_name
    curr += fn_attr_len

    # 3. $DATA (0x80)
    if is_resident:
        data_content_len = len(data)
        data_attr_len = (data_content_len + 0x18 + 7) & ~7
        pack_resident_attr_header(buf, curr, 0x80, data_attr_len, data_content_len, 0x18)
        buf[curr + 0x18:curr + 0x18 + data_content_len] = data
        curr += data_attr_len

    # End Marker 0xFFFFFFFF
    struct.pack_into("<I", buf, curr, 0xFFFFFFFF)

    return bytes(buf)


def test_fixup_array_repair():
    rec = create_synthetic_mft_record()
    fixed = apply_fixups(rec)
    assert fixed is not None
    # Sector end bytes should be restored from the fixup array
    assert fixed[510:512] == b"\x11\x22"
    assert fixed[1022:1024] == b"\x33\x44"


def test_mft_deleted_file_recovery_resident():
    sample_data = b"TOP SECRET EXAMINER REPORT - BSA SEC 63 COMPLIANT"
    rec_bytes = create_synthetic_mft_record(
        record_num=105,
        filename="intel_report.txt",
        data=sample_data,
        is_deleted=True
    )
    res = parse_mft_record(rec_bytes, record_number=105)
    assert res is not None
    assert res.is_deleted is True
    assert res.filename == "intel_report.txt"
    assert res.is_resident is True
    assert res.data_bytes == sample_data
    assert res.size_bytes == len(sample_data)
    assert res.sha256 == hashlib.sha256(sample_data).hexdigest()


def test_decode_runlist():
    # Runlist: 0x21 0x14 0x00 0x01 (Length 20 clusters, offset +256)
    # Header 0x21: len_size=1, off_size=2
    # Length=0x14 (20), Offset=0x0100 (256)
    raw_runlist = b"\x21\x14\x00\x01\x00"
    runs = decode_runlist(raw_runlist)
    assert len(runs) == 1
    assert runs[0] == (20, 256)


def test_scan_ntfs_image_for_deleted_files():
    rec1 = create_synthetic_mft_record(record_num=1, filename="deleted1.doc", is_deleted=True)
    rec2 = create_synthetic_mft_record(record_num=2, filename="active.doc", is_deleted=False)
    rec3 = create_synthetic_mft_record(record_num=3, filename="deleted2.pdf", is_deleted=True)

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(rec1)
        tmp.write(rec2)
        tmp.write(rec3)
        tmp_path = tmp.name

    try:
        deleted = scan_ntfs_image_for_deleted_files(tmp_path)
        assert len(deleted) == 2
        filenames = [d.filename for d in deleted]
        assert "deleted1.doc" in filenames
        assert "deleted2.pdf" in filenames
        assert "active.doc" not in filenames
    finally:
        Path(tmp_path).unlink(missing_ok=True)
