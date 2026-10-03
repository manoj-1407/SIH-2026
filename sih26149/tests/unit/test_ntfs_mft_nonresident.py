"""
Tests for NTFS non-resident $DATA byte readback — SIH26149.
Creates a synthetic 4MB NTFS image with valid BPB, resident file, and 64KB
non-resident file filled with a deterministic repeating pattern.
"""
import struct
import hashlib
import tempfile
from pathlib import Path
import pytest

from app.forensics.ntfs_mft import (
    parse_mft_record,
    scan_ntfs_image_for_deleted_files,
    parse_ntfs_bpb,
    MFTRecoveredFile,
    MFT_RECORD_SIZE,
    SECTOR_SIZE,
)


BYTES_PER_SECTOR = 512
SECTORS_PER_CLUSTER = 8
CLUSTER_SIZE = BYTES_PER_SECTOR * SECTORS_PER_CLUSTER  # 4096
IMAGE_SIZE = 4 * 1024 * 1024  # 4 MiB

RESIDENT_FILE_CONTENT = (
    b"[CLASSIFIED] Operation Aurora Summary Report - Case #2026-0427\n"
    b"Suspect: Internal Threat Vector T-7294\n"
    b"Collection Date: 2026-09-15\n"
    b"Analyst: Special Agent J. Carter\n\n"
    b"Evidence gathered from workstation WS-0492 indicates unauthorized"
    b" exfiltration of proprietary algorithm source code via encrypted USB."
    b" Chain of custody preserved per SOP 14-B. Full forensics report attached."
)
# Pad or truncate to exactly 200 bytes
RESIDENT_FILE_CONTENT = (RESIDENT_FILE_CONTENT * 3)[:200]
assert len(RESIDENT_FILE_CONTENT) == 200

NONRESIDENT_PATTERN = b"ABCDEFGH"
NONRESIDENT_FILE_CONTENT = NONRESIDENT_PATTERN * 8192  # 8 * 8192 = 65536 bytes
assert len(NONRESIDENT_FILE_CONTENT) == 65536
NONRESIDENT_SHA256 = hashlib.sha256(NONRESIDENT_FILE_CONTENT).hexdigest()
RESIDENT_SHA256 = hashlib.sha256(RESIDENT_FILE_CONTENT).hexdigest()

MFT_CLUSTER = 4
MFT_OFFSET = MFT_CLUSTER * CLUSTER_SIZE  # 16384
NONRESIDENT_DATA_START_CLUSTER = 32
NONRESIDENT_DATA_OFFSET = NONRESIDENT_DATA_START_CLUSTER * CLUSTER_SIZE  # 131072
NONRESIDENT_CLUSTER_COUNT = 65536 // CLUSTER_SIZE  # 16 clusters


def pack_resident_attr_header(buf, offset, attr_type, attr_len, content_len, content_off=0x18):
    struct.pack_into("<IIBBHHHIHBB", buf, offset, attr_type, attr_len, 0, 0, 0, 0, 0, content_len, content_off, 0, 0)


def pack_nonresident_attr_header(buf, offset, attr_type, attr_len, runlist_off, content_size, cluster_count):
    struct.pack_into("<II", buf, offset, attr_type, attr_len)
    buf[offset + 0x08] = 1
    buf[offset + 0x09] = 0
    struct.pack_into("<H", buf, offset + 0x0A, 0)
    struct.pack_into("<H", buf, offset + 0x0C, 0)
    struct.pack_into("<H", buf, offset + 0x0E, 0)
    struct.pack_into("<Q", buf, offset + 0x10, 0)
    struct.pack_into("<Q", buf, offset + 0x18, cluster_count - 1)
    struct.pack_into("<H", buf, offset + 0x20, runlist_off)
    struct.pack_into("<H", buf, offset + 0x22, 0)
    struct.pack_into("<I", buf, offset + 0x24, 0)
    struct.pack_into("<Q", buf, offset + 0x28, content_size)
    struct.pack_into("<Q", buf, offset + 0x30, content_size)
    struct.pack_into("<Q", buf, offset + 0x38, content_size)


def build_bpb_sector() -> bytes:
    buf = bytearray(b"\x00" * SECTOR_SIZE)
    buf[0x00:3] = b"\xEB\x52\x90"
    buf[0x03:0x0B] = b"NTFS    "
    struct.pack_into("<H", buf, 0x0B, BYTES_PER_SECTOR)
    buf[0x0D] = SECTORS_PER_CLUSTER
    struct.pack_into("<H", buf, 0x0E, 0)
    struct.pack_into("<H", buf, 0x10, 0)
    buf[0x15] = 0xF8
    struct.pack_into("<H", buf, 0x18, 63)
    struct.pack_into("<H", buf, 0x1A, 255)
    struct.pack_into("<Q", buf, 0x28, IMAGE_SIZE // BYTES_PER_SECTOR)
    struct.pack_into("<Q", buf, 0x30, 0x04000000)
    struct.pack_into("<Q", buf, 0x38, MFT_CLUSTER)
    buf[0x1FE:0x200] = b"\x55\xAA"
    return bytes(buf)


def create_synthetic_mft_record_common(
    record_num,
    filename,
    is_deleted,
):
    buf = bytearray(b"\x00" * MFT_RECORD_SIZE)
    buf[0:4] = b"FILE"
    fixup_offset = 0x30
    fixup_count = 3
    struct.pack_into("<HH", buf, 0x04, fixup_offset, fixup_count)
    flags = 0x0000 if is_deleted else 0x0001
    first_attr_off = 0x38
    struct.pack_into("<HH", buf, 0x14, first_attr_off, flags)
    fixup_sig = b"AA"
    buf[fixup_offset:fixup_offset + 2] = fixup_sig
    buf[510:512] = fixup_sig
    buf[1022:1024] = fixup_sig
    buf[fixup_offset + 2:fixup_offset + 4] = b"\x11\x22"
    buf[fixup_offset + 4:fixup_offset + 6] = b"\x33\x44"
    curr = first_attr_off

    std_content_len = 24
    std_attr_len = 0x18 + std_content_len
    pack_resident_attr_header(buf, curr, 0x10, std_attr_len, std_content_len, 0x18)
    struct.pack_into("<Q", buf, curr + 0x18, 133500000000000000)
    struct.pack_into("<Q", buf, curr + 0x18 + 8, 133500000000000000)
    curr += std_attr_len

    utf_name = filename.encode("utf-16le")
    fn_char_count = len(filename)
    fn_content_len = 66 + len(utf_name)
    fn_attr_len = (fn_content_len + 0x18 + 7) & ~7
    pack_resident_attr_header(buf, curr, 0x30, fn_attr_len, fn_content_len, 0x18)
    fn_content_start = curr + 0x18
    struct.pack_into("<Q", buf, fn_content_start, 5)
    buf[fn_content_start + 64] = fn_char_count
    buf[fn_content_start + 65] = 1
    buf[fn_content_start + 66:fn_content_start + 66 + len(utf_name)] = utf_name
    curr += fn_attr_len

    return buf, curr


def create_resident_mft_record(record_num, filename, data, is_deleted):
    buf, curr = create_synthetic_mft_record_common(record_num, filename, is_deleted)
    data_content_len = len(data)
    data_attr_len = (data_content_len + 0x18 + 7) & ~7
    pack_resident_attr_header(buf, curr, 0x80, data_attr_len, data_content_len, 0x18)
    buf[curr + 0x18:curr + 0x18 + data_content_len] = data
    curr += data_attr_len
    struct.pack_into("<I", buf, curr, 0xFFFFFFFF)
    return bytes(buf)


def create_nonresident_mft_record(record_num, filename, content_size, start_lcn, cluster_count, is_deleted):
    buf, curr = create_synthetic_mft_record_common(record_num, filename, is_deleted)

    runlist_off = 0x40
    attr_len = runlist_off + 4
    attr_len_aligned = (attr_len + 7) & ~7

    pack_nonresident_attr_header(
        buf, curr, 0x80, attr_len_aligned, runlist_off, content_size, cluster_count
    )

    runlist_pos = curr + runlist_off
    len_size = 1
    off_size = 1
    header_byte = (off_size << 4) | len_size
    buf[runlist_pos] = header_byte
    runlist_pos += 1
    struct.pack_into("<B", buf, runlist_pos, cluster_count)
    runlist_pos += 1
    struct.pack_into("<b", buf, runlist_pos, start_lcn)
    runlist_pos += 1
    buf[runlist_pos] = 0x00

    curr += attr_len_aligned
    struct.pack_into("<I", buf, curr, 0xFFFFFFFF)
    return bytes(buf)


def build_system_mft_record(record_num):
    buf = bytearray(b"\x00" * MFT_RECORD_SIZE)
    buf[0:4] = b"FILE"
    fixup_offset = 0x30
    fixup_count = 3
    struct.pack_into("<HH", buf, 0x04, fixup_offset, fixup_count)
    flags = 0x0001
    first_attr_off = 0x38
    struct.pack_into("<HH", buf, 0x14, first_attr_off, flags)
    fixup_sig = b"AA"
    buf[fixup_offset:fixup_offset + 2] = fixup_sig
    buf[510:512] = fixup_sig
    buf[1022:1024] = fixup_sig
    buf[fixup_offset + 2:fixup_offset + 4] = b"\x99\x88"
    buf[fixup_offset + 4:fixup_offset + 6] = b"\x77\x66"
    curr = first_attr_off

    std_content_len = 24
    std_attr_len = 0x18 + std_content_len
    pack_resident_attr_header(buf, curr, 0x10, std_attr_len, std_content_len, 0x18)
    curr += std_attr_len

    sys_name = f"$MFT"
    utf_name = sys_name.encode("utf-16le")
    fn_content_len = 66 + len(utf_name)
    fn_attr_len = (fn_content_len + 0x18 + 7) & ~7
    pack_resident_attr_header(buf, curr, 0x30, fn_attr_len, fn_content_len, 0x18)
    fn_content_start = curr + 0x18
    struct.pack_into("<Q", buf, fn_content_start, 0)
    buf[fn_content_start + 64] = len(sys_name)
    buf[fn_content_start + 65] = 1
    buf[fn_content_start + 66:fn_content_start + 66 + len(utf_name)] = utf_name
    curr += fn_attr_len

    struct.pack_into("<I", buf, curr, 0xFFFFFFFF)
    return bytes(buf)


def build_synthetic_ntfs_image() -> bytes:
    image = bytearray(b"\x00" * IMAGE_SIZE)

    image[0:SECTOR_SIZE] = build_bpb_sector()

    sys_rec = build_system_mft_record(0)
    image[MFT_OFFSET:MFT_OFFSET + MFT_RECORD_SIZE] = sys_rec

    res_rec = create_resident_mft_record(
        record_num=1,
        filename="resident_report_2026.txt",
        data=RESIDENT_FILE_CONTENT,
        is_deleted=True,
    )
    res_offset = MFT_OFFSET + MFT_RECORD_SIZE
    image[res_offset:res_offset + MFT_RECORD_SIZE] = res_rec

    nonres_rec = create_nonresident_mft_record(
        record_num=2,
        filename="exfil_dataset_2026.bin",
        content_size=65536,
        start_lcn=NONRESIDENT_DATA_START_CLUSTER,
        cluster_count=NONRESIDENT_CLUSTER_COUNT,
        is_deleted=True,
    )
    nonres_offset = MFT_OFFSET + 2 * MFT_RECORD_SIZE
    image[nonres_offset:nonres_offset + MFT_RECORD_SIZE] = nonres_rec

    data_end = NONRESIDENT_DATA_OFFSET + len(NONRESIDENT_FILE_CONTENT)
    assert data_end <= IMAGE_SIZE, "Non-resident data extends beyond image"
    image[NONRESIDENT_DATA_OFFSET:NONRESIDENT_DATA_OFFSET + len(NONRESIDENT_FILE_CONTENT)] = NONRESIDENT_FILE_CONTENT

    return bytes(image)


def test_bpb_parsing_correct():
    bpb_sector = build_bpb_sector()
    bpb = parse_ntfs_bpb(bpb_sector)
    assert bpb["bytes_per_sector"] == BYTES_PER_SECTOR
    assert bpb["sectors_per_cluster"] == SECTORS_PER_CLUSTER
    assert bpb["cluster_size"] == CLUSTER_SIZE


def test_resident_sha256_known():
    assert hashlib.sha256(RESIDENT_FILE_CONTENT).hexdigest() == RESIDENT_SHA256
    assert len(RESIDENT_FILE_CONTENT) == 200


def test_nonresident_pattern_sha256_verified():
    assert len(NONRESIDENT_FILE_CONTENT) == 65536
    assert NONRESIDENT_FILE_CONTENT[:8] == b"ABCDEFGH"
    assert NONRESIDENT_FILE_CONTENT[-8:] == b"ABCDEFGH"
    expected = hashlib.sha256(NONRESIDENT_PATTERN * 8192).hexdigest()
    assert NONRESIDENT_SHA256 == expected


def test_nonresident_file_readback_from_bytes():
    image = build_synthetic_ntfs_image()

    recovered = scan_ntfs_image_for_deleted_files(image)
    assert len(recovered) >= 2

    by_name = {f.filename: f for f in recovered}

    assert "resident_report_2026.txt" in by_name
    res = by_name["resident_report_2026.txt"]
    assert res.is_resident is True
    assert len(res.data_bytes) == 200
    assert res.data_bytes == RESIDENT_FILE_CONTENT
    assert res.sha256 == RESIDENT_SHA256
    assert res.size_bytes == 200

    assert "exfil_dataset_2026.bin" in by_name
    nonres = by_name["exfil_dataset_2026.bin"]
    assert nonres.is_resident is False
    assert len(nonres.cluster_runs) >= 1
    assert nonres.size_bytes == 65536
    assert len(nonres.data_bytes) == 65536
    assert nonres.data_bytes == NONRESIDENT_FILE_CONTENT
    assert nonres.sha256 == NONRESIDENT_SHA256
    assert nonres.data_bytes[:8] == b"ABCDEFGH"
    assert nonres.data_bytes[-8:] == b"ABCDEFGH"
    assert nonres.data_bytes[0:16] == b"ABCDEFGHABCDEFGH"


def test_nonresident_file_readback_from_tempfile():
    image = build_synthetic_ntfs_image()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".dd") as tmp:
        tmp.write(image)
        tmp_path = tmp.name

    try:
        recovered = scan_ntfs_image_for_deleted_files(tmp_path)
        assert len(recovered) >= 2

        by_name = {f.filename: f for f in recovered}
        assert "exfil_dataset_2026.bin" in by_name
        nonres = by_name["exfil_dataset_2026.bin"]
        assert nonres.is_resident is False
        assert len(nonres.data_bytes) == 65536
        assert nonres.sha256 == NONRESIDENT_SHA256

        assert "resident_report_2026.txt" in by_name
        res = by_name["resident_report_2026.txt"]
        assert res.is_resident is True
        assert res.sha256 == RESIDENT_SHA256
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_parse_mft_record_direct_nonresident():
    image = build_synthetic_ntfs_image()

    nonres_offset = MFT_OFFSET + 2 * MFT_RECORD_SIZE
    raw_rec = image[nonres_offset:nonres_offset + MFT_RECORD_SIZE]
    assert raw_rec[:4] == b"FILE"

    result = parse_mft_record(
        raw_rec,
        record_number=2,
        image_source=image,
        bytes_per_sector=BYTES_PER_SECTOR,
        sectors_per_cluster=SECTORS_PER_CLUSTER,
    )
    assert result is not None
    assert result.filename == "exfil_dataset_2026.bin"
    assert result.is_resident is False
    assert result.size_bytes == 65536
    assert len(result.data_bytes) == 65536
    assert result.sha256 == NONRESIDENT_SHA256
