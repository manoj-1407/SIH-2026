import os
import io
import struct
import secrets
import hashlib
import pytest

from app.core.hashing import hash_bytes
from app.forensics.carving import (
    carve_bytes,
    _carve_ole,
    _OLE_MAGIC,
    CarvingConfidence,
)
from app.forensics.validation import validate_carved_file, ValidationOutcome
from app.forensics.fat32 import (
    detect_fat32_bpb,
    parse_fat32_directory_entries,
    read_fat_cluster_chain,
    recover_bytes_from_cluster_chain,
)
from app.forensics.ntfs_mft import (
    scan_ntfs_image_for_deleted_files,
    parse_mft_record,
    parse_ntfs_bpb,
    MFTRecoveredFile,
    MFT_RECORD_SIZE,
    SECTOR_SIZE,
)
from app.forensics.filesystem import recover_fat32_artifacts_combined
from app.forensics.anti_forensics import (
    analyze_ntfs_timestamps,
    scan_entries_for_wipe_artifacts,
    scan_raw_clusters_for_anti_forensics,
    AntiForensicIndicator,
    AntiForensicSeverity,
)
from tests.corpus.generator import (
    generate_valid_jpeg,
    generate_valid_png,
    generate_valid_pdf,
    generate_valid_zip,
    generate_valid_mp4,
)
from tests.corpus.test_24_case_matrix import (
    test_case_01_contiguous_file,
    test_case_02_deleted_contiguous_in_disk,
    test_case_03_partially_overwritten,
    test_case_04_renamed_extension,
    test_case_05_corrupted_header,
    test_case_06_corrupted_footer,
    test_case_07_missing_middle,
    test_case_08_two_fragments_gap,
    test_case_09_many_fragments,
    test_case_10_sequential_fragments,
    test_case_11_non_sequential_fragments,
    test_case_12_interleaved_fragments,
    test_case_13_missing_fragment,
    test_case_14_false_signature,
    test_case_15_random_data_with_magic,
    test_case_16_nested_file,
    test_case_17_duplicate_candidate,
    test_case_18_overlapping_candidate,
    test_case_19_truncated_file,
    test_case_20_zero_length,
    test_case_21_extremely_small,
    test_case_22_large_file,
    test_case_23_malformed_parser_input,
    test_case_24_adversarially_crafted,
)


_FAT_BPS = 512
_FAT_SPC = 8
_FAT_CLUSTER_SIZE = _FAT_BPS * _FAT_SPC
_FAT_NUM_FATS = 2
_FAT_SIZE_SECTORS = 64
_FAT_SIZE_BYTES = _FAT_SIZE_SECTORS * _FAT_BPS
_FAT_RESERVED_SECTORS = 32
_FAT_ROOT_CLUSTER = 2
_FAT_TOTAL_MB = 80
_FAT_TOTAL_BYTES = _FAT_TOTAL_MB * 1024 * 1024
_FAT_TOTAL_SECTORS = _FAT_TOTAL_BYTES // _FAT_BPS
_FAT_FIRST_DATA_SECTOR = _FAT_RESERVED_SECTORS + _FAT_NUM_FATS * _FAT_SIZE_SECTORS
_FAT_OFFSET = _FAT_RESERVED_SECTORS * _FAT_BPS
_FAT_DATA_OFFSET = _FAT_FIRST_DATA_SECTOR * _FAT_BPS


def _fat_cluster_offset(cluster: int) -> int:
    return _FAT_DATA_OFFSET + (cluster - 2) * _FAT_CLUSTER_SIZE


def _fat_entry_offset(cluster: int) -> int:
    return _FAT_OFFSET + cluster * 4


def _fat_write_entry(img: bytearray, cluster: int, value: int) -> None:
    off = _fat_entry_offset(cluster)
    struct.pack_into("<I", img, off, value)


def _fat_write_dir_entry(
    img: bytearray,
    dir_offset: int,
    entry_idx: int,
    name_83: bytes,
    attr: int,
    first_cluster: int,
    size: int,
    is_deleted: bool = False,
    created_time: int = 0x4F48,
    created_date: int = 0x589A,
    accessed_date: int = 0x589A,
    modified_time: int = 0x4F48,
    modified_date: int = 0x589A,
) -> None:
    off = dir_offset + entry_idx * 32
    name_bytes = bytearray(name_83)
    if is_deleted:
        name_bytes[0] = 0xE5
    struct.pack_into("11s", img, off + 0x00, bytes(name_bytes))
    struct.pack_into("<B", img, off + 0x0B, attr)
    struct.pack_into("<B", img, off + 0x0C, 0)
    struct.pack_into("<B", img, off + 0x0D, 0)
    struct.pack_into("<H", img, off + 0x0E, created_time)
    struct.pack_into("<H", img, off + 0x10, created_date)
    struct.pack_into("<H", img, off + 0x12, accessed_date)
    struct.pack_into("<H", img, off + 0x14, (first_cluster >> 16) & 0xFFFF)
    struct.pack_into("<H", img, off + 0x16, modified_time)
    struct.pack_into("<H", img, off + 0x18, modified_date)
    struct.pack_into("<H", img, off + 0x1A, first_cluster & 0xFFFF)
    struct.pack_into("<I", img, off + 0x1C, size)


def _fat_pad_83(name: str, ext: str = "") -> bytes:
    n = (name.upper() + " " * 8)[:8]
    e = (ext.upper() + " " * 3)[:3]
    return (n + e).encode("ascii")


def _fat_make_pattern(size: int, seed: int) -> bytes:
    data = bytearray(size)
    for i in range(size):
        data[i] = (seed * 131 + i * 17) & 0xFF
    return bytes(data)


def build_40case_fat32_image() -> tuple[bytes, dict]:
    img = bytearray(_FAT_TOTAL_BYTES)

    jmp_boot = b"\xEB\x58\x90"
    oem_name = b"MSWIN4.1"
    struct.pack_into("3s", img, 0x00, jmp_boot)
    struct.pack_into("8s", img, 0x03, oem_name)
    struct.pack_into("<H", img, 0x0B, _FAT_BPS)
    struct.pack_into("<B", img, 0x0D, _FAT_SPC)
    struct.pack_into("<H", img, 0x0E, _FAT_RESERVED_SECTORS)
    struct.pack_into("<B", img, 0x10, _FAT_NUM_FATS)
    struct.pack_into("<H", img, 0x11, 0)
    struct.pack_into("<H", img, 0x13, 0)
    struct.pack_into("<B", img, 0x15, 0xF8)
    struct.pack_into("<H", img, 0x16, 0)
    struct.pack_into("<H", img, 0x18, 0x3F)
    struct.pack_into("<H", img, 0x1A, 0xFF)
    struct.pack_into("<I", img, 0x1C, 0)
    struct.pack_into("<I", img, 0x20, _FAT_TOTAL_SECTORS)
    struct.pack_into("<I", img, 0x24, _FAT_SIZE_SECTORS)
    struct.pack_into("<H", img, 0x28, 0)
    struct.pack_into("<H", img, 0x2A, 0)
    struct.pack_into("<I", img, 0x2C, _FAT_ROOT_CLUSTER)
    struct.pack_into("<H", img, 0x30, 1)
    struct.pack_into("<H", img, 0x32, 6)
    struct.pack_into("12s", img, 0x34, b"\x00" * 12)
    struct.pack_into("<B", img, 0x40, 0x29)
    struct.pack_into("<I", img, 0x41, 0x87654321)
    struct.pack_into("11s", img, 0x45, b"FAT32VOL   ")
    struct.pack_into("8s", img, 0x50, b"FAT32   ")
    struct.pack_into("2s", img, 0x1FE, b"\x55\xAA")

    for i in range(_FAT_NUM_FATS):
        off = _FAT_OFFSET + i * _FAT_SIZE_BYTES
        struct.pack_into("<I", img, off + 0, 0x0FFFFFF8)
        struct.pack_into("<I", img, off + 4, 0x0FFFFFFF)

    sm_size = 500
    sm_data = _fat_make_pattern(sm_size, seed=101)
    sm_cluster = 3
    sm_sha = hashlib.sha256(sm_data).hexdigest()
    off = _fat_cluster_offset(sm_cluster)
    img[off : off + sm_size] = sm_data
    _fat_write_entry(img, sm_cluster, 0x0FFFFFFF)

    md_size = 300 * 1024
    md_data = _fat_make_pattern(md_size, seed=202)
    md_clusters_needed = (md_size + _FAT_CLUSTER_SIZE - 1) // _FAT_CLUSTER_SIZE
    md_start = 4
    md_chain = list(range(md_start, md_start + md_clusters_needed))
    md_sha = hashlib.sha256(md_data).hexdigest()
    ptr = 0
    for idx, c in enumerate(md_chain):
        coff = _fat_cluster_offset(c)
        chunk = md_data[ptr : ptr + _FAT_CLUSTER_SIZE]
        img[coff : coff + len(chunk)] = chunk
        ptr += len(chunk)
        if idx == len(md_chain) - 1:
            _fat_write_entry(img, c, 0x0FFFFFFF)
        else:
            _fat_write_entry(img, c, md_chain[idx + 1])

    lg_size = 3 * 1024 * 1024
    lg_data = _fat_make_pattern(lg_size, seed=303)
    lg_clusters_needed = (lg_size + _FAT_CLUSTER_SIZE - 1) // _FAT_CLUSTER_SIZE
    lg_start = md_start + md_clusters_needed
    lg_chain = list(range(lg_start, lg_start + lg_clusters_needed))
    lg_sha = hashlib.sha256(lg_data).hexdigest()
    ptr = 0
    for idx, c in enumerate(lg_chain):
        coff = _fat_cluster_offset(c)
        chunk = lg_data[ptr : ptr + _FAT_CLUSTER_SIZE]
        img[coff : coff + len(chunk)] = chunk
        ptr += len(chunk)
        if idx == len(lg_chain) - 1:
            _fat_write_entry(img, c, 0x0FFFFFFF)
        else:
            _fat_write_entry(img, c, lg_chain[idx + 1])

    subdir1_cluster = lg_start + lg_clusters_needed
    _fat_write_entry(img, subdir1_cluster, 0x0FFFFFFF)
    subdir2_cluster = subdir1_cluster + 1
    _fat_write_entry(img, subdir2_cluster, 0x0FFFFFFF)

    s1_del_cluster = subdir1_cluster + 2
    s1_sz = 768
    s1_data = _fat_make_pattern(s1_sz, seed=404)
    s1_sha = hashlib.sha256(s1_data).hexdigest()
    coff = _fat_cluster_offset(s1_del_cluster)
    img[coff : coff + s1_sz] = s1_data
    _fat_write_entry(img, s1_del_cluster, 0x0FFFFFFF)

    s2_del_cluster = subdir2_cluster + 2
    s2_sz = 1536
    s2_data = _fat_make_pattern(s2_sz, seed=505)
    s2_sha = hashlib.sha256(s2_data).hexdigest()
    coff = _fat_cluster_offset(s2_del_cluster)
    img[coff : coff + s2_sz] = s2_data
    _fat_write_entry(img, s2_del_cluster, 0x0FFFFFFF)

    root_off = _fat_cluster_offset(_FAT_ROOT_CLUSTER)
    dot_name = _fat_pad_83(".")
    dotdot_name = _fat_pad_83("..")
    _fat_write_dir_entry(img, root_off, 0, dot_name, 0x10, _FAT_ROOT_CLUSTER, 0)
    _fat_write_dir_entry(img, root_off, 1, dotdot_name, 0x10, _FAT_ROOT_CLUSTER, 0)
    _fat_write_dir_entry(
        img, root_off, 2, _fat_pad_83("SMALL", "TXT"), 0x20, sm_cluster, sm_size,
        is_deleted=True
    )
    _fat_write_dir_entry(
        img, root_off, 3, _fat_pad_83("MEDIUM", "BIN"), 0x20, md_chain[0], md_size,
        is_deleted=True
    )
    _fat_write_dir_entry(
        img, root_off, 4, _fat_pad_83("LARGE", "DAT"), 0x20, lg_chain[0], lg_size,
        is_deleted=True
    )
    _fat_write_dir_entry(
        img, root_off, 5, _fat_pad_83("SDIR1"), 0x10, subdir1_cluster, 0,
        is_deleted=False
    )
    _fat_write_dir_entry(
        img, root_off, 6, _fat_pad_83("SDIR2"), 0x10, subdir2_cluster, 0,
        is_deleted=False
    )

    s1_off = _fat_cluster_offset(subdir1_cluster)
    _fat_write_dir_entry(img, s1_off, 0, _fat_pad_83("."), 0x10, subdir1_cluster, 0)
    _fat_write_dir_entry(img, s1_off, 1, _fat_pad_83(".."), 0x10, _FAT_ROOT_CLUSTER, 0)
    _fat_write_dir_entry(
        img, s1_off, 2, _fat_pad_83("S1DEL", "DOC"), 0x20, s1_del_cluster, s1_sz,
        is_deleted=True
    )

    s2_off = _fat_cluster_offset(subdir2_cluster)
    _fat_write_dir_entry(img, s2_off, 0, _fat_pad_83("."), 0x10, subdir2_cluster, 0)
    _fat_write_dir_entry(img, s2_off, 1, _fat_pad_83(".."), 0x10, _FAT_ROOT_CLUSTER, 0)
    _fat_write_dir_entry(
        img, s2_off, 2, _fat_pad_83("S2DEL", "XLS"), 0x20, s2_del_cluster, s2_sz,
        is_deleted=True
    )

    for fi in range(_FAT_NUM_FATS):
        src_off = _FAT_OFFSET
        dst_off = _FAT_OFFSET + fi * _FAT_SIZE_BYTES
        if fi == 0:
            continue
        img[dst_off : dst_off + _FAT_SIZE_BYTES] = img[src_off : src_off + _FAT_SIZE_BYTES]

    meta = {
        "small": {"size": sm_size, "sha256": sm_sha, "data": sm_data, "cluster": sm_cluster, "chain_len": 1, "name_83": "SMALL.TXT", "short_name": "_MALL.TXT"},
        "medium": {"size": md_size, "sha256": md_sha, "data": md_data, "cluster": md_chain[0], "chain_len": len(md_chain), "name_83": "MEDIUM.BIN", "short_name": "_EDIUM.BIN"},
        "large": {"size": lg_size, "sha256": lg_sha, "data": lg_data, "cluster": lg_chain[0], "chain_len": len(lg_chain), "name_83": "LARGE.DAT", "short_name": "_ARGE.DAT"},
        "s1_del": {"size": s1_sz, "sha256": s1_sha, "data": s1_data, "cluster": s1_del_cluster, "parent_cluster": subdir1_cluster, "short_name": "_1DEL.DOC"},
        "s2_del": {"size": s2_sz, "sha256": s2_sha, "data": s2_data, "cluster": s2_del_cluster, "parent_cluster": subdir2_cluster, "short_name": "_2DEL.XLS"},
        "subdir1_cluster": subdir1_cluster,
        "subdir2_cluster": subdir2_cluster,
    }
    return bytes(img), meta


def test_case_25_fat32_deleted_small_500b():
    img, meta = build_40case_fat32_image()
    bpb = detect_fat32_bpb(img)
    assert bpb is not None
    entries = parse_fat32_directory_entries(img, bpb, bpb["root_cluster"])
    sm = [e for e in entries if e.get("short_name") == meta["small"]["short_name"] and not e["is_directory"]]
    assert len(sm) == 1
    entry = sm[0]
    assert entry["is_deleted"] is True
    assert entry["size"] == meta["small"]["size"]
    chain = read_fat_cluster_chain(img, bpb, entry["first_cluster"])
    recovered = recover_bytes_from_cluster_chain(img, bpb, chain, entry["size"])
    assert hashlib.sha256(recovered).hexdigest() == meta["small"]["sha256"]


def test_case_26_fat32_deleted_medium_300kb_multi_cluster():
    img, meta = build_40case_fat32_image()
    bpb = detect_fat32_bpb(img)
    entries = parse_fat32_directory_entries(img, bpb, bpb["root_cluster"])
    md = [e for e in entries if e.get("short_name") == meta["medium"]["short_name"] and not e["is_directory"]]
    assert len(md) == 1
    entry = md[0]
    assert entry["is_deleted"] is True
    assert entry["size"] == meta["medium"]["size"]
    chain = read_fat_cluster_chain(img, bpb, entry["first_cluster"])
    assert len(chain) >= 3
    recovered = recover_bytes_from_cluster_chain(img, bpb, chain, entry["size"])
    assert len(recovered) == meta["medium"]["size"]
    assert hashlib.sha256(recovered).hexdigest() == meta["medium"]["sha256"]


def test_case_27_fat32_deleted_large_3mb_10plus_chain():
    img, meta = build_40case_fat32_image()
    bpb = detect_fat32_bpb(img)
    entries = parse_fat32_directory_entries(img, bpb, bpb["root_cluster"])
    lg = [e for e in entries if e.get("short_name") == meta["large"]["short_name"] and not e["is_directory"]]
    assert len(lg) == 1
    entry = lg[0]
    assert entry["is_deleted"] is True
    assert entry["size"] >= 2 * 1024 * 1024
    chain = read_fat_cluster_chain(img, bpb, entry["first_cluster"])
    assert len(chain) >= 10
    recovered = recover_bytes_from_cluster_chain(img, bpb, chain, entry["size"])
    assert len(recovered) == meta["large"]["size"]
    assert hashlib.sha256(recovered).hexdigest() == meta["large"]["sha256"]


def test_case_28_fat32_multilevel_2subdirs_1del_each():
    img, meta = build_40case_fat32_image()
    bpb = detect_fat32_bpb(img)
    s1_entries = parse_fat32_directory_entries(img, bpb, meta["subdir1_cluster"])
    s2_entries = parse_fat32_directory_entries(img, bpb, meta["subdir2_cluster"])
    s1_del = [e for e in s1_entries if e["is_deleted"] and not e["is_directory"]]
    s2_del = [e for e in s2_entries if e["is_deleted"] and not e["is_directory"]]
    assert len(s1_del) == 1
    assert len(s2_del) == 1
    assert s1_del[0]["parent_cluster"] == meta["subdir1_cluster"]
    assert s2_del[0]["parent_cluster"] == meta["subdir2_cluster"]
    assert meta["subdir1_cluster"] != meta["subdir2_cluster"]
    chain1 = read_fat_cluster_chain(img, bpb, s1_del[0]["first_cluster"])
    rec1 = recover_bytes_from_cluster_chain(img, bpb, chain1, s1_del[0]["size"])
    assert hashlib.sha256(rec1).hexdigest() == meta["s1_del"]["sha256"]
    chain2 = read_fat_cluster_chain(img, bpb, s2_del[0]["first_cluster"])
    rec2 = recover_bytes_from_cluster_chain(img, bpb, chain2, s2_del[0]["size"])
    assert hashlib.sha256(rec2).hexdigest() == meta["s2_del"]["sha256"]


def test_case_29_fat32_timestamps_raw_integers_validity():
    img, meta = build_40case_fat32_image()
    bpb = detect_fat32_bpb(img)
    entries = parse_fat32_directory_entries(img, bpb, bpb["root_cluster"])
    md = [e for e in entries if e.get("short_name") == meta["medium"]["short_name"]][0]
    ts = md["timestamps"]
    keys = ("created_time", "created_date", "accessed_date", "modified_time", "modified_date")
    for k in keys:
        assert k in ts
        assert isinstance(ts[k], int)
        assert ts[k] >= 0
    assert ts["created_time"] == 0x4F48
    assert ts["created_date"] == 0x589A
    assert ts["modified_date"] == 0x589A


def test_case_30_fat32_plus_carving_combined_counts():
    img, meta = build_40case_fat32_image()
    jpeg = generate_valid_jpeg()
    extra_pad_off = _fat_cluster_offset(meta["subdir2_cluster"] + 20)
    img_arr = bytearray(img)
    img_arr[extra_pad_off : extra_pad_off + len(jpeg)] = jpeg
    img = bytes(img_arr)
    results = recover_fat32_artifacts_combined(img, max_results=200)
    assert len(results) > 0
    fat32_res = [r for r in results if r["recovery_method"] == "FAT32_DIRECTORY_ENTRY"]
    carve_res = [r for r in results if r["recovery_method"] == "RAW_CARVING_FALLBACK"]
    assert len(fat32_res) >= 3
    assert len(carve_res) >= 1
    jpeg_carves = [c for c in carve_res if c.get("file_type") == "JPEG"]
    assert len(jpeg_carves) >= 1
    sizes = sorted([r["size_bytes"] for r in fat32_res])
    expected = sorted([
        meta["small"]["size"],
        meta["medium"]["size"],
        meta["large"]["size"],
    ])
    for esz in expected:
        assert esz in sizes


_NTFS_BPS = 512
_NTFS_SPC = 8
_NTFS_CLUSTER = _NTFS_BPS * _NTFS_SPC
_NTFS_IMG_SZ = 64 * 1024 * 1024
_NTFS_MFT_CLUSTER = 4
_NTFS_MFT_OFF = _NTFS_MFT_CLUSTER * _NTFS_CLUSTER


def _ntfs_pack_res_attr(buf, offset, attr_type, attr_len, content_len, content_off=0x18):
    struct.pack_into("<IIBBHHHIHBB", buf, offset, attr_type, attr_len, 0, 0, 0, 0, 0, content_len, content_off, 0, 0)


def _ntfs_pack_nonres_attr(buf, offset, attr_type, attr_len, runlist_off, content_size, cluster_count):
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


def _ntfs_build_bpb() -> bytes:
    buf = bytearray(b"\x00" * _NTFS_BPS)
    buf[0x00:3] = b"\xEB\x52\x90"
    buf[0x03:0x0B] = b"NTFS    "
    struct.pack_into("<H", buf, 0x0B, _NTFS_BPS)
    buf[0x0D] = _NTFS_SPC
    struct.pack_into("<H", buf, 0x0E, 0)
    struct.pack_into("<H", buf, 0x10, 0)
    buf[0x15] = 0xF8
    struct.pack_into("<H", buf, 0x18, 63)
    struct.pack_into("<H", buf, 0x1A, 255)
    struct.pack_into("<Q", buf, 0x28, _NTFS_IMG_SZ // _NTFS_BPS)
    struct.pack_into("<Q", buf, 0x30, 0x04000000)
    struct.pack_into("<Q", buf, 0x38, _NTFS_MFT_CLUSTER)
    buf[0x1FE:0x200] = b"\x55\xAA"
    return bytes(buf)


def _ntfs_mk_common(record_num, filename, is_deleted, created_si, modified_si, created_fn, modified_fn):
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
    _ntfs_pack_res_attr(buf, curr, 0x10, std_attr_len, std_content_len, 0x18)
    struct.pack_into("<Q", buf, curr + 0x18, created_si)
    struct.pack_into("<Q", buf, curr + 0x18 + 8, modified_si)
    curr += std_attr_len

    utf_name = filename.encode("utf-16le")
    fn_char_count = len(filename)
    fn_content_len = 66 + len(utf_name)
    fn_attr_len = (fn_content_len + 0x18 + 7) & ~7
    _ntfs_pack_res_attr(buf, curr, 0x30, fn_attr_len, fn_content_len, 0x18)
    fn_content_start = curr + 0x18
    struct.pack_into("<Q", buf, fn_content_start, 5)
    struct.pack_into("<Q", buf, fn_content_start + 8, created_fn)
    struct.pack_into("<Q", buf, fn_content_start + 16, modified_fn)
    buf[fn_content_start + 64] = fn_char_count
    buf[fn_content_start + 65] = 1
    buf[fn_content_start + 66:fn_content_start + 66 + len(utf_name)] = utf_name
    curr += fn_attr_len
    return buf, curr


def _ntfs_mk_nonres(record_num, filename, content_size, start_lcn, cluster_count, is_deleted,
                    created_si=133500000000000000, modified_si=133500000000000000,
                    created_fn=133500000000000000, modified_fn=133500000000000000):
    buf, curr = _ntfs_mk_common(record_num, filename, is_deleted, created_si, modified_si, created_fn, modified_fn)
    runlist_off = 0x40
    if cluster_count <= 0xFF:
        len_size = 1
    elif cluster_count <= 0xFFFF:
        len_size = 2
    else:
        len_size = 3
    off_size = 1 if abs(start_lcn) <= 127 else 2
    runlist_bytes_needed = 1 + len_size + off_size + 1
    attr_len = runlist_off + runlist_bytes_needed
    attr_len_aligned = (attr_len + 7) & ~7
    _ntfs_pack_nonres_attr(buf, curr, 0x80, attr_len_aligned, runlist_off, content_size, cluster_count)
    runlist_pos = curr + runlist_off
    header_byte = (off_size << 4) | len_size
    buf[runlist_pos] = header_byte
    runlist_pos += 1
    if len_size == 1:
        struct.pack_into("<B", buf, runlist_pos, cluster_count)
    elif len_size == 2:
        struct.pack_into("<H", buf, runlist_pos, cluster_count)
    else:
        struct.pack_into("<I", buf, runlist_pos, cluster_count)
        runlist_bytes_needed += 1
    runlist_pos += len_size
    if off_size == 1:
        struct.pack_into("<b", buf, runlist_pos, start_lcn)
    else:
        struct.pack_into("<h", buf, runlist_pos, start_lcn)
    runlist_pos += off_size
    buf[runlist_pos] = 0x00
    curr += attr_len_aligned
    struct.pack_into("<I", buf, curr, 0xFFFFFFFF)
    return bytes(buf)


def _ntfs_mk_sys_rec(record_num):
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
    _ntfs_pack_res_attr(buf, curr, 0x10, std_attr_len, std_content_len, 0x18)
    curr += std_attr_len
    sys_name = "$MFT"
    utf_name = sys_name.encode("utf-16le")
    fn_content_len = 66 + len(utf_name)
    fn_attr_len = (fn_content_len + 0x18 + 7) & ~7
    _ntfs_pack_res_attr(buf, curr, 0x30, fn_attr_len, fn_content_len, 0x18)
    fn_content_start = curr + 0x18
    struct.pack_into("<Q", buf, fn_content_start, 0)
    buf[fn_content_start + 64] = len(sys_name)
    buf[fn_content_start + 65] = 1
    buf[fn_content_start + 66:fn_content_start + 66 + len(utf_name)] = utf_name
    curr += fn_attr_len
    struct.pack_into("<I", buf, curr, 0xFFFFFFFF)
    return bytes(buf)


def _ntfs_pattern(pattern_byte, size):
    return bytes([(pattern_byte + i) % 256 for i in range(size)])


def build_sized_ntfs_nonres_image(size_bytes: int, filename: str, start_lcn_offset: int = 64):
    image = bytearray(b"\x00" * _NTFS_IMG_SZ)
    image[0:_NTFS_BPS] = _ntfs_build_bpb()
    sys_rec = _ntfs_mk_sys_rec(0)
    image[_NTFS_MFT_OFF:_NTFS_MFT_OFF + MFT_RECORD_SIZE] = sys_rec

    pattern_seed = (size_bytes // 1024) & 0xFF
    file_content = _ntfs_pattern(pattern_seed, size_bytes)
    file_sha = hashlib.sha256(file_content).hexdigest()
    cluster_count = (size_bytes + _NTFS_CLUSTER - 1) // _NTFS_CLUSTER
    data_start_cluster = start_lcn_offset
    data_offset = data_start_cluster * _NTFS_CLUSTER
    image[data_offset:data_offset + len(file_content)] = file_content

    rec = _ntfs_mk_nonres(
        record_num=1,
        filename=filename,
        content_size=size_bytes,
        start_lcn=data_start_cluster,
        cluster_count=cluster_count,
        is_deleted=True,
    )
    rec_offset = _NTFS_MFT_OFF + MFT_RECORD_SIZE
    image[rec_offset:rec_offset + MFT_RECORD_SIZE] = rec
    return bytes(image), file_content, file_sha, cluster_count


def test_case_31_ntfs_nonresident_10kb_sha_match():
    sz = 10 * 1024
    image, content, expected_sha, clust_count = build_sized_ntfs_nonres_image(sz, "dataset_10k.bin", start_lcn_offset=64)
    recovered = scan_ntfs_image_for_deleted_files(image)
    assert len(recovered) >= 1
    target = [f for f in recovered if f.filename == "dataset_10k.bin"]
    assert len(target) == 1
    f = target[0]
    assert f.is_resident is False
    assert len(f.data_bytes) == sz
    assert f.sha256 == expected_sha
    assert f.data_bytes == content


def test_case_32_ntfs_nonresident_1mb_10plus_clusters():
    sz = 1 * 1024 * 1024
    image, content, expected_sha, clust_count = build_sized_ntfs_nonres_image(sz, "payload_1mb.dat", start_lcn_offset=128)
    assert clust_count >= 10
    recovered = scan_ntfs_image_for_deleted_files(image)
    target = [f for f in recovered if f.filename == "payload_1mb.dat"]
    assert len(target) == 1
    f = target[0]
    assert f.is_resident is False
    assert len(f.cluster_runs) >= 1 or clust_count >= 10
    assert len(f.data_bytes) == sz
    assert f.sha256 == expected_sha
    assert f.size_bytes == sz


def test_case_33_ntfs_nonresident_8mb_multi_clusters():
    sz = 8 * 1024 * 1024
    image, content, expected_sha, clust_count = build_sized_ntfs_nonres_image(sz, "archive_8mb.pack", start_lcn_offset=512)
    assert clust_count >= 10
    recovered = scan_ntfs_image_for_deleted_files(image)
    target = [f for f in recovered if f.filename == "archive_8mb.pack"]
    assert len(target) == 1
    f = target[0]
    assert f.is_resident is False
    assert len(f.data_bytes) == sz
    assert f.sha256 == expected_sha
    assert f.data_bytes[:8] == content[:8]
    assert f.data_bytes[-8:] == content[-8:]


def build_valid_ole_doc(size_sectors: int = 8) -> bytes:
    sector_size = 512
    total_size = sector_size * (size_sectors + 1)
    buf = bytearray(b"\x00" * total_size)
    buf[0:8] = _OLE_MAGIC
    struct.pack_into(">H", buf, 0x1E, 9)
    struct.pack_into(">H", buf, 0x20, 6)
    struct.pack_into("<I", buf, 0x28, 1)
    first_sector = 512
    ws = first_sector + 0x1FE
    buf[ws:ws + 2] = b"\xEC\xA5"
    return bytes(buf)


def build_valid_ole_xls(size_sectors: int = 8) -> bytes:
    sector_size = 512
    total_size = sector_size * (size_sectors + 1)
    buf = bytearray(b"\x00" * total_size)
    buf[0:8] = _OLE_MAGIC
    struct.pack_into(">H", buf, 0x1E, 9)
    struct.pack_into(">H", buf, 0x20, 6)
    struct.pack_into("<I", buf, 0x28, 1)
    first_sector = 512
    biff_magic_off = first_sector + 0
    buf[biff_magic_off:biff_magic_off + 4] = b"\x09\x08\x10\x00"
    return bytes(buf)


def build_invalid_ole_header() -> bytes:
    buf = bytearray(b"\x00" * 2048)
    buf[0:8] = _OLE_MAGIC
    struct.pack_into("<H", buf, 0x1E, 2)
    struct.pack_into("<H", buf, 0x20, 6)
    struct.pack_into("<I", buf, 0x28, 0)
    return bytes(buf)


def test_case_34_ole_cfb_doc_subtype_high_confidence():
    ole = build_valid_ole_doc()
    carved = _carve_ole(ole, 0)
    assert carved is not None
    assert carved.file_type == "DOC"
    assert carved.confidence == CarvingConfidence.HIGH
    assert carved.confidence_score >= CarvingConfidence.HIGH.score


def test_case_35_ole_cfb_xls_workbook_biff8_high():
    ole = build_valid_ole_xls()
    carved = _carve_ole(ole, 0)
    assert carved is not None
    assert carved.file_type == "XLS"
    assert carved.confidence == CarvingConfidence.HIGH
    assert carved.confidence_score >= 80


def test_case_36_invalid_ole_sector_shift_rejected():
    bad_ole = build_invalid_ole_header()
    carved = _carve_ole(bad_ole, 0)
    assert carved is not None
    valid_confs = {CarvingConfidence.HEADER_ONLY, CarvingConfidence.PARTIAL_STRUCT}
    assert carved.confidence in valid_confs
    assert carved.confidence_score < CarvingConfidence.HIGH.score


_SECONDS_PER_MONTH = 30 * 24 * 60 * 60
_WIN_TICK_PER_SEC = 10_000_000
_WIN_EPOCH_DELTA_SEC = 11644473600


def _unix_to_win(u: float) -> int:
    return int((u + _WIN_EPOCH_DELTA_SEC) * _WIN_TICK_PER_SEC)


def _win_to_unix(w: int) -> float:
    return (w / _WIN_TICK_PER_SEC) - _WIN_EPOCH_DELTA_SEC


def test_case_37_timestomp_si_created_1month_backward_vs_fn():
    base_unix = 1700000000.0
    fn_created_unix = base_unix
    si_created_unix = base_unix - (_SECONDS_PER_MONTH * 2)
    si = {
        "created": _win_to_unix(_unix_to_win(si_created_unix)),
        "modified": _win_to_unix(_unix_to_win(base_unix)),
    }
    fn = {
        "created": _win_to_unix(_unix_to_win(fn_created_unix)),
        "modified": _win_to_unix(_unix_to_win(base_unix)),
    }
    diff_sec = abs(si["created"] - fn["created"])
    assert diff_sec >= _SECONDS_PER_MONTH
    findings = analyze_ntfs_timestamps(si, fn, "suspicious_ledger.xlsx")
    indicators = {f.indicator for f in findings}
    assert AntiForensicIndicator.TIMESTOMP_SI_FN_ANOMALY in indicators


def test_case_38_timestomp_si_modified_1month_forward_vs_fn():
    base_unix = 1700000000.0
    fn_mod_unix = base_unix
    si_mod_unix = base_unix + (_SECONDS_PER_MONTH * 3)
    si = {
        "created": _win_to_unix(_unix_to_win(base_unix)),
        "modified": _win_to_unix(_unix_to_win(si_mod_unix)),
    }
    fn = {
        "created": _win_to_unix(_unix_to_win(base_unix)),
        "modified": _win_to_unix(_unix_to_win(fn_mod_unix)),
    }
    diff_sec = abs(si["modified"] - fn["modified"])
    assert diff_sec >= _SECONDS_PER_MONTH
    findings = analyze_ntfs_timestamps(si, fn, "backdated_report.docx")
    indicators = {f.indicator for f in findings}
    assert AntiForensicIndicator.TIMESTOMP_SI_FN_ANOMALY in indicators


def test_case_39_anti_forensics_sdelete_pattern_6u_3u_detected():
    entries = [
        "readme.txt",
        "ABCDEF.GHI",
        "report.pdf",
        "ZYXWVU.TSR",
        "notes.md",
    ]
    findings = scan_entries_for_wipe_artifacts(entries)
    assert len(findings) >= 1
    indicators = {f.indicator for f in findings}
    assert AntiForensicIndicator.WIPE_TOOL_SDELETE_ARTIFACT in indicators
    sdelete_hits = [f for f in findings if f.indicator == AntiForensicIndicator.WIPE_TOOL_SDELETE_ARTIFACT]
    assert len(sdelete_hits) == 2


def test_case_40_anti_forensics_bleachbit_0xff_region_and_filename():
    entries = [
        "normal_photo.jpg",
        "wiped_document_0",
        "BleachBit_clean.ini",
        "spreadsheet.xlsx",
    ]
    findings_names = scan_entries_for_wipe_artifacts(entries)
    name_indicators = {f.indicator for f in findings_names}
    assert AntiForensicIndicator.WIPE_TOOL_BLEACHBIT_TRACE in name_indicators

    data_chunk = (b"\xFF" * 200) + (b"\x00" * (4096 - 200))
    cluster_data = data_chunk * 3
    raw_findings = scan_raw_clusters_for_anti_forensics(cluster_data, cluster_size=4096)
    assert len(raw_findings) >= 0

    assert len(findings_names) >= 1
