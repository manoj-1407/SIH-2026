import os
import struct
import hashlib
import pytest
from pathlib import Path


BPS = 512
SPC = 8
CLUSTER_SIZE = BPS * SPC
NUM_FATS = 2
FAT_SIZE_SECTORS = 32
FAT_SIZE_BYTES = FAT_SIZE_SECTORS * BPS
RESERVED_SECTORS = 32
ROOT_CLUSTER = 2
TOTAL_MB = 50
TOTAL_BYTES = TOTAL_MB * 1024 * 1024
TOTAL_SECTORS = TOTAL_BYTES // BPS
FIRST_DATA_SECTOR = RESERVED_SECTORS + NUM_FATS * FAT_SIZE_SECTORS
FAT_OFFSET = RESERVED_SECTORS * BPS
DATA_OFFSET = FIRST_DATA_SECTOR * BPS


def _cluster_offset(cluster: int) -> int:
    return DATA_OFFSET + (cluster - 2) * CLUSTER_SIZE


def _fat_entry_offset(cluster: int) -> int:
    return FAT_OFFSET + cluster * 4


def _write_fat_entry(img: bytearray, cluster: int, value: int) -> None:
    off = _fat_entry_offset(cluster)
    struct.pack_into("<I", img, off, value)


def _write_directory_entry(
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


def _pad_83(name: str, ext: str = "") -> bytes:
    n = (name.upper() + " " * 8)[:8]
    e = (ext.upper() + " " * 3)[:3]
    return (n + e).encode("ascii")


def _make_pattern(size: int, seed: int) -> bytes:
    data = bytearray(size)
    for i in range(size):
        data[i] = (seed * 131 + i * 17) & 0xFF
    return bytes(data)


def build_synthetic_fat32_image() -> tuple[bytes, dict]:
    img = bytearray(TOTAL_BYTES)

    jmp_boot = b"\xEB\x58\x90"
    oem_name = b"MSWIN4.1"
    struct.pack_into("3s", img, 0x00, jmp_boot)
    struct.pack_into("8s", img, 0x03, oem_name)
    struct.pack_into("<H", img, 0x0B, BPS)
    struct.pack_into("<B", img, 0x0D, SPC)
    struct.pack_into("<H", img, 0x0E, RESERVED_SECTORS)
    struct.pack_into("<B", img, 0x10, NUM_FATS)
    struct.pack_into("<H", img, 0x11, 0)
    struct.pack_into("<H", img, 0x13, 0)
    struct.pack_into("<B", img, 0x15, 0xF8)
    struct.pack_into("<H", img, 0x16, 0)
    struct.pack_into("<H", img, 0x18, 0x3F)
    struct.pack_into("<H", img, 0x1A, 0xFF)
    struct.pack_into("<I", img, 0x1C, 0)
    struct.pack_into("<I", img, 0x20, TOTAL_SECTORS)
    struct.pack_into("<I", img, 0x24, FAT_SIZE_SECTORS)
    struct.pack_into("<H", img, 0x28, 0)
    struct.pack_into("<H", img, 0x2A, 0)
    struct.pack_into("<I", img, 0x2C, ROOT_CLUSTER)
    struct.pack_into("<H", img, 0x30, 1)
    struct.pack_into("<H", img, 0x32, 6)
    struct.pack_into("12s", img, 0x34, b"\x00" * 12)
    struct.pack_into("<B", img, 0x40, 0x29)
    struct.pack_into("<I", img, 0x41, 0x12345678)
    struct.pack_into("11s", img, 0x45, b"FAT32VOL   ")
    struct.pack_into("8s", img, 0x50, b"FAT32   ")
    struct.pack_into("2s", img, 0x1FE, b"\x55\xAA")

    for i in range(NUM_FATS):
        off = FAT_OFFSET + i * FAT_SIZE_BYTES
        struct.pack_into("<I", img, off + 0, 0x0FFFFFF8)
        struct.pack_into("<I", img, off + 4, 0x0FFFFFFF)

    file_a_size = 500
    file_a_data = _make_pattern(file_a_size, seed=11)
    file_a_cluster = 3
    file_a_sha = hashlib.sha256(file_a_data).hexdigest()

    off = _cluster_offset(file_a_cluster)
    img[off : off + file_a_size] = file_a_data
    _write_fat_entry(img, file_a_cluster, 0x0FFFFFFF)

    file_b_size = 300 * 1024
    file_b_data = _make_pattern(file_b_size, seed=22)
    file_b_clusters_needed = (file_b_size + CLUSTER_SIZE - 1) // CLUSTER_SIZE
    file_b_start = 4
    file_b_chain = list(range(file_b_start, file_b_start + file_b_clusters_needed))
    file_b_sha = hashlib.sha256(file_b_data).hexdigest()

    ptr = 0
    for idx, c in enumerate(file_b_chain):
        coff = _cluster_offset(c)
        chunk = file_b_data[ptr : ptr + CLUSTER_SIZE]
        img[coff : coff + len(chunk)] = chunk
        ptr += len(chunk)
        if idx == len(file_b_chain) - 1:
            _write_fat_entry(img, c, 0x0FFFFFFF)
        else:
            _write_fat_entry(img, c, file_b_chain[idx + 1])

    file_c_size = 10 * 1024 * 1024
    file_c_data = _make_pattern(file_c_size, seed=33)
    file_c_clusters_needed = (file_c_size + CLUSTER_SIZE - 1) // CLUSTER_SIZE
    file_c_start = file_b_start + file_b_clusters_needed
    file_c_chain = list(range(file_c_start, file_c_start + file_c_clusters_needed))
    file_c_sha = hashlib.sha256(file_c_data).hexdigest()

    ptr = 0
    for idx, c in enumerate(file_c_chain):
        coff = _cluster_offset(c)
        chunk = file_c_data[ptr : ptr + CLUSTER_SIZE]
        img[coff : coff + len(chunk)] = chunk
        ptr += len(chunk)
        if idx == len(file_c_chain) - 1:
            _write_fat_entry(img, c, 0x0FFFFFFF)
        else:
            _write_fat_entry(img, c, file_c_chain[idx + 1])

    subdir_cluster = file_c_start + file_c_clusters_needed
    _write_fat_entry(img, subdir_cluster, 0x0FFFFFFF)

    sub_subdir = subdir_cluster + 1
    subfile1_cluster = subdir_cluster + 2
    subfile2_cluster = subdir_cluster + 3

    sub_f1_size = 1024
    sub_f1_data = _make_pattern(sub_f1_size, seed=44)
    sub_f1_sha = hashlib.sha256(sub_f1_data).hexdigest()
    coff = _cluster_offset(subfile1_cluster)
    img[coff : coff + sub_f1_size] = sub_f1_data
    _write_fat_entry(img, subfile1_cluster, 0x0FFFFFFF)

    sub_f2_size = 2048
    sub_f2_data = _make_pattern(sub_f2_size, seed=55)
    sub_f2_sha = hashlib.sha256(sub_f2_data).hexdigest()
    coff = _cluster_offset(subfile2_cluster)
    img[coff : coff + sub_f2_size] = sub_f2_data
    _write_fat_entry(img, subfile2_cluster, 0x0FFFFFFF)

    root_off = _cluster_offset(ROOT_CLUSTER)

    dot_name = _pad_83(".")
    dotdot_name = _pad_83("..")
    _write_directory_entry(img, root_off, 0, dot_name, 0x10, ROOT_CLUSTER, 0)
    _write_directory_entry(img, root_off, 1, dotdot_name, 0x10, ROOT_CLUSTER, 0)

    _write_directory_entry(
        img, root_off, 2, _pad_83("FILEA", "TXT"), 0x20, file_a_cluster, file_a_size,
        is_deleted=True
    )
    _write_directory_entry(
        img, root_off, 3, _pad_83("FILEB", "BIN"), 0x20, file_b_chain[0], file_b_size,
        is_deleted=True
    )
    _write_directory_entry(
        img, root_off, 4, _pad_83("FILEC", "DAT"), 0x20, file_c_chain[0], file_c_size,
        is_deleted=False
    )
    _write_directory_entry(
        img, root_off, 5, _pad_83("SUBDIR"), 0x10, subdir_cluster, 0,
        is_deleted=False
    )

    sub_off = _cluster_offset(subdir_cluster)
    _write_directory_entry(img, sub_off, 0, _pad_83("."), 0x10, subdir_cluster, 0)
    _write_directory_entry(img, sub_off, 1, _pad_83(".."), 0x10, ROOT_CLUSTER, 0)
    _write_directory_entry(
        img, sub_off, 2, _pad_83("SUBF1", "TXT"), 0x20, subfile1_cluster, sub_f1_size,
        is_deleted=True
    )
    _write_directory_entry(
        img, sub_off, 3, _pad_83("SUBF2", "LOG"), 0x20, subfile2_cluster, sub_f2_size,
        is_deleted=False
    )

    for fi in range(NUM_FATS):
        src_off = FAT_OFFSET
        dst_off = FAT_OFFSET + fi * FAT_SIZE_BYTES
        if fi == 0:
            continue
        img[dst_off : dst_off + FAT_SIZE_BYTES] = img[src_off : src_off + FAT_SIZE_BYTES]

    meta = {
        "file_a": {"size": file_a_size, "sha256": file_a_sha, "data": file_a_data, "cluster": file_a_cluster},
        "file_b": {"size": file_b_size, "sha256": file_b_sha, "data": file_b_data, "cluster": file_b_chain[0], "chain_len": len(file_b_chain)},
        "file_c": {"size": file_c_size, "sha256": file_c_sha, "data": file_c_data, "cluster": file_c_chain[0], "chain_len": len(file_c_chain)},
        "sub_f1": {"size": sub_f1_size, "sha256": sub_f1_sha, "data": sub_f1_data, "cluster": subfile1_cluster},
        "sub_f2": {"size": sub_f2_size, "sha256": sub_f2_sha, "data": sub_f2_data, "cluster": subfile2_cluster},
        "subdir_cluster": subdir_cluster,
    }
    return bytes(img), meta


def test_detect_fat32_bpb_valid():
    from app.forensics.fat32 import detect_fat32_bpb
    img, meta = build_synthetic_fat32_image()
    bpb = detect_fat32_bpb(img)
    assert bpb is not None
    assert bpb["bytes_per_sector"] == BPS
    assert bpb["sectors_per_cluster"] == SPC
    assert bpb["reserved_sectors"] == RESERVED_SECTORS
    assert bpb["num_fats"] == NUM_FATS
    assert bpb["fat_size_32"] == FAT_SIZE_SECTORS
    assert bpb["root_cluster"] == ROOT_CLUSTER
    assert bpb["ext_boot_sig"] in (0x28, 0x29)
    assert bpb["first_data_sector"] == FIRST_DATA_SECTOR
    assert bpb["cluster_size"] == CLUSTER_SIZE
    assert bpb["fat_offset"] == FAT_OFFSET


def test_detect_fat32_bpb_invalid():
    from app.forensics.fat32 import detect_fat32_bpb
    bad = b"\x00" * 1024
    assert detect_fat32_bpb(bad) is None
    short = b"\x00" * 100
    assert detect_fat32_bpb(short) is None


def test_fat_entry_is_eoc():
    from app.forensics.fat32 import _fat_entry_is_eoc
    assert _fat_entry_is_eoc(0x0FFFFFF8) is True
    assert _fat_entry_is_eoc(0x0FFFFFFF) is True
    assert _fat_entry_is_eoc(0x0FFFFFF9) is True
    assert _fat_entry_is_eoc(0xFFFFFFFF & 0x0FFFFFFF) is True
    assert _fat_entry_is_eoc(0x0FFFFFF7) is False
    assert _fat_entry_is_eoc(0x00000005) is False
    assert _fat_entry_is_eoc(0) is False
    assert _fat_entry_is_eoc(0xF0000000 | 0x0FFFFFF8) is True


def test_read_cluster_chain_file_b():
    from app.forensics.fat32 import detect_fat32_bpb, read_fat_cluster_chain
    img, meta = build_synthetic_fat32_image()
    bpb = detect_fat32_bpb(img)
    chain = read_fat_cluster_chain(img, bpb, meta["file_b"]["cluster"])
    assert len(chain) == meta["file_b"]["chain_len"]
    assert chain[0] == meta["file_b"]["cluster"]
    for i in range(len(chain) - 1):
        assert chain[i + 1] == chain[i] + 1


def test_parse_fat32_directory_entries_three_deleted():
    from app.forensics.fat32 import detect_fat32_bpb, parse_fat32_directory_entries
    img, meta = build_synthetic_fat32_image()
    bpb = detect_fat32_bpb(img)
    entries = parse_fat32_directory_entries(img, bpb, bpb["root_cluster"])
    assert len(entries) >= 6

    deleted_files = [e for e in entries if e["is_deleted"] and not e["is_directory"]]
    assert len(deleted_files) == 3, f"Expected 3 deleted files, got {len(deleted_files)}: {[(e['name'], e['size']) for e in deleted_files]}"

    sizes = sorted([e["size"] for e in deleted_files])
    expected_sorted = sorted([
        meta["file_a"]["size"],
        meta["file_b"]["size"],
        meta["sub_f1"]["size"],
    ])
    assert sizes == expected_sorted

    names = {e["short_name"] for e in entries}
    assert "_ILEA.TXT" in names
    assert "_ILEB.BIN" in names
    assert "FILEC.DAT" in names
    assert "SUBDIR" in names

    subs = [e for e in entries if e["parent_cluster"] == meta["subdir_cluster"]]
    assert len(subs) >= 2
    sub_deleted = [s for s in subs if s["is_deleted"]]
    assert len(sub_deleted) == 1
    assert sub_deleted[0]["size"] == meta["sub_f1"]["size"]
    assert sub_deleted[0]["short_name"] == "_UBF1.TXT"


def test_recover_bytes_from_cluster_chain_file_b_sha256():
    from app.forensics.fat32 import (
        detect_fat32_bpb,
        read_fat_cluster_chain,
        recover_bytes_from_cluster_chain,
    )
    img, meta = build_synthetic_fat32_image()
    bpb = detect_fat32_bpb(img)
    chain = read_fat_cluster_chain(img, bpb, meta["file_b"]["cluster"])
    recovered = recover_bytes_from_cluster_chain(img, bpb, chain, meta["file_b"]["size"])
    assert len(recovered) == meta["file_b"]["size"]
    assert hashlib.sha256(recovered).hexdigest() == meta["file_b"]["sha256"]
    assert recovered == meta["file_b"]["data"]


def test_recover_small_file_a():
    from app.forensics.fat32 import (
        detect_fat32_bpb,
        read_fat_cluster_chain,
        recover_bytes_from_cluster_chain,
    )
    img, meta = build_synthetic_fat32_image()
    bpb = detect_fat32_bpb(img)
    chain = read_fat_cluster_chain(img, bpb, meta["file_a"]["cluster"])
    assert len(chain) == 1
    recovered = recover_bytes_from_cluster_chain(img, bpb, chain, meta["file_a"]["size"])
    assert len(recovered) == 500
    assert hashlib.sha256(recovered).hexdigest() == meta["file_a"]["sha256"]


def test_recover_10mb_file_c():
    from app.forensics.fat32 import (
        detect_fat32_bpb,
        read_fat_cluster_chain,
        recover_bytes_from_cluster_chain,
    )
    img, meta = build_synthetic_fat32_image()
    bpb = detect_fat32_bpb(img)
    chain = read_fat_cluster_chain(img, bpb, meta["file_c"]["cluster"])
    assert len(chain) == meta["file_c"]["chain_len"]
    recovered = recover_bytes_from_cluster_chain(img, bpb, chain, meta["file_c"]["size"])
    assert len(recovered) == meta["file_c"]["size"]
    assert hashlib.sha256(recovered).hexdigest() == meta["file_c"]["sha256"]


def test_recover_subdir_deleted_subfile1():
    from app.forensics.fat32 import (
        detect_fat32_bpb,
        read_fat_cluster_chain,
        recover_bytes_from_cluster_chain,
    )
    img, meta = build_synthetic_fat32_image()
    bpb = detect_fat32_bpb(img)
    chain = read_fat_cluster_chain(img, bpb, meta["sub_f1"]["cluster"])
    recovered = recover_bytes_from_cluster_chain(img, bpb, chain, meta["sub_f1"]["size"])
    assert len(recovered) == meta["sub_f1"]["size"]
    assert hashlib.sha256(recovered).hexdigest() == meta["sub_f1"]["sha256"]


def test_combined_fat32_plus_carving_from_filesystem():
    from app.forensics.filesystem import recover_fat32_artifacts_combined
    img, meta = build_synthetic_fat32_image()

    jpeg = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        + b"\xff\xdb\x00\x43\x00" + (b"\x01" * 64)
        + b"\xff\xc0\x00\x0b\x08\x00\x10\x00\x10\x01\x01\x11\x00"
        + b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00\x00"
        + (b"\xAB" * 100)
        + b"\xff\xd9"
    )
    jpeg_off = _cluster_offset(meta["file_c"]["cluster"] + meta["file_c"]["chain_len"] + 10)
    img_arr = bytearray(img)
    img_arr[jpeg_off : jpeg_off + len(jpeg)] = jpeg
    img = bytes(img_arr)

    results = recover_fat32_artifacts_combined(img, max_results=100)
    assert len(results) > 0

    fat32_res = [r for r in results if r["recovery_method"] == "FAT32_DIRECTORY_ENTRY"]
    carve_res = [r for r in results if r["recovery_method"] == "RAW_CARVING_FALLBACK"]
    assert len(fat32_res) >= 3
    assert len(carve_res) >= 1

    sizes = sorted([r["size_bytes"] for r in fat32_res])
    expected = sorted([
        meta["file_a"]["size"],
        meta["file_b"]["size"],
        meta["sub_f1"]["size"],
    ])
    assert sizes == expected

    big = [r for r in fat32_res if r["size_bytes"] == meta["file_b"]["size"]][0]
    assert big["sha256"] == meta["file_b"]["sha256"]
    assert big["is_deleted"] is True
    assert "first_cluster" in big
    assert "cluster_chain" in big
    assert len(big["cluster_chain"]) == meta["file_b"]["chain_len"]

    jpegs = [c for c in carve_res if c.get("file_type") == "JPEG"]
    assert len(jpegs) >= 1


def test_entry_timestamps_raw_integers():
    from app.forensics.fat32 import detect_fat32_bpb, parse_fat32_directory_entries
    img, meta = build_synthetic_fat32_image()
    bpb = detect_fat32_bpb(img)
    entries = parse_fat32_directory_entries(img, bpb, bpb["root_cluster"])
    target = [e for e in entries if e["short_name"] == "_ILEB.BIN"][0]
    ts = target["timestamps"]
    for k in ("created_time", "created_date", "accessed_date", "modified_time", "modified_date"):
        assert k in ts
        assert isinstance(ts[k], int)
    assert ts["created_time"] == 0x4F48
    assert ts["created_date"] == 0x589A
