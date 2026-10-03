import struct


def detect_fat32_bpb(image: bytes) -> dict | None:
    if len(image) < 512:
        return None
    try:
        bytes_per_sector = struct.unpack_from("<H", image, 0x0B)[0]
        sectors_per_cluster = struct.unpack_from("<B", image, 0x0D)[0]
        reserved_sectors = struct.unpack_from("<H", image, 0x0E)[0]
        num_fats = struct.unpack_from("<B", image, 0x10)[0]
        total_sectors_16 = struct.unpack_from("<H", image, 0x13)[0]
        fat_size_16 = struct.unpack_from("<H", image, 0x16)[0]
        total_sectors_32 = struct.unpack_from("<I", image, 0x20)[0]
        fat_size_32 = struct.unpack_from("<I", image, 0x24)[0]
        root_cluster = struct.unpack_from("<I", image, 0x2C)[0]
        ext_boot_sig_fat16 = struct.unpack_from("<B", image, 0x26)[0]
        ext_boot_sig_fat32 = struct.unpack_from("<B", image, 0x42)[0] if len(image) >= 0x43 else 0
        ext_boot_sig_drive = struct.unpack_from("<B", image, 0x40)[0] if len(image) >= 0x41 else 0

        ext_boot_sig = 0
        if ext_boot_sig_fat32 in (0x29, 0x28):
            ext_boot_sig = ext_boot_sig_fat32
        elif ext_boot_sig_fat16 in (0x29, 0x28):
            ext_boot_sig = ext_boot_sig_fat16
        elif ext_boot_sig_drive in (0x29, 0x28):
            ext_boot_sig = ext_boot_sig_drive

        if bytes_per_sector == 0 or sectors_per_cluster == 0 or num_fats == 0:
            return None
        if total_sectors_16 != 0 and total_sectors_32 != 0:
            return None
        if fat_size_16 != 0 or fat_size_32 == 0:
            return None
        total = total_sectors_32 if total_sectors_16 == 0 else total_sectors_16
        if total < 65525:
            return None
        if root_cluster < 2:
            return None
        if not (bytes_per_sector in (512, 1024, 2048, 4096)):
            return None
        if reserved_sectors == 0:
            return None
    except Exception:
        return None

    first_data_sector = reserved_sectors + num_fats * fat_size_32
    cluster_size = bytes_per_sector * sectors_per_cluster
    fat_offset = reserved_sectors * bytes_per_sector

    return {
        "bytes_per_sector": bytes_per_sector,
        "sectors_per_cluster": sectors_per_cluster,
        "reserved_sectors": reserved_sectors,
        "num_fats": num_fats,
        "total_sectors_32": total_sectors_32,
        "fat_size_32": fat_size_32,
        "root_cluster": root_cluster,
        "ext_boot_sig": ext_boot_sig,
        "first_data_sector": first_data_sector,
        "cluster_size": cluster_size,
        "fat_offset": fat_offset,
    }


def _fat_entry_is_eoc(v: int) -> bool:
    masked = v & 0x0FFFFFFF
    if masked == 0x0FFFFFF7:
        return False
    return 0x0FFFFFF8 <= masked <= 0x0FFFFFFF


def read_fat_cluster_chain(image: bytes, bpb: dict, start_cluster: int) -> list[int]:
    chain: list[int] = []
    fat_offset = bpb["fat_offset"]
    current = start_cluster
    safety_max = 1_000_000
    while len(chain) < safety_max:
        if current < 2:
            break
        chain.append(current)
        entry_off = fat_offset + (current * 4)
        if entry_off + 4 > len(image):
            break
        entry_val = struct.unpack_from("<I", image, entry_off)[0]
        masked = entry_val & 0x0FFFFFFF
        if masked == 0x0FFFFFF7:
            break
        if 0x0FFFFFF8 <= masked <= 0x0FFFFFFF:
            break
        if masked < 2:
            break
        current = masked
    return chain


def _decode_8dot3(name_bytes: bytes) -> str:
    name_part = name_bytes[:8].rstrip(b" ").decode("ascii", errors="replace")
    ext_part = name_bytes[8:11].rstrip(b" ").decode("ascii", errors="replace")
    if ext_part:
        return f"{name_part}.{ext_part}"
    return name_part


def parse_fat32_directory_entries(
    image: bytes,
    bpb: dict,
    cluster: int,
    max_depth: int = 6,
    _depth: int = 0,
    _parent_cluster: int | None = None,
) -> list[dict]:
    results: list[dict] = []
    parent = _parent_cluster if _parent_cluster is not None else cluster

    chain = read_fat_cluster_chain(image, bpb, cluster)
    cluster_size = bpb["cluster_size"]
    dir_bytes = b""
    for c in chain:
        off = (
            bpb["first_data_sector"] * bpb["bytes_per_sector"]
            + (c - 2) * cluster_size
        )
        dir_bytes += image[off : off + cluster_size]

    lfn_parts: list[str] = []
    pos = 0
    end = len(dir_bytes)

    while pos + 32 <= end:
        entry = dir_bytes[pos : pos + 32]
        first_byte = entry[0]
        if first_byte == 0x00:
            break
        attr = entry[0x0B]

        if attr == 0x0F:
            seq = first_byte & 0x1F
            is_last = bool(first_byte & 0x40)
            raw_chars = (
                entry[0x01:0x0B]
                + entry[0x0E:0x1A]
                + entry[0x1C:0x20]
            )
            try:
                text = raw_chars.decode("utf-16-le", errors="replace")
            except Exception:
                text = ""
            clean = []
            for ch in text:
                if ch == "\x00":
                    break
                clean.append(ch)
            lfn_parts.append("".join(clean))
            pos += 32
            continue

        is_deleted = first_byte == 0xE5
        fc_high = struct.unpack_from("<H", entry, 0x14)[0]
        fc_low = struct.unpack_from("<H", entry, 0x1A)[0]
        first_cluster = (fc_high << 16) | fc_low
        file_size = struct.unpack_from("<I", entry, 0x1C)[0]

        short_name_raw = bytearray(entry[0x00:0x0B])
        if is_deleted:
            short_name_raw[0] = ord("_")
        short_name = _decode_8dot3(bytes(short_name_raw))

        lfn_name = None
        if lfn_parts:
            lfn_parts_rev = list(reversed(lfn_parts))
            combined = "".join(lfn_parts_rev)
            stripped = combined.strip(" ").rstrip("\x00").strip("\x00").strip()
            if stripped:
                lfn_name = stripped
        lfn_parts = []

        display_name = lfn_name if lfn_name else short_name

        if display_name in (".", ".."):
            pos += 32
            continue

        is_directory = bool(attr & 0x10)

        created_time = struct.unpack_from("<H", entry, 0x0E)[0]
        created_date = struct.unpack_from("<H", entry, 0x10)[0]
        accessed_date = struct.unpack_from("<H", entry, 0x12)[0]
        modified_time = struct.unpack_from("<H", entry, 0x16)[0]
        modified_date = struct.unpack_from("<H", entry, 0x18)[0]

        cluster_chain: list[int] = []
        if first_cluster >= 2 and not is_directory and file_size > 0:
            cluster_chain = read_fat_cluster_chain(image, bpb, first_cluster)
        elif is_directory and first_cluster >= 2:
            cluster_chain = read_fat_cluster_chain(image, bpb, first_cluster)

        entry_dict = {
            "name": display_name,
            "lfn_name": lfn_name,
            "short_name": short_name,
            "size": int(file_size),
            "first_cluster": int(first_cluster),
            "is_deleted": bool(is_deleted),
            "is_directory": bool(is_directory),
            "parent_cluster": int(parent),
            "cluster_chain": cluster_chain,
            "attr": int(attr),
            "timestamps": {
                "created_time": int(created_time),
                "created_date": int(created_date),
                "accessed_date": int(accessed_date),
                "modified_time": int(modified_time),
                "modified_date": int(modified_date),
            },
        }
        results.append(entry_dict)

        if is_directory and first_cluster >= 2 and _depth < max_depth:
            if display_name not in (".", ".."):
                sub_results = parse_fat32_directory_entries(
                    image,
                    bpb,
                    first_cluster,
                    max_depth=max_depth,
                    _depth=_depth + 1,
                    _parent_cluster=first_cluster,
                )
                results.extend(sub_results)

        pos += 32

    return results


def recover_bytes_from_cluster_chain(
    image: bytes,
    bpb: dict,
    cluster_chain: list[int],
    size: int,
) -> bytes:
    cluster_size = bpb["cluster_size"]
    first_data_off = bpb["first_data_sector"] * bpb["bytes_per_sector"]
    parts: list[bytes] = []
    collected = 0
    for c in cluster_chain:
        if c < 2:
            continue
        off = first_data_off + (c - 2) * cluster_size
        chunk = image[off : off + cluster_size]
        parts.append(chunk)
        collected += len(chunk)
        if collected >= size:
            break
    combined = b"".join(parts)
    return combined[:size]
