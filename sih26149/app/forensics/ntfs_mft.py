"""
Native NTFS $MFT Parser and Deleted File Recovery Engine — SIH26149.

Provides standalone, dependency-free forensic recovery of deleted files from NTFS media:
- Parses 1024-byte MFT record structures (FILE magic signature)
- Applies update sequence array (fixup) validation
- Evaluates Record Allocation Flag: (flags & 0x0001 == 0) indicates DELETED file
- Extracts $STANDARD_INFORMATION (0x10) timestamps (Creation, Modification, MFT-modified, Access)
- Extracts $FILE_NAME (0x30) UTF-16LE filename and parent directory references
- Recovers $DATA (0x80) payloads:
    * Resident data (embedded directly in MFT record)
    * Non-resident data (decodes compressed cluster runlists)
- Computes cryptographic SHA-256 digest of recovered content
"""
import struct
import hashlib
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any

logger = logging.getLogger(__name__)

MFT_RECORD_SIZE = 1024
SECTOR_SIZE = 512

# MFT Record Flags
MFT_RECORD_IN_USE = 0x0001
MFT_RECORD_IS_DIRECTORY = 0x0002

# Attribute Types
ATTR_STANDARD_INFORMATION = 0x10
ATTR_ATTRIBUTE_LIST = 0x20
ATTR_FILE_NAME = 0x30
ATTR_OBJECT_ID = 0x40
ATTR_SECURITY_DESCRIPTOR = 0x50
ATTR_VOLUME_NAME = 0x60
ATTR_VOLUME_INFORMATION = 0x70
ATTR_DATA = 0x80
ATTR_INDEX_ROOT = 0x90
ATTR_INDEX_ALLOCATION = 0xA0
ATTR_BITMAP = 0xB0
ATTR_END_MARKER = 0xFFFFFFFF


@dataclass
class MFTRecoveredFile:
    record_number: int
    filename: str
    is_deleted: bool
    is_directory: bool
    size_bytes: int
    data_bytes: bytes
    sha256: str
    created_time_windows: int = 0
    modified_time_windows: int = 0
    parent_record: int = 0
    is_resident: bool = True
    cluster_runs: List[Tuple[int, int]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_number": self.record_number,
            "filename": self.filename,
            "is_deleted": self.is_deleted,
            "is_directory": self.is_directory,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "parent_record": self.parent_record,
            "is_resident": self.is_resident,
            "cluster_runs_count": len(self.cluster_runs),
        }


def apply_fixups(raw_record: bytes) -> Optional[bytes]:
    """
    Applies NTFS MFT Update Sequence (fixup) array to repair the 1024-byte record.
    Returns corrected bytes or None if fixup signature is corrupt.
    """
    if len(raw_record) < MFT_RECORD_SIZE:
        return None
    if raw_record[:4] != b"FILE":
        return None

    try:
        fixup_offset, fixup_count = struct.unpack_from("<HH", raw_record, 0x04)
        if fixup_offset + (fixup_count * 2) > len(raw_record):
            return None

        # Fixup signature expected at the end of each 512-byte sector
        expected_sig = raw_record[fixup_offset:fixup_offset + 2]
        fixed = bytearray(raw_record)

        for i in range(1, fixup_count):
            sector_end_offset = (i * SECTOR_SIZE) - 2
            current_sig = raw_record[sector_end_offset:sector_end_offset + 2]
            if current_sig != expected_sig:
                # Corrupt fixup signature
                return None
            # Replace with true original bytes from fixup array
            replacement = raw_record[fixup_offset + (i * 2):fixup_offset + (i * 2) + 2]
            fixed[sector_end_offset:sector_end_offset + 2] = replacement

        return bytes(fixed)
    except Exception as e:
        logger.debug(f"Fixup error: {e}")
        return None


def decode_runlist(runlist_bytes: bytes) -> List[Tuple[int, int]]:
    """
    Decodes an NTFS non-resident data runlist.
    Returns list of (cluster_length, cluster_offset_lcn).
    """
    runs = []
    idx = 0
    prev_lcn = 0

    while idx < len(runlist_bytes):
        header = runlist_bytes[idx]
        if header == 0:
            break
        idx += 1

        len_size = header & 0x0F
        offset_size = (header >> 4) & 0x0F

        if idx + len_size + offset_size > len(runlist_bytes):
            break

        # Read length (unsigned)
        run_len_bytes = runlist_bytes[idx:idx + len_size]
        run_len = int.from_bytes(run_len_bytes, byteorder="little", signed=False)
        idx += len_size

        # Read offset (signed relative LCN delta)
        run_off_bytes = runlist_bytes[idx:idx + offset_size]
        run_off_delta = int.from_bytes(run_off_bytes, byteorder="little", signed=True)
        idx += offset_size

        current_lcn = prev_lcn + run_off_delta
        prev_lcn = current_lcn
        runs.append((run_len, current_lcn))

    return runs


def parse_mft_record(raw_record: bytes, record_number: int = 0) -> Optional[MFTRecoveredFile]:
    """
    Parses a single 1024-byte MFT record.
    Extracts deleted and active files, recovering resident and non-resident metadata.
    """
    fixed = apply_fixups(raw_record)
    if not fixed:
        return None

    try:
        first_attr_offset, flags = struct.unpack_from("<HH", fixed, 0x14)
        is_in_use = bool(flags & MFT_RECORD_IN_USE)
        is_directory = bool(flags & MFT_RECORD_IS_DIRECTORY)

        filename = ""
        parent_rec = 0
        created_time = 0
        modified_time = 0
        recovered_data = b""
        data_size = 0
        is_resident = True
        cluster_runs = []

        curr_offset = first_attr_offset

        while curr_offset + 8 <= len(fixed):
            attr_type, attr_len = struct.unpack_from("<II", fixed, curr_offset)
            if attr_type == ATTR_END_MARKER or attr_len == 0:
                break
            if curr_offset + attr_len > len(fixed):
                break

            attr_record = fixed[curr_offset:curr_offset + attr_len]
            non_resident = bool(attr_record[8])

            if not non_resident and len(attr_record) >= 24:
                content_len = struct.unpack_from("<I", attr_record, 0x10)[0]
                content_off = struct.unpack_from("<H", attr_record, 0x14)[0]

                if attr_type == ATTR_STANDARD_INFORMATION and content_off + 32 <= len(attr_record):
                    # Extract timestamps
                    created_time = struct.unpack_from("<Q", attr_record, content_off)[0]
                    modified_time = struct.unpack_from("<Q", attr_record, content_off + 8)[0]

                elif attr_type == ATTR_FILE_NAME and content_off + content_len <= len(attr_record):
                    fn_data = attr_record[content_off:content_off + content_len]
                    if len(fn_data) >= 66:
                        parent_rec = struct.unpack_from("<Q", fn_data, 0)[0] & 0x0000FFFFFFFFFFFF
                        fn_len = fn_data[64]
                        fn_ns = fn_data[65]
                        # Read UTF-16LE filename string
                        raw_fn = fn_data[66:66 + (fn_len * 2)]
                        decoded_fn = raw_fn.decode("utf-16le", errors="replace")
                        # Prefer Win32 / POSIX namespace (0 or 1) over DOS namespace (2)
                        if not filename or fn_ns in (0, 1):
                            filename = decoded_fn

                elif attr_type == ATTR_DATA:
                    # Resident Data: stored directly inside MFT record!
                    is_resident = True
                    recovered_data = attr_record[content_off:content_off + content_len]
            elif attr_type == ATTR_DATA and non_resident:
                    # Non-Resident Data
                    is_resident = False
                    if len(attr_record) >= 64:
                        runlist_off = struct.unpack_from("<H", attr_record, 0x20)[0]
                        data_size = struct.unpack_from("<Q", attr_record, 0x30)[0]
                        runlist_bytes = attr_record[runlist_off:]
                        cluster_runs = decode_runlist(runlist_bytes)

            curr_offset += attr_len

        if not filename:
            filename = f"mft_record_{record_number}"

        sha256 = hashlib.sha256(recovered_data).hexdigest() if recovered_data else hashlib.sha256(b"").hexdigest()

        return MFTRecoveredFile(
            record_number=record_number,
            filename=filename,
            is_deleted=not is_in_use,
            is_directory=is_directory,
            size_bytes=data_size if not is_resident else len(recovered_data),
            data_bytes=recovered_data,
            sha256=sha256,
            created_time_windows=created_time,
            modified_time_windows=modified_time,
            parent_record=parent_rec,
            is_resident=is_resident,
            cluster_runs=cluster_runs,
        )
    except Exception as e:
        logger.debug(f"Error parsing MFT record {record_number}: {e}")
        return None


def scan_ntfs_image_for_deleted_files(image_path: str, max_records: int = 5000) -> List[MFTRecoveredFile]:
    """
    Scans a raw image or NTFS partition for deleted MFT records.
    Returns all successfully parsed deleted file artifacts.
    """
    deleted_files = []
    record_num = 0

    try:
        with open(image_path, "rb") as f:
            while len(deleted_files) < max_records:
                chunk = f.read(MFT_RECORD_SIZE)
                if len(chunk) < MFT_RECORD_SIZE:
                    break

                if chunk[:4] == b"FILE":
                    rec = parse_mft_record(chunk, record_number=record_num)
                    if rec and rec.is_deleted and not rec.is_directory:
                        # Exclude system internal records ($MFT, $LogFile, etc) if desired,
                        # but keep genuine deleted user artifacts
                        if not rec.filename.startswith("$") or rec.size_bytes > 0:
                            deleted_files.append(rec)

                record_num += 1
    except Exception as e:
        logger.error(f"Error scanning NTFS image {image_path}: {e}")

    return deleted_files
