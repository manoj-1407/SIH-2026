"""
Create a clean, reproducible zip archive of the sih26149 repository,
excluding temporary caches, .git, and downloaded large binaries.
"""
import zipfile
import hashlib
from pathlib import Path

ROOT_DIR = Path("d:/SIH-2026/sih26149")
OUT_ZIP = Path("d:/SIH-2026/sih26149_current_verified.zip")

EXCLUDE_PATTERNS = [
    "__pycache__",
    ".pytest_cache",
    ".git",
    "data",
    "data/cases",
    "data/evidence",
    "data/audit",
    "data/artifacts",
    "data/uploads",
    "data/keys",
    "data/real_samples",
    "*.pyc",
    "*.pyo",
    "*.raw",
    "*.img",
    "*.priv",
    "*.pem",
    "*.key",
    "*.jsonl",
    "*.env",
    "*.zip",
]


def should_exclude(rel_path: str) -> bool:
    normalized = rel_path.replace('\\', '/').lower()
    for pat in EXCLUDE_PATTERNS:
        low_pat = pat.lower()
        if low_pat.endswith("/*"):
            prefix = low_pat[:-2]
            if normalized.startswith(prefix) and normalized != prefix:
                return True
        elif low_pat.startswith("*."):
            ext = low_pat[1:]
            if normalized.endswith(ext):
                return True
        elif normalized == low_pat or normalized.startswith(low_pat + "/"):
            return True
        elif low_pat in normalized.split("/"):
            return True
        elif normalized.startswith(low_pat):
            return True
    return False

print(f"[-] Packaging clean verified archive from {ROOT_DIR} into {OUT_ZIP}...")
file_count = 0
total_uncompressed_bytes = 0

with zipfile.ZipFile(OUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
    for file_path in ROOT_DIR.rglob("*"):
        if file_path.is_file():
            rel = file_path.relative_to(ROOT_DIR).as_posix()
            if should_exclude(rel):
                continue
            zf.write(file_path, arcname=f"sih26149/{rel}")
            file_count += 1
            total_uncompressed_bytes += file_path.stat().st_size

# Calculate SHA-256 of the generated zip
h = hashlib.sha256(OUT_ZIP.read_bytes()).hexdigest()
zip_size = OUT_ZIP.stat().st_size

print(f"[+] Clean archive created: {OUT_ZIP}")
print(f"    - Included files: {file_count}")
print(f"    - Uncompressed: {total_uncompressed_bytes:,} bytes")
print(f"    - Zip Size: {zip_size:,} bytes")
print(f"    - SHA-256: {h}")

# Verify key new modules are definitely in the zip
with zipfile.ZipFile(OUT_ZIP, "r") as zf:
    namelist = zf.namelist()
    critical_checks = [
        "sih26149/app/forensics/anti_forensics.py",
        "sih26149/app/sanitization/destroy_manifest.py",
        "sih26149/app/static/verifier.html",
        "sih26149/app/forensics/known_hashes.py",
        "sih26149/scripts/brutal_live_test.py",
        "sih26149/scripts/fetch_real_internet_samples.py",
        "sih26149/tests/unit/test_destroy_manifest.py",
        "sih26149/tests/unit/test_anti_forensics.py"
    ]
    print("[-] Checking critical new modules in archive:")
    for c in critical_checks:
        status = "FOUND" if c in namelist else "MISSING"
        print(f"    [{status}] {c}")
