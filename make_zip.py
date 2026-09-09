"""
Creates clean SIH 2026 submission ZIP using Python zipfile.
Excludes: .git, __pycache__, .pytest_cache, keys, runtime data, existing zips.
"""
import os
import zipfile
import sys
from pathlib import Path

SRC   = Path(r'D:\SIH_FINAL_v5')
DEST  = SRC / 'SIH_2026_SUBMISSION_v2.zip'

EXCLUDE_DIRS  = {'.git', '__pycache__', '.pytest_cache', '.mypy_cache',
                 'node_modules', '.venv', 'venv', '.agents'}
EXCLUDE_EXTS  = {'.priv', '.key', '.pem', '.raw', '.img', '.jsonl',
                 '.env', '.pyc', '.pyo', '.DS_Store'}
EXCLUDE_NAMES = {'SIH_2026_FINAL_SUBMISSION_PACKAGE.zip',
                 'SIH_2026_SUBMISSION_v2.zip',
                 'benchmark_results.json',
                 'make_zip.ps1',
                 'make_zip.py',
                 'scratch_test_everything.py'}

if DEST.exists():
    DEST.unlink()
    print(f"Removed old: {DEST.name}")

count = 0
skipped = 0

with zipfile.ZipFile(DEST, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    for root, dirs, files in os.walk(SRC):
        root_path = Path(root)
        rel_root  = root_path.relative_to(SRC)

        # Prune excluded directories in-place
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith('.')]

        for fname in files:
            fpath = root_path / fname
            rel   = rel_root / fname

            # Exclude by extension
            if fpath.suffix.lower() in EXCLUDE_EXTS:
                skipped += 1
                continue
            # Exclude by name
            if fname in EXCLUDE_NAMES:
                skipped += 1
                continue
            # Exclude .env files (any filename ending in .env or named .env)
            if fname == '.env' or fname.endswith('.env'):
                skipped += 1
                continue

            try:
                zf.write(fpath, rel)
                count += 1
            except Exception as e:
                print(f"  [SKIP] {rel}: {e}", file=sys.stderr)
                skipped += 1

size_kb = round(DEST.stat().st_size / 1024, 1)
size_mb = round(DEST.stat().st_size / (1024*1024), 2)
print(f"\n{'='*50}")
print(f"ZIP: {DEST}")
print(f"Files included: {count} | Skipped: {skipped}")
print(f"Size: {size_kb} KB ({size_mb} MB)")
print(f"{'='*50}")
