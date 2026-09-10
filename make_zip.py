"""
Creates clean SIH 2026 submission ZIP using Python zipfile.
Excludes: .git, __pycache__, .pytest_cache, keys, runtime data, existing zips, scratch tools.
"""
import os
import zipfile
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent
DEST = SRC / "SIH_2026_FINAL_SUBMISSION_PACKAGE.zip"

EXCLUDE_DIRS = {
    ".git", "__pycache__", ".pytest_cache", ".mypy_cache",
    "node_modules", ".venv", "venv", ".agents", "data",
}
EXCLUDE_EXTS = {
    ".priv", ".key", ".pem", ".raw", ".img", ".jsonl",
    ".env", ".pyc", ".pyo", ".DS_Store", ".zip",
}
EXCLUDE_NAMES = {
    "SIH_2026_FINAL_SUBMISSION_PACKAGE.zip",
    "SIH_2026_SUBMISSION_v2.zip",
    "benchmark_results.json",
    "make_zip.ps1",
    "make_zip.py",
    "scratch_test_everything.py",
    "scratch_contract_verify.py",
    "scratch_live_smoke.py",
    "audit_zip.py",
}


def should_skip(fpath: Path, fname: str) -> bool:
    if fpath.suffix.lower() in EXCLUDE_EXTS:
        return True
    if fname in EXCLUDE_NAMES:
        return True
    if fname == ".env" or fname.endswith(".env"):
        return True
    # Runtime evidence / keys under data dirs (belt-and-suspenders)
    parts = {p.lower() for p in fpath.parts}
    if "uploads" in parts and fpath.suffix.lower() not in {".gitkeep", ".md"}:
        if fname != ".gitkeep":
            return True
    return False


if DEST.exists():
    DEST.unlink()
    print(f"Removed old: {DEST.name}")

count = 0
skipped = 0
names_seen = set()

with zipfile.ZipFile(DEST, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    for root, dirs, files in os.walk(SRC):
        root_path = Path(root)
        rel_root = root_path.relative_to(SRC)

        dirs[:] = [
            d for d in dirs
            if d not in EXCLUDE_DIRS and not d.startswith(".")
        ]

        for fname in files:
            fpath = root_path / fname
            rel = (rel_root / fname).as_posix()
            if rel_root == Path("."):
                rel = fname

            if should_skip(fpath, fname):
                skipped += 1
                continue

            # Skip any leftover zip archives inside tree
            if fname.lower().endswith(".zip"):
                skipped += 1
                continue

            if rel in names_seen:
                print(f"  [DUP SKIP] {rel}", file=sys.stderr)
                skipped += 1
                continue
            names_seen.add(rel)

            try:
                zf.write(fpath, rel)
                count += 1
            except Exception as e:
                print(f"  [SKIP] {rel}: {e}", file=sys.stderr)
                skipped += 1

size_kb = round(DEST.stat().st_size / 1024, 1)
size_mb = round(DEST.stat().st_size / (1024 * 1024), 2)
print(f"\n{'=' * 50}")
print(f"ZIP: {DEST}")
print(f"Files included: {count} | Skipped: {skipped}")
print(f"Size: {size_kb} KB ({size_mb} MB)")
print(f"{'=' * 50}")

# Hygiene report
bad_exts = {".priv", ".key", ".pem", ".raw", ".img", ".jsonl", ".env"}
with zipfile.ZipFile(DEST, "r") as zf:
    infos = zf.infolist()
    print(f"Archive entries: {len(infos)}")
    py_count = sum(1 for i in infos if i.filename.endswith(".py"))
    print(f"Python files: {py_count}")
    for i in infos:
        suf = Path(i.filename).suffix.lower()
        if suf in bad_exts or i.filename.endswith(".env"):
            print(f"  !! BAD FILE IN ZIP: {i.filename}")
        if i.filename.endswith("/.git") or "/.git/" in i.filename:
            print(f"  !! GIT IN ZIP: {i.filename}")
