import zipfile
from pathlib import Path
from collections import Counter

z = zipfile.ZipFile(r'D:\SIH_FINAL_v5\SIH_2026_SUBMISSION_v2.zip')
names = z.namelist()

print(f'Total entries: {len(names)}')

bad_ext  = ['.priv', '.key', '.pem', '.raw', '.img', '.jsonl', '.env', '.pyc']
bad_dirs = ['.git', '__pycache__', '.pytest_cache']

issues = []
for n in names:
    p = Path(n)
    parts = p.parts
    found_bad_dir = False
    for bd in bad_dirs:
        if bd in parts:
            issues.append('BAD DIR  : ' + n)
            found_bad_dir = True
            break
    if not found_bad_dir:
        if p.suffix.lower() in bad_ext:
            issues.append('BAD EXT  : ' + n)
        elif p.name == '.env':
            issues.append('BAD FILE : ' + n)

if issues:
    print('PROBLEMS:')
    for i in issues:
        print(' ', i)
else:
    print('CLEAN: No private keys, no .env, no caches, no raw data.')

exts = Counter(Path(n).suffix.lower() for n in names)
print()
print('Top file types:')
for ext, cnt in sorted(exts.items(), key=lambda x: -x[1])[:10]:
    label = ext if ext else '(no ext)'
    print(f'  {label:12s} {cnt}')
