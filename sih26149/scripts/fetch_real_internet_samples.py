"""
Fetch authentic public test files from real internet sources (W3C, Wikimedia, NIST, RFC)
and assemble both standalone evidence artifacts and composite forensic raw images.
"""
import urllib.request
import ssl
from pathlib import Path

OUT_DIR = Path("d:/SIH-2026/sih26149/data/real_samples")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Ignore SSL verification for tests if corporate proxy or local cert issues arise
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

URLS = {
    # Real PDF from RFC editor
    "rfc8785.pdf": "https://www.rfc-editor.org/rfc/rfc8785.pdf",
    # Real JPEG from Wikimedia Commons (small sample)
    "wikimedia_sample.jpg": "https://upload.wikimedia.org/wikipedia/commons/4/47/PNG_transparency_demonstration_1.png", # will test mismatch or real jpg
    "real_sample.jpg": "https://raw.githubusercontent.com/ianare/exif-samples/master/jpg/fixed/iphone_7.jpg",
    # Real PNG from W3C
    "w3c_sample.png": "https://www.w3.org/Icons/valid-html401.png",
    # Real ZIP archive
    "sample_archive.zip": "https://raw.githubusercontent.com/madler/zlib/develop/examples/zlib_how.html"
}

print(f"[-] Fetching authentic samples from real internet into {OUT_DIR}...")
fetched = {}
for name, url in URLS.items():
    dest = OUT_DIR / name
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            data = resp.read()
            dest.write_bytes(data)
            fetched[name] = len(data)
            print(f" [+] Downloaded {name}: {len(data)} bytes from {url[:45]}...")
    except Exception as e:
        print(f" [!] Error fetching {name} ({url}): {e}")

# Also assemble a real forensic raw carrier disk image embedding these real files with slack space and padding
carrier_path = OUT_DIR / "real_internet_carrier.raw"
carrier_bytes = bytearray(b"\x00" * 4096) # Initial master boot / partition table padding

for name in ["real_sample.jpg", "w3c_sample.png", "rfc8785.pdf"]:
    f_path = OUT_DIR / name
    if f_path.exists():
        content = f_path.read_bytes()
        # align to 512 sector
        carrier_bytes.extend(content)
        slack = (512 - (len(content) % 512)) % 512
        carrier_bytes.extend(b"\x55\xaa" * (slack // 2) + (b"\x00" if slack % 2 else b""))
        # Add 8KB of unallocated space between files
        carrier_bytes.extend(b"\xe5" * 8192)

carrier_path.write_bytes(carrier_bytes)
print(f"[+] Assembled composite forensic disk carrier: {carrier_path} ({len(carrier_bytes)} bytes)")
