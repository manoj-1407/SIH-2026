"""
In-memory sliding-window rate limiter for SIH26149.

No external dependency (no slowapi/redis) — appropriate for a single-process
forensic workstation that already keeps all other state in-process. Keyed by
API key when present (X-API-Key), else by client IP, so one noisy client
can't exhaust another's quota.

Two tiers, since not all endpoints carry equal cost:
  - GENERAL_LIMIT applies to everything by default (cheap reads: list cases,
    health, get evidence).
  - UPLOAD_LIMIT is stricter and applies to the forensic-image upload route,
    the one endpoint that accepts large request bodies and does real disk
    I/O — the natural target for a DoS attempt.

Both are configurable via env vars so an operator can tune them without a
code change; defaults are deliberately generous for a demo/single-operator
tool while still proving the limiter works under a real burst.
"""
import os
import time
import threading
from collections import deque, defaultdict

GENERAL_LIMIT = int(os.environ.get("SIH26149_RATE_LIMIT_GENERAL", "120"))
GENERAL_WINDOW_SECONDS = int(os.environ.get("SIH26149_RATE_WINDOW_GENERAL", "60"))
UPLOAD_LIMIT = int(os.environ.get("SIH26149_RATE_LIMIT_UPLOAD", "10"))
UPLOAD_WINDOW_SECONDS = int(os.environ.get("SIH26149_RATE_WINDOW_UPLOAD", "60"))

# Paths that should never be rate limited, regardless of tier below —
# Docker's healthcheck polls /health frequently and must never be throttled.
EXEMPT_PREFIXES = ("/health",)
# Paths that use the stricter upload tier instead of the general tier.
# The upload route is mounted as /cases/{case_id}/upload — case_id is a
# path parameter, so it can't be matched as a fixed prefix. Match by
# prefix+suffix instead. (A previous version checked for the fixed string
# "/api/forensics/upload", which no real route ever produces — that made
# the upload tier completely dead; every upload silently fell through to
# the 120/min general limit instead of the intended 10/min. Confirmed via
# the actual router registration: prefix='/cases/{case_id}', route
# @router.post('/upload').)
UPLOAD_PATH_PREFIX = "/cases/"
UPLOAD_PATH_SUFFIX = "/upload"


class SlidingWindowLimiter:
    def __init__(self):
        self._lock = threading.Lock()
        self._hits: dict[str, deque] = defaultdict(deque)

    def check(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
        """Returns (allowed, retry_after_seconds)."""
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            cutoff = now - window_seconds
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= limit:
                retry_after = max(1, int(window_seconds - (now - q[0])))
                return False, retry_after
            q.append(now)
            return True, 0


_general_limiter = SlidingWindowLimiter()
_upload_limiter = SlidingWindowLimiter()


def _client_key(request) -> str:
    # Bucket by (API key, IP) together — see sih26013/app/core/rate_limit.py
    # for why keying by API key alone breaks under the shared-key deployment
    # model in docker-compose.yml.
    api_key = request.headers.get("X-API-Key")
    client = request.client
    ip = client.host if client else "unknown"
    if api_key:
        return f"key:{api_key}:ip:{ip}"
    return f"ip:{ip}"


def check_rate_limit(request) -> tuple[bool, int]:
    """Returns (allowed, retry_after_seconds). Call from middleware."""
    path = request.url.path
    if any(path.startswith(p) for p in EXEMPT_PREFIXES):
        return True, 0
    key = _client_key(request)
    if path.startswith("/cases/") and path.endswith(UPLOAD_PATH_SUFFIX):
        return _upload_limiter.check(f"upload:{key}", UPLOAD_LIMIT, UPLOAD_WINDOW_SECONDS)
    if path.startswith("/api/cases/") and path.endswith(UPLOAD_PATH_SUFFIX):
        return _upload_limiter.check(f"upload:{key}", UPLOAD_LIMIT, UPLOAD_WINDOW_SECONDS)
    return _general_limiter.check(key, GENERAL_LIMIT, GENERAL_WINDOW_SECONDS)
