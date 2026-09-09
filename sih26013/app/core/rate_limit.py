"""
In-memory sliding-window rate limiter for SIH26013.

Same design as sih26149/app/api/rate_limit.py (kept independent rather than
shared across the two projects, since each package ships standalone). Keyed
by API key when present, else client IP.

INGEST_LIMIT applies to /cases/{id}/ingest and /cases/{id}/analyze — the
CPU/spatial-index-heavy endpoints — everything else uses the more generous
GENERAL_LIMIT.
"""
import os
import time
import threading
from collections import deque, defaultdict

GENERAL_LIMIT = int(os.environ.get("SIH26013_RATE_LIMIT_GENERAL", "120"))
GENERAL_WINDOW_SECONDS = int(os.environ.get("SIH26013_RATE_WINDOW_GENERAL", "60"))
INGEST_LIMIT = int(os.environ.get("SIH26013_RATE_LIMIT_INGEST", "30"))
INGEST_WINDOW_SECONDS = int(os.environ.get("SIH26013_RATE_WINDOW_INGEST", "60"))

EXEMPT_PREFIXES = ("/health",)
INGEST_SUFFIXES = ("/ingest", "/analyze")


class SlidingWindowLimiter:
    def __init__(self):
        self._lock = threading.Lock()
        self._hits: dict[str, deque] = defaultdict(deque)

    def check(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
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
_ingest_limiter = SlidingWindowLimiter()


def _client_key(request) -> str:
    # Bucket by (API key, IP) together, not API key alone. The deployment
    # model in docker-compose.yml is one shared API key for all legitimate
    # clients — keying by API key alone means every authenticated client
    # competes for the same bucket, so one busy legitimate client can
    # exhaust the quota for everyone else using the same key. Combining
    # with IP keeps the "throttle abusive traffic" intent while no longer
    # collapsing distinct clients into one bucket just because they share
    # a key.
    api_key = request.headers.get("X-API-Key")
    client = request.client
    ip = client.host if client else "unknown"
    if api_key:
        return f"key:{api_key}:ip:{ip}"
    return f"ip:{ip}"


def check_rate_limit(request) -> tuple[bool, int]:
    path = request.url.path
    if any(path.startswith(p) for p in EXEMPT_PREFIXES):
        return True, 0
    key = _client_key(request)
    if any(path.endswith(s) for s in INGEST_SUFFIXES):
        return _ingest_limiter.check(f"ingest:{key}", INGEST_LIMIT, INGEST_WINDOW_SECONDS)
    return _general_limiter.check(key, GENERAL_LIMIT, GENERAL_WINDOW_SECONDS)
