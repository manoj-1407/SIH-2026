"""
API key authentication middleware for SIH26149.

In demo/hackathon mode: set DEMO_MODE=1 to bypass API key checks (tamper
endpoint also requires this).

In deployed mode: set SIH26149_API_KEY env var. All requests must supply
    X-API-Key: <value>
in the request header. Missing or incorrect key returns 401.

Design note: deliberately simple — no JWT, no sessions. The threat model for
this tool is unauthorized access to a running instance, not credential theft.
A shared API key is appropriate for a single-operator forensic workstation.
"""
import hmac
import os
from fastapi import Request, HTTPException, status

_API_KEY = os.environ.get("SIH26149_API_KEY", "")
_DEMO_MODE = os.environ.get("DEMO_MODE", "0").strip() == "1"


async def require_api_key(request: Request) -> None:
    """FastAPI dependency. Raises 401 if API key auth fails.

    Skipped entirely when:
      - DEMO_MODE=1 (hackathon demo / local dev without key)
      - SIH26149_API_KEY is not set (treats deployment as open — operator's choice)
      - Request path is /health or /docs* or /openapi.json (always public)
    """
    public_prefixes = (
        "/health", "/api/health", "/docs", "/openapi.json", "/redoc", "/static",
        "/cases/CASE-DEMO-2026", "/api/cases/CASE-DEMO-2026",
        "/cases/seed-demo", "/api/cases/seed-demo",
        "/benchmark", "/api/benchmark"
    )
    if any(request.url.path.startswith(p) for p in public_prefixes):
        return
    if _DEMO_MODE or not _API_KEY:
        return
    supplied = request.headers.get("X-API-Key", "")
    # Constant-time comparison: a plain `!=` here leaks timing information
    # an attacker could use to recover the API key byte-by-byte.
    if not hmac.compare_digest(supplied, _API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key. Supply X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
