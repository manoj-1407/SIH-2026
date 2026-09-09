"""
API key authentication middleware for SIH26013.

Usage identical to SIH26149 auth module:
  - DEMO_MODE=1 → bypass (local/hackathon use)
  - SIH26013_API_KEY set → all requests must supply X-API-Key header
  - Neither set → open (operator's choice for deployment)
"""
import hmac
import os
from fastapi import Request, HTTPException, status

_API_KEY = os.environ.get("SIH26013_API_KEY", "")
_DEMO_MODE = os.environ.get("DEMO_MODE", "0").strip() == "1"


async def require_api_key(request: Request) -> None:
    public_prefixes = (
        "/health", "/api/health", "/docs", "/openapi.json", "/redoc", "/static",
        "/benchmark", "/api/benchmark", "/reconcile", "/api/reconcile",
        "/cases/DEMO-", "/api/cases/DEMO-"
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
