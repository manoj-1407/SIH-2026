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

# Exact public routes — health/docs + read-only showcase GETs.
# Mutating endpoints (seed, reconcile, tamper) are NEVER public; use DEMO_MODE=1 locally.
EXACT_PUBLIC_PATHS = {
    "/",
    "/health",
    "/api/health",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/cases/DEMO-ALIGN/benchmark",
    "/api/cases/DEMO-ALIGN/benchmark",
    "/benchmark",
    "/api/benchmark",
    "/cases/DEMO-ALIGN",
    "/api/cases/DEMO-ALIGN",
    "/cases/DEMO-ENCROACH",
    "/api/cases/DEMO-ENCROACH",
    "/cases/DEMO-TOPOLOGY",
    "/api/cases/DEMO-TOPOLOGY",
    "/cases/DEMO-CONFLICT",
    "/api/cases/DEMO-CONFLICT",
}


async def require_api_key(request: Request) -> None:
    """FastAPI dependency. Raises 401/500 if API key auth fails.

    Skipped entirely when:
      - Request path is an exact public endpoint or /static/ asset
      - DEMO_MODE != "0" and no SIH26013_API_KEY is set (dev/demo/test mode)
    Fails closed when:
      - DEMO_MODE=0 and SIH26013_API_KEY is unset (raises 500 configuration error)
      - SIH26013_API_KEY is set and X-API-Key is invalid/missing (raises 401)
    """
    path = request.url.path

    # Static assets and docs prefixes
    if path.startswith("/static/") or path.startswith("/docs/") or path.startswith("/redoc/"):
        return

    # Exact public paths
    if path in EXACT_PUBLIC_PATHS:
        return

    demo_mode_env = os.environ.get("DEMO_MODE", "").strip()
    api_key = os.environ.get("SIH26013_API_KEY", "").strip()

    # Explicit production mode (DEMO_MODE=0)
    if demo_mode_env == "0":
        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Production authentication error: SIH26013_API_KEY is not configured and DEMO_MODE is 0.",
            )
        supplied = request.headers.get("X-API-Key", "")
        if not hmac.compare_digest(supplied, api_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key. Supply X-API-Key header.",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        return

    # If API key is explicitly configured in environment, enforce it
    if api_key:
        supplied = request.headers.get("X-API-Key", "")
        if not hmac.compare_digest(supplied, api_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key. Supply X-API-Key header.",
                headers={"WWW-Authenticate": "ApiKey"},
            )
