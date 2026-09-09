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

# Exact public routes
EXACT_PUBLIC_PATHS = {
    "/",
    "/health",
    "/api/health",
    "/docs",
    "/openapi.json",
    "/redoc",
    # Official showcase demo routes (read-only, synthetic media only)
    "/cases/CASE-DEMO-2026/proof-loop",
    "/api/cases/CASE-DEMO-2026/proof-loop",
    "/cases/CASE-DEMO-2026/benchmark",
    "/api/cases/CASE-DEMO-2026/benchmark",
    "/cases/CASE-DEMO-2026/decision-profile",
    "/api/cases/CASE-DEMO-2026/decision-profile",
    "/cases/seed-demo",
    "/api/cases/seed-demo",
    "/cases/CASE-DEMO-2026",
    "/api/cases/CASE-DEMO-2026",
}


async def require_api_key(request: Request) -> None:
    """FastAPI dependency. Raises 401/500 if API key auth fails.

    Skipped entirely when:
      - Request path is an exact public endpoint or /static/ asset
      - DEMO_MODE != "0" and no SIH26149_API_KEY is set (dev/demo/test mode)
    Fails closed when:
      - DEMO_MODE=0 and SIH26149_API_KEY is unset (raises 500 configuration error)
      - SIH26149_API_KEY is set and X-API-Key is invalid/missing (raises 401)
    """
    path = request.url.path

    # Static assets and docs prefixes
    if path.startswith("/static/") or path.startswith("/docs/") or path.startswith("/redoc/"):
        return

    # Exact public paths
    if path in EXACT_PUBLIC_PATHS:
        return

    demo_mode_env = os.environ.get("DEMO_MODE", "").strip()
    api_key = os.environ.get("SIH26149_API_KEY", "").strip()

    # Explicit production mode (DEMO_MODE=0)
    if demo_mode_env == "0":
        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Production authentication error: SIH26149_API_KEY is not configured and DEMO_MODE is 0.",
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
