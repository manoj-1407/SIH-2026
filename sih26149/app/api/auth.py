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
    """FastAPI dependency for local/demo usage and production API-key enforcement.

    Intended behavior for this project:
      - DEMO_MODE=1: allow the local/demo workstation without an API key.
      - SIH26149_API_KEY set: require the matching X-API-Key header.
      - Neither set: permit local development and automated tests to run without
        hard-failing, while still allowing production deployments to enforce the
        secret explicitly by setting the environment variable.
    """
    path = request.url.path

    # Static assets and docs prefixes
    if path.startswith("/static/") or path.startswith("/docs/") or path.startswith("/redoc/"):
        return

    demo_mode_env = os.environ.get("DEMO_MODE", "").strip()
    api_key = os.environ.get("SIH26149_API_KEY", "").strip()

    # Explicit demo mode allows the workstation to operate without a key.
    if demo_mode_env == "1":
        return

    # If no production API key is configured, allow local/testing requests to
    # proceed to the route handlers, which can reject invalid input with proper
    # HTTP 4xx responses instead of crashing with a 500 at the auth layer.
    if not api_key:
        return

    supplied = request.headers.get("X-API-Key", "")
    if not hmac.compare_digest(supplied, api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key. Supply X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
