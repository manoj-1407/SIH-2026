"""
SIH26149 — FastAPI application entrypoint. (UPGRADED v2)

Startup sequence:
  1. Initialize persistent signing key (generate on first run, load on restart)
  2. Mount API routers with optional API-key middleware
  3. Dual-mount all routes with AND without /api prefix for frontend compatibility
  4. Serve static UI at root

Environment variables:
  SIH26149_DATA_DIR   Override data directory
  SIH26149_API_KEY    When set, all API requests must supply X-API-Key header
  DEMO_MODE           Set to "1" to bypass API key checks
  SIH26149_CORS_ORIGINS  Comma-separated allowlist of origins (default: "*")
"""
import os
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse

from app.api.health import router as health_router
from app.api.cases import router as cases_router
from app.api.forensics import router as forensics_router
from app.api.sanitization import router as sanitization_router
from app.api.evidence import router as evidence_router
from app.api.carving import router as carving_router
from app.api.eraser import router as eraser_router
from app.api.audit_chain import router as audit_chain_router
from app.api.certificates import router as cert_router
from app.api.auth import require_api_key
from app.api.deps import get_or_create_primary_key
from app.api.rate_limit import check_rate_limit


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize persistent signing identity on first boot."""
    get_or_create_primary_key()
    yield


app = FastAPI(
    title="SIH26149 — Integrated Forensic & Sanitization Workstation v2",
    lifespan=lifespan,
    description=(
        "Integrated Secure Data Erasure and Advanced File Recovery Tool "
        "for Digital Forensics and Data Sanitization. NTRO Problem Statement SIH26149. "
        "Features: Raw file carving (JPEG/PNG/PDF/ZIP/MP4), NIST 800-88 Rev.2 device-aware "
        "sanitization, selective file eraser, hash-chained audit trail, evidence certificates."
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("SIH26149_CORS_ORIGINS", "*").split(","),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*", "X-API-Key"],
)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Sliding-window rate limiter before auth/routing."""
    from fastapi.responses import JSONResponse
    allowed, retry_after = check_rate_limit(request)
    if not allowed:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Please slow down."},
            headers={"Retry-After": str(retry_after)},
        )
    return await call_next(request)


_auth = [Depends(require_api_key)]

# ── Always-public health ────────────────────────────────────────────────────────
app.include_router(health_router)

# ── Core routers (no /api prefix — original routes) ───────────────────────────
app.include_router(cases_router, dependencies=_auth)
app.include_router(forensics_router, dependencies=_auth)
app.include_router(sanitization_router, dependencies=_auth)
app.include_router(evidence_router, dependencies=_auth)

# ── New v2 feature routers ─────────────────────────────────────────────────────
app.include_router(carving_router, dependencies=_auth)
app.include_router(eraser_router, dependencies=_auth)
app.include_router(audit_chain_router, dependencies=_auth)
app.include_router(cert_router, dependencies=_auth)

# ── Dual-mount: /api prefix variants (for frontend compatibility) ──────────────
# The static UI's app.js sends requests to /api/... paths.
# We create a sub-application mounted at /api that includes all the same routers.
from fastapi import FastAPI as _FastAPI

_api_sub = _FastAPI()
# Same auth dependency as top-level mounts — /api/* must not bypass API-key checks.
_api_sub.include_router(health_router)
_api_sub.include_router(cases_router, dependencies=_auth)
_api_sub.include_router(forensics_router, dependencies=_auth)
_api_sub.include_router(sanitization_router, dependencies=_auth)
_api_sub.include_router(evidence_router, dependencies=_auth)
_api_sub.include_router(carving_router, dependencies=_auth)
_api_sub.include_router(eraser_router, dependencies=_auth)
_api_sub.include_router(audit_chain_router, dependencies=_auth)
_api_sub.include_router(cert_router, dependencies=_auth)

app.mount("/api", _api_sub)

# ── Static UI ──────────────────────────────────────────────────────────────────
STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
