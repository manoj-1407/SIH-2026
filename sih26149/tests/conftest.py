"""
SIH26149 — Root test configuration.

Sets environment variables required for the test suite to operate correctly
before any module-level imports (i.e., before the FastAPI app is instantiated).

- SIH26149_DISABLE_RATE_LIMIT=1: Bypass the in-memory sliding-window rate
  limiter so rapid-fire test requests don't trigger 429 responses. This does
  not affect production behavior — the env var must be explicitly set.
- DEMO_MODE=1: Enable demo-tamper endpoints that require X-Demo-Mode header
  or DEMO_MODE env var, so adversarial tests can exercise them freely.
"""
import os
import pytest

# Must be set BEFORE app.main is imported — the rate_limit module reads this
# at module import time.
os.environ.setdefault("SIH26149_DISABLE_RATE_LIMIT", "1")
os.environ.setdefault("DEMO_MODE", "1")
