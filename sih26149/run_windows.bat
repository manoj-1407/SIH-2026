@echo off
REM SIH26149 — Forensic Evidence Workstation — Windows Quick Start
REM Run this to start the backend server on http://localhost:8000

cd /d "%~dp0"
echo.
echo =========================================
echo  SIH26149 Forensic Workstation
echo  URL: http://localhost:8000
echo  API Docs: http://localhost:8000/docs
echo  Press Ctrl+C to stop
echo =========================================
echo.

REM Local/demo default: open access without API key
if not defined DEMO_MODE set DEMO_MODE=1
echo [CONFIG] DEMO_MODE=%DEMO_MODE%

REM Check if requirements are installed
python -c "import fastapi" 2>nul || (
    echo [SETUP] Installing Python dependencies...
    pip install -r requirements.txt
)

echo [START] Starting backend server...
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
