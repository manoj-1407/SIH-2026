@echo off
REM SIH26013 — Geospatial Cadastral Workstation — Windows Quick Start
REM Run this to start the backend server on http://localhost:8001

cd /d "%~dp0"
echo.
echo =========================================
echo  SIH26013 Geospatial Workstation
echo  URL: http://localhost:8001
echo  API Docs: http://localhost:8001/docs
echo  Press Ctrl+C to stop
echo =========================================
echo.

REM Check if requirements are installed
python -c "import fastapi" 2>nul || (
    echo [SETUP] Installing Python dependencies...
    pip install -r requirements.txt
)

echo [START] Starting backend server...
python -m uvicorn app.api.server:app --host 127.0.0.1 --port 8001 --reload
