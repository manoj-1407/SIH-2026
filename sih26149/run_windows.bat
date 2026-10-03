@echo off
REM SIH26149 — Forensic Evidence Workstation — Windows Quick Start
REM Run this to start the backend server on http://localhost:8000

setlocal enabledelayedexpansion
cd /d "%~dp0"

echo.
echo =========================================
echo  SIH26149 Forensic Workstation
echo  RC2 · CERTIFIED BUILD
echo =========================================
echo.

REM --- (1) Python version check >= 3.11 ---
set "PYEXE=python"
where python >nul 2>nul || (
    where py >nul 2>nul && set "PYEXE=py" || (
        echo [ERROR] Python not found in PATH. Install Python 3.11+ from https://www.python.org/downloads/windows/
        echo.
        exit /b 1
    )
)

for /f "tokens=*" %%v in ('%PYEXE% -c "import sys;v=sys.version_info;print(f'{v.major}.{v.minor}.{v.micro}')" 2^>nul') do set PYVER=%%v
for /f "tokens=1,2 delims=." %%a in ("%PYVER%") do (
    set MAJOR=%%a
    set MINOR=%%b
)

if %MAJOR% LSS 3 (
    echo [ERROR] Python %PYVER% detected — Python 3.11 or newer is required.
    echo         Download from: https://www.python.org/downloads/windows/
    exit /b 1
)
if %MAJOR% EQU 3 if %MINOR% LSS 11 (
    echo [ERROR] Python %PYVER% detected — Python 3.11 or newer is required.
    echo         Download from: https://www.python.org/downloads/windows/
    exit /b 1
)
echo [CHECK] Python %PYVER% — OK (>=3.11)

REM --- (2) Auto-create venv .venv if not present ---
set VENV_DIR=.venv
set VENV_PY=%VENV_DIR%\Scripts\python.exe
set FASTAPI_MARKER=%VENV_DIR%\Lib\site-packages\fastapi

if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo [SETUP] Creating virtual environment .venv ...
    %PYEXE% -m venv %VENV_DIR%
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        exit /b 1
    )
    echo [OK] Virtual environment created.
) else (
    echo [OK] Virtual environment .venv already exists.
)

REM --- (3) pip install -r requirements.txt ONLY on first creation of venv ---
REM (check if .venv/Lib/site-packages/fastapi exists already — if present skip install)
if not exist "%FASTAPI_MARKER%" (
    echo [SETUP] Installing Python dependencies (first-time setup)...
    "%VENV_PY%" -m pip install --upgrade pip >nul
    "%VENV_PY%" -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Dependency installation failed.
        exit /b 1
    )
    echo [OK] Dependencies installed.
) else (
    echo [OK] Dependencies already installed (fastapi detected). Skipping pip install.
)

REM Local/demo default: open access without API key
if not defined DEMO_MODE set DEMO_MODE=1
echo [CONFIG] DEMO_MODE=%DEMO_MODE%

echo.
echo =========================================
echo   STARTING SERVER
echo =========================================
echo.
echo   URL:              http://localhost:8000
echo   API Docs:         http://localhost:8000/docs
echo   System Caps API:  http://localhost:8000/api/system/capabilities
echo   Press Ctrl+C to stop
echo.
echo   SUGGESTED DEMO:   Visit http://localhost:8000 -^> Seeded National Demo button (~90 seconds end-to-end).
echo.
echo =========================================
echo.

REM --- (4) Start uvicorn ---
"%VENV_PY%" -m uvicorn app.main:app --host 0.0.0.0 --port 8000

endlocal
