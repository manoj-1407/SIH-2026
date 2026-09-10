#!/usr/bin/env bash
# SIH26149 Startup Script
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

# Local/demo default: open access without API key (recommended for localhost)
export DEMO_MODE="${DEMO_MODE:-1}"

echo "=== Starting SIH26149 Forensic Workstation ==="
echo "Host: http://127.0.0.1:8000"
echo "API Docs: http://127.0.0.1:8000/docs"
echo "DEMO_MODE: ${DEMO_MODE}"
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
