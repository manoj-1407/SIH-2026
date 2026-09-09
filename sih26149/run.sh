#!/usr/bin/env bash
# SIH26149 Startup Script
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

echo "=== Starting SIH26149 Forensic Workstation ==="
echo "Host: http://127.0.0.1:8000"
echo "API Docs: http://127.0.0.1:8000/docs"
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
