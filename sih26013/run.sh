#!/usr/bin/env bash
# SIH26013 — Geospatial Harmonization Workstation
# Starts the workstation server for local/native development.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="${SCRIPT_DIR}"
export SIH26013_DATA_DIR="${SIH26013_DATA_DIR:-${SCRIPT_DIR}/data}"
export DEMO_MODE="${DEMO_MODE:-1}"

echo "[SIH26013] Data directory : ${SIH26013_DATA_DIR}"
echo "[SIH26013] Demo mode      : ${DEMO_MODE}"
echo "[SIH26013] Starting server at http://127.0.0.1:8001"
echo "[SIH26013] API docs        : http://127.0.0.1:8001/docs"
echo ""

python3 -m uvicorn app.api.server:app \
    --host 127.0.0.1 \
    --port 8001 \
    --reload
