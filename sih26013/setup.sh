#!/usr/bin/env bash
# SIH26013 — Geospatial Harmonization Workstation setup
# Run once to install system and Python dependencies.
set -euo pipefail

echo "[SIH26013] Installing system geospatial libraries..."
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev \
    libgeos-dev libspatialindex-dev libproj-dev \
    curl

echo "[SIH26013] Installing Python dependencies..."
pip3 install --break-system-packages -r requirements.txt

echo "[SIH26013] Setup complete."
echo "  Run:  ./run.sh          to start the workstation"
echo "  Run:  python3 -m pytest tests/ -v    to run tests"
