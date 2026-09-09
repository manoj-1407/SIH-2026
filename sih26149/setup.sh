#!/usr/bin/env bash
# SIH26149 Clean-Environment Setup Script
set -e

echo "=== SIH26149 Bootstrap ==="
sudo apt-get update
sudo apt-get install -y python3 python3-pip sleuthkit e2fsprogs file
pip3 install --break-system-packages -r requirements.txt
echo "=== Environment Ready ==="
