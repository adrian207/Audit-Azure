#!/bin/bash
# Check for Azure Security Benchmark Updates

set -e

echo "============================================"
echo "Azure Security Benchmark Update Checker"
echo "============================================"
echo ""

cd "$(dirname "$0")/api"

if [ ! -d "venv" ]; then
    echo "[ERROR] Virtual environment not found"
    echo "Please run install.sh first"
    exit 1
fi

source venv/bin/activate

echo "Checking for benchmark updates..."
echo ""

python -m scripts.update_benchmarks

if [ $? -eq 0 ]; then
    echo ""
    echo "[SUCCESS] Benchmark check complete"
else
    echo ""
    echo "[ERROR] Benchmark check failed"
fi

deactivate
