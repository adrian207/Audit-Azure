#!/bin/bash
# Start Azure Audit Platform - API Backend

set -e

echo "Starting Azure Audit API..."
cd "$(dirname "$0")/api"

if [ ! -d "venv" ]; then
    echo "[ERROR] Virtual environment not found"
    echo "Please run install.sh first"
    exit 1
fi

source venv/bin/activate

echo "Starting FastAPI server on http://localhost:8000"
echo "API Documentation: http://localhost:8000/docs"
echo ""

uvicorn main:app --host 0.0.0.0 --port 8000 --reload
