#!/bin/bash
# Start Azure Audit Platform - React UI

set -e

echo "Starting Azure Audit UI..."
cd "$(dirname "$0")/ui"

if [ ! -d "node_modules" ]; then
    echo "[ERROR] Node modules not found"
    echo "Please run install.sh first"
    exit 1
fi

echo "Starting React development server..."
echo "UI will open at http://localhost:3000"
echo ""

npm start
