#!/bin/bash
# Start both API and UI in background

set -e

SCRIPT_DIR="$(dirname "$0")"

echo "Starting Azure Audit Platform (API + UI)..."
echo ""

# Start API in background
cd "$SCRIPT_DIR"
./run_api.sh &
API_PID=$!

echo "API started (PID: $API_PID)"

# Wait for API to be ready
sleep 3

# Start UI in background
./run_ui.sh &
UI_PID=$!

echo "UI started (PID: $UI_PID)"
echo ""
echo "Both services running:"
echo "- API: http://localhost:8000 (PID: $API_PID)"
echo "- UI:  http://localhost:3000 (PID: $UI_PID)"
echo ""
echo "To stop services:"
echo "  kill $API_PID $UI_PID"
echo ""

# Save PIDs to file for easy cleanup
echo "$API_PID" > .api.pid
echo "$UI_PID" > .ui.pid

# Wait for both processes
wait $API_PID $UI_PID
