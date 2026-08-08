#!/bin/bash

# Ensure we exit on script error
set -e

echo "=== [AuthDiff Integration Demo] Starting ==="

# Define paths
CONFIG_PATH="extensions/authdiff/config.yaml"
MOCK_API="extensions/authdiff/mock_api.py"
ADDON_SCRIPT="extensions/authdiff/authdiff.py"
OUT_JSON="authdiff_results.json"
OUT_HTML="authdiff_report.html"

# Clean old results
rm -f "$OUT_JSON" "$OUT_HTML" mock_api.log mitmdump.log

# Ensure port 5000 and 8080 are free
kill $(lsof -t -i :5000) 2>/dev/null || true
kill $(lsof -t -i :8080) 2>/dev/null || true

# Start Mock API in background
echo "1. Starting Flask Mock API on port 5000..."
python3 "$MOCK_API" > mock_api.log 2>&1 &
MOCK_PID=$!
sleep 2

# Start mitmdump with AuthDiff addon on port 8080
echo "2. Starting mitmdump with AuthDiff addon on port 8080..."
mitmdump -s "$ADDON_SCRIPT" --set config_path="$CONFIG_PATH" --set output_json="$OUT_JSON" --set output_html="$OUT_HTML" > mitmdump.log 2>&1 &
MITM_PID=$!
sleep 4

# Run original User A requests via proxy
echo "3. Triggering original User A traffic through proxy..."

echo " -> GET /api/v1/public/health"
curl -s -x http://127.0.0.1:8080 http://127.0.0.1:5000/api/v1/public/health
echo ""

echo " -> GET /api/v1/user/profile"
curl -s -x http://127.0.0.1:8080 http://127.0.0.1:5000/api/v1/user/profile
echo ""

echo " -> GET /api/v1/documents/doc_1001"
curl -s -x http://127.0.0.1:8080 http://127.0.0.1:5000/api/v1/documents/doc_1001
echo ""

echo " -> POST /api/v1/admin/delete"
curl -s -x http://127.0.0.1:8080 -X POST http://127.0.0.1:5000/api/v1/admin/delete
echo ""

# Wait for async replays to write results
echo "4. Waiting for replays to complete..."
sleep 5

# Stop processes
echo "5. Shutting down Mock API and mitmproxy..."
kill $MOCK_PID 2>/dev/null || true
kill $MITM_PID 2>/dev/null || true

# Wait for them to exit
sleep 2

# Verify files were generated
echo "6. Verifying generated reports..."
if [ -f "$OUT_JSON" ]; then
    echo " -> OK: $OUT_JSON generated successfully."
    echo " --- JSON Contents (Vulnerability findings) ---"
    cat "$OUT_JSON"
    echo " --------------------------------------------"
else
    echo " -> ERROR: $OUT_JSON was not generated!"
    exit 1
fi

if [ -f "$OUT_HTML" ]; then
    echo " -> OK: $OUT_HTML generated successfully."
else
    echo " -> ERROR: $OUT_HTML was not generated!"
    exit 1
fi

echo "=== [AuthDiff Integration Demo] Complete ==="
