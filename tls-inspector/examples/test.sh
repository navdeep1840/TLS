#!/bin/bash

# Quick test script to verify TLS inspector is working

set -e

echo "TLS Inspector Test Script"
echo "========================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: This script must be run as root"
  exit 1
fi

# Check if binary exists
if [ ! -f "./tls-inspector" ]; then
  echo "ERROR: tls-inspector binary not found. Run 'make build' first."
  exit 1
fi

echo "Starting TLS Inspector in background..."
./tls-inspector run --config configs/config.yaml > test-output.json 2>&1 &
INSPECTOR_PID=$!
echo "Inspector PID: $INSPECTOR_PID"

sleep 2

echo ""
echo "Generating test traffic..."
echo ""

# Test 1: curl
echo "Test 1: curl with JWT token"
curl -s -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig" \
  https://httpbin.org/headers > /dev/null
sleep 1

# Test 2: Python
echo "Test 2: Python requests"
python3 -c "
import requests
requests.get('https://httpbin.org/get', headers={'X-API-Key': 'AKIAIOSFODNN7EXAMPLE'})
" 2>/dev/null || true
sleep 1

echo ""
echo "Stopping inspector..."
kill $INSPECTOR_PID 2>/dev/null || true
wait $INSPECTOR_PID 2>/dev/null || true

echo ""
echo "Test Results:"
echo "=============\n"

if [ -f test-output.json ]; then
  EVENT_COUNT=$(grep -c '"timestamp"' test-output.json || echo "0")
  DETECTION_COUNT=$(grep -c '"detections"' test-output.json || echo "0")
  
  echo "Events captured: $EVENT_COUNT"
  echo "Events with detections: $DETECTION_COUNT"
  echo ""
  
  if [ $EVENT_COUNT -gt 0 ]; then
    echo "✓ SUCCESS: TLS Inspector captured events!"
    echo ""
    echo "Sample event:"
    grep '"timestamp"' test-output.json | head -n 1 | jq '.' 2>/dev/null || \
      grep '"timestamp"' test-output.json | head -n 1
  else
    echo "✗ WARNING: No events captured. Check logs above."
  fi
else
  echo "✗ ERROR: No output file generated"
fi

echo ""
rm -f test-output.json
