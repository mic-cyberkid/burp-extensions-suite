#!/bin/bash
# Test script for all Burp extensions

set -e

echo "Running Java tests..."
cd extensions/param-fuzzer && mvn test && cd ../..
cd extensions/custom-decoder && mvn test && cd ../..
cd extensions/logic-flaw-visualizer && mvn test && cd ../..

echo "Running Python tests..."
python3 extensions/passive-scanner/tests/test_scanner_logic.py
python3 extensions/auth-analyzer/tests/test_auth_logic.py
python3 extensions/report-generator/tests/test_report_logic.py
python3 extensions/reset-otp-analyzer/tests/test_reset_otp_logic.py

echo "All tests passed successfully!"
