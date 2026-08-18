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
python3 extensions/js-miner/tests/test_js_miner_logic.py
python3 extensions/cloud-hunter/tests/test_cloud_hunter_logic.py
python3 extensions/tech-stack-detector/tests/test_tech_stack_logic.py
python3 extensions/graphql-auditor/tests/test_graphql_logic.py
python3 extensions/api-miner/tests/test_api_miner_logic.py
python3 extensions/subdomain-hunter/tests/test_takeover_logic.py
python3 extensions/jwt-idor-tester/tests/test_jwt_idor_logic.py
python3 extensions/jules-ai-assistant/tests/test_jules_ai_logic.py

echo "All tests passed successfully!"
