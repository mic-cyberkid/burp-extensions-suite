#!/bin/bash
# Build script for all Burp extensions

set -e

echo "Building Java extensions..."

# Param Fuzzer
echo "Building Param Fuzzer..."
cd extensions/param-fuzzer
mvn package
cd ../..

# Custom Decoder
echo "Building Custom Decoder..."
cd extensions/custom-decoder
mvn package
cd ../..

echo "Java extensions built successfully."

echo "Python extensions require no build step (load directly into Burp)."
