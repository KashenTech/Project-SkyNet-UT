#!/bin/bash
# SkyNet — Automated VM Test & Execution Script
set -e

echo "=== SkyNet VM Test Harness ==="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Project directory: $PROJECT_DIR"
cd "$PROJECT_DIR"

# 1. Install prerequisites if missing
if ! command -v cmake &> /dev/null || ! command -v g++ &> /dev/null; then
    echo "Installing build prerequisites (cmake, build-essential)..."
    sudo apt-get update -qq
    sudo apt-get install -y build-essential cmake
fi

# 2. Build
echo "Building SkyNet..."
mkdir -p build
cd build
cmake ..
make -j$(nproc)

# 3. Run test suites
echo ""
echo "=== Running Schema Tests ==="
./test_schema

echo ""
echo "=== Running Correlation Rules Tests ==="
./test_correlator

echo ""
echo "=== Running Fixture Replay Tests ==="
./test_fixture_replay

echo ""
echo "=== Running Deep Scanner Tests ==="
./test_deep_scan

echo ""
echo "=== Testing Agent CLI --help ==="
./skynet-agent --help

echo ""
echo "=== Running Deep System Inventory Scan via CLI ==="
./skynet-agent --deep-scan deep_scan_report.json

echo ""
echo "=== Replaying Fixture Events via Agent CLI ==="
./skynet-agent --replay ../fixtures/events.jsonl

echo ""
echo "All tests passed successfully inside the VM!"

