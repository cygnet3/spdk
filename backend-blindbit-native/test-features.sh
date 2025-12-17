#!/bin/bash
# Test script for all feature flag combinations
# Ensures that all valid combinations compile successfully
#
# Usage:
#   ./test-features.sh          # Normal output with colors
#   ./test-features.sh --ci     # CI-friendly output without colors

# Check for CI mode
CI_MODE=false
if [ "$1" = "--ci" ] || [ "$CI" = "true" ]; then
    CI_MODE=true
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
else
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m' # No Color
fi

FAILED=0
PASSED=0

test_features() {
    local name="$1"
    local flags="$2"
    
    echo -n "Testing $name... "
    
    # Run cargo check and capture output
    local output
    output=$(cargo check $flags 2>&1)
    local exit_code=$?
    
    if [ $exit_code -eq 0 ] && echo "$output" | grep -q "Finished"; then
        echo -e "${GREEN}✓ PASS${NC}"
        ((PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC}"
        echo "  Command: cargo check $flags"
        echo "  Exit code: $exit_code"
        echo "$output" | tail -20
        ((FAILED++))
    fi
}

echo "================================================"
echo "Testing backend-blindbit-native feature flags"
echo "================================================"
echo ""

# Minimal builds
echo "=== Minimal Builds ==="
test_features "No features (trait only)" "--no-default-features"
test_features "Sync backend only" "--no-default-features --features sync"
test_features "Async backend only" "--no-default-features --features async"
echo ""

# Single client builds
echo "=== Single HTTP Client Builds ==="
test_features "ureq-client only" "--no-default-features --features ureq-client"
test_features "reqwest-client only" "--no-default-features --features reqwest-client"
echo ""

# Backend + Client combinations
echo "=== Backend + Client Combinations ==="
test_features "Sync + ureq" "--no-default-features --features sync,ureq-client"
test_features "Sync + reqwest" "--no-default-features --features sync,reqwest-client"
test_features "Async + ureq" "--no-default-features --features async,ureq-client"
test_features "Async + reqwest" "--no-default-features --features async,reqwest-client"
echo ""

# Multiple clients
echo "=== Multiple Client Builds ==="
test_features "Both clients (sync)" "--no-default-features --features sync,ureq-client,reqwest-client"
test_features "Both clients (async)" "--no-default-features --features async,ureq-client,reqwest-client"
test_features "Both clients + backends" "--no-default-features --features sync,async,ureq-client,reqwest-client"
echo ""

# Default
echo "=== Default Configuration ==="
test_features "Default features" ""
echo ""

# Summary
echo "================================================"
echo "Summary"
echo "================================================"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All feature combinations passed!${NC}"
    exit 0
else
    echo -e "${RED}Some feature combinations failed!${NC}"
    exit 1
fi

