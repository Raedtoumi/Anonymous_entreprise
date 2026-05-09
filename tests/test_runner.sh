#!/bin/bash
# ISO 27001:2022 Compliance Test Runner
# Tests all OPA policies and generates compliance reports

set -e

DEFENSY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICIES_DIR="$DEFENSY_DIR/policies"
DATA_DIR="$DEFENSY_DIR/data/examples"
RESULTS_DIR="$DEFENSY_DIR/compliance-results"
TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "ISO 27001:2022 Compliance Test Suite"
echo "=========================================="
echo ""

# Create results directory
mkdir -p "$RESULTS_DIR"

# Check if OPA is installed
if ! command -v opa &> /dev/null; then
    echo -e "${RED}ERROR: OPA is not installed${NC}"
    echo "Install OPA: https://www.openpolicyagent.org/docs/latest/"
    exit 1
fi

echo -e "${GREEN}✓ OPA installed${NC}"
echo ""

# Run policy syntax check
echo "Running policy syntax check..."
opa check -b "$POLICIES_DIR" 2>&1 | tee "$RESULTS_DIR/syntax_check_$TIMESTAMP.log"
echo -e "${GREEN}✓ Syntax check passed${NC}"
echo ""

# Run all policy tests
echo "Running policy unit tests..."
opa test -v "$POLICIES_DIR" 2>&1 | tee "$RESULTS_DIR/unit_tests_$TIMESTAMP.log"
echo -e "${GREEN}✓ Unit tests completed${NC}"
echo ""

# Evaluate policies against example data
echo "Evaluating policies against example data..."
echo ""

echo "1. Authentication & Identity (A.5.15, A.5.16)"
opa eval -d "$DATA_DIR/azure_users.json" \
  -b "$POLICIES_DIR" \
  'data.iso27001_2022.authentication.deny' > "$RESULTS_DIR/auth_violations_$TIMESTAMP.json"
AUTH_VIOLATIONS=$(jq 'length' "$RESULTS_DIR/auth_violations_$TIMESTAMP.json")
echo "   Found $AUTH_VIOLATIONS authentication violations"

echo ""
echo "2. Cryptography & Cloud (A.5.10, A.5.23)"
opa eval -d "$DATA_DIR/cloud_resources.json" \
  -b "$POLICIES_DIR" \
  'data.iso27001_2022.cryptography.deny' > "$RESULTS_DIR/crypto_violations_$TIMESTAMP.json"
CRYPTO_VIOLATIONS=$(jq 'length' "$RESULTS_DIR/crypto_violations_$TIMESTAMP.json")
echo "   Found $CRYPTO_VIOLATIONS encryption violations"

echo ""
echo "3. Monitoring & Measurement (A.5.18 - NEW in 2022)"
opa eval -d "$DATA_DIR/cloud_resources.json" \
  -b "$POLICIES_DIR" \
  'data.iso27001_2022.monitoring.deny' > "$RESULTS_DIR/monitoring_violations_$TIMESTAMP.json"
MONITOR_VIOLATIONS=$(jq 'length' "$RESULTS_DIR/monitoring_violations_$TIMESTAMP.json")
echo "   Found $MONITOR_VIOLATIONS monitoring violations"

echo ""
echo "4. Data Protection & Cloud (A.5.19, A.5.23)"
opa eval -d "$DATA_DIR/m365_resources.json" \
  -b "$POLICIES_DIR" \
  'data.iso27001_2022.m365_data_protection.deny' > "$RESULTS_DIR/data_protection_violations_$TIMESTAMP.json"
DATA_VIOLATIONS=$(jq 'length' "$RESULTS_DIR/data_protection_violations_$TIMESTAMP.json")
echo "   Found $DATA_VIOLATIONS data protection violations"

echo ""
echo "=========================================="
echo "Compliance Summary"
echo "=========================================="
TOTAL_VIOLATIONS=$((AUTH_VIOLATIONS + CRYPTO_VIOLATIONS + MONITOR_VIOLATIONS + DATA_VIOLATIONS))
echo -e "Total Violations Found: ${YELLOW}$TOTAL_VIOLATIONS${NC}"
echo ""
echo "Violations by Category:"
echo "  • Authentication: $AUTH_VIOLATIONS"
echo "  • Encryption: $CRYPTO_VIOLATIONS"
echo "  • Monitoring: $MONITOR_VIOLATIONS"
echo "  • Data Protection: $DATA_VIOLATIONS"
echo ""

if [ $TOTAL_VIOLATIONS -eq 0 ]; then
    echo -e "${GREEN}✓ All compliance checks passed!${NC}"
else
    echo -e "${YELLOW}⚠ Violations found. Review detailed reports:${NC}"
    echo "  • $RESULTS_DIR/auth_violations_$TIMESTAMP.json"
    echo "  • $RESULTS_DIR/crypto_violations_$TIMESTAMP.json"
    echo "  • $RESULTS_DIR/monitoring_violations_$TIMESTAMP.json"
    echo "  • $RESULTS_DIR/data_protection_violations_$TIMESTAMP.json"
fi

echo ""
echo "Test Results:"
echo "  • Syntax Check: $RESULTS_DIR/syntax_check_$TIMESTAMP.log"
echo "  • Unit Tests: $RESULTS_DIR/unit_tests_$TIMESTAMP.log"
echo ""
echo "=========================================="
echo ""
