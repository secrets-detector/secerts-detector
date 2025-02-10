#!/bin/bash

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Test counter
PASSED=0
FAILED=0

# Function to test secret detection
test_secret() {
    local secret_type=$1
    local secret_value=$2
    local expected_result=$3

    echo -e "\nTesting ${secret_type}..."
    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "{\"content\": \"${secret_value}\"}" \
        http://localhost:3000/validate)
    
    if [[ $response == *"$expected_result"* ]]; then
        echo -e "${GREEN}✓ Test passed for ${secret_type}${NC}"
        ((PASSED++))
    else
        echo -e "${RED}✗ Test failed for ${secret_type}${NC}"
        echo "Expected: $expected_result"
        echo "Got: $response"
        ((FAILED++))
    fi
}

# Test cases
echo "Starting secret detection tests..."

# AWS Key
test_secret "AWS Key" "AKIAIOSFODNN7EXAMPLE" "aws_key"

# Stripe Key
test_secret "Stripe Key" "sk_test_12345678901234567890abcd" "stripe_key"

# GitHub Token
test_secret "GitHub Token" "ghp_abcdefghijklmnopqrstuvwxyz0123" "github_token"

# JWT Token
test_secret "JWT Token" "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" "jwt_token"

# Print summary
echo -e "\n=== Test Summary ==="
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo "Total: $((PASSED + FAILED))"

# Exit with failure if any tests failed
if [ $FAILED -gt 0 ]; then
    exit 1
fi