#!/bin/bash

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to test webhook
test_webhook() {
    local test_name=$1
    local commit_message=$2
    local expected_result=$3

    echo -e "\nTesting webhook: ${test_name}..."
    
    # Create webhook payload
    payload=$(cat <<EOF
{
  "ref": "refs/heads/main",
  "before": "6113728f27ae82c7b1a177c8d03f9e96e0adf246",
  "after": "6113728f27ae82c7b1a177c8d03f9e96e0adf247",
  "repository": {
    "id": 123456,
    "name": "test-repo",
    "full_name": "test-org/test-repo",
    "owner": {
      "name": "test-org",
      "email": "test@example.com",
      "login": "test-org",
      "type": "Organization"
    }
  },
  "pusher": {
    "name": "test-user",
    "email": "test-user@example.com"
  },
  "commits": [
    {
      "id": "6113728f27ae82c7b1a177c8d03f9e96e0adf247",
      "message": "${commit_message}",
      "timestamp": "2024-02-09T10:00:00Z",
      "author": {
        "name": "Test User",
        "email": "test@example.com"
      },
      "patch": "diff --git a/test.txt b/test.txt\nnew file mode 100644\nindex 0000000..1234567\n--- /dev/null\n+++ b/test.txt\n@@ -0,0 +1 @@\n+${commit_message}"
    }
  ]
}
EOF
)

    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "X-GitHub-Event: push" \
        -H "X-Hub-Signature: sha1=fake" \
        -H "X-GitHub-Delivery: 123e4567-e89b-12d3-a456-426614174000" \
        -d "$payload" \
        http://localhost:3000/webhook)

    if [[ $response == *"$expected_result"* ]]; then
        echo -e "${GREEN}✓ Test passed: ${test_name}${NC}"
        return 0
    else
        echo -e "${RED}✗ Test failed: ${test_name}${NC}"
        echo "Expected: $expected_result"
        echo "Got: $response"
        return 1
    fi
}

# Run webhook tests
echo "Starting webhook tests..."

PASSED=0
FAILED=0

# Test AWS Key in commit
if test_webhook "AWS Key in commit" "Added AWS key AKIAIOSFODNN7EXAMPLE" "secret"; then
    ((PASSED++))
else
    ((FAILED++))
fi

# Test Stripe Key in commit
if test_webhook "Stripe Key in commit" "Added stripe key sk_test_12345678901234567890abcd" "secret"; then
    ((PASSED++))
else
    ((FAILED++))
fi

# Test multiple secrets in commit
if test_webhook "Multiple secrets" "Added keys: AKIAIOSFODNN7EXAMPLE and sk_test_12345678901234567890abcd" "secret"; then
    ((PASSED++))
else
    ((FAILED++))
fi

# Test no secrets in commit
if test_webhook "No secrets" "Regular commit message without secrets" "No secrets detected"; then
    ((PASSED++))
else
    ((FAILED++))
fi

# Print summary
echo -e "\n=== Webhook Test Summary ==="
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo "Total: $((PASSED + FAILED))"

# Exit with failure if any tests failed
if [ $FAILED -gt 0 ]; then
    exit 1
fi