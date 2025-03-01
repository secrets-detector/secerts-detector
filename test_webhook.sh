#!/bin/bash

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "=== Secrets Detector Test Script ==="
echo "Testing both valid and invalid certificates to verify detection logic"

# Valid certificate - will be blocked
VALID_CERT="-----BEGIN CERTIFICATE-----\nMIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL\nBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\nGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA1MTUxMjAwMDBaFw0yNDA1\nMTQxMjAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDOpTb21lLVN0YXRlMSEw\nHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB\nAQUAA4IBDwAwggEKAoIBAQC5eIuoSCHDCIWgI2CObfvgJCyPulUGj0VxbOJmZWzl\nJdHmv5QlWcV8Kls5+PnC6hFIQX0/NjR2JlAH7m3KBNDv7B2+bwxlUzSI0T+/eR6v\n/Tbw51h+0NbO88UPv3fyr/eXRu1OXqZJUoLN5pRq7PQyyeZXY2ImWCJ1DdoocRBq\naBHctXyZdawOdQs3nalPsOu0U9IXf2RJoCY3+aEk9Hwk5eM55w2UZjsYUOQBKPU9\nl1WQhRKUNMqRdCIniRaW5D83g4FSsYqlZcR0zIhjXL4SUwqhYvqQg/O0BUopQZyu\ngY0R0vZdepvWK51dHdLqm9YUyJx6V9UlY0A9m27jAgMBAAGjUzBRMB0GA1UdDgQW\nBBRTl8Ym4z5GtKLUxGTFZQkBYJ2mdzAfBgNVHSMEGDAWgBRTl8Ym4z5GtKLUxGTF\nZQkBYJ2mdzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBZPJbi\n9SJ7WhKZrOVOLNzuDmTfYYvfXCpILDWwYwYYZPGBgyrbbOm+tENpV/ADN4mF6vM3\n8OvZg3+tBGK5fSfVHnc/CV9UBGpL89/K2y3fspyQvMuMEVHVqB5XTgUGG5mMDqga\nA2kAJhyopkIc4J5VcRE0kdiHYlQlmZjcMnpKYaWZZySVLiqvQi2G+YHvq3z9HMUT\n-----END CERTIFICATE-----"

# Test certificate with "TEST" marker - should be allowed
TEST_CERT="-----BEGIN CERTIFICATE-----\nMIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL\nBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\nGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA1MTUxMjAwMDBaFw0yNDA1\nMTQxMjAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDOpTb21lLVN0YXRlMSEw\nHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB\nAQUAA4IBDwAwggEKAoIBAQDUMbTESTAMSIQmHRtXmOxVVnpAIrTYo1DvOXKQ8jPg\nfz2kQV9ABAuqI+z0v4mgLTUb7MIZ6lEHKjWLy+BQBlwRNdScOHpbhkFiv1RPq5Cn\nkjEoVpCvehFELFEH3a1fuwYOkPnT3yzFrXWEI5h3QXR5LJgIpc1J/HOdWo3hm3CK\ntz2BDv+KCWlb+rN/fiuKHmaEFP1QG/TbifXO+ns1BfhTcnXg5nY0I8IM4GnYHXEX\nYyEPtFWBwx8g0rYKL+NXvjo8NUyn2RRpT9+nKIKu7QSM1qy0xUBPydADQ5X1+reK\nTESTCERTIFICATE123\nOI5TXpRzZsMfYxCrpZPVsRZvC2Zp+OL6wYEuAgMBAAGjUzBRMB0GA1UdDgQWBBSP\nM4RLzCu3HAwxsS7dIlWH80bFujAfBgNVHSMEGDAWgBSPM4RLzCu3HAwxsS7dIlWH\n80bFujAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB8XqqJLG50\n-----END CERTIFICATE-----"

echo -e "\n=== Testing Validation of Valid Certificate ==="
echo "This certificate should be detected as valid and would be blocked in a commit"

# Create JSON payload with properly escaped certificate
VALIDATE_FILE=$(mktemp)
echo "{\"content\":\"$VALID_CERT\"}" > "$VALIDATE_FILE"

# Send request to validation endpoint
VALID_RESPONSE=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    --data-binary "@$VALIDATE_FILE" \
    http://localhost:3000/validate)

echo -e "\nResponse for valid certificate:"
echo "$VALID_RESPONSE"

# Check if validation was successful and certificate was properly detected
if [[ "$VALID_RESPONSE" == *"certificate"* && "$VALID_RESPONSE" == *"is_valid\":true"* ]]; then
    echo -e "\n${GREEN}✓ PASSED: Valid certificate properly detected and marked as valid${NC}"
    VALID_TEST_PASSED=true
else
    echo -e "\n${RED}✗ FAILED: Valid certificate not properly detected${NC}"
    VALID_TEST_PASSED=false
fi

echo -e "\n=== Testing Validation of Test Certificate ==="
echo "This certificate contains 'TEST' and should be detected but allowed"

# Create JSON payload with test certificate
TEST_FILE=$(mktemp)
echo "{\"content\":\"$TEST_CERT\"}" > "$TEST_FILE"

# Send request to validation endpoint
TEST_RESPONSE=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    --data-binary "@$TEST_FILE" \
    http://localhost:3000/validate)

echo -e "\nResponse for test certificate:"
echo "$TEST_RESPONSE"

# Check if validation was successful and certificate was properly detected as test
if [[ "$TEST_RESPONSE" == *"certificate"* && "$TEST_RESPONSE" == *"is_valid\":false"* ]]; then
    echo -e "\n${GREEN}✓ PASSED: Test certificate properly detected and marked as invalid/test${NC}"
    TEST_CERT_PASSED=true
else
    echo -e "\n${RED}✗ FAILED: Test certificate not properly detected${NC}"
    TEST_CERT_PASSED=false
fi

# Clean up temp files
rm -f "$VALIDATE_FILE" "$TEST_FILE"

echo -e "\n=== Test Summary ==="
echo "Valid certificate test: $(if [[ "$VALID_TEST_PASSED" == "true" ]]; then echo "${GREEN}PASSED${NC}"; else echo "${RED}FAILED${NC}"; fi)"
echo "Test certificate test: $(if [[ "$TEST_CERT_PASSED" == "true" ]]; then echo "${GREEN}PASSED${NC}"; else echo "${RED}FAILED${NC}"; fi)"

if [[ "$VALID_TEST_PASSED" == "true" && "$TEST_CERT_PASSED" == "true" ]]; then
    echo -e "\n${GREEN}All tests PASSED! The secret detection logic is working correctly.${NC}"
    echo -e "\nThe core functionality of the Secrets Detector application is working:"
    echo "1. Valid certificates are detected and would be blocked"
    echo "2. Test certificates are detected but allowed"
    
    echo -e "\nNote on Webhook Testing:"
    echo "Full webhook testing requires a GitHub API server or mock, as the application"
    echo "tries to fetch the actual diff from GitHub after validating the webhook."
    echo "This connection fails in a test environment with:"
    echo "  'Failed to handle push event: failed to get diff: failed to compare commits...'"
    
    echo -e "\nRecommendations for complete testing:"
    echo "1. Use the direct validation endpoint for functional testing (as demonstrated)"
    echo "2. For webhook testing, consider:"
    echo "   - Creating a mock GitHub API server"
    echo "   - Modifying the application to bypass GitHub API calls in test mode"
    echo "   - Setting up a complete integration test with a real GitHub instance"
else
    echo -e "\n${RED}Some tests FAILED. Please check the logs for details.${NC}"
fi