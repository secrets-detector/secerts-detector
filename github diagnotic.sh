#!/bin/bash

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}===== GitHub Webhook Debug Script =====${NC}"
echo "This script will perform multiple tests to diagnose webhook issues"

# Check Docker containers
echo -e "\n${BLUE}Checking Docker containers:${NC}"
docker ps | grep -E 'github-app|validation-service'

# Check container environment variables
echo -e "\n${BLUE}Checking GitHub App environment variables:${NC}"
WEBHOOK_SECRET=$(docker-compose exec github-app printenv GITHUB_WEBHOOK_SECRET)
echo "GITHUB_WEBHOOK_SECRET: $WEBHOOK_SECRET"

# Create a payload with secrets to detect
PAYLOAD_FILE=$(mktemp)
cat > "$PAYLOAD_FILE" << 'EOF'
{
    "ref": "refs/heads/main",
    "before": "6113728f27ae82c7b1a177c8d03f9e96e0adf246",
    "after": "6113728f27ae82c7b1a177c8d03f9e96e0adf247",
    "repository": {
        "full_name": "test-org/test-repo",
        "name": "test-repo",
        "owner": {
            "name": "test-org",
            "email": "org-admin@example.com"
        }
    },
    "commits": [
        {
            "id": "6113728f27ae82c7b1a177c8d03f9e96e0adf247",
            "message": "Test commit with embedded secrets\n\nCertificate:\n-----BEGIN CERTIFICATE-----\nMIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL\nBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\nGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA1MTUxMjAwMDBaFw0yNDA1\nMTQxMjAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw\nHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB\nAQUAA4IBDwAwggEKAoIBAQC5eIuoSCHDCIWgI2CObfvgJCyPulUGj0VxbOJmZWzl\nJdHmv5QlWcV8Kls5+PnC6hFIQX0/NjR2JlAH7m3KBNDv7B2+bwxlUzSI0T+/eR6v\n-----END CERTIFICATE-----",
            "added": [],
            "modified": ["secrets_test.txt"],
            "removed": []
        }
    ]
}
EOF

# Read the payload from the file
PAYLOAD=$(cat "$PAYLOAD_FILE")

# Check network connectivity to validation service directly
echo -e "\n${BLUE}Checking direct connectivity to validation service:${NC}"
docker-compose exec github-app curl -s -o /dev/null -w "%{http_code}" validation-service:8080 || echo "Failed to connect to validation-service:8080"

# Check connectivity to the GitHub app port on the host
echo -e "\n${BLUE}Checking connectivity to GitHub app ports:${NC}"
curl -s -o /dev/null -w "Port 3000: %{http_code}\n" http://localhost:3000 || echo "Failed to connect to port 3000"
curl -s -o /dev/null -w "Port 8080: %{http_code}\n" http://localhost:8080 || echo "Failed to connect to port 8080"

# Test validation endpoint directly
echo -e "\n${BLUE}Testing validation endpoint directly:${NC}"
VALIDATION_RESPONSE=$(curl -s -X POST \
    http://localhost:3000/validate \
    -H "Content-Type: application/json" \
    -d '{"content":"-----BEGIN CERTIFICATE-----\nMIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL\n-----END CERTIFICATE-----"}')
echo "Validation Response: $VALIDATION_RESPONSE"

# Try multiple methods for calculating signature
echo -e "\n${BLUE}Calculating webhook signatures using multiple methods:${NC}"
# GitHub method (SHA1 HMAC)
HMAC_SHA1=$(echo -n "$PAYLOAD" | openssl dgst -sha1 -hmac "$WEBHOOK_SECRET" | sed 's/^.* //')
echo "SHA1 HMAC (GitHub standard): $HMAC_SHA1"

# Binary output converted to hex
HMAC_SHA1_BINARY=$(echo -n "$PAYLOAD" | openssl dgst -binary -sha1 -hmac "$WEBHOOK_SECRET" | xxd -p | tr -d '\n')
echo "SHA1 HMAC (binary->hex): $HMAC_SHA1_BINARY"

# Show the docker-compose file port mappings
echo -e "\n${BLUE}Docker-compose port mappings:${NC}"
grep -A 5 "ports:" docker-compose.yaml || grep -A 5 "ports:" docker-compose.yml

# Debug the webhook from code
echo -e "\n${BLUE}Checking relevant code in main.go for signature verification:${NC}"
docker-compose exec github-app grep -n "ValidatePayload" /app/github-app || echo "Couldn't find signature validation code"

# Test webhook with different signature formats and ports
echo -e "\n${BLUE}Testing webhook with multiple signature formats:${NC}"

# Function to test webhook with different configurations
test_webhook() {
    local port="$1"
    local sig_format="$2"
    local sig_value="$3"
    
    echo -e "\nTesting on port $port with signature: $sig_format=$sig_value"
    response=$(curl -s -X POST \
        "http://localhost:$port/webhook" \
        -H "Content-Type: application/json" \
        -H "X-GitHub-Event: push" \
        -H "$sig_format: sha1=$sig_value" \
        -d "@$PAYLOAD_FILE")
    
    echo "Response: $response"
    if [[ "$response" != *"Invalid webhook payload"* ]]; then
        echo -e "${GREEN}SUCCESS! Webhook accepted${NC}"
        return 0
    else
        echo -e "${RED}Failed: Webhook validation error${NC}"
        return 1
    fi
}

# Try multiple combinations
# 1. GitHub's standard format
test_webhook 3000 "X-Hub-Signature" "$HMAC_SHA1"

# 2. Using binary->hex conversion
test_webhook 3000 "X-Hub-Signature" "$HMAC_SHA1_BINARY"

# 3. Try with lowercase header
test_webhook 3000 "x-hub-signature" "$HMAC_SHA1"

# 4. Try direct on port 8080
test_webhook 8080 "X-Hub-Signature" "$HMAC_SHA1"

# Check the server logs for the latest errors
echo -e "\n${BLUE}Latest logs from the GitHub app:${NC}"
docker-compose logs --tail=10 github-app

# Clean up the temp file
rm "$PAYLOAD_FILE"

echo -e "\n${BLUE}===== Diagnostic Complete =====${NC}"