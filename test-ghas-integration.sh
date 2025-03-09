#!/bin/bash

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}===== Testing GitHub Advanced Security Push Protection Integration =====${NC}"

# Check if docker-compose is running
if ! docker-compose ps >/dev/null 2>&1; then
  echo -e "${RED}Docker-compose is not running. Please start the services first:${NC}"
  echo "docker-compose up -d"
  exit 1
fi

# Set environment variables
export GITHUB_ADVANCED_SECURITY_ENABLED=true
export BLOCK_COMMITS=true

# Restart the github-app service with GHAS enabled
echo -e "${BLUE}Restarting github-app with GITHUB_ADVANCED_SECURITY_ENABLED=true...${NC}"
docker-compose up -d --force-recreate github-app

# Wait for the service to restart
echo "Waiting for service to restart..."
sleep 5

# Verify environment variables are set
ENV_CHECK=$(docker-compose exec -T github-app env | grep -E 'GITHUB_ADVANCED_SECURITY_ENABLED|BLOCK_COMMITS')
echo "Environment settings:"
echo "$ENV_CHECK"

# Create a test payload for the GHAS push protection API
PAYLOAD_FILE=$(mktemp)
cat > "$PAYLOAD_FILE" << 'EOF'
{
  "repository": {
    "owner": "test-org",
    "name": "test-repo"
  },
  "content": "This is a sample file content with a certificate embedded:\n\n-----BEGIN CERTIFICATE-----\nMIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL\nBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\nGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA1MTUxMjAwMDBaFw0yNDA1\nMTQxMjAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw\nHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB\nAQUAA4IBDwAwggEKAoIBAQC5eIuoSCHDCIWgI2CObfvgJCyPulUGj0VxbOJmZWzl\nJdHmv5QlWcV8Kls5+PnC6hFIQX0/NjR2JlAH7m3KBNDv7B2+bwxlUzSI0T+/eR6v\n/Tbw51h+0NbO88UPv3fyr/eXRu1OXqZJUoLN5pRq7PQyyeZXY2ImWCJ1DdoocRBq\naBHctXyZdawOdQs3nalPsOu0U9IXf2RJoCY3+aEk9Hwk5eM55w2UZjsYUOQBKPU9\nl1WQhRKUNMqRdCIniRaW5D83g4FSsYqlZcR0zIhjXL4SUwqhYvqQg/O0BUopQZyu\ngY0R0vZdepvWK51dHdLqm9YUyJx6V9UlY0A9m27jAgMBAAGjUzBRMB0GA1UdDgQW\nBBRTl8Ym4z5GtKLUxGTFZQkBYJ2mdzAfBgNVHSMEGDAWgBRTl8Ym4z5GtKLUxGTF\nZQkBYJ2mdzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBZPJbi\n9SJ7WhKZrOVOLNzuDmTfYYvfXCpILDWwYwYYZPGBgyrbbOm+tENpV/ADN4mF6vM3\n8OvZg3+tBGK5fSfVHnc/CV9UBGpL89/K2y3fspyQvMuMEVHVqB5XTgUGG5mMDqga\nA2kAJhyopkIc4J5VcRE0kdiHYlQlmZjcMnpKYaWZZySVLiqvQi2G+YHvq3z9HMUT\n+2PV3mpc6m1ypF/vwVPtPTtc2VT9gYfaZ9Ge2AYQr3L9EYRHsZn3H3Nz6/ufKdja\nOO8YFPZCZ+hQkvYPBYjOF0l2qF6KPqkzQgzxBK6xzmY1J9obtr7HwgZ0Ktbk43c8\n2HkWMLiKSslaaDcP\n-----END CERTIFICATE-----\n\nThis is more content after the certificate.",
  "content_type": "file",
  "filename": "config.txt",
  "ref": "refs/heads/feature/new-config"
}
EOF

# Send request to the push protection endpoint
echo -e "\n${BLUE}Testing GitHub Advanced Security push protection endpoint...${NC}"
RESPONSE=$(curl -s -X POST \
  "http://localhost:3000/api/v1/push-protection" \
  -H "Content-Type: application/json" \
  -d @"$PAYLOAD_FILE")

echo -e "\nPush protection response:"
echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"

# Check if the push was blocked (should be if a valid certificate was found)
if [[ "$RESPONSE" == *"\"allow\":false"* && "$RESPONSE" == *"blocking_findings"* ]]; then
  echo -e "\n${GREEN}Success! Push protection correctly blocked the push containing a secret.${NC}"
else
  echo -e "\n${RED}Failed! Push protection did not block the push containing a secret.${NC}"
fi

# Check logs for GHAS detection
echo -e "\n${BLUE}Checking logs for GHAS detection:${NC}"
GHAS_LOGS=$(docker-compose logs --tail=30 github-app | grep -E "GitHub Advanced Security|push protection|BLOCKING:|Found valid")

if [[ -n "$GHAS_LOGS" ]]; then
  echo -e "${GREEN}Success! Found log entries for GHAS push protection:${NC}"
  echo "$GHAS_LOGS"
else
  echo -e "${RED}Failed to find log entries for GHAS push protection.${NC}"
  echo "Recent logs:"
  docker-compose logs --tail=10 github-app
fi

# Clean up
rm "$PAYLOAD_FILE"

echo -e "\n${BLUE}GitHub Advanced Security Push Protection Integration Test Completed${NC}"
echo "A successful test should show:"
echo "1. A response with 'allow: false' and blocking findings"
echo "2. Log entries showing detection of the certificate"