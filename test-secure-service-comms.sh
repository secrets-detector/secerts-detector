#!/bin/bash

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}===== Testing Secure Service Communication =====${NC}"

# Check if Docker Compose is running
if ! docker-compose ps >/dev/null 2>&1; then
  echo -e "${RED}Docker Compose is not running. Please start the services first:${NC}"
  echo "docker-compose up -d"
  exit 1
fi

# Check if certificates exist
if [ ! -d "./certs" ]; then
  echo -e "${BLUE}Certificates not found. Generating certificates...${NC}"
  ./generate-certs.sh
fi

# Get API key from environment or Docker Compose
API_KEY=$(docker-compose exec -T github-app printenv VALIDATION_API_KEY || echo "default-development-key-do-not-use-in-production")
echo "Using API key: $API_KEY"

# Test health endpoint on dedicated health port
echo -e "\n${BLUE}Testing health endpoint on dedicated health port...${NC}"
HEALTH_RESPONSE=$(curl -s http://localhost:8081/health)
echo "Health response: $HEALTH_RESPONSE"

if [[ "$HEALTH_RESPONSE" == *"ok"* ]]; then
  echo -e "${GREEN}Health check passed!${NC}"
else
  echo -e "${RED}Health check failed!${NC}"
fi

# Test authenticated endpoint with API key and mTLS
echo -e "\n${BLUE}Testing authenticated endpoint with API key and mTLS...${NC}"
AUTH_RESPONSE=$(curl -s -k \
  --cert ./certs/github-app/github-app.crt \
  --key ./certs/github-app/github-app.key \
  --cacert ./certs/ca/ca.crt \
  -X POST \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"content":"no secrets here"}' \
  https://localhost:8443/validate)

echo "Authentication response: $AUTH_RESPONSE"

if [[ "$AUTH_RESPONSE" == *"No secrets detected"* ]]; then
  echo -e "${GREEN}Authentication test passed!${NC}"
else
  echo -e "${RED}Authentication test failed!${NC}"
fi

# Test authentication failure with incorrect API key but valid mTLS
echo -e "\n${BLUE}Testing authentication failure with incorrect API key but valid mTLS...${NC}"
BAD_AUTH_RESPONSE=$(curl -s -k \
  --cert ./certs/github-app/github-app.crt \
  --key ./certs/github-app/github-app.key \
  --cacert ./certs/ca/ca.crt \
  -X POST \
  -H "Content-Type: application/json" \
  -H "X-API-Key: wrong-key" \
  -d '{"content":"no secrets here"}' \
  https://localhost:8443/validate)

echo "Bad authentication response: $BAD_AUTH_RESPONSE"

if [[ "$BAD_AUTH_RESPONSE" == *"Invalid API key"* ]]; then
  echo -e "${GREEN}Authentication failure test passed!${NC}"
else
  echo -e "${RED}Authentication failure test failed!${NC}"
fi

# Test mTLS failure with valid API key but missing client certificate
echo -e "\n${BLUE}Testing mTLS failure with valid API key but missing client certificate...${NC}"
NO_CERT_RESPONSE=$(curl -s -k \
  -X POST \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"content":"no secrets here"}' \
  https://localhost:8443/validate)

echo "No certificate response: $NO_CERT_RESPONSE"

if [[ -z "$NO_CERT_RESPONSE" || "$NO_CERT_RESPONSE" == *"handshake failure"* || "$NO_CERT_RESPONSE" == *"bad certificate"* ]]; then
  echo -e "${GREEN}mTLS failure test passed!${NC}"
else
  echo -e "${RED}mTLS failure test failed!${NC}"
fi

# Test valid mTLS + API key with certificate content
echo -e "\n${BLUE}Testing with certificate content...${NC}"
CERT_TEST_RESPONSE=$(curl -s -k \
  --cert ./certs/github-app/github-app.crt \
  --key ./certs/github-app/github-app.key \
  --cacert ./certs/ca/ca.crt \
  -X POST \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"content":"-----BEGIN CERTIFICATE-----\nMIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL\nBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\nGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA1MTUxMjAwMDBaFw0yNDA1\nMTQxMjAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw\nHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB\nAQUAA4IBDwAwggEKAoIBAQC5eIuoSCHDCIWgI2CObfvgJCyPulUGj0VxbOJmZWzl\nJdHmv5QlWcV8Kls5+PnC6hFIQX0/NjR2JlAH7m3KBNDv7B2+bwxlUzSI0T+/eR6v\n/Tbw51h+0NbO88UPv3fyr/eXRu1OXqZJUoLN5pRq7PQyyeZXY2ImWCJ1DdoocRBq\naBHctXyZdawOdQs3nalPsOu0U9IXf2RJoCY3+aEk9Hwk5eM55w2UZjsYUOQBKPU9\nl1WQhRKUNMqRdCIniRaW5D83g4FSsYqlZcR0zIhjXL4SUwqhYvqQg/O0BUopQZyu\ngY0R0vZdepvWK51dHdLqm9YUyJx6V9UlY0A9m27jAgMBAAGjUzBRMB0GA1UdDgQW\nBBRTl8Ym4z5GtKLUxGTFZQkBYJ2mdzAfBgNVHSMEGDAWgBRTl8Ym4z5GtKLUxGTF\nZQkBYJ2mdzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBZPJbi\n9SJ7WhKZrOVOLNzuDmTfYYvfXCpILDWwYwYYZPGBgyrbbOm+tENpV/ADN4mF6vM3\n8OvZg3+tBGK5fSfVHnc/CV9UBGpL89/K2y3fspyQvMuMEVHVqB5XTgUGG5mMDqga\nA2kAJhyopkIc4J5VcRE0kdiHYlQlmZjcMnpKYaWZZySVLiqvQi2G+YHvq3z9HMUT\n+2PV3mpc6m1ypF/vwVPtPTtc2VT9gYfaZ9Ge2AYQr3L9EYRHsZn3H3Nz6/ufKdja\nOO8YFPZCZ+hQkvYPBYjOF0l2qF6KPqkzQgzxBK6xzmY1J9obtr7HwgZ0Ktbk43c8\n2HkWMLiKSslaaDcP\n-----END CERTIFICATE-----"}' \
  https://localhost:8443/validate)

echo "Certificate test response: $CERT_TEST_RESPONSE"

if [[ "$CERT_TEST_RESPONSE" == *"certificate"* && "$CERT_TEST_RESPONSE" == *"Valid"* ]]; then
  echo -e "${GREEN}Certificate detection test passed!${NC}"
else
  echo -e "${RED}Certificate detection test failed!${NC}"
fi

# Test if GitHub app can communicate with validation service
echo -e "\n${BLUE}Testing if GitHub app can communicate with validation service...${NC}"
TEST_WEBHOOK_RESPONSE=$(curl -s -k -X POST \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: push" \
  -H "X-Hub-Signature: sha1=dummy" \
  -d '{"ref":"refs/heads/main","repository":{"name":"test-repo","owner":{"name":"test-org"}},"commits":[{"id":"1234","message":"Test commit"}]}' \
  http://localhost:3000/webhook)

echo "Webhook response: $TEST_WEBHOOK_RESPONSE"

# Check GitHub app logs to verify secure communication
echo -e "\n${BLUE}Checking GitHub app logs for TLS communication...${NC}"
GITHUB_APP_LOGS=$(docker-compose logs --tail=50 github-app | grep -E "TLS|certificate|secure|https|8443")
echo "$GITHUB_APP_LOGS"

echo -e "\n${BLUE}Checking validation service logs for API key authentication...${NC}"
VALIDATION_LOGS=$(docker-compose logs --tail=50 validation-service | grep -E "API|key|auth")
echo "$VALIDATION_LOGS"

echo -e "\n${GREEN}Testing complete!${NC}"