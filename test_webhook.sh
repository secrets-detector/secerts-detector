#!/bin/bash

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}===== Self-Contained Webhook Test =====${NC}"

# Use the correct webhook secret
WEBHOOK_SECRET="development_webhook_secret_123"
echo "Using webhook secret: $WEBHOOK_SECRET"

# Create a test certificate to embed in the commit message
TEST_CERT="-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA1MTUxMjAwMDBaFw0yNDA1
MTQxMjAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC5eIuoSCHDCIWgI2CObfvgJCyPulUGj0VxbOJmZWzl
JdHmv5QlWcV8Kls5+PnC6hFIQX0/NjR2JlAH7m3KBNDv7B2+bwxlUzSI0T+/eR6v
/Tbw51h+0NbO88UPv3fyr/eXRu1OXqZJUoLN5pRq7PQyyeZXY2ImWCJ1DdoocRBq
aBHctXyZdawOdQs3nalPsOu0U9IXf2RJoCY3+aEk9Hwk5eM55w2UZjsYUOQBKPU9
l1WQhRKUNMqRdCIniRaW5D83g4FSsYqlZcR0zIhjXL4SUwqhYvqQg/O0BUopQZyu
gY0R0vZdepvWK51dHdLqm9YUyJx6V9UlY0A9m27jAgMBAAGjUzBRMB0GA1UdDgQW
BBRTl8Ym4z5GtKLUxGTFZQkBYJ2mdzAfBgNVHSMEGDAWgBRTl8Ym4z5GtKLUxGTF
ZQkBYJ2mdzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBZPJbi
9SJ7WhKZrOVOLNzuDmTfYYvfXCpILDWwYwYYZPGBgyrbbOm+tENpV/ADN4mF6vM3
8OvZg3+tBGK5fSfVHnc/CV9UBGpL89/K2y3fspyQvMuMEVHVqB5XTgUGG5mMDqga
A2kAJhyopkIc4J5VcRE0kdiHYlQlmZjcMnpKYaWZZySVLiqvQi2G+YHvq3z9HMUT
-----END CERTIFICATE-----"

# Create a webhook payload with the certificate embedded in the commit message
# This way, we don't need GitHub API for diff comparison
PAYLOAD_FILE=$(mktemp)
cat > "$PAYLOAD_FILE" << EOF
{"ref":"refs/heads/main","before":"0000000000000000000000000000000000000000","after":"1111111111111111111111111111111111111111","repository":{"name":"test-repo","owner":{"name":"test-org"}},"commits":[{"id":"1111111111111111111111111111111111111111","message":"Test commit with embedded certificate\n\n${TEST_CERT}","added":[],"modified":["test.txt"],"removed":[]}]}
EOF

# Read the exact payload
PAYLOAD=$(cat "$PAYLOAD_FILE")
echo -e "Created webhook payload with embedded certificate"

# Calculate the signature
echo -e "\nCalculating signature..."
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -binary -sha1 -hmac "$WEBHOOK_SECRET" | xxd -p | tr -d '\n')
echo "Calculated signature: $SIGNATURE"

# Send the webhook request
echo -e "\n${BLUE}Sending webhook...${NC}"
RESPONSE=$(curl -s -i -X POST \
  http://localhost:3000/webhook \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: push" \
  -H "X-Hub-Signature: sha1=$SIGNATURE" \
  -d @"$PAYLOAD_FILE")

echo -e "\nResponse:"
echo "$RESPONSE"

# If it failed, check logs
if [[ "$RESPONSE" != *"200 OK"* ]]; then
  echo -e "\n${RED}Webhook test failed. Checking logs...${NC}"
  docker-compose logs --tail=10 github-app
  
  # Try direct validation endpoint as a fallback
  echo -e "\n${BLUE}Testing the validation endpoint directly...${NC}"
  VAL_RESPONSE=$(curl -s -X POST \
    http://localhost:3000/validate \
    -H "Content-Type: application/json" \
    -d "{\"content\":\"$TEST_CERT\"}")
  
  echo "Validation endpoint response:"
  echo "$VAL_RESPONSE" | grep -o '"findings":\[[^]]*\]'
else
  echo -e "\n${GREEN}Success! Webhook was accepted. Checking database for detections...${NC}"
  
  # Check the database for detections
  docker-compose exec postgres psql -U secretsuser -d secretsdb -c "
  SELECT 
      r.name as repository_name, 
      r.owner as repository_owner, 
      sd.secret_type, 
      sd.is_blocked, 
      sd.validation_status
  FROM secret_detections sd
  JOIN repositories r ON sd.repository_id = r.id
  WHERE r.name = 'test-repo'
  ORDER BY sd.detected_at DESC
  LIMIT 5;"
fi

# Clean up temp file
rm "$PAYLOAD_FILE"

echo -e "\n${BLUE}===== Test Complete =====${NC}"