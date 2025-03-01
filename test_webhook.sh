#!/bin/bash

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}===== Enhanced Webhook Test (Fixed) =====${NC}"

# Use the EXACT webhook secret that matches the server
WEBHOOK_SECRET="dummy-secret-for-testing"  # This is the default server uses
echo "Using webhook secret: $WEBHOOK_SECRET"

# Check what webhook secret the server is actually using
echo -e "\n${BLUE}Checking server webhook secret...${NC}"
SERVER_SECRET=$(docker-compose exec github-app printenv GITHUB_WEBHOOK_SECRET || echo "Not found")
echo "Server is using webhook secret: $SERVER_SECRET"

if [[ -n "$SERVER_SECRET" ]]; then
    WEBHOOK_SECRET="$SERVER_SECRET"
    echo "Using server webhook secret instead: $WEBHOOK_SECRET"
fi

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

# Create a SIMPLE webhook payload with minimal formatting to avoid JSON issues
# Use single quotes to prevent bash string interpretation
PAYLOAD_FILE=$(mktemp)
cat > "$PAYLOAD_FILE" << 'EOF'
{"ref":"refs/heads/main","before":"0000000000000000000000000000000000000000","after":"1111111111111111111111111111111111111111","repository":{"name":"test-repo","owner":{"name":"test-org"}},"commits":[{"id":"1111111111111111111111111111111111111111","message":"Test commit with embedded certificate","added":[],"modified":["test.txt"],"removed":[]}]}
EOF

# Verify payload contents
echo -e "\n${BLUE}Webhook payload content:${NC}"
cat "$PAYLOAD_FILE"

# Read the exact payload as a single string with no modifications
PAYLOAD=$(cat "$PAYLOAD_FILE")

# Calculate the signature - IMPORTANT: Use exact same payload and secret
echo -e "\n${BLUE}Calculating signature...${NC}"

# Try multiple signature methods to ensure we match what the server expects
echo "Using multiple signature calculation methods:"

# Method 1: openssl dgst with hex output
SIG1=$(echo -n "$PAYLOAD" | openssl dgst -sha1 -hmac "$WEBHOOK_SECRET" | sed 's/^.* //')
echo "1. openssl dgst (standard): sha1=$SIG1"

# Method 2: openssl dgst with binary first, then xxd to hex
SIG2=$(echo -n "$PAYLOAD" | openssl dgst -binary -sha1 -hmac "$WEBHOOK_SECRET" | xxd -p | tr -d '\n')
echo "2. openssl binary->hex: sha1=$SIG2"

# Try both signature methods with multiple ports
for PORT in 3000 8080; do
    echo -e "\n${BLUE}Testing on port $PORT...${NC}"
    
    # Try with the first signature method
    echo -e "\nTesting with signature method 1"
    RESPONSE1=$(curl -s -i -X POST \
      "http://localhost:$PORT/webhook" \
      -H "Content-Type: application/json" \
      -H "X-GitHub-Event: push" \
      -H "X-Hub-Signature: sha1=$SIG1" \
      -d @"$PAYLOAD_FILE")
    
    HTTP_STATUS1=$(echo "$RESPONSE1" | grep -o "HTTP/1.1 [0-9]\+" | head -1)
    echo "Response: $HTTP_STATUS1"
    
    # Try with the second signature method
    echo -e "\nTesting with signature method 2"
    RESPONSE2=$(curl -s -i -X POST \
      "http://localhost:$PORT/webhook" \
      -H "Content-Type: application/json" \
      -H "X-GitHub-Event: push" \
      -H "X-Hub-Signature: sha1=$SIG2" \
      -d @"$PAYLOAD_FILE")
    
    HTTP_STATUS2=$(echo "$RESPONSE2" | grep -o "HTTP/1.1 [0-9]\+" | head -1)
    echo "Response: $HTTP_STATUS2"
    
    # If either one worked, break out of the loop
    if [[ "$HTTP_STATUS1" == *"200"* || "$HTTP_STATUS2" == *"200"* ]]; then
        echo -e "${GREEN}Success on port $PORT!${NC}"
        SUCCESSFUL_PORT=$PORT
        SUCCESSFUL_RESPONSE=${HTTP_STATUS1:-$HTTP_STATUS2}
        break 2  # Break out of both loops
    fi
done

# Check if we had a success
if [[ -n "$SUCCESSFUL_PORT" ]]; then
    echo -e "\n${GREEN}Webhook test SUCCESSFUL on port $SUCCESSFUL_PORT!${NC}"
    echo "Response: $SUCCESSFUL_RESPONSE"
    
    # Check the database for detections
    echo -e "\n${BLUE}Checking database for detections...${NC}"
    sleep 2 # give a moment for the database writes to complete
    
    docker-compose exec postgres psql -U secretsuser -d secretsdb -c "
    SELECT 
        r.name as repository_name, 
        r.owner as repository_owner, 
        sd.secret_type, 
        sd.is_blocked, 
        sd.validation_status,
        sd.detected_at
    FROM secret_detections sd
    JOIN repositories r ON sd.repository_id = r.id
    WHERE r.name = 'test-repo'
    ORDER BY sd.detected_at DESC
    LIMIT 5;"
else
    echo -e "\n${RED}Webhook test FAILED on all ports!${NC}"
    
    # Simple diagnostic test with a valid secret
    echo -e "\n${BLUE}Testing direct validation endpoint...${NC}"
    VALIDATE_RESPONSE=$(curl -s -X POST "http://localhost:3000/validate" \
        -H "Content-Type: application/json" \
        -d "{\"content\":\"$TEST_CERT\"}")
    
    echo "Validation response:"
    echo "$VALIDATE_RESPONSE" | grep -o '"findings":\[[^]]*\]'
    
    # Check logs for detailed error messages
    echo -e "\n${BLUE}Recent logs:${NC}"
    docker-compose logs --tail=20 github-app
fi

# Clean up
rm "$PAYLOAD_FILE"
echo -e "\n${BLUE}===== Test Complete =====${NC}"