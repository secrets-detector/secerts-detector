#!/bin/bash

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}===== Webhook Test With Certificate =====${NC}"

# Get webhook secret from container
echo "Getting webhook secret from container..."
WEBHOOK_SECRET=$(docker-compose exec -T github-app printenv GITHUB_WEBHOOK_SECRET || echo "development_webhook_secret_123")
echo "Using container webhook secret: $WEBHOOK_SECRET"

# Create a payload with a certificate embedded in a commit message
PAYLOAD_FILE=$(mktemp)
cat > "$PAYLOAD_FILE" << 'EOF'
{
  "ref": "refs/heads/main",
  "before": "0000000000000000000000000000000000000000",
  "after": "1111111111111111111111111111111111111111",
  "repository": {
    "name": "test-repo",
    "owner": {
      "name": "test-org"
    }
  },
  "commits": [
    {
      "id": "1111111111111111111111111111111111111111",
      "message": "Test commit with certificate in patch field",
      "added": [],
      "modified": ["test.txt"],
      "removed": [],
      "patch": "-----BEGIN CERTIFICATE-----\nMIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL\nBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\nGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA1MTUxMjAwMDBaFw0yNDA1\nMTQxMjAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw\nHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB\nAQUAA4IBDwAwggEKAoIBAQC5eIuoSCHDCIWgI2CObfvgJCyPulUGj0VxbOJmZWzl\nJdHmv5QlWcV8Kls5+PnC6hFIQX0/NjR2JlAH7m3KBNDv7B2+bwxlUzSI0T+/eR6v\n/Tbw51h+0NbO88UPv3fyr/eXRu1OXqZJUoLN5pRq7PQyyeZXY2ImWCJ1DdoocRBq\naBHctXyZdawOdQs3nalPsOu0U9IXf2RJoCY3+aEk9Hwk5eM55w2UZjsYUOQBKPU9\nl1WQhRKUNMqRdCIniRaW5D83g4FSsYqlZcR0zIhjXL4SUwqhYvqQg/O0BUopQZyu\ngY0R0vZdepvWK51dHdLqm9YUyJx6V9UlY0A9m27jAgMBAAGjUzBRMB0GA1UdDgQW\nBBRTl8Ym4z5GtKLUxGTFZQkBYJ2mdzAfBgNVHSMEGDAWgBRTl8Ym4z5GtKLUxGTF\nZQkBYJ2mdzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBZPJbi\n9SJ7WhKZrOVOLNzuDmTfYYvfXCpILDWwYwYYZPGBgyrbbOm+tENpV/ADN4mF6vM3\n8OvZg3+tBGK5fSfVHnc/CV9UBGpL89/K2y3fspyQvMuMEVHVqB5XTgUGG5mMDqga\nA2kAJhyopkIc4J5VcRE0kdiHYlQlmZjcMnpKYaWZZySVLiqvQi2G+YHvq3z9HMUT\n+2PV3mpc6m1ypF/vwVPtPTtc2VT9gYfaZ9Ge2AYQr3L9EYRHsZn3H3Nz6/ufKdja\nOO8YFPZCZ+hQkvYPBYjOF0l2qF6KPqkzQgzxBK6xzmY1J9obtr7HwgZ0Ktbk43c8\n2HkWMLiKSslaaDcP"
    }
  ]
}
EOF

echo "Created webhook payload with embedded certificate in patch field"

# Directly check the server's code to understand how it calculates the signature
echo "Examining how server calculates signature..."
# Use docker exec to check how the secret is set in the app
ACTUAL_SECRET=$(docker-compose exec -T github-app sh -c 'echo $GITHUB_WEBHOOK_SECRET')
echo "Actual webhook secret in container: $ACTUAL_SECRET"

# Read the payload from file to ensure it's preserved exactly
PAYLOAD=$(cat "$PAYLOAD_FILE")

# Calculate signature using the webhook secret
# Important: The server uses raw HMAC calculation, so we need to match that exactly
echo "Calculating signature..."
# Try multiple signature calculation methods to match what the server expects
SIGNATURE1=$(echo -n "$PAYLOAD" | openssl dgst -sha1 -hmac "$WEBHOOK_SECRET" | sed 's/^.* //')
SIGNATURE2=$(echo -n "$PAYLOAD" | openssl sha1 -hmac "$WEBHOOK_SECRET" | sed 's/^.* //')

# This binary conversion is closer to what Go's crypto/hmac package does
SIGNATURE3=$(echo -n "$PAYLOAD" | openssl dgst -binary -sha1 -hmac "$WEBHOOK_SECRET" | xxd -p)

echo "Method 1 signature: sha1=$SIGNATURE1"
echo "Method 2 signature: sha1=$SIGNATURE2"
echo "Method 3 signature: sha1=$SIGNATURE3"

# Try signature from method 3 (binary conversion) - most likely to match Go's implementation
SIGNATURE="$SIGNATURE3"
echo "Using signature: sha1=$SIGNATURE"

# Send webhook to server
echo "Sending webhook to server..."
RESPONSE=$(curl -v -X POST \
  "http://localhost:3000/webhook" \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: push" \
  -H "X-Hub-Signature: sha1=$SIGNATURE" \
  -d @"$PAYLOAD_FILE")

# If that fails, try signature method 1 (standard openssl output)
if [[ "$RESPONSE" == *"Invalid webhook payload"* ]]; then
  echo "First signature attempt failed, trying method 1..."
  SIGNATURE="$SIGNATURE1"
  echo "Using signature: sha1=$SIGNATURE"
  
  RESPONSE=$(curl -v -X POST \
    "http://localhost:3000/webhook" \
    -H "Content-Type: application/json" \
    -H "X-GitHub-Event: push" \
    -H "X-Hub-Signature: sha1=$SIGNATURE" \
    -d @"$PAYLOAD_FILE")
fi

echo -e "\nServer response:"
echo "$RESPONSE"

# Check for data in the database
echo "Checking for data in the database..."
sleep 2 # Give time for the server to process and save data
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
ORDER BY sd.detected_at DESC
LIMIT 5;"

echo "===== Webhook Test Complete ====="
rm "$PAYLOAD_FILE"