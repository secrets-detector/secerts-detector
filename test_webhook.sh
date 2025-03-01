#!/bin/bash

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}===== Webhook Test With Certificate =====${NC}"

# Get the actual webhook secret directly from the running container
echo -e "\n${BLUE}Getting webhook secret from container...${NC}"
WEBHOOK_SECRET=$(docker-compose exec -T github-app printenv GITHUB_WEBHOOK_SECRET)
if [ -z "$WEBHOOK_SECRET" ]; then
    echo -e "${RED}Error: Could not retrieve webhook secret from container${NC}"
    WEBHOOK_SECRET="development_webhook_secret_123"  # Fallback
    echo "Using default webhook secret: $WEBHOOK_SECRET"
else
    echo "Using container webhook secret: $WEBHOOK_SECRET"
fi

# Create a modified payload with the certificate PROPERLY ENCODED
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
      "message": "Test commit with embedded certificate",
      "added": [],
      "modified": ["test.txt"],
      "removed": [],
      "patch": "diff --git a/test.txt b/test.txt\nindex 1234567..abcdef 100644\n--- a/test.txt\n+++ b/test.txt\n@@ -1,1 +1,1 @@\n-test\n+-----BEGIN CERTIFICATE-----\nMIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL\nBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\nGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA1MTUxMjAwMDBaFw0yNDA1\nMTQxMjAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw\nHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB\nAQUAA4IBDwAwggEKAoIBAQC5eIuoSCHDCIWgI2CObfvgJCyPulUGj0VxbOJmZWzl\nJdHmv5QlWcV8Kls5+PnC6hFIQX0/NjR2JlAH7m3KBNDv7B2+bwxlUzSI0T+/eR6v\nAQUAA4IBAQBZPJbi\n-----END CERTIFICATE-----"
    }
  ]
}
EOF

echo -e "\n${BLUE}Created webhook payload with embedded certificate in patch field${NC}"

# Read the payload into a variable
PAYLOAD=$(cat "$PAYLOAD_FILE")

echo -e "\n${BLUE}Calculating signature...${NC}"
# Calculate signature with appropriate method
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha1 -hmac "$WEBHOOK_SECRET" | sed 's/^.* //')
echo "Calculated signature: sha1=$SIGNATURE"

# Make the webhook request
echo -e "\n${BLUE}Sending webhook to server...${NC}"
RESPONSE=$(curl -s -i -X POST \
  "http://localhost:3000/webhook" \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: push" \
  -H "X-Hub-Signature: sha1=$SIGNATURE" \
  -d "@$PAYLOAD_FILE")

# Check response
echo -e "\n${BLUE}Server response:${NC}"
echo "$RESPONSE"

# Let's check if there's any data in the database after the webhook
echo -e "\n${BLUE}Checking for data in the database...${NC}"
sleep 2  # Give time for database operations to complete

DB_RESULT=$(docker-compose exec -T postgres psql -U secretsuser -d secretsdb -c "
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
LIMIT 5;")

echo "$DB_RESULT"

# Clean up
rm "$PAYLOAD_FILE"

echo -e "\n${BLUE}===== Webhook Test Complete =====${NC}"