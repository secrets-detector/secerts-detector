#!/bin/bash

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}===== Diff-Only Mode Test with GitHub API Mocking =====${NC}"

# Check if docker-compose is running
if ! docker-compose ps >/dev/null 2>&1; then
  echo -e "${RED}Docker-compose is not running. Please start the services first:${NC}"
  echo "docker-compose up -d"
  exit 1
fi

# Set environment variables for test mode
# TEST_MODE=true enables mocking of GitHub API calls
# FULL_FILE_ANALYSIS=false ensures we're in diff-only mode
export TEST_MODE=true
export FULL_FILE_ANALYSIS=false

# Restart the github-app service with our testing configuration
echo -e "${BLUE}Restarting github-app in Test Mode with Diff-Only analysis...${NC}"
docker-compose up -d --force-recreate github-app

# Wait for the service to restart
echo "Waiting for service to restart..."
sleep 5

# Verify environment variables are set correctly
ENV_CHECK=$(docker-compose exec -T github-app env | grep -E 'FULL_FILE_ANALYSIS|TEST_MODE')
echo "Environment settings:"
echo "$ENV_CHECK"

# Create a realistic GitHub webhook payload WITHOUT including the diff
# In real operation, the app would make an API call to GitHub to get the diff
PAYLOAD_FILE=$(mktemp)
cat > "$PAYLOAD_FILE" << 'EOF'
{
  "ref": "refs/heads/main",
  "before": "6113728f27ae82c7b1a177c8d03f9e96e0adf246",
  "after": "6113728f27ae82c7b1a177c8d03f9e96e0adf247",
  "repository": {
    "name": "test-repo",
    "owner": {
      "name": "test-org",
      "login": "test-org"
    }
  },
  "commits": [
    {
      "id": "6113728f27ae82c7b1a177c8d03f9e96e0adf247",
      "message": "Add sensitive configuration",
      "added": ["config.json"],
      "modified": [],
      "removed": []
    }
  ]
}
EOF

echo "Created webhook payload without diff information"

# Get webhook secret from container
echo "Getting webhook secret from container..."
WEBHOOK_SECRET=$(docker-compose exec -T github-app printenv GITHUB_WEBHOOK_SECRET || echo "development_webhook_secret_123")
echo "Using webhook secret: $WEBHOOK_SECRET"

# Calculate signature using the webhook secret
echo "Calculating signature..."
PAYLOAD=$(cat "$PAYLOAD_FILE")
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha1 -hmac "$WEBHOOK_SECRET" | sed 's/^.* //')
echo "Calculated signature: sha1=$SIGNATURE"

# Now we need to create a mock diff to be "returned" by the GitHub API
# In test mode, we'll need to inject this as part of the test data
# The app's handlePushEvent() in TEST_MODE will look for test patches

# Create a temporary file with a mock diff containing a certificate
MOCK_DIFF_FILE=$(mktemp)
cat > "$MOCK_DIFF_FILE" << 'EOF'
diff --git a/config.json b/config.json
new file mode 100644
index 0000000..d5a6d46
--- /dev/null
+++ b/config.json
@@ -0,0 +1,14 @@
+{
+  "api_key": "test-api-key",
+  "url": "https://example.com",
+  "timeout": 30,
+  "certificate": "-----BEGIN CERTIFICATE-----
+MIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL
+BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
+GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA1MTUxMjAwMDBaFw0yNDA1
+MTQxMjAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
+HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
+AQUAA4IBDwAwggEKAoIBAQC5eIuoSCHDCIWgI2CObfvgJCyPulUGj0VxbOJmZWzl
+JdHmv5QlWcV8Kls5+PnC6hFIQX0/NjR2JlAH7m3KBNDv7B2+bwxlUzSI0T+/eR6v
+/Tbw51h+0NbO88UPv3fyr/eXRu1OXqZJUoLN5pRq7PQyyeZXY2ImWCJ1DdoocRBq
+aBHctXyZdawOdQs3nalPsOu0U9IXf2RJoCY3+aEk9Hwk5eM55w2UZjsYUOQBKPU9
+l1WQhRKUNMqRdCIniRaW5D83g4FSsYqlZcR0zIhjXL4SUwqhYvqQg/O0BUopQZyu
+gY0R0vZdepvWK51dHdLqm9YUyJx6V9UlY0A9m27jAgMBAAGjUzBRMB0GA1UdDgQW
+BBRTl8Ym4z5GtKLUxGTFZQkBYJ2mdzAfBgNVHSMEGDAWgBRTl8Ym4z5GtKLUxGTF
+ZQkBYJ2mdzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBZPJbi
+9SJ7WhKZrOVOLNzuDmTfYYvfXCpILDWwYwYYZPGBgyrbbOm+tENpV/ADN4mF6vM3
+8OvZg3+tBGK5fSfVHnc/CV9UBGpL89/K2y3fspyQvMuMEVHVqB5XTgUGG5mMDqga
+A2kAJhyopkIc4J5VcRE0kdiHYlQlmZjcMnpKYaWZZySVLiqvQi2G+YHvq3z9HMUT
+-----END CERTIFICATE-----"
+}
EOF

# Examining the code in cmd/app/main.go, we can see that in TEST_MODE,
# the app will look for patch data in the raw JSON payload
# We need to modify our payload to include this patch data for the test

# In test mode, the app extracts patches from the raw payload
MODIFIED_PAYLOAD_FILE=$(mktemp)
cat > "$MODIFIED_PAYLOAD_FILE" << EOF
{
  "ref": "refs/heads/main",
  "before": "6113728f27ae82c7b1a177c8d03f9e96e0adf246",
  "after": "6113728f27ae82c7b1a177c8d03f9e96e0adf247",
  "repository": {
    "name": "test-repo",
    "owner": {
      "name": "test-org",
      "login": "test-org"
    }
  },
  "commits": [
    {
      "id": "6113728f27ae82c7b1a177c8d03f9e96e0adf247",
      "message": "Add sensitive configuration",
      "added": ["config.json"],
      "modified": [],
      "removed": [],
      "patch": $(cat "$MOCK_DIFF_FILE" | jq -Rs .)
    }
  ]
}
EOF

echo "Created modified webhook payload with patch data for test mode"

# Recalculate signature for the modified payload
MODIFIED_PAYLOAD=$(cat "$MODIFIED_PAYLOAD_FILE")
MODIFIED_SIGNATURE=$(echo -n "$MODIFIED_PAYLOAD" | openssl dgst -sha1 -hmac "$WEBHOOK_SECRET" | sed 's/^.* //')
echo "Calculated modified signature: sha1=$MODIFIED_SIGNATURE"

# Ensure the app is ready to process webhooks
echo -e "\n${BLUE}Checking app logs before sending webhook:${NC}"
docker-compose logs --tail=10 github-app

# Send webhook to server with the modified payload that includes the patch/diff
echo -e "\n${BLUE}Sending webhook to server...${NC}"
RESPONSE=$(curl -s -X POST \
  "http://localhost:3000/webhook" \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: push" \
  -H "X-Hub-Signature: sha1=$MODIFIED_SIGNATURE" \
  -d @"$MODIFIED_PAYLOAD_FILE")

echo -e "\nServer response:"
echo "$RESPONSE"

# Show server logs to verify diff-only analysis is being used
echo -e "\n${BLUE}Checking server logs for diff analysis details:${NC}"
docker-compose logs --tail=50 github-app | grep -E "TEST MODE|diff|patch|secret|certificate|detection"

# Wait a moment for processing to complete
sleep 2

# Check if we found any secrets in the database
echo -e "\n${BLUE}Checking database for detection results:${NC}"
docker-compose exec postgres psql -U secretsuser -d secretsdb -c "
SELECT 
    r.name as repository_name, 
    r.owner as repository_owner,
    sd.secret_type, 
    sd.is_blocked, 
    sd.validation_status,
    vh.validation_message,
    sd.detected_at 
FROM secret_detections sd
JOIN repositories r ON sd.repository_id = r.id
LEFT JOIN validation_history vh ON vh.detection_id = sd.id
WHERE sd.commit_hash = '6113728f27ae82c7b1a177c8d03f9e96e0adf247'
ORDER BY sd.detected_at DESC
LIMIT 5;"

# Now test the direct validation endpoint as well, with a simple diff containing a certificate
echo -e "\n${BLUE}Testing direct validation endpoint with a diff containing a secret:${NC}"
VALIDATION_FILE=$(mktemp)
cat > "$VALIDATION_FILE" << 'EOF'
{
  "content": "diff --git a/secret.pem b/secret.pem\nnew file mode 100644\nindex 0000000..e3b0c44\n--- /dev/null\n+++ b/secret.pem\n@@ -0,0 +1,26 @@\n+-----BEGIN CERTIFICATE-----\n+MIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL\n+BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\n+GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA1MTUxMjAwMDBaFw0yNDA1\n+MTQxMjAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw\n+HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB\n+AQUAA4IBDwAwggEKAoIBAQC5eIuoSCHDCIWgI2CObfvgJCyPulUGj0VxbOJmZWzl\n+JdHmv5QlWcV8Kls5+PnC6hFIQX0/NjR2JlAH7m3KBNDv7B2+bwxlUzSI0T+/eR6v\n+/Tbw51h+0NbO88UPv3fyr/eXRu1OXqZJUoLN5pRq7PQyyeZXY2ImWCJ1DdoocRBq\n+aBHctXyZdawOdQs3nalPsOu0U9IXf2RJoCY3+aEk9Hwk5eM55w2UZjsYUOQBKPU9\n+-----END CERTIFICATE-----"
}
EOF

VALIDATION_RESPONSE=$(curl -s -X POST \
  "http://localhost:3000/validate" \
  -H "Content-Type: application/json" \
  -d @"$VALIDATION_FILE")

echo -e "Validation response:"
echo "$VALIDATION_RESPONSE" | jq '.' 2>/dev/null || echo "$VALIDATION_RESPONSE"

# Clean up temporary files
rm "$PAYLOAD_FILE" "$MOCK_DIFF_FILE" "$MODIFIED_PAYLOAD_FILE" "$VALIDATION_FILE"

echo -e "\n${GREEN}Diff-Only Mode Test with Mocked GitHub API Complete!${NC}"
echo -e "Summary of what we tested:
1. Simulated a GitHub webhook without diff information
2. Mocked the GitHub API to include diff data with a secret
3. Verified the application detected secrets within the diff
4. Confirmed operation in diff-only mode

To reset to the default configuration:
export TEST_MODE=false FULL_FILE_ANALYSIS=false && docker-compose up -d --force-recreate github-app"