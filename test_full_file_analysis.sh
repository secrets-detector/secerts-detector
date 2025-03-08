#!/bin/bash

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}===== Full File Analysis Test =====${NC}"

# Check if docker-compose is running
if ! docker-compose ps >/dev/null 2>&1; then
  echo -e "${RED}Docker-compose is not running. Please start the services first:${NC}"
  echo "docker-compose up -d"
  exit 1
fi

# Set FULL_FILE_ANALYSIS=true in the environment
export FULL_FILE_ANALYSIS=true

# Restart the github-app service with full file analysis enabled
echo -e "${BLUE}Restarting github-app with FULL_FILE_ANALYSIS=true...${NC}"
docker-compose up -d --force-recreate github-app

# Wait for the service to restart
echo "Waiting for service to restart..."
sleep 5

# Check if full file analysis is active
ANALYSIS_MODE_CHECK=$(docker-compose exec -T github-app env | grep FULL_FILE_ANALYSIS || echo "Not set")
echo "Full file analysis status: $ANALYSIS_MODE_CHECK"

# Run the webhook test with a payload that references a file with a secret
# Create a payload with a reference to a file that would contain a certificate
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
      "message": "Add secure file",
      "added": ["secure-config.json"],
      "modified": [],
      "removed": []
    }
  ]
}
EOF

echo "Created webhook payload for file analysis test"

# Get webhook secret from container
echo "Getting webhook secret from container..."
WEBHOOK_SECRET=$(docker-compose exec -T github-app printenv GITHUB_WEBHOOK_SECRET || echo "development_webhook_secret_123")
echo "Using container webhook secret: $WEBHOOK_SECRET"

# Calculate signature using the webhook secret
echo "Calculating signature..."
PAYLOAD=$(cat "$PAYLOAD_FILE")
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha1 -hmac "$WEBHOOK_SECRET" | sed 's/^.* //')
echo "Calculated signature: sha1=$SIGNATURE"

# Send webhook to server
echo "Sending webhook to server..."
RESPONSE=$(curl -v -X POST \
  "http://localhost:3000/webhook" \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: push" \
  -H "X-Hub-Signature: sha1=$SIGNATURE" \
  -d @"$PAYLOAD_FILE")

echo -e "\nServer response:"
echo "$RESPONSE"

# Show server logs to verify full file analysis is being used
echo -e "\n${BLUE}Checking server logs for file analysis details:${NC}"
docker-compose logs --tail=20 github-app

# Clean up
rm "$PAYLOAD_FILE"

echo -e "\n${BLUE}To disable full file analysis, run:${NC}"
echo "export FULL_FILE_ANALYSIS=false && docker-compose up -d --force-recreate github-app"