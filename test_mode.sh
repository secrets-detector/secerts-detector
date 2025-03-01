#!/bin/bash

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}===== Running Tests in Test Mode =====${NC}"

# Check if docker-compose is running
if ! docker-compose ps >/dev/null 2>&1; then
  echo -e "${RED}Docker-compose is not running. Please start the services first:${NC}"
  echo "docker-compose up -d"
  exit 1
fi

# Set TEST_MODE=true in the environment
export TEST_MODE=true

# Restart the github-app service with test mode enabled
echo -e "${BLUE}Restarting github-app with TEST_MODE=true...${NC}"
docker-compose up -d --force-recreate github-app

# Wait for the service to start
echo "Waiting for service to restart..."
sleep 5

# Check if test mode is active
TEST_MODE_CHECK=$(docker-compose exec github-app env | grep TEST_MODE || echo "Not set")
echo "Test mode status: $TEST_MODE_CHECK"

# Run the webhook test
echo -e "\n${BLUE}Running webhook test...${NC}"
./test_webhook.sh

# Run the secrets test
echo -e "\n${BLUE}Running secrets detection test...${NC}"
./test_secrets.sh

echo -e "\n${BLUE}Tests completed.${NC}"
echo -e "To disable test mode, run: export TEST_MODE=false && docker-compose up -d --force-recreate github-app"