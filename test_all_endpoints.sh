#!/bin/bash

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test all possible endpoints
echo -e "${BLUE}===== Testing All Endpoints =====${NC}"

# Test GitHub App and Validation Service endpoints on both ports
echo -e "\n${BLUE}Testing HTTP endpoints:${NC}"

test_endpoint() {
    local url="$1"
    local name="$2"
    
    echo -n "Testing $name ($url): "
    response=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "Failed")
    
    if [[ "$response" == "Failed" ]]; then
        echo -e "${RED}Connection failed${NC}"
    else
        echo -e "${GREEN}$response${NC}"
    fi
}

# Test all combinations
test_endpoint "http://localhost:3000" "GitHub App on mapped port 3000"
test_endpoint "http://localhost:8080" "GitHub App on direct port 8080"
test_endpoint "http://localhost:3000/validate" "Validation endpoint on port 3000"
test_endpoint "http://localhost:8080/validate" "Validation endpoint on port 8080"
test_endpoint "http://localhost:3000/webhook" "Webhook endpoint on port 3000"
test_endpoint "http://localhost:8080/webhook" "Webhook endpoint on port 8080"

# Check Docker container setup
echo -e "\n${BLUE}Docker container networking:${NC}"
docker-compose ps

# Check Docker container logs
echo -e "\n${BLUE}Last 5 lines of app logs:${NC}"
docker-compose logs --tail=5 github-app

echo -e "\n${BLUE}Last 5 lines of validation service logs:${NC}"
docker-compose logs --tail=5 validation-service

# Print port mappings from docker-compose.yml
echo -e "\n${BLUE}Docker-compose port mappings:${NC}"
grep -A 3 "ports:" docker-compose.yml || grep -A 3 "ports:" docker-compose.yaml

# Check internal DNS resolution within Docker network
echo -e "\n${BLUE}Testing internal Docker DNS:${NC}"
docker-compose exec github-app ping -c 1 validation-service 2>/dev/null || echo "Cannot ping validation-service from github-app"

# Check if app is listening on port 8080 internally
echo -e "\n${BLUE}Checking if app is actually listening on port 8080 internally:${NC}"
docker-compose exec github-app netstat -tlnp 2>/dev/null | grep 8080 || echo "Port 8080 not found in netstat output"

# Try a direct test to the validate endpoint
echo -e "\n${BLUE}Testing certificate validation endpoint directly:${NC}"
curl -s -X POST http://localhost:3000/validate -H "Content-Type: application/json" -d '{"content":"-----BEGIN CERTIFICATE-----\nMIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL\n-----END CERTIFICATE-----"}' | grep -o 'findings\|certificate'

echo -e "\n${BLUE}===== Test Complete =====${NC}"
echo "Based on the above results, you should be able to determine which endpoint is working."
echo "Try the webhook test on the working endpoint after confirming the validation endpoint works."