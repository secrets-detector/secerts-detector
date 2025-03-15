#!/bin/bash

# This script runs the scanner for multiple specific organizations
# Usage: ./scan-orgs.sh "org1 org2 org3"

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if organizations were provided
if [ -z "$1" ]; then
  echo -e "${RED}Error: Please provide a space-separated list of organizations to scan${NC}"
  echo "Usage: ./scan-orgs.sh \"org1 org2 org3\""
  exit 1
fi

# Parse the organizations from the input
ORG_LIST=($1)

# Verify .env file exists
if [ ! -f .env ]; then
  echo -e "${RED}Error: .env file not found. Please create it from .env.example${NC}"
  exit 1
fi

# Check that GITHUB_TOKEN is set in .env
source .env
if [ -z "$GITHUB_TOKEN" ]; then
  echo -e "${RED}Error: GITHUB_TOKEN not set in .env file${NC}"
  exit 1
fi

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}Starting scan of ${#ORG_LIST[@]} organizations${NC}"
echo -e "${BLUE}============================================${NC}"

# Scan each organization in sequence
for ORG in "${ORG_LIST[@]}"; do
  echo -e "\n${BLUE}Scanning organization: ${GREEN}$ORG${NC}"
  echo -e "${BLUE}--------------------------------------------${NC}"
  
  # Export the organization name as an environment variable
  export SCANNER_OWNER=$ORG
  
  # Run the scanner for this organization
  docker-compose up --no-deps scanner
  
  # Check if scanner exited successfully
  if [ $? -eq 0 ]; then
    echo -e "\n${GREEN}Successfully scanned $ORG${NC}"
  else
    echo -e "\n${RED}Error scanning $ORG${NC}"
  fi
done

echo -e "\n${BLUE}============================================${NC}"
echo -e "${GREEN}Scan complete for all specified organizations${NC}"
echo -e "${BLUE}============================================${NC}"

# Summary from database
echo -e "\n${BLUE}Getting summary from database...${NC}"
docker-compose exec postgres psql -U secretsuser -d secretsdb -c "
SELECT 
    r.owner, 
    COUNT(DISTINCT r.id) as repos_scanned,
    COUNT(*) as secrets_found,
    COUNT(CASE WHEN sd.is_blocked THEN 1 END) as critical_secrets,
    MAX(sd.detected_at) as last_detection
FROM 
    repositories r
LEFT JOIN 
    secret_detections sd ON r.id = sd.repository_id
WHERE 
    r.owner IN ('$(echo "${ORG_LIST[@]}" | sed "s/ /','/g")')
GROUP BY 
    r.owner
ORDER BY 
    secrets_found DESC;
"

echo -e "\nTo see full details, visit the Grafana dashboard at: http://localhost:3001"