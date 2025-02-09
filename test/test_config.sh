#!/bin/bash

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0

# Function to check if a service is running
check_service() {
    local service=$1
    echo -e "\nChecking $service service..."
    
    if docker-compose ps | grep -q "$service.*running"; then
        echo -e "${GREEN}✓ $service is running${NC}"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}✗ $service is not running${NC}"
        ((FAILED++))
        return 1
    fi
}

# Function to check if a port is open
check_port() {
    local port=$1
    local service=$2
    echo -e "\nChecking port $port for $service..."
    
    if nc -z localhost $port; then
        echo -e "${GREEN}✓ Port $port is open ($service)${NC}"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}✗ Port $port is not open ($service)${NC}"
        ((FAILED++))
        return 1
    fi
}

# Function to check if config file exists and is valid JSON
check_config() {
    local container=$1
    local config_path=$2
    echo -e "\nChecking config file in $container..."
    
    if docker-compose exec $container cat $config_path > /dev/null 2>&1; then
        if docker-compose exec $container cat $config_path | jq . > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Config file exists and is valid JSON${NC}"
            ((PASSED++))
            return 0
        else
            echo -e "${RED}✗ Config file exists but is not valid JSON${NC}"
            ((FAILED++))
            return 1
        fi
    else
        echo -e "${RED}✗ Config file does not exist${NC}"
        ((FAILED++))
        return 1
    fi
}

# Check all required services
echo "Starting configuration tests..."

# Check services
check_service "github-app"
check_service "validation-service"
check_service "postgres"
check_service "grafana"

# Check ports
check_port "3000" "github-app"
check_port "8080" "validation-service"
check_port "5432" "postgres"
check_port "3001" "grafana"

# Check configuration files
check_config "github-app" "/app/config/config.json"

# Check database connection
echo -e "\nChecking database connection..."
if docker-compose exec postgres psql -U secretsuser -d secretsdb -c "\dt" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Database connection successful${NC}"
    ((PASSED++))
else
    echo -e "${RED}✗ Database connection failed${NC}"
    ((FAILED++))
fi

# Print summary
echo -e "\n=== Configuration Test Summary ==="
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo "Total: $((PASSED + FAILED))"

# Exit with failure if any tests failed
if [ $FAILED -gt 0 ]; then
    exit 1
fi