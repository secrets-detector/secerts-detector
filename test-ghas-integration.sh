#!/bin/bash

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Arrays to store test results
declare -a TEST_NAMES=()
declare -a TEST_DESCRIPTIONS=()
declare -a TEST_EXPECTED=()
declare -a TEST_ACTUAL=()
declare -a TEST_STATUS=()

# Function to add a test result
add_test_result() {
  local name="$1"
  local description="$2"
  local expected="$3"
  local actual="$4"
  local status="$5"
  
  TEST_NAMES+=("$name")
  TEST_DESCRIPTIONS+=("$description")
  TEST_EXPECTED+=("$expected")
  TEST_ACTUAL+=("$actual")
  TEST_STATUS+=("$status")
}

# Function to send GHAS request and process result
test_ghas_case() {
  local name="$1"
  local description="$2"
  local expected_result="$3"
  local payload_file="$4"
  
  echo -e "\n${BLUE}Testing: ${BOLD}$name${NC} - $description"
  echo "Sending GHAS push protection request..."
  
  local response=$(curl -s -X POST \
    "http://localhost:3000/api/v1/push-protection" \
    -H "Content-Type: application/json" \
    -d @"$payload_file")
  
  echo -e "Response:"
  echo "$response" | jq . 2>/dev/null || echo "$response"
  
  # Determine actual result and status
  local actual_result=""
  local test_status="FAIL"
  
  if [[ "$expected_result" == "Should be blocked" ]]; then
    # Check if it was properly blocked
    if [[ "$response" == *'"allow":false'* && "$response" == *'"blocking_findings"'* ]]; then
      actual_result="Blocked correctly"
      test_status="PASS"
    else
      actual_result="Not blocked"
      test_status="FAIL"
    fi
  elif [[ "$expected_result" == "Should be allowed" ]]; then
    # Check if it was properly allowed
    if [[ "$response" == *'"allow":true'* ]]; then
      actual_result="Allowed correctly"
      test_status="PASS"
    elif [[ "$response" == *'"non_blocking_findings"'* && ! "$response" == *'"blocking_findings"'* ]]; then
      actual_result="Detected as non-blocking"
      test_status="PASS"
    else
      actual_result="Incorrectly blocked"
      test_status="FAIL"
    fi
  elif [[ "$expected_result" == "Should not be detected" ]]; then
    # Check if it wasn't detected at all
    if [[ "$response" == *'"allow":true'* && ! "$response" == *'"non_blocking_findings"'* ]]; then
      actual_result="Not detected (allowed correctly)"
      test_status="PASS"
    else
      actual_result="Incorrectly detected"
      test_status="FAIL"
    fi
  fi
  
  add_test_result "$name" "$description" "$expected_result" "$actual_result" "$test_status"
}

echo -e "${BLUE}===== GitHub Advanced Security (GHAS) Push Protection Test Suite =====${NC}"

# Check if docker-compose is running
if ! docker-compose ps >/dev/null 2>&1; then
  echo -e "${RED}Docker-compose is not running. Please start the services first:${NC}"
  echo "docker-compose up -d"
  exit 1
fi

# Set environment variables
export FULL_FILE_ANALYSIS=true
export TEST_MODE=true
export MOCK_FILES_MODE=true
export BLOCK_COMMITS=true  # Ensure blocking is enabled
export GITHUB_ADVANCED_SECURITY_ENABLED=true # Enable GHAS integration

# Restart the github-app service with required settings
echo -e "${BLUE}Restarting github-app with test detection settings...${NC}"
docker-compose up -d --force-recreate github-app

# Wait for the service to restart
echo "Waiting for service to restart..."
sleep 5

# Verify all environment variables are set
ENV_CHECK=$(docker-compose exec -T github-app env | grep -E 'FULL_FILE_ANALYSIS|TEST_MODE|MOCK_FILES_MODE|BLOCK_COMMITS|GITHUB_ADVANCED_SECURITY')
echo "Environment settings:"
echo "$ENV_CHECK"

# Check that all required variables are present
if [[ $ENV_CHECK != *"GITHUB_ADVANCED_SECURITY_ENABLED=true"* ]]; then
  echo -e "${RED}ERROR: GITHUB_ADVANCED_SECURITY_ENABLED is not set to true in the container!${NC}"
  echo "Please update your docker-compose.yaml to include GITHUB_ADVANCED_SECURITY_ENABLED."
  exit 1
fi

echo -e "\n${BLUE}======== Test Suite: Certificates ========${NC}"

# 1. Test certificate with "TEST" marker (should be detected but allowed)
TEST1_PAYLOAD=$(mktemp)
cat > "$TEST1_PAYLOAD" << 'EOF'
{
  "repository": {
    "owner": "test-org",
    "name": "test-repo"
  },
  "content": "This is a sample file content with a TEST certificate embedded:\n\n-----BEGIN CERTIFICATE-----\nMIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL\nBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\nGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA1MTUxMjAwMDBaFw0yNDA1\nMTQxMjAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw\nHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB\nAQUAA4IBDwAwggEKAoIBAQC5eIuoSCHDCIWgI2CObfvgJCyPulUGj0VxbOJmZWzl\nJdHmv5QlWcV8Kls5+PnC6hFIQX0/NjR2JlAH7m3KBNDv7B2+bwxlUzSI0T+/eR6v\n/Tbw51h+0NbO88UPv3fyr/eXRu1OXqZJUoLN5pRq7PQyyeZXY2ImWCJ1DdoocRBq\naBHctXyZdawOdQs3nalPsOu0U9IXf2RJoCY3+aEk9Hwk5eM55w2UZjsYUOQBKPU9\nl1WQhRKUNMqRdCIniRaW5D83g4FSsYqlZcR0zIhjXL4SUwqhYvqQg/O0BUopQZyu\ngY0R0vZdepvWK51dHdLqm9YUyJx6V9UlY0A9m27jAgMBAAGjUzBRMB0GA1UdDgQW\nBBRTl8Ym4z5GtKLUxGTFZQkBYJ2mdzAfBgNVHSMEGDAWgBRTl8Ym4z5GtKLUxGTF\nZQkBYJ2mdzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBZPJbi\n9SJ7WhKZrOVOLNzuDmTfYYvfXCpILDWwYwYYZPGBgyrbbOm+tENpV/ADN4mF6vM3\n8OvZg3+tBGK5fSfVHnc/CV9UBGpL89/K2y3fspyQvMuMEVHVqB5XTgUGG5mMDqga\nA2kAJhyopkIc4J5VcRE0kdiHYlQlmZjcMnpKYaWZZySVLiqvQi2G+YHvq3z9HMUT\nTEST_CERT\n-----END CERTIFICATE-----\n\nThis is more content after the certificate.",
  "content_type": "file",
  "filename": "test-config.txt",
  "ref": "refs/heads/feature/test-config"
}
EOF

test_ghas_case "Test Certificate" "Certificate with TEST marker in it" "Should be allowed" "$TEST1_PAYLOAD"

# 2. Real certificate (should be detected and blocked)
TEST2_PAYLOAD=$(mktemp)
cat > "$TEST2_PAYLOAD" << 'EOF'
{
  "repository": {
    "owner": "test-org",
    "name": "test-repo"
  },
  "content": "This is a sample file content with a real certificate embedded:\n\n-----BEGIN CERTIFICATE-----\nMIIFHTCCAwWgAwIBAgIUUGihu0CQ3okROlCakzXXIODzMqUwDQYJKoZIhvcNAQEL\nBQAwHjEcMBoGA1UEAwwTU2VjcmV0cy1EZXRlY3Rvci1DQTAeFw0yNTAzMDgyMDU3\nNDFaFw0yNjAzMDgyMDU3NDFaMB4xHDAaBgNVBAMME1NlY3JldHMtRGV0ZWN0b3It\nQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDPTNL0QNlOaymOGVSO\nfmkOSlmxFK1HhprMzdm+EWSMeWj/r8TrGQrgQoLsZU8cW94jkmjcNfU9C+xfUR9G\nJoAwEfCMmr/wHNETH8XCVbgIkqw8AHgpn4gS2NhhhoxsQ/PnzhHS3juNeWB4hcmQ\nayuudLsUad+bWQPn7+JS4n3JZQ1ikfjd+a5W+FDAzcdOLvK1QTnb3s74zDRzYQz0\nISXUBOIjUxZXFZHP5rY1k3B3hsGQQpztgBKtLInnXpP+pm8WmIa/1s9yGfnaZDo/\nObpcVX7csTwIvlDtQ9yreRvdtp3GaDkePD//krFDFDycXGquvliXs65WT4DSGNz9\n+HO0IosEsdV6z+oQr9RSzA6OaywSs6QtBt3MDBOA2oPB/2AQVfXVncN/pCGoAnyn\n1RNg3+9QWYbampT18iUIIyYti8qqBHBoMSieI4TNSTjsl4IvTABpoYzBLFT83Q6c\nxAJCv3ZyiF57RWAahGq4H74WdCrqIiq7QJa4yuPabFU7hg0niqP8dgtAYyjOwI/R\n6WzgPJ/20Gt4RSuFVsVv+AOrtjWaQnNCaBN/52HZk2vYPg2vi0ebMN+ssTuypPob\nHBj4VY7jdfEdg4/2EJtkEwXdGGR4BqA1j/S99Yem0uqMqJrYipU7JDRYMqz5eX5A\nwuy4qyO+fMkhMtKE1Bsyn69OZQIDAQABo1MwUTAdBgNVHQ4EFgQUQ9H1O1l8lVer\nRx7XODWSDtwHGmEwHwYDVR0jBBgwFoAUQ9H1O1l8lVerRx7XODWSDtwHGmEwDwYD\nVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAA2FiaB9uvx+QwTJXiciB\nnDym2reqq/+lXvB3HCEua3JOS/UL6sN0vo9hbTr9v8ETLSpL5HUblbhoLLGfx1MT\nvUiiCfPIfQqjrZX472g4XSUYmrxoPiDsRqQvk0rpeQ5nalc23it2xojJ7Cd5t2j6\n2M0ShlIcDAbwJFd6j8nFc/VDmmns22QKEd2RX30ksTdvfF8JS8OqdKmA6U9sSVGZ\nDa22cXQK1oAEHkb8g/BGtxZNs1FBroIqYESSbLoLruRaGsjvFCQw0EBYbOFC6MK1\n6sK2cX1V0lpteN0juIR4fx3J/83EYF7OPffPM6eDq9eDKgQIskZm7kifKGznT9WJ\nK2IFVAfGVHkiyHgm8/iyXrQE7bS/r4qzeLa4vwSeuXK65AuDN+aFHLtl0OAVNmKK\nqu8YcEuycGs11feB2pIJji6zeeDiBeeKk3twFYcLDW2H/i7aF/sgPbXxCwPAx98M\nnBhVOAe+Ua/fBrFpaOWSa8p7YUUCLTOCh2EKHC+TC3OxMyB8G1LUfphzwfRjVT/e\nwGvlYoIBRRzqHBUhljDfzemX0yFq+n9CZp4njGL9+S4hE4Wezal8YRxMhYP+uQTs\nl4UuM48ZxCi2bTATJg9rt1cTvo1SL6XcqmO8/kR8MMxKiLW3yvxh955lkkZS8WCv\nioZk5QXbCg/GPerdWDHPS9c=\n-----END CERTIFICATE-----\n\nThis is more content after the certificate.",
  "content_type": "file",
  "filename": "real-config.txt",
  "ref": "refs/heads/feature/real-config"
}
EOF

test_ghas_case "Real Certificate" "Certificate without test markers" "Should be blocked" "$TEST2_PAYLOAD"

# 3. Invalid certificate format (should be allowed)
TEST3_PAYLOAD=$(mktemp)
cat > "$TEST3_PAYLOAD" << 'EOF'
{
  "repository": {
    "owner": "test-org",
    "name": "test-repo"
  },
  "content": "This is a sample file with an invalid certificate format:\n\n-----BEGIN CERTIFICATE-----\nThis is not a valid certificate format. It's just random text that\nlooks like it might be a certificate but it's not correctly formatted\nand should not be detected as a valid certificate by the system.\n-----END CERTIFICATE-----\n\nMore content after the invalid certificate.",
  "content_type": "file",
  "filename": "invalid-cert.txt",
  "ref": "refs/heads/feature/invalid-cert"
}
EOF

test_ghas_case "Invalid Certificate" "Certificate with invalid format" "Should be allowed" "$TEST3_PAYLOAD"

# 4. Commented out certificate (should not be detected or allowed)
TEST4_PAYLOAD=$(mktemp)
cat > "$TEST4_PAYLOAD" << 'EOF'
{
  "repository": {
    "owner": "test-org",
    "name": "test-repo"
  },
  "content": "// This is a commented out certificate in code:\n//\n// -----BEGIN CERTIFICATE-----\n// MIIFHTCCAwWgAwIBAgIUUGihu0CQ3okROlCakzXXIODzMqUwDQYJKoZIhvcNAQEL\n// BQAwHjEcMBoGA1UEAwwTU2VjcmV0cy1EZXRlY3Rvci1DQTAeFw0yNTAzMDgyMDU3\n// NQAwHjEcMBoGA1UEAwwTU2VjcmV0cy1EZXRlY3Rvci1DQTAeFw0yNTAzMDgyMDU3\n// ...(truncated for brevity)\n// -----END CERTIFICATE-----\n\nfunction loadCertificate() {\n  // Certificate should be loaded from a secure source in production\n  return 'secure-certificate-placeholder';\n}",
  "content_type": "file",
  "filename": "commented-code.js",
  "ref": "refs/heads/feature/commented-code"
}
EOF

test_ghas_case "Commented Certificate" "Certificate inside code comments" "Should be allowed" "$TEST4_PAYLOAD"

echo -e "\n${BLUE}======== Test Suite: Private Keys ========${NC}"

# 5. Real private key (should be detected and blocked)
TEST5_PAYLOAD=$(mktemp)
cat > "$TEST5_PAYLOAD" << 'EOF'
{
  "repository": {
    "owner": "test-org",
    "name": "test-repo"
  },
  "content": "This file contains a private key:\n\n-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5F0ifNQF20kJi\nzRTmsea44zy0xM8+BjZ7pEr587gO6Ov3KoKZCV4xcFhvJ/9yWgRWoCYMvpOIxW/G\nWufmRObVReT7bhYYZquJcpOBgNJ7elPwKxi7mZ18Dedlf+fowwx3L5+agq2SZ4AV\n4ftNWl3R9uz5SiuGGkdQ14G4AMzEabV6hf53VZ1bvPM48bLZ2BzJRjrdcWFmCUla\n/usTP6/mEL1nK4APtce7Z/GeA1H7BKRkYlWB9UHfKFgTAh7/NtbW+H4phgpSAhkA\nJiJA0cGUhYlUjJ0D6Wd17y+iPU42/GsDPu/eP5z0M+N8H9K+lPE/7Chto5k7i3cW\nIBuiS70tAgMBAAECggEATkjZz3S03NPLfkxtZbGi+1opR+/iE8K+8oanq5Z4p92+\nR/kz6ZR7wX9Z+BG7ylrmcNklnshQUE3pm8TBRrSnyVbZpbqHH+T08pqCZwjcfZtc\nuz0PJfGwGVMsJtL1fI5azGJZKBnTXhPmqdq91pa9DdxZmIrVY8/jj/7Gf9Pex8eR\nsv3v8lPGpVpBaSVeXL+KGa0RO15bGbXudnKoSBj85mbjZhjODNs82XjLr1aYDxsP\n0QpOHsN38J20sgMZHadiKw0EtVMMqsjNYYJUea7wano/q0Zp1RjiDzceMKfRjUAf\nS4gA/jhAryMFS+1yyBtOl9rzan7Sae+3iQXkPp/7BQKBgQDlo+kEYsmSMhu0tH9n\nNWVZ4+ZqN2YhooFRnGqs3tRy5CrWYQUW2JDbQE20KDq/raqt1shviHTEBJ7Q9xOd\ny0iMTfmQq8Qt+jJR7zomNgBzlU+N9ZnGcst5aNf/K7SHvysMX2oGuJKSk8sJzR0t\nkbt+dgopac8l63EEbH2xrss7XwKBgQDOVkUs1huszUjaX2edT6q6578LJti8TfGj\npGBxffMmCPcXdJF8jGwtvezIAq2ny8jtyaPq3A23DHCsC239romK0dpwt0TsIMqK\nHi1v3XVAy6SHroC2q/xZFxTw+uEoUWaoPb+b1Zn9Dit3h11QL0JSHJwZXB6VwSUo\nIluE9dre8wKBgQDg7WuPoDNPv0Tj+ufPb72WDmPiJeEjkMiZ51uVd60f290Znm4d\nsoIwPwvdKopgtPo4y+gHVuEIHn5wr5HHPRYSV03bJmNBpY8kMe4C/2Hx1I3Xvnig\nqFAk20y141kwnU7ND6gKbT8j0x9MuluaBuRfOb86USlVOwe4DYwQPeVSgQKBgGpg\n1/Exwbrpa3IKVeUouaD68efR81PB656ulHpusPkfDiUtmARacTtz+6tylg04ZzMR\nDk17fiatZzmL+v0bCxZi8vfBxOroTQPAYzSVPGpXk0/Qi9Oh/8v+tnE3JvYeYYrD\nqxGwol9w+r/5Lga1FsA2t9PrRml21q1GaWC3UEw5AoGBAJOQa0zlLJoBQBHbKiv/\nKpeY8sWSe/A+ATLgPoTxRAtLtQENBlesIly9tosRRTuMmB4NwHAeC9oaUcvmTjFP\nmxeWLnE3s04tSeL+8rA4nsBmKai6Geu1KFhjzWF6kvyAwexyCBMnBFCLQTPtD8SR\nZgKdq3m6TIeDdL7+dt2m2W+d\n-----END PRIVATE KEY-----\n",
  "content_type": "file",
  "filename": "private-key.pem",
  "ref": "refs/heads/feature/private-key"
}
EOF

test_ghas_case "Real Private Key" "Actual private key" "Should be blocked" "$TEST5_PAYLOAD"

# 6. Test/Dummy private key (should be allowed)
TEST6_PAYLOAD=$(mktemp)
cat > "$TEST6_PAYLOAD" << 'EOF'
{
  "repository": {
    "owner": "test-org",
    "name": "test-repo"
  },
  "content": "This file contains a DUMMY private key for testing:\n\n-----BEGIN PRIVATE KEY-----\nDUMMY_PRIVATE_KEY_FOR_TESTING_PURPOSES_ONLY\nTHIS_IS_NOT_A_REAL_KEY_AND_SHOULD_NOT_BE_DETECTED\nAS_A_VALID_PRIVATE_KEY_BY_THE_SECRETS_DETECTOR\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5F0ifNQF20kJi\nzRTmsea44zy0xM8+BjZ7pEr587gO6Ov3KoKZCV4xcFhvJ/9yWgRWoCYMvpOIxW/G\nWufmRObVReT7bhYYZquJcpOBgNJ7elPwKxi7mZ18Dedlf+fowwx3L5+agq2SZ4AV\n-----END PRIVATE KEY-----\n",
  "content_type": "file",
  "filename": "dummy-key.pem",
  "ref": "refs/heads/feature/dummy-key"
}
EOF

test_ghas_case "Test Private Key" "Private key marked as DUMMY/TEST" "Should be allowed" "$TEST6_PAYLOAD"

echo -e "\n${BLUE}======== Test Suite: Other Secret Types ========${NC}"

# 7. AWS access key (should be blocked)
TEST7_PAYLOAD=$(mktemp)
cat > "$TEST7_PAYLOAD" << 'EOF'
{
  "repository": {
    "owner": "test-org",
    "name": "test-repo"
  },
  "content": "# AWS Configuration\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nregion = us-west-2\noutput = json",
  "content_type": "file",
  "filename": "aws-config.txt",
  "ref": "refs/heads/feature/aws-config"
}
EOF

test_ghas_case "AWS Access Key" "AWS credentials in config file" "Should be blocked" "$TEST7_PAYLOAD"

# 8. Short plaintext password (may not be detectable, should be allowed)
TEST8_PAYLOAD=$(mktemp)
cat > "$TEST8_PAYLOAD" << 'EOF'
{
  "repository": {
    "owner": "test-org",
    "name": "test-repo"
  },
  "content": "# User credentials\nusername = admin\npassword = password123\nrole = administrator",
  "content_type": "file",
  "filename": "user-config.txt",
  "ref": "refs/heads/feature/user-config"
}
EOF

test_ghas_case "Simple Password" "Basic plaintext password" "Should be allowed" "$TEST8_PAYLOAD"

# 9. GitHub token (should be blocked)
TEST9_PAYLOAD=$(mktemp)
cat > "$TEST9_PAYLOAD" << 'EOF'
{
  "repository": {
    "owner": "test-org",
    "name": "test-repo"
  },
  "content": "// GitHub Personal Access Token\nconst githubToken = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789';\n\nasync function fetchRepoData() {\n  const response = await fetch('https://api.github.com/repos/user/repo', {\n    headers: {\n      Authorization: `token ${githubToken}`\n    }\n  });\n  return await response.json();\n}",
  "content_type": "file",
  "filename": "github-api.js",
  "ref": "refs/heads/feature/github-api"
}
EOF

test_ghas_case "GitHub Token" "GitHub personal access token" "Should be blocked" "$TEST9_PAYLOAD"

# 10. Base64 encoded content (should be analyzed and if it contains secrets, should be blocked)
TEST10_PAYLOAD=$(mktemp)
cat > "$TEST10_PAYLOAD" << 'EOF'
{
  "repository": {
    "owner": "test-org",
    "name": "test-repo"
  },
  "content": "# Base64 encoded certificate\nCRUT_CERT=LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZ3VENDQTZtZ0F3SUJBZ0lVSExBQkFTMzNZRFhlMzJMRlZadVdMYmx0aDdnd0RRWUpLb1pJaHZjTkFRRUwKQlFBd2NqRUxNQWtHQTFVRUJoTUNWVk14RXpBUkJnTlZCQWdNQ2xOdmJXVXRVM1JoZEdVeElUQWZCZ05WQkFvTQpHRWx1ZEdWeWJtVjBJRmRwWkdkcGRITWdVSFI1SUV4MFpERWRNQnNHQTFVRUF3d1VTVzUwWlhKdVpYUWdWMmxrClozSmhkR2x2YmpFT01Bd0dBMVVFQXd3RlZFVlRWRU13SGhjTk1qTXdPVEl6TVRZd01ETXhXaGNOTXpNd09USXgKTVRZd01ETXhXakJ5TVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNBd0tVMjl0WlMxVGRHRjBaVEVoTUI4RwpBMVVFQ2d3WVNXNTBaWEp1WlhRZ1YybGtaMmwwY3lCUWRIa2dUSFJrTVIwd0d3WURWUVFEREJSSmJuUmxjbTVsCmRDQlhhV1JuY21GMGFXOXVNUTR3REFZRFZRUUREQVZVUlZOVVF6Q0NBaUl3RFFZSktvWklodmNOQVFFQkJRQUQKQ29Pd0FEQ0NBaXdEZ2dJSkFPSi9pZUluWmt2ek1Jckl1M0JUZkkxSHFsVmRlckZiV1F2ZGdXWHd4S1pZVkphcApRUWZTQnZJN3dxd25MWU9mT20wajJ5MndwUWN0Z1RTQ3FlNGNmc0crZlNxbnBQclRwd0x5UHBxcmswQVBuZmhyCkNrUmNzOUJuOGM3ZnljMnF5OURDSVdJRTRidWJSNHBzZHpLdU5mK0Qwd2dyNG5CaC9aU1FNV1Q2bDlwQlVTWXcKTUxzK3hYU3g5aGtFSXJrQ2tXZ2J3ZFRzSWhFbjZ1ZTU0S0tCdGY2QXVMcTN1T0RadjcyM3R5UmFCRVJhYTZoZQpNcFRLdmtUeVhCbXQ0TFZUQXd2WjZUdTkzS0JxTmJpZWlId2o2YWd2ZEtLakhVSkRlblVyeHF2UysrM05VZUljCnRvSDRSN0N2UWpJNzdzQmszQzFta01zbjEvckhYN3BMWW5QK25jdUZnVzRhK1V4SnFsN2VBNDY1NWFzRnEwcWUKMTl2WURtQ05JZHlVSElXSHRMRFZXbksyTG9wTTNobGRoZmVFWVdIdzFEeG4rcFYvMTA1MWphYUlYYmVLaGFqNwo3RlJsQlFScDZGeCtPSmJRUDBYZFJUTWJSQ250Qnp2VlV5R0M3RnM2YlBhYklzTVBJbkY4QVBVZVp1YzdwUG1MCkpsUjlrWGpRVmtUQ09KeHQyM3gxWFdwc1hJWXBGYW5lWXd0UDYzTi9MdkJGWUFGMTdXQXliRmFiNXp6V0cyTmMKbFZVPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",
  "content_type": "file",
  "filename": "encoded-secrets.env",
  "ref": "refs/heads/feature/encoded-secrets"
}
EOF

test_ghas_case "Base64 Encoded Secret" "Certificate encoded in Base64" "Should be blocked" "$TEST10_PAYLOAD"

# Wait a moment for processing to complete
sleep 2

echo -e "\n${BLUE}======== Database Records ========${NC}"

# Check the database for detection results
echo -e "\n${BLUE}Checking database for detection results (most recent entries):${NC}"
docker-compose exec postgres psql -U secretsuser -d secretsdb -c "
SELECT 
    r.name as repository_name, 
    r.owner as repository_owner,
    LEFT(sd.commit_hash, 12) as reference,
    sd.secret_type, 
    CASE WHEN sd.is_blocked THEN '${RED}BLOCKED${NC}' ELSE '${GREEN}ALLOWED${NC}' END as status,
    sd.validation_status,
    vh.validation_message,
    sd.detected_at 
FROM secret_detections sd
JOIN repositories r ON sd.repository_id = r.id
LEFT JOIN validation_history vh ON vh.detection_id = sd.id
WHERE sd.detected_at >= NOW() - INTERVAL '10 minutes'
ORDER BY sd.detected_at DESC
LIMIT 10;"

# Print a nicely formatted summary table of all test results
echo -e "\n${BOLD}${BLUE}============== TEST RESULTS SUMMARY ==============${NC}"
printf "\n${BOLD}%-20s %-35s %-20s %-25s %-10s${NC}\n" "TEST TYPE" "DESCRIPTION" "EXPECTED RESULT" "ACTUAL RESULT" "STATUS"
printf "%s\n" "------------------------------------------------------------------------------------------------------------"

for i in "${!TEST_NAMES[@]}"; do
  # Set color based on status
  if [[ "${TEST_STATUS[$i]}" == "PASS" ]]; then
    STATUS_COLOR="${GREEN}"
  else
    STATUS_COLOR="${RED}"
  fi
  
  printf "%-20s %-35s %-20s %-25s ${STATUS_COLOR}%-10s${NC}\n" \
    "${TEST_NAMES[$i]}" "${TEST_DESCRIPTIONS[$i]}" "${TEST_EXPECTED[$i]}" "${TEST_ACTUAL[$i]}" "${TEST_STATUS[$i]}"
done

echo -e "\n${CYAN}Key Points About GHAS Push Protection:${NC}"
echo -e "1. Files are directly included in request payload - no need for separate API fetching"
echo -e "2. Each file is analyzed individually before being committed"
echo -e "3. Real certificates and private keys should be blocked (allow: false)"
echo -e "4. Test certificates and keys should be detected but allowed (allow: true)"
echo -e "5. The system should ignore commented code and invalid formats"
echo -e "6. The system analyzes other secret types like AWS keys and GitHub tokens"
echo -e "7. The system can handle encoded content if it contains secrets"

# Clean up
rm "$TEST1_PAYLOAD" "$TEST2_PAYLOAD" "$TEST3_PAYLOAD" "$TEST4_PAYLOAD" "$TEST5_PAYLOAD" "$TEST6_PAYLOAD" "$TEST7_PAYLOAD" "$TEST8_PAYLOAD" "$TEST9_PAYLOAD" "$TEST10_PAYLOAD"

echo -e "\n${BLUE}Test complete. To disable test modes, run:${NC}"
echo "export TEST_MODE=false FULL_FILE_ANALYSIS=false MOCK_FILES_MODE=false GITHUB_ADVANCED_SECURITY_ENABLED=false && docker-compose up -d --force-recreate github-app"