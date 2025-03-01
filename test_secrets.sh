#!/bin/bash

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Test counter
PASSED=0
FAILED=0

# Function to test secret detection with proper JSON escaping
test_secret() {
    local test_name=$1
    local secret_value=$2
    local expected_result=$3
    local should_be_valid=$4  # true or false

    echo -e "\nTesting ${test_name}..."
    
    # Create a temporary file with the JSON payload
    # This avoids issues with bash string escaping
    PAYLOAD_FILE=$(mktemp)
    cat > "$PAYLOAD_FILE" << EOF
{
  "content": $(printf '%s' "$secret_value" | jq -Rs .)
}
EOF

    # Debug
    echo "Sending request to validation service..."

    # Make the request
    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        --data @"$PAYLOAD_FILE" \
        http://localhost:3000/validate)
    
    # Clean up temp file
    rm "$PAYLOAD_FILE"
    
    # Debug output
    echo "Response: $response"
    
    if [[ $response == *"$expected_result"* ]]; then
        echo -e "${GREEN}✓ Test passed: Found expected type ${expected_result}${NC}"
        
        # Check validity of finding based on response format
        if [[ $should_be_valid == true && $response == *"\"is_valid\":true"* ]]; then
            echo -e "${GREEN}✓ Test passed: Secret correctly identified as valid${NC}"
            ((PASSED++))
        elif [[ $should_be_valid == false && ($response == *"\"is_valid\":false"* || $response == *"\"findings\":[]"*) ]]; then
            echo -e "${GREEN}✓ Test passed: Secret correctly identified as invalid/test data${NC}"
            ((PASSED++))
        else
            echo -e "${RED}✗ Test failed: Secret validity incorrect${NC}"
            echo "Expected valid: $should_be_valid"
            ((FAILED++))
        fi
    else
        echo -e "${RED}✗ Test failed: Expected '$expected_result' not found${NC}"
        ((FAILED++))
    fi
}

# Test cases
echo "Starting secret detection tests..."

# Use real valid certificates and keys (but with line breaks preserved correctly)
valid_cert=$(cat <<EOF
-----BEGIN CERTIFICATE-----
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
+2PV3mpc6m1ypF/vwVPtPTtc2VT9gYfaZ9Ge2AYQr3L9EYRHsZn3H3Nz6/ufKdja
OO8YFPZCZ+hQkvYPBYjOF0l2qF6KPqkzQgzxBK6xzmY1J9obtr7HwgZ0Ktbk43c8
2HkWMLiKSslaaDcP
-----END CERTIFICATE-----
EOF
)

# Test certificate 
test_cert=$(cat <<EOF
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA1MTUxMjAwMDBaFw0yNDA1
MTQxMjAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDUMbTESTAMSIQmHRtXmOxVVnpAIrTYo1DvOXKQ8jPg
fz2kQV9ABAuqI+z0v4mgLTUb7MIZ6lEHKjWLy+BQBlwRNdScOHpbhkFiv1RPq5Cn
kjEoVpCvehFELFEH3a1fuwYOkPnT3yzFrXWEI5h3QXR5LJgIpc1J/HOdWo3hm3CK
tz2BDv+KCWlb+rN/fiuKHmaEFP1QG/TbifXO+ns1BfhTcnXg5nY0I8IM4GnYHXEX
YyEPtFWBwx8g0rYKL+NXvjo8NUyn2RRpT9+nKIKu7QSM1qy0xUBPydADQ5X1+reK
TESTCERTIFICATE123
OI5TXpRzZsMfYxCrpZPVsRZvC2Zp+OL6wYEuAgMBAAGjUzBRMB0GA1UdDgQWBBSP
M4RLzCu3HAwxsS7dIlWH80bFujAfBgNVHSMEGDAWgBSPM4RLzCu3HAwxsS7dIlWH
80bFujAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB8XqqJLG50
p58xmg1bvzPDonMoXsj+wqK+YHEQKNLiTGbQ+O6qQQTBuXHCTTHf4uC0cV3ElRd8
QTZAEDvbKnGDAV7xwVKcjZ/VxQaUgcYK6CB3xn0Q9cKJOzJz6pWmpKJrq4P1kJBq
NDNSgfNLoxPJEwK3G0Q/9/auVYwZQmjIbLTXSPZ0jTKFyrMi5csQNMD2vXQFdjFT
BwLHdqgFUgTiEPfyAzomL2aEmPCdJUcV+UhpXAaLMHK2n/tPvBPxBPv0QXaTMQFa
MC3jkQ9R5K3zXj0kwiOQMINj9TAm7GV7FiZ9RwTjHx6+bJpj+Z7ZSJbz1Dl+eCiF
yPCjPQQdnNtq
-----END CERTIFICATE-----
EOF
)

# Valid private key
valid_key=$(cat <<EOF
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCz5HbiHPPGtYd5
Lcix2lCcOF0bnPOSdJV0jxFG36vZFF1eeTuiloxWymtZ6R695lhWfnUtDuoxeL9t
RmQYxEgK982MEQpoearvijpd99piLXZ1ZVXvEU0X1/Dy6hOAFD9CCFUwO8OH4S4Y
p1LjZwfaQ9bEjm52EC9RMQg4JSk1vYmtnKsycUdOny6CSbrrbbVS/us6xIW2GTzh
H2kl0E10nZtrS50cuanA18kE6GTq1iY9RWF+jgF1Eb2szW8XOyptmuigOaKXYmFR
aosREhTWZX3v+AOEvn6U6EaCDh7gBMRNfTX/hcpuZYqVga4f7zCGPDiFC8cM4TKG
10OvYsiNAgMBAAECggEAFbGROZratgWZqP4hs/r7Gh+88LHIeMqo5FXFdFnQWD0Z
tmUh0S1dDrFZ6U2Q2L9Au2uEF3MzQFSKpzOkKg1vj60LA19htTAo8jql58OWOR04
6hbWml4ogR3YL38Va25lo4GsPkUSwx3faHczKnu4CXUBXxI7FW9FuYGTd2vZ0KJP
SBh39dQUerfdA/KOkCnU0JyRIwOXDTvB5ieN/mILHuLSAqe3SN/pQUaw6fOSsrJ+
1u5VKemHPIg7JHYY0F3s4R/iI5cxagLN66/lGfqz/AJptpnMBhM2Wo5JeoUj4vwY
YeSvN8ZmMPanPQDPguzi5Djvro2PNsMq/saNnge9QQKBgQDXQhJTTq7qWDtFYynO
0XtoKwWeYtNI1SNAjK4QhQ6nJNZCNWbrFL4ZlEQBtzH+iznlG6/CKjPgT8M167ZS
c2lTLsCI8lpkDyLKBVEyzakfIqa2qNSJHveb9w0/IxEL1VHKO85pftGYjqZV9h+1
z9CEL4IhCFnkwvLfHkPevVJQwQKBgQDV8NDyiM9d1eHVg7cDYDMRwnhVIAXWOhnd
AoidZ94EP/1ZTvkxeTnXFvtYTwRF3A+uYf95ux/1CtwmP7fQh1LK3La31YqKKx11
3oglxtqZaUOFSZFQgMSMFvB+zCtO+olG2qOUYJVse7OzMDA5UMdwqV0jfyYYyy2F
l926jeGezQKBgQCueIgf69OMcA1CdViKoHIVAWHheZplGxQimqPvEdnJkerz6RLN
EZfvZaQle9XSyggX8fPoPYqkkiHYT4AMnizNVkSJ+11WYopBEkQ5GEauzMgxnu/9
YBMz3+9lsEd9vt43O3hXO4ooy954KDCVjaYlrdgcbAdoiraOL5q1K+BPQQKBgQDP
pm+IGJX9I+2QicmGs0aeRDz7kptXtQkJZL4o2Xm6ckl695YTGPC0/g9zRS6Gh/OI
dIG9K4z3EFVhopLNCauoTtXiVJelR/fOQfGviPT/1hW9NwyeMH2U42cGCzE19SJs
7SW8jIo7w01F7M3Bs9AAX8KRA4Z8pihG9II34iJNOQKBgDvEAe18F2+TcRZPEB97
VKwe6oRveGiwcPCr1jBCScg8gwVPr1gGsnV5QXwc4vpGHGwIcDBV8bWQ4Bcs0tFk
kMRHNRB1b+8X7MP39gl6grjou7lUwhPWUyQ/8wnMvO2oby/o91E2DFY3qUPfFvPU
+bHUjJcX4z8JTsLzhYXJp1op
-----END PRIVATE KEY-----
EOF
)

# Test private key with the "TEST" marker
test_key=$(cat <<EOF
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDeuIu63xvBLIrz
nDn0LqUJDCrKBvhklDGan3H9m4fsG5uLOVR1WUY8LHQpK6kSQlMGdgOBFXfCTgsl
L3+XvUTPr78t7xTZSQkpMBZVvEOzGlLFtQwUCw/+Mm9mYLKGQHfz4JvP2nXpOJVZ
HmSSh3TKhtQ9Cgg4TESTPRIVATEKEY123JGkynK9rPF6iEjR38nXPa2E5
8DBv9hU8DZlG3WrJJgUVQR2knK0kRZ0U+HQJ2fGLtK7jWIAgUPlPMdHCJQEFO8k7
8X2+AHkdlQfIj5k7mJeKV4EUQ+jgDgZEQPUQDsl4O86leuoGEAOREj+Ey6wFmiT+
0Xgz0XotAgMBAAECggEAaxY4LZXPVqEoZ5gXXgESXB9H3ntMPVzD2X53XJ9MQnpJ
KQHGI29o2j5zy7zGABU3UZ14PYbm4ByP+IVHkETHPPSH3XjJX6T3aGOk/OAM5WTJ
QqPTWZU5Dg/AUNx/kZ8MWvf5wR3+3QGlK6jY5B3p3+TCNzGr0TlxZXYGQNf5UfKd
jXfIrTGZZeIwSPUmapVgdMQIYl0UHnYKsJYuY9s0P0WfEKbZKfc7FTFxzb8tVLR0
kJIfXBJOeUk9K0p4PRZMZVm5EdYGebII74wREuUhwbLxzyfL1TkF/MdQYo4eBUQf
YwGYJjkG/JXafpwjBWg8CBHSEOGddMuYTk89y5kzuQKBgQDxa6cz/xZfID6K7oPn
ftRnZyQnxRVU8C+Ps7aZyJKfAJkoIq/0IBnJc1vEQlfnW4BzAZXKyFPkXYJzQQ3N
nbYmiwJKpbD6U/YdCjXJyKOP+fflwSPlnxnDFCu/egdTcfQIiGdHEBGGgj5hKkP+
MU+COA+DF5g50GQf0MvGY9WlUwKBgQDrp6Y0j6RlcxHbYA0x5yK9S+8nFcB957Mi
U9sKEIb+yJkNGjUVTS3Qp9BEMlMULCnWbZxvySOdAwD3/eYLpwI0/4FZxlGZ0BSx
5TSU8MWnS7nH7PZdQbMOXeVgUJuUi3FyaY6iJyQGUH5mhQBV+xkk91jgO2X3aeOz
WqkZHAE3fwKBgGT1LYEDzIlBqChGi/GK3wIcn9lbBtDt1OZDv+ZKuBFHXE6UWNND
dh8qgZB3/VRVMAimG6wdTVR+UXbH3YkM6uNFQBV84qoQmUXdXH5lMgptCjdB2oOO
CLUKGd63XPbFuUO26gBjw8xXkm3RDFowb8UMcbL+ru4j3ERh6Y2+ZoSXAoGBANxY
UwXAYvLhqoLpXzWWcQ9p+uGZ/5dEP07Nd0lOKAWJHRECM38LvMEFldXRJbiGQnYL
1N1QwVa1WUJbYhSv86T+YUMsVfcNh9F7JCs5SLnuYzH9kPrKuxxS9kCeHDkr+fLf
0ECsKEoDIwLmRG0PMjpA3hMJDkC9jKCKfLVMEP+pAoGBAKRiA7dIbhYVbIx0EwO7
0mxVISRwX/NBUP0V79xXI7P2vvtTg+wBSrYy2oRHm2hUXTIjPFxpLRboryFM0C3t
4tZdEg8OStnUdbx1/YCZg3X9avd3C4DgoZQKDk6+yCSihMJ7MQ2VEPbMBbzQgn5F
QY0PvFYtaRnzZLSq/fJQ7N0t
-----END PRIVATE KEY-----
EOF
)

# Make sure jq is installed
if ! command -v jq &> /dev/null; then
    echo "jq is required but not installed. Please install it."
    exit 1
fi

# Test cases
test_secret "Valid Certificate" "$valid_cert" "certificate" true
test_secret "Test Certificate" "$test_cert" "certificate" false
test_secret "Valid Private Key" "$valid_key" "private_key" true 
test_secret "Test Private Key" "$test_key" "private_key" false

# Test that non-secrets are ignored
test_secret "Non-Secret" "This is just some regular text with no secrets" "No secrets detected" false

# Print summary
echo -e "\n=== Test Summary ==="
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo "Total: $((PASSED + FAILED))"

# Exit with failure if any tests failed
if [ $FAILED -gt 0 ]; then
    exit 1
fi