#!/bin/bash

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Generate a webhook signature
generate_signature() {
    local payload=$1
    local secret=$2
    echo -n "$payload" | openssl sha1 -hmac "$secret" | sed 's/^.* //'
}

# Function to test webhook with different payloads
test_webhook() {
    local test_name=$1
    local diff_content=$2
    local expected_block=$3  # true or false
    local webhook_secret=${4:-"dummysecret"}

    echo -e "\nTesting webhook: ${test_name}..."
    
    # Create webhook payload with the diff content
    payload=$(cat <<EOF
{
  "ref": "refs/heads/main",
  "before": "6113728f27ae82c7b1a177c8d03f9e96e0adf246",
  "after": "6113728f27ae82c7b1a177c8d03f9e96e0adf247",
  "repository": {
    "id": 123456,
    "name": "test-repo",
    "full_name": "test-org/test-repo",
    "owner": {
      "name": "test-org",
      "email": "test@example.com",
      "login": "test-org",
      "type": "Organization"
    }
  },
  "pusher": {
    "name": "test-user",
    "email": "test-user@example.com"
  },
  "commits": [
    {
      "id": "6113728f27ae82c7b1a177c8d03f9e96e0adf247",
      "message": "Test commit",
      "timestamp": "2025-02-09T10:00:00Z",
      "author": {
        "name": "Test User",
        "email": "test@example.com"
      },
      "added": ["test.txt"],
      "modified": [],
      "removed": [],
      "patch": "${diff_content}"
    }
  ]
}
EOF
)

    # Generate signature
    signature=$(generate_signature "$payload" "$webhook_secret")

    # Send the webhook request
    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "X-GitHub-Event: push" \
        -H "X-Hub-Signature: sha1=$signature" \
        -H "X-GitHub-Delivery: $(uuidgen)" \
        -d "$payload" \
        http://localhost:3000/webhook)

    # Check response for expected behavior
    if [[ $expected_block == true && $response == *"failure"* ]] || 
       [[ $expected_block == false && $response == *"success"* ]]; then
        echo -e "${GREEN}✓ Test passed: ${test_name}${NC}"
        return 0
    else
        echo -e "${RED}✗ Test failed: ${test_name}${NC}"
        echo "Expected block: $expected_block"
        echo "Got response: $response"
        return 1
    fi
}

# Run webhook tests
echo "Starting webhook tests..."

PASSED=0
FAILED=0

# Test valid certificate in commit (should be blocked)
valid_cert="diff --git a/cert.pem b/cert.pem
new file mode 100644
index 0000000..abcd1234
--- /dev/null
+++ b/cert.pem
@@ -0,0 +1,30 @@
+-----BEGIN CERTIFICATE-----
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

if test_webhook "Valid Certificate" "$valid_cert" true; then
    ((PASSED++))
else
    ((FAILED++))
fi

# Test certificate labeled as test (should be allowed)
test_cert="diff --git a/testcert.pem b/testcert.pem
new file mode 100644
index 0000000..abcd1234
--- /dev/null
+++ b/testcert.pem
@@ -0,0 +1,30 @@
+-----BEGIN CERTIFICATE-----
+MIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL
+BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
+GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA1MTUxMjAwMDBaFw0yNDA1
+MTQxMjAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
+HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
+AQUAA4IBDwAwggEKAoIBAQDUMbTESTAMSIQmHRtXmOxVVnpAIrTYo1DvOXKQ8jPg
+fz2kQV9ABAuqI+z0v4mgLTUb7MIZ6lEHKjWLy+BQBlwRNdScOHpbhkFiv1RPq5Cn
+kjEoVpCvehFELFEH3a1fuwYOkPnT3yzFrXWEI5h3QXR5LJgIpc1J/HOdWo3hm3CK
+tz2BDv+KCWlb+rN/fiuKHmaEFP1QG/TbifXO+ns1BfhTcnXg5nY0I8IM4GnYHXEX
+YyEPtFWBwx8g0rYKL+NXvjo8NUyn2RRpT9+nKIKu7QSM1qy0xUBPydADQ5X1+reK
+TESTCERTIFICATE123
+OI5TXpRzZsMfYxCrpZPVsRZvC2Zp+OL6wYEuAgMBAAGjUzBRMB0GA1UdDgQWBBSP
+M4RLzCu3HAwxsS7dIlWH80bFujAfBgNVHSMEGDAWgBSPM4RLzCu3HAwxsS7dIlWH
+80bFujAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB8XqqJLG50
+-----END CERTIFICATE-----"

if test_webhook "Test Certificate" "$test_cert" false; then
    ((PASSED++))
else
    ((FAILED++))
fi

# Test valid private key (should be blocked)
valid_key="diff --git a/key.pem b/key.pem
new file mode 100644
index 0000000..abcd1234
--- /dev/null
+++ b/key.pem
@@ -0,0 +1,30 @@
+-----BEGIN PRIVATE KEY-----
+MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCz5HbiHPPGtYd5
+Lcix2lCcOF0bnPOSdJV0jxFG36vZFF1eeTuiloxWymtZ6R695lhWfnUtDuoxeL9t
+RmQYxEgK982MEQpoearvijpd99piLXZ1ZVXvEU0X1/Dy6hOAFD9CCFUwO8OH4S4Y
+p1LjZwfaQ9bEjm52EC9RMQg4JSk1vYmtnKsycUdOny6CSbrrbbVS/us6xIW2GTzh
+H2kl0E10nZtrS50cuanA18kE6GTq1iY9RWF+jgF1Eb2szW8XOyptmuigOaKXYmFR
+aosREhTWZX3v+AOEvn6U6EaCDh7gBMRNfTX/hcpuZYqVga4f7zCGPDiFC8cM4TKG
+10OvYsiNAgMBAAECggEAFbGROZratgWZqP4hs/r7Gh+88LHIeMqo5FXFdFnQWD0Z
+tmUh0S1dDrFZ6U2Q2L9Au2uEF3MzQFSKpzOkKg1vj60LA19htTAo8jql58OWOR04
+6hbWml4ogR3YL38Va25lo4GsPkUSwx3faHczKnu4CXUBXxI7FW9FuYGTd2vZ0KJP
+SBh39dQUerfdA/KOkCnU0JyRIwOXDTvB5ieN/mILHuLSAqe3SN/pQUaw6fOSsrJ+
+1u5VKemHPIg7JHYY0F3s4R/iI5cxagLN66/lGfqz/AJptpnMBhM2Wo5JeoUj4vwY
+YeSvN8ZmMPanPQDPguzi5Djvro2PNsMq/saNnge9QQKBgQDXQhJTTq7qWDtFYynO
+-----END PRIVATE KEY-----"

if test_webhook "Valid Private Key" "$valid_key" true; then
    ((PASSED++))
else
    ((FAILED++))
fi

# Test private key labeled as test (should be allowed)
test_key="diff --git a/testkey.pem b/testkey.pem
new file mode 100644
index 0000000..abcd1234
--- /dev/null
+++ b/testkey.pem
@@ -0,0 +1,30 @@
+-----BEGIN PRIVATE KEY-----
+MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDeuIu63xvBLIrz
+nDn0LqUJDCrKBvhklDGan3H9m4fsG5uLOVR1WUY8LHQpK6kSQlMGdgOBFXfCTgsl
+L3+XvUTPr78t7xTZSQkpMBZVvEOzGlLFtQwUCw/+Mm9mYLKGQHfz4JvP2nXpOJVZ
+HmSSh3TKhtQ9Cgg4TESTPRIVATEKEY123JGkynK9rPF6iEjR38nXPa2E5
+8DBv9hU8DZlG3WrJJgUVQR2knK0kRZ0U+HQJ2fGLtK7jWIAgUPlPMdHCJQEFO8k7
+8X2+AHkdlQfIj5k7mJeKV4EUQ+jgDgZEQPUQDsl4O86leuoGEAOREj+Ey6wFmiT+
+0Xgz0XotAgMBAAECggEAaxY4LZXPVqEoZ5gXXgESXB9H3ntMPVzD2X53XJ9MQnpJ
+KQHGI29o2j5zy7zGABU3UZ14PYbm4ByP+IVHkETHPPSH3XjJX6T3aGOk/OAM5WTJ
+QqPTWZU5Dg/AUNx/kZ8MWvf5wR3+3QGlK6jY5B3p3+TCNzGr0TlxZXYGQNf5UfKd
+jXfIrTGZZeIwSPUmapVgdMQIYl0UHnYKsJYuY9s0P0WfEKbZKfc7FTFxzb8tVLR0
+kJIfXBJOeUk9K0p4PRZMZVm5EdYGebII74wREuUhwbLxzyfL1TkF/MdQYo4eBUQf
+YwGYJjkG/JXafpwjBWg8CBHSEOGddMuYTk89y5kzuQKBgQDxa6cz/xZfID6K7oPn
+-----END PRIVATE KEY-----"

if test_webhook "Test Private Key" "$test_key" false; then
    ((PASSED++))
else
    ((FAILED++))
fi

# Test non-secret commit (should be allowed)
nonsecret="diff --git a/README.md b/README.md
new file mode 100644
index 0000000..abcd1234
--- /dev/null
+++ b/README.md
@@ -0,0 +1,5 @@
+# Test Project
+
+This is a test project with no secrets.
+
+Nothing to see here!"

if test_webhook "Non-Secret Commit" "$nonsecret" false; then
    ((PASSED++))
else
    ((FAILED++))
fi

# Print summary
echo -e "\n=== Webhook Test Summary ==="
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo "Total: $((PASSED + FAILED))"

# Exit with failure if any tests failed
if [ $FAILED -gt 0 ]; then
    exit 1
fi