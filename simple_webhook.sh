#!/bin/bash

# Use a very simple, minimal payload with no whitespace variations
WEBHOOK_SECRET="development_webhook_secret_123"
PAYLOAD='{"event":"test"}'

# Use a few different methods to calculate the signature
SIG1=$(echo -n "$PAYLOAD" | openssl dgst -sha1 -hmac "$WEBHOOK_SECRET" | sed 's/^.* //')
SIG2=$(echo -n "$PAYLOAD" | openssl dgst -binary -sha1 -hmac "$WEBHOOK_SECRET" | xxd -p | tr -d '\n')

echo "Testing webhook with minimal payload"
echo "Secret: $WEBHOOK_SECRET"
echo "Payload: $PAYLOAD"
echo "Signature 1: $SIG1"
echo "Signature 2: $SIG2"

# Try with the first signature method
echo -e "\nAttempt 1: Using text digest output"
curl -v -X POST \
  http://localhost:3000/webhook \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: ping" \
  -H "X-Hub-Signature: sha1=$SIG1" \
  -d "$PAYLOAD"

echo -e "\n\nAttempt 2: Using binary->hex conversion"
curl -v -X POST \
  http://localhost:3000/webhook \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: ping" \
  -H "X-Hub-Signature: sha1=$SIG2" \
  -d "$PAYLOAD"

# Try one more with a direct validation endpoint test
echo -e "\n\nAttempt 3: Testing validation endpoint directly"
curl -v -X POST \
  http://localhost:3000/validate \
  -H "Content-Type: application/json" \
  -d '{"content":"-----BEGIN CERTIFICATE-----\nMIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL\n-----END CERTIFICATE-----"}'