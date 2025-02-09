#!/bin/bash

# Test payload
PAYLOAD='{
    "ref": "refs/heads/main",
    "before": "6113728f27ae82c7b1a177c8d03f9e96e0adf246",
    "after": "6113728f27ae82c7b1a177c8d03f9e96e0adf247",
    "repository": {
        "full_name": "owner/repo",
        "name": "repo",
        "owner": {
            "login": "owner"
        }
    }
}'

# Generate signature using webhook secret from .env
source .env
SIGNATURE=$(echo -n "$PAYLOAD" | openssl sha1 -hmac "$GITHUB_WEBHOOK_SECRET" | sed 's/^.* //')

# Create curl command
echo "curl -X POST http://localhost:3000/webhook \\"
echo "  -H \"Content-Type: application/json\" \\"
echo "  -H \"X-GitHub-Event: push\" \\"
echo "  -H \"X-Hub-Signature: sha1=$SIGNATURE\" \\"
echo "  -d '$PAYLOAD'"