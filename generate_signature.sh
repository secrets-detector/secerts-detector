#!/bin/bash

# Test payload with content that includes secrets
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
    },
    "commits": [
        {
            "id": "6113728f27ae82c7b1a177c8d03f9e96e0adf247",
            "message": "add config",
            "added": ["config.txt"],
            "modified": [],
            "removed": []
        }
    ]
}'

# Generate signature using webhook secret from .env
source .env
SIGNATURE=$(echo -n "$PAYLOAD" | openssl sha1 -hmac "$GITHUB_WEBHOOK_SECRET" | sed 's/^.* //')

# Make the request
curl -X POST http://localhost:3000/webhook \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: push" \
  -H "X-Hub-Signature: sha1=$SIGNATURE" \
  -d "$PAYLOAD"