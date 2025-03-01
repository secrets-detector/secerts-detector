# Secrets Detector

A GitHub App that detects and blocks commits containing secrets, with a focus on certificates and private keys. Works with both GitHub.com and GitHub Enterprise.

## Features

- Detects certificates and private keys in commits
- Validates authenticity of detected secrets
- Blocks commits containing valid secrets but allows test/dummy data to pass
- Works with both GitHub.com and GitHub Enterprise
- Real-time feedback via GitHub status checks
- Comprehensive logging to PostgreSQL for audit purposes
- Grafana dashboards for monitoring detection metrics
- Expandable architecture to support additional secret types in the future

## Architecture

The system consists of several components:

- **GitHub App**: Receives webhooks from GitHub, processes push events, and updates commit statuses
- **Validation Service**: Analyzes content to detect and validate certificates and private keys
- **PostgreSQL Database**: Stores detection logs for auditing and reporting
- **Grafana**: Provides dashboards for monitoring and analytics

## Prerequisites

- Docker and Docker Compose
- GitHub App credentials (App ID, Installation ID, Private Key, Webhook Secret)
- For GitHub Enterprise: Enterprise instance URL and credentials

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-org/secrets-detector
cd secrets-detector
```

### 2. Set up GitHub App

1. Create a GitHub App on GitHub.com or your Enterprise instance:
   - Go to GitHub Settings > Developer Settings > GitHub Apps
   - Create New GitHub App
   - Set permissions:
     - Repository contents: Read
     - Pull requests: Read & Write
     - Commit statuses: Read & Write
   - Subscribe to webhook events:
     - Push
   - Generate and download private key
   - Note your App ID and Installation ID

2. Place your private key in the `keys` directory:
```bash
# For GitHub.com
cp /path/to/downloaded/private-key.pem keys/github.pem

# For GitHub Enterprise (if using)
cp /path/to/enterprise/private-key.pem keys/enterprise.pem
```

### 3. Configure environment variables

Create a `.env` file in the project root:

```bash
# GitHub.com
GITHUB_APP_ID=your_app_id
GITHUB_INSTALLATION_ID=your_installation_id
GITHUB_WEBHOOK_SECRET=your_webhook_secret

# GitHub Enterprise (optional)
GITHUB_ENTERPRISE_HOST=github.your-company.com
GITHUB_ENTERPRISE_APP_ID=your_enterprise_app_id
GITHUB_ENTERPRISE_INSTALLATION_ID=your_enterprise_installation_id
GITHUB_ENTERPRISE_WEBHOOK_SECRET=your_enterprise_webhook_secret

# Database (change as needed)
DB_HOST=postgres
DB_PORT=5432
DB_USER=secretsuser
DB_PASSWORD=secretspass
DB_NAME=secretsdb
```

## Building and Running

### Local Development

1. Start all services using Docker Compose:

```bash
docker-compose up -d
```

2. Verify all services are running:

```bash
docker-compose ps
```

### Production Deployment

For production deployments, we recommend:

1. Building the containers:

```bash
docker-compose build
```

2. Using a container orchestration system like Kubernetes:

```bash
# Example: Push to registry
docker-compose push

# Example: Deploy to Kubernetes
kubectl apply -f k8s/
```

## Configuration

### Detection Patterns

Detection patterns are defined in `config/config.json`. The default configuration includes patterns for:

- Certificates
- Private keys

To add additional patterns, edit this file and add new regular expressions to the `patterns` section.

### Database Schema

The database schema is defined in `db/init.sql` and includes tables for:

- Repositories
- Secret detections
- Validation history
- Views for reporting and analytics

## Testing

### Unit Tests

Run individual component tests:

```bash
go test ./cmd/app
go test ./cmd/service
go test ./pkg/db
```

### Integration Tests

We provide two test scripts to verify the system works correctly:

1. Test secret detection:

```bash
chmod +x test_secrets.sh
./test_secrets.sh
```

2. Test webhook handling:

```bash
chmod +x test_webhook.sh
./test_webhook.sh
```

### Manual Testing

To manually test a webhook:

1. Ensure the system is running with `docker-compose up -d`
2. Create a mock webhook payload:

```json
{
  "ref": "refs/heads/main",
  "before": "6113728f27ae82c7b1a177c8d03f9e96e0adf246",
  "after": "6113728f27ae82c7b1a177c8d03f9e96e0adf247",
  "repository": {
    "name": "test-repo",
    "owner": {
      "name": "test-owner"
    }
  },
  "commits": [
    {
      "id": "6113728f27ae82c7b1a177c8d03f9e96e0adf247",
      "message": "Test commit"
    }
  ]
}
```

3. Send the webhook with the proper signatures:

```bash
# Replace 'your_webhook_secret' with the actual secret
SIGNATURE=$(echo -n '<your_payload>' | openssl sha1 -hmac "your_webhook_secret" | sed 's/^.* //')

curl -X POST http://localhost:3000/webhook \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: push" \
  -H "X-Hub-Signature: sha1=$SIGNATURE" \
  -d @payload.json
```

## Usage

### Configuring GitHub Webhooks

1. In your GitHub App settings, set the webhook URL to your deployed instance:
   - For local testing with forwarding: `https://your-domain.ngrok.io/webhook`
   - For production: `https://your-production-domain.com/webhook`

2. Set the webhook secret to match your `GITHUB_WEBHOOK_SECRET` environment variable

3. Subscribe to the following events:
   - Push

### Viewing Dashboards

Grafana dashboards are available at:

- Local: http://localhost:3001
- Default credentials: admin/admin

## Extending

### Adding New Secret Types

To add support for additional secret types:

1. Add the regex pattern to `config/config.json`
2. Implement validation logic in `cmd/service/main.go` 
3. Update tests as needed

### Customizing Validation Rules

Validation rules are defined in `cmd/service/main.go`. To customize:

1. Modify the validation functions for certificates or private keys
2. Add new validation functions for additional secret types
3. Update the webhook handler to process the new validations

## Troubleshooting

Common issues and solutions:

### Database Connection Failures

Check database connectivity:

```bash
docker-compose exec postgres psql -U secretsuser -d secretsdb -c "SELECT 1"
```

### GitHub Webhook Errors

Verify webhook processing:

1. Check logs: `docker-compose logs github-app`
2. Verify webhook signature calculation in `test_webhook.sh`

### Service Connectivity Issues

Ensure services can communicate:

```bash
docker-compose exec github-app curl -v validation-service:8080/validate
```

## License

MIT License - See LICENSE file for details.