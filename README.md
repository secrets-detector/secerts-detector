# Secrets Detector

A GitHub App that detects and blocks commits containing secrets, sensitive information, and credentials. Works with both GitHub.com and GitHub Enterprise.

## Features

- Detects various types of secrets (AWS keys, certificates, API tokens, etc.)
- Validates authenticity of detected secrets
- Blocks commits containing valid secrets
- Works with both GitHub.com and GitHub Enterprise
- Supports multiple GitHub instances simultaneously
- Real-time feedback via GitHub status checks

## Prerequisites

- Go 1.21 or higher
- Docker and Docker Compose
- GitHub App credentials
- GitHub Enterprise (optional)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/your-org/secrets-detector
cd secrets-detector
```

2. Install dependencies:
```bash
go mod download
```

3. Create configuration:
```bash
# Copy example config
cp config.example.json config.json

# Edit with your settings
vim config.json
```

## Configuration

### GitHub.com Setup

1. Create a GitHub App:
   - Go to GitHub Settings > Developer Settings > GitHub Apps
   - Create New GitHub App
   - Set permissions:
     - Repository contents: Read
     - Pull requests: Read & Write
     - Commit statuses: Read & Write
   - Generate and download private key
   - Note your App ID and Installation ID

2. Configure environment variables:
```bash
export GITHUB_APP_ID=your_app_id
export GITHUB_INSTALLATION_ID=your_installation_id
export GITHUB_WEBHOOK_SECRET=your_webhook_secret
```

3. Place your private key:
```bash
cp /path/to/downloaded/private-key.pem private-key.pem
```

### GitHub Enterprise Setup

1. Create Enterprise GitHub App:
   - Access your GitHub Enterprise instance
   - Follow same steps as GitHub.com app creation
   - Note Enterprise-specific credentials

2. Configure Enterprise environment:
```bash
export GITHUB_ENTERPRISE_HOST=github.your-company.com
export GITHUB_ENTERPRISE_APP_ID=your_enterprise_app_id
export GITHUB_ENTERPRISE_INSTALLATION_ID=your_enterprise_installation_id
export GITHUB_ENTERPRISE_WEBHOOK_SECRET=your_enterprise_webhook_secret
```

## Running Locally

1. Start the services:
```bash
docker-compose up -d
```

2. Test the validation service:
```bash
curl -X POST http://localhost:8080/validate \
  -H "Content-Type: application/json" \
  -d '{
    "secret": {
      "type": "aws_key",
      "value": "AKIAIOSFODNN7EXAMPLE"
    }
  }'
```

3. Test webhook handling:
```bash
# GitHub.com webhook
curl -X POST http://localhost:8080/webhook \
  -H "X-GitHub-Event: push" \
  -H "X-Hub-Signature: sha1=..." \
  -d @test/fixtures/push-event.json

# Enterprise webhook
curl -X POST http://localhost:8080/webhook \
  -H "X-GitHub-Event: push" \
  -H "X-GitHub-Enterprise-Host: github.your-company.com" \
  -H "X-Hub-Signature: sha1=..." \
  -d @test/fixtures/push-event.json
```

## Testing

Run the test suite:
```bash
go test ./...
```

Run with coverage:
```bash
go test -cover ./...
```

## Production Deployment

1. Build the containers:
```bash
docker-compose build
```

2. Deploy using your preferred method:
```bash
# Example: Push to registry
docker-compose push

# Example: Deploy to Kubernetes
kubectl apply -f k8s/
```

3. Configure webhooks in GitHub:
   - Set Webhook URL to your deployed instance
   - Configure secret
   - Select events (push, pull request)

## Contributing

### Development Process

1. Fork the repository
2. Create a feature branch
```bash
git checkout -b feature/your-feature-name
```

3. Make your changes:
   - Follow Go best practices
   - Add tests for new functionality
   - Update documentation
   - Run linter: `golangci-lint run`

4. Commit your changes:
```bash
git add .
git commit -m "feat: add your feature"
```

5. Push and create a Pull Request
```bash
git push origin feature/your-feature-name
```

### Code Style

- Follow standard Go conventions
- Use meaningful variable names
- Add comments for complex logic
- Write unit tests for new code

### Pull Request Process

1. Update the README.md if needed
2. Update the version numbers if applicable
3. Get review from at least one maintainer
4. PRs are merged after passing:
   - CI checks
   - Code review
   - Test coverage requirements

## Support

- Create an issue for bugs
- Discussions for general questions
- Security issues: Contact maintainers directly

## License

MIT License