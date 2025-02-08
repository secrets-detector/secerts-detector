# Secrets Detector

A GitHub Enterprise pre-receive hook application that detects and validates potential secrets in code commits.

## Features

- Detects various types of secrets using configurable regex patterns
- Validates detected secrets through a dedicated validation service
- Blocks commits containing valid secrets
- Supports custom validation rules and patterns
- Configurable notifications via email and Slack
- Docker-based deployment

## Installation and Setup

### 1. Build and Run using Docker Compose

Build the images:
```bash
docker-compose build
```

Start the services:
```bash
docker-compose up -d
```

### 2. GitHub Enterprise Integration

Configure the pre-receive hook on your GitHub Enterprise server:
```bash
docker cp secret-validator:/app/secret-validator /github/data/git-hooks/pre-receive.d/
chmod +x /github/data/git-hooks/pre-receive.d/secret-validator
```

### 3. Configuration

Create a `config.json` file with your settings:
```json
{
    "patterns": {
        "aws_key": "AKIA[0-9A-Z]{16}",
        "private_key": "-----BEGIN\\s*(?:RSA|DSA|EC|OPENSSH|PRIVATE)\\s*KEY-----",
        "certificate": "-----BEGIN\\s*CERTIFICATE-----",
        "github_token": "gh[pos]_[0-9a-zA-Z]{36}"
    },
    "api": {
        "validate_endpoint": "http://validation-service:8080/validate",
        "token": "your-auth-token-here"
    }
}
```

### 4. Environment Variables

Required environment variables:
- `VALIDATION_SERVICE_URL`: URL of the validation service
- `GIN_MODE`: Gin framework mode (development/release)
- `PORT`: Port for the validation service

## Testing

### Local Testing

View logs:
```bash
docker-compose logs -f
```

Test the validation service:
```bash
curl -X POST http://localhost:8080/validate \
  -H "Content-Type: application/json" \
  -d '{
    "secret": {
      "type": "certificate",
      "value": "-----BEGIN CERTIFICATE-----..."
    }
  }'
```

To run the tests:
```
# Run all tests
go test ./...

# Run tests with coverage
go test ./... -cover

# Run specific test
go test ./cmd/validator -run TestValidateContent

# Run tests with verbose output
go test -v ./...
```

### Validation Rules

The service validates several types of secrets:
- SSL/TLS Certificates
- Private Keys (RSA, DSA, EC)
- API Keys
- Authentication Tokens

## Security Considerations

- The validator container requires git command access
- The validation service runs on port 8080
- Services communicate over a dedicated Docker network
- Configuration and logs are managed through Docker volumes
- Multi-stage builds are used to minimize image size

## Scaling

To scale the application:
- Add a load balancer for the validation service
- Deploy using Docker Swarm or Kubernetes
- Implement health checks
- Add monitoring and alerting

## Project Structure

```
secrets-detector/
├── Dockerfile.validator
├── Dockerfile.service
├── docker-compose.yml
├── main.go
├── validation_service.go
├── go.mod
├── go.sum
└── config/
    └── config.json
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your c