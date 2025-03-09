# Secrets Detector

A security scanning application that detects and validates sensitive information in GitHub repositories. It identifies secrets, certificates, and API tokens committed to code repositories, helping protect your organization from credential leaks and security breaches.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Kubernetes Deployment with Helm](#kubernetes-deployment-with-helm)
  - [Docker Compose Deployment](#docker-compose-deployment)
- [Configuration](#configuration)
  - [GitHub App Setup](#github-app-setup)
  - [Environment Variables](#environment-variables)
  - [Secrets Management](#secrets-management)
- [Local Development](#local-development)
  - [Development Environment Setup](#development-environment-setup)
  - [Running the Services Locally](#running-the-services-locally)
  - [Debug and Testing Tools](#debug-and-testing-tools)
- [Testing](#testing)
  - [Running Tests](#running-tests)
  - [Test Coverage](#test-coverage)
  - [Integration Testing](#integration-testing)
- [Security](#security)
  - [TLS Configuration](#tls-configuration)
  - [Secure Service Communication](#secure-service-communication)
  - [Secrets Storage](#secrets-storage)
- [Contributing](#contributing)
  - [Development Workflow](#development-workflow)
  - [Pull Request Process](#pull-request-process)
  - [Coding Standards](#coding-standards)
- [License](#license)

## 🔍 Overview

The Secrets Detector scans GitHub repositories for committed secrets, certificates, and API tokens. When detected, these items are validated to determine if they are legitimate secrets or test/dummy data. Real secrets can be blocked from being committed, protecting your organization from accidental credential leaks.

### Key Features

- **Automated Secret Detection**: Scans repository content for various types of sensitive information
- **Validation Engine**: Distinguishes between real secrets and test/dummy data
- **GitHub Integration**: Works as a GitHub App to process repository events
- **Push Protection**: Can block commits containing real secrets
- **Visualization**: Includes Grafana dashboards for monitoring and reporting
- **GitHub Advanced Security Integration**: Compatible with GitHub's security features

## 🏗️ Architecture

The application consists of several key components:

1. **GitHub App** - A service that receives webhook events from GitHub, processes the repository content, and detects potential secrets. Written in Go, it communicates with GitHub's API and your repositories.

2. **Validation Service** - A separate service that validates detected secrets to determine if they are legitimate issues or test/dummy data. It employs various validation techniques for different types of secrets.

3. **Database** - A PostgreSQL database stores detection results, repository information, and validation history.

4. **Grafana Dashboard** - Visualization and monitoring of detection metrics and repository risk.

The components communicate securely using mutual TLS authentication and API keys for service-to-service communication.

## 📋 Prerequisites

- **For Kubernetes deployment:**
  - Kubernetes 1.19+
  - Helm 3.2.0+
  - A registered GitHub App with appropriate permissions
  - A PostgreSQL-compatible database (AWS Aurora PostgreSQL, Azure Database, etc.)
  - An Ingress controller for webhook endpoint exposure

- **For local development:**
  - Go 1.23+
  - Docker and Docker Compose
  - Git
  - OpenSSL (for certificate generation)

## 🚀 Installation

### Kubernetes Deployment with Helm

1. **Register a GitHub App** in your organization with the following permissions:
   - Repository contents: Read
   - Metadata: Read
   - Pull requests: Read
   - Subscribe to events: Push, Pull request

2. **Get your GitHub App credentials**:
   - App ID
   - Installation ID
   - Private key (download and save securely)
   - Generate a webhook secret

3. **Install using Helm**:

```bash
# Add the Helm repository (if applicable)
# helm repo add secrets-detector https://your-helm-repo.example.com
# helm repo update

# Create namespace
kubectl create namespace secrets-detector

# Create a secret for GitHub App credentials
kubectl create secret generic github-app-credentials \
  --namespace secrets-detector \
  --from-file=github.pem=/path/to/private-key.pem \
  --from-literal=webhook-secret=your-webhook-secret \
  --from-literal=app-id=your-app-id \
  --from-literal=installation-id=your-installation-id

# Create a secret for database credentials
kubectl create secret generic db-credentials \
  --namespace secrets-detector \
  --from-literal=DB_USER=your-db-user \
  --from-literal=DB_PASSWORD=your-db-password

# Install the Helm chart
helm install secrets-detector ./secrets-detector \
  --namespace secrets-detector \
  --set database.host=your-db-host.example.com \
  --set database.credentialsSecret=db-credentials \
  --set githubApp.githubSecret.existingSecret=github-app-credentials
```

4. **Configure your GitHub App webhook URL**:
   - After deployment, get your ingress URL: `kubectl get ingress -n secrets-detector`
   - Update your GitHub App settings with the webhook URL: `https://your-ingress-url/webhook`

### Docker Compose Deployment

For development or smaller deployments, you can use Docker Compose:

1. **Clone the repository**:
```bash
git clone https://github.com/your-org/secrets-detector.git
cd secrets-detector
```

2. **Configure environment variables**:
```bash
cp .env.example .env
# Edit .env with your GitHub App credentials and other configuration
```

3. **Generate TLS certificates** (if using mTLS):
```bash
./test-tls-cert-creation.sh
```

4. **Start the services**:
```bash
docker-compose up -d
```

5. **Update your GitHub App webhook URL** to point to your Docker host: `http://your-server:3000/webhook`

## ⚙️ Configuration

### GitHub App Setup

1. **Create a GitHub App** in your organization:
   - Navigate to Settings → Developer settings → GitHub Apps → New GitHub App
   - Set the name, homepage URL, and webhook URL
   - Set permissions:
     - Repository contents: Read
     - Metadata: Read
     - Pull requests: Read
   - Subscribe to events: Push, Pull request
   - Generate and download a private key

2. **Install the app** to your organization or specific repositories

### Environment Variables

The application can be configured using environment variables:

**GitHub App:**
- `GITHUB_APP_ID` - The ID of your GitHub App
- `GITHUB_INSTALLATION_ID` - The installation ID of your GitHub App
- `GITHUB_WEBHOOK_SECRET` - Secret used to validate webhook payloads
- `GITHUB_ENTERPRISE_HOST` - (Optional) For GitHub Enterprise deployments
- `LOG_LEVEL` - Logging level (debug, info, warn, error)
- `TEST_MODE` - Enable test mode (true/false)
- `FULL_FILE_ANALYSIS` - Analyze full files rather than just diffs (true/false)
- `BLOCK_COMMITS` - Whether to block commits containing secrets (true/false)

**Validation Service:**
- `GIN_MODE` - Gin framework mode (debug, release)
- `TLS_ENABLED` - Enable TLS (true/false)
- `MTLS_ENABLED` - Enable mutual TLS (true/false)
- `TLS_CERT_FILE` - Path to TLS certificate
- `TLS_KEY_FILE` - Path to TLS key
- `CA_CERT_FILE` - Path to CA certificate for mTLS

**Database:**
- `DB_HOST` - Database host
- `DB_PORT` - Database port
- `DB_USER` - Database username
- `DB_PASSWORD` - Database password
- `DB_NAME` - Database name

### Secrets Management

For production deployments, we recommend using a secure secrets management solution:

**Kubernetes Secrets with RBAC:**
```bash
kubectl create secret generic github-app-credentials \
  --namespace secrets-detector \
  --from-file=github.pem=/path/to/private-key.pem \
  --from-literal=webhook-secret=your-webhook-secret \
  --from-literal=app-id=your-app-id \
  --from-literal=installation-id=your-installation-id
```

**AWS Secrets Manager:**
```bash
aws secretsmanager create-secret \
  --name github-app-secrets \
  --secret-string '{"webhook-secret":"your-webhook-secret","app-id":"your-app-id","installation-id":"your-installation-id"}'
```

**HashiCorp Vault:**
```bash
vault kv put secret/github-app/credentials \
  webhook-secret="your-webhook-secret" \
  app-id="your-app-id" \
  installation-id="your-installation-id" \
  private-key=@/path/to/private-key.pem
```

## 💻 Local Development

### Development Environment Setup

1. **Prerequisites**:
   - Go 1.23+
   - Docker and Docker Compose
   - Git

2. **Clone the repository**:
   ```bash
   git clone https://github.com/your-org/secrets-detector.git
   cd secrets-detector
   ```

3. **Generate TLS certificates** for secure communication:
   ```bash
   ./test-tls-cert-creation.sh
   ```

4. **Set up environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Set up a local GitHub App** for testing:
   - Create a new GitHub App in your personal GitHub account
   - Set permissions and webhook URL (can use ngrok)
   - Download the private key and update your .env file

### Running the Services Locally

1. **Using Docker Compose**:
   ```bash
   # Start all services
   docker-compose up -d
   
   # View logs
   docker-compose logs -f
   ```

2. **Running individual services** for development:
   ```bash
   # Run the validation service
   cd cmd/service
   go run main.go
   
   # Run the GitHub App
   cd cmd/app
   go run main.go
   ```

3. **Expose webhook endpoint** for testing with GitHub:
   ```bash
   # Using ngrok to expose local port 3000
   ngrok http 3000
   
   # Update your GitHub App's webhook URL with the ngrok URL
   # e.g., https://a1b2c3d4.ngrok.io/webhook
   ```

### Debug and Testing Tools

The repository includes several scripts for testing and debugging:

- `test_full_file_analysis.sh` - Tests full file analysis mode
- `diff-test-script.sh` - Tests diff-only mode
- `test-ghas-integration.sh` - Tests GitHub Advanced Security integration
- `test-secure-service-comms.sh` - Tests secure communication between services
- `debug-test-script` - Helps debug and trace issues with the application

## 🧪 Testing

### Running Tests

1. **Unit tests**:
   ```bash
   # Run all unit tests
   go test -v ./...
   
   # Run specific package tests
   go test -v ./pkg/models/...
   ```

2. **Integration tests**:
   ```bash
   # Start required services
   docker-compose up -d postgres
   
   # Run integration tests
   go test -tags=integration -v ./...
   ```

3. **End-to-end tests**:
   ```bash
   # Run E2E tests with simulated GitHub webhooks
   ./test_full_file_analysis.sh
   ./diff-test-script.sh
   ```

### Test Coverage

Generate and view test coverage reports:

```bash
# Generate coverage report
go test -coverprofile=coverage.out ./...

# View coverage in browser
go tool cover -html=coverage.out
```

### Code Quality

Ensure code quality with linting tools:

```bash
# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run linting
golangci-lint run

# Check for security issues
gosec ./...
```

## 🔒 Security

### TLS Configuration

The application supports TLS and mutual TLS (mTLS) for secure communication between services:

1. **Generate certificates** for development:
   ```bash
   ./test-tls-cert-creation.sh
   ```

2. **Configure TLS** in the docker-compose.yaml file:
   ```yaml
   environment:
     - TLS_ENABLED=true
     - TLS_CERT_FILE=/app/certs/server.crt
     - TLS_KEY_FILE=/app/certs/server.key
   ```

3. **Enable mutual TLS** for service-to-service authentication:
   ```yaml
   environment:
     - MTLS_ENABLED=true
     - CA_CERT_FILE=/app/certs/ca.crt
   ```

### Secure Service Communication

The services communicate securely using:

1. **mTLS** - Both services authenticate each other using certificates
2. **API Key Authentication** - The GitHub App must provide a valid API key when calling the Validation Service
3. **Secure HTTP Headers** - Only specific HTTP headers are allowed

### Secrets Storage

Sensitive information is handled securely:

1. **GitHub App Private Keys** - Stored as Kubernetes secrets or in external secret managers
2. **Database Credentials** - Stored as Kubernetes secrets or in external secret managers
3. **Webhook Secrets** - Used to validate incoming webhooks from GitHub

## 👥 Contributing

We welcome contributions to improve the Secrets Detector! Here's how to get started:

### Development Workflow

1. **Create an issue** describing the bug or feature
2. **Discuss the implementation** with maintainers
3. **Implement the changes** on your branch
4. **Write tests** for your changes
5. **Update documentation** as needed
6. **Submit a pull request**

### Pull Request Process

1. **Create a descriptive pull request** that references related issues
2. **Ensure all tests pass** and code quality checks succeed
3. **Update documentation** as needed
4. **Wait for code review** from maintainers
5. **Address any feedback** from the review
6. **Maintainers will merge** approved pull requests

### Coding Standards

1. **Go Code**:
   - Follow [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
   - Use `gofmt` to format your code
   - Document exported functions, types, and constants

2. **Commit Messages**:
   - Use the imperative mood ("Add feature" not "Added feature")
   - Keep the first line under 50 characters
   - Reference issue numbers when applicable

3. **Testing Requirements**:
   - Write unit tests for new functionality
   - Maintain or improve test coverage
   - Include integration tests for complex features

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.