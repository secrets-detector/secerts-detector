# Secrets Detector

A security scanning application that detects and validates sensitive information in GitHub repositories. It identifies secrets, certificates, and API tokens committed to code repositories, helping protect your organization from credential leaks and security breaches.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Docker Compose Deployment](#docker-compose-deployment)
  - [Setting Up Your .env File](#setting-up-your-env-file)
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

For local development:
  - Go 1.23+
  - Docker and Docker Compose
  - Git
  - OpenSSL (for certificate generation)

## 🚀 Installation

### Docker Compose Deployment

1. **Clone the repository**:
```bash
git clone https://github.com/your-org/secrets-detector.git
cd secrets-detector
```

2. **Configure environment variables**:
```bash
cp .env.example .env
# Edit the .env file with your GitHub App credentials and other configuration
```

3. **Generate TLS certificates** (for secure service communication):
```bash
./test-tls-cert-creation.sh
```

4. **Start the services**:
```bash
docker-compose up -d
```

5. **Update your GitHub App webhook URL** to point to your Docker host: `http://your-server:3000/webhook`

6. **Access the Grafana dashboard** at `http://localhost:3001` (default credentials: admin/admin)

### Setting Up Your .env File

The `.env` file contains all the configuration settings for the application. Here's a detailed guide to set it up properly:

1. **Copy the example file**:
   ```bash
   cp .env.example .env
   ```

2. **GitHub Authentication**: You must configure at least one of these authentication methods:
   ```
   # Option 1: Personal Access Token (simplest method)
   GITHUB_TOKEN=your_github_token_here
   
   # Option 2: GitHub App Authentication
   GITHUB_APP_ID=12345
   GITHUB_INSTALLATION_ID=67890
   ```
   - For GitHub App authentication, you'll also need to place your private key in `./keys/github.pem`

3. **GitHub Enterprise Configuration** (optional):
   ```
   # Only needed for GitHub Enterprise
   GITHUB_BASE_URL=https://github.yourcompany.com/api/v3/
   ```

4. **Scanner Configuration**:
   ```
   SCANNER_CONCURRENCY=5         # Number of parallel scanning operations
   SCANNER_BATCH_SIZE=10         # Commits to process in a batch
   SCANNER_MAX_DEPTH=1000        # Maximum commit history depth 
   SCANNER_SCAN_PRIVATE=true     # Whether to scan private repositories
   SCANNER_RATE_LIMIT=5000       # GitHub API rate limit to respect
   SCANNER_PAUSE_TIME=60         # Pause time in seconds when rate limited
   ```

5. **Repository Filtering**:
   ```
   EXCLUDE_REPOS=archived-repo,test-repo  # Comma-separated list of repos to ignore
   EXCLUDE_ORGS=third-party-org           # Comma-separated list of orgs to ignore
   ```

6. **Debug Mode**:
   ```
   DEBUG_MODE=false              # Enable for verbose logging
   ```

7. **Security Settings**:
   ```
   # TLS Configuration
   TLS_ENABLED=true              # Enable TLS for validation service
   MTLS_ENABLED=true             # Enable mutual TLS for service-to-service auth
   
   # Blocking behavior
   BLOCK_COMMITS=true            # Whether to block commits with real secrets
   ```

8. **API Keys and Secrets**:
   ```
   # Used for service-to-service authentication
   VALIDATION_API_KEY=your-secure-api-key-here
   
   # For GitHub webhook verification
   GITHUB_WEBHOOK_SECRET=your-webhook-secret-here
   ```

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

3. **Configure the webhook URL** to point to your Docker host: `http://your-server:3000/webhook`

### Environment Variables

The application can be configured using environment variables (see the .env file setup section above). Key variables include:

**GitHub App:**
- `GITHUB_APP_ID` - The ID of your GitHub App
- `GITHUB_INSTALLATION_ID` - The installation ID of your GitHub App
- `GITHUB_WEBHOOK_SECRET` - Secret used to validate webhook payloads
- `GITHUB_TOKEN` - Alternative to GitHub App for simpler setup
- `LOG_LEVEL` - Logging level (debug, info, warn, error)
- `FULL_FILE_ANALYSIS` - Analyze full files rather than just diffs (true/false)
- `BLOCK_COMMITS` - Whether to block commits containing secrets (true/false)

**Validation Service:**
- `TLS_ENABLED` - Enable TLS (true/false)
- `MTLS_ENABLED` - Enable mutual TLS (true/false)
- `API_KEY` - API key for service-to-service authentication

**Database:**
- `DB_HOST` - Database host (default: postgres)
- `DB_PORT` - Database port (default: 5432)
- `DB_USER` - Database username (default: secretsuser)
- `DB_PASSWORD` - Database password (default: secretspass)
- `DB_NAME` - Database name (default: secretsdb)

### Secrets Management

Your `.env` file should never be committed to version control. Here are best practices for managing secrets:

1. **Use .gitignore**: Ensure `.env` is included in your `.gitignore` file
2. **Use environment variables**: For production, prefer environment variables instead of .env files
3. **Rotate secrets regularly**: Change your GitHub webhook secrets and API keys periodically

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

### Integration Testing

You can use the provided scripts to test different aspects of the system:

```bash
# Test full file analysis mode
./test_full_file_analysis.sh

# Test diff analysis mode
./diff-test-script.sh

# Test GitHub Advanced Security integration
./test-ghas-integration.sh

# Test secure service communication
./test-secure-service-comms.sh
```

## 🔒 Security

### TLS Configuration

The application supports TLS and mutual TLS (mTLS) for secure communication between services:

1. **Generate certificates** for development:
   ```bash
   ./test-tls-cert-creation.sh
   ```

2. **Configure TLS** in your .env file:
   ```
   TLS_ENABLED=true
   TLS_CERT_FILE=/app/certs/server.crt
   TLS_KEY_FILE=/app/certs/server.key
   ```

3. **Enable mutual TLS** for service-to-service authentication:
   ```
   MTLS_ENABLED=true
   CA_CERT_FILE=/app/certs/ca.crt
   ```

### Secure Service Communication

The services communicate securely using:

1. **mTLS** - Both services authenticate each other using certificates
2. **API Key Authentication** - The GitHub App must provide a valid API key when calling the Validation Service
3. **Secure HTTP Headers** - Only specific HTTP headers are allowed

### Secrets Storage

Sensitive information is handled securely:

1. **GitHub App Private Keys** - Stored in `./keys/github.pem` (never commit to version control)
2. **Database Credentials** - Stored in .env file (never commit to version control)
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