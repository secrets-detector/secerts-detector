# Secrets Detector Helm Chart

This Helm chart deploys the Secrets Detector application, which scans GitHub repositories for secrets, certificates, and sensitive tokens in committed code.

## Architecture

The application consists of two main components:

1. **GitHub App** - Receives webhooks from GitHub and processes repository events
2. **Validation Service** - Validates detected secrets to determine if they are legitimate issues

This architecture uses a managed database (e.g., AWS Aurora PostgreSQL, Azure Database for PostgreSQL, Google Cloud SQL) for storing detection results.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+
- A registered GitHub App with appropriate permissions
- A managed PostgreSQL-compatible database instance
- An Ingress controller for webhook endpoint exposure

## Local Development

### Development Environment Setup

1. **Prerequisites**:
   - Go 1.23+
   - Docker and Docker Compose
   - kubectl
   - A local Kubernetes cluster (minikube, kind, or Docker Desktop)
   - Git

2. **Clone the repository**:
   ```bash
   git clone https://github.com/your-org/secrets-detector.git
   cd secrets-detector
   ```

3. **Set up local GitHub App for development**:
   - Create a new GitHub App in your personal GitHub account
   - Set Webhook URL to your local development environment (can use ngrok for this)
   - Download the private key
   - Copy the `.env.example` file to `.env` and update with your GitHub App details:
     ```
     GITHUB_APP_ID=<your-app-id>
     GITHUB_INSTALLATION_ID=<your-installation-id>
     GITHUB_WEBHOOK_SECRET=<your-webhook-secret>
     TEST_MODE=true  # For easier local development
     ```

4. **Set up local PostgreSQL**:
   ```bash
   # Start local PostgreSQL database
   docker-compose up -d postgres
   
   # Initialize database schema
   cat db/init.sql | docker exec -i $(docker-compose ps -q postgres) psql -U secretsuser -d secretsdb
   ```

### Running the Application Locally

1. **Run with Docker Compose (easiest method)**:
   ```bash
   # Start all services
   docker-compose up -d
   
   # View logs
   docker-compose logs -f
   ```

2. **Run the services directly for development**:
   ```bash
   # Terminal 1: Run the validation service
   cd cmd/service
   go run main.go
   
   # Terminal 2: Run the GitHub App
   cd cmd/app
   go run main.go
   ```

3. **Expose webhook endpoint with ngrok**:
   ```bash
   # Install ngrok if you haven't already
   # Expose local port 3000 to the internet
   ngrok http 3000
   
   # Update your GitHub App's webhook URL with the ngrok URL
   # e.g., https://a1b2c3d4.ngrok.io/webhook
   ```

### Local Testing with Mock Webhooks

For development without connecting to GitHub:

1. **Enable test mode in your `.env` file**:
   ```
   TEST_MODE=true
   MOCK_FILES_MODE=true
   ```

2. **Use the test scripts to send mock webhooks**:
   ```bash
   # Test a push event
   ./test_webhook.sh
   
   # Test secret detection
   ./test_secrets.sh
   ```

3. **Manually test the validation endpoint**:
   ```bash
   curl -X POST http://localhost:8080/validate \
     -H "Content-Type: application/json" \
     -d '{"content":"-----BEGIN CERTIFICATE-----\nMIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL\n-----END CERTIFICATE-----"}'
   ```

### Developing with Kubernetes

1. **Install Kind (Kubernetes in Docker) if you haven't already**:
   ```bash
   go install sigs.k8s.io/kind@latest
   ```

2. **Create a local cluster**:
   ```bash
   kind create cluster --name secrets-detector
   ```

3. **Build and load the Docker images into Kind**:
   ```bash
   # Build the images
   docker build -t secrets-detector/github-app:dev -f Dockerfile.app .
   docker build -t secrets-detector/validation-service:dev -f Dockerfile.service .
   
   # Load the images into Kind
   kind load docker-image secrets-detector/github-app:dev --name secrets-detector
   kind load docker-image secrets-detector/validation-service:dev --name secrets-detector
   ```

4. **Deploy to the local cluster**:
   ```bash
   # Create namespace
   kubectl create namespace secrets-dev
   
   # Install chart with development values
   helm install secrets-detector ./secrets-detector \
     -f ./secrets-detector/environments/dev.yaml \
     -n secrets-dev
   ```

5. **Forward ports for local testing**:
   ```bash
   kubectl port-forward -n secrets-dev svc/secrets-detector-github-app 3000:80
   ```

## Testing

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
   # Start the required services for integration tests
   docker-compose up -d postgres
   
   # Run integration tests
   go test -tags=integration -v ./...
   ```

3. **End-to-end tests**:
   ```bash
   # Run E2E tests that simulate GitHub webhooks
   ./test_full_file_analysis.sh
   ./test_diff_mode.sh
   ```

### Test Coverage

Generate test coverage reports:

```bash
# Generate coverage report
go test -coverprofile=coverage.out ./...

# View coverage in browser
go tool cover -html=coverage.out
```

### Code Quality Checks

```bash
# Install golangci-lint if you haven't already
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run linting
golangci-lint run

# Check for security issues
gosec ./...
```

## Building and Releasing

### Building Docker Images

```bash
# Build the GitHub App
docker build -t secrets-detector/github-app:latest -f Dockerfile.app .

# Build the Validation Service
docker build -t secrets-detector/validation-service:latest -f Dockerfile.service .

# Tag with version number for release
docker tag secrets-detector/github-app:latest secrets-detector/github-app:v1.0.0
docker tag secrets-detector/validation-service:latest secrets-detector/validation-service:v1.0.0
```

### Publishing Helm Chart

```bash
# Package the Helm chart
helm package ./secrets-detector -d ./charts

# Update the Helm repository index
helm repo index ./charts
```

## Contribution Guide

We welcome contributions to the Secrets Detector project! This guide will help you get started.

### Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

### Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally
3. **Create a new branch** from the `main` branch
4. **Make your changes**
5. **Submit a pull request**

### Development Workflow

1. **Create an issue** describing the bug or feature
2. **Discuss the implementation** with maintainers
3. **Implement the changes** on your branch
4. **Write tests** for your changes
5. **Update documentation** as needed
6. **Submit a pull request**

### Pull Request Process

1. **Check the guidelines**:
   - Create a descriptive title that summarizes the change
   - Reference the related issue(s)
   - Update documentation and tests

2. **Code Review**:
   - A maintainer will review your code
   - Address any feedback or questions
   - Make requested changes

3. **Continuous Integration**:
   - Ensure all CI checks pass
   - Fix any issues that arise

4. **Merging**:
   - A maintainer will merge your PR once approved
   - Your contribution will be included in the next release

### Coding Standards

1. **Go Code**:
   - Follow the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
   - Use `gofmt` to format your code
   - Document exported functions, types, and constants

2. **Helm Chart**:
   - Follow [Helm Best Practices](https://helm.sh/docs/chart_best_practices/)
   - Keep templates clean and readable
   - Use helpers for repetitive code

3. **Commit Messages**:
   - Use the imperative mood ("Add feature" not "Added feature")
   - Keep the first line under 50 characters
   - Reference issue numbers when applicable

### Testing Requirements

All contributions must include appropriate tests:

1. **New Features**:
   - Unit tests for isolated functionality
   - Integration tests for component interaction
   - End-to-end tests for user workflows

2. **Bug Fixes**:
   - Tests that reproduce the bug
   - Tests that verify the fix

3. **Test Coverage**:
   - Aim for >80% test coverage for new code
   - Don't break existing tests

### Documentation Requirements

Update documentation for any user-facing changes:

1. **Code Documentation**:
   - Document all exported types, functions, and methods
   - Include examples where appropriate

2. **README and User Docs**:
   - Update user instructions if behavior changes
   - Add new configuration options to README

3. **Architecture Docs**:
   - Update architecture diagrams for significant changes
   - Document design decisions for major features

### Security Considerations

Security is a top priority for this project:

1. **Security Review**:
   - All code that handles sensitive information will undergo security review
   - Secret handling code must follow security best practices

2. **Dependency Management**:
   - Keep dependencies up to date
   - Avoid adding unnecessary dependencies

3. **Vulnerability Reporting**:
   - If you discover a security vulnerability, please follow our [Security Policy](SECURITY.md)
   - Do not report security vulnerabilities via public GitHub issues

### License

By contributing to this project, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).

## Installation

### Creating the GitHub App

Before deploying the Helm chart, you need to create a GitHub App in your organization:

1. In your GitHub organization, go to Settings → Developer settings → GitHub Apps → New GitHub App
2. Configure your app with the following settings:
   - **Name**: Secrets Detector
   - **Homepage URL**: Your organization's URL
   - **Webhook URL**: Leave blank temporarily - we'll update after deployment
   - **Webhook Secret**: Generate a secure random string (use a password generator with 32+ characters)
   - **Permissions**:
     - Repository permissions:
       - **Contents**: Read-only (needed to read repository content)
       - **Metadata**: Read-only
       - **Pull requests**: Read-only
     - Organization permissions:
       - **Members**: Read-only
   - **Subscribe to events**:
     - Push
     - Pull request
3. Create the app and note your:
   - App ID
   - Installation ID (after installing the app to your org)
   - Generate and download a private key

> **Security Note**: Store the private key securely. Treat it as a critical secret and never commit it to version control.
   
### Securely Storing GitHub App Credentials

For production environments, store your GitHub App credentials securely:

**Option 1: Using Kubernetes Secrets with RBAC (basic approach)**

```bash
# Create a namespace with restricted access
kubectl create namespace secrets-detector

# Create secret
kubectl create secret generic github-app-credentials \
  --namespace secrets-detector \
  --from-file=github.pem=/path/to/private-key.pem \
  --from-literal=webhook-secret=your-webhook-secret \
  --from-literal=app-id=your-app-id \
  --from-literal=installation-id=your-installation-id

# Restrict access to the namespace using RBAC
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secrets-manager
  namespace: secrets-detector
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
  resourceNames: ["github-app-credentials"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: secrets-manager-binding
  namespace: secrets-detector
subjects:
- kind: ServiceAccount
  name: secrets-detector
  namespace: secrets-detector
roleRef:
  kind: Role
  name: secrets-manager
  apiGroup: rbac.authorization.k8s.io
EOF
```

**Option 2: Using AWS Secrets Manager (recommended for production)**

```bash
# Store secrets in AWS Secrets Manager
aws secretsmanager create-secret \
  --name github-app-secrets \
  --secret-string '{"webhook-secret":"your-webhook-secret","app-id":"your-app-id","installation-id":"your-installation-id"}'

# Upload the private key separately
aws secretsmanager put-secret-value \
  --secret-id github-app-secrets \
  --secret-binary fileb:///path/to/private-key.pem
```

Then install [External Secrets Operator](https://external-secrets.io/) to sync with Kubernetes:

```bash
# Install External Secrets Operator
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets \
  -n external-secrets --create-namespace

# Configure the External Secret
cat <<EOF | kubectl apply -f -
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: github-app-credentials
  namespace: secrets-detector
spec:
  refreshInterval: "1h"
  secretStoreRef:
    name: aws-secretsmanager
    kind: ClusterSecretStore
  target:
    name: github-app-credentials
  data:
  - secretKey: webhook-secret
    remoteRef:
      key: github-app-secrets
      property: webhook-secret
  - secretKey: app-id
    remoteRef:
      key: github-app-secrets
      property: app-id
  - secretKey: installation-id
    remoteRef:
      key: github-app-secrets
      property: installation-id
  - secretKey: github.pem
    remoteRef:
      key: github-app-secrets
      property: github.pem
EOF
```

**Option 3: Hashicorp Vault (for multi-cloud or hybrid environments)**

```bash
# Assuming Vault is installed via the Helm chart
kubectl exec -it vault-0 -- /bin/sh

# Inside vault pod
vault kv put secret/github-app/credentials \
  webhook-secret="your-webhook-secret" \
  app-id="your-app-id" \
  installation-id="your-installation-id" \
  private-key=@/path/to/private-key.pem
```

### Database Credentials Management

For production, use a similar approach to secure database credentials:

```bash
# For AWS RDS with IAM authentication (recommended)
aws secretsmanager create-secret \
  --name rds-credentials \
  --secret-string '{"username":"dbuser","password":"strong-password","host":"your-db.cluster-id.region.rds.amazonaws.com","port":"5432","dbname":"secretsdb"}'
```

### Deploying the Helm Chart

1. Clone the repository:

```bash
git clone https://github.com/your-org/secrets-detector.git
cd secrets-detector
```

2. Deploy to the development environment:

```bash
# Create namespace
kubectl create namespace secrets-dev

# Install chart with development values
helm install secrets-detector ./secrets-detector \
  -f ./secrets-detector/environments/dev.yaml \
  -n secrets-dev
```

3. Deploy to production:

```bash
# Create namespace
kubectl create namespace secrets-prod

# Install chart with production values
helm install secrets-detector ./secrets-detector \
  -f ./secrets-detector/environments/prod.yaml \
  -n secrets-prod \
  --set database.host=your-db-host.rds.amazonaws.com \
  --set database.credentialsSecret=prod-db-credentials \
  --set githubApp.githubSecret.existingSecret=github-app-credentials
```

4. Update the webhook URL in your GitHub App settings once the ingress is provisioned:
   - Get your ingress URL: `kubectl get ingress -n secrets-prod`
   - Add `/webhook` path to the URL and update in GitHub App settings

## Configuration

### Environment-specific Values

This chart supports multiple environments through values files:

- `values.yaml` - Default configuration
- `environments/dev.yaml` - Development environment
- `environments/test.yaml` - Test environment
- `environments/staging.yaml` - Staging environment
- `environments/prod.yaml` - Production environment

To use:

```bash
helm install secrets-detector ./secrets-detector -f ./secrets-detector/environments/prod.yaml -n prod
```

### Important Production Settings

For production deployments, ensure you set:

1. **Database Configuration**
   ```yaml
   database:
     host: "prod-aurora-postgres.rds.amazonaws.com"
     credentialsSecret: "prod-db-credentials"
   ```

2. **GitHub App Credentials**
   ```yaml
   githubApp:
     githubSecret:
       existingSecret: "github-app-credentials"
   ```

3. **Ingress Configuration**
   ```yaml
   ingress:
     enabled: true
     className: "alb" # Or appropriate for your cluster
     annotations:
       kubernetes.io/ingress.class: alb
       alb.ingress.kubernetes.io/scheme: internet-facing
       alb.ingress.kubernetes.io/listen-ports: '[{"HTTPS":443}]'
       alb.ingress.kubernetes.io/certificate-arn: "arn:aws:acm:region:account-id:certificate/cert-id"
   ```

## Enterprise Security Best Practices

### Private Key Security

- **Never commit private keys** to your repository
- Use a secrets management system (AWS Secrets Manager, HashiCorp Vault, etc.)
- Rotate keys every 60-90 days (GitHub recommends this for Apps)
- Implement key rotation without downtime:
  
  ```bash
  # 1. Generate new private key in GitHub App settings
  # 2. Store the new key in your secrets management system
  # 3. Update the Kubernetes secret with both old and new keys
  kubectl create secret generic github-app-credentials-new \
    --from-file=github.pem=/path/to/new-private-key.pem \
    --from-literal=webhook-secret=your-webhook-secret \
    --from-literal=app-id=your-app-id \
    --from-literal=installation-id=your-installation-id
  
  # 4. Update the deployment to use the new secret
  kubectl patch deployment secrets-detector-github-app -n secrets-prod \
    -p '{"spec":{"template":{"spec":{"volumes":[{"name":"keys-volume","secret":{"secretName":"github-app-credentials-new"}}]}}}}'
  
  # 5. After verifying everything works, delete the old key from GitHub
  ```

### Webhook Security

1. **Always use HTTPS** for webhook endpoints
2. Use a **strong webhook secret** (32+ random characters)
3. Validate the webhook signature in your code
4. Protect your webhook endpoint with network policies
5. Consider using a WAF in front of your webhook endpoint
   ```yaml
   # In values.yaml for AWS WAF
   ingress:
     annotations:
       alb.ingress.kubernetes.io/wafv2-acl-arn: "arn:aws:wafv2:region:account-id:regional/webacl/name/id"
   ```

### Network Security

1. **Restrict Pod Communication** with NetworkPolicies:
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: github-app-network-policy
     namespace: secrets-prod
   spec:
     podSelector:
       matchLabels:
         app.kubernetes.io/component: github-app
     policyTypes:
     - Ingress
     - Egress
     ingress:
     - from:
       - namespaceSelector:
           matchLabels:
             name: ingress-controller
     egress:
     - to:
       - podSelector:
           matchLabels:
             app.kubernetes.io/component: validation-service
     - to:
       # Allow GitHub API access
       - ipBlock:
           cidr: 0.0.0.0/0
         ports:
         - port: 443
           protocol: TCP
   ```

2. **Secure Database Connection**:
   - Use SSL/TLS for database connections (verify-full mode)
   - Store database credentials in a secure secret manager
   - Ensure database is not publicly accessible
   - Use IAM authentication for AWS RDS when possible
   - Configure appropriate security groups or VPC endpoints

### RBAC Configuration

Apply the principle of least privilege to your Kubernetes RBAC:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: secrets-detector
  namespace: secrets-prod
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secrets-detector-role
  namespace: secrets-prod
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
  resourceNames: ["github-app-credentials", "db-credentials"]
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get"]
  resourceNames: ["secrets-detector-config"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: secrets-detector-rolebinding
  namespace: secrets-prod
subjects:
- kind: ServiceAccount
  name: secrets-detector
  namespace: secrets-prod
roleRef:
  kind: Role
  name: secrets-detector-role
  apiGroup: rbac.authorization.k8s.io
```

### Audit Trail

Enable audit logging to track all interactions with secrets:

```yaml
githubApp:
  config:
    logLevel: info
    auditEnabled: true
```

Ship logs to a centralized logging system:

1. **AWS CloudWatch**:
   - Deploy the CloudWatch agent
   - Configure log forwarding
   
2. **ELK Stack**:
   - Deploy Filebeat DaemonSet
   - Configure log shipping to Elasticsearch
   
3. **Cloud-based Logging**:
   - Datadog, New Relic, etc.

### Monitoring and Alerting

Set up monitoring with Prometheus and Grafana:

```bash
# Install Prometheus stack
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring --create-namespace

# Create ServiceMonitor for your app
cat <<EOF | kubectl apply -f -
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: secrets-detector
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: secrets-detector
  namespaceSelector:
    matchNames:
      - secrets-prod
  endpoints:
  - port: http
    interval: 30s
    path: /metrics
EOF
```

Set up alerts for:
- High error rates
- Detection of valid secrets
- Service unavailability
- Database connectivity issues

### Compliance Considerations

For regulated environments:

1. **Data Retention**:
   - Configure database retention policies
   - Set up data lifecycle management
   
2. **Access Controls**:
   - Implement strict RBAC
   - Use multi-factor authentication for cluster access
   
3. **Encryption**:
   - Enable encryption at rest for database
   - Use TLS for all communications
   
4. **Audit**:
   - Maintain comprehensive audit logs
   - Regularly review access patterns

## Disaster Recovery

### Backup and Restore

1. **Database Backup**:
   - For AWS RDS:
     ```bash
     # Create DB snapshot
     aws rds create-db-snapshot \
       --db-instance-identifier your-db-identifier \
       --db-snapshot-identifier backup-$(date +%Y%m%d)
     ```
   
2. **Application Configuration**:
   - Back up Kubernetes resources:
     ```bash
     kubectl get secret github-app-credentials -n secrets-prod -o yaml > github-app-credentials.yaml
     kubectl get configmap secrets-detector-config -n secrets-prod -o yaml > config.yaml
     ```

3. **Recovery Procedure**:
   - Restore database from snapshot
   - Reapply Kubernetes resources
   - Verify webhook connectivity

### High Availability

The chart includes configuration for HA deployments:

- Multiple replicas
- Pod anti-affinity
- Pod disruption budgets
- Topology spread constraints

Ensure these are properly configured in your production environment.

## Troubleshooting

### Common Issues

1. **Webhook delivery failures**
   - Check the Ingress configuration
   - Verify webhook secret matches GitHub App settings
   - Inspect GitHub App logs with: `kubectl logs -f -l app.kubernetes.io/component=github-app -n your-namespace`

2. **Database connection failures**
   - Verify database credentials
   - Check if database is accessible from the cluster
   - Check network policies allowing database communication

3. **Scaling issues**
   - Check HPA metrics with: `kubectl get hpa -n your-namespace`
   - Verify resource requests and limits are set appropriately

### Logging

Access logs for debugging:

```bash
# GitHub App logs
kubectl logs -f -l app.kubernetes.io/component=github-app -n secrets-prod

# Validation Service logs
kubectl logs -f -l app.kubernetes.io/component=validation-service -n secrets-prod
```

## Upgrading

To upgrade the chart:

```bash
helm upgrade secrets-detector ./secrets-detector -f ./secrets-detector/environments/prod.yaml -n prod
```

For major version upgrades, always check the upgrade notes in CHANGELOG.md.

## License

This chart is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.