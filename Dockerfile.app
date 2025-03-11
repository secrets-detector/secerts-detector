# Build stage
FROM amazonlinux:2023.6.20250218.2 AS builder

# Install Go 1.24.1 and necessary build tools
RUN yum install -y tar gzip wget shadow-utils && \
    wget https://go.dev/dl/go1.24.1.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.24.1.linux-amd64.tar.gz && \
    rm go1.24.1.linux-amd64.tar.gz && \
    yum clean all && \
    rm -rf /var/cache/yum

# Set Go environment variables
ENV PATH="/usr/local/go/bin:${PATH}" \
    GOPATH="/go" \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

# Create app directory and set it as working directory
WORKDIR /src

# Copy go mod files and download dependencies first (better layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application with security flags
RUN go build -ldflags="-s -w -extldflags=-static" -o github-app ./cmd/app

# Final stage - minimal production image
FROM amazonlinux:2023.6.20250218.2

# Add labels for better maintainability
LABEL maintainer="Security Team" \
      description="GitHub Secrets Detector App" \
      version="1.0"

# Install minimal runtime dependencies and create non-root user
RUN yum update -y && \
    yum install -y ca-certificates tzdata shadow-utils && \
    yum clean all && \
    rm -rf /var/cache/yum && \
    mkdir -p /app/keys && \
    adduser -r -u 1000 appuser && \
    chown -R appuser:appuser /app

# Set working directory
WORKDIR /app

# Copy only the necessary files from the builder stage
COPY --from=builder --chown=appuser:appuser /src/github-app /app/
COPY --from=builder --chown=appuser:appuser /src/config/config.json /app/config/

# Switch to non-root user
USER appuser

# Expose application port
EXPOSE 8080

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/validate || exit 1

# Set entrypoint
ENTRYPOINT ["/app/github-app"]