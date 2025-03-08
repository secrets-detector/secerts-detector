#!/bin/bash

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}===== Generating TLS Certificates for Development =====${NC}"

# Create directories for certificates
mkdir -p ./certs/{ca,validation-service,github-app}

# Change to the certs directory
cd ./certs

# Generate CA Key and Certificate
echo -e "${BLUE}Generating CA Certificate...${NC}"
openssl genrsa -out ca/ca.key 4096
openssl req -new -x509 -key ca/ca.key -sha256 -subj "/CN=Secrets-Detector-CA" -days 365 -out ca/ca.crt

# Generate Validation Service Key and CSR
echo -e "${BLUE}Generating Validation Service Certificate...${NC}"
openssl genrsa -out validation-service/validation-service.key 2048
openssl req -new -key validation-service/validation-service.key -subj "/CN=validation-service" -out validation-service/validation-service.csr

# Create config for SAN (Subject Alternative Names)
cat > validation-service/validation-service.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = validation-service
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

# Sign Validation Service Certificate with CA
openssl x509 -req -in validation-service/validation-service.csr \
    -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial \
    -out validation-service/validation-service.crt -days 365 \
    -sha256 -extfile validation-service/validation-service.ext

# Generate GitHub App Key and CSR
echo -e "${BLUE}Generating GitHub App Certificate...${NC}"
openssl genrsa -out github-app/github-app.key 2048
openssl req -new -key github-app/github-app.key -subj "/CN=github-app" -out github-app/github-app.csr

# Create config for SAN
cat > github-app/github-app.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = github-app
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

# Sign GitHub App Certificate with CA
openssl x509 -req -in github-app/github-app.csr \
    -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial \
    -out github-app/github-app.crt -days 365 \
    -sha256 -extfile github-app/github-app.ext

# Set appropriate permissions
chmod 400 ca/ca.key validation-service/validation-service.key github-app/github-app.key
chmod 444 ca/ca.crt validation-service/validation-service.crt github-app/github-app.crt

echo -e "${GREEN}Certificates generated successfully!${NC}"
echo
echo "Files created:"
echo "  - CA certificate: ./certs/ca/ca.crt"
echo "  - CA key: ./certs/ca/ca.key"
echo "  - Validation Service certificate: ./certs/validation-service/validation-service.crt"
echo "  - Validation Service key: ./certs/validation-service/validation-service.key"
echo "  - GitHub App certificate: ./certs/github-app/github-app.crt"
echo "  - GitHub App key: ./certs/github-app/github-app.key"
echo
echo "To use these certificates in your Docker Compose setup, update your docker-compose.yaml file to mount these certificates and set the appropriate environment variables."