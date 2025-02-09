# Build stage
FROM golang:1.23-bookworm  AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o github-app ./cmd/app

# Final stage
FROM debian:bookworm-slim

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/github-app .
COPY config.json .

# Create directory for keys
RUN mkdir -p /app/keys

EXPOSE 8080

ENTRYPOINT ["/app/github-app"]