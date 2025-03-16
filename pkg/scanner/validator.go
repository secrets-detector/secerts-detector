package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"secrets-detector/pkg/models"
)

// Validator handles content validation using the validation service
type Validator struct {
	url    string
	token  string
	client *http.Client
	logger *log.Logger
}

// NewValidator creates a new validator
func NewValidator(url, token string, logger *log.Logger) *Validator {
	// Create base HTTP transport
	transport := &http.Transport{
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Check if TLS verification should be skipped
	if os.Getenv("TLS_SKIP_VERIFY") == "true" {
		tlsConfig.InsecureSkipVerify = true
		logger.Printf("Warning: TLS certificate verification is disabled")
	} else {
		// Load CA certificate if provided
		caCertFile := os.Getenv("CA_CERT_FILE")
		if caCertFile != "" {
			logger.Printf("Loading CA certificate from: %s", caCertFile)

			caCert, err := os.ReadFile(caCertFile)
			if err != nil {
				logger.Printf("Error reading CA certificate: %v", err)
			} else {
				caCertPool := x509.NewCertPool()
				if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
					logger.Printf("Failed to add CA certificate to pool")
				} else {
					tlsConfig.RootCAs = caCertPool
					logger.Printf("Added CA certificate to trust store")
				}
			}
		} else {
			logger.Printf("Warning: CA_CERT_FILE not set, using system certificates")
		}
	}

	// Configure mTLS if enabled
	certFile := os.Getenv("TLS_CLIENT_CERT_FILE")
	keyFile := os.Getenv("TLS_CLIENT_KEY_FILE")
	if certFile != "" && keyFile != "" {
		logger.Printf("Loading client certificates for mTLS from: %s, %s", certFile, keyFile)

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			logger.Printf("Error loading client certificates: %v", err)
		} else {
			tlsConfig.Certificates = []tls.Certificate{cert}
			logger.Printf("Added client certificates for mTLS")
		}
	}

	// Apply TLS configuration to transport
	transport.TLSClientConfig = tlsConfig

	// Create HTTP client with the configured transport
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	return &Validator{
		url:    url,
		token:  token,
		client: client,
		logger: logger,
	}
}

// ValidateContent sends content to the validation service to check for secrets
func (v *Validator) ValidateContent(ctx context.Context, content string) ([]models.SecretFinding, error) {
	reqBody := struct {
		Content string `json:"content"`
	}{
		Content: content,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Ensure URL has a proper protocol prefix
	requestURL := v.url
	if !strings.HasPrefix(requestURL, "http://") && !strings.HasPrefix(requestURL, "https://") {
		// Default to HTTPS if TLS is likely enabled (check environment or config)
		if v.isTLSEnabled() {
			requestURL = fmt.Sprintf("https://%s", requestURL)
		} else {
			requestURL = fmt.Sprintf("http://%s", requestURL)
		}
	}

	// Ensure URL has the /validate endpoint
	if !strings.HasSuffix(requestURL, "/validate") {
		requestURL = fmt.Sprintf("%s/validate", requestURL)
	}

	v.logger.Printf("Sending validation request to: %s", requestURL)

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, "POST", requestURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if v.token != "" {
		req.Header.Set("X-API-Key", v.token)
	}

	// Send request
	resp, err := v.client.Do(req)
	if err != nil {
		// Provide more detailed error for TLS issues
		if strings.Contains(err.Error(), "x509") || strings.Contains(err.Error(), "tls") {
			v.logger.Printf("TLS error: %v", err)
			return nil, fmt.Errorf("TLS error connecting to validation service: %w", err)
		}
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("validation service returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var response struct {
		Findings []models.SecretFinding `json:"findings"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return response.Findings, nil
}

// Helper method to check if TLS is enabled
func (v *Validator) isTLSEnabled() bool {
	// Check if the transport has TLS configuration
	if transport, ok := v.client.Transport.(*http.Transport); ok {
		return transport.TLSClientConfig != nil && transport.TLSClientConfig.RootCAs != nil
	}

	// Alternatively, check environment variables
	_, tlsEnabled := os.LookupEnv("TLS_ENABLED")
	_, mtlsEnabled := os.LookupEnv("MTLS_ENABLED")
	_, caCertExists := os.LookupEnv("CA_CERT_FILE")

	return tlsEnabled || mtlsEnabled || caCertExists
}
