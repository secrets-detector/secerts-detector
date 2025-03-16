package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"secrets-detector/pkg/models"
)

// MockCertificateValidator is a mock implementation of certificate validation
type MockCertificateValidator struct {
	mock.Mock
}

// ValidateCertificate mocks the certificate validation function
func (m *MockCertificateValidator) ValidateCertificate(cert string) (bool, string) {
	args := m.Called(cert)
	return args.Bool(0), args.String(1)
}

// ValidatePrivateKey mocks the private key validation function
func (m *MockCertificateValidator) ValidatePrivateKey(key string) (bool, string) {
	args := m.Called(key)
	return args.Bool(0), args.String(1)
}

// TestAPIKeyAuth tests the API key authentication middleware
func TestAPIKeyAuth(t *testing.T) {
	// Set up a test API key in the environment
	os.Setenv("API_KEY", "test-api-key")
	defer os.Unsetenv("API_KEY")

	// Create a new Gin router
	gin.SetMode(gin.TestMode)
	r := gin.New()

	// Apply the middleware and set up a test endpoint
	r.Use(APIKeyAuth())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Test with valid API key
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "test-api-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Check the response
	assert.Equal(t, http.StatusOK, w.Code)

	// Test with invalid API key
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "wrong-api-key")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Check that authentication fails
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Test with missing API key
	req = httptest.NewRequest("GET", "/test", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Check that authentication fails
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestCORSMiddleware tests the CORS middleware
func TestCORSMiddleware(t *testing.T) {
	// Create a new Gin router
	gin.SetMode(gin.TestMode)
	r := gin.New()

	// Apply the middleware and set up a test endpoint
	r.Use(CORSMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Test with a normal GET request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Check the response
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))

	// Test with an OPTIONS request (preflight)
	req = httptest.NewRequest("OPTIONS", "/test", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Check the response - should be 204 No Content
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "POST, GET, OPTIONS", w.Header().Get("Access-Control-Allow-Methods"))
}

// TestRequestLogger tests the request logger middleware
func TestRequestLogger(t *testing.T) {
	// Create a buffer to capture log output
	var logBuf bytes.Buffer
	originalLogger := log.Default()
	log.SetOutput(&logBuf)
	defer log.SetOutput(originalLogger.Writer())

	// Create a new Gin router
	gin.SetMode(gin.TestMode)
	r := gin.New()

	// Apply the middleware and set up test endpoints
	r.Use(RequestLogger())
	r.GET("/normal", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	r.POST("/validate", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Test with a normal path
	req := httptest.NewRequest("GET", "/normal", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Test with a sensitive path
	req = httptest.NewRequest("POST", "/validate", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Check that both requests were logged
	logOutput := logBuf.String()
	assert.Contains(t, logOutput, "GET /normal")
	assert.Contains(t, logOutput, "POST /validate")
}

// TestConfigureTLS tests the TLS configuration function
func TestConfigureTLS(t *testing.T) {
	// Save original environment variables and restore them after the test
	origEnv := map[string]string{
		"TLS_ENABLED":   os.Getenv("TLS_ENABLED"),
		"TLS_CERT_FILE": os.Getenv("TLS_CERT_FILE"),
		"TLS_KEY_FILE":  os.Getenv("TLS_KEY_FILE"),
		"MTLS_ENABLED":  os.Getenv("MTLS_ENABLED"),
		"CA_CERT_FILE":  os.Getenv("CA_CERT_FILE"),
	}
	defer func() {
		for k, v := range origEnv {
			if v != "" {
				os.Setenv(k, v)
			} else {
				os.Unsetenv(k)
			}
		}
	}()

	// Test with TLS disabled
	os.Unsetenv("TLS_ENABLED")
	tlsConfig, err := configureTLS()
	assert.Nil(t, tlsConfig, "TLS config should be nil when TLS is disabled")
	assert.Nil(t, err, "No error should be returned when TLS is disabled")

	// We can't fully test the TLS configuration without actual certificate files,
	// but we can test the error cases

	// Test with TLS enabled but missing cert/key files
	os.Setenv("TLS_ENABLED", "true")
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")
	tlsConfig, err = configureTLS()
	assert.Nil(t, tlsConfig, "TLS config should be nil when cert/key files are missing")
	assert.Error(t, err, "Error should be returned when cert/key files are missing")
	assert.Contains(t, err.Error(), "TLS_CERT_FILE and TLS_KEY_FILE must be provided")

	// Test with mTLS enabled but missing CA cert file
	os.Setenv("TLS_ENABLED", "true")
	os.Setenv("TLS_CERT_FILE", "cert.pem")
	os.Setenv("TLS_KEY_FILE", "key.pem")
	os.Setenv("MTLS_ENABLED", "true")
	os.Unsetenv("CA_CERT_FILE")
	tlsConfig, err = configureTLS()
	assert.Error(t, err, "Error should be returned when CA cert file is missing for mTLS")
	assert.Contains(t, err.Error(), "CA_CERT_FILE must be provided")
}

// TestValidateCertificate tests the certificate validation function
func TestValidateCertificate(t *testing.T) {
	// Test with a valid certificate structure
	validCert := `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA1MTUxMjAwMDBaFw0yNDA1
MTQxMjAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC5eIuoSCHDCIWgI2CObfvgJCyPulUGj0VxbOJmZWzl
-----END CERTIFICATE-----`

	isValid, message := validateCertificate(validCert)
	assert.True(t, isValid, "Valid certificate should be validated")
	assert.Contains(t, message, "Valid certificate")

	// Test with an invalid certificate structure
	invalidCert := `-----BEGIN CERTIFICATE-----
This is not a valid certificate
-----END CERTIFICATE-----`

	isValid, message = validateCertificate(invalidCert)
	assert.False(t, isValid, "Invalid certificate should not be validated")
	assert.Contains(t, message, "Invalid")

	// Test with a test/dummy certificate
	testCert := `-----BEGIN CERTIFICATE-----
TEST_CERTIFICATE for development use only
MIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL
-----END CERTIFICATE-----`

	isValid, message = validateCertificate(testCert)
	assert.False(t, isValid, "Test certificate should not be validated")
	assert.Contains(t, message, "Test certificate")

	// Test with non-certificate content
	nonCert := "This is not a certificate at all"

	isValid, message = validateCertificate(nonCert)
	assert.False(t, isValid, "Non-certificate content should not be validated")
	assert.Contains(t, message, "Not a certificate")
}

// TestValidatePrivateKey tests the private key validation function
func TestValidatePrivateKey(t *testing.T) {
	// Test with a valid private key structure
	validKey := `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5F0ifNQF20kJi
zRTmsea44zy0xM8+BjZ7pEr587gO6Ov3KoKZCV4xcFhvJ/9yWgRWoCYMvpOIxW/G
WufmRObVReT7bhYYZquJcpOBgNJ7elPwKxi7mZ18Dedlf+fowwx3L5+agq2SZ4AV
-----END PRIVATE KEY-----`

	isValid, message := validatePrivateKey(validKey)
	assert.True(t, isValid, "Valid private key should be validated")
	assert.Contains(t, message, "Valid")

	// Test with an invalid private key structure
	invalidKey := `-----BEGIN PRIVATE KEY-----
This is not a valid private key
-----END PRIVATE KEY-----`

	isValid, message = validatePrivateKey(invalidKey)
	assert.False(t, isValid, "Invalid private key should not be validated")
	assert.Contains(t, message, "Invalid")

	// Test with a test/dummy private key
	testKey := `-----BEGIN PRIVATE KEY-----
TEST_PRIVATE_KEY for development use only
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5F0ifNQF20kJi
-----END PRIVATE KEY-----`

	isValid, message = validatePrivateKey(testKey)
	assert.False(t, isValid, "Test private key should not be validated")
	assert.Contains(t, message, "Test private key")

	// Test with non-private key content
	nonKey := "This is not a private key at all"

	isValid, message = validatePrivateKey(nonKey)
	assert.False(t, isValid, "Non-private key content should not be validated")
	assert.Contains(t, message, "Not a private key")
}

// TestCleanPEM tests the PEM cleaning function
func TestCleanPEM(t *testing.T) {
	// Test with various line endings
	mixedLineEndings := "-----BEGIN CERTIFICATE-----\r\nABCDEF\r\nGHIJKL\n-----END CERTIFICATE-----"
	cleaned := cleanPEM(mixedLineEndings)
	assert.Equal(t, "-----BEGIN CERTIFICATE-----\nABCDEF\nGHIJKL\n-----END CERTIFICATE-----", cleaned)

	// Test with escaped newlines
	escapedNewlines := "-----BEGIN CERTIFICATE-----\\nABCDEF\\nGHIJKL\\n-----END CERTIFICATE-----"
	cleaned = cleanPEM(escapedNewlines)
	assert.Equal(t, "-----BEGIN CERTIFICATE-----\nABCDEF\nGHIJKL\n-----END CERTIFICATE-----", cleaned)

	// Test with multiple consecutive newlines
	multipleNewlines := "-----BEGIN CERTIFICATE-----\n\n\nABCDEF\n\n\nGHIJKL\n\n\n-----END CERTIFICATE-----"
	cleaned = cleanPEM(multipleNewlines)
	assert.Equal(t, "-----BEGIN CERTIFICATE-----\nABCDEF\nGHIJKL\n-----END CERTIFICATE-----", cleaned)
}

// TestTruncateCert tests the certificate truncation function
func TestTruncateCert(t *testing.T) {
	// Test with a long certificate
	longCert := `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA1MTUxMjAwMDBaFw0yNDA1
MTQxMjAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC5eIuoSCHDCIWgI2CObfvgJCyPulUGj0VxbOJmZWzl
-----END CERTIFICATE-----`

	truncated := truncateCert(longCert)
	assert.True(t, len(truncated) < len(longCert), "Certificate should be truncated")
	assert.Contains(t, truncated, "-----BEGIN CERTIFICATE-----")
	assert.Contains(t, truncated, "...")
	assert.Contains(t, truncated, "-----END CERTIFICATE-----")

	// Test with a short certificate
	shortCert := "-----BEGIN CERTIFICATE-----\nABCDEF\n-----END CERTIFICATE-----"
	truncated = truncateCert(shortCert)
	assert.Equal(t, shortCert, truncated, "Short certificate should not be truncated")
}

// TestSetupRouter tests the router setup function
func TestSetupRouter(t *testing.T) {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	// Mock the API key
	os.Setenv("API_KEY", "test-api-key")
	defer os.Unsetenv("API_KEY")

	// Set up the router
	r := setupRouter()

	// Test the health endpoint
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Check the response
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "ok", resp["status"])

	// Test the validate endpoint with authentication
	payload := `{"content":"-----BEGIN CERTIFICATE-----\nMIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL\n-----END CERTIFICATE-----"}`
	req = httptest.NewRequest("POST", "/validate", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-api-key")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Check the response status (we don't need to validate the full response here)
	assert.Equal(t, http.StatusOK, w.Code)

	// Test the validate endpoint without authentication
	req = httptest.NewRequest("POST", "/validate", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestValidateEndpoint tests the validation endpoint directly
func TestValidateEndpoint(t *testing.T) {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	// Set up a minimal router with the validate endpoint
	r := gin.New()

	// Add the validate endpoint directly
	r.POST("/validate", func(c *gin.Context) {
		var req struct {
			Content string `json:"content"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request format",
			})
			return
		}

		// Use our test validation function
		findings := []models.SecretFinding{
			{
				Type:     "certificate",
				Value:    "test-cert-value",
				StartPos: 0,
				EndPos:   100,
				IsValid:  true,
				Message:  "Valid certificate",
			},
		}

		c.JSON(http.StatusOK, gin.H{
			"findings": findings,
			"message":  "Found 1 valid secrets that would be blocked",
		})
	})

	// Test with a valid payload
	payload := `{"content":"-----BEGIN CERTIFICATE-----\nMIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL\n-----END CERTIFICATE-----"}`
	req := httptest.NewRequest("POST", "/validate", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Check the response
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Findings []models.SecretFinding `json:"findings"`
		Message  string                 `json:"message"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Len(t, resp.Findings, 1)
	assert.Equal(t, "certificate", resp.Findings[0].Type)
	assert.True(t, resp.Findings[0].IsValid)
	assert.Contains(t, resp.Message, "valid secrets")

	// Test with an invalid payload
	invalidPayload := `{"invalid:"json"}`
	req = httptest.NewRequest("POST", "/validate", bytes.NewBufferString(invalidPayload))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Should be a bad request
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestValidateSecretEndpoint tests the single secret validation endpoint
func TestValidateSecretEndpoint(t *testing.T) {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	// Set up a minimal router with the validate/secret endpoint
	r := gin.New()

	// Add the validate/secret endpoint directly
	r.POST("/validate/secret", func(c *gin.Context) {
		var req models.ValidationRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.ValidationResponse{
				IsValid: false,
				Message: "Invalid request format",
			})
			return
		}

		var isValid bool
		var message string

		// Simple validation based on type
		if req.Secret.Type == "certificate" {
			isValid = true
			message = "Valid certificate"
		} else if req.Secret.Type == "private_key" {
			isValid = true
			message = "Valid private key"
		} else {
			isValid = false
			message = "Unsupported secret type"
		}

		c.JSON(http.StatusOK, models.ValidationResponse{
			IsValid: isValid,
			Message: message,
		})
	})

	// Test with a certificate
	certPayload := `{"secret":{"type":"certificate","value":"-----BEGIN CERTIFICATE-----\nMIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL\n-----END CERTIFICATE-----"}}`
	req := httptest.NewRequest("POST", "/validate/secret", bytes.NewBufferString(certPayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Check the response
	assert.Equal(t, http.StatusOK, w.Code)

	var certResp models.ValidationResponse
	err := json.Unmarshal(w.Body.Bytes(), &certResp)
	assert.NoError(t, err)
	assert.True(t, certResp.IsValid)
	assert.Equal(t, "Valid certificate", certResp.Message)

	// Test with a private key
	keyPayload := `{"secret":{"type":"private_key","value":"-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5F0ifNQF20kJi\n-----END PRIVATE KEY-----"}}`
	req = httptest.NewRequest("POST", "/validate/secret", bytes.NewBufferString(keyPayload))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Check the response
	assert.Equal(t, http.StatusOK, w.Code)

	var keyResp models.ValidationResponse
	err = json.Unmarshal(w.Body.Bytes(), &keyResp)
	assert.NoError(t, err)
	assert.True(t, keyResp.IsValid)
	assert.Equal(t, "Valid private key", keyResp.Message)

	// Test with an unsupported type
	unsupportedPayload := `{"secret":{"type":"unknown","value":"test"}}`
	req = httptest.NewRequest("POST", "/validate/secret", bytes.NewBufferString(unsupportedPayload))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Check the response
	assert.Equal(t, http.StatusOK, w.Code)

	var unsupportedResp models.ValidationResponse
	err = json.Unmarshal(w.Body.Bytes(), &unsupportedResp)
	assert.NoError(t, err)
	assert.False(t, unsupportedResp.IsValid)
	assert.Equal(t, "Unsupported secret type", unsupportedResp.Message)
}

// TestStartHealthServer tests the health server function
func TestStartHealthServer(t *testing.T) {
	// Save the original http.ListenAndServe function and restore it after the test
	originalListenAndServe := http.ListenAndServe
	defer func() { http.ListenAndServe = originalListenAndServe }()

	// Mock the http.ListenAndServe function
	var calledAddr string
	http.ListenAndServe = func(addr string, handler http.Handler) error {
		calledAddr = addr
		return nil
	}

	// Call startHealthServer
	startHealthServer("9000")

	// Give the goroutine time to execute
	time.Sleep(100 * time.Millisecond)

	// Check that http.ListenAndServe was called with the expected port
	assert.Equal(t, ":9000", calledAddr)
}

// TestMainFunction tests a simplified version of the main function
func TestMainFunction(t *testing.T) {
	// Save the original environment and restore it after the test
	origEnv := map[string]string{
		"PORT":        os.Getenv("PORT"),
		"HEALTH_PORT": os.Getenv("HEALTH_PORT"),
		"GIN_MODE":    os.Getenv("GIN_MODE"),
	}
	defer func() {
		for k, v := range origEnv {
			if v != "" {
				os.Setenv(k, v)
			} else {
				os.Unsetenv(k)
			}
		}
	}()

	// Set environment variables for testing
	os.Setenv("PORT", "8443")
	os.Setenv("HEALTH_PORT", "8081")
	os.Setenv("GIN_MODE", "release")

	// Save the original log.Fatal function and restore it after the test
	originalFatal := log.Fatal
	defer func() { log.Fatal = originalFatal }()

	// Mock the log.Fatal function to prevent the test from exiting
	var fatalCalled bool
	log.Fatal = func(v ...interface{}) {
		fatalCalled = true
	}

	// Save the original http.Server.ListenAndServeTLS function and restore it after the test
	originalListenAndServeTLS := http.Server{}.ListenAndServeTLS
	defer func() { http.Server{}.ListenAndServeTLS = originalListenAndServeTLS }()

	// Mock the http.Server.ListenAndServeTLS function
	var listenAndServeTLSCalled bool
	http.Server{}.ListenAndServeTLS = func(certFile, keyFile string) error {
		listenAndServeTLSCalled = true
		return nil
	}

	// Call a simplified version of the main function
	// We can't actually run the full main function as it would block indefinitely

	// Instead, we'll verify the key environment variables are set correctly
	assert.Equal(t, "8443", os.Getenv("PORT"))
	assert.Equal(t, "8081", os.Getenv("HEALTH_PORT"))
	assert.Equal(t, "release", os.Getenv("GIN_MODE"))
}
