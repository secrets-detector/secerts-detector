package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockHTTPClient is a mock for the HTTP client
type MockHTTPClient struct {
	mock.Mock
}

// Do mocks the Do method of http.Client
func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	return args.Get(0).(*http.Response), args.Error(1)
}

// MockValidationServiceResponse creates a mock response from the validation service
func MockValidationServiceResponse(findings []map[string]interface{}) *http.Response {
	resp := struct {
		Findings []map[string]interface{} `json:"findings"`
		Message  string                   `json:"message"`
	}{
		Findings: findings,
		Message:  "Test message",
	}

	jsonResp, _ := json.Marshal(resp)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(jsonResp)),
	}
}

// TestNewSafeLogger tests the NewSafeLogger function
func TestNewSafeLogger(t *testing.T) {
	logger := log.New(os.Stdout, "TestPrefix ", log.LstdFlags)
	safeLogger := NewSafeLogger(logger, "info")

	assert.NotNil(t, safeLogger)
	assert.Equal(t, "info", safeLogger.logLevel)
	assert.Equal(t, logger, safeLogger.Logger)
}

// TestSafeLoggerMethods tests the methods of the SafeLogger
func TestSafeLoggerMethods(t *testing.T) {
	// Redirect logs to a buffer for testing
	var buf bytes.Buffer
	logger := log.New(&buf, "Test ", log.LstdFlags)
	safeLogger := NewSafeLogger(logger, "debug")

	// Test Debug method
	safeLogger.Debug("Test debug message: %s", "sensitive-data")
	assert.Contains(t, buf.String(), "Test debug message")
	assert.NotContains(t, buf.String(), "sensitive-data") // Should be sanitized

	// Reset buffer
	buf.Reset()

	// Test Info method with sensitive content
	safeLogger.Info("Test info with SECRET: %s", "PASSWORD123")
	assert.Contains(t, buf.String(), "Test info with SECRET")
	assert.NotContains(t, buf.String(), "PASSWORD123") // Should be redacted

	// Reset buffer
	buf.Reset()

	// Test Warn method
	safeLogger.Warn("Test warning: %s", "warning-message")
	assert.Contains(t, buf.String(), "Test warning: warning-message")

	// Reset buffer
	buf.Reset()

	// Test Error method
	safeLogger.Error("Test error: %s", "error-message")
	assert.Contains(t, buf.String(), "Test error: error-message")
}

// TestSecretDetectorApp_HandleWebhook tests the HandleWebhook method
func TestSecretDetectorApp_HandleWebhook(t *testing.T) {
	// Create a new SecretDetectorApp with mocked components
	logger := log.New(os.Stdout, "TestPrefix ", log.LstdFlags)
	app := NewSecretDetectorApp("http://validation-service:8080", logger, true, false, true)

	// Add a test configuration
	err := app.AddInstance(&GitHubConfig{
		IsEnterprise:   false,
		AppID:          12345,
		InstallationID: 67890,
		PrivateKey:     "test-key",
		WebhookSecret:  "test-secret",
	})
	assert.NoError(t, err)

	// Create a test webhook payload
	payload := `{
		"ref": "refs/heads/main",
		"repository": {
			"name": "test-repo",
			"owner": {
				"name": "test-org",
				"login": "test-org"
			}
		},
		"commits": [
			{
				"id": "1234567890abcdef",
				"message": "Test commit"
			}
		]
	}`

	// Calculate the HMAC signature
	mac := hmac.New(sha1.New, []byte("test-secret"))
	mac.Write([]byte(payload))
	signature := "sha1=" + hex.EncodeToString(mac.Sum(nil))

	// Create a test HTTP request
	req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString(payload))
	req.Header.Set("X-Hub-Signature", signature)
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("Content-Type", "application/json")

	// Create a recorder to capture the response
	rr := httptest.NewRecorder()

	// Call the webhook handler
	http.HandlerFunc(app.HandleWebhook).ServeHTTP(rr, req)

	// Check the response
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestSanitizeFunctions tests the various sanitization functions
func TestSanitizeFunctions(t *testing.T) {
	// Test sanitizeSignature
	sig := "abcdef1234567890"
	sanitized := sanitizeSignature(sig)
	assert.Equal(t, "abcdef...7890", sanitized)

	// Test sanitizePayload
	payload := `{"key": "value", "sensitive": "secret"}`
	sanitized = sanitizePayload(payload)
	assert.Contains(t, sanitized, "[JSON_PAYLOAD_STRUCTURE_ONLY]")

	// Test sanitizeContent
	content := "This contains a PASSWORD=verysecret"
	sanitized = sanitizeContent(content)
	assert.Contains(t, sanitized, "[SENSITIVE_CONTENT_REDACTED]")

	// Test isSensitiveContent
	assert.True(t, isSensitiveContent("PRIVATE KEY"))
	assert.True(t, isSensitiveContent("password=123"))
	assert.False(t, isSensitiveContent("regular content"))
}

// TestGetEnvInt64 tests the getEnvInt64 helper function
func TestGetEnvInt64(t *testing.T) {
	// Test with environment variable set
	os.Setenv("TEST_ENV_INT", "123")
	defer os.Unsetenv("TEST_ENV_INT")

	result := getEnvInt64("TEST_ENV_INT", 456)
	assert.Equal(t, int64(123), result)

	// Test with environment variable not set
	result = getEnvInt64("NONEXISTENT_ENV", 789)
	assert.Equal(t, int64(789), result)

	// Test with invalid environment variable
	os.Setenv("INVALID_ENV_INT", "not-an-integer")
	defer os.Unsetenv("INVALID_ENV_INT")

	result = getEnvInt64("INVALID_ENV_INT", 999)
	assert.Equal(t, int64(999), result)
}
