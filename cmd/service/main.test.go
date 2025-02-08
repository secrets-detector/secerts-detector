package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"secrets-detector/pkg/models"
)

func TestValidateCertificate(t *testing.T) {
	tests := []struct {
		name     string
		cert     string
		expected bool
	}{
		{
			name:     "Invalid certificate",
			cert:     "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----",
			expected: false,
		},
		{
			name: "Valid certificate",
			cert: `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUXw1hAWO9kTVRj26qJHgMJX6wx+gwDQYJKoZIhvcNAQEL
BQAwQTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxDjAMBgNVBAoM
BU15T3JnMQ0wCwYDVQQDDARUZXN0MB4XDTE5MDcyMzE3MjgzNVoXDTI5MDcyMDE3
MjgzNVowQTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxDjAMBgNV
BAoMBU15T3JnMQ0wCwYDVQQDDARUZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA0Gjl8buPjyFbLXNI2HrYatZ+5nhBNpm9JzYxbKxn1R6C8LZ+EXNh
qzRQe/dUQhxqw1USRVQsYnI5l/0h1yVqwYvlf8pJ8ACVGsqQEX9sT4FQzNCZ7Jme
TvjzBBXRymwKLRUj4oqgQXdV+vNS6DTrvZXFGEsHuY7QFQQWVuNW+E/+FcY7Hef+
Pl3pPzrjU4RZysfQqQrBpVqZ8/LVBz9/9YLdsTJBmHHM+kGuG8EqaUhwk2wXMgKR
MDKZR8gR8CyYnYo4RKg8bNpbGYgT7zxj5YOIOu+NFhxRrGE6BD1D4shaqY6d0PZQ
Q8wFqTOZnQE0CZZ8il9avGXJlyS/1yTBkQIDAQABo1MwUTAdBgNVHQ4EFgQUx6xj
z8Y5s+J/TYD8N8mE8xRn5nswHwYDVR0jBBgwFoAUx6xjz8Y5s+J/TYD8N8mE8xRn
5nswDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAr/FKQRLQcH4T
qPxPBXByX/flwL5kI7HhZxjkcjR6Hjk3TEA9JlFUqWjEZHQAkrFfuQK8YlV0Zz1j
Tt04kHZ5MHdpHKwZVuXZ3ZgLgwO8Q7JIEEr9ZjRwxI5Hv2VGcr2TY9KQP5wJxoPs
yxRA1PSi5JIVWQRDhtE7MxzaKAPGJYbbftVdZ7Z3DWTLhzPMu+//P9HgYA8e6sod
KJ6iiLtEOF9A7eUe+1THJwGn5oGE8oCkYsqHZVd1KFajfX9Rl8YT1QGP8XxIhpMV
fnPj0g6F4p9nfFhI/Vi7aKDRf4Ga8cw6SaCaLW3jtRaV718N0Nj1aSfB7Q3TBF9x
jK1fwKdGZw==
-----END CERTIFICATE-----`,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateCertificate(tt.cert)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidatePrivateKey(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		{
			name:     "Invalid key",
			key:      "-----BEGIN RSA PRIVATE KEY-----\ninvalid\n-----END RSA PRIVATE KEY-----",
			expected: false,
		},
		{
			name:     "Invalid format",
			key:      "not a key",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validatePrivateKey(tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateAWSKey(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		{
			name:     "Valid AWS key",
			key:      "AKIAIOSFODNN7EXAMPLE",
			expected: true,
		},
		{
			name:     "Invalid prefix",
			key:      "AKIA12345",
			expected: false,
		},
		{
			name:     "Invalid length",
			key:      "AKIAIOSFODNN7",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateAWSKey(tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateEndpoint(t *testing.T) {
	router := setupRouter()

	tests := []struct {
		name           string
		request        models.ValidationRequest
		expectedStatus int
		expectedValid  bool
	}{
		{
			name: "Valid certificate",
			request: models.ValidationRequest{
				Secret: models.SecretFinding{
					Type: "certificate",
					Value: `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUXw1hAWO9kTVRj26qJHgMJX6wx+gwDQYJKoZIhvcNAQEL
-----END CERTIFICATE-----`,
				},
			},
			expectedStatus: http.StatusOK,
			expectedValid:  true,
		},
		{
			name: "Invalid type",
			request: models.ValidationRequest{
				Secret: models.SecretFinding{
					Type:  "unknown",
					Value: "test",
				},
			},
			expectedStatus: http.StatusOK,
			expectedValid:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.request)
			assert.NoError(t, err)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/validate", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response models.ValidationResponse
			err = json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedValid, response.IsValid)
		})
	}
}
