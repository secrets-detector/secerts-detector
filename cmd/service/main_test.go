package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"secrets-detector/pkg/models"

	"github.com/stretchr/testify/assert"
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateCertificate(tt.cert)
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
			name: "Invalid certificate",
			request: models.ValidationRequest{
				Secret: models.SecretFinding{
					Type:  "certificate",
					Value: "invalid cert",
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
