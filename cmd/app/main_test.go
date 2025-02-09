package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"secrets-detector/pkg/models"
	"testing"
	"time"

	"github.com/google/go-github/v45/github"
	"github.com/stretchr/testify/assert"
)

func TestNewSecretDetectorApp(t *testing.T) {
	tests := []struct {
		name               string
		validationEndpoint string
		logger             *log.Logger
		expectNilLogger    bool
	}{
		{
			name:               "Creates app with provided logger",
			validationEndpoint: "http://test-endpoint",
			logger:             log.New(os.Stdout, "[Test] ", log.LstdFlags),
			expectNilLogger:    false,
		},
		{
			name:               "Creates app with default logger when nil provided",
			validationEndpoint: "http://test-endpoint",
			logger:             nil,
			expectNilLogger:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := NewSecretDetectorApp(tt.validationEndpoint, tt.logger)
			assert.NotNil(t, app)
			assert.NotNil(t, app.configs)
			assert.NotNil(t, app.clients)
			assert.Equal(t, tt.validationEndpoint, app.valService.Endpoint)
			assert.Equal(t, 30*time.Second, app.valService.Timeout)
			assert.NotNil(t, app.logger)
		})
	}
}

func TestAddInstance(t *testing.T) {
	app := NewSecretDetectorApp("http://test", nil)

	tests := []struct {
		name        string
		config      *GitHubConfig
		expectError bool
	}{
		{
			name:        "Nil config",
			config:      nil,
			expectError: true,
		},
		{
			name: "Missing IDs",
			config: &GitHubConfig{
				PrivateKey:    "test-key",
				WebhookSecret: "test-secret",
			},
			expectError: true,
		},
		{
			name: "Missing private key",
			config: &GitHubConfig{
				AppID:          123,
				InstallationID: 456,
				WebhookSecret:  "test-secret",
			},
			expectError: true,
		},
		{
			name: "Enterprise without host",
			config: &GitHubConfig{
				IsEnterprise:   true,
				AppID:          123,
				InstallationID: 456,
				PrivateKey:     "test-key",
				WebhookSecret:  "test-secret",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := app.AddInstance(tt.config)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/validate", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var reqBody struct {
			Content string `json:"content"`
		}
		json.NewDecoder(r.Body).Decode(&reqBody)

		response := struct {
			Findings []models.SecretFinding `json:"findings"`
		}{
			Findings: []models.SecretFinding{},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	app := NewSecretDetectorApp(server.URL, nil)
	findings, err := app.validateContent(context.Background(), "test content")

	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestHandlePushEvent(t *testing.T) {
	app := NewSecretDetectorApp("http://test", nil)
	client := github.NewClient(nil)

	event := &github.PushEvent{
		Before: github.String("abc123"),
		After:  github.String("def456"),
		Repo: &github.PushEventRepository{
			Name: github.String("test-repo"),
			Owner: &github.User{
				Name: github.String("test-owner"),
			},
		},
	}

	err := app.handlePushEvent(context.Background(), client, event)
	assert.Error(t, err) // Expected error due to mock client
}
