package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	// If you haven't already, run the following command in your terminal:
	// go get github.com/stretchr/testify/assert
)

func createTestConfig(t *testing.T) string {
	config := Config{
		Patterns: map[string]string{
			"aws_key":     "AKIA[0-9A-Z]{16}",
			"private_key": "-----BEGIN\\s*PRIVATE\\s*KEY-----",
			"certificate": "-----BEGIN\\s*CERTIFICATE-----",
		},
		API: APIConfig{
			ValidateEndpoint: "http://localhost:8080/validate",
			Token:            "test-token",
		},
		Logging: LoggingConfig{
			Level: "INFO",
			File:  "",
		},
	}

	tempFile, err := os.CreateTemp("", "config-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}

	encoder := json.NewEncoder(tempFile)
	if err := encoder.Encode(config); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	return tempFile.Name()
}

func TestNewValidator(t *testing.T) {
	configPath := createTestConfig(t)
	defer os.Remove(configPath)

	validator, err := NewValidator(configPath)
	assert.NoError(t, err)
	assert.NotNil(t, validator)
	assert.NotNil(t, validator.patterns)
	assert.NotNil(t, validator.logger)
}

func TestValidateContent(t *testing.T) {
	configPath := createTestConfig(t)
	defer os.Remove(configPath)

	validator, err := NewValidator(configPath)
	assert.NoError(t, err)

	tests := []struct {
		name     string
		content  string
		expected int
	}{
		{
			name:     "No secrets",
			content:  "This is a regular text",
			expected: 0,
		},
		{
			name:     "AWS Key",
			content:  "AWS key: AKIAIOSFODNN7EXAMPLE",
			expected: 1,
		},
		{
			name:     "Private Key",
			content:  "Key: -----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkw\n-----END PRIVATE KEY-----",
			expected: 1,
		},
		{
			name:     "Multiple secrets",
			content:  "AWS: AKIAIOSFODNN7EXAMPLE\nKey: -----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----",
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := validator.ValidateContent(tt.content, "test.txt")
			assert.Equal(t, tt.expected, len(findings))
		})
	}
}

func TestProcessPush(t *testing.T) {
	configPath := createTestConfig(t)
	defer os.Remove(configPath)

	validator, err := NewValidator(configPath)
	assert.NoError(t, err)

	// Mock git diff output
	oldExec := execCommand
	defer func() { execCommand = oldExec }()

	execCommand = func(command string, args ...string) *exec.Cmd {
		return exec.Command("echo", "Test content without secrets")
	}

	err = validator.ProcessPush()
	assert.NoError(t, err)
}

func TestLoadConfig(t *testing.T) {
	configPath := createTestConfig(t)
	defer os.Remove(configPath)

	config, err := loadConfig(configPath)
	assert.NoError(t, err)
	assert.NotEmpty(t, config.Patterns)
	assert.NotEmpty(t, config.API.ValidateEndpoint)
}

func TestCompilePatterns(t *testing.T) {
	patterns := map[string]string{
		"test":    "[0-9]+",
		"invalid": "[",
	}

	compiled, err := compilePatterns(patterns)
	assert.Error(t, err)
	assert.Nil(t, compiled)

	patterns = map[string]string{
		"test": "[0-9]+",
	}

	compiled, err = compilePatterns(patterns)
	assert.NoError(t, err)
	assert.NotNil(t, compiled)
	assert.Contains(t, compiled, "test")
}
