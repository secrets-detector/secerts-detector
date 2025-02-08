package main

import (
	"log"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"secrets-detector/pkg/models"

	"github.com/stretchr/testify/assert"
)

func TestNewValidator(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	configContent := `{
		"patterns": {
			"aws_key": "[A-Z0-9]{20}",
			"password": "password[=:][A-Za-z0-9]+"
		},
		"api": {
			"validate_endpoint": "http://localhost:8080/validate",
			"token": "test-token"
		},
		"logging": {
			"level": "info",
			"file": "test.log"
		}
	}`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	assert.NoError(t, err)

	validator, err := NewValidator(configPath)
	assert.NoError(t, err)
	assert.NotNil(t, validator)
	assert.Len(t, validator.patterns, 2)
	assert.NotNil(t, validator.logger)
}

func TestValidateContent(t *testing.T) {
	validator := &Validator{
		patterns: map[string]*regexp.Regexp{
			"aws_key":  regexp.MustCompile("[A-Z0-9]{20}"),
			"password": regexp.MustCompile("password[=:][A-Za-z0-9]{8,}"), // More specific pattern
		},
		logger: log.New(os.Stdout, "", log.LstdFlags),
	}

	tests := []struct {
		name     string
		content  string
		filePath string
		want     []models.SecretFinding
	}{
		{
			name:     "No secrets",
			content:  "This is clean content",
			filePath: "test.txt",
			want:     nil,
		},
		{
			name:     "AWS key detection",
			content:  "AWS key: AKIAIOSFODNN7EXAMPLE",
			filePath: "config.txt",
			want: []models.SecretFinding{
				{
					Type:     "aws_key",
					Value:    "AKIAIOSFODNN7EXAMPLE",
					StartPos: 9,
					EndPos:   29,
					FilePath: "config.txt",
				},
			},
		},
		{
			name:     "Password detection",
			content:  "password=secret123",
			filePath: "settings.txt",
			want: []models.SecretFinding{
				{
					Type:     "password",
					Value:    "password=secret123",
					StartPos: 0,
					EndPos:   18,
					FilePath: "settings.txt",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validator.ValidateContent(tt.content, tt.filePath)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLoadConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	validConfig := `{
		"patterns": {
			"test": "test.*"
		},
		"api": {
			"validate_endpoint": "http://test.com",
			"token": "test"
		},
		"logging": {
			"level": "debug",
			"file": "test.log"
		}
	}`

	err := os.WriteFile(configPath, []byte(validConfig), 0644)
	assert.NoError(t, err)

	config, err := loadConfig(configPath)
	assert.NoError(t, err)
	assert.Equal(t, "test.*", config.Patterns["test"])
	assert.Equal(t, "http://test.com", config.API.ValidateEndpoint)
	assert.Equal(t, "test", config.API.Token)
	assert.Equal(t, "debug", config.Logging.Level)
	assert.Equal(t, "test.log", config.Logging.File)
}

func TestCompilePatterns(t *testing.T) {
	patterns := map[string]string{
		"test1": "[0-9]+",
		"test2": "[A-Z]+",
	}

	compiled, err := compilePatterns(patterns)
	assert.NoError(t, err)
	assert.Len(t, compiled, 2)
	assert.True(t, compiled["test1"].MatchString("123"))
	assert.True(t, compiled["test2"].MatchString("ABC"))
	assert.False(t, compiled["test1"].MatchString("abc"))
	assert.False(t, compiled["test2"].MatchString("123"))
}
