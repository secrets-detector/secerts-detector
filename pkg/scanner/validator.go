package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
		},
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

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, "POST", v.url+"/validate", bytes.NewBuffer(jsonBody))
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
