package scanner

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v45/github"
)

// GitHubAppClient provides GitHub client using a GitHub App installation
type GitHubAppClient struct {
	client *github.Client
	logger *log.Logger
}

// NewGitHubAppClient creates a GitHub client using GitHub App authentication
func NewGitHubAppClient(appID int64, installationID int64, privateKeyPath string, baseURL string, logger *log.Logger) (*GitHubClient, error) {
	// Read private key
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("GitHub App private key not found at %s: %w", privateKeyPath, err)
	}

	// Create GitHub App transport
	itr, err := ghinstallation.NewKeyFromFile(
		http.DefaultTransport,
		appID,
		installationID,
		privateKeyPath,
	)
	if err != nil {
		return nil, fmt.Errorf("error creating GitHub App transport: %w", err)
	}

	// Configure transport parameters
	itr.BaseURL = strings.TrimSuffix(baseURL, "/")

	// Configure HTTP client with performance settings
	httpClient := &http.Client{
		Transport: itr,
		Timeout:   30 * time.Second,
	}

	var client *github.Client

	// Check if we're using GitHub Enterprise
	if baseURL != "https://api.github.com/" {
		// Parse the base URL
		baseEndpoint, err := url.Parse(baseURL)
		if err != nil {
			return nil, fmt.Errorf("invalid GitHub base URL: %w", err)
		}

		// Create client with enterprise URL
		client, err = github.NewEnterpriseClient(baseEndpoint.String(), baseEndpoint.String(), httpClient)
		if err != nil {
			return nil, fmt.Errorf("failed to create GitHub Enterprise client: %w", err)
		}
	} else {
		// Create standard GitHub client
		client = github.NewClient(httpClient)
	}

	logger.Printf("Initialized GitHub App client for App ID %d, Installation ID %d", appID, installationID)
	return &GitHubClient{
		client: client,
		logger: logger,
	}, nil
}

// GetGitHubClient creates a GitHub client using either token or GitHub App authentication
func GetGitHubClient(ctx context.Context, logger *log.Logger) (*GitHubClient, error) {
	// Check if GitHub App auth is configured
	appIDStr := os.Getenv("GITHUB_APP_ID")
	installIDStr := os.Getenv("GITHUB_INSTALLATION_ID")
	keyPath := os.Getenv("GITHUB_APP_KEY_PATH")
	baseURL := os.Getenv("GITHUB_BASE_URL")
	if baseURL == "" {
		baseURL = "https://api.github.com/"
	}

	// Check if GitHub token is provided
	token := os.Getenv("GITHUB_TOKEN")

	if token != "" {
		logger.Println("Using GitHub token authentication")
		return NewGitHubClient(token, baseURL, logger), nil
	} else if appIDStr != "" && installIDStr != "" && keyPath != "" {
		logger.Println("Using GitHub App authentication")
		appID, err := strconv.ParseInt(appIDStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid GITHUB_APP_ID: %w", err)
		}

		installID, err := strconv.ParseInt(installIDStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid GITHUB_INSTALLATION_ID: %w", err)
		}

		return NewGitHubAppClient(appID, installID, keyPath, baseURL, logger)
	}

	return nil, fmt.Errorf("no GitHub authentication method configured")
}
