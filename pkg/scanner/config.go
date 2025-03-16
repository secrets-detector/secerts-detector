package scanner

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v45/github"
)

// Config holds the scanner configuration
type Config struct {
	// GitHub Authentication - Token OR App
	GitHubToken     string
	GitHubAppID     int64
	GitHubInstallID int64
	GitHubKeyPath   string
	GitHubBaseURL   string

	// Repository filtering
	Owner         string
	Repo          string
	ExcludedRepos []string
	ExcludedOrgs  []string

	// Performance settings
	PageSize    int
	Concurrency int
	BatchSize   int
	RateLimit   int
	PauseTime   time.Duration

	// Validation
	ValidationURL   string
	ValidationToken string

	// Other settings
	DebugMode   bool
	MaxDepth    int
	ScanPrivate bool
}

// InitGitHubClient initializes GitHub client based on available credentials
func (s *Scanner) initGitHubClient() error {
	var err error

	if s.config.GitHubToken != "" {
		// Use token authentication
		s.github = NewGitHubClient(s.config.GitHubToken, s.config.GitHubBaseURL, s.logger)
		s.logger.Printf("Using GitHub Token authentication")
	} else if s.config.GitHubAppID != 0 && s.config.GitHubInstallID != 0 && s.config.GitHubKeyPath != "" {
		// Use GitHub App authentication
		s.github, err = NewGitHubAppClient(
			s.config.GitHubAppID,
			s.config.GitHubInstallID,
			s.config.GitHubKeyPath,
			s.config.GitHubBaseURL,
			s.logger,
		)
		if err != nil {
			return err
		}
		s.logger.Printf("Using GitHub App authentication (App ID: %d, Installation ID: %d)",
			s.config.GitHubAppID, s.config.GitHubInstallID)
	} else {
		return ErrNoGitHubAuth
	}
	return nil
}

// Common errors
var (
	ErrNoGitHubAuth = NewError("no GitHub authentication method provided")
)

// Error represents a scanner error
type Error struct {
	msg string
}

// NewError creates a new error with the given message
func NewError(msg string) *Error {
	return &Error{msg: msg}
}

// Error returns the error message
func (e *Error) Error() string {
	return e.msg
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
	if baseURL != "" && baseURL != "https://api.github.com/" {
		itr.BaseURL = strings.TrimSuffix(baseURL, "/")
	}

	// Configure HTTP client with performance settings
	httpClient := &http.Client{
		Transport: itr,
		Timeout:   30 * time.Second,
	}

	var client *github.Client

	// Check if we're using GitHub Enterprise
	if baseURL != "" && baseURL != "https://api.github.com/" {
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
