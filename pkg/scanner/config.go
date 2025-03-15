package scanner

import (
	"time"
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
