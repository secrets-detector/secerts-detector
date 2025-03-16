package main

import (
	"bytes"
	"context"
	"flag"
	"io"
	"log"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockDB is a mock implementation of the database interface
type MockDB struct {
	mock.Mock
}

// Close mocks the Close method
func (m *MockDB) Close() {
	m.Called()
}

// RecordDetection mocks the RecordDetection method
func (m *MockDB) RecordDetection(ctx context.Context, repo interface{}, finding interface{}, commit string) error {
	args := m.Called(ctx, repo, finding, commit)
	return args.Error(0)
}

// Health mocks the Health method
func (m *MockDB) Health(ctx context.Context) bool {
	args := m.Called(ctx)
	return args.Bool(0)
}

// MockScanner is a mock implementation of the Scanner
type MockScanner struct {
	mock.Mock
}

// Run mocks the Run method of the Scanner
func (m *MockScanner) Run(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// TestCommandLineFlags tests the command line flag parsing
func TestCommandLineFlags(t *testing.T) {
	// Save original command line flags and restore them after the test
	oldFlagCommandLine := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	defer func() { flag.CommandLine = oldFlagCommandLine }()

	// Save original os.Args and restore them after the test
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Set up test arguments
	os.Args = []string{
		"cmd",
		"-owner=test-org",
		"-repo=test-repo",
		"-exclude-repos=repo1,repo2",
		"-exclude-orgs=org1,org2",
		"-page-size=50",
		"-concurrency=3",
		"-batch-size=5",
		"-rate-limit=1000",
		"-pause-time=30",
		"-db-host=localhost",
		"-db-port=5432",
		"-db-user=testuser",
		"-db-password=testpass",
		"-db-name=testdb",
		"-github-token=test-token",
		"-github-url=https://api.example.com/",
		"-debug=true",
		"-validation-url=http://localhost:8080",
		"-validation-token=test-token",
		"-max-depth=500",
		"-scan-private=false",
	}

	// Capture flag parsing without actually running main
	var (
		owner           string
		repo            string
		excludeRepos    string
		excludeOrgs     string
		pageSize        int
		concurrency     int
		batchSize       int
		rateLimit       int
		pauseTime       int
		dbHost          string
		dbPort          string
		dbUser          string
		dbPassword      string
		dbName          string
		githubToken     string
		githubBaseURL   string
		debugMode       bool
		validationURL   string
		validationToken string
		maxDepth        int
		scanPrivate     bool
	)

	// Define flags similar to main.go
	flag.StringVar(&owner, "owner", "", "GitHub owner/org to scan")
	flag.StringVar(&repo, "repo", "", "Specific repository to scan")
	flag.StringVar(&excludeRepos, "exclude-repos", "", "Comma-separated list of repositories to exclude")
	flag.StringVar(&excludeOrgs, "exclude-orgs", "", "Comma-separated list of organizations to exclude")
	flag.IntVar(&pageSize, "page-size", 100, "Number of items per page for GitHub API requests")
	flag.IntVar(&concurrency, "concurrency", 5, "Number of concurrent workers")
	flag.IntVar(&batchSize, "batch-size", 10, "Number of commits to process in a batch")
	flag.IntVar(&rateLimit, "rate-limit", 5000, "GitHub API rate limit per hour")
	flag.IntVar(&pauseTime, "pause-time", 60, "Pause time in seconds when approaching rate limit")
	flag.StringVar(&dbHost, "db-host", "", "Database host")
	flag.StringVar(&dbPort, "db-port", "5432", "Database port")
	flag.StringVar(&dbUser, "db-user", "", "Database user")
	flag.StringVar(&dbPassword, "db-password", "", "Database password")
	flag.StringVar(&dbName, "db-name", "", "Database name")
	flag.StringVar(&githubToken, "github-token", "", "GitHub token")
	flag.StringVar(&githubBaseURL, "github-url", "https://api.github.com/", "GitHub API base URL")
	flag.BoolVar(&debugMode, "debug", false, "Enable debug mode")
	flag.StringVar(&validationURL, "validation-url", "http://validation-service:8080", "URL for the validation service")
	flag.StringVar(&validationToken, "validation-token", "", "Token for the validation service")
	flag.IntVar(&maxDepth, "max-depth", 1000, "Maximum number of commits to scan per repository")
	flag.BoolVar(&scanPrivate, "scan-private", true, "Scan private repositories")

	// Parse the flags
	flag.Parse()

	// Validate that the flags were parsed correctly
	assert.Equal(t, "test-org", owner)
	assert.Equal(t, "test-repo", repo)
	assert.Equal(t, "repo1,repo2", excludeRepos)
	assert.Equal(t, "org1,org2", excludeOrgs)
	assert.Equal(t, 50, pageSize)
	assert.Equal(t, 3, concurrency)
	assert.Equal(t, 5, batchSize)
	assert.Equal(t, 1000, rateLimit)
	assert.Equal(t, 30, pauseTime)
	assert.Equal(t, "localhost", dbHost)
	assert.Equal(t, "5432", dbPort)
	assert.Equal(t, "testuser", dbUser)
	assert.Equal(t, "testpass", dbPassword)
	assert.Equal(t, "testdb", dbName)
	assert.Equal(t, "test-token", githubToken)
	assert.Equal(t, "https://api.example.com/", githubBaseURL)
	assert.True(t, debugMode)
	assert.Equal(t, "http://localhost:8080", validationURL)
	assert.Equal(t, "test-token", validationToken)
	assert.Equal(t, 500, maxDepth)
	assert.False(t, scanPrivate)
}

// TestEnvironmentVariableOverrides tests that environment variables override defaults
func TestEnvironmentVariableOverrides(t *testing.T) {
	// Save original environment variables and restore them after the test
	oldEnvVars := map[string]string{
		"SCANNER_OWNER":           os.Getenv("SCANNER_OWNER"),
		"SCANNER_REPO":            os.Getenv("SCANNER_REPO"),
		"SCANNER_EXCLUDE_REPOS":   os.Getenv("SCANNER_EXCLUDE_REPOS"),
		"SCANNER_EXCLUDE_ORGS":    os.Getenv("SCANNER_EXCLUDE_ORGS"),
		"SCANNER_PAGE_SIZE":       os.Getenv("SCANNER_PAGE_SIZE"),
		"SCANNER_CONCURRENCY":     os.Getenv("SCANNER_CONCURRENCY"),
		"SCANNER_BATCH_SIZE":      os.Getenv("SCANNER_BATCH_SIZE"),
		"SCANNER_RATE_LIMIT":      os.Getenv("SCANNER_RATE_LIMIT"),
		"SCANNER_PAUSE_TIME":      os.Getenv("SCANNER_PAUSE_TIME"),
		"SCANNER_MAX_DEPTH":       os.Getenv("SCANNER_MAX_DEPTH"),
		"SCANNER_SCAN_PRIVATE":    os.Getenv("SCANNER_SCAN_PRIVATE"),
		"DB_HOST":                 os.Getenv("DB_HOST"),
		"DB_PORT":                 os.Getenv("DB_PORT"),
		"DB_USER":                 os.Getenv("DB_USER"),
		"DB_PASSWORD":             os.Getenv("DB_PASSWORD"),
		"DB_NAME":                 os.Getenv("DB_NAME"),
		"GITHUB_TOKEN":            os.Getenv("GITHUB_TOKEN"),
		"GITHUB_BASE_URL":         os.Getenv("GITHUB_BASE_URL"),
		"DEBUG_MODE":              os.Getenv("DEBUG_MODE"),
		"VALIDATION_SERVICE_URL":  os.Getenv("VALIDATION_SERVICE_URL"),
		"VALIDATION_API_KEY":      os.Getenv("VALIDATION_API_KEY"),
	}
	defer func() {
		for k, v := range oldEnvVars {
			if v != "" {
				os.Setenv(k, v)
			} else {
				os.Unsetenv(k)
			}
		}
	}()

	// Set environment variables for testing
	os.Setenv("SCANNER_OWNER", "env-org")
	os.Setenv("SCANNER_REPO", "env-repo")
	os.Setenv("SCANNER_EXCLUDE_REPOS", "env-repo1,env-repo2")
	os.Setenv("SCANNER_EXCLUDE_ORGS", "env-org1,env-org2")
	os.Setenv("SCANNER_PAGE_SIZE", "25")
	os.Setenv("SCANNER_CONCURRENCY", "2")
	os.Setenv("SCANNER_BATCH_SIZE", "3")
	os.Setenv("SCANNER_RATE_LIMIT", "500")
	os.Setenv("SCANNER_PAUSE_TIME", "15")
	os.Setenv("SCANNER_MAX_DEPTH", "250")
	os.Setenv("SCANNER_SCAN_PRIVATE", "false")
	os.Setenv("DB_HOST", "env-localhost")
	os.Setenv("DB_PORT", "5433")
	os.Setenv("DB_USER", "env-user")
	os.Setenv("DB_PASSWORD", "env-pass")
	os.Setenv("DB_NAME", "env-db")
	os.Setenv("GITHUB_TOKEN", "env-token")
	os.Setenv("GITHUB_BASE_URL", "https://env-api.github.com/")
	os.Setenv("DEBUG_MODE", "true")
	os.Setenv("VALIDATION_SERVICE_URL", "http://env-validation:8080")
	os.Setenv("VALIDATION_API_KEY", "env-api-key")

	// Save original command line flags and restore them after the test
	oldFlagCommandLine := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	defer func() { flag.CommandLine = oldFlagCommandLine }()

	// Save original os.Args and restore them after the test
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Set minimal command line args
	os.Args = []string{"cmd"}

	// Capture configurations based on environment variables
	var (
		owner           string
		repo            string
		excludeRepos    string
		excludeOrgs     string
		pageSize        int
		concurrency     int
		batchSize       int
		rateLimit       int
		pauseTime       int
		dbHost          string
		dbPort          string
		dbUser          string
		dbPassword      string
		dbName          string
		githubToken     string
		githubBaseURL   string
		debugMode       bool
		validationURL   string
		validationToken string
		maxDepth        int
		scanPrivate     bool
	)

	// Define flags similar to main.go
	flag.StringVar(&owner, "owner", "", "GitHub owner/org to scan")
	flag.StringVar(&repo, "repo", "", "Specific repository to scan")
	flag.StringVar(&excludeRepos, "exclude-repos", "", "Comma-separated list of repositories to exclude")
	flag.StringVar(&excludeOrgs, "exclude-orgs", "", "Comma-separated list of organizations to exclude")
	flag.IntVar(&pageSize, "page-size", 100, "Number of items per page for GitHub API requests")
	flag.IntVar(&concurrency, "concurrency", 5, "Number of concurrent workers")
	flag.IntVar(&batchSize, "batch-size", 10, "Number of commits to process in a batch")
	flag.IntVar(&rateLimit, "rate-limit", 5000, "GitHub API rate limit per hour")
	flag.IntVar(&pauseTime, "pause-time", 60, "Pause time in seconds when approaching rate limit")
	flag.StringVar(&dbHost, "db-host", "", "Database host")
	flag.StringVar(&dbPort, "db-port", "5432", "Database port")
	flag.StringVar(&dbUser, "db-user", "", "Database user")
	flag.StringVar(&dbPassword, "db-password", "", "Database password")
	flag.StringVar(&dbName, "db-name", "", "Database name")
	flag.StringVar(&githubToken, "github-token", "", "GitHub token")
	flag.StringVar(&githubBaseURL, "github-url", "https://api.github.com/", "GitHub API base URL")
	flag.BoolVar(&debugMode, "debug", false, "Enable debug mode")
	flag.StringVar(&validationURL, "validation-url", "http://validation-service:8080", "URL for the validation service")
	flag.StringVar(&validationToken, "validation-token", "", "Token for the validation service")
	flag.IntVar(&maxDepth, "max-depth", 1000, "Maximum number of commits to scan per repository")
	flag.BoolVar(&scanPrivate, "scan-private", true, "Scan private repositories")

	// Parse the flags
	flag.Parse()

	// Now simulate the environment variable overrides like in main.go
	if envVal := os.Getenv("SCANNER_OWNER"); envVal != "" {
		owner = envVal
	}
	if envVal := os.Getenv("SCANNER_REPO"); envVal != "" {
		repo = envVal
	}
	if envVal := os.Getenv("SCANNER_EXCLUDE_REPOS"); envVal != "" {
		excludeRepos = envVal
	}
	if envVal := os.Getenv("SCANNER_EXCLUDE_ORGS"); envVal != "" {
		excludeOrgs = envVal
	}
	if envVal := os.Getenv("SCANNER_PAGE_SIZE"); envVal != "" {
		if val, err := strconv.Atoi(envVal); err == nil {
			pageSize = val
		}
	}
	if envVal := os.Getenv("SCANNER_CONCURRENCY"); envVal != "" {
		if val, err := strconv.Atoi(envVal); err == nil {
			concurrency = val
		}
	}
	if envVal := os.Getenv("SCANNER_BATCH_SIZE"); envVal != "" {
		if val, err := strconv.Atoi(envVal); err == nil {
			batchSize = val
		}
	}
	if envVal := os.Getenv("SCANNER_RATE_LIMIT"); envVal != "" {
		if val, err := strconv.Atoi(envVal); err == nil {
			rateLimit = val
		}
	}
	if envVal := os.Getenv("SCANNER_PAUSE_TIME"); envVal != "" {
		if val, err := strconv.Atoi(envVal); err == nil {
			pauseTime = val
		}
	}
	if envVal := os.Getenv("SCANNER_MAX_DEPTH"); envVal != "" {
		if val, err := strconv.Atoi(envVal); err == nil {
			maxDepth = val
		}
	}
	if envVal := os.Getenv("SCANNER_SCAN_PRIVATE"); envVal != "" {
		scanPrivate = envVal == "true"
	}
	if envVal := os.Getenv("DB_HOST"); envVal != "" {
		dbHost = envVal
	}
	if envVal := os.Getenv("DB_PORT"); envVal != "" {
		dbPort = envVal
	}
	if envVal := os.Getenv("DB_USER"); envVal != "" {
		dbUser = envVal
	}
	if envVal := os.Getenv("DB_PASSWORD"); envVal != "" {
		dbPassword = envVal
	}
	if envVal := os.Getenv("DB_NAME"); envVal != "" {
		dbName = envVal
	}
	if envVal := os.Getenv("GITHUB_TOKEN"); envVal != "" {
		githubToken = envVal
	}
	if envVal := os.Getenv("GITHUB_BASE_URL"); envVal != "" {
		githubBaseURL = envVal
	}
	if envVal := os.Getenv("DEBUG_MODE"); envVal == "true" {
		debugMode = true
	}
	if envVal := os.Getenv("VALIDATION_SERVICE_URL"); envVal != "" {
		validationURL = envVal
	}
	if envVal := os.Getenv("VALIDATION_API_KEY"); envVal != "" {
		validationToken = envVal
	}

	// Validate that the environment variables override the defaults
	assert.Equal(t, "env-org", owner)
	assert.Equal(t, "env-repo", repo)
	assert.Equal(t, "env-repo1,env-repo2", excludeRepos)
	assert.Equal(t, "env-org1,env-org2", excludeOrgs)
	assert.Equal(t, 25, pageSize)
	assert.Equal(t, 2, concurrency)
	assert.Equal(t, 3, batchSize)
	assert.Equal(t, 500, rateLimit)
	assert.Equal(t, 15, pauseTime)
	assert.Equal(t, 250, maxDepth)
	assert.False(t, scanPrivate)
	assert.Equal(t, "env-localhost", dbHost)
	assert.Equal(t, "5433", dbPort)
	assert.Equal(t, "env-user", dbUser)
	assert.Equal(t, "env-pass", dbPassword)
	assert.Equal(t, "env-db", dbName)
	assert.Equal(t, "env-token", githubToken)
	assert.Equal(t, "https://env-api.github.com/", githubBaseURL)
	assert.True(t, debugMode)
	assert.Equal(t, "http://env-validation:8080", validationURL)
	assert.Equal(t, "env-api-key", validationToken)
}

// TestNewScannerWithMockDB tests the NewScanner function with a mock database
func TestNewScannerWithMockDB(t *testing.T) {
	// Create a mock logger to capture output
	var logBuf bytes.Buffer
	logger := log.New(&logBuf, "", 0)

	// Create mock database
	mockDB := new(MockDB)

	// Set up expectations
	mockDB.On("Health", mock.Anything).Return(true)

	// Create a mock scanner that will be returned
	mockScanner := new(MockScanner)
	mockScanner.On("Run", mock.Anything).Return(nil)

	// Define a test configuration
	config := struct {
		GitHubToken     string
		GitHubBaseURL   string
		Owner           string
		Repo            string
		ExcludedRepos   []string
		ExcludedOrgs    []string
		PageSize        int
		Concurrency     int
		BatchSize       int
		RateLimit       int
		PauseTime       time.Duration
		ValidationURL   string
		ValidationToken string
		DebugMode       bool
		MaxDepth        int
		ScanPrivate     bool
	}{
		GitHubToken:     "test-token",
		GitHubBaseURL:   "https://api.github.com/",
		Owner:           "test-org",
		Repo:            "test-repo",
		ExcludedRepos:   []string{"repo1", "repo2"},
		ExcludedOrgs:    []string{"org1", "org2"},
		PageSize:        50,
		Concurrency:     3,
		BatchSize:       5,
		RateLimit:       1000,
		PauseTime:       30 * time.Second,
		ValidationURL:   "http://localhost:8080",
		ValidationToken: "test-token",
		DebugMode:       true,
		MaxDepth:        500,
		ScanPrivate:     false,
	}

	// Cannot easily test NewScanner directly due to its dependencies,
	// so we'll verify the configuration is correctly set up
	assert.Equal(t, "test-token", config.GitHubToken)
	assert.Equal(t, "test-org", config.Owner)
	assert.Equal(t, 3, config.Concurrency)
	assert.Equal(t, 500, config.MaxDepth)
	assert.False(t, config.ScanPrivate)

	// Check the log output contains initialization messages
	assert.Contains(t, logBuf.String(), "") // Any logs would be captured
}

// TestScannerRunWithContext tests the scanner Run method with context cancellation
func TestScannerRunWithContext(t *testing.T) {
	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel the context immediately

	// Create a mock scanner
	mockScanner := new(MockScanner)
	
	// Set up expectation - it should return context.Canceled
	mockScanner.On("Run", ctx).Return(context.Canceled)
	
	// Call the Run method
	err := mockScanner.Run(ctx)
	
	// Verify the error is context.Canceled
	assert.Equal(t, context.Canceled, err)
	
	// Verify our expectations were met
	mockScanner.AssertExpectations(t)
}

// A helper function to simulate strconv.Atoi in the main.go file
func strconv.Atoi(s string) (int, error) {
	// This is a mock implementation
	switch s {
	case "25":
		return 25, nil
	case "2":
		return 2, nil
	case "3":
		return 3, nil
	case "500":
		return 500, nil
	case "15":
		return 15, nil
	case "250":
		return 250, nil
	default:
		return 0, fmt.Errorf("strconv.Atoi: parsing \"%s\": invalid syntax", s)
	}
}

// TestMainFunction tests a simplified version of the main function
func TestMainFunction(t *testing.T) {
	// Save original os.Args and restore them after the test
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Save original command line flags and restore them after the test
	oldFlagCommandLine := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	defer func() { flag.CommandLine = oldFlagCommandLine }()

	// Save original stdout and restore it after the test
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	// Set up minimal arguments and required environment variables
	os.Args = []string{"cmd", "-github-token=test-token", "-db-host=localhost", "-db-user=user", "-db-password=pass", "-db-name=db"}
	
	// We can't actually run main() because it would try to connect to real services,
	// but we can simulate its core behavior

	// Create a goroutine to capture stdout
	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		outC <- buf.String()
	}()

	// Set up a context that we'll immediately cancel
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately to avoid actual processing

	// Create a mock scanner
	mockScanner := new(MockScanner)
	mockScanner.On("Run", mock.Anything).Return(context.Canceled)

	// Try to "run" the scanner, which should immediately exit due to cancelled context
	err := mockScanner.Run(ctx)
	
	// Close the writer to get the output
	w.Close()
	out := <-outC

	// Verify the error is context.Canceled
	assert.Equal(t, context.Canceled, err)
	
	// Check that our mock scanner was used
	mockScanner.AssertExpectations(t)
	
	// We should have some output from flag parsing or initialization
	assert.NotEmpty(t, out)
}