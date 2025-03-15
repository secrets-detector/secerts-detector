package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"secrets-detector/pkg/db"
	"secrets-detector/pkg/scanner"
)

func main() {
	// Parse command line arguments
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

	flag.StringVar(&owner, "owner", "", "GitHub owner/org to scan (leave empty for all accessible repos)")
	flag.StringVar(&repo, "repo", "", "Specific repository to scan (requires owner)")
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
	flag.Parse()

	// Set up logging
	logger := log.New(os.Stdout, "[GitHubScanner] ", log.LstdFlags)

	// Override values from environment variables if present
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

	// Validate required parameters
	if githubToken == "" {
		logger.Fatal("GitHub token is required (set via --github-token flag or GITHUB_TOKEN env var)")
	}
	if dbHost == "" || dbUser == "" || dbPassword == "" || dbName == "" {
		logger.Fatal("Database configuration is incomplete")
	}

	logger.Printf("Starting GitHub secrets scanner with concurrency=%d, max-depth=%d", concurrency, maxDepth)

	// Set up database connection
	database, err := db.NewDB(dbHost, dbPort, dbUser, dbPassword, dbName)
	if err != nil {
		logger.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()

	// Set up context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle termination signals
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		logger.Println("Received termination signal, shutting down gracefully...")
		cancel()
	}()

	// Parse excluded repos and orgs
	excludedRepos := []string{}
	if excludeRepos != "" {
		excludedRepos = strings.Split(excludeRepos, ",")
		for i := range excludedRepos {
			excludedRepos[i] = strings.TrimSpace(excludedRepos[i])
		}
	}

	excludedOrgs := []string{}
	if excludeOrgs != "" {
		excludedOrgs = strings.Split(excludeOrgs, ",")
		for i := range excludedOrgs {
			excludedOrgs[i] = strings.TrimSpace(excludedOrgs[i])
		}
	}

	// Create scanner configuration
	config := scanner.Config{
		GitHubToken:     githubToken,
		GitHubBaseURL:   githubBaseURL,
		Owner:           owner,
		Repo:            repo,
		ExcludedRepos:   excludedRepos,
		ExcludedOrgs:    excludedOrgs,
		PageSize:        pageSize,
		Concurrency:     concurrency,
		BatchSize:       batchSize,
		RateLimit:       rateLimit,
		PauseTime:       time.Duration(pauseTime) * time.Second,
		ValidationURL:   validationURL,
		ValidationToken: validationToken,
		DebugMode:       debugMode,
		MaxDepth:        maxDepth,
		ScanPrivate:     scanPrivate,
	}

	// Create and run the scanner
	s := scanner.NewScanner(config, database, logger)
	if err := s.Run(ctx); err != nil {
		if err == context.Canceled {
			logger.Println("Scanner was canceled")
		} else {
			logger.Fatalf("Scanner error: %v", err)
		}
	}

	logger.Println("Scanner completed successfully")
}
