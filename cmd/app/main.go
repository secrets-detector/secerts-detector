package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"secrets-detector/pkg/db"
	"secrets-detector/pkg/models"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v45/github"
)

type GitHubConfig struct {
	IsEnterprise   bool
	EnterpriseHost string
	AppID          int64
	InstallationID int64
	PrivateKey     string
	WebhookSecret  string
}

type ValidationServiceConfig struct {
	Endpoint string
	Timeout  time.Duration
}

type SecretDetectorApp struct {
	configs    map[string]*GitHubConfig
	clients    map[string]*github.Client
	valService ValidationServiceConfig
	logger     *log.Logger
	patterns   map[string]*regexp.Regexp
	db         *db.DB // Database field
	testMode   bool   // New field to indicate test mode
}

func NewSecretDetectorApp(validationEndpoint string, logger *log.Logger, testMode bool) *SecretDetectorApp {
	if logger == nil {
		logger = log.New(os.Stdout, "[SecretDetector] ", log.LstdFlags|log.Lshortfile)
	}

	patterns, err := loadPatterns("/app/config/config.json")
	if err != nil {
		logger.Printf("Warning: Failed to load patterns: %v", err)
		// Initialize with empty patterns map to prevent nil pointer dereference
		patterns = make(map[string]*regexp.Regexp)
	}

	// Initialize database connection with retries
	var dbConn *db.DB

	// Get database connection parameters
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")

	// Try to connect with retries
	maxRetries := 5
	retryDelay := time.Second * 5

	for i := 0; i < maxRetries; i++ {
		logger.Printf("Attempting to connect to database (attempt %d/%d)...", i+1, maxRetries)

		dbConn, err = db.NewDB(dbHost, dbPort, dbUser, dbPassword, dbName)
		if err == nil {
			logger.Printf("Successfully connected to database")
			break
		}

		logger.Printf("Warning: Failed to connect to database: %v. Retrying in %v...", err, retryDelay)
		time.Sleep(retryDelay)
	}

	if dbConn == nil {
		logger.Printf("Warning: All database connection attempts failed. App will run with limited functionality.")
	}

	return &SecretDetectorApp{
		configs: make(map[string]*GitHubConfig),
		clients: make(map[string]*github.Client),
		valService: ValidationServiceConfig{
			Endpoint: validationEndpoint,
			Timeout:  30 * time.Second,
		},
		logger:   logger,
		patterns: patterns,
		db:       dbConn,
		testMode: testMode,
	}
}

func loadPatterns(configPath string) (map[string]*regexp.Regexp, error) {
	log.Printf("Attempting to load patterns from: %s", configPath)

	configFile, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("Error reading config file: %v", err)
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config struct {
		Patterns map[string]string `json:"patterns"`
	}
	if err := json.Unmarshal(configFile, &config); err != nil {
		log.Printf("Error unmarshaling config: %v", err)
		return nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}

	log.Printf("Loaded patterns: %+v", config.Patterns)

	patterns := make(map[string]*regexp.Regexp)
	for name, pattern := range config.Patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			log.Printf("Error compiling pattern %s: %v", name, err)
			return nil, fmt.Errorf("failed to compile pattern %s: %v", name, err)
		}
		patterns[name] = re
		log.Printf("Successfully compiled pattern: %s", name)
	}

	return patterns, nil
}

func (app *SecretDetectorApp) AddInstance(config *GitHubConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	if config.AppID == 0 || config.InstallationID == 0 {
		return fmt.Errorf("invalid app or installation ID")
	}

	if config.PrivateKey == "" || config.WebhookSecret == "" {
		return fmt.Errorf("private key and webhook secret are required")
	}

	itr, err := ghinstallation.New(
		http.DefaultTransport,
		config.AppID,
		config.InstallationID,
		[]byte(config.PrivateKey),
	)
	if err != nil {
		return fmt.Errorf("failed to create installation transport: %v", err)
	}

	var client *github.Client
	if config.IsEnterprise {
		if config.EnterpriseHost == "" {
			return fmt.Errorf("enterprise host is required for enterprise instances")
		}
		baseURL := fmt.Sprintf("https://%s/api/v3/", config.EnterpriseHost)
		uploadURL := fmt.Sprintf("https://%s/api/uploads/", config.EnterpriseHost)
		client, err = github.NewEnterpriseClient(baseURL, uploadURL, &http.Client{Transport: itr})
	} else {
		client = github.NewClient(&http.Client{Transport: itr})
	}

	if err != nil {
		return fmt.Errorf("failed to create client: %v", err)
	}

	host := "github.com"
	if config.IsEnterprise {
		host = config.EnterpriseHost
	}

	app.configs[host] = config
	app.clients[host] = client
	return nil
}

func (app *SecretDetectorApp) validateContent(ctx context.Context, content string) ([]models.SecretFinding, error) {
	client := &http.Client{
		Timeout: app.valService.Timeout,
	}

	reqBody := struct {
		Content string `json:"content"`
	}{
		Content: content,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", app.valService.Endpoint+"/validate", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("validation service returned status %d: %s", resp.StatusCode, string(body))
	}

	var response struct {
		Findings []models.SecretFinding `json:"findings"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return response.Findings, nil
}

func (app *SecretDetectorApp) getDiff(ctx context.Context, client *github.Client,
	repo *github.Repository, base, head string) (string, error) {
	comparison, _, err := client.Repositories.CompareCommits(
		ctx,
		repo.GetOwner().GetLogin(),
		repo.GetName(),
		base,
		head,
		&github.ListOptions{},
	)
	if err != nil {
		return "", fmt.Errorf("failed to compare commits: %v", err)
	}

	var diff string
	for _, file := range comparison.Files {
		if file.Patch != nil {
			diff += *file.Patch
		}
	}
	return diff, nil
}

func (app *SecretDetectorApp) createStatus(ctx context.Context, client *github.Client,
	repo *github.Repository, commit string, findings []models.SecretFinding) error {

	var description string
	state := "success"

	// Check if any valid secrets were found
	validSecrets := false
	secretCount := 0

	for _, finding := range findings {
		if finding.IsValid {
			validSecrets = true
			secretCount++
		}
	}

	if validSecrets {
		state = "failure"
		description = fmt.Sprintf("Blocked: Found %d valid secrets (certificate/key)", secretCount)
	} else if len(findings) > 0 {
		// Findings exist but none are valid (test data, etc.)
		description = fmt.Sprintf("No valid secrets detected (%d invalid/test secrets found)", len(findings))
	} else {
		description = "No secrets detected"
	}

	status := &github.RepoStatus{
		State:       &state,
		Description: &description,
		Context:     github.String("secrets-detector"),
	}

	_, _, err := client.Repositories.CreateStatus(
		ctx,
		repo.GetOwner().GetLogin(),
		repo.GetName(),
		commit,
		status,
	)
	if err != nil {
		return fmt.Errorf("failed to create status: %v", err)
	}

	return nil
}

func (app *SecretDetectorApp) handlePushEvent(ctx context.Context, client *github.Client, event *github.PushEvent) error {
	base := event.GetBefore()
	head := event.GetAfter()
	repo := event.GetRepo()

	// Collect all content to scan
	var contentToScan []string

	if app.testMode {
		// In test mode, skip GitHub API calls and just use commit messages
		app.logger.Printf("Running in test mode - skipping diff retrieval from GitHub API")

		// Just use the commit messages for validation
		for _, commit := range event.Commits {
			contentToScan = append(contentToScan, commit.GetMessage())
		}
	} else {
		// Normal mode - get diff from GitHub API
		diff, err := app.getDiff(ctx, client, &github.Repository{Owner: repo.Owner, Name: repo.Name}, base, head)
		if err != nil {
			return fmt.Errorf("failed to get diff: %v", err)
		}
		contentToScan = append(contentToScan, diff)

		// Also add commit messages
		for _, commit := range event.Commits {
			contentToScan = append(contentToScan, commit.GetMessage())
		}
	}

	// Combine all content with newlines
	combinedContent := strings.Join(contentToScan, "\n")
	app.logger.Printf("Content to scan: %s", combinedContent)

	findings, err := app.validateContent(ctx, combinedContent)
	if err != nil {
		return fmt.Errorf("failed to validate content: %v", err)
	}

	// Convert PushEventRepository to Repository
	repository := &github.Repository{
		Owner: &github.User{Login: github.String(repo.GetOwner().GetName())},
		Name:  github.String(repo.GetName()),
	}

	// Log findings to database
	if len(findings) > 0 {
		for _, finding := range findings {
			// Only block if the secret is valid
			if finding.IsValid {
				app.logger.Printf("BLOCKING: Found valid %s in commit", finding.Type)

				// Log to database
				repoModel := &models.Repository{
					Name: *repository.Name,
					Owner: &models.Owner{
						Login: *repository.Owner.Login,
						Type:  "User", // Default to user, could be overridden if known
					},
				}

				err := app.db.RecordDetection(
					ctx,
					repoModel,
					finding,
					head,
				)

				if err != nil {
					app.logger.Printf("Error recording detection: %v", err)
				}
			} else {
				app.logger.Printf("ALLOWING: Found invalid/test %s in commit", finding.Type)

				// Log to database with is_blocked=false
				repoModel := &models.Repository{
					Name: *repository.Name,
					Owner: &models.Owner{
						Login: *repository.Owner.Login,
						Type:  "User", // Default to user, could be overridden if known
					},
				}

				// Mark as not blocked since it's invalid/test data
				finding.Message += " (Commit allowed - not blocked)"

				err := app.db.RecordDetection(
					ctx,
					repoModel,
					finding,
					head,
				)

				if err != nil {
					app.logger.Printf("Error recording detection: %v", err)
				}
			}
		}
	}

	// In test mode, we can skip the create status call as well
	if app.testMode {
		app.logger.Printf("Test mode: Skipping GitHub status update")
		return nil
	}

	// Create GitHub status based on findings
	return app.createStatus(ctx, client, repository, head, findings)
}

func (app *SecretDetectorApp) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	host := r.Header.Get("X-GitHub-Enterprise-Host")
	if host == "" {
		host = "github.com"
	}

	config, exists := app.configs[host]
	if !exists {
		app.logger.Printf("Unknown GitHub instance: %s", host)
		http.Error(w, "Unknown GitHub instance", http.StatusBadRequest)
		return
	}

	// Debug logging to troubleshoot signature validation
	app.logger.Printf("Received webhook with signature: %s", r.Header.Get("X-Hub-Signature"))

	// Read the request body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		app.logger.Printf("Error reading request body: %v", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// Restore the body for later use
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Log the first 100 bytes of the payload for debugging
	payloadPrefix := string(bodyBytes)
	if len(payloadPrefix) > 100 {
		payloadPrefix = payloadPrefix[:100] + "..."
	}
	app.logger.Printf("Received payload (first 100 bytes): %s", payloadPrefix)

	// Calculate signature manually to compare with received signature
	mac := hmac.New(sha1.New, []byte(config.WebhookSecret))
	mac.Write(bodyBytes)
	expectedSig := "sha1=" + hex.EncodeToString(mac.Sum(nil))

	// Get the signature from the request
	receivedSig := r.Header.Get("X-Hub-Signature")

	// Log both signatures for comparison
	app.logger.Printf("Expected signature: %s", expectedSig)
	app.logger.Printf("Received signature: %s", receivedSig)

	// Do a manual signature comparison
	signatureIsValid := hmac.Equal(
		[]byte(expectedSig),
		[]byte(receivedSig),
	)

	// If manual validation passes, proceed; otherwise use the library method
	if signatureIsValid {
		app.logger.Printf("Manual signature validation successful")
	} else {
		// Try the library method as backup
		_, err = github.ValidatePayload(r, []byte(config.WebhookSecret))
		if err != nil {
			app.logger.Printf("Signature validation failed: %v", err)
			http.Error(w, "Invalid webhook payload", http.StatusBadRequest)
			return
		}
	}

	// Restore the body again after validation
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Parse the webhook event
	event, err := github.ParseWebHook(github.WebHookType(r), bodyBytes)
	if err != nil {
		app.logger.Printf("Failed to parse webhook: %v", err)
		http.Error(w, "Failed to parse webhook", http.StatusBadRequest)
		return
	}

	client := app.clients[host]

	switch e := event.(type) {
	case *github.PushEvent:
		if err := app.handlePushEvent(ctx, client, e); err != nil {
			app.logger.Printf("Failed to handle push event: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	default:
		app.logger.Printf("Unsupported event type: %s", github.WebHookType(r))
		http.Error(w, "Unsupported event type", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (app *SecretDetectorApp) HandleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		app.logger.Printf("Error decoding request: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	app.logger.Printf("Received content to validate. Length: %d", len(req.Content))

	// Handle empty content
	if strings.TrimSpace(req.Content) == "" {
		app.logger.Printf("Empty content received")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.DetectionResponse{
			Findings: []models.SecretFinding{},
			Message:  "No content to validate",
		})
		return
	}

	// Validate the content using validation service
	findings, err := app.validateContent(r.Context(), req.Content)
	if err != nil {
		app.logger.Printf("Error validating content: %v", err)
		http.Error(w, fmt.Sprintf("Error validating content: %v", err), http.StatusInternalServerError)
		return
	}

	// Generate appropriate message
	message := app.getMessage(findings)

	// Return the findings
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.DetectionResponse{
		Findings: findings,
		Message:  message,
	})
}

func (app *SecretDetectorApp) getMessage(findings []models.SecretFinding) string {
	if len(findings) == 0 {
		return "No secrets detected"
	}

	validCount := 0
	for _, finding := range findings {
		if finding.IsValid {
			validCount++
		}
	}

	if validCount > 0 {
		return fmt.Sprintf("Found %d valid secrets that would be blocked", validCount)
	}

	return fmt.Sprintf("Found %d potential secrets, but none are valid or they are test data", len(findings))
}

func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Helper function to get int64 from environment with default
func getEnvInt64(key string, defaultVal int64) int64 {
	if val := os.Getenv(key); val != "" {
		if intVal, err := strconv.ParseInt(val, 10, 64); err == nil {
			return intVal
		}
	}
	return defaultVal
}

func main() {
	logger := log.New(os.Stdout, "[SecretDetector] ", log.LstdFlags|log.Lshortfile)

	// Get validation service URL from environment or use default
	validationServiceURL := os.Getenv("VALIDATION_SERVICE_URL")
	if validationServiceURL == "" {
		validationServiceURL = "http://validation-service:8080"
	}

	// Check if we're in test mode
	testMode := os.Getenv("TEST_MODE") == "true"
	if testMode {
		logger.Printf("Starting in TEST MODE - GitHub API calls will be skipped")
	}

	app := NewSecretDetectorApp(validationServiceURL, logger, testMode)

	// Load GitHub.com private key
	privateKey, err := os.ReadFile("/app/keys/github.pem")
	if err != nil {
		logger.Printf("Warning: Failed to read private key: %v", err)
		privateKey = []byte("dummy-key-for-testing") // Allow app to start for testing
	}

	webhookSecret := os.Getenv("GITHUB_WEBHOOK_SECRET")
	if webhookSecret == "" {
		logger.Printf("Warning: GITHUB_WEBHOOK_SECRET not set, using default test secret")
		webhookSecret = "dummy-secret-for-testing" // Allow app to start for testing
	}

	// Add GitHub.com instance
	appID := getEnvInt64("GITHUB_APP_ID", 12345)                   // Default value for testing
	installationID := getEnvInt64("GITHUB_INSTALLATION_ID", 67890) // Default value for testing

	err = app.AddInstance(&GitHubConfig{
		IsEnterprise:   false,
		AppID:          appID,
		InstallationID: installationID,
		PrivateKey:     string(privateKey),
		WebhookSecret:  webhookSecret,
	})
	if err != nil {
		logger.Printf("Warning: Failed to add GitHub.com instance: %v", err)
	}

	// Add Enterprise instance only if ALL required config is present
	enterpriseHost := os.Getenv("GITHUB_ENTERPRISE_HOST")
	enterpriseSecret := os.Getenv("GITHUB_ENTERPRISE_WEBHOOK_SECRET")
	if enterpriseHost != "" && enterpriseSecret != "" {
		enterpriseKey, err := os.ReadFile("/app/keys/enterprise.pem")
		if err != nil {
			logger.Printf("Warning: Skipping enterprise setup - Failed to read enterprise key: %v", err)
		} else {
			enterpriseAppID := getEnvInt64("GITHUB_ENTERPRISE_APP_ID", 0)
			enterpriseInstallID := getEnvInt64("GITHUB_ENTERPRISE_INSTALLATION_ID", 0)

			if enterpriseAppID > 0 && enterpriseInstallID > 0 {
				err = app.AddInstance(&GitHubConfig{
					IsEnterprise:   true,
					EnterpriseHost: enterpriseHost,
					AppID:          enterpriseAppID,
					InstallationID: enterpriseInstallID,
					PrivateKey:     string(enterpriseKey),
					WebhookSecret:  enterpriseSecret,
				})
				if err != nil {
					logger.Printf("Warning: Failed to add Enterprise instance: %v", err)
				}
			} else {
				logger.Printf("Warning: Skipping enterprise setup - Missing enterprise app ID or installation ID")
			}
		}
	}

	http.HandleFunc("/webhook", app.HandleWebhook)
	http.HandleFunc("/validate", app.HandleValidate)

	listenAddr := ":8080"
	logger.Printf("Starting server on %s", listenAddr)
	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		logger.Fatalf("Server failed: %v", err)
	}
}
