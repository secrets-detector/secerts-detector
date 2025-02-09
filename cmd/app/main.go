package main

import (
	"bytes"
	"context"
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
	db         *db.DB // New database field
}

func NewSecretDetectorApp(validationEndpoint string, logger *log.Logger) *SecretDetectorApp {
	if logger == nil {
		logger = log.New(os.Stdout, "[SecretDetector] ", log.LstdFlags|log.Lshortfile)
	}

	patterns, err := loadPatterns("/app/config/config.json")
	if err != nil {
		logger.Printf("Warning: Failed to load patterns: %v", err)
	}

	// Initialize database connection
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")

	dbConn, err := db.NewDB(dbHost, dbPort, dbUser, dbPassword, dbName)
	if err != nil {
		logger.Printf("Warning: Failed to connect to database: %v", err)
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
	}
}

func loadPatterns(configPath string) (map[string]*regexp.Regexp, error) {
	log.Printf("Attempting to load patterns from: %s", configPath)

	configFile, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("Error reading config file: %v", err)
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	log.Printf("Config file content: %s", string(configFile))

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

	if len(findings) > 0 {
		state = "failure"
		description = fmt.Sprintf("Found %d potential secrets", len(findings))
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

	// Get the diff content
	diff, err := app.getDiff(ctx, client, &github.Repository{Owner: repo.Owner, Name: repo.Name}, base, head)
	if err != nil {
		return fmt.Errorf("failed to get diff: %v", err)
	}

	// Collect all content to scan
	var contentToScan []string
	contentToScan = append(contentToScan, diff)

	// Add commit messages to scan
	for _, commit := range event.Commits {
		contentToScan = append(contentToScan, commit.GetMessage())
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

	// Add missing return statement
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

	payload, err := github.ValidatePayload(r, []byte(config.WebhookSecret))
	if err != nil {
		app.logger.Printf("Invalid webhook payload: %v", err)
		http.Error(w, "Invalid webhook payload", http.StatusBadRequest)
		return
	}

	event, err := github.ParseWebHook(github.WebHookType(r), payload)
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

	app.logger.Printf("Number of loaded patterns: %d", len(app.patterns))
	for patternType := range app.patterns {
		app.logger.Printf("Available pattern: %s", patternType)
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
	app.logger.Printf("Content preview: %s", truncateString(req.Content, 100))

	// Handle empty content
	if strings.TrimSpace(req.Content) == "" {
		app.logger.Printf("Empty content received")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.ValidationResponse{
			IsValid: true,
			Message: "No content to validate",
		})
		return
	}
}

func (app *SecretDetectorApp) getMessage(findings []models.SecretFinding) string {
	if len(findings) == 0 {
		return "No secrets detected"
	}
	return fmt.Sprintf("Found %d potential secrets", len(findings))
}

func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func main() {
	logger := log.New(os.Stdout, "[SecretDetector] ", log.LstdFlags|log.Lshortfile)
	app := NewSecretDetectorApp("http://validation-service:8080", logger)

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

	logger.Printf("Starting server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		logger.Fatalf("Server failed: %v", err)
	}
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
