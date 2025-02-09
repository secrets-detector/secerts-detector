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
	"time"

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
}

func NewSecretDetectorApp(validationEndpoint string, logger *log.Logger) *SecretDetectorApp {
	if logger == nil {
		logger = log.New(os.Stdout, "[SecretDetector] ", log.LstdFlags)
	}
	return &SecretDetectorApp{
		configs: make(map[string]*GitHubConfig),
		clients: make(map[string]*github.Client),
		valService: ValidationServiceConfig{
			Endpoint: validationEndpoint,
			Timeout:  30 * time.Second,
		},
		logger: logger,
	}
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

func (app *SecretDetectorApp) getDiff(ctx context.Context, client *github.Client, repo *github.Repository, base, head string) (string, error) {
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

func (app *SecretDetectorApp) createStatus(ctx context.Context, client *github.Client, repo *github.Repository, commit string, findings []models.SecretFinding) error {
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

	fullRepo := &github.Repository{
		Owner: &github.User{Login: github.String(repo.GetOwner().GetName())},
		Name:  github.String(repo.GetName()),
	}

	diff, err := app.getDiff(ctx, client, fullRepo, base, head)
	if err != nil {
		return fmt.Errorf("failed to get diff: %v", err)
	}

	findings, err := app.validateContent(ctx, diff)
	if err != nil {
		return fmt.Errorf("failed to validate content: %v", err)
	}

	if err := app.createStatus(ctx, client, fullRepo, head, findings); err != nil {
		return fmt.Errorf("failed to create status: %v", err)
	}

	return nil
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

func main() {
	logger := log.New(os.Stdout, "[SecretDetector] ", log.LstdFlags|log.Lshortfile)
	app := NewSecretDetectorApp("http://validation-service:8080", logger)

	// Load private key from file
	privateKey, err := os.ReadFile("path/to/private-key.pem")
	if err != nil {
		logger.Fatalf("Failed to read private key: %v", err)
	}

	// Add GitHub.com instance
	err = app.AddInstance(&GitHubConfig{
		IsEnterprise:   false,
		AppID:          12345, // Replace with your App ID
		InstallationID: 67890, // Replace with your Installation ID
		PrivateKey:     string(privateKey),
		WebhookSecret:  os.Getenv("GITHUB_WEBHOOK_SECRET"),
	})
	if err != nil {
		logger.Fatalf("Failed to add GitHub.com instance: %v", err)
	}

	// Add Enterprise instance (optional)
	if os.Getenv("GITHUB_ENTERPRISE_HOST") != "" {
		enterpriseKey, err := os.ReadFile("path/to/enterprise-key.pem")
		if err != nil {
			logger.Fatalf("Failed to read enterprise key: %v", err)
		}

		err = app.AddInstance(&GitHubConfig{
			IsEnterprise:   true,
			EnterpriseHost: os.Getenv("GITHUB_ENTERPRISE_HOST"),
			AppID:          54321,
			InstallationID: 98765,
			PrivateKey:     string(enterpriseKey),
			WebhookSecret:  os.Getenv("GITHUB_ENTERPRISE_WEBHOOK_SECRET"),
		})
		if err != nil {
			logger.Fatalf("Failed to add Enterprise instance: %v", err)
		}
	}

	http.HandleFunc("/webhook", app.HandleWebhook)
	logger.Printf("Starting server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		logger.Fatalf("Server failed: %v", err)
	}
}
