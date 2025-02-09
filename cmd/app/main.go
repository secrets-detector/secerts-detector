package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

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

type SecretDetectorApp struct {
	configs   map[string]*GitHubConfig
	clients   map[string]*github.Client
	validator *Validator
}

func NewSecretDetectorApp() *SecretDetectorApp {
	return &SecretDetectorApp{
		configs: make(map[string]*GitHubConfig),
		clients: make(map[string]*github.Client),
	}
}

func (app *SecretDetectorApp) AddInstance(config *GitHubConfig) error {
	// Create transport for GitHub App authentication
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
		// Enterprise client
		baseURL := fmt.Sprintf("https://%s/api/v3/", config.EnterpriseHost)
		uploadURL := fmt.Sprintf("https://%s/api/uploads/", config.EnterpriseHost)
		client, err = github.NewEnterpriseClient(baseURL, uploadURL, &http.Client{Transport: itr})
	} else {
		// GitHub.com client
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

func (app *SecretDetectorApp) getDiff(client *github.Client, repo *github.Repository, base, head string) (string, error) {
	ctx := context.Background()
	comparison, _, err := client.Repositories.CompareCommits(
		ctx,
		repo.GetOwner().GetLogin(),
		repo.GetName(),
		base,
		head,
		&github.ListOptions{},
	)
	if err != nil {
		return "", err
	}

	var diff string
	for _, file := range comparison.Files {
		diff += *file.Patch
	}
	return diff, nil
}

func (app *SecretDetectorApp) handlePushEvent(client *github.Client, event *github.PushEvent) {
	// Get the changes
	base := event.GetBefore()
	head := event.GetAfter()
	repo := event.GetRepo()

	// Fetch the diff
	diff, err := app.getDiff(client, repo, base, head)
	if err != nil {
		log.Printf("Failed to get diff: %v", err)
		return
	}

	// Call validation service
	findings, err := app.validateContent(diff)
	if err != nil {
		log.Printf("Failed to validate content: %v", err)
		return
	}

	if len(findings) > 0 {
		// Create failure status
		status := &github.RepoStatus{
			State:       github.String("failure"),
			Description: github.String("Secrets detected in commit"),
			Context:     github.String("secrets-detector"),
		}

		_, _, err = client.Repositories.CreateStatus(
			context.Background(),
			repo.GetOwner().GetLogin(),
			repo.GetName(),
			head,
			status,
		)

		if err != nil {
			log.Printf("Failed to create status: %v", err)
		}
	}
}

// validateContent calls the validation service
func (app *SecretDetectorApp) validateContent(content string) ([]models.SecretFinding, error) {
	// TODO: Implement call to validation service
	return nil, nil
}

func (app *SecretDetectorApp) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	// Determine which instance this webhook is from
	host := r.Header.Get("X-GitHub-Enterprise-Host")
	if host == "" {
		host = "github.com"
	}

	config, exists := app.configs[host]
	if !exists {
		http.Error(w, "Unknown GitHub instance", http.StatusBadRequest)
		return
	}

	// Validate webhook payload
	payload, err := github.ValidatePayload(r, []byte(config.WebhookSecret))
	if err != nil {
		http.Error(w, "Invalid webhook payload", http.StatusBadRequest)
		return
	}

	event, err := github.ParseWebHook(github.WebHookType(r), payload)
	if err != nil {
		http.Error(w, "Failed to parse webhook", http.StatusBadRequest)
		return
	}

	client := app.clients[host]

	switch e := event.(type) {
	case *github.PushEvent:
		app.handlePushEvent(client, e)
	}

	w.WriteHeader(http.StatusOK)
}

func main() {
	app := NewSecretDetectorApp()

	// Add GitHub.com instance
	err := app.AddInstance(&GitHubConfig{
		IsEnterprise:   false,
		AppID:          12345,                              // Replace with your App ID
		InstallationID: 67890,                              // Replace with your Installation ID
		PrivateKey:     "-----BEGIN PRIVATE KEY-----\n...", // Replace with your private key
		WebhookSecret:  "your-webhook-secret",
	})
	if err != nil {
		log.Fatalf("Failed to add GitHub.com instance: %v", err)
	}

	// Add Enterprise instance
	err = app.AddInstance(&GitHubConfig{
		IsEnterprise:   true,
		EnterpriseHost: "github.your-company.com",
		AppID:          54321,
		InstallationID: 98765,
		PrivateKey:     "-----BEGIN PRIVATE KEY-----\n...",
		WebhookSecret:  "your-enterprise-webhook-secret",
	})
	if err != nil {
		log.Fatalf("Failed to add Enterprise instance: %v", err)
	}

	http.HandleFunc("/webhook", app.HandleWebhook)
	log.Printf("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
