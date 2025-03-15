package scanner

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v45/github"
	"golang.org/x/oauth2"
)

// GitHubClient provides GitHub API operations
type GitHubClient struct {
	client *github.Client
	logger *log.Logger
}

// NewGitHubClient creates a GitHub client with the provided token and base URL
func NewGitHubClient(token string, baseURL string, logger *log.Logger) *GitHubClient {
	// Create HTTP client with authorization
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &oauth2.Transport{
			Source: oauth2.StaticTokenSource(
				&oauth2.Token{AccessToken: token},
			),
			Base: http.DefaultTransport,
		},
	}

	var client *github.Client

	// Check if we're using GitHub Enterprise
	if baseURL != "https://api.github.com/" {
		// Parse the base URL
		baseEndpoint, err := url.Parse(baseURL)
		if err != nil {
			logger.Printf("Warning: Invalid GitHub base URL: %v. Using default.", err)
			client = github.NewClient(httpClient)
		} else {
			// Create client with enterprise URL
			client, err = github.NewEnterpriseClient(baseEndpoint.String(), baseEndpoint.String(), httpClient)
			if err != nil {
				logger.Printf("Warning: Failed to create GitHub Enterprise client: %v. Using default.", err)
				client = github.NewClient(httpClient)
			}
		}
	} else {
		// Create standard GitHub client
		client = github.NewClient(httpClient)
	}

	return &GitHubClient{
		client: client,
		logger: logger,
	}
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

// GetRepository gets a repository by owner and name
func (g *GitHubClient) GetRepository(ctx context.Context, owner, name string) (*github.Repository, error) {
	repo, _, err := g.client.Repositories.Get(ctx, owner, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository %s/%s: %w", owner, name, err)
	}
	return repo, nil
}

// ListRepositoriesByOwner lists repositories for a specific owner or organization
func (g *GitHubClient) ListRepositoriesByOwner(ctx context.Context, owner string, pageSize int, throttler *Throttler) ([]*github.Repository, error) {
	var allRepos []*github.Repository
	opts := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{
			PerPage: pageSize,
		},
	}

	for {
		// Wait for rate limit if necessary
		if err := throttler.WaitForPermission(ctx); err != nil {
			return nil, err
		}

		// Check if we should fetch from org or user
		var (
			repos []*github.Repository
			resp  *github.Response
			err   error
		)

		// Try as organization first
		repos, resp, err = g.client.Repositories.ListByOrg(ctx, owner, opts)

		// If org not found, try as user
		if err != nil && strings.Contains(err.Error(), "404") {
			userOpts := &github.RepositoryListOptions{
				ListOptions: opts.ListOptions,
			}
			repos, resp, err = g.client.Repositories.List(ctx, owner, userOpts)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to list repositories for %s: %w", owner, err)
		}

		// Update rate limit info
		throttler.UpdateRateLimitInfo(resp.Rate)

		// Append results
		allRepos = append(allRepos, repos...)

		// Check if there are more pages
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allRepos, nil
}

// ListAllRepositories lists all repositories accessible to the client
func (g *GitHubClient) ListAllRepositories(ctx context.Context, pageSize int, throttler *Throttler) ([]*github.Repository, error) {
	var allRepos []*github.Repository
	opts := &github.RepositoryListOptions{
		ListOptions: github.ListOptions{
			PerPage: pageSize,
		},
	}

	for {
		// Wait for rate limit if necessary
		if err := throttler.WaitForPermission(ctx); err != nil {
			return nil, err
		}

		repos, resp, err := g.client.Repositories.List(ctx, "", opts)
		if err != nil {
			return nil, fmt.Errorf("failed to list repositories: %w", err)
		}

		// Update rate limit info
		throttler.UpdateRateLimitInfo(resp.Rate)

		// Append results
		allRepos = append(allRepos, repos...)

		// Check if there are more pages
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allRepos, nil
}

// ListCommits lists commits for a repository with maximum depth
func (g *GitHubClient) ListCommits(ctx context.Context, repo *github.Repository, pageSize int, throttler *Throttler, maxDepth int) ([]*github.RepositoryCommit, error) {
	var allCommits []*github.RepositoryCommit
	opts := &github.CommitsListOptions{
		ListOptions: github.ListOptions{
			PerPage: pageSize,
		},
	}

	// Limit the number of commits to fetch
	remaining := maxDepth

	for remaining > 0 {
		// Wait for rate limit if necessary
		if err := throttler.WaitForPermission(ctx); err != nil {
			return nil, err
		}

		// Adjust per-page count for last request
		if remaining < opts.PerPage {
			opts.PerPage = remaining
		}

		commits, resp, err := g.client.Repositories.ListCommits(
			ctx,
			repo.GetOwner().GetLogin(),
			repo.GetName(),
			opts,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to list commits for %s: %w", repo.GetFullName(), err)
		}

		// Update rate limit info
		throttler.UpdateRateLimitInfo(resp.Rate)

		// Append results
		allCommits = append(allCommits, commits...)

		// Reduce remaining count
		remaining -= len(commits)

		// Check if there are more pages
		if resp.NextPage == 0 || len(commits) < opts.PerPage {
			break
		}
		opts.Page = resp.NextPage
	}

	return allCommits, nil
}

// GetCommitContent gets the content of files in a commit
func (g *GitHubClient) GetCommitContent(ctx context.Context, repo *github.Repository, commitSHA string, throttler *Throttler) (string, error) {
	// Wait for rate limit if necessary
	if err := throttler.WaitForPermission(ctx); err != nil {
		return "", err
	}

	// Get the commit details
	commit, resp, err := g.client.Repositories.GetCommit(
		ctx,
		repo.GetOwner().GetLogin(),
		repo.GetName(),
		commitSHA,
		&github.ListOptions{},
	)
	if err != nil {
		return "", fmt.Errorf("failed to get commit %s: %w", commitSHA, err)
	}

	// Update rate limit info
	throttler.UpdateRateLimitInfo(resp.Rate)

	var content strings.Builder

	// Process each file in the commit
	for _, file := range commit.Files {
		// Skip deleted files
		if file.GetStatus() == "removed" {
			continue
		}

		// Get the content of the file at this commit
		fileContent, resp, _, err := g.client.Repositories.GetContents(
			ctx,
			repo.GetOwner().GetLogin(),
			repo.GetName(),
			file.GetFilename(),
			&github.RepositoryContentGetOptions{
				Ref: commitSHA,
			},
		)

		// Update rate limit info if response is not nil
		if resp != nil {
			throttler.UpdateRateLimitInfo(resp.Rate)
		}

		if err != nil {
			g.logger.Printf("Warning: Failed to get content for file %s: %v", file.GetFilename(), err)
			continue
		}

		// Skip directories
		if fileContent == nil {
			continue
		}

		// Get the file content
		fileContentStr, err := fileContent.GetContent()
		if err != nil {
			g.logger.Printf("Warning: Failed to decode content for file %s: %v", file.GetFilename(), err)
			continue
		}

		// Add file header and content
		content.WriteString(fmt.Sprintf("--- %s ---\n", file.GetFilename()))
		content.WriteString(fileContentStr)
		content.WriteString("\n\n")
	}

	return content.String(), nil
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
		appID, err := parseInt64(appIDStr)
		if err != nil {
			return nil, fmt.Errorf("invalid GITHUB_APP_ID: %w", err)
		}

		installID, err := parseInt64(installIDStr)
		if err != nil {
			return nil, fmt.Errorf("invalid GITHUB_INSTALLATION_ID: %w", err)
		}

		return NewGitHubAppClient(appID, installID, keyPath, baseURL, logger)
	}

	return nil, fmt.Errorf("no GitHub authentication method configured")
}

// Helper function to parse int64
func parseInt64(s string) (int64, error) {
	var i int64
	_, err := fmt.Sscanf(s, "%d", &i)
	return i, err
}
