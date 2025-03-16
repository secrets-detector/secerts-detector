package scanner

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/go-github/v45/github"
)

// GitHubClient wraps the GitHub API client
type GitHubClient struct {
	client *github.Client
	logger *log.Logger
}

// NewGitHubClient creates a new GitHub client using a personal access token
func NewGitHubClient(token string, baseURL string, logger *log.Logger) *GitHubClient {
	// Create HTTP client with token authentication
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &AuthTransport{
			Token: token,
			Base:  http.DefaultTransport,
		},
	}

	var client *github.Client

	// Check if we're using GitHub Enterprise
	if baseURL != "https://api.github.com/" {
		// Parse the base URL
		baseEndpoint, err := url.Parse(baseURL)
		if err != nil {
			logger.Printf("Invalid GitHub base URL %s: %v, falling back to github.com", baseURL, err)
			client = github.NewClient(httpClient)
		} else {
			// Create client with enterprise URL
			var createErr error
			client, createErr = github.NewEnterpriseClient(baseEndpoint.String(), baseEndpoint.String(), httpClient)
			if createErr != nil {
				logger.Printf("Failed to create GitHub Enterprise client: %v, falling back to github.com", createErr)
				client = github.NewClient(httpClient)
			}
		}
	} else {
		// Create standard GitHub client
		client = github.NewClient(httpClient)
	}

	logger.Printf("Initialized GitHub client with token authentication")
	return &GitHubClient{
		client: client,
		logger: logger,
	}
}

// AuthTransport is an http.RoundTripper that adds authentication
type AuthTransport struct {
	Token string
	Base  http.RoundTripper
}

// RoundTrip implements the http.RoundTripper interface
func (t *AuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	req2 := req.Clone(req.Context())

	// Add authorization header
	req2.Header.Set("Authorization", "token "+t.Token)

	// Send the request using the base transport
	return t.Base.RoundTrip(req2)
}

// GetRepository gets a single repository
func (gc *GitHubClient) GetRepository(ctx context.Context, owner, repo string) (*github.Repository, error) {
	repository, resp, err := gc.client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository %s/%s: %w", owner, repo, err)
	}

	// Update rate limit if available
	if resp != nil {
		gc.logger.Printf("Rate limit: %d/%d, reset at: %s",
			resp.Rate.Remaining, resp.Rate.Limit, resp.Rate.Reset.Format(time.RFC3339))
	}

	return repository, nil
}

// ListRepositoriesByOwner lists repositories for a specific owner/org
func (gc *GitHubClient) ListRepositoriesByOwner(ctx context.Context, owner string, pageSize int, throttler *Throttler) ([]*github.Repository, error) {
	var allRepos []*github.Repository
	opts := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{
			PerPage: pageSize,
		},
	}

	// Try to get repositories treating owner as an organization
	for {
		repos, resp, err := gc.client.Repositories.ListByOrg(ctx, owner, opts)
		if err != nil {
			// If not found as org, try as user
			if isNotFound(err) {
				gc.logger.Printf("%s not found as org, trying as user", owner)
				break
			}
			return nil, fmt.Errorf("failed to list repositories for org %s: %w", owner, err)
		}

		allRepos = append(allRepos, repos...)

		// Update rate limit info if available
		if resp != nil && throttler != nil {
			throttler.UpdateRateLimitInfo(resp.Rate)

			// Wait if we need to respect rate limits
			if err := throttler.WaitForPermission(ctx); err != nil {
				return nil, err
			}
		}

		// Check if there are more pages
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	// If no repositories found as org, try as user
	if len(allRepos) == 0 {
		userOpts := &github.RepositoryListOptions{
			ListOptions: github.ListOptions{
				PerPage: pageSize,
			},
		}

		for {
			repos, resp, err := gc.client.Repositories.List(ctx, owner, userOpts)
			if err != nil {
				return nil, fmt.Errorf("failed to list repositories for user %s: %w", owner, err)
			}

			allRepos = append(allRepos, repos...)

			// Update rate limit info if available
			if resp != nil && throttler != nil {
				throttler.UpdateRateLimitInfo(resp.Rate)

				// Wait if we need to respect rate limits
				if err := throttler.WaitForPermission(ctx); err != nil {
					return nil, err
				}
			}

			// Check if there are more pages
			if resp.NextPage == 0 {
				break
			}
			userOpts.Page = resp.NextPage
		}
	}

	return allRepos, nil
}

// ListAllRepositories lists all repositories accessible to the authenticated user
func (gc *GitHubClient) ListAllRepositories(ctx context.Context, pageSize int, throttler *Throttler) ([]*github.Repository, error) {
	var allRepos []*github.Repository
	opts := &github.RepositoryListOptions{
		ListOptions: github.ListOptions{
			PerPage: pageSize,
		},
	}

	for {
		repos, resp, err := gc.client.Repositories.List(ctx, "", opts)
		if err != nil {
			return nil, fmt.Errorf("failed to list repositories: %w", err)
		}

		allRepos = append(allRepos, repos...)

		// Update rate limit info if available
		if resp != nil && throttler != nil {
			throttler.UpdateRateLimitInfo(resp.Rate)

			// Wait if we need to respect rate limits
			if err := throttler.WaitForPermission(ctx); err != nil {
				return nil, err
			}
		}

		// Check if there are more pages
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allRepos, nil
}

// ListCommits lists commits for a repository
func (gc *GitHubClient) ListCommits(ctx context.Context, repo *github.Repository, pageSize int, throttler *Throttler, maxDepth int) ([]*github.RepositoryCommit, error) {
	var allCommits []*github.RepositoryCommit
	opts := &github.CommitsListOptions{
		ListOptions: github.ListOptions{
			PerPage: pageSize,
		},
	}

	// Keep track of how many commits we've fetched
	totalFetched := 0

	for {
		commits, resp, err := gc.client.Repositories.ListCommits(ctx, repo.GetOwner().GetLogin(), repo.GetName(), opts)
		if err != nil {
			return nil, fmt.Errorf("failed to list commits for %s: %w", repo.GetFullName(), err)
		}

		allCommits = append(allCommits, commits...)
		totalFetched += len(commits)

		// Update rate limit info if available
		if resp != nil && throttler != nil {
			throttler.UpdateRateLimitInfo(resp.Rate)

			// Wait if we need to respect rate limits
			if err := throttler.WaitForPermission(ctx); err != nil {
				return nil, err
			}
		}

		// Check if we've reached the maximum depth or there are no more pages
		if totalFetched >= maxDepth || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	// If we fetched more commits than the max depth, trim the slice
	if maxDepth > 0 && totalFetched > maxDepth {
		allCommits = allCommits[:maxDepth]
	}

	return allCommits, nil
}

// GetCommitContent gets the content of a specific commit
func (gc *GitHubClient) GetCommitContent(ctx context.Context, repo *github.Repository, commitSHA string, throttler *Throttler) (string, error) {
	// First, get the commit to get the files
	commit, resp, err := gc.client.Repositories.GetCommit(ctx, repo.GetOwner().GetLogin(), repo.GetName(), commitSHA, &github.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get commit %s: %w", commitSHA, err)
	}

	// Update rate limit info if available
	if resp != nil && throttler != nil {
		throttler.UpdateRateLimitInfo(resp.Rate)

		// Wait if we need to respect rate limits
		if err := throttler.WaitForPermission(ctx); err != nil {
			return "", err
		}
	}

	// Combine the contents of all files in the commit
	var allContent strings.Builder
	for _, file := range commit.Files {
		// Skip deleted files
		if file.GetStatus() == "removed" {
			continue
		}

		// Add file header
		allContent.WriteString(fmt.Sprintf("--- %s ---\n", file.GetFilename()))

		// Get file content at this commit
		content, err := gc.getFileContentAtCommit(ctx, repo, file.GetFilename(), commitSHA, throttler)
		if err != nil {
			gc.logger.Printf("Failed to get content for file %s at commit %s: %v", file.GetFilename(), commitSHA, err)
			continue
		}

		// Add file content
		allContent.WriteString(content)
		allContent.WriteString("\n\n")
	}

	return allContent.String(), nil
}

// getFileContentAtCommit gets the content of a file at a specific commit
func (gc *GitHubClient) getFileContentAtCommit(ctx context.Context, repo *github.Repository, path, commitSHA string, throttler *Throttler) (string, error) {
	// Get file content using GetContents with the commit SHA as reference
	fileContent, directoryContent, resp, err := gc.client.Repositories.GetContents(
		ctx,
		repo.GetOwner().GetLogin(),
		repo.GetName(),
		path,
		&github.RepositoryContentGetOptions{
			Ref: commitSHA,
		},
	)

	// Update rate limit info if response is not nil
	if resp != nil && throttler != nil {
		throttler.UpdateRateLimitInfo(resp.Rate)
	}

	if err != nil {
		// Check if it's a rate limit error
		if isRateLimitError(err) && throttler != nil {
			// Wait for permission to continue
			if err := throttler.WaitForPermission(ctx); err != nil {
				return "", err
			}
			// Retry the request
			return gc.getFileContentAtCommit(ctx, repo, path, commitSHA, throttler)
		}
		return "", fmt.Errorf("failed to get content for file %s at commit %s: %w", path, commitSHA, err)
	}

	// Handle file content
	if fileContent != nil {
		content, err := fileContent.GetContent()
		if err != nil {
			return "", fmt.Errorf("failed to decode content for file %s: %w", path, err)
		}
		return content, nil
	}

	// Handle directory content
	if directoryContent != nil && len(directoryContent) > 0 {
		gc.logger.Printf("Path %s returned %d items, expected a single file", path, len(directoryContent))
		return "", fmt.Errorf("path %s is a directory, not a file", path)
	}

	return "", fmt.Errorf("unexpected content type for path %s", path)
}

// Check if an error is a "not found" error
func isNotFound(err error) bool {
	if gerr, ok := err.(*github.ErrorResponse); ok {
		return gerr.Response.StatusCode == http.StatusNotFound
	}
	return false
}

// Check if an error is a rate limit error
func isRateLimitError(err error) bool {
	if _, ok := err.(*github.RateLimitError); ok {
		return true
	}
	return false
}
