package scanner

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"secrets-detector/pkg/db"
	"secrets-detector/pkg/models"

	"github.com/google/go-github/v45/github"
)

// Config holds the scanner configuration
type Config struct {
	GitHubToken       string
	GitHubBaseURL     string
	Owner             string
	Repo              string
	ExcludedRepos     []string
	ExcludedOrgs      []string
	PageSize          int
	Concurrency       int
	BatchSize         int
	RateLimit         int
	PauseTime         time.Duration
	ValidationURL     string
	ValidationToken   string
	DebugMode         bool
	MaxDepth          int
	ScanPrivate       bool
}

// Scanner implements the repository scanning logic
type Scanner struct {
	config         Config
	db             *db.DB
	logger         *log.Logger
	github         *GitHubClient
	throttler      *Throttler
	validator      *Validator
	repoCounter    int
	commitCounter  int
	secretCounter  int
	processedRepos map[string]bool
	mu             sync.Mutex
}

// NewScanner creates a new scanner with the given configuration
func NewScanner(config Config, database *db.DB, logger *log.Logger) *Scanner {
	// Create GitHub client
	githubClient := NewGitHubClient(config.GitHubToken, config.GitHubBaseURL, logger)
	
	// Create throttler for API rate limiting
	throttler := NewThrottler(config.RateLimit, config.PauseTime, logger)
	
	// Create validator
	validator := NewValidator(config.ValidationURL, config.ValidationToken, logger)
	
	return &Scanner{
		config:         config,
		db:             database,
		logger:         logger,
		github:         githubClient,
		throttler:      throttler,
		validator:      validator,
		repoCounter:    0,
		commitCounter:  0,
		secretCounter:  0,
		processedRepos: make(map[string]bool),
	}
}

// Run executes the scanning process
func (s *Scanner) Run(ctx context.Context) error {
	s.logger.Printf("Starting scanner with concurrency=%d, pageSize=%d, batchSize=%d, maxDepth=%d",
		s.config.Concurrency, s.config.PageSize, s.config.BatchSize, s.config.MaxDepth)
	
	// Get repositories to scan
	repos, err := s.getRepositoriesToScan(ctx)
	if err != nil {
		return fmt.Errorf("failed to get repositories: %w", err)
	}
	
	s.logger.Printf("Found %d repositories to scan", len(repos))
	
	// Process repositories with worker pool
	err = s.processRepositories(ctx, repos)
	
	// Print final summary
	s.mu.Lock()
	repoCount := s.repoCounter
	commitCount := s.commitCounter
	secretCount := s.secretCounter
	s.mu.Unlock()
	
	s.logger.Printf("Scan complete! Processed %d repositories, %d commits, found %d secrets",
		repoCount, commitCount, secretCount)
	
	return err
}

// getRepositoriesToScan returns the list of repositories to scan
func (s *Scanner) getRepositoriesToScan(ctx context.Context) ([]*github.Repository, error) {
	// Check if specific repo is requested
	if s.config.Owner != "" && s.config.Repo != "" {
		s.logger.Printf("Scanning specific repository: %s/%s", s.config.Owner, s.config.Repo)
		repo, err := s.github.GetRepository(ctx, s.config.Owner, s.config.Repo)
		if err != nil {
			return nil, err
		}
		return []*github.Repository{repo}, nil
	}
	
	// Otherwise get all accessible repositories
	var allRepos []*github.Repository
	var err error
	
	if s.config.Owner != "" {
		// Get repositories for specific owner/org
		s.logger.Printf("Scanning repositories for owner: %s", s.config.Owner)
		allRepos, err = s.github.ListRepositoriesByOwner(ctx, s.config.Owner, s.config.PageSize, s.throttler)
	} else {
		// Get all accessible repositories
		s.logger.Println("Scanning all accessible repositories")
		allRepos, err = s.github.ListAllRepositories(ctx, s.config.PageSize, s.throttler)
	}
	
	if err != nil {
		return nil, err
	}
	
	// Apply filters (privacy and exclusion)
	filtered := s.filterRepositories(allRepos)
	s.logger.Printf("After filtering: %d repositories to scan", len(filtered))
	
	return filtered, nil
}

// filterRepositories applies filters to the repository list
func (s *Scanner) filterRepositories(repos []*github.Repository) []*github.Repository {
	filtered := make([]*github.Repository, 0, len(repos))
	
	for _, repo := range repos {
		// Skip if repo is private and we're not scanning private repos
		if repo.GetPrivate() && !s.config.ScanPrivate {
			s.logger.Printf("Skipping private repository: %s", repo.GetFullName())
			continue
		}
		
		// Skip if repo is in excluded list
		fullName := repo.GetFullName()
		excluded := false
		
		for _, excludedRepo := range s.config.ExcludedRepos {
			if fullName == excludedRepo || repo.GetName() == excludedRepo {
				excluded = true
				s.logger.Printf("Excluding repository: %s (matched exclude pattern)", fullName)
				break
			}
		}
		
		if excluded {
			continue
		}
		
		// Skip if owner is in excluded orgs
		owner := repo.GetOwner().GetLogin()
		for _, excludedOrg := range s.config.ExcludedOrgs {
			if owner == excludedOrg {
				excluded = true
				s.logger.Printf("Excluding repository: %s (owner matched excluded org)", fullName)
				break
			}
		}
		
		if !excluded {
			filtered = append(filtered, repo)
		}
	}
	
	return filtered
}

// processRepositories scans multiple repositories using a worker pool
func (s *Scanner) processRepositories(ctx context.Context, repos []*github.Repository) error {
	// Create a worker pool
	workerCount := s.config.Concurrency
	if workerCount > len(repos) {
		workerCount = len(repos)
	}
	
	// Create semaphore to limit concurrency
	sem := make(chan struct{}, workerCount)
	var wg sync.WaitGroup
	
	// Create error channel for collecting errors
	errChan := make(chan error, len(repos))
	
	// To gracefully handle large numbers of repositories, process them in batches
	const batchSize = 50
	var firstErr error
	
	for i := 0; i < len(repos); i += batchSize {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		
		end := i + batchSize
		if end > len(repos) {
			end = len(repos)
		}
		
		batchRepos := repos[i:end]
		s.logger.Printf("Processing batch of %d repositories (%d-%d of %d)",
			len(batchRepos), i+1, end, len(repos))
		
		// Process each repository in the batch with controlled concurrency
		for _, repo := range batchRepos {
			// Check for cancellation
			select {
			case <-ctx.Done():
				wg.Wait()
				return ctx.Err()
			default:
			}
			
			// Skip if already processed
			repoFullName := repo.GetFullName()
			s.mu.Lock()
			if s.processedRepos[repoFullName] {
				s.mu.Unlock()
				continue
			}
			s.processedRepos[repoFullName] = true
			s.mu.Unlock()
			
			// Acquire semaphore slot
			sem <- struct{}{}
			
			wg.Add(1)
			go func(r *github.Repository) {
				defer wg.Done()
				defer func() { <-sem }() // Release semaphore slot
				
				// Process single repository
				if err := s.processRepository(ctx, r); err != nil {
					if err != context.Canceled {
						s.logger.Printf("Error processing repository %s: %v", r.GetFullName(), err)
						errChan <- fmt.Errorf("repository %s: %w", r.GetFullName(), err)
					} else {
						errChan <- err
					}
				}
			}(repo)
		}
		
		// Collect any errors from the batch
		for len(errChan) > 0 {
			err := <-errChan
			if err == context.Canceled {
				wg.Wait()
				return err
			}
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	
	// Wait for all goroutines to finish
	wg.Wait()
	
	// Collect any remaining errors
	close(errChan)
	for err := range errChan {
		if firstErr == nil {
			firstErr = err
		}
	}
	
	return firstErr
}

// processRepository scans a single repository
func (s *Scanner) processRepository(ctx context.Context, repo *github.Repository) error {
	fullName := repo.GetFullName()
	s.logger.Printf("Processing repository: %s", fullName)
	
	// Get commits for the repository with maximum depth
	commits, err := s.github.ListCommits(ctx, repo, s.config.PageSize, s.throttler, s.config.MaxDepth)
	if err != nil {
		return fmt.Errorf("failed to list commits for %s: %w", fullName, err)
	}
	
	s.logger.Printf("Found %d commits in repository %s (limited to max depth %d)", 
		len(commits), fullName, s.config.MaxDepth)
	
	// Process commits in batches to limit memory usage
	for i := 0; i < len(commits); i += s.config.BatchSize {
		// Check for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		
		// Determine batch size
		end := i + s.config.BatchSize
		if end > len(commits) {
			end = len(commits)
		}
		
		batch := commits[i:end]
		if s.config.DebugMode {
			s.logger.Printf("Processing batch of %d commits in %s (%d/%d)",
				len(batch), fullName, i+len(batch), len(commits))
		}
		
		// Process batch
		if err := s.processCommitBatch(ctx, repo, batch); err != nil {
			if err == context.Canceled {
				return err
			}
			s.logger.Printf("Error processing batch in %s: %v", fullName, err)
			// Continue with next batch despite errors
		}
	}
	
	// Update repo counter
	s.mu.Lock()
	s.repoCounter++
	s.mu.Unlock()
	
	return nil
}

// processCommitBatch processes a batch of commits
func (s *Scanner) processCommitBatch(ctx context.Context, repo *github.Repository, commits []*github.RepositoryCommit) error {
	// Process commits with controlled concurrency
	sem := make(chan struct{}, s.config.Concurrency)
	var wg sync.WaitGroup
	errChan := make(chan error, len(commits))
	
	for _, commit := range commits {
		// Check for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		
		// Acquire semaphore slot
		sem <- struct{}{}
		
		wg.Add(1)
		go func(c *github.RepositoryCommit) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore slot
			
			// Process the commit
			if err := s.processCommit(ctx, repo, c); err != nil {
				if err != context.Canceled {
					errChan <- fmt.Errorf("commit %s: %w", c.GetSHA(), err)
				} else {
					errChan <- err
				}
			}
		}(commit)
	}
	
	// Wait for all goroutines to finish
	wg.Wait()
	close(errChan)
	
	// Return the first error encountered, if any
	for err := range errChan {
		if err == context.Canceled {
			return err
		}
		return err // Return first error
	}
	
	return nil
}

// processCommit analyzes a single commit for secrets
func (s *Scanner) processCommit(ctx context.Context, repo *github.Repository, commit *github.RepositoryCommit) error {
	sha := commit.GetSHA()
	if sha == "" {
		return errors.New("commit SHA is empty")
	}
	
	// Update commit counter - do this first to track our progress
	s.mu.Lock()
	s.commitCounter++
	s.mu.Unlock()
	
	// Every 100 commits, log progress
	if s.commitCounter%100 == 0 {
		s.logger.Printf("Progress: Processed %d commits, found %d secrets", 
			s.commitCounter, s.secretCounter)
	}
	
	// Get the commit changes
	content, err := s.github.GetCommitContent(ctx, repo, sha, s.throttler)
	if err != nil {
		return fmt.Errorf("failed to get content for commit %s: %w", sha, err)
	}
	
	if content == "" {
		// No content to scan (empty commit or only removed files)
		return nil
	}
	
	// Validate content for secrets
	findings, err := s.validator.ValidateContent(ctx, content)
	if err != nil {
		return fmt.Errorf("failed to validate content for commit %s: %w", sha, err)
	}
	
	if len(findings) == 0 {
		// No secrets found
		return nil
	}
	
	// Record findings in database
	repoModel := &models.Repository{
		Name: repo.GetName(),
		Owner: &models.Owner{
			Login: repo.GetOwner().GetLogin(),
			Type:  repo.GetOwner().GetType(),
		},
	}
	
	for _, finding := range findings {
		// Only record valid secrets by default
		if finding.IsValid || s.config.DebugMode {
			s.logger.Printf("Found %s %s in commit %s of %s",
				finding.IsValid ? "valid" : "invalid", 
				finding.Type, sha[:8], repo.GetFullName())
			
			err := s.db.RecordDetection(
				ctx,
				repoModel,
				finding,
				sha,
			)
			
			if err != nil {
				s.logger.Printf("Error recording detection: %v", err)
				// Continue despite error
			} else if finding.IsValid {
				// Update secret counter for valid secrets
				s.mu.Lock()
				s.secretCounter++
				s.mu.Unlock()
			}
		}
	}
	
	return nil
}