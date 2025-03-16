package scanner

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/google/go-github/v45/github"
)

// Throttler manages GitHub API rate limits
type Throttler struct {
	hourlyLimit int
	remaining   int
	resetTime   time.Time
	pauseTime   time.Duration
	logger      *log.Logger
	mu          sync.Mutex
	warnedLow   bool
}

// NewThrottler creates a new throttler for GitHub API rate limiting
func NewThrottler(hourlyLimit int, pauseTime time.Duration, logger *log.Logger) *Throttler {
	return &Throttler{
		hourlyLimit: hourlyLimit,
		remaining:   hourlyLimit,               // Start with full limit until we get real values
		resetTime:   time.Now().Add(time.Hour), // Default reset time
		pauseTime:   pauseTime,
		logger:      logger,
		warnedLow:   false,
	}
}

// UpdateRateLimitInfo updates rate limit information from GitHub API response
func (t *Throttler) UpdateRateLimitInfo(rate github.Rate) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.remaining = rate.Remaining
	t.resetTime = rate.Reset.Time
	t.hourlyLimit = rate.Limit

	// Log when we're getting low on requests, but only once to avoid log spam
	if t.remaining < t.hourlyLimit/10 && !t.warnedLow {
		t.logger.Printf("WARNING: API rate limit getting low: %d/%d requests remaining, reset at %s",
			t.remaining, t.hourlyLimit, t.resetTime.Format(time.RFC3339))
		t.warnedLow = true
	} else if t.remaining > t.hourlyLimit/5 {
		// Reset warning flag when we have more capacity
		t.warnedLow = false
	}
}

// WaitForPermission waits until it's safe to make another API request
func (t *Throttler) WaitForPermission(ctx context.Context) error {
	t.mu.Lock()
	remaining := t.remaining
	resetTime := t.resetTime
	limit := t.hourlyLimit
	t.mu.Unlock()

	// Calculate percentage remaining to make decisions more proportional
	percentRemaining := float64(remaining) / float64(limit) * 100

	// If we have plenty of requests remaining (more than 5%), proceed immediately
	if percentRemaining > 5 {
		return nil
	}

	// If we're critically low (less than 1% or fewer than 10 requests), wait until reset
	if percentRemaining < 1 || remaining < 10 {
		timeUntilReset := resetTime.Sub(time.Now())
		if timeUntilReset > 0 {
			t.logger.Printf("Rate limit critical (%d remaining), pausing until reset in %v",
				remaining, timeUntilReset.Round(time.Second))

			// Wait until reset or context cancellation
			timer := time.NewTimer(timeUntilReset)
			defer timer.Stop()

			select {
			case <-timer.C:
				// Reset time reached
				t.mu.Lock()
				t.remaining = t.hourlyLimit // Assume full quota after reset
				t.mu.Unlock()
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	} else if percentRemaining < 5 {
		// We're getting low (1-5%), implement adaptive backoff strategy based on remaining percentage
		// The closer to 1%, the longer we wait
		adaptiveDelay := time.Duration((5 - percentRemaining) / 4 * float64(t.pauseTime))
		if adaptiveDelay < time.Second {
			adaptiveDelay = time.Second
		}

		t.logger.Printf("Rate limit low (%.1f%% remaining), pausing for %v",
			percentRemaining, adaptiveDelay)

		timer := time.NewTimer(adaptiveDelay)
		defer timer.Stop()

		select {
		case <-timer.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}
