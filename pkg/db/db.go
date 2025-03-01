package db

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"secrets-detector/pkg/models"
	"time"

	_ "github.com/lib/pq"
)

type DB struct {
	*sql.DB
	logger *log.Logger
}

// NewDB establishes a connection to the database with retry logic
func NewDB(host, port, user, password, dbname string) (*DB, error) {
	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname,
	)

	logger := log.New(log.Writer(), "[DB] ", log.LstdFlags)

	// Add retry logic for database connection
	var db *sql.DB
	var err error

	maxRetries := 5
	retryDelay := 5 * time.Second

	for i := 0; i < maxRetries; i++ {
		logger.Printf("Attempting to connect to PostgreSQL database (attempt %d/%d)...", i+1, maxRetries)

		db, err = sql.Open("postgres", connStr)
		if err != nil {
			logger.Printf("Error opening database connection: %v", err)
			time.Sleep(retryDelay)
			continue
		}

		// Test the connection
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = db.PingContext(ctx)
		cancel()

		if err == nil {
			logger.Printf("Successfully connected to PostgreSQL database")

			// Set connection pool parameters
			db.SetMaxOpenConns(25)
			db.SetMaxIdleConns(10)
			db.SetConnMaxLifetime(time.Hour)

			return &DB{db, logger}, nil
		}

		logger.Printf("Failed to ping database: %v. Retrying in %v...", err, retryDelay)
		time.Sleep(retryDelay)
	}

	return nil, fmt.Errorf("failed to connect to database after %d attempts: %v", maxRetries, err)
}

// Health returns true if the database connection is working
func (db *DB) Health(ctx context.Context) bool {
	if db == nil || db.DB == nil {
		return false
	}

	// Create a timeout context
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Try a simple query to check connectivity
	rows, err := db.QueryContext(ctx, "SELECT 1")
	if err != nil {
		db.logger.Printf("Database health check failed: %v", err)
		return false
	}
	defer rows.Close()

	return true
}

// RecordDetection logs a secret detection to the database
func (db *DB) RecordDetection(ctx context.Context, repo *models.Repository, finding models.SecretFinding, commit string) error {
	// If database connection is nil, log warning and return error
	if db == nil || db.DB == nil {
		return fmt.Errorf("database connection is nil")
	}

	// Check database connectivity
	if !db.Health(ctx) {
		return fmt.Errorf("database connection is unhealthy")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("error starting transaction: %v", err)
	}
	defer tx.Rollback()

	db.logger.Printf("Recording detection for repo %s/%s, secret type: %s", repo.Owner.Login, repo.Name, finding.Type)

	// Get or create repository with additional logging
	var repoID int
	err = tx.QueryRowContext(ctx,
		`INSERT INTO repositories (name, owner, is_enterprise) 
         VALUES ($1, $2, $3) 
         ON CONFLICT (owner, name) DO UPDATE SET name = EXCLUDED.name 
         RETURNING id`,
		repo.Name, repo.Owner.Login, repo.Owner.Type == "Organization",
	).Scan(&repoID)
	if err != nil {
		db.logger.Printf("Error upserting repository: %v", err)
		return fmt.Errorf("error upserting repository: %v", err)
	}
	db.logger.Printf("Repository ID: %d", repoID)

	// Determine if we should block based on IsValid field
	isBlocked := finding.IsValid

	// Prep filepath/location field - ensure it's not empty
	filePath := finding.FilePath
	if filePath == "" {
		filePath = "commit message or diff"
	}

	// Record detection with improved error handling
	var detectionID int
	err = tx.QueryRowContext(ctx,
		`INSERT INTO secret_detections 
         (repository_id, commit_hash, secret_type, secret_location, 
          line_number, is_blocked, validation_status, branch_name, author, commit_timestamp, detected_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         RETURNING id`,
		repoID, commit, finding.Type, filePath,
		finding.StartPos, isBlocked,
		map[bool]string{true: "VALID", false: "INVALID"}[finding.IsValid],
		"main", "unknown", time.Now(), time.Now(),
	).Scan(&detectionID)
	if err != nil {
		db.logger.Printf("Error inserting detection: %v", err)
		return fmt.Errorf("error inserting detection: %v", err)
	}
	db.logger.Printf("Detection ID: %d", detectionID)

	// If we got this far, record validation history
	_, err = tx.ExecContext(ctx,
		`INSERT INTO validation_history 
         (detection_id, validation_result, validation_message, validated_at)
         VALUES ($1, $2, $3, $4)`,
		detectionID, finding.IsValid, finding.Message, time.Now(),
	)
	if err != nil {
		db.logger.Printf("Error inserting validation history: %v", err)
		return fmt.Errorf("error inserting validation history: %v", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		db.logger.Printf("Error committing transaction: %v", err)
		return fmt.Errorf("error committing transaction: %v", err)
	}

	db.logger.Printf("Successfully recorded detection #%d (blocked: %t)", detectionID, isBlocked)

	return nil
}

func (db *DB) GetMetrics(ctx context.Context, start, end time.Time) ([]models.Metrics, error) {
	// If database connection is nil, return empty slice without error
	if db == nil || db.DB == nil {
		log.Printf("Warning: Database connection is nil, returning empty metrics")
		return []models.Metrics{}, nil
	}

	rows, err := db.QueryContext(ctx,
		`SELECT detection_date, owner, repository_name, 
                secret_type, validation_status, detection_count, blocked_count
         FROM secret_detection_metrics
         WHERE detection_date BETWEEN $1 AND $2
         ORDER BY detection_date DESC`,
		start, end,
	)
	if err != nil {
		return nil, fmt.Errorf("error querying metrics: %v", err)
	}
	defer rows.Close()

	var metrics []models.Metrics
	for rows.Next() {
		var m models.Metrics
		err := rows.Scan(
			&m.Date, &m.Owner, &m.Repository,
			&m.SecretType, &m.Status, &m.DetectionCount, &m.BlockedCount,
		)
		if err != nil {
			return nil, fmt.Errorf("error scanning metrics row: %v", err)
		}
		metrics = append(metrics, m)
	}

	return metrics, nil
}

func (db *DB) GetRepositoryRiskMetrics(ctx context.Context) ([]models.RiskMetrics, error) {
	// If database connection is nil, return empty slice without error
	if db == nil || db.DB == nil {
		log.Printf("Warning: Database connection is nil, returning empty risk metrics")
		return []models.RiskMetrics{}, nil
	}

	rows, err := db.QueryContext(ctx,
		`SELECT owner, repository_name, total_detections, 
                unique_secret_types, last_detection, total_blocked
         FROM repository_risk_metrics
         ORDER BY total_detections DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("error querying risk metrics: %v", err)
	}
	defer rows.Close()

	var metrics []models.RiskMetrics
	for rows.Next() {
		var m models.RiskMetrics
		err := rows.Scan(
			&m.Owner, &m.Repository, &m.TotalDetections,
			&m.UniqueSecretTypes, &m.LastDetection, &m.TotalBlocked,
		)
		if err != nil {
			return nil, fmt.Errorf("error scanning risk metrics row: %v", err)
		}
		metrics = append(metrics, m)
	}

	return metrics, nil
}
