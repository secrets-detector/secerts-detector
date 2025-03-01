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

func NewDB(host, port, user, password, dbname string) (*DB, error) {
	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("error connecting to database: %v", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("error connecting to the database: %v", err)
	}

	logger := log.New(log.Writer(), "[DB] ", log.LstdFlags)
	logger.Printf("Successfully connected to PostgreSQL database")

	return &DB{db, logger}, nil
}

func (db *DB) RecordDetection(ctx context.Context, repo *models.Repository, finding models.SecretFinding, commit string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("error starting transaction: %v", err)
	}
	defer tx.Rollback()

	db.logger.Printf("Recording detection for repo %s/%s, secret type: %s", repo.Owner.Login, repo.Name, finding.Type)

	// Get or create repository
	var repoID int
	err = tx.QueryRowContext(ctx,
		`INSERT INTO repositories (name, owner, is_enterprise) 
         VALUES ($1, $2, $3) 
         ON CONFLICT (owner, name) DO UPDATE SET name = EXCLUDED.name 
         RETURNING id`,
		repo.Name, repo.Owner.Login, repo.Owner.Type == "Organization",
	).Scan(&repoID)
	if err != nil {
		return fmt.Errorf("error upserting repository: %v", err)
	}

	// Determine if we should block based on IsValid field
	isBlocked := finding.IsValid

	// Record detection
	var detectionID int
	err = tx.QueryRowContext(ctx,
		`INSERT INTO secret_detections 
         (repository_id, commit_hash, secret_type, secret_location, 
          line_number, is_blocked, validation_status, branch_name, author, commit_timestamp, detected_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         RETURNING id`,
		repoID, commit, finding.Type, finding.FilePath,
		finding.StartPos, isBlocked,
		map[bool]string{true: "VALID", false: "INVALID"}[finding.IsValid],
		"main", "unknown", time.Now(), time.Now(),
	).Scan(&detectionID)
	if err != nil {
		return fmt.Errorf("error inserting detection: %v", err)
	}

	// Record validation history
	_, err = tx.ExecContext(ctx,
		`INSERT INTO validation_history 
         (detection_id, validation_result, validation_message, validated_at)
         VALUES ($1, $2, $3, $4)`,
		detectionID, finding.IsValid, finding.Message, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("error inserting validation history: %v", err)
	}

	db.logger.Printf("Successfully recorded detection #%d (blocked: %t)", detectionID, isBlocked)

	return tx.Commit()
}

func (db *DB) GetMetrics(ctx context.Context, start, end time.Time) ([]models.Metrics, error) {
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
