package models

import "time"

type Metrics struct {
	Date           time.Time
	Owner          string
	Repository     string
	SecretType     string
	Status         string
	DetectionCount int
	BlockedCount   int
}

type RiskMetrics struct {
	Owner             string
	Repository        string
	TotalDetections   int
	UniqueSecretTypes int
	LastDetection     time.Time
	TotalBlocked      int
}

type Repository struct {
	ID        int64
	Name      string
	Owner     *Owner
	IsPrivate bool
}

type Owner struct {
	Login string
	Type  string
}
