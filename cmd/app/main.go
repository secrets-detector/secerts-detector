package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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

// SafeLogger wraps the standard logger with sanitization methods
type SafeLogger struct {
	*log.Logger
	logLevel string // "debug", "info", "warn", "error"
}

// NewSafeLogger creates a new safe logger with proper sanitization
func NewSafeLogger(logger *log.Logger, level string) *SafeLogger {
	return &SafeLogger{
		Logger:   logger,
		logLevel: strings.ToLower(level),
	}
}

// isLevelEnabled checks if the given log level should be logged
func (s *SafeLogger) isLevelEnabled(level string) bool {
	levels := map[string]int{
		"debug": 0,
		"info":  1,
		"warn":  2,
		"error": 3,
	}

	currentLevel, ok := levels[s.logLevel]
	if !ok {
		return true // Default to showing everything if level is unknown
	}

	requestedLevel, ok := levels[level]
	if !ok {
		return true // Default to showing the message if level is unknown
	}

	return requestedLevel >= currentLevel
}

// Debug logs debug messages, with heavy sanitization in production
func (s *SafeLogger) Debug(format string, v ...interface{}) {
	if !s.isLevelEnabled("debug") {
		return
	}

	// Apply extra sanitization for debug messages
	sanitizedArgs := make([]interface{}, len(v))
	for i, arg := range v {
		switch val := arg.(type) {
		case string:
			sanitizedArgs[i] = sanitizeContent(val)
		default:
			sanitizedArgs[i] = arg
		}
	}

	s.Logger.Printf("[DEBUG] "+format, sanitizedArgs...)
}

// Info logs info messages with moderate sanitization
func (s *SafeLogger) Info(format string, v ...interface{}) {
	if !s.isLevelEnabled("info") {
		return
	}

	// Apply sanitization for info messages
	sanitizedArgs := make([]interface{}, len(v))
	for i, arg := range v {
		switch val := arg.(type) {
		case string:
			if isSensitiveContent(val) {
				sanitizedArgs[i] = "[REDACTED]"
			} else {
				sanitizedArgs[i] = val
			}
		default:
			sanitizedArgs[i] = arg
		}
	}

	s.Logger.Printf("[INFO] "+format, sanitizedArgs...)
}

// Warn logs warning messages
func (s *SafeLogger) Warn(format string, v ...interface{}) {
	if !s.isLevelEnabled("warn") {
		return
	}
	s.Logger.Printf("[WARN] "+format, v...)
}

// Error logs error messages
func (s *SafeLogger) Error(format string, v ...interface{}) {
	if !s.isLevelEnabled("error") {
		return
	}
	s.Logger.Printf("[ERROR] "+format, v...)
}

// LogSignature safely logs a signature value
func (s *SafeLogger) LogSignature(description, signature string) {
	if !s.isLevelEnabled("debug") {
		return
	}
	s.Debug("%s: %s", description, sanitizeSignature(signature))
}

// LogPayload safely logs a payload
func (s *SafeLogger) LogPayload(description, payload string) {
	if !s.isLevelEnabled("debug") {
		return
	}
	s.Debug("%s: %s", description, sanitizePayload(payload))
}

// LogCertificate safely logs certificate information
func (s *SafeLogger) LogCertificate(description, cert string) {
	if !s.isLevelEnabled("debug") {
		return
	}
	s.Debug("%s found, length: %d", description, len(cert))
}

// sanitizeSignature redacts most of a signature for logging
func sanitizeSignature(signature string) string {
	if len(signature) <= 10 {
		return "[REDACTED]"
	}
	// Keep only first 6 and last 4 characters
	return signature[:6] + "..." + signature[len(signature)-4:]
}

// sanitizePayload redacts payload content for logging
func sanitizePayload(payload string) string {
	if len(payload) <= 20 {
		return "[PAYLOAD_REDACTED]"
	}

	// For JSON payloads, extract only the structure, not the values
	if len(payload) > 0 && payload[0] == '{' {
		return "[JSON_PAYLOAD_STRUCTURE_ONLY]"
	}

	// For other payloads, show only length and first few non-sensitive chars
	return fmt.Sprintf("[PAYLOAD_LENGTH: %d chars] %s...",
		len(payload), payload[:10])
}

// sanitizeCertificate redacts certificate content for logging
func sanitizeCertificate(cert string) string {
	if strings.Contains(cert, "BEGIN CERTIFICATE") {
		return "[CERTIFICATE_REDACTED]"
	}
	return cert
}

// sanitizePrivateKey redacts private key content for logging
func sanitizePrivateKey(key string) string {
	if strings.Contains(key, "PRIVATE KEY") {
		return "[PRIVATE_KEY_REDACTED]"
	}
	return key
}

// isSensitiveContent checks if content might contain sensitive data
func isSensitiveContent(content string) bool {
	sensitivePatterns := []string{
		"CERTIFICATE",
		"PRIVATE KEY",
		"SECRET",
		"TOKEN",
		"PASSWORD",
		"AUTH",
		"CRED",
		"KEY",
	}

	lowerContent := strings.ToLower(content)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(lowerContent, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// sanitizeContent is a general function to sanitize potentially sensitive content
func sanitizeContent(content string) string {
	if isSensitiveContent(content) {
		// If content matches sensitive patterns, redact it
		return "[SENSITIVE_CONTENT_REDACTED]"
	}

	// For very long content, truncate it
	if len(content) > 100 {
		return content[:50] + "..." + content[len(content)-10:] +
			fmt.Sprintf(" [TRUNCATED, total length: %d]", len(content))
	}

	return content
}

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
	configs          map[string]*GitHubConfig
	clients          map[string]*github.Client
	valService       ValidationServiceConfig
	logger           *SafeLogger
	patterns         map[string]*regexp.Regexp
	db               *db.DB            // Database field
	testMode         bool              // Field to indicate test mode
	fullFileAnalysis bool              // Field to indicate if we should analyze full files instead of just diffs
	testPatches      []string          // Field to store extracted patches for test mode
	mockFilesMode    bool              // New field to indicate mock files mode
	mockFiles        map[string]string // Map to store mock file contents by filename
}

func NewSecretDetectorApp(validationEndpoint string, logger *log.Logger, testMode bool, fullFileAnalysis bool) *SecretDetectorApp {
	defaultLogger := log.New(os.Stdout, "[SecretDetector] ", log.LstdFlags|log.Lshortfile)
	if logger == nil {
		logger = defaultLogger
	}

	// Create safe logger with appropriate level
	logLevel := "info"
	if val := os.Getenv("LOG_LEVEL"); val != "" {
		logLevel = strings.ToLower(val)
	}
	safeLogger := NewSafeLogger(logger, logLevel)

	// Check if we're in mock files mode
	mockFilesMode := os.Getenv("MOCK_FILES_MODE") == "true"
	if mockFilesMode {
		safeLogger.Info("Starting in MOCK FILES MODE - will use local mock file contents")
	}

	patterns, err := loadPatterns("/app/config/config.json")
	if err != nil {
		safeLogger.Warn("Failed to load patterns: %v", err)
		// Initialize with empty patterns map to prevent nil pointer dereference
		patterns = make(map[string]*regexp.Regexp)
	}

	// Initialize database connection with retries
	var dbConn *db.DB

	// Get database connection parameters
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")

	// Try to connect with retries
	maxRetries := 5
	retryDelay := time.Second * 5

	for i := 0; i < maxRetries; i++ {
		safeLogger.Info("Attempting to connect to database (attempt %d/%d)...", i+1, maxRetries)

		dbConn, err = db.NewDB(dbHost, dbPort, dbUser, dbPassword, dbName)
		if err == nil {
			safeLogger.Info("Successfully connected to database")
			break
		}

		safeLogger.Warn("Failed to connect to database: %v. Retrying in %v...", err, retryDelay)
		time.Sleep(retryDelay)
	}

	if dbConn == nil {
		safeLogger.Warn("All database connection attempts failed. App will run with limited functionality.")
	}

	app := &SecretDetectorApp{
		configs: make(map[string]*GitHubConfig),
		clients: make(map[string]*github.Client),
		valService: ValidationServiceConfig{
			Endpoint: validationEndpoint,
			Timeout:  30 * time.Second,
		},
		logger:           safeLogger,
		patterns:         patterns,
		db:               dbConn,
		testMode:         testMode,
		fullFileAnalysis: fullFileAnalysis,
		testPatches:      make([]string, 0),
		mockFilesMode:    mockFilesMode,
		mockFiles:        make(map[string]string),
	}

	// If in mock files mode, initialize with some test files
	if mockFilesMode {
		app.initializeMockFiles()
	}

	return app
}

// Add method to initialize mock files with sample content
func (app *SecretDetectorApp) initializeMockFiles() {
	// Sample certificate to be detected
	sampleCert := `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA1MTUxMjAwMDBaFw0yNDA1
MTQxMjAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC5eIuoSCHDCIWgI2CObfvgJCyPulUGj0VxbOJmZWzl
JdHmv5QlWcV8Kls5+PnC6hFIQX0/NjR2JlAH7m3KBNDv7B2+bwxlUzSI0T+/eR6v
/Tbw51h+0NbO88UPv3fyr/eXRu1OXqZJUoLN5pRq7PQyyeZXY2ImWCJ1DdoocRBq
aBHctXyZdawOdQs3nalPsOu0U9IXf2RJoCY3+aEk9Hwk5eM55w2UZjsYUOQBKPU9
l1WQhRKUNMqRdCIniRaW5D83g4FSsYqlZcR0zIhjXL4SUwqhYvqQg/O0BUopQZyu
gY0R0vZdepvWK51dHdLqm9YUyJx6V9UlY0A9m27jAgMBAAGjUzBRMB0GA1UdDgQW
BBRTl8Ym4z5GtKLUxGTFZQkBYJ2mdzAfBgNVHSMEGDAWgBRTl8Ym4z5GtKLUxGTF
ZQkBYJ2mdzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBZPJbi
9SJ7WhKZrOVOLNzuDmTfYYvfXCpILDWwYwYYZPGBgyrbbOm+tENpV/ADN4mF6vM3
8OvZg3+tBGK5fSfVHnc/CV9UBGpL89/K2y3fspyQvMuMEVHVqB5XTgUGG5mMDqga
A2kAJhyopkIc4J5VcRE0kdiHYlQlmZjcMnpKYaWZZySVLiqvQi2G+YHvq3z9HMUT
+2PV3mpc6m1ypF/vwVPtPTtc2VT9gYfaZ9Ge2AYQr3L9EYRHsZn3H3Nz6/ufKdja
OO8YFPZCZ+hQkvYPBYjOF0l2qF6KPqkzQgzxBK6xzmY1J9obtr7HwgZ0Ktbk43c8
2HkWMLiKSslaaDcP
-----END CERTIFICATE-----`

	// Sample JSON config with a private key
	sampleConfig := `{
  "api_key": "test_api_key_123",
  "environment": "development",
  "certificate": "-----BEGIN CERTIFICATE-----\\nMIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL\\n-----END CERTIFICATE-----",
  "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCz5HbiHPPGtYd5\\nLcix2lCcOF0bnPOSdJV0jxFG36vZFF1eeTuiloxWymtZ6R695lhWfnUtDuoxeL9t\\nRmQYxEgK982MEQpoearvijpd99piLXZ1ZVXvEU0X1/Dy6hOAFD9CCFUwO8OH4S4Y\\n-----END PRIVATE KEY-----"
}`

	// Add mock files
	app.mockFiles["secure-config.json"] = sampleConfig
	app.mockFiles["cert.pem"] = sampleCert
	app.mockFiles["config/credentials.json"] = sampleConfig

	app.logger.Info("Initialized %d mock files for testing", len(app.mockFiles))
	for filename := range app.mockFiles {
		app.logger.Debug("Mock file available: %s", filename)
	}
}

// Method to add custom mock files
func (app *SecretDetectorApp) AddMockFile(filename, content string) {
	app.mockFiles[filename] = content
	app.logger.Info("Added mock file: %s", filename)
}

func loadPatterns(configPath string) (map[string]*regexp.Regexp, error) {
	defaultLogger := log.New(log.Writer(), "[LoadPatterns] ", log.LstdFlags)
	safeLogger := NewSafeLogger(defaultLogger, "info")

	safeLogger.Info("Attempting to load patterns from: %s", configPath)

	configFile, err := os.ReadFile(configPath)
	if err != nil {
		safeLogger.Error("Error reading config file: %v", err)
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config struct {
		Patterns map[string]string `json:"patterns"`
	}
	if err := json.Unmarshal(configFile, &config); err != nil {
		safeLogger.Error("Error unmarshaling config: %v", err)
		return nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}

	safeLogger.Debug("Loaded %d patterns", len(config.Patterns))

	patterns := make(map[string]*regexp.Regexp)
	for name, pattern := range config.Patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			safeLogger.Error("Error compiling pattern %s: %v", name, err)
			return nil, fmt.Errorf("failed to compile pattern %s: %v", name, err)
		}
		patterns[name] = re
		safeLogger.Debug("Successfully compiled pattern: %s", name)
	}

	return patterns, nil
}

func (app *SecretDetectorApp) getFileContents(ctx context.Context, client *github.Client,
	repo *github.Repository, commit string) (string, error) {

	// If we're in mock files mode, use mock files instead of calling GitHub API
	if app.mockFilesMode {
		app.logger.Info("Using mock files for commit %s in %s/%s",
			commit, repo.GetOwner().GetLogin(), repo.GetName())

		var allContent strings.Builder

		// Initialize mock files if needed
		if len(app.mockFiles) == 0 {
			app.logger.Info("Mock files map is empty! Initializing...")
			app.initializeMockFiles()
		}

		// Count available mock files
		app.logger.Debug("Total mock files available: %d", len(app.mockFiles))

		// In a real webhook, we'd filter by what files were actually modified
		// But for testing, we'll use all mock files
		fileList := make([]string, 0, len(app.mockFiles))
		for filename := range app.mockFiles {
			fileList = append(fileList, filename)
			app.logger.Debug("Adding file to process: %s", filename)
		}

		// Process each file
		for _, filename := range fileList {
			content, exists := app.mockFiles[filename]
			if !exists {
				app.logger.Debug("Skipping unknown mock file: %s", filename)
				continue
			}

			app.logger.Debug("Adding mock file: %s (length: %d)", filename, len(content))
			allContent.WriteString(fmt.Sprintf("--- %s ---\n", filename))
			allContent.WriteString(content)
			allContent.WriteString("\n\n")
		}

		result := allContent.String()
		if len(result) == 0 {
			app.logger.Warn("WARNING: Generated empty mock file content!")
		} else {
			app.logger.Debug("Generated mock file content (total length: %d)", len(result))
		}

		return result, nil
	}

	app.logger.Info("Fetching file contents for commit %s in %s/%s",
		commit, repo.GetOwner().GetLogin(), repo.GetName())

	// Get the commit details to identify all files
	commitObj, _, err := client.Repositories.GetCommit(
		ctx,
		repo.GetOwner().GetLogin(),
		repo.GetName(),
		commit,
		&github.ListOptions{},
	)

	if err != nil {
		return "", fmt.Errorf("failed to get commit details: %v", err)
	}

	var allContent strings.Builder

	// Track how many files we're analyzing for logging
	fileCount := len(commitObj.Files)
	app.logger.Info("Found %d files in commit", fileCount)

	// Process each file in the commit
	for i, file := range commitObj.Files {
		// Skip deleted files
		if file.GetStatus() == "removed" {
			app.logger.Debug("Skipping deleted file: %s", file.GetFilename())
			continue
		}

		// Get the content of the file at this commit
		fileContent, _, _, err := client.Repositories.GetContents(
			ctx,
			repo.GetOwner().GetLogin(),
			repo.GetName(),
			file.GetFilename(),
			&github.RepositoryContentGetOptions{
				Ref: commit,
			},
		)

		if err != nil {
			app.logger.Warn("Failed to get content for file %s: %v", file.GetFilename(), err)
			continue
		}

		// fileContent can be a single file or a directory
		if fileContent == nil {
			app.logger.Debug("Skipping directory or empty file: %s", file.GetFilename())
			continue
		}

		// For large files, GetContents may not return content directly
		// We need to handle multiple content types
		var content string

		if fileContent.GetType() == "file" {
			// If Content is available directly
			if fileContent.Content != nil {
				content, err = fileContent.GetContent()
				if err != nil {
					app.logger.Warn("Failed to decode content for file %s: %v", file.GetFilename(), err)
					continue
				}
			} else {
				// If Content is not available directly, we need to fetch it another way
				// For large files, we can use the download URL
				if fileContent.GetDownloadURL() != "" {
					req, err := http.NewRequestWithContext(ctx, "GET", fileContent.GetDownloadURL(), nil)
					if err != nil {
						app.logger.Warn("Failed to create request for file %s: %v", file.GetFilename(), err)
						continue
					}

					resp, err := client.Client().Do(req)
					if err != nil {
						app.logger.Warn("Failed to download file %s: %v", file.GetFilename(), err)
						continue
					}
					defer resp.Body.Close()

					bodyBytes, err := io.ReadAll(resp.Body)
					if err != nil {
						app.logger.Warn("Failed to read file content for %s: %v", file.GetFilename(), err)
						continue
					}
					content = string(bodyBytes)
				} else {
					app.logger.Warn("No content available for file %s", file.GetFilename())
					continue
				}
			}

			app.logger.Debug("Successfully fetched file %d/%d: %s (size: %d bytes)",
				i+1, fileCount, file.GetFilename(), len(content))

			// Add file header and content to our combined content
			allContent.WriteString(fmt.Sprintf("--- %s ---\n", file.GetFilename()))
			allContent.WriteString(content)
			allContent.WriteString("\n\n")
		} else {
			app.logger.Debug("Skipping non-file content type: %s (%s)", file.GetFilename(), fileContent.GetType())
		}
	}

	return allContent.String(), nil
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
	// Create a custom HTTP client with TLS configuration
	var tlsConfig *tls.Config

	// Check if TLS verification should be enabled
	tlsVerify := true
	if val := os.Getenv("TLS_SKIP_VERIFY"); val == "true" {
		tlsVerify = false
		app.logger.Warn("TLS certificate verification is disabled. This should only be used in development.")
	}

	// Check if mutual TLS is enabled
	if os.Getenv("MTLS_ENABLED") == "true" {
		// Load client certificate and key
		certFile := os.Getenv("TLS_CLIENT_CERT_FILE")
		keyFile := os.Getenv("TLS_CLIENT_KEY_FILE")

		if certFile == "" || keyFile == "" {
			return nil, fmt.Errorf("TLS_CLIENT_CERT_FILE and TLS_CLIENT_KEY_FILE must be provided when mTLS is enabled")
		}

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client TLS certificate: %v", err)
		}

		// Create a custom CA cert pool if a CA cert is provided
		var caCertPool *x509.CertPool
		caCertFile := os.Getenv("CA_CERT_FILE")
		if caCertFile != "" {
			caCert, err := os.ReadFile(caCertFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA certificate: %v", err)
			}

			caCertPool = x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse CA certificate")
			}
		}

		tlsConfig = &tls.Config{
			Certificates:       []tls.Certificate{cert},
			RootCAs:            caCertPool,
			InsecureSkipVerify: !tlsVerify,
			MinVersion:         tls.VersionTLS12,
		}
	} else if !tlsVerify {
		// If only disabling TLS verification
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		// Add modern security defaults
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   app.valService.Timeout,
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

	// Determine the protocol based on TLS configuration
	protocol := "http"
	if tlsConfig != nil || strings.HasPrefix(app.valService.Endpoint, "https://") {
		protocol = "https"
	}

	// Ensure endpoint doesn't already have a protocol
	endpoint := app.valService.Endpoint
	if strings.HasPrefix(endpoint, "http://") {
		endpoint = strings.TrimPrefix(endpoint, "http://")
	} else if strings.HasPrefix(endpoint, "https://") {
		endpoint = strings.TrimPrefix(endpoint, "https://")
	}

	url := fmt.Sprintf("%s://%s/validate", protocol, endpoint)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add API key authentication
	apiKey := os.Getenv("VALIDATION_API_KEY")
	if apiKey == "" {
		// Default key for development only
		apiKey = "default-development-key-do-not-use-in-production"
		app.logger.Warn("Using default API key for validation service. This is not secure for production.")
	}

	req.Header.Set("X-API-Key", apiKey)

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

	// Check if any valid secrets were found
	validSecrets := false
	secretCount := 0

	for _, finding := range findings {
		if finding.IsValid {
			validSecrets = true
			secretCount++
		}
	}

	if validSecrets {
		state = "failure"
		description = fmt.Sprintf("Blocked: Found %d valid secrets (certificate/key)", secretCount)
	} else if len(findings) > 0 {
		// Findings exist but none are valid (test data, etc.)
		description = fmt.Sprintf("No valid secrets detected (%d invalid/test secrets found)", len(findings))
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

	// Collect all content to scan
	var contentToScan []string

	// Special case for test+mock mode with full file analysis
	if app.testMode && app.mockFilesMode && app.fullFileAnalysis {
		app.logger.Info("Running in TEST+MOCK+FULL_FILE_ANALYSIS mode - using mock files")

		// First, make sure mock files are initialized
		if len(app.mockFiles) == 0 {
			app.logger.Info("Mock files not initialized, initializing now...")
			app.initializeMockFiles()
		}

		// Use commit messages for validation
		for _, commit := range event.Commits {
			contentToScan = append(contentToScan, commit.GetMessage())
		}

		// Create a GitHub repository object for getFileContents
		repository := &github.Repository{
			Name:  github.String(repo.GetName()),
			Owner: &github.User{Login: github.String(repo.GetOwner().GetName())},
		}

		// Get the mock file contents
		fileContent, err := app.getFileContents(ctx, client, repository, head)
		if err != nil {
			app.logger.Warn("Error getting mock file contents: %v", err)
		} else if fileContent != "" {
			app.logger.Debug("Retrieved mock file contents (length: %d)", len(fileContent))
			contentToScan = append(contentToScan, fileContent)
		} else {
			app.logger.Warn("Retrieved empty mock file contents")
		}
	} else if app.testMode {
		// Regular test mode - skip API retrieval
		app.logger.Info("Running in test mode - skipping API retrieval")

		// Use the commit messages for validation
		for _, commit := range event.Commits {
			contentToScan = append(contentToScan, commit.GetMessage())
		}

		// If we have any stored patches, use them
		if len(app.testPatches) > 0 {
			app.logger.Debug("Found %d patches from test mode", len(app.testPatches))
			contentToScan = append(contentToScan, app.testPatches...)
		}
	} else {
		// Normal mode - either get diff or full file content based on configuration
		if app.fullFileAnalysis {
			// Full file analysis mode - fetch the content of each modified file
			app.logger.Info("Running in full file analysis mode - fetching complete file contents")

			// Get each commit and fetch its file contents
			for _, commit := range event.Commits {
				commitSHA := commit.GetSHA() // Use GetSHA() instead of GetID()
				fileContent, err := app.getFileContents(ctx, client, &github.Repository{
					Owner: repo.Owner,
					Name:  repo.Name,
				}, commitSHA)

				if err != nil {
					app.logger.Warn("Error fetching file contents for commit %s: %v", commitSHA, err)
					continue
				}

				contentToScan = append(contentToScan, fileContent)

				// Always scan commit messages as well
				contentToScan = append(contentToScan, commit.GetMessage())
			}
		} else {
			// Diff-only mode (original behavior)
			app.logger.Info("Running in diff-only mode - fetching git diff")
			diff, err := app.getDiff(ctx, client, &github.Repository{Owner: repo.Owner, Name: repo.Name}, base, head)
			if err != nil {
				return fmt.Errorf("failed to get diff: %v", err)
			}
			contentToScan = append(contentToScan, diff)

			// Also add commit messages
			for _, commit := range event.Commits {
				contentToScan = append(contentToScan, commit.GetMessage())
			}
		}
	}

	// Combine all content with newlines
	combinedContent := strings.Join(contentToScan, "\n")
	app.logger.Info("Content to scan (length: %d)", len(combinedContent))
	// Do not log content itself, only metadata
	app.logger.Debug("Content contains %d files, %d lines",
		strings.Count(combinedContent, "---"),
		strings.Count(combinedContent, "\n"))

	findings, err := app.validateContent(ctx, combinedContent)
	if err != nil {
		return fmt.Errorf("failed to validate content: %v", err)
	}

	// Convert PushEventRepository to Repository
	repository := &github.Repository{
		Owner: &github.User{Login: github.String(repo.GetOwner().GetName())},
		Name:  github.String(repo.GetName()),
	}

	// Log findings to database
	if len(findings) > 0 {
		app.logger.Info("Found %d findings", len(findings))
		for i, finding := range findings {
			app.logger.Info("Finding %d: Type=%s, Valid=%t", i, finding.Type, finding.IsValid)

			// Only log the finding message, not the actual secret
			app.logger.Debug("Finding %d message: %s", i, finding.Message)

			// Only block if the secret is valid
			if finding.IsValid {
				app.logger.Warn("BLOCKING: Found valid %s in commit", finding.Type)

				// Log to database
				repoModel := &models.Repository{
					Name: *repository.Name,
					Owner: &models.Owner{
						Login: *repository.Owner.Login,
						Type:  "User", // Default to user, could be overridden if known
					},
				}

				err := app.db.RecordDetection(
					ctx,
					repoModel,
					finding,
					head,
				)

				if err != nil {
					app.logger.Error("Error recording detection: %v", err)
				}
			} else {
				app.logger.Info("ALLOWING: Found invalid/test %s in commit", finding.Type)

				// Log to database with is_blocked=false
				repoModel := &models.Repository{
					Name: *repository.Name,
					Owner: &models.Owner{
						Login: *repository.Owner.Login,
						Type:  "User", // Default to user, could be overridden if known
					},
				}

				// Mark as not blocked since it's invalid/test data
				finding.Message += " (Commit allowed - not blocked)"

				err := app.db.RecordDetection(
					ctx,
					repoModel,
					finding,
					head,
				)

				if err != nil {
					app.logger.Error("Error recording detection: %v", err)
				}
			}
		}
	} else {
		app.logger.Info("No findings detected")
	}

	// In test mode, we can skip the create status call as well
	if app.testMode {
		app.logger.Info("Test mode: Skipping GitHub status update")
		return nil
	}

	// Create GitHub status based on findings
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
		app.logger.Warn("Unknown GitHub instance: %s", host)
		http.Error(w, "Unknown GitHub instance", http.StatusBadRequest)
		return
	}

	// Get the signature from the request - log safely
	receivedSig := r.Header.Get("X-Hub-Signature")
	app.logger.LogSignature("Received webhook with signature", receivedSig)

	// Read the request body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		app.logger.Error("Error reading request body: %v", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// Restore the body for later use
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Log payload safely
	app.logger.LogPayload("Received payload", string(bodyBytes))

	// Calculate signature manually to compare with received signature
	mac := hmac.New(sha1.New, []byte(config.WebhookSecret))
	mac.Write(bodyBytes)
	expectedSig := "sha1=" + hex.EncodeToString(mac.Sum(nil))

	// Log both signatures for comparison - safely
	app.logger.LogSignature("Expected signature", expectedSig)
	app.logger.LogSignature("Received signature", receivedSig)

	// Skip signature validation if in test mode
	if !app.testMode {
		// Do a manual signature comparison only if not in test mode
		if receivedSig == "" {
			app.logger.Warn("No signature received")
			http.Error(w, "Missing signature", http.StatusBadRequest)
			return
		}

		// Allow either exact string match or hmac.Equal()
		if expectedSig != receivedSig && !hmac.Equal([]byte(expectedSig), []byte(receivedSig)) {
			app.logger.Warn("Signature validation failed")
			http.Error(w, "Invalid webhook payload", http.StatusBadRequest)
			return
		}
	} else {
		app.logger.Info("TEST MODE: Bypassing signature validation")
	}

	// Clear any previous test patches
	if app.testMode {
		app.testPatches = make([]string, 0)

		// For test mode, extract patch data from the raw JSON payload if available
		var rawPayload map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &rawPayload); err == nil {
			if commits, ok := rawPayload["commits"].([]interface{}); ok {
				app.logger.Debug("Test mode: Found %d commits in raw payload", len(commits))

				// Iterate through commits to find patches
				for i, c := range commits {
					if commitObj, ok := c.(map[string]interface{}); ok {
						// Try to extract patch data
						if patch, ok := commitObj["patch"].(string); ok && patch != "" {
							app.logger.Debug("Test mode: Found patch data in commit %d", i)
							// Store patch data for later use
							app.testPatches = append(app.testPatches, patch)

							// If we have a message, add it to the commit object
							if message, ok := commitObj["message"].(string); ok {
								app.logger.Debug("Test mode: Adding patch data to commit with message: %s",
									truncateString(message, 50))
							}
						}
					}
				}
			}
		} else {
			app.logger.Debug("Test mode: Failed to parse raw payload as JSON: %v", err)
		}
	}

	// Restore the body again after validation
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Parse the webhook event
	event, err := github.ParseWebHook(github.WebHookType(r), bodyBytes)
	if err != nil {
		app.logger.Error("Failed to parse webhook: %v", err)
		http.Error(w, "Failed to parse webhook", http.StatusBadRequest)
		return
	}

	client := app.clients[host]

	switch e := event.(type) {
	case *github.PushEvent:
		if err := app.handlePushEvent(ctx, client, e); err != nil {
			app.logger.Error("Failed to handle push event: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	default:
		app.logger.Info("Unsupported event type: %s", github.WebHookType(r))
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

	var req struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		app.logger.Error("Error decoding request: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	app.logger.Info("Received content to validate. Length: %d", len(req.Content))

	// Handle empty content
	if strings.TrimSpace(req.Content) == "" {
		app.logger.Info("Empty content received")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.DetectionResponse{
			Findings: []models.SecretFinding{},
			Message:  "No content to validate",
		})
		return
	}

	// Validate the content using validation service
	findings, err := app.validateContent(r.Context(), req.Content)
	if err != nil {
		app.logger.Error("Error validating content: %v", err)
		http.Error(w, fmt.Sprintf("Error validating content: %v", err), http.StatusInternalServerError)
		return
	}

	// Generate appropriate message
	message := app.getMessage(findings)

	// Return the findings
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.DetectionResponse{
		Findings: findings,
		Message:  message,
	})
}

func (app *SecretDetectorApp) getMessage(findings []models.SecretFinding) string {
	if len(findings) == 0 {
		return "No secrets detected"
	}

	validCount := 0
	for _, finding := range findings {
		if finding.IsValid {
			validCount++
		}
	}

	if validCount > 0 {
		return fmt.Sprintf("Found %d valid secrets that would be blocked", validCount)
	}

	return fmt.Sprintf("Found %d potential secrets, but none are valid or they are test data", len(findings))
}

func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
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

func main() {
	// Configure log level from environment
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		// Default to info in production, debug in development
		if os.Getenv("APP_ENV") == "production" {
			logLevel = "info"
		} else {
			logLevel = "debug"
		}
	}

	// Create standard logger
	stdLogger := log.New(os.Stdout, "[SecretDetector] ", log.LstdFlags|log.Lshortfile)

	// Create our safe logger
	logger := NewSafeLogger(stdLogger, logLevel)

	// Get validation service URL from environment or use default
	validationServiceURL := os.Getenv("VALIDATION_SERVICE_URL")
	if validationServiceURL == "" {
		validationServiceURL = "http://validation-service:8080"
	}

	// Check if we're in test mode
	testMode := os.Getenv("TEST_MODE") == "true"
	if testMode {
		logger.Info("Starting in TEST MODE - GitHub API calls will be skipped")
	}

	// Check if we should use full file analysis
	fullFileAnalysis := os.Getenv("FULL_FILE_ANALYSIS") == "true"
	if fullFileAnalysis {
		logger.Info("Starting with FULL FILE ANALYSIS enabled - will fetch complete file contents")
	} else {
		logger.Info("Starting with diff-only analysis - will only examine git diffs")
	}

	// Check if we're in mock files mode
	mockFilesMode := os.Getenv("MOCK_FILES_MODE") == "true"
	if mockFilesMode {
		logger.Info("Starting with MOCK FILES MODE enabled - will use local mock files instead of GitHub API")
	}

	app := NewSecretDetectorApp(validationServiceURL, stdLogger, testMode, fullFileAnalysis)

	// Load GitHub.com private key
	privateKey, err := os.ReadFile("/app/keys/github.pem")
	if err != nil {
		logger.Warn("Failed to read private key: %v", err)
		privateKey = []byte("dummy-key-for-testing") // Allow app to start for testing
	}

	webhookSecret := os.Getenv("GITHUB_WEBHOOK_SECRET")
	if webhookSecret == "" {
		logger.Warn("GITHUB_WEBHOOK_SECRET not set, using default test secret")
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
		logger.Warn("Failed to add GitHub.com instance: %v", err)
	}

	// Add Enterprise instance only if ALL required config is present
	enterpriseHost := os.Getenv("GITHUB_ENTERPRISE_HOST")
	enterpriseSecret := os.Getenv("GITHUB_ENTERPRISE_WEBHOOK_SECRET")
	if enterpriseHost != "" && enterpriseSecret != "" {
		enterpriseKey, err := os.ReadFile("/app/keys/enterprise.pem")
		if err != nil {
			logger.Warn("Skipping enterprise setup - Failed to read enterprise key: %v", err)
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
					logger.Warn("Failed to add Enterprise instance: %v", err)
				}
			} else {
				logger.Warn("Skipping enterprise setup - Missing enterprise app ID or installation ID")
			}
		}
	}

	http.HandleFunc("/webhook", app.HandleWebhook)
	http.HandleFunc("/validate", app.HandleValidate)

	listenAddr := ":8080"
	logger.Info("Starting server on %s", listenAddr)
	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		logger.Error("Server failed: %v", err)
		os.Exit(1)
	}
}
