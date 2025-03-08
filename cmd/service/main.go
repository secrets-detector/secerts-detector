package main

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"secrets-detector/pkg/models"
)

// APIKeyAuth middleware enforces API key authentication
func APIKeyAuth() gin.HandlerFunc {
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		// Default key for development - in production, this should always be overridden
		apiKey = "default-development-key-do-not-use-in-production"
	}

	return func(c *gin.Context) {
		clientKey := c.GetHeader("X-API-Key")

		// Constant time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(clientKey), []byte(apiKey)) != 1 {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid API key",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// CORSMiddleware handles Cross-Origin Resource Sharing
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-API-Key, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// RequestLogger logs requests with sensitive data redacted
func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		start := time.Now()
		path := c.Request.URL.Path

		// Process request
		c.Next()

		// Execution time
		latency := time.Since(start)

		// Log only non-sensitive paths and information
		if !strings.Contains(path, "/validate") {
			log.Printf("[INFO] %s %s - %d (%s)", c.Request.Method, path, c.Writer.Status(), latency)
		} else {
			// For sensitive paths, log minimal information
			log.Printf("[INFO] %s %s - %d (%s)", c.Request.Method, path, c.Writer.Status(), latency)
		}
	}
}

// TLS configuration
func configureTLS() (*tls.Config, error) {
	// Check if TLS is enabled
	tlsEnabled := os.Getenv("TLS_ENABLED")
	if strings.ToLower(tlsEnabled) != "true" {
		log.Println("[WARN] TLS is disabled. This should only be used in development.")
		return nil, nil
	}

	// Load TLS certificate and key
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE must be provided when TLS is enabled")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %v", err)
	}

	// Configure TLS with modern cipher suites and TLS 1.2+
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Optionally configure mutual TLS (client certificate validation)
	if strings.ToLower(os.Getenv("MTLS_ENABLED")) == "true" {
		caCertFile := os.Getenv("CA_CERT_FILE")
		if caCertFile == "" {
			return nil, fmt.Errorf("CA_CERT_FILE must be provided when mTLS is enabled")
		}

		caCert, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %v", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}

// Function to set up a health endpoint server
func startHealthServer(port string) {
	// Create a separate router for health checks
	healthRouter := gin.New()
	healthRouter.Use(gin.Recovery())

	// Health check endpoint on separate port without mTLS
	healthRouter.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})

	// Start health server on its own port
	healthPort := port
	if healthPort == "" {
		healthPort = "8081" // Default health port if not specified
	}

	go func() {
		log.Printf("Starting health check server on port %s", healthPort)
		if err := http.ListenAndServe(":"+healthPort, healthRouter); err != nil {
			log.Printf("Health server failed: %v", err)
		}
	}()
}

// Simplified certificate validation - focus on structure not content
func validateCertificate(cert string) (bool, string) {
	// Check if this is actually a certificate
	if !strings.Contains(cert, "BEGIN CERTIFICATE") {
		return false, "Not a certificate"
	}

	// Clean the certificate string - normalize line endings and spaces
	cert = strings.ReplaceAll(cert, "\\n", "\n")
	cert = strings.ReplaceAll(cert, "\r\n", "\n")
	cert = strings.ReplaceAll(cert, "\r", "\n")
	cert = strings.TrimSpace(cert)

	// Check for test/dummy certificates by exact string match
	if strings.Contains(strings.ToLower(cert), "test") ||
		strings.Contains(strings.ToLower(cert), "dummy") ||
		strings.Contains(strings.ToLower(cert), "example") {
		return false, "Test certificate"
	}

	// For this simplified implementation, we'll consider any well-formed certificate
	// that doesn't contain "test" keywords to be valid
	pemBlock, _ := pem.Decode([]byte(cert))
	if pemBlock == nil {
		return false, "Invalid PEM format"
	}

	// Simple structure check - if we can decode the PEM and it's labeled as a certificate
	// and doesn't have test markers, we'll consider it valid
	if pemBlock.Type == "CERTIFICATE" {
		log.Printf("Certificate appears valid (simplified validation)")
		return true, "Valid certificate (structure check passed)"
	}

	return false, "Invalid certificate: wrong block type " + pemBlock.Type
}

// ValidatePrivateKey checks if the provided private key is valid
func validatePrivateKey(key string) (bool, string) {
	// Check if this is actually a private key
	if !strings.Contains(key, "BEGIN") || !strings.Contains(key, "PRIVATE KEY") {
		return false, "Not a private key"
	}

	// Clean the key string - normalize line endings
	key = strings.ReplaceAll(key, "\\n", "\n")
	key = strings.ReplaceAll(key, "\r\n", "\n")
	key = strings.ReplaceAll(key, "\r", "\n")
	key = strings.TrimSpace(key)

	// Check for test/dummy keys
	if strings.Contains(strings.ToLower(key), "test") ||
		strings.Contains(strings.ToLower(key), "dummy") ||
		strings.Contains(strings.ToLower(key), "example") {
		return false, "Test private key"
	}

	// Try to decode the PEM block
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		log.Printf("Failed to decode PEM block: %s", key)
		return false, "Invalid PEM format"
	}

	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		_, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		_, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return false, "Unsupported private key type: " + block.Type
	}

	if err != nil {
		log.Printf("Private key parse error: %v", err)
		return false, "Invalid private key: " + err.Error()
	}

	return true, "Valid " + block.Type
}

// Helper function to clean up PEM content
func cleanPEM(content string) string {
	// Handle various line ending formats
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")

	// Handle escaped newlines (which might be in JSON)
	content = strings.ReplaceAll(content, "\\n", "\n")

	// Replace multiple newlines with a single newline
	multipleNewlines := regexp.MustCompile(`\n+`)
	content = multipleNewlines.ReplaceAllString(content, "\n")

	return content
}

// Helper function to truncate cert/key for logging
func truncateCert(cert string) string {
	if len(cert) > 100 {
		return cert[:50] + "..." + cert[len(cert)-50:]
	}
	return cert
}

func setupRouter() *gin.Engine {
	// Set Gin mode from environment
	ginMode := os.Getenv("GIN_MODE")
	if ginMode != "" {
		gin.SetMode(ginMode)
	}

	r := gin.New() // Use New() instead of Default() for more control

	// Apply middleware
	r.Use(CORSMiddleware())
	r.Use(RequestLogger())

	// Add health check to main router too (but it will require mTLS when enabled)
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})

	// Create an authenticated group for sensitive endpoints
	authGroup := r.Group("/")
	authGroup.Use(APIKeyAuth())

	// Authenticated validate endpoint
	authGroup.POST("/validate", func(c *gin.Context) {
		var req struct {
			Content string `json:"content"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request format",
			})
			return
		}

		// Clean the content and normalize line endings
		content := cleanPEM(req.Content)

		// Look for patterns in the content
		findings := []models.SecretFinding{}

		// Check for certificates - more flexible pattern that handles newlines and escaped newlines
		certPattern := "-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----"
		certRegex := regexp.MustCompile(certPattern)
		certMatches := certRegex.FindAllStringIndex(content, -1)

		for _, match := range certMatches {
			cert := content[match[0]:match[1]]
			// Normalize the certificate by replacing escaped newlines with actual newlines
			cert = strings.ReplaceAll(cert, "\\n", "\n")
			cert = strings.TrimSpace(cert)

			// Log for debugging - redact sensitive data
			log.Printf("Found certificate: %s", truncateCert(cert))

			isValid, message := validateCertificate(cert)
			finding := models.SecretFinding{
				Type:     "certificate",
				Value:    cert,
				StartPos: match[0],
				EndPos:   match[1],
				IsValid:  isValid,
				Message:  message,
			}
			findings = append(findings, finding)
		}

		// Check for private keys with more flexible pattern
		keyPattern := "-----BEGIN[\\s\\S]*?PRIVATE KEY-----[\\s\\S]*?-----END[\\s\\S]*?PRIVATE KEY-----"
		keyRegex := regexp.MustCompile(keyPattern)
		keyMatches := keyRegex.FindAllStringIndex(content, -1)

		for _, match := range keyMatches {
			key := content[match[0]:match[1]]
			// Normalize the key by replacing escaped newlines with actual newlines
			key = strings.ReplaceAll(key, "\\n", "\n")
			key = strings.TrimSpace(key)

			// Log for debugging - redact sensitive data
			log.Printf("Found private key: %s", truncateCert(key))

			isValid, message := validatePrivateKey(key)
			finding := models.SecretFinding{
				Type:     "private_key",
				Value:    key,
				StartPos: match[0],
				EndPos:   match[1],
				IsValid:  isValid,
				Message:  message,
			}
			findings = append(findings, finding)
		}

		// Generate appropriate message
		message := "No secrets detected"
		if len(findings) > 0 {
			validCount := 0
			for _, finding := range findings {
				if finding.IsValid {
					validCount++
				}
			}

			if validCount > 0 {
				message = fmt.Sprintf("Found %d valid secrets that would be blocked", validCount)
			} else {
				message = fmt.Sprintf("Found %d potential secrets, but none are valid or they are test data", len(findings))
			}
		}

		// Log what we found
		log.Printf("Found %d secrets in content", len(findings))
		for i, finding := range findings {
			log.Printf("Finding %d: Type=%s, Valid=%t, Message=%s",
				i, finding.Type, finding.IsValid, finding.Message)
		}

		c.JSON(http.StatusOK, gin.H{
			"findings": findings,
			"message":  message,
		})
	})

	// Endpoint for validating individual secrets
	authGroup.POST("/validate/secret", func(c *gin.Context) {
		var req models.ValidationRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.ValidationResponse{
				IsValid: false,
				Message: "Invalid request format",
			})
			return
		}

		var isValid bool
		var message string

		switch req.Secret.Type {
		case "certificate":
			isValid, message = validateCertificate(req.Secret.Value)
		case "private_key":
			isValid, message = validatePrivateKey(req.Secret.Value)
		default:
			isValid = false
			message = "Unsupported secret type"
		}

		c.JSON(http.StatusOK, models.ValidationResponse{
			IsValid: isValid,
			Message: message,
		})
	})

	return r
}

func main() {
	// Main server port
	port := os.Getenv("PORT")
	if port == "" {
		port = "8443" // Default to secure port
	}

	// Health server port
	healthPort := os.Getenv("HEALTH_PORT")
	if healthPort == "" {
		healthPort = "8081" // Default health port
	}

	// Add standard library logging
	logger := log.New(os.Stdout, "[ValidationService] ", log.LstdFlags)
	logger.Printf("Starting validation service on port %s", port)

	// Start the health endpoint on a separate port
	startHealthServer(healthPort)

	r := setupRouter()

	// Check if TLS is enabled
	tlsConfig, err := configureTLS()
	if err != nil {
		logger.Fatalf("Failed to configure TLS: %v", err)
	}

	server := &http.Server{
		Addr:    ":" + port,
		Handler: r,
	}

	// Start the server with or without TLS
	if tlsConfig != nil {
		server.TLSConfig = tlsConfig
		logger.Printf("Starting server with TLS on port %s", port)
		logger.Fatal(server.ListenAndServeTLS("", ""))
	} else {
		logger.Printf("Starting server without TLS on port %s (NOT RECOMMENDED FOR PRODUCTION)", port)
		logger.Fatal(server.ListenAndServe())
	}
}
