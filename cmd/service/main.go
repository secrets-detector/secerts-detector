package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"

	"secrets-detector/pkg/models"
)

// Simplified certificate validation - focus on structure not content
func validateCertificate(cert string) (bool, string) {
	// Check if this is actually a certificate
	if !strings.Contains(cert, "BEGIN CERTIFICATE") {
		return false, "Not a certificate"
	}

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

	// Check for test/dummy keys
	if strings.Contains(strings.ToLower(key), "test") ||
		strings.Contains(strings.ToLower(key), "dummy") ||
		strings.Contains(strings.ToLower(key), "example") {
		return false, "Test private key"
	}

	// Normalize whitespace and line endings
	key = strings.ReplaceAll(key, "\r\n", "\n")
	key = strings.ReplaceAll(key, "\r", "\n")
	key = strings.TrimSpace(key)

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
	// Replace all line endings with \n
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")

	// Replace multiple newlines with a single newline
	multipleNewlines := regexp.MustCompile(`\n+`)
	content = multipleNewlines.ReplaceAllString(content, "\n")

	return content
}

func setupRouter() *gin.Engine {
	r := gin.Default()

	// Add this health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "validation-service",
		})
	})

	r.POST("/validate", func(c *gin.Context) {
		var req struct {
			Content string `json:"content"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request format",
			})
			return
		}

		// Clean the content
		content := cleanPEM(req.Content)

		// Look for patterns in the content
		findings := []models.SecretFinding{}

		// Check for certificates
		certPattern := "-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----"
		certRegex := regexp.MustCompile(certPattern)
		certMatches := certRegex.FindAllStringIndex(content, -1)

		for _, match := range certMatches {
			cert := content[match[0]:match[1]]
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
	r.POST("/validate/secret", func(c *gin.Context) {
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
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Add standard library logging
	logger := log.New(os.Stdout, "[ValidationService] ", log.LstdFlags)
	logger.Printf("Starting validation service on port %s", port)

	r := setupRouter()
	r.Run(":" + port)
}
