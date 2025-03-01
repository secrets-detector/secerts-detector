package main

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"

	"secrets-detector/pkg/models"
)

// ValidateCertificate checks if the provided certificate is valid
func validateCertificate(cert string) (bool, string) {
	if !strings.Contains(cert, "BEGIN CERTIFICATE") {
		return false, "Not a certificate"
	}

	// Check for test/dummy certificates
	if strings.Contains(strings.ToLower(cert), "test") ||
		strings.Contains(strings.ToLower(cert), "dummy") ||
		strings.Contains(strings.ToLower(cert), "example") {
		return false, "Test certificate"
	}

	block, _ := pem.Decode([]byte(cert))
	if block == nil {
		return false, "Invalid PEM format"
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, "Invalid certificate: " + err.Error()
	}

	// It's a valid certificate
	issuer := certificate.Issuer.CommonName
	subject := certificate.Subject.CommonName
	return true, "Valid certificate issued by " + issuer + " for " + subject
}

// ValidatePrivateKey checks if the provided private key is valid
func validatePrivateKey(key string) (bool, string) {
	if !strings.Contains(key, "BEGIN") || !strings.Contains(key, "PRIVATE KEY") {
		return false, "Not a private key"
	}

	// Check for test/dummy keys
	if strings.Contains(strings.ToLower(key), "test") ||
		strings.Contains(strings.ToLower(key), "dummy") ||
		strings.Contains(strings.ToLower(key), "example") {
		return false, "Test private key"
	}

	block, _ := pem.Decode([]byte(key))
	if block == nil {
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
		return false, "Invalid private key: " + err.Error()
	}

	return true, "Valid " + block.Type
}

func setupRouter() *gin.Engine {
	r := gin.Default()

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

		// Look for patterns in the content
		findings := []models.SecretFinding{}

		// Check for certificates
		certPattern := "-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----"
		certRegex := regexp.MustCompile(certPattern)
		certMatches := certRegex.FindAllStringIndex(req.Content, -1)

		for _, match := range certMatches {
			cert := req.Content[match[0]:match[1]]
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

		// Check for private keys
		keyPattern := "-----BEGIN [\\w\\s]+ PRIVATE KEY-----[\\s\\S]*?-----END [\\w\\s]+ PRIVATE KEY-----"
		keyRegex := regexp.MustCompile(keyPattern)
		keyMatches := keyRegex.FindAllStringIndex(req.Content, -1)

		for _, match := range keyMatches {
			key := req.Content[match[0]:match[1]]
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

		c.JSON(http.StatusOK, gin.H{
			"findings": findings,
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
