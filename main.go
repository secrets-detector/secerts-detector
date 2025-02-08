// main.go
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

type Config struct {
	Patterns map[string]string `json:"patterns"`
	API      APIConfig         `json:"api"`
	Logging  LoggingConfig     `json:"logging"`
	Rules    RulesConfig       `json:"rules"`
}

type APIConfig struct {
	ValidateEndpoint string `json:"validate_endpoint"`
	Token            string `json:"token"`
}

type LoggingConfig struct {
	Level string `json:"level"`
	File  string `json:"file"`
}

type RulesConfig struct {
	BlockOnValidationFailure bool     `json:"block_on_validation_failure"`
	NotifyAdmins             bool     `json:"notify_admins"`
	AllowedBranches          []string `json:"allowed_branches"`
	ExcludedFiles            []string `json:"excluded_files"`
}

type SecretFinding struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	StartPos int    `json:"start_pos"`
	EndPos   int    `json:"end_pos"`
	FilePath string `json:"file_path"`
}

type Validator struct {
	config   Config
	patterns map[string]*regexp.Regexp
	logger   *log.Logger
}

func NewValidator(configPath string) (*Validator, error) {
	config, err := loadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	patterns, err := compilePatterns(config.Patterns)
	if err != nil {
		return nil, fmt.Errorf("failed to compile patterns: %v", err)
	}

	logger := log.New(os.Stdout, "[secret-validator] ", log.LstdFlags)
	if config.Logging.File != "" {
		f, err := os.OpenFile(config.Logging.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %v", err)
		}
		logger = log.New(f, "", log.LstdFlags)
	}

	return &Validator{
		config:   config,
		patterns: patterns,
		logger:   logger,
	}, nil
}

func loadConfig(path string) (Config, error) {
	var config Config
	file, err := os.Open(path)
	if err != nil {
		return config, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	return config, err
}

func compilePatterns(patterns map[string]string) (map[string]*regexp.Regexp, error) {
	compiled := make(map[string]*regexp.Regexp)
	for name, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile pattern %s: %v", name, err)
		}
		compiled[name] = re
	}
	return compiled, nil
}

func (v *Validator) ValidateContent(content, filePath string) []SecretFinding {
	var findings []SecretFinding

	for name, pattern := range v.patterns {
		matches := pattern.FindAllStringIndex(content, -1)
		for _, match := range matches {
			finding := SecretFinding{
				Type:     name,
				Value:    content[match[0]:match[1]],
				StartPos: match[0],
				EndPos:   match[1],
				FilePath: filePath,
			}
			if v.validateSecret(finding) {
				findings = append(findings, finding)
			}
		}
	}
	return findings
}

func (v *Validator) validateSecret(finding SecretFinding) bool {
	// Implement your secret validation logic here
	// This could include:
	// - Calling an external validation service
	// - Checking certificate validity
	// - Verifying API keys
	// For now, we'll consider all matches as valid secrets
	return true
}

func (v *Validator) ProcessPush() error {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return fmt.Errorf("invalid input: %s", line)
		}

		oldRev, newRev, ref := fields[0], fields[1], fields[2]

		// Skip if deleting a ref
		if strings.HasPrefix(newRev, "0000000") {
			continue
		}

		findings, err := v.checkDiff(oldRev, newRev)
		if err != nil {
			return fmt.Errorf("failed to check diff: %v", err)
		}

		if len(findings) > 0 {
			for _, finding := range findings {
				v.logger.Printf("Secret detected: %s in %s", finding.Type, finding.FilePath)
			}
			return fmt.Errorf("secrets detected in commit")
		}
	}

	return scanner.Err()
}

func (v *Validator) checkDiff(oldRev, newRev string) ([]SecretFinding, error) {
	cmd := exec.Command("git", "diff", oldRev, newRev)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get diff: %v", err)
	}

	return v.ValidateContent(string(output), ""), nil
}

func main() {
	validator, err := NewValidator("/github/data/git-hooks/config/config.json")
	if err != nil {
		log.Fatalf("Failed to initialize validator: %v", err)
	}

	if err := validator.ProcessPush(); err != nil {
		validator.logger.Printf("Error: %v", err)
		os.Exit(1)
	}

	validator.logger.Println("No secrets detected")
}
