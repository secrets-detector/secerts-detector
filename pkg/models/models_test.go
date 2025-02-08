package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecretFindingJSON(t *testing.T) {
	finding := SecretFinding{
		Type:     "certificate",
		Value:    "test-value",
		StartPos: 0,
		EndPos:   10,
		FilePath: "test.txt",
	}

	// Test marshaling
	data, err := json.Marshal(finding)
	assert.NoError(t, err)
	assert.Contains(t, string(data), "certificate")
	assert.Contains(t, string(data), "test-value")

	// Test unmarshaling
	var decoded SecretFinding
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, finding, decoded)
}

func TestValidationRequestJSON(t *testing.T) {
	req := ValidationRequest{
		Secret: SecretFinding{
			Type:  "certificate",
			Value: "test-value",
		},
	}

	// Test marshaling
	data, err := json.Marshal(req)
	assert.NoError(t, err)
	assert.Contains(t, string(data), "certificate")

	// Test unmarshaling
	var decoded ValidationRequest
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, req, decoded)
}
