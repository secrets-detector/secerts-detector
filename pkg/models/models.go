package models

type SecretFinding struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	StartPos int    `json:"start_pos"`
	EndPos   int    `json:"end_pos"`
	FilePath string `json:"file_path,omitempty"`
	IsValid  bool   `json:"is_valid"`
	Message  string `json:"message,omitempty"`
}

type ValidationRequest struct {
	Secret SecretFinding `json:"secret"`
}

type ValidationResponse struct {
	IsValid bool   `json:"is_valid"`
	Message string `json:"message"`
}

type DetectionResponse struct {
	Findings []SecretFinding `json:"findings"`
	Message  string          `json:"message"`
}
