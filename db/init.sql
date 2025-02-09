CREATE TABLE IF NOT EXISTS repositories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    owner VARCHAR(255) NOT NULL,
    is_enterprise BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(owner, name)
);

CREATE TABLE IF NOT EXISTS secret_detections (
    id SERIAL PRIMARY KEY,
    repository_id INTEGER REFERENCES repositories(id),
    commit_hash VARCHAR(40) NOT NULL,
    secret_type VARCHAR(50) NOT NULL,
    secret_location TEXT NOT NULL,
    line_number INTEGER,
    is_blocked BOOLEAN DEFAULT false,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    validation_status VARCHAR(20) NOT NULL,
    branch_name VARCHAR(255),
    author VARCHAR(255),
    commit_timestamp TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS validation_history (
    id SERIAL PRIMARY KEY,
    detection_id INTEGER REFERENCES secret_detections(id),
    validation_result BOOLEAN NOT NULL,
    validation_message TEXT,
    validated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_detections_repo ON secret_detections(repository_id);
CREATE INDEX idx_detections_date ON secret_detections(detected_at);
CREATE INDEX idx_detections_type ON secret_detections(secret_type);
CREATE INDEX idx_detections_status ON secret_detections(validation_status);

-- Create views for executive dashboards
CREATE VIEW secret_detection_metrics AS
SELECT 
    DATE_TRUNC('day', detected_at) as detection_date,
    r.owner,
    r.name as repository_name,
    secret_type,
    validation_status,
    COUNT(*) as detection_count,
    SUM(CASE WHEN is_blocked THEN 1 ELSE 0 END) as blocked_count
FROM secret_detections sd
JOIN repositories r ON r.id = sd.repository_id
GROUP BY 
    DATE_TRUNC('day', detected_at),
    r.owner,
    r.name,
    secret_type,
    validation_status;

CREATE VIEW repository_risk_metrics AS
SELECT 
    r.owner,
    r.name as repository_name,
    COUNT(*) as total_detections,
    COUNT(DISTINCT secret_type) as unique_secret_types,
    MAX(detected_at) as last_detection,
    SUM(CASE WHEN is_blocked THEN 1 ELSE 0 END) as total_blocked
FROM secret_detections sd
JOIN repositories r ON r.id = sd.repository_id
GROUP BY r.owner, r.name;