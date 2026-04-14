-- Database schema for Intelligent Full-Stack Web Security Analyzer Using AI

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);

-- Targets table
CREATE TABLE targets (
    id SERIAL PRIMARY KEY,
    url VARCHAR(2048) NOT NULL,
    name VARCHAR(200),
    description TEXT,
    is_active BOOLEAN DEFAULT true,
    last_scan_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id)
);

CREATE INDEX idx_targets_url ON targets(url);
CREATE INDEX idx_targets_created_by ON targets(created_by);

-- Scans table
CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id),
    user_id INTEGER REFERENCES users(id),
    status VARCHAR(20) DEFAULT 'pending',
    scan_type VARCHAR(50),
    config JSONB,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration FLOAT,
    progress INTEGER DEFAULT 0,
    ml_analysis_enabled BOOLEAN DEFAULT true,
    nlp_report_enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_scans_target_id ON scans(target_id);
CREATE INDEX idx_scans_user_id ON scans(user_id);
CREATE INDEX idx_scans_status ON scans(status);

-- Vulnerabilities table
CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    vulnerability_type VARCHAR(50),
    severity VARCHAR(20),
    title VARCHAR(200) NOT NULL,
    description TEXT,
    url VARCHAR(2048),
    method VARCHAR(10),
    param VARCHAR(200),
    payload TEXT,
    evidence TEXT,
    remediation TEXT,
    cwe_id VARCHAR(20),
    cvss_score FLOAT,
    cvss_vector VARCHAR(100),
    is_false_positive BOOLEAN DEFAULT false,
    ml_confidence FLOAT,
    ml_prediction BOOLEAN,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_type ON vulnerabilities(vulnerability_type);

-- Reports table
CREATE TABLE reports (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    report_type VARCHAR(50),
    title VARCHAR(200),
    content TEXT,
    summary TEXT,
    ml_insights JSONB,
    nlp_summary TEXT,
    file_path VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_reports_scan_id ON reports(scan_id);

-- API Keys table
CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    key_hash VARCHAR(255) NOT NULL,
    name VARCHAR(100),
    description TEXT,
    is_active BOOLEAN DEFAULT true,
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);

-- ML Models table (for storing model metadata)
CREATE TABLE ml_models (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    version VARCHAR(50),
    model_type VARCHAR(50),
    accuracy FLOAT,
    precision_score FLOAT,
    recall_score FLOAT,
    f1_score FLOAT,
    training_data_date DATE,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scan History table (for tracking scan progress over time)
CREATE TABLE scan_history (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    status VARCHAR(20),
    progress INTEGER,
    message TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_scan_history_scan_id ON scan_history(scan_id);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers for updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- View for vulnerability statistics
CREATE OR REPLACE VIEW vulnerability_stats AS
SELECT 
    v.severity,
    v.vulnerability_type,
    COUNT(*) as count,
    AVG(v.ml_confidence) as avg_confidence
FROM vulnerabilities v
GROUP BY v.severity, v.vulnerability_type;

-- View for scan summary
CREATE OR REPLACE VIEW scan_summary AS
SELECT 
    s.id,
    s.status,
    s.scan_type,
    t.url as target_url,
    u.username,
    s.started_at,
    s.completed_at,
    s.duration,
    COUNT(v.id) as vulnerability_count,
    SUM(CASE WHEN v.severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
    SUM(CASE WHEN v.severity = 'high' THEN 1 ELSE 0 END) as high_count
FROM scans s
LEFT JOIN targets t ON s.target_id = t.id
LEFT JOIN users u ON s.user_id = u.id
LEFT JOIN vulnerabilities v ON s.id = v.scan_id
GROUP BY s.id, t.url, u.username;

