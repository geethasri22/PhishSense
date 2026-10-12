-- PhishSense PostgreSQL Database Schema
-- Version: 1.0.0

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users Table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Email Analysis History Table
CREATE TABLE IF NOT EXISTS email_analysis (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    message_hash VARCHAR(64) NOT NULL,
    sender_domain VARCHAR(255),
    classification VARCHAR(50) NOT NULL CHECK (classification IN ('SAFE', 'SPAM', 'SUSPICIOUS', 'HIGH_RISK', 'PHISHING')),
    risk_score INT NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    confidence NUMERIC(3,2) NOT NULL CHECK (confidence >= 0.00 AND confidence <= 1.00),
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    reasons JSONB NOT NULL DEFAULT '[]',
    recommendation TEXT NOT NULL,
    user_action VARCHAR(50) DEFAULT 'NONE' CHECK (user_action IN ('NONE', 'MARKED_SAFE', 'REPORTED', 'IGNORED')),
    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_email_analysis_hash ON email_analysis(message_hash);
CREATE INDEX IF NOT EXISTS idx_email_analysis_class ON email_analysis(classification);
CREATE INDEX IF NOT EXISTS idx_email_analysis_scanned ON email_analysis(scanned_at DESC);

-- Threat Reports Table
CREATE TABLE IF NOT EXISTS threat_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    analysis_id UUID REFERENCES email_analysis(id) ON DELETE SET NULL,
    message_hash VARCHAR(64) NOT NULL,
    reported_target VARCHAR(50) NOT NULL CHECK (reported_target IN ('GMAIL', 'PHISHSENSE', 'BOTH')),
    status VARCHAR(50) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'REVIEWED', 'CONFIRMED', 'DISMISSED')),
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- User Feedback Table
CREATE TABLE IF NOT EXISTS user_feedback (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    analysis_id UUID REFERENCES email_analysis(id) ON DELETE CASCADE,
    feedback_type VARCHAR(50) NOT NULL CHECK (feedback_type IN ('SAFE', 'SPAM', 'PHISHING')),
    original_classification VARCHAR(50) NOT NULL,
    user_comment TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Trusted Senders Table
CREATE TABLE IF NOT EXISTS trusted_senders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sender_or_domain VARCHAR(255) NOT NULL UNIQUE,
    added_by VARCHAR(255) DEFAULT 'USER',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Blocked Senders Table
CREATE TABLE IF NOT EXISTS blocked_senders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sender_or_domain VARCHAR(255) NOT NULL UNIQUE,
    added_by VARCHAR(255) DEFAULT 'USER',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Aggregated Statistics Table
CREATE TABLE IF NOT EXISTS statistics (
    id INT PRIMARY KEY DEFAULT 1,
    total_scanned INT NOT NULL DEFAULT 0,
    safe_count INT NOT NULL DEFAULT 0,
    spam_count INT NOT NULL DEFAULT 0,
    suspicious_count INT NOT NULL DEFAULT 0,
    high_risk_count INT NOT NULL DEFAULT 0,
    phishing_count INT NOT NULL DEFAULT 0,
    reports_count INT NOT NULL DEFAULT 0,
    marked_safe_count INT NOT NULL DEFAULT 0,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT single_row CHECK (id = 1)
);

-- Insert initial stats row if not exists
INSERT INTO statistics (id, total_scanned, safe_count, spam_count, suspicious_count, high_risk_count, phishing_count, reports_count, marked_safe_count)
VALUES (1, 0, 0, 0, 0, 0, 0, 0, 0)
ON CONFLICT (id) DO NOTHING;
