-- Threat Intelligence Platform Database Schema
-- SQLite database schema for IOC tracking, correlation, and reporting

-- IOCs table: stores all indicators of compromise
CREATE TABLE IF NOT EXISTS iocs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_value       TEXT NOT NULL,
    ioc_type        TEXT NOT NULL,        -- ip, domain, url, hash, email
    source_feed     TEXT,                 -- URLhaus, ThreatFox, Feodo, MalwareBazaar, Manual, Demo
    threat_type     TEXT,                 -- malware, phishing, c2, botnet, ransomware
    malware_family  TEXT,                 -- Emotet, CobaltStrike, etc.
    confidence      INTEGER DEFAULT 50,   -- 0 to 100
    severity        TEXT DEFAULT 'Medium', -- Critical, High, Medium, Low
    first_seen      TEXT,                 -- ISO timestamp
    last_seen       TEXT,                 -- ISO timestamp
    tags            TEXT,                 -- JSON array stored as string
    is_active       INTEGER DEFAULT 1,    -- 1=active, 0=expired or removed
    false_positive  INTEGER DEFAULT 0,    -- 0=unknown, 1=confirmed FP
    enriched        INTEGER DEFAULT 0,    -- 0=not enriched, 1=enriched
    enrichment_data TEXT,                 -- JSON blob of VT/AbuseIPDB data
    created_at      TEXT,
    updated_at      TEXT,
    UNIQUE(ioc_value, ioc_type)
);

-- Correlations table: stores matches between IOCs and log entries
CREATE TABLE IF NOT EXISTS correlations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    correlation_id  TEXT UNIQUE,
    ioc_id          INTEGER REFERENCES iocs(id),
    log_source      TEXT,                 -- firewall, dns, proxy, auth, file_hash
    log_entry       TEXT,                 -- JSON of matched log entry
    matched_at      TEXT,
    threat_score    INTEGER DEFAULT 0,    -- 0 to 100
    verdict         TEXT,                 -- Confirmed Threat / Suspicious / Low Confidence
    analyst_notes   TEXT,
    reviewed        INTEGER DEFAULT 0,    -- 0=pending, 1=reviewed
    created_at      TEXT
);

-- Feed status table: tracks the health and status of threat feeds
CREATE TABLE IF NOT EXISTS feed_status (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_name       TEXT UNIQUE,
    feed_url        TEXT,
    last_updated    TEXT,
    ioc_count       INTEGER DEFAULT 0,
    status          TEXT DEFAULT 'active', -- active, error, disabled
    error_message   TEXT
);

-- Reports table: stores generated correlation and briefing reports
CREATE TABLE IF NOT EXISTS reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id       TEXT UNIQUE,
    generated_at    TEXT,
    total_iocs      INTEGER DEFAULT 0,
    total_matches   INTEGER DEFAULT 0,
    confirmed_threats INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    report_data     TEXT,                 -- Full JSON report blob
    ai_briefing     TEXT                  -- AI generated markdown briefing
);

-- Create indexes for faster queries
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(ioc_value);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_active ON iocs(is_active);
CREATE INDEX IF NOT EXISTS idx_iocs_severity ON iocs(severity);
CREATE INDEX IF NOT EXISTS idx_correlations_ioc_id ON correlations(ioc_id);
CREATE INDEX IF NOT EXISTS idx_correlations_verdict ON correlations(verdict);
CREATE INDEX IF NOT EXISTS idx_correlations_matched_at ON correlations(matched_at);
