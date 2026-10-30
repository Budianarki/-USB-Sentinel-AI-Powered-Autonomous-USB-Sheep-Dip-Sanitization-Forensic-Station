-- SQLite Schema for USB Sentinel (CLAUDE.md Section 12)

CREATE TABLE IF NOT EXISTS devices (
    fingerprint TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    reputation TEXT NOT NULL DEFAULT 'unknown', -- 'known_good', 'unknown', 'previously_blocked'
    label TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    device_fingerprint TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    decision TEXT,                             -- 'ALLOW', 'QUARANTINE', 'BLOCK', 'HUMAN_REVIEW'
    risk REAL,
    policy_version TEXT,
    ai_available INTEGER NOT NULL DEFAULT 0,    -- boolean 0 or 1
    operator_id TEXT,
    FOREIGN KEY (device_fingerprint) REFERENCES devices(fingerprint)
);

CREATE TABLE IF NOT EXISTS file_results (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    detected_type TEXT,
    size INTEGER NOT NULL,
    risk_det REAL NOT NULL,
    risk_ai REAL,
    flags_json TEXT NOT NULL DEFAULT '[]',
    action TEXT NOT NULL,                      -- 'ALLOW', 'QUARANTINE', 'BLOCK', 'HUMAN_REVIEW'
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS agent_runs (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    agent TEXT NOT NULL,
    model TEXT NOT NULL,
    tokens_in INTEGER NOT NULL DEFAULT 0,
    tokens_out INTEGER NOT NULL DEFAULT 0,
    cost_est REAL NOT NULL DEFAULT 0.0,
    latency_ms REAL NOT NULL DEFAULT 0.0,
    status TEXT NOT NULL,                      -- 'success', 'timeout', 'error', 'budget_exhausted'
    verdict_json TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS hash_cache (
    sha256 TEXT PRIMARY KEY,
    status TEXT NOT NULL,                      -- 'good', 'bad'
    source TEXT NOT NULL,                      -- 'local_admin', 'intel_virustotal', 'intel_malwarebazaar'
    added_at TEXT NOT NULL
);

-- Tamper-evident Audit Log Hash Chain (Invariant 10)
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    this_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reviews (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    action TEXT NOT NULL,                      -- 'APPROVE', 'REJECT'
    note TEXT,
    ts REAL NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

-- Indices for performance
CREATE INDEX IF NOT EXISTS idx_sessions_fingerprint ON sessions(device_fingerprint);
CREATE INDEX IF NOT EXISTS idx_file_results_session ON file_results(session_id);
CREATE INDEX IF NOT EXISTS idx_file_results_sha256 ON file_results(sha256);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
