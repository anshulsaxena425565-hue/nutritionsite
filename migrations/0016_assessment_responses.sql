-- Secure public nutrition intake responses submitted from the guided assessment form.
CREATE TABLE IF NOT EXISTS assessment_responses (
 id TEXT PRIMARY KEY,
 full_name TEXT NOT NULL,
 email TEXT NOT NULL,
 phone TEXT NOT NULL DEFAULT '',
 answers_json TEXT NOT NULL DEFAULT '{}',
 calculated_json TEXT NOT NULL DEFAULT '{}',
 created_at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_assessment_responses_created ON assessment_responses(created_at DESC);

-- Hashed IP-only throttle for public intake submissions; raw IPs are never persisted.
CREATE TABLE IF NOT EXISTS assessment_submission_limits (
 ip_hash TEXT PRIMARY KEY,
 window_started_at TEXT NOT NULL,
 request_count INTEGER NOT NULL DEFAULT 0
);
