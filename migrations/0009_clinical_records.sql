-- 0009_clinical_records.sql
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS clinical_records (
 id TEXT PRIMARY KEY,
 practice_id TEXT NOT NULL REFERENCES practices(id) ON DELETE CASCADE,
 client_user_id TEXT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
 dietitian_user_id TEXT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
 profile_json TEXT NOT NULL DEFAULT '{}',
 patient_notes TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','reviewed')),
 created_at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 updated_at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 UNIQUE(practice_id,client_user_id,dietitian_user_id)
);
CREATE INDEX IF NOT EXISTS idx_clinical_records_patient ON clinical_records(practice_id,client_user_id,updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_clinical_records_dietitian ON clinical_records(practice_id,dietitian_user_id,updated_at DESC);
