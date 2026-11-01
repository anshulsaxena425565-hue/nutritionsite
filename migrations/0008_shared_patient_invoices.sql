-- 0008_shared_patient_invoices.sql
-- Server-side invoices shared securely between the issuing dietitian and the addressed patient.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS practice_invoices (
 id TEXT PRIMARY KEY,
 practice_id TEXT NOT NULL REFERENCES practices(id) ON DELETE CASCADE,
 dietitian_user_id TEXT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
 patient_user_id TEXT REFERENCES app_users(id) ON DELETE SET NULL,
 invoice_number TEXT NOT NULL,
 patient_name TEXT NOT NULL,
 patient_email TEXT NOT NULL COLLATE NOCASE,
 status TEXT NOT NULL DEFAULT 'Draft' CHECK(status IN ('Draft','Sent','Paid','Overdue','Cancelled')),
 invoice_json TEXT NOT NULL,
 sent_at TEXT,
 created_at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 updated_at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 UNIQUE(practice_id, invoice_number)
);

CREATE INDEX IF NOT EXISTS idx_practice_invoices_dietitian
 ON practice_invoices(practice_id, dietitian_user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_practice_invoices_patient
 ON practice_invoices(patient_user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_practice_invoices_email
 ON practice_invoices(patient_email, status, updated_at DESC);
