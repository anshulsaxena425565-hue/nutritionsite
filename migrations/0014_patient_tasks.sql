-- 0014_patient_tasks.sql
-- Tasks assigned by dietitians and status updates made by patients.
CREATE TABLE IF NOT EXISTS patient_tasks (
  id TEXT PRIMARY KEY,
  practice_id TEXT NOT NULL,
  dietitian_user_id TEXT NOT NULL,
  client_user_id TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  due_at TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','in_progress','completed')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_patient_tasks_client_status_due ON patient_tasks(client_user_id, status, due_at);
CREATE INDEX IF NOT EXISTS idx_patient_tasks_practice_dietitian_client ON patient_tasks(practice_id, dietitian_user_id, client_user_id, created_at);
