-- 0015_recurring_patient_tasks.sql
-- Additive recurrence metadata. Existing tasks remain one-time tasks.
ALTER TABLE patient_tasks ADD COLUMN recurrence_type TEXT NOT NULL DEFAULT 'once' CHECK (recurrence_type IN ('once','daily','weekly'));
ALTER TABLE patient_tasks ADD COLUMN recurrence_days TEXT NOT NULL DEFAULT '';
ALTER TABLE patient_tasks ADD COLUMN series_id TEXT;
CREATE INDEX IF NOT EXISTS idx_patient_tasks_series ON patient_tasks(series_id, due_at);
