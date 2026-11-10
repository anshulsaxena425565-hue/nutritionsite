-- 0013_patient_measurement_time.sql
-- Preserve the time at which each patient measurement was recorded.
ALTER TABLE patient_measurements ADD COLUMN measurement_time TEXT NOT NULL DEFAULT '00:00';
