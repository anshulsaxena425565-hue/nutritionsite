-- 0009_patient_weight_measurements.sql
-- Shared, account-level measurement history for the client tracker and the
-- authorised dietitian patient record. BMI is stored as a calculated snapshot.
CREATE TABLE IF NOT EXISTS patient_measurements (
  id TEXT PRIMARY KEY,
  client_user_id TEXT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
  practice_id TEXT REFERENCES practices(id) ON DELETE SET NULL,
  measurement_date TEXT NOT NULL,
  weight_kg REAL NOT NULL CHECK(weight_kg > 0 AND weight_kg < 500),
  height_cm REAL NOT NULL CHECK(height_cm > 0 AND height_cm < 260),
  bmi REAL NOT NULL CHECK(bmi > 0 AND bmi < 200),
  recorded_by_user_id TEXT REFERENCES app_users(id) ON DELETE SET NULL,
  recorded_by_role TEXT NOT NULL CHECK(recorded_by_role IN ('client','dietitian')),
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_patient_measurements_client_date
  ON patient_measurements(client_user_id, measurement_date DESC, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_patient_measurements_practice_client
  ON patient_measurements(practice_id, client_user_id, measurement_date DESC);
