CREATE TABLE IF NOT EXISTS patient_food_diary (
  id TEXT PRIMARY KEY,
  client_user_id TEXT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
  diary_date TEXT NOT NULL,
  meal_slot TEXT NOT NULL CHECK(meal_slot IN ('Early morning','Breakfast','Mid-morning','Lunch','Evening snack','Dinner','Bedtime','Other')),
  meal_time TEXT NOT NULL DEFAULT '',
  food_description TEXT NOT NULL,
  quantity TEXT NOT NULL DEFAULT '',
  note TEXT NOT NULL DEFAULT '',
  recorded_by_user_id TEXT NOT NULL REFERENCES app_users(id),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_patient_food_diary_client_date
  ON patient_food_diary(client_user_id, diary_date DESC, meal_time ASC, created_at ASC);
