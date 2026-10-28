CREATE TABLE IF NOT EXISTS dietitian_directory (
 user_id TEXT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
 practice_id TEXT NOT NULL REFERENCES practices(id) ON DELETE CASCADE,
 specialties_json TEXT NOT NULL DEFAULT '[]',
 languages_json TEXT NOT NULL DEFAULT '[]',
 consultation_modes_json TEXT NOT NULL DEFAULT '["Online"]',
 gender TEXT,
 fee_minor INTEGER NOT NULL DEFAULT 0 CHECK(fee_minor>=0),
 experience_years INTEGER NOT NULL DEFAULT 0 CHECK(experience_years>=0),
 accepting_clients INTEGER NOT NULL DEFAULT 1 CHECK(accepting_clients IN (0,1)),
 updated_at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 PRIMARY KEY(user_id,practice_id)
);
CREATE TABLE IF NOT EXISTS dietitian_requests (
 id TEXT PRIMARY KEY,
 practice_id TEXT NOT NULL REFERENCES practices(id) ON DELETE CASCADE,
 client_user_id TEXT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
 dietitian_user_id TEXT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
 message TEXT,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','declined','cancelled')),
 created_at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 updated_at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 UNIQUE(client_user_id,practice_id,dietitian_user_id)
);
CREATE INDEX IF NOT EXISTS idx_dietitian_directory_filters ON dietitian_directory(practice_id,accepting_clients,fee_minor,experience_years);
CREATE INDEX IF NOT EXISTS idx_dietitian_requests_dietitian ON dietitian_requests(dietitian_user_id,status,created_at);
CREATE INDEX IF NOT EXISTS idx_dietitian_requests_client ON dietitian_requests(client_user_id,status,created_at);