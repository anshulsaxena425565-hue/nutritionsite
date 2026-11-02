CREATE TABLE IF NOT EXISTS platform_module_controls (
  user_type TEXT NOT NULL,
  module_key TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_by TEXT,
  PRIMARY KEY (user_type, module_key)
);
