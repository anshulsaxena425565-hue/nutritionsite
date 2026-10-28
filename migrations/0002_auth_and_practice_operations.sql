-- 0002_auth_and_practice_operations.sql
-- Applied to Cloudflare D1. Authentication tables only; endpoints remain disabled until
-- a verified transactional email sender and session-signing secret are configured.
CREATE TABLE IF NOT EXISTS auth_challenges (
 id TEXT PRIMARY KEY, email TEXT NOT NULL COLLATE NOCASE,
 purpose TEXT NOT NULL CHECK(purpose IN ('login','invite','verify_email')),
 code_hash TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, expires_at TEXT NOT NULL,
 consumed_at TEXT, created_at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_email_purpose ON auth_challenges(email,purpose,created_at);
CREATE TABLE IF NOT EXISTS auth_sessions (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
 token_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL, revoked_at TEXT, last_seen_at TEXT,
 created_at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_expiry ON auth_sessions(user_id,expires_at);
CREATE TABLE IF NOT EXISTS platform_admins (
 user_id TEXT PRIMARY KEY REFERENCES app_users(id) ON DELETE CASCADE,
 granted_by_user_id TEXT REFERENCES app_users(id) ON DELETE SET NULL,
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended')),
 created_at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS practice_invitations (
 id TEXT PRIMARY KEY, practice_id TEXT NOT NULL REFERENCES practices(id) ON DELETE CASCADE,
 email TEXT NOT NULL COLLATE NOCASE,
 role TEXT NOT NULL CHECK(role IN ('owner','admin','dietitian','assistant','client')),
 invited_by_user_id TEXT NOT NULL REFERENCES app_users(id) ON DELETE RESTRICT,
 token_hash TEXT NOT NULL UNIQUE,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','revoked','expired')),
 expires_at TEXT NOT NULL, accepted_at TEXT,
 created_at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_invitations_practice_status ON practice_invitations(practice_id,status,created_at);
CREATE INDEX IF NOT EXISTS idx_invitations_email_status ON practice_invitations(email,status);
CREATE TABLE IF NOT EXISTS practice_settings (
 practice_id TEXT PRIMARY KEY REFERENCES practices(id) ON DELETE CASCADE,
 logo_url TEXT, support_email TEXT, support_phone TEXT,
 brand_primary TEXT NOT NULL DEFAULT '#315a45', brand_secondary TEXT NOT NULL DEFAULT '#dce7d9',
 booking_enabled INTEGER NOT NULL DEFAULT 1 CHECK(booking_enabled IN (0,1)),
 client_chat_enabled INTEGER NOT NULL DEFAULT 1 CHECK(client_chat_enabled IN (0,1)),
 updated_at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
