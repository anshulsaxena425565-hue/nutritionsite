-- 0003_password_auth.sql
-- Adds a password hash field; plaintext passwords are never stored.
ALTER TABLE app_users ADD COLUMN password_hash TEXT;
