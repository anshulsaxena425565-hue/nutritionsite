-- Pseudonymous, HMAC-keyed fixed-window authentication throttles.
-- Apply to the production Cloudflare D1 database before deploying the updated Worker.
CREATE TABLE IF NOT EXISTS auth_rate_limits (
  bucket_key TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  hits INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_auth_rate_limits_expiry ON auth_rate_limits(expires_at);
