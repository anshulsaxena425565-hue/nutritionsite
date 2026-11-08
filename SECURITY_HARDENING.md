# Security hardening rollout

## Required production configuration

Before deploying the Worker revision, create a Cloudflare Worker secret named `RATE_LIMIT_SECRET` containing at least 32 cryptographically random bytes. Do not put the value in GitHub, source files, or client-side configuration.

Apply `migrations/0010_auth_rate_limits.sql` to the production Cloudflare D1 database bound as `DB`. Authentication endpoints intentionally fail closed with HTTP 503 if the secret is absent.

## Authentication changes

- Browser sessions are stored only in an HttpOnly, Secure, SameSite=None cookie scoped to the API host. The frontend sends cookies and an allowlisted custom CSRF header. Bearer tokens and JSON session-token responses are no longer accepted.
- Session absolute lifetime is 12 hours. Existing bearer-token sessions require a fresh sign-in after rollout.
- Existing PBKDF2-SHA256 hashes at 100,000 iterations are verified once and upgraded to the versioned 600,000-iteration format after successful password login.
- Login, registration, OTP issue and OTP verification are throttled by IP and account/email using HMAC-pseudonymised D1 bucket keys.
- OTP consumption is atomic to prevent parallel replay.
- API JSON responses include CSP, HSTS, frame, MIME-sniffing, referrer, permissions and opener protections.

## Deployment sequence

1. Set the Worker secret `RATE_LIMIT_SECRET`.
2. Apply migration 0010 to the production Cloudflare D1 database.
3. Deploy `worker/index.js` to the existing Worker, preserving its D1 and Resend bindings.
4. Merge the frontend and workflow changes only after CI passes.
5. Verify password login, OTP login, registration, logout, 12-hour session expiry, CSRF rejection, rate-limit responses, and dashboard read/write flows.
6. Confirm document response headers on the production dashboard. The portal now has a CSP meta policy; HSTS, X-Frame-Options and Permissions-Policy for the HTML document must also be enforced at the hosting/Cloudflare edge because meta policies cannot set every response header.

## Password-hashing rationale

The Cloudflare Worker Web Crypto API does not expose Argon2id as a native primitive. This change uses PBKDF2-HMAC-SHA256 at 600,000 iterations, with automatic legacy rehash, rather than adding an unaudited WASM password-hashing dependency to a latency-sensitive Worker. Argon2id can be revisited if an audited implementation is benchmarked and supported in the deployed runtime.
