# Security hardening rollout

## Production configuration completed

- Created the Cloudflare Worker secret RATE_LIMIT_SECRET (48 cryptographically random bytes); its value is not stored in this repository.
- Applied the D1 migration creating auth_rate_limits and its expiry index to the production database bound as DB.
- The Vercel project already has a same-origin rewrite from /api/worker/:path* to the Cloudflare Worker. The dashboard now calls /api/worker, so browser session cookies are first-party to prachisayani.online instead of third-party workers.dev cookies.

## Authentication changes

- Browser sessions are stored only in an HttpOnly, Secure, SameSite=Lax cookie. The frontend sends cookies with same-origin requests and an allowlisted custom CSRF header. Bearer tokens and JSON session-token responses are no longer accepted.
- Session absolute lifetime is 12 hours. Existing bearer-token sessions require a fresh sign-in after rollout.
- Existing PBKDF2-SHA256 hashes at 100,000 iterations are verified once and upgraded to the versioned 600,000-iteration format after successful password login.
- Login, registration, OTP issue and OTP verification are throttled by IP and account/email using HMAC-pseudonymised D1 bucket keys. Expired buckets are cleaned during auth requests.
- OTP consumption is conditional/atomic and digest comparisons use a constant-time comparison helper.
- API responses, including CORS preflight, include CSP, HSTS, frame, MIME-sniffing, referrer, permissions and opener protections.
- Static HTML pages include CSP and referrer meta policies. The landing page inline JavaScript was moved to a same-origin asset so the page can use script-src 'self'.

## Deployment sequence

1. Merge the reviewed security branch only after CI is green.
2. Deploy the updated Cloudflare Worker script, preserving its existing D1 and Resend bindings. The D1 migration and RATE_LIMIT_SECRET are already in place.
3. Verify password login, OTP login, registration, patient activation, logout, 12-hour session expiry, CSRF rejection, rate-limit responses, and dashboard read/write flows on the production domain.
4. Confirm document-level response headers on the Vercel edge. CSP meta policies cannot set HSTS, X-Frame-Options or Permissions-Policy; add those as Vercel response headers (or at the CDN edge) for all HTML routes.

## Password-hashing rationale

The Cloudflare Worker Web Crypto API does not expose Argon2id as a native primitive. This change uses PBKDF2-HMAC-SHA256 at 600,000 iterations, with automatic legacy rehash, rather than adding an unaudited WASM password-hashing dependency to a latency-sensitive Worker. Argon2id can be revisited if an audited implementation is benchmarked and supported in the deployed runtime.
