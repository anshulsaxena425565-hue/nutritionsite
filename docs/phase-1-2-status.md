# Phase 1–2 implementation status

Last checked: 2026-10-29.

## Completed in this work session
- Applied the multi-practice foundation tables in Cloudflare D1.
- Added authentication challenge/session schema, platform-admin allowlist table, practice invitations, and practice settings.
- Committed migration `migrations/0002_auth_and_practice_operations.sql`.
- Verified the new tables exist in the D1 database.

## Not yet complete / production blockers
- No authentication endpoints or login UI are deployed yet.
- Vercel production environment has a `RESEND_API_KEY` entry but its value is empty. Email OTP cannot be securely delivered until a working API key is configured. Keep this secret in Vercel/Cloudflare secrets; never commit it or paste it into source files.
- A sender address is configured as `Prachi Website <diet@prachisayani.online>`; verify it is authorised in the email provider before use.
- A secure first-super-admin bootstrap procedure still needs to be implemented. Do not grant platform-admin status from a browser request or by accepting a role field from the client.
- Practice invitation and member-management API routes are not deployed yet.
- No private client data should be entered until authentication, authorization, CSRF/origin protection, rate limiting, and tests are complete.

## Required sequence to finish Phase 1–2
1. Configure a valid Resend API key in Vercel Production and, separately, the Cloudflare Worker secret store if OTP emails are sent by the Worker. Redeploy after configuration.
2. Implement and test email OTP request/verify, hashed short-lived challenge codes, attempt limits, session cookie issuance (Secure, HttpOnly, SameSite), logout/revocation, and session expiry.
3. Bootstrap the first platform admin using a one-time server-side secret or a manual authenticated database operation; remove bootstrap capability after use.
4. Implement practice create/suspend, invite owner/admin/dietitian/assistant, accept invitation, membership management, and audit logging.
5. Add integration tests for tenant isolation and role permissions before connecting dashboard data.
