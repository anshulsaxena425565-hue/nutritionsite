# Nutrition platform architecture

## Product model
Multi-practice SaaS. Every practice-owned record carries a `practice_id`; every API request must derive the authenticated user and active membership from a verified session. Never trust a role, user ID, or practice ID sent by the browser.

## Roles
- Platform super admin: platform-level tenant and safety operations.
- Practice owner/admin: manages one practice, its dietitians, clients, packages, and billing settings.
- Dietitian: accesses only assigned/authorised clients in their practice.
- Client: accesses only their own profile, packages, published diet-plan versions, appointments, and conversations.
- Assistant: limited, configurable practice permissions; no clinical access unless explicitly granted.

## First foundation migration
`migrations/0001_multi_practice_foundation.sql` creates the tenant, membership, dietitian/client profile, package, client-package, diet-plan/version, chat, appointment, payment-order, and audit-log tables. It is additive and retains the existing public-enquiry table.

## Non-negotiable security rules
1. Add authentication before any private dashboard/API data is exposed. Use a maintained identity provider or a carefully reviewed signed-session implementation; do not store passwords in plaintext or implement improvised crypto.
2. Enforce role + practice membership + record ownership/assignment in the Worker for every private read and write.
3. Use parameterised D1 statements; validate request bodies and enforce size/rate limits.
4. Store only payment provider references/status; never store card numbers, CVV, or raw payment credentials. Verify gateway signatures server-side and make webhooks idempotent.
5. Private diet charts, lab reports, and attachments must not use public URLs. Use private object storage with short-lived authorised access once a storage option is enabled.
6. Write audit events for sensitive access, role changes, diet-plan publication, payment state changes, and exports.
7. Do not use real client clinical data in development or test fixtures.

## Planned implementation order
1. Authentication, tenant bootstrap, membership/role middleware, and super-admin access.
2. Practice setup, dietitian invitations/verification, package catalogue and client assignment.
3. Dietitian client workspace, assessment and versioned diet-plan publishing.
4. Client dashboard for packages, published plans, appointments, and chat.
5. Payment gateway adapter (provider selected after checking no-card onboarding and fees), verified webhooks and refunds.
6. Private attachments, food/nutrient database, notifications, backups, access review, and testing.

## Current limitations
- This migration is database foundation only; it does not implement login, sessions, or private dashboard routes.
- Online payment gateway is not configured. Gateway choice depends on account eligibility, onboarding requirements, and fees.
- R2 was not enabled in the Cloudflare account during initial setup, so no object storage should be assumed available.
- Treat production use with real health information as blocked until authentication, authorisation, private storage, backup/retention, and security tests are complete.
