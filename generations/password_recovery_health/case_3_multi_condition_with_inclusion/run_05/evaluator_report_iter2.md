## SUMMARY

The artifact is a well-structured single-file Bun HTTPS application with a clear, low-stress recovery UI, CSRF protections, security headers, hashed passwords, token expiry, rate limiting, manual/link recovery-code verification, and browser-console mock delivery. However, it has authentication-state flaws that can bypass the intended MFA step in an existing authenticated session, does not enforce server-side session expiry, and does not provide a usable/documented approved mock identifier to complete the recovery flow out of the box. These issues prevent acceptance.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun implementation with no build tooling**
  - The complete server, HTML, CSS, and browser JavaScript are in `app.ts`.
  - It uses `Bun.serve` directly and has no frameworks, bundlers, external assets, or external network calls.

- **PASS — HTTPS/TLS server uses supplied certificates**
  - The server is configured with `certs/cert.pem` and `certs/key.pem`.
  - Requests whose URL protocol is not HTTPS are rejected.

- **PASS — Clear, structured, ADHD-inclusive multi-step UX**
  - The UI provides visible six-step progress, consistent language, low-density instructions, explicit “Next” guidance, no countdown display, a pause action, and readily available help.
  - The UI avoids unexpected screen changes: transitions occur after user actions and server confirmations.

- **PASS — Pause and return support is present**
  - The pause button records a local reminder and does not store passwords or codes in browser storage.
  - Server-side session state allows progress to be resumed while the session remains valid.

- **FAIL — Recovery flow is usable and verifications work out of the box**
  - Recovery only proceeds for an identifier whose SHA-256 hash matches a hardcoded value, but no approved mock account email/ID is documented, displayed, or otherwise made available to the user/tester.
  - A normal user cannot know which identifier will produce `recoveryRequested: true`, receive the browser mock code, and complete the reset flow.
  - The application therefore does not reliably satisfy the requirement that deterministic mocks and their verification “must work.”

- **PASS — Mock recovery delivery is available in the browser and manual verification is supported**
  - On an approved recovery request, the random mock recovery code is returned to the client, logged through browser `console.log`, displayed in the demo activity log, and can be entered manually.
  - The recovery-link path populates the code field without automatically consuming or verifying it.

- **PASS — Recovery links and internal navigation function**
  - `/recovery-link?token=...` is served by the application and initializes the verification screen.
  - Internal controls support returning to recovery, login, password creation, MFA, privacy acceptance, confirmation, and start.

- **PASS — Reset tokens are random, short-lived, and consumed after a successful password reset**
  - Tokens are generated with `randomBytes(32)`, stored only as SHA-256 hashes, expire after 15 minutes, and are marked used before password hashing.
  - Tokens are bound to the requesting session’s approved account key.

- **PASS — Password policy and secure password storage are implemented**
  - New passwords require at least 12 characters, upper/lowercase letters, a number, a symbol, and no spaces.
  - Passwords are stored using Bun bcrypt hashing and verified with bcrypt verification.
  - Password values are cleared in the browser after submission and are not logged.

- **FAIL — MFA is reliably enforced after password reset**
  - `/api/password` sets `pendingMfa = true` but does not clear `session.authenticated` or `session.privacyAccepted`.
  - If an already authenticated session starts a recovery/reset flow, it can remain authenticated after resetting the password. `bootstrap()` prioritizes `authenticated && privacyAccepted` over `pendingMfa`, rendering the confirmation page rather than MFA.
  - This violates the intended “confirm security code” protection after reset and creates an authentication-state bypass.

- **PASS — Login and sensitive actions are rate-limited**
  - Recovery, verification, password update, login, MFA, and privacy acceptance routes use per-session and source/account/action rate limits.
  - Limits persist across newly created sessions for the same source/account/action combination.

- **PASS — CSRF controls are implemented for state-changing API routes**
  - A random per-session CSRF token is created server-side.
  - All POST API routes require `X-CSRF-Token`.
  - The session cookie is `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **PASS — Output handling and browser-side XSS protections are generally sound**
  - User-controlled values are not inserted with `innerHTML`; dynamic UI text uses `textContent`.
  - Inputs are validated server-side.
  - CSP uses a per-response nonce, and no untrusted external scripts are loaded.

- **PASS — Secure response headers are broadly configured**
  - HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, referrer policy, permissions policy, COOP, and no-store caching are configured.
  - Error responses are generic and do not expose stack traces.

- **FAIL — Configured session lifetime is not enforced server-side**
  - `SESSION_MAX_AGE` is used only in the cookie’s `Max-Age`; `session.createdAt` is never checked.
  - Session records remain valid indefinitely in the in-memory `sessions` map if a session ID is reused or otherwise retained.
  - This contradicts the code’s apparent intended session lifetime and weakens access-control/session-security guarantees.

- **FAIL — Account recovery response leaks approval status to API callers**
  - Although the visible message is generic, approved requests return `recoveryRequested: true`, `mockRecoveryCode`, and `recoveryLink`; unapproved requests return `recoveryRequested: false` without those fields.
  - A caller that obtains its own CSRF token can distinguish approved from unapproved identifiers programmatically.
  - This conflicts with the stated privacy intent of providing the same outcome regardless of whether an account can receive recovery messages.

## FAILING_ITEMS

- MFA can be bypassed after a password reset when recovery is performed from a session that was already authenticated and/or had already accepted privacy conditions.
- Server-side sessions never expire despite `SESSION_MAX_AGE` and `createdAt` being defined.
- No usable or documented approved mock account identifier exists, so the demonstrable recovery flow cannot be completed reliably by a user/tester.
- The recovery API’s response shape exposes whether an identifier is approved, despite the UI claiming the response is the same for all identifiers.

## NEW_TASKS

1. Update recovery and password-reset state transitions to clear `authenticated` and `privacyAccepted` whenever a recovery flow begins and before setting `pendingMfa = true`; ensure `/api/password` always requires a successful MFA confirmation before any authenticated/confirmation state can be reached.

2. Enforce `SESSION_MAX_AGE` in `sessionFor()` by rejecting/deleting expired session records and issuing a new session; optionally add periodic cleanup of expired sessions and expired reset records.

3. Provide a safe, explicit test mechanism for the approved mock account identifier so the complete recovery flow is testable without exposing real user data; for example, define and document a clearly synthetic test account in the browser-only demonstration UI or provide a deterministic mock recovery path that does not reveal real account existence.

4. Make recovery responses externally indistinguishable for approved and unapproved identifiers. Preserve testability by returning the simulated code only through a controlled demonstration mechanism after a non-enumerating request, rather than exposing different API response fields based on account approval.

## DECISION

**FAIL**