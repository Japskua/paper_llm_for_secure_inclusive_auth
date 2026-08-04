## SUMMARY

The artifact is a valid single-file Bun HTTPS SPA with a generally strong recovery flow: session-bound CSRF protection, secure cookie flags, CSP nonces, random short-lived single-use reset tokens, bcrypt password hashing, MFA, server-side stage enforcement, and browser-console mock delivery logs are implemented. However, it does not fully meet the security requirements because throttling can be trivially bypassed by obtaining new sessions, and privacy acceptance is enforced only in client-side UI rather than validated by the server.

## FUNCTIONAL_CHECK

- **Single `app.ts` file containing Bun server, HTML, CSS, and vanilla JavaScript — PASS**
  - The submitted artifact is one `app.ts` file and contains the Bun server, generated HTML, inline CSS, and browser JavaScript. It uses no frameworks, bundlers, external assets, or external network calls.

- **Bun HTTPS server uses supplied TLS certificate locations — PASS**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - The server rejects non-HTTPS request URLs and sets HSTS.

- **Password-recovery flow is functional — PASS**
  - The SPA supports requesting a token, manually entering it, selecting a password, completing MFA, accepting privacy conditions, and viewing completion.
  - Server-side stages prevent skipping password, MFA, or privacy stages.
  - Hash-based internal navigation functions through the configured UI routing.

- **Simulated delivery is visible in browser console and UI — PASS**
  - The reset token and MFA code are returned specifically for evaluation and passed through `mockLog`, which calls browser-side `console.log`.
  - The values are also shown in the visible test-log panel.
  - Manual reset-token submission is supported.

- **CSRF controls on state-changing endpoints — PASS**
  - Every `/api/recovery/*` POST first calls `requireCsrf`.
  - The token is session-specific, checked using a timing-resistant comparison, and is paired with exact Origin validation.
  - The session cookie is opaque, `HttpOnly`, `Secure`, `SameSite=Strict`, and scoped to `/`.

- **Sensitive route and recovery-stage access control — PASS**
  - Password changes require `tokenVerified`.
  - MFA requires `passwordSet`.
  - Privacy acceptance requires `mfaVerified`.
  - The API does not accept user-controlled identifiers selecting another user/session record, avoiding an IDOR-style route design.

- **XSS and injection protections — PASS**
  - Browser UI uses DOM APIs and `textContent`, not `innerHTML`.
  - User-provided contact, token, password, and MFA inputs are neither reflected nor logged by the server.
  - Dynamic server-rendered values are escaped.
  - CSP uses per-page nonces and restricts sources to the application.

- **Secure headers and production-error behavior — PASS**
  - CSP, HSTS, `X-Content-Type-Options`, frame protections, `Referrer-Policy`, permissions policy, COOP/CORP, and no-store cache control are configured.
  - Generic error responses avoid stack traces and debug output.

- **Reset-token security — PASS**
  - Tokens are generated from `randomBytes(32)`, stored only as SHA-256 digests, bound to the current session, expire after ten minutes, and are marked single-use after successful verification.

- **Password security and MFA — PASS**
  - Password policy requires 12–128 characters with lowercase, uppercase, numeric, and symbol characters.
  - Passwords are hashed server-side with bcrypt at cost 12 and are not logged or returned.
  - MFA is required before the privacy statement can be accepted.

- **Automated guessing/recovery throttling — FAIL**
  - Limits are maintained only within `session.attempts`.
  - An attacker can repeatedly request `GET /` without retaining the existing cookie, receive a new session each time, and obtain a fresh attempt bucket. This bypasses limits for recovery requests, reset-token attempts, password submissions, and MFA attempts.
  - This does not satisfy the requirement that automated guessing attempts be throttled or blocked.

- **Server-side validation of privacy acceptance — FAIL**
  - `/api/recovery/privacy-accept` accepts an empty JSON body and unconditionally records `privacyAccepted = true` whenever the session has reached `mfaVerified`.
  - The checkbox is checked only in browser JavaScript. A direct authenticated API call with a valid CSRF token can record acceptance without any explicit affirmative acceptance value being validated by the backend.

- **No external redirects/SSRF paths and anti-phishing guidance — PASS**
  - The application has no user-supplied outgoing URL, redirect, fetch target, or support/staff impersonation workflow.
  - The UI prominently tells users not to share passwords, reset tokens, or MFA codes with callers or staff.

## FAILING_ITEMS

- **Rate limiting is session-only and bypassable.**
  - The `throttled()` function records attempts in `session.attempts`.
  - New sessions are freely created on `GET /`, so a client can reset the limit simply by not sending the current `recovery_session` cookie.
  - This weakens brute-force protection for token verification and MFA, and permits unlimited recovery-token requests across new sessions.

- **Privacy acceptance is not verified server-side.**
  - The backend does not require or validate an explicit `{ accepted: true }` value.
  - The user-visible checkbox is therefore only a client-side control, not an authoritative record of user consent.

## NEW_TASKS

1. Replace or supplement session-only throttling with server-side rate limiting that cannot be reset by creating a new session, such as a bounded rate-limit bucket keyed by client IP address plus action, with sensible expiry and cleanup.

2. Apply the non-bypassable rate limiter to recovery-token issuance, reset-token verification, password-change attempts, and MFA verification attempts; retain the existing per-session limits as defense in depth if desired.

3. Send an explicit acceptance value from the privacy form, for example `{ accepted: check.checked }`, to `/api/recovery/privacy-accept`.

4. Require `body.accepted === true` in `/api/recovery/privacy-accept`; otherwise return a validation error and do not set `privacyAccepted` or advance the recovery stage.

## DECISION

FAIL