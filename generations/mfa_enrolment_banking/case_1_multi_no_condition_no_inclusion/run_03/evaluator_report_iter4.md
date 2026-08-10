## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a functional MFA enrolment flow, responsive mobile UI, server-side session ownership checks, CSRF tokens, security headers, encrypted TOTP secrets, recovery-code verifiers, deterministic browser-visible test fixtures, and working authentication/recovery interactions. However, it does not fully meet the security requirements because verification rate limits can be bypassed, pending recovery codes are retained in plaintext server session state, and sign-in behavior permits distinguishable account-validity timing.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, bundler, compiler, or external assets.**  
  The complete Bun server, HTML, CSS, and browser-side vanilla JavaScript are contained in `app.ts`. There are no imports, external scripts, remote fonts, build steps, or network calls.

- **PASS — HTTPS/TLS is configured with the required certificate paths.**  
  `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.

- **PASS — Mobile-responsive SPA UI is present and usable.**  
  The app has a viewport meta tag, constrained mobile-width layout, responsive typography, accessible labels, sufficiently large controls, and a one-column fallback for narrow viewports.

- **PASS — Core MFA enrolment flow works.**  
  The flow supports sign-in, identity-code verification, authenticator-secret generation, TOTP confirmation, recovery-code display/download, acknowledgement, recovery-code verification, regeneration, and logout.

- **PASS — Deterministic test values are exposed in the browser as required for evaluation.**  
  The identity fixture, authenticator secret, TOTP fixture, and recovery codes are logged using browser-side `console.log` and shown in the visible Logs panel. This is consistent with the explicit non-production test-fixture requirement.

- **PASS — MFA settings access is based on server-side session ownership rather than client-supplied user IDs.**  
  All protected endpoints derive the account identity from the `HttpOnly` `mfa_session` cookie. There is no user ID parameter that could be manipulated for an IDOR attack.

- **PASS — CSRF and origin protections exist for protected state-changing MFA requests.**  
  Authenticated mutation endpoints require a per-session CSRF token. Requests with an explicitly supplied untrusted `Origin` are rejected. Session cookies also use `SameSite=Strict`.

- **PASS — Security headers and restrictive CORS are implemented.**  
  Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, permissions policy, no-store caching, and trusted-localhost-only CORS behavior.

- **PASS — Session management is substantially secure.**  
  Cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`; the session ID is rotated after identity verification; idle and absolute timeouts are enforced; and logout invalidates the server session and expires the cookie.

- **PASS — TOTP secrets and consumed recovery codes are protected at rest.**  
  Authenticator secrets are AES-GCM encrypted. Persisted recovery codes are stored as PBKDF2-derived verifiers with random salts rather than plaintext values.

- **FAIL — Backup recovery codes are temporarily persisted in plaintext in server-side session state.**  
  `Session.pendingRecoveryCodes?: string[]` stores raw recovery codes after enrolment and regeneration. This conflicts with the requirement to store backup codes using strong hashing/encryption at rest. The codes should only be returned once to the UI and not retained as plaintext in the session map.

- **FAIL — Identity verification lockout can be bypassed by repeatedly calling sign-in.**  
  `signIn()` resets `challenge.identityFailures = 0` every time valid Marcus credentials are submitted. An attacker can submit one bad identity code, sign in again, and repeat indefinitely without reaching the five-failure lockout.

- **FAIL — Authenticator OTP lockout can be bypassed by re-provisioning.**  
  A new `/api/mfa/provision` request may replace a still-pending MFA record with a new record whose `authenticatorFailures` and `authenticatorLockedUntil` are reset. In addition, expiry cleanup deletes the entire pending record, including OTP failure/lock information. This prevents reliable enforcement of repeated-failure lockout.

- **FAIL — Sign-in timing can distinguish valid configured account credentials from invalid credentials.**  
  Invalid email/phone combinations return before the async identity-code hash/session creation work, while valid Marcus credentials perform additional operations and return a session. Although visible messages are generic, this violates the requirement to avoid user/account enumeration in response timing.

- **PASS — Input validation and output handling are generally safe.**  
  JSON request bodies use allow-listed keys; email, phone, OTP, and recovery-code formats are validated; redirect input is restricted to `/`; and client-rendered dynamic values are inserted using `textContent` where user-derived values are involved. No SQL/database layer exists, so parameterized-query requirements are not applicable.

- **PASS — OTP and recovery credentials are single-use and time-bounded in the normal flow.**  
  Identity codes are consumed after verification, pending provisioning expires after five minutes, authenticator confirmation transitions the record to enabled, and successful recovery-code verification removes the matching verifier.

- **PASS — Errors are generic and do not expose stack traces or server secrets.**  
  The outer server handler catches exceptions and returns a generic JSON failure response.

## FAILING_ITEMS

- Raw recovery codes are retained in `Session.pendingRecoveryCodes`, leaving backup codes in plaintext server memory/state after they have been delivered.
- Valid sign-in requests reset `identityFailures`, allowing repeated failed identity-code attempts to avoid account lockout.
- New provisioning attempts can replace pending authenticator records and reset authenticator failure/lock state; pending-record deletion on expiry also discards lock state.
- Sign-in performs observably different work for valid Marcus credentials versus invalid credentials, enabling account-validity timing differences.

## NEW_TASKS

1. Replace `Session.pendingRecoveryCodes?: string[]` with a non-secret pending-delivery marker, and stop storing raw recovery codes after sending them in the enrolment/regeneration response.
2. Preserve identity-verification failure counters and lockout state across subsequent sign-in attempts; do not reset `identityFailures` merely because valid credentials initiate a new challenge.
3. Make authenticator provisioning and OTP throttling atomic per account, prevent replacement of an active pending provisioning record, and retain OTP lockout state independently of pending-secret cleanup.
4. Normalize sign-in processing time for valid and invalid account identifiers, including a comparable cryptographic operation and response timing path before returning the same generic outcome.

## DECISION

**FAIL**