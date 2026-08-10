## SUMMARY

The artifact is a single-file Bun/TypeScript MFA enrolment SPA with responsive UI, HTTPS/TLS, owner-bound sessions, CSRF protection, secure headers, encrypted TOTP-secret storage, hashed recovery codes, and working simulated identity/TOTP verification. However, it does not fully meet the security requirements because lockouts can be bypassed by requesting new identity/authenticator setup data, and recovery codes are generated and stored but cannot be verified or marked used. The on-page activity log also displays sensitive OTP and recovery-code values.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, bundler, compiler, or external assets.**  
  All server code, HTML, CSS, and browser JavaScript are contained in `app.ts`. Bun can execute TypeScript directly, and the page does not load third-party assets.

- **PASS — TLS server uses the supplied certificate paths.**  
  `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.

- **PASS — Responsive, mobile-oriented MFA enrolment UI.**  
  The layout has a constrained mobile width, large controls, responsive code layout, accessible labels, and mobile input attributes such as `inputmode="numeric"` and `autocomplete="one-time-code"`.

- **PASS — Dyslexia-aware UX is substantially implemented.**  
  The UI uses spacious typography, plain-language instructions, icons, short hints, visible step progress, no animation/timers, copy controls, QR setup, hide/reveal controls, retry paths, and specific input-error messages.

- **PASS — Identity-code delivery and verification work.**  
  The identity-code endpoint creates a challenge, hashes it with a salt, expires it after 15 minutes, supports re-requesting, and verifies six-digit input. The simulated code is returned to the client as required for the demo.

- **PASS — Authenticator provisioning and TOTP confirmation work.**  
  A cryptographically random Base32 seed is generated, encrypted at rest with AES-GCM, exposed to the browser only for provisioning, included in a provisioning URI/QR code, and checked using an HMAC-SHA1 TOTP implementation with a small clock-skew window.

- **PASS — Manual setup-key and QR-code options are available.**  
  The setup flow provides a QR code, a revealable manual setup key, and a copy-to-clipboard action.

- **PASS — Session ownership / IDOR protection is implemented for MFA endpoints.**  
  MFA API routes derive the account exclusively from the server-side session cookie. The client cannot submit an account ID, user ID, or redirect-related identifier because `validObject()` rejects those fields.

- **PASS — CSRF protection is present on state-changing requests.**  
  Sign-in uses a bootstrap CSRF token tied to a SameSite cookie, and authenticated POST endpoints require the session-bound `X-CSRF-Token`.

- **PASS — Secure headers and restrictive CORS are implemented.**  
  Responses include CSP with nonce-bound scripts/styles, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, and no-store caching. CORS is restricted to the listed localhost origins.

- **PASS — Session-cookie flags and server-side session expiration are implemented.**  
  The `mfa_session` cookie is `HttpOnly`, `Secure`, and `SameSite=Strict`. Server-side idle and absolute session timeouts are enforced, sessions rotate on sign-in, and logout invalidates the session.

- **FAIL — Repeated-failure lockouts are bypassable.**  
  Identity lockout is attached to `account.identity`, but `/api/identity/request` always overwrites it with a new challenge. After five failed attempts, a user can immediately request a new code and continue guessing.  
  Authenticator lockout is also bypassable because `/api/authenticator/provision` resets `account.authFailures` and `account.authLockedUntil` to zero. After a five-attempt lockout, requesting a new setup key immediately clears the lockout.

- **FAIL — Recovery codes are not usable as recovery credentials.**  
  Recovery codes are securely generated and stored as salted hashes, but there is no API endpoint or UI flow to submit a recovery code, verify it, set `used: true`, or enforce single use. The `Recovery.used` field is never read or updated.

- **FAIL — Sensitive values are exposed in the visible activity-log panel.**  
  The browser `log()` function appends simulated identity OTPs, authenticator OTPs, and recovery codes to `<pre id="logs">`. This directly conflicts with the requirement not to expose OTPs, backup codes, or seeds in logs. Demo values may be written to `console.log` as explicitly required for testing, but they should not also be displayed in a persistent on-page “Activity logs” area.

- **PASS — Input validation and XSS protections are largely adequate.**  
  Server-side email, password, OTP, and recovery-code validators exist; request objects reject identifier/redirect fields; no database is used; and dynamic browser rendering generally uses `textContent` or escaped text.

- **PASS — No open redirects are present.**  
  Navigation is hash-based and limited to an allow-listed `routes` set. The server does not accept redirect destinations.

## FAILING_ITEMS

- Identity-code lockout can be bypassed by calling `/api/identity/request`, which replaces the locked challenge with a fresh unlocked challenge.
- Authenticator-code lockout can be bypassed by calling `/api/authenticator/provision`, which clears `authFailures` and `authLockedUntil`.
- Recovery codes are never verifiable, consumable, or marked as used; therefore their single-use security property is not implemented.
- OTPs and backup codes are written into the persistent visible “Activity logs” UI, unnecessarily exposing sensitive credentials.

## NEW_TASKS

1. Make identity-verification lockout account/session scoped and preserve it when a new identity code is requested; reject re-requests until `lockedUntil` has passed.
2. Remove the `authFailures` and `authLockedUntil` reset from `/api/authenticator/provision`; only clear failed-attempt state after a successful authenticator confirmation or after the lockout expires.
3. Add an owner-authorized, CSRF-protected recovery-code verification endpoint that validates the recovery-code format, compares salted hashes in constant time, marks a matching code as used, rejects reused codes, and applies rate limiting/lockout.
4. Add a corresponding recovery-code entry UI with clear plain-language feedback for valid, invalid, used, and locked-out recovery-code attempts.
5. Remove sensitive OTP and recovery-code values from the on-page activity-log panel. Keep the required demo `console.log` output in the browser, and show codes only in the purpose-specific protected setup/recovery screens.

## DECISION

FAIL