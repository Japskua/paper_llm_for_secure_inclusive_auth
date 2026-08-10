## SUMMARY

The artifact is a well-structured single-file Bun HTTPS application with a responsive mobile MFA enrolment UI, server-side sessions, CSRF checks, encryption/hashing, restrictive security headers, and working simulated identity/TOTP/backup-code flows. However, it does not fully meet the repeated-failed-verification rate-limiting and lockout requirement because recovery-code verification is unbounded, and malformed TOTP submissions are not counted toward the TOTP lockout.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework/build tooling**
  - The server, HTML template, inline CSS, and browser JavaScript are all contained in `app.ts`.
  - It uses `Bun.serve` directly and does not use external packages, bundlers, compilation steps, or external assets.

- **PASS — HTTPS/TLS is configured using the required certificate paths**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - Requests whose URL protocol is not HTTPS are rejected.

- **PASS — Mobile-responsive and accessible enrolment UI**
  - The HTML includes a mobile viewport declaration.
  - Content is constrained to a mobile-friendly width, controls have readable sizing, focus states are present, and forms use labels, semantic sections, live regions, and suitable mobile input modes.
  - The manual authenticator-secret option is clearly presented, avoiding a QR-only flow.

- **PASS — Simulated delivery and verification flows function**
  - Identity codes, authenticator setup values, current TOTP test values, and recovery codes are returned to the browser and logged with `console.log`.
  - Identity verification, authenticator activation, recovery-code verification, regeneration, acknowledgement, and logout are all implemented.
  - Backup codes are displayed once in the main flow and are single-use server-side.

- **PASS — Server-side MFA authorization and IDOR protections**
  - MFA endpoints derive the owner solely from the opaque session cookie.
  - No user identifier is accepted from the client for MFA operations.
  - MFA operations require an authenticated session and verify `ownerId === ACCOUNT_OWNER_ID`.
  - Manipulating a guessed user identifier cannot select another account because no client-supplied identifier is used.

- **PASS — CSRF protection for state-changing requests**
  - State-changing endpoints require both a session-bound CSRF token and a trusted same-origin HTTPS `Origin`.
  - The CSRF token is rotated when the pending session becomes authenticated.
  - The session cookie uses `SameSite=Strict`.

- **PASS — Secure session cookie and lifecycle handling**
  - The session cookie has `HttpOnly`, `Secure`, `SameSite=Strict`, and `Path=/` attributes.
  - Session identifiers are generated from cryptographically secure random values.
  - Session IDs are rotated after identity verification.
  - Idle and absolute session expiration are enforced server-side.
  - Logout deletes the server session and expires the cookie.

- **PASS — Security headers, CORS restrictions, and generic errors**
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, no-referrer policy, and no-store caching.
  - CORS is restricted to trusted HTTPS localhost origins.
  - Exceptions produce generic error responses without stack traces or debug output.

- **PASS — Secret and backup-code protections**
  - TOTP secrets are generated using `crypto.getRandomValues` and AES-GCM encrypted while held server-side.
  - Backup recovery codes are generated using a cryptographically secure RNG and only SHA-256 hashes with a server pepper are retained.
  - Secrets, OTPs, backup codes, and sessions are not written to browser storage or non-HttpOnly cookies.

- **PASS — Input validation, output encoding, and redirect handling**
  - Email, phone, OTP, and recovery-code inputs are validated server-side.
  - Client rendering of dynamic values uses `textContent` rather than unsafe HTML interpolation for secrets and codes.
  - No external or user-controlled redirects exist.

- **FAIL — Failed verification attempts are not consistently rate-limited and locked out**
  - `/api/mfa/recovery/verify` has no failure counter, rate limit, or lockout state. An attacker with an authenticated session can submit unlimited recovery-code guesses.
  - `/api/mfa/activate` increments `totpFailures` only after a syntactically valid six-digit code. Repeated malformed TOTP submissions are rejected but never contribute to lockout.
  - This does not fully satisfy the requirement to rate-limit and lock out repeated failed verification attempts.

## FAILING_ITEMS

- **Recovery-code verification has unlimited failed attempts.**
  - The endpoint `/api/mfa/recovery/verify` checks whether a recovery code matches, but it neither records unsuccessful attempts nor blocks further attempts after a threshold.
  - This allows unlimited online guessing attempts against backup codes during an authenticated session.

- **Malformed authenticator-code submissions bypass the existing lockout counter.**
  - In `/api/mfa/activate`, `validOtp(body.code)` is checked before the failure counter is incremented.
  - Invalid-format submissions therefore produce unlimited failed verification requests without triggering `totpLockUntil`.

## NEW_TASKS

1. **Add recovery-code verification failure tracking and lockout enforcement.**
   - Add `recoveryFailures` and `recoveryLockUntil` fields to `Session`.
   - Before processing `/api/mfa/recovery/verify`, reject requests while `recoveryLockUntil` is active.
   - Increment `recoveryFailures` for every invalid, malformed, already-used, or non-matching recovery-code attempt.
   - Set `recoveryLockUntil` after a defined threshold, such as five failures, using `LOCKOUT_MS`.
   - Reset the recovery failure counter after a successful recovery-code verification.

2. **Ensure every failed TOTP activation submission contributes to TOTP lockout.**
   - In `/api/mfa/activate`, check `totpLockUntil` first.
   - Treat malformed OTP input as a failed verification attempt by incrementing `totpFailures`.
   - Apply `totpLockUntil` after the configured failure threshold for malformed as well as incorrect six-digit codes.
   - Reset `totpFailures` only after successful authenticator activation.

## DECISION

FAIL