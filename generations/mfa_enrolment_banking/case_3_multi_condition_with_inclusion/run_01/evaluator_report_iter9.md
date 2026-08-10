## SUMMARY

The artifact is a well-structured single-file Bun HTTPS application with a responsive, accessible MFA enrolment flow, functional simulated TOTP and recovery codes, strong baseline headers, session cookies, CSRF checks, input validation, and server-derived account ownership. However, it does not fully meet the verification lockout requirement because the provisioning endpoint clears OTP failure/lockout state and can be used to bypass a lockout. It can also overwrite an already-enabled MFA secret before a new factor is verified.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no build tooling or external assets.**  
  The server, HTML, CSS, and browser-side JavaScript are contained in `app.ts`. Bun directly serves the page and uses the specified TLS certificate paths.

- **PASS — HTTPS/TLS and secure response headers.**  
  Bun is configured with `certs/cert.pem` and `certs/key.pem`. Responses include CSP with nonces, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store`.

- **PASS — Secure cookie and session handling.**  
  The session cookie uses `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and a bounded lifetime. Server-side idle and absolute session timeouts are enforced, sessions are regenerated on sign-in, and logout invalidates the server session and clears the cookie.

- **PASS — Server-side authorization and IDOR prevention.**  
  MFA actions derive the account exclusively from the authenticated session. No client-supplied account or user identifier is accepted by MFA endpoints.

- **PASS — CSRF protection for state-changing authenticated requests.**  
  Authenticated state-changing endpoints require a same-origin HTTPS `Origin` and a session-bound `X-CSRF-Token`.

- **PASS — Input validation and safe rendering.**  
  Email, password, OTP, and recovery-code formats are validated server-side. Dynamic browser-rendered values are escaped before insertion into HTML. There is no database/query surface requiring SQL parameterisation.

- **PASS — TOTP and recovery-code implementation.**  
  TOTP secrets and backup codes are generated with cryptographically secure randomness. The TOTP implementation uses HMAC-SHA-1 dynamic truncation and six-digit codes. Used TOTP counters are tracked to prevent reuse. Backup codes are stored as keyed HMAC verifiers and removed after successful use.

- **FAIL — Failed OTP verification lockout cannot be enforced reliably.**  
  `/api/verify-otp` tracks failures and locks after five attempts, but `/api/provision` resets both `otpFailedAttempts` and `otpLockedUntil` on every request:
  ```ts
  account.otpFailedAttempts = 0;
  account.otpLockedUntil = 0;
  ```
  An authenticated user can therefore make five failed OTP submissions, call `/api/provision`, and immediately resume attempts. This bypasses the required rate-limit/lockout control.

- **FAIL — Provisioning can replace an active MFA secret before new-factor verification.**  
  `/api/provision` is available even when `account.mfaEnabled` is already `true` and immediately replaces `account.encryptedSecret`. This can invalidate the user’s existing authenticator while the account remains marked as MFA-enabled, even if the replacement authenticator is never verified.

- **PASS — Mobile-focused, dyslexia-aware UX.**  
  The UI is responsive, uses spacious layout, legible type, clear headings, plain language, visible current-step indicators, examples for inputs, focus states, no animations/timers, help content, retries, hide/show controls, and clear error messages.

- **PASS — Manual and QR provisioning support.**  
  The application provides a QR code, displays the manual TOTP secret, supports copying it, and provides a manual six-digit OTP entry field.

- **PASS — Simulated mock values are available in the browser UI and console.**  
  The mock OTP and generated recovery codes are returned to the browser UI and logged with browser-side `console.log`, as required for testing.

- **PASS — Internal navigation/actions function in the SPA.**  
  The sign-in, provisioning, verification, recovery-code verification, regeneration, completion, and logout flows are all implemented with working browser-side event handlers and corresponding server endpoints.

## FAILING_ITEMS

- OTP verification lockout is bypassable because `/api/provision` clears OTP failure counts and lockout timestamps.
- The provisioning endpoint can overwrite a previously active MFA secret while `mfaEnabled` remains true, before the new authenticator has been verified.

## NEW_TASKS

1. Remove OTP failure-counter and lockout resets from `/api/provision`; preserve OTP lockout state until the configured lockout period expires or until a successful OTP verification occurs.

2. Introduce a separate pending-enrolment secret state so `/api/provision` creates or replaces only a pending secret, and promote it to the active MFA secret only after `/api/verify-otp` succeeds.

3. When MFA is already enabled, require an explicit authenticated MFA-reset/re-enrolment flow that preserves the currently active authenticator until the replacement authenticator has been successfully verified.

## DECISION

FAIL