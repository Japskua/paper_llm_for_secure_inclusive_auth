## SUMMARY

The artifact is a valid single-file Bun application with inline HTML, CSS, and vanilla browser JavaScript. It provides a responsive four-step MFA enrolment flow, TLS startup using the specified certificate files, authenticated server-side MFA routes, CSRF checks, secure cookie attributes, TOTP generation/verification, encrypted OTP-secret storage, hashed recovery codes, and accessible dyslexia-conscious UI patterns. However, it does not fully meet the authentication-failure protection requirements because failed identity and recovery-code verification attempts are not rate-limited or locked out, and the existing TOTP lockout can be bypassed by requesting a new provisioning secret.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and client application**
  - The full server, HTML template, CSS, and client-side JavaScript are contained in `app.ts`.
  - It uses `Bun.serve` directly and does not require a bundler, compiler, framework, package, or external asset.

- **PASS — TLS is required and uses the specified certificate paths**
  - The server checks for `certs/cert.pem` and `certs/key.pem` before starting.
  - `Bun.serve` is configured with `tls: { cert: certificate, key: privateKey }`.
  - The application exits rather than silently falling back to HTTP.

- **PASS — Responsive, mobile-oriented MFA enrolment UI**
  - The document includes a viewport meta tag, constrained mobile-width layout, readable input sizes, and mobile media rules.
  - The flow is clear and ordered as identity confirmation, authenticator setup, recovery-code storage, and completion.

- **PASS — Dyslexia-conscious and inclusive UX**
  - The UI uses a legible sans-serif font stack, increased letter spacing and line height, large controls, plain wording, short examples, icon-assisted headings, generous spacing, and visible step indicators.
  - There are no timers, animations, flashing elements, or auto-updating code displays.
  - Errors state the problem and a corrective action without blaming the user.
  - Help text is shown consistently and retry paths exist.

- **PASS — QR, copy, reveal/hide, and manual authenticator setup support**
  - The provisioning screen supplies a QR code, a reveal/hide setup key option, copy-to-clipboard actions for the setup key and provisioning URI, and a manual TOTP entry field.
  - The TOTP input uses `autocomplete="one-time-code"` and numeric mobile input hints.
  - Recovery codes can be copied and are displayed to the user after creation.

- **PASS — Mock values are available in the browser console**
  - The provisioning secret, mock TOTP, original recovery codes, and regenerated recovery codes are logged through browser-side `console.log`.
  - This matches the explicit testing deliverable requiring browser-console mocks.

- **PASS — Server-side ownership enforcement / no user-ID IDOR**
  - MFA routes require a valid `sid` session through `requireSession`.
  - MFA state is derived only from `authenticated.session.userId`.
  - No MFA endpoint accepts a caller-controlled user identifier, preventing manipulated user-ID access.

- **PASS — CSRF and origin protection on state-changing authenticated routes**
  - State-changing endpoints require both the exact trusted `Origin` and the session-specific `X-CSRF-Token`.
  - Login requires the trusted origin before issuing a session.
  - Session cookies use `SameSite=Strict`.

- **PASS — Secure response headers and secure session cookie flags**
  - The application sends CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store`.
  - Session cookies are `HttpOnly`, `Secure`, `SameSite=Strict`, and path-restricted.

- **PASS — No external network calls, no browser secret persistence**
  - Client requests are same-origin relative API calls only.
  - No `localStorage`, `sessionStorage`, non-HttpOnly browser cookie storage, or external asset/API dependency is used.

- **PASS — OTP-secret and recovery-code cryptographic handling**
  - OTP secrets are generated with `crypto.getRandomValues`.
  - OTP secrets are held as AES-GCM encrypted values in server state.
  - Recovery codes are generated with cryptographic randomness and stored as independent salted PBKDF2-SHA-256 derived values.
  - Plain recovery codes are not retained in server state after the API response.

- **PASS — TOTP functionality, bounded validity, and single-use counters**
  - The artifact implements RFC-6238-style TOTP using HMAC-SHA-1, 30-second counters, and six-digit output.
  - Verification permits a limited adjacent-counter tolerance.
  - Used counter values are recorded, preventing reuse of a successful TOTP value for the same provisioning secret.

- **PASS — Recovery-code functionality and single use**
  - Recovery codes have strict server-side format validation.
  - Recovery-code hashes are compared using a constant-time comparison helper.
  - A matched recovery code is marked consumed and cannot be used again.
  - Recovery-code replacement atomically replaces the old hash records only after new records are prepared.

- **FAIL — Repeated failed identity verification attempts are not rate-limited or locked**
  - `/api/login` allows unlimited invalid date-of-birth/account-ending submissions.
  - This does not satisfy the requirement to rate-limit and lock out repeated failed verification/authentication attempts.

- **FAIL — Repeated failed recovery-code verification attempts are not rate-limited or locked**
  - `/api/mfa/recovery/verify` performs PBKDF2 comparisons for every supplied code but has no failed-attempt counter, rate limit, or lockout.
  - An authenticated attacker with a session can make unlimited recovery-code guesses and impose repeated expensive KDF work.

- **FAIL — The TOTP lockout can be bypassed through reprovisioning**
  - `/api/mfa/verify` locks after five failures, but `/api/mfa/provision` resets `failedAttempts` and `lockedUntil` to zero.
  - A locked user can call `/api/mfa/provision`, receive a new setup secret, and thereby clear the lockout immediately.
  - This defeats the intended repeated-failure lockout control.

- **PASS — Input validation and output encoding**
  - Login input, OTP input, and recovery-code input are validated server-side.
  - The client escapes dynamically displayed server values before inserting them into HTML.
  - Redirect parameters are not accepted or used, so no open redirect is present.

- **PASS — Session lifecycle basics**
  - New authenticated sessions receive newly generated session identifiers.
  - Idle and absolute session expiry are enforced.
  - Logout deletes the server-side session and expires the cookie.

- **PASS — Generic server error behavior**
  - The Bun server `error()` handler returns a generic response without stack traces.
  - Startup errors do not disclose certificate paths, stack traces, secrets, or internal state.

## FAILING_ITEMS

- `/api/login` has no rate limiting or lockout for repeated failed identity-verification attempts.
- `/api/mfa/recovery/verify` has no rate limiting or lockout for repeated failed recovery-code attempts.
- The TOTP lockout is bypassable because `/api/mfa/provision` resets `failedAttempts` and `lockedUntil`, including while the account is currently locked.

## NEW_TASKS

1. Add a server-side failed-attempt rate limiter and temporary lockout for `/api/login`, keyed using a privacy-preserving server-side key such as a normalized account-proof value plus client IP, with generic failure responses and expiry cleanup.

2. Add failed-attempt tracking, rate limiting, and temporary lockout to `/api/mfa/recovery/verify`; increment failures for invalid-format and non-matching recovery codes, reset the counter after a successful recovery-code use, and return a clear `429` response while locked.

3. Make TOTP lockout non-bypassable by preserving `lockedUntil` across provisioning attempts and rejecting `/api/mfa/provision` while the MFA state is locked; do not reset TOTP failure/lock state merely because a new provisioning secret is requested.

## DECISION

FAIL