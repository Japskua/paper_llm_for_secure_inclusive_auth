## SUMMARY

The artifact is a single-file Bun application with an inline mobile SPA, TLS configuration, responsive accessibility-focused UI, simulated OTP/TOTP flows, secure cookie attributes, CSP/HSTS headers, CSRF checks on authenticated state-changing routes, encrypted TOTP-secret storage, hashed recovery codes, and verification lockouts for email and authenticator codes. However, it does not securely establish that the requester is the account owner at sign-in, and recovery-code verification is not rate-limited or locked after repeated failures. These are material failures against the security requirements.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun SPA with no framework, bundler, external assets, or compilation step**
  - The supplied implementation is entirely in `app.ts`, uses `Bun.serve`, embeds HTML/CSS/client JavaScript, and does not import frameworks or external assets.

- **PASS — TLS is configured for Bun using the specified certificate paths**
  - `Bun.serve` uses `tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") }`.

- **PASS — Responsive, mobile-oriented and dyslexia-conscious UI**
  - The layout has a constrained mobile shell, mobile viewport metadata, large controls, generous line/letter spacing, plain language, visible step progress, short hints, no animation, and clear primary actions.

- **PASS — MFA enrolment journey functions in the browser**
  - The flow supports sign-in, email identity code delivery/verification, TOTP provisioning, QR rendering, copying the provisioning URI/secret, TOTP verification, recovery-code generation/copying/printing, completion, and logout.
  - Client-side test values are logged with `console.log`, as explicitly required for mocks.

- **PASS — Manual alternative to QR provisioning is available**
  - The provisioning screen provides a “Show manual secret instead” option and a copy button.
  - The authenticator code can be entered manually using the six-digit OTP input.

- **PASS — Email identity codes and TOTP codes are time-bound, single-use, and protected by lockout**
  - Identity challenges expire after ten minutes, become used after successful verification, and lock after five failures.
  - TOTP validation accepts a limited time window, records accepted TOTP time steps to prevent reuse, and locks after five failures.

- **PASS — Secure session-cookie configuration and session expiry are implemented**
  - Session cookies use `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Sessions have idle and absolute expiry checks.
  - A new random session is created at sign-in, and logout invalidates the server-side session and clears the cookie.

- **PASS — Protected MFA routes enforce session ownership and CSRF tokens**
  - Protected endpoints call `authenticated(req)`.
  - State-changing protected endpoints require the per-session `X-CSRF-Token`.
  - Supplied `userId` values are rejected unless they equal `session.userId`, preventing direct manipulated-ID access for routes that accept such a field.

- **FAIL — Sign-in does not actually authenticate or bind the session to the account owner**
  - `/api/auth/signin` accepts any syntactically valid email address but always creates a session for `USER.id` (`acct_marcus_01`).
  - For example, an attacker can submit `attacker@example.test`, receive a session for Marcus, receive the mock identity code in the response, and access Marcus’s MFA enrolment endpoints.
  - This violates the requirement that only the authenticated account owner may view or modify their MFA settings and that session ownership be verified server-side.

- **PASS — Strong generation and protected at-rest handling of MFA material**
  - Random values are generated with `crypto.getRandomValues`.
  - TOTP secrets are AES-GCM encrypted before being retained in the server-side session record.
  - Recovery codes are stored as SHA-256 hashes with a server-side pepper rather than stored in plaintext.

- **FAIL — Recovery-code verification is not rate-limited or locked after failed attempts**
  - `/api/mfa/recovery/verify` rejects invalid recovery codes but does not increment failure counters, delay requests, or lock the session/account after repeated failed attempts.
  - This fails the requirement to rate-limit and lock out repeated failed verification attempts.

- **PASS — Secure HTTP response headers and restrictive CORS are substantially implemented**
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store`.
  - CORS is restricted to an explicit allow-list of local HTTPS origins.

- **PASS — Input validation and output encoding are present**
  - Server-side validation exists for email addresses, six-digit OTPs, and recovery-code format.
  - Client-rendered dynamic text is escaped through `esc()` before interpolation into HTML.
  - User-generated values are not inserted through unsafe HTML paths.

- **PASS — Generic server failures do not expose stack traces**
  - The top-level request handler catches errors and returns a generic error message.

## FAILING_ITEMS

- **Unauthenticated sign-in can create a session for Marcus regardless of the submitted email address.**
  - `createSession()` always assigns `userId: USER.id`.
  - `/api/auth/signin` validates only email syntax and does not validate that the submitted identity belongs to the account being enrolled.
  - The mock email verification code is returned to the caller, so it does not compensate for the missing account-owner authentication in this implementation.

- **Recovery-code verification has unlimited failed attempts.**
  - The session has lockout fields for identity and TOTP verification but no equivalent fields for recovery-code verification.
  - An attacker with a valid authenticated session can submit unlimited recovery-code guesses to `/api/mfa/recovery/verify`.

## NEW_TASKS

1. **Bind sign-in to a verified account identity.**
   - Change `/api/auth/signin` so it does not create a Marcus session for arbitrary valid email addresses.
   - In this mock application, validate the supplied email against the mock account identity and issue a generic non-enumerating response for unknown accounts.
   - Ensure the identity-verification challenge is tied to the intended account before creating or authorizing an MFA session.

2. **Add recovery-code failed-attempt rate limiting and lockout.**
   - Add recovery verification attempt-count and lock-expiry fields to `Session`.
   - Increment the counter for invalid, previously used, or non-matching recovery codes.
   - Lock recovery-code verification after `MAX_FAILURES` for `LOCK_MS`, return a clear user-facing message, and reset the counter after successful recovery-code verification as appropriate.

## DECISION

FAIL