## SUMMARY

The artifact is a single-file Bun application with inline HTML, CSS, and vanilla browser JavaScript. It provides a responsive MFA enrolment flow, simulated identity and authenticator verification, backup codes, HTTPS/TLS setup, CSRF protection, secure headers, server-side ownership checks, encrypted TOTP secrets, hashed recovery codes, and browser-console simulation logging. However, the sign-in rate limit is bound only to a pre-authentication session and can be bypassed by obtaining a new anonymous session, so repeated failed login attempts are not effectively rate-limited or locked out. This fails the authentication-failure security requirement.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun implementation with no build tooling or external assets**
  - The complete server, HTML template, CSS, and browser-side JavaScript are contained in `app.ts`.
  - It uses Bun’s `serve()` directly and does not import frameworks, bundlers, CDNs, or other external assets.

- **PASS — HTTPS/TLS is configured**
  - The Bun server is configured with `certs/cert.pem` and `certs/key.pem`.
  - Requests whose parsed URL protocol is not `https:` are rejected.
  - HSTS is sent on responses.

- **PASS — Responsive, mobile-oriented, dyslexia-aware UX**
  - The layout has a constrained mobile width, readable default font size, generous line-height and letter-spacing, labelled inputs, short instructions, icons, clear primary actions, examples of expected code formats, and accessible live regions.
  - The UI does not include moving, flashing, countdown, or auto-updating content.
  - Help is available on every rendered screen, and code retry/re-request paths are present.

- **PASS — Simulated identity verification works**
  - `/api/identity/send` generates a six-digit code, returns it to the browser client, and the browser logs it with `console.log`.
  - `/api/identity/verify` validates format, expiry, single use, CSRF, ownership, and failed-attempt lockout.
  - The UI permits requesting a replacement code.

- **PASS — Authenticator provisioning and TOTP verification work**
  - A TOTP secret is generated using `crypto.getRandomValues`, encrypted with AES-GCM at rest, and used with HMAC-SHA-1 TOTP generation.
  - The server returns the provisioning URI, secret, and mock code only to the authenticated, identity-verified session.
  - The UI offers both a generated QR code and a manually copyable setup key.
  - TOTP verification accepts a limited clock-skew window and prevents reuse of an accepted TOTP counter.

- **PASS — Backup code flow works**
  - Eight recovery codes are generated with cryptographic randomness.
  - Only hashes are stored server-side.
  - Codes can be copied, checked, are single-use, expire, can be regenerated with confirmation, and failed verification attempts are locked out.

- **PASS — Server-side authorization and IDOR protection**
  - MFA endpoints derive the account solely from the server-side session’s `userId`.
  - No endpoint accepts a caller-controlled account/user identifier.
  - MFA endpoints requiring an account use `owner()` or `verified()` checks.

- **PASS — CSRF protection for state-changing requests**
  - State-changing endpoints require the `X-CSRF-Token` header to match the session token.
  - The CSRF token is session-bound and refreshed when a session is created or rotated.
  - Session cookies use `SameSite=Strict`.

- **PASS — Secure session cookie and session lifecycle controls**
  - Cookies have `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and a lifetime.
  - The session identifier is rotated on successful login.
  - Idle and absolute session timeouts are enforced.
  - Logout removes the server-side session and expires the cookie.

- **PASS — Secure headers and browser hardening**
  - CSP includes nonce-based script/style controls, `frame-ancestors 'none'`, `base-uri 'none'`, and same-origin `connect-src`.
  - HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, and no-store cache controls are provided.
  - CORS is not permissively enabled; unexpected `Origin` values are rejected.

- **PASS — Input validation and output handling**
  - Email, OTP, recovery-code, and request-body formats are server-side validated.
  - User-provided values are not interpolated into server-generated HTML.
  - Browser error messages are inserted with `textContent`, avoiding reflected DOM XSS from API messages.

- **FAIL — Repeated failed sign-in attempts are not effectively rate-limited/locked out**
  - Login failures are stored in `Session.loginFailures` and `Session.loginLockedUntil`.
  - An attacker can bypass the lock by starting a new anonymous session via `GET /api/state` and then retrying `/api/login` with the fresh session and CSRF token.
  - Because the failed-login counter is not account-, identifier-, or source-rate-limit scoped, the intended login lockout does not protect the account from repeated password guessing.
  - This does not meet the requirement to rate-limit and lock out repeated authentication failures.

## FAILING_ITEMS

- **Login lockout is session-scoped and bypassable.**
  - `old.loginFailures` and `old.loginLockedUntil` belong to an unauthenticated session.
  - A fresh session can be obtained without authentication, resetting the failure count.
  - Failed login attempts must be tracked independently of an attacker-controlled pre-login session, such as by normalized account identifier plus an appropriate source/IP rate limiter.

## NEW_TASKS

1. Move failed-login counters and lockout expiry from `Session` to a server-side rate-limit record keyed by normalized login identifier, with optional additional source/IP-based throttling.
2. On every failed `/api/login` attempt, increment the identifier-scoped failure record and return a `429` response after the configured threshold regardless of whether the requester presents a new session.
3. On successful login, reset the successful account’s identifier-scoped failed-login record and continue rotating the session identifier as currently implemented.

## DECISION

**FAIL**