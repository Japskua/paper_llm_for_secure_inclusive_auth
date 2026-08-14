## SUMMARY

The artifact meets the MFA enrolment, security, mobile UX, single-file, and Bun/TLS requirements. It is a self-contained `app.ts` using Bun’s native TypeScript execution, serves a responsive SPA over TLS, implements working simulated identity/TOTP/recovery-code verification, and applies session authorization, CSRF controls, secure headers, encryption/hashing, validation, rate limiting, and generic production errors. Browser-console/UI exposure of simulated OTPs and recovery codes is intentional and required by the testing deliverable; no sensitive values are server-logged.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no frameworks, bundlers, or external assets.**  
  The entire server, HTML, CSS, and browser JavaScript are contained in `app.ts`. It uses `Bun.serve` directly and does not depend on external resources or compilation steps.

- **PASS — TLS/HTTPS is configured with the supplied certificate paths.**  
  Bun is configured with `certs/cert.pem` and `certs/key.pem`. The server only exposes a TLS listener, and requests explicitly marked as forwarded HTTP are rejected.

- **PASS — Mobile-responsive and legible SPA UI.**  
  The HTML includes a mobile viewport meta tag, constrained mobile shell, accessible labels, touch-sized controls, responsive recovery-code layout, and a small-screen media query.

- **PASS — Semantic and usable enrolment flow.**  
  The flow supports sign-in, simulated identity confirmation, authenticator setup, authenticator verification, recovery-code display, recovery-code regeneration, recovery-code redemption, settings view, and logout.

- **PASS — Simulated delivery and verification work deterministically for evaluation.**  
  Identity codes, provisioning details, current TOTP values, and recovery codes are returned to the browser UI and logged with `console.log`, as required for testing. The supplied values can be submitted through the UI to complete the flow.

- **PASS — Manual authenticator setup is supported.**  
  The setup screen provides both a manual Base32 secret and an `otpauth://` provisioning URI. Users can enter the setup key in an authenticator and manually submit the generated six-digit TOTP.

- **PASS — Server-side MFA authorization prevents IDOR.**  
  MFA endpoints derive the account only from the `bank_session` cookie via `requireSession`; no user/account identifier from request data or URL is trusted. MFA endpoints require an identity-verified authenticated session.

- **PASS — State-changing endpoints have CSRF protection.**  
  Sign-in is origin-restricted. Authenticated state-changing endpoints require both a trusted `Origin` and a session-bound `X-CSRF-Token`; tokens are cryptographically random and validated using a constant-time comparison.

- **PASS — Session cookies use required secure attributes.**  
  The session cookie is configured with `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and an expiration matching the absolute session lifetime.

- **PASS — Sessions are securely managed.**  
  Successful sign-in creates a fresh random session identifier and CSRF token. Sessions enforce idle and absolute expirations, and logout deletes the server-side session and clears the cookie.

- **PASS — Required security response headers are present.**  
  Responses include CSP with nonces and `frame-ancestors 'none'`, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store`.

- **PASS — CORS is restricted to trusted origins.**  
  Only explicit trusted localhost HTTPS origins receive CORS permission and credentials support. Preflight requests from untrusted or absent origins are rejected.

- **PASS — Sensitive values are not persisted in browser storage or JavaScript-readable cookies.**  
  The application does not use `localStorage`, `sessionStorage`, or non-HttpOnly cookies for session IDs, OTP secrets, OTPs, or recovery codes.

- **PASS — OTP secrets and recovery codes are protected at rest.**  
  OTP secrets are stored encrypted with AES-GCM using a runtime-generated AES key. Recovery codes are generated with cryptographic randomness and stored only as SHA-256 hashes.

- **PASS — OTPs and identity codes are time-bound and single-use.**  
  Identity codes expire after five minutes and are marked consumed after successful use. Enrollment TOTPs use 30-second periods, and a successful TOTP period is recorded to prevent reuse.

- **PASS — Rate limiting and lockout are implemented.**  
  Sign-in, identity-code verification, authenticator verification, and recovery-code redemption each enforce failed-attempt counters and ten-minute lockouts.

- **PASS — Server-side input validation is implemented.**  
  Email, phone, OTP, password length, session ID format, CSRF token format, and recovery-code format are validated before use. No SQL/database layer exists, so parameterized-query requirements are not applicable to this in-memory implementation.

- **PASS — Output handling avoids reflected and DOM XSS.**  
  Dynamic server-provided provisioning data and recovery codes are rendered through `textContent` or DOM node creation rather than interpolated into HTML. Server errors are generic fixed strings.

- **PASS — Generic errors and anti-enumeration behavior are used.**  
  Invalid credentials, unknown accounts, and lockouts return the same generic authentication failure. Top-level server exceptions return generic errors without stack traces.

- **PASS — No open redirect functionality exists.**  
  The application does not accept or process redirect URLs. Navigation is handled through fixed client-side flow functions.

- **PASS — Internal application navigation functions correctly.**  
  The SPA’s transitions between sign-in, identity verification, enrollment, confirmation, settings, regeneration, recovery redemption, and logout are all wired to functioning handlers and API routes.

- **PASS — Comments map implementation areas to the security requirements.**  
  The artifact includes comments identifying controls for requirements 1 through 5, including authorization, CSRF, encryption, TOTP, headers, CORS, and error handling.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. No changes required.

## DECISION

PASS