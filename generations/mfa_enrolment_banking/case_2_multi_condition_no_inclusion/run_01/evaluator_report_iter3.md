## SUMMARY

The artifact is a valid single-file Bun HTTPS MFA enrolment SPA. It provides a mobile-responsive UI, identity verification, TOTP enrolment with manual secret/URI entry, recovery-code generation and use, secure session handling, CSRF protection, input validation, encryption/hashing of MFA material, and browser-console test logging. The implementation is internally consistent and does not contain evident compile-time or runtime faults under Bun 1.3.0 with the required TLS certificate files present.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no build tooling or external assets.**  
  The full server, HTML, CSS, and vanilla browser JavaScript are contained in `app.ts`. It uses Bun directly and imports only Bun/runtime-native capabilities and Node-compatible `fs`.

- **PASS — HTTPS/TLS is enforced using the supplied certificate paths.**  
  `Bun.serve` is configured with `tls: { cert, key }`, loading `certs/cert.pem` and `certs/key.pem`. The server advertises and serves HTTPS only.

- **PASS — Mobile-responsive and legible SPA UI.**  
  The UI has a constrained mobile layout, appropriately sized controls, responsive width rules, a narrow-viewport media query, semantic forms/labels, focus styles, and accessible live regions.

- **PASS — Sign-in and identity-verification flow works.**  
  The sign-in route validates email and phone, creates a short-lived pre-auth session, generates a six-digit code with a cryptographic RNG, and returns the test-mode mock code to the client. The browser logs the mock code and can use it to complete verification.

- **PASS — Authenticator provisioning works and supports manual setup.**  
  `/api/mfa/enrol` generates a cryptographically random TOTP secret and returns both a manual Base32 setup key and an `otpauth://` provisioning URI. The UI clearly displays the secret for manual authenticator setup and accepts a manually entered six-digit TOTP code.

- **PASS — TOTP verification is functional, time-bound, and replay-protected during enrolment.**  
  The code implements standard HMAC-SHA-1 TOTP processing with a 30-second time step and a ±1-step validation window. Successfully used enrolment counters are retained in `usedSetupCounters`, preventing replay of a successfully used setup OTP.

- **PASS — Recovery-code generation, display, regeneration, and one-time use work.**  
  Eight recovery codes are generated with cryptographically secure randomness, returned to the UI, and logged in the browser in test mode. Codes are HMAC-protected at rest, regenerated only for the authenticated account, and marked used after successful recovery verification.

- **PASS — MFA settings authorization prevents IDOR.**  
  MFA records are selected exclusively from `session.accountId`; no API accepts a user/account identifier from the client. All `/api/*` MFA routes require an authenticated session before viewing or modifying MFA state.

- **PASS — CSRF protection is applied to authenticated state-changing MFA operations.**  
  Sessions contain a cryptographically random CSRF token. Protected POST requests require `X-CSRF-Token`, and the session cookies use `SameSite=Strict`. Enrolment, MFA confirmation, recovery-code use/regeneration, and logout are CSRF-protected.

- **PASS — Session security requirements are substantially met.**  
  Session identifiers are cryptographically random, stored only in `HttpOnly; Secure; SameSite=Strict` cookies, regenerated when identity verification succeeds, checked for idle and absolute expiration, and deleted on logout. No session token is placed in browser storage or URLs.

- **PASS — Secure response headers and clickjacking protections are present.**  
  Responses include CSP with per-response nonces, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store`.

- **PASS — CORS is restricted to trusted local TLS origins.**  
  Trusted origins are explicitly allow-listed for `localhost`, `127.0.0.1`, and `::1` on the configured HTTPS port. Requests with an untrusted `Origin` are rejected.

- **PASS — Secrets are not persistently exposed in browser storage, cookies, URLs, server logs, or errors.**  
  OTP secrets are encrypted with AES-GCM in server memory. Recovery codes are HMAC-protected. Setup secrets are delivered only in an authenticated API response and rendered with `textContent`; they are not put in URL parameters, cookies, local/session storage, or server logs. Test-mode recovery-code logging occurs in the browser as expressly required for testing.

- **PASS — Input validation and output-safety controls are present.**  
  Server-side validation exists for emails, phone numbers, six-digit OTPs, and recovery-code format. Dynamic UI output uses `textContent` and DOM node creation rather than unsafe user-controlled HTML interpolation. The only `innerHTML` assignments are fixed static strings.

- **PASS — Failed verification attempts are rate-limited/locked out.**  
  Identity verification and MFA/recovery verification track failure counts and apply a ten-minute lockout after five failed attempts.

- **PASS — Enumeration and verbose error exposure are mitigated.**  
  Sign-in failures use a generic response, comparable minimum response timing, and do not disclose whether an email or phone is registered. The top-level request handler suppresses stack traces and returns generic errors.

- **PASS — Internal UI navigation functions.**  
  The SPA view transitions for sign-in, identity verification, MFA setup, recovery-code confirmation, recovery-code use, cancellation, return-to-home, and logout are all wired to functional event handlers.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. No changes required.

## DECISION

PASS