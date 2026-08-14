## SUMMARY

The artifact is a valid single-file Bun application implementing a mobile-responsive MFA enrolment flow with simulated identity verification, TOTP provisioning, backup-code issuance, recovery-code verification, and session/logout handling. It uses TLS certificates, secure headers, authenticated server-side MFA endpoints, CSRF protections, cryptographic RNG, encrypted TOTP-secret storage, hashed recovery codes, rate limiting, and generic errors. The client-side routes and API calls are internally constrained and function without external assets, frameworks, build tools, or network calls.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and SPA delivery**
  - All HTML, CSS, browser JavaScript, server logic, TLS configuration, and mock logic are contained in `app.ts`.
  - The app uses `Bun.serve()` directly and requires no bundler, compiler step, framework, external assets, or external API calls.

- **PASS — TLS/HTTPS enforcement**
  - The server loads `certs/cert.pem` and `certs/key.pem` and configures Bun TLS.
  - Requests whose URL protocol is not `https:` are rejected.
  - HSTS is included in response headers.

- **PASS — Mobile-responsive, usable enrolment UI**
  - The page includes a viewport meta tag, narrow responsive content layout, readable form controls, large buttons, and a small-viewport media query.
  - The flow includes sign-in, identity-code verification, authenticator setup, manual secret display, OTP confirmation, backup-code display, confirmation, settings, recovery-code testing, replacement-code generation, and logout.

- **PASS — Identity verification simulation works**
  - The identity challenge endpoint creates an expiring, one-use challenge.
  - Browser-side test-mode output logs the deterministic identity mock code.
  - Sign-in requires a valid challenge cookie, matching normalized identity values, ownership matching, expiry validation, unused status, and correct code before a session is created.

- **PASS — Authenticator provisioning and manual setup work**
  - `/api/mfa/provision` generates a cryptographically random Base32 secret.
  - The secret is returned only for the immediate authorized provisioning response and displayed as a manual setup secret.
  - A provisioning URI/QR code is not offered, so the manual-secret requirement is satisfied directly.
  - The test-mode authenticator OTP is returned to the UI and logged in the browser as required for the simulation.

- **PASS — TOTP verification and enrolment work**
  - The application supports standard time-step TOTP verification using HMAC-based TOTP generation.
  - It accepts a current-window TOTP value with limited clock skew and prevents reuse of the accepted provisioning counter.
  - The provisioning operation expires after five minutes and is consumed after successful verification.
  - Successful authenticator verification enables MFA and issues recovery codes.

- **PASS — Backup recovery code generation and single use**
  - Eight recovery codes are generated with cryptographically secure random bytes.
  - Backup codes are stored as PBKDF2-SHA-256 derived hashes with per-code random salts, rather than plaintext.
  - A successful recovery-code check marks the code as used.
  - Regeneration replaces the entire saved code set, invalidating prior codes.
  - Newly issued backup codes are shown in the UI and logged in the browser, as explicitly required for the mock environment.

- **PASS — Server-side authorization and IDOR resistance**
  - MFA state is derived exclusively from the server-side session’s `accountId`.
  - MFA API endpoints do not accept client-supplied account or user identifiers.
  - A client cannot manipulate a user ID to read or alter another account’s MFA state.
  - State-changing MFA actions require an authenticated session.

- **PASS — CSRF protection**
  - State-changing authenticated endpoints require both a trusted `Origin` and a session-specific CSRF token in `X-CSRF-Token`.
  - Session and pre-authentication challenge cookies use `SameSite=Strict`.
  - The server rejects untrusted origins for POST requests.

- **PASS — Secure session management**
  - Session IDs are cryptographically random and stored server-side.
  - Successful sign-in invalidates any existing session cookie value and creates a new session, mitigating session fixation.
  - Sessions have idle and absolute expiration controls.
  - Logout removes the server-side session and clears the cookie.
  - Session cookies are `HttpOnly`, `Secure`, `SameSite=Strict`, and use the `__Host-` prefix with `Path=/`.

- **PASS — Rate limiting and lockout**
  - Identity verification, authenticator OTP verification, and recovery-code verification track failed attempts.
  - Five failures trigger a ten-minute lockout.
  - Successful verification resets the corresponding failure counters.

- **PASS — Secure headers and CORS restriction**
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store`.
  - CSP uses a per-page nonce for inline style and script content.
  - CORS is restricted to explicit localhost TLS origins and only supplies credentialed CORS headers for those origins.

- **PASS — Input validation, injection prevention, and safe output handling**
  - Email, phone number, OTP, recovery-code, route, and request-body shapes are validated server-side.
  - No SQL or database query surface exists.
  - Client-rendered dynamic text uses `textContent` or static controlled values rather than interpolating untrusted values into HTML.
  - Redirect-like input is constrained to an internal route allow-list and is not used to redirect externally.

- **PASS — No secret persistence in browser storage**
  - The app does not use `localStorage`, `sessionStorage`, IndexedDB, or non-HttpOnly cookies for session values, OTP seeds, or recovery codes.
  - Provisioning secrets and recovery codes are held only in transient JavaScript memory for the current UI flow.

- **PASS — Generic error handling and no server secret logging**
  - Server errors return generic response content and top-level exceptions are caught without stack traces.
  - The server does not log OTP seeds, verification codes, recovery codes, or sessions.
  - Required mock values are logged only by the browser simulation output.

- **PASS — Internal navigation works**
  - Hash routes cover sign-in, setup, OTP verification, backup-code storage, confirmation, and settings.
  - Route guards return unauthenticated users to sign-in and redirect inappropriate post-enrolment states to relevant internal routes.
  - No external links or open redirect behavior are present.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. None.

## DECISION

PASS