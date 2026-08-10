## SUMMARY

The artifact is a single-file Bun MFA enrolment application with a strong overall structure: TLS setup, secure headers, HttpOnly/Secure/SameSite session cookies, CSRF checks, server-side session ownership checks, encrypted TOTP secrets, hashed recovery codes, validation, and a mobile-oriented accessible UI are largely implemented correctly. However, it does not meet all requirements because the displayed “QR code” is not a real scannable QR code, and MFA verification rate limiting can be bypassed by requesting a replacement identity or provisioning secret. These are functional and security failures.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework/build tooling**
  - The full server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses `Bun.serve` directly and imports only Node’s built-in `fs` API for certificate loading.

- **PASS — TLS is configured using the required certificate paths**
  - The server uses `certs/cert.pem` and `certs/key.pem` in the Bun `tls` configuration.
  - The application is served as HTTPS and includes an attempted HTTP-to-HTTPS redirect.

- **PASS — Mobile-responsive, dyslexia-conscious UI**
  - The page has a mobile viewport meta tag, constrained mobile shell width, readable base font size, generous line/letter spacing, clear spacing, plain language, icons, and no moving/flashing content.
  - Inputs include examples and appropriate autocomplete/inputmode attributes.
  - Primary actions are prominent and the current step is consistently displayed.

- **PASS — Sign-in, identity verification, authenticator setup, OTP verification, recovery-code confirmation, and logout routes are implemented**
  - The client routes through all five enrolment steps and reaches a completion screen.
  - The identity OTP, authenticator TOTP, and recovery-code confirmation have server-side validation.
  - Logout invalidates the server-side session and expires the cookie.

- **PASS — Browser-side simulated delivery logging is implemented**
  - Identity codes, provisioning secrets, test TOTP values, and recovery codes are returned to the UI and written with browser-side `console.log` through `say(...)`.
  - The server does not log the sensitive mock values.

- **FAIL — The offered QR code is not a real QR code**
  - `drawQR()` creates a deterministic “QR-style setup graphic,” not a standards-compliant QR encoding of the `otpauth://` URI.
  - The UI tells the user to “Scan this QR code,” but authenticator apps cannot scan it to provision the account.
  - This fails the requirement to provide a QR-code option when one is offered.

- **PASS — Manual authenticator-secret entry is supported**
  - The manual secret is visible/copyable, can be hidden/shown, and is submitted to `/api/provision/manual`.
  - The server validates its format and confirms it matches the encrypted server-side secret.

- **PASS — Copy-to-clipboard support is provided**
  - Setup secrets and recovery codes have copy buttons with a clear fallback message when the Clipboard API is unavailable.

- **PASS — Server-side authorization and IDOR resistance are substantially implemented**
  - MFA state is associated with a server-side session, not a client-supplied account identifier.
  - Inputs reject `userId`, `accountId`, and `redirect` fields.
  - Protected routes require the authenticated demo account binding and do not accept arbitrary account identifiers.

- **PASS — CSRF protections are implemented for state-changing requests**
  - State-changing API calls require a session-bound CSRF token.
  - Session cookies use `SameSite=Strict`.
  - Client requests include the CSRF value in JSON bodies.

- **PASS — Required security headers and restrictive CORS are substantially implemented**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, permissions policy, and `Cache-Control: no-store` are set.
  - CORS only reflects a predefined localhost origin allow-list.

- **PASS — Sensitive state is not persisted in browser storage**
  - The app does not use `localStorage`, `sessionStorage`, IndexedDB, or non-HttpOnly cookies for session tokens, OTP seeds, or recovery codes.
  - Sensitive UI state exists only in page memory/DOM during the active page session.

- **PASS — OTP secret and recovery codes are protected at rest**
  - TOTP secrets are encrypted using AES-GCM with a random IV.
  - Recovery codes are generated using `crypto.getRandomValues` and protected with PBKDF2-SHA-256 plus per-code random salts.
  - Recovery-code values are not retained server-side after hashing.

- **PASS — Verification values are single-use/time-bound in normal flow**
  - Identity codes have a 15-minute expiry and a used flag.
  - TOTP verification records used time steps to prevent reuse.
  - Recovery-code confirmation checks the code without consuming it, matching the stated UI behavior.

- **FAIL — Identity-code lockout can be bypassed by resending a code**
  - `/api/identity/resend` calls `newIdentityCode(session)`, which replaces the entire `identity` record.
  - This resets `attempts` and `lockedUntil` to zero.
  - After reaching the five-attempt lockout, an attacker can call resend and immediately obtain a fresh attempt counter, bypassing the intended verification lockout.

- **FAIL — Authenticator OTP lockout can be bypassed by generating a new provisioning secret**
  - `/api/provision` resets `session.otpAttempts` and `session.otpLockedUntil` every time it is called.
  - An authenticated user who has completed identity verification can repeatedly request a new provisioning secret, complete `/api/provision/manual`, and receive another five OTP attempts.
  - This defeats the required rate-limit/lockout behavior for repeated failed authenticator verification attempts.

- **FAIL — Failed password authentication has no rate limiting or lockout**
  - `/api/signin` returns a generic message for invalid credentials, which is good for enumeration resistance, but it has no attempt counter, backoff, rate limit, or lockout.
  - Repeated password attempts can be made indefinitely against the demo account endpoint.

- **PASS — Input validation and output encoding are present**
  - Email, password length, identity OTP, authenticator OTP, manual secret, and recovery code formats are validated server-side.
  - Dynamic values inserted into HTML are escaped using `esc(...)`.
  - User-facing error messages are specific and actionable without exposing stack traces.

- **PASS — No obvious TypeScript/JavaScript syntax or direct runtime logic error was found**
  - The route names, client API calls, CSRF lifecycle, cookie lifecycle, encryption calls, TOTP implementation, and DOM IDs are internally consistent.
  - This assessment assumes the required certificate files are present at `certs/cert.pem` and `certs/key.pem` when the server starts.

## FAILING_ITEMS

- The setup canvas is presented as a scannable QR code but is only a pseudo-random QR-like image. It does not encode the provisioning URI and cannot be scanned by an authenticator application.

- Identity verification lockout is ineffective because requesting a replacement identity code resets failed-attempt and lockout state.

- Authenticator OTP verification lockout is ineffective because regenerating the provisioning secret resets failed-attempt and lockout state.

- The sign-in endpoint has no server-side throttling, delay, attempt limit, or lockout for repeated invalid password submissions.

## NEW_TASKS

1. Replace `drawQR()` with a standards-compliant, scannable QR-code encoder that encodes the returned `otpauth://` provisioning URI; alternatively, remove the scan-QR claim and QR UI entirely while retaining manual secret setup and copy support.

2. Preserve identity-verification failure and lockout state across `/api/identity/resend`; add a resend rate limit so requesting a new code cannot bypass the lockout.

3. Preserve authenticator OTP failure and lockout state across provisioning-secret regeneration, or prohibit `/api/provision` regeneration while an OTP lockout is active; ensure a new secret cannot reset the OTP verification attempt budget.

4. Add server-side sign-in throttling/lockout for repeated failed credentials, with generic responses and consistent behavior that does not permit account enumeration.

## DECISION

FAIL