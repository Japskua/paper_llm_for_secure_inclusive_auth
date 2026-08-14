## SUMMARY

The artifact is a single-file Bun TLS server and vanilla-JS mobile SPA with strong coverage of the MFA enrolment, TOTP, recovery-code, authorization, CSRF, encryption, validation, and security-header requirements. However, it has a session-handling defect: loading or refreshing the SPA while an authenticated session exists causes `/api/bootstrap` to overwrite that authenticated session cookie with a new pre-authentication session. This logs the user out on refresh and breaks authenticated state restoration. Therefore, the artifact cannot be accepted as fully functional.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application / no build tooling**
  - The complete server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses Bun APIs and Node-compatible built-ins only; there are no frameworks, external assets, bundlers, or network calls.

- **PASS — TLS and secure transport**
  - Bun is configured with `tls: { cert, key }` using `certs/cert.pem` and `certs/key.pem`.
  - HSTS is applied on server responses.
  - Requests explicitly marked with `x-forwarded-proto: http` are rejected.

- **PASS — Mobile-responsive SPA and enrolment UX**
  - The UI has a mobile-first viewport, constrained content width, responsive CSS, semantic forms, labels, accessible live regions, and readable recovery-code layout.
  - The flow covers sign-in, identity confirmation, TOTP setup, OTP verification, MFA confirmation, recovery-code display, regeneration, verification, and logout.

- **PASS — Simulated OTP and recovery-code delivery**
  - The TOTP manual secret, simulated current TOTP value, and recovery codes are returned to the UI.
  - These simulated values are logged through browser-side `console.log` and are visibly mirrored in the UI log area.
  - Manual TOTP-secret provisioning is supported without requiring a QR code.

- **PASS — Broken access control / CSRF protections**
  - MFA endpoints derive ownership from an HttpOnly server-side session and do not accept user/account identifiers.
  - Client-supplied `accountId` and `userId` fields are rejected.
  - State-changing authenticated endpoints validate an anti-CSRF token.
  - Session cookies use `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **PASS — Security misconfiguration protections**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, restrictive referrer policy, permissions policy, and no-store caching are applied.
  - CORS is restricted to localhost TLS origins.
  - Top-level request handling returns generic errors rather than stack traces.
  - Server-side code does not log session IDs, OTP secrets, OTP values, or recovery codes.

- **PASS — Cryptographic protections**
  - TOTP secrets and recovery-code records are encrypted at rest with AES-256-GCM.
  - TOTP secrets, sessions, CSRF tokens, and recovery codes use cryptographically secure random values.
  - TOTP verification uses HMAC-based standard TOTP generation and replay prevention through the accepted counter.
  - Recovery codes are consumed after successful use.

- **PASS — Input validation, output safety, and redirect handling**
  - JSON bodies are size-limited and validated.
  - Email, phone, OTP, and recovery-code formats are validated server-side.
  - The UI uses `textContent`, `createTextNode`, and DOM construction for secret/code rendering rather than injecting user-controlled values as HTML.
  - Redirect values are restricted to an internal allow-list.

- **PASS — OTP/recovery verification security**
  - TOTP values are time-bound, accept only a narrow skew window, and cannot be replayed after acceptance.
  - Recovery codes expire and are removed after use.
  - Failed TOTP and recovery-code checks are rate-limited with an account-level lockout after repeated failures.
  - Authentication and identity failure messages are generic and do not enumerate accounts.

- **FAIL — Secure session continuity and authenticated SPA restoration**
  - `/api/bootstrap` only attempts `preauthSession(req)`. If the browser already has a valid authenticated session, `preauthSession` returns `undefined`, then `newPreauthSession()` is called.
  - The response sets a new `mfa_session` cookie, overwriting the valid authenticated cookie with a pre-auth session cookie.
  - Immediately afterward, the client calls `/api/mfa/status`, which rejects the new pre-auth session with `401`; the client falls back to the sign-in screen.
  - As a result, refreshing the page always destroys the active authenticated session from the browser’s perspective, even if it has not reached its idle or absolute timeout.

## FAILING_ITEMS

- A valid authenticated session is overwritten by a newly created pre-authentication session whenever the SPA loads and calls `GET /api/bootstrap`.
  - This prevents normal authenticated session restoration after a page refresh.
  - It makes the configured idle and absolute session lifetimes ineffective for normal SPA reload behavior.
  - It breaks expected access to the already-enrolled MFA confirmation/recovery-code state after refresh.

## NEW_TASKS

1. Update `GET /api/bootstrap` so it recognizes and preserves a valid authenticated session before creating or reusing a pre-auth session. Return that authenticated session’s CSRF token without replacing its cookie; only create/set a pre-auth session cookie when no valid authenticated session exists.

## DECISION

**FAIL**