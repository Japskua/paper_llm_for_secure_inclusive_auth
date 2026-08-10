## SUMMARY

The artifact is a well-structured single-file Bun HTTPS SPA with a functional mobile MFA enrolment flow, server-side session authorization, CSRF validation, encrypted TOTP-secret storage, hashed recovery-code verifiers, secure cookies, response-security headers, and browser-console test fixtures. However, the authenticator OTP fixture is tied permanently to a fixed clock and the pending enrolment has no expiry, so an issued authenticator code can remain valid indefinitely before confirmation. This fails the explicit requirement that OTPs be time-bound.

## FUNCTIONAL_CHECK

- **Single `app.ts` file contains Bun server, HTML, CSS, and vanilla browser JavaScript — PASS**
  - The server, SPA template, CSS, and client-side JavaScript are all contained in the supplied `app.ts`.
  - No framework, bundler, compiler, or external assets are used.

- **Bun serves the app over HTTPS using supplied certificates — PASS**
  - `Bun.serve` uses `certs/cert.pem` and `certs/key.pem` in its TLS configuration.
  - The session cookie is marked `Secure`, which is appropriate for the HTTPS-only server.

- **Mobile-responsive and legible SPA UI — PASS**
  - The template includes a viewport meta tag, constrained mobile-width layout, touch-friendly inputs/buttons, and a narrow-screen media query.
  - The enrolment stages are implemented in-browser without page reloads.

- **Identity verification flow works with browser-visible deterministic mock delivery — PASS**
  - The identity simulation code is returned after sign-in and written via browser-side `console.log`.
  - Identity codes are hashed server-side, expire after five minutes, and are marked used after successful verification.

- **Authenticator provisioning and manual secret/code entry work — PASS**
  - The user can generate a provisioning secret and manually submit the displayed TOTP fixture.
  - Provisioning values are surfaced to the UI and browser console as required for the non-production test flow.

- **Recovery-code generation, display, acknowledgement, regeneration, and verification work — PASS**
  - Eight recovery codes are generated with a CSPRNG.
  - The plaintext codes are only held in the active server session until acknowledgement and are not persisted in browser storage.
  - Persisted recovery-code records use salted PBKDF2 verifiers.
  - Successful recovery-code use removes the matched verifier, enforcing single use.

- **Server-side authorization / IDOR prevention for MFA endpoints — PASS**
  - MFA data is keyed exclusively from `session.userId`; no client-provided user identifier is accepted by MFA endpoints.
  - MFA-changing endpoints require an authenticated, identity-verified server session.

- **CSRF protection for state-changing actions — PASS**
  - State-changing authenticated endpoints require a high-entropy CSRF token tied to the server-side session.
  - Session cookies use `SameSite=Strict`; origin validation rejects untrusted origins.
  - The sign-in endpoint uses strict origin validation and only accepts the fixed internal redirect value `/`.

- **Security headers and CORS restriction — PASS**
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Permissions-Policy`.
  - CORS response headers are only emitted for localhost/loopback HTTPS origins.
  - Responses use `Cache-Control: no-store`.

- **Secure session handling — PASS**
  - Cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Session IDs are CSPRNG-generated.
  - The pre-verification session is deleted and replaced with a new session on successful identity verification.
  - Idle and absolute session expiry are enforced.
  - Logout invalidates the session and expires the cookie.

- **Input validation and output safety — PASS**
  - JSON requests enforce allowed-key lists and expected content type.
  - Email, phone, identity code, OTP, and recovery-code formats are validated server-side.
  - Client-controlled values are not interpolated into HTML; displayed generated values use `textContent`.

- **Verification codes/OTPs are single-use, time-bound, and rate-limited — FAIL**
  - Identity codes are single-use, time-limited, and failure-limited.
  - Recovery codes are single-use and failure-limited.
  - Authenticator confirmation is effectively one-time after success because MFA becomes enabled.
  - However, authenticator OTP validation uses `TEST_TOTP_CLOCK_MS` unconditionally when `TEST_MODE` is enabled:
    ```ts
    const clock = TEST_MODE ? TEST_TOTP_CLOCK_MS : now();
    ```
    The provisioned authenticator secret has no expiry timestamp. Consequently, the displayed authenticator code remains valid indefinitely for an unconfirmed provisioning record rather than only during a 30-second TOTP window or another explicitly bounded test window.

- **No external network calls or browser secret persistence — PASS**
  - Browser fetches are same-origin API calls only.
  - The app does not use `localStorage`, `sessionStorage`, IndexedDB, or client-readable session cookies.

- **Code validity / runtime viability — PASS with the exception noted above**
  - The Bun/TypeScript and browser JavaScript are syntactically coherent.
  - No obvious route mismatch, missing handler, or client/server payload mismatch prevents the primary flow from operating.
  - The OTP expiry flaw is a security/requirements failure rather than a syntax or startup failure.

## FAILING_ITEMS

- **Authenticator OTPs are not time-bound in test mode.**
  - `confirmAuthenticator` validates against a permanent fixed timestamp instead of the current TOTP window.
  - Since `MfaRecord` has no provisioning creation/expiry metadata, a user can generate a secret, wait indefinitely, and still confirm with the originally displayed TOTP fixture.
  - This violates the requirement that verification codes/OTPs be time-bound.

## NEW_TASKS

1. Add a provisioning-expiry field (for example, `provisioningExpiresAt`) to `MfaRecord`, set it when `/api/mfa/provision` creates the secret, and reject authenticator confirmation after the bounded expiry period.

2. Make authenticator-code validation time-bound:
   - In normal mode, calculate TOTP from `now()` and optionally permit only a narrowly defined adjacent time-step skew.
   - In deterministic test mode, retain the fixed fixture clock if needed, but enforce a short server-side fixture/provisioning expiry so the fixture cannot be submitted indefinitely.

3. On expired authenticator provisioning, clear or replace the pending MFA record and require the user to generate a fresh secret and fixture before retrying confirmation.

## DECISION

FAIL