## SUMMARY

The artifact is structurally strong: it is a single `app.ts` Bun HTTPS server with an inline mobile SPA, secure session handling, CSRF checks, security headers, encrypted/HMAC-protected MFA material, OTP/recovery-code verification, and accessible enrolment screens. However, a server-side email-validation regex is incorrectly escaped. As written, the supplied valid demo email (`marcus@example.com`) fails validation, so sign-in cannot succeed and the MFA flow is blocked. This is a functional blocker.

## FUNCTIONAL_CHECK

- **FAIL — User can sign in and start MFA enrolment**
  - The sign-in handler validates email with:
    ```ts
    /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/
    ```
  - In a JavaScript regex literal, `\\s` matches a literal backslash followed by `s`, rather than whitespace, and `\\.` does not correctly represent a literal dot in the intended email pattern.
  - Therefore, `marcus@example.com` does not satisfy the validation expression. The hard-coded demo account cannot sign in, despite using the documented password.

- **FAIL — End-to-end MFA enrolment works**
  - Provisioning, OTP verification, recovery-code saving, reenrolment, and recovery verification are implemented, but they are inaccessible because successful sign-in is required before all protected MFA endpoints can be used.

- **PASS — Mobile, dyslexia-conscious UI**
  - The SPA uses responsive layout rules, generous spacing, readable font sizing, clear step indicators, short instructions, plain language, input examples, no animated/timed content, visible focus styles, help disclosures, copy buttons, and retry/re-request flows.

- **PASS — QR and manual authenticator setup options**
  - The application provides a QR code, visible secret, full setup URI, copy-to-clipboard support, hide/reveal controls, and a manual secret option for authenticator apps.

- **PASS — OTP and recovery-code verification behavior**
  - OTP values are format-validated, TOTP is checked in an allowed time window, used counters are tracked during pending enrolment, recovery codes are one-time-use, and invalid verification attempts are rate-limited with a lockout.

- **PASS — Browser-side mock logging in documented test mode**
  - With `MFA_TEST_MOCK_LOGGING=1`, the provisioning TOTP and deterministic recovery codes are returned to the browser UI path and logged with `console.log`.
  - Production mode avoids logging or exposing test-only OTP values through the Logs panel.

- **PASS — Server-side authorization and IDOR protection**
  - MFA actions derive identity solely from the authenticated HttpOnly session; no client-supplied user ID is accepted by MFA endpoints.
  - The authenticated session resolves the account owner server-side for each protected request.

- **PASS — CSRF protection for state-changing MFA actions**
  - Protected POST actions require both same-origin validation and an `X-CSRF-Token` matching the server-side session token.
  - Session cookies use `SameSite=Strict`.

- **PASS — Secure transport and HTTP security configuration**
  - The server uses Bun TLS with the required certificate paths.
  - HTTPS is enforced in request handling.
  - HSTS, CSP with per-page nonces, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, restrictive CORS behavior, no-store caching, and other defensive headers are present.

- **PASS — Session security**
  - Session IDs are cryptographically generated and rotated on successful authentication.
  - Cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Idle and absolute session expiration are enforced, and logout invalidates the session and expires the cookie.

- **PASS — MFA secret and backup-code protection**
  - OTP secrets are AES-GCM encrypted in server memory.
  - Recovery codes are generated using cryptographically secure randomness outside test mode and stored as keyed HMAC values rather than plaintext.
  - Secrets, codes, and session IDs are not placed in URL query parameters or server logs.

- **PASS — Single-file and zero-compilation compliance**
  - The server, HTML, CSS, and browser JavaScript are all contained in `app.ts`.
  - The implementation uses Bun directly, contains no framework imports, external assets, build tooling, bundler, or compiler requirement.

## FAILING_ITEMS

- **Broken email validation prevents all sign-ins**
  - The regex in `/api/signin` is over-escaped:
    ```ts
    /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/
    ```
  - This rejects ordinary valid email addresses such as the configured account email, `marcus@example.com`.
  - Since MFA endpoints require an authenticated session, this blocks the complete user journey.

## NEW_TASKS

1. Replace the incorrectly escaped email regex in `/api/signin` with a valid JavaScript regex literal:
   ```ts
   /^[^\s@]+@[^\s@]+\.[^\s@]+$/
   ```
2. Verify that signing in with `marcus@example.com` and `BankDemo!42` returns HTTP 200, sets the secure session cookie, returns a CSRF token, and allows the enrolment flow to proceed.

## DECISION

FAIL