## SUMMARY

The artifact is a well-structured single-file Bun HTTPS application with strong baseline controls: TLS, secure cookie attributes, CSP/HSTS/clickjacking headers, CSRF validation, encrypted TOTP-secret storage, hashed recovery codes, input validation, generic errors, and no external assets. However, the MFA enrolment UI is currently broken after sign-in because the client requests `/api/status` with `GET` while the server only accepts `POST`, and sign-in does not update client authentication state. There are also material authorization and rate-limiting gaps. Therefore, the artifact cannot be accepted.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application, no framework/build tooling/external assets**
  - The complete server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses `Bun.serve` directly and references only local TLS certificate files.
  - No external network calls, CDN resources, frameworks, bundlers, or browser storage are used.

- **PASS — HTTPS/TLS is configured and HTTP is rejected**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - Requests whose URL protocol is not `https:` receive an `HTTPS required` response.
  - HSTS is set in the common security-header function.

- **FAIL — Core sign-in → identity-verification navigation works**
  - The client calls `fetch("/api/status", ...)` with the default `GET` method.
  - `handleApi()` rejects every non-`POST` request before reaching the `/api/status` route, returning HTTP 405.
  - `status()` does not check the failed response and consequently leaves `state.auth` false.
  - After successful sign-in, `signin()` changes the hash to `#/identity`, but does not set `state.auth = true`. `identity()` immediately redirects the user back to `#/signin`.
  - This prevents the normal enrolment flow from proceeding.

- **FAIL — MFA endpoints are restricted to the authenticated account owner**
  - Although protected endpoints derive the account from the session rather than a client-supplied user ID, `/api/signin` always creates a session for the hard-coded account ID `"marcus-demo-account"`.
  - Any caller supplying any syntactically valid email receives a session that can modify the same shared Marcus account after completing the deterministic identity step.
  - This violates the requirement that only the authenticated account owner may access or modify their own MFA settings.

- **PASS — IDOR resistance for protected endpoint request bodies**
  - State-changing request validation rejects bodies containing `userId` or `accountId`.
  - Protected handlers derive account identity from the server-side opaque session rather than client-controlled identifiers.

- **PASS — CSRF protection for state-changing actions**
  - State-changing requests require a session-bound 64-hex-character CSRF token.
  - Sign-in, identity verification, provisioning, MFA verification, recovery-code use, recovery-code regeneration, and logout all pass through `stateChangingValid()`.

- **PASS — Session cookie security and session lifecycle controls**
  - Session cookies use `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Sessions have idle and absolute expiration checks.
  - Session IDs are rotated on sign-in.
  - Sessions are deleted on logout and expired cookies are returned when authentication is unavailable.

- **PASS — Required security headers and restrictive CORS are present**
  - The application sets CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Cache-Control: no-store`.
  - The HTML response uses a per-response CSP nonce for inline style and script.
  - CORS is only enabled for local HTTPS development origins.

- **PASS — TOTP secret and recovery-code storage use cryptographic protection**
  - TOTP secrets are generated with `crypto.getRandomValues()` and stored using AES-GCM encryption.
  - Recovery codes are generated with cryptographically secure random bytes and only protected hashes are retained server-side.
  - OTP secrets, session tokens, and recovery-code records are not persisted in browser storage.

- **PASS — TOTP verification is time-bound and prevents reuse**
  - TOTP verification checks the current time step with a limited ±1 time-step window.
  - Used TOTP time steps are retained and rejected, preventing reuse.
  - Identity verification codes have expiration and a single-use flag.

- **FAIL — Repeated failed verification attempts are rate-limited for all verification methods**
  - Identity-code and TOTP failures have `AttemptState` locking.
  - `/api/mfa/recovery/use` has no failure counter, rate limit, or lockout.
  - An attacker with an authenticated session can make unlimited recovery-code guesses, contrary to the explicit repeated-failure rate-limit/lockout requirement.

- **PASS — Server-side input validation and safe DOM rendering**
  - Email, OTP, and recovery-code formats are validated server-side.
  - JSON request body size is bounded.
  - User-facing dynamic values are inserted using `textContent`, not unsafe HTML sinks.
  - No SQL/database queries are used, so parameterized-query concerns do not apply to this in-memory demo.

- **PASS — Redirects are constrained to internal allow-listed routes**
  - The submitted redirect value is restricted to known internal hash routes.
  - The UI uses only local hash navigation.

- **PASS — Deterministic test values are shown in the browser console/UI**
  - The identity test code, simulated current TOTP, and recovery codes are delivered to the UI and sent through browser `console.log`.
  - No secrets are logged by the server.
  - This matches the explicit testing-deliverable exception requiring browser-console mock values.

- **PASS — Mobile-oriented, semantic SPA presentation**
  - The page has a mobile viewport meta tag, constrained mobile-width shell, legible typography, form labels, semantic headings/forms, focus styles, and responsive layout.
  - Manual TOTP-secret entry is supported alongside the displayed provisioning URI.

## FAILING_ITEMS

- The browser requests `/api/status` with `GET`, but the API permits only `POST`. This yields HTTP 405 and prevents session state from being loaded.
- Successful sign-in does not set `state.auth` to `true`; therefore navigation to `#/identity` redirects immediately back to sign-in.
- All valid-email sign-ins are assigned to the same hard-coded `"marcus-demo-account"` account. This allows unrelated users to access and alter a shared MFA configuration and violates account-owner authorization.
- Recovery-code verification lacks failure counting, rate limiting, and lockout despite the explicit requirement to rate-limit repeated failed verification attempts.

## NEW_TASKS

1. Fix client session-state loading and post-sign-in state transition:
   - Change `status()` to use the supported `POST /api/status` request path, or explicitly add a secure `GET /api/status` server handler.
   - Check failed status responses rather than silently treating them as anonymous status.
   - On successful `/api/signin`, set `state.auth = true`, reset `state.identity`/`state.mfa` appropriately, and then navigate to `#/identity`.

2. Remove the shared hard-coded account assignment:
   - Derive a stable opaque account ID from the authenticated demo identity/email rather than always using `"marcus-demo-account"`.
   - Ensure the account selected by protected MFA endpoints is exclusively the account associated with that session.
   - Preserve generic responses so the change does not introduce account enumeration.

3. Add recovery-code failed-attempt protection:
   - Add recovery-code `AttemptState` to `Account`.
   - Reject requests during recovery lockout.
   - Increment failures for malformed, unknown, and already-used recovery codes.
   - Apply the existing lockout duration after the configured maximum failures and reset failures after a successful recovery-code use.

## DECISION

**FAIL**