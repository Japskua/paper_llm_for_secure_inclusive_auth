## SUMMARY

The artifact is a single-file Bun HTTPS SPA with strong overall security structure: TLS, secure headers, HttpOnly/Secure/SameSite session cookies, CSRF validation, ownership checks, input validation, encrypted authenticator secrets, hashed recovery codes, session rotation, expirations, and rate limits are implemented. However, it does not fully satisfy the deterministic browser-side mock delivery requirement in its normal runnable configuration, and its visible activity-log panel retains sensitive recovery codes after the user leaves the one-time recovery-code screen. These are functional and security/UX failures.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework/build tooling**
  - `app.ts` contains the Bun server, inline HTML, inline CSS, and vanilla browser JavaScript.
  - No external assets, package dependencies, bundlers, or compilation workflow are required.

- **PASS — Bun HTTPS server uses the specified certificate locations**
  - `Bun.serve` is configured with:
    - `certs/cert.pem`
    - `certs/key.pem`
  - The application is served over TLS rather than exposing an HTTP listener.

- **PASS — Mobile-responsive and legible SPA UI**
  - The viewport meta tag is present.
  - The UI uses a constrained mobile-width layout, large form controls, visible focus indicators, semantic headings, labels, error regions, and accessible form inputs.

- **PASS — MFA enrolment flow supports manual authenticator setup**
  - `/api/mfa/provision` returns a manual Base32 secret.
  - The UI displays the secret and permits copying it.
  - `/api/mfa/confirm` requires the manual secret and a TOTP, so manual provisioning is functional.

- **PASS — MFA verification works in explicit evaluation mode**
  - With `MFA_TEST_MODE=true`, the application can use deterministic identity and authenticator values.
  - The fixed identity OTP, authenticator secret, and recovery codes are validated server-side.
  - The TOTP is calculated from the displayed test secret and is accepted by the server.

- **FAIL — Mock OTP delivery is not consistently deterministic or browser-console simulated in the ordinary application configuration**
  - The requirements state that OTP delivery and verification are simulated with deterministic mock values and browser `console.log`.
  - In the default configuration, `TEST_MODE_AVAILABLE` is false unless both:
    - `NODE_ENV !== "production"`, and
    - `MFA_TEST_MODE === "true"`.
  - Without this undocumented runtime configuration, `/api/sign-in` generates a random identity code but does not return it to the UI and does not log it in the browser console. The user cannot complete the identity-verification flow.
  - The UI also does not disclose the required mock sign-in credentials (`marcus@example.test` and `+15550101954`) in evaluation mode, making the expected test flow unnecessarily undiscoverable.

- **FAIL — Sensitive recovery codes remain displayed after the one-time recovery-code screen is closed**
  - The recovery-code page claims: “they will not be shown again after you leave.”
  - In test mode, `logTestRecoveryCodes()` calls `log(...)`, which both:
    - writes the full recovery-code set to `console.log`, and
    - appends the full code set to the persistent visible `<section class="logs">`.
  - After “I have copied or written them down” is selected, `leaveRecoveryCodes()` clears `visibleCodes`, but it does not remove the previously rendered recovery codes from the visible Logs panel.
  - This contradicts the one-time-display UX promise and unnecessarily exposes recovery codes in the page UI.

- **PASS — Broken access control protections**
  - MFA endpoints require a valid session and CSRF token.
  - Client-controlled account/user identifiers are explicitly rejected by `manipulated(...)`.
  - MFA records are looked up only through the server-derived authenticated `session.userId`.
  - Authenticated operations require `session.state === "authenticated"` and the expected server-side `ACCOUNT_ID`.

- **PASS — CSRF protections for state-changing endpoints**
  - State-changing API requests require a matching server-side CSRF token.
  - The session cookie is `SameSite=Strict`.
  - Requests with untrusted `Origin` values are rejected.

- **PASS — Secure HTTP response headers and CORS restrictions**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Permissions-Policy` are present.
  - CORS only reflects configured localhost HTTPS origins and enables credentials only for those trusted origins.

- **PASS — Secure session handling**
  - Cookies use `HttpOnly`, `Secure`, `SameSite=Strict`, and the valid `__Host-` cookie prefix form.
  - Sessions have idle and absolute expiry.
  - Sessions rotate on transition to identity verification and again upon authentication.
  - Logout removes the server session and clears the cookie.

- **PASS — Secret storage and generation**
  - Authenticator secrets are generated with Web Crypto RNG and encrypted with AES-GCM.
  - Recovery codes are generated with Web Crypto RNG and stored only as salted SHA-256 digests.
  - The client does not use `localStorage`, `sessionStorage`, or script-readable cookies for MFA secrets or sessions.

- **PASS — Input validation and output encoding**
  - Email, phone, OTP, authenticator secret, and recovery code values are allow-list validated server-side.
  - Dynamic values inserted into HTML are passed through `escapeHTML`.
  - No SQL/database layer is present, so there are no unparameterized database queries.

- **PASS — Verification expiry, single-use behavior, rate limits, and lockouts**
  - Identity codes expire and are consumed after successful verification.
  - Recovery codes are marked used after successful verification.
  - Identity, authenticator-enrolment, and recovery-code verification attempts are rate-limited and locked after repeated failures.
  - Enrolment drafts expire and cannot be reused after successful confirmation.

- **PASS — Generic error handling and no server-side sensitive logging**
  - Error responses are generic and do not reveal stack traces.
  - The server does not log OTPs, secrets, recovery codes, or tokens.
  - The identified exposure issue is in the browser-visible Logs UI during test mode, not server logging.

## FAILING_ITEMS

- **The default flow is not testable or completable without external environment configuration.**
  - Identity codes are random and unavailable to the browser unless `MFA_TEST_MODE=true` is supplied and the test checkbox is enabled.
  - This conflicts with the requirement for deterministic browser-side mocked OTP delivery and working verification.
  - The hardcoded test credentials are not presented in the evaluation UI.

- **The visible Logs panel persists full recovery codes after the user leaves the recovery-code screen.**
  - `logTestRecoveryCodes()` places recovery codes in the persistent page DOM.
  - `leaveRecoveryCodes()` only clears the in-memory code array; it does not remove the already-rendered sensitive log entry.
  - This violates the UI statement that recovery codes “will not be shown again after you leave.”

- **The evaluation-mode authenticator setup secret is not logged to the browser console.**
  - The requirements state that mocks are to be available through browser `console.log`.
  - The test identity OTP, TOTP, and recovery codes are logged, but the deterministic setup secret is only displayed in the page and is not logged.

## NEW_TASKS

1. Make the deterministic non-production evaluation flow reachable without an undocumented environment prerequisite, while preserving a production-safe mode. In evaluation mode, disclose the mock sign-in credentials in the UI and ensure the identity delivery code is returned to the browser and emitted through browser `console.log`.

2. Change sensitive test-value logging so identity OTPs, authenticator setup secrets, TOTP values, and recovery codes are written to the browser console only, not appended to the persistent visible Logs panel.

3. Ensure that leaving the recovery-code page removes all recovery-code text from the rendered UI and that the “will not be shown again after you leave” statement is true.

4. In evaluation mode, emit the deterministic authenticator setup secret to browser `console.log` when provisioning is created, alongside the existing deterministic OTP and recovery-code test disclosures.

## DECISION

FAIL