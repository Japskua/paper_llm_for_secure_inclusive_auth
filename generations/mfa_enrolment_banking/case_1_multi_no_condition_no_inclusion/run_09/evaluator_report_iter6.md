## SUMMARY

The artifact is a well-structured single-file Bun HTTPS SPA with responsive mobile UI, server-side sessions, CSRF checks, secure headers, MFA enrolment flows, TOTP verification, recovery codes, and working internal hash routes. However, it does not fully meet the security requirements because it uses a hard-coded authenticator secret rather than a cryptographically generated secret, and its identity-challenge response leaks whether an account is allow-listed, enabling account enumeration. The mock OTP behavior is also not deterministic as required.

## FUNCTIONAL_CHECK

- **Single-file `app.ts`, Bun server, no frameworks/build tools/external assets: PASS**
  - The server, HTML, CSS, and browser JavaScript are all contained in `app.ts`.
  - It uses Bun’s built-in server and TLS configuration without bundlers, frameworks, external JavaScript, or external network calls.

- **HTTPS/TLS using supplied certificates: PASS**
  - `readFileSync("certs/cert.pem")` and `readFileSync("certs/key.pem")` are used with `Bun.serve({ tls: { cert, key } })`.
  - Requests whose URL protocol is not HTTPS are rejected.

- **Mobile-responsive SPA UI and semantic usability: PASS**
  - The viewport meta tag is present.
  - The layout has a narrow `max-width`, mobile padding adjustments, legible controls, responsive recovery-code columns, labels, forms, headings, and accessible input types.
  - Internal hash links such as `#/setup`, `#/verify`, `#/backup`, `#/confirmed`, and `#/settings` are implemented and routed.

- **Simulated identity verification, authenticator provisioning, TOTP verification, and recovery-code flow: PASS**
  - The browser receives simulated values and sends them to `console.log`.
  - The user can manually enter the provisioning secret in an authenticator application.
  - TOTP verification works against the generated current/adjacent 30-second windows.
  - Recovery codes are displayed after initial setup and regeneration, and can be verified once.

- **Server-side authorization and IDOR prevention: PASS**
  - MFA records are accessed only through the authenticated server session’s `accountId`.
  - No request accepts a user/account identifier for MFA settings or MFA changes.
  - Sessions are server-side and account ownership is checked through the session on each protected endpoint.

- **CSRF protection for state-changing authenticated requests: PASS**
  - Authenticated state-changing endpoints require both a valid `X-CSRF-Token` and trusted `Origin`.
  - Session cookies are `SameSite=Strict`.
  - Logout, provisioning, OTP verification, recovery-code regeneration, and recovery-code use are protected.

- **Security headers and restrictive CORS: PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, permissions policy, and no-store caching are configured.
  - CORS only permits explicitly trusted localhost HTTPS origins.
  - Generic error responses are used rather than stack traces.

- **Secure cookies and session lifecycle: PASS**
  - Session and identity-challenge cookies use `HttpOnly`, `Secure`, `SameSite=Strict`, and `Path=/`.
  - Session IDs are rotated after successful authentication.
  - Idle and absolute session expiry are enforced server-side.
  - Logout invalidates the server-side session and expires the cookie.

- **Secure storage and generation of OTP shared secrets and recovery codes: FAIL**
  - Recovery codes are securely generated using `crypto.getRandomValues`, salted, PBKDF2-hashed, and marked single-use.
  - The OTP shared secret is encrypted with AES-GCM before storage.
  - However, the OTP shared secret is hard-coded as:
    ```ts
    const manualSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    ```
    This means every provisioning operation uses the same known secret and does not meet the requirement to generate OTP secrets with a cryptographically secure RNG.

- **Single-use, time-bound verification, rate limiting, and lockout: PASS**
  - Identity challenges expire and are deleted after successful use.
  - TOTP verification accepts only a bounded time window and blocks replay of the accepted counter.
  - Recovery codes are invalidated on successful use.
  - Identity, OTP, and recovery-code failures are rate-limited and locked for ten minutes after five failures.

- **Input validation, output handling, and redirect safety: PASS**
  - Email, phone, OTP, recovery-code, and redirect inputs are validated server-side.
  - Redirects are constrained to an allow-list of internal route names.
  - Dynamic browser content is mostly assigned through `textContent`; server-provided sensitive values are not interpolated into HTML strings.
  - No SQL/database layer exists, so parameterized-query requirements are not applicable to this artifact.

- **Avoiding account/user enumeration: FAIL**
  - `/api/identity-challenge` returns `identityCode` only if the submitted identity belongs to the allow-listed account:
    ```ts
    ...(activeCode ? { identityCode: activeCode } : {}),
    ```
  - An attacker can submit candidate identities and determine whether an account exists by checking for the presence of `identityCode` in the response.
  - This violates the requirement to avoid account/user enumeration through messages, response data, and behavioral differences.

- **Deterministic mock values: FAIL**
  - The requirements explicitly call for deterministic mock values.
  - Identity codes are randomly generated using `secureDigits(6)`.
  - The displayed TOTP is dependent on the current wall-clock time.
  - While the values are functional and securely generated, they are not deterministic for repeatable evaluation/testing.

## FAILING_ITEMS

- The authenticator provisioning secret is a public, fixed Base32 value rather than a unique secret generated with a cryptographically secure RNG for each enrolment.
- `/api/identity-challenge` leaks allow-listed account existence by including `identityCode` only for recognized identities.
- Mock challenge and OTP values are not deterministic, despite the explicit testing requirement for deterministic mock values.

## NEW_TASKS

1. Replace the hard-coded `manualSecret` in `/api/mfa/provision` with a newly generated Base32-encoded secret created from cryptographically secure random bytes for every provisioning attempt; continue encrypting it with AES-GCM before storing it.
2. Change `/api/identity-challenge` so recognized and unrecognized valid identities return the same response schema and observable behavior, including a testing-only mock code field if needed; ensure only a challenge bound to an allow-listed account can successfully authenticate.
3. Implement a deterministic, test-mode mock-code strategy that preserves the required security behavior for actual enrolment flows, or document and implement a controlled deterministic test fixture that does not replace the cryptographically random production OTP secret/challenge generation.

## DECISION

FAIL