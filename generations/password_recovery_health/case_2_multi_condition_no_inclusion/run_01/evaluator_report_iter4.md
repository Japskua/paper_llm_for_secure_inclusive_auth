## SUMMARY

The artifact is a well-structured single-file Bun application with functional recovery, reset, login, MFA, privacy acknowledgement, CSRF validation, TLS configuration, secure cookies, CSP/security headers, input validation, rate limiting, and browser-console mock delivery logging. However, it does not fully meet the password-storage requirement because the initial account password is embedded in plaintext in the server source before being hashed at runtime.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework/build tooling**
  - The entire server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses `Bun.serve` directly and does not require bundlers, external assets, or external network calls.

- **PASS — HTTPS/TLS configuration**
  - The Bun server is configured with `certs/cert.pem` and `certs/key.pem`.
  - Requests whose URL protocol is not HTTPS are rejected.
  - HSTS is configured.

- **PASS — Security headers and production-safe error handling**
  - CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, cache prevention, and COOP headers are present.
  - Errors return generic JSON responses and do not expose stack traces or debug information.

- **PASS — CSRF protection for sensitive actions**
  - A random CSRF token is generated per session.
  - State-changing API routes require the `X-CSRF-Token` header and validate it with constant-time comparison.
  - The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, and uses a `__Host-` prefix.

- **PASS — Session-bound access control and sensitive-route protection**
  - Recovery codes are tied to a server-side session and account ID.
  - Password-reset authorization is temporary and requires successful recovery-code verification.
  - Privacy acceptance requires authenticated MFA-completed state.
  - Confirmation view requires both authentication and accepted privacy conditions.

- **PASS — Password reset token security**
  - Reset tokens are random (`randomBytes`), sufficiently long, session-bound, short-lived, and single-use.
  - The token is invalidated after use and cannot be used to reset a password without the associated session.
  - A manual recovery-code entry screen is available in addition to the generated recovery link.

- **PASS — Recovery flow and internal navigation**
  - Recovery request, simulated reset-link navigation, manual code verification, password reset, MFA, login, privacy acceptance, and confirmation screens are implemented.
  - Hash navigation and internal links function correctly.
  - Direct access to reset/password/privacy-related routes is checked server-side where relevant.

- **PASS — XSS and injection handling**
  - Browser input is sent as JSON and server input validation is applied.
  - User-controlled values are not inserted into HTML via string interpolation.
  - The client uses `textContent` for log messages and URL recovery codes are assigned to an input value rather than rendered as HTML.
  - The browser script is loaded from a same-origin external endpoint and constrained by CSP.

- **PASS — Account enumeration mitigation**
  - Recovery requests return the same generic message for unknown, invalid, and non-eligible identifiers.
  - No account identifier or account ID is returned in API responses or rendered in the UI.
  - The evaluation-only simulated delivery exception does not return the account identity.

- **PASS — Throttling and MFA**
  - Recovery requests, recovery verification, password-reset attempts, login attempts, and MFA attempts are rate-limited.
  - Login and post-reset flows require MFA verification before establishing authenticated access.
  - Browser-console and visible log panel delivery simulation is implemented.

- **PASS — Strong password-policy enforcement**
  - Passwords must be 12–128 characters and contain uppercase, lowercase, numeric, and symbol characters.
  - Password confirmation is checked both client-side and server-side.

- **FAIL — Passwords are never stored in plaintext**
  - The account map ultimately stores a bcrypt hash, but the initial password is present as a plaintext source literal:
    ```ts
    Bun.password.hash("Initial!Secure2025", { algorithm: "bcrypt" })
    ```
  - Embedding an account password in application source violates the requirement that passwords must be hashed and never stored in plaintext. Anyone with source or deployed bundle access can recover the initial credential.

- **PASS — Safe-authentication and anti-phishing guidance**
  - The UI tells users not to share passwords or verification codes and advises use of the local portal only.
  - There are no outgoing URLs, redirect parameters, or external fetches that could create SSRF or open-redirect behavior.

## FAILING_ITEMS

- The initial evaluation account password, `Initial!Secure2025`, is embedded in plaintext in `app.ts`.
  - Although it is bcrypt-hashed during initialization, the plaintext credential remains exposed in the application source.
  - This conflicts with the explicit requirement that passwords must never be stored in plaintext.

## NEW_TASKS

1. Replace the runtime hashing of the plaintext initial password with a pre-generated bcrypt hash string stored directly in `evaluationMockAccount.passwordHash`.
2. Remove the plaintext literal `Initial!Secure2025` from `app.ts`.
3. Verify that login still works using the corresponding known evaluation fixture credential in the test process without exposing that credential through source, API responses, UI content, or browser logs.

## DECISION

FAIL