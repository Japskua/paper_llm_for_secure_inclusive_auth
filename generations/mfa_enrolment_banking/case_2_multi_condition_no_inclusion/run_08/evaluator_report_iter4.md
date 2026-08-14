## SUMMARY

The artifact is a single-file Bun/TLS SPA with a largely complete MFA enrolment flow. It implements secure cookies, CSP/HSTS/clickjacking protections, CSRF checks, server-side account binding, encrypted TOTP secrets, hashed recovery codes, validation, and lockout behavior. However, it has authentication timing/account-lockout weaknesses, exposes sensitive mock values indefinitely in an on-page log, and permits concurrent recovery-code regeneration requests to return code sets that may no longer be valid. Therefore it cannot be accepted as fully compliant.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, bundler, compiler, or external assets.**  
  The complete server, HTML, CSS, and browser-side vanilla JavaScript are contained in `app.ts`. It uses `Bun.serve` directly and does not import dependencies or call external services.

- **PASS — TLS/HTTPS server configuration.**  
  Bun is configured with `certs/cert.pem` and `certs/key.pem`, and the startup URL is HTTPS. HTTP is not served by this listener.

- **PASS — Responsive mobile SPA UI and enrolment journey.**  
  The UI has mobile viewport support, responsive CSS, semantic forms/labels, accessible live status output, and a complete flow for sign-in, identity verification, authenticator provisioning, TOTP verification, recovery-code display, settings, regeneration, recovery-code testing, and logout.

- **PASS — Identity verification mock works and is server-enforced.**  
  The identity code is cryptographically generated, expires after five minutes, is marked used after successful validation, and is shown to the browser for the academic mock flow. Identity-verification failures are rate-limited and locked after repeated failures.

- **PASS — Authenticator provisioning and manual secret support.**  
  The server generates a Base32 TOTP secret with `crypto.getRandomValues`, encrypts it with AES-GCM, and returns it to the browser only for the mock setup flow. The user can enter the TOTP manually and can optionally submit the provisioning secret manually.

- **PASS — TOTP verification and MFA activation are server-side.**  
  The server decrypts the pending secret and verifies the submitted TOTP using HMAC-SHA-1 TOTP logic. Pending provisioning is time-limited, reserved before asynchronous work, and consumed on a successful MFA enablement.

- **PASS — Backup recovery codes are generated securely and stored as digests.**  
  Recovery codes are generated using cryptographically secure random bytes and only SHA-256 digests with a server-side pepper are retained in account state. Used recovery codes are marked consumed server-side.

- **FAIL — Recovery-code regeneration is not concurrency-safe.**  
  Two simultaneous `POST /api/mfa/recovery/regenerate` requests can both generate different code sets and both return `200`. Since `setCodes()` performs asynchronous hashing before assigning `a.backupCodes`, one response can contain a set of recovery codes that has already been overwritten by the other request and is therefore unusable.

- **PASS — Server-side authorization and IDOR resistance.**  
  MFA state is accessed through the authenticated session’s `accountId`; endpoints do not accept user/account identifiers from the browser. MFA settings, provisioning, recovery verification, and recovery regeneration use the account associated with the server-side session.

- **PASS — CSRF protections on state-changing operations.**  
  Sign-in, identity actions, provisioning, MFA activation, recovery-code verification/regeneration, and logout require a CSRF token and a trusted same-origin HTTPS `Origin`. Session cookies use `SameSite=Strict`.

- **PASS — Secure response headers and CORS restrictions.**  
  Responses include CSP with a nonce, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, and no-store cache controls. CORS is only reflected for the same trusted HTTPS origin.

- **PASS — Secure session cookie configuration and session lifecycle.**  
  The `__Host-mfa_session` cookie has `Path=/`, `HttpOnly`, `Secure`, and `SameSite=Strict`. Sessions have idle and absolute timeouts, are rotated after successful sign-in, and are invalidated on logout.

- **FAIL — Sign-in behavior permits account enumeration through response timing.**  
  In `/api/signin`, password hashing is only performed if the supplied email equals `marcus@example.test`:
  ```ts
  same(x.email.toLowerCase(),a.email) && same(await hash(x.password),a.passwordHash)
  ```
  Requests with a valid-format unknown email avoid the asynchronous hash operation, while requests for the known email perform it. This creates a measurable timing difference that violates the requirement to avoid user enumeration in response timing.

- **FAIL — Invalid sign-in attempts for arbitrary email addresses lock the Marcus account.**  
  The sign-in endpoint always retrieves `accounts.get("acct_marcus")` before evaluating the submitted email. Any invalid request, including an arbitrary or malformed email address, increments `marcus`’s `loginFailures` and can lock that account. This creates an avoidable account-lockout denial-of-service condition and does not correctly associate failed attempts with the submitted principal.

- **FAIL — Sensitive values remain displayed in an on-page log after the user leaves the setup/recovery screen.**  
  The browser `log()` helper appends provisioning secrets, current TOTP values, and recovery codes to the persistent visible `<pre id="logs">`. After clicking “I have saved these codes,” recovery codes remain visible in the page’s log section while the user is on MFA settings. This conflicts with the UX assertion that recovery codes are “shown once” and unnecessarily exposes sensitive values in a persistent UI log. The requirement specifically requires browser `console.log` for test mocks; it does not require a persistent, visible page transcript.

- **PASS — Server-side input validation and output handling.**  
  Email, phone, TOTP, recovery-code, manual-secret, password-length, request-body type, and request-size inputs are validated. User-controlled values are not interpolated into HTML via `innerHTML`; dynamically displayed recovery codes use `textContent`.

- **PASS — Generic error responses and no server-side secret logging.**  
  The server returns generic failure messages and uses a top-level generic error handler. It does not log OTPs, TOTP secrets, recovery codes, or session IDs on the server.

## FAILING_ITEMS

- The sign-in endpoint has a timing side channel: known-email attempts perform an async password hash while unknown-email attempts do not.
- The sign-in endpoint applies failed-login lockout to `acct_marcus` for every invalid email/password submission, allowing arbitrary requests to lock the demo account.
- Recovery-code regeneration can run concurrently and return a recovery-code set that is immediately overwritten and invalid.
- The persistent visible `Logs` panel retains MFA provisioning secrets, TOTP values, and recovery codes after their intended one-time display, including after the recovery-code confirmation step.

## NEW_TASKS

1. Update `/api/signin` so every syntactically valid credential attempt performs equivalent password-hash work before returning, regardless of whether the submitted email matches an account; ensure failure timing does not disclose account existence.

2. Change failed-login tracking so arbitrary email submissions cannot increment and lock the Marcus account. Track failures for the matched account only, while applying a separate generic/session/IP-oriented throttle for unknown principals if needed.

3. Serialize or atomically reserve recovery-code regeneration per account/session so only one regeneration operation can succeed at a time and every returned code set remains the currently active set.

4. Remove the persistent in-page sensitive-value transcript, or clear/redact provisioning secrets, OTPs, and recovery codes when progressing away from their relevant step. Keep the required mock output in the browser developer console via `console.log`, and show recovery codes only on the dedicated recovery-code screen.

## DECISION

**FAIL**