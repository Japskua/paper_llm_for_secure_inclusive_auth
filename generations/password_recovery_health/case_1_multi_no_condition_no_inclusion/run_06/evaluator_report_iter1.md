## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a well-structured password-reset, password-update, login, MFA, and privacy-acceptance flow. It correctly uses TLS certificates, security headers, CSP nonces, server-side session state, CSRF validation, bcrypt password hashing, escaped browser output, reset-token expiry, and generic account-recovery responses. However, it does not fully meet the security acceptance requirements because important throttling controls are only session-scoped and can be trivially bypassed, reset-token single-use is vulnerable to concurrent confirmation requests, and login password handling truncates attacker-controlled input before verification.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and browser SPA implementation**
  - The HTML, CSS, browser-side vanilla JavaScript, server routes, TLS setup, and state logic are contained in `app.ts`.
  - No frameworks, bundlers, compilation steps, external assets, or external network calls are used.

- **PASS — Bun TLS server uses the required certificate paths**
  - The server reads `certs/cert.pem` and `certs/key.pem` and passes them to `Bun.serve({ tls: ... })`.
  - The app is served by an HTTPS-only Bun server.

- **PASS — HTTPS/security headers are substantially configured**
  - Responses include HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store`.
  - CSP uses a newly generated nonce for the inline style and script tags.
  - The application has no external script, font, image, redirect, or API dependencies.

- **PASS — CSRF controls exist on state-changing endpoints**
  - State-changing API endpoints require `X-CSRF-Token`.
  - The submitted token must match both the server session’s CSRF value and the CSRF cookie.
  - CSRF tokens are cryptographically random and generated per session.
  - Session cookies are configured with `Secure`, `HttpOnly`, `SameSite=Strict`, and a path restriction.

- **PASS — Sensitive actions enforce session-based authorization**
  - Reset confirmation requires a reset token associated with the current session.
  - MFA verification requires `mfaPending`.
  - Privacy acceptance requires `authenticated`.
  - There are no user/account IDs accepted in request paths or bodies for protected actions, reducing IDOR exposure.

- **PASS — XSS/injection protections are appropriately implemented**
  - Dynamic browser content is inserted with `textContent`, not `innerHTML`.
  - Inputs are type-checked, size-limited, and validated server-side.
  - No `eval`, inline event handlers, dynamically injected untrusted scripts, or untrusted URLs are present.
  - API responses do not reflect user-supplied values into HTML.

- **PASS — Reset-token generation, hashing, expiry, and normal single-use behavior**
  - Reset tokens are generated with cryptographically secure random bytes.
  - Only SHA-256 token hashes are stored server-side.
  - Tokens expire after 15 minutes.
  - Sequential reset confirmation attempts are blocked after `record.used` is set.

- **FAIL — Reset tokens are not safely single-use under concurrent requests**
  - In `/api/reset/confirm`, `record.used` is set only **after** awaiting `Bun.password.hash(...)`.
  - Two concurrent confirmation requests using the same valid verified token can both pass `resetRecordFor(...)` before either request marks the record used.
  - This violates the requirement that password reset tokens be single-use.

- **FAIL — Automated guessing and authentication throttling can be bypassed**
  - Reset-request, reset-verification, login-failure, and MFA-failure limits are stored only on the current session.
  - An attacker can repeatedly obtain a new session cookie and evade all of these limits.
  - Login attempts are especially affected because the password hash is global account state while `loginFailures` and `loginLockedUntil` are per-session.
  - This does not adequately satisfy the requirement that brute-force attempts be throttled or blocked.

- **FAIL — Login verification truncates supplied passwords before authentication**
  - `/api/login` uses:
    ```ts
    const password = typeof body.password === "string" ? body.password.slice(0, 128) : "";
    ```
  - If an account password is exactly 128 characters, a longer supplied password with the same first 128 characters will authenticate successfully.
  - The server must reject overlong password submissions rather than silently truncate them before bcrypt verification.

- **PASS — Password policy and password hashing are implemented**
  - Reset passwords require at least 12 characters, uppercase, lowercase, a digit, and a symbol.
  - Passwords are hashed using Bun bcrypt with cost 10.
  - Plaintext passwords are not stored.

- **PASS — MFA flow is implemented for the deterministic training simulation**
  - MFA is required after either successful reset confirmation or successful password login.
  - MFA failures are limited and lock the current session temporarily.
  - The deterministic mock code is returned only as part of the explicitly required simulation and logged in the browser.

- **PASS — Password-reset flow gives clear feedback and supports manual code entry**
  - The generated reset code is returned to the UI for the training simulation.
  - It is logged through browser-side `console.log`.
  - The user can manually paste a code into the verification form.
  - A fragment route of the form `#verify?token=...` populates the verification code field.

- **PASS — Privacy and anti-phishing guidance is present**
  - The UI explicitly tells users not to share passwords or security codes via email or phone.
  - The UI states that the service uses fixed internal pages and does not redirect to other websites.
  - No outgoing URLs or redirect parameters are implemented.

- **PASS — Errors do not expose stack traces or debug data**
  - The top-level server handler returns a generic error response on unexpected exceptions.
  - There are no directory-listing or static-file routes.

## FAILING_ITEMS

- Reset-token consumption is race-prone: `/api/reset/confirm` checks that a token is unused, awaits password hashing, and only then marks the token as used. Concurrent requests can reuse one token.

- Brute-force and rate-limit protections are bound only to browser sessions. Attackers can bypass reset, verification, login, and MFA limits by creating new sessions.

- Login password handling truncates values longer than 128 characters before bcrypt verification, allowing an overlong supplied value to authenticate when its first 128 characters equal the actual 128-character password.

## NEW_TASKS

1. Make reset-token consumption atomic in `/api/reset/confirm`.
   - After validating the token and verified-token state, immediately mark the reset record as consumed/reserved before awaiting bcrypt hashing.
   - Ensure any concurrent use of the same token is rejected.
   - If password hashing fails, handle the failure safely without restoring a token in a way that permits concurrent reuse.

2. Replace session-only throttling with server-side shared throttling.
   - Add shared rate-limit/lockout records for password login attempts and MFA attempts.
   - Apply reset-request and reset-verification limits using a server-controlled key that cannot be reset merely by receiving a new browser session.
   - Use an appropriate local-safe key such as a normalized contact digest for reset requests and a global/account-level login lockout in this single-account simulation.
   - Retain session-level controls as defense in depth if desired.

3. Reject overlong login passwords instead of truncating them.
   - In `/api/login`, validate that the supplied password is a string with length from 1 through 128.
   - Return the same generic invalid-credentials response for invalid length to avoid creating an account-information oracle.
   - Pass the original validated password unchanged to `Bun.password.verify`.

## DECISION

**FAIL**