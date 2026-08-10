## SUMMARY

The artifact is a well-structured single-file Bun HTTPS SPA with working sign-in, identity confirmation, TOTP verification, recovery-code generation, CSRF/session protections, and a mobile-friendly UI. However, it does not fully meet the requirements because the displayed “QR code” is only decorative and cannot be scanned by an authenticator app, sensitive material is copied into an on-page log, and recovery codes use fast unsalted SHA-256 hashes rather than a strong password-style hashing method. These issues prevent acceptance.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no framework, bundler, external assets, or compilation workflow**
  - The server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses `Bun.serve()` directly and references only local TLS certificate paths.
  - No external network calls, package imports, framework code, or build tooling are present.

- **PASS — HTTPS/TLS configuration**
  - Bun is configured with `certs/cert.pem` and `certs/key.pem`.
  - The session cookie is marked `Secure`, and HSTS is returned.

- **PASS — Mobile-responsive and dyslexia-conscious UI**
  - The layout uses a constrained mobile-friendly main column, adequate input sizes, generous line height/letter spacing, high-contrast focus styles, plain wording, visible step labels, examples, and help text.
  - There are no animations, timers, flashing elements, or auto-updating UI.
  - Inputs use suitable mobile/autofill attributes such as `autocomplete`, `inputmode="numeric"`, and `type="tel"`.

- **PASS — MFA enrolment flow is functional**
  - The sign-in, identity confirmation, provisioning, OTP verification, recovery-code generation, recovery-code confirmation, completion, settings, regeneration, and logout flows are connected through working browser event handlers and server endpoints.
  - The supplied demo credentials can authenticate.
  - Error responses are displayed in the UI with actionable messages.

- **FAIL — A usable authenticator QR code is provided**
  - `drawQR()` creates a pseudo-random “QR-style visual,” not a standards-compliant QR code encoding `provisioningUri`.
  - Scanning the canvas with an authenticator app will not provision the account.
  - The UI explicitly instructs the user to scan the square, so this is a material functional failure.
  - The copyable setup key is a useful manual fallback, but it does not make the non-functional QR option acceptable.

- **PASS — Manual authenticator setup is supported**
  - The server returns a Base32 secret and an `otpauth://` provisioning URI.
  - The secret is displayed, can be hidden/revealed, and can be copied to the clipboard.
  - A user can manually enter the setup key into an authenticator application.

- **PASS — OTP verification works and has core abuse protections**
  - TOTP is generated using HMAC-SHA-1, six digits, and 30-second steps.
  - Verification accepts only a narrow time window.
  - Previously accepted TOTP steps are rejected as used.
  - Failed verification attempts are rate-limited and locked for five minutes after five failures.
  - Reissue requests are rate-limited.

- **PASS — Server-side authorization and IDOR protections**
  - Protected endpoints derive the account exclusively from the authenticated server-side session.
  - State-changing requests reject supplied account/user identifier fields through `noSuppliedAccountId()`.
  - MFA provisioning, verification, recovery-code creation/confirmation, regeneration, and logout require the authenticated session.

- **PASS — CSRF and session protections**
  - State-changing authenticated endpoints require the per-session CSRF token.
  - Requests with foreign origins are rejected for state-changing actions.
  - Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Sessions have idle and absolute expiration, are rotated on sign-in, and are removed on logout.

- **PASS — Secure headers and restricted CORS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Permissions-Policy` are set.
  - CORS is only granted to HTTPS localhost origins.
  - Responses are marked `Cache-Control: no-store`.

- **PASS — Input handling and XSS/open-redirect protections**
  - Email, phone, password, OTP, and recovery-code formats are validated server-side.
  - No database is used, so SQL injection paths and parameterized-query requirements are not applicable to this implementation.
  - Client output uses `textContent` rather than unsafe HTML insertion.
  - Redirect values are constrained to an internal allow-list.

- **FAIL — Sensitive values are not kept out of logs**
  - The browser `log()` function writes values into the visible `#logs` on-page list as well as to `console.log`.
  - The code logs the MFA setup seed using:
    - `log("Browser mock: authenticator setup secret delivered:",secret);`
  - This directly violates the requirement not to expose OTP seeds in logs. An on-page “Logs” panel is also an unnecessary exposure of current OTPs and recovery codes.
  - The requirements explicitly request browser-console mock output for test OTPs and recovery codes, but they do not require the setup seed to be logged and do not require a visible in-page sensitive log.

- **FAIL — Recovery codes are not stored with strong password-style hashing**
  - Recovery codes are stored as unsalted, single-round SHA-256 values:
    - `new Set(await Promise.all(codes.map(sha256)))`
  - SHA-256 is a fast general-purpose hash and is not appropriate for storing recovery codes at rest because it enables efficient offline guessing if storage is exposed.
  - Use a slow, salted password-hashing/KDF approach, such as Argon2id, bcrypt, scrypt, or PBKDF2 with per-code salts and a sufficiently high work factor.

- **PASS — OTP shared secret is encrypted at rest**
  - The TOTP secret is generated with `crypto.getRandomValues()`.
  - It is encrypted with AES-GCM before being stored on the account/provisioning object.
  - The plaintext secret is only decrypted server-side when needed for provisioning or TOTP validation.

## FAILING_ITEMS

- The canvas QR image is not a valid QR code and cannot be scanned by an authenticator app to import the supplied `otpauth://` provisioning URI.
- The browser logs the TOTP setup seed, which violates the prohibition on logging OTP seeds.
- Sensitive OTP and recovery-code values are additionally rendered into the persistent on-page `Logs` list, unnecessarily exposing them in the UI.
- Recovery codes are protected with fast, unsalted SHA-256 hashes rather than a strong salted password-hashing/KDF scheme.

## NEW_TASKS

1. Replace `drawQR()` with a standards-compliant, self-contained QR encoder that encodes the exact `provisioningUri` returned by `/api/mfa/provision`, so the canvas can be scanned successfully by common authenticator apps.

2. Remove logging of the MFA setup secret from browser code, including:
   - `log("Browser mock: authenticator setup secret delivered:", secret);`
   - Any other future seed/provisioning-URI logging.

3. Remove the visible `Logs` card and stop inserting OTPs, recovery codes, or other secrets into the page DOM. Keep only the explicitly required browser-console mock outputs for test OTPs and recovery codes, without logging the TOTP seed.

4. Replace recovery-code SHA-256 storage with a salted, slow KDF/password-hashing representation. Store the salt and derived hash per code, use cryptographically secure generated salts, and update any future recovery-code verification logic to validate against that representation.

## DECISION

FAIL