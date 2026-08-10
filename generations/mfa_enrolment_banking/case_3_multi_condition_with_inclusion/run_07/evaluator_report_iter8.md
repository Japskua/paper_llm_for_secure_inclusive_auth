## SUMMARY

The artifact is a valid single-file Bun HTTPS SPA with no external assets or build tooling. It implements a mostly functional MFA enrolment flow with identity-code simulation, TOTP setup, QR rendering, TOTP verification, recovery-code generation, TLS cookies, CSRF checks, security headers, and encrypted/hashed MFA material. However, it does not fully meet the security and inclusivity requirements: failed sign-in and identity verification attempts are not rate-limited, production code generation uses `Math.random`, recovery codes are logged to the browser console even outside academic mode, required copy/hide/reveal and autofill support are incomplete, and several client paths incorrectly show progress/success without checking API failures.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and SPA**
  - The HTML, CSS, browser JavaScript, and Bun server are all contained in `app.ts`.
  - It uses `Bun.serve`, has no framework, build step, bundler, compiler, or external network dependency.

- **PASS — HTTPS/TLS server configuration**
  - Bun is configured with `certs/cert.pem` and `certs/key.pem`.
  - The server binds to `localhost:3000`.

- **PASS — Mobile-responsive, readable UI foundation**
  - The layout has a constrained mobile-width shell, adequate spacing, large controls, plain-language instructions, icons, and no moving/flashing UI.
  - The UI uses a legible sans-serif stack and does not use all-caps or italic instructional text.

- **FAIL — Required copy-to-clipboard support**
  - The authenticator secret is displayed, but there is no copy button or clipboard action.
  - Recovery codes are displayed, but there is no copy/download action.
  - This does not satisfy the requirement to offer copy-to-clipboard options to reduce manual transcription.

- **FAIL — Required reveal/hide and re-request support**
  - The displayed authenticator secret and recovery codes cannot be hidden or revealed.
  - Identity codes can effectively be requested again by pressing the existing send button, and TOTP test codes can be refreshed, but the UI does not provide consistent reveal/hide controls for sensitive values.

- **FAIL — Browser autofill and password-manager support**
  - The sign-in email and password fields do not specify appropriate `autocomplete` values such as `username` and `current-password`.
  - OTP inputs do not use `autocomplete="one-time-code"` or suitable input hints such as `inputmode="numeric"`.

- **PASS — Identity-code verification flow is simulated and functional**
  - In academic mode, `/api/identity/send` returns deterministic code `123456`.
  - The browser logs the simulated identity code.
  - Verification checks a six-digit format, expiration, and single use before advancing to authenticator setup.

- **PASS — Authenticator provisioning and manual-secret option**
  - The app provides a QR code and displays the underlying TOTP secret.
  - It also provides a six-digit code entry step, allowing manual verification without requiring QR scanning.
  - Academic mode returns a deterministic/current TOTP in the browser console.

- **PASS — TOTP verification is time-bound and single-use**
  - TOTP verification accepts only six-digit entries.
  - It validates a narrow time window and tracks already-used counters to prevent replay.
  - TOTP failures are rate-limited and lock after five failed attempts.

- **FAIL — Failed identity verification attempts are not rate-limited or locked**
  - `account.identity` includes `failures` and `locked` fields, but `/api/identity/verify` never increments failures or checks lockout.
  - An attacker can submit unlimited incorrect identity codes during the code lifetime.

- **FAIL — Failed sign-in attempts are not rate-limited or locked**
  - `account.signin` has `failures` and `locked` properties, but `/api/signin` never uses them.
  - This violates the requirement to rate-limit and lock out repeated failed verification/authentication attempts.

- **FAIL — Production identity-code generation is not cryptographically secure**
  - Outside academic mode, identity codes are generated with:
    ```ts
    Math.floor(Math.random()*1e6)
    ```
  - `Math.random()` is not a cryptographically secure RNG and does not meet the code entropy requirement.

- **PASS — OTP shared secret and recovery codes are protected at rest**
  - The TOTP secret is AES-GCM encrypted before storage in `account.secret`.
  - Recovery codes are SHA-256 hashed before storage in `account.backups`.
  - Non-academic TOTP secrets and recovery codes use `crypto.getRandomValues` through `random()` / `token()`.

- **PASS — Session security baseline**
  - Session IDs and CSRF tokens use cryptographically secure randomness.
  - The session cookie is `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Sessions have idle and absolute expiry checks.
  - Sign-in creates a new session identifier and logout invalidates the server-side session.

- **PASS — MFA state-changing endpoints use CSRF protection**
  - Protected endpoints require a valid authenticated session and matching `X-CSRF-Token`.
  - State-changing API calls use the CSRF header.
  - The anti-CSRF cookie is intentionally readable by JavaScript, while the session cookie remains `HttpOnly`.

- **PASS — No exposed user identifiers / basic access-control model**
  - MFA API routes do not accept a user ID or account ID from the client.
  - MFA state changes require an authenticated session, preventing straightforward IDOR manipulation in this single-account mock.

- **PASS — Security headers and CORS posture**
  - The app returns CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Cache-Control: no-store`.
  - It does not emit permissive CORS headers.
  - Requests with a supplied foreign `Origin` are rejected by protected endpoints.

- **FAIL — Sensitive recovery codes are logged in production mode**
  - `recovery()` always executes:
    ```js
    console.log("ACADEMIC SIMULATION recovery codes:", d.codes);
    ```
  - This occurs regardless of `academicMode`. In non-academic operation it logs real generated recovery codes to the browser console.
  - This violates the requirement not to expose backup codes in logs. Academic-only mock logging must be explicitly gated.

- **FAIL — Client-side API failure handling can falsely show success**
  - The recovery completion handler ignores the response from `/api/recovery/finish` and always renders “MFA is ready.”
  - If the session expires, CSRF fails, or the API returns an error, the UI still claims MFA was enabled.
  - Similar unchecked error handling exists for identity send and authenticator setup/confirmation paths.

- **FAIL — Authenticated-flow restoration is incomplete**
  - On page reload, the bootstrap logic restores only the `confirm` stage:
    ```js
    d.ok&&d.stage==="confirm" ? ...confirm() : signin()
    ```
  - Active sessions at `identity`, `setup`, `recovery`, or `complete` are incorrectly returned to the sign-in screen.
  - This breaks predictable continuation of an in-progress enrolment session.

- **PASS — Injection and output-encoding baseline**
  - The server validates OTP shape before verification.
  - The app does not construct HTML from untrusted input; UI text is inserted with `textContent`.
  - There are no database queries or redirects, so SQL injection and open redirects are not present in this implementation.

## FAILING_ITEMS

- No copy-to-clipboard controls for authenticator secrets or recovery codes.
- No hide/reveal controls for displayed secrets and recovery codes.
- Missing `autocomplete`, `inputmode`, and related browser autofill/password-manager hints on sign-in and OTP fields.
- Identity-code verification has unlimited failed attempts and no lockout.
- Sign-in has unlimited failed attempts and no lockout despite declared guard state.
- Production identity OTP generation uses `Math.random()` instead of cryptographically secure randomness.
- Recovery codes are always sent to `console.log`, including in non-academic mode.
- The recovery completion UI always claims success even when `/api/recovery/finish` fails.
- Other client API calls do not consistently render returned errors before proceeding.
- Reloading an authenticated session at most enrolment stages sends the user back to sign-in instead of restoring the current stage.

## NEW_TASKS

1. Add clipboard controls for the authenticator setup secret and recovery-code list, with clear success/error feedback and no dependency on external libraries.

2. Add accessible hide/reveal controls for the displayed authenticator secret and recovery codes; default sensitive recovery values to a protected presentation state where appropriate.

3. Add autofill and mobile-entry metadata:
   - Email: `autocomplete="username"` and appropriate `inputmode`.
   - Password: `autocomplete="current-password"`.
   - OTP fields: `autocomplete="one-time-code"`, `inputmode="numeric"`, `maxlength="6"`, and numeric pattern validation.

4. Implement failed-attempt counting and 15-minute lockout for `/api/identity/verify`, using the existing `failures` and `locked` fields; return the existing clear, non-blaming lockout message.

5. Implement failed-attempt counting and lockout for `/api/signin`, including reset of the failure counter after successful authentication and consistent generic failure responses.

6. Replace non-academic identity-code generation based on `Math.random()` with a `crypto.getRandomValues`-based six-digit generator.

7. Gate all browser console output containing actual codes behind academic mode. In particular, only log `d.codes` in `recovery()` when `mode` is true; production recovery codes must never be logged.

8. Make every client action check its API response before changing screens. Show returned errors in the current screen and render the completion screen only after `/api/recovery/finish` returns `{ ok: true }`.

9. Extend the `/api/me` bootstrap routing to restore all valid authenticated stages (`identity`, `setup`, `confirm`, `recovery`, and `complete`) rather than always returning non-confirm stages to sign-in.

## DECISION

FAIL