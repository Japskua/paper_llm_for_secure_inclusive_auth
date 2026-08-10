## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a generally strong security structure: authenticated HttpOnly sessions, CSRF checks, TLS, restrictive headers, server-side MFA ownership checks, input validation, rate limits, encrypted authenticator secrets, hashed recovery codes, and an accessible mobile-focused UI. However, it does not fully meet the requirements because some supplied recovery codes cannot be verified, production-mode authenticator-secret generation can produce invalid Base32 secrets and break setup, and deterministic secrets/codes are enabled by default despite the stated cryptographic requirements.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and client application**
  - All server logic, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses `Bun.serve` directly, without frameworks, bundlers, compilation steps, or external assets.

- **PASS — HTTPS/TLS configuration**
  - The server reads and uses `certs/cert.pem` and `certs/key.pem` in `Bun.serve({ tls: ... })`.
  - Cookies are marked `Secure`, and HSTS is set.

- **PASS — Mobile-responsive and dyslexia-conscious UI**
  - The layout is constrained to a mobile-friendly width, includes a viewport meta tag, uses generous spacing, large controls, visible step progress, plain-language text, examples for inputs, and avoids animation.
  - Inputs use suitable mobile features such as `inputmode="numeric"`, `autocomplete="one-time-code"`, and password-manager-compatible autocomplete attributes.

- **PASS — Identity verification flow works in the default fixture mode**
  - The identity-code request endpoint returns a deterministic mock code, logs it only in the browser console, and verifies it server-side.
  - Identity codes are hashed, time-bound, single-use, and protected by failure rate limiting.

- **PASS — Authenticator enrolment flow is present**
  - The user can request authenticator provisioning details, copy the provisioning URI or secret, reveal the manual secret, view a generated QR canvas, enter an authenticator OTP, and complete enrolment.
  - TOTP verification is server-side and prevents reuse of a successful TOTP time step.

- **FAIL — Authenticator setup works reliably outside fixture mode**
  - When `MFA_TEST_FIXTURES=0`, the generated secret is based on URL-safe Base64 and only replaces `-` and `_`.
  - URL-safe Base64 can still contain characters such as `0`, `1`, `8`, and `9`, which are invalid in the Base32 alphabet accepted by `base32Bytes`.
  - This can cause `totp(secret)` in `/api/authenticator/setup` to throw, returning a generic 500 error and preventing authenticator setup.

- **FAIL — Every issued recovery code can be verified**
  - The deterministic fixture set includes invalid recovery-code characters under the server’s own validation regex.
  - `MARC2-US123` contains `1`, and `GUAR7-DIAN8` contains `I`; both are rejected by `/^[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}$/`.
  - The UI presents these as usable recovery codes, but the recovery-verification endpoint will reject them before checking their hashes.

- **PASS — Recovery codes are protected at rest and single-use**
  - Recovery codes are stored server-side as peppered SHA-256 hashes rather than plaintext.
  - A successfully verified recovery code is removed from the hash set and cannot be used again.
  - Regeneration replaces the previous hash set.

- **FAIL — Cryptographically secure values are used by default**
  - `TEST_FIXTURES` defaults to enabled: `process.env.MFA_TEST_FIXTURES !== "0"`.
  - As a result, the application deploys with a known authenticator secret, known identity code, and known recovery-code set unless an environment variable is explicitly configured.
  - This conflicts with the requirements to generate OTP secrets and backup codes using cryptographically secure randomness. Test fixtures should require explicit opt-in rather than being the default deployment behavior.

- **PASS — Server-side authorization and IDOR prevention**
  - MFA endpoints derive the user solely from the authenticated server-side session.
  - No request accepts a user ID or account ID that could be manipulated to access another account.
  - Endpoints check progression conditions, such as identity verification before setup and MFA enablement before recovery-code actions.

- **PASS — CSRF protection**
  - State-changing endpoints require a CSRF token.
  - Sign-in uses a boot token, and authenticated actions use a per-session CSRF token.
  - Cookies also use `SameSite=Strict`.

- **PASS — Security headers and CORS restrictions**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Permissions-Policy` are set.
  - CORS is only granted for HTTPS localhost loopback origins.

- **PASS — Session security**
  - Sessions use high-entropy random IDs in HttpOnly, Secure, SameSite cookies.
  - Sign-in replaces any existing session ID, preventing fixation.
  - Idle and absolute timeouts are enforced, and logout invalidates the server-side session.

- **PASS — Input validation and output handling**
  - Email, password, OTP, and recovery-code input are server-side validated.
  - Browser-rendered dynamic text is escaped through the `esc()` helper before being assigned to `innerHTML`.
  - There are no database queries, so SQL injection is not applicable to the in-memory mock store.

- **FAIL — One clear primary action is not consistently maintained**
  - After requesting an identity code, both “Request a new check code” and “Check code” remain styled as primary actions on the same screen.
  - This conflicts with the inclusivity requirement to present one clear primary action per screen and minimize simultaneous choices.

## FAILING_ITEMS

- Default deployment uses deterministic test credentials, OTP values, authenticator secret, and recovery codes because `MFA_TEST_FIXTURES` is enabled unless explicitly set to `"0"`.
- Production-mode authenticator-secret generation can generate invalid Base32 strings, causing `/api/authenticator/setup` to fail when it computes the TOTP.
- Two deterministic recovery codes do not satisfy the server’s recovery-code input regex:
  - `MARC2-US123` contains `1`.
  - `GUAR7-DIAN8` contains `I`.
- The recovery-code UI can display codes that the server will reject, so the advertised recovery-code verification flow is inconsistent.
- The identity screen presents multiple primary actions after a code is requested.

## NEW_TASKS

1. Change fixture handling so deterministic MFA fixtures are enabled only through an explicit test-mode environment setting, while normal operation always uses cryptographically secure random identity codes, Base32 authenticator secrets, and recovery codes.

2. Replace the non-fixture authenticator-secret generation logic with cryptographically secure Base32 generation using only `A-Z` and `2-7`, and verify that every generated secret is accepted by `base32Bytes()`.

3. Correct `fixtureRecoveryCodes()` so every fixture code matches `^[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}$` and is therefore usable by `/api/recovery/verify`.

4. Add an automated or startup-level validation that each fixture recovery code passes `validRecoveryCode()` before being returned to the UI.

5. On the identity screen after a code has been requested, demote “Request a new check code” to a secondary action so “Check code” is the only primary action.

## DECISION

FAIL