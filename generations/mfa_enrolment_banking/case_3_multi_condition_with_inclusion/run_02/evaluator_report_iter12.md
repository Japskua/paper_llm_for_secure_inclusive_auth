## SUMMARY

The artifact is a strong single-file Bun implementation with TLS, session ownership checks, CSRF protection, restrictive headers, encrypted TOTP secrets, hashed recovery codes, input validation, and usable mobile-oriented screens. However, it does not fully meet the requirements because the displayed “setup square” is not a valid scannable QR code, sensitive secrets and recovery codes are retained in a visible on-page log, CSP blocks an inline style used by the checkbox, client routes can falsely show completion before MFA is enabled, and login comparison has avoidable account-dependent timing behavior. Therefore the artifact cannot be accepted as-is.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no frameworks, bundlers, compilation pipeline, or external assets**
  - All server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses `Bun.serve` directly and only Node built-in `fs` imports.
  - No third-party or external network assets are used.

- **PASS — TLS is configured using the required certificate paths**
  - The server loads `certs/cert.pem` and `certs/key.pem`.
  - The server refuses to start when certificates are unavailable, preventing accidental HTTP operation.
  - HSTS is set on responses.

- **PASS — Server-side authorization and IDOR protection**
  - Authenticated session state is derived from the `HttpOnly` session cookie, not a client-provided user ID.
  - MFA records are accessed through `session.userId`, which is checked against the fixed authenticated account.
  - There are no API parameters allowing a caller to select or manipulate another user’s MFA record.

- **PASS — CSRF protection on authenticated state-changing MFA endpoints**
  - State-changing authenticated API calls require both a trusted `Origin` and a matching `X-CSRF-Token`.
  - Session cookies use `SameSite=Strict`.
  - Login appropriately does not depend on a pre-existing session CSRF token.

- **PASS — Security headers and restrictive CORS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Cache-Control: no-store` are configured.
  - CORS is restricted to the localhost HTTPS origins in `TRUSTED`.
  - Generic error responses prevent stack traces from being exposed.

- **FAIL — CSP is not fully compatible with the rendered page**
  - The page CSP permits nonce-authorized `<style>` blocks but does not permit inline `style=""` attributes.
  - The recovery-code acknowledgement checkbox contains `style="width:auto;min-height:auto;margin-right:9px"`.
  - Modern browsers will block that inline style under this CSP, leaving the checkbox subject to the broad `input { width:100%; min-height:52px; ... }` rule and producing an oversized/mis-styled control.

- **PASS — Cryptographic handling of MFA data**
  - TOTP secrets are encrypted using AES-GCM with a 32-byte server key.
  - Recovery codes are individually salted and hashed with PBKDF2-SHA-256 at 120,000 iterations.
  - Cryptographic randomness is used for session IDs, CSRF tokens, encryption IVs, salts, non-test secrets, and recovery codes.
  - TOTP values are not stored and used TOTP counters prevent replay.

- **PASS — Verification expiry, single use, and lockout**
  - Identity codes expire after 20 minutes and are marked used after successful verification.
  - TOTP codes are tied to time counters and accepted counters cannot be reused.
  - Recovery codes are marked used after successful use.
  - Failed identity, TOTP, and recovery-code verification attempts are locked for five minutes after five failures.

- **FAIL — The advertised QR setup option is not a real QR code**
  - `drawQr()` creates a deterministic pseudo-random canvas pattern rather than encoding the provisioning URI as a standards-compliant QR code.
  - An authenticator application cannot scan this canvas to provision the TOTP secret.
  - This violates the requirement to offer a functioning QR-code option. The manual key is present, but it does not make the non-working QR option acceptable.

- **FAIL — Sensitive values are exposed in a persistent visible activity log**
  - The `log()` function writes identity codes, authenticator secrets, provisioning URIs, and recovery codes into the visible `#logs` DOM element.
  - This log remains visible across the enrolment flow, including after the recovery codes have ostensibly been saved.
  - The security requirements prohibit exposing OTP seeds, OTPs, and backup codes in logs. Browser-console mock output is explicitly required for testing, but retaining these values in an on-page activity log is unnecessary and insecure.

- **FAIL — Client-side route rendering can falsely indicate MFA is complete**
  - A signed-in user can manually navigate to `#/done` before completing identity verification, provisioning, TOTP verification, or recovery-code acknowledgement.
  - `done()` only checks that a session exists; it does not check `state.enabled` or whether recovery-code acknowledgement is complete.
  - The UI can display “MFA is ready” when MFA has not actually been enabled. Server-side APIs remain protected, but the user-facing flow is misleading and inconsistent.

- **PASS — Input validation and output escaping**
  - Server-side validation exists for email, password length, identity codes, TOTP codes, and recovery-code format.
  - Dynamic strings inserted through HTML are escaped via `esc()`, while provisioning values are assigned with `textContent`.
  - No database is used, so parameterized-query requirements are not applicable to this implementation.
  - Redirect-like flow values are constrained by `safePath()`.

- **FAIL — Login handling has account-dependent comparison timing**
  - The condition `if (!equal(email, USER.email) || !equal(password, USER.password))` short-circuits.
  - When the email is wrong, password comparison is skipped; when it is correct, password comparison occurs.
  - This creates avoidable account-dependent timing behavior, contrary to the requirement to avoid user enumeration in timing as well as messaging.

- **PASS — Mobile and dyslexia-conscious UI foundation**
  - The layout is responsive, constrained to a readable mobile width, and uses generous spacing, large inputs, plain language, icons, autocomplete hints, and visible current-step labels.
  - There are no moving or flashing elements.
  - Copy controls, download support for recovery codes, resend support for identity codes, and recovery-code regeneration are provided.

- **FAIL — Mock authenticator verification is not clearly available as a deterministic browser-console test value**
  - Identity and recovery-code mock values are returned and logged in the browser.
  - The provision endpoint logs the secret and URI, but it does not return/log a current mock authenticator OTP for direct test verification.
  - Since the requirement specifically calls for simulated deterministic mock values and browser-console visibility for OTP testing, a test-mode-only valid TOTP value should be provided and logged. The current TOTP is time-dependent and requires independently generating it from the secret.

## FAILING_ITEMS

- The displayed authenticator “setup square” is not a valid QR code and cannot be scanned by authenticator applications.
- Sensitive identity codes, provisioning secrets, provisioning URIs, and recovery codes are copied into the persistent visible `#logs` panel.
- The CSP blocks the acknowledgement checkbox’s inline `style` attribute, causing a CSP violation and incorrect checkbox styling.
- The `#/done` route can claim MFA setup is complete even when the server state shows MFA is not enabled.
- Login credential comparisons short-circuit and create different work/timing paths for valid versus invalid email addresses.
- Test-mode authenticator OTP verification is not exposed as a clear deterministic mock browser-console value.

## NEW_TASKS

1. Replace `drawQr()` with a standards-compliant, self-contained QR encoder that encodes the exact `otpauth://` provisioning URI and produces a canvas scannable by common authenticator apps.

2. Remove the visible persistent sensitive activity log, or ensure it never contains identity codes, TOTP secrets, provisioning URIs, TOTP values, or recovery codes. Keep the required mock diagnostics in `console.log` only, and show only non-sensitive status text in the UI.

3. Remove the inline checkbox `style` attribute and add a nonce-authorized stylesheet class/rule for acknowledgement checkboxes so the UI complies with its own CSP.

4. Add client-side route-state guards using `/api/state` so `/done` only renders after MFA is enabled and recovery-code setup is complete; redirect incomplete users to the appropriate next step.

5. Make login verification perform equivalent comparison work regardless of whether the submitted email matches, avoiding short-circuit account-dependent timing.

6. In explicit test mode only, return a valid current authenticator OTP or a deterministic test verification value from the provisioning/test endpoint and log it with `console.log` in the browser. Do not expose this value in production mode.

## DECISION

FAIL