## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a generally strong mobile-oriented MFA flow, server-side session ownership checks, CSRF checks on protected mutations, secure cookie attributes, rate limiting, encrypted OTP-secret storage, hashed recovery codes, and browser-console mock delivery. However, it does not fully meet the authenticator/QR and secure-CSP requirements: the generated QR code cannot encode the provisioning URI, the simulated verification code is unrelated to the provisioned TOTP secret and is non-deterministic, and the CSP permits arbitrary inline scripts/styles through `unsafe-inline`.

## FUNCTIONAL_CHECK

- **FAIL — Single-file Bun server with inline HTML, CSS, and vanilla JavaScript**
  - The entire application is contained in `app.ts`, uses `Bun.serve`, and has no framework, bundler, compiler, external asset, or external network dependency.
  - However, the app has functional QR/provisioning defects described below, so full functional compliance is not achieved.

- **PASS — HTTPS/TLS server uses the specified certificate paths**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - TLS is required for served traffic, and HSTS is set.

- **PASS — Responsive, legible mobile SPA and dyslexia-aware UX**
  - The viewport meta tag, constrained mobile layout, generous spacing, clear labels, high-contrast controls, plain language, examples, persistent help text, and no moving/flashing UI are present.
  - The flow visibly indicates the current step and provides one prominent primary action per stage.
  - Inputs include useful browser autofill attributes, including `autocomplete="one-time-code"` for OTP input.

- **PASS — Identity confirmation, MFA setup, verification, recovery-code flow, settings, and logout exist**
  - The intended screens and transitions are implemented.
  - Recovery codes can be copied, printed, confirmed, regenerated, and used once through server-side endpoints.
  - Logout invalidates the server session and expires the cookie.

- **FAIL — Authenticator provisioning via QR code works**
  - The QR generator is hard-coded as “Version 5, level L” with `dataBytes = 108`, allowing at most 106 bytes of byte-mode content after QR overhead.
  - The generated `otpauth://` URI is approximately 146 bytes, far exceeding that capacity.
  - The generator does not reject or resize oversized input; it creates more data codewords than the QR version can contain, then only places a truncated stream into the QR modules. The resulting QR code is invalid/unscannable.
  - A manual setup-key path exists, but the offered QR-code option itself does not function correctly.

- **FAIL — Provisioned authenticator and verification code correspond to one another**
  - `/api/mfa/provision` creates a random Base32 secret and returns an `otpauth://totp/...` URI, suggesting a real TOTP authenticator setup.
  - `/api/mfa/verify` does not validate a TOTP value derived from that secret. It validates only a separate random `testCode` produced by `issueChallenge`.
  - Therefore, a user who scans the QR code or manually enters the supplied setup key into an authenticator app cannot verify using the authenticator’s generated TOTP code.
  - This fails the requirement to set up a time-based OTP authenticator whose verification works.

- **FAIL — Mock OTP behavior uses deterministic mock values**
  - `secureOtp()` uses `crypto.getRandomValues`, and every provision/reissue produces a random OTP.
  - The requirements expressly call for deterministic mock values while still requiring verification to work.
  - The random test code also has no cryptographic relationship to the provisioned shared secret.

- **PASS — Browser-console mock delivery and UI return of test values**
  - The client logs the setup secret, simulated OTP, and recovery codes via browser `console.log`.
  - The secret and recovery codes are rendered in the UI; the OTP is returned from the API to client JavaScript and logged in the browser console.
  - No server-side `console.log` leaks these values.

- **PASS — Server-side authorization and IDOR resistance**
  - Protected endpoints derive the account exclusively from the HttpOnly session cookie.
  - State-changing endpoints call `requireProtected`, which rejects supplied `userId`, `accountId`, and `emailOwner` properties and resolves the account from `session.userId`.
  - Settings access is also session-bound.

- **PASS — CSRF and session protections**
  - Protected state-changing routes require a per-session CSRF token and same-origin validation.
  - The session cookie uses `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Session IDs rotate on sign-in, have idle and absolute timeouts, and are invalidated on logout.
  - OTP and recovery verification failures are rate-limited with temporary lockouts.

- **FAIL — Secure CSP configuration**
  - The CSP includes both `script-src 'unsafe-inline'` and `style-src 'unsafe-inline'`.
  - `unsafe-inline` allows injected inline JavaScript to execute and materially weakens the intended XSS protection of the CSP.
  - A secure single-file implementation can use a per-response nonce on the inline `<script>` and `<style>` tags, or fixed CSP hashes where appropriate, rather than permitting arbitrary inline content.

- **PASS — Other response-header and clickjacking protections**
  - `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store` are provided.
  - CORS is not broadly enabled; only trusted local HTTPS origins are considered for CORS headers.

- **PASS — Sensitive-value storage and server-side validation**
  - OTP shared secrets are encrypted using AES-GCM before storage in server memory.
  - Recovery codes are generated using a cryptographic RNG and only SHA-256 hashes are retained server-side.
  - The browser does not use `localStorage`, `sessionStorage`, or non-HttpOnly cookies for secrets/session tokens.
  - Server-side input validation is present for email, phone, password, OTP, and recovery-code formats.
  - Client rendering uses `textContent` rather than unsafe HTML insertion for dynamic values.

- **PASS — Generic production errors and no verbose stack traces**
  - The request handler and Bun error handler return generic messages and do not expose stack traces or internal exception details.

## FAILING_ITEMS

- The QR implementation is capacity-invalid: a Version 5-L QR code cannot hold the generated provisioning URI, so the QR code is not a usable provisioning option.
- The supplied provisioning secret/URI does not produce the code accepted by `/api/mfa/verify`; verification accepts an unrelated random server challenge instead of a TOTP derived from the setup secret.
- OTP mock values are random rather than deterministic, contrary to the explicit mock-value requirement.
- The CSP uses `unsafe-inline` for scripts and styles, which weakens CSP-based XSS protection and does not satisfy a secure CSP requirement.

## NEW_TASKS

1. Replace the fixed, capacity-limited QR encoder with a correct in-file QR implementation that selects a QR version/error-correction capacity sufficient for the full generated `otpauth://` URI, and add a length/capacity guard so invalid QR output is never rendered.

2. Make MFA verification validate a code derived from the actual provisioned secret:
   - Implement server-side TOTP generation/validation from the decrypted setup secret, including permitted clock-window handling and single-use protection for accepted time steps; or
   - If the evaluation requires a fully simulated deterministic authenticator, use a deterministic mock code derived from the issued provisioning secret and validate that exact deterministic code.
   - Ensure the code logged in the browser is the same code that `/api/mfa/verify` accepts.

3. Replace random simulated OTP delivery values with deterministic mock values as required, while retaining the existing expiry, single-use, retry, and lockout behavior.

4. Remove `unsafe-inline` from `script-src` and `style-src`. Generate a per-response CSP nonce, attach it to the inline `<style>` and `<script>` elements, and include the nonce in the CSP header.

## DECISION

**FAIL**