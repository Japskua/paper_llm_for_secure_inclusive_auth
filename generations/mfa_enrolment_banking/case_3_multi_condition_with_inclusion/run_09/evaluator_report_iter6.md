## SUMMARY

The artifact is a single `app.ts` Bun application with inline HTML, CSS, and vanilla browser JavaScript. It implements a responsive MFA enrolment flow with sign-in, identity verification, authenticator setup, recovery codes, CSRF/session protection, TLS, secure headers, input validation, rate limiting, and simulated browser-console delivery values. However, it does not fully meet the requirements because the locally generated QR code is likely malformed and therefore cannot reliably fulfil the scan option, and sensitive mock values are rendered into an on-page “Logs” panel in addition to browser console logging, conflicting with the requirement not to expose OTPs, OTP seeds, and recovery codes in logs.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun implementation with no frameworks, bundlers, compilers, or external assets**
  - The server, HTML template, CSS, and browser-side JavaScript are all contained in `app.ts`.
  - Uses `Bun.serve` directly and does not reference external scripts, stylesheets, fonts, APIs, or build tooling.

- **PASS — TLS is required and uses the specified certificate locations**
  - The application loads `./certs/cert.pem` and `./certs/key.pem`.
  - Startup fails if the certificate files are unavailable.
  - The Bun server is configured with `tls: { cert, key: privateKey }`.
  - Non-HTTPS requests are rejected with HTTP `426`.

- **PASS — Mobile-responsive, readable MFA flow**
  - The page includes a mobile viewport meta tag.
  - The main layout is narrow and adapts below `380px`.
  - Typography, spacing, focus states, short instructions, examples, and plain-language messages generally support the dyslexia-focused UX requirements.
  - No auto-updating, flashing, countdowns, or reading time limits are present.

- **PASS — Sign-in, identity verification, authenticator verification, backup-code generation, confirmation, recovery-code use, and logout are implemented**
  - The main flow is coherent and works in the default simulated mode:
    1. Sign in.
    2. Request and verify an identity code.
    3. Start authenticator provisioning and verify a deterministic mock authenticator code.
    4. Generate, save, and confirm recovery codes.
    5. Use a recovery code once.
    6. Log out.
  - Step-state enforcement prevents skipping ahead.

- **PASS — Simulated OTP and recovery values are returned to the browser and logged with `console.log`**
  - Default development/demo mode returns deterministic identity code, authenticator confirmation code, and recovery codes.
  - Browser-side `logFixture()` calls `console.log(...)`, satisfying the explicit testing-delivery requirement.
  - The values are not placed in URLs.

- **FAIL — QR-code provisioning option is not reliable**
  - The custom QR encoder’s format-information placement is incorrect. The QR format bits are written to invalid locations, mixing top-left, top-right, and bottom-left format regions.
  - A QR scanner may therefore reject the rendered code even though the provisioning URI itself is correct.
  - This means the “scan this setup square” option cannot be accepted as a working provisioning method.
  - Manual setup-key copy/paste is available, but it does not repair the failed QR option.

- **PASS — Manual authenticator setup is supported**
  - The secret is displayed after the user requests setup options.
  - The secret can be copied with the Clipboard API.
  - The secret can be hidden and revealed again.
  - The browser does not store the seed in localStorage, sessionStorage, or non-HttpOnly cookies.

- **PASS — Recovery-code usability and single-use verification are implemented**
  - Recovery codes can be copied and downloaded.
  - Codes are stored as peppered hashes, not plaintext, in the account record.
  - Successful recovery-code use marks the code as consumed.
  - Validation enforces the expected recovery-code format.

- **FAIL — Sensitive OTP/recovery values are exposed in an on-page log panel**
  - `logFixture()` writes mock identity OTPs, authenticator OTPs, and recovery codes into the visible `<pre id="logs">` element.
  - The security requirements state that OTPs, OTP seeds, and backup codes must not be exposed in logs.
  - The deliverable requires browser `console.log` in simulated mode, but it does not require displaying those sensitive values in a visible application “Logs” panel.
  - The UI log panel unnecessarily broadens secret exposure and also leaves values visible after setup completion.

- **PASS — Server-side authorization and IDOR protection are generally enforced**
  - Protected endpoints resolve the account exclusively through the server-side session’s `userId`.
  - No endpoint accepts a client-controlled account ID or user ID.
  - Session ownership is checked through `required(...)` for protected MFA actions.
  - Stage checks prevent actions outside the authenticated user’s expected enrolment state.

- **PASS — CSRF protection is applied to state-changing endpoints**
  - Mutating requests require an `X-CSRF-Token` matching the server-side session token.
  - Origin checks are enforced for state-changing endpoints.
  - Session cookies use `SameSite=Strict`, providing additional CSRF protection.

- **PASS — Secure session-cookie configuration and session lifecycle controls**
  - Session cookies include `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Sessions have idle and absolute expiration checks.
  - The session ID is regenerated on successful sign-in, mitigating session fixation.
  - Logout deletes the server-side session and clears the cookie.

- **PASS — Secure headers and CORS restrictions are substantially implemented**
  - CSP includes nonce-based script/style authorization, `frame-ancestors 'none'`, and restrictive source directives.
  - HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, and `Permissions-Policy` are set.
  - CORS only returns `Access-Control-Allow-Origin` for the same origin.

- **PASS — Input validation, generic server errors, and redirect safety**
  - Email, OTP, and recovery code inputs are validated server-side.
  - There are no database queries or dynamic SQL, so SQL injection is not applicable to this in-memory implementation.
  - User content is inserted using `textContent` rather than HTML interpolation on the client.
  - No user-controlled redirect targets are accepted.
  - The outer server catch returns a generic error rather than a stack trace.

- **PASS — Verification expiry, rate limiting, lockout, and non-enumerating sign-in failures**
  - Identity codes are hashed, time-bound, and marked used after verification.
  - Identity requests are rate limited.
  - Sign-in, identity, authenticator, and recovery-code failures lock after repeated failed attempts.
  - Sign-in uses a dummy password hash for unknown accounts to reduce timing/account-enumeration differences.
  - Sign-in errors do not disclose whether an account exists.

## FAILING_ITEMS

- The generated QR code is likely invalid because QR format-information bits are placed incorrectly in `renderSetupSquare()`. This makes the promised scan-based authenticator provisioning method unreliable or unusable.

- Sensitive simulated values are placed into the visible application log panel:
  - identity verification OTP,
  - authenticator confirmation OTP,
  - recovery codes.
  
  This conflicts with the requirement not to expose OTPs, seeds, or backup codes in logs. Browser-console simulation can remain for the explicit test requirement, but the visible in-app log panel should not contain secret material.

## NEW_TASKS

1. Replace or correct `renderSetupSquare()` so it produces standards-compliant, scanner-readable QR codes for the exact returned `otpauth://` provisioning URI. In particular, fix QR format-information placement and validate the result with at least one common authenticator/QR decoder.

2. Remove sensitive values from the visible `<pre id="logs">` panel. Keep simulated OTP and recovery-code delivery exclusively in browser `console.log` as required for testing, or change the panel to show only non-sensitive status messages such as “A simulated identity code was sent.”

3. Ensure secret-bearing UI state is cleared when no longer needed, including clearing or replacing any visible simulated-delivery status after completion, regeneration, logout, or navigation away from the related step.

## DECISION

FAIL