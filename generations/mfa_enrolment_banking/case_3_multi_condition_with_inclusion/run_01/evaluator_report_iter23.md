## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a generally strong mobile MFA flow, secure headers, HttpOnly/Secure/SameSite session cookies, CSRF checks, server-side session checks, encrypted TOTP seed storage, PBKDF2-hashed recovery codes, and accessible UX features such as copy, download, print, manual secret reveal, and clear error text. However, it does not fully meet the requirements because the generated QR code is malformed, recovery-code verification has no rate limiting or lockout, and the publicly selectable demo mode creates a fixed-OTP MFA bypass.

## FUNCTIONAL_CHECK

- **PASS — Single `app.ts` deliverable with Bun server, HTML, CSS, and vanilla browser JavaScript**
  - The server and entire client SPA are contained in one file.
  - No framework, bundler, compiler, imported package, or external asset is used.

- **PASS — HTTPS/TLS server configuration**
  - `Bun.serve` uses `certs/cert.pem` and `certs/key.pem`.
  - The server only serves the configured TLS endpoint.

- **PASS — Mobile-responsive and dyslexia-aware UI**
  - The layout has a narrow mobile max width, responsive CSS, legible base font sizing, increased letter spacing, generous padding, plain-language content, no animations, visible focus styles, and clear step labels.
  - The interface avoids all-caps instructional text and provides examples for expected email, OTP, and recovery-code formats.

- **PASS — MFA setup flow and manual secret option**
  - The app supports sign-in, provisioning, authenticator-code verification, recovery-code display, copy/download/print actions, completion, regeneration, recovery-code use, and logout.
  - The secret may be revealed and copied manually when QR scanning is not suitable.

- **FAIL — Offered QR code must function correctly**
  - `renderQR()` declares QR Version 10 but encodes the byte-mode character-count field using 8 bits:
    - `push(bytes.length,8)`
  - QR byte mode requires a **16-bit character-count field for QR versions 10–40**. Version 10 is used here.
  - This makes the payload bitstream invalid for standard QR scanners, so the QR code cannot be relied upon as a functioning provisioning method.

- **PASS — Browser simulation logging and test values**
  - Browser-side `console.log` is used through `browserLog`.
  - In demo mode, the deterministic OTP and generated recovery codes are displayed in the UI and written to the browser console/log panel.
  - No server-side logging prints secrets, OTPs, recovery codes, or session identifiers.

- **PASS — Server-side authorization and IDOR protection**
  - MFA endpoints derive identity from the HttpOnly session cookie rather than accepting a user identifier from the client.
  - `authorized()` verifies that the session belongs to the fixed account owner.
  - Manipulated user IDs cannot be supplied to access another account’s settings.

- **PASS — CSRF protection for state-changing MFA requests**
  - Authenticated POST routes require same-origin `Origin` and a matching `X-CSRF-Token`.
  - The session CSRF token is generated server-side and is not stored in browser storage.
  - Sign-in also requires a one-time pre-auth token plus a same-origin `Origin`.

- **PASS — Secure headers and cookie configuration**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, referrer policy, and no-store cache control are present.
  - Session cookies use `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **PASS — OTP seed and recovery-code storage protections**
  - Provisioning seeds are generated with `crypto.getRandomValues` and stored with AES-GCM encryption.
  - Recovery codes are generated with cryptographic randomness and stored as independent PBKDF2-SHA-256 salted records.
  - Plain recovery codes are not persisted server-side after the response.

- **PASS — TOTP verification behavior**
  - TOTP is implemented with HMAC-SHA-1, six digits, and 30-second periods.
  - OTP provisioning challenges expire after ten minutes.
  - The accepted TOTP counter is tracked and a provisioning challenge is marked used after success.
  - OTP failures are rate-limited and lock after five failures.

- **FAIL — Verification attempts must be rate-limited and locked out**
  - `/api/recovery/verify` allows unlimited incorrect recovery-code submissions.
  - It performs expensive PBKDF2 work for each stored recovery record on every failed request.
  - There is no counter, delay, rate limit, or lockout for repeated failed recovery-code verification attempts.

- **FAIL — Fixed demo OTP is available as a production MFA bypass**
  - Any user who signs in with the supplied account credentials can select the visible “Demo/testing mode” checkbox.
  - That mode causes `/api/verify-otp` to accept the permanent fixed value `654321`:
    - `const validDemoCode = session.demo && sameText(d.otp, challenge.testOtp);`
  - This permits enrollment without possessing an authenticator application and violates the security requirement for OTP verification with sufficient entropy.
  - A testing-only bypass must not be exposed as a normal production UI option.

- **PASS — Input validation and output handling**
  - JSON bodies are allow-listed by field name and validated by type, length, and format.
  - Client-rendered dynamic text is escaped through `esc()` before being placed in `innerHTML`.
  - Internal routing does not accept arbitrary redirect targets.

- **PASS — Session lifecycle handling**
  - Sessions are newly generated at sign-in, use secure cookies, enforce idle and absolute timeouts, and are deleted on logout.
  - Expired sessions are rejected and their cookie is cleared.

## FAILING_ITEMS

- The QR encoder creates a Version 10 QR code with an invalid byte-mode character count because it uses an 8-bit count field instead of the required 16-bit field.
- Recovery-code verification lacks failed-attempt tracking, rate limiting, and lockout.
- The regular user-facing demo checkbox enables acceptance of a fixed OTP (`654321`), creating an MFA bypass in the deployed application.
- IPv6 localhost support is likely incomplete: `new URL("https://[::1]/").hostname` is typically `"[::1]"`, while `trusted()` only allows `"::1"`. This can reject the required `https://[::1]:3000` host.

## NEW_TASKS

1. Correct `renderQR()` for Version 10 byte mode by encoding the byte-mode character count with 16 bits; add a deterministic validation test or use a simpler valid QR version/encoder implementation that standard authenticator apps can scan.
2. Add per-session or per-account failed-attempt tracking for `/api/recovery/verify`, enforce a bounded number of failures, return a generic retry message, and lock verification temporarily after the threshold.
3. Remove the user-selectable production demo mode and fixed OTP acceptance path; if testing support is necessary, restrict it to an explicit server-side test-only configuration that cannot be enabled by an end user in normal operation.
4. Update `trusted()` to correctly recognize bracketed IPv6 URL hostnames, such as `"[::1]"`, while retaining the localhost-only allow-list.

## DECISION

FAIL