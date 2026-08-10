## SUMMARY

The artifact is a strong single-file Bun HTTPS MFA demo with functional enrolment, TOTP verification, recovery codes, CSRF checks, secure cookies, CSP/HSTS headers, encrypted OTP-secret storage, hashed recovery codes, input validation, and a mobile-oriented accessible UI. However, it does not fully satisfy the required retry/reveal/hide/re-request UX, and session-expiry handling can leave the user on a protected screen instead of reliably returning them to sign-in. These are functional and UX compliance gaps.

## FUNCTIONAL_CHECK

- **Single `app.ts` file containing Bun server, HTML, CSS, and vanilla browser JavaScript — PASS**
  - The complete application is contained in one TypeScript file.
  - It uses `Bun.serve` directly and does not require a bundler, framework, external asset, or compilation pipeline.

- **Bun HTTPS server uses the supplied TLS certificate locations — PASS**
  - The server is configured with `certs/cert.pem` and `certs/key.pem`.
  - It serves HTTPS on port 3000.

- **Responsive, legible mobile UI — PASS**
  - The HTML includes a mobile viewport meta tag.
  - CSS constrains the main layout to a narrow mobile-friendly width and includes a small-screen media query.
  - Typography, contrast, spacing, field sizing, and focus indicators are suitable for mobile use.

- **Dyslexia-friendly, low-reading-load UI — PASS**
  - The interface uses short, plain-language instructions, roomy spacing, a legible font stack, icons, examples, visible hints, and no moving or flashing elements.
  - It provides copy controls for the OTP secret, provisioning URI, and recovery codes.
  - It uses browser autofill hints such as `autocomplete="username"`, `current-password`, and `one-time-code`.

- **Clear and predictable MFA enrolment flow — PASS**
  - The flow proceeds through sign-in, identity verification, authenticator setup, OTP verification, and backup-code saving.
  - Current progress is visibly presented as a step indicator.
  - Primary actions are prominent and consistently styled.

- **Authenticator provisioning supports QR and manual setup — PASS**
  - The application provides a locally generated QR code.
  - The TOTP secret and `otpauth://` URI can be copied manually.
  - No external QR service or network call is used.

- **Mock OTPs and recovery codes are returned to the UI and logged in the browser console — PASS**
  - The provisioning response returns the mock TOTP and displays it in the testing UI.
  - Recovery codes are returned to the UI and logged using browser-side `console.log`.
  - The server does not log these secrets.

- **TOTP verification works and is time-bound/single-use — PASS**
  - OTPs are generated using HMAC-SHA-1 TOTP-style logic.
  - The current and previous time slots are accepted.
  - Used time slots are tracked to prevent replay.
  - The OTP secret is generated using `crypto.getRandomValues`.

- **Recovery codes work, are single-use, and are protected at rest — PASS**
  - Recovery codes are cryptographically generated.
  - Codes are PBKDF2-hashed with unique salts before storage.
  - Successfully used codes are marked unusable.
  - Recovery-code regeneration replaces the stored set.

- **Rate limiting and lockout exist for repeated failures — PASS**
  - Identity, authenticator OTP, and recovery-code verification have failure counters.
  - Each locks after five failed attempts for five minutes.
  - User-facing lockout messages are clear and non-blaming.

- **Session management and session fixation protections — PASS**
  - A fresh cryptographically random session identifier is created at sign-in.
  - Sessions have idle and absolute expiration checks.
  - Logout deletes the server-side session and expires the cookie.
  - Session cookies use `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **Server-side authorization / IDOR protection — PASS**
  - MFA API routes derive the user from the server-side session.
  - They do not accept a client-supplied account or user ID.
  - The authenticated session is checked against the account owner before MFA state is accessed or modified.

- **CSRF protections on state-changing MFA endpoints — PASS**
  - State-changing routes require both a trusted `Origin` and a session-bound `X-CSRF-Token`.
  - The CSRF token is not stored in browser storage.

- **Security response headers and restricted CORS — PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, and `Cache-Control: no-store` are set.
  - CSP uses a per-page nonce for scripts and styles.
  - CORS is only emitted for an explicit trusted-origin allow-list.

- **Input validation and XSS mitigation — PASS**
  - Server-side validation is present for email, password, identity codes, OTPs, and recovery codes.
  - Dynamic client-side content is inserted using DOM APIs and `textContent`, rather than interpolated as HTML.
  - Redirect functionality is absent, so no open redirect is introduced.

- **No browser persistence of secrets or session tokens — PASS**
  - The application does not use `localStorage`, `sessionStorage`, IndexedDB, or non-HttpOnly cookies for session data or secrets.

- **Users can reveal, hide, and re-request codes without penalty — FAIL**
  - The manual TOTP secret and backup-code lists are always displayed while on their respective screens, but there is no hide/reveal control.
  - There is no clear re-request action for the identity verification code.
  - The setup flow can generate a new provisioning secret, but the UI does not explicitly present this as a safe “request a new code/setup value” option.
  - This does not fully meet the explicit inclusivity requirement to let users reveal, hide, and re-request codes without penalty.

- **Expired sessions reliably return the user to sign-in — FAIL**
  - `api()` calls `signin()` on HTTP 401, but several calling handlers immediately render their current page again after receiving the failed response.
  - For example, the identity handler calls `identity(r.message)`, the setup handler calls `setup(r.message)`, and the OTP handler calls `verify(r.message)` after `api()` has already attempted to show sign-in.
  - A user whose session expires during a POST can remain on a protected step displaying “Please sign in to continue,” rather than being reliably redirected to the sign-in screen.

## FAILING_ITEMS

- **Missing hide/reveal controls for sensitive displayed values**
  - The manual TOTP secret is permanently visible on the provisioning screen.
  - Recovery codes are permanently visible on the backup-code screen.
  - Add explicit “Show value” / “Hide value” controls, with the hidden state as the default where practical.

- **Incomplete code re-request support**
  - The identity code has no dedicated re-request action.
  - The authenticator setup flow does not clearly label or expose regeneration as a “get a new setup code” option.
  - Add a user-visible re-request control that produces/logs a replacement deterministic mock identity code or clearly regenerates setup material with explanatory confirmation.

- **401/session-expiry UI race**
  - `api()` renders sign-in on 401, but its caller may overwrite that view with a stale protected-step renderer.
  - This can make the expired-session flow confusing and prevent the intended recovery path.

## NEW_TASKS

1. Update `api()` and all API-call handlers so a 401 result stops the current handler and leaves the user on the sign-in screen; use a dedicated result flag or throw/catch mechanism rather than rendering a protected screen after a 401.

2. Add accessible show/hide controls for the manual TOTP secret and backup-code list, including clear button labels and status text confirming whether the value is hidden or shown.

3. Add explicit re-request controls for mock verification/setup values:
   - Add a “Send/check code again” action for the identity-check mock.
   - Add a clearly labelled “Create a new setup value” action for authenticator provisioning.
   - Log the relevant replacement mock value in the browser console and confirm the action plainly in the UI.

## DECISION

**FAIL**