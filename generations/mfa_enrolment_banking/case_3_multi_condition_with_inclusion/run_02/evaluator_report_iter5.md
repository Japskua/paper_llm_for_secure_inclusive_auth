## SUMMARY

The artifact is a single-file Bun HTTPS MFA enrolment app with a functional mobile-oriented flow, CSRF/session protections, encrypted OTP secret handling, hashed recovery codes, TOTP verification, rate limiting, and working manual/QR provisioning paths. However, it fails the security and UX requirements because it persistently displays sensitive OTP and recovery-code values in an in-page “Logs” panel, and it does not provide an in-flow way to re-request/restart authenticator provisioning after the setup details have been hidden or a mock code has expired.

## FUNCTIONAL_CHECK

- **Single `app.ts` Bun server with inline HTML, CSS, and vanilla browser JavaScript: PASS**
  - The supplied artifact contains the Bun server, HTML template, inline CSS, and inline browser JS in one file. It uses no framework, bundler, external asset, or external network call.

- **HTTPS/TLS using the supplied certificate paths: PASS**
  - The server checks for and uses `certs/cert.pem` and `certs/key.pem` in `Bun.serve({ tls: ... })`.
  - It fails safely with a generic startup message if the certificate files are unavailable.

- **Mobile-responsive, dyslexia-conscious UI: PASS**
  - The app has a narrow mobile layout, readable font sizing, spacing, high-visibility focus states, short plain-language instructions, examples for inputs, icons, and clear step indicators.
  - There are no moving, flashing, or auto-updating UI elements.
  - Inputs support appropriate autofill/input modes, including `autocomplete="one-time-code"`.

- **Authenticator provisioning by QR code and manual setup key/link: PASS**
  - The setup flow renders a QR code and provides a manual secret and provisioning URI.
  - Copy buttons and selectable readonly textareas provide a fallback where clipboard access fails.
  - The secret is not placed in a URL query parameter.

- **OTP verification works and supports deterministic browser-test mocking: PASS**
  - The server validates the deterministic mock OTP and RFC-style TOTP values.
  - The mock OTP is returned only after authenticated provisioning and is logged in the browser console as required for testing.
  - TOTP counters are tracked to prevent reuse, and the mock OTP is marked single-use.

- **Recovery-code generation, display, regeneration, and single-use verification: PASS**
  - Recovery codes are generated with `crypto.getRandomValues`.
  - They are stored only as PBKDF2-derived values with unique salts.
  - Used recovery codes are marked consumed.
  - Regeneration replaces the stored recovery-code set.
  - The browser console logs returned mock/recovery values as required for testing.

- **Retry/reveal/hide/re-request support: FAIL**
  - The UI supports retrying a failed OTP entry and revealing/hiding setup details.
  - However, after the initial provisioning response, there is no user-facing control to re-request/restart provisioning and obtain a new mock setup code or setup secret. This is particularly problematic if the mock OTP expires or the user wants to restart setup without navigating away and signing in again.
  - This does not meet the requirement that users can “re-request codes without penalty.”

- **Server-side authorization and IDOR protection: PASS**
  - MFA state is selected only by the authenticated server-side session’s fixed account owner (`marcus-account`).
  - No endpoint accepts a user ID or account ID from the browser.
  - Session ownership is checked before MFA routes are processed.

- **CSRF protection for state-changing MFA endpoints: PASS**
  - Authenticated state-changing routes require both the trusted origin and the matching `X-CSRF-Token`.
  - Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **Security headers and clickjacking protection: PASS**
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, restrictive referrer policy, permissions policy, and no-store caching.
  - The CSP uses a fresh nonce for inline style and script content.

- **CORS and generic production errors: PASS**
  - The app does not send permissive CORS headers.
  - Cross-origin state-changing requests are rejected through exact origin checking.
  - The Bun error handler returns a generic error response without a stack trace.

- **Secret storage and cryptographic controls: PASS**
  - OTP secrets are generated with cryptographically secure randomness and encrypted with AES-GCM in server memory.
  - Recovery codes are stored as salted PBKDF2-derived values rather than plaintext.
  - Sessions and secrets are not stored in browser storage or non-HttpOnly cookies.

- **Input validation and XSS protections: PASS**
  - OTPs, recovery codes, account-ending digits, and date-of-birth input are validated server-side.
  - Dynamic browser-rendered values are escaped before insertion into `innerHTML`.
  - Redirect functionality is not present, so no open redirect is introduced.

- **Rate limiting, lockouts, session rotation, and logout invalidation: PASS**
  - Login, authenticator OTP, and recovery code attempts are rate-limited and locked after repeated failures.
  - The session ID is regenerated on successful identity verification.
  - Idle and absolute session limits are checked on authenticated requests.
  - Logout deletes the session and expires the cookie.

- **No exposure of OTPs or recovery codes in application logs/UI logs: FAIL**
  - The in-page `<section class="logs">` permanently displays the mock OTP and actual recovery codes through the `log()` function.
  - For example, `log("Mock OTP issued: "+mockOtp)` and `log("Recovery codes issued: "+r.codes.join(", "))` write sensitive values into the visible DOM.
  - The requirement explicitly prohibits exposing OTPs and backup codes in logs. Browser `console.log` is required for test mocks, but a persistent visible application log panel is not required and unnecessarily exposes secrets after the user moves to later steps.

## FAILING_ITEMS

- **Sensitive authentication material is retained and displayed in the visible “Logs” panel.**
  - Mock OTPs and actual recovery codes are appended to `#logs` and remain visible throughout later screens, including after MFA completion.
  - This violates the requirement not to expose OTPs or backup codes in logs and weakens the intended “store recovery codes securely” flow.

- **The authenticator setup flow lacks a user-facing re-request/restart provisioning action.**
  - A user can reveal/hide the existing setup details and retry verification, but cannot request a replacement setup secret/mock OTP from the current screen.
  - A replacement setup path is necessary to meet the retry/re-request usability requirement, especially after an expired mock OTP or abandoned setup attempt.

## NEW_TASKS

1. Remove the visible in-page `Logs` panel and ensure `log()` writes required test values only to `console.log`; do not render mock OTPs, recovery codes, provisioning secrets, or provisioning URIs into persistent application log UI.

2. Add a clearly labelled secondary action in the authenticator setup screen, such as “Start setup again” or “Get new setup details,” which calls `/api/mfa/provision`, replaces the unverified setup secret/URI/mock OTP, resets the setup display safely, and confirms in plain language that previous unverified setup details have been replaced.

## DECISION

**FAIL**