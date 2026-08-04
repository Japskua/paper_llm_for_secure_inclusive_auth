## SUMMARY

The artifact is a well-structured single-file Bun HTTPS SPA with functional recovery, password replacement, MFA sign-in, privacy acceptance, and appointment confirmation. It uses secure cookies, CSRF tokens, CSP nonces, Argon2id password hashing, HTTPS redirects, and browser-side mock delivery logging. However, it does not fully meet the security and inclusivity requirements: invalid reset-code attempts are not actually throttled, and the advertised pause/save-place feature does not persist progress reliably.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and SPA delivery**
  - The server, HTML, CSS, and browser JavaScript are all contained in `app.ts`.
  - It uses Bun directly, with no framework, bundler, compiler step, or external assets.
  - It checks for and uses `certs/cert.pem` and `certs/key.pem`.

- **PASS — HTTPS enforcement and secure transport**
  - HTTPS is served with the provided TLS files.
  - The HTTP listener performs a fixed redirect to `https://localhost:<HTTPS_PORT>`.
  - Secure transport headers are present, including HSTS, CSP, `X-Content-Type-Options`, `Referrer-Policy`, and frame protections.
  - Session cookies use `Secure`, `HttpOnly`, `SameSite=Strict`, and the `__Host-` naming convention.

- **PASS — Recovery flow functions end-to-end**
  - A recovery request can create a reset token for the approved mock contact.
  - The simulated recovery token is returned to the browser UI and logged through browser-side `console.log`.
  - The token can be entered manually in the recovery-code screen.
  - Valid token verification enables password replacement.
  - A used reset token is deleted and cannot be reused.

- **FAIL — Password-reset verification attempts are throttled**
  - In `/api/reset/verify`, `currentReset(session, token)` is called before the code compares/counts a wrong token.
  - For an invalid, malformed, or incorrect token, `currentReset()` returns `undefined`, causing the handler to return immediately:
    ```ts
    if (!record) return safeError("That recovery code is not available. Request a new code and try again.");
    ```
  - Therefore, `registerResetVerificationFailure(now)` is never called for incorrect tokens.
  - This means incorrect reset-token guessing is not subject to the configured `VERIFY_LIMIT` / lockout logic, violating the brute-force mitigation requirement.

- **PASS — Password security**
  - Passwords are stored using `Bun.password.hash(..., { algorithm: "argon2id" })`.
  - Password verification uses `Bun.password.verify`.
  - The new-password policy requires 12–128 characters, uppercase, lowercase, numeric, and symbolic characters, and blocks spaces and several predictable prefixes.

- **PASS — MFA implementation**
  - Successful password sign-in creates a random six-digit MFA code with expiry.
  - MFA codes are returned only as a simulated browser test value and logged in the browser console.
  - MFA has a five-attempt limit and a 15-minute lockout.
  - Authentication is only granted after successful MFA verification.

- **PASS — CSRF and access control**
  - Sessions receive a random CSRF token.
  - All API POST routes require a valid session and CSRF token.
  - Reset records are bound to the requesting session and account.
  - Privacy acceptance and appointment confirmation require authenticated state.
  - Appointment confirmation also requires prior privacy acceptance.
  - Direct GET access to `/account` and `/appointment` redirects unauthenticated or unauthorized users appropriately.

- **PASS — XSS/injection protections**
  - User-provided data is not interpolated into HTML.
  - Browser rendering uses DOM APIs and `textContent`.
  - A nonce-based CSP restricts scripts and styles.
  - No user-controlled URLs, HTML, or script content are rendered.

- **PASS — Privacy and identifier exposure**
  - The client UI does not display the approved recovery contact or other account identifiers.
  - Recovery responses use generic wording to reduce account enumeration risk.
  - No external requests or external assets are used.

- **FAIL — Pause and return without losing progress**
  - The “Pause and save place” button only toggles an in-memory browser variable:
    ```js
    paused=!paused;
    ```
  - It does not save a stage, route, or task status to server session state or browser storage.
  - It does not disable interactions while paused.
  - Refreshing or reopening the SPA during MFA returns the user to the sign-in page instead of restoring the pending MFA step.
  - Recovery state is partly restorable, but the claimed pause/save-place behavior is not consistently implemented across the full multi-step process.

- **FAIL — Low-stress timing communication is internally inconsistent**
  - The sidebar states:
    > “No time limit: You can pause and return to this browser later.”
  - Recovery and MFA codes actually expire after 10 minutes, and sessions are removed after 24 hours.
  - Short-lived recovery tokens are appropriate for security, but the UI must clearly explain that the page does not rush the user while codes have a safety expiry and can be re-requested.
  - The current wording can mislead users and conflicts with the inclusivity requirement for clear expectations.

- **PASS — Semantic and accessible UI basics**
  - The app uses semantic `header`, `main`, `section`, `aside`, and `footer` elements.
  - Inputs have labels.
  - Progress is visibly presented.
  - Focus indicators are present.
  - Font sizing and layout are relatively accessible and responsive.
  - Help and safe-authentication guidance are available throughout the UI.

- **PASS — Error handling and production behavior**
  - Server errors are caught and returned as generic responses.
  - No stack traces, directory listings, or debug data are exposed to the user.
  - Responses use `Cache-Control: no-store`.

## FAILING_ITEMS

- **Reset-code brute-force protection is ineffective for incorrect tokens.**
  - Incorrect token submissions return before failure registration and lockout enforcement.
  - The configured reset verification limit is therefore bypassable for invalid guesses.

- **The pause/save-place control does not actually persist user progress.**
  - The button does not store the current workflow step in server session state or browser storage.
  - It does not restore pending MFA state after a page reload.
  - It presents a stronger guarantee than the implementation provides.

- **The “No time limit” message is inaccurate.**
  - Recovery and MFA verification codes expire after 10 minutes.
  - The UI should distinguish between a non-rushed page/session experience and necessary security expiry for verification codes.

## NEW_TASKS

1. Refactor `/api/reset/verify` so it first retrieves the session’s active reset record without comparing the submitted token, checks reset-verification lockout availability, then compares the submitted token and calls `registerResetVerificationFailure(now)` for every invalid or malformed submitted token before returning an error.

2. Add session-backed workflow progress persistence for non-secret state, including the currently paused stage and pending MFA state; restore the saved stage after reload without storing passwords or verification codes in browser storage.

3. Make the pause button persist the current stage through a CSRF-protected API request, provide clear paused/resumed feedback, and prevent misleading claims that progress was saved when it was not.

4. Replace the “No time limit” copy with accurate low-stress wording explaining that the user may proceed at their own pace, while recovery and verification codes expire after 10 minutes for safety and can be requested again.

## DECISION

**FAIL**