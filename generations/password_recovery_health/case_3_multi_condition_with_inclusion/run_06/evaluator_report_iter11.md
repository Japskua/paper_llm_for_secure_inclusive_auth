## SUMMARY

The artifact is a well-structured single-file Bun application with a functional recovery, verification, MFA simulation, password-change, login, and privacy-acceptance flow. It uses HTTPS, session cookies, CSRF validation, CSP/security headers, bcrypt hashing for changed passwords, rate limiting, and browser-side simulated-delivery logs. However, it does not fully meet the security and ADHD-focused persistence requirements: the initial account password is stored in plaintext in source code, and recovery delivery information is lost after a browser reload despite the requirement to pause and return without losing progress. Therefore, the artifact cannot be accepted as-is.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and SPA delivery**
  - The entire server, HTML template, CSS, and browser JavaScript are contained in `app.ts`.
  - The browser script is served from `/app.js`, generated from code in the same source file.
  - No framework, bundler, compiler, external asset, or external network call is used.

- **PASS — HTTPS and HTTP-to-HTTPS redirect**
  - The app reads `certs/cert.pem` and `certs/key.pem` and starts TLS on port `3443`.
  - HTTP on port `3000` returns a `308` redirect to `https://localhost:3443`.

- **PASS — Security headers and restrictive browser policy**
  - HTTPS/API/page responses include HSTS, CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, and no-store cache headers.
  - The CSP restricts scripts to same-origin `/app.js` and prevents framing, object embedding, external connections, and external form submissions.

- **PASS — CSRF protection on sensitive requests**
  - State-changing API endpoints use `guarded()`.
  - `guarded()` requires a server-side session and a session-specific `X-CSRF-Token`.
  - The session cookie uses `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **PASS — Session-bound reset token handling**
  - Reset tokens are generated using `randomBytes`, are 32 bytes encoded as Base64URL, are validated against a strict format, expire after 15 minutes, and are marked single-use after a password change.
  - Reset state is bound to the current server-side session and account ID rather than accepted as an arbitrary account reference.

- **PASS — Password-reset verification works manually**
  - The user can copy/type the recovery token into the manual recovery-code field.
  - The “Open simulated recovery link” button also populates the token field.
  - The browser logs the generated mock reset token and MFA code using `console.log`, as required for testing.

- **PASS — Password policy and password hashing after reset**
  - New passwords require 12–128 characters with uppercase, lowercase, number, symbol, and no whitespace.
  - Changed passwords are hashed with `Bun.password.hash(..., { algorithm: "bcrypt", cost: 10 })`.
  - Password values are not logged.

- **FAIL — Passwords are never stored in plaintext**
  - `INITIAL_DEMO_PASSWORD = "HelenaCare#2025"` stores a real usable password in plaintext in `app.ts`.
  - This directly conflicts with the requirement that passwords be hashed using bcrypt/Argon2 and never stored in plaintext.
  - The comment saying the bcrypt value is generated at startup is misleading because the plaintext password remains embedded in the deployed source.

- **PASS — Brute-force mitigation is present for verification and login**
  - Login, reset-token verification, and MFA verification have per-session counters, global counters, a maximum attempt threshold, and a 15-minute lock.
  - The server returns `429`-style generic failures when a relevant action is locked.

- **PARTIAL / FAIL — MFA is only a deterministic recovery mock and is not part of login authentication**
  - The reset flow includes a simulated MFA step, but the actual sign-in flow authenticates solely with the password.
  - The MFA code is a globally fixed constant (`246810`) and is returned to any requester with an eligible reset session.
  - While deterministic mocks are required for testing, the implementation does not provide meaningful MFA/SSO for account sign-in as required by the authentication-security requirements.

- **PASS — Privacy acceptance requires authentication**
  - `/api/privacy/accept` verifies `authenticatedAccountId` before changing privacy state.
  - The privacy page redirects unauthenticated users to login.

- **PASS — XSS resistance in the UI**
  - User-controlled values are not injected as HTML.
  - Browser log entries use `textContent`, not `innerHTML`.
  - Server responses are JSON-serialized rather than string-concatenated HTML from user input.
  - No user-controlled redirect URL is accepted.

- **PASS — Generic response reduces direct email-account enumeration**
  - Recovery requests return the same user-facing message whether an account exists or not.
  - The recovery email address is not echoed back to the browser.

- **FAIL — Pause-and-return recovery experience is incomplete**
  - Server-side recovery progress survives the browser session, but the simulated delivered token exists only in the client variable `delivered` and the in-page `Logs` list.
  - Reloading the page clears `delivered` and the browser log UI. The app returns the user to step 2 but tells them to use a token “shown in Logs,” even though the token is no longer available in the new page instance.
  - This does not fully satisfy the inclusivity requirement to let users pause and return without losing progress or reminders of the next actionable step.

- **PASS — ADHD-oriented UX structure**
  - The app provides a visible five-step progress indicator, orientation text, explicit next-step messaging, clear headings, restrained layout, no timeout countdown, and always-visible help/safe-sign-in reminders.
  - The recovery state is retained server-side until expiration.

- **PASS — Internal navigation functions**
  - `/recovery`, `/login`, and `/privacy` are handled by the server.
  - Navigation uses History API routing and `popstate` rendering.
  - Recovery completion leads to login, and successful login leads to privacy acceptance.

- **PASS — No debug stack traces exposed**
  - The top-level request handler catches exceptions and returns a generic response.
  - No directory listings or development stack traces are exposed by the application code.

## FAILING_ITEMS

- The plaintext constant `INITIAL_DEMO_PASSWORD = "HelenaCare#2025"` stores a usable account password directly in source code. This violates the password-storage requirement.

- Recovery-token availability does not survive a page reload. The server retains recovery state, but the mock token is only returned on the original request and is then lost from the UI/log panel on reload.

- The app’s authentication flow does not enforce MFA or SSO at sign-in. The only MFA step is a recovery mock using a globally fixed code returned by the API.

- The initial-password comment is inaccurate: it claims a bcrypt value is generated securely at startup, but the application still retains the initial plaintext password in its source.

## NEW_TASKS

1. Remove `INITIAL_DEMO_PASSWORD` from source code and replace startup initialization with a precomputed bcrypt hash stored as `demoAccount.passwordHash`; do not retain any plaintext password constant.

2. Update the demo/test workflow so it does not require a hardcoded plaintext initial password. The evaluator should be able to reset the password through the recovery flow and then sign in with the newly created password.

3. Persist the simulated recovery delivery token in server-side recovery state in a test-safe manner, and expose it again to the existing session after reload through a protected recovery-status endpoint or `/api/session` response.

4. Update the client `load()`/`render()` behavior to restore the visible recovery reminder and simulated token/log entry when the user returns to an in-progress recovery session.

5. Implement an MFA or SSO requirement for actual sign-in, or explicitly add a server-side, session-bound deterministic MFA challenge after password verification for this mock environment. Ensure it has expiration, attempt throttling, and is not a globally reusable constant.

6. Correct the misleading password-initialization comment so it accurately reflects the final implementation and confirms that no plaintext password is retained.

## DECISION

**FAIL**