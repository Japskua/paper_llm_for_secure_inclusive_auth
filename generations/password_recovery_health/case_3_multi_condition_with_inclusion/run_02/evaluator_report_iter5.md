## SUMMARY

The artifact is a single `app.ts` Bun HTTPS SPA with a clear, accessible recovery-to-appointment flow, CSRF protection, secure cookies, CSP/nonces, Argon2id password hashing, throttling, and browser-console mock messages. However, it does not fully meet the stated mock-delivery requirement because the actual reset authorization/token is deliberately withheld from the UI and browser console, and MFA-authenticated access remains valid after the MFA expiration time. These are functional/security failures, so the artifact cannot be accepted as-is.

## FUNCTIONAL_CHECK

- **Single-file Bun server + inline HTML/CSS/vanilla JavaScript: PASS**
  - The complete server and client SPA are contained in `app.ts`.
  - It uses `Bun.serve`, serves HTML directly, and does not rely on frameworks, bundlers, external assets, or network calls.

- **TLS certificate usage and HTTPS delivery: PASS**
  - The server is configured with `certs/cert.pem` and `certs/key.pem`.
  - Cookies are marked `Secure`, and HSTS is sent.
  - The server runs as a TLS Bun server rather than serving the portal over plaintext HTTP.

- **Calm, structured, ADHD-inclusive multi-step UX: PASS**
  - The UI provides progress indicators, explicit next-step text, low-density content, visible help, pause/return messaging, and no visible timers/countdowns.
  - Feedback is provided after each significant action through ARIA live regions.
  - The recovery, identity, password, sign-in, MFA, privacy, and appointment steps are clearly separated.

- **Recovery instruction link and manual-code path function: PASS**
  - The simulated recovery instruction link routes to `/?recovery-test=...`.
  - The recovery test value can be entered manually in the form.
  - The link navigation and `#instruction` handling correctly open the instruction confirmation UI.

- **Mock delivery and verification values are exposed in the browser console/UI as required: FAIL**
  - The browser logs and exposes only a deliberately non-authorizing `decoy`/“test value.”
  - The actual reset authorization is explicitly not returned to the UI or browser console: `No live token is returned, linked, logged, or available in browser JS.`
  - This conflicts with the deliverable requirement that simulated delivery/verification use browser `console.log` and that, for testing, a reset token be returned to the UI and shown in the browser console.
  - The visible value cannot be used as a reset credential; the real reset authorization is hidden server-side and is not a simulated delivered reset token.

- **Password reset authorization is random, single-use, and short-lived: PASS**
  - A random server-side reset token is generated with cryptographic randomness.
  - It has a 15-minute expiration and is invalidated after password replacement.
  - Password replacement requires a completed recovery identity step and valid session-held reset authorization.

- **Strong password policy and secure password storage: PASS**
  - Passwords require at least 12 characters, upper/lowercase letters, a number, and a symbol.
  - Password hashes use `Bun.password.hash(..., { algorithm: "argon2id" })`.
  - Passwords are not stored in plaintext.

- **CSRF defenses on state-changing endpoints: PASS**
  - All POST endpoints use `sensitive()`.
  - Requests require an existing session, matching same-origin `Origin`, and matching per-session `X-CSRF-Token`.
  - The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, and correctly uses `__Host-` cookie constraints.

- **XSS/injection defenses: PASS**
  - User input is validated server-side and client-side.
  - Client-generated log entries use `textContent`, not `innerHTML`.
  - A strict nonce-based CSP is present and no external scripts are loaded.
  - Dynamic server values injected into the script use `JSON.stringify`, reducing script-injection risk.

- **Authentication, MFA, and brute-force mitigation: FAIL**
  - Login, instruction confirmation, and MFA-code verification have attempt throttling/lockouts.
  - However, `authenticated(session)` does not verify `session.mfa.expiresAt > now()`.
  - Once MFA has been completed, `authenticated()` remains true until the much longer session expiry, even after the 10-minute MFA validity period ends.
  - Consequently, `/api/privacy/accept` and `/api/appointment` can still succeed after MFA expiry because they rely on `authenticated()`.

- **Access control and IDOR prevention: PASS**
  - Account records are keyed by server-side digests and are never exposed.
  - Sensitive state changes require the active session and do not accept account IDs/object IDs from the client.
  - The portal does not expose usernames, account folders, or patient records.

- **Security headers and secure configuration: PASS**
  - HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, cache prevention, and COOP are configured.
  - Production error responses are generic and do not expose stack traces or debug information.

- **SSRF, open redirect, and social-engineering protections: PASS**
  - No outbound network requests are made.
  - No user-supplied redirect target is accepted.
  - The help text warns users not to share passwords or recovery codes via email or phone.

## FAILING_ITEMS

- The actual password-reset authorization/token is intentionally withheld from the browser:
  - `verifyRecoveryIdentity()` generates a server-only token.
  - The code comments explicitly state that it is not returned, linked, logged, or available to browser JavaScript.
  - This does not satisfy the stated testing/mock-delivery requirement for a reset token/value to be returned to the UI and logged in the browser console.

- MFA expiration is not enforced for post-login authenticated actions:
  - `authenticated(session)` checks only `authenticatedAccount`, `mfa.completed`, and `mfa.independentPossession`.
  - It does not check `mfa.expiresAt`.
  - A user can accept privacy conditions and book an appointment after the MFA challenge has expired.

## NEW_TASKS

1. **Implement a compliant simulated reset-token delivery path.**
   - Return a testable simulated reset token/value in the recovery response/UI.
   - Log that same simulated value with `console.log` in browser JavaScript.
   - Permit manual submission of that value.
   - Preserve security semantics by clearly labeling it as a mock/testing value and ensuring any production-equivalent authorization remains cryptographically random, short-lived, and single-use.

2. **Enforce MFA expiration in authorization checks.**
   - Update `authenticated(session)` to require a valid, unexpired MFA record, including `session.mfa.expiresAt > now()`.
   - Ensure expired MFA state prevents `/api/privacy/accept` and `/api/appointment`.
   - Return a clear low-stress message instructing the user to sign in and complete MFA again when MFA has expired.

## DECISION

FAIL