## SUMMARY

The artifact is a single-file Bun application with a functional password-recovery, password-change, login, MFA, privacy-acceptance, and appointment-request flow. It has strong implementation coverage for CSP, HTTPS/TLS, session cookies, CSRF on POST APIs, password hashing, token expiry/single-use behavior, validation, output-safe DOM updates, and rate limiting. However, the recovery-link GET route performs a recovery-state transition without CSRF protection, which conflicts with the requirement that sensitive actions validate unique per-session CSRF tokens. This must be corrected before acceptance.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with inline HTML, CSS, and vanilla browser JavaScript**
  - Everything is contained in `app.ts`.
  - Bun directly serves the page and API endpoints; no framework, bundler, compiler pipeline, external asset, or network call is used.

- **PASS — TLS certificate use and HTTPS-oriented configuration**
  - The Bun server is configured with `tls: { cert: CERT, key: KEY }` using the required `certs/cert.pem` and `certs/key.pem` paths.
  - HSTS is supplied on responses.
  - Secure, `HttpOnly`, `SameSite=Strict`, `__Host-` session cookies are used.

- **PASS — Password recovery flow is usable and supports both verification-link and manual-token paths**
  - A recovery request creates a random token and a separate identity value.
  - The UI logs simulated delivery values in the browser through `console.log`.
  - Manual reset-token submission is implemented through `/api/recovery/instruction`.
  - Recovery URLs using `?recovery-test=...` work across a fresh browser session.
  - Reset tokens are random, hashed at rest, short-lived, and marked single-use after password replacement.

- **PASS — Strong password policy and secure password storage**
  - Passwords require at least 12 characters, upper/lowercase letters, a number, and a symbol.
  - Passwords are stored using `Bun.password.hash(..., { algorithm: "argon2id" })`.
  - Password replacement requires successful reset-token and recovery-identity verification.

- **PASS — Authentication and MFA simulation**
  - Login uses Argon2id password verification.
  - MFA requires a six-digit mock code and a separate possession value.
  - Both mock values are browser-console logged as required for testing.
  - MFA state, expiry, and failure handling are tracked server-side.

- **PASS — Brute-force protections**
  - Login attempts are locked after repeated failures.
  - Reset-token confirmation attempts are throttled per session.
  - Recovery identity and MFA values have repeated-failure lockouts.
  - Recovery instruction issuance is rate-limited per session/account combination.

- **PASS — Input validation and XSS protections**
  - API inputs are type checked and constrained.
  - Client-visible dynamic text is written via `textContent`, not `innerHTML`.
  - The recovery link is parsed, origin-checked, path-checked, and created via safe DOM APIs.
  - A nonce-based CSP is used for the required inline page CSS and script.

- **PASS — ADHD/inclusivity-oriented UX**
  - The UI provides numbered progress, one visible task at a time, clear next-step messages, live feedback, pause-oriented messaging, and easily accessible help.
  - Internal progression buttons work for all recovery, login, MFA, privacy, and appointment stages.
  - The UI avoids dense content and uses consistent step wording.

- **FAIL — CSRF is not enforced for the recovery-link state transition**
  - `GET /?recovery-test=<token>` calls `attachRecovery(session, found.hash, found.record, true)` directly.
  - This marks the token as confirmed in the victim’s session without checking `Origin` or a session-specific CSRF token.
  - The code explicitly labels CSRF as required for sensitive actions, but this recovery confirmation is a security-sensitive state change performed through a GET request.
  - A cross-site navigation can trigger this transition if an attacker supplies a recovery link, violating the requirement that sessions must not allow unintended actions and that CSRF tokens be validated on sensitive requests.

- **PASS — No obvious TypeScript/Bun syntax or execution errors**
  - The code is structurally valid TypeScript for Bun.
  - `Bun.password`, `Bun.serve`, `Bun.file`, Web Crypto APIs, and the `node:crypto` import are used in a Bun-compatible manner.
  - Route handling, response generation, body parsing, and client-side element references appear internally consistent.

## FAILING_ITEMS

- **Recovery-token confirmation is performed by a GET request without CSRF validation.**
  - In the root GET handler, a `recovery-test` query parameter immediately calls `attachRecovery(...)` and sets `tokenConfirmed: true`.
  - The action changes server-side session state and moves the user past the reset-token confirmation stage.
  - This bypasses the existing `sensitive()` CSRF and same-origin validation that protects POST routes.

- **The browser script treats a recovery URL as already confirmed without making a CSRF-protected confirmation request.**
  - On page load, when `recovery-test` is present, the script immediately runs `show("identity")`.
  - This matches the server’s unsafe GET state change rather than using the existing protected `/api/recovery/instruction` endpoint.

## NEW_TASKS

1. **Make recovery-link GET handling non-mutating.**
   - Remove the `attachRecovery(...)`, `clearResetConfirmationFailures(...)`, and `session.recovery = ...` mutations from the `GET /` handler when `recovery-test` is present.
   - The GET route may validate format and render the page, but it must not confirm or attach a reset token to the session.

2. **Confirm a recovery-link token through the existing CSRF-protected POST API.**
   - On client startup, if `recovery-test` is present, retain the token locally and submit it to `/api/recovery/instruction` via `api(...)`.
   - Only proceed to the identity stage after the protected API returns `{ ok: true }`.
   - If confirmation fails, show the instruction/manual-token step and display the safe server error message.

3. **Ensure the recovery-link UI remains functional after the CSRF change.**
   - Preserve the current link behavior: opening a valid simulated recovery link should still lead the user to recovery identity verification.
   - Keep manual token entry available as a fallback.
   - Avoid exposing the token in unsafe DOM insertion; continue using the current safe DOM and URL-validation approach.

## DECISION

**FAIL**